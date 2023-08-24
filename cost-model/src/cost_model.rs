//! 'cost_model` provides service to estimate a transaction's cost
//! following proposed fee schedule #16984; Relevant cluster cost
//! measuring is described by #19627
//!
//! The main function is `calculate_cost` which returns &TransactionCost.
//!

use {
    crate::{block_cost_limits::*, transaction_cost::TransactionCost},
    log::*,
    solana_program_runtime::compute_budget::{
        ComputeBudget, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT, MAX_COMPUTE_UNIT_LIMIT,
    },
    solana_sdk::{
        borsh0_10::try_from_slice_unchecked,
        compute_budget::{self, ComputeBudgetInstruction},
        feature_set::{
            add_set_tx_loaded_accounts_data_size_instruction,
            include_loaded_accounts_data_size_in_fee_calculation,
            remove_deprecated_request_unit_ix, FeatureSet,
        },
        fee::FeeStructure,
        instruction::CompiledInstruction,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        system_instruction::SystemInstruction,
        system_program,
        transaction::SanitizedTransaction,
    },
};

pub struct CostModel;

impl CostModel {
    pub fn calculate_cost(
        transaction: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) -> TransactionCost {
        let mut tx_cost = TransactionCost::new_with_default_capacity();

        tx_cost.signature_cost = Self::get_signature_cost(transaction);
        Self::get_write_lock_cost(&mut tx_cost, transaction);
        Self::get_transaction_cost(&mut tx_cost, transaction, feature_set);
        tx_cost.account_data_size = Self::calculate_account_data_size(transaction);
        tx_cost.is_simple_vote = transaction.is_simple_vote_transaction();

        debug!("transaction {:?} has cost {:?}", transaction, tx_cost);
        tx_cost
    }

    // Calculate cost of loaded accounts size in the same way heap cost is charged at
    // rate of 8cu per 32K. Citing `program_runtime\src\compute_budget.rs`: "(cost of
    // heap is about) 0.5us per 32k at 15 units/us rounded up"
    //
    // Before feature `support_set_loaded_accounts_data_size_limit_ix` is enabled, or
    // if user doesn't use compute budget ix `set_loaded_accounts_data_size_limit_ix`
    // to set limit, `compute_budget.loaded_accounts_data_size_limit` is set to default
    // limit of 64MB; which will convert to (64M/32K)*8CU = 16_000 CUs
    //
    pub fn calculate_loaded_accounts_data_size_cost(compute_budget: &ComputeBudget) -> u64 {
        FeeStructure::calculate_memory_usage_cost(
            compute_budget.loaded_accounts_data_size_limit,
            compute_budget.heap_cost,
        )
    }

    fn get_signature_cost(transaction: &SanitizedTransaction) -> u64 {
        transaction.signatures().len() as u64 * SIGNATURE_COST
    }

    fn get_write_lock_cost(tx_cost: &mut TransactionCost, transaction: &SanitizedTransaction) {
        let message = transaction.message();
        message
            .account_keys()
            .iter()
            .enumerate()
            .for_each(|(i, k)| {
                let is_writable = message.is_writable(i);

                if is_writable {
                    tx_cost.writable_accounts.push(*k);
                    tx_cost.write_lock_cost += WRITE_LOCK_UNITS;
                }
            });
    }

    fn get_transaction_cost(
        tx_cost: &mut TransactionCost,
        transaction: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) {
        let mut builtin_costs = 0u64;
        let mut bpf_costs = 0u64;
        let mut loaded_accounts_data_size_cost = 0u64;
        let mut data_bytes_len_total = 0u64;
        let mut compute_unit_limit_is_set = false;

        for (program_id, instruction) in transaction.message().program_instructions_iter() {
            // to keep the same behavior, look for builtin first
            if let Some(builtin_cost) = BUILT_IN_INSTRUCTION_COSTS.get(program_id) {
                builtin_costs = builtin_costs.saturating_add(*builtin_cost);
            } else {
                bpf_costs = bpf_costs
                    .saturating_add(u64::from(DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT))
                    .min(u64::from(MAX_COMPUTE_UNIT_LIMIT));
            }
            data_bytes_len_total =
                data_bytes_len_total.saturating_add(instruction.data.len() as u64);

            if compute_budget::check_id(program_id) {
                if let Ok(ComputeBudgetInstruction::SetComputeUnitLimit(_)) =
                    try_from_slice_unchecked(&instruction.data)
                {
                    compute_unit_limit_is_set = true;
                }
            }
        }

        // calculate bpf cost based on compute budget instructions
        let mut compute_budget = ComputeBudget::default();

        // Starting from v1.15, cost model uses compute_budget.set_compute_unit_limit to
        // measure bpf_costs (code below), vs earlier versions that use estimated
        // bpf instruction costs. The calculated transaction costs are used by leaders
        // during block packing, different costs for same transaction due to different versions
        // will not impact consensus. So for v1.15+, should call compute budget with
        // the feature gate `enable_request_heap_frame_ix` enabled.
        let enable_request_heap_frame_ix = true;
        let result = compute_budget.process_instructions(
            transaction.message().program_instructions_iter(),
            !feature_set.is_active(&remove_deprecated_request_unit_ix::id()),
            enable_request_heap_frame_ix,
            feature_set.is_active(&add_set_tx_loaded_accounts_data_size_instruction::id()),
        );

        // if failed to process compute_budget instructions, the transaction will not be executed
        // by `bank`, therefore it should be considered as no execution cost by cost model.
        match result {
            Ok(_) => {
                // if tx contained user-space instructions and a more accurate estimate available correct it,
                // where "user-space instructions" must be specifically checked by
                // 'compute_unit_limit_is_set' flag, because compute_budget does not distinguish
                // builtin and bpf instructions when calculating default compute-unit-limit. (see
                // compute_budget.rs test `test_process_mixed_instructions_without_compute_budget`)
                if bpf_costs > 0 && compute_unit_limit_is_set {
                    bpf_costs = compute_budget.compute_unit_limit
                }

                if feature_set
                    .is_active(&include_loaded_accounts_data_size_in_fee_calculation::id())
                {
                    loaded_accounts_data_size_cost =
                        Self::calculate_loaded_accounts_data_size_cost(&compute_budget);
                }
            }
            Err(_) => {
                builtin_costs = 0;
                bpf_costs = 0;
            }
        }

        tx_cost.builtins_execution_cost = builtin_costs;
        tx_cost.bpf_execution_cost = bpf_costs;
        tx_cost.loaded_accounts_data_size_cost = loaded_accounts_data_size_cost;
        tx_cost.data_bytes_cost = data_bytes_len_total / INSTRUCTION_DATA_BYTES_COST;
    }

    fn calculate_account_data_size_on_deserialized_system_instruction(
        instruction: SystemInstruction,
    ) -> u64 {
        match instruction {
            SystemInstruction::CreateAccount {
                lamports: _lamports,
                space,
                owner: _owner,
            } => space,
            SystemInstruction::CreateAccountWithSeed {
                base: _base,
                seed: _seed,
                lamports: _lamports,
                space,
                owner: _owner,
            } => space,
            SystemInstruction::Allocate { space } => space,
            SystemInstruction::AllocateWithSeed {
                base: _base,
                seed: _seed,
                space,
                owner: _owner,
            } => space,
            _ => 0,
        }
    }

    fn calculate_account_data_size_on_instruction(
        program_id: &Pubkey,
        instruction: &CompiledInstruction,
    ) -> u64 {
        if program_id == &system_program::id() {
            if let Ok(instruction) = limited_deserialize(&instruction.data) {
                return Self::calculate_account_data_size_on_deserialized_system_instruction(
                    instruction,
                );
            }
        }
        0
    }

    /// eventually, potentially determine account data size of all writable accounts
    /// at the moment, calculate account data size of account creation
    fn calculate_account_data_size(transaction: &SanitizedTransaction) -> u64 {
        transaction
            .message()
            .program_instructions_iter()
            .map(|(program_id, instruction)| {
                Self::calculate_account_data_size_on_instruction(program_id, instruction)
            })
            .sum()
    }
}
