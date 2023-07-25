//! 'cost_model` provides service to estimate a transaction's cost
//! following proposed fee schedule #16984; Relevant cluster cost
//! measuring is described by #19627
//!
//! The main function is `calculate_cost` which returns &TransactionCost.
//!

use {
    crate::block_cost_limits::*,
    log::*,
    solana_program_runtime::compute_budget::{
        ComputeBudget, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
    },
    solana_sdk::{
        feature_set::{
            add_set_tx_loaded_accounts_data_size_instruction, remove_deprecated_request_unit_ix,
            use_default_units_in_fee_calculation, FeatureSet,
        },
        instruction::CompiledInstruction,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        system_instruction::SystemInstruction,
        system_program,
        transaction::SanitizedTransaction,
    },
};

const MAX_WRITABLE_ACCOUNTS: usize = 256;

// costs are stored in number of 'compute unit's
#[derive(Debug)]
pub struct TransactionCost {
    pub writable_accounts: Vec<Pubkey>,
    pub signature_cost: u64,
    pub write_lock_cost: u64,
    pub data_bytes_cost: u64,
    pub builtins_execution_cost: u64,
    pub bpf_execution_cost: u64,
    pub account_data_size: u64,
    pub is_simple_vote: bool,
}

impl Default for TransactionCost {
    fn default() -> Self {
        Self {
            writable_accounts: Vec::with_capacity(MAX_WRITABLE_ACCOUNTS),
            signature_cost: 0u64,
            write_lock_cost: 0u64,
            data_bytes_cost: 0u64,
            builtins_execution_cost: 0u64,
            bpf_execution_cost: 0u64,
            account_data_size: 0u64,
            is_simple_vote: false,
        }
    }
}

impl TransactionCost {
    pub fn new_with_capacity(capacity: usize) -> Self {
        Self {
            writable_accounts: Vec::with_capacity(capacity),
            ..Self::default()
        }
    }

    pub fn reset(&mut self) {
        self.writable_accounts.clear();
        self.signature_cost = 0;
        self.write_lock_cost = 0;
        self.data_bytes_cost = 0;
        self.builtins_execution_cost = 0;
        self.bpf_execution_cost = 0;
        self.is_simple_vote = false;
    }

    pub fn sum(&self) -> u64 {
        self.signature_cost
            .saturating_add(self.write_lock_cost)
            .saturating_add(self.data_bytes_cost)
            .saturating_add(self.builtins_execution_cost)
            .saturating_add(self.bpf_execution_cost)
    }
}

pub struct CostModel;

impl CostModel {
    pub fn calculate_cost(
        transaction: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) -> TransactionCost {
        let mut tx_cost = TransactionCost::new_with_capacity(MAX_WRITABLE_ACCOUNTS);

        tx_cost.signature_cost = Self::get_signature_cost(transaction);
        Self::get_write_lock_cost(&mut tx_cost, transaction);
        Self::get_transaction_cost(&mut tx_cost, transaction, feature_set);
        tx_cost.account_data_size = Self::calculate_account_data_size(transaction);
        tx_cost.is_simple_vote = transaction.is_simple_vote_transaction();

        debug!("transaction {:?} has cost {:?}", transaction, tx_cost);
        tx_cost
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
        let mut data_bytes_len_total = 0u64;

        for (program_id, instruction) in transaction.message().program_instructions_iter() {
            // to keep the same behavior, look for builtin first
            if let Some(builtin_cost) = BUILT_IN_INSTRUCTION_COSTS.get(program_id) {
                builtin_costs = builtin_costs.saturating_add(*builtin_cost);
            } else {
                bpf_costs = bpf_costs.saturating_add(DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT.into());
            }
            data_bytes_len_total =
                data_bytes_len_total.saturating_add(instruction.data.len() as u64);
        }

        // calculate bpf cost based on compute budget instructions
        let mut budget = ComputeBudget::default();

        // Starting from v1.15, cost model uses compute_budget.set_compute_unit_limit to
        // measure bpf_costs (code below), vs earlier versions that use estimated
        // bpf instruction costs. The calculated transaction costs are used by leaders
        // during block packing, different costs for same transaction due to different versions
        // will not impact consensus. So for v1.15+, should call compute budget with
        // the feature gate `enable_request_heap_frame_ix` enabled.
        let enable_request_heap_frame_ix = true;
        let result = budget.process_instructions(
            transaction.message().program_instructions_iter(),
            feature_set.is_active(&use_default_units_in_fee_calculation::id()),
            !feature_set.is_active(&remove_deprecated_request_unit_ix::id()),
            enable_request_heap_frame_ix,
            feature_set.is_active(&add_set_tx_loaded_accounts_data_size_instruction::id()),
        );

        // if tx contained user-space instructions and a more accurate estimate available correct it
        if bpf_costs > 0 && result.is_ok() {
            bpf_costs = budget.compute_unit_limit
        }

        tx_cost.builtins_execution_cost = builtin_costs;
        tx_cost.bpf_execution_cost = bpf_costs;
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
