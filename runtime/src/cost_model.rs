//! 'cost_model` provides service to estimate a transaction's cost
//! following proposed fee schedule #16984; Relevant cluster cost
//! measuring is described by #19627
//!
//! The main function is `calculate_cost` which returns &TransactionCost.
//!
use {
    crate::{block_cost_limits::*, execute_cost_table::ExecuteCostTable},
    log::*,
    solana_sdk::{
        instruction::CompiledInstruction, program_utils::limited_deserialize, pubkey::Pubkey,
        system_instruction::SystemInstruction, system_program, transaction::SanitizedTransaction,
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
        self.sum_without_bpf()
            .saturating_add(self.bpf_execution_cost)
    }

    pub fn sum_without_bpf(&self) -> u64 {
        self.signature_cost
            .saturating_add(self.write_lock_cost)
            .saturating_add(self.data_bytes_cost)
            .saturating_add(self.builtins_execution_cost)
    }
}

#[derive(Debug, Default)]
pub struct CostModel {
    instruction_execution_cost_table: ExecuteCostTable,
}

impl CostModel {
    pub fn new() -> Self {
        Self {
            instruction_execution_cost_table: ExecuteCostTable::default(),
        }
    }

    pub fn initialize_cost_table(&mut self, cost_table: &[(Pubkey, u64)]) {
        cost_table
            .iter()
            .map(|(key, cost)| (key, cost))
            .for_each(|(program_id, cost)| {
                self.upsert_instruction_cost(program_id, *cost);
            });
    }

    pub fn calculate_cost(&self, transaction: &SanitizedTransaction) -> TransactionCost {
        let mut tx_cost = TransactionCost::new_with_capacity(MAX_WRITABLE_ACCOUNTS);

        tx_cost.signature_cost = self.get_signature_cost(transaction);
        self.get_write_lock_cost(&mut tx_cost, transaction);
        self.get_transaction_cost(&mut tx_cost, transaction);
        tx_cost.account_data_size = self.calculate_account_data_size(transaction);
        tx_cost.is_simple_vote = transaction.is_simple_vote_transaction();

        debug!("transaction {:?} has cost {:?}", transaction, tx_cost);
        tx_cost
    }

    pub fn upsert_instruction_cost(&mut self, program_key: &Pubkey, cost: u64) {
        self.instruction_execution_cost_table
            .upsert(program_key, cost);
    }

    pub fn find_instruction_cost(&self, program_key: &Pubkey) -> u64 {
        match self.instruction_execution_cost_table.get_cost(program_key) {
            Some(cost) => *cost,
            None => {
                let default_value = self
                    .instruction_execution_cost_table
                    .get_default_compute_unit_limit();
                debug!(
                    "Program {:?} does not have aggregated cost, using default value {}",
                    program_key, default_value
                );
                default_value
            }
        }
    }

    fn get_signature_cost(&self, transaction: &SanitizedTransaction) -> u64 {
        transaction.signatures().len() as u64 * SIGNATURE_COST
    }

    fn get_write_lock_cost(
        &self,
        tx_cost: &mut TransactionCost,
        transaction: &SanitizedTransaction,
    ) {
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
        &self,
        tx_cost: &mut TransactionCost,
        transaction: &SanitizedTransaction,
    ) {
        let mut builtin_costs = 0u64;
        let mut bpf_costs = 0u64;
        let mut data_bytes_len_total = 0u64;

        for (program_id, instruction) in transaction.message().program_instructions_iter() {
            // to keep the same behavior, look for builtin first
            if let Some(builtin_cost) = BUILT_IN_INSTRUCTION_COSTS.get(program_id) {
                builtin_costs = builtin_costs.saturating_add(*builtin_cost);
            } else {
                let instruction_cost = self.find_instruction_cost(program_id);
                trace!(
                    "instruction {:?} has cost of {}",
                    instruction,
                    instruction_cost
                );
                bpf_costs = bpf_costs.saturating_add(instruction_cost);
            }
            data_bytes_len_total =
                data_bytes_len_total.saturating_add(instruction.data.len() as u64);
        }
        tx_cost.builtins_execution_cost = builtin_costs;
        tx_cost.bpf_execution_cost = bpf_costs;
        tx_cost.data_bytes_cost = data_bytes_len_total / DATA_BYTES_UNITS;
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
    fn calculate_account_data_size(&self, transaction: &SanitizedTransaction) -> u64 {
        transaction
            .message()
            .program_instructions_iter()
            .map(|(program_id, instruction)| {
                Self::calculate_account_data_size_on_instruction(program_id, instruction)
            })
            .sum()
    }
}
