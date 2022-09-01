use {
    solana_program_runtime::compute_budget::ComputeBudget,
    solana_sdk::{
        instruction::CompiledInstruction,
        pubkey::Pubkey,
        transaction::{SanitizedTransaction, SanitizedVersionedTransaction},
    },
};

#[derive(Debug, PartialEq, Eq)]
pub struct TransactionPriorityDetails {
    pub priority: u64,
    pub compute_unit_limit: u64,
}

pub trait GetTransactionPriorityDetails {
    fn get_transaction_priority_details(&self) -> Option<TransactionPriorityDetails>;

    fn process_compute_budget_instruction<'a>(
        instructions: impl Iterator<Item = (&'a Pubkey, &'a CompiledInstruction)>,
    ) -> Option<TransactionPriorityDetails> {
        let mut compute_budget = ComputeBudget::default();
        let prioritization_fee_details = compute_budget
            .process_instructions(
                instructions,
                true, // use default units per instruction
                true, // don't reject txs that use set compute unit price ix
            )
            .ok()?;
        Some(TransactionPriorityDetails {
            priority: prioritization_fee_details.get_priority(),
            compute_unit_limit: compute_budget.compute_unit_limit,
        })
    }
}

impl GetTransactionPriorityDetails for SanitizedVersionedTransaction {
    fn get_transaction_priority_details(&self) -> Option<TransactionPriorityDetails> {
        Self::process_compute_budget_instruction(self.get_message().program_instructions_iter())
    }
}

impl GetTransactionPriorityDetails for SanitizedTransaction {
    fn get_transaction_priority_details(&self) -> Option<TransactionPriorityDetails> {
        Self::process_compute_budget_instruction(self.message().program_instructions_iter())
    }
}
