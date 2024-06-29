use {
    solana_compute_budget::compute_budget_processor::process_compute_budget_instructions,
    solana_sdk::{
        instruction::CompiledInstruction,
        pubkey::Pubkey,
        transaction::{SanitizedTransaction, SanitizedVersionedTransaction},
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeBudgetDetails {
    pub compute_unit_price: u64,
    pub compute_unit_limit: u64,
}

pub trait GetComputeBudgetDetails {
    fn get_compute_budget_details(
        &self,
        round_compute_unit_price_enabled: bool,
    ) -> Option<ComputeBudgetDetails>;

    fn process_compute_budget_instruction<'a>(
        instructions: impl Iterator<Item = (&'a Pubkey, &'a CompiledInstruction)>,
        _round_compute_unit_price_enabled: bool,
    ) -> Option<ComputeBudgetDetails> {
        let compute_budget_limits = process_compute_budget_instructions(instructions).ok()?;
        Some(ComputeBudgetDetails {
            compute_unit_price: compute_budget_limits.compute_unit_price,
            compute_unit_limit: u64::from(compute_budget_limits.compute_unit_limit),
        })
    }
}

impl GetComputeBudgetDetails for SanitizedVersionedTransaction {
    fn get_compute_budget_details(
        &self,
        round_compute_unit_price_enabled: bool,
    ) -> Option<ComputeBudgetDetails> {
        Self::process_compute_budget_instruction(
            self.get_message().program_instructions_iter(),
            round_compute_unit_price_enabled,
        )
    }
}

impl GetComputeBudgetDetails for SanitizedTransaction {
    fn get_compute_budget_details(
        &self,
        round_compute_unit_price_enabled: bool,
    ) -> Option<ComputeBudgetDetails> {
        Self::process_compute_budget_instruction(
            self.message().program_instructions_iter(),
            round_compute_unit_price_enabled,
        )
    }
}
