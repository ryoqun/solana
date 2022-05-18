use {
    crate::prioritization_fee::{PrioritizationFeeDetails, PrioritizationFeeType},
    solana_sdk::{
        borsh::try_from_slice_unchecked,
        compute_budget::{self, ComputeBudgetInstruction},
        entrypoint::HEAP_LENGTH as MIN_HEAP_FRAME_BYTES,
        instruction::{CompiledInstruction, InstructionError},
        pubkey::Pubkey,
        transaction::TransactionError,
    },
};

pub const DEFAULT_UNITS: u32 = 200_000;
pub const MAX_UNITS: u32 = 1_400_000;
const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024;

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl ::solana_frozen_abi::abi_example::AbiExample for ComputeBudget {
    fn example() -> Self {
        // ComputeBudget is not Serialize so just rely on Default.
        ComputeBudget::default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ComputeBudget {
    /// Number of compute units that an instruction is allowed.  Compute units
    /// are consumed by program execution, resources they use, etc...
    pub max_units: u64,
    /// Number of compute units consumed by a log_u64 call
    pub log_64_units: u64,
    /// Number of compute units consumed by a create_program_address call
    pub create_program_address_units: u64,
    /// Number of compute units consumed by an invoke call (not including the cost incurred by
    /// the called program)
    pub invoke_units: u64,
    /// Maximum cross-program invocation depth allowed
    pub max_invoke_depth: usize,
    /// Base number of compute units consumed to call SHA256
    pub sha256_base_cost: u64,
    /// Incremental number of units consumed by SHA256 (based on bytes)
    pub sha256_byte_cost: u64,
    /// Maximum number of slices hashed per syscall
    pub sha256_max_slices: u64,
    /// Maximum BPF to BPF call depth
    pub max_call_depth: usize,
    /// Size of a stack frame in bytes, must match the size specified in the LLVM BPF backend
    pub stack_frame_size: usize,
    /// Number of compute units consumed by logging a `Pubkey`
    pub log_pubkey_units: u64,
    /// Maximum cross-program invocation instruction size
    pub max_cpi_instruction_size: usize,
    /// Number of account data bytes per conpute unit charged during a cross-program invocation
    pub cpi_bytes_per_unit: u64,
    /// Base number of compute units consumed to get a sysvar
    pub sysvar_base_cost: u64,
    /// Number of compute units consumed to call secp256k1_recover
    pub secp256k1_recover_cost: u64,
    /// Number of compute units consumed to do a syscall without any work
    pub syscall_base_cost: u64,
    /// Number of compute units consumed to call zktoken_crypto_op
    pub zk_token_elgamal_op_cost: u64,
    /// Optional program heap region size, if `None` then loader default
    pub heap_size: Option<usize>,
    /// Number of compute units per additional 32k heap above the default (~.5
    /// us per 32k at 15 units/us rounded up)
    pub heap_cost: u64,
    /// Memory operation syscall base cost
    pub mem_op_base_cost: u64,
}

impl Default for ComputeBudget {
    fn default() -> Self {
        Self::new(MAX_UNITS)
    }
}

impl ComputeBudget {
    pub fn new(max_units: u32) -> Self {
        ComputeBudget {
            max_units: max_units as u64,
            log_64_units: 100,
            create_program_address_units: 1500,
            invoke_units: 1000,
            max_invoke_depth: 4,
            sha256_base_cost: 85,
            sha256_byte_cost: 1,
            sha256_max_slices: 20_000,
            max_call_depth: 64,
            stack_frame_size: 4_096,
            log_pubkey_units: 100,
            max_cpi_instruction_size: 1280, // IPv6 Min MTU size
            cpi_bytes_per_unit: 250,        // ~50MB at 200,000 units
            sysvar_base_cost: 100,
            secp256k1_recover_cost: 25_000,
            syscall_base_cost: 100,
            zk_token_elgamal_op_cost: 25_000,
            heap_size: None,
            heap_cost: 8,
            mem_op_base_cost: 10,
        }
    }

    pub fn process_instructions<'a>(
        &mut self,
        instructions: impl Iterator<Item = (&'a Pubkey, &'a CompiledInstruction)>,
        requestable_heap_size: bool,
        default_units_per_instruction: bool,
        support_set_compute_unit_price_ix: bool,
    ) -> Result<PrioritizationFeeDetails, TransactionError> {
        let mut num_non_compute_budget_instructions: usize = 0;
        let mut requested_units = None;
        let mut requested_heap_size = None;
        let mut prioritization_fee = None;

        for (i, (program_id, instruction)) in instructions.enumerate() {
            if compute_budget::check_id(program_id) {
                if support_set_compute_unit_price_ix {
                    let invalid_instruction_data_error = TransactionError::InstructionError(
                        i as u8,
                        InstructionError::InvalidInstructionData,
                    );
                    let duplicate_instruction_error =
                        TransactionError::DuplicateInstruction(i as u8);

                    match try_from_slice_unchecked(&instruction.data) {
                        Ok(ComputeBudgetInstruction::RequestUnitsDeprecated {
                            units,
                            additional_fee,
                        }) => {
                            if requested_units.is_some() {
                                return Err(duplicate_instruction_error);
                            }
                            if prioritization_fee.is_some() {
                                return Err(duplicate_instruction_error);
                            }
                            requested_units = Some(units as u64);
                            prioritization_fee =
                                Some(PrioritizationFeeType::Deprecated(additional_fee as u64));
                        }
                        Ok(ComputeBudgetInstruction::RequestHeapFrame(bytes)) => {
                            if requested_heap_size.is_some() {
                                return Err(duplicate_instruction_error);
                            }
                            requested_heap_size = Some((bytes, i as u8));
                        }
                        Ok(ComputeBudgetInstruction::RequestUnits(units)) => {
                            if requested_units.is_some() {
                                return Err(duplicate_instruction_error);
                            }
                            requested_units = Some(units as u64);
                        }
                        Ok(ComputeBudgetInstruction::SetComputeUnitPrice(micro_lamports)) => {
                            if prioritization_fee.is_some() {
                                return Err(duplicate_instruction_error);
                            }
                            prioritization_fee =
                                Some(PrioritizationFeeType::ComputeUnitPrice(micro_lamports));
                        }
                        _ => return Err(invalid_instruction_data_error),
                    }
                } else if i < 3 {
                    match try_from_slice_unchecked(&instruction.data) {
                        Ok(ComputeBudgetInstruction::RequestUnitsDeprecated {
                            units,
                            additional_fee,
                        }) => {
                            requested_units = Some(units as u64);
                            prioritization_fee =
                                Some(PrioritizationFeeType::Deprecated(additional_fee as u64));
                        }
                        Ok(ComputeBudgetInstruction::RequestHeapFrame(bytes)) => {
                            requested_heap_size = Some((bytes, 0));
                        }
                        _ => {
                            return Err(TransactionError::InstructionError(
                                0,
                                InstructionError::InvalidInstructionData,
                            ))
                        }
                    }
                }
            } else {
                // only include non-request instructions in default max calc
                num_non_compute_budget_instructions =
                    num_non_compute_budget_instructions.saturating_add(1);
            }
        }

        if let Some((bytes, i)) = requested_heap_size {
            if !requestable_heap_size
                || bytes > MAX_HEAP_FRAME_BYTES
                || bytes < MIN_HEAP_FRAME_BYTES as u32
                || bytes % 1024 != 0
            {
                return Err(TransactionError::InstructionError(
                    i,
                    InstructionError::InvalidInstructionData,
                ));
            }
            self.heap_size = Some(bytes as usize);
        }

        self.max_units = if default_units_per_instruction {
            requested_units.or_else(|| {
                Some(
                    num_non_compute_budget_instructions.saturating_mul(DEFAULT_UNITS as usize)
                        as u64,
                )
            })
        } else {
            requested_units
        }
        .unwrap_or(MAX_UNITS as u64)
        .min(MAX_UNITS as u64);

        Ok(prioritization_fee
            .map(|fee_type| PrioritizationFeeDetails::new(fee_type, self.max_units))
            .unwrap_or_default())
    }
}

