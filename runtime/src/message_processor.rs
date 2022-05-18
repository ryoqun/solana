use {
    serde::{Deserialize, Serialize},
    solana_measure::measure::Measure,
    solana_program_runtime::{
        compute_budget::ComputeBudget,
        instruction_recorder::InstructionRecorder,
        invoke_context::{
            BuiltinProgram, Executors, InvokeContext, ProcessInstructionResult,
            TransactionAccountRefCell,
        },
        log_collector::LogCollector,
        sysvar_cache::SysvarCache,
        timings::ExecuteTimings,
    },
    solana_sdk::{
        account::WritableAccount,
        feature_set::{prevent_calling_precompiles_as_programs, FeatureSet},
        hash::Hash,
        message::SanitizedMessage,
        precompiles::is_precompile,
        rent::Rent,
        saturating_add_assign,
        sysvar::instructions,
        transaction::TransactionError,
    },
    std::{borrow::Cow, cell::RefCell, rc::Rc, sync::Arc},
};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct MessageProcessor {}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl ::solana_frozen_abi::abi_example::AbiExample for MessageProcessor {
    fn example() -> Self {
        // MessageProcessor's fields are #[serde(skip)]-ed and not Serialize
        // so, just rely on Default anyway.
        MessageProcessor::default()
    }
}

/// Trace of all instructions attempted
pub type InstructionTrace = Vec<InstructionRecorder>;

/// Resultant information gathered from calling process_message()
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProcessedMessageInfo {
    /// The change in accounts data len
    pub accounts_data_len_delta: i64,
}

impl MessageProcessor {
    /// Process a message.
    /// This method calls each instruction in the message over the set of loaded accounts.
    /// For each instruction it calls the program entrypoint method and verifies that the result of
    /// the call does not violate the bank's accounting rules.
    /// The accounts are committed back to the bank only if every instruction succeeds.
    #[allow(clippy::too_many_arguments)]
    pub fn process_message(
        builtin_programs: &[BuiltinProgram],
        message: &SanitizedMessage,
        program_indices: &[Vec<usize>],
        accounts: &[TransactionAccountRefCell],
        rent: Rent,
        log_collector: Option<Rc<RefCell<LogCollector>>>,
        executors: Rc<RefCell<Executors>>,
        instruction_trace: &mut InstructionTrace,
        feature_set: Arc<FeatureSet>,
        compute_budget: ComputeBudget,
        timings: &mut ExecuteTimings,
        sysvar_cache: &SysvarCache,
        blockhash: Hash,
        lamports_per_signature: u64,
        current_accounts_data_len: u64,
        accumulated_consumed_units: &mut u64,
    ) -> Result<ProcessedMessageInfo, TransactionError> {
        let mut invoke_context = InvokeContext::new(
            rent,
            accounts,
            builtin_programs,
            Cow::Borrowed(sysvar_cache),
            log_collector,
            compute_budget,
            executors,
            feature_set,
            blockhash,
            lamports_per_signature,
            current_accounts_data_len,
        );

        debug_assert_eq!(program_indices.len(), message.instructions().len());
        for (instruction_index, ((program_id, instruction), program_indices)) in message
            .program_instructions_iter()
            .zip(program_indices.iter())
            .enumerate()
        {
            invoke_context.record_top_level_instruction(
                instruction.decompile(message).map_err(|err| {
                    TransactionError::InstructionError(instruction_index as u8, err)
                })?,
            );

            if invoke_context
                .feature_set
                .is_active(&prevent_calling_precompiles_as_programs::id())
                && is_precompile(program_id, |id| invoke_context.feature_set.is_active(id))
            {
                // Precompiled programs don't have an instruction processor
                continue;
            }

            // Fixup the special instructions key if present
            // before the account pre-values are taken care of
            for (pubkey, account) in accounts.iter().take(message.account_keys_len()) {
                if instructions::check_id(pubkey) {
                    let mut mut_account_ref = account.borrow_mut();
                    instructions::store_current_index(
                        mut_account_ref.data_as_mut_slice(),
                        instruction_index as u16,
                    );
                    break;
                }
            }

            let mut time = Measure::start("execute_instruction");
            let ProcessInstructionResult {
                compute_units_consumed,
                result,
            } = invoke_context.process_instruction(
                message,
                instruction,
                program_indices,
                &[],
                &[],
                timings,
            );
            time.stop();
            *accumulated_consumed_units =
                accumulated_consumed_units.saturating_add(compute_units_consumed);
            timings.details.accumulate_program(
                program_id,
                time.as_us(),
                compute_units_consumed,
                result.is_err(),
            );
            timings.details.accumulate(&invoke_context.timings);
            saturating_add_assign!(
                timings.execute_accessories.process_instructions.total_us,
                time.as_us()
            );

            result.map_err(|err| {
                instruction_trace.append(invoke_context.get_instruction_trace_mut());
                TransactionError::InstructionError(instruction_index as u8, err)
            })?;
        }
        instruction_trace.append(invoke_context.get_instruction_trace_mut());
        Ok(ProcessedMessageInfo {
            accounts_data_len_delta: invoke_context.get_accounts_data_meter().delta(),
        })
    }
}

