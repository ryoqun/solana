#![deny(clippy::integer_arithmetic)]
#![deny(clippy::indexing_slicing)]

pub mod alloc;
pub mod allocator_bump;
pub mod deprecated;
pub mod serialization;
pub mod syscalls;
pub mod upgradeable;
pub mod upgradeable_with_jit;
pub mod with_jit;

#[macro_use]
extern crate solana_metrics;

use {
    crate::{
        serialization::{deserialize_parameters, serialize_parameters},
        syscalls::SyscallError,
    },
    log::{log_enabled, trace, Level::Trace},
    solana_measure::measure::Measure,
    solana_program_runtime::{
        ic_logger_msg, ic_msg,
        invoke_context::{ComputeMeter, Executor, InvokeContext},
        log_collector::LogCollector,
        stable_log,
        sysvar_cache::get_sysvar_with_account_check,
    },
    solana_rbpf::{
        aligned_memory::AlignedMemory,
        ebpf::HOST_ALIGN,
        elf::Executable,
        error::{EbpfError, UserDefinedError},
        static_analysis::Analysis,
        verifier::{self, VerifierError},
        vm::{Config, EbpfVm, InstructionMeter},
    },
    solana_sdk::{
        account::{ReadableAccount, WritableAccount},
        account_utils::State,
        bpf_loader, bpf_loader_deprecated,
        bpf_loader_upgradeable::{self, UpgradeableLoaderState},
        entrypoint::{HEAP_LENGTH, SUCCESS},
        feature_set::{
            cap_accounts_data_len, disable_bpf_deprecated_load_instructions,
            disable_bpf_unresolved_symbols_at_runtime, disable_deprecated_loader,
            do_support_realloc, reduce_required_deploy_balance, requestable_heap_size,
        },
        instruction::{AccountMeta, InstructionError},
        keyed_account::{keyed_account_at_index, KeyedAccount},
        loader_instruction::LoaderInstruction,
        loader_upgradeable_instruction::UpgradeableLoaderInstruction,
        program_error::MAX_ACCOUNTS_DATA_SIZE_EXCEEDED,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        saturating_add_assign,
        system_instruction::{self, MAX_PERMITTED_DATA_LENGTH},
    },
    std::{cell::RefCell, fmt::Debug, pin::Pin, rc::Rc, sync::Arc},
    thiserror::Error,
};

solana_sdk::declare_builtin!(
    solana_sdk::bpf_loader::ID,
    solana_bpf_loader_program,
    solana_bpf_loader_program::process_instruction
);

/// Errors returned by functions the BPF Loader registers with the VM
#[derive(Debug, Error, PartialEq)]
pub enum BpfError {
    #[error("{0}")]
    VerifierError(#[from] VerifierError),
    #[error("{0}")]
    SyscallError(#[from] SyscallError),
}
impl UserDefinedError for BpfError {}

fn map_ebpf_error(invoke_context: &InvokeContext, e: EbpfError<BpfError>) -> InstructionError {
    ic_msg!(invoke_context, "{}", e);
    InstructionError::InvalidAccountData
}

mod executor_metrics {
    #[derive(Debug, Default)]
    pub struct CreateMetrics {
        pub program_id: String,
        pub load_elf_us: u64,
        pub verify_code_us: u64,
        pub jit_compile_us: u64,
    }

    impl CreateMetrics {
        pub fn submit_datapoint(&self) {
            datapoint_trace!(
                "create_executor_trace",
                ("program_id", self.program_id, String),
                ("load_elf_us", self.load_elf_us, i64),
                ("verify_code_us", self.verify_code_us, i64),
                ("jit_compile_us", self.jit_compile_us, i64),
            );
        }
    }
}

pub fn create_executor(
    programdata_account_index: usize,
    programdata_offset: usize,
    invoke_context: &mut InvokeContext,
    use_jit: bool,
    reject_deployment_of_broken_elfs: bool,
) -> Result<Arc<BpfExecutor>, InstructionError> {
    let mut register_syscalls_time = Measure::start("register_syscalls_time");
    let register_syscall_result = syscalls::register_syscalls(invoke_context);
    register_syscalls_time.stop();
    invoke_context.timings.create_executor_register_syscalls_us = invoke_context
        .timings
        .create_executor_register_syscalls_us
        .saturating_add(register_syscalls_time.as_us());
    let syscall_registry = register_syscall_result.map_err(|e| {
        ic_msg!(invoke_context, "Failed to register syscalls: {}", e);
        InstructionError::ProgramEnvironmentSetupFailure
    })?;
    let compute_budget = invoke_context.get_compute_budget();
    let config = Config {
        max_call_depth: compute_budget.max_call_depth,
        stack_frame_size: compute_budget.stack_frame_size,
        enable_instruction_tracing: log_enabled!(Trace),
        disable_deprecated_load_instructions: reject_deployment_of_broken_elfs
            && invoke_context
                .feature_set
                .is_active(&disable_bpf_deprecated_load_instructions::id()),
        disable_unresolved_symbols_at_runtime: invoke_context
            .feature_set
            .is_active(&disable_bpf_unresolved_symbols_at_runtime::id()),
        reject_broken_elfs: reject_deployment_of_broken_elfs,
        ..Config::default()
    };
    let mut create_executor_metrics = executor_metrics::CreateMetrics::default();
    let mut executable = {
        let keyed_accounts = invoke_context.get_keyed_accounts()?;
        let programdata = keyed_account_at_index(keyed_accounts, programdata_account_index)?;
        create_executor_metrics.program_id = programdata.unsigned_key().to_string();
        let mut load_elf_time = Measure::start("load_elf_time");
        let executable = Executable::<BpfError, ThisInstructionMeter>::from_elf(
            programdata
                .try_account_ref()?
                .data()
                .get(programdata_offset..)
                .ok_or(InstructionError::AccountDataTooSmall)?,
            None,
            config,
            syscall_registry,
        );
        load_elf_time.stop();
        create_executor_metrics.load_elf_us = load_elf_time.as_us();
        invoke_context.timings.create_executor_load_elf_us = invoke_context
            .timings
            .create_executor_load_elf_us
            .saturating_add(create_executor_metrics.load_elf_us);
        executable
    }
    .map_err(|e| map_ebpf_error(invoke_context, e))?;
    let text_bytes = executable.get_text_bytes().1;
    let mut verify_code_time = Measure::start("verify_code_time");
    verifier::check(text_bytes, &config)
        .map_err(|e| map_ebpf_error(invoke_context, EbpfError::UserError(e.into())))?;
    verify_code_time.stop();
    create_executor_metrics.verify_code_us = verify_code_time.as_us();
    invoke_context.timings.create_executor_verify_code_us = invoke_context
        .timings
        .create_executor_verify_code_us
        .saturating_add(create_executor_metrics.verify_code_us);
    if use_jit {
        let mut jit_compile_time = Measure::start("jit_compile_time");
        let jit_compile_result =
            Executable::<BpfError, ThisInstructionMeter>::jit_compile(&mut executable);
        jit_compile_time.stop();
        create_executor_metrics.jit_compile_us = jit_compile_time.as_us();
        invoke_context.timings.create_executor_jit_compile_us = invoke_context
            .timings
            .create_executor_jit_compile_us
            .saturating_add(create_executor_metrics.jit_compile_us);
        if let Err(err) = jit_compile_result {
            ic_msg!(invoke_context, "Failed to compile program {:?}", err);
            return Err(InstructionError::ProgramFailedToCompile);
        }
    }
    create_executor_metrics.submit_datapoint();
    Ok(Arc::new(BpfExecutor {
        executable,
        use_jit,
    }))
}

fn write_program_data(
    program_account_index: usize,
    program_data_offset: usize,
    bytes: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let keyed_accounts = invoke_context.get_keyed_accounts()?;
    let program = keyed_account_at_index(keyed_accounts, program_account_index)?;
    let mut account = program.try_account_ref_mut()?;
    let data = &mut account.data_as_mut_slice();
    let len = bytes.len();
    if data.len() < program_data_offset.saturating_add(len) {
        ic_msg!(
            invoke_context,
            "Write overflow: {} < {}",
            data.len(),
            program_data_offset.saturating_add(len),
        );
        return Err(InstructionError::AccountDataTooSmall);
    }
    data.get_mut(program_data_offset..program_data_offset.saturating_add(len))
        .ok_or(InstructionError::AccountDataTooSmall)?
        .copy_from_slice(bytes);
    Ok(())
}

fn check_loader_id(id: &Pubkey) -> bool {
    bpf_loader::check_id(id)
        || bpf_loader_deprecated::check_id(id)
        || bpf_loader_upgradeable::check_id(id)
}

/// Create the BPF virtual machine
pub fn create_vm<'a, 'b>(
    program: &'a Pin<Box<Executable<BpfError, ThisInstructionMeter>>>,
    parameter_bytes: &mut [u8],
    invoke_context: &'a mut InvokeContext<'b>,
    orig_data_lens: &'a [usize],
) -> Result<EbpfVm<'a, BpfError, ThisInstructionMeter>, EbpfError<BpfError>> {
    let compute_budget = invoke_context.get_compute_budget();
    let heap_size = compute_budget.heap_size.unwrap_or(HEAP_LENGTH);
    if invoke_context
        .feature_set
        .is_active(&requestable_heap_size::id())
    {
        let _ = invoke_context.get_compute_meter().borrow_mut().consume(
            ((heap_size as u64).saturating_div(32_u64.saturating_mul(1024)))
                .saturating_sub(1)
                .saturating_mul(compute_budget.heap_cost),
        );
    }
    let mut heap =
        AlignedMemory::new_with_size(compute_budget.heap_size.unwrap_or(HEAP_LENGTH), HOST_ALIGN);
    let mut vm = EbpfVm::new(program, heap.as_slice_mut(), parameter_bytes)?;
    syscalls::bind_syscall_context_objects(&mut vm, invoke_context, heap, orig_data_lens)?;
    Ok(vm)
}

pub fn process_instruction(
    first_instruction_account: usize,
    instruction_data: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    process_instruction_common(
        first_instruction_account,
        instruction_data,
        invoke_context,
        false,
    )
}

pub fn process_instruction_jit(
    first_instruction_account: usize,
    instruction_data: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    process_instruction_common(
        first_instruction_account,
        instruction_data,
        invoke_context,
        true,
    )
}

fn process_instruction_common(
    first_instruction_account: usize,
    instruction_data: &[u8],
    invoke_context: &mut InvokeContext,
    use_jit: bool,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let program_id = instruction_context.get_program_key(transaction_context)?;

    let keyed_accounts = invoke_context.get_keyed_accounts()?;
    let first_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
    let second_account =
        keyed_account_at_index(keyed_accounts, first_instruction_account.saturating_add(1));
    let (program, next_first_instruction_account) = if first_account.unsigned_key() == program_id {
        (first_account, first_instruction_account)
    } else if second_account
        .as_ref()
        .map(|keyed_account| keyed_account.unsigned_key() == program_id)
        .unwrap_or(false)
    {
        (second_account?, first_instruction_account.saturating_add(1))
    } else {
        if first_account.executable()? {
            ic_logger_msg!(log_collector, "BPF loader is executable");
            return Err(InstructionError::IncorrectProgramId);
        }
        (first_account, first_instruction_account)
    };

    if program.executable()? {
        // First instruction account can only be zero if called from CPI, which
        // means stack height better be greater than one
        debug_assert_eq!(
            first_instruction_account == 0,
            invoke_context.get_stack_height() > 1
        );

        if !check_loader_id(&program.owner()?) {
            ic_logger_msg!(
                log_collector,
                "Executable account not owned by the BPF loader"
            );
            return Err(InstructionError::IncorrectProgramId);
        }

        let program_data_offset = if bpf_loader_upgradeable::check_id(&program.owner()?) {
            if let UpgradeableLoaderState::Program {
                programdata_address,
            } = program.state()?
            {
                if programdata_address != *first_account.unsigned_key() {
                    ic_logger_msg!(
                        log_collector,
                        "Wrong ProgramData account for this Program account"
                    );
                    return Err(InstructionError::InvalidArgument);
                }
                if !matches!(
                    first_account.state()?,
                    UpgradeableLoaderState::ProgramData {
                        slot: _,
                        upgrade_authority_address: _,
                    }
                ) {
                    ic_logger_msg!(log_collector, "Program has been closed");
                    return Err(InstructionError::InvalidAccountData);
                }
                UpgradeableLoaderState::programdata_data_offset()?
            } else {
                ic_logger_msg!(log_collector, "Invalid Program account");
                return Err(InstructionError::InvalidAccountData);
            }
        } else {
            0
        };

        let mut get_or_create_executor_time = Measure::start("get_or_create_executor_time");
        let executor = match invoke_context.get_executor(program_id) {
            Some(executor) => executor,
            None => {
                let executor = create_executor(
                    first_instruction_account,
                    program_data_offset,
                    invoke_context,
                    use_jit,
                    false,
                )?;
                let transaction_context = &invoke_context.transaction_context;
                let instruction_context = transaction_context.get_current_instruction_context()?;
                let program_id = instruction_context.get_program_key(transaction_context)?;
                invoke_context.add_executor(program_id, executor.clone());
                executor
            }
        };
        get_or_create_executor_time.stop();
        saturating_add_assign!(
            invoke_context.timings.get_or_create_executor_us,
            get_or_create_executor_time.as_us()
        );

        executor.execute(
            next_first_instruction_account,
            instruction_data,
            invoke_context,
        )
    } else {
        debug_assert_eq!(first_instruction_account, 1);

        let disable_deprecated_loader = invoke_context
            .feature_set
            .is_active(&disable_deprecated_loader::id());
        if bpf_loader_upgradeable::check_id(program_id) {
            process_loader_upgradeable_instruction(
                first_instruction_account,
                instruction_data,
                invoke_context,
                use_jit,
            )
        } else if bpf_loader::check_id(program_id)
            || (!disable_deprecated_loader && bpf_loader_deprecated::check_id(program_id))
        {
            process_loader_instruction(
                first_instruction_account,
                instruction_data,
                invoke_context,
                use_jit,
            )
        } else if disable_deprecated_loader && bpf_loader_deprecated::check_id(program_id) {
            ic_logger_msg!(log_collector, "Deprecated loader is no longer supported");
            Err(InstructionError::UnsupportedProgramId)
        } else {
            ic_logger_msg!(log_collector, "Invalid BPF loader id");
            Err(InstructionError::IncorrectProgramId)
        }
    }
}

fn process_loader_upgradeable_instruction(
    first_instruction_account: usize,
    instruction_data: &[u8],
    invoke_context: &mut InvokeContext,
    use_jit: bool,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let program_id = instruction_context.get_program_key(transaction_context)?;
    let keyed_accounts = invoke_context.get_keyed_accounts()?;

    match limited_deserialize(instruction_data)? {
        UpgradeableLoaderInstruction::InitializeBuffer => {
            let buffer = keyed_account_at_index(keyed_accounts, first_instruction_account)?;

            if UpgradeableLoaderState::Uninitialized != buffer.state()? {
                ic_logger_msg!(log_collector, "Buffer account already initialized");
                return Err(InstructionError::AccountAlreadyInitialized);
            }

            let authority = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(1),
            )?;

            buffer.set_state(&UpgradeableLoaderState::Buffer {
                authority_address: Some(*authority.unsigned_key()),
            })?;
        }
        UpgradeableLoaderInstruction::Write { offset, bytes } => {
            let buffer = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let authority = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(1),
            )?;

            if let UpgradeableLoaderState::Buffer { authority_address } = buffer.state()? {
                if authority_address.is_none() {
                    ic_logger_msg!(log_collector, "Buffer is immutable");
                    return Err(InstructionError::Immutable); // TODO better error code
                }
                if authority_address != Some(*authority.unsigned_key()) {
                    ic_logger_msg!(log_collector, "Incorrect buffer authority provided");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if authority.signer_key().is_none() {
                    ic_logger_msg!(log_collector, "Buffer authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid Buffer account");
                return Err(InstructionError::InvalidAccountData);
            }
            write_program_data(
                first_instruction_account,
                UpgradeableLoaderState::buffer_data_offset()?.saturating_add(offset as usize),
                &bytes,
                invoke_context,
            )?;
        }
        UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len } => {
            let payer = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let programdata = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(1),
            )?;
            let program = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(2),
            )?;
            let buffer = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(3),
            )?;
            let rent = get_sysvar_with_account_check::rent(
                keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account.saturating_add(4),
                )?,
                invoke_context,
            )?;
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account.saturating_add(5),
                )?,
                invoke_context,
            )?;
            let authority = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(7),
            )?;
            let upgrade_authority_address = Some(*authority.unsigned_key());
            let upgrade_authority_signer = authority.signer_key().is_none();

            // Verify Program account

            if UpgradeableLoaderState::Uninitialized != program.state()? {
                ic_logger_msg!(log_collector, "Program account already initialized");
                return Err(InstructionError::AccountAlreadyInitialized);
            }
            if program.data_len()? < UpgradeableLoaderState::program_len()? {
                ic_logger_msg!(log_collector, "Program account too small");
                return Err(InstructionError::AccountDataTooSmall);
            }
            if program.lamports()? < rent.minimum_balance(program.data_len()?) {
                ic_logger_msg!(log_collector, "Program account not rent-exempt");
                return Err(InstructionError::ExecutableAccountNotRentExempt);
            }

            let new_program_id = *program.unsigned_key();

            // Verify Buffer account

            if let UpgradeableLoaderState::Buffer { authority_address } = buffer.state()? {
                if authority_address != upgrade_authority_address {
                    ic_logger_msg!(log_collector, "Buffer and upgrade authority don't match");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if upgrade_authority_signer {
                    ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid Buffer account");
                return Err(InstructionError::InvalidArgument);
            }

            let buffer_data_offset = UpgradeableLoaderState::buffer_data_offset()?;
            let buffer_data_len = buffer.data_len()?.saturating_sub(buffer_data_offset);
            let programdata_data_offset = UpgradeableLoaderState::programdata_data_offset()?;
            let programdata_len = UpgradeableLoaderState::programdata_len(max_data_len)?;

            if buffer.data_len()? < UpgradeableLoaderState::buffer_data_offset()?
                || buffer_data_len == 0
            {
                ic_logger_msg!(log_collector, "Buffer account too small");
                return Err(InstructionError::InvalidAccountData);
            }
            if max_data_len < buffer_data_len {
                ic_logger_msg!(
                    log_collector,
                    "Max data length is too small to hold Buffer data"
                );
                return Err(InstructionError::AccountDataTooSmall);
            }
            if programdata_len > MAX_PERMITTED_DATA_LENGTH as usize {
                ic_logger_msg!(log_collector, "Max data length is too large");
                return Err(InstructionError::InvalidArgument);
            }

            // Create ProgramData account

            let (derived_address, bump_seed) =
                Pubkey::find_program_address(&[new_program_id.as_ref()], program_id);
            if derived_address != *programdata.unsigned_key() {
                ic_logger_msg!(log_collector, "ProgramData address is not derived");
                return Err(InstructionError::InvalidArgument);
            }

            let predrain_buffer = invoke_context
                .feature_set
                .is_active(&reduce_required_deploy_balance::id());
            if predrain_buffer {
                // Drain the Buffer account to payer before paying for programdata account
                payer
                    .try_account_ref_mut()?
                    .checked_add_lamports(buffer.lamports()?)?;
                buffer.try_account_ref_mut()?.set_lamports(0);
            }

            let mut instruction = system_instruction::create_account(
                payer.unsigned_key(),
                programdata.unsigned_key(),
                1.max(rent.minimum_balance(programdata_len)),
                programdata_len as u64,
                program_id,
            );

            // pass an extra account to avoid the overly strict UnbalancedInstruction error
            instruction
                .accounts
                .push(AccountMeta::new(*buffer.unsigned_key(), false));

            let transaction_context = &invoke_context.transaction_context;
            let instruction_context = transaction_context.get_current_instruction_context()?;
            let caller_program_id = instruction_context.get_program_key(transaction_context)?;
            let signers = [&[new_program_id.as_ref(), &[bump_seed]]]
                .iter()
                .map(|seeds| Pubkey::create_program_address(*seeds, caller_program_id))
                .collect::<Result<Vec<Pubkey>, solana_sdk::pubkey::PubkeyError>>()?;
            invoke_context.native_invoke(instruction, signers.as_slice())?;

            // Load and verify the program bits
            let executor = create_executor(
                first_instruction_account.saturating_add(3),
                buffer_data_offset,
                invoke_context,
                use_jit,
                true,
            )?;
            invoke_context.update_executor(&new_program_id, executor);

            let keyed_accounts = invoke_context.get_keyed_accounts()?;
            let payer = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let programdata = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(1),
            )?;
            let program = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(2),
            )?;
            let buffer = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(3),
            )?;

            // Update the ProgramData account and record the program bits
            programdata.set_state(&UpgradeableLoaderState::ProgramData {
                slot: clock.slot,
                upgrade_authority_address,
            })?;
            programdata
                .try_account_ref_mut()?
                .data_as_mut_slice()
                .get_mut(
                    programdata_data_offset
                        ..programdata_data_offset.saturating_add(buffer_data_len),
                )
                .ok_or(InstructionError::AccountDataTooSmall)?
                .copy_from_slice(
                    buffer
                        .try_account_ref()?
                        .data()
                        .get(buffer_data_offset..)
                        .ok_or(InstructionError::AccountDataTooSmall)?,
                );

            // Update the Program account
            program.set_state(&UpgradeableLoaderState::Program {
                programdata_address: *programdata.unsigned_key(),
            })?;
            program.try_account_ref_mut()?.set_executable(true);

            if !predrain_buffer {
                // Drain the Buffer account back to the payer
                payer
                    .try_account_ref_mut()?
                    .checked_add_lamports(buffer.lamports()?)?;
                buffer.try_account_ref_mut()?.set_lamports(0);
            }

            ic_logger_msg!(log_collector, "Deployed program {:?}", new_program_id);
        }
        UpgradeableLoaderInstruction::Upgrade => {
            let programdata = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let program = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(1),
            )?;
            let buffer = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(2),
            )?;
            let rent = get_sysvar_with_account_check::rent(
                keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account.saturating_add(4),
                )?,
                invoke_context,
            )?;
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account.saturating_add(5),
                )?,
                invoke_context,
            )?;
            let authority = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(6),
            )?;

            // Verify Program account

            if !program.executable()? {
                ic_logger_msg!(log_collector, "Program account not executable");
                return Err(InstructionError::AccountNotExecutable);
            }
            if !program.is_writable() {
                ic_logger_msg!(log_collector, "Program account not writeable");
                return Err(InstructionError::InvalidArgument);
            }
            if &program.owner()? != program_id {
                ic_logger_msg!(log_collector, "Program account not owned by loader");
                return Err(InstructionError::IncorrectProgramId);
            }
            if let UpgradeableLoaderState::Program {
                programdata_address,
            } = program.state()?
            {
                if programdata_address != *programdata.unsigned_key() {
                    ic_logger_msg!(log_collector, "Program and ProgramData account mismatch");
                    return Err(InstructionError::InvalidArgument);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid Program account");
                return Err(InstructionError::InvalidAccountData);
            }

            let new_program_id = *program.unsigned_key();

            // Verify Buffer account

            if let UpgradeableLoaderState::Buffer { authority_address } = buffer.state()? {
                if authority_address != Some(*authority.unsigned_key()) {
                    ic_logger_msg!(log_collector, "Buffer and upgrade authority don't match");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if authority.signer_key().is_none() {
                    ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid Buffer account");
                return Err(InstructionError::InvalidArgument);
            }

            let buffer_data_offset = UpgradeableLoaderState::buffer_data_offset()?;
            let buffer_data_len = buffer.data_len()?.saturating_sub(buffer_data_offset);
            let programdata_data_offset = UpgradeableLoaderState::programdata_data_offset()?;
            let programdata_balance_required = 1.max(rent.minimum_balance(programdata.data_len()?));

            if buffer.data_len()? < UpgradeableLoaderState::buffer_data_offset()?
                || buffer_data_len == 0
            {
                ic_logger_msg!(log_collector, "Buffer account too small");
                return Err(InstructionError::InvalidAccountData);
            }

            // Verify ProgramData account

            if programdata.data_len()? < UpgradeableLoaderState::programdata_len(buffer_data_len)? {
                ic_logger_msg!(log_collector, "ProgramData account not large enough");
                return Err(InstructionError::AccountDataTooSmall);
            }
            if programdata.lamports()?.saturating_add(buffer.lamports()?)
                < programdata_balance_required
            {
                ic_logger_msg!(
                    log_collector,
                    "Buffer account balance too low to fund upgrade"
                );
                return Err(InstructionError::InsufficientFunds);
            }
            if let UpgradeableLoaderState::ProgramData {
                slot: _,
                upgrade_authority_address,
            } = programdata.state()?
            {
                if upgrade_authority_address.is_none() {
                    ic_logger_msg!(log_collector, "Program not upgradeable");
                    return Err(InstructionError::Immutable);
                }
                if upgrade_authority_address != Some(*authority.unsigned_key()) {
                    ic_logger_msg!(log_collector, "Incorrect upgrade authority provided");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if authority.signer_key().is_none() {
                    ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid ProgramData account");
                return Err(InstructionError::InvalidAccountData);
            }

            // Load and verify the program bits
            let executor = create_executor(
                first_instruction_account.saturating_add(2),
                buffer_data_offset,
                invoke_context,
                use_jit,
                true,
            )?;
            invoke_context.update_executor(&new_program_id, executor);

            let keyed_accounts = invoke_context.get_keyed_accounts()?;
            let programdata = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let buffer = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(2),
            )?;
            let spill = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(3),
            )?;
            let authority = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(6),
            )?;

            // Update the ProgramData account, record the upgraded data, and zero
            // the rest
            programdata.set_state(&UpgradeableLoaderState::ProgramData {
                slot: clock.slot,
                upgrade_authority_address: Some(*authority.unsigned_key()),
            })?;
            programdata
                .try_account_ref_mut()?
                .data_as_mut_slice()
                .get_mut(
                    programdata_data_offset
                        ..programdata_data_offset.saturating_add(buffer_data_len),
                )
                .ok_or(InstructionError::AccountDataTooSmall)?
                .copy_from_slice(
                    buffer
                        .try_account_ref()?
                        .data()
                        .get(buffer_data_offset..)
                        .ok_or(InstructionError::AccountDataTooSmall)?,
                );
            programdata
                .try_account_ref_mut()?
                .data_as_mut_slice()
                .get_mut(programdata_data_offset.saturating_add(buffer_data_len)..)
                .ok_or(InstructionError::AccountDataTooSmall)?
                .fill(0);

            // Fund ProgramData to rent-exemption, spill the rest

            spill.try_account_ref_mut()?.checked_add_lamports(
                programdata
                    .lamports()?
                    .saturating_add(buffer.lamports()?)
                    .saturating_sub(programdata_balance_required),
            )?;
            buffer.try_account_ref_mut()?.set_lamports(0);
            programdata
                .try_account_ref_mut()?
                .set_lamports(programdata_balance_required);

            ic_logger_msg!(log_collector, "Upgraded program {:?}", new_program_id);
        }
        UpgradeableLoaderInstruction::SetAuthority => {
            let account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let present_authority = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(1),
            )?;
            let new_authority =
                keyed_account_at_index(keyed_accounts, first_instruction_account.saturating_add(2))
                    .ok()
                    .map(|account| account.unsigned_key());

            match account.state()? {
                UpgradeableLoaderState::Buffer { authority_address } => {
                    if new_authority.is_none() {
                        ic_logger_msg!(log_collector, "Buffer authority is not optional");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if authority_address.is_none() {
                        ic_logger_msg!(log_collector, "Buffer is immutable");
                        return Err(InstructionError::Immutable);
                    }
                    if authority_address != Some(*present_authority.unsigned_key()) {
                        ic_logger_msg!(log_collector, "Incorrect buffer authority provided");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if present_authority.signer_key().is_none() {
                        ic_logger_msg!(log_collector, "Buffer authority did not sign");
                        return Err(InstructionError::MissingRequiredSignature);
                    }
                    account.set_state(&UpgradeableLoaderState::Buffer {
                        authority_address: new_authority.cloned(),
                    })?;
                }
                UpgradeableLoaderState::ProgramData {
                    slot,
                    upgrade_authority_address,
                } => {
                    if upgrade_authority_address.is_none() {
                        ic_logger_msg!(log_collector, "Program not upgradeable");
                        return Err(InstructionError::Immutable);
                    }
                    if upgrade_authority_address != Some(*present_authority.unsigned_key()) {
                        ic_logger_msg!(log_collector, "Incorrect upgrade authority provided");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if present_authority.signer_key().is_none() {
                        ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                        return Err(InstructionError::MissingRequiredSignature);
                    }
                    account.set_state(&UpgradeableLoaderState::ProgramData {
                        slot,
                        upgrade_authority_address: new_authority.cloned(),
                    })?;
                }
                _ => {
                    ic_logger_msg!(log_collector, "Account does not support authorities");
                    return Err(InstructionError::InvalidArgument);
                }
            }

            ic_logger_msg!(log_collector, "New authority {:?}", new_authority);
        }
        UpgradeableLoaderInstruction::Close => {
            let close_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let recipient_account = keyed_account_at_index(
                keyed_accounts,
                first_instruction_account.saturating_add(1),
            )?;
            if close_account.unsigned_key() == recipient_account.unsigned_key() {
                ic_logger_msg!(
                    log_collector,
                    "Recipient is the same as the account being closed"
                );
                return Err(InstructionError::InvalidArgument);
            }

            match close_account.state()? {
                UpgradeableLoaderState::Uninitialized => {
                    recipient_account
                        .try_account_ref_mut()?
                        .checked_add_lamports(close_account.lamports()?)?;
                    close_account.try_account_ref_mut()?.set_lamports(0);

                    ic_logger_msg!(
                        log_collector,
                        "Closed Uninitialized {}",
                        close_account.unsigned_key()
                    );
                }
                UpgradeableLoaderState::Buffer { authority_address } => {
                    let authority = keyed_account_at_index(
                        keyed_accounts,
                        first_instruction_account.saturating_add(2),
                    )?;

                    common_close_account(
                        &authority_address,
                        authority,
                        close_account,
                        recipient_account,
                        &log_collector,
                    )?;

                    ic_logger_msg!(
                        log_collector,
                        "Closed Buffer {}",
                        close_account.unsigned_key()
                    );
                }
                UpgradeableLoaderState::ProgramData {
                    slot: _,
                    upgrade_authority_address: authority_address,
                } => {
                    let program_account = keyed_account_at_index(
                        keyed_accounts,
                        first_instruction_account.saturating_add(3),
                    )?;

                    if !program_account.is_writable() {
                        ic_logger_msg!(log_collector, "Program account is not writable");
                        return Err(InstructionError::InvalidArgument);
                    }
                    if &program_account.owner()? != program_id {
                        ic_logger_msg!(log_collector, "Program account not owned by loader");
                        return Err(InstructionError::IncorrectProgramId);
                    }

                    match program_account.state()? {
                        UpgradeableLoaderState::Program {
                            programdata_address,
                        } => {
                            if programdata_address != *close_account.unsigned_key() {
                                ic_logger_msg!(
                                    log_collector,
                                    "ProgramData account does not match ProgramData account"
                                );
                                return Err(InstructionError::InvalidArgument);
                            }

                            let authority = keyed_account_at_index(
                                keyed_accounts,
                                first_instruction_account.saturating_add(2),
                            )?;
                            common_close_account(
                                &authority_address,
                                authority,
                                close_account,
                                recipient_account,
                                &log_collector,
                            )?;
                        }
                        _ => {
                            ic_logger_msg!(log_collector, "Invalid Program account");
                            return Err(InstructionError::InvalidArgument);
                        }
                    }

                    ic_logger_msg!(
                        log_collector,
                        "Closed Program {}",
                        program_account.unsigned_key()
                    );
                }
                _ => {
                    ic_logger_msg!(log_collector, "Account does not support closing");
                    return Err(InstructionError::InvalidArgument);
                }
            }
        }
    }

    Ok(())
}

fn common_close_account(
    authority_address: &Option<Pubkey>,
    authority_account: &KeyedAccount,
    close_account: &KeyedAccount,
    recipient_account: &KeyedAccount,
    log_collector: &Option<Rc<RefCell<LogCollector>>>,
) -> Result<(), InstructionError> {
    if authority_address.is_none() {
        ic_logger_msg!(log_collector, "Account is immutable");
        return Err(InstructionError::Immutable);
    }
    if *authority_address != Some(*authority_account.unsigned_key()) {
        ic_logger_msg!(log_collector, "Incorrect authority provided");
        return Err(InstructionError::IncorrectAuthority);
    }
    if authority_account.signer_key().is_none() {
        ic_logger_msg!(log_collector, "Authority did not sign");
        return Err(InstructionError::MissingRequiredSignature);
    }

    recipient_account
        .try_account_ref_mut()?
        .checked_add_lamports(close_account.lamports()?)?;
    close_account.try_account_ref_mut()?.set_lamports(0);
    close_account.set_state(&UpgradeableLoaderState::Uninitialized)?;
    Ok(())
}

fn process_loader_instruction(
    first_instruction_account: usize,
    instruction_data: &[u8],
    invoke_context: &mut InvokeContext,
    use_jit: bool,
) -> Result<(), InstructionError> {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let program_id = instruction_context.get_program_key(transaction_context)?;
    let keyed_accounts = invoke_context.get_keyed_accounts()?;
    let program = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
    if program.owner()? != *program_id {
        ic_msg!(
            invoke_context,
            "Executable account not owned by the BPF loader"
        );
        return Err(InstructionError::IncorrectProgramId);
    }
    match limited_deserialize(instruction_data)? {
        LoaderInstruction::Write { offset, bytes } => {
            if program.signer_key().is_none() {
                ic_msg!(invoke_context, "Program account did not sign");
                return Err(InstructionError::MissingRequiredSignature);
            }
            write_program_data(
                first_instruction_account,
                offset as usize,
                &bytes,
                invoke_context,
            )?;
        }
        LoaderInstruction::Finalize => {
            if program.signer_key().is_none() {
                ic_msg!(invoke_context, "key[0] did not sign the transaction");
                return Err(InstructionError::MissingRequiredSignature);
            }

            let executor =
                create_executor(first_instruction_account, 0, invoke_context, use_jit, true)?;
            let keyed_accounts = invoke_context.get_keyed_accounts()?;
            let program = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            invoke_context.update_executor(program.unsigned_key(), executor);
            program.try_account_ref_mut()?.set_executable(true);
            ic_msg!(
                invoke_context,
                "Finalized account {:?}",
                program.unsigned_key()
            );
        }
    }

    Ok(())
}

/// Passed to the VM to enforce the compute budget
pub struct ThisInstructionMeter {
    pub compute_meter: Rc<RefCell<ComputeMeter>>,
}
impl ThisInstructionMeter {
    fn new(compute_meter: Rc<RefCell<ComputeMeter>>) -> Self {
        Self { compute_meter }
    }
}
impl InstructionMeter for ThisInstructionMeter {
    fn consume(&mut self, amount: u64) {
        // 1 to 1 instruction to compute unit mapping
        // ignore error, Ebpf will bail if exceeded
        let _ = self.compute_meter.borrow_mut().consume(amount);
    }
    fn get_remaining(&self) -> u64 {
        self.compute_meter.borrow().get_remaining()
    }
}

/// BPF Loader's Executor implementation
pub struct BpfExecutor {
    executable: Pin<Box<Executable<BpfError, ThisInstructionMeter>>>,
    use_jit: bool,
}

// Well, implement Debug for solana_rbpf::vm::Executable in solana-rbpf...
impl Debug for BpfExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BpfExecutor({:p})", self)
    }
}

impl Executor for BpfExecutor {
    fn execute<'a, 'b>(
        &self,
        _first_instruction_account: usize,
        _instruction_data: &[u8],
        invoke_context: &'a mut InvokeContext<'b>,
    ) -> Result<(), InstructionError> {
        let log_collector = invoke_context.get_log_collector();
        let compute_meter = invoke_context.get_compute_meter();
        let stack_height = invoke_context.get_stack_height();
        let transaction_context = &invoke_context.transaction_context;
        let instruction_context = transaction_context.get_current_instruction_context()?;
        let program_id = *instruction_context.get_program_key(transaction_context)?;

        let mut serialize_time = Measure::start("serialize");
        let (mut parameter_bytes, account_lengths) =
            serialize_parameters(invoke_context.transaction_context, instruction_context)?;
        serialize_time.stop();
        let mut create_vm_time = Measure::start("create_vm");
        let mut execute_time;
        let execution_result = {
            let mut vm = match create_vm(
                &self.executable,
                parameter_bytes.as_slice_mut(),
                invoke_context,
                &account_lengths,
            ) {
                Ok(info) => info,
                Err(e) => {
                    ic_logger_msg!(log_collector, "Failed to create BPF VM: {}", e);
                    return Err(InstructionError::ProgramEnvironmentSetupFailure);
                }
            };
            create_vm_time.stop();

            execute_time = Measure::start("execute");
            stable_log::program_invoke(&log_collector, &program_id, stack_height);
            let mut instruction_meter = ThisInstructionMeter::new(compute_meter.clone());
            let before = compute_meter.borrow().get_remaining();
            let result = if self.use_jit {
                vm.execute_program_jit(&mut instruction_meter)
            } else {
                vm.execute_program_interpreted(&mut instruction_meter)
            };
            let after = compute_meter.borrow().get_remaining();
            ic_logger_msg!(
                log_collector,
                "Program {} consumed {} of {} compute units",
                &program_id,
                before.saturating_sub(after),
                before
            );
            if log_enabled!(Trace) {
                let mut trace_buffer = Vec::<u8>::new();
                let analysis = Analysis::from_executable(&self.executable);
                vm.get_tracer().write(&mut trace_buffer, &analysis).unwrap();
                let trace_string = String::from_utf8(trace_buffer).unwrap();
                trace!("BPF Program Instruction Trace:\n{}", trace_string);
            }
            drop(vm);
            let (_returned_from_program_id, return_data) =
                invoke_context.transaction_context.get_return_data();
            if !return_data.is_empty() {
                stable_log::program_return(&log_collector, &program_id, return_data);
            }
            match result {
                Ok(status) if status != SUCCESS => {
                    let error: InstructionError = if status == MAX_ACCOUNTS_DATA_SIZE_EXCEEDED
                        && !invoke_context
                            .feature_set
                            .is_active(&cap_accounts_data_len::id())
                    {
                        // Until the cap_accounts_data_len feature is enabled, map the
                        // MAX_ACCOUNTS_DATA_SIZE_EXCEEDED error to InvalidError
                        InstructionError::InvalidError
                    } else {
                        status.into()
                    };
                    stable_log::program_failure(&log_collector, &program_id, &error);
                    Err(error)
                }
                Err(error) => {
                    let error = match error {
                        EbpfError::UserError(BpfError::SyscallError(
                            SyscallError::InstructionError(error),
                        )) => error,
                        err => {
                            ic_logger_msg!(log_collector, "Program failed to complete: {}", err);
                            InstructionError::ProgramFailedToComplete
                        }
                    };
                    stable_log::program_failure(&log_collector, &program_id, &error);
                    Err(error)
                }
                _ => Ok(()),
            }
        };
        execute_time.stop();

        let mut deserialize_time = Measure::start("deserialize");
        let execute_or_deserialize_result = execution_result.and_then(|_| {
            deserialize_parameters(
                invoke_context.transaction_context,
                invoke_context
                    .transaction_context
                    .get_current_instruction_context()?,
                parameter_bytes.as_slice(),
                &account_lengths,
                invoke_context
                    .feature_set
                    .is_active(&do_support_realloc::id()),
            )
        });
        deserialize_time.stop();

        // Update the timings
        let timings = &mut invoke_context.timings;
        timings.serialize_us = timings.serialize_us.saturating_add(serialize_time.as_us());
        timings.create_vm_us = timings.create_vm_us.saturating_add(create_vm_time.as_us());
        timings.execute_us = timings.execute_us.saturating_add(execute_time.as_us());
        timings.deserialize_us = timings
            .deserialize_us
            .saturating_add(deserialize_time.as_us());

        if execute_or_deserialize_result.is_ok() {
            stable_log::program_success(&log_collector, &program_id);
        }
        execute_or_deserialize_result
    }
}

