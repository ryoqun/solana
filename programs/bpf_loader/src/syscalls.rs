use {
    crate::{alloc, BpfError},
    alloc::Alloc,
    solana_program_runtime::{
        ic_logger_msg, ic_msg,
        invoke_context::{ComputeMeter, InvokeContext},
        stable_log,
        timings::ExecuteTimings,
    },
    solana_rbpf::{
        aligned_memory::AlignedMemory,
        ebpf,
        error::EbpfError,
        memory_region::{AccessType, MemoryMapping},
        question_mark,
        vm::{EbpfVm, SyscallObject, SyscallRegistry},
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        account_info::AccountInfo,
        blake3, bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable,
        entrypoint::{BPF_ALIGN_OF_U128, MAX_PERMITTED_DATA_INCREASE, SUCCESS},
        feature_set::{
            add_get_processed_sibling_instruction_syscall, blake3_syscall_enabled,
            disable_fees_sysvar, do_support_realloc, fixed_memcpy_nonoverlapping_check,
            libsecp256k1_0_5_upgrade_enabled, prevent_calling_precompiles_as_programs,
            return_data_syscall_enabled, secp256k1_recover_syscall_enabled,
            sol_log_data_syscall_enabled, update_syscall_base_costs,
        },
        hash::{Hasher, HASH_BYTES},
        instruction::{
            AccountMeta, Instruction, InstructionError, ProcessedSiblingInstruction,
            TRANSACTION_LEVEL_STACK_HEIGHT,
        },
        keccak,
        message::{Message, SanitizedMessage},
        native_loader,
        precompiles::is_precompile,
        program::MAX_RETURN_DATA,
        program_stubs::is_nonoverlapping,
        pubkey::{Pubkey, PubkeyError, MAX_SEEDS, MAX_SEED_LEN},
        secp256k1_recover::{
            Secp256k1RecoverError, SECP256K1_PUBLIC_KEY_LENGTH, SECP256K1_SIGNATURE_LENGTH,
        },
        sysvar::{Sysvar, SysvarId},
    },
    std::{
        alloc::Layout,
        cell::{Ref, RefCell, RefMut},
        mem::{align_of, size_of},
        rc::Rc,
        slice::from_raw_parts_mut,
        str::{from_utf8, Utf8Error},
        sync::Arc,
    },
    thiserror::Error as ThisError,
};

/// Maximum signers
pub const MAX_SIGNERS: usize = 16;

/// Error definitions
#[derive(Debug, ThisError, PartialEq)]
pub enum SyscallError {
    #[error("{0}: {1:?}")]
    InvalidString(Utf8Error, Vec<u8>),
    #[error("BPF program panicked")]
    Abort,
    #[error("BPF program Panicked in {0} at {1}:{2}")]
    Panic(String, u64, u64),
    #[error("Cannot borrow invoke context")]
    InvokeContextBorrowFailed,
    #[error("Malformed signer seed: {0}: {1:?}")]
    MalformedSignerSeed(Utf8Error, Vec<u8>),
    #[error("Could not create program address with signer seeds: {0}")]
    BadSeeds(PubkeyError),
    #[error("Program {0} not supported by inner instructions")]
    ProgramNotSupported(Pubkey),
    #[error("{0}")]
    InstructionError(InstructionError),
    #[error("Unaligned pointer")]
    UnalignedPointer,
    #[error("Too many signers")]
    TooManySigners,
    #[error("Instruction passed to inner instruction is too large ({0} > {1})")]
    InstructionTooLarge(usize, usize),
    #[error("Too many accounts passed to inner instruction")]
    TooManyAccounts,
    #[error("Overlapping copy")]
    CopyOverlapping,
    #[error("Return data too large ({0} > {1})")]
    ReturnDataTooLarge(u64, u64),
    #[error("Hashing too many sequences")]
    TooManySlices,
}
impl From<SyscallError> for EbpfError<BpfError> {
    fn from(error: SyscallError) -> Self {
        EbpfError::UserError(error.into())
    }
}

trait SyscallConsume {
    fn consume(&mut self, amount: u64) -> Result<(), EbpfError<BpfError>>;
}
impl SyscallConsume for Rc<RefCell<ComputeMeter>> {
    fn consume(&mut self, amount: u64) -> Result<(), EbpfError<BpfError>> {
        self.try_borrow_mut()
            .map_err(|_| SyscallError::InvokeContextBorrowFailed)?
            .consume(amount)
            .map_err(SyscallError::InstructionError)?;
        Ok(())
    }
}

/// Program heap allocators are intended to allocate/free from a given
/// chunk of memory.  The specific allocator implementation is
/// selectable at build-time.
/// Only one allocator is currently supported

/// Simple bump allocator, never frees
use crate::allocator_bump::BpfAllocator;

pub fn register_syscalls(
    invoke_context: &mut InvokeContext,
) -> Result<SyscallRegistry, EbpfError<BpfError>> {
    let mut syscall_registry = SyscallRegistry::default();

    syscall_registry.register_syscall_by_name(b"abort", SyscallAbort::call)?;
    syscall_registry.register_syscall_by_name(b"sol_panic_", SyscallPanic::call)?;
    syscall_registry.register_syscall_by_name(b"sol_log_", SyscallLog::call)?;
    syscall_registry.register_syscall_by_name(b"sol_log_64_", SyscallLogU64::call)?;

    syscall_registry
        .register_syscall_by_name(b"sol_log_compute_units_", SyscallLogBpfComputeUnits::call)?;

    syscall_registry.register_syscall_by_name(b"sol_log_pubkey", SyscallLogPubkey::call)?;

    syscall_registry.register_syscall_by_name(
        b"sol_create_program_address",
        SyscallCreateProgramAddress::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_try_find_program_address",
        SyscallTryFindProgramAddress::call,
    )?;

    syscall_registry.register_syscall_by_name(b"sol_sha256", SyscallSha256::call)?;
    syscall_registry.register_syscall_by_name(b"sol_keccak256", SyscallKeccak256::call)?;

    if invoke_context
        .feature_set
        .is_active(&secp256k1_recover_syscall_enabled::id())
    {
        syscall_registry
            .register_syscall_by_name(b"sol_secp256k1_recover", SyscallSecp256k1Recover::call)?;
    }

    if invoke_context
        .feature_set
        .is_active(&blake3_syscall_enabled::id())
    {
        syscall_registry.register_syscall_by_name(b"sol_blake3", SyscallBlake3::call)?;
    }

    syscall_registry
        .register_syscall_by_name(b"sol_get_clock_sysvar", SyscallGetClockSysvar::call)?;
    syscall_registry.register_syscall_by_name(
        b"sol_get_epoch_schedule_sysvar",
        SyscallGetEpochScheduleSysvar::call,
    )?;
    if !invoke_context
        .feature_set
        .is_active(&disable_fees_sysvar::id())
    {
        syscall_registry
            .register_syscall_by_name(b"sol_get_fees_sysvar", SyscallGetFeesSysvar::call)?;
    }
    syscall_registry
        .register_syscall_by_name(b"sol_get_rent_sysvar", SyscallGetRentSysvar::call)?;

    syscall_registry.register_syscall_by_name(b"sol_memcpy_", SyscallMemcpy::call)?;
    syscall_registry.register_syscall_by_name(b"sol_memmove_", SyscallMemmove::call)?;
    syscall_registry.register_syscall_by_name(b"sol_memcmp_", SyscallMemcmp::call)?;
    syscall_registry.register_syscall_by_name(b"sol_memset_", SyscallMemset::call)?;

    // Cross-program invocation syscalls
    syscall_registry
        .register_syscall_by_name(b"sol_invoke_signed_c", SyscallInvokeSignedC::call)?;
    syscall_registry
        .register_syscall_by_name(b"sol_invoke_signed_rust", SyscallInvokeSignedRust::call)?;

    // Memory allocator
    syscall_registry.register_syscall_by_name(b"sol_alloc_free_", SyscallAllocFree::call)?;

    // Return data
    if invoke_context
        .feature_set
        .is_active(&return_data_syscall_enabled::id())
    {
        syscall_registry
            .register_syscall_by_name(b"sol_set_return_data", SyscallSetReturnData::call)?;
        syscall_registry
            .register_syscall_by_name(b"sol_get_return_data", SyscallGetReturnData::call)?;
    }

    // Log data
    if invoke_context
        .feature_set
        .is_active(&sol_log_data_syscall_enabled::id())
    {
        syscall_registry.register_syscall_by_name(b"sol_log_data", SyscallLogData::call)?;
    }

    if invoke_context
        .feature_set
        .is_active(&add_get_processed_sibling_instruction_syscall::id())
    {
        syscall_registry.register_syscall_by_name(
            b"sol_get_processed_sibling_instruction",
            SyscallGetProcessedSiblingInstruction::call,
        )?;
    }

    if invoke_context
        .feature_set
        .is_active(&add_get_processed_sibling_instruction_syscall::id())
    {
        syscall_registry
            .register_syscall_by_name(b"sol_get_stack_height", SyscallGetStackHeight::call)?;
    }

    Ok(syscall_registry)
}

macro_rules! bind_feature_gated_syscall_context_object {
    ($vm:expr, $is_feature_active:expr, $syscall_context_object:expr $(,)?) => {
        if $is_feature_active {
            match $vm.bind_syscall_context_object($syscall_context_object, None) {
                Err(EbpfError::SyscallNotRegistered(_)) | Ok(()) => {}
                Err(err) => {
                    return Err(err);
                }
            }
        }
    };
}

pub fn bind_syscall_context_objects<'a, 'b>(
    vm: &mut EbpfVm<'a, BpfError, crate::ThisInstructionMeter>,
    invoke_context: &'a mut InvokeContext<'b>,
    heap: AlignedMemory,
    orig_data_lens: &'a [usize],
) -> Result<(), EbpfError<BpfError>> {
    let is_blake3_syscall_active = invoke_context
        .feature_set
        .is_active(&blake3_syscall_enabled::id());
    let is_secp256k1_recover_syscall_active = invoke_context
        .feature_set
        .is_active(&secp256k1_recover_syscall_enabled::id());
    let is_fee_sysvar_via_syscall_active = !invoke_context
        .feature_set
        .is_active(&disable_fees_sysvar::id());
    let is_return_data_syscall_active = invoke_context
        .feature_set
        .is_active(&return_data_syscall_enabled::id());
    let is_sol_log_data_syscall_active = invoke_context
        .feature_set
        .is_active(&sol_log_data_syscall_enabled::id());
    let add_get_processed_sibling_instruction_syscall = invoke_context
        .feature_set
        .is_active(&add_get_processed_sibling_instruction_syscall::id());

    let loader_id = invoke_context
        .get_loader()
        .map_err(SyscallError::InstructionError)?;
    let invoke_context = Rc::new(RefCell::new(invoke_context));

    // Syscall functions common across languages

    vm.bind_syscall_context_object(Box::new(SyscallAbort {}), None)?;
    vm.bind_syscall_context_object(
        Box::new(SyscallPanic {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallLog {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallLogU64 {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;

    vm.bind_syscall_context_object(
        Box::new(SyscallLogBpfComputeUnits {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallLogPubkey {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;

    vm.bind_syscall_context_object(
        Box::new(SyscallCreateProgramAddress {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallTryFindProgramAddress {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;

    vm.bind_syscall_context_object(
        Box::new(SyscallSha256 {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallKeccak256 {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;

    vm.bind_syscall_context_object(
        Box::new(SyscallMemcpy {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallMemmove {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallMemcmp {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallMemset {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;

    bind_feature_gated_syscall_context_object!(
        vm,
        is_secp256k1_recover_syscall_active,
        Box::new(SyscallSecp256k1Recover {
            invoke_context: invoke_context.clone(),
        }),
    );
    bind_feature_gated_syscall_context_object!(
        vm,
        is_blake3_syscall_active,
        Box::new(SyscallBlake3 {
            invoke_context: invoke_context.clone(),
        }),
    );

    vm.bind_syscall_context_object(
        Box::new(SyscallGetClockSysvar {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallGetEpochScheduleSysvar {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;
    bind_feature_gated_syscall_context_object!(
        vm,
        is_fee_sysvar_via_syscall_active,
        Box::new(SyscallGetFeesSysvar {
            invoke_context: invoke_context.clone(),
        }),
    );
    vm.bind_syscall_context_object(
        Box::new(SyscallGetRentSysvar {
            invoke_context: invoke_context.clone(),
        }),
        None,
    )?;

    // Return data
    bind_feature_gated_syscall_context_object!(
        vm,
        is_return_data_syscall_active,
        Box::new(SyscallSetReturnData {
            invoke_context: invoke_context.clone(),
        }),
    );

    bind_feature_gated_syscall_context_object!(
        vm,
        is_return_data_syscall_active,
        Box::new(SyscallGetReturnData {
            invoke_context: invoke_context.clone(),
        }),
    );

    // sol_log_data
    bind_feature_gated_syscall_context_object!(
        vm,
        is_sol_log_data_syscall_active,
        Box::new(SyscallLogData {
            invoke_context: invoke_context.clone(),
        }),
    );

    // processed inner instructions
    bind_feature_gated_syscall_context_object!(
        vm,
        add_get_processed_sibling_instruction_syscall,
        Box::new(SyscallGetProcessedSiblingInstruction {
            invoke_context: invoke_context.clone(),
        }),
    );

    // Get stack height
    bind_feature_gated_syscall_context_object!(
        vm,
        add_get_processed_sibling_instruction_syscall,
        Box::new(SyscallGetStackHeight {
            invoke_context: invoke_context.clone(),
        }),
    );

    // Cross-program invocation syscalls
    vm.bind_syscall_context_object(
        Box::new(SyscallInvokeSignedC {
            invoke_context: invoke_context.clone(),
            orig_data_lens,
        }),
        None,
    )?;
    vm.bind_syscall_context_object(
        Box::new(SyscallInvokeSignedRust {
            invoke_context: invoke_context.clone(),
            orig_data_lens,
        }),
        None,
    )?;

    // Memory allocator
    vm.bind_syscall_context_object(
        Box::new(SyscallAllocFree {
            aligned: loader_id != bpf_loader_deprecated::id(),
            allocator: BpfAllocator::new(heap, ebpf::MM_HEAP_START),
        }),
        None,
    )?;

    Ok(())
}

fn translate(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
) -> Result<u64, EbpfError<BpfError>> {
    memory_mapping.map::<BpfError>(access_type, vm_addr, len)
}

fn translate_type_inner<'a, T>(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    loader_id: &Pubkey,
) -> Result<&'a mut T, EbpfError<BpfError>> {
    let host_addr = translate(memory_mapping, access_type, vm_addr, size_of::<T>() as u64)?;

    if loader_id != &bpf_loader_deprecated::id()
        && (host_addr as *mut T).align_offset(align_of::<T>()) != 0
    {
        return Err(SyscallError::UnalignedPointer.into());
    }
    Ok(unsafe { &mut *(host_addr as *mut T) })
}
fn translate_type_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    loader_id: &Pubkey,
) -> Result<&'a mut T, EbpfError<BpfError>> {
    translate_type_inner::<T>(memory_mapping, AccessType::Store, vm_addr, loader_id)
}
fn translate_type<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    loader_id: &Pubkey,
) -> Result<&'a T, EbpfError<BpfError>> {
    translate_type_inner::<T>(memory_mapping, AccessType::Load, vm_addr, loader_id)
        .map(|value| &*value)
}

fn translate_slice_inner<'a, T>(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
    loader_id: &Pubkey,
) -> Result<&'a mut [T], EbpfError<BpfError>> {
    if len == 0 {
        return Ok(&mut []);
    }

    let host_addr = translate(
        memory_mapping,
        access_type,
        vm_addr,
        len.saturating_mul(size_of::<T>() as u64),
    )?;

    if loader_id != &bpf_loader_deprecated::id()
        && (host_addr as *mut T).align_offset(align_of::<T>()) != 0
    {
        return Err(SyscallError::UnalignedPointer.into());
    }
    Ok(unsafe { from_raw_parts_mut(host_addr as *mut T, len as usize) })
}
fn translate_slice_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    loader_id: &Pubkey,
) -> Result<&'a mut [T], EbpfError<BpfError>> {
    translate_slice_inner::<T>(memory_mapping, AccessType::Store, vm_addr, len, loader_id)
}
fn translate_slice<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    loader_id: &Pubkey,
) -> Result<&'a [T], EbpfError<BpfError>> {
    translate_slice_inner::<T>(memory_mapping, AccessType::Load, vm_addr, len, loader_id)
        .map(|value| &*value)
}

/// Take a virtual pointer to a string (points to BPF VM memory space), translate it
/// pass it to a user-defined work function
fn translate_string_and_do(
    memory_mapping: &MemoryMapping,
    addr: u64,
    len: u64,
    loader_id: &Pubkey,
    work: &mut dyn FnMut(&str) -> Result<u64, EbpfError<BpfError>>,
) -> Result<u64, EbpfError<BpfError>> {
    let buf = translate_slice::<u8>(memory_mapping, addr, len, loader_id)?;
    let i = match buf.iter().position(|byte| *byte == 0) {
        Some(i) => i,
        None => len as usize,
    };
    match from_utf8(&buf[..i]) {
        Ok(message) => work(message),
        Err(err) => Err(SyscallError::InvalidString(err, buf[..i].to_vec()).into()),
    }
}

/// Abort syscall functions, called when the BPF program calls `abort()`
/// LLVM will insert calls to `abort()` if it detects an untenable situation,
/// `abort()` is not intended to be called explicitly by the program.
/// Causes the BPF program to be halted immediately
pub struct SyscallAbort {}
impl SyscallObject<BpfError> for SyscallAbort {
    fn call(
        &mut self,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        *result = Err(SyscallError::Abort.into());
    }
}

/// Panic syscall function, called when the BPF program calls 'sol_panic_()`
/// Causes the BPF program to be halted immediately
/// Log a user's info message
pub struct SyscallPanic<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallPanic<'a, 'b> {
    fn call(
        &mut self,
        file: u64,
        len: u64,
        line: u64,
        column: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        if !invoke_context
            .feature_set
            .is_active(&update_syscall_base_costs::id())
        {
            question_mark!(invoke_context.get_compute_meter().consume(len), result);
        }
        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        *result = translate_string_and_do(
            memory_mapping,
            file,
            len,
            &loader_id,
            &mut |string: &str| Err(SyscallError::Panic(string.to_string(), line, column).into()),
        );
    }
}

/// Log a user's info message
pub struct SyscallLog<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallLog<'a, 'b> {
    fn call(
        &mut self,
        addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let cost = if invoke_context
            .feature_set
            .is_active(&update_syscall_base_costs::id())
        {
            invoke_context
                .get_compute_budget()
                .syscall_base_cost
                .max(len)
        } else {
            len
        };
        question_mark!(invoke_context.get_compute_meter().consume(cost), result);

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        question_mark!(
            translate_string_and_do(
                memory_mapping,
                addr,
                len,
                &loader_id,
                &mut |string: &str| {
                    stable_log::program_log(&invoke_context.get_log_collector(), string);
                    Ok(0)
                },
            ),
            result
        );
        *result = Ok(0);
    }
}

/// Log 5 64-bit values
pub struct SyscallLogU64<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallLogU64<'a, 'b> {
    fn call(
        &mut self,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let cost = invoke_context.get_compute_budget().log_64_units;
        question_mark!(invoke_context.get_compute_meter().consume(cost), result);

        stable_log::program_log(
            &invoke_context.get_log_collector(),
            &format!(
                "{:#x}, {:#x}, {:#x}, {:#x}, {:#x}",
                arg1, arg2, arg3, arg4, arg5
            ),
        );
        *result = Ok(0);
    }
}

/// Log current compute consumption
pub struct SyscallLogBpfComputeUnits<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallLogBpfComputeUnits<'a, 'b> {
    fn call(
        &mut self,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let cost = if invoke_context
            .feature_set
            .is_active(&update_syscall_base_costs::id())
        {
            invoke_context.get_compute_budget().syscall_base_cost
        } else {
            0
        };
        question_mark!(invoke_context.get_compute_meter().consume(cost), result);

        ic_logger_msg!(
            invoke_context.get_log_collector(),
            "Program consumption: {} units remaining",
            invoke_context.get_compute_meter().borrow().get_remaining()
        );
        *result = Ok(0);
    }
}

/// Log 5 64-bit values
pub struct SyscallLogPubkey<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallLogPubkey<'a, 'b> {
    fn call(
        &mut self,
        pubkey_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let cost = invoke_context.get_compute_budget().log_pubkey_units;
        question_mark!(invoke_context.get_compute_meter().consume(cost), result);

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let pubkey = question_mark!(
            translate_type::<Pubkey>(memory_mapping, pubkey_addr, &loader_id),
            result
        );
        stable_log::program_log(&invoke_context.get_log_collector(), &pubkey.to_string());
        *result = Ok(0);
    }
}

/// Dynamic memory allocation syscall called when the BPF program calls
/// `sol_alloc_free_()`.  The allocator is expected to allocate/free
/// from/to a given chunk of memory and enforce size restrictions.  The
/// memory chunk is given to the allocator during allocator creation and
/// information about that memory (start address and size) is passed
/// to the VM to use for enforcement.
pub struct SyscallAllocFree {
    aligned: bool,
    allocator: BpfAllocator,
}
impl SyscallObject<BpfError> for SyscallAllocFree {
    fn call(
        &mut self,
        size: u64,
        free_addr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let align = if self.aligned {
            BPF_ALIGN_OF_U128
        } else {
            align_of::<u8>()
        };
        let layout = match Layout::from_size_align(size as usize, align) {
            Ok(layout) => layout,
            Err(_) => {
                *result = Ok(0);
                return;
            }
        };
        *result = if free_addr == 0 {
            match self.allocator.alloc(layout) {
                Ok(addr) => Ok(addr as u64),
                Err(_) => Ok(0),
            }
        } else {
            self.allocator.dealloc(free_addr, layout);
            Ok(0)
        };
    }
}

fn translate_and_check_program_address_inputs<'a>(
    seeds_addr: u64,
    seeds_len: u64,
    program_id_addr: u64,
    memory_mapping: &MemoryMapping,
    loader_id: &Pubkey,
) -> Result<(Vec<&'a [u8]>, &'a Pubkey), EbpfError<BpfError>> {
    let untranslated_seeds =
        translate_slice::<&[&u8]>(memory_mapping, seeds_addr, seeds_len, loader_id)?;
    if untranslated_seeds.len() > MAX_SEEDS {
        return Err(SyscallError::BadSeeds(PubkeyError::MaxSeedLengthExceeded).into());
    }
    let seeds = untranslated_seeds
        .iter()
        .map(|untranslated_seed| {
            if untranslated_seed.len() > MAX_SEED_LEN {
                return Err(SyscallError::BadSeeds(PubkeyError::MaxSeedLengthExceeded).into());
            }
            translate_slice::<u8>(
                memory_mapping,
                untranslated_seed.as_ptr() as *const _ as u64,
                untranslated_seed.len() as u64,
                loader_id,
            )
        })
        .collect::<Result<Vec<_>, EbpfError<BpfError>>>()?;
    let program_id = translate_type::<Pubkey>(memory_mapping, program_id_addr, loader_id)?;
    Ok((seeds, program_id))
}

/// Create a program address
struct SyscallCreateProgramAddress<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallCreateProgramAddress<'a, 'b> {
    fn call(
        &mut self,
        seeds_addr: u64,
        seeds_len: u64,
        program_id_addr: u64,
        address_addr: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let cost = invoke_context
            .get_compute_budget()
            .create_program_address_units;
        question_mark!(invoke_context.get_compute_meter().consume(cost), result);

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let (seeds, program_id) = question_mark!(
            translate_and_check_program_address_inputs(
                seeds_addr,
                seeds_len,
                program_id_addr,
                memory_mapping,
                &loader_id,
            ),
            result
        );

        let new_address = match Pubkey::create_program_address(&seeds, program_id) {
            Ok(address) => address,
            Err(_) => {
                *result = Ok(1);
                return;
            }
        };
        let address = question_mark!(
            translate_slice_mut::<u8>(memory_mapping, address_addr, 32, &loader_id),
            result
        );
        address.copy_from_slice(new_address.as_ref());
        *result = Ok(0);
    }
}

/// Create a program address
struct SyscallTryFindProgramAddress<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallTryFindProgramAddress<'a, 'b> {
    fn call(
        &mut self,
        seeds_addr: u64,
        seeds_len: u64,
        program_id_addr: u64,
        address_addr: u64,
        bump_seed_addr: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let cost = invoke_context
            .get_compute_budget()
            .create_program_address_units;
        question_mark!(invoke_context.get_compute_meter().consume(cost), result);

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let (seeds, program_id) = question_mark!(
            translate_and_check_program_address_inputs(
                seeds_addr,
                seeds_len,
                program_id_addr,
                memory_mapping,
                &loader_id,
            ),
            result
        );

        let mut bump_seed = [std::u8::MAX];
        for _ in 0..std::u8::MAX {
            {
                let mut seeds_with_bump = seeds.to_vec();
                seeds_with_bump.push(&bump_seed);

                if let Ok(new_address) =
                    Pubkey::create_program_address(&seeds_with_bump, program_id)
                {
                    let bump_seed_ref = question_mark!(
                        translate_type_mut::<u8>(memory_mapping, bump_seed_addr, &loader_id),
                        result
                    );
                    let address = question_mark!(
                        translate_slice_mut::<u8>(memory_mapping, address_addr, 32, &loader_id),
                        result
                    );
                    *bump_seed_ref = bump_seed[0];
                    address.copy_from_slice(new_address.as_ref());
                    *result = Ok(0);
                    return;
                }
            }
            bump_seed[0] -= 1;
            question_mark!(invoke_context.get_compute_meter().consume(cost), result);
        }
        *result = Ok(1);
    }
}

/// SHA256
pub struct SyscallSha256<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallSha256<'a, 'b> {
    fn call(
        &mut self,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let compute_budget = invoke_context.get_compute_budget();
        if invoke_context
            .feature_set
            .is_active(&update_syscall_base_costs::id())
            && compute_budget.sha256_max_slices < vals_len
        {
            ic_msg!(
                invoke_context,
                "Sha256 hashing {} sequences in one syscall is over the limit {}",
                vals_len,
                compute_budget.sha256_max_slices,
            );
            *result = Err(SyscallError::TooManySlices.into());
            return;
        }
        question_mark!(
            invoke_context
                .get_compute_meter()
                .consume(compute_budget.sha256_base_cost),
            result
        );

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let hash_result = question_mark!(
            translate_slice_mut::<u8>(memory_mapping, result_addr, HASH_BYTES as u64, &loader_id),
            result
        );
        let mut hasher = Hasher::default();
        if vals_len > 0 {
            let vals = question_mark!(
                translate_slice::<&[u8]>(memory_mapping, vals_addr, vals_len, &loader_id),
                result
            );
            for val in vals.iter() {
                let bytes = question_mark!(
                    translate_slice::<u8>(
                        memory_mapping,
                        val.as_ptr() as u64,
                        val.len() as u64,
                        &loader_id,
                    ),
                    result
                );
                let cost = if invoke_context
                    .feature_set
                    .is_active(&update_syscall_base_costs::id())
                {
                    compute_budget.mem_op_base_cost.max(
                        compute_budget
                            .sha256_byte_cost
                            .saturating_mul(val.len() as u64 / 2),
                    )
                } else {
                    compute_budget.sha256_byte_cost * (val.len() as u64 / 2)
                };
                question_mark!(invoke_context.get_compute_meter().consume(cost), result);
                hasher.hash(bytes);
            }
        }
        hash_result.copy_from_slice(&hasher.result().to_bytes());
        *result = Ok(0);
    }
}

fn get_sysvar<T: std::fmt::Debug + Sysvar + SysvarId + Clone>(
    sysvar: Result<Arc<T>, InstructionError>,
    var_addr: u64,
    loader_id: &Pubkey,
    memory_mapping: &MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<u64, EbpfError<BpfError>> {
    invoke_context
        .get_compute_meter()
        .consume(invoke_context.get_compute_budget().sysvar_base_cost + size_of::<T>() as u64)?;
    let var = translate_type_mut::<T>(memory_mapping, var_addr, loader_id)?;

    let sysvar: Arc<T> = sysvar.map_err(SyscallError::InstructionError)?;
    *var = T::clone(sysvar.as_ref());

    Ok(SUCCESS)
}

/// Get a Clock sysvar
struct SyscallGetClockSysvar<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallGetClockSysvar<'a, 'b> {
    fn call(
        &mut self,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let mut invoke_context = question_mark!(
            self.invoke_context
                .try_borrow_mut()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        *result = get_sysvar(
            invoke_context.get_sysvar_cache().get_clock(),
            var_addr,
            &loader_id,
            memory_mapping,
            &mut invoke_context,
        );
    }
}
/// Get a EpochSchedule sysvar
struct SyscallGetEpochScheduleSysvar<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallGetEpochScheduleSysvar<'a, 'b> {
    fn call(
        &mut self,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let mut invoke_context = question_mark!(
            self.invoke_context
                .try_borrow_mut()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        *result = get_sysvar(
            invoke_context.get_sysvar_cache().get_epoch_schedule(),
            var_addr,
            &loader_id,
            memory_mapping,
            &mut invoke_context,
        );
    }
}
/// Get a Fees sysvar
struct SyscallGetFeesSysvar<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
#[allow(deprecated)]
impl<'a, 'b> SyscallObject<BpfError> for SyscallGetFeesSysvar<'a, 'b> {
    fn call(
        &mut self,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let mut invoke_context = question_mark!(
            self.invoke_context
                .try_borrow_mut()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        *result = get_sysvar(
            invoke_context.get_sysvar_cache().get_fees(),
            var_addr,
            &loader_id,
            memory_mapping,
            &mut invoke_context,
        );
    }
}
/// Get a Rent sysvar
struct SyscallGetRentSysvar<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallGetRentSysvar<'a, 'b> {
    fn call(
        &mut self,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let mut invoke_context = question_mark!(
            self.invoke_context
                .try_borrow_mut()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        *result = get_sysvar(
            invoke_context.get_sysvar_cache().get_rent(),
            var_addr,
            &loader_id,
            memory_mapping,
            &mut invoke_context,
        );
    }
}

// Keccak256
pub struct SyscallKeccak256<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallKeccak256<'a, 'b> {
    fn call(
        &mut self,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let compute_budget = invoke_context.get_compute_budget();
        if invoke_context
            .feature_set
            .is_active(&update_syscall_base_costs::id())
            && compute_budget.sha256_max_slices < vals_len
        {
            ic_msg!(
                invoke_context,
                "Keccak256 hashing {} sequences in one syscall is over the limit {}",
                vals_len,
                compute_budget.sha256_max_slices,
            );
            *result = Err(SyscallError::TooManySlices.into());
            return;
        }
        question_mark!(
            invoke_context
                .get_compute_meter()
                .consume(compute_budget.sha256_base_cost),
            result
        );

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let hash_result = question_mark!(
            translate_slice_mut::<u8>(
                memory_mapping,
                result_addr,
                keccak::HASH_BYTES as u64,
                &loader_id,
            ),
            result
        );
        let mut hasher = keccak::Hasher::default();
        if vals_len > 0 {
            let vals = question_mark!(
                translate_slice::<&[u8]>(memory_mapping, vals_addr, vals_len, &loader_id),
                result
            );
            for val in vals.iter() {
                let bytes = question_mark!(
                    translate_slice::<u8>(
                        memory_mapping,
                        val.as_ptr() as u64,
                        val.len() as u64,
                        &loader_id,
                    ),
                    result
                );
                let cost = if invoke_context
                    .feature_set
                    .is_active(&update_syscall_base_costs::id())
                {
                    compute_budget.mem_op_base_cost.max(
                        compute_budget
                            .sha256_byte_cost
                            .saturating_mul(val.len() as u64 / 2),
                    )
                } else {
                    compute_budget.sha256_byte_cost * (val.len() as u64 / 2)
                };
                question_mark!(invoke_context.get_compute_meter().consume(cost), result);
                hasher.hash(bytes);
            }
        }
        hash_result.copy_from_slice(&hasher.result().to_bytes());
        *result = Ok(0);
    }
}

/// This function is incorrect due to arithmetic overflow and only exists for
/// backwards compatibility. Instead use program_stubs::is_nonoverlapping.
fn check_overlapping_do_not_use(src_addr: u64, dst_addr: u64, n: u64) -> bool {
    (src_addr <= dst_addr && src_addr + n > dst_addr)
        || (dst_addr <= src_addr && dst_addr + n > src_addr)
}

fn mem_op_consume<'a, 'b>(
    invoke_context: &Ref<&'a mut InvokeContext<'b>>,
    n: u64,
) -> Result<(), EbpfError<BpfError>> {
    let compute_budget = invoke_context.get_compute_budget();
    let cost = if invoke_context
        .feature_set
        .is_active(&update_syscall_base_costs::id())
    {
        compute_budget
            .mem_op_base_cost
            .max(n / compute_budget.cpi_bytes_per_unit)
    } else {
        n / compute_budget.cpi_bytes_per_unit
    };
    invoke_context.get_compute_meter().consume(cost)
}

/// memcpy
pub struct SyscallMemcpy<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallMemcpy<'a, 'b> {
    fn call(
        &mut self,
        dst_addr: u64,
        src_addr: u64,
        n: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let use_fixed_nonoverlapping_check = invoke_context
            .feature_set
            .is_active(&fixed_memcpy_nonoverlapping_check::id());

        #[allow(clippy::collapsible_else_if)]
        if use_fixed_nonoverlapping_check {
            if !is_nonoverlapping(src_addr, dst_addr, n) {
                *result = Err(SyscallError::CopyOverlapping.into());
                return;
            }
        } else {
            if check_overlapping_do_not_use(src_addr, dst_addr, n) {
                *result = Err(SyscallError::CopyOverlapping.into());
                return;
            }
        }

        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        // When deprecating `update_syscall_base_costs` switch to `mem_op_consume`
        let compute_budget = invoke_context.get_compute_budget();
        let update_syscall_base_costs = invoke_context
            .feature_set
            .is_active(&update_syscall_base_costs::id());
        if update_syscall_base_costs {
            let cost = compute_budget
                .mem_op_base_cost
                .max(n / compute_budget.cpi_bytes_per_unit);
            question_mark!(invoke_context.get_compute_meter().consume(cost), result);
        }

        if !update_syscall_base_costs {
            let cost = n / compute_budget.cpi_bytes_per_unit;
            question_mark!(invoke_context.get_compute_meter().consume(cost), result);
        };

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let dst = question_mark!(
            translate_slice_mut::<u8>(memory_mapping, dst_addr, n, &loader_id),
            result
        );
        let src = question_mark!(
            translate_slice::<u8>(memory_mapping, src_addr, n, &loader_id),
            result
        );
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n as usize);
        }
        *result = Ok(0);
    }
}
/// memmove
pub struct SyscallMemmove<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallMemmove<'a, 'b> {
    fn call(
        &mut self,
        dst_addr: u64,
        src_addr: u64,
        n: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        question_mark!(mem_op_consume(&invoke_context, n), result);

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let dst = question_mark!(
            translate_slice_mut::<u8>(memory_mapping, dst_addr, n, &loader_id),
            result
        );
        let src = question_mark!(
            translate_slice::<u8>(memory_mapping, src_addr, n, &loader_id),
            result
        );
        unsafe {
            std::ptr::copy(src.as_ptr(), dst.as_mut_ptr(), n as usize);
        }
        *result = Ok(0);
    }
}
/// memcmp
pub struct SyscallMemcmp<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallMemcmp<'a, 'b> {
    fn call(
        &mut self,
        s1_addr: u64,
        s2_addr: u64,
        n: u64,
        cmp_result_addr: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        question_mark!(mem_op_consume(&invoke_context, n), result);

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let s1 = question_mark!(
            translate_slice::<u8>(memory_mapping, s1_addr, n, &loader_id),
            result
        );
        let s2 = question_mark!(
            translate_slice::<u8>(memory_mapping, s2_addr, n, &loader_id),
            result
        );
        let cmp_result = question_mark!(
            translate_type_mut::<i32>(memory_mapping, cmp_result_addr, &loader_id),
            result
        );
        let mut i = 0;
        while i < n as usize {
            let a = s1[i];
            let b = s2[i];
            if a != b {
                *cmp_result = a as i32 - b as i32;
                *result = Ok(0);
                return;
            }
            i += 1;
        }
        *cmp_result = 0;
        *result = Ok(0);
    }
}
/// memset
pub struct SyscallMemset<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallMemset<'a, 'b> {
    fn call(
        &mut self,
        s_addr: u64,
        c: u64,
        n: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        question_mark!(mem_op_consume(&invoke_context, n), result);

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let s = question_mark!(
            translate_slice_mut::<u8>(memory_mapping, s_addr, n, &loader_id),
            result
        );
        for val in s.iter_mut().take(n as usize) {
            *val = c as u8;
        }
        *result = Ok(0);
    }
}

/// secp256k1_recover
pub struct SyscallSecp256k1Recover<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}

impl<'a, 'b> SyscallObject<BpfError> for SyscallSecp256k1Recover<'a, 'b> {
    fn call(
        &mut self,
        hash_addr: u64,
        recovery_id_val: u64,
        signature_addr: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let cost = invoke_context.get_compute_budget().secp256k1_recover_cost;
        question_mark!(invoke_context.get_compute_meter().consume(cost), result);

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let hash = question_mark!(
            translate_slice::<u8>(
                memory_mapping,
                hash_addr,
                keccak::HASH_BYTES as u64,
                &loader_id,
            ),
            result
        );
        let signature = question_mark!(
            translate_slice::<u8>(
                memory_mapping,
                signature_addr,
                SECP256K1_SIGNATURE_LENGTH as u64,
                &loader_id,
            ),
            result
        );
        let secp256k1_recover_result = question_mark!(
            translate_slice_mut::<u8>(
                memory_mapping,
                result_addr,
                SECP256K1_PUBLIC_KEY_LENGTH as u64,
                &loader_id,
            ),
            result
        );

        let message = match libsecp256k1::Message::parse_slice(hash) {
            Ok(msg) => msg,
            Err(_) => {
                *result = Ok(Secp256k1RecoverError::InvalidHash.into());
                return;
            }
        };
        let recovery_id = match libsecp256k1::RecoveryId::parse(recovery_id_val as u8) {
            Ok(id) => id,
            Err(_) => {
                *result = Ok(Secp256k1RecoverError::InvalidRecoveryId.into());
                return;
            }
        };
        let sig_parse_result = if invoke_context
            .feature_set
            .is_active(&libsecp256k1_0_5_upgrade_enabled::id())
        {
            libsecp256k1::Signature::parse_standard_slice(signature)
        } else {
            libsecp256k1::Signature::parse_overflowing_slice(signature)
        };

        let signature = match sig_parse_result {
            Ok(sig) => sig,
            Err(_) => {
                *result = Ok(Secp256k1RecoverError::InvalidSignature.into());
                return;
            }
        };

        let public_key = match libsecp256k1::recover(&message, &signature, &recovery_id) {
            Ok(key) => key.serialize(),
            Err(_) => {
                *result = Ok(Secp256k1RecoverError::InvalidSignature.into());
                return;
            }
        };

        secp256k1_recover_result.copy_from_slice(&public_key[1..65]);
        *result = Ok(SUCCESS);
    }
}

// Blake3
pub struct SyscallBlake3<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallBlake3<'a, 'b> {
    fn call(
        &mut self,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let compute_budget = invoke_context.get_compute_budget();
        if invoke_context
            .feature_set
            .is_active(&update_syscall_base_costs::id())
            && compute_budget.sha256_max_slices < vals_len
        {
            ic_msg!(
                invoke_context,
                "Blake3 hashing {} sequences in one syscall is over the limit {}",
                vals_len,
                compute_budget.sha256_max_slices,
            );
            *result = Err(SyscallError::TooManySlices.into());
            return;
        }
        question_mark!(
            invoke_context
                .get_compute_meter()
                .consume(compute_budget.sha256_base_cost),
            result
        );

        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );
        let hash_result = question_mark!(
            translate_slice_mut::<u8>(
                memory_mapping,
                result_addr,
                blake3::HASH_BYTES as u64,
                &loader_id,
            ),
            result
        );
        let mut hasher = blake3::Hasher::default();
        if vals_len > 0 {
            let vals = question_mark!(
                translate_slice::<&[u8]>(memory_mapping, vals_addr, vals_len, &loader_id),
                result
            );
            for val in vals.iter() {
                let bytes = question_mark!(
                    translate_slice::<u8>(
                        memory_mapping,
                        val.as_ptr() as u64,
                        val.len() as u64,
                        &loader_id,
                    ),
                    result
                );
                let cost = if invoke_context
                    .feature_set
                    .is_active(&update_syscall_base_costs::id())
                {
                    compute_budget.mem_op_base_cost.max(
                        compute_budget
                            .sha256_byte_cost
                            .saturating_mul(val.len() as u64 / 2),
                    )
                } else {
                    compute_budget.sha256_byte_cost * (val.len() as u64 / 2)
                };
                question_mark!(invoke_context.get_compute_meter().consume(cost), result);
                hasher.hash(bytes);
            }
        }
        hash_result.copy_from_slice(&hasher.result().to_bytes());
        *result = Ok(0);
    }
}

// Cross-program invocation syscalls

struct CallerAccount<'a> {
    lamports: &'a mut u64,
    owner: &'a mut Pubkey,
    original_data_len: usize,
    data: &'a mut [u8],
    vm_data_addr: u64,
    ref_to_len_in_vm: &'a mut u64,
    serialized_len_ptr: &'a mut u64,
    executable: bool,
    rent_epoch: u64,
}
type TranslatedAccounts<'a> = (
    Vec<usize>,
    Vec<(Rc<RefCell<AccountSharedData>>, Option<CallerAccount<'a>>)>,
);

/// Implemented by language specific data structure translators
trait SyscallInvokeSigned<'a, 'b> {
    fn get_context_mut(&self) -> Result<RefMut<&'a mut InvokeContext<'b>>, EbpfError<BpfError>>;
    fn translate_instruction(
        &self,
        loader_id: &Pubkey,
        addr: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<Instruction, EbpfError<BpfError>>;
    fn translate_accounts<'c>(
        &'c self,
        loader_id: &Pubkey,
        message: &Message,
        account_infos_addr: u64,
        account_infos_len: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<TranslatedAccounts<'c>, EbpfError<BpfError>>;
    fn translate_signers(
        &self,
        loader_id: &Pubkey,
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
    ) -> Result<Vec<Pubkey>, EbpfError<BpfError>>;
}

/// Cross-program invocation called from Rust
pub struct SyscallInvokeSignedRust<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
    orig_data_lens: &'a [usize],
}
impl<'a, 'b> SyscallInvokeSigned<'a, 'b> for SyscallInvokeSignedRust<'a, 'b> {
    fn get_context_mut(&self) -> Result<RefMut<&'a mut InvokeContext<'b>>, EbpfError<BpfError>> {
        self.invoke_context
            .try_borrow_mut()
            .map_err(|_| SyscallError::InvokeContextBorrowFailed.into())
    }

    fn translate_instruction(
        &self,
        loader_id: &Pubkey,
        addr: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<Instruction, EbpfError<BpfError>> {
        let ix = translate_type::<Instruction>(memory_mapping, addr, loader_id)?;

        check_instruction_size(ix.accounts.len(), ix.data.len(), invoke_context)?;

        let accounts = translate_slice::<AccountMeta>(
            memory_mapping,
            ix.accounts.as_ptr() as u64,
            ix.accounts.len() as u64,
            loader_id,
        )?
        .to_vec();
        let data = translate_slice::<u8>(
            memory_mapping,
            ix.data.as_ptr() as u64,
            ix.data.len() as u64,
            loader_id,
        )?
        .to_vec();
        Ok(Instruction {
            program_id: ix.program_id,
            accounts,
            data,
        })
    }

    fn translate_accounts<'c>(
        &'c self,
        loader_id: &Pubkey,
        message: &Message,
        account_infos_addr: u64,
        account_infos_len: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<TranslatedAccounts<'c>, EbpfError<BpfError>> {
        let account_infos = translate_slice::<AccountInfo>(
            memory_mapping,
            account_infos_addr,
            account_infos_len,
            loader_id,
        )?;
        check_account_infos(account_infos.len(), invoke_context)?;
        let account_info_keys = account_infos
            .iter()
            .map(|account_info| {
                translate_type::<Pubkey>(
                    memory_mapping,
                    account_info.key as *const _ as u64,
                    loader_id,
                )
            })
            .collect::<Result<Vec<_>, EbpfError<BpfError>>>()?;

        let translate = |account_info: &AccountInfo, invoke_context: &InvokeContext| {
            // Translate the account from user space

            let lamports = {
                // Double translate lamports out of RefCell
                let ptr = translate_type::<u64>(
                    memory_mapping,
                    account_info.lamports.as_ptr() as u64,
                    loader_id,
                )?;
                translate_type_mut::<u64>(memory_mapping, *ptr, loader_id)?
            };
            let owner = translate_type_mut::<Pubkey>(
                memory_mapping,
                account_info.owner as *const _ as u64,
                loader_id,
            )?;

            let (data, vm_data_addr, ref_to_len_in_vm, serialized_len_ptr) = {
                // Double translate data out of RefCell
                let data = *translate_type::<&[u8]>(
                    memory_mapping,
                    account_info.data.as_ptr() as *const _ as u64,
                    loader_id,
                )?;

                invoke_context.get_compute_meter().consume(
                    data.len() as u64 / invoke_context.get_compute_budget().cpi_bytes_per_unit,
                )?;

                let translated = translate(
                    memory_mapping,
                    AccessType::Store,
                    unsafe { (account_info.data.as_ptr() as *const u64).offset(1) as u64 },
                    8,
                )? as *mut u64;
                let ref_to_len_in_vm = unsafe { &mut *translated };
                let ref_of_len_in_input_buffer = unsafe { data.as_ptr().offset(-8) };
                let serialized_len_ptr = translate_type_mut::<u64>(
                    memory_mapping,
                    ref_of_len_in_input_buffer as *const _ as u64,
                    loader_id,
                )?;
                let vm_data_addr = data.as_ptr() as u64;
                (
                    translate_slice_mut::<u8>(
                        memory_mapping,
                        vm_data_addr,
                        data.len() as u64,
                        loader_id,
                    )?,
                    vm_data_addr,
                    ref_to_len_in_vm,
                    serialized_len_ptr,
                )
            };

            Ok(CallerAccount {
                lamports,
                owner,
                original_data_len: 0, // set later
                data,
                vm_data_addr,
                ref_to_len_in_vm,
                serialized_len_ptr,
                executable: account_info.executable,
                rent_epoch: account_info.rent_epoch,
            })
        };

        get_translated_accounts(
            message,
            &account_info_keys,
            account_infos,
            invoke_context,
            self.orig_data_lens,
            translate,
        )
    }

    fn translate_signers(
        &self,
        loader_id: &Pubkey,
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
    ) -> Result<Vec<Pubkey>, EbpfError<BpfError>> {
        let mut signers = Vec::new();
        if signers_seeds_len > 0 {
            let signers_seeds = translate_slice::<&[&[u8]]>(
                memory_mapping,
                signers_seeds_addr,
                signers_seeds_len,
                loader_id,
            )?;
            if signers_seeds.len() > MAX_SIGNERS {
                return Err(SyscallError::TooManySigners.into());
            }
            for signer_seeds in signers_seeds.iter() {
                let untranslated_seeds = translate_slice::<&[u8]>(
                    memory_mapping,
                    signer_seeds.as_ptr() as *const _ as u64,
                    signer_seeds.len() as u64,
                    loader_id,
                )?;
                if untranslated_seeds.len() > MAX_SEEDS {
                    return Err(SyscallError::InstructionError(
                        InstructionError::MaxSeedLengthExceeded,
                    )
                    .into());
                }
                let seeds = untranslated_seeds
                    .iter()
                    .map(|untranslated_seed| {
                        translate_slice::<u8>(
                            memory_mapping,
                            untranslated_seed.as_ptr() as *const _ as u64,
                            untranslated_seed.len() as u64,
                            loader_id,
                        )
                    })
                    .collect::<Result<Vec<_>, EbpfError<BpfError>>>()?;
                let signer = Pubkey::create_program_address(&seeds, program_id)
                    .map_err(SyscallError::BadSeeds)?;
                signers.push(signer);
            }
            Ok(signers)
        } else {
            Ok(vec![])
        }
    }
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallInvokeSignedRust<'a, 'b> {
    fn call(
        &mut self,
        instruction_addr: u64,
        account_infos_addr: u64,
        account_infos_len: u64,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        *result = call(
            self,
            instruction_addr,
            account_infos_addr,
            account_infos_len,
            signers_seeds_addr,
            signers_seeds_len,
            memory_mapping,
        );
    }
}

/// Rust representation of C's SolInstruction
#[derive(Debug)]
struct SolInstruction {
    program_id_addr: u64,
    accounts_addr: u64,
    accounts_len: usize,
    data_addr: u64,
    data_len: usize,
}

/// Rust representation of C's SolAccountMeta
#[derive(Debug)]
struct SolAccountMeta {
    pubkey_addr: u64,
    is_writable: bool,
    is_signer: bool,
}

/// Rust representation of C's SolAccountInfo
#[derive(Debug)]
struct SolAccountInfo {
    key_addr: u64,
    lamports_addr: u64,
    data_len: u64,
    data_addr: u64,
    owner_addr: u64,
    rent_epoch: u64,
    #[allow(dead_code)]
    is_signer: bool,
    #[allow(dead_code)]
    is_writable: bool,
    executable: bool,
}

/// Rust representation of C's SolSignerSeed
#[derive(Debug)]
struct SolSignerSeedC {
    addr: u64,
    len: u64,
}

/// Rust representation of C's SolSignerSeeds
#[derive(Debug)]
struct SolSignerSeedsC {
    #[allow(dead_code)]
    addr: u64,
    #[allow(dead_code)]
    len: u64,
}

/// Cross-program invocation called from C
pub struct SyscallInvokeSignedC<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
    orig_data_lens: &'a [usize],
}
impl<'a, 'b> SyscallInvokeSigned<'a, 'b> for SyscallInvokeSignedC<'a, 'b> {
    fn get_context_mut(&self) -> Result<RefMut<&'a mut InvokeContext<'b>>, EbpfError<BpfError>> {
        self.invoke_context
            .try_borrow_mut()
            .map_err(|_| SyscallError::InvokeContextBorrowFailed.into())
    }

    fn translate_instruction(
        &self,
        loader_id: &Pubkey,
        addr: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<Instruction, EbpfError<BpfError>> {
        let ix_c = translate_type::<SolInstruction>(memory_mapping, addr, loader_id)?;

        check_instruction_size(ix_c.accounts_len, ix_c.data_len, invoke_context)?;
        let program_id = translate_type::<Pubkey>(memory_mapping, ix_c.program_id_addr, loader_id)?;
        let meta_cs = translate_slice::<SolAccountMeta>(
            memory_mapping,
            ix_c.accounts_addr,
            ix_c.accounts_len as u64,
            loader_id,
        )?;
        let data = translate_slice::<u8>(
            memory_mapping,
            ix_c.data_addr,
            ix_c.data_len as u64,
            loader_id,
        )?
        .to_vec();
        let accounts = meta_cs
            .iter()
            .map(|meta_c| {
                let pubkey =
                    translate_type::<Pubkey>(memory_mapping, meta_c.pubkey_addr, loader_id)?;
                Ok(AccountMeta {
                    pubkey: *pubkey,
                    is_signer: meta_c.is_signer,
                    is_writable: meta_c.is_writable,
                })
            })
            .collect::<Result<Vec<AccountMeta>, EbpfError<BpfError>>>()?;

        Ok(Instruction {
            program_id: *program_id,
            accounts,
            data,
        })
    }

    fn translate_accounts<'c>(
        &'c self,
        loader_id: &Pubkey,
        message: &Message,
        account_infos_addr: u64,
        account_infos_len: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<TranslatedAccounts<'c>, EbpfError<BpfError>> {
        let account_infos = translate_slice::<SolAccountInfo>(
            memory_mapping,
            account_infos_addr,
            account_infos_len,
            loader_id,
        )?;
        check_account_infos(account_infos.len(), invoke_context)?;
        let account_info_keys = account_infos
            .iter()
            .map(|account_info| {
                translate_type::<Pubkey>(memory_mapping, account_info.key_addr, loader_id)
            })
            .collect::<Result<Vec<_>, EbpfError<BpfError>>>()?;

        let translate = |account_info: &SolAccountInfo, invoke_context: &InvokeContext| {
            // Translate the account from user space

            let lamports =
                translate_type_mut::<u64>(memory_mapping, account_info.lamports_addr, loader_id)?;
            let owner =
                translate_type_mut::<Pubkey>(memory_mapping, account_info.owner_addr, loader_id)?;
            let vm_data_addr = account_info.data_addr;

            invoke_context.get_compute_meter().consume(
                account_info.data_len / invoke_context.get_compute_budget().cpi_bytes_per_unit,
            )?;

            let data = translate_slice_mut::<u8>(
                memory_mapping,
                vm_data_addr,
                account_info.data_len,
                loader_id,
            )?;

            let first_info_addr = &account_infos[0] as *const _ as u64;
            let addr = &account_info.data_len as *const u64 as u64;
            let vm_addr = account_infos_addr + (addr - first_info_addr);
            let _ = translate(
                memory_mapping,
                AccessType::Store,
                vm_addr,
                size_of::<u64>() as u64,
            )?;
            let ref_to_len_in_vm = unsafe { &mut *(addr as *mut u64) };

            let ref_of_len_in_input_buffer =
                unsafe { (account_info.data_addr as *mut u8).offset(-8) };
            let serialized_len_ptr = translate_type_mut::<u64>(
                memory_mapping,
                ref_of_len_in_input_buffer as *const _ as u64,
                loader_id,
            )?;

            Ok(CallerAccount {
                lamports,
                owner,
                original_data_len: 0, // set later
                data,
                vm_data_addr,
                ref_to_len_in_vm,
                serialized_len_ptr,
                executable: account_info.executable,
                rent_epoch: account_info.rent_epoch,
            })
        };

        get_translated_accounts(
            message,
            &account_info_keys,
            account_infos,
            invoke_context,
            self.orig_data_lens,
            translate,
        )
    }

    fn translate_signers(
        &self,
        loader_id: &Pubkey,
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
    ) -> Result<Vec<Pubkey>, EbpfError<BpfError>> {
        if signers_seeds_len > 0 {
            let signers_seeds = translate_slice::<SolSignerSeedC>(
                memory_mapping,
                signers_seeds_addr,
                signers_seeds_len,
                loader_id,
            )?;
            if signers_seeds.len() > MAX_SIGNERS {
                return Err(SyscallError::TooManySigners.into());
            }
            Ok(signers_seeds
                .iter()
                .map(|signer_seeds| {
                    let seeds = translate_slice::<SolSignerSeedC>(
                        memory_mapping,
                        signer_seeds.addr,
                        signer_seeds.len,
                        loader_id,
                    )?;
                    if seeds.len() > MAX_SEEDS {
                        return Err(SyscallError::InstructionError(
                            InstructionError::MaxSeedLengthExceeded,
                        )
                        .into());
                    }
                    let seeds_bytes = seeds
                        .iter()
                        .map(|seed| {
                            translate_slice::<u8>(memory_mapping, seed.addr, seed.len, loader_id)
                        })
                        .collect::<Result<Vec<_>, EbpfError<BpfError>>>()?;
                    Pubkey::create_program_address(&seeds_bytes, program_id)
                        .map_err(|err| SyscallError::BadSeeds(err).into())
                })
                .collect::<Result<Vec<_>, EbpfError<BpfError>>>()?)
        } else {
            Ok(vec![])
        }
    }
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallInvokeSignedC<'a, 'b> {
    fn call(
        &mut self,
        instruction_addr: u64,
        account_infos_addr: u64,
        account_infos_len: u64,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        *result = call(
            self,
            instruction_addr,
            account_infos_addr,
            account_infos_len,
            signers_seeds_addr,
            signers_seeds_len,
            memory_mapping,
        );
    }
}

fn get_translated_accounts<'a, T, F>(
    message: &Message,
    account_info_keys: &[&Pubkey],
    account_infos: &[T],
    invoke_context: &mut InvokeContext,
    orig_data_lens: &[usize],
    do_translate: F,
) -> Result<TranslatedAccounts<'a>, EbpfError<BpfError>>
where
    F: Fn(&T, &InvokeContext) -> Result<CallerAccount<'a>, EbpfError<BpfError>>,
{
    let keyed_accounts = invoke_context
        .get_instruction_keyed_accounts()
        .map_err(SyscallError::InstructionError)?;
    let mut account_indices = Vec::with_capacity(message.account_keys.len());
    let mut accounts = Vec::with_capacity(message.account_keys.len());
    for (i, account_key) in message.account_keys.iter().enumerate() {
        if let Some((account_index, account)) = invoke_context.get_account(account_key) {
            if i == message.instructions[0].program_id_index as usize
                || account.borrow().executable()
            {
                // Use the known account
                account_indices.push(account_index);
                accounts.push((account, None));
                continue;
            } else if let Some(caller_account_index) =
                account_info_keys.iter().position(|key| *key == account_key)
            {
                let mut caller_account =
                    do_translate(&account_infos[caller_account_index], invoke_context)?;
                {
                    let mut account = account.borrow_mut();
                    account.copy_into_owner_from_slice(caller_account.owner.as_ref());
                    account.set_data_from_slice(caller_account.data);
                    account.set_lamports(*caller_account.lamports);
                    account.set_executable(caller_account.executable);
                    account.set_rent_epoch(caller_account.rent_epoch);
                }
                let caller_account = if message.is_writable(i) {
                    if let Some(orig_data_len_index) = keyed_accounts
                        .iter()
                        .position(|keyed_account| keyed_account.unsigned_key() == account_key)
                        .map(|index| {
                            // index starts at first instruction account
                            index - keyed_accounts.len().saturating_sub(orig_data_lens.len())
                        })
                        .and_then(|index| {
                            if index >= orig_data_lens.len() {
                                None
                            } else {
                                Some(index)
                            }
                        })
                    {
                        caller_account.original_data_len = orig_data_lens[orig_data_len_index];
                    } else {
                        ic_msg!(
                            invoke_context,
                            "Internal error: index mismatch for account {}",
                            account_key
                        );
                        return Err(SyscallError::InstructionError(
                            InstructionError::MissingAccount,
                        )
                        .into());
                    }

                    Some(caller_account)
                } else {
                    None
                };
                account_indices.push(account_index);
                accounts.push((account, caller_account));
                continue;
            }
        }
        ic_msg!(
            invoke_context,
            "Instruction references an unknown account {}",
            account_key
        );
        return Err(SyscallError::InstructionError(InstructionError::MissingAccount).into());
    }

    Ok((account_indices, accounts))
}

fn check_instruction_size(
    num_accounts: usize,
    data_len: usize,
    invoke_context: &mut InvokeContext,
) -> Result<(), EbpfError<BpfError>> {
    let size = num_accounts
        .saturating_mul(size_of::<AccountMeta>())
        .saturating_add(data_len);
    let max_size = invoke_context.get_compute_budget().max_cpi_instruction_size;
    if size > max_size {
        return Err(SyscallError::InstructionTooLarge(size, max_size).into());
    }
    Ok(())
}

fn check_account_infos(
    len: usize,
    invoke_context: &mut InvokeContext,
) -> Result<(), EbpfError<BpfError>> {
    if len * size_of::<Pubkey>() > invoke_context.get_compute_budget().max_cpi_instruction_size {
        // Cap the number of account_infos a caller can pass to approximate
        // maximum that accounts that could be passed in an instruction
        return Err(SyscallError::TooManyAccounts.into());
    };
    Ok(())
}

fn check_authorized_program(
    program_id: &Pubkey,
    instruction_data: &[u8],
    invoke_context: &InvokeContext,
) -> Result<(), EbpfError<BpfError>> {
    #[allow(clippy::blocks_in_if_conditions)]
    if native_loader::check_id(program_id)
        || bpf_loader::check_id(program_id)
        || bpf_loader_deprecated::check_id(program_id)
        || (bpf_loader_upgradeable::check_id(program_id)
            && !(bpf_loader_upgradeable::is_upgrade_instruction(instruction_data)
                || bpf_loader_upgradeable::is_set_authority_instruction(instruction_data)
                || bpf_loader_upgradeable::is_close_instruction(instruction_data)))
        || (invoke_context
            .feature_set
            .is_active(&prevent_calling_precompiles_as_programs::id())
            && is_precompile(program_id, |feature_id: &Pubkey| {
                invoke_context.feature_set.is_active(feature_id)
            }))
    {
        return Err(SyscallError::ProgramNotSupported(*program_id).into());
    }
    Ok(())
}

/// Call process instruction, common to both Rust and C
fn call<'a, 'b: 'a>(
    syscall: &mut dyn SyscallInvokeSigned<'a, 'b>,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    memory_mapping: &MemoryMapping,
) -> Result<u64, EbpfError<BpfError>> {
    let mut invoke_context = syscall.get_context_mut()?;
    invoke_context
        .get_compute_meter()
        .consume(invoke_context.get_compute_budget().invoke_units)?;
    let do_support_realloc = invoke_context
        .feature_set
        .is_active(&do_support_realloc::id());

    // Translate and verify caller's data
    let loader_id = invoke_context
        .get_loader()
        .map_err(SyscallError::InstructionError)?;
    let instruction = syscall.translate_instruction(
        &loader_id,
        instruction_addr,
        memory_mapping,
        *invoke_context,
    )?;
    let caller_program_id = invoke_context
        .get_caller()
        .map_err(SyscallError::InstructionError)?;
    let signers = syscall.translate_signers(
        &loader_id,
        caller_program_id,
        signers_seeds_addr,
        signers_seeds_len,
        memory_mapping,
    )?;
    let stack_height = invoke_context.get_stack_height();
    let (message, caller_write_privileges, program_indices) = invoke_context
        .create_message(&instruction, &signers)
        .map_err(SyscallError::InstructionError)?;
    check_authorized_program(&instruction.program_id, &instruction.data, *invoke_context)?;
    let (account_indices, mut accounts) = syscall.translate_accounts(
        &loader_id,
        &message,
        account_infos_addr,
        account_infos_len,
        memory_mapping,
        *invoke_context,
    )?;

    // Record the instruction
    invoke_context.record_instruction(stack_height.saturating_add(1), instruction);

    // Process instruction
    let message = SanitizedMessage::Legacy(message);
    invoke_context
        .process_instruction(
            &message,
            &message.instructions()[0],
            &program_indices,
            &account_indices,
            &caller_write_privileges,
            &mut ExecuteTimings::default(),
        )
        .result
        .map_err(SyscallError::InstructionError)?;

    // Copy results back to caller
    for (callee_account, caller_account) in accounts.iter_mut() {
        if let Some(caller_account) = caller_account {
            let callee_account = callee_account.borrow();
            *caller_account.lamports = callee_account.lamports();
            *caller_account.owner = *callee_account.owner();
            let new_len = callee_account.data().len();
            if caller_account.data.len() != new_len {
                if !do_support_realloc && !caller_account.data.is_empty() {
                    // Only support for `CreateAccount` at this time.
                    // Need a way to limit total realloc size across multiple CPI calls
                    ic_msg!(
                        invoke_context,
                        "Inner instructions do not support realloc, only SystemProgram::CreateAccount",
                    );
                    return Err(
                        SyscallError::InstructionError(InstructionError::InvalidRealloc).into(),
                    );
                }
                let data_overflow = if do_support_realloc {
                    new_len > caller_account.original_data_len + MAX_PERMITTED_DATA_INCREASE
                } else {
                    new_len > caller_account.data.len() + MAX_PERMITTED_DATA_INCREASE
                };
                if data_overflow {
                    ic_msg!(
                        invoke_context,
                        "Account data size realloc limited to {} in inner instructions",
                        MAX_PERMITTED_DATA_INCREASE
                    );
                    return Err(
                        SyscallError::InstructionError(InstructionError::InvalidRealloc).into(),
                    );
                }
                if new_len < caller_account.data.len() {
                    caller_account.data[new_len..].fill(0);
                }
                caller_account.data = translate_slice_mut::<u8>(
                    memory_mapping,
                    caller_account.vm_data_addr,
                    new_len as u64,
                    &bpf_loader_deprecated::id(), // Don't care since it is byte aligned
                )?;
                *caller_account.ref_to_len_in_vm = new_len as u64;
                *caller_account.serialized_len_ptr = new_len as u64;
            }
            caller_account
                .data
                .copy_from_slice(&callee_account.data()[0..new_len]);
        }
    }

    Ok(SUCCESS)
}

// Return data handling
pub struct SyscallSetReturnData<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallSetReturnData<'a, 'b> {
    fn call(
        &mut self,
        addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let mut invoke_context = question_mark!(
            self.invoke_context
                .try_borrow_mut()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );

        let budget = invoke_context.get_compute_budget();

        question_mark!(
            invoke_context
                .get_compute_meter()
                .consume(len / budget.cpi_bytes_per_unit + budget.syscall_base_cost),
            result
        );

        if len > MAX_RETURN_DATA as u64 {
            *result = Err(SyscallError::ReturnDataTooLarge(len, MAX_RETURN_DATA as u64).into());
            return;
        }

        let return_data = if len == 0 {
            Vec::new()
        } else {
            question_mark!(
                translate_slice::<u8>(memory_mapping, addr, len, &loader_id),
                result
            )
            .to_vec()
        };
        let program_id = question_mark!(
            invoke_context
                .get_caller()
                .map_err(SyscallError::InstructionError),
            result
        );
        invoke_context.return_data = (*program_id, return_data);

        *result = Ok(0);
    }
}

pub struct SyscallGetReturnData<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallGetReturnData<'a, 'b> {
    fn call(
        &mut self,
        return_data_addr: u64,
        mut length: u64,
        program_id_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );

        let budget = invoke_context.get_compute_budget();

        question_mark!(
            invoke_context
                .get_compute_meter()
                .consume(budget.syscall_base_cost),
            result
        );

        let (program_id, return_data) = &invoke_context.return_data;
        length = length.min(return_data.len() as u64);
        if length != 0 {
            question_mark!(
                invoke_context
                    .get_compute_meter()
                    .consume((length + size_of::<Pubkey>() as u64) / budget.cpi_bytes_per_unit),
                result
            );

            let return_data_result = question_mark!(
                translate_slice_mut::<u8>(memory_mapping, return_data_addr, length, &loader_id),
                result
            );

            return_data_result.copy_from_slice(&return_data[..length as usize]);

            let program_id_result = question_mark!(
                translate_slice_mut::<Pubkey>(memory_mapping, program_id_addr, 1, &loader_id),
                result
            );

            program_id_result[0] = *program_id;
        }

        // Return the actual length, rather the length returned
        *result = Ok(return_data.len() as u64);
    }
}

// Log data handling
pub struct SyscallLogData<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallLogData<'a, 'b> {
    fn call(
        &mut self,
        addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );

        let budget = invoke_context.get_compute_budget();

        question_mark!(
            invoke_context
                .get_compute_meter()
                .consume(budget.syscall_base_cost),
            result
        );

        let untranslated_fields = question_mark!(
            translate_slice::<&[u8]>(memory_mapping, addr, len, &loader_id),
            result
        );

        question_mark!(
            invoke_context.get_compute_meter().consume(
                budget
                    .syscall_base_cost
                    .saturating_mul(untranslated_fields.len() as u64)
            ),
            result
        );
        question_mark!(
            invoke_context.get_compute_meter().consume(
                untranslated_fields
                    .iter()
                    .fold(0, |total, e| total.saturating_add(e.len() as u64))
            ),
            result
        );

        let mut fields = Vec::with_capacity(untranslated_fields.len());

        for untranslated_field in untranslated_fields {
            fields.push(question_mark!(
                translate_slice::<u8>(
                    memory_mapping,
                    untranslated_field.as_ptr() as *const _ as u64,
                    untranslated_field.len() as u64,
                    &loader_id,
                ),
                result
            ));
        }

        let log_collector = invoke_context.get_log_collector();

        stable_log::program_data(&log_collector, &fields);

        *result = Ok(0);
    }
}

pub struct SyscallGetProcessedSiblingInstruction<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallGetProcessedSiblingInstruction<'a, 'b> {
    fn call(
        &mut self,
        index: u64,
        meta_addr: u64,
        program_id_addr: u64,
        data_addr: u64,
        accounts_addr: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let loader_id = question_mark!(
            invoke_context
                .get_loader()
                .map_err(SyscallError::InstructionError),
            result
        );

        let budget = invoke_context.get_compute_budget();
        question_mark!(
            invoke_context
                .get_compute_meter()
                .consume(budget.syscall_base_cost),
            result
        );

        let stack_height = invoke_context.get_stack_height();
        let instruction_trace = invoke_context.get_instruction_trace();
        let instruction = if stack_height == TRANSACTION_LEVEL_STACK_HEIGHT {
            // pick one of the top-level instructions
            instruction_trace
                .len()
                .checked_sub(2)
                .and_then(|result| result.checked_sub(index as usize))
                .and_then(|index| instruction_trace.get(index))
                .and_then(|instruction_recorder| instruction_recorder.get(0))
        } else {
            // Walk the last list of inner instructions
            instruction_trace
                .last()
                .and_then(|inners| inners.find(stack_height, index as usize))
        };

        if let Some(instruction) = instruction {
            let ProcessedSiblingInstruction {
                data_len,
                accounts_len,
            } = question_mark!(
                translate_type_mut::<ProcessedSiblingInstruction>(
                    memory_mapping,
                    meta_addr,
                    &loader_id
                ),
                result
            );

            if *data_len == instruction.data.len() && *accounts_len == instruction.accounts.len() {
                let program_id = question_mark!(
                    translate_type_mut::<Pubkey>(memory_mapping, program_id_addr, &loader_id),
                    result
                );
                let data = question_mark!(
                    translate_slice_mut::<u8>(
                        memory_mapping,
                        data_addr,
                        *data_len as u64,
                        &loader_id,
                    ),
                    result
                );
                let accounts = question_mark!(
                    translate_slice_mut::<AccountMeta>(
                        memory_mapping,
                        accounts_addr,
                        *accounts_len as u64,
                        &loader_id,
                    ),
                    result
                );

                *program_id = instruction.program_id;
                data.clone_from_slice(instruction.data.as_slice());
                accounts.clone_from_slice(instruction.accounts.as_slice());
            }
            *data_len = instruction.data.len();
            *accounts_len = instruction.accounts.len();
            *result = Ok(true as u64);
            return;
        }
        *result = Ok(false as u64);
    }
}

pub struct SyscallGetStackHeight<'a, 'b> {
    invoke_context: Rc<RefCell<&'a mut InvokeContext<'b>>>,
}
impl<'a, 'b> SyscallObject<BpfError> for SyscallGetStackHeight<'a, 'b> {
    fn call(
        &mut self,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );

        let budget = invoke_context.get_compute_budget();
        question_mark!(
            invoke_context
                .get_compute_meter()
                .consume(budget.syscall_base_cost),
            result
        );

        *result = Ok(invoke_context.get_stack_height() as u64);
    }
}

