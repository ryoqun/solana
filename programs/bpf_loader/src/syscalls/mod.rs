pub use self::{
    cpi::{SyscallInvokeSignedC, SyscallInvokeSignedRust},
    logging::{
        SyscallLog, SyscallLogBpfComputeUnits, SyscallLogData, SyscallLogPubkey, SyscallLogU64,
    },
    mem_ops::{SyscallMemcmp, SyscallMemcpy, SyscallMemmove, SyscallMemset},
    sysvar::{
        SyscallGetClockSysvar, SyscallGetEpochScheduleSysvar, SyscallGetFeesSysvar,
        SyscallGetRentSysvar,
    },
};
#[allow(deprecated)]
use {
    crate::{allocator_bump::BpfAllocator, BpfError},
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
        verifier::RequisiteVerifier,
        vm::{EbpfVm, SyscallObject, SyscallRegistry},
    },
    solana_sdk::{
        account::{ReadableAccount, WritableAccount},
        account_info::AccountInfo,
        blake3, bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable,
        entrypoint::{BPF_ALIGN_OF_U128, MAX_PERMITTED_DATA_INCREASE, SUCCESS},
        feature_set::{
            self, blake3_syscall_enabled, check_physical_overlapping, check_slice_translation_size,
            check_syscall_outputs_do_not_overlap, curve25519_syscall_enabled, disable_fees_sysvar,
            enable_early_verification_of_account_modifications, libsecp256k1_0_5_upgrade_enabled,
            limit_secp256k1_recovery_id, prevent_calling_precompiles_as_programs,
            syscall_saturated_math,
        },
        hash::{Hasher, HASH_BYTES},
        instruction::{
            AccountMeta, Instruction, InstructionError, ProcessedSiblingInstruction,
            TRANSACTION_LEVEL_STACK_HEIGHT,
        },
        keccak, native_loader,
        precompiles::is_precompile,
        program::MAX_RETURN_DATA,
        program_stubs::is_nonoverlapping,
        pubkey::{Pubkey, PubkeyError, MAX_SEEDS, MAX_SEED_LEN},
        secp256k1_recover::{
            Secp256k1RecoverError, SECP256K1_PUBLIC_KEY_LENGTH, SECP256K1_SIGNATURE_LENGTH,
        },
        sysvar::{Sysvar, SysvarId},
        transaction_context::InstructionAccount,
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

mod cpi;
mod logging;
mod mem_ops;
mod sysvar;

/// Maximum signers
pub const MAX_SIGNERS: usize = 16;

/// Error definitions
#[derive(Debug, ThisError, PartialEq, Eq)]
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
    #[error("InvalidLength")]
    InvalidLength,
    #[error("Invoked an instruction with data that is too large ({data_len} > {max_data_len})")]
    MaxInstructionDataLenExceeded { data_len: u64, max_data_len: u64 },
    #[error("Invoked an instruction with too many accounts ({num_accounts} > {max_accounts})")]
    MaxInstructionAccountsExceeded {
        num_accounts: u64,
        max_accounts: u64,
    },
    #[error("Invoked an instruction with too many account info's ({num_account_infos} > {max_account_infos})")]
    MaxInstructionAccountInfosExceeded {
        num_account_infos: u64,
        max_account_infos: u64,
    },
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

macro_rules! register_feature_gated_syscall {
    ($syscall_registry:expr, $is_feature_active:expr, $name:expr, $init:expr, $call:expr $(,)?) => {
        if $is_feature_active {
            $syscall_registry.register_syscall_by_name($name, $init, $call)
        } else {
            Ok(())
        }
    };
}

pub fn register_syscalls(
    invoke_context: &mut InvokeContext,
    disable_deploy_of_alloc_free_syscall: bool,
) -> Result<SyscallRegistry, EbpfError<BpfError>> {
    let blake3_syscall_enabled = invoke_context
        .feature_set
        .is_active(&blake3_syscall_enabled::id());
    let curve25519_syscall_enabled = invoke_context
        .feature_set
        .is_active(&curve25519_syscall_enabled::id());
    let disable_fees_sysvar = invoke_context
        .feature_set
        .is_active(&disable_fees_sysvar::id());

    let mut syscall_registry = SyscallRegistry::default();

    // Abort
    syscall_registry.register_syscall_by_name(b"abort", SyscallAbort::init, SyscallAbort::call)?;

    // Panic
    syscall_registry.register_syscall_by_name(
        b"sol_panic_",
        SyscallPanic::init,
        SyscallPanic::call,
    )?;

    // Logging
    syscall_registry.register_syscall_by_name(b"sol_log_", SyscallLog::init, SyscallLog::call)?;
    syscall_registry.register_syscall_by_name(
        b"sol_log_64_",
        SyscallLogU64::init,
        SyscallLogU64::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_log_compute_units_",
        SyscallLogBpfComputeUnits::init,
        SyscallLogBpfComputeUnits::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_log_pubkey",
        SyscallLogPubkey::init,
        SyscallLogPubkey::call,
    )?;

    // Program defined addresses (PDA)
    syscall_registry.register_syscall_by_name(
        b"sol_create_program_address",
        SyscallCreateProgramAddress::init,
        SyscallCreateProgramAddress::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_try_find_program_address",
        SyscallTryFindProgramAddress::init,
        SyscallTryFindProgramAddress::call,
    )?;

    // Sha256
    syscall_registry.register_syscall_by_name(
        b"sol_sha256",
        SyscallSha256::init,
        SyscallSha256::call,
    )?;

    // Keccak256
    syscall_registry.register_syscall_by_name(
        b"sol_keccak256",
        SyscallKeccak256::init,
        SyscallKeccak256::call,
    )?;

    // Secp256k1 Recover
    syscall_registry.register_syscall_by_name(
        b"sol_secp256k1_recover",
        SyscallSecp256k1Recover::init,
        SyscallSecp256k1Recover::call,
    )?;

    // Blake3
    register_feature_gated_syscall!(
        syscall_registry,
        blake3_syscall_enabled,
        b"sol_blake3",
        SyscallBlake3::init,
        SyscallBlake3::call,
    )?;

    // Elliptic Curve Point Validation
    //
    // TODO: add group operations and multiscalar multiplications
    register_feature_gated_syscall!(
        syscall_registry,
        curve25519_syscall_enabled,
        b"sol_curve_validate_point",
        SyscallCurvePointValidation::init,
        SyscallCurvePointValidation::call,
    )?;
    register_feature_gated_syscall!(
        syscall_registry,
        curve25519_syscall_enabled,
        b"sol_curve_group_op",
        SyscallCurveGroupOps::init,
        SyscallCurveGroupOps::call,
    )?;

    // Sysvars
    syscall_registry.register_syscall_by_name(
        b"sol_get_clock_sysvar",
        SyscallGetClockSysvar::init,
        SyscallGetClockSysvar::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_get_epoch_schedule_sysvar",
        SyscallGetEpochScheduleSysvar::init,
        SyscallGetEpochScheduleSysvar::call,
    )?;
    register_feature_gated_syscall!(
        syscall_registry,
        !disable_fees_sysvar,
        b"sol_get_fees_sysvar",
        SyscallGetFeesSysvar::init,
        SyscallGetFeesSysvar::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_get_rent_sysvar",
        SyscallGetRentSysvar::init,
        SyscallGetRentSysvar::call,
    )?;

    // Memory ops
    syscall_registry.register_syscall_by_name(
        b"sol_memcpy_",
        SyscallMemcpy::init,
        SyscallMemcpy::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_memmove_",
        SyscallMemmove::init,
        SyscallMemmove::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_memcmp_",
        SyscallMemcmp::init,
        SyscallMemcmp::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_memset_",
        SyscallMemset::init,
        SyscallMemset::call,
    )?;

    // Cross-program invocation
    syscall_registry.register_syscall_by_name(
        b"sol_invoke_signed_c",
        SyscallInvokeSignedC::init,
        SyscallInvokeSignedC::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_invoke_signed_rust",
        SyscallInvokeSignedRust::init,
        SyscallInvokeSignedRust::call,
    )?;

    // Memory allocator
    register_feature_gated_syscall!(
        syscall_registry,
        !disable_deploy_of_alloc_free_syscall,
        b"sol_alloc_free_",
        SyscallAllocFree::init,
        SyscallAllocFree::call,
    )?;

    // Return data
    syscall_registry.register_syscall_by_name(
        b"sol_set_return_data",
        SyscallSetReturnData::init,
        SyscallSetReturnData::call,
    )?;
    syscall_registry.register_syscall_by_name(
        b"sol_get_return_data",
        SyscallGetReturnData::init,
        SyscallGetReturnData::call,
    )?;

    // Log data
    syscall_registry.register_syscall_by_name(
        b"sol_log_data",
        SyscallLogData::init,
        SyscallLogData::call,
    )?;

    // Processed sibling instructions
    syscall_registry.register_syscall_by_name(
        b"sol_get_processed_sibling_instruction",
        SyscallGetProcessedSiblingInstruction::init,
        SyscallGetProcessedSiblingInstruction::call,
    )?;

    // Stack height
    syscall_registry.register_syscall_by_name(
        b"sol_get_stack_height",
        SyscallGetStackHeight::init,
        SyscallGetStackHeight::call,
    )?;

    Ok(syscall_registry)
}

pub fn bind_syscall_context_objects<'a, 'b>(
    vm: &mut EbpfVm<'a, RequisiteVerifier, BpfError, crate::ThisInstructionMeter>,
    invoke_context: &'a mut InvokeContext<'b>,
    heap: AlignedMemory,
    orig_account_lengths: Vec<usize>,
) -> Result<(), EbpfError<BpfError>> {
    let check_aligned = bpf_loader_deprecated::id()
        != invoke_context
            .transaction_context
            .get_current_instruction_context()
            .and_then(|instruction_context| {
                instruction_context
                    .try_borrow_last_program_account(invoke_context.transaction_context)
            })
            .map(|program_account| *program_account.get_owner())
            .map_err(SyscallError::InstructionError)?;
    let check_size = invoke_context
        .feature_set
        .is_active(&check_slice_translation_size::id());

    invoke_context
        .set_syscall_context(
            check_aligned,
            check_size,
            orig_account_lengths,
            Rc::new(RefCell::new(BpfAllocator::new(heap, ebpf::MM_HEAP_START))),
        )
        .map_err(SyscallError::InstructionError)?;

    let invoke_context = Rc::new(RefCell::new(invoke_context));
    vm.bind_syscall_context_objects(invoke_context)?;

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
    check_aligned: bool,
) -> Result<&'a mut T, EbpfError<BpfError>> {
    let host_addr = translate(memory_mapping, access_type, vm_addr, size_of::<T>() as u64)?;

    if check_aligned && (host_addr as *mut T as usize).wrapping_rem(align_of::<T>()) != 0 {
        return Err(SyscallError::UnalignedPointer.into());
    }
    Ok(unsafe { &mut *(host_addr as *mut T) })
}
fn translate_type_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    check_aligned: bool,
) -> Result<&'a mut T, EbpfError<BpfError>> {
    translate_type_inner::<T>(memory_mapping, AccessType::Store, vm_addr, check_aligned)
}
fn translate_type<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    check_aligned: bool,
) -> Result<&'a T, EbpfError<BpfError>> {
    translate_type_inner::<T>(memory_mapping, AccessType::Load, vm_addr, check_aligned)
        .map(|value| &*value)
}

fn translate_slice_inner<'a, T>(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
    check_size: bool,
) -> Result<&'a mut [T], EbpfError<BpfError>> {
    if len == 0 {
        return Ok(&mut []);
    }

    let total_size = len.saturating_mul(size_of::<T>() as u64);
    if check_size & isize::try_from(total_size).is_err() {
        return Err(SyscallError::InvalidLength.into());
    }

    let host_addr = translate(memory_mapping, access_type, vm_addr, total_size)?;

    if check_aligned && (host_addr as *mut T as usize).wrapping_rem(align_of::<T>()) != 0 {
        return Err(SyscallError::UnalignedPointer.into());
    }
    Ok(unsafe { from_raw_parts_mut(host_addr as *mut T, len as usize) })
}
fn translate_slice_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
    check_size: bool,
) -> Result<&'a mut [T], EbpfError<BpfError>> {
    translate_slice_inner::<T>(
        memory_mapping,
        AccessType::Store,
        vm_addr,
        len,
        check_aligned,
        check_size,
    )
}
fn translate_slice<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
    check_size: bool,
) -> Result<&'a [T], EbpfError<BpfError>> {
    translate_slice_inner::<T>(
        memory_mapping,
        AccessType::Load,
        vm_addr,
        len,
        check_aligned,
        check_size,
    )
    .map(|value| &*value)
}

/// Take a virtual pointer to a string (points to BPF VM memory space), translate it
/// pass it to a user-defined work function
fn translate_string_and_do(
    memory_mapping: &MemoryMapping,
    addr: u64,
    len: u64,
    check_aligned: bool,
    check_size: bool,
    work: &mut dyn FnMut(&str) -> Result<u64, EbpfError<BpfError>>,
) -> Result<u64, EbpfError<BpfError>> {
    let buf = translate_slice::<u8>(memory_mapping, addr, len, check_aligned, check_size)?;
    let i = match buf.iter().position(|byte| *byte == 0) {
        Some(i) => i,
        None => len as usize,
    };
    let msg = buf.get(..i).ok_or(SyscallError::InvalidLength)?;
    match from_utf8(msg) {
        Ok(message) => work(message),
        Err(err) => Err(SyscallError::InvalidString(err, msg.to_vec()).into()),
    }
}

type SyscallContext<'a, 'b> = Rc<RefCell<&'a mut InvokeContext<'b>>>;

#[macro_export]
macro_rules! declare_syscall {
    ($(#[$attr:meta])* $name:ident, $call:item) => {
        $(#[$attr])*
        pub struct $name<'a, 'b> {
            pub(crate) invoke_context: SyscallContext<'a, 'b>,
        }
        impl<'a, 'b> $name<'a, 'b> {
            pub fn init(
                invoke_context: SyscallContext<'a, 'b>,
            ) -> Box<(dyn SyscallObject<BpfError> + 'a)> {
                Box::new(Self { invoke_context })
            }
        }
        impl<'a, 'b> SyscallObject<BpfError> for $name<'a, 'b> {
            $call
        }
    };
}

declare_syscall!(
    /// Abort syscall functions, called when the BPF program calls `abort()`
    /// LLVM will insert calls to `abort()` if it detects an untenable situation,
    /// `abort()` is not intended to be called explicitly by the program.
    /// Causes the BPF program to be halted immediately
    SyscallAbort,
    fn call(
        &mut self,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let _ = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        *result = Err(SyscallError::Abort.into());
    }
);

declare_syscall!(
    /// Panic syscall function, called when the BPF program calls 'sol_panic_()`
    /// Causes the BPF program to be halted immediately
    SyscallPanic,
    fn call(
        &mut self,
        file: u64,
        len: u64,
        line: u64,
        column: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        question_mark!(invoke_context.get_compute_meter().consume(len), result);

        *result = translate_string_and_do(
            memory_mapping,
            file,
            len,
            invoke_context.get_check_aligned(),
            invoke_context.get_check_size(),
            &mut |string: &str| Err(SyscallError::Panic(string.to_string(), line, column).into()),
        );
    }
);

declare_syscall!(
    /// Dynamic memory allocation syscall called when the BPF program calls
    /// `sol_alloc_free_()`.  The allocator is expected to allocate/free
    /// from/to a given chunk of memory and enforce size restrictions.  The
    /// memory chunk is given to the allocator during allocator creation and
    /// information about that memory (start address and size) is passed
    /// to the VM to use for enforcement.
    SyscallAllocFree,
    fn call(
        &mut self,
        size: u64,
        free_addr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let allocator = question_mark!(
            invoke_context
                .get_allocator()
                .map_err(SyscallError::InstructionError),
            result
        );
        let mut allocator = question_mark!(
            allocator
                .try_borrow_mut()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );

        let align = if invoke_context.get_check_aligned() {
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
            match allocator.alloc(layout) {
                Ok(addr) => Ok(addr as u64),
                Err(_) => Ok(0),
            }
        } else {
            allocator.dealloc(free_addr, layout);
            Ok(0)
        };
    }
);

fn translate_and_check_program_address_inputs<'a>(
    seeds_addr: u64,
    seeds_len: u64,
    program_id_addr: u64,
    memory_mapping: &mut MemoryMapping,
    check_aligned: bool,
    check_size: bool,
) -> Result<(Vec<&'a [u8]>, &'a Pubkey), EbpfError<BpfError>> {
    let untranslated_seeds = translate_slice::<&[&u8]>(
        memory_mapping,
        seeds_addr,
        seeds_len,
        check_aligned,
        check_size,
    )?;
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
                check_aligned,
                check_size,
            )
        })
        .collect::<Result<Vec<_>, EbpfError<BpfError>>>()?;
    let program_id = translate_type::<Pubkey>(memory_mapping, program_id_addr, check_aligned)?;
    Ok((seeds, program_id))
}

declare_syscall!(
    /// Create a program address
    SyscallCreateProgramAddress,
    fn call(
        &mut self,
        seeds_addr: u64,
        seeds_len: u64,
        program_id_addr: u64,
        address_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
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

        let (seeds, program_id) = question_mark!(
            translate_and_check_program_address_inputs(
                seeds_addr,
                seeds_len,
                program_id_addr,
                memory_mapping,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size()
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
            translate_slice_mut::<u8>(
                memory_mapping,
                address_addr,
                32,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            ),
            result
        );
        address.copy_from_slice(new_address.as_ref());
        *result = Ok(0);
    }
);

declare_syscall!(
    /// Create a program address
    SyscallTryFindProgramAddress,
    fn call(
        &mut self,
        seeds_addr: u64,
        seeds_len: u64,
        program_id_addr: u64,
        address_addr: u64,
        bump_seed_addr: u64,
        memory_mapping: &mut MemoryMapping,
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

        let (seeds, program_id) = question_mark!(
            translate_and_check_program_address_inputs(
                seeds_addr,
                seeds_len,
                program_id_addr,
                memory_mapping,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size()
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
                        translate_type_mut::<u8>(
                            memory_mapping,
                            bump_seed_addr,
                            invoke_context.get_check_aligned()
                        ),
                        result
                    );
                    let address = question_mark!(
                        translate_slice_mut::<u8>(
                            memory_mapping,
                            address_addr,
                            32,
                            invoke_context.get_check_aligned(),
                            invoke_context.get_check_size(),
                        ),
                        result
                    );
                    if !is_nonoverlapping(
                        bump_seed_ref as *const _ as usize,
                        std::mem::size_of_val(bump_seed_ref),
                        address.as_ptr() as usize,
                        std::mem::size_of::<Pubkey>(),
                    ) && invoke_context
                        .feature_set
                        .is_active(&check_syscall_outputs_do_not_overlap::id())
                    {
                        *result = Err(SyscallError::CopyOverlapping.into());
                        return;
                    }
                    *bump_seed_ref = bump_seed[0];
                    address.copy_from_slice(new_address.as_ref());
                    *result = Ok(0);
                    return;
                }
            }
            bump_seed[0] = bump_seed[0].saturating_sub(1);
            question_mark!(invoke_context.get_compute_meter().consume(cost), result);
        }
        *result = Ok(1);
    }
);

declare_syscall!(
    /// SHA256
    SyscallSha256,
    fn call(
        &mut self,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let compute_budget = invoke_context.get_compute_budget();
        if compute_budget.sha256_max_slices < vals_len {
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

        let hash_result = question_mark!(
            translate_slice_mut::<u8>(
                memory_mapping,
                result_addr,
                HASH_BYTES as u64,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            ),
            result
        );
        let mut hasher = Hasher::default();
        if vals_len > 0 {
            let vals = question_mark!(
                translate_slice::<&[u8]>(
                    memory_mapping,
                    vals_addr,
                    vals_len,
                    invoke_context.get_check_aligned(),
                    invoke_context.get_check_size(),
                ),
                result
            );
            for val in vals.iter() {
                let bytes = question_mark!(
                    translate_slice::<u8>(
                        memory_mapping,
                        val.as_ptr() as u64,
                        val.len() as u64,
                        invoke_context.get_check_aligned(),
                        invoke_context.get_check_size(),
                    ),
                    result
                );
                let cost = compute_budget.mem_op_base_cost.max(
                    compute_budget
                        .sha256_byte_cost
                        .saturating_mul((val.len() as u64).saturating_div(2)),
                );
                question_mark!(invoke_context.get_compute_meter().consume(cost), result);
                hasher.hash(bytes);
            }
        }
        hash_result.copy_from_slice(&hasher.result().to_bytes());
        *result = Ok(0);
    }
);

declare_syscall!(
    // Keccak256
    SyscallKeccak256,
    fn call(
        &mut self,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let compute_budget = invoke_context.get_compute_budget();
        if compute_budget.sha256_max_slices < vals_len {
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

        let hash_result = question_mark!(
            translate_slice_mut::<u8>(
                memory_mapping,
                result_addr,
                keccak::HASH_BYTES as u64,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            ),
            result
        );
        let mut hasher = keccak::Hasher::default();
        if vals_len > 0 {
            let vals = question_mark!(
                translate_slice::<&[u8]>(
                    memory_mapping,
                    vals_addr,
                    vals_len,
                    invoke_context.get_check_aligned(),
                    invoke_context.get_check_size(),
                ),
                result
            );
            for val in vals.iter() {
                let bytes = question_mark!(
                    translate_slice::<u8>(
                        memory_mapping,
                        val.as_ptr() as u64,
                        val.len() as u64,
                        invoke_context.get_check_aligned(),
                        invoke_context.get_check_size(),
                    ),
                    result
                );
                let cost = compute_budget.mem_op_base_cost.max(
                    compute_budget
                        .sha256_byte_cost
                        .saturating_mul((val.len() as u64).saturating_div(2)),
                );
                question_mark!(invoke_context.get_compute_meter().consume(cost), result);
                hasher.hash(bytes);
            }
        }
        hash_result.copy_from_slice(&hasher.result().to_bytes());
        *result = Ok(0);
    }
);

declare_syscall!(
    /// secp256k1_recover
    SyscallSecp256k1Recover,
    fn call(
        &mut self,
        hash_addr: u64,
        recovery_id_val: u64,
        signature_addr: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
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

        let hash = question_mark!(
            translate_slice::<u8>(
                memory_mapping,
                hash_addr,
                keccak::HASH_BYTES as u64,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            ),
            result
        );
        let signature = question_mark!(
            translate_slice::<u8>(
                memory_mapping,
                signature_addr,
                SECP256K1_SIGNATURE_LENGTH as u64,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            ),
            result
        );
        let secp256k1_recover_result = question_mark!(
            translate_slice_mut::<u8>(
                memory_mapping,
                result_addr,
                SECP256K1_PUBLIC_KEY_LENGTH as u64,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
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
        let adjusted_recover_id_val = if invoke_context
            .feature_set
            .is_active(&limit_secp256k1_recovery_id::id())
        {
            match recovery_id_val.try_into() {
                Ok(adjusted_recover_id_val) => adjusted_recover_id_val,
                Err(_) => {
                    *result = Ok(Secp256k1RecoverError::InvalidRecoveryId.into());
                    return;
                }
            }
        } else {
            recovery_id_val as u8
        };
        let recovery_id = match libsecp256k1::RecoveryId::parse(adjusted_recover_id_val) {
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
);

declare_syscall!(
    // Elliptic Curve Point Validation
    //
    // Currently, only curve25519 Edwards and Ristretto representations are supported
    SyscallCurvePointValidation,
    fn call(
        &mut self,
        curve_id: u64,
        point_addr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        use solana_zk_token_sdk::curve25519::{curve_syscall_traits::*, edwards, ristretto};

        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );

        match curve_id {
            CURVE25519_EDWARDS => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_edwards_validate_point_cost;
                question_mark!(invoke_context.get_compute_meter().consume(cost), result);

                let point = question_mark!(
                    translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        point_addr,
                        invoke_context.get_check_aligned()
                    ),
                    result
                );

                if edwards::validate_edwards(point) {
                    *result = Ok(0);
                } else {
                    *result = Ok(1);
                }
            }
            CURVE25519_RISTRETTO => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_ristretto_validate_point_cost;
                question_mark!(invoke_context.get_compute_meter().consume(cost), result);

                let point = question_mark!(
                    translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        point_addr,
                        invoke_context.get_check_aligned()
                    ),
                    result
                );

                if ristretto::validate_ristretto(point) {
                    *result = Ok(0);
                } else {
                    *result = Ok(1);
                }
            }
            _ => {
                *result = Ok(1);
            }
        };
    }
);

declare_syscall!(
    // Elliptic Curve Group Operations
    //
    // Currently, only curve25519 Edwards and Ristretto representations are supported
    SyscallCurveGroupOps,
    fn call(
        &mut self,
        curve_id: u64,
        group_op: u64,
        left_input_addr: u64,
        right_input_addr: u64,
        result_point_addr: u64,
        memory_mapping: &mut MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        use solana_zk_token_sdk::curve25519::{
            curve_syscall_traits::*, edwards, ristretto, scalar,
        };

        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );

        match curve_id {
            CURVE25519_EDWARDS => match group_op {
                ADD => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_edwards_add_cost;
                    question_mark!(invoke_context.get_compute_meter().consume(cost), result);

                    let left_point = question_mark!(
                        translate_type::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            left_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );
                    let right_point = question_mark!(
                        translate_type::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            right_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );

                    if let Some(result_point) = edwards::add_edwards(left_point, right_point) {
                        *question_mark!(
                            translate_type_mut::<edwards::PodEdwardsPoint>(
                                memory_mapping,
                                result_point_addr,
                                invoke_context.get_check_aligned(),
                            ),
                            result
                        ) = result_point;
                    } else {
                        *result = Ok(1);
                    }
                }
                SUB => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_edwards_subtract_cost;
                    question_mark!(invoke_context.get_compute_meter().consume(cost), result);

                    let left_point = question_mark!(
                        translate_type::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            left_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );
                    let right_point = question_mark!(
                        translate_type::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            right_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );

                    if let Some(result_point) = edwards::subtract_edwards(left_point, right_point) {
                        *question_mark!(
                            translate_type_mut::<edwards::PodEdwardsPoint>(
                                memory_mapping,
                                result_point_addr,
                                invoke_context.get_check_aligned(),
                            ),
                            result
                        ) = result_point;
                    } else {
                        *result = Ok(1);
                    }
                }
                MUL => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_edwards_multiply_cost;
                    question_mark!(invoke_context.get_compute_meter().consume(cost), result);

                    let scalar = question_mark!(
                        translate_type::<scalar::PodScalar>(
                            memory_mapping,
                            left_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );
                    let input_point = question_mark!(
                        translate_type::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            right_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );

                    if let Some(result_point) = edwards::multiply_edwards(scalar, input_point) {
                        *question_mark!(
                            translate_type_mut::<edwards::PodEdwardsPoint>(
                                memory_mapping,
                                result_point_addr,
                                invoke_context.get_check_aligned(),
                            ),
                            result
                        ) = result_point;
                    } else {
                        *result = Ok(1);
                    }
                }
                _ => {
                    *result = Ok(1);
                }
            },

            CURVE25519_RISTRETTO => match group_op {
                ADD => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_ristretto_add_cost;
                    question_mark!(invoke_context.get_compute_meter().consume(cost), result);

                    let left_point = question_mark!(
                        translate_type::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            left_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );
                    let right_point = question_mark!(
                        translate_type::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            right_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );

                    if let Some(result_point) = ristretto::add_ristretto(left_point, right_point) {
                        *question_mark!(
                            translate_type_mut::<ristretto::PodRistrettoPoint>(
                                memory_mapping,
                                result_point_addr,
                                invoke_context.get_check_aligned(),
                            ),
                            result
                        ) = result_point;
                    } else {
                        *result = Ok(1);
                    }
                }
                SUB => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_ristretto_subtract_cost;
                    question_mark!(invoke_context.get_compute_meter().consume(cost), result);

                    let left_point = question_mark!(
                        translate_type::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            left_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );
                    let right_point = question_mark!(
                        translate_type::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            right_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );

                    if let Some(result_point) =
                        ristretto::subtract_ristretto(left_point, right_point)
                    {
                        *question_mark!(
                            translate_type_mut::<ristretto::PodRistrettoPoint>(
                                memory_mapping,
                                result_point_addr,
                                invoke_context.get_check_aligned(),
                            ),
                            result
                        ) = result_point;
                    } else {
                        *result = Ok(1);
                    }
                }
                MUL => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_ristretto_multiply_cost;
                    question_mark!(invoke_context.get_compute_meter().consume(cost), result);

                    let scalar = question_mark!(
                        translate_type::<scalar::PodScalar>(
                            memory_mapping,
                            left_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );
                    let input_point = question_mark!(
                        translate_type::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            right_input_addr,
                            invoke_context.get_check_aligned(),
                        ),
                        result
                    );

                    if let Some(result_point) = ristretto::multiply_ristretto(scalar, input_point) {
                        *question_mark!(
                            translate_type_mut::<ristretto::PodRistrettoPoint>(
                                memory_mapping,
                                result_point_addr,
                                invoke_context.get_check_aligned(),
                            ),
                            result
                        ) = result_point;
                    } else {
                        *result = Ok(1);
                    }
                }
                _ => {
                    *result = Ok(1);
                }
            },

            _ => {
                *result = Ok(1);
            }
        }
    }
);

declare_syscall!(
    // Blake3
    SyscallBlake3,
    fn call(
        &mut self,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let invoke_context = question_mark!(
            self.invoke_context
                .try_borrow()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let compute_budget = invoke_context.get_compute_budget();
        if compute_budget.sha256_max_slices < vals_len {
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

        let hash_result = question_mark!(
            translate_slice_mut::<u8>(
                memory_mapping,
                result_addr,
                blake3::HASH_BYTES as u64,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            ),
            result
        );
        let mut hasher = blake3::Hasher::default();
        if vals_len > 0 {
            let vals = question_mark!(
                translate_slice::<&[u8]>(
                    memory_mapping,
                    vals_addr,
                    vals_len,
                    invoke_context.get_check_aligned(),
                    invoke_context.get_check_size(),
                ),
                result
            );
            for val in vals.iter() {
                let bytes = question_mark!(
                    translate_slice::<u8>(
                        memory_mapping,
                        val.as_ptr() as u64,
                        val.len() as u64,
                        invoke_context.get_check_aligned(),
                        invoke_context.get_check_size(),
                    ),
                    result
                );
                let cost = compute_budget.mem_op_base_cost.max(
                    compute_budget
                        .sha256_byte_cost
                        .saturating_mul((val.len() as u64).saturating_div(2)),
                );
                question_mark!(invoke_context.get_compute_meter().consume(cost), result);
                hasher.hash(bytes);
            }
        }
        hash_result.copy_from_slice(&hasher.result().to_bytes());
        *result = Ok(0);
    }
);

declare_syscall!(
    /// Set return data
    SyscallSetReturnData,
    fn call(
        &mut self,
        addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let mut invoke_context = question_mark!(
            self.invoke_context
                .try_borrow_mut()
                .map_err(|_| SyscallError::InvokeContextBorrowFailed),
            result
        );
        let budget = invoke_context.get_compute_budget();

        let cost = if invoke_context
            .feature_set
            .is_active(&syscall_saturated_math::id())
        {
            len.saturating_div(budget.cpi_bytes_per_unit)
                .saturating_add(budget.syscall_base_cost)
        } else {
            #[allow(clippy::integer_arithmetic)]
            {
                len / budget.cpi_bytes_per_unit + budget.syscall_base_cost
            }
        };
        question_mark!(invoke_context.get_compute_meter().consume(cost), result);

        if len > MAX_RETURN_DATA as u64 {
            *result = Err(SyscallError::ReturnDataTooLarge(len, MAX_RETURN_DATA as u64).into());
            return;
        }

        let return_data = if len == 0 {
            Vec::new()
        } else {
            question_mark!(
                translate_slice::<u8>(
                    memory_mapping,
                    addr,
                    len,
                    invoke_context.get_check_aligned(),
                    invoke_context.get_check_size(),
                ),
                result
            )
            .to_vec()
        };
        let transaction_context = &mut invoke_context.transaction_context;
        let program_id = *question_mark!(
            transaction_context
                .get_current_instruction_context()
                .and_then(|instruction_context| instruction_context
                    .get_last_program_key(transaction_context))
                .map_err(SyscallError::InstructionError),
            result
        );
        question_mark!(
            transaction_context
                .set_return_data(program_id, return_data)
                .map_err(SyscallError::InstructionError),
            result
        );

        *result = Ok(0);
    }
);

declare_syscall!(
    /// Get return data
    SyscallGetReturnData,
    fn call(
        &mut self,
        return_data_addr: u64,
        mut length: u64,
        program_id_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
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

        let (program_id, return_data) = invoke_context.transaction_context.get_return_data();
        length = length.min(return_data.len() as u64);
        if length != 0 {
            let cost = if invoke_context
                .feature_set
                .is_active(&syscall_saturated_math::id())
            {
                length
                    .saturating_add(size_of::<Pubkey>() as u64)
                    .saturating_div(budget.cpi_bytes_per_unit)
            } else {
                #[allow(clippy::integer_arithmetic)]
                {
                    (length + size_of::<Pubkey>() as u64) / budget.cpi_bytes_per_unit
                }
            };
            question_mark!(invoke_context.get_compute_meter().consume(cost), result);

            let return_data_result = question_mark!(
                translate_slice_mut::<u8>(
                    memory_mapping,
                    return_data_addr,
                    length,
                    invoke_context.get_check_aligned(),
                    invoke_context.get_check_size(),
                ),
                result
            );

            let to_slice = return_data_result;
            let from_slice = question_mark!(
                return_data
                    .get(..length as usize)
                    .ok_or(SyscallError::InvokeContextBorrowFailed),
                result
            );
            if to_slice.len() != from_slice.len() {
                *result = Err(SyscallError::InvalidLength.into());
                return;
            }
            to_slice.copy_from_slice(from_slice);

            let program_id_result = question_mark!(
                translate_type_mut::<Pubkey>(
                    memory_mapping,
                    program_id_addr,
                    invoke_context.get_check_aligned()
                ),
                result
            );

            if !is_nonoverlapping(
                to_slice.as_ptr() as usize,
                length as usize,
                program_id_result as *const _ as usize,
                std::mem::size_of::<Pubkey>(),
            ) && invoke_context
                .feature_set
                .is_active(&check_syscall_outputs_do_not_overlap::id())
            {
                *result = Err(SyscallError::CopyOverlapping.into());
                return;
            }

            *program_id_result = *program_id;
        }

        // Return the actual length, rather the length returned
        *result = Ok(return_data.len() as u64);
    }
);

declare_syscall!(
    /// Get a processed sigling instruction
    SyscallGetProcessedSiblingInstruction,
    fn call(
        &mut self,
        index: u64,
        meta_addr: u64,
        program_id_addr: u64,
        data_addr: u64,
        accounts_addr: u64,
        memory_mapping: &mut MemoryMapping,
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

        let stack_height = invoke_context.get_stack_height();
        let instruction_trace = invoke_context.transaction_context.get_instruction_trace();
        let instruction_context = if stack_height == TRANSACTION_LEVEL_STACK_HEIGHT {
            // pick one of the top-level instructions
            instruction_trace
                .len()
                .checked_sub(2)
                .and_then(|result| result.checked_sub(index as usize))
                .and_then(|index| instruction_trace.get(index))
                .and_then(|instruction_list| instruction_list.first())
        } else {
            // Walk the last list of inner instructions
            instruction_trace.last().and_then(|inners| {
                let mut current_index = 0;
                inners.iter().rev().skip(1).find(|instruction_context| {
                    if stack_height == instruction_context.get_stack_height() {
                        if index == current_index {
                            return true;
                        } else {
                            current_index = current_index.saturating_add(1);
                        }
                    }
                    false
                })
            })
        };

        if let Some(instruction_context) = instruction_context {
            let result_header = question_mark!(
                translate_type_mut::<ProcessedSiblingInstruction>(
                    memory_mapping,
                    meta_addr,
                    invoke_context.get_check_aligned(),
                ),
                result
            );

            if result_header.data_len == (instruction_context.get_instruction_data().len() as u64)
                && result_header.accounts_len
                    == (instruction_context.get_number_of_instruction_accounts() as u64)
            {
                let program_id = question_mark!(
                    translate_type_mut::<Pubkey>(
                        memory_mapping,
                        program_id_addr,
                        invoke_context.get_check_aligned()
                    ),
                    result
                );
                let data = question_mark!(
                    translate_slice_mut::<u8>(
                        memory_mapping,
                        data_addr,
                        result_header.data_len as u64,
                        invoke_context.get_check_aligned(),
                        invoke_context.get_check_size(),
                    ),
                    result
                );
                let accounts = question_mark!(
                    translate_slice_mut::<AccountMeta>(
                        memory_mapping,
                        accounts_addr,
                        result_header.accounts_len as u64,
                        invoke_context.get_check_aligned(),
                        invoke_context.get_check_size(),
                    ),
                    result
                );

                if (!is_nonoverlapping(
                    result_header as *const _ as usize,
                    std::mem::size_of::<ProcessedSiblingInstruction>(),
                    program_id as *const _ as usize,
                    std::mem::size_of::<Pubkey>(),
                ) || !is_nonoverlapping(
                    result_header as *const _ as usize,
                    std::mem::size_of::<ProcessedSiblingInstruction>(),
                    accounts.as_ptr() as usize,
                    std::mem::size_of::<AccountMeta>()
                        .saturating_mul(result_header.accounts_len as usize),
                ) || !is_nonoverlapping(
                    result_header as *const _ as usize,
                    std::mem::size_of::<ProcessedSiblingInstruction>(),
                    data.as_ptr() as usize,
                    result_header.data_len as usize,
                ) || !is_nonoverlapping(
                    program_id as *const _ as usize,
                    std::mem::size_of::<Pubkey>(),
                    data.as_ptr() as usize,
                    result_header.data_len as usize,
                ) || !is_nonoverlapping(
                    program_id as *const _ as usize,
                    std::mem::size_of::<Pubkey>(),
                    accounts.as_ptr() as usize,
                    std::mem::size_of::<AccountMeta>()
                        .saturating_mul(result_header.accounts_len as usize),
                ) || !is_nonoverlapping(
                    data.as_ptr() as usize,
                    result_header.data_len as usize,
                    accounts.as_ptr() as usize,
                    std::mem::size_of::<AccountMeta>()
                        .saturating_mul(result_header.accounts_len as usize),
                )) && invoke_context
                    .feature_set
                    .is_active(&check_syscall_outputs_do_not_overlap::id())
                {
                    *result = Err(SyscallError::CopyOverlapping.into());
                    return;
                }

                *program_id = *question_mark!(
                    instruction_context
                        .get_last_program_key(invoke_context.transaction_context)
                        .map_err(SyscallError::InstructionError),
                    result
                );
                data.clone_from_slice(instruction_context.get_instruction_data());
                let account_metas = question_mark!(
                    (0..instruction_context.get_number_of_instruction_accounts())
                        .map(|instruction_account_index| Ok(AccountMeta {
                            pubkey: *invoke_context.get_key_of_account_at_index(
                                instruction_context
                                    .get_index_of_instruction_account_in_transaction(
                                        instruction_account_index
                                    )?
                            )?,
                            is_signer: instruction_context
                                .is_instruction_account_signer(instruction_account_index)?,
                            is_writable: instruction_context
                                .is_instruction_account_writable(instruction_account_index)?,
                        }))
                        .collect::<Result<Vec<_>, InstructionError>>()
                        .map_err(SyscallError::InstructionError),
                    result
                );
                accounts.clone_from_slice(account_metas.as_slice());
            }
            result_header.data_len = instruction_context.get_instruction_data().len() as u64;
            result_header.accounts_len =
                instruction_context.get_number_of_instruction_accounts() as u64;
            *result = Ok(true as u64);
            return;
        }
        *result = Ok(false as u64);
    }
);

declare_syscall!(
    /// Get current call stack height
    SyscallGetStackHeight,
    fn call(
        &mut self,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
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
);
