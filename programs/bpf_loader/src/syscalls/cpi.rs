use {
    super::*,
    crate::declare_syscall,
    solana_sdk::{
        feature_set::enable_bpf_loader_set_authority_checked_ix,
        stable_layout::stable_instruction::StableInstruction,
        syscalls::{
            MAX_CPI_ACCOUNT_INFOS, MAX_CPI_INSTRUCTION_ACCOUNTS, MAX_CPI_INSTRUCTION_DATA_LEN,
        },
        transaction_context::BorrowedAccount,
    },
    std::{mem, ptr, slice},
};

/// Host side representation of AccountInfo or SolAccountInfo passed to the CPI syscall.
///
/// At the start of a CPI, this can be different from the data stored in the
/// corresponding BorrowedAccount, and needs to be synched.
struct CallerAccount<'a> {
    lamports: &'a mut u64,
    owner: &'a mut Pubkey,
    // The original data length of the account at the start of the current
    // instruction. We use this to determine wether an account was shrunk or
    // grown before or after CPI, and to derive the vm address of the realloc
    // region.
    original_data_len: usize,
    // This points to the data section for this account, as serialized and
    // mapped inside the vm (see serialize_parameters() in
    // BpfExecutor::execute).
    //
    // When direct mapping is off, this includes both the account data _and_ the
    // realloc padding. When direct mapping is on, account data is mapped in its
    // own separate memory region which is directly mutated from inside the vm,
    // and the serialized buffer includes only the realloc padding.
    serialized_data: &'a mut [u8],
    // Given the corresponding input AccountInfo::data, vm_data_addr points to
    // the pointer field and ref_to_len_in_vm points to the length field.
    vm_data_addr: u64,
    ref_to_len_in_vm: &'a mut u64,
    // To be removed once `feature_set::move_serialized_len_ptr_in_cpi` is active everywhere
    serialized_len_ptr: *mut u64,
    executable: bool,
    rent_epoch: u64,
}

impl<'a> CallerAccount<'a> {
    // Create a CallerAccount given an AccountInfo.
    fn from_account_info(
        invoke_context: &InvokeContext,
        memory_mapping: &MemoryMapping,
        is_loader_deprecated: bool,
        _vm_addr: u64,
        account_info: &AccountInfo,
        original_data_len: usize,
    ) -> Result<CallerAccount<'a>, Error> {
        // account_info points to host memory. The addresses used internally are
        // in vm space so they need to be translated.

        let lamports = {
            // Double translate lamports out of RefCell
            let ptr = translate_type::<u64>(
                memory_mapping,
                account_info.lamports.as_ptr() as u64,
                invoke_context.get_check_aligned(),
            )?;
            translate_type_mut::<u64>(memory_mapping, *ptr, invoke_context.get_check_aligned())?
        };
        let owner = translate_type_mut::<Pubkey>(
            memory_mapping,
            account_info.owner as *const _ as u64,
            invoke_context.get_check_aligned(),
        )?;

        let (serialized_data, vm_data_addr, ref_to_len_in_vm, serialized_len_ptr) = {
            // Double translate data out of RefCell
            let data = *translate_type::<&[u8]>(
                memory_mapping,
                account_info.data.as_ptr() as *const _ as u64,
                invoke_context.get_check_aligned(),
            )?;

            consume_compute_meter(
                invoke_context,
                (data.len() as u64)
                    .saturating_div(invoke_context.get_compute_budget().cpi_bytes_per_unit),
            )?;

            let translated = translate(
                memory_mapping,
                AccessType::Store,
                (account_info.data.as_ptr() as *const u64 as u64)
                    .saturating_add(size_of::<u64>() as u64),
                8,
            )? as *mut u64;
            let ref_to_len_in_vm = unsafe { &mut *translated };
            let serialized_len_ptr = if invoke_context
                .feature_set
                .is_active(&feature_set::move_serialized_len_ptr_in_cpi::id())
            {
                std::ptr::null_mut()
            } else {
                let ref_of_len_in_input_buffer =
                    (data.as_ptr() as *const _ as u64).saturating_sub(8);
                translate_type_mut::<u64>(
                    memory_mapping,
                    ref_of_len_in_input_buffer,
                    invoke_context.get_check_aligned(),
                )?
            };
            let vm_data_addr = data.as_ptr() as u64;

            let bpf_account_data_direct_mapping = invoke_context
                .feature_set
                .is_active(&feature_set::bpf_account_data_direct_mapping::id());
            let serialized_data = translate_slice_mut::<u8>(
                memory_mapping,
                if bpf_account_data_direct_mapping {
                    vm_data_addr.saturating_add(original_data_len as u64)
                } else {
                    vm_data_addr
                },
                if bpf_account_data_direct_mapping {
                    if is_loader_deprecated {
                        0
                    } else {
                        MAX_PERMITTED_DATA_INCREASE
                    }
                } else {
                    data.len()
                } as u64,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            )?;

            (
                serialized_data,
                vm_data_addr,
                ref_to_len_in_vm,
                serialized_len_ptr,
            )
        };

        Ok(CallerAccount {
            lamports,
            owner,
            original_data_len,
            serialized_data,
            vm_data_addr,
            ref_to_len_in_vm,
            serialized_len_ptr,
            executable: account_info.executable,
            rent_epoch: account_info.rent_epoch,
        })
    }

    // Create a CallerAccount given a SolAccountInfo.
    fn from_sol_account_info(
        invoke_context: &InvokeContext,
        memory_mapping: &MemoryMapping,
        is_loader_deprecated: bool,
        vm_addr: u64,
        account_info: &SolAccountInfo,
        original_data_len: usize,
    ) -> Result<CallerAccount<'a>, Error> {
        // account_info points to host memory. The addresses used internally are
        // in vm space so they need to be translated.

        let lamports = translate_type_mut::<u64>(
            memory_mapping,
            account_info.lamports_addr,
            invoke_context.get_check_aligned(),
        )?;
        let owner = translate_type_mut::<Pubkey>(
            memory_mapping,
            account_info.owner_addr,
            invoke_context.get_check_aligned(),
        )?;
        let vm_data_addr = account_info.data_addr;

        consume_compute_meter(
            invoke_context,
            account_info
                .data_len
                .saturating_div(invoke_context.get_compute_budget().cpi_bytes_per_unit),
        )?;

        let bpf_account_data_direct_mapping = invoke_context
            .feature_set
            .is_active(&feature_set::bpf_account_data_direct_mapping::id());
        let serialized_data = translate_slice_mut::<u8>(
            memory_mapping,
            if bpf_account_data_direct_mapping {
                vm_data_addr.saturating_add(original_data_len as u64)
            } else {
                vm_data_addr
            },
            if bpf_account_data_direct_mapping {
                if is_loader_deprecated {
                    0
                } else {
                    MAX_PERMITTED_DATA_INCREASE as u64
                }
            } else {
                account_info.data_len
            },
            invoke_context.get_check_aligned(),
            invoke_context.get_check_size(),
        )?;

        // we already have the host addr we want: &mut account_info.data_len.
        // The account info might be read only in the vm though, so we translate
        // to ensure we can write. This is tested by programs/sbf/rust/ro_modify
        // which puts SolAccountInfo in rodata.
        let data_len_vm_addr = vm_addr
            .saturating_add(&account_info.data_len as *const u64 as u64)
            .saturating_sub(account_info as *const _ as *const u64 as u64);
        let data_len_addr = translate(
            memory_mapping,
            AccessType::Store,
            data_len_vm_addr,
            size_of::<u64>() as u64,
        )?;
        let ref_to_len_in_vm = unsafe { &mut *(data_len_addr as *mut u64) };

        let ref_of_len_in_input_buffer =
            (account_info.data_addr as *mut u8 as u64).saturating_sub(8);
        let serialized_len_ptr = if invoke_context
            .feature_set
            .is_active(&feature_set::move_serialized_len_ptr_in_cpi::id())
        {
            std::ptr::null_mut()
        } else {
            translate_type_mut::<u64>(
                memory_mapping,
                ref_of_len_in_input_buffer,
                invoke_context.get_check_aligned(),
            )?
        };

        Ok(CallerAccount {
            lamports,
            owner,
            original_data_len,
            serialized_data,
            vm_data_addr,
            ref_to_len_in_vm,
            serialized_len_ptr,
            executable: account_info.executable,
            rent_epoch: account_info.rent_epoch,
        })
    }
}

type TranslatedAccounts<'a> = Vec<(IndexOfAccount, Option<CallerAccount<'a>>)>;

/// Implemented by language specific data structure translators
trait SyscallInvokeSigned {
    fn translate_instruction(
        addr: u64,
        memory_mapping: &mut MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<StableInstruction, Error>;
    fn translate_accounts<'a>(
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        account_infos_addr: u64,
        account_infos_len: u64,
        is_loader_deprecated: bool,
        memory_mapping: &mut MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<TranslatedAccounts<'a>, Error>;
    fn translate_signers(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &mut MemoryMapping,
        invoke_context: &InvokeContext,
    ) -> Result<Vec<Pubkey>, Error>;
}

declare_syscall!(
    /// Cross-program invocation called from Rust
    SyscallInvokeSignedRust,
    fn inner_call(
        invoke_context: &mut InvokeContext,
        instruction_addr: u64,
        account_infos_addr: u64,
        account_infos_len: u64,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        cpi_common::<Self>(
            invoke_context,
            instruction_addr,
            account_infos_addr,
            account_infos_len,
            signers_seeds_addr,
            signers_seeds_len,
            memory_mapping,
        )
    }
);

impl SyscallInvokeSigned for SyscallInvokeSignedRust {
    fn translate_instruction(
        addr: u64,
        memory_mapping: &mut MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<StableInstruction, Error> {
        let ix = translate_type::<StableInstruction>(
            memory_mapping,
            addr,
            invoke_context.get_check_aligned(),
        )?;

        check_instruction_size(ix.accounts.len(), ix.data.len(), invoke_context)?;

        let accounts = translate_slice::<AccountMeta>(
            memory_mapping,
            ix.accounts.as_ptr() as u64,
            ix.accounts.len() as u64,
            invoke_context.get_check_aligned(),
            invoke_context.get_check_size(),
        )?
        .to_vec();

        let ix_data_len = ix.data.len() as u64;
        if invoke_context
            .feature_set
            .is_active(&feature_set::loosen_cpi_size_restriction::id())
        {
            consume_compute_meter(
                invoke_context,
                (ix_data_len)
                    .saturating_div(invoke_context.get_compute_budget().cpi_bytes_per_unit),
            )?;
        }

        let data = translate_slice::<u8>(
            memory_mapping,
            ix.data.as_ptr() as u64,
            ix_data_len,
            invoke_context.get_check_aligned(),
            invoke_context.get_check_size(),
        )?
        .to_vec();

        Ok(StableInstruction {
            accounts: accounts.into(),
            data: data.into(),
            program_id: ix.program_id,
        })
    }

    fn translate_accounts<'a>(
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        account_infos_addr: u64,
        account_infos_len: u64,
        is_loader_deprecated: bool,
        memory_mapping: &mut MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<TranslatedAccounts<'a>, Error> {
        let (account_infos, account_info_keys) = translate_account_infos(
            account_infos_addr,
            account_infos_len,
            |account_info: &AccountInfo| account_info.key as *const _ as u64,
            memory_mapping,
            invoke_context,
        )?;

        translate_and_update_accounts(
            instruction_accounts,
            program_indices,
            &account_info_keys,
            account_infos,
            account_infos_addr,
            is_loader_deprecated,
            invoke_context,
            memory_mapping,
            CallerAccount::from_account_info,
        )
    }

    fn translate_signers(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &mut MemoryMapping,
        invoke_context: &InvokeContext,
    ) -> Result<Vec<Pubkey>, Error> {
        let mut signers = Vec::new();
        if signers_seeds_len > 0 {
            let signers_seeds = translate_slice::<&[&[u8]]>(
                memory_mapping,
                signers_seeds_addr,
                signers_seeds_len,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            )?;
            if signers_seeds.len() > MAX_SIGNERS {
                return Err(Box::new(SyscallError::TooManySigners));
            }
            for signer_seeds in signers_seeds.iter() {
                let untranslated_seeds = translate_slice::<&[u8]>(
                    memory_mapping,
                    signer_seeds.as_ptr() as *const _ as u64,
                    signer_seeds.len() as u64,
                    invoke_context.get_check_aligned(),
                    invoke_context.get_check_size(),
                )?;
                if untranslated_seeds.len() > MAX_SEEDS {
                    return Err(Box::new(InstructionError::MaxSeedLengthExceeded));
                }
                let seeds = untranslated_seeds
                    .iter()
                    .map(|untranslated_seed| {
                        translate_slice::<u8>(
                            memory_mapping,
                            untranslated_seed.as_ptr() as *const _ as u64,
                            untranslated_seed.len() as u64,
                            invoke_context.get_check_aligned(),
                            invoke_context.get_check_size(),
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
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

/// Rust representation of C's SolInstruction
#[derive(Debug)]
#[repr(C)]
struct SolInstruction {
    program_id_addr: u64,
    accounts_addr: u64,
    accounts_len: u64,
    data_addr: u64,
    data_len: u64,
}

/// Rust representation of C's SolAccountMeta
#[derive(Debug)]
#[repr(C)]
struct SolAccountMeta {
    pubkey_addr: u64,
    is_writable: bool,
    is_signer: bool,
}

/// Rust representation of C's SolAccountInfo
#[derive(Debug)]
#[repr(C)]
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
#[repr(C)]
struct SolSignerSeedC {
    addr: u64,
    len: u64,
}

/// Rust representation of C's SolSignerSeeds
#[derive(Debug)]
#[repr(C)]
struct SolSignerSeedsC {
    addr: u64,
    len: u64,
}

declare_syscall!(
    /// Cross-program invocation called from C
    SyscallInvokeSignedC,
    fn inner_call(
        invoke_context: &mut InvokeContext,
        instruction_addr: u64,
        account_infos_addr: u64,
        account_infos_len: u64,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        cpi_common::<Self>(
            invoke_context,
            instruction_addr,
            account_infos_addr,
            account_infos_len,
            signers_seeds_addr,
            signers_seeds_len,
            memory_mapping,
        )
    }
);

impl SyscallInvokeSigned for SyscallInvokeSignedC {
    fn translate_instruction(
        addr: u64,
        memory_mapping: &mut MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<StableInstruction, Error> {
        let ix_c = translate_type::<SolInstruction>(
            memory_mapping,
            addr,
            invoke_context.get_check_aligned(),
        )?;

        check_instruction_size(
            ix_c.accounts_len as usize,
            ix_c.data_len as usize,
            invoke_context,
        )?;
        let program_id = translate_type::<Pubkey>(
            memory_mapping,
            ix_c.program_id_addr,
            invoke_context.get_check_aligned(),
        )?;
        let meta_cs = translate_slice::<SolAccountMeta>(
            memory_mapping,
            ix_c.accounts_addr,
            ix_c.accounts_len,
            invoke_context.get_check_aligned(),
            invoke_context.get_check_size(),
        )?;

        let ix_data_len = ix_c.data_len;
        if invoke_context
            .feature_set
            .is_active(&feature_set::loosen_cpi_size_restriction::id())
        {
            consume_compute_meter(
                invoke_context,
                (ix_data_len)
                    .saturating_div(invoke_context.get_compute_budget().cpi_bytes_per_unit),
            )?;
        }

        let data = translate_slice::<u8>(
            memory_mapping,
            ix_c.data_addr,
            ix_data_len,
            invoke_context.get_check_aligned(),
            invoke_context.get_check_size(),
        )?
        .to_vec();
        let accounts = meta_cs
            .iter()
            .map(|meta_c| {
                let pubkey = translate_type::<Pubkey>(
                    memory_mapping,
                    meta_c.pubkey_addr,
                    invoke_context.get_check_aligned(),
                )?;
                Ok(AccountMeta {
                    pubkey: *pubkey,
                    is_signer: meta_c.is_signer,
                    is_writable: meta_c.is_writable,
                })
            })
            .collect::<Result<Vec<AccountMeta>, Error>>()?;

        Ok(StableInstruction {
            accounts: accounts.into(),
            data: data.into(),
            program_id: *program_id,
        })
    }

    fn translate_accounts<'a>(
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        account_infos_addr: u64,
        account_infos_len: u64,
        is_loader_deprecated: bool,
        memory_mapping: &mut MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<TranslatedAccounts<'a>, Error> {
        let (account_infos, account_info_keys) = translate_account_infos(
            account_infos_addr,
            account_infos_len,
            |account_info: &SolAccountInfo| account_info.key_addr,
            memory_mapping,
            invoke_context,
        )?;

        translate_and_update_accounts(
            instruction_accounts,
            program_indices,
            &account_info_keys,
            account_infos,
            account_infos_addr,
            is_loader_deprecated,
            invoke_context,
            memory_mapping,
            CallerAccount::from_sol_account_info,
        )
    }

    fn translate_signers(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &mut MemoryMapping,
        invoke_context: &InvokeContext,
    ) -> Result<Vec<Pubkey>, Error> {
        if signers_seeds_len > 0 {
            let signers_seeds = translate_slice::<SolSignerSeedsC>(
                memory_mapping,
                signers_seeds_addr,
                signers_seeds_len,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            )?;
            if signers_seeds.len() > MAX_SIGNERS {
                return Err(Box::new(SyscallError::TooManySigners));
            }
            Ok(signers_seeds
                .iter()
                .map(|signer_seeds| {
                    let seeds = translate_slice::<SolSignerSeedC>(
                        memory_mapping,
                        signer_seeds.addr,
                        signer_seeds.len,
                        invoke_context.get_check_aligned(),
                        invoke_context.get_check_size(),
                    )?;
                    if seeds.len() > MAX_SEEDS {
                        return Err(Box::new(InstructionError::MaxSeedLengthExceeded) as Error);
                    }
                    let seeds_bytes = seeds
                        .iter()
                        .map(|seed| {
                            translate_slice::<u8>(
                                memory_mapping,
                                seed.addr,
                                seed.len,
                                invoke_context.get_check_aligned(),
                                invoke_context.get_check_size(),
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                    Pubkey::create_program_address(&seeds_bytes, program_id)
                        .map_err(|err| Box::new(SyscallError::BadSeeds(err)) as Error)
                })
                .collect::<Result<Vec<_>, Error>>()?)
        } else {
            Ok(vec![])
        }
    }
}

fn translate_account_infos<'a, T, F>(
    account_infos_addr: u64,
    account_infos_len: u64,
    key_addr: F,
    memory_mapping: &mut MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<(&'a [T], Vec<&'a Pubkey>), Error>
where
    F: Fn(&T) -> u64,
{
    let account_infos = translate_slice::<T>(
        memory_mapping,
        account_infos_addr,
        account_infos_len,
        invoke_context.get_check_aligned(),
        invoke_context.get_check_size(),
    )?;
    check_account_infos(account_infos.len(), invoke_context)?;
    let account_info_keys = account_infos
        .iter()
        .map(|account_info| {
            translate_type::<Pubkey>(
                memory_mapping,
                key_addr(account_info),
                invoke_context.get_check_aligned(),
            )
        })
        .collect::<Result<Vec<_>, Error>>()?;

    Ok((account_infos, account_info_keys))
}

// Finish translating accounts, build CallerAccount values and update callee
// accounts in preparation of executing the callee.
fn translate_and_update_accounts<'a, T, F>(
    instruction_accounts: &[InstructionAccount],
    program_indices: &[IndexOfAccount],
    account_info_keys: &[&Pubkey],
    account_infos: &[T],
    account_infos_addr: u64,
    is_loader_deprecated: bool,
    invoke_context: &mut InvokeContext,
    memory_mapping: &MemoryMapping,
    do_translate: F,
) -> Result<TranslatedAccounts<'a>, Error>
where
    F: Fn(&InvokeContext, &MemoryMapping, bool, u64, &T, usize) -> Result<CallerAccount<'a>, Error>,
{
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut accounts = Vec::with_capacity(instruction_accounts.len().saturating_add(1));

    let program_account_index = program_indices
        .last()
        .ok_or_else(|| Box::new(InstructionError::MissingAccount))?;
    accounts.push((*program_account_index, None));

    // unwrapping here is fine: we're in a syscall and the method below fails
    // only outside syscalls
    let orig_data_lens = &invoke_context
        .get_syscall_context()
        .unwrap()
        .orig_account_lengths;

    let direct_mapping = invoke_context
        .feature_set
        .is_active(&feature_set::bpf_account_data_direct_mapping::id());

    for (instruction_account_index, instruction_account) in instruction_accounts.iter().enumerate()
    {
        if instruction_account_index as IndexOfAccount != instruction_account.index_in_callee {
            continue; // Skip duplicate account
        }

        let callee_account = instruction_context.try_borrow_instruction_account(
            transaction_context,
            instruction_account.index_in_caller,
        )?;
        let account_key = invoke_context
            .transaction_context
            .get_key_of_account_at_index(instruction_account.index_in_transaction)?;

        if callee_account.is_executable() {
            // Use the known account
            consume_compute_meter(
                invoke_context,
                (callee_account.get_data().len() as u64)
                    .saturating_div(invoke_context.get_compute_budget().cpi_bytes_per_unit),
            )?;

            accounts.push((instruction_account.index_in_caller, None));
        } else if let Some(caller_account_index) =
            account_info_keys.iter().position(|key| *key == account_key)
        {
            let original_data_len = *orig_data_lens
                .get(instruction_account.index_in_caller as usize)
                .ok_or_else(|| {
                    ic_msg!(
                        invoke_context,
                        "Internal error: index mismatch for account {}",
                        account_key
                    );
                    Box::new(InstructionError::MissingAccount)
                })?;

            // build the CallerAccount corresponding to this account.
            let caller_account =
                do_translate(
                    invoke_context,
                    memory_mapping,
                    is_loader_deprecated,
                    account_infos_addr.saturating_add(
                        caller_account_index.saturating_mul(mem::size_of::<T>()) as u64,
                    ),
                    account_infos
                        .get(caller_account_index)
                        .ok_or(SyscallError::InvalidLength)?,
                    original_data_len,
                )?;

            // before initiating CPI, the caller may have modified the
            // account (caller_account). We need to update the corresponding
            // BorrowedAccount (callee_account) so the callee can see the
            // changes.
            update_callee_account(
                invoke_context,
                is_loader_deprecated,
                &caller_account,
                callee_account,
                direct_mapping,
            )?;

            let caller_account = if instruction_account.is_writable {
                Some(caller_account)
            } else {
                None
            };
            accounts.push((instruction_account.index_in_caller, caller_account));
        } else {
            ic_msg!(
                invoke_context,
                "Instruction references an unknown account {}",
                account_key
            );
            return Err(Box::new(InstructionError::MissingAccount));
        }
    }

    Ok(accounts)
}

fn check_instruction_size(
    num_accounts: usize,
    data_len: usize,
    invoke_context: &mut InvokeContext,
) -> Result<(), Error> {
    if invoke_context
        .feature_set
        .is_active(&feature_set::loosen_cpi_size_restriction::id())
    {
        let data_len = data_len as u64;
        let max_data_len = MAX_CPI_INSTRUCTION_DATA_LEN;
        if data_len > max_data_len {
            return Err(Box::new(SyscallError::MaxInstructionDataLenExceeded {
                data_len,
                max_data_len,
            }));
        }

        let num_accounts = num_accounts as u64;
        let max_accounts = MAX_CPI_INSTRUCTION_ACCOUNTS as u64;
        if num_accounts > max_accounts {
            return Err(Box::new(SyscallError::MaxInstructionAccountsExceeded {
                num_accounts,
                max_accounts,
            }));
        }
    } else {
        let max_size = invoke_context.get_compute_budget().max_cpi_instruction_size;
        let size = num_accounts
            .saturating_mul(size_of::<AccountMeta>())
            .saturating_add(data_len);
        if size > max_size {
            return Err(Box::new(SyscallError::InstructionTooLarge(size, max_size)));
        }
    }
    Ok(())
}

fn check_account_infos(
    num_account_infos: usize,
    invoke_context: &mut InvokeContext,
) -> Result<(), Error> {
    if invoke_context
        .feature_set
        .is_active(&feature_set::loosen_cpi_size_restriction::id())
    {
        let max_cpi_account_infos = if invoke_context
            .feature_set
            .is_active(&feature_set::increase_tx_account_lock_limit::id())
        {
            MAX_CPI_ACCOUNT_INFOS
        } else {
            64
        };
        let num_account_infos = num_account_infos as u64;
        let max_account_infos = max_cpi_account_infos as u64;
        if num_account_infos > max_account_infos {
            return Err(Box::new(SyscallError::MaxInstructionAccountInfosExceeded {
                num_account_infos,
                max_account_infos,
            }));
        }
    } else {
        let adjusted_len = num_account_infos.saturating_mul(size_of::<Pubkey>());

        if adjusted_len > invoke_context.get_compute_budget().max_cpi_instruction_size {
            // Cap the number of account_infos a caller can pass to approximate
            // maximum that accounts that could be passed in an instruction
            return Err(Box::new(SyscallError::TooManyAccounts));
        };
    }
    Ok(())
}

fn check_authorized_program(
    program_id: &Pubkey,
    instruction_data: &[u8],
    invoke_context: &InvokeContext,
) -> Result<(), Error> {
    if native_loader::check_id(program_id)
        || bpf_loader::check_id(program_id)
        || bpf_loader_deprecated::check_id(program_id)
        || (bpf_loader_upgradeable::check_id(program_id)
            && !(bpf_loader_upgradeable::is_upgrade_instruction(instruction_data)
                || bpf_loader_upgradeable::is_set_authority_instruction(instruction_data)
                || (invoke_context
                    .feature_set
                    .is_active(&enable_bpf_loader_set_authority_checked_ix::id())
                    && bpf_loader_upgradeable::is_set_authority_checked_instruction(
                        instruction_data,
                    ))
                || bpf_loader_upgradeable::is_close_instruction(instruction_data)))
        || is_precompile(program_id, |feature_id: &Pubkey| {
            invoke_context.feature_set.is_active(feature_id)
        })
    {
        return Err(Box::new(SyscallError::ProgramNotSupported(*program_id)));
    }
    Ok(())
}

/// Call process instruction, common to both Rust and C
fn cpi_common<S: SyscallInvokeSigned>(
    invoke_context: &mut InvokeContext,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    memory_mapping: &mut MemoryMapping,
) -> Result<u64, Error> {
    // CPI entry.
    //
    // Translate the inputs to the syscall and synchronize the caller's account
    // changes so the callee can see them.
    consume_compute_meter(
        invoke_context,
        invoke_context.get_compute_budget().invoke_units,
    )?;

    let instruction = S::translate_instruction(instruction_addr, memory_mapping, invoke_context)?;
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let caller_program_id = instruction_context.get_last_program_key(transaction_context)?;
    let signers = S::translate_signers(
        caller_program_id,
        signers_seeds_addr,
        signers_seeds_len,
        memory_mapping,
        invoke_context,
    )?;
    let is_loader_deprecated = *instruction_context
        .try_borrow_last_program_account(transaction_context)?
        .get_owner()
        == bpf_loader_deprecated::id();
    let (instruction_accounts, program_indices) =
        invoke_context.prepare_instruction(&instruction, &signers)?;
    check_authorized_program(&instruction.program_id, &instruction.data, invoke_context)?;

    let mut accounts = S::translate_accounts(
        &instruction_accounts,
        &program_indices,
        account_infos_addr,
        account_infos_len,
        is_loader_deprecated,
        memory_mapping,
        invoke_context,
    )?;

    // Process the callee instruction
    let mut compute_units_consumed = 0;
    invoke_context.process_instruction(
        &instruction.data,
        &instruction_accounts,
        &program_indices,
        &mut compute_units_consumed,
        &mut ExecuteTimings::default(),
    )?;

    // re-bind to please the borrow checker
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;

    // CPI exit.
    //
    // Synchronize the callee's account changes so the caller can see them.
    let direct_mapping = invoke_context
        .feature_set
        .is_active(&feature_set::bpf_account_data_direct_mapping::id());

    for (index_in_caller, caller_account) in accounts.iter_mut() {
        if let Some(caller_account) = caller_account {
            let mut callee_account = instruction_context
                .try_borrow_instruction_account(transaction_context, *index_in_caller)?;
            update_caller_account(
                invoke_context,
                memory_mapping,
                is_loader_deprecated,
                caller_account,
                &mut callee_account,
                direct_mapping,
            )?;
        }
    }

    Ok(SUCCESS)
}

// Update the given account before executing CPI.
//
// caller_account and callee_account describe the same account. At CPI entry
// caller_account might include changes the caller has made to the account
// before executing CPI.
//
// This method updates callee_account so the CPI callee can see the caller's
// changes.
fn update_callee_account(
    invoke_context: &InvokeContext,
    is_loader_deprecated: bool,
    caller_account: &CallerAccount,
    mut callee_account: BorrowedAccount<'_>,
    direct_mapping: bool,
) -> Result<(), Error> {
    let is_disable_cpi_setting_executable_and_rent_epoch_active = invoke_context
        .feature_set
        .is_active(&disable_cpi_setting_executable_and_rent_epoch::id());
    if callee_account.get_lamports() != *caller_account.lamports {
        callee_account.set_lamports(*caller_account.lamports)?;
    }

    if direct_mapping {
        let prev_len = callee_account.get_data().len();
        let post_len = *caller_account.ref_to_len_in_vm as usize;
        match callee_account
            .can_data_be_resized(post_len)
            .and_then(|_| callee_account.can_data_be_changed())
        {
            Ok(()) => {
                callee_account.set_data_length(post_len)?;
                let realloc_bytes_used = post_len.saturating_sub(caller_account.original_data_len);
                if !is_loader_deprecated && realloc_bytes_used > 0 {
                    callee_account
                        .get_data_mut()?
                        .get_mut(caller_account.original_data_len..post_len)
                        .ok_or(SyscallError::InvalidLength)?
                        .copy_from_slice(
                            caller_account
                                .serialized_data
                                .get(0..realloc_bytes_used)
                                .ok_or(SyscallError::InvalidLength)?,
                        );
                }
            }
            Err(err) if prev_len != post_len => {
                return Err(Box::new(err));
            }
            _ => {}
        }
    } else {
        // The redundant check helps to avoid the expensive data comparison if we can
        match callee_account
            .can_data_be_resized(caller_account.serialized_data.len())
            .and_then(|_| callee_account.can_data_be_changed())
        {
            Ok(()) => callee_account.set_data_from_slice(caller_account.serialized_data)?,
            Err(err) if callee_account.get_data() != caller_account.serialized_data => {
                return Err(Box::new(err));
            }
            _ => {}
        }
    }

    if !is_disable_cpi_setting_executable_and_rent_epoch_active
        && callee_account.is_executable() != caller_account.executable
    {
        callee_account.set_executable(caller_account.executable)?;
    }

    // Change the owner at the end so that we are allowed to change the lamports and data before
    if callee_account.get_owner() != caller_account.owner {
        callee_account.set_owner(caller_account.owner.as_ref())?;
    }

    // BorrowedAccount doesn't allow changing the rent epoch. Drop it and use
    // AccountSharedData directly.
    let index_in_transaction = callee_account.get_index_in_transaction();
    drop(callee_account);
    let callee_account = invoke_context
        .transaction_context
        .get_account_at_index(index_in_transaction)?;
    if !is_disable_cpi_setting_executable_and_rent_epoch_active
        && callee_account.borrow().rent_epoch() != caller_account.rent_epoch
    {
        if invoke_context
            .feature_set
            .is_active(&enable_early_verification_of_account_modifications::id())
        {
            return Err(Box::new(InstructionError::RentEpochModified));
        } else {
            callee_account
                .borrow_mut()
                .set_rent_epoch(caller_account.rent_epoch);
        }
    }

    Ok(())
}

// Update the given account after executing CPI.
//
// caller_account and callee_account describe to the same account. At CPI exit
// callee_account might include changes the callee has made to the account
// after executing.
//
// This method updates caller_account so the CPI caller can see the callee's
// changes.
fn update_caller_account(
    invoke_context: &InvokeContext,
    memory_mapping: &mut MemoryMapping,
    is_loader_deprecated: bool,
    caller_account: &mut CallerAccount,
    callee_account: &mut BorrowedAccount<'_>,
    direct_mapping: bool,
) -> Result<(), Error> {
    *caller_account.lamports = callee_account.get_lamports();
    *caller_account.owner = *callee_account.get_owner();

    if direct_mapping && caller_account.original_data_len > 0 {
        // Since each instruction account is directly mapped in a memory region
        // with a *fixed* length, upon returning from CPI we must ensure that the
        // current capacity is at least the original length (what is mapped in
        // memory), so that the account's memory region never points to an
        // invalid address.
        let min_capacity = caller_account.original_data_len;
        if callee_account.capacity() < min_capacity {
            callee_account.reserve(min_capacity.saturating_sub(callee_account.capacity()))?
        }

        // If an account's data pointer has changed - because of CoW or because
        // of using AccountSharedData directly (deprecated) - we must update the
        // corresponding MemoryRegion in the caller's address space. Address
        // spaces are fixed so we don't need to update the MemoryRegion's length.
        let region = memory_mapping.region(AccessType::Load, caller_account.vm_data_addr)?;
        let callee_ptr = callee_account.get_data().as_ptr() as u64;
        if region.host_addr.get() != callee_ptr {
            region.host_addr.set(callee_ptr);
        }
    }
    let prev_len = *caller_account.ref_to_len_in_vm as usize;
    let post_len = callee_account.get_data().len();
    if prev_len != post_len {
        let max_increase = if direct_mapping && !invoke_context.get_check_aligned() {
            0
        } else {
            MAX_PERMITTED_DATA_INCREASE
        };
        let data_overflow = post_len
            > caller_account
                .original_data_len
                .saturating_add(max_increase);
        if data_overflow {
            ic_msg!(
                invoke_context,
                "Account data size realloc limited to {max_increase} in inner instructions",
            );
            return Err(Box::new(InstructionError::InvalidRealloc));
        }
        if post_len < prev_len {
            if direct_mapping {
                if post_len < caller_account.original_data_len {
                    // zero the spare capacity in the account data. We only need
                    // to zero up to the original data length, everything else
                    // is not accessible from the vm anyway.
                    let spare_len = caller_account.original_data_len.saturating_sub(post_len);
                    let dst = callee_account
                        .spare_data_capacity_mut()?
                        .get_mut(..spare_len)
                        .ok_or_else(|| Box::new(InstructionError::AccountDataTooSmall))?
                        .as_mut_ptr();
                    // Safety: we check bounds above
                    unsafe { ptr::write_bytes(dst, 0, spare_len) };
                }

                // zero the spare capacity in the realloc padding
                let spare_realloc = unsafe {
                    slice::from_raw_parts_mut(
                        caller_account.serialized_data.as_mut_ptr(),
                        prev_len.saturating_sub(caller_account.original_data_len),
                    )
                };
                spare_realloc.fill(0);
            } else {
                caller_account
                    .serialized_data
                    .get_mut(post_len..)
                    .ok_or_else(|| Box::new(InstructionError::AccountDataTooSmall))?
                    .fill(0);
            }
        }

        // with direct_mapping on, serialized_data is fixed and holds the
        // realloc padding
        if !direct_mapping {
            caller_account.serialized_data = translate_slice_mut::<u8>(
                memory_mapping,
                caller_account.vm_data_addr,
                post_len as u64,
                false, // Don't care since it is byte aligned
                invoke_context.get_check_size(),
            )?;
        }
        // this is the len field in the AccountInfo::data slice
        *caller_account.ref_to_len_in_vm = post_len as u64;

        // this is the len field in the serialized parameters
        if invoke_context
            .feature_set
            .is_active(&feature_set::move_serialized_len_ptr_in_cpi::id())
        {
            let serialized_len_ptr = translate_type_mut::<u64>(
                memory_mapping,
                caller_account
                    .vm_data_addr
                    .saturating_sub(std::mem::size_of::<u64>() as u64),
                invoke_context.get_check_aligned(),
            )?;
            *serialized_len_ptr = post_len as u64;
        } else {
            unsafe {
                *caller_account.serialized_len_ptr = post_len as u64;
            }
        }
    }
    let realloc_bytes_used = post_len.saturating_sub(caller_account.original_data_len);
    if !direct_mapping {
        let to_slice = &mut caller_account.serialized_data;
        let from_slice = callee_account
            .get_data()
            .get(0..post_len)
            .ok_or(SyscallError::InvalidLength)?;
        if to_slice.len() != from_slice.len() {
            return Err(Box::new(InstructionError::AccountDataTooSmall));
        }
        to_slice.copy_from_slice(from_slice);
    } else if !is_loader_deprecated && realloc_bytes_used > 0 {
        let to_slice = caller_account
            .serialized_data
            .get_mut(0..realloc_bytes_used)
            .ok_or(SyscallError::InvalidLength)?;
        let from_slice = callee_account
            .get_data()
            .get(caller_account.original_data_len..post_len)
            .ok_or(SyscallError::InvalidLength)?;
        to_slice.copy_from_slice(from_slice);
    }

    Ok(())
}
