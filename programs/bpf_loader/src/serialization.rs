#![allow(clippy::integer_arithmetic)]

use {
    byteorder::{ByteOrder, LittleEndian},
    solana_rbpf::{
        aligned_memory::{AlignedMemory, Pod},
        ebpf::{HOST_ALIGN, MM_INPUT_START},
        memory_region::MemoryRegion,
    },
    solana_sdk::{
        bpf_loader_deprecated,
        entrypoint::{BPF_ALIGN_OF_U128, MAX_PERMITTED_DATA_INCREASE, NON_DUP_MARKER},
        instruction::InstructionError,
        pubkey::Pubkey,
        system_instruction::MAX_PERMITTED_DATA_LENGTH,
        transaction_context::{
            BorrowedAccount, IndexOfAccount, InstructionContext, TransactionContext,
        },
    },
    std::mem::{self, size_of},
};

/// Maximum number of instruction accounts that can be serialized into the
/// SBF VM.
const MAX_INSTRUCTION_ACCOUNTS: u8 = NON_DUP_MARKER;

enum SerializeAccount<'a> {
    Account(IndexOfAccount, BorrowedAccount<'a>),
    Duplicate(IndexOfAccount),
}

struct Serializer {
    pub buffer: AlignedMemory<HOST_ALIGN>,
    regions: Vec<MemoryRegion>,
    vaddr: u64,
    region_start: usize,
    aligned: bool,
    copy_account_data: bool,
}

impl Serializer {
    fn new(size: usize, start_addr: u64, aligned: bool, copy_account_data: bool) -> Serializer {
        Serializer {
            buffer: AlignedMemory::with_capacity(size),
            regions: Vec::new(),
            region_start: 0,
            vaddr: start_addr,
            aligned,
            copy_account_data,
        }
    }

    fn fill_write(&mut self, num: usize, value: u8) -> std::io::Result<()> {
        self.buffer.fill_write(num, value)
    }

    pub fn write<T: Pod>(&mut self, value: T) {
        self.debug_assert_alignment::<T>();
        // Safety:
        // in serialize_parameters_(aligned|unaligned) first we compute the
        // required size then we write into the newly allocated buffer. There's
        // no need to check bounds at every write.
        //
        // AlignedMemory::write_unchecked _does_ debug_assert!() that the capacity
        // is enough, so in the unlikely case we introduce a bug in the size
        // computation, tests will abort.
        unsafe {
            self.buffer.write_unchecked(value);
        }
    }

    fn write_all(&mut self, value: &[u8]) {
        // Safety:
        // see write() - the buffer is guaranteed to be large enough
        unsafe {
            self.buffer.write_all_unchecked(value);
        }
    }

    fn write_account(&mut self, account: &mut BorrowedAccount<'_>) -> Result<(), InstructionError> {
        if self.copy_account_data {
            self.write_all(account.get_data());
        } else {
            self.push_account_region(account)?;
        }

        if self.aligned {
            let align_offset =
                (account.get_data().len() as *const u8).align_offset(BPF_ALIGN_OF_U128);
            if self.copy_account_data {
                self.fill_write(MAX_PERMITTED_DATA_INCREASE + align_offset, 0)
                    .map_err(|_| InstructionError::InvalidArgument)?;
            } else {
                // The deserialization code is going to align the vm_addr to
                // BPF_ALIGN_OF_U128. Always add one BPF_ALIGN_OF_U128 worth of
                // padding and shift the start of the next region, so that once
                // vm_addr is aligned, the corresponding host_addr is aligned
                // too.
                self.fill_write(MAX_PERMITTED_DATA_INCREASE + BPF_ALIGN_OF_U128, 0)
                    .map_err(|_| InstructionError::InvalidArgument)?;
                self.region_start += BPF_ALIGN_OF_U128.saturating_sub(align_offset);
            }
        }

        Ok(())
    }

    fn push_account_region(
        &mut self,
        account: &mut BorrowedAccount<'_>,
    ) -> Result<(), InstructionError> {
        self.push_region();
        let account_len = account.get_data().len();
        if account_len > 0 {
            let region = if account.can_data_be_changed().is_ok() {
                if account.is_shared() {
                    // If the account is still shared it means it wasn't written to yet during this
                    // transaction. We map it as CoW and it'll be copied the first time something
                    // tries to write into it.
                    let index_in_transaction = account.get_index_in_transaction();

                    MemoryRegion::new_cow(
                        account.get_data(),
                        self.vaddr,
                        index_in_transaction as u64,
                    )
                } else {
                    // The account isn't shared anymore, meaning it was written to earlier during
                    // this transaction. We can just map as writable no need for any fancy CoW
                    // business.
                    MemoryRegion::new_writable(account.get_data_mut()?, self.vaddr)
                }
            } else {
                MemoryRegion::new_readonly(account.get_data(), self.vaddr)
            };
            self.vaddr += region.len;
            self.regions.push(region);
        }
        Ok(())
    }

    fn push_region(&mut self) {
        let range = self.region_start..self.buffer.len();
        let region = MemoryRegion::new_writable(
            self.buffer.as_slice_mut().get_mut(range.clone()).unwrap(),
            self.vaddr,
        );
        self.regions.push(region);
        self.region_start = range.end;
        self.vaddr += range.len() as u64;
    }

    fn finish(mut self) -> (AlignedMemory<HOST_ALIGN>, Vec<MemoryRegion>) {
        self.push_region();
        debug_assert_eq!(self.region_start, self.buffer.len());
        (self.buffer, self.regions)
    }

    fn debug_assert_alignment<T>(&self) {
        debug_assert!(
            !self.aligned
                || self
                    .buffer
                    .as_slice()
                    .as_ptr_range()
                    .end
                    .align_offset(mem::align_of::<T>())
                    == 0
        );
    }
}

pub fn serialize_parameters(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
    should_cap_ix_accounts: bool,
    copy_account_data: bool,
) -> Result<(AlignedMemory<HOST_ALIGN>, Vec<MemoryRegion>, Vec<usize>), InstructionError> {
    let num_ix_accounts = instruction_context.get_number_of_instruction_accounts();
    if should_cap_ix_accounts && num_ix_accounts > MAX_INSTRUCTION_ACCOUNTS as IndexOfAccount {
        return Err(InstructionError::MaxAccountsExceeded);
    }
    let is_loader_deprecated = *instruction_context
        .try_borrow_last_program_account(transaction_context)?
        .get_owner()
        == bpf_loader_deprecated::id();

    let num_accounts = instruction_context.get_number_of_instruction_accounts() as usize;
    let mut accounts = Vec::with_capacity(num_accounts);
    let mut account_lengths: Vec<usize> = Vec::with_capacity(num_accounts);
    for instruction_account_index in 0..instruction_context.get_number_of_instruction_accounts() {
        if let Some(index) =
            instruction_context.is_instruction_account_duplicate(instruction_account_index)?
        {
            accounts.push(SerializeAccount::Duplicate(index));
            // unwrap here is safe: if an account is a duplicate, we must have
            // seen the original already
            account_lengths.push(*account_lengths.get(index as usize).unwrap());
        } else {
            let account = instruction_context
                .try_borrow_instruction_account(transaction_context, instruction_account_index)?;
            account_lengths.push(account.get_data().len());
            accounts.push(SerializeAccount::Account(
                instruction_account_index,
                account,
            ));
        };
    }

    if is_loader_deprecated {
        serialize_parameters_unaligned(
            transaction_context,
            instruction_context,
            accounts,
            copy_account_data,
        )
    } else {
        serialize_parameters_aligned(
            transaction_context,
            instruction_context,
            accounts,
            copy_account_data,
        )
    }
    .map(|(buffer, regions)| (buffer, regions, account_lengths))
}

pub fn deserialize_parameters(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
    copy_account_data: bool,
    buffer: &[u8],
    account_lengths: &[usize],
) -> Result<(), InstructionError> {
    let is_loader_deprecated = *instruction_context
        .try_borrow_last_program_account(transaction_context)?
        .get_owner()
        == bpf_loader_deprecated::id();
    if is_loader_deprecated {
        deserialize_parameters_unaligned(
            transaction_context,
            instruction_context,
            copy_account_data,
            buffer,
            account_lengths,
        )
    } else {
        deserialize_parameters_aligned(
            transaction_context,
            instruction_context,
            copy_account_data,
            buffer,
            account_lengths,
        )
    }
}

fn serialize_parameters_unaligned(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
    accounts: Vec<SerializeAccount>,
    copy_account_data: bool,
) -> Result<(AlignedMemory<HOST_ALIGN>, Vec<MemoryRegion>), InstructionError> {
    // Calculate size in order to alloc once
    let mut size = size_of::<u64>();
    for account in &accounts {
        size += 1; // dup
        match account {
            SerializeAccount::Duplicate(_) => {}
            SerializeAccount::Account(_, account) => {
                size += size_of::<u8>() // is_signer
                + size_of::<u8>() // is_writable
                + size_of::<Pubkey>() // key
                + size_of::<u64>()  // lamports
                + size_of::<u64>()  // data len
                + size_of::<Pubkey>() // owner
                + size_of::<u8>() // executable
                + size_of::<u64>(); // rent_epoch
                if copy_account_data {
                    size += account.get_data().len();
                }
            }
        }
    }
    size += size_of::<u64>() // instruction data len
         + instruction_context.get_instruction_data().len() // instruction data
         + size_of::<Pubkey>(); // program id

    let mut s = Serializer::new(size, MM_INPUT_START, false, copy_account_data);

    s.write::<u64>((accounts.len() as u64).to_le());
    for account in accounts {
        match account {
            SerializeAccount::Duplicate(position) => s.write(position as u8),
            SerializeAccount::Account(_, mut account) => {
                s.write::<u8>(NON_DUP_MARKER);
                s.write::<u8>(account.is_signer() as u8);
                s.write::<u8>(account.is_writable() as u8);
                s.write_all(account.get_key().as_ref());
                s.write::<u64>(account.get_lamports().to_le());
                s.write::<u64>((account.get_data().len() as u64).to_le());
                s.write_account(&mut account)?;
                s.write_all(account.get_owner().as_ref());
                s.write::<u8>(account.is_executable() as u8);
                s.write::<u64>((account.get_rent_epoch()).to_le());
            }
        };
    }
    s.write::<u64>((instruction_context.get_instruction_data().len() as u64).to_le());
    s.write_all(instruction_context.get_instruction_data());
    s.write_all(
        instruction_context
            .try_borrow_last_program_account(transaction_context)?
            .get_key()
            .as_ref(),
    );

    Ok(s.finish())
}

pub fn deserialize_parameters_unaligned(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
    copy_account_data: bool,
    buffer: &[u8],
    account_lengths: &[usize],
) -> Result<(), InstructionError> {
    let mut start = size_of::<u64>(); // number of accounts
    for (instruction_account_index, pre_len) in
        (0..instruction_context.get_number_of_instruction_accounts()).zip(account_lengths.iter())
    {
        let duplicate =
            instruction_context.is_instruction_account_duplicate(instruction_account_index)?;
        start += 1; // is_dup
        if duplicate.is_none() {
            let mut borrowed_account = instruction_context
                .try_borrow_instruction_account(transaction_context, instruction_account_index)?;
            start += size_of::<u8>(); // is_signer
            start += size_of::<u8>(); // is_writable
            start += size_of::<Pubkey>(); // key
            let lamports = LittleEndian::read_u64(
                buffer
                    .get(start..)
                    .ok_or(InstructionError::InvalidArgument)?,
            );
            if borrowed_account.get_lamports() != lamports {
                borrowed_account.set_lamports(lamports)?;
            }
            start += size_of::<u64>() // lamports
                + size_of::<u64>(); // data length
            if copy_account_data {
                let data = buffer
                    .get(start..start + pre_len)
                    .ok_or(InstructionError::InvalidArgument)?;
                // The redundant check helps to avoid the expensive data comparison if we can
                match borrowed_account
                    .can_data_be_resized(data.len())
                    .and_then(|_| borrowed_account.can_data_be_changed())
                {
                    Ok(()) => borrowed_account.set_data_from_slice(data)?,
                    Err(err) if borrowed_account.get_data() != data => return Err(err),
                    _ => {}
                }
                start += pre_len; // data
            }
            start += size_of::<Pubkey>() // owner
                + size_of::<u8>() // executable
                + size_of::<u64>(); // rent_epoch
        }
    }
    Ok(())
}

fn serialize_parameters_aligned(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
    accounts: Vec<SerializeAccount>,
    copy_account_data: bool,
) -> Result<(AlignedMemory<HOST_ALIGN>, Vec<MemoryRegion>), InstructionError> {
    // Calculate size in order to alloc once
    let mut size = size_of::<u64>();
    for account in &accounts {
        size += 1; // dup
        match account {
            SerializeAccount::Duplicate(_) => size += 7, // padding to 64-bit aligned
            SerializeAccount::Account(_, account) => {
                let data_len = account.get_data().len();
                size += size_of::<u8>() // is_signer
                + size_of::<u8>() // is_writable
                + size_of::<u8>() // executable
                + size_of::<u32>() // original_data_len
                + size_of::<Pubkey>()  // key
                + size_of::<Pubkey>() // owner
                + size_of::<u64>()  // lamports
                + size_of::<u64>()  // data len
                + MAX_PERMITTED_DATA_INCREASE
                + size_of::<u64>(); // rent epoch
                if copy_account_data {
                    size += data_len + (data_len as *const u8).align_offset(BPF_ALIGN_OF_U128);
                } else {
                    size += BPF_ALIGN_OF_U128;
                }
            }
        }
    }
    size += size_of::<u64>() // data len
    + instruction_context.get_instruction_data().len()
    + size_of::<Pubkey>(); // program id;

    let mut s = Serializer::new(size, MM_INPUT_START, true, copy_account_data);

    // Serialize into the buffer
    s.write::<u64>((accounts.len() as u64).to_le());
    for account in accounts {
        match account {
            SerializeAccount::Account(_, mut borrowed_account) => {
                s.write::<u8>(NON_DUP_MARKER);
                s.write::<u8>(borrowed_account.is_signer() as u8);
                s.write::<u8>(borrowed_account.is_writable() as u8);
                s.write::<u8>(borrowed_account.is_executable() as u8);
                s.write_all(&[0u8, 0, 0, 0]);
                s.write_all(borrowed_account.get_key().as_ref());
                s.write_all(borrowed_account.get_owner().as_ref());
                s.write::<u64>(borrowed_account.get_lamports().to_le());
                s.write::<u64>((borrowed_account.get_data().len() as u64).to_le());
                s.write_account(&mut borrowed_account)?;
                s.write::<u64>((borrowed_account.get_rent_epoch()).to_le());
            }
            SerializeAccount::Duplicate(position) => {
                s.write::<u8>(position as u8);
                s.write_all(&[0u8, 0, 0, 0, 0, 0, 0]);
            }
        };
    }
    s.write::<u64>((instruction_context.get_instruction_data().len() as u64).to_le());
    s.write_all(instruction_context.get_instruction_data());
    s.write_all(
        instruction_context
            .try_borrow_last_program_account(transaction_context)?
            .get_key()
            .as_ref(),
    );

    Ok(s.finish())
}

pub fn deserialize_parameters_aligned(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
    copy_account_data: bool,
    buffer: &[u8],
    account_lengths: &[usize],
) -> Result<(), InstructionError> {
    let mut start = size_of::<u64>(); // number of accounts
    for (instruction_account_index, pre_len) in
        (0..instruction_context.get_number_of_instruction_accounts()).zip(account_lengths.iter())
    {
        let duplicate =
            instruction_context.is_instruction_account_duplicate(instruction_account_index)?;
        start += size_of::<u8>(); // position
        if duplicate.is_some() {
            start += 7; // padding to 64-bit aligned
        } else {
            let mut borrowed_account = instruction_context
                .try_borrow_instruction_account(transaction_context, instruction_account_index)?;
            start += size_of::<u8>() // is_signer
                + size_of::<u8>() // is_writable
                + size_of::<u8>() // executable
                + size_of::<u32>() // original_data_len
                + size_of::<Pubkey>(); // key
            let owner = buffer
                .get(start..start + size_of::<Pubkey>())
                .ok_or(InstructionError::InvalidArgument)?;
            start += size_of::<Pubkey>(); // owner
            let lamports = LittleEndian::read_u64(
                buffer
                    .get(start..)
                    .ok_or(InstructionError::InvalidArgument)?,
            );
            if borrowed_account.get_lamports() != lamports {
                borrowed_account.set_lamports(lamports)?;
            }
            start += size_of::<u64>(); // lamports
            let post_len = LittleEndian::read_u64(
                buffer
                    .get(start..)
                    .ok_or(InstructionError::InvalidArgument)?,
            ) as usize;
            start += size_of::<u64>(); // data length
            if post_len.saturating_sub(*pre_len) > MAX_PERMITTED_DATA_INCREASE
                || post_len > MAX_PERMITTED_DATA_LENGTH as usize
            {
                return Err(InstructionError::InvalidRealloc);
            }
            // The redundant check helps to avoid the expensive data comparison if we can
            let alignment_offset = (*pre_len as *const u8).align_offset(BPF_ALIGN_OF_U128);
            if copy_account_data {
                let data = buffer
                    .get(start..start + post_len)
                    .ok_or(InstructionError::InvalidArgument)?;
                match borrowed_account
                    .can_data_be_resized(post_len)
                    .and_then(|_| borrowed_account.can_data_be_changed())
                {
                    Ok(()) => borrowed_account.set_data_from_slice(data)?,
                    Err(err) if borrowed_account.get_data() != data => return Err(err),
                    _ => {}
                }
                start += *pre_len; // data
            } else {
                // See Serializer::write_account() as to why we have this
                // padding before the realloc region here.
                start += BPF_ALIGN_OF_U128.saturating_sub(alignment_offset);
                let data = buffer
                    .get(start..start + MAX_PERMITTED_DATA_INCREASE)
                    .ok_or(InstructionError::InvalidArgument)?;
                match borrowed_account
                    .can_data_be_resized(post_len)
                    .and_then(|_| borrowed_account.can_data_be_changed())
                {
                    Ok(()) => {
                        borrowed_account.set_data_length(post_len)?;
                        let allocated_bytes = post_len.saturating_sub(*pre_len);
                        if allocated_bytes > 0 {
                            borrowed_account
                                .get_data_mut()?
                                .get_mut(*pre_len..pre_len.saturating_add(allocated_bytes))
                                .ok_or(InstructionError::InvalidArgument)?
                                .copy_from_slice(
                                    data.get(0..allocated_bytes)
                                        .ok_or(InstructionError::InvalidArgument)?,
                                );
                        }
                    }
                    Err(err) if borrowed_account.get_data().len() != post_len => return Err(err),
                    _ => {}
                }
            }
            start += MAX_PERMITTED_DATA_INCREASE;
            start += alignment_offset;
            start += size_of::<u64>(); // rent_epoch
            if borrowed_account.get_owner().to_bytes() != owner {
                // Change the owner at the end so that we are allowed to change the lamports and data before
                borrowed_account.set_owner(owner)?;
            }
        }
    }
    Ok(())
}
