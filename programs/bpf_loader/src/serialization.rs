#![allow(clippy::integer_arithmetic)]

use {
    byteorder::{ByteOrder, LittleEndian, WriteBytesExt},
    solana_rbpf::{aligned_memory::AlignedMemory, ebpf::HOST_ALIGN},
    solana_sdk::{
        bpf_loader_deprecated,
        entrypoint::{BPF_ALIGN_OF_U128, MAX_PERMITTED_DATA_INCREASE, NON_DUP_MARKER},
        instruction::InstructionError,
        pubkey::Pubkey,
        system_instruction::MAX_PERMITTED_DATA_LENGTH,
        transaction_context::{InstructionContext, TransactionContext},
    },
    std::{io::prelude::*, mem::size_of},
};

/// Maximum number of instruction accounts that can be serialized into the
/// BPF VM.
const MAX_INSTRUCTION_ACCOUNTS: u8 = NON_DUP_MARKER;

pub fn serialize_parameters(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
    should_cap_ix_accounts: bool,
) -> Result<(AlignedMemory, Vec<usize>), InstructionError> {
    let num_ix_accounts = instruction_context.get_number_of_instruction_accounts();
    if should_cap_ix_accounts && num_ix_accounts > usize::from(MAX_INSTRUCTION_ACCOUNTS) {
        return Err(InstructionError::MaxAccountsExceeded);
    }

    let is_loader_deprecated = *instruction_context
        .try_borrow_last_program_account(transaction_context)?
        .get_owner()
        == bpf_loader_deprecated::id();
    if is_loader_deprecated {
        serialize_parameters_unaligned(transaction_context, instruction_context)
    } else {
        serialize_parameters_aligned(transaction_context, instruction_context)
    }
    .and_then(|buffer| {
        let account_lengths = (0..instruction_context.get_number_of_instruction_accounts())
            .map(|instruction_account_index| {
                Ok(instruction_context
                    .try_borrow_instruction_account(transaction_context, instruction_account_index)?
                    .get_data()
                    .len())
            })
            .collect::<Result<Vec<usize>, InstructionError>>()?;
        Ok((buffer, account_lengths))
    })
}

pub fn deserialize_parameters(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
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
            buffer,
            account_lengths,
        )
    } else {
        deserialize_parameters_aligned(
            transaction_context,
            instruction_context,
            buffer,
            account_lengths,
        )
    }
}

pub fn serialize_parameters_unaligned(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
) -> Result<AlignedMemory, InstructionError> {
    // Calculate size in order to alloc once
    let mut size = size_of::<u64>();
    for instruction_account_index in 0..instruction_context.get_number_of_instruction_accounts() {
        let duplicate =
            instruction_context.is_instruction_account_duplicate(instruction_account_index)?;
        size += 1; // dup
        if duplicate.is_none() {
            let data_len = instruction_context
                .try_borrow_instruction_account(transaction_context, instruction_account_index)?
                .get_data()
                .len();
            size += size_of::<u8>() // is_signer
                + size_of::<u8>() // is_writable
                + size_of::<Pubkey>() // key
                + size_of::<u64>()  // lamports
                + size_of::<u64>()  // data len
                + data_len // data
                + size_of::<Pubkey>() // owner
                + size_of::<u8>() // executable
                + size_of::<u64>(); // rent_epoch
        }
    }
    size += size_of::<u64>() // instruction data len
         + instruction_context.get_instruction_data().len() // instruction data
         + size_of::<Pubkey>(); // program id
    let mut v = AlignedMemory::new(size, HOST_ALIGN);

    v.write_u64::<LittleEndian>(instruction_context.get_number_of_instruction_accounts() as u64)
        .map_err(|_| InstructionError::InvalidArgument)?;
    for instruction_account_index in 0..instruction_context.get_number_of_instruction_accounts() {
        let duplicate =
            instruction_context.is_instruction_account_duplicate(instruction_account_index)?;
        if let Some(position) = duplicate {
            v.write_u8(position as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
        } else {
            let borrowed_account = instruction_context
                .try_borrow_instruction_account(transaction_context, instruction_account_index)?;
            v.write_u8(NON_DUP_MARKER)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(borrowed_account.is_signer() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(borrowed_account.is_writable() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(borrowed_account.get_key().as_ref())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(borrowed_account.get_lamports())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(borrowed_account.get_data().len() as u64)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(borrowed_account.get_data())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(borrowed_account.get_owner().as_ref())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(borrowed_account.is_executable() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(borrowed_account.get_rent_epoch() as u64)
                .map_err(|_| InstructionError::InvalidArgument)?;
        }
    }
    v.write_u64::<LittleEndian>(instruction_context.get_instruction_data().len() as u64)
        .map_err(|_| InstructionError::InvalidArgument)?;
    v.write_all(instruction_context.get_instruction_data())
        .map_err(|_| InstructionError::InvalidArgument)?;
    v.write_all(
        instruction_context
            .try_borrow_last_program_account(transaction_context)?
            .get_key()
            .as_ref(),
    )
    .map_err(|_| InstructionError::InvalidArgument)?;
    Ok(v)
}

pub fn deserialize_parameters_unaligned(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
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
            let data = buffer
                .get(start..start + pre_len)
                .ok_or(InstructionError::InvalidArgument)?;
            // The redundant check helps to avoid the expensive data comparison if we can
            match borrowed_account
                .can_data_be_resized(data.len())
                .and_then(|_| borrowed_account.can_data_be_changed())
            {
                Ok(()) => borrowed_account.set_data(data)?,
                Err(err) if borrowed_account.get_data() != data => return Err(err),
                _ => {}
            }
            start += pre_len // data
                + size_of::<Pubkey>() // owner
                + size_of::<u8>() // executable
                + size_of::<u64>(); // rent_epoch
        }
    }
    Ok(())
}

pub fn serialize_parameters_aligned(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
) -> Result<AlignedMemory, InstructionError> {
    // Calculate size in order to alloc once
    let mut size = size_of::<u64>();
    for instruction_account_index in 0..instruction_context.get_number_of_instruction_accounts() {
        let duplicate =
            instruction_context.is_instruction_account_duplicate(instruction_account_index)?;
        size += 1; // dup
        if duplicate.is_some() {
            size += 7; // padding to 64-bit aligned
        } else {
            let data_len = instruction_context
                .try_borrow_instruction_account(transaction_context, instruction_account_index)?
                .get_data()
                .len();
            size += size_of::<u8>() // is_signer
                + size_of::<u8>() // is_writable
                + size_of::<u8>() // executable
                + size_of::<u32>() // original_data_len
                + size_of::<Pubkey>()  // key
                + size_of::<Pubkey>() // owner
                + size_of::<u64>()  // lamports
                + size_of::<u64>()  // data len
                + data_len
                + MAX_PERMITTED_DATA_INCREASE
                + (data_len as *const u8).align_offset(BPF_ALIGN_OF_U128)
                + size_of::<u64>(); // rent epoch
        }
    }
    size += size_of::<u64>() // data len
    + instruction_context.get_instruction_data().len()
    + size_of::<Pubkey>(); // program id;
    let mut v = AlignedMemory::new(size, HOST_ALIGN);

    // Serialize into the buffer
    v.write_u64::<LittleEndian>(instruction_context.get_number_of_instruction_accounts() as u64)
        .map_err(|_| InstructionError::InvalidArgument)?;
    for instruction_account_index in 0..instruction_context.get_number_of_instruction_accounts() {
        let duplicate =
            instruction_context.is_instruction_account_duplicate(instruction_account_index)?;
        if let Some(position) = duplicate {
            v.write_u8(position as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(&[0u8, 0, 0, 0, 0, 0, 0])
                .map_err(|_| InstructionError::InvalidArgument)?; // 7 bytes of padding to make 64-bit aligned
        } else {
            let borrowed_account = instruction_context
                .try_borrow_instruction_account(transaction_context, instruction_account_index)?;
            v.write_u8(NON_DUP_MARKER)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(borrowed_account.is_signer() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(borrowed_account.is_writable() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(borrowed_account.is_executable() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(&[0u8, 0, 0, 0])
                .map_err(|_| InstructionError::InvalidArgument)?; // 4 bytes of padding to make 128-bit aligned
            v.write_all(borrowed_account.get_key().as_ref())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(borrowed_account.get_owner().as_ref())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(borrowed_account.get_lamports())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(borrowed_account.get_data().len() as u64)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(borrowed_account.get_data())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.resize(
                MAX_PERMITTED_DATA_INCREASE
                    + (v.write_index() as *const u8).align_offset(BPF_ALIGN_OF_U128),
                0,
            )
            .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(borrowed_account.get_rent_epoch() as u64)
                .map_err(|_| InstructionError::InvalidArgument)?;
        }
    }
    v.write_u64::<LittleEndian>(instruction_context.get_instruction_data().len() as u64)
        .map_err(|_| InstructionError::InvalidArgument)?;
    v.write_all(instruction_context.get_instruction_data())
        .map_err(|_| InstructionError::InvalidArgument)?;
    v.write_all(
        instruction_context
            .try_borrow_last_program_account(transaction_context)?
            .get_key()
            .as_ref(),
    )
    .map_err(|_| InstructionError::InvalidArgument)?;
    Ok(v)
}

pub fn deserialize_parameters_aligned(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
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
            let data_end = start + post_len;
            let data = buffer
                .get(start..data_end)
                .ok_or(InstructionError::InvalidArgument)?;
            // The redundant check helps to avoid the expensive data comparison if we can
            match borrowed_account
                .can_data_be_resized(data.len())
                .and_then(|_| borrowed_account.can_data_be_changed())
            {
                Ok(()) => borrowed_account.set_data(data)?,
                Err(err) if borrowed_account.get_data() != data => return Err(err),
                _ => {}
            }
            start += *pre_len + MAX_PERMITTED_DATA_INCREASE; // data
            start += (start as *const u8).align_offset(BPF_ALIGN_OF_U128);
            start += size_of::<u64>(); // rent_epoch
            if borrowed_account.get_owner().to_bytes() != owner {
                // Change the owner at the end so that we are allowed to change the lamports and data before
                borrowed_account.set_owner(owner)?;
            }
        }
    }
    Ok(())
}
