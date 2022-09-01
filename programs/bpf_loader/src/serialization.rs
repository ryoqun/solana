#![allow(clippy::integer_arithmetic)]

use {
    byteorder::{ByteOrder, LittleEndian, WriteBytesExt},
    solana_rbpf::{aligned_memory::AlignedMemory, ebpf::HOST_ALIGN},
    solana_sdk::{
        bpf_loader_deprecated,
        entrypoint::{BPF_ALIGN_OF_U128, MAX_PERMITTED_DATA_INCREASE},
        instruction::InstructionError,
        pubkey::Pubkey,
        system_instruction::MAX_PERMITTED_DATA_LENGTH,
        transaction_context::{InstructionContext, TransactionContext},
    },
    std::{io::prelude::*, mem::size_of},
};

/// Look for a duplicate account and return its position if found
pub fn is_duplicate(
    instruction_context: &InstructionContext,
    index_in_instruction: usize,
) -> Option<usize> {
    let index_in_transaction = instruction_context.get_index_in_transaction(index_in_instruction);
    (instruction_context.get_number_of_program_accounts()..index_in_instruction).position(
        |index_in_instruction| {
            instruction_context.get_index_in_transaction(index_in_instruction)
                == index_in_transaction
        },
    )
}

pub fn serialize_parameters(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
) -> Result<(AlignedMemory, Vec<usize>), InstructionError> {
    let is_loader_deprecated = *instruction_context
        .try_borrow_program_account(transaction_context)?
        .get_owner()
        == bpf_loader_deprecated::id();
    if is_loader_deprecated {
        serialize_parameters_unaligned(transaction_context, instruction_context)
    } else {
        serialize_parameters_aligned(transaction_context, instruction_context)
    }
    .and_then(|buffer| {
        let account_lengths = (instruction_context.get_number_of_program_accounts()
            ..instruction_context.get_number_of_accounts())
            .map(|index_in_instruction| {
                Ok(instruction_context
                    .try_borrow_account(transaction_context, index_in_instruction)?
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
    do_support_realloc: bool,
) -> Result<(), InstructionError> {
    let is_loader_deprecated = *instruction_context
        .try_borrow_program_account(transaction_context)?
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
            do_support_realloc,
        )
    }
}

pub fn serialize_parameters_unaligned(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
) -> Result<AlignedMemory, InstructionError> {
    // Calculate size in order to alloc once
    let mut size = size_of::<u64>();
    for index_in_instruction in instruction_context.get_number_of_program_accounts()
        ..instruction_context.get_number_of_accounts()
    {
        let duplicate = is_duplicate(instruction_context, index_in_instruction);
        size += 1; // dup
        if duplicate.is_none() {
            let data_len = instruction_context
                .try_borrow_account(transaction_context, index_in_instruction)?
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
    for index_in_instruction in instruction_context.get_number_of_program_accounts()
        ..instruction_context.get_number_of_accounts()
    {
        let duplicate = is_duplicate(instruction_context, index_in_instruction);
        if let Some(position) = duplicate {
            v.write_u8(position as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
        } else {
            let borrowed_account = instruction_context
                .try_borrow_account(transaction_context, index_in_instruction)?;
            v.write_u8(std::u8::MAX)
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
            .try_borrow_program_account(transaction_context)?
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
    for (index_in_instruction, pre_len) in (instruction_context.get_number_of_program_accounts()
        ..instruction_context.get_number_of_accounts())
        .zip(account_lengths.iter())
    {
        let duplicate = is_duplicate(instruction_context, index_in_instruction);
        start += 1; // is_dup
        if duplicate.is_none() {
            let mut borrowed_account = instruction_context
                .try_borrow_account(transaction_context, index_in_instruction)?;
            start += size_of::<u8>(); // is_signer
            start += size_of::<u8>(); // is_writable
            start += size_of::<Pubkey>(); // key
            let _ = borrowed_account.set_lamports(LittleEndian::read_u64(
                buffer
                    .get(start..)
                    .ok_or(InstructionError::InvalidArgument)?,
            ));
            start += size_of::<u64>() // lamports
                + size_of::<u64>(); // data length
            let _ = borrowed_account.set_data(
                buffer
                    .get(start..start + pre_len)
                    .ok_or(InstructionError::InvalidArgument)?,
            );
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
    for index_in_instruction in instruction_context.get_number_of_program_accounts()
        ..instruction_context.get_number_of_accounts()
    {
        let duplicate = is_duplicate(instruction_context, index_in_instruction);
        size += 1; // dup
        if duplicate.is_some() {
            size += 7; // padding to 64-bit aligned
        } else {
            let data_len = instruction_context
                .try_borrow_account(transaction_context, index_in_instruction)?
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
    for index_in_instruction in instruction_context.get_number_of_program_accounts()
        ..instruction_context.get_number_of_accounts()
    {
        let duplicate = is_duplicate(instruction_context, index_in_instruction);
        if let Some(position) = duplicate {
            v.write_u8(position as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(&[0u8, 0, 0, 0, 0, 0, 0])
                .map_err(|_| InstructionError::InvalidArgument)?; // 7 bytes of padding to make 64-bit aligned
        } else {
            let borrowed_account = instruction_context
                .try_borrow_account(transaction_context, index_in_instruction)?;
            v.write_u8(std::u8::MAX)
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
            .try_borrow_program_account(transaction_context)?
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
    do_support_realloc: bool,
) -> Result<(), InstructionError> {
    let mut start = size_of::<u64>(); // number of accounts
    for (index_in_instruction, pre_len) in (instruction_context.get_number_of_program_accounts()
        ..instruction_context.get_number_of_accounts())
        .zip(account_lengths.iter())
    {
        let duplicate = is_duplicate(instruction_context, index_in_instruction);
        start += size_of::<u8>(); // position
        if duplicate.is_some() {
            start += 7; // padding to 64-bit aligned
        } else {
            let mut borrowed_account = instruction_context
                .try_borrow_account(transaction_context, index_in_instruction)?;
            start += size_of::<u8>() // is_signer
                + size_of::<u8>() // is_writable
                + size_of::<u8>() // executable
                + size_of::<u32>() // original_data_len
                + size_of::<Pubkey>(); // key
            let _ = borrowed_account.set_owner(
                buffer
                    .get(start..start + size_of::<Pubkey>())
                    .ok_or(InstructionError::InvalidArgument)?,
            );
            start += size_of::<Pubkey>(); // owner
            let _ = borrowed_account.set_lamports(LittleEndian::read_u64(
                buffer
                    .get(start..)
                    .ok_or(InstructionError::InvalidArgument)?,
            ));
            start += size_of::<u64>(); // lamports
            let post_len = LittleEndian::read_u64(
                buffer
                    .get(start..)
                    .ok_or(InstructionError::InvalidArgument)?,
            ) as usize;
            start += size_of::<u64>(); // data length
            let data_end = if do_support_realloc {
                if post_len.saturating_sub(*pre_len) > MAX_PERMITTED_DATA_INCREASE
                    || post_len > MAX_PERMITTED_DATA_LENGTH as usize
                {
                    return Err(InstructionError::InvalidRealloc);
                }
                start + post_len
            } else {
                let mut data_end = start + *pre_len;
                if post_len != *pre_len
                    && (post_len.saturating_sub(*pre_len)) <= MAX_PERMITTED_DATA_INCREASE
                {
                    data_end = start + post_len;
                }
                data_end
            };
            let _ = borrowed_account.set_data(
                buffer
                    .get(start..data_end)
                    .ok_or(InstructionError::InvalidArgument)?,
            );
            start += *pre_len + MAX_PERMITTED_DATA_INCREASE; // data
            start += (start as *const u8).align_offset(BPF_ALIGN_OF_U128);
            start += size_of::<u64>(); // rent_epoch
        }
    }
    Ok(())
}
