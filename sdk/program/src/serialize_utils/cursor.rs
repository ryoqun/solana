use {
    crate::{instruction::InstructionError, pubkey::Pubkey},
    std::io::{Cursor, Read},
};

pub(crate) fn read_u8<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> Result<u8, InstructionError> {
    let mut buf = [0; 1];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| InstructionError::InvalidAccountData)?;

    Ok(buf[0])
}

pub(crate) fn read_u32<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> Result<u32, InstructionError> {
    let mut buf = [0; 4];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| InstructionError::InvalidAccountData)?;

    Ok(u32::from_le_bytes(buf))
}

pub(crate) fn read_u64<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> Result<u64, InstructionError> {
    let mut buf = [0; 8];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| InstructionError::InvalidAccountData)?;

    Ok(u64::from_le_bytes(buf))
}

pub(crate) fn read_option_u64<T: AsRef<[u8]>>(
    cursor: &mut Cursor<T>,
) -> Result<Option<u64>, InstructionError> {
    let variant = read_u8(cursor)?;
    match variant {
        0 => Ok(None),
        1 => read_u64(cursor).map(Some),
        _ => Err(InstructionError::InvalidAccountData),
    }
}

pub(crate) fn read_i64<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> Result<i64, InstructionError> {
    let mut buf = [0; 8];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| InstructionError::InvalidAccountData)?;

    Ok(i64::from_le_bytes(buf))
}

pub(crate) fn read_pubkey<T: AsRef<[u8]>>(
    cursor: &mut Cursor<T>,
) -> Result<Pubkey, InstructionError> {
    let mut buf = [0; 32];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| InstructionError::InvalidAccountData)?;

    Ok(Pubkey::from(buf))
}

pub(crate) fn read_bool<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> Result<bool, InstructionError> {
    let byte = read_u8(cursor)?;
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(InstructionError::InvalidAccountData),
    }
}
