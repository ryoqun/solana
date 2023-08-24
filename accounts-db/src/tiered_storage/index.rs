use {
    crate::tiered_storage::{
        file::TieredStorageFile, footer::TieredStorageFooter, mmap_utils::get_type,
        TieredStorageResult,
    },
    memmap2::Mmap,
    solana_sdk::pubkey::Pubkey,
};

/// The in-memory struct for the writing index block.
/// The actual storage format of a tiered account index entry might be different
/// from this.
#[derive(Debug)]
pub struct AccountIndexWriterEntry<'a> {
    pub address: &'a Pubkey,
    pub block_offset: u64,
    pub intra_block_offset: u64,
}

/// The index format of a tiered accounts file.
#[repr(u16)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    PartialEq,
    num_enum::IntoPrimitive,
    num_enum::TryFromPrimitive,
)]
pub enum AccountIndexFormat {
    /// This format optimizes the storage size by storing only account addresses
    /// and offsets.  It skips storing the size of account data by storing account
    /// block entries and index block entries in the same order.
    #[default]
    AddressAndOffset = 0,
}

impl AccountIndexFormat {
    /// Persists the specified index_entries to the specified file and returns
    /// the total number of bytes written.
    pub fn write_index_block(
        &self,
        file: &TieredStorageFile,
        index_entries: &[AccountIndexWriterEntry],
    ) -> TieredStorageResult<usize> {
        match self {
            Self::AddressAndOffset => {
                let mut bytes_written = 0;
                for index_entry in index_entries {
                    bytes_written += file.write_type(index_entry.address)?;
                }
                for index_entry in index_entries {
                    bytes_written += file.write_type(&index_entry.block_offset)?;
                }
                Ok(bytes_written)
            }
        }
    }

    /// Returns the address of the account given the specified index.
    pub fn get_account_address<'a>(
        &self,
        map: &'a Mmap,
        footer: &TieredStorageFooter,
        index: usize,
    ) -> TieredStorageResult<&'a Pubkey> {
        let offset = match self {
            Self::AddressAndOffset => {
                footer.account_index_offset as usize + std::mem::size_of::<Pubkey>() * index
            }
        };
        let (address, _) = get_type::<Pubkey>(map, offset)?;
        Ok(address)
    }

    /// Returns the offset to the account block that contains the account
    /// associated with the specified index to the index block.
    pub fn get_account_block_offset(
        &self,
        map: &Mmap,
        footer: &TieredStorageFooter,
        index: usize,
    ) -> TieredStorageResult<u64> {
        match self {
            Self::AddressAndOffset => {
                let offset = footer.account_index_offset as usize
                    + std::mem::size_of::<Pubkey>() * footer.account_entry_count as usize
                    + index * std::mem::size_of::<u64>();
                let (account_block_offset, _) = get_type(map, offset)?;
                Ok(*account_block_offset)
            }
        }
    }

    /// Returns the size of one index entry.
    pub fn entry_size(&self) -> usize {
        match self {
            Self::AddressAndOffset => std::mem::size_of::<Pubkey>() + std::mem::size_of::<u64>(),
        }
    }
}
