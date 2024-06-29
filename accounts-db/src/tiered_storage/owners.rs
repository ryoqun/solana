use {
    crate::tiered_storage::{
        file::TieredWritableFile, footer::TieredStorageFooter, mmap_utils::get_pod,
        TieredStorageResult,
    },
    indexmap::set::IndexSet,
    memmap2::Mmap,
    solana_sdk::pubkey::Pubkey,
};

/// The offset to an owner entry in the owners block.
/// This is used to obtain the address of the account owner.
///
/// Note that as its internal type is u32, it means the maximum number of
/// unique owners in one TieredStorageFile is 2^32.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
pub struct OwnerOffset(pub u32);

/// Owner block holds a set of unique addresses of account owners,
/// and an account meta has a owner_offset field for accessing
/// it's owner address.
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
pub enum OwnersBlockFormat {
    /// This format persists OwnerBlock as a consecutive bytes of pubkeys
    /// without any meta-data.  For each account meta, it has a owner_offset
    /// field to access its owner's address in the OwnersBlock.
    #[default]
    AddressesOnly = 0,
}

impl OwnersBlockFormat {
    /// Persists the provided owners' addresses into the specified file.
    pub fn write_owners_block(
        &self,
        file: &mut TieredWritableFile,
        owners_table: &OwnersTable,
    ) -> TieredStorageResult<usize> {
        match self {
            Self::AddressesOnly => {
                let mut bytes_written = 0;
                for address in &owners_table.owners_set {
                    bytes_written += file.write_pod(address)?;
                }

                Ok(bytes_written)
            }
        }
    }

    /// Returns the owner address associated with the specified owner_offset
    /// and footer inside the input mmap.
    pub fn get_owner_address<'a>(
        &self,
        mmap: &'a Mmap,
        footer: &TieredStorageFooter,
        owner_offset: OwnerOffset,
    ) -> TieredStorageResult<&'a Pubkey> {
        match self {
            Self::AddressesOnly => {
                let offset = footer.owners_block_offset as usize
                    + (std::mem::size_of::<Pubkey>() * owner_offset.0 as usize);
                let (pubkey, _) = get_pod::<Pubkey>(mmap, offset)?;

                Ok(pubkey)
            }
        }
    }
}

/// The in-memory representation of owners block for write.
/// It manages a set of unique addresses of account owners.
#[derive(Debug, Default)]
pub struct OwnersTable {
    owners_set: IndexSet<Pubkey>,
}

/// OwnersBlock is persisted as a consecutive bytes of pubkeys without any
/// meta-data.  For each account meta, it has a owner_offset field to
/// access its owner's address in the OwnersBlock.
impl OwnersTable {
    /// Add the specified pubkey as the owner into the OwnersWriterTable
    /// if the specified pubkey has not existed in the OwnersWriterTable
    /// yet.  In any case, the function returns its OwnerOffset.
    pub fn insert(&mut self, pubkey: &Pubkey) -> OwnerOffset {
        let (offset, _existed) = self.owners_set.insert_full(*pubkey);

        OwnerOffset(offset as u32)
    }

    /// Returns the number of unique owner addresses in the table.
    pub fn len(&self) -> usize {
        self.owners_set.len()
    }

    /// Returns true if the OwnersTable is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
