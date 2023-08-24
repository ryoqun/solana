#![allow(dead_code)]
//! The account meta and related structs for hot accounts.

use {
    crate::{
        account_storage::meta::StoredMetaWriteVersion,
        tiered_storage::{
            byte_block,
            footer::{
                AccountBlockFormat, AccountMetaFormat, OwnersBlockFormat, TieredStorageFooter,
            },
            index::AccountIndexFormat,
            meta::{AccountMetaFlags, AccountMetaOptionalFields, TieredAccountMeta},
            TieredStorageFormat, TieredStorageResult,
        },
    },
    memmap2::{Mmap, MmapOptions},
    modular_bitfield::prelude::*,
    solana_sdk::{hash::Hash, stake_history::Epoch},
    std::{fs::OpenOptions, option::Option, path::Path},
};

pub const HOT_FORMAT: TieredStorageFormat = TieredStorageFormat {
    meta_entry_size: std::mem::size_of::<HotAccountMeta>(),
    account_meta_format: AccountMetaFormat::Hot,
    owners_block_format: OwnersBlockFormat::LocalIndex,
    account_index_format: AccountIndexFormat::AddressAndOffset,
    account_block_format: AccountBlockFormat::AlignedRaw,
};

/// The maximum number of padding bytes used in a hot account entry.
const MAX_HOT_PADDING: u8 = 7;

/// The maximum allowed value for the owner index of a hot account.
const MAX_HOT_OWNER_INDEX: u32 = (1 << 29) - 1;

#[bitfield(bits = 32)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
struct HotMetaPackedFields {
    /// A hot account entry consists of the following elements:
    ///
    /// * HotAccountMeta
    /// * [u8] account data
    /// * 0-7 bytes padding
    /// * optional fields
    ///
    /// The following field records the number of padding bytes used
    /// in its hot account entry.
    padding: B3,
    /// The index to the owner of a hot account inside an AccountsFile.
    owner_index: B29,
}

/// The storage and in-memory representation of the metadata entry for a
/// hot account.
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct HotAccountMeta {
    /// The balance of this account.
    lamports: u64,
    /// Stores important fields in a packed struct.
    packed_fields: HotMetaPackedFields,
    /// Stores boolean flags and existence of each optional field.
    flags: AccountMetaFlags,
}

impl TieredAccountMeta for HotAccountMeta {
    /// Construct a HotAccountMeta instance.
    fn new() -> Self {
        HotAccountMeta {
            lamports: 0,
            packed_fields: HotMetaPackedFields::default(),
            flags: AccountMetaFlags::new(),
        }
    }

    /// A builder function that initializes lamports.
    fn with_lamports(mut self, lamports: u64) -> Self {
        self.lamports = lamports;
        self
    }

    /// A builder function that initializes the number of padding bytes
    /// for the account data associated with the current meta.
    fn with_account_data_padding(mut self, padding: u8) -> Self {
        if padding > MAX_HOT_PADDING {
            panic!("padding exceeds MAX_HOT_PADDING");
        }
        self.packed_fields.set_padding(padding);
        self
    }

    /// A builder function that initializes the owner's index.
    fn with_owner_index(mut self, owner_index: u32) -> Self {
        if owner_index > MAX_HOT_OWNER_INDEX {
            panic!("owner_index exceeds MAX_HOT_OWNER_INDEX");
        }
        self.packed_fields.set_owner_index(owner_index);
        self
    }

    /// A builder function that initializes the account data size.
    fn with_account_data_size(self, _account_data_size: u64) -> Self {
        // Hot meta does not store its data size as it derives its data length
        // by comparing the offets of two consecutive account meta entries.
        self
    }

    /// A builder function that initializes the AccountMetaFlags of the current
    /// meta.
    fn with_flags(mut self, flags: &AccountMetaFlags) -> Self {
        self.flags = *flags;
        self
    }

    /// Returns the balance of the lamports associated with the account.
    fn lamports(&self) -> u64 {
        self.lamports
    }

    /// Returns the number of padding bytes for the associated account data
    fn account_data_padding(&self) -> u8 {
        self.packed_fields.padding()
    }

    /// Returns the index to the accounts' owner in the current AccountsFile.
    fn owner_index(&self) -> u32 {
        self.packed_fields.owner_index()
    }

    /// Returns the AccountMetaFlags of the current meta.
    fn flags(&self) -> &AccountMetaFlags {
        &self.flags
    }

    /// Always returns false as HotAccountMeta does not support multiple
    /// meta entries sharing the same account block.
    fn supports_shared_account_block() -> bool {
        false
    }

    /// Returns the epoch that this account will next owe rent by parsing
    /// the specified account block.  None will be returned if this account
    /// does not persist this optional field.
    fn rent_epoch(&self, account_block: &[u8]) -> Option<Epoch> {
        self.flags()
            .has_rent_epoch()
            .then(|| {
                let offset = self.optional_fields_offset(account_block)
                    + AccountMetaOptionalFields::rent_epoch_offset(self.flags());
                byte_block::read_type::<Epoch>(account_block, offset).copied()
            })
            .flatten()
    }

    /// Returns the account hash by parsing the specified account block.  None
    /// will be returned if this account does not persist this optional field.
    fn account_hash<'a>(&self, account_block: &'a [u8]) -> Option<&'a Hash> {
        self.flags()
            .has_account_hash()
            .then(|| {
                let offset = self.optional_fields_offset(account_block)
                    + AccountMetaOptionalFields::account_hash_offset(self.flags());
                byte_block::read_type::<Hash>(account_block, offset)
            })
            .flatten()
    }

    /// Returns the write version by parsing the specified account block.  None
    /// will be returned if this account does not persist this optional field.
    fn write_version(&self, account_block: &[u8]) -> Option<StoredMetaWriteVersion> {
        self.flags
            .has_write_version()
            .then(|| {
                let offset = self.optional_fields_offset(account_block)
                    + AccountMetaOptionalFields::write_version_offset(self.flags());
                byte_block::read_type::<StoredMetaWriteVersion>(account_block, offset).copied()
            })
            .flatten()
    }

    /// Returns the offset of the optional fields based on the specified account
    /// block.
    fn optional_fields_offset(&self, account_block: &[u8]) -> usize {
        account_block
            .len()
            .saturating_sub(AccountMetaOptionalFields::size_from_flags(&self.flags))
    }

    /// Returns the length of the data associated to this account based on the
    /// specified account block.
    fn account_data_size(&self, account_block: &[u8]) -> usize {
        self.optional_fields_offset(account_block)
            .saturating_sub(self.account_data_padding() as usize)
    }

    /// Returns the data associated to this account based on the specified
    /// account block.
    fn account_data<'a>(&self, account_block: &'a [u8]) -> &'a [u8] {
        &account_block[..self.account_data_size(account_block)]
    }
}

/// The reader to a hot accounts file.
#[derive(Debug)]
pub struct HotStorageReader {
    mmap: Mmap,
    footer: TieredStorageFooter,
}

impl HotStorageReader {
    /// Constructs a HotStorageReader from the specified path.
    pub fn new_from_path(path: impl AsRef<Path>) -> TieredStorageResult<Self> {
        let file = OpenOptions::new().read(true).open(path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        // Here we are cloning the footer as accessing any data in a
        // TieredStorage instance requires accessing its Footer.
        // This can help improve cache locality and reduce the overhead
        // of indirection associated with memory-mapped accesses.
        let footer = TieredStorageFooter::new_from_mmap(&mmap)?.clone();

        Ok(Self { mmap, footer })
    }

    /// Returns the footer of the underlying tiered-storage accounts file.
    pub fn footer(&self) -> &TieredStorageFooter {
        &self.footer
    }

    /// Returns the number of files inside the underlying tiered-storage
    /// accounts file.
    pub fn num_accounts(&self) -> usize {
        self.footer.account_entry_count as usize
    }
}
