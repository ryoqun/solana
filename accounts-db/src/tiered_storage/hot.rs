//! The account meta and related structs for hot accounts.

use {
    crate::{
        account_info::AccountInfo,
        account_storage::meta::StoredAccountMeta,
        accounts_file::{MatchAccountOwnerError, StoredAccountsInfo},
        append_vec::{IndexInfo, IndexInfoInner},
        tiered_storage::{
            byte_block,
            file::{TieredReadableFile, TieredWritableFile},
            footer::{AccountBlockFormat, AccountMetaFormat, TieredStorageFooter},
            index::{AccountIndexWriterEntry, AccountOffset, IndexBlockFormat, IndexOffset},
            meta::{
                AccountAddressRange, AccountMetaFlags, AccountMetaOptionalFields, TieredAccountMeta,
            },
            mmap_utils::{get_pod, get_slice},
            owners::{OwnerOffset, OwnersBlockFormat, OwnersTable},
            StorableAccounts, TieredStorageError, TieredStorageFormat, TieredStorageResult,
        },
    },
    bytemuck_derive::{Pod, Zeroable},
    memmap2::{Mmap, MmapOptions},
    modular_bitfield::prelude::*,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        pubkey::Pubkey,
        rent_collector::RENT_EXEMPT_RENT_EPOCH,
        stake_history::Epoch,
    },
    std::{io::Write, option::Option, path::Path},
};

pub const HOT_FORMAT: TieredStorageFormat = TieredStorageFormat {
    meta_entry_size: std::mem::size_of::<HotAccountMeta>(),
    account_meta_format: AccountMetaFormat::Hot,
    owners_block_format: OwnersBlockFormat::AddressesOnly,
    index_block_format: IndexBlockFormat::AddressesThenOffsets,
    account_block_format: AccountBlockFormat::AlignedRaw,
};

/// An helper function that creates a new default footer for hot
/// accounts storage.
fn new_hot_footer() -> TieredStorageFooter {
    TieredStorageFooter {
        account_meta_format: HOT_FORMAT.account_meta_format,
        account_meta_entry_size: HOT_FORMAT.meta_entry_size as u32,
        account_block_format: HOT_FORMAT.account_block_format,
        index_block_format: HOT_FORMAT.index_block_format,
        owners_block_format: HOT_FORMAT.owners_block_format,
        ..TieredStorageFooter::default()
    }
}

/// The maximum allowed value for the owner index of a hot account.
const MAX_HOT_OWNER_OFFSET: OwnerOffset = OwnerOffset((1 << 29) - 1);

/// The byte alignment for hot accounts.  This alignment serves duo purposes.
/// First, it allows hot accounts to be directly accessed when the underlying
/// file is mmapped.  In addition, as all hot accounts are aligned, it allows
/// each hot accounts file to handle more accounts with the same number of
/// bytes in HotAccountOffset.
pub(crate) const HOT_ACCOUNT_ALIGNMENT: usize = 8;

/// The alignment for the blocks inside a hot accounts file.  A hot accounts
/// file consists of accounts block, index block, owners block, and footer.
/// This requirement allows the offset of each block properly aligned so
/// that they can be readable under mmap.
pub(crate) const HOT_BLOCK_ALIGNMENT: usize = 8;

/// The maximum supported offset for hot accounts storage.
const MAX_HOT_ACCOUNT_OFFSET: usize = u32::MAX as usize * HOT_ACCOUNT_ALIGNMENT;

// returns the required number of padding
fn padding_bytes(data_len: usize) -> u8 {
    ((HOT_ACCOUNT_ALIGNMENT - (data_len % HOT_ACCOUNT_ALIGNMENT)) % HOT_ACCOUNT_ALIGNMENT) as u8
}

/// The maximum number of padding bytes used in a hot account entry.
const MAX_HOT_PADDING: u8 = 7;

/// The buffer that is used for padding.
const PADDING_BUFFER: [u8; 8] = [0u8; HOT_ACCOUNT_ALIGNMENT];

#[bitfield(bits = 32)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Pod, Zeroable)]
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
    owner_offset: B29,
}

// Ensure there are no implicit padding bytes
const _: () = assert!(std::mem::size_of::<HotMetaPackedFields>() == 4);

/// The offset to access a hot account.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Pod, Zeroable)]
pub struct HotAccountOffset(u32);

// Ensure there are no implicit padding bytes
const _: () = assert!(std::mem::size_of::<HotAccountOffset>() == 4);

impl AccountOffset for HotAccountOffset {}

impl HotAccountOffset {
    /// Creates a new AccountOffset instance
    pub fn new(offset: usize) -> TieredStorageResult<Self> {
        if offset > MAX_HOT_ACCOUNT_OFFSET {
            return Err(TieredStorageError::OffsetOutOfBounds(
                offset,
                MAX_HOT_ACCOUNT_OFFSET,
            ));
        }

        // Hot accounts are aligned based on HOT_ACCOUNT_ALIGNMENT.
        if offset % HOT_ACCOUNT_ALIGNMENT != 0 {
            return Err(TieredStorageError::OffsetAlignmentError(
                offset,
                HOT_ACCOUNT_ALIGNMENT,
            ));
        }

        Ok(HotAccountOffset((offset / HOT_ACCOUNT_ALIGNMENT) as u32))
    }

    /// Returns the offset to the account.
    fn offset(&self) -> usize {
        self.0 as usize * HOT_ACCOUNT_ALIGNMENT
    }
}

/// The storage and in-memory representation of the metadata entry for a
/// hot account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct HotAccountMeta {
    /// The balance of this account.
    lamports: u64,
    /// Stores important fields in a packed struct.
    packed_fields: HotMetaPackedFields,
    /// Stores boolean flags and existence of each optional field.
    flags: AccountMetaFlags,
}

// Ensure there are no implicit padding bytes
const _: () = assert!(std::mem::size_of::<HotAccountMeta>() == 8 + 4 + 4);

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
    fn with_owner_offset(mut self, owner_offset: OwnerOffset) -> Self {
        if owner_offset > MAX_HOT_OWNER_OFFSET {
            panic!("owner_offset exceeds MAX_HOT_OWNER_OFFSET");
        }
        self.packed_fields.set_owner_offset(owner_offset.0);
        self
    }

    /// A builder function that initializes the account data size.
    fn with_account_data_size(self, _account_data_size: u64) -> Self {
        // Hot meta does not store its data size as it derives its data length
        // by comparing the offsets of two consecutive account meta entries.
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
    fn owner_offset(&self) -> OwnerOffset {
        OwnerOffset(self.packed_fields.owner_offset())
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
                byte_block::read_pod::<Epoch>(account_block, offset).copied()
            })
            .flatten()
    }

    /// Returns the epoch that this account will next owe rent by parsing
    /// the specified account block.  RENT_EXEMPT_RENT_EPOCH will be returned
    /// if the account is rent-exempt.
    ///
    /// For a zero-lamport account, Epoch::default() will be returned to
    /// default states of an AccountSharedData.
    fn final_rent_epoch(&self, account_block: &[u8]) -> Epoch {
        self.rent_epoch(account_block)
            .unwrap_or(if self.lamports() != 0 {
                RENT_EXEMPT_RENT_EPOCH
            } else {
                // While there is no valid-values for any fields of a zero
                // lamport account, here we return Epoch::default() to
                // match the default states of AccountSharedData.  Otherwise,
                // a hash mismatch will occur.
                Epoch::default()
            })
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

/// The struct that offers read APIs for accessing a hot account.
#[derive(PartialEq, Eq, Debug)]
pub struct HotAccount<'accounts_file, M: TieredAccountMeta> {
    /// TieredAccountMeta
    pub meta: &'accounts_file M,
    /// The address of the account
    pub address: &'accounts_file Pubkey,
    /// The address of the account owner
    pub owner: &'accounts_file Pubkey,
    /// The index for accessing the account inside its belonging AccountsFile
    pub index: IndexOffset,
    /// The account block that contains this account.  Note that this account
    /// block may be shared with other accounts.
    pub account_block: &'accounts_file [u8],
}

impl<'accounts_file, M: TieredAccountMeta> HotAccount<'accounts_file, M> {
    /// Returns the address of this account.
    pub fn address(&self) -> &'accounts_file Pubkey {
        self.address
    }

    /// Returns the index to this account in its AccountsFile.
    pub fn index(&self) -> IndexOffset {
        self.index
    }

    /// Returns the data associated to this account.
    pub fn data(&self) -> &'accounts_file [u8] {
        self.meta.account_data(self.account_block)
    }

    /// Returns the approximate stored size of this account.
    pub fn stored_size(&self) -> usize {
        stored_size(self.meta.account_data_size(self.account_block))
    }
}

impl<'accounts_file, M: TieredAccountMeta> ReadableAccount for HotAccount<'accounts_file, M> {
    /// Returns the balance of the lamports of this account.
    fn lamports(&self) -> u64 {
        self.meta.lamports()
    }

    /// Returns the address of the owner of this account.
    fn owner(&self) -> &'accounts_file Pubkey {
        self.owner
    }

    /// Returns true if the data associated to this account is executable.
    fn executable(&self) -> bool {
        self.meta.flags().executable()
    }

    /// Returns the epoch that this account will next owe rent by parsing
    /// the specified account block.  RENT_EXEMPT_RENT_EPOCH will be returned
    /// if the account is rent-exempt.
    ///
    /// For a zero-lamport account, Epoch::default() will be returned to
    /// default states of an AccountSharedData.
    fn rent_epoch(&self) -> Epoch {
        self.meta.final_rent_epoch(self.account_block)
    }

    /// Returns the data associated to this account.
    fn data(&self) -> &'accounts_file [u8] {
        self.data()
    }
}

/// The reader to a hot accounts file.
#[derive(Debug)]
pub struct HotStorageReader {
    mmap: Mmap,
    footer: TieredStorageFooter,
}

impl HotStorageReader {
    pub fn new(file: TieredReadableFile) -> TieredStorageResult<Self> {
        let mmap = unsafe { MmapOptions::new().map(&file.0)? };
        // Here we are copying the footer, as accessing any data in a
        // TieredStorage instance requires accessing its Footer.
        // This can help improve cache locality and reduce the overhead
        // of indirection associated with memory-mapped accesses.
        let footer = *TieredStorageFooter::new_from_mmap(&mmap)?;

        Ok(Self { mmap, footer })
    }

    /// Returns the size of the underlying storage.
    pub fn len(&self) -> usize {
        self.mmap.len()
    }

    /// Returns whether the nderlying storage is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> u64 {
        self.len() as u64
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

    /// Returns the account meta located at the specified offset.
    fn get_account_meta_from_offset(
        &self,
        account_offset: HotAccountOffset,
    ) -> TieredStorageResult<&HotAccountMeta> {
        let offset = account_offset.offset();

        assert!(
            offset.saturating_add(std::mem::size_of::<HotAccountMeta>())
                <= self.footer.index_block_offset as usize,
            "reading HotAccountOffset ({}) would exceed accounts blocks offset boundary ({}).",
            offset,
            self.footer.index_block_offset,
        );
        let (meta, _) = get_pod::<HotAccountMeta>(&self.mmap, offset)?;
        Ok(meta)
    }

    /// Returns the offset to the account given the specified index.
    pub(super) fn get_account_offset(
        &self,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<HotAccountOffset> {
        self.footer
            .index_block_format
            .get_account_offset::<HotAccountOffset>(&self.mmap, &self.footer, index_offset)
    }

    /// Returns the address of the account associated with the specified index.
    fn get_account_address(&self, index: IndexOffset) -> TieredStorageResult<&Pubkey> {
        self.footer
            .index_block_format
            .get_account_address(&self.mmap, &self.footer, index)
    }

    /// Returns the address of the account owner given the specified
    /// owner_offset.
    fn get_owner_address(&self, owner_offset: OwnerOffset) -> TieredStorageResult<&Pubkey> {
        self.footer
            .owners_block_format
            .get_owner_address(&self.mmap, &self.footer, owner_offset)
    }

    /// Returns Ok(index_of_matching_owner) if the account owner at
    /// `account_offset` is one of the pubkeys in `owners`.
    ///
    /// Returns Err(MatchAccountOwnerError::NoMatch) if the account has 0
    /// lamports or the owner is not one of the pubkeys in `owners`.
    ///
    /// Returns Err(MatchAccountOwnerError::UnableToLoad) if there is any internal
    /// error that causes the data unable to load, including `account_offset`
    /// causes a data overrun.
    pub fn account_matches_owners(
        &self,
        account_offset: HotAccountOffset,
        owners: &[Pubkey],
    ) -> Result<usize, MatchAccountOwnerError> {
        let account_meta = self
            .get_account_meta_from_offset(account_offset)
            .map_err(|_| MatchAccountOwnerError::UnableToLoad)?;

        if account_meta.lamports() == 0 {
            Err(MatchAccountOwnerError::NoMatch)
        } else {
            let account_owner = self
                .get_owner_address(account_meta.owner_offset())
                .map_err(|_| MatchAccountOwnerError::UnableToLoad)?;

            owners
                .iter()
                .position(|candidate| account_owner == candidate)
                .ok_or(MatchAccountOwnerError::NoMatch)
        }
    }

    /// Returns the size of the account block based on its account offset
    /// and index offset.
    ///
    /// The account block size information is omitted in the hot accounts file
    /// as it can be derived by comparing the offset of the next hot account
    /// meta in the index block.
    fn get_account_block_size(
        &self,
        account_offset: HotAccountOffset,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<usize> {
        // the offset that points to the hot account meta.
        let account_meta_offset = account_offset.offset();

        // Obtain the ending offset of the account block.  If the current
        // account is the last account, then the ending offset is the
        // index_block_offset.
        let account_block_ending_offset =
            if index_offset.0.saturating_add(1) == self.footer.account_entry_count {
                self.footer.index_block_offset as usize
            } else {
                self.get_account_offset(IndexOffset(index_offset.0.saturating_add(1)))?
                    .offset()
            };

        // With the ending offset, minus the starting offset (i.e.,
        // the account meta offset) and the HotAccountMeta size, the reminder
        // is the account block size (account data + optional fields).
        Ok(account_block_ending_offset
            .saturating_sub(account_meta_offset)
            .saturating_sub(std::mem::size_of::<HotAccountMeta>()))
    }

    /// Returns the account block that contains the account associated with
    /// the specified index given the offset to the account meta and its index.
    fn get_account_block(
        &self,
        account_offset: HotAccountOffset,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<&[u8]> {
        let (data, _) = get_slice(
            &self.mmap,
            account_offset.offset() + std::mem::size_of::<HotAccountMeta>(),
            self.get_account_block_size(account_offset, index_offset)?,
        )?;

        Ok(data)
    }

    /// calls `callback` with the account located at the specified index offset.
    pub fn get_stored_account_meta_callback<Ret>(
        &self,
        index_offset: IndexOffset,
        mut callback: impl for<'local> FnMut(StoredAccountMeta<'local>) -> Ret,
    ) -> TieredStorageResult<Option<Ret>> {
        if index_offset.0 >= self.footer.account_entry_count {
            return Ok(None);
        }

        let account_offset = self.get_account_offset(index_offset)?;

        let meta = self.get_account_meta_from_offset(account_offset)?;
        let address = self.get_account_address(index_offset)?;
        let owner = self.get_owner_address(meta.owner_offset())?;
        let account_block = self.get_account_block(account_offset, index_offset)?;

        Ok(Some(callback(StoredAccountMeta::Hot(HotAccount {
            meta,
            address,
            owner,
            index: index_offset,
            account_block,
        }))))
    }

    /// Returns the account located at the specified index offset.
    pub fn get_account_shared_data(
        &self,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<Option<AccountSharedData>> {
        if index_offset.0 >= self.footer.account_entry_count {
            return Ok(None);
        }

        let account_offset = self.get_account_offset(index_offset)?;

        let meta = self.get_account_meta_from_offset(account_offset)?;
        let account_block = self.get_account_block(account_offset, index_offset)?;

        let lamports = meta.lamports();
        let data = meta.account_data(account_block).to_vec();
        let owner = *self.get_owner_address(meta.owner_offset())?;
        let executable = meta.flags().executable();
        let rent_epoch = meta.final_rent_epoch(account_block);
        Ok(Some(AccountSharedData::create(
            lamports, data, owner, executable, rent_epoch,
        )))
    }

    /// iterate over all pubkeys
    pub fn scan_pubkeys(&self, mut callback: impl FnMut(&Pubkey)) -> TieredStorageResult<()> {
        for i in 0..self.footer.account_entry_count {
            let address = self.get_account_address(IndexOffset(i))?;
            callback(address);
        }
        Ok(())
    }

    /// for each offset in `sorted_offsets`, return the account size
    pub(crate) fn get_account_sizes(
        &self,
        sorted_offsets: &[usize],
    ) -> TieredStorageResult<Vec<usize>> {
        let mut result = Vec::with_capacity(sorted_offsets.len());
        for &offset in sorted_offsets {
            let index_offset = IndexOffset(AccountInfo::get_reduced_offset(offset));
            let account_offset = self.get_account_offset(index_offset)?;
            let meta = self.get_account_meta_from_offset(account_offset)?;
            let account_block = self.get_account_block(account_offset, index_offset)?;
            let data_len = meta.account_data_size(account_block);
            result.push(stored_size(data_len));
        }
        Ok(result)
    }

    /// Iterate over all accounts and call `callback` with each account.
    pub(crate) fn scan_accounts(
        &self,
        mut callback: impl for<'local> FnMut(StoredAccountMeta<'local>),
    ) -> TieredStorageResult<()> {
        for i in 0..self.footer.account_entry_count {
            self.get_stored_account_meta_callback(IndexOffset(i), &mut callback)?;
        }
        Ok(())
    }

    /// iterate over all entries to put in index
    pub(crate) fn scan_index(
        &self,
        mut callback: impl FnMut(IndexInfo),
    ) -> TieredStorageResult<()> {
        for i in 0..self.footer.account_entry_count {
            let index_offset = IndexOffset(i);
            let account_offset = self.get_account_offset(index_offset)?;

            let meta = self.get_account_meta_from_offset(account_offset)?;
            let pubkey = self.get_account_address(index_offset)?;
            let lamports = meta.lamports();
            let account_block = self.get_account_block(account_offset, index_offset)?;
            let data_len = meta.account_data_size(account_block);
            callback(IndexInfo {
                index_info: {
                    IndexInfoInner {
                        pubkey: *pubkey,
                        lamports,
                        offset: AccountInfo::reduced_offset_to_offset(i),
                        data_len: data_len as u64,
                        executable: meta.flags().executable(),
                        rent_epoch: meta.final_rent_epoch(account_block),
                    }
                },
                stored_size_aligned: stored_size(data_len),
            });
        }
        Ok(())
    }

    /// Returns a slice suitable for use when archiving hot storages
    pub fn data_for_archive(&self) -> &[u8] {
        self.mmap.as_ref()
    }
}

/// return an approximation of the cost to store an account.
/// Some fields like owner are shared across multiple accounts.
fn stored_size(data_len: usize) -> usize {
    data_len + std::mem::size_of::<Pubkey>()
}

fn write_optional_fields(
    file: &mut TieredWritableFile,
    opt_fields: &AccountMetaOptionalFields,
) -> TieredStorageResult<usize> {
    let mut size = 0;
    if let Some(rent_epoch) = opt_fields.rent_epoch {
        size += file.write_pod(&rent_epoch)?;
    }

    debug_assert_eq!(size, opt_fields.size());

    Ok(size)
}

/// The writer that creates a hot accounts file.
#[derive(Debug)]
pub struct HotStorageWriter {
    storage: TieredWritableFile,
}

impl HotStorageWriter {
    /// Create a new HotStorageWriter with the specified path.
    pub fn new(file_path: impl AsRef<Path>) -> TieredStorageResult<Self> {
        Ok(Self {
            storage: TieredWritableFile::new(file_path)?,
        })
    }

    /// Persists an account with the specified information and returns
    /// the stored size of the account.
    fn write_account(
        &mut self,
        lamports: u64,
        owner_offset: OwnerOffset,
        account_data: &[u8],
        executable: bool,
        rent_epoch: Option<Epoch>,
    ) -> TieredStorageResult<usize> {
        let optional_fields = AccountMetaOptionalFields { rent_epoch };

        let mut flags = AccountMetaFlags::new_from(&optional_fields);
        flags.set_executable(executable);

        let padding_len = padding_bytes(account_data.len());
        let meta = HotAccountMeta::new()
            .with_lamports(lamports)
            .with_owner_offset(owner_offset)
            .with_account_data_size(account_data.len() as u64)
            .with_account_data_padding(padding_len)
            .with_flags(&flags);

        let mut stored_size = 0;

        stored_size += self.storage.write_pod(&meta)?;
        stored_size += self.storage.write_bytes(account_data)?;
        stored_size += self
            .storage
            .write_bytes(&PADDING_BUFFER[0..(padding_len as usize)])?;
        stored_size += write_optional_fields(&mut self.storage, &optional_fields)?;

        Ok(stored_size)
    }

    /// Persists `accounts` into the underlying hot accounts file associated
    /// with this HotStorageWriter.  The first `skip` number of accounts are
    /// *not* persisted.
    pub fn write_accounts<'a>(
        &mut self,
        accounts: &impl StorableAccounts<'a>,
        skip: usize,
    ) -> TieredStorageResult<StoredAccountsInfo> {
        let mut footer = new_hot_footer();
        let mut index = vec![];
        let mut owners_table = OwnersTable::default();
        let mut cursor = 0;
        let mut address_range = AccountAddressRange::default();

        let len = accounts.len();
        let total_input_accounts = len.saturating_sub(skip);
        let mut offsets = Vec::with_capacity(total_input_accounts);

        // writing accounts blocks
        for i in skip..len {
            accounts.account_default_if_zero_lamport::<TieredStorageResult<()>>(i, |account| {
                let index_entry = AccountIndexWriterEntry {
                    address: *account.pubkey(),
                    offset: HotAccountOffset::new(cursor)?,
                };
                address_range.update(account.pubkey());

                // Obtain necessary fields from the account, or default fields
                // for a zero-lamport account in the None case.
                let (lamports, owner, data, executable, rent_epoch) = {
                    (
                        account.lamports(),
                        account.owner(),
                        account.data(),
                        account.executable(),
                        // only persist rent_epoch for those rent-paying accounts
                        (account.rent_epoch() != RENT_EXEMPT_RENT_EPOCH)
                            .then_some(account.rent_epoch()),
                    )
                };
                let owner_offset = owners_table.insert(owner);
                cursor +=
                    self.write_account(lamports, owner_offset, data, executable, rent_epoch)?;

                // Here we pass the IndexOffset as the get_account() API
                // takes IndexOffset.  Given the account address is also
                // maintained outside the TieredStorage, a potential optimization
                // is to store AccountOffset instead, which can further save
                // one jump from the index block to the accounts block.
                offsets.push(index.len());
                index.push(index_entry);
                Ok(())
            })?;
        }
        footer.account_entry_count = total_input_accounts as u32;

        // writing index block
        // expect the offset of each block aligned.
        assert!(cursor % HOT_BLOCK_ALIGNMENT == 0);
        footer.index_block_offset = cursor as u64;
        cursor += footer
            .index_block_format
            .write_index_block(&mut self.storage, &index)?;
        if cursor % HOT_BLOCK_ALIGNMENT != 0 {
            // In case it is not yet aligned, it is due to the fact that
            // the index block has an odd number of entries.  In such case,
            // we expect the amount off is equal to 4.
            assert_eq!(cursor % HOT_BLOCK_ALIGNMENT, 4);
            cursor += self.storage.write_pod(&0u32)?;
        }

        // writing owners block
        assert!(cursor % HOT_BLOCK_ALIGNMENT == 0);
        footer.owners_block_offset = cursor as u64;
        footer.owner_count = owners_table.len() as u32;
        cursor += footer
            .owners_block_format
            .write_owners_block(&mut self.storage, &owners_table)?;

        // writing footer
        footer.min_account_address = address_range.min;
        footer.max_account_address = address_range.max;
        cursor += footer.write_footer_block(&mut self.storage)?;

        Ok(StoredAccountsInfo {
            offsets,
            size: cursor,
        })
    }

    /// Flushes any buffered data to the file
    pub fn flush(&mut self) -> TieredStorageResult<()> {
        self.storage
            .0
            .flush()
            .map_err(TieredStorageError::FlushHotWriter)
    }
}
