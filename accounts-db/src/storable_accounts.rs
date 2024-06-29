//! trait for abstracting underlying storage of pubkey and account pairs to be written
use {
    crate::{
        account_storage::meta::StoredAccountMeta,
        accounts_db::{AccountFromStorage, AccountStorageEntry, AccountsDb},
        accounts_index::ZeroLamport,
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        clock::{Epoch, Slot},
        pubkey::Pubkey,
    },
    std::sync::{Arc, RwLock},
};

/// hold a ref to an account to store. The account could be represented in memory a few different ways
#[derive(Debug, Copy, Clone)]
pub enum AccountForStorage<'a> {
    AddressAndAccount((&'a Pubkey, &'a AccountSharedData)),
    StoredAccountMeta(&'a StoredAccountMeta<'a>),
}

impl<'a> From<(&'a Pubkey, &'a AccountSharedData)> for AccountForStorage<'a> {
    fn from(source: (&'a Pubkey, &'a AccountSharedData)) -> Self {
        Self::AddressAndAccount(source)
    }
}

impl<'a> From<&'a StoredAccountMeta<'a>> for AccountForStorage<'a> {
    fn from(source: &'a StoredAccountMeta<'a>) -> Self {
        Self::StoredAccountMeta(source)
    }
}

impl<'a> ZeroLamport for AccountForStorage<'a> {
    fn is_zero_lamport(&self) -> bool {
        self.lamports() == 0
    }
}

impl<'a> AccountForStorage<'a> {
    pub fn pubkey(&self) -> &'a Pubkey {
        match self {
            AccountForStorage::AddressAndAccount((pubkey, _account)) => pubkey,
            AccountForStorage::StoredAccountMeta(account) => account.pubkey(),
        }
    }
}

impl<'a> ReadableAccount for AccountForStorage<'a> {
    fn lamports(&self) -> u64 {
        match self {
            AccountForStorage::AddressAndAccount((_pubkey, account)) => account.lamports(),
            AccountForStorage::StoredAccountMeta(account) => account.lamports(),
        }
    }
    fn data(&self) -> &[u8] {
        match self {
            AccountForStorage::AddressAndAccount((_pubkey, account)) => account.data(),
            AccountForStorage::StoredAccountMeta(account) => account.data(),
        }
    }
    fn owner(&self) -> &Pubkey {
        match self {
            AccountForStorage::AddressAndAccount((_pubkey, account)) => account.owner(),
            AccountForStorage::StoredAccountMeta(account) => account.owner(),
        }
    }
    fn executable(&self) -> bool {
        match self {
            AccountForStorage::AddressAndAccount((_pubkey, account)) => account.executable(),
            AccountForStorage::StoredAccountMeta(account) => account.executable(),
        }
    }
    fn rent_epoch(&self) -> Epoch {
        match self {
            AccountForStorage::AddressAndAccount((_pubkey, account)) => account.rent_epoch(),
            AccountForStorage::StoredAccountMeta(account) => account.rent_epoch(),
        }
    }
    fn to_account_shared_data(&self) -> AccountSharedData {
        match self {
            AccountForStorage::AddressAndAccount((_pubkey, account)) => {
                account.to_account_shared_data()
            }
            AccountForStorage::StoredAccountMeta(account) => account.to_account_shared_data(),
        }
    }
}

lazy_static! {
    static ref DEFAULT_ACCOUNT_SHARED_DATA: AccountSharedData = AccountSharedData::default();
}

#[derive(Default, Debug)]
pub struct StorableAccountsCacher {
    slot: Slot,
    storage: Option<Arc<AccountStorageEntry>>,
}

/// abstract access to pubkey, account, slot, target_slot of either:
/// a. (slot, &[&Pubkey, &ReadableAccount])
/// b. (slot, &[&Pubkey, &ReadableAccount, Slot]) (we will use this later)
/// This trait avoids having to allocate redundant data when there is a duplicated slot parameter.
/// All legacy callers do not have a unique slot per account to store.
pub trait StorableAccounts<'a>: Sync {
    /// account at 'index'
    fn account<Ret>(
        &self,
        index: usize,
        callback: impl for<'local> FnMut(AccountForStorage<'local>) -> Ret,
    ) -> Ret;
    /// None if account is zero lamports
    fn account_default_if_zero_lamport<Ret>(
        &self,
        index: usize,
        mut callback: impl for<'local> FnMut(AccountForStorage<'local>) -> Ret,
    ) -> Ret {
        self.account(index, |account| {
            callback(if account.lamports() != 0 {
                account
            } else {
                // preserve the pubkey, but use a default value for the account
                AccountForStorage::AddressAndAccount((
                    account.pubkey(),
                    &DEFAULT_ACCOUNT_SHARED_DATA,
                ))
            })
        })
    }
    // current slot for account at 'index'
    fn slot(&self, index: usize) -> Slot;
    /// slot that all accounts are to be written to
    fn target_slot(&self) -> Slot;
    /// true if no accounts to write
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// # accounts to write
    fn len(&self) -> usize;
    /// are there accounts from multiple slots
    /// only used for an assert
    fn contains_multiple_slots(&self) -> bool {
        false
    }
}

impl<'a: 'b, 'b> StorableAccounts<'a> for (Slot, &'b [(&'a Pubkey, &'a AccountSharedData)]) {
    fn account<Ret>(
        &self,
        index: usize,
        mut callback: impl for<'local> FnMut(AccountForStorage<'local>) -> Ret,
    ) -> Ret {
        callback((self.1[index].0, self.1[index].1).into())
    }
    fn slot(&self, _index: usize) -> Slot {
        // per-index slot is not unique per slot when per-account slot is not included in the source data
        self.target_slot()
    }
    fn target_slot(&self) -> Slot {
        self.0
    }
    fn len(&self) -> usize {
        self.1.len()
    }
}

/// holds slices of accounts being moved FROM a common source slot to 'target_slot'
pub struct StorableAccountsBySlot<'a> {
    target_slot: Slot,
    /// each element is (source slot, accounts moving FROM source slot)
    slots_and_accounts: &'a [(Slot, &'a [&'a AccountFromStorage])],

    /// This is calculated based off slots_and_accounts.
    /// cumulative offset of all account slices prior to this one
    /// starting_offsets[0] is the starting offset of slots_and_accounts[1]
    /// The starting offset of slots_and_accounts[0] is always 0
    starting_offsets: Vec<usize>,
    /// true if there is more than 1 slot represented in slots_and_accounts
    contains_multiple_slots: bool,
    /// total len of all accounts, across all slots_and_accounts
    len: usize,
    db: &'a AccountsDb,
    /// remember the last storage we looked up for a given slot
    cached_storage: RwLock<StorableAccountsCacher>,
}

impl<'a> StorableAccountsBySlot<'a> {
    /// each element of slots_and_accounts is (source slot, accounts moving FROM source slot)
    pub fn new(
        target_slot: Slot,
        slots_and_accounts: &'a [(Slot, &'a [&'a AccountFromStorage])],
        db: &'a AccountsDb,
    ) -> Self {
        let mut cumulative_len = 0usize;
        let mut starting_offsets = Vec::with_capacity(slots_and_accounts.len());
        let first_slot = slots_and_accounts
            .first()
            .map(|(slot, _)| *slot)
            .unwrap_or_default();
        let mut contains_multiple_slots = false;
        for (slot, accounts) in slots_and_accounts {
            cumulative_len = cumulative_len.saturating_add(accounts.len());
            starting_offsets.push(cumulative_len);
            contains_multiple_slots |= &first_slot != slot;
        }
        Self {
            target_slot,
            slots_and_accounts,
            starting_offsets,
            contains_multiple_slots,
            len: cumulative_len,
            db,
            cached_storage: RwLock::default(),
        }
    }
    /// given an overall index for all accounts in self:
    /// return (slots_and_accounts index, index within those accounts)
    fn find_internal_index(&self, index: usize) -> (usize, usize) {
        // search offsets for the accounts slice that contains 'index'.
        // This could be a binary search.
        for (offset_index, next_offset) in self.starting_offsets.iter().enumerate() {
            if next_offset > &index {
                // offset of prior entry
                let prior_offset = if offset_index > 0 {
                    self.starting_offsets[offset_index.saturating_sub(1)]
                } else {
                    0
                };
                return (offset_index, index - prior_offset);
            }
        }
        panic!("failed");
    }
}

impl<'a> StorableAccounts<'a> for StorableAccountsBySlot<'a> {
    fn account<Ret>(
        &self,
        index: usize,
        mut callback: impl for<'local> FnMut(AccountForStorage<'local>) -> Ret,
    ) -> Ret {
        let indexes = self.find_internal_index(index);
        let slot = self.slots_and_accounts[indexes.0].0;
        let data = self.slots_and_accounts[indexes.0].1[indexes.1];
        let offset = data.index_info.offset();
        let mut call_callback = |storage: &AccountStorageEntry| {
            storage
                .accounts
                .get_stored_account_meta_callback(offset, |account: StoredAccountMeta| {
                    callback((&account).into())
                })
                .expect("account has to exist to be able to store it")
        };
        {
            let reader = self.cached_storage.read().unwrap();
            if reader.slot == slot {
                if let Some(storage) = reader.storage.as_ref() {
                    return call_callback(storage);
                }
            }
        }
        // cache doesn't contain a storage for this slot, so lookup storage in db.
        // note we do not use file id here. We just want the normal unshrunk storage for this slot.
        let storage = self
            .db
            .storage
            .get_slot_storage_entry_shrinking_in_progress_ok(slot)
            .expect("source slot has to have a storage to be able to store accounts");
        let ret = call_callback(&storage);
        let mut writer = self.cached_storage.write().unwrap();
        writer.slot = slot;
        writer.storage = Some(storage);
        ret
    }
    fn slot(&self, index: usize) -> Slot {
        let indexes = self.find_internal_index(index);
        self.slots_and_accounts[indexes.0].0
    }
    fn target_slot(&self) -> Slot {
        self.target_slot
    }
    fn len(&self) -> usize {
        self.len
    }
    fn contains_multiple_slots(&self) -> bool {
        self.contains_multiple_slots
    }
}
