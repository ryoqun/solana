//! trait for abstracting underlying storage of pubkey and account pairs to be written
use {
    crate::{
        accounts_db::{FoundStoredAccount, IncludeSlotInHash},
        append_vec::StoredAccountMeta,
    },
    solana_sdk::{account::ReadableAccount, clock::Slot, hash::Hash, pubkey::Pubkey},
};

/// abstract access to pubkey, account, slot, target_slot of either:
/// a. (slot, &[&Pubkey, &ReadableAccount])
/// b. (slot, &[&Pubkey, &ReadableAccount, Slot]) (we will use this later)
/// This trait avoids having to allocate redundant data when there is a duplicated slot parameter.
/// All legacy callers do not have a unique slot per account to store.
pub trait StorableAccounts<'a, T: ReadableAccount + Sync>: Sync {
    /// pubkey at 'index'
    fn pubkey(&self, index: usize) -> &Pubkey;
    /// account at 'index'
    fn account(&self, index: usize) -> &T;
    /// None if account is zero lamports
    fn account_default_if_zero_lamport(&self, index: usize) -> Option<&T> {
        let account = self.account(index);
        (account.lamports() != 0).then_some(account)
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
    fn contains_multiple_slots(&self) -> bool;
    /// true iff hashing these accounts should include the slot
    fn include_slot_in_hash(&self) -> IncludeSlotInHash;

    /// true iff the impl can provide hash and write_version
    /// Otherwise, hash and write_version have to be provided separately to store functions.
    fn has_hash_and_write_version(&self) -> bool {
        false
    }

    /// return hash for account at 'index'
    /// Should only be called if 'has_hash_and_write_version' = true
    fn hash(&self, _index: usize) -> &Hash {
        // this should never be called if has_hash_and_write_version returns false
        unimplemented!();
    }

    /// return write_version for account at 'index'
    /// Should only be called if 'has_hash_and_write_version' = true
    fn write_version(&self, _index: usize) -> u64 {
        // this should never be called if has_hash_and_write_version returns false
        unimplemented!();
    }
}

/// accounts that are moving from 'old_slot' to 'target_slot'
/// since all accounts are from the same old slot, we don't need to create a slice with per-account slot
/// but, we need slot(_) to return 'old_slot' for all accounts
/// Created a struct instead of a tuple to make the code easier to read.
pub struct StorableAccountsMovingSlots<'a, T: ReadableAccount + Sync> {
    pub accounts: &'a [(&'a Pubkey, &'a T)],
    /// accounts will be written to this slot
    pub target_slot: Slot,
    /// slot where accounts are currently stored
    pub old_slot: Slot,
    /// This is temporarily here until feature activation.
    pub include_slot_in_hash: IncludeSlotInHash,
}

impl<'a, T: ReadableAccount + Sync> StorableAccounts<'a, T> for StorableAccountsMovingSlots<'a, T> {
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.accounts[index].0
    }
    fn account(&self, index: usize) -> &T {
        self.accounts[index].1
    }
    fn slot(&self, _index: usize) -> Slot {
        // per-index slot is not unique per slot, but it is different than 'target_slot'
        self.old_slot
    }
    fn target_slot(&self) -> Slot {
        self.target_slot
    }
    fn len(&self) -> usize {
        self.accounts.len()
    }
    fn contains_multiple_slots(&self) -> bool {
        false
    }
    fn include_slot_in_hash(&self) -> IncludeSlotInHash {
        self.include_slot_in_hash
    }
}

/// The last parameter exists until this feature is activated:
///  ignore slot when calculating an account hash #28420
impl<'a, T: ReadableAccount + Sync> StorableAccounts<'a, T>
    for (Slot, &'a [(&'a Pubkey, &'a T)], IncludeSlotInHash)
{
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.1[index].0
    }
    fn account(&self, index: usize) -> &T {
        self.1[index].1
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
    fn contains_multiple_slots(&self) -> bool {
        false
    }
    fn include_slot_in_hash(&self) -> IncludeSlotInHash {
        self.2
    }
}

/// The last parameter exists until this feature is activated:
///  ignore slot when calculating an account hash #28420
impl<'a> StorableAccounts<'a, StoredAccountMeta<'a>>
    for (Slot, &'a [&'a StoredAccountMeta<'a>], IncludeSlotInHash)
{
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.1[index].pubkey()
    }
    fn account(&self, index: usize) -> &StoredAccountMeta<'a> {
        self.1[index]
    }
    fn slot(&self, _index: usize) -> Slot {
        // per-index slot is not unique per slot when per-account slot is not included in the source data
        self.0
    }
    fn target_slot(&self) -> Slot {
        self.0
    }
    fn len(&self) -> usize {
        self.1.len()
    }
    fn contains_multiple_slots(&self) -> bool {
        false
    }
    fn include_slot_in_hash(&self) -> IncludeSlotInHash {
        self.2
    }
}

/// this tuple contains a single different source slot that applies to all accounts
/// accounts are StoredAccountMeta
impl<'a> StorableAccounts<'a, StoredAccountMeta<'a>>
    for (
        Slot,
        &'a [&'a StoredAccountMeta<'a>],
        IncludeSlotInHash,
        Slot,
    )
{
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.1[index].pubkey()
    }
    fn account(&self, index: usize) -> &StoredAccountMeta<'a> {
        self.1[index]
    }
    fn slot(&self, _index: usize) -> Slot {
        // same other slot for all accounts
        self.3
    }
    fn target_slot(&self) -> Slot {
        self.0
    }
    fn len(&self) -> usize {
        self.1.len()
    }
    fn contains_multiple_slots(&self) -> bool {
        false
    }
    fn include_slot_in_hash(&self) -> IncludeSlotInHash {
        self.2
    }
    fn has_hash_and_write_version(&self) -> bool {
        true
    }
    fn hash(&self, index: usize) -> &Hash {
        self.1[index].hash
    }
    fn write_version(&self, index: usize) -> u64 {
        self.1[index].meta.write_version
    }
}

/// this tuple contains a single different source slot that applies to all accounts
/// accounts are FoundStoredAccount
impl<'a> StorableAccounts<'a, StoredAccountMeta<'a>>
    for (
        Slot,
        &'a [&'a FoundStoredAccount<'a>],
        IncludeSlotInHash,
        Slot,
    )
{
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.1[index].pubkey()
    }
    fn account(&self, index: usize) -> &StoredAccountMeta<'a> {
        &self.1[index].account
    }
    fn slot(&self, _index: usize) -> Slot {
        // same other slot for all accounts
        self.3
    }
    fn target_slot(&self) -> Slot {
        self.0
    }
    fn len(&self) -> usize {
        self.1.len()
    }
    fn contains_multiple_slots(&self) -> bool {
        false
    }
    fn include_slot_in_hash(&self) -> IncludeSlotInHash {
        self.2
    }
    fn has_hash_and_write_version(&self) -> bool {
        true
    }
    fn hash(&self, index: usize) -> &Hash {
        self.1[index].account.hash
    }
    fn write_version(&self, index: usize) -> u64 {
        self.1[index].account.meta.write_version
    }
}
