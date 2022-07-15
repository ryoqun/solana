//! trait for abstracting underlying storage of pubkey and account pairs to be written
use solana_sdk::{account::ReadableAccount, clock::Slot, pubkey::Pubkey};

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
}

impl<'a, T: ReadableAccount + Sync> StorableAccounts<'a, T> for (Slot, &'a [(&'a Pubkey, &'a T)]) {
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
}

/// this tuple contains slot info PER account
impl<'a, T: ReadableAccount + Sync> StorableAccounts<'a, T>
    for (Slot, &'a [(&'a Pubkey, &'a T, Slot)])
{
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.1[index].0
    }
    fn account(&self, index: usize) -> &T {
        self.1[index].1
    }
    fn slot(&self, index: usize) -> Slot {
        // note that this could be different than 'target_slot()' PER account
        self.1[index].2
    }
    fn target_slot(&self) -> Slot {
        self.0
    }
    fn len(&self) -> usize {
        self.1.len()
    }
    fn contains_multiple_slots(&self) -> bool {
        let len = self.len();
        if len > 0 {
            let slot = self.slot(0);
            // true if any item has a different slot than the first item
            (1..len).any(|i| slot != self.slot(i))
        } else {
            false
        }
    }
}
