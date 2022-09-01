//! helpers for squashing append vecs into ancient append vecs
//! an ancient append vec is:
//! 1. a slot that is older than an epoch old
//! 2. multiple 'slots' squashed into a single older (ie. ancient) slot for convenience and performance
//! Otherwise, an ancient append vec is the same as any other append vec
use {
    crate::{
        accounts_db::FoundStoredAccount,
        append_vec::{AppendVec, StoredAccountMeta},
    },
    solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey},
};

/// a set of accounts need to be stored.
/// If there are too many to fit in 'Primary', the rest are put in 'Overflow'
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StorageSelector {
    Primary,
    Overflow,
}

/// reference a set of accounts to store
/// The accounts may have to be split between 2 storages (primary and overflow) if there is not enough room in the primary storage.
/// The 'store' functions need data stored in a slice of specific type.
/// We need 1-2 of these slices constructed based on available bytes and individual account sizes.
/// The slice arithmetic accross both hashes and account data gets messy. So, this struct abstracts that.
pub struct AccountsToStore<'a> {
    hashes: Vec<&'a Hash>,
    accounts: Vec<(&'a Pubkey, &'a StoredAccountMeta<'a>, Slot)>,
    /// if 'accounts' contains more items than can be contained in the primary storage, then we have to split these accounts.
    /// 'index_first_item_overflow' specifies the index of the first item in 'accounts' that will go into the overflow storage
    index_first_item_overflow: usize,
}

impl<'a> AccountsToStore<'a> {
    /// break 'stored_accounts' into primary and overflow
    /// available_bytes: how many bytes remain in the primary storage. Excess accounts will be directed to an overflow storage
    pub fn new(
        mut available_bytes: u64,
        stored_accounts: &'a [&'a (Pubkey, FoundStoredAccount<'a>)],
        slot: Slot,
    ) -> Self {
        let num_accounts = stored_accounts.len();
        let mut hashes = Vec::with_capacity(num_accounts);
        let mut accounts = Vec::with_capacity(num_accounts);
        // index of the first account that doesn't fit in the current append vec
        let mut index_first_item_overflow = num_accounts; // assume all fit
        stored_accounts.iter().for_each(|account| {
            let account_size = account.1.account.stored_size as u64;
            if available_bytes >= account_size {
                available_bytes = available_bytes.saturating_sub(account_size);
            } else if index_first_item_overflow == num_accounts {
                available_bytes = 0;
                // the # of accounts we have so far seen is the most that will fit in the current ancient append vec
                index_first_item_overflow = hashes.len();
            }
            hashes.push(account.1.account.hash);
            // we have to specify 'slot' here because we are writing to an ancient append vec and squashing slots,
            // so we need to update the previous accounts index entry for this account from 'slot' to 'ancient_slot'
            accounts.push((&account.1.account.meta.pubkey, &account.1.account, slot));
        });
        Self {
            hashes,
            accounts,
            index_first_item_overflow,
        }
    }

    /// true if a request to 'get' 'Overflow' would return accounts & hashes
    pub fn has_overflow(&self) -> bool {
        self.index_first_item_overflow < self.accounts.len()
    }

    /// get the accounts and hashes to store in the given 'storage'
    pub fn get(
        &self,
        storage: StorageSelector,
    ) -> (
        &[(&'a Pubkey, &'a StoredAccountMeta<'a>, Slot)],
        &[&'a Hash],
    ) {
        let range = match storage {
            StorageSelector::Primary => 0..self.index_first_item_overflow,
            StorageSelector::Overflow => self.index_first_item_overflow..self.accounts.len(),
        };
        (&self.accounts[range.clone()], &self.hashes[range])
    }
}

/// capacity of an ancient append vec
pub fn get_ancient_append_vec_capacity() -> u64 {
    use crate::append_vec::MAXIMUM_APPEND_VEC_FILE_SIZE;
    // smaller than max by a bit just in case
    // some functions add slop on allocation
    // temporarily smaller to force ancient append vec operations to occur more often to flush out any bugs
    MAXIMUM_APPEND_VEC_FILE_SIZE / 10 - 2048
}

/// true iff storage is ancient size and is almost completely full
pub fn is_full_ancient(storage: &AppendVec) -> bool {
    // not sure of slop amount here. Maybe max account size with 10MB data?
    // append vecs can't usually be made entirely full
    let threshold_bytes = 10_000;
    is_ancient(storage) && storage.remaining_bytes() < threshold_bytes
}

/// is this a max-size append vec designed to be used as an ancient append vec?
pub fn is_ancient(storage: &AppendVec) -> bool {
    storage.capacity() >= get_ancient_append_vec_capacity()
}
