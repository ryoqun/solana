//! Account locks that keep track of which threads hold them.
//!

use {
    solana_sdk::pubkey::Pubkey,
    std::{
        collections::{hash_map::Entry, HashMap},
        ops::{BitAnd, BitAndAssign},
    },
};

pub const MAX_THREADS: u8 = 8;

/// Identifier for a thread.
pub type ThreadId = u8; // Only supports up to 8 threads currently.

/// Set of threads an account is scheduled or can be scheduled for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ThreadSet {
    /// Bitset for threads - `u8` is sufficient for up to 8 threads.
    set: u8,
}

/// Thread-aware account locks which allows for scheduling on threads
/// that already hold locks. This is useful for allowing queued
/// transactions to be scheduled on a thread while the transaction is
/// still executing on that thread.
pub struct ThreadAwareAccountLocks {
    /// Number of threads.
    num_threads: u8,
    /// Write locks - only one thread can hold a write lock at a time.
    /// Contains how many write locks are held by the thread.
    write_locks: HashMap<Pubkey, (ThreadId, u32)>,
    /// Read locks - multiple threads can hold a read lock at the same time.
    /// Contains thread-set for easily checking which threads are scheudled.
    /// Contains how many read locks are held by each thread.
    read_locks: HashMap<Pubkey, (ThreadSet, [u32; MAX_THREADS as usize])>,
}

impl ThreadAwareAccountLocks {
    /// Creates a new `ThreadAwareAccountLocks` with the given number of threads.
    pub fn new(num_threads: u8) -> Self {
        assert!(num_threads <= MAX_THREADS);
        Self {
            num_threads,
            write_locks: HashMap::new(),
            read_locks: HashMap::new(),
        }
    }

    /// Returns `ThreadSet` that the given accounts can be scheduled on.
    pub fn accounts_schedulable_threads<'a>(
        &self,
        write_account_locks: impl Iterator<Item = &'a Pubkey>,
        read_account_locks: impl Iterator<Item = &'a Pubkey>,
    ) -> ThreadSet {
        let mut schedulable_threads = ThreadSet::any(self.num_threads);

        // Get schedulable threads for write-locked accounts.
        write_account_locks.for_each(|pubkey| {
            schedulable_threads &= self.account_write_lockable_threads(pubkey);
        });

        // Get schedulable threads for read-locked accounts.
        read_account_locks.for_each(|pubkey| {
            schedulable_threads &= self.account_read_lockable_threads(pubkey);
        });

        schedulable_threads
    }

    /// Adds locks for all writable and readable accounts.
    pub fn lock_accounts<'a>(
        &mut self,
        write_account_locks: impl Iterator<Item = &'a Pubkey>,
        read_account_locks: impl Iterator<Item = &'a Pubkey>,
        thread_id: ThreadId,
    ) {
        // Lock write-locked accounts.
        write_account_locks.for_each(|pubkey| {
            self.lock_account_write(pubkey, thread_id);
        });

        // Lock read-locked accounts.
        read_account_locks.for_each(|pubkey| {
            self.lock_account_read(pubkey, thread_id);
        });
    }

    /// Removes locks for all writable and readable accounts.
    pub fn unlock_accounts<'a>(
        &mut self,
        write_account_locks: impl Iterator<Item = &'a Pubkey>,
        read_account_locks: impl Iterator<Item = &'a Pubkey>,
        thread_id: ThreadId,
    ) {
        // Unlock write-locked accounts.
        write_account_locks.for_each(|pubkey| {
            self.unlock_account_write(pubkey, thread_id);
        });

        // Unlock read-locked accounts.
        read_account_locks.for_each(|pubkey| {
            self.unlock_account_read(pubkey, thread_id);
        });
    }

    /// Returns `ThreadSet` that the given `pubkey` can be scheduled on for writing.
    fn account_write_lockable_threads(&self, pubkey: &Pubkey) -> ThreadSet {
        // If the account is write-locked, only the thread that holds the lock can schedule it.
        // Otherwise, we need to check against read-locks.
        if let Some((thread_id, _)) = self.write_locks.get(pubkey) {
            ThreadSet::only(*thread_id)
        } else if let Some((read_thread_set, _)) = self.read_locks.get(pubkey) {
            // If the account is read-locked, then it can only be write-locked iff there is only one
            // thread that holds the read-lock currently.
            (read_thread_set.num_threads() == 1)
                .then_some(*read_thread_set)
                .unwrap_or_else(ThreadSet::none)
        } else {
            ThreadSet::any(self.num_threads)
        }
    }

    /// Returns `ThreadSet` that the given `pubkey` can be scheduled on for reading.
    fn account_read_lockable_threads(&self, pubkey: &Pubkey) -> ThreadSet {
        self.write_locks
            .get(pubkey)
            .map(|(thread_id, _)| ThreadSet::only(*thread_id))
            .unwrap_or_else(|| ThreadSet::any(self.num_threads))
    }

    /// Locks the given `pubkey` for writing by the given `thread_id`.
    fn lock_account_write(&mut self, pubkey: &Pubkey, thread_id: ThreadId) {
        match self.write_locks.entry(*pubkey) {
            Entry::Occupied(mut entry) => {
                let (lock_thread_id, lock_count) = entry.get_mut();
                assert_eq!(*lock_thread_id, thread_id);
                *lock_count += 1;
            }
            Entry::Vacant(entry) => {
                entry.insert((thread_id, 1));
            }
        }
    }

    /// Unlocks the given `pubkey` for writing by the given `thread_id`.
    fn unlock_account_write(&mut self, pubkey: &Pubkey, thread_id: ThreadId) {
        match self.write_locks.entry(*pubkey) {
            Entry::Occupied(mut entry) => {
                let (lock_thread_id, lock_count) = entry.get_mut();
                assert_eq!(*lock_thread_id, thread_id);
                *lock_count -= 1;
                if *lock_count == 0 {
                    entry.remove();
                }
            }
            Entry::Vacant(_) => panic!("write lock not held for pubkey: {pubkey:?}"),
        }
    }

    /// Locks the given `pubkey` for reading by the given `thread_id`.
    fn lock_account_read(&mut self, pubkey: &Pubkey, thread_id: ThreadId) {
        match self.read_locks.entry(*pubkey) {
            Entry::Occupied(mut entry) => {
                let (read_thread_set, read_lock_counts) = entry.get_mut();
                read_thread_set.insert(thread_id);
                read_lock_counts[thread_id as usize] += 1;
            }
            Entry::Vacant(entry) => {
                let mut read_lock_counts = [0; MAX_THREADS as usize];
                read_lock_counts[thread_id as usize] = 1;
                entry.insert((ThreadSet::only(thread_id), read_lock_counts));
            }
        }
    }

    /// Unlocks the given `pubkey` for reading by the given `thread_id`.
    fn unlock_account_read(&mut self, pubkey: &Pubkey, thread_id: ThreadId) {
        match self.read_locks.entry(*pubkey) {
            Entry::Occupied(mut entry) => {
                let (read_thread_set, read_lock_counts) = entry.get_mut();
                read_lock_counts[thread_id as usize] -= 1;
                if read_lock_counts[thread_id as usize] == 0 {
                    read_thread_set.remove(thread_id);
                }
                if read_thread_set.is_empty() {
                    entry.remove();
                }
            }
            Entry::Vacant(_) => panic!("read lock not held for pubkey: {pubkey:?}"),
        }
    }
}

impl ThreadSet {
    #[inline(always)]
    pub fn none() -> Self {
        Self { set: 0 }
    }

    #[inline(always)]
    pub fn any(num_threads: u8) -> Self {
        Self {
            set: (1 << num_threads) - 1,
        }
    }

    #[inline(always)]
    pub fn only(thread_id: ThreadId) -> Self {
        Self {
            set: 1 << thread_id,
        }
    }

    #[inline(always)]
    pub fn num_threads(&self) -> u8 {
        self.set.count_ones() as u8
    }

    #[inline(always)]
    pub fn only_one_scheduled(&self) -> Option<ThreadId> {
        (self.num_threads() == 1).then_some(self.set.trailing_zeros() as ThreadId)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.set == 0
    }

    #[inline(always)]
    pub fn contains(&self, thread_id: ThreadId) -> bool {
        self.set & (1 << thread_id) != 0
    }

    #[inline(always)]
    pub fn insert(&mut self, thread_id: ThreadId) {
        self.set |= 1 << thread_id;
    }

    #[inline(always)]
    pub fn remove(&mut self, thread_id: ThreadId) {
        self.set &= !(1 << thread_id);
    }

    #[inline(always)]
    pub fn threads_iter(self) -> impl Iterator<Item = ThreadId> {
        (0..MAX_THREADS as ThreadId).filter(move |thread_id| self.contains(*thread_id))
    }
}

impl BitAndAssign for ThreadSet {
    fn bitand_assign(&mut self, rhs: Self) {
        self.set &= rhs.set;
    }
}

impl BitAnd for ThreadSet {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self {
            set: self.set & rhs.set,
        }
    }
}
