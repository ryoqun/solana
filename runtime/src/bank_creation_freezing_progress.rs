//! Keep track of how many banks have been created and how many have been frozen or dropped.
//! This is useful to track foreground progress to understand expected access to accounts db.
use {
    crate::waitable_condvar::WaitableCondvar,
    solana_sdk::timing::AtomicInterval,
    std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

#[derive(Debug, Default)]
/// Keeps track of when all banks that were started as of a known point in time have been frozen or otherwise destroyed.
/// When 'bank_freeze_or_destruction_count' exceeds a prior value of 'bank_creation_count',
/// this means that we can know all banks that began loading accounts have completed as of the prior value of 'bank_creation_count'.
pub(crate) struct BankCreationFreezingProgress {
    /// Incremented each time a bank is created.
    /// Starting now, this bank could be finding accounts in the index and loading them from accounts db.
    bank_creation_count: AtomicU32,
    /// Incremented each time a bank is frozen or destroyed.
    /// At this point, this bank has completed all account loading.
    bank_freeze_or_destruction_count: AtomicU32,

    /// enable waiting for bank_freeze_or_destruction_count to increment
    bank_frozen_or_destroyed: Arc<WaitableCondvar>,

    last_report: AtomicInterval,
}

impl BankCreationFreezingProgress {
    pub(crate) fn increment_bank_frozen_or_destroyed(&self) {
        self.bank_freeze_or_destruction_count
            .fetch_add(1, Ordering::Release);
        self.bank_frozen_or_destroyed.notify_all();
    }

    pub(crate) fn get_bank_frozen_or_destroyed_count(&self) -> u32 {
        self.bank_freeze_or_destruction_count
            .load(Ordering::Acquire)
    }

    pub(crate) fn increment_bank_creation_count(&self) {
        self.bank_creation_count.fetch_add(1, Ordering::Release);
    }

    pub(crate) fn get_bank_creation_count(&self) -> u32 {
        self.bank_creation_count.load(Ordering::Acquire)
    }

    pub(crate) fn report(&self) {
        if self.last_report.should_update(60_000) {
            datapoint_info!(
                "bank_progress",
                (
                    "difference",
                    self.get_bank_creation_count()
                        .wrapping_sub(self.get_bank_frozen_or_destroyed_count()),
                    i64
                )
            );
        }
    }
}
