use {
    solana_runtime::bank::Bank,
    solana_sdk::slot_history::Slot,
    std::{
        sync::{Arc, Condvar, Mutex, MutexGuard, Weak},
        time::{Duration, Instant},
    },
};

/// Tracks leader status of the validator node and notifies when:
///     1. A leader bank initiates (=PoH-initiated)
///     2. A leader slot completes (=PoH-completed)
#[derive(Debug, Default)]
pub struct LeaderBankNotifier {
    /// Current state (slot, bank, and status) of the system
    state: Mutex<SlotAndBankWithStatus>,
    /// CondVar to notify status changes and waiting
    condvar: Condvar,
}

/// Leader status state machine for the validator.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum Status {
    /// The leader bank is not currently available. Either not initialized, or PoH-completed bank.
    #[default]
    StandBy,
    /// PoH-initiated bank is available.
    InProgress,
}

#[derive(Debug, Default)]
struct SlotAndBankWithStatus {
    status: Status,
    slot: Option<Slot>,
    bank: Weak<Bank>,
}

impl LeaderBankNotifier {
    /// Set the status to `InProgress` and notify any waiting threads.
    /// Panics if the status is not `StandBy` - cannot have multiple
    /// leader banks in progress.
    pub(crate) fn set_in_progress(&self, bank: &Arc<Bank>) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.status, Status::StandBy);

        *state = SlotAndBankWithStatus {
            status: Status::InProgress,
            slot: Some(bank.slot()),
            bank: Arc::downgrade(bank),
        };
        drop(state);

        self.condvar.notify_all();
    }

    /// Set the status to `StandBy` and notify any waiting threads.
    /// Panics if the current status is not `InProgress` or the stored slot does not match
    /// the given slot.
    pub(crate) fn set_completed(&self, slot: Slot) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.status, Status::InProgress);
        assert_eq!(state.slot, Some(slot));

        state.status = Status::StandBy;
        drop(state);

        self.condvar.notify_all();
    }

    /// If the status is `InProgress`, immediately return a weak reference to the bank.
    /// Otherwise, wait up to the `timeout` for the status to become `InProgress`.
    /// If the timeout is reached, the weak reference is unupgradable.
    pub fn get_or_wait_for_in_progress(&self, timeout: Duration) -> Weak<Bank> {
        let state = self.state.lock().unwrap();
        Self::get_or_wait_for_in_progress_state(&self.condvar, state, timeout)
            .map(|state| state.bank.clone())
            .unwrap_or_default()
    }

    /// Wait for next notification for a completed leader slot.
    /// Returns `None` if the timeout is reached
    pub fn wait_for_completed(&self, mut remaining_timeout: Duration) -> Option<Slot> {
        let state = self.state.lock().unwrap();

        // If currently `StandBy`, need to wait for `InProgress` to begin.
        let now = Instant::now();
        let state =
            Self::get_or_wait_for_in_progress_state(&self.condvar, state, remaining_timeout)?;
        remaining_timeout = remaining_timeout.checked_sub(now.elapsed())?;

        // Wait for `StandBy` to be set.
        let (state, wait_timeout_result) = self
            .condvar
            .wait_timeout_while(state, remaining_timeout, |state| {
                matches!(state.status, Status::InProgress)
            })
            .unwrap();

        (!wait_timeout_result.timed_out()).then(|| state.slot.expect("some slot when completed"))
    }

    /// Helper function to get or wait for the `InProgress` status with a given `MutexGuard`.
    /// If `InProgress` status is reached, the state `MutexGuard` is returned, otherwise None.
    fn get_or_wait_for_in_progress_state<'a>(
        condvar: &'a Condvar,
        state: MutexGuard<'a, SlotAndBankWithStatus>,
        timeout: Duration,
    ) -> Option<MutexGuard<'a, SlotAndBankWithStatus>> {
        let (state, wait_timeout_result) = condvar
            .wait_timeout_while(state, timeout, |state| {
                matches!(state.status, Status::StandBy)
            })
            .unwrap();

        (!wait_timeout_result.timed_out()).then_some(state)
    }
}
