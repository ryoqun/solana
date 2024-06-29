//! The `optimistically_confirmed_bank_tracker` module implements a threaded service to track the
//! most recent optimistically confirmed bank for use in rpc services, and triggers gossip
//! subscription notifications.
//! This module also supports notifying of slot status for subscribers using the SlotNotificationSender.
//! It receives the BankNotification events, transforms them into SlotNotification and sends them via
//! SlotNotificationSender in the following way:
//! BankNotification::OptimisticallyConfirmed --> SlotNotification::OptimisticallyConfirmed
//! BankNotification::Frozen --> SlotNotification::Frozen
//! BankNotification::NewRootedChain --> SlotNotification::Root for the roots in the chain.

use {
    crate::rpc_subscriptions::RpcSubscriptions,
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender},
    solana_rpc_client_api::response::{SlotTransactionStats, SlotUpdate},
    solana_runtime::{
        bank::Bank, bank_forks::BankForks, prioritization_fee_cache::PrioritizationFeeCache,
    },
    solana_sdk::{clock::Slot, timing::timestamp},
    std::{
        collections::HashSet,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct OptimisticallyConfirmedBank {
    pub bank: Arc<Bank>,
}

impl OptimisticallyConfirmedBank {
    pub fn locked_from_bank_forks_root(bank_forks: &Arc<RwLock<BankForks>>) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            bank: bank_forks.read().unwrap().root_bank(),
        }))
    }
}

#[derive(Clone)]
pub enum BankNotification {
    OptimisticallyConfirmed(Slot),
    Frozen(Arc<Bank>),
    NewRootBank(Arc<Bank>),
    /// The newly rooted slot chain including the parent slot of the oldest bank in the rooted chain.
    NewRootedChain(Vec<Slot>),
}

#[derive(Clone, Debug)]
pub enum SlotNotification {
    OptimisticallyConfirmed(Slot),
    /// The (Slot, Parent Slot) pair for the slot frozen
    Frozen((Slot, Slot)),
    /// The (Slot, Parent Slot) pair for the root slot
    Root((Slot, Slot)),
}

impl std::fmt::Debug for BankNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BankNotification::OptimisticallyConfirmed(slot) => {
                write!(f, "OptimisticallyConfirmed({slot:?})")
            }
            BankNotification::Frozen(bank) => write!(f, "Frozen({})", bank.slot()),
            BankNotification::NewRootBank(bank) => write!(f, "Root({})", bank.slot()),
            BankNotification::NewRootedChain(chain) => write!(f, "RootedChain({chain:?})"),
        }
    }
}

pub type BankNotificationReceiver = Receiver<BankNotification>;
pub type BankNotificationSender = Sender<BankNotification>;

#[derive(Clone)]
pub struct BankNotificationSenderConfig {
    pub sender: BankNotificationSender,
    pub should_send_parents: bool,
}

pub type SlotNotificationReceiver = Receiver<SlotNotification>;
pub type SlotNotificationSender = Sender<SlotNotification>;

pub struct OptimisticallyConfirmedBankTracker {
    thread_hdl: JoinHandle<()>,
}

impl OptimisticallyConfirmedBankTracker {
    pub fn new(
        receiver: BankNotificationReceiver,
        exit: Arc<AtomicBool>,
        bank_forks: Arc<RwLock<BankForks>>,
        optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
        subscriptions: Arc<RpcSubscriptions>,
        slot_notification_subscribers: Option<Arc<RwLock<Vec<SlotNotificationSender>>>>,
        prioritization_fee_cache: Arc<PrioritizationFeeCache>,
    ) -> Self {
        let mut pending_optimistically_confirmed_banks = HashSet::new();
        let mut last_notified_confirmed_slot: Slot = 0;
        let mut highest_confirmed_slot: Slot = 0;
        let mut newest_root_slot: Slot = 0;
        let thread_hdl = Builder::new()
            .name("solOpConfBnkTrk".to_string())
            .spawn(move || loop {
                if exit.load(Ordering::Relaxed) {
                    break;
                }

                if let Err(RecvTimeoutError::Disconnected) = Self::recv_notification(
                    &receiver,
                    &bank_forks,
                    &optimistically_confirmed_bank,
                    &subscriptions,
                    &mut pending_optimistically_confirmed_banks,
                    &mut last_notified_confirmed_slot,
                    &mut highest_confirmed_slot,
                    &mut newest_root_slot,
                    &slot_notification_subscribers,
                    &prioritization_fee_cache,
                ) {
                    break;
                }
            })
            .unwrap();
        Self { thread_hdl }
    }

    #[allow(clippy::too_many_arguments)]
    fn recv_notification(
        receiver: &Receiver<BankNotification>,
        bank_forks: &RwLock<BankForks>,
        optimistically_confirmed_bank: &RwLock<OptimisticallyConfirmedBank>,
        subscriptions: &RpcSubscriptions,
        pending_optimistically_confirmed_banks: &mut HashSet<Slot>,
        last_notified_confirmed_slot: &mut Slot,
        highest_confirmed_slot: &mut Slot,
        newest_root_slot: &mut Slot,
        slot_notification_subscribers: &Option<Arc<RwLock<Vec<SlotNotificationSender>>>>,
        prioritization_fee_cache: &PrioritizationFeeCache,
    ) -> Result<(), RecvTimeoutError> {
        let notification = receiver.recv_timeout(Duration::from_secs(1))?;
        Self::process_notification(
            notification,
            bank_forks,
            optimistically_confirmed_bank,
            subscriptions,
            pending_optimistically_confirmed_banks,
            last_notified_confirmed_slot,
            highest_confirmed_slot,
            newest_root_slot,
            slot_notification_subscribers,
            prioritization_fee_cache,
        );
        Ok(())
    }

    fn notify_slot_status(
        slot_notification_subscribers: &Option<Arc<RwLock<Vec<SlotNotificationSender>>>>,
        notification: SlotNotification,
    ) {
        if let Some(slot_notification_subscribers) = slot_notification_subscribers {
            for sender in slot_notification_subscribers.read().unwrap().iter() {
                match sender.send(notification.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        info!(
                            "Failed to send notification {:?}, error: {:?}",
                            notification, err
                        );
                    }
                }
            }
        }
    }

    fn notify_or_defer(
        subscriptions: &RpcSubscriptions,
        bank_forks: &RwLock<BankForks>,
        bank: &Bank,
        last_notified_confirmed_slot: &mut Slot,
        pending_optimistically_confirmed_banks: &mut HashSet<Slot>,
        slot_notification_subscribers: &Option<Arc<RwLock<Vec<SlotNotificationSender>>>>,
        prioritization_fee_cache: &PrioritizationFeeCache,
    ) {
        if bank.is_frozen() {
            if bank.slot() > *last_notified_confirmed_slot {
                debug!(
                    "notify_or_defer notifying via notify_gossip_subscribers for slot {:?}",
                    bank.slot()
                );
                subscriptions.notify_gossip_subscribers(bank.slot());
                *last_notified_confirmed_slot = bank.slot();
                Self::notify_slot_status(
                    slot_notification_subscribers,
                    SlotNotification::OptimisticallyConfirmed(bank.slot()),
                );

                // finalize block's minimum prioritization fee cache for this bank
                prioritization_fee_cache.finalize_priority_fee(bank.slot(), bank.bank_id());
            }
        } else if bank.slot() > bank_forks.read().unwrap().root() {
            pending_optimistically_confirmed_banks.insert(bank.slot());
            debug!("notify_or_defer defer notifying for slot {:?}", bank.slot());
        }
    }

    fn notify_or_defer_confirmed_banks(
        subscriptions: &RpcSubscriptions,
        bank_forks: &RwLock<BankForks>,
        bank: Arc<Bank>,
        slot_threshold: Slot,
        last_notified_confirmed_slot: &mut Slot,
        pending_optimistically_confirmed_banks: &mut HashSet<Slot>,
        slot_notification_subscribers: &Option<Arc<RwLock<Vec<SlotNotificationSender>>>>,
        prioritization_fee_cache: &PrioritizationFeeCache,
    ) {
        for confirmed_bank in bank.parents_inclusive().iter().rev() {
            if confirmed_bank.slot() > slot_threshold {
                debug!(
                    "Calling notify_or_defer for confirmed_bank {:?}",
                    confirmed_bank.slot()
                );
                Self::notify_or_defer(
                    subscriptions,
                    bank_forks,
                    confirmed_bank,
                    last_notified_confirmed_slot,
                    pending_optimistically_confirmed_banks,
                    slot_notification_subscribers,
                    prioritization_fee_cache,
                );
            }
        }
    }

    fn notify_new_root_slots(
        roots: &mut [Slot],
        newest_root_slot: &mut Slot,
        slot_notification_subscribers: &Option<Arc<RwLock<Vec<SlotNotificationSender>>>>,
    ) {
        if slot_notification_subscribers.is_none() {
            return;
        }
        roots.sort_unstable();
        // The chain are sorted already and must contain at least the parent of a newly rooted slot as the first element
        assert!(roots.len() >= 2);
        for i in 1..roots.len() {
            let root = roots[i];
            if root > *newest_root_slot {
                let parent = roots[i - 1];
                debug!(
                    "Doing SlotNotification::Root for root {}, parent: {}",
                    root, parent
                );
                Self::notify_slot_status(
                    slot_notification_subscribers,
                    SlotNotification::Root((root, parent)),
                );
                *newest_root_slot = root;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_notification(
        notification: BankNotification,
        bank_forks: &RwLock<BankForks>,
        optimistically_confirmed_bank: &RwLock<OptimisticallyConfirmedBank>,
        subscriptions: &RpcSubscriptions,
        pending_optimistically_confirmed_banks: &mut HashSet<Slot>,
        last_notified_confirmed_slot: &mut Slot,
        highest_confirmed_slot: &mut Slot,
        newest_root_slot: &mut Slot,
        slot_notification_subscribers: &Option<Arc<RwLock<Vec<SlotNotificationSender>>>>,
        prioritization_fee_cache: &PrioritizationFeeCache,
    ) {
        debug!("received bank notification: {:?}", notification);
        match notification {
            BankNotification::OptimisticallyConfirmed(slot) => {
                let bank = bank_forks.read().unwrap().get(slot);
                if let Some(bank) = bank {
                    let mut w_optimistically_confirmed_bank =
                        optimistically_confirmed_bank.write().unwrap();

                    if bank.slot() > w_optimistically_confirmed_bank.bank.slot() && bank.is_frozen()
                    {
                        w_optimistically_confirmed_bank.bank = bank.clone();
                    }

                    if slot > *highest_confirmed_slot {
                        Self::notify_or_defer_confirmed_banks(
                            subscriptions,
                            bank_forks,
                            bank,
                            *highest_confirmed_slot,
                            last_notified_confirmed_slot,
                            pending_optimistically_confirmed_banks,
                            slot_notification_subscribers,
                            prioritization_fee_cache,
                        );

                        *highest_confirmed_slot = slot;
                    }
                    drop(w_optimistically_confirmed_bank);
                } else if slot > bank_forks.read().unwrap().root() {
                    pending_optimistically_confirmed_banks.insert(slot);
                } else {
                    inc_new_counter_info!("dropped-already-rooted-optimistic-bank-notification", 1);
                }

                // Send slot notification regardless of whether the bank is replayed
                subscriptions.notify_slot_update(SlotUpdate::OptimisticConfirmation {
                    slot,
                    timestamp: timestamp(),
                });
                // NOTE: replay of `slot` may or may not be complete. Therefore, most new
                // functionality to be triggered on optimistic confirmation should go in
                // `notify_or_defer()` under the `bank.is_frozen()` case instead of here.
            }
            BankNotification::Frozen(bank) => {
                let frozen_slot = bank.slot();
                if let Some(parent) = bank.parent() {
                    let num_successful_transactions = bank
                        .transaction_count()
                        .saturating_sub(parent.transaction_count());
                    subscriptions.notify_slot_update(SlotUpdate::Frozen {
                        slot: frozen_slot,
                        timestamp: timestamp(),
                        stats: SlotTransactionStats {
                            num_transaction_entries: bank.transaction_entries_count(),
                            num_successful_transactions,
                            num_failed_transactions: bank.transaction_error_count(),
                            max_transactions_per_entry: bank.transactions_per_entry_max(),
                        },
                    });

                    Self::notify_slot_status(
                        slot_notification_subscribers,
                        SlotNotification::Frozen((bank.slot(), bank.parent_slot())),
                    );
                }

                if pending_optimistically_confirmed_banks.remove(&bank.slot()) {
                    debug!(
                        "Calling notify_gossip_subscribers to send deferred notification {:?}",
                        frozen_slot
                    );

                    Self::notify_or_defer_confirmed_banks(
                        subscriptions,
                        bank_forks,
                        bank.clone(),
                        *last_notified_confirmed_slot,
                        last_notified_confirmed_slot,
                        pending_optimistically_confirmed_banks,
                        slot_notification_subscribers,
                        prioritization_fee_cache,
                    );

                    let mut w_optimistically_confirmed_bank =
                        optimistically_confirmed_bank.write().unwrap();
                    if frozen_slot > w_optimistically_confirmed_bank.bank.slot() {
                        w_optimistically_confirmed_bank.bank = bank;
                    }
                    drop(w_optimistically_confirmed_bank);
                }
            }
            BankNotification::NewRootBank(bank) => {
                let root_slot = bank.slot();
                let mut w_optimistically_confirmed_bank =
                    optimistically_confirmed_bank.write().unwrap();
                if root_slot > w_optimistically_confirmed_bank.bank.slot() {
                    w_optimistically_confirmed_bank.bank = bank;
                }
                drop(w_optimistically_confirmed_bank);

                pending_optimistically_confirmed_banks.retain(|&s| s > root_slot);
            }
            BankNotification::NewRootedChain(mut roots) => {
                Self::notify_new_root_slots(
                    &mut roots,
                    newest_root_slot,
                    slot_notification_subscribers,
                );
            }
        }
    }

    pub fn close(self) -> thread::Result<()> {
        self.join()
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}
