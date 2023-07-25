//! [`CompletedDataSetsService`] is a hub, that runs different operations when a "completed data
//! set", also known as a [`Vec<Entry>`], is received by the validator.
//!
//! Currently, `WindowService` sends [`CompletedDataSetInfo`]s via a `completed_sets_receiver`
//! provided to the [`CompletedDataSetsService`].

use {
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender},
    solana_entry::entry::Entry,
    solana_ledger::blockstore::{Blockstore, CompletedDataSetInfo},
    solana_rpc::{max_slots::MaxSlots, rpc_subscriptions::RpcSubscriptions},
    solana_sdk::signature::Signature,
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub type CompletedDataSetsReceiver = Receiver<Vec<CompletedDataSetInfo>>;
pub type CompletedDataSetsSender = Sender<Vec<CompletedDataSetInfo>>;

pub struct CompletedDataSetsService {
    thread_hdl: JoinHandle<()>,
}

impl CompletedDataSetsService {
    pub fn new(
        completed_sets_receiver: CompletedDataSetsReceiver,
        blockstore: Arc<Blockstore>,
        rpc_subscriptions: Arc<RpcSubscriptions>,
        exit: &Arc<AtomicBool>,
        max_slots: Arc<MaxSlots>,
    ) -> Self {
        let exit = exit.clone();
        let thread_hdl = Builder::new()
            .name("solComplDataSet".to_string())
            .spawn(move || loop {
                if exit.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(RecvTimeoutError::Disconnected) = Self::recv_completed_data_sets(
                    &completed_sets_receiver,
                    &blockstore,
                    &rpc_subscriptions,
                    &max_slots,
                ) {
                    break;
                }
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn recv_completed_data_sets(
        completed_sets_receiver: &CompletedDataSetsReceiver,
        blockstore: &Blockstore,
        rpc_subscriptions: &RpcSubscriptions,
        max_slots: &Arc<MaxSlots>,
    ) -> Result<(), RecvTimeoutError> {
        let completed_data_sets = completed_sets_receiver.recv_timeout(Duration::from_secs(1))?;
        let mut max_slot = 0;
        for completed_set_info in std::iter::once(completed_data_sets)
            .chain(completed_sets_receiver.try_iter())
            .flatten()
        {
            let CompletedDataSetInfo {
                slot,
                start_index,
                end_index,
            } = completed_set_info;
            max_slot = max_slot.max(slot);
            match blockstore.get_entries_in_data_block(slot, start_index, end_index, None) {
                Ok(entries) => {
                    let transactions = Self::get_transaction_signatures(entries);
                    if !transactions.is_empty() {
                        rpc_subscriptions.notify_signatures_received((slot, transactions));
                    }
                }
                Err(e) => warn!("completed-data-set-service deserialize error: {:?}", e),
            }
        }
        max_slots
            .shred_insert
            .fetch_max(max_slot, Ordering::Relaxed);

        Ok(())
    }

    fn get_transaction_signatures(entries: Vec<Entry>) -> Vec<Signature> {
        entries
            .into_iter()
            .flat_map(|e| {
                e.transactions
                    .into_iter()
                    .filter_map(|mut t| t.signatures.drain(..).next())
            })
            .collect::<Vec<Signature>>()
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}
