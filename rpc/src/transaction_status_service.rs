use {
    crate::transaction_notifier_interface::TransactionNotifierArc,
    crossbeam_channel::{Receiver, RecvTimeoutError},
    itertools::izip,
    solana_ledger::{
        blockstore::Blockstore,
        blockstore_processor::{TransactionStatusBatch, TransactionStatusMessage},
    },
    solana_svm::transaction_results::TransactionExecutionDetails,
    solana_transaction_status::{
        extract_and_fmt_memos, map_inner_instructions, Reward, TransactionStatusMeta,
    },
    std::{
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct TransactionStatusService {
    thread_hdl: JoinHandle<()>,
}

impl TransactionStatusService {
    pub fn new(
        write_transaction_status_receiver: Receiver<TransactionStatusMessage>,
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        enable_rpc_transaction_history: bool,
        transaction_notifier: Option<TransactionNotifierArc>,
        blockstore: Arc<Blockstore>,
        enable_extended_tx_metadata_storage: bool,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let thread_hdl = Builder::new()
            .name("solTxStatusWrtr".to_string())
            .spawn(move || loop {
                if exit.load(Ordering::Relaxed) {
                    break;
                }

                if let Err(RecvTimeoutError::Disconnected) = Self::write_transaction_status_batch(
                    &write_transaction_status_receiver,
                    &max_complete_transaction_status_slot,
                    enable_rpc_transaction_history,
                    transaction_notifier.clone(),
                    &blockstore,
                    enable_extended_tx_metadata_storage,
                ) {
                    break;
                }
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn write_transaction_status_batch(
        write_transaction_status_receiver: &Receiver<TransactionStatusMessage>,
        max_complete_transaction_status_slot: &Arc<AtomicU64>,
        enable_rpc_transaction_history: bool,
        transaction_notifier: Option<TransactionNotifierArc>,
        blockstore: &Blockstore,
        enable_extended_tx_metadata_storage: bool,
    ) -> Result<(), RecvTimeoutError> {
        match write_transaction_status_receiver.recv_timeout(Duration::from_secs(1))? {
            TransactionStatusMessage::Batch(TransactionStatusBatch {
                bank,
                transactions,
                execution_results,
                balances,
                token_balances,
                rent_debits,
                transaction_indexes,
            }) => {
                let slot = bank.slot();
                for (
                    transaction,
                    execution_result,
                    pre_balances,
                    post_balances,
                    pre_token_balances,
                    post_token_balances,
                    rent_debits,
                    transaction_index,
                ) in izip!(
                    transactions,
                    execution_results,
                    balances.pre_balances,
                    balances.post_balances,
                    token_balances.pre_token_balances,
                    token_balances.post_token_balances,
                    rent_debits,
                    transaction_indexes,
                ) {
                    if let Some(details) = execution_result {
                        let TransactionExecutionDetails {
                            status,
                            log_messages,
                            inner_instructions,
                            return_data,
                            executed_units,
                            fee_details,
                            ..
                        } = details;
                        let tx_account_locks = transaction.get_account_locks_unchecked();

                        let fee = fee_details.total_fee();
                        let inner_instructions = inner_instructions.map(|inner_instructions| {
                            map_inner_instructions(inner_instructions).collect()
                        });

                        let pre_token_balances = Some(pre_token_balances);
                        let post_token_balances = Some(post_token_balances);
                        let rewards = Some(
                            rent_debits
                                .into_unordered_rewards_iter()
                                .map(|(pubkey, reward_info)| Reward {
                                    pubkey: pubkey.to_string(),
                                    lamports: reward_info.lamports,
                                    post_balance: reward_info.post_balance,
                                    reward_type: Some(reward_info.reward_type),
                                    commission: reward_info.commission,
                                })
                                .collect(),
                        );
                        let loaded_addresses = transaction.get_loaded_addresses();
                        let mut transaction_status_meta = TransactionStatusMeta {
                            status,
                            fee,
                            pre_balances,
                            post_balances,
                            inner_instructions,
                            log_messages,
                            pre_token_balances,
                            post_token_balances,
                            rewards,
                            loaded_addresses,
                            return_data,
                            compute_units_consumed: Some(executed_units),
                        };

                        if let Some(transaction_notifier) = transaction_notifier.as_ref() {
                            transaction_notifier.notify_transaction(
                                slot,
                                transaction_index,
                                transaction.signature(),
                                &transaction_status_meta,
                                &transaction,
                            );
                        }

                        if !(enable_extended_tx_metadata_storage || transaction_notifier.is_some())
                        {
                            transaction_status_meta.log_messages.take();
                            transaction_status_meta.inner_instructions.take();
                            transaction_status_meta.return_data.take();
                        }

                        if enable_rpc_transaction_history {
                            if let Some(memos) = extract_and_fmt_memos(transaction.message()) {
                                blockstore
                                    .write_transaction_memos(transaction.signature(), slot, memos)
                                    .expect("Expect database write to succeed: TransactionMemos");
                            }

                            blockstore
                                .write_transaction_status(
                                    slot,
                                    *transaction.signature(),
                                    tx_account_locks.writable,
                                    tx_account_locks.readonly,
                                    transaction_status_meta,
                                    transaction_index,
                                )
                                .expect("Expect database write to succeed: TransactionStatus");
                        }
                    }
                }
            }
            TransactionStatusMessage::Freeze(slot) => {
                max_complete_transaction_status_slot.fetch_max(slot, Ordering::SeqCst);
            }
        }
        Ok(())
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}
