use {
    super::{
        consumer::{Consumer, ExecuteAndCommitTransactionsOutput, ProcessTransactionBatchOutput},
        scheduler_messages::{ConsumeWork, FinishedConsumeWork},
    },
    crossbeam_channel::{Receiver, RecvError, SendError, Sender},
    solana_poh::leader_bank_notifier::LeaderBankNotifier,
    solana_runtime::bank::Bank,
    std::{sync::Arc, time::Duration},
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum ConsumeWorkerError {
    #[error("Failed to receive work from scheduler: {0}")]
    Recv(#[from] RecvError),
    #[error("Failed to send finalized consume work to scheduler: {0}")]
    Send(#[from] SendError<FinishedConsumeWork>),
}

pub(crate) struct ConsumeWorker {
    consume_receiver: Receiver<ConsumeWork>,
    consumer: Consumer,
    consumed_sender: Sender<FinishedConsumeWork>,

    leader_bank_notifier: Arc<LeaderBankNotifier>,
}

#[allow(dead_code)]
impl ConsumeWorker {
    pub fn new(
        consume_receiver: Receiver<ConsumeWork>,
        consumer: Consumer,
        consumed_sender: Sender<FinishedConsumeWork>,
        leader_bank_notifier: Arc<LeaderBankNotifier>,
    ) -> Self {
        Self {
            consume_receiver,
            consumer,
            consumed_sender,
            leader_bank_notifier,
        }
    }

    pub fn run(self) -> Result<(), ConsumeWorkerError> {
        loop {
            let work = self.consume_receiver.recv()?;
            self.consume_loop(work)?;
        }
    }

    fn consume_loop(&self, work: ConsumeWork) -> Result<(), ConsumeWorkerError> {
        let Some(mut bank) = self.get_consume_bank() else {
            return self.retry_drain(work);
        };

        for work in try_drain_iter(work, &self.consume_receiver) {
            if bank.is_complete() {
                if let Some(new_bank) = self.get_consume_bank() {
                    bank = new_bank;
                } else {
                    return self.retry_drain(work);
                }
            }
            self.consume(&bank, work)?;
        }

        Ok(())
    }

    /// Consume a single batch.
    fn consume(&self, bank: &Arc<Bank>, work: ConsumeWork) -> Result<(), ConsumeWorkerError> {
        let ProcessTransactionBatchOutput {
            execute_and_commit_transactions_output:
                ExecuteAndCommitTransactionsOutput {
                    retryable_transaction_indexes,
                    ..
                },
            ..
        } = self.consumer.process_and_record_aged_transactions(
            bank,
            &work.transactions,
            &work.max_age_slots,
        );

        self.consumed_sender.send(FinishedConsumeWork {
            work,
            retryable_indexes: retryable_transaction_indexes,
        })?;
        Ok(())
    }

    /// Try to get a bank for consuming.
    fn get_consume_bank(&self) -> Option<Arc<Bank>> {
        self.leader_bank_notifier
            .get_or_wait_for_in_progress(Duration::from_millis(50))
            .upgrade()
    }

    /// Retry current batch and all outstanding batches.
    fn retry_drain(&self, work: ConsumeWork) -> Result<(), ConsumeWorkerError> {
        for work in try_drain_iter(work, &self.consume_receiver) {
            self.retry(work)?;
        }
        Ok(())
    }

    /// Send transactions back to scheduler as retryable.
    fn retry(&self, work: ConsumeWork) -> Result<(), ConsumeWorkerError> {
        let retryable_indexes = (0..work.transactions.len()).collect();
        self.consumed_sender.send(FinishedConsumeWork {
            work,
            retryable_indexes,
        })?;
        Ok(())
    }
}

/// Helper function to create an non-blocking iterator over work in the receiver,
/// starting with the given work item.
fn try_drain_iter<T>(work: T, receiver: &Receiver<T>) -> impl Iterator<Item = T> + '_ {
    std::iter::once(work).chain(receiver.try_iter())
}
