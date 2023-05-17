use {
    super::{
        consumer::{Consumer, ExecuteAndCommitTransactionsOutput, ProcessTransactionBatchOutput},
        forwarder::Forwarder,
        scheduler_messages::{ConsumeWork, FinishedConsumeWork, FinishedForwardWork, ForwardWork},
        ForwardOption,
    },
    crossbeam_channel::{select, Receiver, RecvError, SendError, Sender},
    solana_poh::leader_bank_notifier::LeaderBankNotifier,
    solana_runtime::bank::Bank,
    std::{sync::Arc, time::Duration},
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("Failed to receive work from scheduler: {0}")]
    Recv(#[from] RecvError),
    #[error("Failed to send finalized consume work to scheduler: {0}")]
    ConsumedSend(SendError<FinishedConsumeWork>),
    #[error("Failed to send finalized forward work to scheduler: {0}")]
    ForwardedSend(SendError<FinishedForwardWork>),
}

impl From<SendError<FinishedConsumeWork>> for WorkerError {
    fn from(err: SendError<FinishedConsumeWork>) -> Self {
        Self::ConsumedSend(err)
    }
}

impl From<SendError<FinishedForwardWork>> for WorkerError {
    fn from(err: SendError<FinishedForwardWork>) -> Self {
        Self::ForwardedSend(err)
    }
}

pub(crate) struct Worker {
    consume_receiver: Receiver<ConsumeWork>,
    consumer: Consumer,
    consumed_sender: Sender<FinishedConsumeWork>,

    forward_receiver: Receiver<ForwardWork>,
    forward_option: ForwardOption,
    forwarder: Forwarder,
    forwarded_sender: Sender<FinishedForwardWork>,

    leader_bank_notifier: Arc<LeaderBankNotifier>,
}

#[allow(dead_code)]
impl Worker {
    pub fn new(
        consume_receiver: Receiver<ConsumeWork>,
        consumer: Consumer,
        consumed_sender: Sender<FinishedConsumeWork>,
        forward_receiver: Receiver<ForwardWork>,
        forward_option: ForwardOption,
        forwarder: Forwarder,
        forwarded_sender: Sender<FinishedForwardWork>,
        leader_bank_notifier: Arc<LeaderBankNotifier>,
    ) -> Self {
        Self {
            consume_receiver,
            consumer,
            consumed_sender,
            forward_receiver,
            forward_option,
            forwarder,
            forwarded_sender,
            leader_bank_notifier,
        }
    }

    pub fn run(self) -> Result<(), WorkerError> {
        loop {
            select! {
                recv(self.consume_receiver) -> work => {
                    self.consume_loop(work?)?;
                },
                recv(self.forward_receiver) -> work => {
                    self.forward_loop(work?)?;
                },
            }
        }
    }

    fn consume_loop(&self, work: ConsumeWork) -> Result<(), WorkerError> {
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
    fn consume(&self, bank: &Arc<Bank>, mut work: ConsumeWork) -> Result<(), WorkerError> {
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
            &mut work.max_age_slots,
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
    fn retry_drain(&self, work: ConsumeWork) -> Result<(), WorkerError> {
        for work in try_drain_iter(work, &self.consume_receiver) {
            self.retry(work)?;
        }
        Ok(())
    }

    /// Send transactions back to scheduler as retryable.
    fn retry(&self, work: ConsumeWork) -> Result<(), WorkerError> {
        let retryable_indexes = (0..work.transactions.len()).collect();
        self.consumed_sender.send(FinishedConsumeWork {
            work,
            retryable_indexes,
        })?;
        Ok(())
    }

    fn forward_loop(&self, work: ForwardWork) -> Result<(), WorkerError> {
        for work in try_drain_iter(work, &self.forward_receiver) {
            let (res, _num_packets, _forward_us, _leader_pubkey) = self.forwarder.forward_packets(
                &self.forward_option,
                work.packets.iter().map(|p| p.original_packet()),
            );
            match res {
                Ok(()) => self.forwarded_sender.send(FinishedForwardWork {
                    work,
                    successful: true,
                })?,
                Err(_err) => return self.failed_forward_drain(work),
            };
        }
        Ok(())
    }

    fn failed_forward_drain(&self, work: ForwardWork) -> Result<(), WorkerError> {
        for work in try_drain_iter(work, &self.forward_receiver) {
            self.forwarded_sender.send(FinishedForwardWork {
                work,
                successful: false,
            })?;
        }
        Ok(())
    }
}

/// Helper function to create an non-blocking iterator over work in the receiver,
/// starting with the given work item.
fn try_drain_iter<T>(work: T, receiver: &Receiver<T>) -> impl Iterator<Item = T> + '_ {
    std::iter::once(work).chain(receiver.try_iter())
}
