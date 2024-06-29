use {
    super::{
        in_flight_tracker::InFlightTracker,
        scheduler_error::SchedulerError,
        thread_aware_account_locks::{ThreadAwareAccountLocks, ThreadId, ThreadSet},
        transaction_state::SanitizedTransactionTTL,
        transaction_state_container::TransactionStateContainer,
    },
    crate::banking_stage::{
        consumer::TARGET_NUM_TRANSACTIONS_PER_BATCH,
        read_write_account_set::ReadWriteAccountSet,
        scheduler_messages::{ConsumeWork, FinishedConsumeWork, TransactionBatchId, TransactionId},
        transaction_scheduler::{
            transaction_priority_id::TransactionPriorityId, transaction_state::TransactionState,
        },
    },
    crossbeam_channel::{Receiver, Sender, TryRecvError},
    itertools::izip,
    prio_graph::{AccessKind, PrioGraph},
    solana_cost_model::block_cost_limits::MAX_BLOCK_UNITS,
    solana_measure::measure_us,
    solana_sdk::{
        pubkey::Pubkey, saturating_add_assign, slot_history::Slot,
        transaction::SanitizedTransaction,
    },
};

pub(crate) struct PrioGraphScheduler {
    in_flight_tracker: InFlightTracker,
    account_locks: ThreadAwareAccountLocks,
    consume_work_senders: Vec<Sender<ConsumeWork>>,
    finished_consume_work_receiver: Receiver<FinishedConsumeWork>,
    look_ahead_window_size: usize,
}

impl PrioGraphScheduler {
    pub(crate) fn new(
        consume_work_senders: Vec<Sender<ConsumeWork>>,
        finished_consume_work_receiver: Receiver<FinishedConsumeWork>,
    ) -> Self {
        let num_threads = consume_work_senders.len();
        Self {
            in_flight_tracker: InFlightTracker::new(num_threads),
            account_locks: ThreadAwareAccountLocks::new(num_threads),
            consume_work_senders,
            finished_consume_work_receiver,
            look_ahead_window_size: 2048,
        }
    }

    /// Schedule transactions from the given `TransactionStateContainer` to be
    /// consumed by the worker threads. Returns summary of scheduling, or an
    /// error.
    /// `pre_graph_filter` is used to filter out transactions that should be
    /// skipped and dropped before insertion to the prio-graph. This fn should
    /// set `false` for transactions that should be dropped, and `true`
    /// otherwise.
    /// `pre_lock_filter` is used to filter out transactions after they have
    /// made it to the top of the prio-graph, and immediately before locks are
    /// checked and taken. This fn should return `true` for transactions that
    /// should be scheduled, and `false` otherwise.
    ///
    /// Uses a `PrioGraph` to perform look-ahead during the scheduling of transactions.
    /// This, combined with internal tracking of threads' in-flight transactions, allows
    /// for load-balancing while prioritizing scheduling transactions onto threads that will
    /// not cause conflicts in the near future.
    pub(crate) fn schedule(
        &mut self,
        container: &mut TransactionStateContainer,
        pre_graph_filter: impl Fn(&[&SanitizedTransaction], &mut [bool]),
        pre_lock_filter: impl Fn(&SanitizedTransaction) -> bool,
    ) -> Result<SchedulingSummary, SchedulerError> {
        let num_threads = self.consume_work_senders.len();
        let max_cu_per_thread = MAX_BLOCK_UNITS / num_threads as u64;

        let mut schedulable_threads = ThreadSet::any(num_threads);
        for thread_id in 0..num_threads {
            if self.in_flight_tracker.cus_in_flight_per_thread()[thread_id] >= max_cu_per_thread {
                schedulable_threads.remove(thread_id);
            }
        }
        if schedulable_threads.is_empty() {
            return Ok(SchedulingSummary {
                num_scheduled: 0,
                num_unschedulable: 0,
                num_filtered_out: 0,
                filter_time_us: 0,
            });
        }

        let mut batches = Batches::new(num_threads);
        // Some transactions may be unschedulable due to multi-thread conflicts.
        // These transactions cannot be scheduled until some conflicting work is completed.
        // However, the scheduler should not allow other transactions that conflict with
        // these transactions to be scheduled before them.
        let mut unschedulable_ids = Vec::new();
        let mut blocking_locks = ReadWriteAccountSet::default();
        let mut prio_graph = PrioGraph::new(|id: &TransactionPriorityId, _graph_node| *id);

        // Track metrics on filter.
        let mut num_filtered_out: usize = 0;
        let mut total_filter_time_us: u64 = 0;

        let mut window_budget = self.look_ahead_window_size;
        let mut chunked_pops = |container: &mut TransactionStateContainer,
                                prio_graph: &mut PrioGraph<_, _, _, _>,
                                window_budget: &mut usize| {
            while *window_budget > 0 {
                const MAX_FILTER_CHUNK_SIZE: usize = 128;
                let mut filter_array = [true; MAX_FILTER_CHUNK_SIZE];
                let mut ids = Vec::with_capacity(MAX_FILTER_CHUNK_SIZE);
                let mut txs = Vec::with_capacity(MAX_FILTER_CHUNK_SIZE);

                let chunk_size = (*window_budget).min(MAX_FILTER_CHUNK_SIZE);
                for _ in 0..chunk_size {
                    if let Some(id) = container.pop() {
                        ids.push(id);
                    } else {
                        break;
                    }
                }
                *window_budget = window_budget.saturating_sub(chunk_size);

                ids.iter().for_each(|id| {
                    let transaction = container.get_transaction_ttl(&id.id).unwrap();
                    txs.push(&transaction.transaction);
                });

                let (_, filter_us) =
                    measure_us!(pre_graph_filter(&txs, &mut filter_array[..chunk_size]));
                saturating_add_assign!(total_filter_time_us, filter_us);

                for (id, filter_result) in ids.iter().zip(&filter_array[..chunk_size]) {
                    if *filter_result {
                        let transaction = container.get_transaction_ttl(&id.id).unwrap();
                        prio_graph.insert_transaction(
                            *id,
                            Self::get_transaction_account_access(transaction),
                        );
                    } else {
                        saturating_add_assign!(num_filtered_out, 1);
                        container.remove_by_id(&id.id);
                    }
                }

                if ids.len() != chunk_size {
                    break;
                }
            }
        };

        // Create the initial look-ahead window.
        // Check transactions against filter, remove from container if it fails.
        chunked_pops(container, &mut prio_graph, &mut window_budget);

        let mut unblock_this_batch =
            Vec::with_capacity(self.consume_work_senders.len() * TARGET_NUM_TRANSACTIONS_PER_BATCH);
        const MAX_TRANSACTIONS_PER_SCHEDULING_PASS: usize = 100_000;
        let mut num_scheduled: usize = 0;
        let mut num_sent: usize = 0;
        let mut num_unschedulable: usize = 0;
        while num_scheduled < MAX_TRANSACTIONS_PER_SCHEDULING_PASS {
            // If nothing is in the main-queue of the `PrioGraph` then there's nothing left to schedule.
            if prio_graph.is_empty() {
                break;
            }

            while let Some(id) = prio_graph.pop() {
                unblock_this_batch.push(id);

                // Should always be in the container, during initial testing phase panic.
                // Later, we can replace with a continue in case this does happen.
                let Some(transaction_state) = container.get_mut_transaction_state(&id.id) else {
                    panic!("transaction state must exist")
                };

                let maybe_schedule_info = try_schedule_transaction(
                    transaction_state,
                    &pre_lock_filter,
                    &mut blocking_locks,
                    &mut self.account_locks,
                    num_threads,
                    |thread_set| {
                        Self::select_thread(
                            thread_set,
                            &batches.total_cus,
                            self.in_flight_tracker.cus_in_flight_per_thread(),
                            &batches.transactions,
                            self.in_flight_tracker.num_in_flight_per_thread(),
                        )
                    },
                );

                match maybe_schedule_info {
                    Err(TransactionSchedulingError::Filtered) => {
                        container.remove_by_id(&id.id);
                    }
                    Err(TransactionSchedulingError::UnschedulableConflicts) => {
                        unschedulable_ids.push(id);
                        saturating_add_assign!(num_unschedulable, 1);
                    }
                    Ok(TransactionSchedulingInfo {
                        thread_id,
                        transaction,
                        max_age_slot,
                        cost,
                    }) => {
                        saturating_add_assign!(num_scheduled, 1);
                        batches.transactions[thread_id].push(transaction);
                        batches.ids[thread_id].push(id.id);
                        batches.max_age_slots[thread_id].push(max_age_slot);
                        saturating_add_assign!(batches.total_cus[thread_id], cost);

                        // If target batch size is reached, send only this batch.
                        if batches.ids[thread_id].len() >= TARGET_NUM_TRANSACTIONS_PER_BATCH {
                            saturating_add_assign!(
                                num_sent,
                                self.send_batch(&mut batches, thread_id)?
                            );
                        }

                        // if the thread is at max_cu_per_thread, remove it from the schedulable threads
                        // if there are no more schedulable threads, stop scheduling.
                        if self.in_flight_tracker.cus_in_flight_per_thread()[thread_id]
                            + batches.total_cus[thread_id]
                            >= max_cu_per_thread
                        {
                            schedulable_threads.remove(thread_id);
                            if schedulable_threads.is_empty() {
                                break;
                            }
                        }

                        if num_scheduled >= MAX_TRANSACTIONS_PER_SCHEDULING_PASS {
                            break;
                        }
                    }
                }
            }

            // Send all non-empty batches
            saturating_add_assign!(num_sent, self.send_batches(&mut batches)?);

            // Refresh window budget and do chunked pops
            saturating_add_assign!(window_budget, unblock_this_batch.len());
            chunked_pops(container, &mut prio_graph, &mut window_budget);

            // Unblock all transactions that were blocked by the transactions that were just sent.
            for id in unblock_this_batch.drain(..) {
                prio_graph.unblock(&id);
            }
        }

        // Send batches for any remaining transactions
        saturating_add_assign!(num_sent, self.send_batches(&mut batches)?);

        // Push unschedulable ids back into the container
        for id in unschedulable_ids {
            container.push_id_into_queue(id);
        }

        // Push remaining transactions back into the container
        while let Some((id, _)) = prio_graph.pop_and_unblock() {
            container.push_id_into_queue(id);
        }

        assert_eq!(
            num_scheduled, num_sent,
            "number of scheduled and sent transactions must match"
        );

        Ok(SchedulingSummary {
            num_scheduled,
            num_unschedulable,
            num_filtered_out,
            filter_time_us: total_filter_time_us,
        })
    }

    /// Receive completed batches of transactions without blocking.
    /// Returns (num_transactions, num_retryable_transactions) on success.
    pub fn receive_completed(
        &mut self,
        container: &mut TransactionStateContainer,
    ) -> Result<(usize, usize), SchedulerError> {
        let mut total_num_transactions: usize = 0;
        let mut total_num_retryable: usize = 0;
        loop {
            let (num_transactions, num_retryable) = self.try_receive_completed(container)?;
            if num_transactions == 0 {
                break;
            }
            saturating_add_assign!(total_num_transactions, num_transactions);
            saturating_add_assign!(total_num_retryable, num_retryable);
        }
        Ok((total_num_transactions, total_num_retryable))
    }

    /// Receive completed batches of transactions.
    /// Returns `Ok((num_transactions, num_retryable))` if a batch was received, `Ok((0, 0))` if no batch was received.
    fn try_receive_completed(
        &mut self,
        container: &mut TransactionStateContainer,
    ) -> Result<(usize, usize), SchedulerError> {
        match self.finished_consume_work_receiver.try_recv() {
            Ok(FinishedConsumeWork {
                work:
                    ConsumeWork {
                        batch_id,
                        ids,
                        transactions,
                        max_age_slots,
                    },
                retryable_indexes,
            }) => {
                let num_transactions = ids.len();
                let num_retryable = retryable_indexes.len();

                // Free the locks
                self.complete_batch(batch_id, &transactions);

                // Retryable transactions should be inserted back into the container
                let mut retryable_iter = retryable_indexes.into_iter().peekable();
                for (index, (id, transaction, max_age_slot)) in
                    izip!(ids, transactions, max_age_slots).enumerate()
                {
                    if let Some(retryable_index) = retryable_iter.peek() {
                        if *retryable_index == index {
                            container.retry_transaction(
                                id,
                                SanitizedTransactionTTL {
                                    transaction,
                                    max_age_slot,
                                },
                            );
                            retryable_iter.next();
                            continue;
                        }
                    }
                    container.remove_by_id(&id);
                }

                Ok((num_transactions, num_retryable))
            }
            Err(TryRecvError::Empty) => Ok((0, 0)),
            Err(TryRecvError::Disconnected) => Err(SchedulerError::DisconnectedRecvChannel(
                "finished consume work",
            )),
        }
    }

    /// Mark a given `TransactionBatchId` as completed.
    /// This will update the internal tracking, including account locks.
    fn complete_batch(
        &mut self,
        batch_id: TransactionBatchId,
        transactions: &[SanitizedTransaction],
    ) {
        let thread_id = self.in_flight_tracker.complete_batch(batch_id);
        for transaction in transactions {
            let message = transaction.message();
            let account_keys = message.account_keys();
            let write_account_locks = account_keys
                .iter()
                .enumerate()
                .filter_map(|(index, key)| message.is_writable(index).then_some(key));
            let read_account_locks = account_keys
                .iter()
                .enumerate()
                .filter_map(|(index, key)| (!message.is_writable(index)).then_some(key));
            self.account_locks
                .unlock_accounts(write_account_locks, read_account_locks, thread_id);
        }
    }

    /// Send all batches of transactions to the worker threads.
    /// Returns the number of transactions sent.
    fn send_batches(&mut self, batches: &mut Batches) -> Result<usize, SchedulerError> {
        (0..self.consume_work_senders.len())
            .map(|thread_index| self.send_batch(batches, thread_index))
            .sum()
    }

    /// Send a batch of transactions to the given thread's `ConsumeWork` channel.
    /// Returns the number of transactions sent.
    fn send_batch(
        &mut self,
        batches: &mut Batches,
        thread_index: usize,
    ) -> Result<usize, SchedulerError> {
        if batches.ids[thread_index].is_empty() {
            return Ok(0);
        }

        let (ids, transactions, max_age_slots, total_cus) = batches.take_batch(thread_index);

        let batch_id = self
            .in_flight_tracker
            .track_batch(ids.len(), total_cus, thread_index);

        let num_scheduled = ids.len();
        let work = ConsumeWork {
            batch_id,
            ids,
            transactions,
            max_age_slots,
        };
        self.consume_work_senders[thread_index]
            .send(work)
            .map_err(|_| SchedulerError::DisconnectedSendChannel("consume work sender"))?;

        Ok(num_scheduled)
    }

    /// Given the schedulable `thread_set`, select the thread with the least amount
    /// of work queued up.
    /// Currently, "work" is just defined as the number of transactions.
    ///
    /// If the `chain_thread` is available, this thread will be selected, regardless of
    /// load-balancing.
    ///
    /// Panics if the `thread_set` is empty. This should never happen, see comment
    /// on `ThreadAwareAccountLocks::try_lock_accounts`.
    fn select_thread(
        thread_set: ThreadSet,
        batch_cus_per_thread: &[u64],
        in_flight_cus_per_thread: &[u64],
        batches_per_thread: &[Vec<SanitizedTransaction>],
        in_flight_per_thread: &[usize],
    ) -> ThreadId {
        thread_set
            .contained_threads_iter()
            .map(|thread_id| {
                (
                    thread_id,
                    batch_cus_per_thread[thread_id] + in_flight_cus_per_thread[thread_id],
                    batches_per_thread[thread_id].len() + in_flight_per_thread[thread_id],
                )
            })
            .min_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)))
            .map(|(thread_id, _, _)| thread_id)
            .unwrap()
    }

    /// Gets accessed accounts (resources) for use in `PrioGraph`.
    fn get_transaction_account_access(
        transaction: &SanitizedTransactionTTL,
    ) -> impl Iterator<Item = (Pubkey, AccessKind)> + '_ {
        let message = transaction.transaction.message();
        message
            .account_keys()
            .iter()
            .enumerate()
            .map(|(index, key)| {
                if message.is_writable(index) {
                    (*key, AccessKind::Write)
                } else {
                    (*key, AccessKind::Read)
                }
            })
    }
}

/// Metrics from scheduling transactions.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SchedulingSummary {
    /// Number of transactions scheduled.
    pub num_scheduled: usize,
    /// Number of transactions that were not scheduled due to conflicts.
    pub num_unschedulable: usize,
    /// Number of transactions that were dropped due to filter.
    pub num_filtered_out: usize,
    /// Time spent filtering transactions
    pub filter_time_us: u64,
}

struct Batches {
    ids: Vec<Vec<TransactionId>>,
    transactions: Vec<Vec<SanitizedTransaction>>,
    max_age_slots: Vec<Vec<Slot>>,
    total_cus: Vec<u64>,
}

impl Batches {
    fn new(num_threads: usize) -> Self {
        Self {
            ids: vec![Vec::with_capacity(TARGET_NUM_TRANSACTIONS_PER_BATCH); num_threads],
            transactions: vec![Vec::with_capacity(TARGET_NUM_TRANSACTIONS_PER_BATCH); num_threads],
            max_age_slots: vec![Vec::with_capacity(TARGET_NUM_TRANSACTIONS_PER_BATCH); num_threads],
            total_cus: vec![0; num_threads],
        }
    }

    fn take_batch(
        &mut self,
        thread_id: ThreadId,
    ) -> (
        Vec<TransactionId>,
        Vec<SanitizedTransaction>,
        Vec<Slot>,
        u64,
    ) {
        (
            core::mem::replace(
                &mut self.ids[thread_id],
                Vec::with_capacity(TARGET_NUM_TRANSACTIONS_PER_BATCH),
            ),
            core::mem::replace(
                &mut self.transactions[thread_id],
                Vec::with_capacity(TARGET_NUM_TRANSACTIONS_PER_BATCH),
            ),
            core::mem::replace(
                &mut self.max_age_slots[thread_id],
                Vec::with_capacity(TARGET_NUM_TRANSACTIONS_PER_BATCH),
            ),
            core::mem::replace(&mut self.total_cus[thread_id], 0),
        )
    }
}

/// A transaction has been scheduled to a thread.
struct TransactionSchedulingInfo {
    thread_id: ThreadId,
    transaction: SanitizedTransaction,
    max_age_slot: Slot,
    cost: u64,
}

/// Error type for reasons a transaction could not be scheduled.
enum TransactionSchedulingError {
    /// Transaction was filtered out before locking.
    Filtered,
    /// Transaction cannot be scheduled due to conflicts, or
    /// higher priority conflicting transactions are unschedulable.
    UnschedulableConflicts,
}

fn try_schedule_transaction(
    transaction_state: &mut TransactionState,
    pre_lock_filter: impl Fn(&SanitizedTransaction) -> bool,
    blocking_locks: &mut ReadWriteAccountSet,
    account_locks: &mut ThreadAwareAccountLocks,
    num_threads: usize,
    thread_selector: impl Fn(ThreadSet) -> ThreadId,
) -> Result<TransactionSchedulingInfo, TransactionSchedulingError> {
    let transaction = &transaction_state.transaction_ttl().transaction;
    if !pre_lock_filter(transaction) {
        return Err(TransactionSchedulingError::Filtered);
    }

    // Check if this transaction conflicts with any blocked transactions
    let message = transaction.message();
    if !blocking_locks.check_locks(message) {
        blocking_locks.take_locks(message);
        return Err(TransactionSchedulingError::UnschedulableConflicts);
    }

    // Schedule the transaction if it can be.
    let transaction_locks = transaction.get_account_locks_unchecked();
    let Some(thread_id) = account_locks.try_lock_accounts(
        transaction_locks.writable.into_iter(),
        transaction_locks.readonly.into_iter(),
        ThreadSet::any(num_threads),
        thread_selector,
    ) else {
        blocking_locks.take_locks(message);
        return Err(TransactionSchedulingError::UnschedulableConflicts);
    };

    let sanitized_transaction_ttl = transaction_state.transition_to_pending();
    let cost = transaction_state.cost();

    Ok(TransactionSchedulingInfo {
        thread_id,
        transaction: sanitized_transaction_ttl.transaction,
        max_age_slot: sanitized_transaction_ttl.max_age_slot,
        cost,
    })
}
