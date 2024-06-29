use {
    super::{batch_id_generator::BatchIdGenerator, thread_aware_account_locks::ThreadId},
    crate::banking_stage::scheduler_messages::TransactionBatchId,
    std::collections::HashMap,
};

/// Tracks the number of transactions that are in flight for each thread.
pub struct InFlightTracker {
    num_in_flight_per_thread: Vec<usize>,
    cus_in_flight_per_thread: Vec<u64>,
    batches: HashMap<TransactionBatchId, BatchEntry>,
    batch_id_generator: BatchIdGenerator,
}

struct BatchEntry {
    thread_id: ThreadId,
    num_transactions: usize,
    total_cus: u64,
}

impl InFlightTracker {
    pub fn new(num_threads: usize) -> Self {
        Self {
            num_in_flight_per_thread: vec![0; num_threads],
            cus_in_flight_per_thread: vec![0; num_threads],
            batches: HashMap::new(),
            batch_id_generator: BatchIdGenerator::default(),
        }
    }

    /// Returns the number of transactions that are in flight for each thread.
    pub fn num_in_flight_per_thread(&self) -> &[usize] {
        &self.num_in_flight_per_thread
    }

    /// Returns the number of cus that are in flight for each thread.
    pub fn cus_in_flight_per_thread(&self) -> &[u64] {
        &self.cus_in_flight_per_thread
    }

    /// Tracks number of transactions and CUs in-flight for the `thread_id`.
    /// Returns a `TransactionBatchId` that can be used to stop tracking the batch
    /// when it is complete.
    pub fn track_batch(
        &mut self,
        num_transactions: usize,
        total_cus: u64,
        thread_id: ThreadId,
    ) -> TransactionBatchId {
        let batch_id = self.batch_id_generator.next();
        self.num_in_flight_per_thread[thread_id] += num_transactions;
        self.cus_in_flight_per_thread[thread_id] += total_cus;
        self.batches.insert(
            batch_id,
            BatchEntry {
                thread_id,
                num_transactions,
                total_cus,
            },
        );

        batch_id
    }

    /// Stop tracking the batch with given `batch_id`.
    /// Removes the number of transactions for the scheduled thread.
    /// Returns the thread id that the batch was scheduled on.
    ///
    /// # Panics
    /// Panics if the batch id does not exist in the tracker.
    pub fn complete_batch(&mut self, batch_id: TransactionBatchId) -> ThreadId {
        let Some(BatchEntry {
            thread_id,
            num_transactions,
            total_cus,
        }) = self.batches.remove(&batch_id)
        else {
            panic!("batch id {batch_id} is not being tracked");
        };
        self.num_in_flight_per_thread[thread_id] -= num_transactions;
        self.cus_in_flight_per_thread[thread_id] -= total_cus;

        thread_id
    }
}
