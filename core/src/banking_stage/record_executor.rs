use {
    crate::leader_slot_banking_stage_timing_metrics::RecordTransactionsTimings,
    solana_entry::entry::hash_transactions,
    solana_measure::measure,
    solana_poh::poh_recorder::{PohRecorderError, Slot, TransactionRecorder},
    solana_sdk::transaction::VersionedTransaction,
};

pub struct RecordTransactionsSummary {
    // Metrics describing how time was spent recording transactions
    pub record_transactions_timings: RecordTransactionsTimings,
    // Result of trying to record the transactions into the PoH stream
    pub result: Result<(), PohRecorderError>,
    // Index in the slot of the first transaction recorded
    pub starting_transaction_index: Option<usize>,
}

pub struct RecordExecutor {
    recorder: TransactionRecorder,
}

impl RecordExecutor {
    pub fn new(recorder: TransactionRecorder) -> Self {
        Self { recorder }
    }

    pub fn record_transactions(
        &self,
        bank_slot: Slot,
        transactions: Vec<VersionedTransaction>,
    ) -> RecordTransactionsSummary {
        let mut record_transactions_timings = RecordTransactionsTimings::default();
        let mut starting_transaction_index = None;

        if !transactions.is_empty() {
            let num_to_record = transactions.len();
            inc_new_counter_info!("banking_stage-record_count", 1);
            inc_new_counter_info!("banking_stage-record_transactions", num_to_record);

            let (hash, hash_time) = measure!(hash_transactions(&transactions), "hash");
            record_transactions_timings.hash_us = hash_time.as_us();

            let (res, poh_record_time) =
                measure!(self.recorder.record(bank_slot, hash, transactions), "hash");
            record_transactions_timings.poh_record_us = poh_record_time.as_us();

            match res {
                Ok(starting_index) => {
                    starting_transaction_index = starting_index;
                }
                Err(PohRecorderError::MaxHeightReached) => {
                    inc_new_counter_info!("banking_stage-max_height_reached", 1);
                    inc_new_counter_info!(
                        "banking_stage-max_height_reached_num_to_commit",
                        num_to_record
                    );
                    return RecordTransactionsSummary {
                        record_transactions_timings,
                        result: Err(PohRecorderError::MaxHeightReached),
                        starting_transaction_index: None,
                    };
                }
                Err(e) => panic!("Poh recorder returned unexpected error: {:?}", e),
            }
        }

        RecordTransactionsSummary {
            record_transactions_timings,
            result: Ok(()),
            starting_transaction_index,
        }
    }
}
