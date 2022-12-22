use {
    super::BankingStageStats,
    crate::{
        banking_stage::{
            commit_executor::CommitExecutor,
            record_executor::{RecordExecutor, RecordTransactionsSummary},
            CommitTransactionDetails, ExecuteAndCommitTransactionsOutput, PreBalanceInfo,
            ProcessTransactionBatchOutput, MAX_NUM_TRANSACTIONS_PER_BATCH,
        },
        leader_slot_banking_stage_metrics::{LeaderSlotMetricsTracker, ProcessTransactionsSummary},
        leader_slot_banking_stage_timing_metrics::{
            LeaderExecuteAndCommitTimings, RecordTransactionsTimings,
        },
        qos_service::QosService,
    },
    itertools::Itertools,
    solana_ledger::token_balances::collect_token_balances,
    solana_measure::{measure, measure_us},
    solana_poh::poh_recorder::{BankStart, PohRecorderError},
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        bank::{Bank, LoadAndExecuteTransactionsOutput, TransactionCheckResult},
        transaction_batch::TransactionBatch,
        transaction_error_metrics::TransactionErrorMetrics,
    },
    solana_sdk::{
        clock::{FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET, MAX_PROCESSING_AGE},
        transaction::{self, SanitizedTransaction, TransactionError},
    },
    std::sync::{atomic::Ordering, Arc},
};

pub struct ConsumeExecutor {
    record_executor: RecordExecutor,
    commit_executor: CommitExecutor,
    qos_service: QosService,
    log_messages_bytes_limit: Option<usize>,
}

impl ConsumeExecutor {
    pub fn new(
        record_executor: RecordExecutor,
        commit_executor: CommitExecutor,
        qos_service: QosService,
        log_messages_bytes_limit: Option<usize>,
    ) -> Self {
        Self {
            record_executor,
            commit_executor,
            qos_service,
            log_messages_bytes_limit,
        }
    }

    pub(crate) fn process_packets_transactions<'a>(
        &self,
        bank_start: &BankStart,
        sanitized_transactions: &[SanitizedTransaction],
        banking_stage_stats: &'a BankingStageStats,
        slot_metrics_tracker: &'a mut LeaderSlotMetricsTracker,
    ) -> ProcessTransactionsSummary {
        // Process transactions
        let (mut process_transactions_summary, process_transactions_us) =
            measure_us!(self.process_transactions(bank_start, sanitized_transactions,));
        slot_metrics_tracker.increment_process_transactions_us(process_transactions_us);
        banking_stage_stats
            .transaction_processing_elapsed
            .fetch_add(process_transactions_us, Ordering::Relaxed);

        let ProcessTransactionsSummary {
            ref retryable_transaction_indexes,
            ref error_counters,
            ..
        } = process_transactions_summary;

        slot_metrics_tracker.accumulate_process_transactions_summary(&process_transactions_summary);
        slot_metrics_tracker.accumulate_transaction_errors(error_counters);

        let retryable_tx_count = retryable_transaction_indexes.len();
        inc_new_counter_info!("banking_stage-unprocessed_transactions", retryable_tx_count);

        // Filter out the retryable transactions that are too old
        let (filtered_retryable_transaction_indexes, filter_retryable_packets_us) =
            measure_us!(Self::filter_pending_packets_from_pending_txs(
                &bank_start.working_bank,
                sanitized_transactions,
                retryable_transaction_indexes,
            ));
        slot_metrics_tracker.increment_filter_retryable_packets_us(filter_retryable_packets_us);
        banking_stage_stats
            .filter_pending_packets_elapsed
            .fetch_add(filter_retryable_packets_us, Ordering::Relaxed);

        let retryable_packets_filtered_count = retryable_transaction_indexes
            .len()
            .saturating_sub(filtered_retryable_transaction_indexes.len());
        slot_metrics_tracker
            .increment_retryable_packets_filtered_count(retryable_packets_filtered_count as u64);

        inc_new_counter_info!(
            "banking_stage-dropped_tx_before_forwarding",
            retryable_transaction_indexes
                .len()
                .saturating_sub(filtered_retryable_transaction_indexes.len())
        );

        process_transactions_summary.retryable_transaction_indexes =
            filtered_retryable_transaction_indexes;
        process_transactions_summary
    }

    /// Sends transactions to the bank.
    ///
    /// Returns the number of transactions successfully processed by the bank, which may be less
    /// than the total number if max PoH height was reached and the bank halted
    fn process_transactions(
        &self,
        bank_start: &BankStart,
        transactions: &[SanitizedTransaction],
    ) -> ProcessTransactionsSummary {
        let mut chunk_start = 0;
        let mut all_retryable_tx_indexes = vec![];
        // All the transactions that attempted execution. See description of
        // struct ProcessTransactionsSummary above for possible outcomes.
        let mut total_transactions_attempted_execution_count: usize = 0;
        // All transactions that were executed and committed
        let mut total_committed_transactions_count: usize = 0;
        // All transactions that were executed and committed with a successful result
        let mut total_committed_transactions_with_successful_result_count: usize = 0;
        // All transactions that were executed but then failed record because the
        // slot ended
        let mut total_failed_commit_count: usize = 0;
        let mut total_cost_model_throttled_transactions_count: usize = 0;
        let mut total_cost_model_us: u64 = 0;
        let mut total_execute_and_commit_timings = LeaderExecuteAndCommitTimings::default();
        let mut total_error_counters = TransactionErrorMetrics::default();
        let mut reached_max_poh_height = false;
        while chunk_start != transactions.len() {
            let chunk_end = std::cmp::min(
                transactions.len(),
                chunk_start + MAX_NUM_TRANSACTIONS_PER_BATCH,
            );
            let process_transaction_batch_output = self.process_and_record_transactions(
                &bank_start.working_bank,
                &transactions[chunk_start..chunk_end],
                chunk_start,
            );

            let ProcessTransactionBatchOutput {
                cost_model_throttled_transactions_count: new_cost_model_throttled_transactions_count,
                cost_model_us: new_cost_model_us,
                execute_and_commit_transactions_output,
            } = process_transaction_batch_output;
            total_cost_model_throttled_transactions_count =
                total_cost_model_throttled_transactions_count
                    .saturating_add(new_cost_model_throttled_transactions_count);
            total_cost_model_us = total_cost_model_us.saturating_add(new_cost_model_us);

            let ExecuteAndCommitTransactionsOutput {
                transactions_attempted_execution_count: new_transactions_attempted_execution_count,
                executed_transactions_count: new_executed_transactions_count,
                executed_with_successful_result_count: new_executed_with_successful_result_count,
                retryable_transaction_indexes: new_retryable_transaction_indexes,
                commit_transactions_result: new_commit_transactions_result,
                execute_and_commit_timings: new_execute_and_commit_timings,
                error_counters: new_error_counters,
                ..
            } = execute_and_commit_transactions_output;

            total_execute_and_commit_timings.accumulate(&new_execute_and_commit_timings);
            total_error_counters.accumulate(&new_error_counters);
            total_transactions_attempted_execution_count =
                total_transactions_attempted_execution_count
                    .saturating_add(new_transactions_attempted_execution_count);

            trace!(
                "process_transactions result: {:?}",
                new_commit_transactions_result
            );

            if new_commit_transactions_result.is_ok() {
                total_committed_transactions_count = total_committed_transactions_count
                    .saturating_add(new_executed_transactions_count);
                total_committed_transactions_with_successful_result_count =
                    total_committed_transactions_with_successful_result_count
                        .saturating_add(new_executed_with_successful_result_count);
            } else {
                total_failed_commit_count =
                    total_failed_commit_count.saturating_add(new_executed_transactions_count);
            }

            // Add the retryable txs (transactions that errored in a way that warrants a retry)
            // to the list of unprocessed txs.
            all_retryable_tx_indexes.extend_from_slice(&new_retryable_transaction_indexes);

            // If `bank_creation_time` is None, it's a test so ignore the option so
            // allow processing
            let should_bank_still_be_processing_txs =
                bank_start.should_working_bank_still_be_processing_txs();
            match (
                new_commit_transactions_result,
                should_bank_still_be_processing_txs,
            ) {
                (Err(PohRecorderError::MaxHeightReached), _) | (_, false) => {
                    info!(
                        "process transactions: max height reached slot: {} height: {}",
                        bank_start.working_bank.slot(),
                        bank_start.working_bank.tick_height()
                    );
                    // process_and_record_transactions has returned all retryable errors in
                    // transactions[chunk_start..chunk_end], so we just need to push the remaining
                    // transactions into the unprocessed queue.
                    all_retryable_tx_indexes.extend(chunk_end..transactions.len());
                    reached_max_poh_height = true;
                    break;
                }
                _ => (),
            }
            // Don't exit early on any other type of error, continue processing...
            chunk_start = chunk_end;
        }

        ProcessTransactionsSummary {
            reached_max_poh_height,
            transactions_attempted_execution_count: total_transactions_attempted_execution_count,
            committed_transactions_count: total_committed_transactions_count,
            committed_transactions_with_successful_result_count:
                total_committed_transactions_with_successful_result_count,
            failed_commit_count: total_failed_commit_count,
            retryable_transaction_indexes: all_retryable_tx_indexes,
            cost_model_throttled_transactions_count: total_cost_model_throttled_transactions_count,
            cost_model_us: total_cost_model_us,
            execute_and_commit_timings: total_execute_and_commit_timings,
            error_counters: total_error_counters,
        }
    }

    pub fn process_and_record_transactions(
        &self,
        bank: &Arc<Bank>,
        txs: &[SanitizedTransaction],
        chunk_offset: usize,
    ) -> ProcessTransactionBatchOutput {
        let (
            (transaction_costs, transactions_qos_results, cost_model_throttled_transactions_count),
            cost_model_us,
        ) = measure_us!(self
            .qos_service
            .select_and_accumulate_transaction_costs(bank, txs));

        // Only lock accounts for those transactions are selected for the block;
        // Once accounts are locked, other threads cannot encode transactions that will modify the
        // same account state
        let (batch, lock_us) = measure_us!(
            bank.prepare_sanitized_batch_with_results(txs, transactions_qos_results.iter())
        );

        // retryable_txs includes AccountInUse, WouldExceedMaxBlockCostLimit
        // WouldExceedMaxAccountCostLimit, WouldExceedMaxVoteCostLimit
        // and WouldExceedMaxAccountDataCostLimit
        let mut execute_and_commit_transactions_output =
            self.execute_and_commit_transactions_locked(bank, &batch);

        // Once the accounts are new transactions can enter the pipeline to process them
        let (_, unlock_us) = measure_us!(drop(batch));

        let ExecuteAndCommitTransactionsOutput {
            ref mut retryable_transaction_indexes,
            ref execute_and_commit_timings,
            ref commit_transactions_result,
            ..
        } = execute_and_commit_transactions_output;

        QosService::update_or_remove_transaction_costs(
            transaction_costs.iter(),
            transactions_qos_results.iter(),
            commit_transactions_result.as_ref().ok(),
            bank,
        );

        retryable_transaction_indexes
            .iter_mut()
            .for_each(|x| *x += chunk_offset);

        let (cu, us) =
            Self::accumulate_execute_units_and_time(&execute_and_commit_timings.execute_timings);
        self.qos_service.accumulate_actual_execute_cu(cu);
        self.qos_service.accumulate_actual_execute_time(us);

        // reports qos service stats for this batch
        self.qos_service.report_metrics(bank.clone());

        debug!(
            "bank: {} lock: {}us unlock: {}us txs_len: {}",
            bank.slot(),
            lock_us,
            unlock_us,
            txs.len(),
        );

        ProcessTransactionBatchOutput {
            cost_model_throttled_transactions_count,
            cost_model_us,
            execute_and_commit_transactions_output,
        }
    }

    fn execute_and_commit_transactions_locked(
        &self,
        bank: &Arc<Bank>,
        batch: &TransactionBatch,
    ) -> ExecuteAndCommitTransactionsOutput {
        let has_status_sender = self.commit_executor.has_status_sender();
        let mut execute_and_commit_timings = LeaderExecuteAndCommitTimings::default();

        let mut pre_balance_info = PreBalanceInfo::default();
        let (_, collect_balances_us) = measure_us!({
            // If the extra meta-data services are enabled for RPC, collect the
            // pre-balances for native and token programs.
            if has_status_sender {
                pre_balance_info.native = bank.collect_balances(batch);
                pre_balance_info.token =
                    collect_token_balances(bank, batch, &mut pre_balance_info.mint_decimals)
            }
        });
        execute_and_commit_timings.collect_balances_us = collect_balances_us;

        let (load_and_execute_transactions_output, load_execute_us) = measure_us!(bank
            .load_and_execute_transactions(
                batch,
                MAX_PROCESSING_AGE,
                has_status_sender,
                has_status_sender,
                has_status_sender,
                &mut execute_and_commit_timings.execute_timings,
                None, // account_overrides
                self.log_messages_bytes_limit
            ));
        execute_and_commit_timings.load_execute_us = load_execute_us;

        let LoadAndExecuteTransactionsOutput {
            mut loaded_transactions,
            execution_results,
            mut retryable_transaction_indexes,
            executed_transactions_count,
            executed_with_successful_result_count,
            signature_count,
            error_counters,
            ..
        } = load_and_execute_transactions_output;

        let transactions_attempted_execution_count = execution_results.len();
        let (executed_transactions, execution_results_to_transactions_us): (Vec<_>, u64) =
            measure_us!(execution_results
                .iter()
                .zip(batch.sanitized_transactions())
                .filter_map(|(execution_result, tx)| {
                    if execution_result.was_executed() {
                        Some(tx.to_versioned_transaction())
                    } else {
                        None
                    }
                })
                .collect());

        let (freeze_lock, freeze_lock_us) = measure_us!(bank.freeze_lock());
        execute_and_commit_timings.freeze_lock_us = freeze_lock_us;

        let (record_transactions_summary, record_us) = measure_us!(self
            .record_executor
            .record_transactions(bank.slot(), executed_transactions));
        execute_and_commit_timings.record_us = record_us;

        let RecordTransactionsSummary {
            result: record_transactions_result,
            record_transactions_timings,
            starting_transaction_index,
        } = record_transactions_summary;
        execute_and_commit_timings.record_transactions_timings = RecordTransactionsTimings {
            execution_results_to_transactions_us,
            ..record_transactions_timings
        };

        if let Err(recorder_err) = record_transactions_result {
            inc_new_counter_info!(
                "banking_stage-record_transactions_retryable_record_txs",
                executed_transactions_count
            );

            retryable_transaction_indexes.extend(execution_results.iter().enumerate().filter_map(
                |(index, execution_result)| execution_result.was_executed().then_some(index),
            ));

            return ExecuteAndCommitTransactionsOutput {
                transactions_attempted_execution_count,
                executed_transactions_count,
                executed_with_successful_result_count,
                retryable_transaction_indexes,
                commit_transactions_result: Err(recorder_err),
                execute_and_commit_timings,
                error_counters,
            };
        }

        let sanitized_txs = batch.sanitized_transactions();
        let (commit_time_us, commit_transaction_statuses) = if executed_transactions_count != 0 {
            self.commit_executor.commit_transactions(
                batch,
                &mut loaded_transactions,
                execution_results,
                sanitized_txs,
                starting_transaction_index,
                bank,
                &mut pre_balance_info,
                &mut execute_and_commit_timings,
                signature_count,
                executed_transactions_count,
                executed_with_successful_result_count,
            )
        } else {
            (
                0,
                vec![CommitTransactionDetails::NotCommitted; execution_results.len()],
            )
        };

        drop(freeze_lock);

        debug!(
            "bank: {} process_and_record_locked: {}us record: {}us commit: {}us txs_len: {}",
            bank.slot(),
            load_execute_us,
            record_us,
            commit_time_us,
            sanitized_txs.len(),
        );

        debug!(
            "execute_and_commit_transactions_locked: {:?}",
            execute_and_commit_timings.execute_timings,
        );

        debug_assert_eq!(
            commit_transaction_statuses.len(),
            transactions_attempted_execution_count
        );

        ExecuteAndCommitTransactionsOutput {
            transactions_attempted_execution_count,
            executed_transactions_count,
            executed_with_successful_result_count,
            retryable_transaction_indexes,
            commit_transactions_result: Ok(commit_transaction_statuses),
            execute_and_commit_timings,
            error_counters,
        }
    }

    fn accumulate_execute_units_and_time(execute_timings: &ExecuteTimings) -> (u64, u64) {
        let (units, times): (Vec<_>, Vec<_>) = execute_timings
            .details
            .per_program_timings
            .values()
            .map(|program_timings| {
                (
                    program_timings.accumulated_units,
                    program_timings.accumulated_us,
                )
            })
            .unzip();
        (units.iter().sum(), times.iter().sum())
    }

    /// This function filters pending packets that are still valid
    /// # Arguments
    /// * `transactions` - a batch of transactions deserialized from packets
    /// * `pending_indexes` - identifies which indexes in the `transactions` list are still pending
    fn filter_pending_packets_from_pending_txs(
        bank: &Arc<Bank>,
        transactions: &[SanitizedTransaction],
        pending_indexes: &[usize],
    ) -> Vec<usize> {
        let filter =
            Self::prepare_filter_for_pending_transactions(transactions.len(), pending_indexes);

        let results = bank.check_transactions_with_forwarding_delay(
            transactions.iter(),
            &filter,
            FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET,
        );

        Self::filter_valid_transaction_indexes(&results)
    }

    /// This function creates a filter of transaction results with Ok() for every pending
    /// transaction. The non-pending transactions are marked with TransactionError
    fn prepare_filter_for_pending_transactions(
        transactions_len: usize,
        pending_tx_indexes: &[usize],
    ) -> Vec<transaction::Result<()>> {
        let mut mask = vec![Err(TransactionError::BlockhashNotFound); transactions_len];
        pending_tx_indexes.iter().for_each(|x| mask[*x] = Ok(()));
        mask
    }

    /// This function returns a vector containing index of all valid transactions. A valid
    /// transaction has result Ok() as the value
    fn filter_valid_transaction_indexes(valid_txs: &[TransactionCheckResult]) -> Vec<usize> {
        valid_txs
            .iter()
            .enumerate()
            .filter_map(|(index, (x, _h))| if x.is_ok() { Some(index) } else { None })
            .collect_vec()
    }
}
