use {
    super::{
        committer::{CommitTransactionDetails, Committer, PreBalanceInfo},
        immutable_deserialized_packet::ImmutableDeserializedPacket,
        leader_slot_metrics::{LeaderSlotMetricsTracker, ProcessTransactionsSummary},
        leader_slot_timing_metrics::LeaderExecuteAndCommitTimings,
        qos_service::QosService,
        unprocessed_transaction_storage::{ConsumeScannerPayload, UnprocessedTransactionStorage},
        BankingStageStats,
    },
    itertools::Itertools,
    solana_compute_budget::compute_budget_processor::process_compute_budget_instructions,
    solana_ledger::token_balances::collect_token_balances,
    solana_measure::{measure::Measure, measure_us},
    solana_poh::poh_recorder::{
        BankStart, PohRecorderError, RecordTransactionsSummary, RecordTransactionsTimings,
        TransactionRecorder,
    },
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        bank::{Bank, LoadAndExecuteTransactionsOutput},
        compute_budget_details::GetComputeBudgetDetails,
        transaction_batch::TransactionBatch,
    },
    solana_sdk::{
        clock::{Slot, FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET, MAX_PROCESSING_AGE},
        feature_set,
        message::SanitizedMessage,
        saturating_add_assign,
        timing::timestamp,
        transaction::{self, AddressLoader, SanitizedTransaction, TransactionError},
    },
    solana_svm::{
        account_loader::{validate_fee_payer, TransactionCheckResult},
        transaction_error_metrics::TransactionErrorMetrics,
        transaction_processor::{ExecutionRecordingConfig, TransactionProcessingConfig},
    },
    std::{
        sync::{atomic::Ordering, Arc},
        time::Instant,
    },
};

/// Consumer will create chunks of transactions from buffer with up to this size.
pub const TARGET_NUM_TRANSACTIONS_PER_BATCH: usize = 64;

pub struct ProcessTransactionBatchOutput {
    // The number of transactions filtered out by the cost model
    pub(crate) cost_model_throttled_transactions_count: usize,
    // Amount of time spent running the cost model
    pub(crate) cost_model_us: u64,
    pub execute_and_commit_transactions_output: ExecuteAndCommitTransactionsOutput,
}

pub struct ExecuteAndCommitTransactionsOutput {
    // Total number of transactions that were passed as candidates for execution
    pub(crate) transactions_attempted_execution_count: usize,
    // The number of transactions of that were executed. See description of in `ProcessTransactionsSummary`
    // for possible outcomes of execution.
    pub(crate) executed_transactions_count: usize,
    // Total number of the executed transactions that returned success/not
    // an error.
    pub(crate) executed_with_successful_result_count: usize,
    // Transactions that either were not executed, or were executed and failed to be committed due
    // to the block ending.
    pub(crate) retryable_transaction_indexes: Vec<usize>,
    // A result that indicates whether transactions were successfully
    // committed into the Poh stream.
    pub commit_transactions_result: Result<Vec<CommitTransactionDetails>, PohRecorderError>,
    pub(crate) execute_and_commit_timings: LeaderExecuteAndCommitTimings,
    pub(crate) error_counters: TransactionErrorMetrics,
    pub(crate) min_prioritization_fees: u64,
    pub(crate) max_prioritization_fees: u64,
}

pub struct Consumer {
    committer: Committer,
    transaction_recorder: TransactionRecorder,
    qos_service: QosService,
    log_messages_bytes_limit: Option<usize>,
}

impl Consumer {
    pub fn new(
        committer: Committer,
        transaction_recorder: TransactionRecorder,
        qos_service: QosService,
        log_messages_bytes_limit: Option<usize>,
    ) -> Self {
        Self {
            committer,
            transaction_recorder,
            qos_service,
            log_messages_bytes_limit,
        }
    }

    pub fn consume_buffered_packets(
        &self,
        bank_start: &BankStart,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        banking_stage_stats: &BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) {
        let mut rebuffered_packet_count = 0;
        let mut consumed_buffered_packets_count = 0;
        let mut proc_start = Measure::start("consume_buffered_process");
        let num_packets_to_process = unprocessed_transaction_storage.len();

        let reached_end_of_slot = unprocessed_transaction_storage.process_packets(
            bank_start.working_bank.clone(),
            banking_stage_stats,
            slot_metrics_tracker,
            |packets_to_process, payload| {
                self.do_process_packets(
                    bank_start,
                    payload,
                    banking_stage_stats,
                    &mut consumed_buffered_packets_count,
                    &mut rebuffered_packet_count,
                    packets_to_process,
                )
            },
        );

        if reached_end_of_slot {
            slot_metrics_tracker.set_end_of_slot_unprocessed_buffer_len(
                unprocessed_transaction_storage.len() as u64,
            );
        }

        proc_start.stop();
        debug!(
            "@{:?} done processing buffered batches: {} time: {:?}ms tx count: {} tx/s: {}",
            timestamp(),
            num_packets_to_process,
            proc_start.as_ms(),
            consumed_buffered_packets_count,
            (consumed_buffered_packets_count as f32) / (proc_start.as_s())
        );

        banking_stage_stats
            .consume_buffered_packets_elapsed
            .fetch_add(proc_start.as_us(), Ordering::Relaxed);
        banking_stage_stats
            .rebuffered_packets_count
            .fetch_add(rebuffered_packet_count, Ordering::Relaxed);
        banking_stage_stats
            .consumed_buffered_packets_count
            .fetch_add(consumed_buffered_packets_count, Ordering::Relaxed);
    }

    fn do_process_packets(
        &self,
        bank_start: &BankStart,
        payload: &mut ConsumeScannerPayload,
        banking_stage_stats: &BankingStageStats,
        consumed_buffered_packets_count: &mut usize,
        rebuffered_packet_count: &mut usize,
        packets_to_process: &[Arc<ImmutableDeserializedPacket>],
    ) -> Option<Vec<usize>> {
        if payload.reached_end_of_slot {
            return None;
        }

        let packets_to_process_len = packets_to_process.len();
        let (process_transactions_summary, process_packets_transactions_us) = measure_us!(self
            .process_packets_transactions(
                &bank_start.working_bank,
                &bank_start.bank_creation_time,
                &payload.sanitized_transactions,
                banking_stage_stats,
                payload.slot_metrics_tracker,
            ));
        payload
            .slot_metrics_tracker
            .increment_process_packets_transactions_us(process_packets_transactions_us);

        // Clear payload for next iteration
        payload.sanitized_transactions.clear();
        payload.account_locks.clear();

        let ProcessTransactionsSummary {
            reached_max_poh_height,
            retryable_transaction_indexes,
            ..
        } = process_transactions_summary;

        if reached_max_poh_height || !bank_start.should_working_bank_still_be_processing_txs() {
            payload.reached_end_of_slot = true;
        }

        // The difference between all transactions passed to execution and the ones that
        // are retryable were the ones that were either:
        // 1) Committed into the block
        // 2) Dropped without being committed because they had some fatal error (too old,
        // duplicate signature, etc.)
        //
        // Note: This assumes that every packet deserializes into one transaction!
        *consumed_buffered_packets_count +=
            packets_to_process_len.saturating_sub(retryable_transaction_indexes.len());

        // Out of the buffered packets just retried, collect any still unprocessed
        // transactions in this batch for forwarding
        *rebuffered_packet_count += retryable_transaction_indexes.len();

        payload
            .slot_metrics_tracker
            .increment_retryable_packets_count(retryable_transaction_indexes.len() as u64);

        Some(retryable_transaction_indexes)
    }

    fn process_packets_transactions(
        &self,
        bank: &Arc<Bank>,
        bank_creation_time: &Instant,
        sanitized_transactions: &[SanitizedTransaction],
        banking_stage_stats: &BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) -> ProcessTransactionsSummary {
        let (mut process_transactions_summary, process_transactions_us) = measure_us!(
            self.process_transactions(bank, bank_creation_time, sanitized_transactions)
        );
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

        // Filter out the retryable transactions that are too old
        let (filtered_retryable_transaction_indexes, filter_retryable_packets_us) =
            measure_us!(Self::filter_pending_packets_from_pending_txs(
                bank,
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

        banking_stage_stats
            .dropped_forward_packets_count
            .fetch_add(retryable_packets_filtered_count, Ordering::Relaxed);

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
        bank: &Arc<Bank>,
        bank_creation_time: &Instant,
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
        let mut overall_min_prioritization_fees: u64 = u64::MAX;
        let mut overall_max_prioritization_fees: u64 = 0;
        while chunk_start != transactions.len() {
            let chunk_end = std::cmp::min(
                transactions.len(),
                chunk_start + TARGET_NUM_TRANSACTIONS_PER_BATCH,
            );
            let process_transaction_batch_output = self.process_and_record_transactions(
                bank,
                &transactions[chunk_start..chunk_end],
                chunk_start,
            );

            let ProcessTransactionBatchOutput {
                cost_model_throttled_transactions_count: new_cost_model_throttled_transactions_count,
                cost_model_us: new_cost_model_us,
                execute_and_commit_transactions_output,
            } = process_transaction_batch_output;
            saturating_add_assign!(
                total_cost_model_throttled_transactions_count,
                new_cost_model_throttled_transactions_count
            );
            saturating_add_assign!(total_cost_model_us, new_cost_model_us);

            let ExecuteAndCommitTransactionsOutput {
                transactions_attempted_execution_count: new_transactions_attempted_execution_count,
                executed_transactions_count: new_executed_transactions_count,
                executed_with_successful_result_count: new_executed_with_successful_result_count,
                retryable_transaction_indexes: new_retryable_transaction_indexes,
                commit_transactions_result: new_commit_transactions_result,
                execute_and_commit_timings: new_execute_and_commit_timings,
                error_counters: new_error_counters,
                min_prioritization_fees,
                max_prioritization_fees,
                ..
            } = execute_and_commit_transactions_output;

            total_execute_and_commit_timings.accumulate(&new_execute_and_commit_timings);
            total_error_counters.accumulate(&new_error_counters);
            saturating_add_assign!(
                total_transactions_attempted_execution_count,
                new_transactions_attempted_execution_count
            );
            overall_min_prioritization_fees =
                std::cmp::min(overall_min_prioritization_fees, min_prioritization_fees);
            overall_max_prioritization_fees =
                std::cmp::min(overall_max_prioritization_fees, max_prioritization_fees);

            trace!(
                "process_transactions result: {:?}",
                new_commit_transactions_result
            );

            if new_commit_transactions_result.is_ok() {
                saturating_add_assign!(
                    total_committed_transactions_count,
                    new_executed_transactions_count
                );
                saturating_add_assign!(
                    total_committed_transactions_with_successful_result_count,
                    new_executed_with_successful_result_count
                );
            } else {
                saturating_add_assign!(total_failed_commit_count, new_executed_transactions_count);
            }

            // Add the retryable txs (transactions that errored in a way that warrants a retry)
            // to the list of unprocessed txs.
            all_retryable_tx_indexes.extend_from_slice(&new_retryable_transaction_indexes);

            let should_bank_still_be_processing_txs =
                Bank::should_bank_still_be_processing_txs(bank_creation_time, bank.ns_per_slot);
            match (
                new_commit_transactions_result,
                should_bank_still_be_processing_txs,
            ) {
                (Err(PohRecorderError::MaxHeightReached), _) | (_, false) => {
                    info!(
                        "process transactions: max height reached slot: {} height: {}",
                        bank.slot(),
                        bank.tick_height()
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
            min_prioritization_fees: overall_min_prioritization_fees,
            max_prioritization_fees: overall_max_prioritization_fees,
        }
    }

    pub fn process_and_record_transactions(
        &self,
        bank: &Arc<Bank>,
        txs: &[SanitizedTransaction],
        chunk_offset: usize,
    ) -> ProcessTransactionBatchOutput {
        let mut error_counters = TransactionErrorMetrics::default();
        let pre_results = vec![Ok(()); txs.len()];
        let check_results =
            bank.check_transactions(txs, &pre_results, MAX_PROCESSING_AGE, &mut error_counters);
        // If checks passed, verify pre-compiles and continue processing on success.
        let check_results: Vec<_> = txs
            .iter()
            .zip(check_results)
            .map(|(tx, result)| match result {
                Ok(_) => tx.verify_precompiles(&bank.feature_set),
                Err(err) => Err(err),
            })
            .collect();
        let mut output = self.process_and_record_transactions_with_pre_results(
            bank,
            txs,
            chunk_offset,
            check_results.into_iter(),
        );

        // Accumulate error counters from the initial checks into final results
        output
            .execute_and_commit_transactions_output
            .error_counters
            .accumulate(&error_counters);
        output
    }

    pub fn process_and_record_aged_transactions(
        &self,
        bank: &Arc<Bank>,
        txs: &[SanitizedTransaction],
        max_slot_ages: &[Slot],
    ) -> ProcessTransactionBatchOutput {
        // Verify pre-compiles.
        // Need to filter out transactions since they were sanitized earlier.
        // This means that the transaction may cross and epoch boundary (not allowed),
        //  or account lookup tables may have been closed.
        let pre_results = txs.iter().zip(max_slot_ages).map(|(tx, max_slot_age)| {
            if *max_slot_age < bank.slot() {
                // Pre-compiles are verified here.
                // Attempt re-sanitization after epoch-cross.
                // Re-sanitized transaction should be equal to the original transaction,
                // but whether it will pass sanitization needs to be checked.
                let resanitized_tx =
                    bank.fully_verify_transaction(tx.to_versioned_transaction())?;
                if resanitized_tx != *tx {
                    // Sanitization before/after epoch give different transaction data - do not execute.
                    return Err(TransactionError::ResanitizationNeeded);
                }
            } else {
                // Verify pre-compiles.
                tx.verify_precompiles(&bank.feature_set)?;
                // Any transaction executed between sanitization time and now may have closed the lookup table(s).
                // Above re-sanitization already loads addresses, so don't need to re-check in that case.
                let lookup_tables = tx.message().message_address_table_lookups();
                if !lookup_tables.is_empty() {
                    bank.load_addresses(lookup_tables)?;
                }
            }
            Ok(())
        });
        self.process_and_record_transactions_with_pre_results(bank, txs, 0, pre_results)
    }

    fn process_and_record_transactions_with_pre_results(
        &self,
        bank: &Arc<Bank>,
        txs: &[SanitizedTransaction],
        chunk_offset: usize,
        pre_results: impl Iterator<Item = Result<(), TransactionError>>,
    ) -> ProcessTransactionBatchOutput {
        let (
            (transaction_qos_cost_results, cost_model_throttled_transactions_count),
            cost_model_us,
        ) = measure_us!(self.qos_service.select_and_accumulate_transaction_costs(
            bank,
            txs,
            pre_results
        ));

        // Only lock accounts for those transactions are selected for the block;
        // Once accounts are locked, other threads cannot encode transactions that will modify the
        // same account state
        let (batch, lock_us) = measure_us!(bank.prepare_sanitized_batch_with_results(
            txs,
            transaction_qos_cost_results.iter().map(|r| match r {
                Ok(_cost) => Ok(()),
                Err(err) => Err(err.clone()),
            })
        ));

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

        // Costs of all transactions are added to the cost_tracker before processing.
        // To ensure accurate tracking of compute units, transactions that ultimately
        // were not included in the block should have their cost removed, the rest
        // should update with their actually consumed units.
        QosService::remove_or_update_costs(
            transaction_qos_cost_results.iter(),
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
        self.qos_service.report_metrics(bank.slot());

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
        let transaction_status_sender_enabled = self.committer.transaction_status_sender_enabled();
        let mut execute_and_commit_timings = LeaderExecuteAndCommitTimings::default();

        let mut pre_balance_info = PreBalanceInfo::default();
        let (_, collect_balances_us) = measure_us!({
            // If the extra meta-data services are enabled for RPC, collect the
            // pre-balances for native and token programs.
            if transaction_status_sender_enabled {
                pre_balance_info.native = bank.collect_balances(batch);
                pre_balance_info.token =
                    collect_token_balances(bank, batch, &mut pre_balance_info.mint_decimals)
            }
        });
        execute_and_commit_timings.collect_balances_us = collect_balances_us;

        let min_max = batch
            .sanitized_transactions()
            .iter()
            .filter_map(|transaction| {
                let round_compute_unit_price_enabled = false; // TODO get from working_bank.feature_set
                transaction
                    .get_compute_budget_details(round_compute_unit_price_enabled)
                    .map(|details| details.compute_unit_price)
            })
            .minmax();
        let (min_prioritization_fees, max_prioritization_fees) =
            min_max.into_option().unwrap_or_default();

        let (load_and_execute_transactions_output, load_execute_us) = measure_us!(bank
            .load_and_execute_transactions(
                batch,
                MAX_PROCESSING_AGE,
                &mut execute_and_commit_timings.execute_timings,
                TransactionProcessingConfig {
                    account_overrides: None,
                    check_program_modification_slot: bank.check_program_modification_slot(),
                    compute_budget: bank.compute_budget(),
                    log_messages_bytes_limit: self.log_messages_bytes_limit,
                    limit_to_load_programs: true,
                    recording_config: ExecutionRecordingConfig::new_single_setting(
                        transaction_status_sender_enabled
                    ),
                    transaction_account_lock_limit: Some(bank.get_transaction_account_lock_limit()),
                }
            ));
        execute_and_commit_timings.load_execute_us = load_execute_us;

        let LoadAndExecuteTransactionsOutput {
            mut loaded_transactions,
            execution_results,
            mut retryable_transaction_indexes,
            executed_transactions_count,
            executed_non_vote_transactions_count,
            executed_with_successful_result_count,
            signature_count,
            error_counters,
            ..
        } = load_and_execute_transactions_output;

        let transactions_attempted_execution_count = execution_results.len();
        let (executed_transactions, execution_results_to_transactions_us) =
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
                .collect_vec());

        let (freeze_lock, freeze_lock_us) = measure_us!(bank.freeze_lock());
        execute_and_commit_timings.freeze_lock_us = freeze_lock_us;

        // In order to avoid a race condition, leaders must get the last
        // blockhash *before* recording transactions because recording
        // transactions will only succeed if the block max tick height hasn't
        // been reached yet. If they get the last blockhash *after* recording
        // transactions, the block max tick height could have already been
        // reached and the blockhash queue could have already been updated with
        // a new blockhash.
        let ((last_blockhash, lamports_per_signature), last_blockhash_us) =
            measure_us!(bank.last_blockhash_and_lamports_per_signature());
        execute_and_commit_timings.last_blockhash_us = last_blockhash_us;

        let (record_transactions_summary, record_us) = measure_us!(self
            .transaction_recorder
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
                min_prioritization_fees,
                max_prioritization_fees,
            };
        }

        let (commit_time_us, commit_transaction_statuses) = if executed_transactions_count != 0 {
            self.committer.commit_transactions(
                batch,
                &mut loaded_transactions,
                execution_results,
                last_blockhash,
                lamports_per_signature,
                starting_transaction_index,
                bank,
                &mut pre_balance_info,
                &mut execute_and_commit_timings,
                signature_count,
                executed_transactions_count,
                executed_non_vote_transactions_count,
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
            batch.sanitized_transactions().len(),
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
            min_prioritization_fees,
            max_prioritization_fees,
        }
    }

    pub fn check_fee_payer_unlocked(
        bank: &Bank,
        message: &SanitizedMessage,
        error_counters: &mut TransactionErrorMetrics,
    ) -> Result<(), TransactionError> {
        let fee_payer = message.fee_payer();
        let budget_limits =
            process_compute_budget_instructions(message.program_instructions_iter())?.into();
        let fee = bank.fee_structure().calculate_fee(
            message,
            bank.get_lamports_per_signature(),
            &budget_limits,
            bank.feature_set.is_active(
                &feature_set::include_loaded_accounts_data_size_in_fee_calculation::id(),
            ),
            bank.feature_set
                .is_active(&feature_set::remove_rounding_in_fee_calculation::id()),
        );
        let (mut fee_payer_account, _slot) = bank
            .rc
            .accounts
            .accounts_db
            .load_with_fixed_root(&bank.ancestors, fee_payer)
            .ok_or(TransactionError::AccountNotFound)?;

        validate_fee_payer(
            fee_payer,
            &mut fee_payer_account,
            0,
            error_counters,
            bank.rent_collector(),
            fee,
        )
    }

    fn accumulate_execute_units_and_time(execute_timings: &ExecuteTimings) -> (u64, u64) {
        execute_timings.details.per_program_timings.values().fold(
            (0, 0),
            |(units, times), program_timings| {
                (
                    units
                        .saturating_add(program_timings.accumulated_units)
                        .saturating_add(program_timings.total_errored_units),
                    times.saturating_add(program_timings.accumulated_us),
                )
            },
        )
    }

    /// This function filters pending packets that are still valid
    /// # Arguments
    /// * `transactions` - a batch of transactions deserialized from packets
    /// * `pending_indexes` - identifies which indexes in the `transactions` list are still pending
    fn filter_pending_packets_from_pending_txs(
        bank: &Bank,
        transactions: &[SanitizedTransaction],
        pending_indexes: &[usize],
    ) -> Vec<usize> {
        let filter =
            Self::prepare_filter_for_pending_transactions(transactions.len(), pending_indexes);

        let results = bank.check_transactions_with_forwarding_delay(
            transactions,
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
            .filter_map(|(index, res)| res.as_ref().ok().map(|_| index))
            .collect_vec()
    }
}
