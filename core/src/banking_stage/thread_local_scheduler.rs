use {
    super::{
        consume_executor::ConsumeExecutor,
        decision_maker::{BufferedPacketsDecision, DecisionMaker},
        forward_executor::ForwardExecutor,
        packet_receiver::PacketReceiver,
        scheduler_error::SchedulerError,
        BankingStageStats, SLOT_BOUNDARY_CHECK_PERIOD,
    },
    crate::{
        forward_packet_batches_by_accounts::ForwardPacketBatchesByAccounts,
        immutable_deserialized_packet::ImmutableDeserializedPacket,
        leader_slot_banking_stage_metrics::{LeaderSlotMetricsTracker, ProcessTransactionsSummary},
        tracer_packet_stats::TracerPacketStats,
        unprocessed_transaction_storage::{ConsumeScannerPayload, UnprocessedTransactionStorage},
    },
    crossbeam_channel::RecvTimeoutError,
    solana_measure::{measure, measure::Measure, measure_us},
    solana_poh::poh_recorder::BankStart,
    solana_runtime::bank_forks::BankForks,
    solana_sdk::timing::timestamp,
    std::{
        sync::{atomic::Ordering, Arc, RwLock},
        time::Instant,
    },
};

/// Scheduler that lives in the same thread as executors. Handle is equivalent
/// to the scheduler itself.
pub struct ThreadLocalScheduler {
    decision_maker: DecisionMaker,
    unprocessed_transaction_storage: UnprocessedTransactionStorage,
    bank_forks: Arc<RwLock<BankForks>>,
    packet_receiver: PacketReceiver,
    last_metrics_update: Instant,
    banking_stage_stats: BankingStageStats,
}

impl ThreadLocalScheduler {
    pub fn new(
        id: u32,
        decision_maker: DecisionMaker,
        unprocessed_transaction_storage: UnprocessedTransactionStorage,
        bank_forks: Arc<RwLock<BankForks>>,
        packet_receiver: PacketReceiver,
    ) -> Self {
        Self {
            decision_maker,
            unprocessed_transaction_storage,
            bank_forks,
            packet_receiver,
            last_metrics_update: Instant::now(),
            banking_stage_stats: BankingStageStats::new(id),
        }
    }

    pub fn tick(&mut self) -> Result<(), SchedulerError> {
        let result = if matches!(
            self.packet_receiver
                .do_packet_receiving_and_buffering(&mut self.unprocessed_transaction_storage,),
            Err(RecvTimeoutError::Disconnected)
        ) {
            Err(SchedulerError::PacketReceiverDisconnected)
        } else {
            Ok(())
        };

        self.banking_stage_stats.report(1000);

        result
    }

    pub fn do_scheduled_work(
        &mut self,
        consume_executor: &ConsumeExecutor,
        forward_executor: &ForwardExecutor,
        tracer_packet_stats: &mut TracerPacketStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) -> Result<(), SchedulerError> {
        if !self.unprocessed_transaction_storage.is_empty()
            || self.last_metrics_update.elapsed() >= SLOT_BOUNDARY_CHECK_PERIOD
        {
            let (_, process_buffered_packets_us) = measure_us!(self.process_buffered_packets(
                consume_executor,
                forward_executor,
                tracer_packet_stats,
                slot_metrics_tracker,
            ));
            slot_metrics_tracker.increment_process_buffered_packets_us(process_buffered_packets_us);
            self.last_metrics_update = Instant::now();
        }

        Ok(())
    }

    fn process_buffered_packets(
        &mut self,
        consume_executor: &ConsumeExecutor,
        forward_executor: &ForwardExecutor,
        tracer_packet_stats: &mut TracerPacketStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) {
        if self.unprocessed_transaction_storage.should_not_process() {
            return;
        }

        let (decision, make_decision_us) =
            measure_us!(self.decision_maker.make_consume_or_forward_decision());
        slot_metrics_tracker.increment_make_decision_us(make_decision_us);

        let leader_slot = match &decision {
            BufferedPacketsDecision::Consume(bank_start) => Some(bank_start.working_bank.slot()),
            _ => None,
        };
        self.packet_receiver.check_leader_slot_boundary(leader_slot);

        match decision {
            BufferedPacketsDecision::Consume(bank_start) => {
                // Take metrics action before consume packets (potentially resetting the
                // slot metrics tracker to the next slot) so that we don't count the
                // packet processing metrics from the next slot towards the metrics
                // of the previous slot
                slot_metrics_tracker.apply_working_bank(Some(&bank_start));
                let (_, consume_buffered_packets_us) = measure_us!(Self::consume_buffered_packets(
                    consume_executor,
                    &bank_start,
                    &mut self.unprocessed_transaction_storage,
                    None::<Box<dyn Fn()>>,
                    &self.banking_stage_stats,
                    slot_metrics_tracker
                ));
                slot_metrics_tracker
                    .increment_consume_buffered_packets_us(consume_buffered_packets_us);
            }
            BufferedPacketsDecision::Forward => {
                let (_, forward_us) = measure_us!(Self::handle_forwarding(
                    forward_executor,
                    &mut self.unprocessed_transaction_storage,
                    &self.bank_forks,
                    false,
                    slot_metrics_tracker,
                    &self.banking_stage_stats,
                    tracer_packet_stats,
                ));
                slot_metrics_tracker.increment_forward_us(forward_us);
                // Take metrics action after forwarding packets to include forwarded
                // metrics into current slot
                slot_metrics_tracker.apply_working_bank(None);
            }
            BufferedPacketsDecision::ForwardAndHold => {
                let (_, forward_and_hold_us) = measure_us!(Self::handle_forwarding(
                    forward_executor,
                    &mut self.unprocessed_transaction_storage,
                    &self.bank_forks,
                    true,
                    slot_metrics_tracker,
                    &self.banking_stage_stats,
                    tracer_packet_stats,
                ));
                slot_metrics_tracker.increment_forward_and_hold_us(forward_and_hold_us);
                // Take metrics action after forwarding packets
                slot_metrics_tracker.apply_working_bank(None);
            }
            _ => (),
        }
    }

    pub fn consume_buffered_packets(
        consume_executor: &ConsumeExecutor,
        bank_start: &BankStart,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        test_fn: Option<impl Fn()>,
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
                Self::do_process_packets(
                    consume_executor,
                    bank_start,
                    payload,
                    banking_stage_stats,
                    &mut consumed_buffered_packets_count,
                    &mut rebuffered_packet_count,
                    &test_fn,
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
        consume_executor: &ConsumeExecutor,
        bank_start: &BankStart,
        payload: &mut ConsumeScannerPayload,
        banking_stage_stats: &BankingStageStats,
        consumed_buffered_packets_count: &mut usize,
        rebuffered_packet_count: &mut usize,
        test_fn: &Option<impl Fn()>,
        packets_to_process: &Vec<Arc<ImmutableDeserializedPacket>>,
    ) -> Option<Vec<usize>> {
        if payload.reached_end_of_slot {
            return None;
        }

        let packets_to_process_len = packets_to_process.len();
        let (process_transactions_summary, process_packets_transactions_us) =
            measure_us!(consume_executor.process_packets_transactions(
                bank_start,
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
        if let Some(test_fn) = test_fn {
            test_fn();
        }

        payload
            .slot_metrics_tracker
            .increment_retryable_packets_count(retryable_transaction_indexes.len() as u64);

        Some(retryable_transaction_indexes)
    }

    pub fn handle_forwarding(
        forward_executor: &ForwardExecutor,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        bank_forks: &RwLock<BankForks>,
        hold: bool,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        banking_stage_stats: &BankingStageStats,
        tracer_packet_stats: &mut TracerPacketStats,
    ) {
        let forward_option = unprocessed_transaction_storage.forward_option();

        // get current root bank from bank_forks, use it to sanitize transaction and
        // load all accounts from address loader;
        let current_bank = bank_forks.read().unwrap().root_bank();

        let mut forward_packet_batches_by_accounts =
            ForwardPacketBatchesByAccounts::new_with_default_batch_limits();

        // sanitize and filter packets that are no longer valid (could be too old, a duplicate of something
        // already processed), then add to forwarding buffer.
        let filter_forwarding_result = unprocessed_transaction_storage
            .filter_forwardable_packets_and_add_batches(
                current_bank,
                &mut forward_packet_batches_by_accounts,
            );
        slot_metrics_tracker.increment_transactions_from_packets_us(
            filter_forwarding_result.total_packet_conversion_us,
        );
        banking_stage_stats.packet_conversion_elapsed.fetch_add(
            filter_forwarding_result.total_packet_conversion_us,
            Ordering::Relaxed,
        );
        banking_stage_stats
            .filter_pending_packets_elapsed
            .fetch_add(
                filter_forwarding_result.total_filter_packets_us,
                Ordering::Relaxed,
            );

        forward_packet_batches_by_accounts
            .iter_batches()
            .filter(|&batch| !batch.is_empty())
            .for_each(|forward_batch| {
                slot_metrics_tracker.increment_forwardable_batches_count(1);

                let batched_forwardable_packets_count = forward_batch.len();
                let (_forward_result, sucessful_forwarded_packets_count, leader_pubkey) =
                    forward_executor.forward_buffered_packets(
                        &forward_option,
                        forward_batch.get_forwardable_packets(),
                        banking_stage_stats,
                    );

                if let Some(leader_pubkey) = leader_pubkey {
                    tracer_packet_stats.increment_total_forwardable_tracer_packets(
                        filter_forwarding_result.total_forwardable_tracer_packets,
                        leader_pubkey,
                    );
                }
                let failed_forwarded_packets_count = batched_forwardable_packets_count
                    .saturating_sub(sucessful_forwarded_packets_count);

                if failed_forwarded_packets_count > 0 {
                    slot_metrics_tracker.increment_failed_forwarded_packets_count(
                        failed_forwarded_packets_count as u64,
                    );
                    slot_metrics_tracker.increment_packet_batch_forward_failure_count(1);
                }

                if sucessful_forwarded_packets_count > 0 {
                    slot_metrics_tracker.increment_successful_forwarded_packets_count(
                        sucessful_forwarded_packets_count as u64,
                    );
                }
            });

        if !hold {
            slot_metrics_tracker.increment_cleared_from_buffer_after_forward_count(
                filter_forwarding_result.total_forwardable_packets as u64,
            );
            tracer_packet_stats.increment_total_cleared_from_buffer_after_forward(
                filter_forwarding_result.total_tracer_packets_in_buffer,
            );
            unprocessed_transaction_storage.clear_forwarded_packets();
        }
    }
}
