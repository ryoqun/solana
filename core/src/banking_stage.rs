//! The `banking_stage` processes Transaction messages. It is intended to be used
//! to construct a software pipeline. The stage uses all available CPU cores and
//! can do its processing in parallel with signature verification on the GPU.

use {
    self::{
        committer::Committer,
        consumer::Consumer,
        decision_maker::{BufferedPacketsDecision, DecisionMaker},
        forwarder::Forwarder,
        latest_unprocessed_votes::{LatestUnprocessedVotes, VoteSource},
        leader_slot_metrics::LeaderSlotMetricsTracker,
        packet_receiver::PacketReceiver,
        qos_service::QosService,
        unprocessed_packet_batches::*,
        unprocessed_transaction_storage::{ThreadType, UnprocessedTransactionStorage},
    },
    crate::{
        banking_stage::{
            consume_worker::ConsumeWorker,
            packet_deserializer::PacketDeserializer,
            transaction_scheduler::{
                prio_graph_scheduler::PrioGraphScheduler,
                scheduler_controller::SchedulerController, scheduler_error::SchedulerError,
            },
        },
        banking_trace::BankingPacketReceiver,
        tracer_packet_stats::TracerPacketStats,
        validator::BlockProductionMethod,
    },
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender},
    histogram::Histogram,
    solana_client::connection_cache::ConnectionCache,
    solana_gossip::cluster_info::ClusterInfo,
    solana_ledger::blockstore_processor::TransactionStatusSender,
    solana_measure::{measure, measure_us},
    solana_perf::{data_budget::DataBudget, packet::PACKETS_PER_BATCH},
    solana_poh::poh_recorder::{PohRecorder, TransactionRecorder},
    solana_runtime::{
        bank_forks::BankForks, prioritization_fee_cache::PrioritizationFeeCache,
        vote_sender_types::ReplayVoteSender,
    },
    solana_sdk::timing::AtomicInterval,
    std::{
        cmp, env,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

// Below modules are pub to allow use by banking_stage bench
pub mod committer;
pub mod consumer;
pub mod forwarder;
pub mod leader_slot_metrics;
pub mod qos_service;
pub mod unprocessed_packet_batches;
pub mod unprocessed_transaction_storage;

mod consume_worker;
mod decision_maker;
mod forward_packet_batches_by_accounts;
mod forward_worker;
mod immutable_deserialized_packet;
mod latest_unprocessed_votes;
mod leader_slot_timing_metrics;
mod multi_iterator_scanner;
mod packet_deserializer;
mod packet_filter;
mod packet_receiver;
mod read_write_account_set;
#[allow(dead_code)]
mod scheduler_messages;
mod transaction_scheduler;

// Fixed thread size seems to be fastest on GCP setup
pub const NUM_THREADS: u32 = 6;

const TOTAL_BUFFERED_PACKETS: usize = 700_000;

const NUM_VOTE_PROCESSING_THREADS: u32 = 2;
const MIN_THREADS_BANKING: u32 = 1;
const MIN_TOTAL_THREADS: u32 = NUM_VOTE_PROCESSING_THREADS + MIN_THREADS_BANKING;

const SLOT_BOUNDARY_CHECK_PERIOD: Duration = Duration::from_millis(10);

#[derive(Debug, Default)]
pub struct BankingStageStats {
    last_report: AtomicInterval,
    id: String,
    receive_and_buffer_packets_count: AtomicUsize,
    dropped_packets_count: AtomicUsize,
    pub(crate) dropped_duplicated_packets_count: AtomicUsize,
    dropped_forward_packets_count: AtomicUsize,
    newly_buffered_packets_count: AtomicUsize,
    newly_buffered_forwarded_packets_count: AtomicUsize,
    current_buffered_packets_count: AtomicUsize,
    rebuffered_packets_count: AtomicUsize,
    consumed_buffered_packets_count: AtomicUsize,
    forwarded_transaction_count: AtomicUsize,
    forwarded_vote_count: AtomicUsize,
    batch_packet_indexes_len: Histogram,

    // Timing
    consume_buffered_packets_elapsed: AtomicU64,
    receive_and_buffer_packets_elapsed: AtomicU64,
    filter_pending_packets_elapsed: AtomicU64,
    pub(crate) packet_conversion_elapsed: AtomicU64,
    transaction_processing_elapsed: AtomicU64,
}

impl BankingStageStats {
    pub fn new(id: u32) -> Self {
        BankingStageStats {
            id: id.to_string(),
            batch_packet_indexes_len: Histogram::configure()
                .max_value(PACKETS_PER_BATCH as u64)
                .build()
                .unwrap(),
            ..BankingStageStats::default()
        }
    }

    fn is_empty(&self) -> bool {
        0 == self
            .receive_and_buffer_packets_count
            .load(Ordering::Relaxed) as u64
            + self.dropped_packets_count.load(Ordering::Relaxed) as u64
            + self
                .dropped_duplicated_packets_count
                .load(Ordering::Relaxed) as u64
            + self.dropped_forward_packets_count.load(Ordering::Relaxed) as u64
            + self.newly_buffered_packets_count.load(Ordering::Relaxed) as u64
            + self.current_buffered_packets_count.load(Ordering::Relaxed) as u64
            + self.rebuffered_packets_count.load(Ordering::Relaxed) as u64
            + self.consumed_buffered_packets_count.load(Ordering::Relaxed) as u64
            + self
                .consume_buffered_packets_elapsed
                .load(Ordering::Relaxed)
            + self
                .receive_and_buffer_packets_elapsed
                .load(Ordering::Relaxed)
            + self.filter_pending_packets_elapsed.load(Ordering::Relaxed)
            + self.packet_conversion_elapsed.load(Ordering::Relaxed)
            + self.transaction_processing_elapsed.load(Ordering::Relaxed)
            + self.forwarded_transaction_count.load(Ordering::Relaxed) as u64
            + self.forwarded_vote_count.load(Ordering::Relaxed) as u64
            + self.batch_packet_indexes_len.entries()
    }

    fn report(&mut self, report_interval_ms: u64) {
        // skip reporting metrics if stats is empty
        if self.is_empty() {
            return;
        }
        if self.last_report.should_update(report_interval_ms) {
            datapoint_info!(
                "banking_stage-loop-stats",
                "id" => self.id,
                (
                    "receive_and_buffer_packets_count",
                    self.receive_and_buffer_packets_count
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "dropped_packets_count",
                    self.dropped_packets_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "dropped_duplicated_packets_count",
                    self.dropped_duplicated_packets_count
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "dropped_forward_packets_count",
                    self.dropped_forward_packets_count
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "newly_buffered_packets_count",
                    self.newly_buffered_packets_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "newly_buffered_forwarded_packets_count",
                    self.newly_buffered_forwarded_packets_count
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "current_buffered_packets_count",
                    self.current_buffered_packets_count
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "rebuffered_packets_count",
                    self.rebuffered_packets_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "consumed_buffered_packets_count",
                    self.consumed_buffered_packets_count
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "forwarded_transaction_count",
                    self.forwarded_transaction_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "forwarded_vote_count",
                    self.forwarded_vote_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "consume_buffered_packets_elapsed",
                    self.consume_buffered_packets_elapsed
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "receive_and_buffer_packets_elapsed",
                    self.receive_and_buffer_packets_elapsed
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "filter_pending_packets_elapsed",
                    self.filter_pending_packets_elapsed
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "packet_conversion_elapsed",
                    self.packet_conversion_elapsed.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "transaction_processing_elapsed",
                    self.transaction_processing_elapsed
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "packet_batch_indices_len_min",
                    self.batch_packet_indexes_len.minimum().unwrap_or(0),
                    i64
                ),
                (
                    "packet_batch_indices_len_max",
                    self.batch_packet_indexes_len.maximum().unwrap_or(0),
                    i64
                ),
                (
                    "packet_batch_indices_len_mean",
                    self.batch_packet_indexes_len.mean().unwrap_or(0),
                    i64
                ),
                (
                    "packet_batch_indices_len_90pct",
                    self.batch_packet_indexes_len.percentile(90.0).unwrap_or(0),
                    i64
                )
            );
            self.batch_packet_indexes_len.clear();
        }
    }
}

#[derive(Debug, Default)]
pub struct BatchedTransactionDetails {
    pub costs: BatchedTransactionCostDetails,
    pub errors: BatchedTransactionErrorDetails,
}

#[derive(Debug, Default)]
pub struct BatchedTransactionCostDetails {
    pub batched_signature_cost: u64,
    pub batched_write_lock_cost: u64,
    pub batched_data_bytes_cost: u64,
    pub batched_loaded_accounts_data_size_cost: u64,
    pub batched_programs_execute_cost: u64,
}

#[derive(Debug, Default)]
pub struct BatchedTransactionErrorDetails {
    pub batched_retried_txs_per_block_limit_count: u64,
    pub batched_retried_txs_per_vote_limit_count: u64,
    pub batched_retried_txs_per_account_limit_count: u64,
    pub batched_retried_txs_per_account_data_block_limit_count: u64,
    pub batched_dropped_txs_per_account_data_total_limit_count: u64,
}

/// Stores the stage's thread handle and output receiver.
pub struct BankingStage {
    bank_thread_hdls: Vec<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
pub enum ForwardOption {
    NotForward,
    ForwardTpuVote,
    ForwardTransaction,
}

#[derive(Debug, Default)]
pub struct FilterForwardingResults {
    pub(crate) total_forwardable_packets: usize,
    pub(crate) total_tracer_packets_in_buffer: usize,
    pub(crate) total_forwardable_tracer_packets: usize,
    pub(crate) total_dropped_packets: usize,
    pub(crate) total_packet_conversion_us: u64,
    pub(crate) total_filter_packets_us: u64,
}

impl BankingStage {
    /// Create the stage using `bank`. Exit when `verified_receiver` is dropped.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_production_method: BlockProductionMethod,
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        non_vote_receiver: BankingPacketReceiver,
        tpu_vote_receiver: BankingPacketReceiver,
        gossip_vote_receiver: BankingPacketReceiver,
        transaction_status_sender: Option<TransactionStatusSender>,
        replay_vote_sender: ReplayVoteSender,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: Arc<RwLock<BankForks>>,
        prioritization_fee_cache: &Arc<PrioritizationFeeCache>,
    ) -> Self {
        Self::new_num_threads(
            block_production_method,
            cluster_info,
            poh_recorder,
            non_vote_receiver,
            tpu_vote_receiver,
            gossip_vote_receiver,
            Self::num_threads(),
            transaction_status_sender,
            replay_vote_sender,
            log_messages_bytes_limit,
            connection_cache,
            bank_forks,
            prioritization_fee_cache,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_num_threads(
        block_production_method: BlockProductionMethod,
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        non_vote_receiver: BankingPacketReceiver,
        tpu_vote_receiver: BankingPacketReceiver,
        gossip_vote_receiver: BankingPacketReceiver,
        num_threads: u32,
        transaction_status_sender: Option<TransactionStatusSender>,
        replay_vote_sender: ReplayVoteSender,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: Arc<RwLock<BankForks>>,
        prioritization_fee_cache: &Arc<PrioritizationFeeCache>,
    ) -> Self {
        use BlockProductionMethod::*;

        match block_production_method {
            ThreadLocalMultiIterator => Self::new_thread_local_multi_iterator(
                cluster_info,
                poh_recorder,
                non_vote_receiver,
                tpu_vote_receiver,
                gossip_vote_receiver,
                num_threads,
                transaction_status_sender,
                replay_vote_sender,
                log_messages_bytes_limit,
                connection_cache,
                bank_forks,
                prioritization_fee_cache,
            ),
            CentralScheduler => Self::new_central_scheduler(
                cluster_info,
                poh_recorder,
                non_vote_receiver,
                tpu_vote_receiver,
                gossip_vote_receiver,
                num_threads,
                transaction_status_sender,
                replay_vote_sender,
                log_messages_bytes_limit,
                connection_cache,
                bank_forks,
                prioritization_fee_cache,
            ),
            UnifiedScheduler => Self::new_unified_scheduler(
                cluster_info,
                poh_recorder,
                non_vote_receiver,
                tpu_vote_receiver,
                gossip_vote_receiver,
                bank_forks,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_thread_local_multi_iterator(
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        non_vote_receiver: BankingPacketReceiver,
        tpu_vote_receiver: BankingPacketReceiver,
        gossip_vote_receiver: BankingPacketReceiver,
        num_threads: u32,
        transaction_status_sender: Option<TransactionStatusSender>,
        replay_vote_sender: ReplayVoteSender,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: Arc<RwLock<BankForks>>,
        prioritization_fee_cache: &Arc<PrioritizationFeeCache>,
    ) -> Self {
        assert!(num_threads >= MIN_TOTAL_THREADS);
        // Single thread to generate entries from many banks.
        // This thread talks to poh_service and broadcasts the entries once they have been recorded.
        // Once an entry has been recorded, its blockhash is registered with the bank.
        let data_budget = Arc::new(DataBudget::default());
        let batch_limit =
            TOTAL_BUFFERED_PACKETS / ((num_threads - NUM_VOTE_PROCESSING_THREADS) as usize);
        // Keeps track of extraneous vote transactions for the vote threads
        let latest_unprocessed_votes = Arc::new(LatestUnprocessedVotes::new());

        let decision_maker = DecisionMaker::new(cluster_info.id(), poh_recorder.clone());
        let committer = Committer::new(
            transaction_status_sender.clone(),
            replay_vote_sender.clone(),
            prioritization_fee_cache.clone(),
        );
        let transaction_recorder = poh_recorder.read().unwrap().new_recorder();

        // Many banks that process transactions in parallel.
        let bank_thread_hdls: Vec<JoinHandle<()>> = (0..num_threads)
            .map(|id| {
                let (packet_receiver, unprocessed_transaction_storage) = match id {
                    0 => (
                        gossip_vote_receiver.clone(),
                        UnprocessedTransactionStorage::new_vote_storage(
                            latest_unprocessed_votes.clone(),
                            VoteSource::Gossip,
                        ),
                    ),
                    1 => (
                        tpu_vote_receiver.clone(),
                        UnprocessedTransactionStorage::new_vote_storage(
                            latest_unprocessed_votes.clone(),
                            VoteSource::Tpu,
                        ),
                    ),
                    _ => (
                        non_vote_receiver.clone(),
                        UnprocessedTransactionStorage::new_transaction_storage(
                            UnprocessedPacketBatches::with_capacity(batch_limit),
                            ThreadType::Transactions,
                        ),
                    ),
                };

                let forwarder = Forwarder::new(
                    poh_recorder.clone(),
                    bank_forks.clone(),
                    cluster_info.clone(),
                    connection_cache.clone(),
                    data_budget.clone(),
                );

                Self::spawn_thread_local_multi_iterator_thread(
                    id,
                    packet_receiver,
                    bank_forks.clone(),
                    decision_maker.clone(),
                    committer.clone(),
                    transaction_recorder.clone(),
                    log_messages_bytes_limit,
                    forwarder,
                    unprocessed_transaction_storage,
                )
            })
            .collect();
        Self { bank_thread_hdls }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_central_scheduler(
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        non_vote_receiver: BankingPacketReceiver,
        tpu_vote_receiver: BankingPacketReceiver,
        gossip_vote_receiver: BankingPacketReceiver,
        num_threads: u32,
        transaction_status_sender: Option<TransactionStatusSender>,
        replay_vote_sender: ReplayVoteSender,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: Arc<RwLock<BankForks>>,
        prioritization_fee_cache: &Arc<PrioritizationFeeCache>,
    ) -> Self {
        assert!(num_threads >= MIN_TOTAL_THREADS);
        // Single thread to generate entries from many banks.
        // This thread talks to poh_service and broadcasts the entries once they have been recorded.
        // Once an entry has been recorded, its blockhash is registered with the bank.
        let data_budget = Arc::new(DataBudget::default());
        // Keeps track of extraneous vote transactions for the vote threads
        let latest_unprocessed_votes = Arc::new(LatestUnprocessedVotes::new());

        let decision_maker = DecisionMaker::new(cluster_info.id(), poh_recorder.clone());
        let committer = Committer::new(
            transaction_status_sender.clone(),
            replay_vote_sender.clone(),
            prioritization_fee_cache.clone(),
        );
        let transaction_recorder = poh_recorder.read().unwrap().new_recorder();

        // + 1 for the central scheduler thread
        let mut bank_thread_hdls = Vec::with_capacity(num_threads as usize + 1);

        // Spawn legacy voting threads first: 1 gossip, 1 tpu
        for (id, packet_receiver, vote_source) in [
            (0, gossip_vote_receiver, VoteSource::Gossip),
            (1, tpu_vote_receiver, VoteSource::Tpu),
        ] {
            bank_thread_hdls.push(Self::spawn_thread_local_multi_iterator_thread(
                id,
                packet_receiver,
                bank_forks.clone(),
                decision_maker.clone(),
                committer.clone(),
                transaction_recorder.clone(),
                log_messages_bytes_limit,
                Forwarder::new(
                    poh_recorder.clone(),
                    bank_forks.clone(),
                    cluster_info.clone(),
                    connection_cache.clone(),
                    data_budget.clone(),
                ),
                UnprocessedTransactionStorage::new_vote_storage(
                    latest_unprocessed_votes.clone(),
                    vote_source,
                ),
            ));
        }

        // Create channels for communication between scheduler and workers
        let num_workers = (num_threads).saturating_sub(NUM_VOTE_PROCESSING_THREADS);
        let (work_senders, work_receivers): (Vec<Sender<_>>, Vec<Receiver<_>>) =
            (0..num_workers).map(|_| unbounded()).unzip();
        let (finished_work_sender, finished_work_receiver) = unbounded();

        // Spawn the worker threads
        let mut worker_metrics = Vec::with_capacity(num_workers as usize);
        for (index, work_receiver) in work_receivers.into_iter().enumerate() {
            let id = (index as u32).saturating_add(NUM_VOTE_PROCESSING_THREADS);
            let consume_worker = ConsumeWorker::new(
                id,
                work_receiver,
                Consumer::new(
                    committer.clone(),
                    poh_recorder.read().unwrap().new_recorder(),
                    QosService::new(id),
                    log_messages_bytes_limit,
                ),
                finished_work_sender.clone(),
                poh_recorder.read().unwrap().new_leader_bank_notifier(),
            );

            worker_metrics.push(consume_worker.metrics_handle());
            bank_thread_hdls.push(
                Builder::new()
                    .name(format!("solCoWorker{id:02}"))
                    .spawn(move || {
                        let _ = consume_worker.run();
                    })
                    .unwrap(),
            )
        }

        let forwarder = Forwarder::new(
            poh_recorder.clone(),
            bank_forks.clone(),
            cluster_info.clone(),
            connection_cache.clone(),
            data_budget.clone(),
        );

        // Spawn the central scheduler thread
        bank_thread_hdls.push({
            let packet_deserializer =
                PacketDeserializer::new(non_vote_receiver, bank_forks.clone());
            let scheduler = PrioGraphScheduler::new(work_senders, finished_work_receiver);
            let scheduler_controller = SchedulerController::new(
                decision_maker.clone(),
                packet_deserializer,
                bank_forks,
                scheduler,
                worker_metrics,
                forwarder,
            );
            Builder::new()
                .name("solBnkTxSched".to_string())
                .spawn(move || match scheduler_controller.run() {
                    Ok(_) => {}
                    Err(SchedulerError::DisconnectedRecvChannel(_)) => {}
                    Err(SchedulerError::DisconnectedSendChannel(_)) => {
                        warn!("Unexpected worker disconnect from scheduler")
                    }
                })
                .unwrap()
        });

        Self { bank_thread_hdls }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_unified_scheduler(
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        non_vote_receiver: BankingPacketReceiver,
        tpu_vote_receiver: BankingPacketReceiver,
        gossip_vote_receiver: BankingPacketReceiver,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> Self {
        struct MonotonicIdGenerator {
            next_task_id: AtomicUsize,
        }

        impl MonotonicIdGenerator {
            fn new() -> Arc<Self> {
                Arc::new(Self{next_task_id: Default::default()})
            }

            fn bulk_assign_task_ids(&self, count: usize) -> usize {
                self.next_task_id.fetch_add(count, Ordering::AcqRel)
            }
        }
        let id_generator = MonotonicIdGenerator::new();

        let decision_maker = DecisionMaker::new(cluster_info.id(), poh_recorder.clone());

        let bank_thread_hdls = [non_vote_receiver, tpu_vote_receiver, gossip_vote_receiver].into_iter().map(|receiver| {
            let decision_maker = decision_maker.clone();
            let id_generator = id_generator.clone();
            let packet_deserializer = PacketDeserializer::new(receiver, bank_forks.clone());

            std::thread::spawn(move || loop {
                let decision = decision_maker.make_consume_or_forward_decision();
                match decision {
                    BufferedPacketsDecision::Consume(bank_start) => {
                        let bank = bank_start.working_bank;
                        let recv_timeout = Duration::from_millis(10);

                        let start = Instant::now();

                        while let Ok(aaa) = packet_deserializer.packet_batch_receiver.recv_timeout(recv_timeout) {
                            for pp in &aaa.0 {
                                // over-provision
                                let task_id = id_generator.bulk_assign_task_ids(pp.len());
                                let task_ids = (task_id..(task_id + pp.len())).collect::<Vec<_>>();

                                let indexes = PacketDeserializer::generate_packet_indexes(&pp);
                                let ppp = PacketDeserializer::deserialize_packets2(&pp, &indexes).filter_map(|p| {
                                    p.build_sanitized_transaction(bank.vote_only_bank(), &**bank, bank.get_reserved_account_keys())
                                }).zip(task_id..).collect::<Vec<_>>();

                                if let Err(_) = bank.schedule_transaction_executions(ppp.iter().zip(&task_ids)) {
                                    break;
                                }
                            }

                            if start.elapsed() >= recv_timeout {
                                break;
                            }
                        }
                    },
                    _  => {
                        std::thread::sleep(Duration::from_millis(10));
                    },
                }
            })
        }).collect();

        Self { bank_thread_hdls }
    }

    fn spawn_thread_local_multi_iterator_thread(
        id: u32,
        packet_receiver: BankingPacketReceiver,
        bank_forks: Arc<RwLock<BankForks>>,
        decision_maker: DecisionMaker,
        committer: Committer,
        transaction_recorder: TransactionRecorder,
        log_messages_bytes_limit: Option<usize>,
        mut forwarder: Forwarder,
        unprocessed_transaction_storage: UnprocessedTransactionStorage,
    ) -> JoinHandle<()> {
        let mut packet_receiver = PacketReceiver::new(id, packet_receiver, bank_forks);
        let consumer = Consumer::new(
            committer,
            transaction_recorder,
            QosService::new(id),
            log_messages_bytes_limit,
        );

        Builder::new()
            .name(format!("solBanknStgTx{id:02}"))
            .spawn(move || {
                Self::process_loop(
                    &mut packet_receiver,
                    &decision_maker,
                    &mut forwarder,
                    &consumer,
                    id,
                    unprocessed_transaction_storage,
                )
            })
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn process_buffered_packets(
        decision_maker: &DecisionMaker,
        forwarder: &mut Forwarder,
        consumer: &Consumer,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        banking_stage_stats: &BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        tracer_packet_stats: &mut TracerPacketStats,
    ) {
        if unprocessed_transaction_storage.should_not_process() {
            return;
        }
        let (decision, make_decision_time) =
            measure!(decision_maker.make_consume_or_forward_decision());
        let metrics_action = slot_metrics_tracker.check_leader_slot_boundary(
            decision.bank_start(),
            Some(unprocessed_transaction_storage),
        );
        slot_metrics_tracker.increment_make_decision_us(make_decision_time.as_us());

        match decision {
            BufferedPacketsDecision::Consume(bank_start) => {
                // Take metrics action before consume packets (potentially resetting the
                // slot metrics tracker to the next slot) so that we don't count the
                // packet processing metrics from the next slot towards the metrics
                // of the previous slot
                slot_metrics_tracker.apply_action(metrics_action);
                let (_, consume_buffered_packets_time) = measure!(
                    consumer.consume_buffered_packets(
                        &bank_start,
                        unprocessed_transaction_storage,
                        banking_stage_stats,
                        slot_metrics_tracker,
                    ),
                    "consume_buffered_packets",
                );
                slot_metrics_tracker
                    .increment_consume_buffered_packets_us(consume_buffered_packets_time.as_us());
            }
            BufferedPacketsDecision::Forward => {
                let ((), forward_us) = measure_us!(forwarder.handle_forwarding(
                    unprocessed_transaction_storage,
                    false,
                    slot_metrics_tracker,
                    banking_stage_stats,
                    tracer_packet_stats,
                ));
                slot_metrics_tracker.increment_forward_us(forward_us);
                // Take metrics action after forwarding packets to include forwarded
                // metrics into current slot
                slot_metrics_tracker.apply_action(metrics_action);
            }
            BufferedPacketsDecision::ForwardAndHold => {
                let ((), forward_and_hold_us) = measure_us!(forwarder.handle_forwarding(
                    unprocessed_transaction_storage,
                    true,
                    slot_metrics_tracker,
                    banking_stage_stats,
                    tracer_packet_stats,
                ));
                slot_metrics_tracker.increment_forward_and_hold_us(forward_and_hold_us);
                // Take metrics action after forwarding packets
                slot_metrics_tracker.apply_action(metrics_action);
            }
            _ => (),
        }
    }

    fn process_loop(
        packet_receiver: &mut PacketReceiver,
        decision_maker: &DecisionMaker,
        forwarder: &mut Forwarder,
        consumer: &Consumer,
        id: u32,
        mut unprocessed_transaction_storage: UnprocessedTransactionStorage,
    ) {
        let mut banking_stage_stats = BankingStageStats::new(id);
        let mut tracer_packet_stats = TracerPacketStats::new(id);

        let mut slot_metrics_tracker = LeaderSlotMetricsTracker::new(id);
        let mut last_metrics_update = Instant::now();

        loop {
            if !unprocessed_transaction_storage.is_empty()
                || last_metrics_update.elapsed() >= SLOT_BOUNDARY_CHECK_PERIOD
            {
                let (_, process_buffered_packets_time) = measure!(
                    Self::process_buffered_packets(
                        decision_maker,
                        forwarder,
                        consumer,
                        &mut unprocessed_transaction_storage,
                        &banking_stage_stats,
                        &mut slot_metrics_tracker,
                        &mut tracer_packet_stats,
                    ),
                    "process_buffered_packets",
                );
                slot_metrics_tracker
                    .increment_process_buffered_packets_us(process_buffered_packets_time.as_us());
                last_metrics_update = Instant::now();
            }

            tracer_packet_stats.report(1000);

            match packet_receiver.receive_and_buffer_packets(
                &mut unprocessed_transaction_storage,
                &mut banking_stage_stats,
                &mut tracer_packet_stats,
                &mut slot_metrics_tracker,
            ) {
                Ok(()) | Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => break,
            }
            banking_stage_stats.report(1000);
        }
    }

    pub fn num_threads() -> u32 {
        cmp::max(
            env::var("SOLANA_BANKING_THREADS")
                .map(|x| x.parse().unwrap_or(NUM_THREADS))
                .unwrap_or(NUM_THREADS),
            MIN_TOTAL_THREADS,
        )
    }

    pub fn join(self) -> thread::Result<()> {
        for bank_thread_hdl in self.bank_thread_hdls {
            bank_thread_hdl.join()?;
        }
        Ok(())
    }
}
