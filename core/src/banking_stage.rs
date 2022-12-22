//! The `banking_stage` processes Transaction messages. It is intended to be used
//! to construct a software pipeline. The stage uses all available CPU cores and
//! can do its processing in parallel with signature verification on the GPU.

use {
    self::{
        commit_executor::CommitExecutor, consume_executor::ConsumeExecutor,
        decision_maker::DecisionMaker, forward_executor::ForwardExecutor,
        packet_receiver::PacketReceiver, record_executor::RecordExecutor,
        scheduler_handle::SchedulerHandle,
    },
    crate::{
        latest_unprocessed_votes::{LatestUnprocessedVotes, VoteSource},
        leader_slot_banking_stage_metrics::LeaderSlotMetricsTracker,
        leader_slot_banking_stage_timing_metrics::LeaderExecuteAndCommitTimings,
        packet_deserializer::PacketDeserializer,
        qos_service::QosService,
        scheduler_stage::{ProcessedTransactionsSender, ScheduledTransactionsReceiver},
        sigverify::SigverifyTracerPacketStats,
        tracer_packet_stats::TracerPacketStats,
        unprocessed_packet_batches::*,
        unprocessed_transaction_storage::{ThreadType, UnprocessedTransactionStorage},
    },
    crossbeam_channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender},
    solana_client::connection_cache::ConnectionCache,
    solana_gossip::cluster_info::ClusterInfo,
    solana_ledger::blockstore_processor::TransactionStatusSender,
    solana_perf::{data_budget::DataBudget, packet::PacketBatch},
    solana_poh::poh_recorder::{PohRecorder, PohRecorderError},
    solana_runtime::{
        self, bank_forks::BankForks, transaction_error_metrics::TransactionErrorMetrics,
        vote_sender_types::ReplayVoteSender,
    },
    solana_sdk::{
        feature_set::allow_votes_to_directly_update_vote_state, pubkey::Pubkey,
        timing::AtomicInterval,
    },
    solana_transaction_status::TransactionTokenBalance,
    std::{
        cmp,
        collections::HashMap,
        env,
        net::UdpSocket,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub mod commit_executor;
pub mod consume_executor;
pub mod decision_maker;
pub mod external_scheduler;
pub mod forward_executor;
pub mod multi_iterator_scheduler;
pub mod packet_receiver;
pub mod record_executor;
pub mod scheduler_error;
pub mod scheduler_handle;
pub mod thread_aware_account_locks;
pub mod thread_local_scheduler;

// Fixed thread size seems to be fastest on GCP setup
pub const NUM_THREADS: u32 = 6;

const TOTAL_BUFFERED_PACKETS: usize = 700_000;

const MAX_NUM_TRANSACTIONS_PER_BATCH: usize = 64;

const NUM_VOTE_PROCESSING_THREADS: u32 = 2;
const MIN_THREADS_BANKING: u32 = 1;
const MIN_TOTAL_THREADS: u32 = NUM_VOTE_PROCESSING_THREADS + MIN_THREADS_BANKING;

const SLOT_BOUNDARY_CHECK_PERIOD: Duration = Duration::from_millis(10);
pub type BankingPacketBatch = (Vec<PacketBatch>, Option<SigverifyTracerPacketStats>);
pub type BankingPacketSender = CrossbeamSender<BankingPacketBatch>;
pub type BankingPacketReceiver = CrossbeamReceiver<BankingPacketBatch>;

pub struct ProcessTransactionBatchOutput {
    // The number of transactions filtered out by the cost model
    cost_model_throttled_transactions_count: usize,
    // Amount of time spent running the cost model
    cost_model_us: u64,
    execute_and_commit_transactions_output: ExecuteAndCommitTransactionsOutput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitTransactionDetails {
    Committed { compute_units: u64 },
    NotCommitted,
}

pub struct ExecuteAndCommitTransactionsOutput {
    // Total number of transactions that were passed as candidates for execution
    transactions_attempted_execution_count: usize,
    // The number of transactions of that were executed. See description of in `ProcessTransactionsSummary`
    // for possible outcomes of execution.
    executed_transactions_count: usize,
    // Total number of the executed transactions that returned success/not
    // an error.
    executed_with_successful_result_count: usize,
    // Transactions that either were not executed, or were executed and failed to be committed due
    // to the block ending.
    retryable_transaction_indexes: Vec<usize>,
    // A result that indicates whether transactions were successfully
    // committed into the Poh stream.
    commit_transactions_result: Result<Vec<CommitTransactionDetails>, PohRecorderError>,
    execute_and_commit_timings: LeaderExecuteAndCommitTimings,
    error_counters: TransactionErrorMetrics,
}

#[derive(Debug, Default)]
pub struct BankingStageStats {
    last_report: AtomicInterval,
    id: u32,
    rebuffered_packets_count: AtomicUsize,
    consumed_buffered_packets_count: AtomicUsize,
    forwarded_transaction_count: AtomicUsize,
    forwarded_vote_count: AtomicUsize,

    // Timing
    consume_buffered_packets_elapsed: AtomicU64,
    filter_pending_packets_elapsed: AtomicU64,
    pub(crate) packet_conversion_elapsed: AtomicU64,
    transaction_processing_elapsed: AtomicU64,
}

impl BankingStageStats {
    pub fn new(id: u32) -> Self {
        BankingStageStats {
            id,
            ..BankingStageStats::default()
        }
    }

    fn is_empty(&self) -> bool {
        0 == self.rebuffered_packets_count.load(Ordering::Relaxed) as u64
            + self.consumed_buffered_packets_count.load(Ordering::Relaxed) as u64
            + self
                .consume_buffered_packets_elapsed
                .load(Ordering::Relaxed)
            + self.filter_pending_packets_elapsed.load(Ordering::Relaxed)
            + self.packet_conversion_elapsed.load(Ordering::Relaxed)
            + self.transaction_processing_elapsed.load(Ordering::Relaxed)
            + self.forwarded_transaction_count.load(Ordering::Relaxed) as u64
            + self.forwarded_vote_count.load(Ordering::Relaxed) as u64
    }

    fn report(&mut self, report_interval_ms: u64) {
        // skip reporting metrics if stats is empty
        if self.is_empty() {
            return;
        }
        if self.last_report.should_update(report_interval_ms) {
            datapoint_info!(
                "banking_stage-loop-stats",
                ("id", self.id as i64, i64),
                (
                    "rebuffered_packets_count",
                    self.rebuffered_packets_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "consumed_buffered_packets_count",
                    self.consumed_buffered_packets_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "forwarded_transaction_count",
                    self.forwarded_transaction_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "forwarded_vote_count",
                    self.forwarded_vote_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "consume_buffered_packets_elapsed",
                    self.consume_buffered_packets_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "filter_pending_packets_elapsed",
                    self.filter_pending_packets_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "packet_conversion_elapsed",
                    self.packet_conversion_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "transaction_processing_elapsed",
                    self.transaction_processing_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                )
            );
        }
    }
}

#[derive(Default)]
pub(self) struct PreBalanceInfo {
    native: Vec<Vec<u64>>,
    token: Vec<Vec<TransactionTokenBalance>>,
    mint_decimals: HashMap<Pubkey, u8>,
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
    pub batched_builtins_execute_cost: u64,
    pub batched_bpf_execute_cost: u64,
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
    pub(crate) total_packet_conversion_us: u64,
    pub(crate) total_filter_packets_us: u64,
}

impl BankingStage {
    /// Create the stage using `bank`. Exit when `verified_receiver` is dropped.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        verified_receiver: BankingPacketReceiver,
        tpu_verified_vote_receiver: BankingPacketReceiver,
        verified_vote_receiver: BankingPacketReceiver,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> Self {
        Self::new_num_threads(
            cluster_info,
            poh_recorder,
            verified_receiver,
            tpu_verified_vote_receiver,
            verified_vote_receiver,
            Self::num_threads(),
            transaction_status_sender,
            gossip_vote_sender,
            log_messages_bytes_limit,
            connection_cache,
            bank_forks,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_external_scheduler(
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        transactions_receivers: Vec<ScheduledTransactionsReceiver>,
        processed_transactions_sender: ProcessedTransactionsSender,
        tpu_verified_vote_receiver: BankingPacketReceiver,
        verified_vote_receiver: BankingPacketReceiver,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> Self {
        let num_threads = transactions_receivers.len();
        // Single thread to generate entries from many banks.
        // This thread talks to poh_service and broadcasts the entries once they have been recorded.
        // Once an entry has been recorded, its blockhash is registered with the bank.
        let data_budget = Arc::new(DataBudget::default());
        let batch_limit = TOTAL_BUFFERED_PACKETS / num_threads;
        // Many banks that process transactions in parallel.
        let mut bank_thread_hdls = Self::spawn_voting_threads(
            cluster_info.clone(),
            poh_recorder.clone(),
            tpu_verified_vote_receiver,
            verified_vote_receiver,
            transaction_status_sender.clone(),
            gossip_vote_sender.clone(),
            log_messages_bytes_limit,
            connection_cache.clone(),
            bank_forks,
            data_budget.clone(),
            batch_limit,
        );

        // Add non-vote transaction threads
        let index_to_id_offset = bank_thread_hdls.len() as u32;
        for (index, transactions_receiver) in transactions_receivers.into_iter().enumerate() {
            let id = index as u32 + index_to_id_offset;
            let scheduler_handle = SchedulerHandle::new_external_scheduler(
                id,
                transactions_receiver,
                processed_transactions_sender.clone(),
            );
            bank_thread_hdls.push(Self::spawn_banking_thread_with_scheduler(
                id,
                scheduler_handle,
                poh_recorder.clone(),
                cluster_info.clone(),
                connection_cache.clone(),
                data_budget.clone(),
                log_messages_bytes_limit,
                transaction_status_sender.clone(),
                gossip_vote_sender.clone(),
            ));
        }

        Self { bank_thread_hdls }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_num_threads(
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        verified_receiver: BankingPacketReceiver,
        tpu_verified_vote_receiver: BankingPacketReceiver,
        verified_vote_receiver: BankingPacketReceiver,
        num_threads: u32,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> Self {
        assert!(num_threads >= MIN_TOTAL_THREADS);
        // Single thread to generate entries from many banks.
        // This thread talks to poh_service and broadcasts the entries once they have been recorded.
        // Once an entry has been recorded, its blockhash is registered with the bank.
        let data_budget = Arc::new(DataBudget::default());
        let batch_limit =
            TOTAL_BUFFERED_PACKETS / ((num_threads - NUM_VOTE_PROCESSING_THREADS) as usize);

        // Many banks that process transactions in parallel.
        let mut bank_thread_hdls = Self::spawn_voting_threads(
            cluster_info.clone(),
            poh_recorder.clone(),
            tpu_verified_vote_receiver,
            verified_vote_receiver,
            transaction_status_sender.clone(),
            gossip_vote_sender.clone(),
            log_messages_bytes_limit,
            connection_cache.clone(),
            bank_forks.clone(),
            data_budget.clone(),
            batch_limit,
        );
        // Add non-vote transaction threads
        for id in 2..num_threads {
            let unprocessed_transaction_storage =
                UnprocessedTransactionStorage::new_transaction_storage(
                    UnprocessedPacketBatches::with_capacity(batch_limit),
                    ThreadType::Transactions,
                );
            let packet_deserializer = PacketDeserializer::new(verified_receiver.clone());
            let scheduler_handle = Self::build_thread_local_scheduler_handle(
                packet_deserializer,
                poh_recorder.clone(),
                bank_forks.clone(),
                cluster_info.clone(),
                id,
                unprocessed_transaction_storage,
            );

            bank_thread_hdls.push(Self::spawn_banking_thread_with_scheduler(
                id,
                scheduler_handle,
                poh_recorder.clone(),
                cluster_info.clone(),
                connection_cache.clone(),
                data_budget.clone(),
                log_messages_bytes_limit,
                transaction_status_sender.clone(),
                gossip_vote_sender.clone(),
            ));
        }

        Self { bank_thread_hdls }
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_voting_threads(
        cluster_info: Arc<ClusterInfo>,
        poh_recorder: Arc<RwLock<PohRecorder>>,
        tpu_verified_vote_receiver: BankingPacketReceiver,
        verified_vote_receiver: BankingPacketReceiver,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: Arc<RwLock<BankForks>>,
        data_budget: Arc<DataBudget>,
        batch_limit: usize,
    ) -> Vec<JoinHandle<()>> {
        // Keeps track of extraneous vote transactions for the vote threads
        let latest_unprocessed_votes = Arc::new(LatestUnprocessedVotes::new());
        let should_split_voting_threads = bank_forks
            .read()
            .map(|bank_forks| {
                let bank = bank_forks.root_bank();
                bank.feature_set
                    .is_active(&allow_votes_to_directly_update_vote_state::id())
            })
            .unwrap_or(false);

        vec![
            // Gossip voting thread
            Self::spawn_voting_thread(
                0,
                VoteSource::Gossip,
                should_split_voting_threads,
                batch_limit,
                latest_unprocessed_votes.clone(),
                PacketDeserializer::new(verified_vote_receiver),
                poh_recorder.clone(),
                bank_forks.clone(),
                cluster_info.clone(),
                connection_cache.clone(),
                data_budget.clone(),
                log_messages_bytes_limit,
                transaction_status_sender.clone(),
                gossip_vote_sender.clone(),
            ),
            // TPU voting thread
            Self::spawn_voting_thread(
                1,
                VoteSource::Tpu,
                should_split_voting_threads,
                batch_limit,
                latest_unprocessed_votes,
                PacketDeserializer::new(tpu_verified_vote_receiver),
                poh_recorder,
                bank_forks,
                cluster_info,
                connection_cache,
                data_budget,
                log_messages_bytes_limit,
                transaction_status_sender,
                gossip_vote_sender,
            ),
        ]
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_voting_thread(
        id: u32,
        voting_source: VoteSource,
        should_split_voting_threads: bool,
        buffer_capacity: usize,
        latest_unprocessed_votes: Arc<LatestUnprocessedVotes>,
        packet_deserializer: PacketDeserializer,
        poh_recorder: Arc<RwLock<PohRecorder>>,
        bank_forks: Arc<RwLock<BankForks>>,
        cluster_info: Arc<ClusterInfo>,
        connection_cache: Arc<ConnectionCache>,
        data_budget: Arc<DataBudget>,
        log_messages_bytes_limit: Option<usize>,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
    ) -> JoinHandle<()> {
        let buffer = if should_split_voting_threads {
            UnprocessedTransactionStorage::new_vote_storage(latest_unprocessed_votes, voting_source)
        } else {
            UnprocessedTransactionStorage::new_transaction_storage(
                UnprocessedPacketBatches::with_capacity(buffer_capacity),
                ThreadType::Voting(voting_source),
            )
        };

        let scheduler_handle = Self::build_thread_local_scheduler_handle(
            packet_deserializer,
            poh_recorder.clone(),
            bank_forks,
            cluster_info.clone(),
            id,
            buffer,
        );

        Self::spawn_banking_thread_with_scheduler(
            id,
            scheduler_handle,
            poh_recorder,
            cluster_info,
            connection_cache,
            data_budget,
            log_messages_bytes_limit,
            transaction_status_sender,
            gossip_vote_sender,
        )
    }

    fn spawn_banking_thread_with_scheduler(
        id: u32,
        scheduler_handle: SchedulerHandle,
        poh_recorder: Arc<RwLock<PohRecorder>>,
        cluster_info: Arc<ClusterInfo>,
        connection_cache: Arc<ConnectionCache>,
        data_budget: Arc<DataBudget>,
        log_messages_bytes_limit: Option<usize>,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
    ) -> JoinHandle<()> {
        let (forward_executor, consume_executor) = Self::build_executors(
            id,
            poh_recorder,
            cluster_info,
            connection_cache,
            data_budget,
            log_messages_bytes_limit,
            transaction_status_sender,
            gossip_vote_sender,
        );
        Builder::new()
            .name(format!("solBanknStgTx{:02}", id))
            .spawn(move || {
                Self::process_loop(id, scheduler_handle, forward_executor, consume_executor);
            })
            .unwrap()
    }

    fn build_executors(
        id: u32,
        poh_recorder: Arc<RwLock<PohRecorder>>,
        cluster_info: Arc<ClusterInfo>,
        connection_cache: Arc<ConnectionCache>,
        data_budget: Arc<DataBudget>,
        log_messages_bytes_limit: Option<usize>,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
    ) -> (ForwardExecutor, ConsumeExecutor) {
        let transaction_recorder = poh_recorder.read().unwrap().recorder();
        let forward_executor = ForwardExecutor::new(
            poh_recorder,
            UdpSocket::bind("0.0.0.0:0").unwrap(),
            cluster_info,
            connection_cache,
            data_budget,
        );
        let record_executor = RecordExecutor::new(transaction_recorder);
        let commit_executor = CommitExecutor::new(transaction_status_sender, gossip_vote_sender);
        let consume_executor = ConsumeExecutor::new(
            record_executor,
            commit_executor,
            QosService::new(id),
            log_messages_bytes_limit,
        );

        (forward_executor, consume_executor)
    }

    fn build_thread_local_scheduler_handle(
        packet_deserializer: PacketDeserializer,
        poh_recorder: Arc<RwLock<PohRecorder>>,
        bank_forks: Arc<RwLock<BankForks>>,
        cluster_info: Arc<ClusterInfo>,
        id: u32,
        unprocessed_transaction_storage: UnprocessedTransactionStorage,
    ) -> SchedulerHandle {
        let packet_receiver = PacketReceiver::new(id, packet_deserializer);
        let decision_maker = DecisionMaker::new(cluster_info.id(), poh_recorder);
        SchedulerHandle::new_thread_local_scheduler(
            id,
            decision_maker,
            unprocessed_transaction_storage,
            bank_forks,
            packet_receiver,
        )
    }

    fn process_loop(
        id: u32,
        mut scheduler_handle: SchedulerHandle,
        forward_executor: ForwardExecutor,
        consume_executor: ConsumeExecutor,
    ) {
        let mut tracer_packet_stats = TracerPacketStats::new(id);
        let mut slot_metrics_tracker = LeaderSlotMetricsTracker::new(id);

        loop {
            // Do scheduled work (processing packets)
            if let Err(err) = scheduler_handle.do_scheduled_work(
                &consume_executor,
                &forward_executor,
                &mut tracer_packet_stats,
                &mut slot_metrics_tracker,
            ) {
                warn!("Banking stage scheduler error: {:?}", err);
                break;
            }

            // Do any necessary updates - check if scheduler is still valid
            if let Err(err) = scheduler_handle.tick() {
                warn!("Banking stage scheduler error: {:?}", err);
                break;
            }

            tracer_packet_stats.report(1000);
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

    pub fn num_non_vote_threads() -> u32 {
        Self::num_threads() - NUM_VOTE_PROCESSING_THREADS
    }

    pub fn join(self) -> thread::Result<()> {
        for bank_thread_hdl in self.bank_thread_hdls {
            bank_thread_hdl.join()?;
        }
        Ok(())
    }
}
