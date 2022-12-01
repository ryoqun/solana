//! The `banking_stage` processes Transaction messages. It is intended to be used
//! to construct a software pipeline. The stage uses all available CPU cores and
//! can do its processing in parallel with signature verification on the GPU.

use {
    crate::{
        forward_packet_batches_by_accounts::ForwardPacketBatchesByAccounts,
        immutable_deserialized_packet::ImmutableDeserializedPacket,
        latest_unprocessed_votes::{LatestUnprocessedVotes, VoteSource},
        leader_slot_banking_stage_metrics::{
            LeaderSlotMetricsTracker, MetricsTrackerAction, ProcessTransactionsSummary,
        },
        leader_slot_banking_stage_timing_metrics::{
            LeaderExecuteAndCommitTimings, RecordTransactionsTimings,
        },
        packet_deserializer::{PacketDeserializer, ReceivePacketResults},
        qos_service::QosService,
        sigverify::SigverifyTracerPacketStats,
        tracer_packet_stats::TracerPacketStats,
        unprocessed_packet_batches::*,
        unprocessed_transaction_storage::{
            ConsumeScannerPayload, ThreadType, UnprocessedTransactionStorage,
        },
    },
    core::iter::repeat,
    crossbeam_channel::{
        Receiver as CrossbeamReceiver, RecvTimeoutError, Sender as CrossbeamSender,
    },
    histogram::Histogram,
    itertools::Itertools,
    solana_client::{connection_cache::ConnectionCache, tpu_connection::TpuConnection},
    solana_entry::entry::hash_transactions,
    solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
    solana_ledger::{
        blockstore_processor::TransactionStatusSender, token_balances::collect_token_balances,
    },
    solana_measure::{measure, measure::Measure},
    solana_metrics::inc_new_counter_info,
    solana_perf::{
        data_budget::DataBudget,
        packet::{Packet, PacketBatch, PACKETS_PER_BATCH},
    },
    solana_poh::poh_recorder::{BankStart, PohRecorder, PohRecorderError, TransactionRecorder},
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        accounts::TransactionLoadResult,
        bank::{
            Bank, CommitTransactionCounts, LoadAndExecuteTransactionsOutput,
            TransactionBalancesSet, TransactionCheckResult, TransactionExecutionResult,
            TransactionResults,
        },
        bank_forks::BankForks,
        bank_utils,
        transaction_batch::TransactionBatch,
        transaction_error_metrics::TransactionErrorMetrics,
        vote_sender_types::ReplayVoteSender,
    },
    solana_sdk::{
        clock::{
            Slot, DEFAULT_TICKS_PER_SLOT, FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET,
            HOLD_TRANSACTIONS_SLOT_OFFSET, MAX_PROCESSING_AGE,
        },
        feature_set::allow_votes_to_directly_update_vote_state,
        pubkey::Pubkey,
        saturating_add_assign,
        timing::{duration_as_ms, timestamp, AtomicInterval},
        transaction::{self, SanitizedTransaction, TransactionError, VersionedTransaction},
        transport::TransportError,
    },
    solana_streamer::sendmmsg::batch_send,
    solana_transaction_status::{
        token_balances::TransactionTokenBalancesSet, TransactionTokenBalance,
    },
    std::{
        cmp,
        collections::HashMap,
        env,
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

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

struct RecordTransactionsSummary {
    // Metrics describing how time was spent recording transactions
    record_transactions_timings: RecordTransactionsTimings,
    // Result of trying to record the transactions into the PoH stream
    result: Result<(), PohRecorderError>,
    // Index in the slot of the first transaction recorded
    starting_transaction_index: Option<usize>,
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
    receive_and_buffer_packets_count: AtomicUsize,
    dropped_packets_count: AtomicUsize,
    pub(crate) dropped_duplicated_packets_count: AtomicUsize,
    newly_buffered_packets_count: AtomicUsize,
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
            id,
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
                ("id", self.id as i64, i64),
                (
                    "receive_and_buffer_packets_count",
                    self.receive_and_buffer_packets_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "dropped_packets_count",
                    self.dropped_packets_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "dropped_duplicated_packets_count",
                    self.dropped_duplicated_packets_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "newly_buffered_packets_count",
                    self.newly_buffered_packets_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "current_buffered_packets_count",
                    self.current_buffered_packets_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
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
                    "receive_and_buffer_packets_elapsed",
                    self.receive_and_buffer_packets_elapsed
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
                ),
                (
                    "packet_batch_indices_len_min",
                    self.batch_packet_indexes_len.minimum().unwrap_or(0) as i64,
                    i64
                ),
                (
                    "packet_batch_indices_len_max",
                    self.batch_packet_indexes_len.maximum().unwrap_or(0) as i64,
                    i64
                ),
                (
                    "packet_batch_indices_len_mean",
                    self.batch_packet_indexes_len.mean().unwrap_or(0) as i64,
                    i64
                ),
                (
                    "packet_batch_indices_len_90pct",
                    self.batch_packet_indexes_len.percentile(90.0).unwrap_or(0) as i64,
                    i64
                )
            );
            self.batch_packet_indexes_len.clear();
        }
    }
}

#[derive(Default)]
struct PreBalanceInfo {
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
pub enum BufferedPacketsDecision {
    Consume(u128),
    Forward,
    ForwardAndHold,
    Hold,
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
        // Many banks that process transactions in parallel.
        let bank_thread_hdls: Vec<JoinHandle<()>> = (0..num_threads)
            .map(|i| {
                let (verified_receiver, unprocessed_transaction_storage) =
                    match (i, should_split_voting_threads) {
                        (0, false) => (
                            verified_vote_receiver.clone(),
                            UnprocessedTransactionStorage::new_transaction_storage(
                                UnprocessedPacketBatches::with_capacity(batch_limit),
                                ThreadType::Voting(VoteSource::Gossip),
                            ),
                        ),
                        (0, true) => (
                            verified_vote_receiver.clone(),
                            UnprocessedTransactionStorage::new_vote_storage(
                                latest_unprocessed_votes.clone(),
                                VoteSource::Gossip,
                            ),
                        ),
                        (1, false) => (
                            tpu_verified_vote_receiver.clone(),
                            UnprocessedTransactionStorage::new_transaction_storage(
                                UnprocessedPacketBatches::with_capacity(batch_limit),
                                ThreadType::Voting(VoteSource::Tpu),
                            ),
                        ),
                        (1, true) => (
                            tpu_verified_vote_receiver.clone(),
                            UnprocessedTransactionStorage::new_vote_storage(
                                latest_unprocessed_votes.clone(),
                                VoteSource::Tpu,
                            ),
                        ),
                        _ => (
                            verified_receiver.clone(),
                            UnprocessedTransactionStorage::new_transaction_storage(
                                UnprocessedPacketBatches::with_capacity(batch_limit),
                                ThreadType::Transactions,
                            ),
                        ),
                    };

                let mut packet_deserializer = PacketDeserializer::new(verified_receiver);
                let poh_recorder = poh_recorder.clone();
                let cluster_info = cluster_info.clone();
                let mut recv_start = Instant::now();
                let transaction_status_sender = transaction_status_sender.clone();
                let gossip_vote_sender = gossip_vote_sender.clone();
                let data_budget = data_budget.clone();
                let connection_cache = connection_cache.clone();
                let bank_forks = bank_forks.clone();
                Builder::new()
                    .name(format!("solBanknStgTx{:02}", i))
                    .spawn(move || {
                        Self::process_loop(
                            &mut packet_deserializer,
                            &poh_recorder,
                            &cluster_info,
                            &mut recv_start,
                            i,
                            transaction_status_sender,
                            gossip_vote_sender,
                            &data_budget,
                            log_messages_bytes_limit,
                            connection_cache,
                            &bank_forks,
                            unprocessed_transaction_storage,
                        );
                    })
                    .unwrap()
            })
            .collect();
        Self { bank_thread_hdls }
    }

    /// Forwards all valid, unprocessed packets in the buffer, up to a rate limit. Returns
    /// the number of successfully forwarded packets in second part of tuple
    fn forward_buffered_packets<'a>(
        connection_cache: &ConnectionCache,
        forward_option: &ForwardOption,
        cluster_info: &ClusterInfo,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        socket: &UdpSocket,
        forwardable_packets: impl Iterator<Item = &'a Packet>,
        data_budget: &DataBudget,
        banking_stage_stats: &BankingStageStats,
    ) -> (
        std::result::Result<(), TransportError>,
        usize,
        Option<Pubkey>,
    ) {
        let leader_and_addr = match forward_option {
            ForwardOption::NotForward => return (Ok(()), 0, None),
            ForwardOption::ForwardTransaction => {
                next_leader_tpu_forwards(cluster_info, poh_recorder)
            }

            ForwardOption::ForwardTpuVote => next_leader_tpu_vote(cluster_info, poh_recorder),
        };
        let (leader_pubkey, addr) = match leader_and_addr {
            Some(leader_and_addr) => leader_and_addr,
            None => return (Ok(()), 0, None),
        };

        const INTERVAL_MS: u64 = 100;
        // 12 MB outbound limit per second
        const MAX_BYTES_PER_SECOND: usize = 12_000_000;
        const MAX_BYTES_PER_INTERVAL: usize = MAX_BYTES_PER_SECOND * INTERVAL_MS as usize / 1000;
        const MAX_BYTES_BUDGET: usize = MAX_BYTES_PER_INTERVAL * 5;
        data_budget.update(INTERVAL_MS, |bytes| {
            std::cmp::min(
                bytes.saturating_add(MAX_BYTES_PER_INTERVAL),
                MAX_BYTES_BUDGET,
            )
        });

        let packet_vec: Vec<_> = forwardable_packets
            .filter_map(|p| {
                if !p.meta.forwarded() && data_budget.take(p.meta.size) {
                    Some(p.data(..)?.to_vec())
                } else {
                    None
                }
            })
            .collect();

        let packet_vec_len = packet_vec.len();
        // TODO: see https://github.com/solana-labs/solana/issues/23819
        // fix this so returns the correct number of succeeded packets
        // when there's an error sending the batch. This was left as-is for now
        // in favor of shipping Quic support, which was considered higher-priority
        if !packet_vec.is_empty() {
            inc_new_counter_info!("banking_stage-forwarded_packets", packet_vec_len);

            let mut measure = Measure::start("banking_stage-forward-us");

            let res = if let ForwardOption::ForwardTpuVote = forward_option {
                // The vote must be forwarded using only UDP.
                banking_stage_stats
                    .forwarded_vote_count
                    .fetch_add(packet_vec_len, Ordering::Relaxed);
                let pkts: Vec<_> = packet_vec.into_iter().zip(repeat(addr)).collect();
                batch_send(socket, &pkts).map_err(|err| err.into())
            } else {
                // All other transactions can be forwarded using QUIC, get_connection() will use
                // system wide setting to pick the correct connection object.
                banking_stage_stats
                    .forwarded_transaction_count
                    .fetch_add(packet_vec_len, Ordering::Relaxed);
                let conn = connection_cache.get_connection(&addr);
                conn.send_wire_transaction_batch_async(packet_vec)
            };

            measure.stop();
            inc_new_counter_info!(
                "banking_stage-forward-us",
                measure.as_us() as usize,
                1000,
                1000
            );

            if let Err(err) = res {
                inc_new_counter_info!("banking_stage-forward_packets-failed-batches", 1);
                return (Err(err), 0, Some(leader_pubkey));
            }
        }

        (Ok(()), packet_vec_len, Some(leader_pubkey))
    }

    #[allow(clippy::too_many_arguments)]
    fn do_process_packets(
        max_tx_ingestion_ns: u128,
        working_bank: &Arc<Bank>,
        bank_creation_time: &Arc<Instant>,
        payload: &mut ConsumeScannerPayload,
        recorder: &TransactionRecorder,
        transaction_status_sender: &Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        banking_stage_stats: &BankingStageStats,
        qos_service: &QosService,
        log_messages_bytes_limit: Option<usize>,
        consumed_buffered_packets_count: &mut usize,
        rebuffered_packet_count: &mut usize,
        test_fn: &Option<impl Fn()>,
        packets_to_process: &Vec<Arc<ImmutableDeserializedPacket>>,
    ) -> Option<Vec<usize>> {
        if payload.reached_end_of_slot {
            return None;
        }

        let packets_to_process_len = packets_to_process.len();
        let (process_transactions_summary, process_packets_transactions_time) = measure!(
            Self::process_packets_transactions(
                working_bank,
                bank_creation_time,
                recorder,
                &payload.sanitized_transactions,
                transaction_status_sender,
                gossip_vote_sender,
                banking_stage_stats,
                qos_service,
                payload.slot_metrics_tracker,
                log_messages_bytes_limit
            ),
            "process_packets_transactions",
        );
        payload
            .slot_metrics_tracker
            .increment_process_packets_transactions_us(process_packets_transactions_time.as_us());

        // Clear payload for next iteration
        payload.sanitized_transactions.clear();
        payload.account_locks.clear();

        let ProcessTransactionsSummary {
            reached_max_poh_height,
            retryable_transaction_indexes,
            ..
        } = process_transactions_summary;

        if reached_max_poh_height
            || !Bank::should_bank_still_be_processing_txs(bank_creation_time, max_tx_ingestion_ns)
        {
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

    #[allow(clippy::too_many_arguments)]
    pub fn consume_buffered_packets(
        max_tx_ingestion_ns: u128,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        transaction_status_sender: &Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        test_fn: Option<impl Fn()>,
        banking_stage_stats: &BankingStageStats,
        recorder: &TransactionRecorder,
        qos_service: &QosService,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        log_messages_bytes_limit: Option<usize>,
    ) {
        let mut rebuffered_packet_count = 0;
        let mut consumed_buffered_packets_count = 0;
        let mut proc_start = Measure::start("consume_buffered_process");
        let reached_end_of_slot;
        let num_packets_to_process = unprocessed_transaction_storage.len();

        let (bank_start, poh_recorder_lock_time) = measure!(
            poh_recorder.read().unwrap().bank_start(),
            "poh_recorder.read",
        );
        slot_metrics_tracker.increment_consume_buffered_packets_poh_recorder_lock_us(
            poh_recorder_lock_time.as_us(),
        );

        if let Some(BankStart {
            working_bank,
            bank_creation_time,
        }) = bank_start
        {
            reached_end_of_slot = unprocessed_transaction_storage.process_packets(
                working_bank.clone(),
                banking_stage_stats,
                slot_metrics_tracker,
                |packets_to_process, payload| {
                    Self::do_process_packets(
                        max_tx_ingestion_ns,
                        &working_bank,
                        &bank_creation_time,
                        payload,
                        recorder,
                        transaction_status_sender,
                        gossip_vote_sender,
                        banking_stage_stats,
                        qos_service,
                        log_messages_bytes_limit,
                        &mut consumed_buffered_packets_count,
                        &mut rebuffered_packet_count,
                        &test_fn,
                        packets_to_process,
                    )
                },
            );
        } else {
            reached_end_of_slot = true;
        }

        if reached_end_of_slot {
            slot_metrics_tracker.set_end_of_slot_unprocessed_buffer_len(
                unprocessed_transaction_storage.len() as u64,
            );

            // We've hit the end of this slot, no need to perform more processing,
            // Packet filtering will be done before forwarding.
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

    fn consume_or_forward_packets(
        my_pubkey: &Pubkey,
        leader_pubkey: Option<Pubkey>,
        bank_still_processing_txs: Option<&Arc<Bank>>,
        would_be_leader: bool,
        would_be_leader_shortly: bool,
    ) -> BufferedPacketsDecision {
        // If has active bank, then immediately process buffered packets
        // otherwise, based on leader schedule to either forward or hold packets
        if let Some(bank) = bank_still_processing_txs {
            // If the bank is available, this node is the leader
            BufferedPacketsDecision::Consume(bank.ns_per_slot)
        } else if would_be_leader_shortly {
            // If the node will be the leader soon, hold the packets for now
            BufferedPacketsDecision::Hold
        } else if would_be_leader {
            // Node will be leader within ~20 slots, hold the transactions in
            // case it is the only node which produces an accepted slot.
            BufferedPacketsDecision::ForwardAndHold
        } else if let Some(x) = leader_pubkey {
            if x != *my_pubkey {
                // If the current node is not the leader, forward the buffered packets
                BufferedPacketsDecision::Forward
            } else {
                // If the current node is the leader, return the buffered packets as is
                BufferedPacketsDecision::Hold
            }
        } else {
            // We don't know the leader. Hold the packets for now
            BufferedPacketsDecision::Hold
        }
    }

    fn make_consume_or_forward_decision(
        my_pubkey: &Pubkey,
        poh_recorder: &RwLock<PohRecorder>,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) -> (MetricsTrackerAction, BufferedPacketsDecision) {
        let bank_start;
        let (
            leader_at_slot_offset,
            bank_still_processing_txs,
            would_be_leader,
            would_be_leader_shortly,
        ) = {
            let poh = poh_recorder.read().unwrap();
            bank_start = poh.bank_start();
            (
                poh.leader_after_n_slots(FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET),
                PohRecorder::get_working_bank_if_not_expired(&bank_start.as_ref()),
                poh.would_be_leader(HOLD_TRANSACTIONS_SLOT_OFFSET * DEFAULT_TICKS_PER_SLOT),
                poh.would_be_leader(
                    (FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET - 1) * DEFAULT_TICKS_PER_SLOT,
                ),
            )
        };

        (
            slot_metrics_tracker.check_leader_slot_boundary(&bank_start),
            Self::consume_or_forward_packets(
                my_pubkey,
                leader_at_slot_offset,
                bank_still_processing_txs,
                would_be_leader,
                would_be_leader_shortly,
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn process_buffered_packets(
        my_pubkey: &Pubkey,
        socket: &UdpSocket,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        cluster_info: &ClusterInfo,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        transaction_status_sender: &Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        banking_stage_stats: &BankingStageStats,
        recorder: &TransactionRecorder,
        data_budget: &DataBudget,
        qos_service: &QosService,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: &ConnectionCache,
        tracer_packet_stats: &mut TracerPacketStats,
        bank_forks: &Arc<RwLock<BankForks>>,
    ) {
        if unprocessed_transaction_storage.should_not_process() {
            return;
        }
        let ((metrics_action, decision), make_decision_time) = measure!(
            Self::make_consume_or_forward_decision(my_pubkey, poh_recorder, slot_metrics_tracker)
        );
        slot_metrics_tracker.increment_make_decision_us(make_decision_time.as_us());

        match decision {
            BufferedPacketsDecision::Consume(max_tx_ingestion_ns) => {
                // Take metrics action before consume packets (potentially resetting the
                // slot metrics tracker to the next slot) so that we don't count the
                // packet processing metrics from the next slot towards the metrics
                // of the previous slot
                slot_metrics_tracker.apply_action(metrics_action);
                let (_, consume_buffered_packets_time) = measure!(
                    Self::consume_buffered_packets(
                        max_tx_ingestion_ns,
                        poh_recorder,
                        unprocessed_transaction_storage,
                        transaction_status_sender,
                        gossip_vote_sender,
                        None::<Box<dyn Fn()>>,
                        banking_stage_stats,
                        recorder,
                        qos_service,
                        slot_metrics_tracker,
                        log_messages_bytes_limit
                    ),
                    "consume_buffered_packets",
                );
                slot_metrics_tracker
                    .increment_consume_buffered_packets_us(consume_buffered_packets_time.as_us());
            }
            BufferedPacketsDecision::Forward => {
                let (_, forward_time) = measure!(
                    Self::handle_forwarding(
                        cluster_info,
                        unprocessed_transaction_storage,
                        poh_recorder,
                        socket,
                        false,
                        data_budget,
                        slot_metrics_tracker,
                        banking_stage_stats,
                        connection_cache,
                        tracer_packet_stats,
                        bank_forks,
                    ),
                    "forward",
                );
                slot_metrics_tracker.increment_forward_us(forward_time.as_us());
                // Take metrics action after forwarding packets to include forwarded
                // metrics into current slot
                slot_metrics_tracker.apply_action(metrics_action);
            }
            BufferedPacketsDecision::ForwardAndHold => {
                let (_, forward_and_hold_time) = measure!(
                    Self::handle_forwarding(
                        cluster_info,
                        unprocessed_transaction_storage,
                        poh_recorder,
                        socket,
                        true,
                        data_budget,
                        slot_metrics_tracker,
                        banking_stage_stats,
                        connection_cache,
                        tracer_packet_stats,
                        bank_forks,
                    ),
                    "forward_and_hold",
                );
                slot_metrics_tracker.increment_forward_and_hold_us(forward_and_hold_time.as_us());
                // Take metrics action after forwarding packets
                slot_metrics_tracker.apply_action(metrics_action);
            }
            _ => (),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_forwarding(
        cluster_info: &ClusterInfo,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        socket: &UdpSocket,
        hold: bool,
        data_budget: &DataBudget,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        banking_stage_stats: &BankingStageStats,
        connection_cache: &ConnectionCache,
        tracer_packet_stats: &mut TracerPacketStats,
        bank_forks: &Arc<RwLock<BankForks>>,
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
                    Self::forward_buffered_packets(
                        connection_cache,
                        &forward_option,
                        cluster_info,
                        poh_recorder,
                        socket,
                        forward_batch.get_forwardable_packets(),
                        data_budget,
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

    #[allow(clippy::too_many_arguments)]
    fn process_loop(
        packet_deserializer: &mut PacketDeserializer,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        cluster_info: &ClusterInfo,
        recv_start: &mut Instant,
        id: u32,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
        data_budget: &DataBudget,
        log_messages_bytes_limit: Option<usize>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: &Arc<RwLock<BankForks>>,
        mut unprocessed_transaction_storage: UnprocessedTransactionStorage,
    ) {
        let recorder = poh_recorder.read().unwrap().recorder();
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut banking_stage_stats = BankingStageStats::new(id);
        let mut tracer_packet_stats = TracerPacketStats::new(id);
        let qos_service = QosService::new(id);

        let mut slot_metrics_tracker = LeaderSlotMetricsTracker::new(id);
        let mut last_metrics_update = Instant::now();

        loop {
            let my_pubkey = cluster_info.id();
            if !unprocessed_transaction_storage.is_empty()
                || last_metrics_update.elapsed() >= SLOT_BOUNDARY_CHECK_PERIOD
            {
                let (_, process_buffered_packets_time) = measure!(
                    Self::process_buffered_packets(
                        &my_pubkey,
                        &socket,
                        poh_recorder,
                        cluster_info,
                        &mut unprocessed_transaction_storage,
                        &transaction_status_sender,
                        &gossip_vote_sender,
                        &banking_stage_stats,
                        &recorder,
                        data_budget,
                        &qos_service,
                        &mut slot_metrics_tracker,
                        log_messages_bytes_limit,
                        &connection_cache,
                        &mut tracer_packet_stats,
                        bank_forks,
                    ),
                    "process_buffered_packets",
                );
                slot_metrics_tracker
                    .increment_process_buffered_packets_us(process_buffered_packets_time.as_us());
                last_metrics_update = Instant::now();
            }

            tracer_packet_stats.report(1000);

            // Gossip thread will almost always not wait because the transaction storage will most likely not be empty
            let recv_timeout = if !unprocessed_transaction_storage.is_empty() {
                // If there are buffered packets, run the equivalent of try_recv to try reading more
                // packets. This prevents starving BankingStage::consume_buffered_packets due to
                // buffered_packet_batches containing transactions that exceed the cost model for
                // the current bank.
                Duration::from_millis(0)
            } else {
                // Default wait time
                Duration::from_millis(100)
            };

            let (res, receive_and_buffer_packets_time) = measure!(
                Self::receive_and_buffer_packets(
                    packet_deserializer,
                    recv_start,
                    recv_timeout,
                    id,
                    &mut unprocessed_transaction_storage,
                    &mut banking_stage_stats,
                    &mut tracer_packet_stats,
                    &mut slot_metrics_tracker,
                ),
                "receive_and_buffer_packets",
            );
            slot_metrics_tracker
                .increment_receive_and_buffer_packets_us(receive_and_buffer_packets_time.as_us());

            match res {
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

    fn record_transactions(
        bank_slot: Slot,
        transactions: Vec<VersionedTransaction>,
        recorder: &TransactionRecorder,
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
                measure!(recorder.record(bank_slot, hash, transactions), "hash");
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

    #[allow(clippy::too_many_arguments)]
    fn commit_transactions(
        batch: &TransactionBatch,
        loaded_transactions: &mut [TransactionLoadResult],
        execution_results: Vec<TransactionExecutionResult>,
        sanitized_txs: &[SanitizedTransaction],
        starting_transaction_index: Option<usize>,
        bank: &Arc<Bank>,
        pre_balance_info: &mut PreBalanceInfo,
        execute_and_commit_timings: &mut LeaderExecuteAndCommitTimings,
        transaction_status_sender: &Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        signature_count: u64,
        executed_transactions_count: usize,
        executed_with_successful_result_count: usize,
    ) -> (u64, Vec<CommitTransactionDetails>) {
        inc_new_counter_info!(
            "banking_stage-record_transactions_num_to_commit",
            executed_transactions_count
        );

        let (last_blockhash, lamports_per_signature) =
            bank.last_blockhash_and_lamports_per_signature();

        let (tx_results, commit_time) = measure!(
            bank.commit_transactions(
                sanitized_txs,
                loaded_transactions,
                execution_results,
                last_blockhash,
                lamports_per_signature,
                CommitTransactionCounts {
                    committed_transactions_count: executed_transactions_count as u64,
                    committed_with_failure_result_count: executed_transactions_count
                        .saturating_sub(executed_with_successful_result_count)
                        as u64,
                    signature_count,
                },
                &mut execute_and_commit_timings.execute_timings,
            ),
            "commit",
        );
        let commit_time_us = commit_time.as_us();
        execute_and_commit_timings.commit_us = commit_time_us;

        let commit_transaction_statuses = tx_results
            .execution_results
            .iter()
            .map(|execution_result| match execution_result.details() {
                Some(details) => CommitTransactionDetails::Committed {
                    compute_units: details.executed_units,
                },
                None => CommitTransactionDetails::NotCommitted,
            })
            .collect();

        let (_, find_and_send_votes_time) = measure!(
            {
                bank_utils::find_and_send_votes(
                    sanitized_txs,
                    &tx_results,
                    Some(gossip_vote_sender),
                );
                Self::collect_balances_and_send_status_batch(
                    transaction_status_sender,
                    tx_results,
                    bank,
                    batch,
                    pre_balance_info,
                    starting_transaction_index,
                );
            },
            "find_and_send_votes",
        );
        execute_and_commit_timings.find_and_send_votes_us = find_and_send_votes_time.as_us();
        (commit_time_us, commit_transaction_statuses)
    }

    fn collect_balances_and_send_status_batch(
        transaction_status_sender: &Option<TransactionStatusSender>,
        tx_results: TransactionResults,
        bank: &Arc<Bank>,
        batch: &TransactionBatch,
        pre_balance_info: &mut PreBalanceInfo,
        starting_transaction_index: Option<usize>,
    ) {
        if let Some(transaction_status_sender) = transaction_status_sender {
            let txs = batch.sanitized_transactions().to_vec();
            let post_balances = bank.collect_balances(batch);
            let post_token_balances =
                collect_token_balances(bank, batch, &mut pre_balance_info.mint_decimals);
            let mut transaction_index = starting_transaction_index.unwrap_or_default();
            let batch_transaction_indexes: Vec<_> = tx_results
                .execution_results
                .iter()
                .map(|result| {
                    if result.was_executed() {
                        let this_transaction_index = transaction_index;
                        saturating_add_assign!(transaction_index, 1);
                        this_transaction_index
                    } else {
                        0
                    }
                })
                .collect();
            transaction_status_sender.send_transaction_status_batch(
                bank.clone(),
                txs,
                tx_results.execution_results,
                TransactionBalancesSet::new(
                    std::mem::take(&mut pre_balance_info.native),
                    post_balances,
                ),
                TransactionTokenBalancesSet::new(
                    std::mem::take(&mut pre_balance_info.token),
                    post_token_balances,
                ),
                tx_results.rent_debits,
                batch_transaction_indexes,
            );
        }
    }

    fn execute_and_commit_transactions_locked(
        bank: &Arc<Bank>,
        poh: &TransactionRecorder,
        batch: &TransactionBatch,
        transaction_status_sender: &Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        log_messages_bytes_limit: Option<usize>,
    ) -> ExecuteAndCommitTransactionsOutput {
        let mut execute_and_commit_timings = LeaderExecuteAndCommitTimings::default();

        let mut pre_balance_info = PreBalanceInfo::default();
        let (_, collect_balances_time) = measure!(
            {
                // If the extra meta-data services are enabled for RPC, collect the
                // pre-balances for native and token programs.
                if transaction_status_sender.is_some() {
                    pre_balance_info.native = bank.collect_balances(batch);
                    pre_balance_info.token =
                        collect_token_balances(bank, batch, &mut pre_balance_info.mint_decimals)
                }
            },
            "collect_balances",
        );
        execute_and_commit_timings.collect_balances_us = collect_balances_time.as_us();

        let (load_and_execute_transactions_output, load_execute_time) = measure!(
            bank.load_and_execute_transactions(
                batch,
                MAX_PROCESSING_AGE,
                transaction_status_sender.is_some(),
                transaction_status_sender.is_some(),
                transaction_status_sender.is_some(),
                &mut execute_and_commit_timings.execute_timings,
                None, // account_overrides
                log_messages_bytes_limit
            ),
            "load_execute",
        );
        execute_and_commit_timings.load_execute_us = load_execute_time.as_us();

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
        let (executed_transactions, execution_results_to_transactions_time): (Vec<_>, Measure) = measure!(
            execution_results
                .iter()
                .zip(batch.sanitized_transactions())
                .filter_map(|(execution_result, tx)| {
                    if execution_result.was_executed() {
                        Some(tx.to_versioned_transaction())
                    } else {
                        None
                    }
                })
                .collect(),
            "execution_results_to_transactions",
        );

        let (freeze_lock, freeze_lock_time) = measure!(bank.freeze_lock(), "freeze_lock");
        execute_and_commit_timings.freeze_lock_us = freeze_lock_time.as_us();

        let (record_transactions_summary, record_time) = measure!(
            Self::record_transactions(bank.slot(), executed_transactions, poh),
            "record_transactions",
        );
        execute_and_commit_timings.record_us = record_time.as_us();

        let RecordTransactionsSummary {
            result: record_transactions_result,
            record_transactions_timings,
            starting_transaction_index,
        } = record_transactions_summary;
        execute_and_commit_timings.record_transactions_timings = RecordTransactionsTimings {
            execution_results_to_transactions_us: execution_results_to_transactions_time.as_us(),
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
            Self::commit_transactions(
                batch,
                &mut loaded_transactions,
                execution_results,
                sanitized_txs,
                starting_transaction_index,
                bank,
                &mut pre_balance_info,
                &mut execute_and_commit_timings,
                transaction_status_sender,
                gossip_vote_sender,
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
            load_execute_time.as_us(),
            record_time.as_us(),
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

    pub fn process_and_record_transactions(
        bank: &Arc<Bank>,
        txs: &[SanitizedTransaction],
        poh: &TransactionRecorder,
        chunk_offset: usize,
        transaction_status_sender: &Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        qos_service: &QosService,
        log_messages_bytes_limit: Option<usize>,
    ) -> ProcessTransactionBatchOutput {
        let (
            (transaction_costs, transactions_qos_results, cost_model_throttled_transactions_count),
            cost_model_time,
        ) = measure!(qos_service.select_and_accumulate_transaction_costs(bank, txs));

        // Only lock accounts for those transactions are selected for the block;
        // Once accounts are locked, other threads cannot encode transactions that will modify the
        // same account state
        let (batch, lock_time) = measure!(
            bank.prepare_sanitized_batch_with_results(txs, transactions_qos_results.iter())
        );

        // retryable_txs includes AccountInUse, WouldExceedMaxBlockCostLimit
        // WouldExceedMaxAccountCostLimit, WouldExceedMaxVoteCostLimit
        // and WouldExceedMaxAccountDataCostLimit
        let mut execute_and_commit_transactions_output =
            Self::execute_and_commit_transactions_locked(
                bank,
                poh,
                &batch,
                transaction_status_sender,
                gossip_vote_sender,
                log_messages_bytes_limit,
            );

        // Once the accounts are new transactions can enter the pipeline to process them
        let (_, unlock_time) = measure!(drop(batch));

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
        qos_service.accumulate_actual_execute_cu(cu);
        qos_service.accumulate_actual_execute_time(us);

        // reports qos service stats for this batch
        qos_service.report_metrics(bank.clone());

        debug!(
            "bank: {} lock: {}us unlock: {}us txs_len: {}",
            bank.slot(),
            lock_time.as_us(),
            unlock_time.as_us(),
            txs.len(),
        );

        ProcessTransactionBatchOutput {
            cost_model_throttled_transactions_count,
            cost_model_us: cost_model_time.as_us(),
            execute_and_commit_transactions_output,
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

    /// Sends transactions to the bank.
    ///
    /// Returns the number of transactions successfully processed by the bank, which may be less
    /// than the total number if max PoH height was reached and the bank halted
    fn process_transactions(
        bank: &Arc<Bank>,
        bank_creation_time: &Instant,
        transactions: &[SanitizedTransaction],
        poh: &TransactionRecorder,
        transaction_status_sender: &Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        qos_service: &QosService,
        log_messages_bytes_limit: Option<usize>,
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
            let process_transaction_batch_output = Self::process_and_record_transactions(
                bank,
                &transactions[chunk_start..chunk_end],
                poh,
                chunk_start,
                transaction_status_sender,
                gossip_vote_sender,
                qos_service,
                log_messages_bytes_limit,
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
        }
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
            transactions,
            &filter,
            FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET,
        );

        Self::filter_valid_transaction_indexes(&results)
    }

    #[allow(clippy::too_many_arguments)]
    fn process_packets_transactions<'a>(
        bank: &'a Arc<Bank>,
        bank_creation_time: &Instant,
        poh: &'a TransactionRecorder,
        sanitized_transactions: &[SanitizedTransaction],
        transaction_status_sender: &Option<TransactionStatusSender>,
        gossip_vote_sender: &'a ReplayVoteSender,
        banking_stage_stats: &'a BankingStageStats,
        qos_service: &'a QosService,
        slot_metrics_tracker: &'a mut LeaderSlotMetricsTracker,
        log_messages_bytes_limit: Option<usize>,
    ) -> ProcessTransactionsSummary {
        // Process transactions
        let (mut process_transactions_summary, process_transactions_time) = measure!(
            Self::process_transactions(
                bank,
                bank_creation_time,
                sanitized_transactions,
                poh,
                transaction_status_sender,
                gossip_vote_sender,
                qos_service,
                log_messages_bytes_limit,
            ),
            "process_transaction_time",
        );
        let process_transactions_us = process_transactions_time.as_us();
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
        let (filtered_retryable_transaction_indexes, filter_retryable_packets_time) = measure!(
            Self::filter_pending_packets_from_pending_txs(
                bank,
                sanitized_transactions,
                retryable_transaction_indexes,
            ),
            "filter_pending_packets_time",
        );
        let filter_retryable_packets_us = filter_retryable_packets_time.as_us();
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

    #[allow(clippy::too_many_arguments)]
    /// Receive incoming packets, push into unprocessed buffer with packet indexes
    fn receive_and_buffer_packets(
        packet_deserializer: &mut PacketDeserializer,
        recv_start: &mut Instant,
        recv_timeout: Duration,
        id: u32,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        banking_stage_stats: &mut BankingStageStats,
        tracer_packet_stats: &mut TracerPacketStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) -> Result<(), RecvTimeoutError> {
        let mut recv_time = Measure::start("receive_and_buffer_packets_recv");
        let ReceivePacketResults {
            deserialized_packets,
            new_tracer_stats_option,
            passed_sigverify_count,
            failed_sigverify_count,
        } = packet_deserializer.handle_received_packets(
            recv_timeout,
            unprocessed_transaction_storage.max_receive_size(),
        )?;
        let packet_count = deserialized_packets.len();
        debug!(
            "@{:?} process start stalled for: {:?}ms txs: {} id: {}",
            timestamp(),
            duration_as_ms(&recv_start.elapsed()),
            packet_count,
            id,
        );

        if let Some(new_sigverify_stats) = &new_tracer_stats_option {
            tracer_packet_stats.aggregate_sigverify_tracer_packet_stats(new_sigverify_stats);
        }

        // Track all the packets incoming from sigverify, both valid and invalid
        slot_metrics_tracker.increment_total_new_valid_packets(passed_sigverify_count);
        slot_metrics_tracker.increment_newly_failed_sigverify_count(failed_sigverify_count);

        let mut dropped_packets_count = 0;
        let mut newly_buffered_packets_count = 0;
        Self::push_unprocessed(
            unprocessed_transaction_storage,
            deserialized_packets,
            &mut dropped_packets_count,
            &mut newly_buffered_packets_count,
            banking_stage_stats,
            slot_metrics_tracker,
            tracer_packet_stats,
        );
        recv_time.stop();

        banking_stage_stats
            .receive_and_buffer_packets_elapsed
            .fetch_add(recv_time.as_us(), Ordering::Relaxed);
        banking_stage_stats
            .receive_and_buffer_packets_count
            .fetch_add(packet_count, Ordering::Relaxed);
        banking_stage_stats
            .dropped_packets_count
            .fetch_add(dropped_packets_count, Ordering::Relaxed);
        banking_stage_stats
            .newly_buffered_packets_count
            .fetch_add(newly_buffered_packets_count, Ordering::Relaxed);
        banking_stage_stats
            .current_buffered_packets_count
            .swap(unprocessed_transaction_storage.len(), Ordering::Relaxed);
        *recv_start = Instant::now();
        Ok(())
    }

    fn push_unprocessed(
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        deserialized_packets: Vec<ImmutableDeserializedPacket>,
        dropped_packets_count: &mut usize,
        newly_buffered_packets_count: &mut usize,
        banking_stage_stats: &mut BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        tracer_packet_stats: &mut TracerPacketStats,
    ) {
        if !deserialized_packets.is_empty() {
            let _ = banking_stage_stats
                .batch_packet_indexes_len
                .increment(deserialized_packets.len() as u64);

            *newly_buffered_packets_count += deserialized_packets.len();
            slot_metrics_tracker
                .increment_newly_buffered_packets_count(deserialized_packets.len() as u64);

            let insert_packet_batches_summary =
                unprocessed_transaction_storage.insert_batch(deserialized_packets);
            slot_metrics_tracker
                .accumulate_insert_packet_batches_summary(&insert_packet_batches_summary);
            saturating_add_assign!(
                *dropped_packets_count,
                insert_packet_batches_summary.total_dropped_packets()
            );
            tracer_packet_stats.increment_total_exceeded_banking_stage_buffer(
                insert_packet_batches_summary.dropped_tracer_packets(),
            );
        }
    }

    pub fn join(self) -> thread::Result<()> {
        for bank_thread_hdl in self.bank_thread_hdls {
            bank_thread_hdl.join()?;
        }
        Ok(())
    }
}

pub(crate) fn next_leader_tpu(
    cluster_info: &ClusterInfo,
    poh_recorder: &RwLock<PohRecorder>,
) -> Option<(Pubkey, std::net::SocketAddr)> {
    next_leader_x(cluster_info, poh_recorder, |leader| leader.tpu)
}

fn next_leader_tpu_forwards(
    cluster_info: &ClusterInfo,
    poh_recorder: &RwLock<PohRecorder>,
) -> Option<(Pubkey, std::net::SocketAddr)> {
    next_leader_x(cluster_info, poh_recorder, |leader| leader.tpu_forwards)
}

pub(crate) fn next_leader_tpu_vote(
    cluster_info: &ClusterInfo,
    poh_recorder: &RwLock<PohRecorder>,
) -> Option<(Pubkey, std::net::SocketAddr)> {
    next_leader_x(cluster_info, poh_recorder, |leader| leader.tpu_vote)
}

fn next_leader_x<F>(
    cluster_info: &ClusterInfo,
    poh_recorder: &RwLock<PohRecorder>,
    port_selector: F,
) -> Option<(Pubkey, std::net::SocketAddr)>
where
    F: FnOnce(&ContactInfo) -> SocketAddr,
{
    let leader_pubkey = poh_recorder
        .read()
        .unwrap()
        .leader_after_n_slots(FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET);
    if let Some(leader_pubkey) = leader_pubkey {
        cluster_info
            .lookup_contact_info(&leader_pubkey, port_selector)
            .map(|addr| (leader_pubkey, addr))
    } else {
        None
    }
}
