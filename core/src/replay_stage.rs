//! The `replay_stage` replays transactions broadcast by the leader.

use {
    crate::{
        banking_trace::BankingTracer,
        cache_block_meta_service::CacheBlockMetaSender,
        cluster_info_vote_listener::{
            DuplicateConfirmedSlotsReceiver, GossipVerifiedVoteHashReceiver, VoteTracker,
        },
        cluster_slots_service::{cluster_slots::ClusterSlots, ClusterSlotsUpdateSender},
        commitment_service::{AggregateCommitmentService, CommitmentAggregationData},
        consensus::{
            fork_choice::{ForkChoice, SelectVoteAndResetForkResult},
            heaviest_subtree_fork_choice::HeaviestSubtreeForkChoice,
            latest_validator_votes_for_frozen_banks::LatestValidatorVotesForFrozenBanks,
            progress_map::{ForkProgress, ProgressMap, PropagatedStats},
            tower_storage::{SavedTower, SavedTowerVersions, TowerStorage},
            BlockhashStatus, ComputedBankState, Stake, SwitchForkDecision, ThresholdDecision,
            Tower, TowerError, VotedStakes, SWITCH_FORK_THRESHOLD,
        },
        cost_update_service::CostUpdate,
        repair::{
            ancestor_hashes_service::AncestorHashesReplayUpdateSender,
            cluster_slot_state_verifier::*,
            duplicate_repair_status::AncestorDuplicateSlotToRepair,
            repair_service::{
                AncestorDuplicateSlotsReceiver, DumpedSlotsSender, PopularPrunedForksReceiver,
            },
        },
        rewards_recorder_service::{RewardsMessage, RewardsRecorderSender},
        unfrozen_gossip_verified_vote_hashes::UnfrozenGossipVerifiedVoteHashes,
        voting_service::VoteOp,
        window_service::DuplicateSlotReceiver,
    },
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender},
    rayon::{prelude::*, ThreadPool},
    solana_entry::entry::VerifyRecyclers,
    solana_geyser_plugin_manager::block_metadata_notifier_interface::BlockMetadataNotifierArc,
    solana_gossip::cluster_info::ClusterInfo,
    solana_ledger::{
        block_error::BlockError,
        blockstore::Blockstore,
        blockstore_processor::{
            self, BlockstoreProcessorError, ConfirmationProgress, ExecuteBatchesInternalMetrics,
            ReplaySlotStats, TransactionStatusSender,
        },
        entry_notifier_service::EntryNotifierSender,
        leader_schedule_cache::LeaderScheduleCache,
        leader_schedule_utils::first_of_consecutive_leader_slots,
    },
    solana_measure::measure::Measure,
    solana_poh::poh_recorder::{PohLeaderStatus, PohRecorder, GRACE_TICKS_FACTOR, MAX_GRACE_SLOTS},
    solana_program_runtime::timings::ExecuteTimings,
    solana_rpc::{
        optimistically_confirmed_bank_tracker::{BankNotification, BankNotificationSenderConfig},
        rpc_subscriptions::RpcSubscriptions,
    },
    solana_rpc_client_api::response::SlotUpdate,
    solana_runtime::{
        accounts_background_service::AbsRequestSender,
        bank::{bank_hash_details, Bank, NewBankOptions},
        bank_forks::{BankForks, SetRootError, MAX_ROOT_DISTANCE_FOR_VOTE_ONLY},
        commitment::BlockCommitmentCache,
        installed_scheduler_pool::BankWithScheduler,
        prioritization_fee_cache::PrioritizationFeeCache,
        vote_sender_types::ReplayVoteSender,
    },
    solana_sdk::{
        clock::{BankId, Slot, MAX_PROCESSING_AGE, NUM_CONSECUTIVE_LEADER_SLOTS},
        feature_set,
        genesis_config::ClusterType,
        hash::Hash,
        pubkey::Pubkey,
        saturating_add_assign,
        signature::{Keypair, Signature, Signer},
        timing::timestamp,
        transaction::Transaction,
    },
    solana_vote_program::vote_state::VoteTransaction,
    std::{
        collections::{HashMap, HashSet},
        num::NonZeroUsize,
        result,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

pub const MAX_ENTRY_RECV_PER_ITER: usize = 512;
pub const SUPERMINORITY_THRESHOLD: f64 = 1f64 / 3f64;
pub const MAX_UNCONFIRMED_SLOTS: usize = 5;
pub const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

const MAX_VOTE_SIGNATURES: usize = 200;
const MAX_VOTE_REFRESH_INTERVAL_MILLIS: usize = 5000;
const MAX_REPAIR_RETRY_LOOP_ATTEMPTS: usize = 10;

#[derive(PartialEq, Eq, Debug)]
pub enum HeaviestForkFailures {
    LockedOut(u64),
    FailedThreshold(
        Slot,
        /* vote depth */ u64,
        /* Observed stake */ u64,
        /* Total stake */ u64,
    ),
    FailedSwitchThreshold(
        Slot,
        /* Observed stake */ u64,
        /* Total stake */ u64,
    ),
    NoPropagatedConfirmation(
        Slot,
        /* Observed stake */ u64,
        /* Total stake */ u64,
    ),
}

enum ForkReplayMode {
    Serial,
    Parallel(ThreadPool),
}

#[derive(PartialEq, Eq, Debug)]
enum ConfirmationType {
    SupermajorityVoted,
    DuplicateConfirmed,
}

enum GenerateVoteTxResult {
    // non voting validator, not eligible for refresh
    NonVoting,
    // failed generation, eligible for refresh
    Failed,
    Tx(Transaction),
}

impl GenerateVoteTxResult {
    fn is_non_voting(&self) -> bool {
        matches!(self, Self::NonVoting)
    }
}

#[derive(PartialEq, Eq, Debug)]
struct ConfirmedSlot {
    slot: Slot,
    frozen_hash: Hash,
    confirmation_type: ConfirmationType,
}

impl ConfirmedSlot {
    fn new_supermajority_voted(slot: Slot, frozen_hash: Hash) -> Self {
        Self {
            slot,
            frozen_hash,
            confirmation_type: ConfirmationType::SupermajorityVoted,
        }
    }

    fn new_duplicate_confirmed_slot(slot: Slot, frozen_hash: Hash) -> Self {
        Self {
            slot,
            frozen_hash,
            confirmation_type: ConfirmationType::DuplicateConfirmed,
        }
    }
}

// Implement a destructor for the ReplayStage thread to signal it exited
// even on panics
struct Finalizer {
    exit_sender: Arc<AtomicBool>,
}

impl Finalizer {
    fn new(exit_sender: Arc<AtomicBool>) -> Self {
        Finalizer { exit_sender }
    }
}

// Implement a destructor for Finalizer.
impl Drop for Finalizer {
    fn drop(&mut self) {
        self.exit_sender.clone().store(true, Ordering::Relaxed);
    }
}

struct ReplaySlotFromBlockstore {
    is_slot_dead: bool,
    bank_slot: Slot,
    replay_result: Option<Result<usize /* tx count */, BlockstoreProcessorError>>,
}

struct LastVoteRefreshTime {
    last_refresh_time: Instant,
    last_print_time: Instant,
}

#[derive(Default)]
struct SkippedSlotsInfo {
    last_retransmit_slot: u64,
    last_skipped_slot: u64,
}

struct PartitionInfo {
    partition_start_time: Option<Instant>,
}

impl PartitionInfo {
    fn new() -> Self {
        Self {
            partition_start_time: None,
        }
    }

    fn update(
        &mut self,
        partition_detected: bool,
        heaviest_slot: Slot,
        last_voted_slot: Slot,
        reset_bank_slot: Slot,
        heaviest_fork_failures: Vec<HeaviestForkFailures>,
    ) {
        if self.partition_start_time.is_none() && partition_detected {
            warn!("PARTITION DETECTED waiting to join heaviest fork: {} last vote: {:?}, reset slot: {}",
                heaviest_slot,
                last_voted_slot,
                reset_bank_slot,
            );
            datapoint_info!(
                "replay_stage-partition-start",
                ("heaviest_slot", heaviest_slot as i64, i64),
                ("last_vote_slot", last_voted_slot as i64, i64),
                ("reset_slot", reset_bank_slot as i64, i64),
                (
                    "heaviest_fork_failure_first",
                    format!("{:?}", heaviest_fork_failures.first()),
                    String
                ),
                (
                    "heaviest_fork_failure_second",
                    format!("{:?}", heaviest_fork_failures.get(1)),
                    String
                ),
            );
            self.partition_start_time = Some(Instant::now());
        } else if self.partition_start_time.is_some() && !partition_detected {
            warn!(
                "PARTITION resolved heaviest fork: {} last vote: {:?}, reset slot: {}",
                heaviest_slot, last_voted_slot, reset_bank_slot
            );
            datapoint_info!(
                "replay_stage-partition-resolved",
                ("heaviest_slot", heaviest_slot as i64, i64),
                ("last_vote_slot", last_voted_slot as i64, i64),
                ("reset_slot", reset_bank_slot as i64, i64),
                (
                    "partition_duration_ms",
                    self.partition_start_time.unwrap().elapsed().as_millis() as i64,
                    i64
                ),
            );
            self.partition_start_time = None;
        }
    }
}

pub struct ReplayStageConfig {
    pub vote_account: Pubkey,
    pub authorized_voter_keypairs: Arc<RwLock<Vec<Arc<Keypair>>>>,
    pub exit: Arc<AtomicBool>,
    pub rpc_subscriptions: Arc<RpcSubscriptions>,
    pub leader_schedule_cache: Arc<LeaderScheduleCache>,
    pub accounts_background_request_sender: AbsRequestSender,
    pub block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
    pub transaction_status_sender: Option<TransactionStatusSender>,
    pub rewards_recorder_sender: Option<RewardsRecorderSender>,
    pub cache_block_meta_sender: Option<CacheBlockMetaSender>,
    pub entry_notification_sender: Option<EntryNotifierSender>,
    pub bank_notification_sender: Option<BankNotificationSenderConfig>,
    pub wait_for_vote_to_start_leader: bool,
    pub ancestor_hashes_replay_update_sender: AncestorHashesReplayUpdateSender,
    pub tower_storage: Arc<dyn TowerStorage>,
    // Stops voting until this slot has been reached. Should be used to avoid
    // duplicate voting which can lead to slashing.
    pub wait_to_vote_slot: Option<Slot>,
    pub replay_forks_threads: NonZeroUsize,
    pub replay_transactions_threads: NonZeroUsize,
}

/// Timing information for the ReplayStage main processing loop
#[derive(Default)]
struct ReplayLoopTiming {
    last_submit: u64,
    loop_count: u64,
    collect_frozen_banks_elapsed_us: u64,
    compute_bank_stats_elapsed_us: u64,
    select_vote_and_reset_forks_elapsed_us: u64,
    start_leader_elapsed_us: u64,
    reset_bank_elapsed_us: u64,
    voting_elapsed_us: u64,
    generate_vote_us: u64,
    update_commitment_cache_us: u64,
    select_forks_elapsed_us: u64,
    compute_slot_stats_elapsed_us: u64,
    generate_new_bank_forks_elapsed_us: u64,
    replay_active_banks_elapsed_us: u64,
    wait_receive_elapsed_us: u64,
    heaviest_fork_failures_elapsed_us: u64,
    bank_count: u64,
    process_ancestor_hashes_duplicate_slots_elapsed_us: u64,
    process_duplicate_confirmed_slots_elapsed_us: u64,
    process_duplicate_slots_elapsed_us: u64,
    process_unfrozen_gossip_verified_vote_hashes_elapsed_us: u64,
    process_popular_pruned_forks_elapsed_us: u64,
    repair_correct_slots_elapsed_us: u64,
    retransmit_not_propagated_elapsed_us: u64,
    generate_new_bank_forks_read_lock_us: u64,
    generate_new_bank_forks_get_slots_since_us: u64,
    generate_new_bank_forks_loop_us: u64,
    generate_new_bank_forks_write_lock_us: u64,
    // When processing multiple forks concurrently, only captures the longest fork
    replay_blockstore_us: u64,
}
impl ReplayLoopTiming {
    #[allow(clippy::too_many_arguments)]
    fn update(
        &mut self,
        collect_frozen_banks_elapsed_us: u64,
        compute_bank_stats_elapsed_us: u64,
        select_vote_and_reset_forks_elapsed_us: u64,
        start_leader_elapsed_us: u64,
        reset_bank_elapsed_us: u64,
        voting_elapsed_us: u64,
        select_forks_elapsed_us: u64,
        compute_slot_stats_elapsed_us: u64,
        generate_new_bank_forks_elapsed_us: u64,
        replay_active_banks_elapsed_us: u64,
        wait_receive_elapsed_us: u64,
        heaviest_fork_failures_elapsed_us: u64,
        bank_count: u64,
        process_ancestor_hashes_duplicate_slots_elapsed_us: u64,
        process_duplicate_confirmed_slots_elapsed_us: u64,
        process_unfrozen_gossip_verified_vote_hashes_elapsed_us: u64,
        process_popular_pruned_forks_elapsed_us: u64,
        process_duplicate_slots_elapsed_us: u64,
        repair_correct_slots_elapsed_us: u64,
        retransmit_not_propagated_elapsed_us: u64,
    ) {
        self.loop_count += 1;
        self.collect_frozen_banks_elapsed_us += collect_frozen_banks_elapsed_us;
        self.compute_bank_stats_elapsed_us += compute_bank_stats_elapsed_us;
        self.select_vote_and_reset_forks_elapsed_us += select_vote_and_reset_forks_elapsed_us;
        self.start_leader_elapsed_us += start_leader_elapsed_us;
        self.reset_bank_elapsed_us += reset_bank_elapsed_us;
        self.voting_elapsed_us += voting_elapsed_us;
        self.select_forks_elapsed_us += select_forks_elapsed_us;
        self.compute_slot_stats_elapsed_us += compute_slot_stats_elapsed_us;
        self.generate_new_bank_forks_elapsed_us += generate_new_bank_forks_elapsed_us;
        self.replay_active_banks_elapsed_us += replay_active_banks_elapsed_us;
        self.wait_receive_elapsed_us += wait_receive_elapsed_us;
        self.heaviest_fork_failures_elapsed_us += heaviest_fork_failures_elapsed_us;
        self.bank_count += bank_count;
        self.process_ancestor_hashes_duplicate_slots_elapsed_us +=
            process_ancestor_hashes_duplicate_slots_elapsed_us;
        self.process_duplicate_confirmed_slots_elapsed_us +=
            process_duplicate_confirmed_slots_elapsed_us;
        self.process_unfrozen_gossip_verified_vote_hashes_elapsed_us +=
            process_unfrozen_gossip_verified_vote_hashes_elapsed_us;
        self.process_popular_pruned_forks_elapsed_us += process_popular_pruned_forks_elapsed_us;
        self.process_duplicate_slots_elapsed_us += process_duplicate_slots_elapsed_us;
        self.repair_correct_slots_elapsed_us += repair_correct_slots_elapsed_us;
        self.retransmit_not_propagated_elapsed_us += retransmit_not_propagated_elapsed_us;

        self.maybe_submit();
    }

    fn maybe_submit(&mut self) {
        let now = timestamp();
        let elapsed_ms = now - self.last_submit;

        if elapsed_ms > 1000 {
            datapoint_info!(
                "replay-loop-voting-stats",
                ("generate_vote_us", self.generate_vote_us, i64),
                (
                    "update_commitment_cache_us",
                    self.update_commitment_cache_us,
                    i64
                ),
            );
            datapoint_info!(
                "replay-loop-timing-stats",
                ("loop_count", self.loop_count as i64, i64),
                ("total_elapsed_us", elapsed_ms * 1000, i64),
                (
                    "collect_frozen_banks_elapsed_us",
                    self.collect_frozen_banks_elapsed_us as i64,
                    i64
                ),
                (
                    "compute_bank_stats_elapsed_us",
                    self.compute_bank_stats_elapsed_us as i64,
                    i64
                ),
                (
                    "select_vote_and_reset_forks_elapsed_us",
                    self.select_vote_and_reset_forks_elapsed_us as i64,
                    i64
                ),
                (
                    "start_leader_elapsed_us",
                    self.start_leader_elapsed_us as i64,
                    i64
                ),
                (
                    "reset_bank_elapsed_us",
                    self.reset_bank_elapsed_us as i64,
                    i64
                ),
                ("voting_elapsed_us", self.voting_elapsed_us as i64, i64),
                (
                    "select_forks_elapsed_us",
                    self.select_forks_elapsed_us as i64,
                    i64
                ),
                (
                    "compute_slot_stats_elapsed_us",
                    self.compute_slot_stats_elapsed_us as i64,
                    i64
                ),
                (
                    "generate_new_bank_forks_elapsed_us",
                    self.generate_new_bank_forks_elapsed_us as i64,
                    i64
                ),
                (
                    "replay_active_banks_elapsed_us",
                    self.replay_active_banks_elapsed_us as i64,
                    i64
                ),
                (
                    "process_ancestor_hashes_duplicate_slots_elapsed_us",
                    self.process_ancestor_hashes_duplicate_slots_elapsed_us as i64,
                    i64
                ),
                (
                    "process_duplicate_confirmed_slots_elapsed_us",
                    self.process_duplicate_confirmed_slots_elapsed_us as i64,
                    i64
                ),
                (
                    "process_unfrozen_gossip_verified_vote_hashes_elapsed_us",
                    self.process_unfrozen_gossip_verified_vote_hashes_elapsed_us as i64,
                    i64
                ),
                (
                    "process_popular_pruned_forks_elapsed_us",
                    self.process_popular_pruned_forks_elapsed_us as i64,
                    i64
                ),
                (
                    "wait_receive_elapsed_us",
                    self.wait_receive_elapsed_us as i64,
                    i64
                ),
                (
                    "heaviest_fork_failures_elapsed_us",
                    self.heaviest_fork_failures_elapsed_us as i64,
                    i64
                ),
                ("bank_count", self.bank_count as i64, i64),
                (
                    "process_duplicate_slots_elapsed_us",
                    self.process_duplicate_slots_elapsed_us as i64,
                    i64
                ),
                (
                    "repair_correct_slots_elapsed_us",
                    self.repair_correct_slots_elapsed_us as i64,
                    i64
                ),
                (
                    "retransmit_not_propagated_elapsed_us",
                    self.retransmit_not_propagated_elapsed_us as i64,
                    i64
                ),
                (
                    "generate_new_bank_forks_read_lock_us",
                    self.generate_new_bank_forks_read_lock_us as i64,
                    i64
                ),
                (
                    "generate_new_bank_forks_get_slots_since_us",
                    self.generate_new_bank_forks_get_slots_since_us as i64,
                    i64
                ),
                (
                    "generate_new_bank_forks_loop_us",
                    self.generate_new_bank_forks_loop_us as i64,
                    i64
                ),
                (
                    "generate_new_bank_forks_write_lock_us",
                    self.generate_new_bank_forks_write_lock_us as i64,
                    i64
                ),
                (
                    "replay_blockstore_us",
                    self.replay_blockstore_us as i64,
                    i64
                ),
            );
            *self = ReplayLoopTiming::default();
            self.last_submit = now;
        }
    }
}

pub struct ReplayStage {
    t_replay: JoinHandle<()>,
    commitment_service: AggregateCommitmentService,
}

impl ReplayStage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: ReplayStageConfig,
        blockstore: Arc<Blockstore>,
        bank_forks: Arc<RwLock<BankForks>>,
        cluster_info: Arc<ClusterInfo>,
        ledger_signal_receiver: Receiver<bool>,
        duplicate_slots_receiver: DuplicateSlotReceiver,
        poh_recorder: Arc<RwLock<PohRecorder>>,
        mut tower: Tower,
        vote_tracker: Arc<VoteTracker>,
        cluster_slots: Arc<ClusterSlots>,
        retransmit_slots_sender: Sender<Slot>,
        ancestor_duplicate_slots_receiver: AncestorDuplicateSlotsReceiver,
        replay_vote_sender: ReplayVoteSender,
        duplicate_confirmed_slots_receiver: DuplicateConfirmedSlotsReceiver,
        gossip_verified_vote_hash_receiver: GossipVerifiedVoteHashReceiver,
        cluster_slots_update_sender: ClusterSlotsUpdateSender,
        cost_update_sender: Sender<CostUpdate>,
        voting_sender: Sender<VoteOp>,
        drop_bank_sender: Sender<Vec<BankWithScheduler>>,
        block_metadata_notifier: Option<BlockMetadataNotifierArc>,
        log_messages_bytes_limit: Option<usize>,
        prioritization_fee_cache: Arc<PrioritizationFeeCache>,
        dumped_slots_sender: DumpedSlotsSender,
        banking_tracer: Arc<BankingTracer>,
        popular_pruned_forks_receiver: PopularPrunedForksReceiver,
    ) -> Result<Self, String> {
        let ReplayStageConfig {
            vote_account,
            authorized_voter_keypairs,
            exit,
            rpc_subscriptions,
            leader_schedule_cache,
            accounts_background_request_sender,
            block_commitment_cache,
            transaction_status_sender,
            rewards_recorder_sender,
            cache_block_meta_sender,
            entry_notification_sender,
            bank_notification_sender,
            wait_for_vote_to_start_leader,
            ancestor_hashes_replay_update_sender,
            tower_storage,
            wait_to_vote_slot,
            replay_forks_threads,
            replay_transactions_threads,
        } = config;

        trace!("replay stage");
        // Start the replay stage loop
        let (lockouts_sender, commitment_service) = AggregateCommitmentService::new(
            exit.clone(),
            block_commitment_cache.clone(),
            rpc_subscriptions.clone(),
        );
        let run_replay = move || {
            let verify_recyclers = VerifyRecyclers::default();
            let _exit = Finalizer::new(exit.clone());
            let mut identity_keypair = cluster_info.keypair().clone();
            let mut my_pubkey = identity_keypair.pubkey();
            if my_pubkey != tower.node_pubkey {
                // set-identity was called during the startup procedure, ensure the tower is consistent
                // before starting the loop. further calls to set-identity will reload the tower in the loop
                let my_old_pubkey = tower.node_pubkey;
                tower = match Self::load_tower(
                    tower_storage.as_ref(),
                    &my_pubkey,
                    &vote_account,
                    &bank_forks,
                ) {
                    Ok(tower) => tower,
                    Err(err) => {
                        error!(
                            "Unable to load new tower when attempting to change identity from {} to {} on
                            ReplayStage startup, Exiting: {}",
                            my_old_pubkey,
                            my_pubkey,
                            err
                        );
                        // drop(_exit) will set the exit flag, eventually tearing down the entire process
                        return;
                    }
                };
                warn!(
                    "Identity changed during startup from {} to {}",
                    my_old_pubkey, my_pubkey
                );
            }
            let (mut progress, mut heaviest_subtree_fork_choice) =
                Self::initialize_progress_and_fork_choice_with_locked_bank_forks(
                    &bank_forks,
                    &my_pubkey,
                    &vote_account,
                    &blockstore,
                );
            let mut current_leader = None;
            let mut last_reset = Hash::default();
            let mut last_reset_bank_descendants = Vec::new();
            let mut partition_info = PartitionInfo::new();
            let mut skipped_slots_info = SkippedSlotsInfo::default();
            let mut replay_timing = ReplayLoopTiming::default();
            let mut duplicate_slots_tracker = DuplicateSlotsTracker::default();
            let mut duplicate_confirmed_slots: DuplicateConfirmedSlots =
                DuplicateConfirmedSlots::default();
            let mut epoch_slots_frozen_slots: EpochSlotsFrozenSlots =
                EpochSlotsFrozenSlots::default();
            let mut duplicate_slots_to_repair = DuplicateSlotsToRepair::default();
            let mut purge_repair_slot_counter = PurgeRepairSlotCounter::default();
            let mut unfrozen_gossip_verified_vote_hashes: UnfrozenGossipVerifiedVoteHashes =
                UnfrozenGossipVerifiedVoteHashes::default();
            let mut latest_validator_votes_for_frozen_banks: LatestValidatorVotesForFrozenBanks =
                LatestValidatorVotesForFrozenBanks::default();
            let mut voted_signatures = Vec::new();
            let mut has_new_vote_been_rooted = !wait_for_vote_to_start_leader;
            let mut last_vote_refresh_time = LastVoteRefreshTime {
                last_refresh_time: Instant::now(),
                last_print_time: Instant::now(),
            };
            let (working_bank, in_vote_only_mode) = {
                let r_bank_forks = bank_forks.read().unwrap();
                (
                    r_bank_forks.working_bank(),
                    r_bank_forks.get_vote_only_mode_signal(),
                )
            };
            let mut last_threshold_failure_slot = 0;
            // Thread pool to (maybe) replay multiple threads in parallel
            let replay_mode = if replay_forks_threads.get() == 1 {
                ForkReplayMode::Serial
            } else {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(replay_forks_threads.get())
                    .thread_name(|i| format!("solReplayFork{i:02}"))
                    .build()
                    .expect("new rayon threadpool");
                ForkReplayMode::Parallel(pool)
            };
            // Thread pool to replay multiple transactions within one block in parallel
            let replay_tx_thread_pool = rayon::ThreadPoolBuilder::new()
                .num_threads(replay_transactions_threads.get())
                .thread_name(|i| format!("solReplayTx{i:02}"))
                .build()
                .expect("new rayon threadpool");

            Self::reset_poh_recorder(
                &my_pubkey,
                &blockstore,
                working_bank,
                &poh_recorder,
                &leader_schedule_cache,
            );

            loop {
                // Stop getting entries if we get exit signal
                if exit.load(Ordering::Relaxed) {
                    break;
                }

                let mut generate_new_bank_forks_time =
                    Measure::start("generate_new_bank_forks_time");
                Self::generate_new_bank_forks(
                    &blockstore,
                    &bank_forks,
                    &leader_schedule_cache,
                    &rpc_subscriptions,
                    &mut progress,
                    &mut replay_timing,
                );
                generate_new_bank_forks_time.stop();

                let mut tpu_has_bank = poh_recorder.read().unwrap().has_bank();

                let mut replay_active_banks_time = Measure::start("replay_active_banks_time");
                let (mut ancestors, mut descendants) = {
                    let r_bank_forks = bank_forks.read().unwrap();
                    (r_bank_forks.ancestors(), r_bank_forks.descendants())
                };
                let did_complete_bank = Self::replay_active_banks(
                    &blockstore,
                    &bank_forks,
                    &my_pubkey,
                    &vote_account,
                    &mut progress,
                    transaction_status_sender.as_ref(),
                    cache_block_meta_sender.as_ref(),
                    entry_notification_sender.as_ref(),
                    &verify_recyclers,
                    &mut heaviest_subtree_fork_choice,
                    &replay_vote_sender,
                    &bank_notification_sender,
                    &rewards_recorder_sender,
                    &rpc_subscriptions,
                    &mut duplicate_slots_tracker,
                    &duplicate_confirmed_slots,
                    &mut epoch_slots_frozen_slots,
                    &mut unfrozen_gossip_verified_vote_hashes,
                    &mut latest_validator_votes_for_frozen_banks,
                    &cluster_slots_update_sender,
                    &cost_update_sender,
                    &mut duplicate_slots_to_repair,
                    &ancestor_hashes_replay_update_sender,
                    block_metadata_notifier.clone(),
                    &mut replay_timing,
                    log_messages_bytes_limit,
                    &replay_mode,
                    &replay_tx_thread_pool,
                    &prioritization_fee_cache,
                    &mut purge_repair_slot_counter,
                );
                replay_active_banks_time.stop();

                let forks_root = bank_forks.read().unwrap().root();

                // Process cluster-agreed versions of duplicate slots for which we potentially
                // have the wrong version. Our version was dead or pruned.
                // Signalled by ancestor_hashes_service.
                let mut process_ancestor_hashes_duplicate_slots_time =
                    Measure::start("process_ancestor_hashes_duplicate_slots");
                Self::process_ancestor_hashes_duplicate_slots(
                    &my_pubkey,
                    &blockstore,
                    &ancestor_duplicate_slots_receiver,
                    &mut duplicate_slots_tracker,
                    &duplicate_confirmed_slots,
                    &mut epoch_slots_frozen_slots,
                    &progress,
                    &mut heaviest_subtree_fork_choice,
                    &bank_forks,
                    &mut duplicate_slots_to_repair,
                    &ancestor_hashes_replay_update_sender,
                    &mut purge_repair_slot_counter,
                );
                process_ancestor_hashes_duplicate_slots_time.stop();

                // Check for any newly duplicate confirmed slots detected from gossip / replay
                // Note: since this is tracked using both gossip & replay votes, stake is not
                // rolled up from descendants.
                let mut process_duplicate_confirmed_slots_time =
                    Measure::start("process_duplicate_confirmed_slots");
                Self::process_duplicate_confirmed_slots(
                    &duplicate_confirmed_slots_receiver,
                    &blockstore,
                    &mut duplicate_slots_tracker,
                    &mut duplicate_confirmed_slots,
                    &mut epoch_slots_frozen_slots,
                    &bank_forks,
                    &progress,
                    &mut heaviest_subtree_fork_choice,
                    &mut duplicate_slots_to_repair,
                    &ancestor_hashes_replay_update_sender,
                    &mut purge_repair_slot_counter,
                );
                process_duplicate_confirmed_slots_time.stop();

                // Ingest any new verified votes from gossip. Important for fork choice
                // and switching proofs because these may be votes that haven't yet been
                // included in a block, so we may not have yet observed these votes just
                // by replaying blocks.
                let mut process_unfrozen_gossip_verified_vote_hashes_time =
                    Measure::start("process_gossip_verified_vote_hashes");
                Self::process_gossip_verified_vote_hashes(
                    &gossip_verified_vote_hash_receiver,
                    &mut unfrozen_gossip_verified_vote_hashes,
                    &heaviest_subtree_fork_choice,
                    &mut latest_validator_votes_for_frozen_banks,
                );
                for _ in gossip_verified_vote_hash_receiver.try_iter() {}
                process_unfrozen_gossip_verified_vote_hashes_time.stop();

                let mut process_popular_pruned_forks_time =
                    Measure::start("process_popular_pruned_forks_time");
                // Check for "popular" (52+% stake aggregated across versions/descendants) forks
                // that are pruned, which would not be detected by normal means.
                // Signalled by `repair_service`.
                Self::process_popular_pruned_forks(
                    &popular_pruned_forks_receiver,
                    &blockstore,
                    &mut duplicate_slots_tracker,
                    &mut epoch_slots_frozen_slots,
                    &bank_forks,
                    &mut heaviest_subtree_fork_choice,
                    &mut duplicate_slots_to_repair,
                    &ancestor_hashes_replay_update_sender,
                    &mut purge_repair_slot_counter,
                );
                process_popular_pruned_forks_time.stop();

                // Check to remove any duplicated slots from fork choice
                let mut process_duplicate_slots_time = Measure::start("process_duplicate_slots");
                if !tpu_has_bank {
                    Self::process_duplicate_slots(
                        &blockstore,
                        &duplicate_slots_receiver,
                        &mut duplicate_slots_tracker,
                        &duplicate_confirmed_slots,
                        &mut epoch_slots_frozen_slots,
                        &bank_forks,
                        &progress,
                        &mut heaviest_subtree_fork_choice,
                        &mut duplicate_slots_to_repair,
                        &ancestor_hashes_replay_update_sender,
                        &mut purge_repair_slot_counter,
                    );
                }
                process_duplicate_slots_time.stop();

                let mut collect_frozen_banks_time = Measure::start("frozen_banks");
                let mut frozen_banks: Vec<_> = bank_forks
                    .read()
                    .unwrap()
                    .frozen_banks()
                    .into_iter()
                    .filter(|(slot, _)| *slot >= forks_root)
                    .map(|(_, bank)| bank)
                    .collect();
                collect_frozen_banks_time.stop();

                let mut compute_bank_stats_time = Measure::start("compute_bank_stats");
                let newly_computed_slot_stats = Self::compute_bank_stats(
                    &vote_account,
                    &ancestors,
                    &mut frozen_banks,
                    &mut tower,
                    &mut progress,
                    &vote_tracker,
                    &cluster_slots,
                    &bank_forks,
                    &mut heaviest_subtree_fork_choice,
                    &mut latest_validator_votes_for_frozen_banks,
                );
                compute_bank_stats_time.stop();

                let mut compute_slot_stats_time = Measure::start("compute_slot_stats_time");
                for slot in newly_computed_slot_stats {
                    let fork_stats = progress.get_fork_stats(slot).unwrap();
                    let confirmed_slots = Self::confirm_forks(
                        &tower,
                        &fork_stats.voted_stakes,
                        fork_stats.total_stake,
                        &progress,
                        &bank_forks,
                    );

                    Self::mark_slots_confirmed(
                        &confirmed_slots,
                        &blockstore,
                        &bank_forks,
                        &mut progress,
                        &mut duplicate_slots_tracker,
                        &mut heaviest_subtree_fork_choice,
                        &mut epoch_slots_frozen_slots,
                        &mut duplicate_slots_to_repair,
                        &ancestor_hashes_replay_update_sender,
                        &mut purge_repair_slot_counter,
                        &mut duplicate_confirmed_slots,
                    );
                }
                compute_slot_stats_time.stop();

                let mut select_forks_time = Measure::start("select_forks_time");
                let (heaviest_bank, heaviest_bank_on_same_voted_fork) =
                    heaviest_subtree_fork_choice.select_forks(
                        &frozen_banks,
                        &tower,
                        &progress,
                        &ancestors,
                        &bank_forks,
                    );
                select_forks_time.stop();

                Self::check_for_vote_only_mode(
                    heaviest_bank.slot(),
                    forks_root,
                    &in_vote_only_mode,
                    &bank_forks,
                );

                let mut select_vote_and_reset_forks_time =
                    Measure::start("select_vote_and_reset_forks");
                let SelectVoteAndResetForkResult {
                    vote_bank,
                    reset_bank,
                    heaviest_fork_failures,
                } = Self::select_vote_and_reset_forks(
                    &heaviest_bank,
                    heaviest_bank_on_same_voted_fork.as_ref(),
                    &ancestors,
                    &descendants,
                    &progress,
                    &mut tower,
                    &latest_validator_votes_for_frozen_banks,
                    &heaviest_subtree_fork_choice,
                );
                select_vote_and_reset_forks_time.stop();

                if vote_bank.is_none() {
                    if let Some(heaviest_bank_on_same_voted_fork) =
                        heaviest_bank_on_same_voted_fork.as_ref()
                    {
                        if let Some(my_latest_landed_vote) =
                            progress.my_latest_landed_vote(heaviest_bank_on_same_voted_fork.slot())
                        {
                            Self::refresh_last_vote(
                                &mut tower,
                                heaviest_bank_on_same_voted_fork,
                                my_latest_landed_vote,
                                &vote_account,
                                &identity_keypair,
                                &authorized_voter_keypairs.read().unwrap(),
                                &mut voted_signatures,
                                has_new_vote_been_rooted,
                                &mut last_vote_refresh_time,
                                &voting_sender,
                                wait_to_vote_slot,
                            );
                        }
                    }
                }

                let mut heaviest_fork_failures_time = Measure::start("heaviest_fork_failures_time");
                if tower.is_recent(heaviest_bank.slot()) && !heaviest_fork_failures.is_empty() {
                    Self::log_heaviest_fork_failures(
                        &heaviest_fork_failures,
                        &bank_forks,
                        &tower,
                        &progress,
                        &ancestors,
                        &heaviest_bank,
                        &mut last_threshold_failure_slot,
                    );
                }
                heaviest_fork_failures_time.stop();

                let mut voting_time = Measure::start("voting_time");
                // Vote on a fork
                if let Some((ref vote_bank, ref switch_fork_decision)) = vote_bank {
                    if let Some(votable_leader) =
                        leader_schedule_cache.slot_leader_at(vote_bank.slot(), Some(vote_bank))
                    {
                        Self::log_leader_change(
                            &my_pubkey,
                            vote_bank.slot(),
                            &mut current_leader,
                            &votable_leader,
                        );
                    }

                    if let Err(e) = Self::handle_votable_bank(
                        vote_bank,
                        switch_fork_decision,
                        &bank_forks,
                        &mut tower,
                        &mut progress,
                        &vote_account,
                        &identity_keypair,
                        &authorized_voter_keypairs.read().unwrap(),
                        &blockstore,
                        &leader_schedule_cache,
                        &lockouts_sender,
                        &accounts_background_request_sender,
                        &rpc_subscriptions,
                        &block_commitment_cache,
                        &mut heaviest_subtree_fork_choice,
                        &bank_notification_sender,
                        &mut duplicate_slots_tracker,
                        &mut duplicate_confirmed_slots,
                        &mut unfrozen_gossip_verified_vote_hashes,
                        &mut voted_signatures,
                        &mut has_new_vote_been_rooted,
                        &mut replay_timing,
                        &voting_sender,
                        &mut epoch_slots_frozen_slots,
                        &drop_bank_sender,
                        wait_to_vote_slot,
                    ) {
                        error!("Unable to set root: {e}");
                        return;
                    }
                }
                voting_time.stop();

                let mut reset_bank_time = Measure::start("reset_bank");
                // Reset onto a fork
                if let Some(reset_bank) = reset_bank {
                    if last_reset == reset_bank.last_blockhash() {
                        let reset_bank_descendants =
                            Self::get_active_descendants(reset_bank.slot(), &progress, &blockstore);
                        if reset_bank_descendants != last_reset_bank_descendants {
                            last_reset_bank_descendants = reset_bank_descendants;
                            poh_recorder
                                .write()
                                .unwrap()
                                .update_start_bank_active_descendants(&last_reset_bank_descendants);
                        }
                    } else {
                        info!(
                            "vote bank: {:?} reset bank: {:?}",
                            vote_bank
                                .as_ref()
                                .map(|(b, switch_fork_decision)| (b.slot(), switch_fork_decision)),
                            reset_bank.slot(),
                        );
                        let fork_progress = progress
                            .get(&reset_bank.slot())
                            .expect("bank to reset to must exist in progress map");
                        datapoint_info!(
                            "blocks_produced",
                            ("num_blocks_on_fork", fork_progress.num_blocks_on_fork, i64),
                            (
                                "num_dropped_blocks_on_fork",
                                fork_progress.num_dropped_blocks_on_fork,
                                i64
                            ),
                        );

                        if my_pubkey != cluster_info.id() {
                            identity_keypair = cluster_info.keypair().clone();
                            let my_old_pubkey = my_pubkey;
                            my_pubkey = identity_keypair.pubkey();

                            // Load the new identity's tower
                            tower = match Self::load_tower(
                                tower_storage.as_ref(),
                                &my_pubkey,
                                &vote_account,
                                &bank_forks,
                            ) {
                                Ok(tower) => tower,
                                Err(err) => {
                                    error!(
                                        "Unable to load new tower when attempting to change identity
                                        from {} to {} on set-identity, Exiting: {}",
                                        my_old_pubkey,
                                        my_pubkey,
                                        err
                                    );
                                    // drop(_exit) will set the exit flag, eventually tearing down the entire process
                                    return;
                                }
                            };
                            // Ensure the validator can land votes with the new identity before
                            // becoming leader
                            has_new_vote_been_rooted = !wait_for_vote_to_start_leader;
                            warn!("Identity changed from {} to {}", my_old_pubkey, my_pubkey);
                        }

                        Self::reset_poh_recorder(
                            &my_pubkey,
                            &blockstore,
                            reset_bank.clone(),
                            &poh_recorder,
                            &leader_schedule_cache,
                        );
                        last_reset = reset_bank.last_blockhash();
                        last_reset_bank_descendants = vec![];
                        tpu_has_bank = false;

                        if let Some(last_voted_slot) = tower.last_voted_slot() {
                            // If the current heaviest bank is not a descendant of the last voted slot,
                            // there must be a partition
                            partition_info.update(
                                Self::is_partition_detected(
                                    &ancestors,
                                    last_voted_slot,
                                    heaviest_bank.slot(),
                                ),
                                heaviest_bank.slot(),
                                last_voted_slot,
                                reset_bank.slot(),
                                heaviest_fork_failures,
                            );
                        }
                    }
                }
                reset_bank_time.stop();

                let mut start_leader_time = Measure::start("start_leader_time");
                let mut dump_then_repair_correct_slots_time =
                    Measure::start("dump_then_repair_correct_slots_time");
                // Used for correctness check
                let poh_bank = poh_recorder.read().unwrap().bank();
                // Dump any duplicate slots that have been confirmed by the network in
                // anticipation of repairing the confirmed version of the slot.
                //
                // Has to be before `maybe_start_leader()`. Otherwise, `ancestors` and `descendants`
                // will be outdated, and we cannot assume `poh_bank` will be in either of these maps.
                Self::dump_then_repair_correct_slots(
                    &mut duplicate_slots_to_repair,
                    &mut ancestors,
                    &mut descendants,
                    &mut progress,
                    &bank_forks,
                    &blockstore,
                    poh_bank.map(|bank| bank.slot()),
                    &mut purge_repair_slot_counter,
                    &dumped_slots_sender,
                    &my_pubkey,
                    &leader_schedule_cache,
                );
                dump_then_repair_correct_slots_time.stop();

                let mut retransmit_not_propagated_time =
                    Measure::start("retransmit_not_propagated_time");
                Self::retransmit_latest_unpropagated_leader_slot(
                    &poh_recorder,
                    &retransmit_slots_sender,
                    &mut progress,
                );
                retransmit_not_propagated_time.stop();

                // From this point on, its not safe to use ancestors/descendants since maybe_start_leader
                // may add a bank that will not included in either of these maps.
                drop(ancestors);
                drop(descendants);
                if !tpu_has_bank {
                    Self::maybe_start_leader(
                        &my_pubkey,
                        &bank_forks,
                        &poh_recorder,
                        &leader_schedule_cache,
                        &rpc_subscriptions,
                        &mut progress,
                        &retransmit_slots_sender,
                        &mut skipped_slots_info,
                        &banking_tracer,
                        has_new_vote_been_rooted,
                        transaction_status_sender.is_some(),
                    );

                    let poh_bank = poh_recorder.read().unwrap().bank();
                    if let Some(bank) = poh_bank {
                        Self::log_leader_change(
                            &my_pubkey,
                            bank.slot(),
                            &mut current_leader,
                            &my_pubkey,
                        );
                    }
                }
                start_leader_time.stop();

                let mut wait_receive_time = Measure::start("wait_receive_time");
                if !did_complete_bank {
                    // only wait for the signal if we did not just process a bank; maybe there are more slots available

                    let timer = Duration::from_millis(100);
                    let result = ledger_signal_receiver.recv_timeout(timer);
                    match result {
                        Err(RecvTimeoutError::Timeout) => (),
                        Err(_) => break,
                        Ok(_) => trace!("blockstore signal"),
                    };
                }
                wait_receive_time.stop();

                replay_timing.update(
                    collect_frozen_banks_time.as_us(),
                    compute_bank_stats_time.as_us(),
                    select_vote_and_reset_forks_time.as_us(),
                    start_leader_time.as_us(),
                    reset_bank_time.as_us(),
                    voting_time.as_us(),
                    select_forks_time.as_us(),
                    compute_slot_stats_time.as_us(),
                    generate_new_bank_forks_time.as_us(),
                    replay_active_banks_time.as_us(),
                    wait_receive_time.as_us(),
                    heaviest_fork_failures_time.as_us(),
                    u64::from(did_complete_bank),
                    process_ancestor_hashes_duplicate_slots_time.as_us(),
                    process_duplicate_confirmed_slots_time.as_us(),
                    process_unfrozen_gossip_verified_vote_hashes_time.as_us(),
                    process_popular_pruned_forks_time.as_us(),
                    process_duplicate_slots_time.as_us(),
                    dump_then_repair_correct_slots_time.as_us(),
                    retransmit_not_propagated_time.as_us(),
                );
            }
        };
        let t_replay = Builder::new()
            .name("solReplayStage".to_string())
            .spawn(run_replay)
            .unwrap();

        Ok(Self {
            t_replay,
            commitment_service,
        })
    }

    /// Loads the tower from `tower_storage` with identity `node_pubkey`.
    ///
    /// If the tower is missing or too old, a tower is constructed from bank forks.
    fn load_tower(
        tower_storage: &dyn TowerStorage,
        node_pubkey: &Pubkey,
        vote_account: &Pubkey,
        bank_forks: &Arc<RwLock<BankForks>>,
    ) -> Result<Tower, TowerError> {
        let tower = Tower::restore(tower_storage, node_pubkey).and_then(|restored_tower| {
            let root_bank = bank_forks.read().unwrap().root_bank();
            let slot_history = root_bank.get_slot_history();
            restored_tower.adjust_lockouts_after_replay(root_bank.slot(), &slot_history)
        });
        match tower {
            Ok(tower) => Ok(tower),
            Err(err) if err.is_file_missing() => {
                warn!("Failed to load tower, file missing for {}: {}. Creating a new tower from bankforks.", node_pubkey, err);
                Ok(Tower::new_from_bankforks(
                    &bank_forks.read().unwrap(),
                    node_pubkey,
                    vote_account,
                ))
            }
            Err(err) if err.is_too_old() => {
                warn!("Failed to load tower, too old for {}: {}. Creating a new tower from bankforks.", node_pubkey, err);
                Ok(Tower::new_from_bankforks(
                    &bank_forks.read().unwrap(),
                    node_pubkey,
                    vote_account,
                ))
            }
            Err(err) => Err(err),
        }
    }

    fn check_for_vote_only_mode(
        heaviest_bank_slot: Slot,
        forks_root: Slot,
        in_vote_only_mode: &AtomicBool,
        bank_forks: &RwLock<BankForks>,
    ) {
        if heaviest_bank_slot.saturating_sub(forks_root) > MAX_ROOT_DISTANCE_FOR_VOTE_ONLY {
            if !in_vote_only_mode.load(Ordering::Relaxed)
                && in_vote_only_mode
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                let bank_forks = bank_forks.read().unwrap();
                datapoint_warn!(
                    "bank_forks-entering-vote-only-mode",
                    ("banks_len", bank_forks.len(), i64),
                    ("heaviest_bank", heaviest_bank_slot, i64),
                    ("root", bank_forks.root(), i64),
                );
            }
        } else if in_vote_only_mode.load(Ordering::Relaxed)
            && in_vote_only_mode
                .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let bank_forks = bank_forks.read().unwrap();
            datapoint_warn!(
                "bank_forks-exiting-vote-only-mode",
                ("banks_len", bank_forks.len(), i64),
                ("heaviest_bank", heaviest_bank_slot, i64),
                ("root", bank_forks.root(), i64),
            );
        }
    }

    fn maybe_retransmit_unpropagated_slots(
        metric_name: &'static str,
        retransmit_slots_sender: &Sender<Slot>,
        progress: &mut ProgressMap,
        latest_leader_slot: Slot,
    ) {
        let first_leader_group_slot = first_of_consecutive_leader_slots(latest_leader_slot);

        for slot in first_leader_group_slot..=latest_leader_slot {
            let is_propagated = progress.is_propagated(slot);
            if let Some(retransmit_info) = progress.get_retransmit_info_mut(slot) {
                if !is_propagated.expect(
                    "presence of retransmit_info ensures that propagation status is present",
                ) {
                    if retransmit_info.reached_retransmit_threshold() {
                        info!(
                            "Retrying retransmit: latest_leader_slot={} slot={} retransmit_info={:?}",
                            latest_leader_slot,
                            slot,
                            &retransmit_info,
                        );
                        datapoint_info!(
                            metric_name,
                            ("latest_leader_slot", latest_leader_slot, i64),
                            ("slot", slot, i64),
                            ("retry_iteration", retransmit_info.retry_iteration, i64),
                        );
                        let _ = retransmit_slots_sender.send(slot);
                        retransmit_info.increment_retry_iteration();
                    } else {
                        debug!(
                            "Bypass retransmit of slot={} retransmit_info={:?}",
                            slot, &retransmit_info
                        );
                    }
                }
            }
        }
    }

    fn retransmit_latest_unpropagated_leader_slot(
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        retransmit_slots_sender: &Sender<Slot>,
        progress: &mut ProgressMap,
    ) {
        let start_slot = poh_recorder.read().unwrap().start_slot();

        if let (false, Some(latest_leader_slot)) =
            progress.get_leader_propagation_slot_must_exist(start_slot)
        {
            debug!(
                "Slot not propagated: start_slot={} latest_leader_slot={}",
                start_slot, latest_leader_slot
            );
            Self::maybe_retransmit_unpropagated_slots(
                "replay_stage-retransmit-timing-based",
                retransmit_slots_sender,
                progress,
                latest_leader_slot,
            );
        }
    }

    fn is_partition_detected(
        ancestors: &HashMap<Slot, HashSet<Slot>>,
        last_voted_slot: Slot,
        heaviest_slot: Slot,
    ) -> bool {
        last_voted_slot != heaviest_slot
            && !ancestors
                .get(&heaviest_slot)
                .map(|ancestors| ancestors.contains(&last_voted_slot))
                .unwrap_or(true)
    }

    fn get_active_descendants(
        slot: Slot,
        progress: &ProgressMap,
        blockstore: &Blockstore,
    ) -> Vec<Slot> {
        let Some(slot_meta) = blockstore.meta(slot).ok().flatten() else {
            return vec![];
        };

        slot_meta
            .next_slots
            .iter()
            .filter(|slot| !progress.is_dead(**slot).unwrap_or_default())
            .copied()
            .collect()
    }

    fn initialize_progress_and_fork_choice_with_locked_bank_forks(
        bank_forks: &RwLock<BankForks>,
        my_pubkey: &Pubkey,
        vote_account: &Pubkey,
        blockstore: &Blockstore,
    ) -> (ProgressMap, HeaviestSubtreeForkChoice) {
        let (root_bank, frozen_banks, duplicate_slot_hashes) = {
            let bank_forks = bank_forks.read().unwrap();
            let duplicate_slots = blockstore
                .duplicate_slots_iterator(bank_forks.root_bank().slot())
                .unwrap();
            let duplicate_slot_hashes = duplicate_slots.filter_map(|slot| {
                let bank = bank_forks.get(slot)?;
                Some((slot, bank.hash()))
            });
            (
                bank_forks.root_bank(),
                bank_forks.frozen_banks().values().cloned().collect(),
                duplicate_slot_hashes.collect::<Vec<(Slot, Hash)>>(),
            )
        };

        Self::initialize_progress_and_fork_choice(
            &root_bank,
            frozen_banks,
            my_pubkey,
            vote_account,
            duplicate_slot_hashes,
        )
    }

    pub fn initialize_progress_and_fork_choice(
        root_bank: &Bank,
        mut frozen_banks: Vec<Arc<Bank>>,
        my_pubkey: &Pubkey,
        vote_account: &Pubkey,
        duplicate_slot_hashes: Vec<(Slot, Hash)>,
    ) -> (ProgressMap, HeaviestSubtreeForkChoice) {
        let mut progress = ProgressMap::default();

        frozen_banks.sort_by_key(|bank| bank.slot());

        // Initialize progress map with any root banks
        for bank in &frozen_banks {
            let prev_leader_slot = progress.get_bank_prev_leader_slot(bank);
            progress.insert(
                bank.slot(),
                ForkProgress::new_from_bank(bank, my_pubkey, vote_account, prev_leader_slot, 0, 0),
            );
        }
        let root = root_bank.slot();
        let mut heaviest_subtree_fork_choice = HeaviestSubtreeForkChoice::new_from_frozen_banks(
            (root, root_bank.hash()),
            &frozen_banks,
        );

        for slot_hash in duplicate_slot_hashes {
            heaviest_subtree_fork_choice.mark_fork_invalid_candidate(&slot_hash);
        }

        (progress, heaviest_subtree_fork_choice)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dump_then_repair_correct_slots(
        duplicate_slots_to_repair: &mut DuplicateSlotsToRepair,
        ancestors: &mut HashMap<Slot, HashSet<Slot>>,
        descendants: &mut HashMap<Slot, HashSet<Slot>>,
        progress: &mut ProgressMap,
        bank_forks: &RwLock<BankForks>,
        blockstore: &Blockstore,
        poh_bank_slot: Option<Slot>,
        purge_repair_slot_counter: &mut PurgeRepairSlotCounter,
        dumped_slots_sender: &DumpedSlotsSender,
        my_pubkey: &Pubkey,
        leader_schedule_cache: &LeaderScheduleCache,
    ) {
        if duplicate_slots_to_repair.is_empty() {
            return;
        }

        let root_bank = bank_forks.read().unwrap().root_bank();
        let mut dumped = vec![];
        // TODO: handle if alternate version of descendant also got confirmed after ancestor was
        // confirmed, what happens then? Should probably keep track of dumped list and skip things
        // in `duplicate_slots_to_repair` that have already been dumped. Add test.
        duplicate_slots_to_repair.retain(|duplicate_slot, correct_hash| {
            // Should not dump duplicate slots if there is currently a poh bank building
            // on top of that slot, as BankingStage might still be referencing/touching that state
            // concurrently.
            // Luckily for us, because the fork choice rule removes duplicate slots from fork
            // choice, and this function is called after:
            // 1) We have picked a bank to reset to in `select_vote_and_reset_forks()`
            // 2) And also called `reset_poh_recorder()`
            // Then we should have reset to a fork that doesn't include the duplicate block,
            // which means any working bank in PohRecorder that was built on that duplicate fork
            // should have been cleared as well. However, if there is some violation of this guarantee,
            // then log here
            let is_poh_building_on_duplicate_fork = poh_bank_slot
                .map(|poh_bank_slot| {
                    ancestors
                        .get(&poh_bank_slot)
                        .expect("Poh bank should exist in BankForks and thus in ancestors map")
                        .contains(duplicate_slot)
                })
                .unwrap_or(false);

            let did_dump_repair = {
                if !is_poh_building_on_duplicate_fork {
                    let frozen_hash = bank_forks.read().unwrap().bank_hash(*duplicate_slot);
                    if let Some(frozen_hash) = frozen_hash {
                        if frozen_hash == *correct_hash {
                            warn!(
                                "Trying to dump slot {} with correct_hash {}",
                                *duplicate_slot, *correct_hash
                            );
                            return false;
                        } else if frozen_hash == Hash::default()
                            && !progress.is_dead(*duplicate_slot).expect(
                                "If slot exists in BankForks must exist in the progress map",
                            )
                        {
                            warn!(
                                "Trying to dump unfrozen slot {} that is not dead",
                                *duplicate_slot
                            );
                            return false;
                        }
                    } else {
                        warn!(
                            "Dumping slot {} which does not exist in bank forks (possibly pruned)",
                            *duplicate_slot
                        );
                    }

                    // Should not dump slots for which we were the leader
                    if Some(*my_pubkey) == leader_schedule_cache.slot_leader_at(*duplicate_slot, None) {
                        if let Some(bank) = bank_forks.read().unwrap().get(*duplicate_slot) {
                            bank_hash_details::write_bank_hash_details_file(&bank)
                                .map_err(|err| {
                                    warn!("Unable to write bank hash details file: {err}");
                                })
                                .ok();
                        } else {
                            warn!("Unable to get bank for slot {duplicate_slot} from bank forks \
                                   while attempting to write bank hash details file");
                        }
                        panic!("We are attempting to dump a block that we produced. \
                            This indicates that we are producing duplicate blocks, \
                            or that there is a bug in our runtime/replay code which \
                            causes us to compute different bank hashes than the rest of the cluster. \
                            We froze slot {duplicate_slot} with hash {frozen_hash:?} while the cluster hash is {correct_hash}");
                    }

                    let attempt_no = purge_repair_slot_counter
                        .entry(*duplicate_slot)
                        .and_modify(|x| *x += 1)
                        .or_insert(1);
                    if *attempt_no > MAX_REPAIR_RETRY_LOOP_ATTEMPTS {
                        panic!("We have tried to repair duplicate slot: {duplicate_slot} more than {MAX_REPAIR_RETRY_LOOP_ATTEMPTS} times \
                            and are unable to freeze a block with bankhash {correct_hash}, \
                            instead we have a block with bankhash {frozen_hash:?}. \
                            This is most likely a bug in the runtime. \
                            At this point manual intervention is needed to make progress. Exiting");
                    }

                    Self::purge_unconfirmed_duplicate_slot(
                        *duplicate_slot,
                        ancestors,
                        descendants,
                        progress,
                        &root_bank,
                        bank_forks,
                        blockstore,
                    );

                    dumped.push((*duplicate_slot, *correct_hash));

                    warn!(
                        "Notifying repair service to repair duplicate slot: {}, attempt {}",
                        *duplicate_slot, *attempt_no,
                    );
                    true
                } else {
                    warn!(
                        "PoH bank for slot {} is building on duplicate slot {}",
                        poh_bank_slot.unwrap(),
                        duplicate_slot
                    );
                    false
                }
            };

            // If we dumped/repaired, then no need to keep the slot in the set of pending work
            !did_dump_repair
        });

        // Notify repair of the dumped slots along with the correct hash
        trace!("Dumped {} slots", dumped.len());
        dumped_slots_sender.send(dumped).unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn process_ancestor_hashes_duplicate_slots(
        pubkey: &Pubkey,
        blockstore: &Blockstore,
        ancestor_duplicate_slots_receiver: &AncestorDuplicateSlotsReceiver,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        duplicate_confirmed_slots: &DuplicateConfirmedSlots,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        progress: &ProgressMap,
        fork_choice: &mut HeaviestSubtreeForkChoice,
        bank_forks: &RwLock<BankForks>,
        duplicate_slots_to_repair: &mut DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: &AncestorHashesReplayUpdateSender,
        purge_repair_slot_counter: &mut PurgeRepairSlotCounter,
    ) {
        let root = bank_forks.read().unwrap().root();
        for AncestorDuplicateSlotToRepair {
            slot_to_repair: (epoch_slots_frozen_slot, epoch_slots_frozen_hash),
            request_type,
        } in ancestor_duplicate_slots_receiver.try_iter()
        {
            warn!(
                "{} ReplayStage notified of duplicate slot from ancestor hashes service but we observed as {}: {:?}",
                pubkey, if request_type.is_pruned() {"pruned"} else {"dead"}, (epoch_slots_frozen_slot, epoch_slots_frozen_hash),
            );
            let epoch_slots_frozen_state = EpochSlotsFrozenState::new_from_state(
                epoch_slots_frozen_slot,
                epoch_slots_frozen_hash,
                duplicate_confirmed_slots,
                fork_choice,
                || progress.is_dead(epoch_slots_frozen_slot).unwrap_or(false),
                || {
                    bank_forks
                        .read()
                        .unwrap()
                        .get(epoch_slots_frozen_slot)
                        .map(|b| b.hash())
                },
                request_type.is_pruned(),
            );
            check_slot_agrees_with_cluster(
                epoch_slots_frozen_slot,
                root,
                blockstore,
                duplicate_slots_tracker,
                epoch_slots_frozen_slots,
                fork_choice,
                duplicate_slots_to_repair,
                ancestor_hashes_replay_update_sender,
                purge_repair_slot_counter,
                SlotStateUpdate::EpochSlotsFrozen(epoch_slots_frozen_state),
            );
        }
    }

    fn purge_unconfirmed_duplicate_slot(
        duplicate_slot: Slot,
        ancestors: &mut HashMap<Slot, HashSet<Slot>>,
        descendants: &mut HashMap<Slot, HashSet<Slot>>,
        progress: &mut ProgressMap,
        root_bank: &Bank,
        bank_forks: &RwLock<BankForks>,
        blockstore: &Blockstore,
    ) {
        warn!("purging slot {}", duplicate_slot);

        // Doesn't need to be root bank, just needs a common bank to
        // access the status cache and accounts
        let slot_descendants = descendants.get(&duplicate_slot).cloned();
        if slot_descendants.is_none() {
            // Root has already moved past this slot, no need to purge it
            if root_bank.slot() <= duplicate_slot {
                blockstore.clear_unconfirmed_slot(duplicate_slot);
            }

            return;
        }

        // Clear the ancestors/descendants map to keep them
        // consistent
        let slot_descendants = slot_descendants.unwrap();
        Self::purge_ancestors_descendants(
            duplicate_slot,
            &slot_descendants,
            ancestors,
            descendants,
        );

        // Grab the Slot and BankId's of the banks we need to purge, then clear the banks
        // from BankForks
        let (slots_to_purge, removed_banks): (Vec<(Slot, BankId)>, Vec<BankWithScheduler>) = {
            let mut w_bank_forks = bank_forks.write().unwrap();
            slot_descendants
                .iter()
                .chain(std::iter::once(&duplicate_slot))
                .map(|slot| {
                    // Clear the banks from BankForks
                    let bank = w_bank_forks
                        .remove(*slot)
                        .expect("BankForks should not have been purged yet");
                    bank_hash_details::write_bank_hash_details_file(&bank)
                        .map_err(|err| {
                            warn!("Unable to write bank hash details file: {err}");
                        })
                        .ok();
                    ((*slot, bank.bank_id()), bank)
                })
                .unzip()
        };

        // Clear the accounts for these slots so that any ongoing RPC scans fail.
        // These have to be atomically cleared together in the same batch, in order
        // to prevent RPC from seeing inconsistent results in scans.
        root_bank.remove_unrooted_slots(&slots_to_purge);

        // Once the slots above have been purged, now it's safe to remove the banks from
        // BankForks, allowing the Bank::drop() purging to run and not race with the
        // `remove_unrooted_slots()` call.
        drop(removed_banks);

        for (slot, slot_id) in slots_to_purge {
            // Clear the slot signatures from status cache for this slot.
            // TODO: What about RPC queries that had already cloned the Bank for this slot
            // and are looking up the signature for this slot?
            root_bank.clear_slot_signatures(slot);

            // Remove cached entries of the programs that were deployed in this slot.
            root_bank.prune_program_cache_by_deployment_slot(slot);

            if let Some(bank_hash) = blockstore.get_bank_hash(slot) {
                // If a descendant was successfully replayed and chained from a duplicate it must
                // also be a duplicate. In this case we *need* to repair it, so we clear from
                // blockstore.
                warn!(
                    "purging duplicate descendant: {} with slot_id {} and bank hash {}, of slot {}",
                    slot, slot_id, bank_hash, duplicate_slot
                );
                // Clear the slot-related data in blockstore. This will:
                // 1) Clear old shreds allowing new ones to be inserted
                // 2) Clear the "dead" flag allowing ReplayStage to start replaying
                // this slot
                blockstore.clear_unconfirmed_slot(slot);
            } else if slot == duplicate_slot {
                warn!("purging duplicate slot: {} with slot_id {}", slot, slot_id);
                blockstore.clear_unconfirmed_slot(slot);
            } else {
                // If a descendant was unable to replay and chained from a duplicate, it is not
                // necessary to repair it. It is most likely that this block is fine, and will
                // replay on successful repair of the parent. If this block is also a duplicate, it
                // will be handled in the next round of repair/replay - so we just clear the dead
                // flag for now.
                warn!("not purging descendant {} of slot {} as it is dead. resetting dead flag instead", slot, duplicate_slot);
                // Clear the "dead" flag allowing ReplayStage to start replaying
                // this slot once the parent is repaired
                blockstore.remove_dead_slot(slot).unwrap();
            }

            // Clear the progress map of these forks
            let _ = progress.remove(&slot);
        }
    }

    // Purge given slot and all its descendants from the `ancestors` and
    // `descendants` structures so that they're consistent with `BankForks`
    // and the `progress` map.
    fn purge_ancestors_descendants(
        slot: Slot,
        slot_descendants: &HashSet<Slot>,
        ancestors: &mut HashMap<Slot, HashSet<Slot>>,
        descendants: &mut HashMap<Slot, HashSet<Slot>>,
    ) {
        if !ancestors.contains_key(&slot) {
            // Slot has already been purged
            return;
        }

        // Purge this slot from each of its ancestors' `descendants` maps
        for a in ancestors
            .get(&slot)
            .expect("must exist based on earlier check")
        {
            descendants
                .get_mut(a)
                .expect("If exists in ancestor map must exist in descendants map")
                .retain(|d| *d != slot && !slot_descendants.contains(d));
        }
        ancestors
            .remove(&slot)
            .expect("must exist based on earlier check");

        // Purge all the descendants of this slot from both maps
        for descendant in slot_descendants {
            ancestors.remove(descendant).expect("must exist");
            descendants
                .remove(descendant)
                .expect("must exist based on earlier check");
        }
        descendants
            .remove(&slot)
            .expect("must exist based on earlier check");
    }

    #[allow(clippy::too_many_arguments)]
    fn process_popular_pruned_forks(
        popular_pruned_forks_receiver: &PopularPrunedForksReceiver,
        blockstore: &Blockstore,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        bank_forks: &RwLock<BankForks>,
        fork_choice: &mut HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: &mut DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: &AncestorHashesReplayUpdateSender,
        purge_repair_slot_counter: &mut PurgeRepairSlotCounter,
    ) {
        let root = bank_forks.read().unwrap().root();
        for new_popular_pruned_slots in popular_pruned_forks_receiver.try_iter() {
            for new_popular_pruned_slot in new_popular_pruned_slots {
                if new_popular_pruned_slot <= root {
                    continue;
                }
                check_slot_agrees_with_cluster(
                    new_popular_pruned_slot,
                    root,
                    blockstore,
                    duplicate_slots_tracker,
                    epoch_slots_frozen_slots,
                    fork_choice,
                    duplicate_slots_to_repair,
                    ancestor_hashes_replay_update_sender,
                    purge_repair_slot_counter,
                    SlotStateUpdate::PopularPrunedFork,
                );
            }
        }
    }

    // Check for any newly duplicate confirmed slots by the cluster.
    // This only tracks duplicate slot confirmations on the exact
    // single slots and does not account for votes on their descendants. Used solely
    // for duplicate slot recovery.
    #[allow(clippy::too_many_arguments)]
    fn process_duplicate_confirmed_slots(
        duplicate_confirmed_slots_receiver: &DuplicateConfirmedSlotsReceiver,
        blockstore: &Blockstore,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        duplicate_confirmed_slots: &mut DuplicateConfirmedSlots,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        bank_forks: &RwLock<BankForks>,
        progress: &ProgressMap,
        fork_choice: &mut HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: &mut DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: &AncestorHashesReplayUpdateSender,
        purge_repair_slot_counter: &mut PurgeRepairSlotCounter,
    ) {
        let root = bank_forks.read().unwrap().root();
        for new_duplicate_confirmed_slots in duplicate_confirmed_slots_receiver.try_iter() {
            for (confirmed_slot, duplicate_confirmed_hash) in new_duplicate_confirmed_slots {
                if confirmed_slot <= root {
                    continue;
                } else if let Some(prev_hash) =
                    duplicate_confirmed_slots.insert(confirmed_slot, duplicate_confirmed_hash)
                {
                    assert_eq!(prev_hash, duplicate_confirmed_hash);
                    // Already processed this signal
                    return;
                }

                let duplicate_confirmed_state = DuplicateConfirmedState::new_from_state(
                    duplicate_confirmed_hash,
                    || progress.is_dead(confirmed_slot).unwrap_or(false),
                    || bank_forks.read().unwrap().bank_hash(confirmed_slot),
                );
                check_slot_agrees_with_cluster(
                    confirmed_slot,
                    root,
                    blockstore,
                    duplicate_slots_tracker,
                    epoch_slots_frozen_slots,
                    fork_choice,
                    duplicate_slots_to_repair,
                    ancestor_hashes_replay_update_sender,
                    purge_repair_slot_counter,
                    SlotStateUpdate::DuplicateConfirmed(duplicate_confirmed_state),
                );
            }
        }
    }

    fn process_gossip_verified_vote_hashes(
        gossip_verified_vote_hash_receiver: &GossipVerifiedVoteHashReceiver,
        unfrozen_gossip_verified_vote_hashes: &mut UnfrozenGossipVerifiedVoteHashes,
        heaviest_subtree_fork_choice: &HeaviestSubtreeForkChoice,
        latest_validator_votes_for_frozen_banks: &mut LatestValidatorVotesForFrozenBanks,
    ) {
        for (pubkey, slot, hash) in gossip_verified_vote_hash_receiver.try_iter() {
            let is_frozen = heaviest_subtree_fork_choice.contains_block(&(slot, hash));
            // cluster_info_vote_listener will ensure it doesn't push duplicates
            unfrozen_gossip_verified_vote_hashes.add_vote(
                pubkey,
                slot,
                hash,
                is_frozen,
                latest_validator_votes_for_frozen_banks,
            )
        }
    }

    // Checks for and handle forks with duplicate slots.
    #[allow(clippy::too_many_arguments)]
    fn process_duplicate_slots(
        blockstore: &Blockstore,
        duplicate_slots_receiver: &DuplicateSlotReceiver,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        duplicate_confirmed_slots: &DuplicateConfirmedSlots,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        bank_forks: &RwLock<BankForks>,
        progress: &ProgressMap,
        fork_choice: &mut HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: &mut DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: &AncestorHashesReplayUpdateSender,
        purge_repair_slot_counter: &mut PurgeRepairSlotCounter,
    ) {
        let new_duplicate_slots: Vec<Slot> = duplicate_slots_receiver.try_iter().collect();
        let (root_slot, bank_hashes) = {
            let r_bank_forks = bank_forks.read().unwrap();
            let bank_hashes: Vec<Option<Hash>> = new_duplicate_slots
                .iter()
                .map(|duplicate_slot| r_bank_forks.bank_hash(*duplicate_slot))
                .collect();

            (r_bank_forks.root(), bank_hashes)
        };
        for (duplicate_slot, bank_hash) in
            new_duplicate_slots.into_iter().zip(bank_hashes.into_iter())
        {
            // WindowService should only send the signal once per slot
            let duplicate_state = DuplicateState::new_from_state(
                duplicate_slot,
                duplicate_confirmed_slots,
                fork_choice,
                || progress.is_dead(duplicate_slot).unwrap_or(false),
                || bank_hash,
            );
            check_slot_agrees_with_cluster(
                duplicate_slot,
                root_slot,
                blockstore,
                duplicate_slots_tracker,
                epoch_slots_frozen_slots,
                fork_choice,
                duplicate_slots_to_repair,
                ancestor_hashes_replay_update_sender,
                purge_repair_slot_counter,
                SlotStateUpdate::Duplicate(duplicate_state),
            );
        }
    }

    fn log_leader_change(
        my_pubkey: &Pubkey,
        bank_slot: Slot,
        current_leader: &mut Option<Pubkey>,
        new_leader: &Pubkey,
    ) {
        if let Some(ref current_leader) = current_leader {
            if current_leader != new_leader {
                let msg = if current_leader == my_pubkey {
                    ". I am no longer the leader"
                } else if new_leader == my_pubkey {
                    ". I am now the leader"
                } else {
                    ""
                };
                info!(
                    "LEADER CHANGE at slot: {} leader: {}{}",
                    bank_slot, new_leader, msg
                );
            }
        }
        current_leader.replace(new_leader.to_owned());
    }

    fn check_propagation_for_start_leader(
        poh_slot: Slot,
        parent_slot: Slot,
        progress_map: &ProgressMap,
    ) -> bool {
        // Assume `NUM_CONSECUTIVE_LEADER_SLOTS` = 4. Then `skip_propagated_check`
        // below is true if `poh_slot` is within the same `NUM_CONSECUTIVE_LEADER_SLOTS`
        // set of blocks as `latest_leader_slot`.
        //
        // Example 1 (`poh_slot` directly descended from `latest_leader_slot`):
        //
        // [B B B B] [B B B latest_leader_slot] poh_slot
        //
        // Example 2:
        //
        // [B latest_leader_slot B poh_slot]
        //
        // In this example, even if there's a block `B` on another fork between
        // `poh_slot` and `parent_slot`, because they're in the same
        // `NUM_CONSECUTIVE_LEADER_SLOTS` block, we still skip the propagated
        // check because it's still within the propagation grace period.
        if let Some(latest_leader_slot) =
            progress_map.get_latest_leader_slot_must_exist(parent_slot)
        {
            let skip_propagated_check =
                poh_slot - latest_leader_slot < NUM_CONSECUTIVE_LEADER_SLOTS;
            if skip_propagated_check {
                return true;
            }
        }

        // Note that `is_propagated(parent_slot)` doesn't necessarily check
        // propagation of `parent_slot`, it checks propagation of the latest ancestor
        // of `parent_slot` (hence the call to `get_latest_leader_slot()` in the
        // check above)
        progress_map
            .get_leader_propagation_slot_must_exist(parent_slot)
            .0
    }

    fn should_retransmit(poh_slot: Slot, last_retransmit_slot: &mut Slot) -> bool {
        if poh_slot < *last_retransmit_slot
            || poh_slot >= *last_retransmit_slot + NUM_CONSECUTIVE_LEADER_SLOTS
        {
            *last_retransmit_slot = poh_slot;
            true
        } else {
            false
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn maybe_start_leader(
        my_pubkey: &Pubkey,
        bank_forks: &Arc<RwLock<BankForks>>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        leader_schedule_cache: &Arc<LeaderScheduleCache>,
        rpc_subscriptions: &Arc<RpcSubscriptions>,
        progress_map: &mut ProgressMap,
        retransmit_slots_sender: &Sender<Slot>,
        skipped_slots_info: &mut SkippedSlotsInfo,
        banking_tracer: &Arc<BankingTracer>,
        has_new_vote_been_rooted: bool,
        track_transaction_indexes: bool,
    ) {
        // all the individual calls to poh_recorder.read() are designed to
        // increase granularity, decrease contention

        assert!(!poh_recorder.read().unwrap().has_bank());

        let (poh_slot, parent_slot) =
            match poh_recorder.read().unwrap().reached_leader_slot(my_pubkey) {
                PohLeaderStatus::Reached {
                    poh_slot,
                    parent_slot,
                } => (poh_slot, parent_slot),
                PohLeaderStatus::NotReached => {
                    trace!("{} poh_recorder hasn't reached_leader_slot", my_pubkey);
                    return;
                }
            };

        trace!("{} reached_leader_slot", my_pubkey);

        let parent = bank_forks
            .read()
            .unwrap()
            .get(parent_slot)
            .expect("parent_slot doesn't exist in bank forks");

        assert!(parent.is_frozen());

        if !parent.is_startup_verification_complete() {
            info!("startup verification incomplete, so skipping my leader slot");
            return;
        }

        if bank_forks.read().unwrap().get(poh_slot).is_some() {
            warn!("{} already have bank in forks at {}?", my_pubkey, poh_slot);
            return;
        }
        trace!(
            "{} poh_slot {} parent_slot {}",
            my_pubkey,
            poh_slot,
            parent_slot
        );

        if let Some(next_leader) = leader_schedule_cache.slot_leader_at(poh_slot, Some(&parent)) {
            if !has_new_vote_been_rooted {
                info!("Haven't landed a vote, so skipping my leader slot");
                return;
            }

            trace!(
                "{} leader {} at poh slot: {}",
                my_pubkey,
                next_leader,
                poh_slot
            );

            // I guess I missed my slot
            if next_leader != *my_pubkey {
                return;
            }

            datapoint_info!(
                "replay_stage-new_leader",
                ("slot", poh_slot, i64),
                ("leader", next_leader.to_string(), String),
            );

            if !Self::check_propagation_for_start_leader(poh_slot, parent_slot, progress_map) {
                let latest_unconfirmed_leader_slot = progress_map.get_latest_leader_slot_must_exist(parent_slot)
                    .expect("In order for propagated check to fail, latest leader must exist in progress map");
                if poh_slot != skipped_slots_info.last_skipped_slot {
                    datapoint_info!(
                        "replay_stage-skip_leader_slot",
                        ("slot", poh_slot, i64),
                        ("parent_slot", parent_slot, i64),
                        (
                            "latest_unconfirmed_leader_slot",
                            latest_unconfirmed_leader_slot,
                            i64
                        )
                    );
                    progress_map.log_propagated_stats(latest_unconfirmed_leader_slot, bank_forks);
                    skipped_slots_info.last_skipped_slot = poh_slot;
                }
                if Self::should_retransmit(poh_slot, &mut skipped_slots_info.last_retransmit_slot) {
                    Self::maybe_retransmit_unpropagated_slots(
                        "replay_stage-retransmit",
                        retransmit_slots_sender,
                        progress_map,
                        latest_unconfirmed_leader_slot,
                    );
                }
                return;
            }

            let root_slot = bank_forks.read().unwrap().root();
            datapoint_info!("replay_stage-my_leader_slot", ("slot", poh_slot, i64),);
            info!(
                "new fork:{} parent:{} (leader) root:{}",
                poh_slot, parent_slot, root_slot
            );

            let root_distance = poh_slot - root_slot;
            let vote_only_bank = if root_distance > MAX_ROOT_DISTANCE_FOR_VOTE_ONLY {
                datapoint_info!("vote-only-bank", ("slot", poh_slot, i64));
                true
            } else {
                false
            };

            let tpu_bank = Self::new_bank_from_parent_with_notify(
                parent.clone(),
                poh_slot,
                root_slot,
                my_pubkey,
                rpc_subscriptions,
                NewBankOptions { vote_only_bank },
            );
            // make sure parent is frozen for finalized hashes via the above
            // new()-ing of its child bank
            banking_tracer.hash_event(parent.slot(), &parent.last_blockhash(), &parent.hash());

            let tpu_bank = bank_forks.write().unwrap().insert(tpu_bank);
            poh_recorder
                .write()
                .unwrap()
                .set_bank(tpu_bank, track_transaction_indexes);
        } else {
            error!("{} No next leader found", my_pubkey);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_blockstore_into_bank(
        bank: &BankWithScheduler,
        blockstore: &Blockstore,
        replay_tx_thread_pool: &ThreadPool,
        replay_stats: &RwLock<ReplaySlotStats>,
        replay_progress: &RwLock<ConfirmationProgress>,
        transaction_status_sender: Option<&TransactionStatusSender>,
        entry_notification_sender: Option<&EntryNotifierSender>,
        replay_vote_sender: &ReplayVoteSender,
        verify_recyclers: &VerifyRecyclers,
        log_messages_bytes_limit: Option<usize>,
        prioritization_fee_cache: &PrioritizationFeeCache,
    ) -> result::Result<usize, BlockstoreProcessorError> {
        let mut w_replay_stats = replay_stats.write().unwrap();
        let mut w_replay_progress = replay_progress.write().unwrap();
        let tx_count_before = w_replay_progress.num_txs;
        // All errors must lead to marking the slot as dead, otherwise,
        // the `check_slot_agrees_with_cluster()` called by `replay_active_banks()`
        // will break!
        blockstore_processor::confirm_slot(
            blockstore,
            bank,
            replay_tx_thread_pool,
            &mut w_replay_stats,
            &mut w_replay_progress,
            false,
            transaction_status_sender,
            entry_notification_sender,
            Some(replay_vote_sender),
            verify_recyclers,
            false,
            log_messages_bytes_limit,
            prioritization_fee_cache,
        )?;
        let tx_count_after = w_replay_progress.num_txs;
        let tx_count = tx_count_after - tx_count_before;
        Ok(tx_count)
    }

    #[allow(clippy::too_many_arguments)]
    fn mark_dead_slot(
        blockstore: &Blockstore,
        bank: &Bank,
        root: Slot,
        err: &BlockstoreProcessorError,
        rpc_subscriptions: &Arc<RpcSubscriptions>,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        duplicate_confirmed_slots: &DuplicateConfirmedSlots,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        progress: &mut ProgressMap,
        heaviest_subtree_fork_choice: &mut HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: &mut DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: &AncestorHashesReplayUpdateSender,
        purge_repair_slot_counter: &mut PurgeRepairSlotCounter,
    ) {
        // Do not remove from progress map when marking dead! Needed by
        // `process_duplicate_confirmed_slots()`

        // Block producer can abandon the block if it detects a better one
        // while producing. Somewhat common and expected in a
        // network with variable network/machine configuration.
        let is_serious = !matches!(
            err,
            BlockstoreProcessorError::InvalidBlock(BlockError::TooFewTicks)
        );
        let slot = bank.slot();
        if is_serious {
            datapoint_error!(
                "replay-stage-mark_dead_slot",
                ("error", format!("error: {err:?}"), String),
                ("slot", slot, i64)
            );
        } else {
            datapoint_info!(
                "replay-stage-mark_dead_slot",
                ("error", format!("error: {err:?}"), String),
                ("slot", slot, i64)
            );
        }
        progress.get_mut(&slot).unwrap().is_dead = true;
        blockstore
            .set_dead_slot(slot)
            .expect("Failed to mark slot as dead in blockstore");

        blockstore.slots_stats.mark_dead(slot);

        rpc_subscriptions.notify_slot_update(SlotUpdate::Dead {
            slot,
            err: format!("error: {err:?}"),
            timestamp: timestamp(),
        });
        let dead_state = DeadState::new_from_state(
            slot,
            duplicate_slots_tracker,
            duplicate_confirmed_slots,
            heaviest_subtree_fork_choice,
            epoch_slots_frozen_slots,
        );
        check_slot_agrees_with_cluster(
            slot,
            root,
            blockstore,
            duplicate_slots_tracker,
            epoch_slots_frozen_slots,
            heaviest_subtree_fork_choice,
            duplicate_slots_to_repair,
            ancestor_hashes_replay_update_sender,
            purge_repair_slot_counter,
            SlotStateUpdate::Dead(dead_state),
        );

        // If we previously marked this slot as duplicate in blockstore, let the state machine know
        if !duplicate_slots_tracker.contains(&slot) && blockstore.get_duplicate_slot(slot).is_some()
        {
            let duplicate_state = DuplicateState::new_from_state(
                slot,
                duplicate_confirmed_slots,
                heaviest_subtree_fork_choice,
                || true,
                || None,
            );
            check_slot_agrees_with_cluster(
                slot,
                root,
                blockstore,
                duplicate_slots_tracker,
                epoch_slots_frozen_slots,
                heaviest_subtree_fork_choice,
                duplicate_slots_to_repair,
                ancestor_hashes_replay_update_sender,
                purge_repair_slot_counter,
                SlotStateUpdate::Duplicate(duplicate_state),
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_votable_bank(
        bank: &Arc<Bank>,
        switch_fork_decision: &SwitchForkDecision,
        bank_forks: &Arc<RwLock<BankForks>>,
        tower: &mut Tower,
        progress: &mut ProgressMap,
        vote_account_pubkey: &Pubkey,
        identity_keypair: &Keypair,
        authorized_voter_keypairs: &[Arc<Keypair>],
        blockstore: &Blockstore,
        leader_schedule_cache: &Arc<LeaderScheduleCache>,
        lockouts_sender: &Sender<CommitmentAggregationData>,
        accounts_background_request_sender: &AbsRequestSender,
        rpc_subscriptions: &Arc<RpcSubscriptions>,
        block_commitment_cache: &Arc<RwLock<BlockCommitmentCache>>,
        heaviest_subtree_fork_choice: &mut HeaviestSubtreeForkChoice,
        bank_notification_sender: &Option<BankNotificationSenderConfig>,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        duplicate_confirmed_slots: &mut DuplicateConfirmedSlots,
        unfrozen_gossip_verified_vote_hashes: &mut UnfrozenGossipVerifiedVoteHashes,
        vote_signatures: &mut Vec<Signature>,
        has_new_vote_been_rooted: &mut bool,
        replay_timing: &mut ReplayLoopTiming,
        voting_sender: &Sender<VoteOp>,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        drop_bank_sender: &Sender<Vec<BankWithScheduler>>,
        wait_to_vote_slot: Option<Slot>,
    ) -> Result<(), SetRootError> {
        if bank.is_empty() {
            datapoint_info!("replay_stage-voted_empty_bank", ("slot", bank.slot(), i64));
        }
        trace!("handle votable bank {}", bank.slot());
        let new_root = tower.record_bank_vote(bank);

        if let Some(new_root) = new_root {
            // get the root bank before squash
            let root_bank = bank_forks
                .read()
                .unwrap()
                .get(new_root)
                .expect("Root bank doesn't exist");
            let mut rooted_banks = root_bank.parents();
            let oldest_parent = rooted_banks.last().map(|last| last.parent_slot());
            rooted_banks.push(root_bank.clone());
            let rooted_slots: Vec<_> = rooted_banks.iter().map(|bank| bank.slot()).collect();
            // The following differs from  rooted_slots by including the parent slot of the oldest parent bank.
            let rooted_slots_with_parents = bank_notification_sender
                .as_ref()
                .map_or(false, |sender| sender.should_send_parents)
                .then(|| {
                    let mut new_chain = rooted_slots.clone();
                    new_chain.push(oldest_parent.unwrap_or_else(|| bank.parent_slot()));
                    new_chain
                });

            // Call leader schedule_cache.set_root() before blockstore.set_root() because
            // bank_forks.root is consumed by repair_service to update gossip, so we don't want to
            // get shreds for repair on gossip before we update leader schedule, otherwise they may
            // get dropped.
            leader_schedule_cache.set_root(rooted_banks.last().unwrap());
            blockstore
                .set_roots(rooted_slots.iter())
                .expect("Ledger set roots failed");
            let highest_super_majority_root = Some(
                block_commitment_cache
                    .read()
                    .unwrap()
                    .highest_super_majority_root(),
            );
            Self::handle_new_root(
                new_root,
                bank_forks,
                progress,
                accounts_background_request_sender,
                highest_super_majority_root,
                heaviest_subtree_fork_choice,
                duplicate_slots_tracker,
                duplicate_confirmed_slots,
                unfrozen_gossip_verified_vote_hashes,
                has_new_vote_been_rooted,
                vote_signatures,
                epoch_slots_frozen_slots,
                drop_bank_sender,
            )?;

            blockstore.slots_stats.mark_rooted(new_root);

            rpc_subscriptions.notify_roots(rooted_slots);
            if let Some(sender) = bank_notification_sender {
                sender
                    .sender
                    .send(BankNotification::NewRootBank(root_bank))
                    .unwrap_or_else(|err| warn!("bank_notification_sender failed: {:?}", err));

                if let Some(new_chain) = rooted_slots_with_parents {
                    sender
                        .sender
                        .send(BankNotification::NewRootedChain(new_chain))
                        .unwrap_or_else(|err| warn!("bank_notification_sender failed: {:?}", err));
                }
            }
            info!("new root {}", new_root);
        }

        let mut update_commitment_cache_time = Measure::start("update_commitment_cache");
        Self::update_commitment_cache(
            bank.clone(),
            bank_forks.read().unwrap().root(),
            progress.get_fork_stats(bank.slot()).unwrap().total_stake,
            lockouts_sender,
        );
        update_commitment_cache_time.stop();
        replay_timing.update_commitment_cache_us += update_commitment_cache_time.as_us();

        Self::push_vote(
            bank,
            vote_account_pubkey,
            identity_keypair,
            authorized_voter_keypairs,
            tower,
            switch_fork_decision,
            vote_signatures,
            *has_new_vote_been_rooted,
            replay_timing,
            voting_sender,
            wait_to_vote_slot,
        );
        Ok(())
    }

    fn generate_vote_tx(
        node_keypair: &Keypair,
        bank: &Bank,
        vote_account_pubkey: &Pubkey,
        authorized_voter_keypairs: &[Arc<Keypair>],
        vote: VoteTransaction,
        switch_fork_decision: &SwitchForkDecision,
        vote_signatures: &mut Vec<Signature>,
        has_new_vote_been_rooted: bool,
        wait_to_vote_slot: Option<Slot>,
    ) -> GenerateVoteTxResult {
        if !bank.is_startup_verification_complete() {
            info!("startup verification incomplete, so unable to vote");
            return GenerateVoteTxResult::Failed;
        }

        if authorized_voter_keypairs.is_empty() {
            return GenerateVoteTxResult::NonVoting;
        }
        if let Some(slot) = wait_to_vote_slot {
            if bank.slot() < slot {
                return GenerateVoteTxResult::Failed;
            }
        }
        let vote_account = match bank.get_vote_account(vote_account_pubkey) {
            None => {
                warn!(
                    "Vote account {} does not exist.  Unable to vote",
                    vote_account_pubkey,
                );
                return GenerateVoteTxResult::Failed;
            }
            Some(vote_account) => vote_account,
        };
        let vote_state = vote_account.vote_state();
        let vote_state = match vote_state.as_ref() {
            Err(_) => {
                warn!(
                    "Vote account {} is unreadable.  Unable to vote",
                    vote_account_pubkey,
                );
                return GenerateVoteTxResult::Failed;
            }
            Ok(vote_state) => vote_state,
        };

        if vote_state.node_pubkey != node_keypair.pubkey() {
            info!(
                "Vote account node_pubkey mismatch: {} (expected: {}).  Unable to vote",
                vote_state.node_pubkey,
                node_keypair.pubkey()
            );
            return GenerateVoteTxResult::Failed;
        }

        let Some(authorized_voter_pubkey) = vote_state.get_authorized_voter(bank.epoch()) else {
            warn!(
                "Vote account {} has no authorized voter for epoch {}.  Unable to vote",
                vote_account_pubkey,
                bank.epoch()
            );
            return GenerateVoteTxResult::Failed;
        };

        let authorized_voter_keypair = match authorized_voter_keypairs
            .iter()
            .find(|keypair| keypair.pubkey() == authorized_voter_pubkey)
        {
            None => {
                warn!("The authorized keypair {} for vote account {} is not available.  Unable to vote",
                      authorized_voter_pubkey, vote_account_pubkey);
                return GenerateVoteTxResult::NonVoting;
            }
            Some(authorized_voter_keypair) => authorized_voter_keypair,
        };

        // Send our last few votes along with the new one
        // Compact the vote state update before sending
        let vote = match vote {
            VoteTransaction::VoteStateUpdate(vote_state_update) => {
                VoteTransaction::CompactVoteStateUpdate(vote_state_update)
            }
            vote => vote,
        };
        let vote_ix = switch_fork_decision
            .to_vote_instruction(
                vote,
                vote_account_pubkey,
                &authorized_voter_keypair.pubkey(),
            )
            .expect("Switch threshold failure should not lead to voting");

        let mut vote_tx = Transaction::new_with_payer(&[vote_ix], Some(&node_keypair.pubkey()));

        let blockhash = bank.last_blockhash();
        vote_tx.partial_sign(&[node_keypair], blockhash);
        vote_tx.partial_sign(&[authorized_voter_keypair.as_ref()], blockhash);

        if !has_new_vote_been_rooted {
            vote_signatures.push(vote_tx.signatures[0]);
            if vote_signatures.len() > MAX_VOTE_SIGNATURES {
                vote_signatures.remove(0);
            }
        } else {
            vote_signatures.clear();
        }

        GenerateVoteTxResult::Tx(vote_tx)
    }

    #[allow(clippy::too_many_arguments)]
    fn refresh_last_vote(
        tower: &mut Tower,
        heaviest_bank_on_same_fork: &Bank,
        my_latest_landed_vote: Slot,
        vote_account_pubkey: &Pubkey,
        identity_keypair: &Keypair,
        authorized_voter_keypairs: &[Arc<Keypair>],
        vote_signatures: &mut Vec<Signature>,
        has_new_vote_been_rooted: bool,
        last_vote_refresh_time: &mut LastVoteRefreshTime,
        voting_sender: &Sender<VoteOp>,
        wait_to_vote_slot: Option<Slot>,
    ) {
        let last_voted_slot = tower.last_voted_slot();
        if last_voted_slot.is_none() {
            return;
        }

        // Refresh the vote if our latest vote hasn't landed, and the recent blockhash of the
        // last attempt at a vote transaction has expired
        let last_voted_slot = last_voted_slot.unwrap();
        if my_latest_landed_vote > last_voted_slot
            && last_vote_refresh_time.last_print_time.elapsed().as_secs() >= 1
        {
            last_vote_refresh_time.last_print_time = Instant::now();
            info!(
                "Last landed vote for slot {} in bank {} is greater than the current last vote for slot: {} tracked by Tower",
                my_latest_landed_vote,
                heaviest_bank_on_same_fork.slot(),
                last_voted_slot
            );
        }

        // If we are a non voting validator or have an incorrect setup preventing us from
        // generating vote txs, no need to refresh
        let last_vote_tx_blockhash = match tower.last_vote_tx_blockhash() {
            // Since the checks in vote generation are deterministic, if we were non voting
            // on the original vote, the refresh will also fail. No reason to refresh.
            BlockhashStatus::NonVoting => return,
            // In this case we have not voted since restart, it is unclear if we are non voting.
            // Attempt to refresh.
            BlockhashStatus::Uninitialized => None,
            // Refresh if the blockhash is expired
            BlockhashStatus::Blockhash(blockhash) => Some(blockhash),
        };

        if my_latest_landed_vote >= last_voted_slot
            || {
                last_vote_tx_blockhash.is_some()
                    && heaviest_bank_on_same_fork
                        .is_hash_valid_for_age(&last_vote_tx_blockhash.unwrap(), MAX_PROCESSING_AGE)
            }
            || {
                // In order to avoid voting on multiple forks all past MAX_PROCESSING_AGE that don't
                // include the last voted blockhash
                last_vote_refresh_time
                    .last_refresh_time
                    .elapsed()
                    .as_millis()
                    < MAX_VOTE_REFRESH_INTERVAL_MILLIS as u128
            }
        {
            return;
        }

        // Update timestamp for refreshed vote
        tower.refresh_last_vote_timestamp(heaviest_bank_on_same_fork.slot());

        let vote_tx_result = Self::generate_vote_tx(
            identity_keypair,
            heaviest_bank_on_same_fork,
            vote_account_pubkey,
            authorized_voter_keypairs,
            tower.last_vote(),
            &SwitchForkDecision::SameFork,
            vote_signatures,
            has_new_vote_been_rooted,
            wait_to_vote_slot,
        );

        if let GenerateVoteTxResult::Tx(vote_tx) = vote_tx_result {
            let recent_blockhash = vote_tx.message.recent_blockhash;
            tower.refresh_last_vote_tx_blockhash(recent_blockhash);

            // Send the votes to the TPU and gossip for network propagation
            let hash_string = format!("{recent_blockhash}");
            datapoint_info!(
                "refresh_vote",
                ("last_voted_slot", last_voted_slot, i64),
                ("target_bank_slot", heaviest_bank_on_same_fork.slot(), i64),
                ("target_bank_hash", hash_string, String),
            );
            voting_sender
                .send(VoteOp::RefreshVote {
                    tx: vote_tx,
                    last_voted_slot,
                })
                .unwrap_or_else(|err| warn!("Error: {:?}", err));
            last_vote_refresh_time.last_refresh_time = Instant::now();
        } else if vote_tx_result.is_non_voting() {
            tower.mark_last_vote_tx_blockhash_non_voting();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_vote(
        bank: &Bank,
        vote_account_pubkey: &Pubkey,
        identity_keypair: &Keypair,
        authorized_voter_keypairs: &[Arc<Keypair>],
        tower: &mut Tower,
        switch_fork_decision: &SwitchForkDecision,
        vote_signatures: &mut Vec<Signature>,
        has_new_vote_been_rooted: bool,
        replay_timing: &mut ReplayLoopTiming,
        voting_sender: &Sender<VoteOp>,
        wait_to_vote_slot: Option<Slot>,
    ) {
        let mut generate_time = Measure::start("generate_vote");
        let vote_tx_result = Self::generate_vote_tx(
            identity_keypair,
            bank,
            vote_account_pubkey,
            authorized_voter_keypairs,
            tower.last_vote(),
            switch_fork_decision,
            vote_signatures,
            has_new_vote_been_rooted,
            wait_to_vote_slot,
        );
        generate_time.stop();
        replay_timing.generate_vote_us += generate_time.as_us();
        if let GenerateVoteTxResult::Tx(vote_tx) = vote_tx_result {
            tower.refresh_last_vote_tx_blockhash(vote_tx.message.recent_blockhash);

            let saved_tower = SavedTower::new(tower, identity_keypair).unwrap_or_else(|err| {
                error!("Unable to create saved tower: {:?}", err);
                std::process::exit(1);
            });

            let tower_slots = tower.tower_slots();
            voting_sender
                .send(VoteOp::PushVote {
                    tx: vote_tx,
                    tower_slots,
                    saved_tower: SavedTowerVersions::from(saved_tower),
                })
                .unwrap_or_else(|err| warn!("Error: {:?}", err));
        } else if vote_tx_result.is_non_voting() {
            tower.mark_last_vote_tx_blockhash_non_voting();
        }
    }

    fn update_commitment_cache(
        bank: Arc<Bank>,
        root: Slot,
        total_stake: Stake,
        lockouts_sender: &Sender<CommitmentAggregationData>,
    ) {
        if let Err(e) =
            lockouts_sender.send(CommitmentAggregationData::new(bank, root, total_stake))
        {
            trace!("lockouts_sender failed: {:?}", e);
        }
    }

    fn reset_poh_recorder(
        my_pubkey: &Pubkey,
        blockstore: &Blockstore,
        bank: Arc<Bank>,
        poh_recorder: &RwLock<PohRecorder>,
        leader_schedule_cache: &LeaderScheduleCache,
    ) {
        let slot = bank.slot();
        let tick_height = bank.tick_height();

        let next_leader_slot = leader_schedule_cache.next_leader_slot(
            my_pubkey,
            slot,
            &bank,
            Some(blockstore),
            GRACE_TICKS_FACTOR * MAX_GRACE_SLOTS,
        );

        poh_recorder.write().unwrap().reset(bank, next_leader_slot);

        let next_leader_msg = if let Some(next_leader_slot) = next_leader_slot {
            format!("My next leader slot is {}", next_leader_slot.0)
        } else {
            "I am not in the leader schedule yet".to_owned()
        };
        info!(
            "{my_pubkey} reset PoH to tick {tick_height} (within slot {slot}). {next_leader_msg}",
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_active_banks_concurrently(
        blockstore: &Blockstore,
        bank_forks: &RwLock<BankForks>,
        fork_thread_pool: &ThreadPool,
        replay_tx_thread_pool: &ThreadPool,
        my_pubkey: &Pubkey,
        vote_account: &Pubkey,
        progress: &mut ProgressMap,
        transaction_status_sender: Option<&TransactionStatusSender>,
        entry_notification_sender: Option<&EntryNotifierSender>,
        verify_recyclers: &VerifyRecyclers,
        replay_vote_sender: &ReplayVoteSender,
        replay_timing: &mut ReplayLoopTiming,
        log_messages_bytes_limit: Option<usize>,
        active_bank_slots: &[Slot],
        prioritization_fee_cache: &PrioritizationFeeCache,
    ) -> Vec<ReplaySlotFromBlockstore> {
        // Make mutable shared structures thread safe.
        let progress = RwLock::new(progress);
        let longest_replay_time_us = AtomicU64::new(0);

        // Allow for concurrent replaying of slots from different forks.
        let replay_result_vec: Vec<ReplaySlotFromBlockstore> = fork_thread_pool.install(|| {
            active_bank_slots
                .into_par_iter()
                .map(|bank_slot| {
                    let bank_slot = *bank_slot;
                    let mut replay_result = ReplaySlotFromBlockstore {
                        is_slot_dead: false,
                        bank_slot,
                        replay_result: None,
                    };
                    let my_pubkey = &my_pubkey.clone();
                    trace!(
                        "Replay active bank: slot {}, thread_idx {}",
                        bank_slot,
                        fork_thread_pool.current_thread_index().unwrap_or_default()
                    );
                    let mut progress_lock = progress.write().unwrap();
                    if progress_lock
                        .get(&bank_slot)
                        .map(|p| p.is_dead)
                        .unwrap_or(false)
                    {
                        // If the fork was marked as dead, don't replay it
                        debug!("bank_slot {:?} is marked dead", bank_slot);
                        replay_result.is_slot_dead = true;
                        return replay_result;
                    }

                    let bank = bank_forks
                        .read()
                        .unwrap()
                        .get_with_scheduler(bank_slot)
                        .unwrap();
                    let parent_slot = bank.parent_slot();
                    let (num_blocks_on_fork, num_dropped_blocks_on_fork) = {
                        let stats = progress_lock
                            .get(&parent_slot)
                            .expect("parent of active bank must exist in progress map");
                        let num_blocks_on_fork = stats.num_blocks_on_fork + 1;
                        let new_dropped_blocks = bank.slot() - parent_slot - 1;
                        let num_dropped_blocks_on_fork =
                            stats.num_dropped_blocks_on_fork + new_dropped_blocks;
                        (num_blocks_on_fork, num_dropped_blocks_on_fork)
                    };
                    let prev_leader_slot = progress_lock.get_bank_prev_leader_slot(&bank);

                    let bank_progress = progress_lock.entry(bank.slot()).or_insert_with(|| {
                        ForkProgress::new_from_bank(
                            &bank,
                            my_pubkey,
                            &vote_account.clone(),
                            prev_leader_slot,
                            num_blocks_on_fork,
                            num_dropped_blocks_on_fork,
                        )
                    });

                    let replay_stats = bank_progress.replay_stats.clone();
                    let replay_progress = bank_progress.replay_progress.clone();
                    drop(progress_lock);

                    if bank.collector_id() != my_pubkey {
                        let mut replay_blockstore_time =
                            Measure::start("replay_blockstore_into_bank");
                        let blockstore_result = Self::replay_blockstore_into_bank(
                            &bank,
                            blockstore,
                            replay_tx_thread_pool,
                            &replay_stats,
                            &replay_progress,
                            transaction_status_sender,
                            entry_notification_sender,
                            &replay_vote_sender.clone(),
                            &verify_recyclers.clone(),
                            log_messages_bytes_limit,
                            prioritization_fee_cache,
                        );
                        replay_blockstore_time.stop();
                        replay_result.replay_result = Some(blockstore_result);
                        longest_replay_time_us
                            .fetch_max(replay_blockstore_time.as_us(), Ordering::Relaxed);
                    }
                    replay_result
                })
                .collect()
        });
        // Accumulating time across all slots could inflate this number and make it seem like an
        // overly large amount of time is being spent on blockstore compared to other activities.
        replay_timing.replay_blockstore_us += longest_replay_time_us.load(Ordering::Relaxed);

        replay_result_vec
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_active_bank(
        blockstore: &Blockstore,
        bank_forks: &RwLock<BankForks>,
        replay_tx_thread_pool: &ThreadPool,
        my_pubkey: &Pubkey,
        vote_account: &Pubkey,
        progress: &mut ProgressMap,
        transaction_status_sender: Option<&TransactionStatusSender>,
        entry_notification_sender: Option<&EntryNotifierSender>,
        verify_recyclers: &VerifyRecyclers,
        replay_vote_sender: &ReplayVoteSender,
        replay_timing: &mut ReplayLoopTiming,
        log_messages_bytes_limit: Option<usize>,
        bank_slot: Slot,
        prioritization_fee_cache: &PrioritizationFeeCache,
    ) -> ReplaySlotFromBlockstore {
        let mut replay_result = ReplaySlotFromBlockstore {
            is_slot_dead: false,
            bank_slot,
            replay_result: None,
        };
        let my_pubkey = &my_pubkey.clone();
        trace!("Replay active bank: slot {}", bank_slot);
        if progress.get(&bank_slot).map(|p| p.is_dead).unwrap_or(false) {
            // If the fork was marked as dead, don't replay it
            debug!("bank_slot {:?} is marked dead", bank_slot);
            replay_result.is_slot_dead = true;
        } else {
            let bank = bank_forks
                .read()
                .unwrap()
                .get_with_scheduler(bank_slot)
                .unwrap();
            let parent_slot = bank.parent_slot();
            let prev_leader_slot = progress.get_bank_prev_leader_slot(&bank);
            let (num_blocks_on_fork, num_dropped_blocks_on_fork) = {
                let stats = progress
                    .get(&parent_slot)
                    .expect("parent of active bank must exist in progress map");
                let num_blocks_on_fork = stats.num_blocks_on_fork + 1;
                let new_dropped_blocks = bank.slot() - parent_slot - 1;
                let num_dropped_blocks_on_fork =
                    stats.num_dropped_blocks_on_fork + new_dropped_blocks;
                (num_blocks_on_fork, num_dropped_blocks_on_fork)
            };

            let bank_progress = progress.entry(bank.slot()).or_insert_with(|| {
                ForkProgress::new_from_bank(
                    &bank,
                    my_pubkey,
                    &vote_account.clone(),
                    prev_leader_slot,
                    num_blocks_on_fork,
                    num_dropped_blocks_on_fork,
                )
            });

            if bank.collector_id() != my_pubkey {
                let mut replay_blockstore_time = Measure::start("replay_blockstore_into_bank");
                let blockstore_result = Self::replay_blockstore_into_bank(
                    &bank,
                    blockstore,
                    replay_tx_thread_pool,
                    &bank_progress.replay_stats,
                    &bank_progress.replay_progress,
                    transaction_status_sender,
                    entry_notification_sender,
                    &replay_vote_sender.clone(),
                    &verify_recyclers.clone(),
                    log_messages_bytes_limit,
                    prioritization_fee_cache,
                );
                replay_blockstore_time.stop();
                replay_result.replay_result = Some(blockstore_result);
                replay_timing.replay_blockstore_us += replay_blockstore_time.as_us();
            }
        }
        replay_result
    }

    #[allow(clippy::too_many_arguments)]
    fn process_replay_results(
        blockstore: &Blockstore,
        bank_forks: &RwLock<BankForks>,
        progress: &mut ProgressMap,
        transaction_status_sender: Option<&TransactionStatusSender>,
        cache_block_meta_sender: Option<&CacheBlockMetaSender>,
        heaviest_subtree_fork_choice: &mut HeaviestSubtreeForkChoice,
        bank_notification_sender: &Option<BankNotificationSenderConfig>,
        rewards_recorder_sender: &Option<RewardsRecorderSender>,
        rpc_subscriptions: &Arc<RpcSubscriptions>,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        duplicate_confirmed_slots: &DuplicateConfirmedSlots,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        unfrozen_gossip_verified_vote_hashes: &mut UnfrozenGossipVerifiedVoteHashes,
        latest_validator_votes_for_frozen_banks: &mut LatestValidatorVotesForFrozenBanks,
        cluster_slots_update_sender: &ClusterSlotsUpdateSender,
        cost_update_sender: &Sender<CostUpdate>,
        duplicate_slots_to_repair: &mut DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: &AncestorHashesReplayUpdateSender,
        block_metadata_notifier: Option<BlockMetadataNotifierArc>,
        replay_result_vec: &[ReplaySlotFromBlockstore],
        purge_repair_slot_counter: &mut PurgeRepairSlotCounter,
        my_pubkey: &Pubkey,
    ) -> bool {
        // TODO: See if processing of blockstore replay results and bank completion can be made thread safe.
        let mut did_complete_bank = false;
        let mut tx_count = 0;
        let mut execute_timings = ExecuteTimings::default();
        for replay_result in replay_result_vec {
            if replay_result.is_slot_dead {
                continue;
            }

            let bank_slot = replay_result.bank_slot;
            let bank = &bank_forks
                .read()
                .unwrap()
                .get_with_scheduler(bank_slot)
                .unwrap();
            if let Some(replay_result) = &replay_result.replay_result {
                match replay_result {
                    Ok(replay_tx_count) => tx_count += replay_tx_count,
                    Err(err) => {
                        let root = bank_forks.read().unwrap().root();
                        Self::mark_dead_slot(
                            blockstore,
                            bank,
                            root,
                            err,
                            rpc_subscriptions,
                            duplicate_slots_tracker,
                            duplicate_confirmed_slots,
                            epoch_slots_frozen_slots,
                            progress,
                            heaviest_subtree_fork_choice,
                            duplicate_slots_to_repair,
                            ancestor_hashes_replay_update_sender,
                            purge_repair_slot_counter,
                        );
                        // don't try to run the below logic to check if the bank is completed
                        continue;
                    }
                }
            }

            assert_eq!(bank_slot, bank.slot());
            if bank.is_complete() {
                let mut bank_complete_time = Measure::start("bank_complete_time");
                let bank_progress = progress
                    .get_mut(&bank.slot())
                    .expect("Bank fork progress entry missing for completed bank");

                let replay_stats = bank_progress.replay_stats.clone();
                let mut is_unified_scheduler_enabled = false;

                if let Some((result, completed_execute_timings)) =
                    bank.wait_for_completed_scheduler()
                {
                    // It's guaranteed that wait_for_completed_scheduler() returns Some(_), iff the
                    // unified scheduler is enabled for the bank.
                    is_unified_scheduler_enabled = true;
                    let metrics = ExecuteBatchesInternalMetrics::new_with_timings_from_all_threads(
                        completed_execute_timings,
                    );
                    replay_stats
                        .write()
                        .unwrap()
                        .batch_execute
                        .accumulate(metrics, is_unified_scheduler_enabled);

                    if let Err(err) = result {
                        let root = bank_forks.read().unwrap().root();
                        Self::mark_dead_slot(
                            blockstore,
                            bank,
                            root,
                            &BlockstoreProcessorError::InvalidTransaction(err),
                            rpc_subscriptions,
                            duplicate_slots_tracker,
                            duplicate_confirmed_slots,
                            epoch_slots_frozen_slots,
                            progress,
                            heaviest_subtree_fork_choice,
                            duplicate_slots_to_repair,
                            ancestor_hashes_replay_update_sender,
                            purge_repair_slot_counter,
                        );
                        // don't try to run the remaining normal processing for the completed bank
                        continue;
                    }
                }

                if bank.collector_id() != my_pubkey {
                    // If the block does not have at least DATA_SHREDS_PER_FEC_BLOCK shreds in the last FEC set,
                    // mark it dead. No reason to perform this check on our leader block.
                    if !blockstore
                        .is_last_fec_set_full(bank.slot())
                        .inspect_err(|e| {
                            warn!(
                                "Unable to determine if last fec set is full for slot {} {},
                                marking as dead: {e:?}",
                                bank.slot(),
                                bank.hash()
                            )
                        })
                        .unwrap_or(false)
                    {
                        // Update metric regardless of feature flag
                        datapoint_warn!(
                            "incomplete_final_fec_set",
                            ("slot", bank_slot, i64),
                            ("hash", bank.hash().to_string(), String)
                        );
                        if bank
                            .feature_set
                            .is_active(&solana_sdk::feature_set::vote_only_full_fec_sets::id())
                        {
                            let root = bank_forks.read().unwrap().root();
                            Self::mark_dead_slot(
                                blockstore,
                                bank,
                                root,
                                &BlockstoreProcessorError::IncompleteFinalFecSet,
                                rpc_subscriptions,
                                duplicate_slots_tracker,
                                duplicate_confirmed_slots,
                                epoch_slots_frozen_slots,
                                progress,
                                heaviest_subtree_fork_choice,
                                duplicate_slots_to_repair,
                                ancestor_hashes_replay_update_sender,
                                purge_repair_slot_counter,
                            );
                            continue;
                        }
                    }
                }

                let r_replay_stats = replay_stats.read().unwrap();
                let replay_progress = bank_progress.replay_progress.clone();
                let r_replay_progress = replay_progress.read().unwrap();
                debug!(
                    "bank {} has completed replay from blockstore, \
                     contribute to update cost with {:?}",
                    bank.slot(),
                    r_replay_stats.batch_execute.totals
                );
                did_complete_bank = true;
                let _ = cluster_slots_update_sender.send(vec![bank_slot]);
                if let Some(transaction_status_sender) = transaction_status_sender {
                    transaction_status_sender.send_transaction_status_freeze_message(bank);
                }
                bank.freeze();
                datapoint_info!(
                    "bank_frozen",
                    ("slot", bank_slot, i64),
                    ("hash", bank.hash().to_string(), String),
                );
                // report cost tracker stats
                cost_update_sender
                    .send(CostUpdate::FrozenBank {
                        bank: bank.clone_without_scheduler(),
                    })
                    .unwrap_or_else(|err| {
                        warn!("cost_update_sender failed sending bank stats: {:?}", err)
                    });

                assert_ne!(bank.hash(), Hash::default());
                // Needs to be updated before `check_slot_agrees_with_cluster()` so that
                // any updates in `check_slot_agrees_with_cluster()` on fork choice take
                // effect
                heaviest_subtree_fork_choice.add_new_leaf_slot(
                    (bank.slot(), bank.hash()),
                    Some((bank.parent_slot(), bank.parent_hash())),
                );
                bank_progress.fork_stats.bank_hash = Some(bank.hash());
                let bank_frozen_state = BankFrozenState::new_from_state(
                    bank.slot(),
                    bank.hash(),
                    duplicate_slots_tracker,
                    duplicate_confirmed_slots,
                    heaviest_subtree_fork_choice,
                    epoch_slots_frozen_slots,
                );
                check_slot_agrees_with_cluster(
                    bank.slot(),
                    bank_forks.read().unwrap().root(),
                    blockstore,
                    duplicate_slots_tracker,
                    epoch_slots_frozen_slots,
                    heaviest_subtree_fork_choice,
                    duplicate_slots_to_repair,
                    ancestor_hashes_replay_update_sender,
                    purge_repair_slot_counter,
                    SlotStateUpdate::BankFrozen(bank_frozen_state),
                );
                // If we previously marked this slot as duplicate in blockstore, let the state machine know
                if !duplicate_slots_tracker.contains(&bank.slot())
                    && blockstore.get_duplicate_slot(bank.slot()).is_some()
                {
                    let duplicate_state = DuplicateState::new_from_state(
                        bank.slot(),
                        duplicate_confirmed_slots,
                        heaviest_subtree_fork_choice,
                        || false,
                        || Some(bank.hash()),
                    );
                    check_slot_agrees_with_cluster(
                        bank.slot(),
                        bank_forks.read().unwrap().root(),
                        blockstore,
                        duplicate_slots_tracker,
                        epoch_slots_frozen_slots,
                        heaviest_subtree_fork_choice,
                        duplicate_slots_to_repair,
                        ancestor_hashes_replay_update_sender,
                        purge_repair_slot_counter,
                        SlotStateUpdate::Duplicate(duplicate_state),
                    );
                }
                if let Some(sender) = bank_notification_sender {
                    sender
                        .sender
                        .send(BankNotification::Frozen(bank.clone_without_scheduler()))
                        .unwrap_or_else(|err| warn!("bank_notification_sender failed: {:?}", err));
                }
                blockstore_processor::cache_block_meta(bank, cache_block_meta_sender);

                let bank_hash = bank.hash();
                if let Some(new_frozen_voters) =
                    unfrozen_gossip_verified_vote_hashes.remove_slot_hash(bank.slot(), &bank_hash)
                {
                    for pubkey in new_frozen_voters {
                        latest_validator_votes_for_frozen_banks.check_add_vote(
                            pubkey,
                            bank.slot(),
                            Some(bank_hash),
                            false,
                        );
                    }
                }
                Self::record_rewards(bank, rewards_recorder_sender);
                if let Some(ref block_metadata_notifier) = block_metadata_notifier {
                    let parent_blockhash = bank
                        .parent()
                        .map(|bank| bank.last_blockhash())
                        .unwrap_or_default();
                    block_metadata_notifier.notify_block_metadata(
                        bank.parent_slot(),
                        &parent_blockhash.to_string(),
                        bank.slot(),
                        &bank.last_blockhash().to_string(),
                        &bank.rewards,
                        Some(bank.clock().unix_timestamp),
                        Some(bank.block_height()),
                        bank.executed_transaction_count(),
                        r_replay_progress.num_entries as u64,
                    )
                }
                bank_complete_time.stop();

                r_replay_stats.report_stats(
                    bank.slot(),
                    r_replay_progress.num_txs,
                    r_replay_progress.num_entries,
                    r_replay_progress.num_shreds,
                    bank_complete_time.as_us(),
                    is_unified_scheduler_enabled,
                );
                execute_timings.accumulate(&r_replay_stats.batch_execute.totals);
            } else {
                trace!(
                    "bank {} not completed tick_height: {}, max_tick_height: {}",
                    bank.slot(),
                    bank.tick_height(),
                    bank.max_tick_height()
                );
            }
        }

        did_complete_bank
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_active_banks(
        blockstore: &Blockstore,
        bank_forks: &RwLock<BankForks>,
        my_pubkey: &Pubkey,
        vote_account: &Pubkey,
        progress: &mut ProgressMap,
        transaction_status_sender: Option<&TransactionStatusSender>,
        cache_block_meta_sender: Option<&CacheBlockMetaSender>,
        entry_notification_sender: Option<&EntryNotifierSender>,
        verify_recyclers: &VerifyRecyclers,
        heaviest_subtree_fork_choice: &mut HeaviestSubtreeForkChoice,
        replay_vote_sender: &ReplayVoteSender,
        bank_notification_sender: &Option<BankNotificationSenderConfig>,
        rewards_recorder_sender: &Option<RewardsRecorderSender>,
        rpc_subscriptions: &Arc<RpcSubscriptions>,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        duplicate_confirmed_slots: &DuplicateConfirmedSlots,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        unfrozen_gossip_verified_vote_hashes: &mut UnfrozenGossipVerifiedVoteHashes,
        latest_validator_votes_for_frozen_banks: &mut LatestValidatorVotesForFrozenBanks,
        cluster_slots_update_sender: &ClusterSlotsUpdateSender,
        cost_update_sender: &Sender<CostUpdate>,
        duplicate_slots_to_repair: &mut DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: &AncestorHashesReplayUpdateSender,
        block_metadata_notifier: Option<BlockMetadataNotifierArc>,
        replay_timing: &mut ReplayLoopTiming,
        log_messages_bytes_limit: Option<usize>,
        replay_mode: &ForkReplayMode,
        replay_tx_thread_pool: &ThreadPool,
        prioritization_fee_cache: &PrioritizationFeeCache,
        purge_repair_slot_counter: &mut PurgeRepairSlotCounter,
    ) -> bool /* completed a bank */ {
        let active_bank_slots = bank_forks.read().unwrap().active_bank_slots();
        let num_active_banks = active_bank_slots.len();
        trace!(
            "{} active bank(s) to replay: {:?}",
            num_active_banks,
            active_bank_slots
        );
        if active_bank_slots.is_empty() {
            return false;
        }

        let replay_result_vec = match replay_mode {
            // Skip the overhead of the threadpool if there is only one bank to play
            ForkReplayMode::Parallel(fork_thread_pool) if num_active_banks > 1 => {
                Self::replay_active_banks_concurrently(
                    blockstore,
                    bank_forks,
                    fork_thread_pool,
                    replay_tx_thread_pool,
                    my_pubkey,
                    vote_account,
                    progress,
                    transaction_status_sender,
                    entry_notification_sender,
                    verify_recyclers,
                    replay_vote_sender,
                    replay_timing,
                    log_messages_bytes_limit,
                    &active_bank_slots,
                    prioritization_fee_cache,
                )
            }
            ForkReplayMode::Serial | ForkReplayMode::Parallel(_) => active_bank_slots
                .iter()
                .map(|bank_slot| {
                    Self::replay_active_bank(
                        blockstore,
                        bank_forks,
                        replay_tx_thread_pool,
                        my_pubkey,
                        vote_account,
                        progress,
                        transaction_status_sender,
                        entry_notification_sender,
                        verify_recyclers,
                        replay_vote_sender,
                        replay_timing,
                        log_messages_bytes_limit,
                        *bank_slot,
                        prioritization_fee_cache,
                    )
                })
                .collect(),
        };

        Self::process_replay_results(
            blockstore,
            bank_forks,
            progress,
            transaction_status_sender,
            cache_block_meta_sender,
            heaviest_subtree_fork_choice,
            bank_notification_sender,
            rewards_recorder_sender,
            rpc_subscriptions,
            duplicate_slots_tracker,
            duplicate_confirmed_slots,
            epoch_slots_frozen_slots,
            unfrozen_gossip_verified_vote_hashes,
            latest_validator_votes_for_frozen_banks,
            cluster_slots_update_sender,
            cost_update_sender,
            duplicate_slots_to_repair,
            ancestor_hashes_replay_update_sender,
            block_metadata_notifier,
            &replay_result_vec,
            purge_repair_slot_counter,
            my_pubkey,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compute_bank_stats(
        my_vote_pubkey: &Pubkey,
        ancestors: &HashMap<u64, HashSet<u64>>,
        frozen_banks: &mut [Arc<Bank>],
        tower: &mut Tower,
        progress: &mut ProgressMap,
        vote_tracker: &VoteTracker,
        cluster_slots: &ClusterSlots,
        bank_forks: &RwLock<BankForks>,
        heaviest_subtree_fork_choice: &mut HeaviestSubtreeForkChoice,
        latest_validator_votes_for_frozen_banks: &mut LatestValidatorVotesForFrozenBanks,
    ) -> Vec<Slot> {
        frozen_banks.sort_by_key(|bank| bank.slot());
        let mut new_stats = vec![];
        for bank in frozen_banks.iter() {
            let bank_slot = bank.slot();
            // Only time progress map should be missing a bank slot
            // is if this node was the leader for this slot as those banks
            // are not replayed in replay_active_banks()
            {
                let is_computed = progress
                    .get_fork_stats_mut(bank_slot)
                    .expect("All frozen banks must exist in the Progress map")
                    .computed;
                if !is_computed {
                    // Check if our tower is behind, if so adopt the on chain tower from this Bank
                    Self::adopt_on_chain_tower_if_behind(
                        my_vote_pubkey,
                        ancestors,
                        frozen_banks,
                        tower,
                        progress,
                        bank,
                    );
                    let computed_bank_state = Tower::collect_vote_lockouts(
                        my_vote_pubkey,
                        bank_slot,
                        &bank.vote_accounts(),
                        ancestors,
                        |slot| progress.get_hash(slot),
                        latest_validator_votes_for_frozen_banks,
                    );
                    // Notify any listeners of the votes found in this newly computed
                    // bank
                    heaviest_subtree_fork_choice.compute_bank_stats(
                        bank,
                        tower,
                        latest_validator_votes_for_frozen_banks,
                    );
                    let ComputedBankState {
                        voted_stakes,
                        total_stake,
                        fork_stake,
                        lockout_intervals,
                        my_latest_landed_vote,
                        ..
                    } = computed_bank_state;
                    let stats = progress
                        .get_fork_stats_mut(bank_slot)
                        .expect("All frozen banks must exist in the Progress map");
                    stats.fork_stake = fork_stake;
                    stats.total_stake = total_stake;
                    stats.voted_stakes = voted_stakes;
                    stats.lockout_intervals = lockout_intervals;
                    stats.block_height = bank.block_height();
                    stats.my_latest_landed_vote = my_latest_landed_vote;
                    stats.computed = true;
                    new_stats.push(bank_slot);
                    datapoint_info!(
                        "bank_weight",
                        ("slot", bank_slot, i64),
                        ("fork_stake", stats.fork_stake, i64),
                        ("fork_weight", stats.fork_weight(), f64),
                    );

                    info!(
                        "{} slot_weight: {} {:.1}% {}",
                        my_vote_pubkey,
                        bank_slot,
                        100.0 * stats.fork_weight(), // percentage fork_stake in total_stake
                        bank.parent().map(|b| b.slot()).unwrap_or(0)
                    );
                }
            }

            Self::update_propagation_status(
                progress,
                bank_slot,
                bank_forks,
                vote_tracker,
                cluster_slots,
            );

            Self::cache_tower_stats(progress, tower, bank_slot, ancestors);
        }
        new_stats
    }

    fn adopt_on_chain_tower_if_behind(
        my_vote_pubkey: &Pubkey,
        ancestors: &HashMap<Slot, HashSet<Slot>>,
        frozen_banks: &[Arc<Bank>],
        tower: &mut Tower,
        progress: &mut ProgressMap,
        bank: &Arc<Bank>,
    ) {
        let Some(vote_account) = bank.get_vote_account(my_vote_pubkey) else {
            return;
        };
        let Ok(mut bank_vote_state) = vote_account.vote_state().cloned() else {
            return;
        };
        if bank_vote_state.last_voted_slot() <= tower.vote_state.last_voted_slot() {
            return;
        }
        info!(
            "Frozen bank vote state slot {:?}
             is newer than our local vote state slot {:?},
             adopting the bank vote state as our own.
             Bank votes: {:?}, root: {:?},
             Local votes: {:?}, root: {:?}",
            bank_vote_state.last_voted_slot(),
            tower.vote_state.last_voted_slot(),
            bank_vote_state.votes,
            bank_vote_state.root_slot,
            tower.vote_state.votes,
            tower.vote_state.root_slot
        );

        if let Some(local_root) = tower.vote_state.root_slot {
            if bank_vote_state
                .root_slot
                .map(|bank_root| local_root > bank_root)
                .unwrap_or(true)
            {
                // If the local root is larger than this on chain vote state
                // root (possible due to supermajority roots being set on
                // startup), then we need to adjust the tower
                bank_vote_state.root_slot = Some(local_root);
                bank_vote_state
                    .votes
                    .retain(|lockout| lockout.slot() > local_root);
                info!(
                    "Local root is larger than on chain root,
                     overwrote bank root {:?} and updated votes {:?}",
                    bank_vote_state.root_slot, bank_vote_state.votes
                );

                if let Some(first_vote) = bank_vote_state.votes.front() {
                    assert!(ancestors
                        .get(&first_vote.slot())
                        .expect(
                            "Ancestors map must contain an entry for all slots on this fork \
                             greater than `local_root` and less than `bank_slot`"
                        )
                        .contains(&local_root));
                }
            }
        }

        tower.vote_state.root_slot = bank_vote_state.root_slot;
        tower.vote_state.votes = bank_vote_state.votes;

        let last_voted_slot = tower.vote_state.last_voted_slot().unwrap_or(
            // If our local root is higher than the highest slot in `bank_vote_state` due to
            // supermajority roots, then it's expected that the vote state will be empty.
            // In this case we use the root as our last vote. This root cannot be None, because
            // `tower.vote_state.last_voted_slot()` is None only if `tower.vote_state.root_slot`
            // is Some.
            tower
                .vote_state
                .root_slot
                .expect("root_slot cannot be None here"),
        );
        // This is safe because `last_voted_slot` is now equal to
        // `bank_vote_state.last_voted_slot()` or `local_root`.
        // Since this vote state is contained in `bank`, which we have frozen,
        // we must have frozen all slots contained in `bank_vote_state`,
        // and by definition we must have frozen `local_root`.
        //
        // If `bank` is a duplicate, since we are able to replay it successfully, any slots
        // in its vote state must also be part of the duplicate fork, and thus present in our
        // progress map.
        //
        // Finally if both `bank` and `bank_vote_state.last_voted_slot()` are duplicate,
        // we must have the compatible versions of both duplicates in order to replay `bank`
        // successfully, so we are once again guaranteed that `bank_vote_state.last_voted_slot()`
        // is present in progress map.
        tower.update_last_vote_from_vote_state(
            progress
                .get_hash(last_voted_slot)
                .expect("Must exist for us to have frozen descendant"),
            bank.feature_set
                .is_active(&feature_set::enable_tower_sync_ix::id()),
        );
        // Since we are updating our tower we need to update associated caches for previously computed
        // slots as well.
        for slot in frozen_banks.iter().map(|b| b.slot()) {
            if !progress
                .get_fork_stats(slot)
                .expect("All frozen banks must exist in fork stats")
                .computed
            {
                continue;
            }
            Self::cache_tower_stats(progress, tower, slot, ancestors);
        }
    }

    fn cache_tower_stats(
        progress: &mut ProgressMap,
        tower: &Tower,
        slot: Slot,
        ancestors: &HashMap<u64, HashSet<u64>>,
    ) {
        let stats = progress
            .get_fork_stats_mut(slot)
            .expect("All frozen banks must exist in the Progress map");

        stats.vote_threshold =
            tower.check_vote_stake_thresholds(slot, &stats.voted_stakes, stats.total_stake);
        stats.is_locked_out = tower.is_locked_out(
            slot,
            ancestors
                .get(&slot)
                .expect("Ancestors map should contain slot for is_locked_out() check"),
        );
        stats.has_voted = tower.has_voted(slot);
        stats.is_recent = tower.is_recent(slot);
    }

    fn update_propagation_status(
        progress: &mut ProgressMap,
        slot: Slot,
        bank_forks: &RwLock<BankForks>,
        vote_tracker: &VoteTracker,
        cluster_slots: &ClusterSlots,
    ) {
        // If propagation has already been confirmed, return
        if progress.get_leader_propagation_slot_must_exist(slot).0 {
            return;
        }

        // Otherwise we have to check the votes for confirmation
        let propagated_stats = progress
            .get_propagated_stats_mut(slot)
            .unwrap_or_else(|| panic!("slot={slot} must exist in ProgressMap"));

        if propagated_stats.slot_vote_tracker.is_none() {
            propagated_stats.slot_vote_tracker = vote_tracker.get_slot_vote_tracker(slot);
        }
        let slot_vote_tracker = propagated_stats.slot_vote_tracker.clone();

        if propagated_stats.cluster_slot_pubkeys.is_none() {
            propagated_stats.cluster_slot_pubkeys = cluster_slots.lookup(slot);
        }
        let cluster_slot_pubkeys = propagated_stats.cluster_slot_pubkeys.clone();

        let newly_voted_pubkeys = slot_vote_tracker
            .as_ref()
            .and_then(|slot_vote_tracker| {
                slot_vote_tracker.write().unwrap().get_voted_slot_updates()
            })
            .unwrap_or_default();

        let cluster_slot_pubkeys = cluster_slot_pubkeys
            .map(|v| v.read().unwrap().keys().cloned().collect())
            .unwrap_or_default();

        Self::update_fork_propagated_threshold_from_votes(
            progress,
            newly_voted_pubkeys,
            cluster_slot_pubkeys,
            slot,
            &bank_forks.read().unwrap(),
        );
    }

    fn select_forks_failed_switch_threshold(
        reset_bank: Option<&Bank>,
        progress: &ProgressMap,
        tower: &Tower,
        heaviest_bank_slot: Slot,
        failure_reasons: &mut Vec<HeaviestForkFailures>,
        switch_proof_stake: u64,
        total_stake: u64,
        switch_fork_decision: SwitchForkDecision,
    ) -> SwitchForkDecision {
        let last_vote_unable_to_land = match reset_bank {
            Some(heaviest_bank_on_same_voted_fork) => {
                match tower.last_voted_slot() {
                    Some(last_voted_slot) => {
                        match progress
                            .my_latest_landed_vote(heaviest_bank_on_same_voted_fork.slot())
                        {
                            Some(my_latest_landed_vote) =>
                            // Last vote did not land
                            {
                                my_latest_landed_vote < last_voted_slot
                                    // If we are already voting at the tip, there is nothing we can do.
                                    && last_voted_slot < heaviest_bank_on_same_voted_fork.slot()
                                    // Last vote outside slot hashes of the tip of fork
                                    && !heaviest_bank_on_same_voted_fork
                                        .is_in_slot_hashes_history(&last_voted_slot)
                            }
                            None => false,
                        }
                    }
                    None => false,
                }
            }
            None => false,
        };

        if last_vote_unable_to_land {
            // If we reach here, these assumptions are true:
            // 1. We can't switch because of threshold
            // 2. Our last vote was on a non-duplicate/confirmed slot
            // 3. Our last vote is now outside slot hashes history of the tip of fork
            // So, there was no hope of this last vote ever landing again.

            // In this case, we do want to obey threshold, yet try to register our vote on
            // the current fork, so we choose to vote at the tip of current fork instead.
            // This will not cause longer lockout because lockout doesn't double after 512
            // slots, it might be enough to get majority vote.
            SwitchForkDecision::SameFork
        } else {
            // If we can't switch and our last vote was on a non-duplicate/confirmed slot, then
            // reset to the the next votable bank on the same fork as our last vote,
            // but don't vote.

            // We don't just reset to the heaviest fork when switch threshold fails because
            // a situation like this can occur:

            /* Figure 1:
                        slot 0
                            |
                        slot 1
                        /        \
            slot 2 (last vote)     |
                        |      slot 8 (10%)
                slot 4 (9%)
            */

            // Imagine 90% of validators voted on slot 4, but only 9% landed. If everybody that fails
            // the switch threshold abandons slot 4 to build on slot 8 (because it's *currently* heavier),
            // then there will be no blocks to include the votes for slot 4, and the network halts
            // because 90% of validators can't vote
            info!(
                "Waiting to switch vote to {},
                resetting to slot {:?} for now,
                switch proof stake: {},
                threshold stake: {},
                total stake: {}",
                heaviest_bank_slot,
                reset_bank.as_ref().map(|b| b.slot()),
                switch_proof_stake,
                total_stake as f64 * SWITCH_FORK_THRESHOLD,
                total_stake
            );
            failure_reasons.push(HeaviestForkFailures::FailedSwitchThreshold(
                heaviest_bank_slot,
                switch_proof_stake,
                total_stake,
            ));
            switch_fork_decision
        }
    }

    /// Given a `heaviest_bank` and a `heaviest_bank_on_same_voted_fork`, return
    /// a bank to vote on, a bank to reset to, and a list of switch failure
    /// reasons.
    ///
    /// If `heaviest_bank_on_same_voted_fork` is `None` due to that fork no
    /// longer being valid to vote on, it's possible that a validator will not
    /// be able to reset away from the invalid fork that they last voted on. To
    /// resolve this scenario, validators need to wait until they can create a
    /// switch proof for another fork or until the invalid fork is be marked
    /// valid again if it was confirmed by the cluster.
    /// Until this is resolved, leaders will build each of their
    /// blocks from the last reset bank on the invalid fork.
    pub fn select_vote_and_reset_forks(
        heaviest_bank: &Arc<Bank>,
        // Should only be None if there was no previous vote
        heaviest_bank_on_same_voted_fork: Option<&Arc<Bank>>,
        ancestors: &HashMap<u64, HashSet<u64>>,
        descendants: &HashMap<u64, HashSet<u64>>,
        progress: &ProgressMap,
        tower: &mut Tower,
        latest_validator_votes_for_frozen_banks: &LatestValidatorVotesForFrozenBanks,
        fork_choice: &HeaviestSubtreeForkChoice,
    ) -> SelectVoteAndResetForkResult {
        // Try to vote on the actual heaviest fork. If the heaviest bank is
        // locked out or fails the threshold check, the validator will:
        // 1) Not continue to vote on current fork, waiting for lockouts to expire/
        //    threshold check to pass
        // 2) Will reset PoH to heaviest fork in order to make sure the heaviest
        //    fork is propagated
        // This above behavior should ensure correct voting and resetting PoH
        // behavior under all cases:
        // 1) The best "selected" bank is on same fork
        // 2) The best "selected" bank is on a different fork,
        //    switch_threshold fails
        // 3) The best "selected" bank is on a different fork,
        //    switch_threshold succeeds
        let mut failure_reasons = vec![];
        struct CandidateVoteAndResetBanks<'a> {
            // A bank that the validator will vote on given it passes all
            // remaining vote checks
            candidate_vote_bank: Option<&'a Arc<Bank>>,
            // A bank that the validator will reset its PoH to regardless
            // of voting behavior
            reset_bank: Option<&'a Arc<Bank>>,
            switch_fork_decision: SwitchForkDecision,
        }
        let candidate_vote_and_reset_banks = {
            let switch_fork_decision: SwitchForkDecision = tower.check_switch_threshold(
                heaviest_bank.slot(),
                ancestors,
                descendants,
                progress,
                heaviest_bank.total_epoch_stake(),
                heaviest_bank
                    .epoch_vote_accounts(heaviest_bank.epoch())
                    .expect("Bank epoch vote accounts must contain entry for the bank's own epoch"),
                latest_validator_votes_for_frozen_banks,
                fork_choice,
            );

            match switch_fork_decision {
                SwitchForkDecision::FailedSwitchThreshold(switch_proof_stake, total_stake) => {
                    let final_switch_fork_decision = Self::select_forks_failed_switch_threshold(
                        heaviest_bank_on_same_voted_fork.map(|bank| bank.as_ref()),
                        progress,
                        tower,
                        heaviest_bank.slot(),
                        &mut failure_reasons,
                        switch_proof_stake,
                        total_stake,
                        switch_fork_decision,
                    );
                    let candidate_vote_bank = if final_switch_fork_decision.can_vote() {
                        // The only time we would still vote despite `!switch_fork_decision.can_vote()`
                        // is if we switched the vote candidate to `heaviest_bank_on_same_voted_fork`
                        // because we needed to refresh the vote to the tip of our last voted fork.
                        heaviest_bank_on_same_voted_fork
                    } else {
                        // Otherwise,  we should just return the original vote candidate, the heaviest bank
                        // for logging purposes, namely to check if there are any additional voting failures
                        // besides the switch threshold
                        Some(heaviest_bank)
                    };
                    CandidateVoteAndResetBanks {
                        candidate_vote_bank,
                        reset_bank: heaviest_bank_on_same_voted_fork,
                        switch_fork_decision: final_switch_fork_decision,
                    }
                }
                SwitchForkDecision::FailedSwitchDuplicateRollback(latest_duplicate_ancestor) => {
                    // If we can't switch and our last vote was on an unconfirmed, duplicate slot,
                    // then we need to reset to the heaviest bank, even if the heaviest bank is not
                    // a descendant of the last vote (usually for switch threshold failures we reset
                    // to the heaviest descendant of the last vote, but in this case, the last vote
                    // was on a duplicate branch). This is because in the case of *unconfirmed* duplicate
                    // slots, somebody needs to generate an alternative branch to escape a situation
                    // like a 50-50 split  where both partitions have voted on different versions of the
                    // same duplicate slot.

                    // Unlike the situation described in `Figure 1` above, this is safe. To see why,
                    // imagine the same situation described in Figure 1 above occurs, but slot 2 is
                    // a duplicate block. There are now a few cases:
                    //
                    // Note first that DUPLICATE_THRESHOLD + SWITCH_FORK_THRESHOLD + DUPLICATE_LIVENESS_THRESHOLD = 1;
                    //
                    // 1) > DUPLICATE_THRESHOLD of the network voted on some version of slot 2. Because duplicate slots can be confirmed
                    // by gossip, unlike the situation described in `Figure 1`, we don't need those
                    // votes to land in a descendant to confirm slot 2. Once slot 2 is confirmed by
                    // gossip votes, that fork is added back to the fork choice set and falls back into
                    // normal fork choice, which is covered by the `FailedSwitchThreshold` case above
                    // (everyone will resume building on their last voted fork, slot 4, since slot 8
                    // doesn't have for switch threshold)
                    //
                    // 2) <= DUPLICATE_THRESHOLD of the network voted on some version of slot 2, > SWITCH_FORK_THRESHOLD of the network voted
                    // on slot 8. Then everybody abandons the duplicate fork from fork choice and both builds
                    // on slot 8's fork. They can also vote on slot 8's fork because it has sufficient weight
                    // to pass the switching threshold
                    //
                    // 3) <= DUPLICATE_THRESHOLD of the network voted on some version of slot 2, <= SWITCH_FORK_THRESHOLD of the network voted
                    // on slot 8. This means more than DUPLICATE_LIVENESS_THRESHOLD of the network is gone, so we cannot
                    // guarantee progress anyways

                    // Note the heaviest fork is never descended from a known unconfirmed duplicate slot
                    // because the fork choice rule ensures that (marks it as an invalid candidate),
                    // thus it's safe to use as the reset bank.
                    let reset_bank = Some(heaviest_bank);
                    info!(
                        "Waiting to switch vote to {}, resetting to slot {:?} for now, latest duplicate ancestor: {:?}",
                        heaviest_bank.slot(),
                        reset_bank.as_ref().map(|b| b.slot()),
                        latest_duplicate_ancestor,
                    );
                    failure_reasons.push(HeaviestForkFailures::FailedSwitchThreshold(
                        heaviest_bank.slot(),
                        0, // In this case we never actually performed the switch check, 0 for now
                        0,
                    ));
                    CandidateVoteAndResetBanks {
                        candidate_vote_bank: None,
                        reset_bank,
                        switch_fork_decision,
                    }
                }
                _ => CandidateVoteAndResetBanks {
                    candidate_vote_bank: Some(heaviest_bank),
                    reset_bank: Some(heaviest_bank),
                    switch_fork_decision,
                },
            }
        };

        let CandidateVoteAndResetBanks {
            candidate_vote_bank,
            reset_bank,
            switch_fork_decision,
        } = candidate_vote_and_reset_banks;

        if let Some(candidate_vote_bank) = candidate_vote_bank {
            // If there's a bank to potentially vote on, then make the remaining
            // checks
            let (
                is_locked_out,
                vote_thresholds,
                propagated_stake,
                is_leader_slot,
                fork_weight,
                total_threshold_stake,
                total_epoch_stake,
            ) = {
                let fork_stats = progress.get_fork_stats(candidate_vote_bank.slot()).unwrap();
                let propagated_stats = &progress
                    .get_propagated_stats(candidate_vote_bank.slot())
                    .unwrap();
                (
                    fork_stats.is_locked_out,
                    &fork_stats.vote_threshold,
                    propagated_stats.propagated_validators_stake,
                    propagated_stats.is_leader_slot,
                    fork_stats.fork_weight(),
                    fork_stats.total_stake,
                    propagated_stats.total_epoch_stake,
                )
            };

            let propagation_confirmed = is_leader_slot
                || progress
                    .get_leader_propagation_slot_must_exist(candidate_vote_bank.slot())
                    .0;

            if is_locked_out {
                failure_reasons.push(HeaviestForkFailures::LockedOut(candidate_vote_bank.slot()));
            }
            let mut threshold_passed = true;
            for threshold_failure in vote_thresholds {
                let &ThresholdDecision::FailedThreshold(vote_depth, fork_stake) = threshold_failure
                else {
                    continue;
                };
                failure_reasons.push(HeaviestForkFailures::FailedThreshold(
                    candidate_vote_bank.slot(),
                    vote_depth,
                    fork_stake,
                    total_threshold_stake,
                ));
                // Ignore shallow checks for voting purposes
                if (vote_depth as usize) >= tower.threshold_depth {
                    threshold_passed = false;
                }
            }
            if !propagation_confirmed {
                failure_reasons.push(HeaviestForkFailures::NoPropagatedConfirmation(
                    candidate_vote_bank.slot(),
                    propagated_stake,
                    total_epoch_stake,
                ));
            }

            if !is_locked_out
                && threshold_passed
                && propagation_confirmed
                && switch_fork_decision.can_vote()
            {
                info!(
                    "voting: {} {:.1}%",
                    candidate_vote_bank.slot(),
                    100.0 * fork_weight
                );
                SelectVoteAndResetForkResult {
                    vote_bank: Some((candidate_vote_bank.clone(), switch_fork_decision)),
                    reset_bank: Some(candidate_vote_bank.clone()),
                    heaviest_fork_failures: failure_reasons,
                }
            } else {
                SelectVoteAndResetForkResult {
                    vote_bank: None,
                    reset_bank: reset_bank.cloned(),
                    heaviest_fork_failures: failure_reasons,
                }
            }
        } else if reset_bank.is_some() {
            SelectVoteAndResetForkResult {
                vote_bank: None,
                reset_bank: reset_bank.cloned(),
                heaviest_fork_failures: failure_reasons,
            }
        } else {
            SelectVoteAndResetForkResult {
                vote_bank: None,
                reset_bank: None,
                heaviest_fork_failures: failure_reasons,
            }
        }
    }

    fn update_fork_propagated_threshold_from_votes(
        progress: &mut ProgressMap,
        mut newly_voted_pubkeys: Vec<Pubkey>,
        mut cluster_slot_pubkeys: Vec<Pubkey>,
        fork_tip: Slot,
        bank_forks: &BankForks,
    ) {
        let mut current_leader_slot = progress.get_latest_leader_slot_must_exist(fork_tip);
        let mut did_newly_reach_threshold = false;
        let root = bank_forks.root();
        loop {
            // These cases mean confirmation of propagation on any earlier
            // leader blocks must have been reached
            if current_leader_slot.is_none() || current_leader_slot.unwrap() < root {
                break;
            }

            let leader_propagated_stats = progress
                .get_propagated_stats_mut(current_leader_slot.unwrap())
                .expect("current_leader_slot >= root, so must exist in the progress map");

            // If a descendant has reached propagation threshold, then
            // all its ancestor banks have also reached propagation
            // threshold as well (Validators can't have voted for a
            // descendant without also getting the ancestor block)
            if leader_propagated_stats.is_propagated || {
                // If there's no new validators to record, and there's no
                // newly achieved threshold, then there's no further
                // information to propagate backwards to past leader blocks
                newly_voted_pubkeys.is_empty()
                    && cluster_slot_pubkeys.is_empty()
                    && !did_newly_reach_threshold
            } {
                break;
            }

            // We only iterate through the list of leader slots by traversing
            // the linked list of 'prev_leader_slot`'s outlined in the
            // `progress` map
            assert!(leader_propagated_stats.is_leader_slot);
            let leader_bank = bank_forks
                .get(current_leader_slot.unwrap())
                .expect("Entry in progress map must exist in BankForks")
                .clone();

            did_newly_reach_threshold = Self::update_slot_propagated_threshold_from_votes(
                &mut newly_voted_pubkeys,
                &mut cluster_slot_pubkeys,
                &leader_bank,
                leader_propagated_stats,
                did_newly_reach_threshold,
            ) || did_newly_reach_threshold;

            // Now jump to process the previous leader slot
            current_leader_slot = leader_propagated_stats.prev_leader_slot;
        }
    }

    fn update_slot_propagated_threshold_from_votes(
        newly_voted_pubkeys: &mut Vec<Pubkey>,
        cluster_slot_pubkeys: &mut Vec<Pubkey>,
        leader_bank: &Bank,
        leader_propagated_stats: &mut PropagatedStats,
        did_child_reach_threshold: bool,
    ) -> bool {
        // Track whether this slot newly confirm propagation
        // throughout the network (switched from is_propagated == false
        // to is_propagated == true)
        let mut did_newly_reach_threshold = false;

        // If a child of this slot confirmed propagation, then
        // we can return early as this implies this slot must also
        // be propagated
        if did_child_reach_threshold {
            if !leader_propagated_stats.is_propagated {
                leader_propagated_stats.is_propagated = true;
                return true;
            } else {
                return false;
            }
        }

        if leader_propagated_stats.is_propagated {
            return false;
        }

        // Remove the vote/node pubkeys that we already know voted for this
        // slot. These vote accounts/validator identities are safe to drop
        // because they don't to be ported back any further because earlier
        // parents must have:
        // 1) Also recorded these pubkeys already, or
        // 2) Already reached the propagation threshold, in which case
        //    they no longer need to track the set of propagated validators
        newly_voted_pubkeys.retain(|vote_pubkey| {
            let exists = leader_propagated_stats
                .propagated_validators
                .contains(vote_pubkey);
            leader_propagated_stats.add_vote_pubkey(
                *vote_pubkey,
                leader_bank.epoch_vote_account_stake(vote_pubkey),
            );
            !exists
        });

        cluster_slot_pubkeys.retain(|node_pubkey| {
            let exists = leader_propagated_stats
                .propagated_node_ids
                .contains(node_pubkey);
            leader_propagated_stats.add_node_pubkey(node_pubkey, leader_bank);
            !exists
        });

        if leader_propagated_stats.total_epoch_stake == 0
            || leader_propagated_stats.propagated_validators_stake as f64
                / leader_propagated_stats.total_epoch_stake as f64
                > SUPERMINORITY_THRESHOLD
        {
            leader_propagated_stats.is_propagated = true;
            did_newly_reach_threshold = true
        }

        did_newly_reach_threshold
    }

    #[allow(clippy::too_many_arguments)]
    fn mark_slots_confirmed(
        confirmed_slots: &[ConfirmedSlot],
        blockstore: &Blockstore,
        bank_forks: &RwLock<BankForks>,
        progress: &mut ProgressMap,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        fork_choice: &mut HeaviestSubtreeForkChoice,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        duplicate_slots_to_repair: &mut DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: &AncestorHashesReplayUpdateSender,
        purge_repair_slot_counter: &mut PurgeRepairSlotCounter,
        duplicate_confirmed_slots: &mut DuplicateConfirmedSlots,
    ) {
        let root_slot = bank_forks.read().unwrap().root();
        for ConfirmedSlot {
            slot,
            frozen_hash,
            confirmation_type,
        } in confirmed_slots.iter()
        {
            if *confirmation_type == ConfirmationType::SupermajorityVoted {
                // This case should be guaranteed as false by confirm_forks()
                if let Some(false) = progress.is_supermajority_confirmed(*slot) {
                    // Because supermajority confirmation will iterate through and update the
                    // subtree in fork choice, only incur this cost if the slot wasn't already
                    // confirmed
                    progress.set_supermajority_confirmed_slot(*slot);
                    // If the slot was confirmed, then it must be frozen. Otherwise, we couldn't
                    // have replayed any of its descendants and figured out it was confirmed.
                    assert!(*frozen_hash != Hash::default());
                }
            }

            if *slot <= root_slot {
                continue;
            }

            match confirmation_type {
                ConfirmationType::SupermajorityVoted => (),
                ConfirmationType::DuplicateConfirmed => (),
                #[allow(unreachable_patterns)]
                _ => panic!("programmer error"),
            }

            if let Some(prev_hash) = duplicate_confirmed_slots.insert(*slot, *frozen_hash) {
                assert_eq!(prev_hash, *frozen_hash);
                // Already processed this signal
                return;
            }

            let duplicate_confirmed_state = DuplicateConfirmedState::new_from_state(
                *frozen_hash,
                || false,
                || Some(*frozen_hash),
            );
            check_slot_agrees_with_cluster(
                *slot,
                root_slot,
                blockstore,
                duplicate_slots_tracker,
                epoch_slots_frozen_slots,
                fork_choice,
                duplicate_slots_to_repair,
                ancestor_hashes_replay_update_sender,
                purge_repair_slot_counter,
                SlotStateUpdate::DuplicateConfirmed(duplicate_confirmed_state),
            );
        }
    }

    fn confirm_forks(
        tower: &Tower,
        voted_stakes: &VotedStakes,
        total_stake: Stake,
        progress: &ProgressMap,
        bank_forks: &RwLock<BankForks>,
    ) -> Vec<ConfirmedSlot> {
        let mut confirmed_forks = vec![];
        for (slot, prog) in progress.iter() {
            if !prog.fork_stats.is_supermajority_confirmed {
                let bank = bank_forks
                    .read()
                    .unwrap()
                    .get(*slot)
                    .expect("bank in progress must exist in BankForks")
                    .clone();
                let duration = prog
                    .replay_stats
                    .read()
                    .unwrap()
                    .started
                    .elapsed()
                    .as_millis();
                if bank.is_frozen() && tower.is_slot_confirmed(*slot, voted_stakes, total_stake) {
                    info!("validator fork confirmed {} {}ms", *slot, duration);
                    datapoint_info!("validator-confirmation", ("duration_ms", duration, i64));
                    confirmed_forks
                        .push(ConfirmedSlot::new_supermajority_voted(*slot, bank.hash()));
                } else if bank.is_frozen()
                    && tower.is_slot_duplicate_confirmed(*slot, voted_stakes, total_stake)
                {
                    info!(
                        "validator fork duplicate confirmed {} {}ms",
                        *slot, duration
                    );
                    datapoint_info!(
                        "validator-duplicate-confirmation",
                        ("duration_ms", duration, i64)
                    );
                    confirmed_forks.push(ConfirmedSlot::new_duplicate_confirmed_slot(
                        *slot,
                        bank.hash(),
                    ));
                } else {
                    debug!(
                        "validator fork not confirmed {} {}ms {:?}",
                        *slot,
                        duration,
                        voted_stakes.get(slot)
                    );
                }
            }
        }
        confirmed_forks
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_new_root(
        new_root: Slot,
        bank_forks: &RwLock<BankForks>,
        progress: &mut ProgressMap,
        accounts_background_request_sender: &AbsRequestSender,
        highest_super_majority_root: Option<Slot>,
        heaviest_subtree_fork_choice: &mut HeaviestSubtreeForkChoice,
        duplicate_slots_tracker: &mut DuplicateSlotsTracker,
        duplicate_confirmed_slots: &mut DuplicateConfirmedSlots,
        unfrozen_gossip_verified_vote_hashes: &mut UnfrozenGossipVerifiedVoteHashes,
        has_new_vote_been_rooted: &mut bool,
        voted_signatures: &mut Vec<Signature>,
        epoch_slots_frozen_slots: &mut EpochSlotsFrozenSlots,
        drop_bank_sender: &Sender<Vec<BankWithScheduler>>,
    ) -> Result<(), SetRootError> {
        bank_forks.read().unwrap().prune_program_cache(new_root);
        let removed_banks = bank_forks.write().unwrap().set_root(
            new_root,
            accounts_background_request_sender,
            highest_super_majority_root,
        )?;

        drop_bank_sender
            .send(removed_banks)
            .unwrap_or_else(|err| warn!("bank drop failed: {:?}", err));

        // Dropping the bank_forks write lock and reacquiring as a read lock is
        // safe because updates to bank_forks are only made by a single thread.
        let r_bank_forks = bank_forks.read().unwrap();
        let new_root_bank = &r_bank_forks[new_root];
        if !*has_new_vote_been_rooted {
            for signature in voted_signatures.iter() {
                if new_root_bank.get_signature_status(signature).is_some() {
                    *has_new_vote_been_rooted = true;
                    break;
                }
            }
            if *has_new_vote_been_rooted {
                std::mem::take(voted_signatures);
            }
        }
        progress.handle_new_root(&r_bank_forks);
        heaviest_subtree_fork_choice.set_tree_root((new_root, r_bank_forks.root_bank().hash()));
        *duplicate_slots_tracker = duplicate_slots_tracker.split_off(&new_root);
        // duplicate_slots_tracker now only contains entries >= `new_root`

        *duplicate_confirmed_slots = duplicate_confirmed_slots.split_off(&new_root);
        // gossip_confirmed_slots now only contains entries >= `new_root`

        unfrozen_gossip_verified_vote_hashes.set_root(new_root);
        *epoch_slots_frozen_slots = epoch_slots_frozen_slots.split_off(&new_root);
        Ok(())
        // epoch_slots_frozen_slots now only contains entries >= `new_root`
    }

    fn generate_new_bank_forks(
        blockstore: &Blockstore,
        bank_forks: &RwLock<BankForks>,
        leader_schedule_cache: &Arc<LeaderScheduleCache>,
        rpc_subscriptions: &Arc<RpcSubscriptions>,
        progress: &mut ProgressMap,
        replay_timing: &mut ReplayLoopTiming,
    ) {
        // Find the next slot that chains to the old slot
        let mut generate_new_bank_forks_read_lock =
            Measure::start("generate_new_bank_forks_read_lock");
        let forks = bank_forks.read().unwrap();
        generate_new_bank_forks_read_lock.stop();

        let frozen_banks = forks.frozen_banks();
        let frozen_bank_slots: Vec<u64> = frozen_banks
            .keys()
            .cloned()
            .filter(|s| *s >= forks.root())
            .collect();
        let mut generate_new_bank_forks_get_slots_since =
            Measure::start("generate_new_bank_forks_get_slots_since");
        let next_slots = blockstore
            .get_slots_since(&frozen_bank_slots)
            .expect("Db error");
        generate_new_bank_forks_get_slots_since.stop();

        // Filter out what we've already seen
        trace!("generate new forks {:?}", {
            let mut next_slots = next_slots.iter().collect::<Vec<_>>();
            next_slots.sort();
            next_slots
        });
        let mut generate_new_bank_forks_loop = Measure::start("generate_new_bank_forks_loop");
        let mut new_banks = HashMap::new();
        for (parent_slot, children) in next_slots {
            let parent_bank = frozen_banks
                .get(&parent_slot)
                .expect("missing parent in bank forks");
            for child_slot in children {
                if forks.get(child_slot).is_some() || new_banks.contains_key(&child_slot) {
                    trace!("child already active or frozen {}", child_slot);
                    continue;
                }
                let leader = leader_schedule_cache
                    .slot_leader_at(child_slot, Some(parent_bank))
                    .unwrap();
                info!(
                    "new fork:{} parent:{} root:{}",
                    child_slot,
                    parent_slot,
                    forks.root()
                );
                let child_bank = Self::new_bank_from_parent_with_notify(
                    parent_bank.clone(),
                    child_slot,
                    forks.root(),
                    &leader,
                    rpc_subscriptions,
                    NewBankOptions::default(),
                );
                let empty: Vec<Pubkey> = vec![];
                Self::update_fork_propagated_threshold_from_votes(
                    progress,
                    empty,
                    vec![leader],
                    parent_bank.slot(),
                    &forks,
                );
                new_banks.insert(child_slot, child_bank);
            }
        }
        drop(forks);
        generate_new_bank_forks_loop.stop();

        let mut generate_new_bank_forks_write_lock =
            Measure::start("generate_new_bank_forks_write_lock");
        let mut forks = bank_forks.write().unwrap();
        for (_, bank) in new_banks {
            forks.insert(bank);
        }
        generate_new_bank_forks_write_lock.stop();
        saturating_add_assign!(
            replay_timing.generate_new_bank_forks_read_lock_us,
            generate_new_bank_forks_read_lock.as_us()
        );
        saturating_add_assign!(
            replay_timing.generate_new_bank_forks_get_slots_since_us,
            generate_new_bank_forks_get_slots_since.as_us()
        );
        saturating_add_assign!(
            replay_timing.generate_new_bank_forks_loop_us,
            generate_new_bank_forks_loop.as_us()
        );
        saturating_add_assign!(
            replay_timing.generate_new_bank_forks_write_lock_us,
            generate_new_bank_forks_write_lock.as_us()
        );
    }

    fn new_bank_from_parent_with_notify(
        parent: Arc<Bank>,
        slot: u64,
        root_slot: u64,
        leader: &Pubkey,
        rpc_subscriptions: &Arc<RpcSubscriptions>,
        new_bank_options: NewBankOptions,
    ) -> Bank {
        rpc_subscriptions.notify_slot(slot, parent.slot(), root_slot);
        Bank::new_from_parent_with_options(parent, leader, slot, new_bank_options)
    }

    fn record_rewards(bank: &Bank, rewards_recorder_sender: &Option<RewardsRecorderSender>) {
        if let Some(rewards_recorder_sender) = rewards_recorder_sender {
            let rewards = bank.get_rewards_and_num_partitions();
            if rewards.should_record() {
                rewards_recorder_sender
                    .send(RewardsMessage::Batch((bank.slot(), rewards)))
                    .unwrap_or_else(|err| warn!("rewards_recorder_sender failed: {:?}", err));
            }
            rewards_recorder_sender
                .send(RewardsMessage::Complete(bank.slot()))
                .unwrap_or_else(|err| warn!("rewards_recorder_sender failed: {:?}", err));
        }
    }

    pub fn get_unlock_switch_vote_slot(cluster_type: ClusterType) -> Slot {
        match cluster_type {
            ClusterType::Development => 0,
            ClusterType::Devnet => 0,
            // Epoch 63
            ClusterType::Testnet => 21_692_256,
            // 400_000 slots into epoch 61
            ClusterType::MainnetBeta => 26_752_000,
        }
    }

    fn log_heaviest_fork_failures(
        heaviest_fork_failures: &Vec<HeaviestForkFailures>,
        bank_forks: &Arc<RwLock<BankForks>>,
        tower: &Tower,
        progress: &ProgressMap,
        ancestors: &HashMap<Slot, HashSet<Slot>>,
        heaviest_bank: &Arc<Bank>,
        last_threshold_failure_slot: &mut Slot,
    ) {
        info!(
            "Couldn't vote on heaviest fork: {:?}, heaviest_fork_failures: {:?}",
            heaviest_bank.slot(),
            heaviest_fork_failures
        );

        for failure in heaviest_fork_failures {
            match failure {
                HeaviestForkFailures::NoPropagatedConfirmation(slot, ..) => {
                    if let Some(latest_leader_slot) =
                        progress.get_latest_leader_slot_must_exist(*slot)
                    {
                        progress.log_propagated_stats(latest_leader_slot, bank_forks);
                    }
                }
                &HeaviestForkFailures::FailedThreshold(
                    slot,
                    depth,
                    observed_stake,
                    total_stake,
                ) => {
                    if slot > *last_threshold_failure_slot {
                        *last_threshold_failure_slot = slot;
                        let in_partition = if let Some(last_voted_slot) = tower.last_voted_slot() {
                            Self::is_partition_detected(
                                ancestors,
                                last_voted_slot,
                                heaviest_bank.slot(),
                            )
                        } else {
                            false
                        };
                        datapoint_info!(
                            "replay_stage-threshold-failure",
                            ("slot", slot as i64, i64),
                            ("depth", depth as i64, i64),
                            ("observed_stake", observed_stake as i64, i64),
                            ("total_stake", total_stake as i64, i64),
                            ("in_partition", in_partition, bool),
                        );
                    }
                }
                // These are already logged in the partition info
                HeaviestForkFailures::LockedOut(_)
                | HeaviestForkFailures::FailedSwitchThreshold(_, _, _) => (),
            }
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.commitment_service.join()?;
        self.t_replay.join().map(|_| ())
    }
}
