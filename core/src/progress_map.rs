use {
    crate::{
        cluster_info_vote_listener::SlotVoteTracker,
        cluster_slots::SlotPubkeys,
        consensus::{Stake, ThresholdDecision, VotedStakes},
        replay_stage::SUPERMINORITY_THRESHOLD,
    },
    solana_ledger::blockstore_processor::{ConfirmationProgress, ConfirmationTiming},
    solana_program_runtime::{report_execute_timings, timings::ExecuteTimingType},
    solana_runtime::{bank::Bank, bank_forks::BankForks, vote_account::VoteAccountsHashMap},
    solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey},
    std::{
        collections::{BTreeMap, HashMap, HashSet},
        ops::Index,
        sync::{Arc, RwLock},
        time::Instant,
    },
};

type VotedSlot = Slot;
type ExpirationSlot = Slot;
pub type LockoutIntervals = BTreeMap<ExpirationSlot, Vec<(VotedSlot, Pubkey)>>;

#[derive(Default)]
pub struct ReplaySlotStats(ConfirmationTiming);
impl std::ops::Deref for ReplaySlotStats {
    type Target = ConfirmationTiming;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ReplaySlotStats {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ReplaySlotStats {
    pub fn report_stats(
        &self,
        slot: Slot,
        num_txs: usize,
        num_entries: usize,
        num_shreds: u64,
        bank_complete_time_us: u64,
    ) {
        lazy! {
            datapoint_info!(
                "replay-slot-stats",
                ("slot", slot as i64, i64),
                ("fetch_entries_time", self.fetch_elapsed as i64, i64),
                (
                    "fetch_entries_fail_time",
                    self.fetch_fail_elapsed as i64,
                    i64
                ),
                (
                    "entry_poh_verification_time",
                    self.poh_verify_elapsed as i64,
                    i64
                ),
                (
                    "entry_transaction_verification_time",
                    self.transaction_verify_elapsed as i64,
                    i64
                ),
                ("confirmation_time_us", self.confirmation_elapsed as i64, i64),
                ("replay_time", self.replay_elapsed as i64, i64),
                ("execute_batches_us", self.batch_execute.wall_clock_us as i64, i64),
                (
                    "replay_total_elapsed",
                    self.started.elapsed().as_micros() as i64,
                    i64
                ),
                ("bank_complete_time_us", bank_complete_time_us, i64),
                ("total_transactions", num_txs as i64, i64),
                ("total_entries", num_entries as i64, i64),
                ("total_shreds", num_shreds as i64, i64),
                // Everything inside the `eager!` block will be eagerly expanded before
                // evaluation of the rest of the surrounding macro.
                eager!{report_execute_timings!(self.batch_execute.totals)}
            );
        };

        self.batch_execute.slowest_thread.report_stats(slot);

        let mut per_pubkey_timings: Vec<_> = self
            .batch_execute
            .totals
            .details
            .per_program_timings
            .iter()
            .collect();
        per_pubkey_timings.sort_by(|a, b| b.1.accumulated_us.cmp(&a.1.accumulated_us));
        let (total_us, total_units, total_count, total_errored_units, total_errored_count) =
            per_pubkey_timings.iter().fold(
                (0, 0, 0, 0, 0),
                |(sum_us, sum_units, sum_count, sum_errored_units, sum_errored_count), a| {
                    (
                        sum_us + a.1.accumulated_us,
                        sum_units + a.1.accumulated_units,
                        sum_count + a.1.count,
                        sum_errored_units + a.1.total_errored_units,
                        sum_errored_count + a.1.errored_txs_compute_consumed.len(),
                    )
                },
            );

        for (pubkey, time) in per_pubkey_timings.iter().take(5) {
            datapoint_trace!(
                "per_program_timings",
                ("slot", slot as i64, i64),
                ("pubkey", pubkey.to_string(), String),
                ("execute_us", time.accumulated_us, i64),
                ("accumulated_units", time.accumulated_units, i64),
                ("errored_units", time.total_errored_units, i64),
                ("count", time.count, i64),
                (
                    "errored_count",
                    time.errored_txs_compute_consumed.len(),
                    i64
                ),
            );
        }
        datapoint_info!(
            "per_program_timings",
            ("slot", slot as i64, i64),
            ("pubkey", "all", String),
            ("execute_us", total_us, i64),
            ("accumulated_units", total_units, i64),
            ("count", total_count, i64),
            ("errored_units", total_errored_units, i64),
            ("errored_count", total_errored_count, i64)
        );
    }
}

#[derive(Debug)]
pub struct ValidatorStakeInfo {
    pub validator_vote_pubkey: Pubkey,
    pub stake: u64,
    pub total_epoch_stake: u64,
}

impl Default for ValidatorStakeInfo {
    fn default() -> Self {
        Self {
            stake: 0,
            validator_vote_pubkey: Pubkey::default(),
            total_epoch_stake: 1,
        }
    }
}

impl ValidatorStakeInfo {
    pub fn new(validator_vote_pubkey: Pubkey, stake: u64, total_epoch_stake: u64) -> Self {
        Self {
            validator_vote_pubkey,
            stake,
            total_epoch_stake,
        }
    }
}

pub const RETRANSMIT_BASE_DELAY_MS: u64 = 5_000;
pub const RETRANSMIT_BACKOFF_CAP: u32 = 6;

#[derive(Debug)]
pub struct RetransmitInfo {
    pub(crate) retry_time: Instant,
    pub(crate) retry_iteration: u32,
}

impl RetransmitInfo {
    pub fn reached_retransmit_threshold(&self) -> bool {
        let backoff = std::cmp::min(self.retry_iteration, RETRANSMIT_BACKOFF_CAP);
        let backoff_duration_ms = (1_u64 << backoff) * RETRANSMIT_BASE_DELAY_MS;
        self.retry_time.elapsed().as_millis() > u128::from(backoff_duration_ms)
    }

    pub fn increment_retry_iteration(&mut self) {
        self.retry_iteration = self.retry_iteration.saturating_add(1);
        self.retry_time = Instant::now();
    }
}

pub struct ForkProgress {
    pub is_dead: bool,
    pub fork_stats: ForkStats,
    pub propagated_stats: PropagatedStats,
    pub replay_stats: Arc<RwLock<ReplaySlotStats>>,
    pub replay_progress: Arc<RwLock<ConfirmationProgress>>,
    pub retransmit_info: RetransmitInfo,
    // Note `num_blocks_on_fork` and `num_dropped_blocks_on_fork` only
    // count new blocks replayed since last restart, which won't include
    // blocks already existing in the ledger/before snapshot at start,
    // so these stats do not span all of time
    pub num_blocks_on_fork: u64,
    pub num_dropped_blocks_on_fork: u64,
}

impl ForkProgress {
    pub fn new(
        last_entry: Hash,
        prev_leader_slot: Option<Slot>,
        validator_stake_info: Option<ValidatorStakeInfo>,
        num_blocks_on_fork: u64,
        num_dropped_blocks_on_fork: u64,
    ) -> Self {
        let (
            is_leader_slot,
            propagated_validators_stake,
            propagated_validators,
            is_propagated,
            total_epoch_stake,
        ) = validator_stake_info
            .map(|info| {
                (
                    true,
                    info.stake,
                    vec![info.validator_vote_pubkey].into_iter().collect(),
                    {
                        if info.total_epoch_stake == 0 {
                            true
                        } else {
                            info.stake as f64 / info.total_epoch_stake as f64
                                > SUPERMINORITY_THRESHOLD
                        }
                    },
                    info.total_epoch_stake,
                )
            })
            .unwrap_or((false, 0, HashSet::new(), false, 0));

        Self {
            is_dead: false,
            fork_stats: ForkStats::default(),
            replay_stats: Arc::new(RwLock::new(ReplaySlotStats::default())),
            replay_progress: Arc::new(RwLock::new(ConfirmationProgress::new(last_entry))),
            num_blocks_on_fork,
            num_dropped_blocks_on_fork,
            propagated_stats: PropagatedStats {
                propagated_validators,
                propagated_validators_stake,
                is_propagated,
                is_leader_slot,
                prev_leader_slot,
                total_epoch_stake,
                ..PropagatedStats::default()
            },
            retransmit_info: RetransmitInfo {
                retry_time: Instant::now(),
                retry_iteration: 0u32,
            },
        }
    }

    pub fn new_from_bank(
        bank: &Bank,
        validator_identity: &Pubkey,
        validator_vote_pubkey: &Pubkey,
        prev_leader_slot: Option<Slot>,
        num_blocks_on_fork: u64,
        num_dropped_blocks_on_fork: u64,
    ) -> Self {
        let validator_stake_info = {
            if bank.collector_id() == validator_identity {
                Some(ValidatorStakeInfo::new(
                    *validator_vote_pubkey,
                    bank.epoch_vote_account_stake(validator_vote_pubkey),
                    bank.total_epoch_stake(),
                ))
            } else {
                None
            }
        };

        let mut new_progress = Self::new(
            bank.last_blockhash(),
            prev_leader_slot,
            validator_stake_info,
            num_blocks_on_fork,
            num_dropped_blocks_on_fork,
        );

        if bank.is_frozen() {
            new_progress.fork_stats.bank_hash = Some(bank.hash());
        }
        new_progress
    }
}

#[derive(Debug, Clone, Default)]
pub struct ForkStats {
    pub weight: u128,
    pub fork_weight: u128,
    pub total_stake: Stake,
    pub block_height: u64,
    pub has_voted: bool,
    pub is_recent: bool,
    pub is_empty: bool,
    pub vote_threshold: ThresholdDecision,
    pub is_locked_out: bool,
    pub voted_stakes: VotedStakes,
    pub is_supermajority_confirmed: bool,
    pub computed: bool,
    pub lockout_intervals: LockoutIntervals,
    pub bank_hash: Option<Hash>,
    pub my_latest_landed_vote: Option<Slot>,
}

#[derive(Clone, Default)]
pub struct PropagatedStats {
    pub propagated_validators: HashSet<Pubkey>,
    pub propagated_node_ids: HashSet<Pubkey>,
    pub propagated_validators_stake: u64,
    pub is_propagated: bool,
    pub is_leader_slot: bool,
    pub prev_leader_slot: Option<Slot>,
    pub slot_vote_tracker: Option<Arc<RwLock<SlotVoteTracker>>>,
    pub cluster_slot_pubkeys: Option<Arc<RwLock<SlotPubkeys>>>,
    pub total_epoch_stake: u64,
}

impl PropagatedStats {
    pub fn add_vote_pubkey(&mut self, vote_pubkey: Pubkey, stake: u64) {
        if self.propagated_validators.insert(vote_pubkey) {
            self.propagated_validators_stake += stake;
        }
    }

    pub fn add_node_pubkey(&mut self, node_pubkey: &Pubkey, bank: &Bank) {
        if !self.propagated_node_ids.contains(node_pubkey) {
            let node_vote_accounts = bank
                .epoch_vote_accounts_for_node_id(node_pubkey)
                .map(|v| &v.vote_accounts);

            if let Some(node_vote_accounts) = node_vote_accounts {
                self.add_node_pubkey_internal(
                    node_pubkey,
                    node_vote_accounts,
                    bank.epoch_vote_accounts(bank.epoch())
                        .expect("Epoch stakes for bank's own epoch must exist"),
                );
            }
        }
    }

    fn add_node_pubkey_internal(
        &mut self,
        node_pubkey: &Pubkey,
        vote_account_pubkeys: &[Pubkey],
        epoch_vote_accounts: &VoteAccountsHashMap,
    ) {
        self.propagated_node_ids.insert(*node_pubkey);
        for vote_account_pubkey in vote_account_pubkeys.iter() {
            let stake = epoch_vote_accounts
                .get(vote_account_pubkey)
                .map(|(stake, _)| *stake)
                .unwrap_or(0);
            self.add_vote_pubkey(*vote_account_pubkey, stake);
        }
    }
}

#[derive(Default)]
pub struct ProgressMap {
    progress_map: HashMap<Slot, ForkProgress>,
}

impl std::ops::Deref for ProgressMap {
    type Target = HashMap<Slot, ForkProgress>;
    fn deref(&self) -> &Self::Target {
        &self.progress_map
    }
}

impl std::ops::DerefMut for ProgressMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.progress_map
    }
}

impl ProgressMap {
    pub fn insert(&mut self, slot: Slot, fork_progress: ForkProgress) {
        self.progress_map.insert(slot, fork_progress);
    }

    pub fn get_propagated_stats(&self, slot: Slot) -> Option<&PropagatedStats> {
        self.progress_map
            .get(&slot)
            .map(|fork_progress| &fork_progress.propagated_stats)
    }

    pub fn get_propagated_stats_mut(&mut self, slot: Slot) -> Option<&mut PropagatedStats> {
        self.progress_map
            .get_mut(&slot)
            .map(|fork_progress| &mut fork_progress.propagated_stats)
    }

    pub fn get_propagated_stats_must_exist(&self, slot: Slot) -> &PropagatedStats {
        self.get_propagated_stats(slot)
            .unwrap_or_else(|| panic!("slot={slot} must exist in ProgressMap"))
    }

    pub fn get_fork_stats(&self, slot: Slot) -> Option<&ForkStats> {
        self.progress_map
            .get(&slot)
            .map(|fork_progress| &fork_progress.fork_stats)
    }

    pub fn get_fork_stats_mut(&mut self, slot: Slot) -> Option<&mut ForkStats> {
        self.progress_map
            .get_mut(&slot)
            .map(|fork_progress| &mut fork_progress.fork_stats)
    }

    pub fn get_retransmit_info(&self, slot: Slot) -> Option<&RetransmitInfo> {
        self.progress_map
            .get(&slot)
            .map(|fork_progress| &fork_progress.retransmit_info)
    }

    pub fn get_retransmit_info_mut(&mut self, slot: Slot) -> Option<&mut RetransmitInfo> {
        self.progress_map
            .get_mut(&slot)
            .map(|fork_progress| &mut fork_progress.retransmit_info)
    }

    pub fn is_dead(&self, slot: Slot) -> Option<bool> {
        self.progress_map
            .get(&slot)
            .map(|fork_progress| fork_progress.is_dead)
    }

    pub fn get_hash(&self, slot: Slot) -> Option<Hash> {
        self.progress_map
            .get(&slot)
            .and_then(|fork_progress| fork_progress.fork_stats.bank_hash)
    }

    pub fn is_propagated(&self, slot: Slot) -> Option<bool> {
        self.get_propagated_stats(slot)
            .map(|stats| stats.is_propagated)
    }

    pub fn get_latest_leader_slot_must_exist(&self, slot: Slot) -> Option<Slot> {
        let propagated_stats = self.get_propagated_stats_must_exist(slot);
        if propagated_stats.is_leader_slot {
            Some(slot)
        } else {
            propagated_stats.prev_leader_slot
        }
    }

    pub fn get_leader_propagation_slot_must_exist(&self, slot: Slot) -> (bool, Option<Slot>) {
        if let Some(leader_slot) = self.get_latest_leader_slot_must_exist(slot) {
            // If the leader's stats are None (isn't in the
            // progress map), this means that prev_leader slot is
            // rooted, so return true
            (
                self.is_propagated(leader_slot).unwrap_or(true),
                Some(leader_slot),
            )
        } else {
            // prev_leader_slot doesn't exist because already rooted
            // or this validator hasn't been scheduled as a leader
            // yet. In both cases the latest leader is vacuously
            // confirmed
            (true, None)
        }
    }

    pub fn my_latest_landed_vote(&self, slot: Slot) -> Option<Slot> {
        self.progress_map
            .get(&slot)
            .and_then(|s| s.fork_stats.my_latest_landed_vote)
    }

    pub fn set_supermajority_confirmed_slot(&mut self, slot: Slot) {
        let slot_progress = self.get_mut(&slot).unwrap();
        slot_progress.fork_stats.is_supermajority_confirmed = true;
    }

    pub fn is_supermajority_confirmed(&self, slot: Slot) -> Option<bool> {
        self.progress_map
            .get(&slot)
            .map(|s| s.fork_stats.is_supermajority_confirmed)
    }

    pub fn get_bank_prev_leader_slot(&self, bank: &Bank) -> Option<Slot> {
        let parent_slot = bank.parent_slot();
        self.get_propagated_stats(parent_slot)
            .map(|stats| {
                if stats.is_leader_slot {
                    Some(parent_slot)
                } else {
                    stats.prev_leader_slot
                }
            })
            .unwrap_or(None)
    }

    pub fn handle_new_root(&mut self, bank_forks: &BankForks) {
        self.progress_map
            .retain(|k, _| bank_forks.get(*k).is_some());
    }

    pub fn log_propagated_stats(&self, slot: Slot, bank_forks: &RwLock<BankForks>) {
        if let Some(stats) = self.get_propagated_stats(slot) {
            info!(
                "Propagated stats:
                total staked: {},
                observed staked: {},
                vote pubkeys: {:?},
                node_pubkeys: {:?},
                slot: {},
                epoch: {:?}",
                stats.total_epoch_stake,
                stats.propagated_validators_stake,
                stats.propagated_validators,
                stats.propagated_node_ids,
                slot,
                bank_forks.read().unwrap().get(slot).map(|x| x.epoch()),
            );
        }
    }
}
