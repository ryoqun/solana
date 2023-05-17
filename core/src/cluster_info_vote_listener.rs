use {
    crate::{
        banking_trace::{BankingPacketBatch, BankingPacketSender},
        optimistic_confirmation_verifier::OptimisticConfirmationVerifier,
        replay_stage::DUPLICATE_THRESHOLD,
        result::{Error, Result},
        sigverify,
        verified_vote_packets::{
            ValidatorGossipVotesIterator, VerifiedVoteMetadata, VerifiedVotePackets,
        },
        vote_stake_tracker::VoteStakeTracker,
    },
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Select, Sender},
    log::*,
    solana_gossip::{
        cluster_info::{ClusterInfo, GOSSIP_SLEEP_MILLIS},
        crds::Cursor,
    },
    solana_ledger::blockstore::Blockstore,
    solana_measure::measure::Measure,
    solana_metrics::inc_new_counter_debug,
    solana_perf::packet,
    solana_poh::poh_recorder::PohRecorder,
    solana_rpc::{
        optimistically_confirmed_bank_tracker::{BankNotification, BankNotificationSender},
        rpc_subscriptions::RpcSubscriptions,
    },
    solana_runtime::{
        bank::Bank,
        bank_forks::BankForks,
        commitment::VOTE_THRESHOLD_SIZE,
        epoch_stakes::EpochStakes,
        vote_parser::{self, ParsedVote},
        vote_sender_types::ReplayVoteReceiver,
        vote_transaction::VoteTransaction,
    },
    solana_sdk::{
        clock::{Slot, DEFAULT_MS_PER_SLOT, DEFAULT_TICKS_PER_SLOT},
        hash::Hash,
        pubkey::Pubkey,
        signature::Signature,
        slot_hashes,
        timing::AtomicInterval,
        transaction::Transaction,
    },
    std::{
        collections::{HashMap, HashSet},
        iter::repeat,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, sleep, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

// Map from a vote account to the authorized voter for an epoch
pub type ThresholdConfirmedSlots = Vec<(Slot, Hash)>;
pub type VerifiedLabelVotePacketsSender = Sender<Vec<VerifiedVoteMetadata>>;
pub type VerifiedLabelVotePacketsReceiver = Receiver<Vec<VerifiedVoteMetadata>>;
pub type VerifiedVoteTransactionsSender = Sender<Vec<Transaction>>;
pub type VerifiedVoteTransactionsReceiver = Receiver<Vec<Transaction>>;
pub type VerifiedVoteSender = Sender<(Pubkey, Vec<Slot>)>;
pub type VerifiedVoteReceiver = Receiver<(Pubkey, Vec<Slot>)>;
pub type GossipVerifiedVoteHashSender = Sender<(Pubkey, Slot, Hash)>;
pub type GossipVerifiedVoteHashReceiver = Receiver<(Pubkey, Slot, Hash)>;
pub type GossipDuplicateConfirmedSlotsSender = Sender<ThresholdConfirmedSlots>;
pub type GossipDuplicateConfirmedSlotsReceiver = Receiver<ThresholdConfirmedSlots>;

const THRESHOLDS_TO_CHECK: [f64; 2] = [DUPLICATE_THRESHOLD, VOTE_THRESHOLD_SIZE];
const BANK_SEND_VOTES_LOOP_SLEEP_MS: u128 = 10;

#[derive(Default)]
pub struct SlotVoteTracker {
    // Maps pubkeys that have voted for this slot
    // to whether or not we've seen the vote on gossip.
    // True if seen on gossip, false if only seen in replay.
    voted: HashMap<Pubkey, bool>,
    optimistic_votes_tracker: HashMap<Hash, VoteStakeTracker>,
    voted_slot_updates: Option<Vec<Pubkey>>,
    gossip_only_stake: u64,
}

impl SlotVoteTracker {
    pub(crate) fn get_voted_slot_updates(&mut self) -> Option<Vec<Pubkey>> {
        self.voted_slot_updates.take()
    }

    fn get_or_insert_optimistic_votes_tracker(&mut self, hash: Hash) -> &mut VoteStakeTracker {
        self.optimistic_votes_tracker.entry(hash).or_default()
    }
    pub(crate) fn optimistic_votes_tracker(&self, hash: &Hash) -> Option<&VoteStakeTracker> {
        self.optimistic_votes_tracker.get(hash)
    }
}

#[derive(Default)]
pub struct VoteTracker {
    // Map from a slot to a set of validators who have voted for that slot
    slot_vote_trackers: RwLock<HashMap<Slot, Arc<RwLock<SlotVoteTracker>>>>,
}

impl VoteTracker {
    fn get_or_insert_slot_tracker(&self, slot: Slot) -> Arc<RwLock<SlotVoteTracker>> {
        if let Some(slot_vote_tracker) = self.slot_vote_trackers.read().unwrap().get(&slot) {
            return slot_vote_tracker.clone();
        }
        let mut slot_vote_trackers = self.slot_vote_trackers.write().unwrap();
        slot_vote_trackers.entry(slot).or_default().clone()
    }

    pub(crate) fn get_slot_vote_tracker(&self, slot: Slot) -> Option<Arc<RwLock<SlotVoteTracker>>> {
        self.slot_vote_trackers.read().unwrap().get(&slot).cloned()
    }

    fn purge_stale_state(&self, root_bank: &Bank) {
        // Purge any outdated slot data
        let new_root = root_bank.slot();
        self.slot_vote_trackers
            .write()
            .unwrap()
            .retain(|slot, _| *slot >= new_root);
    }

    fn progress_with_new_root_bank(&self, root_bank: &Bank) {
        self.purge_stale_state(root_bank);
    }
}

struct BankVoteSenderState {
    bank: Arc<Bank>,
    previously_sent_to_bank_votes: HashSet<Signature>,
    bank_send_votes_stats: BankSendVotesStats,
}

impl BankVoteSenderState {
    fn new(bank: Arc<Bank>) -> Self {
        Self {
            bank,
            previously_sent_to_bank_votes: HashSet::new(),
            bank_send_votes_stats: BankSendVotesStats::default(),
        }
    }

    fn report_metrics(&self) {
        self.bank_send_votes_stats.report_metrics(self.bank.slot());
    }
}

#[derive(Default)]
struct BankSendVotesStats {
    num_votes_sent: usize,
    num_batches_sent: usize,
    total_elapsed: u64,
}

impl BankSendVotesStats {
    fn report_metrics(&self, slot: Slot) {
        datapoint_info!(
            "cluster_info_vote_listener-bank-send-vote-stats",
            ("slot", slot, i64),
            ("num_votes_sent", self.num_votes_sent, i64),
            ("total_elapsed", self.total_elapsed, i64),
            ("num_batches_sent", self.num_batches_sent, i64),
        );
    }
}

#[derive(Default)]
struct VoteProcessingTiming {
    gossip_txn_processing_time_us: u64,
    gossip_slot_confirming_time_us: u64,
    last_report: AtomicInterval,
}

const VOTE_PROCESSING_REPORT_INTERVAL_MS: u64 = 1_000;

impl VoteProcessingTiming {
    fn reset(&mut self) {
        self.gossip_txn_processing_time_us = 0;
        self.gossip_slot_confirming_time_us = 0;
    }

    fn update(&mut self, vote_txn_processing_time_us: u64, vote_slot_confirming_time_us: u64) {
        self.gossip_txn_processing_time_us += vote_txn_processing_time_us;
        self.gossip_slot_confirming_time_us += vote_slot_confirming_time_us;

        if self
            .last_report
            .should_update(VOTE_PROCESSING_REPORT_INTERVAL_MS)
        {
            datapoint_info!(
                "vote-processing-timing",
                (
                    "vote_txn_processing_us",
                    self.gossip_txn_processing_time_us as i64,
                    i64
                ),
                (
                    "slot_confirming_time_us",
                    self.gossip_slot_confirming_time_us as i64,
                    i64
                ),
            );
            self.reset();
        }
    }
}

pub struct ClusterInfoVoteListener {
    thread_hdls: Vec<JoinHandle<()>>,
}

impl ClusterInfoVoteListener {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exit: Arc<AtomicBool>,
        cluster_info: Arc<ClusterInfo>,
        verified_packets_sender: BankingPacketSender,
        poh_recorder: Arc<RwLock<PohRecorder>>,
        vote_tracker: Arc<VoteTracker>,
        bank_forks: Arc<RwLock<BankForks>>,
        subscriptions: Arc<RpcSubscriptions>,
        verified_vote_sender: VerifiedVoteSender,
        gossip_verified_vote_hash_sender: GossipVerifiedVoteHashSender,
        replay_votes_receiver: ReplayVoteReceiver,
        blockstore: Arc<Blockstore>,
        bank_notification_sender: Option<BankNotificationSender>,
        cluster_confirmed_slot_sender: GossipDuplicateConfirmedSlotsSender,
    ) -> Self {
        let (verified_vote_label_packets_sender, verified_vote_label_packets_receiver) =
            unbounded();
        let (verified_vote_transactions_sender, verified_vote_transactions_receiver) = unbounded();
        let listen_thread = {
            let exit = exit.clone();
            let bank_forks = bank_forks.clone();
            Builder::new()
                .name("solCiVoteLstnr".to_string())
                .spawn(move || {
                    let _ = Self::recv_loop(
                        exit,
                        &cluster_info,
                        &bank_forks,
                        verified_vote_label_packets_sender,
                        verified_vote_transactions_sender,
                    );
                })
                .unwrap()
        };
        let exit_ = exit.clone();
        let bank_send_thread = Builder::new()
            .name("solCiBankSend".to_string())
            .spawn(move || {
                let _ = Self::bank_send_loop(
                    exit_,
                    verified_vote_label_packets_receiver,
                    poh_recorder,
                    &verified_packets_sender,
                );
            })
            .unwrap();

        let send_thread = Builder::new()
            .name("solCiProcVotes".to_string())
            .spawn(move || {
                let _ = Self::process_votes_loop(
                    exit,
                    verified_vote_transactions_receiver,
                    vote_tracker,
                    bank_forks,
                    subscriptions,
                    gossip_verified_vote_hash_sender,
                    verified_vote_sender,
                    replay_votes_receiver,
                    blockstore,
                    bank_notification_sender,
                    cluster_confirmed_slot_sender,
                );
            })
            .unwrap();

        Self {
            thread_hdls: vec![listen_thread, send_thread, bank_send_thread],
        }
    }

    pub(crate) fn join(self) -> thread::Result<()> {
        self.thread_hdls.into_iter().try_for_each(JoinHandle::join)
    }

    fn recv_loop(
        exit: Arc<AtomicBool>,
        cluster_info: &ClusterInfo,
        bank_forks: &RwLock<BankForks>,
        verified_vote_label_packets_sender: VerifiedLabelVotePacketsSender,
        verified_vote_transactions_sender: VerifiedVoteTransactionsSender,
    ) -> Result<()> {
        let mut cursor = Cursor::default();
        while !exit.load(Ordering::Relaxed) {
            let votes = cluster_info.get_votes(&mut cursor);
            inc_new_counter_debug!("cluster_info_vote_listener-recv_count", votes.len());
            if !votes.is_empty() {
                let (vote_txs, packets) = Self::verify_votes(votes, bank_forks);
                verified_vote_transactions_sender.send(vote_txs)?;
                verified_vote_label_packets_sender.send(packets)?;
            }
            sleep(Duration::from_millis(GOSSIP_SLEEP_MILLIS));
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn verify_votes(
        votes: Vec<Transaction>,
        bank_forks: &RwLock<BankForks>,
    ) -> (Vec<Transaction>, Vec<VerifiedVoteMetadata>) {
        let mut packet_batches = packet::to_packet_batches(&votes, 1);

        // Votes should already be filtered by this point.
        sigverify::ed25519_verify_cpu(
            &mut packet_batches,
            /*reject_non_vote=*/ false,
            votes.len(),
        );
        let root_bank = bank_forks.read().unwrap().root_bank();
        let epoch_schedule = root_bank.epoch_schedule();
        votes
            .into_iter()
            .zip(packet_batches)
            .filter(|(_, packet_batch)| {
                // to_packet_batches() above splits into 1 packet long batches
                assert_eq!(packet_batch.len(), 1);
                !packet_batch[0].meta().discard()
            })
            .filter_map(|(tx, packet_batch)| {
                let (vote_account_key, vote, ..) = vote_parser::parse_vote_transaction(&tx)?;
                let slot = vote.last_voted_slot()?;
                let epoch = epoch_schedule.get_epoch(slot);
                let authorized_voter = root_bank
                    .epoch_stakes(epoch)?
                    .epoch_authorized_voters()
                    .get(&vote_account_key)?;
                let mut keys = tx.message.account_keys.iter().enumerate();
                if !keys.any(|(i, key)| tx.message.is_signer(i) && key == authorized_voter) {
                    return None;
                }
                let verified_vote_metadata = VerifiedVoteMetadata {
                    vote_account_key,
                    vote,
                    packet_batch,
                    signature: *tx.signatures.first()?,
                };
                Some((tx, verified_vote_metadata))
            })
            .unzip()
    }

    fn bank_send_loop(
        exit: Arc<AtomicBool>,
        verified_vote_label_packets_receiver: VerifiedLabelVotePacketsReceiver,
        poh_recorder: Arc<RwLock<PohRecorder>>,
        verified_packets_sender: &BankingPacketSender,
    ) -> Result<()> {
        let mut verified_vote_packets = VerifiedVotePackets::default();
        let mut time_since_lock = Instant::now();
        let mut bank_vote_sender_state_option: Option<BankVoteSenderState> = None;

        loop {
            if exit.load(Ordering::Relaxed) {
                return Ok(());
            }

            let would_be_leader = poh_recorder
                .read()
                .unwrap()
                .would_be_leader(3 * slot_hashes::MAX_ENTRIES as u64 * DEFAULT_TICKS_PER_SLOT);
            let feature_set = poh_recorder
                .read()
                .unwrap()
                .bank()
                .map(|bank| bank.feature_set.clone());

            if let Err(e) = verified_vote_packets.receive_and_process_vote_packets(
                &verified_vote_label_packets_receiver,
                would_be_leader,
                feature_set,
            ) {
                match e {
                    Error::RecvTimeout(RecvTimeoutError::Disconnected)
                    | Error::RecvTimeout(RecvTimeoutError::Timeout) => (),
                    _ => {
                        error!("thread {:?} error {:?}", thread::current().name(), e);
                    }
                }
            }

            if time_since_lock.elapsed().as_millis() > BANK_SEND_VOTES_LOOP_SLEEP_MS {
                // Always set this to avoid taking the poh lock too often
                time_since_lock = Instant::now();
                // We will take this lock at most once every `BANK_SEND_VOTES_LOOP_SLEEP_MS`
                let current_working_bank = poh_recorder.read().unwrap().bank();
                if let Some(current_working_bank) = current_working_bank {
                    Self::check_for_leader_bank_and_send_votes(
                        &mut bank_vote_sender_state_option,
                        current_working_bank,
                        verified_packets_sender,
                        &verified_vote_packets,
                    )?;
                }
            }
        }
    }

    fn check_for_leader_bank_and_send_votes(
        bank_vote_sender_state_option: &mut Option<BankVoteSenderState>,
        current_working_bank: Arc<Bank>,
        verified_packets_sender: &BankingPacketSender,
        verified_vote_packets: &VerifiedVotePackets,
    ) -> Result<()> {
        // We will take this lock at most once every `BANK_SEND_VOTES_LOOP_SLEEP_MS`
        if let Some(bank_vote_sender_state) = bank_vote_sender_state_option {
            if bank_vote_sender_state.bank.slot() != current_working_bank.slot() {
                bank_vote_sender_state.report_metrics();
                *bank_vote_sender_state_option =
                    Some(BankVoteSenderState::new(current_working_bank));
            }
        } else {
            *bank_vote_sender_state_option = Some(BankVoteSenderState::new(current_working_bank));
        }

        let bank_vote_sender_state = bank_vote_sender_state_option.as_mut().unwrap();
        let BankVoteSenderState {
            ref bank,
            ref mut bank_send_votes_stats,
            ref mut previously_sent_to_bank_votes,
        } = bank_vote_sender_state;

        // This logic may run multiple times for the same leader bank,
        // we just have to ensure that the same votes are not sent
        // to the bank multiple times, which is guaranteed by
        // `previously_sent_to_bank_votes`
        let gossip_votes_iterator = ValidatorGossipVotesIterator::new(
            bank.clone(),
            verified_vote_packets,
            previously_sent_to_bank_votes,
        );

        let mut filter_gossip_votes_timing = Measure::start("filter_gossip_votes");

        // Send entire batch at a time so that there is no partial processing of
        // a single validator's votes by two different banks. This might happen
        // if we sent each vote individually, for instance if we created two different
        // leader banks from the same common parent, one leader bank may process
        // only the later votes and ignore the earlier votes.
        for single_validator_votes in gossip_votes_iterator {
            bank_send_votes_stats.num_votes_sent += single_validator_votes.len();
            bank_send_votes_stats.num_batches_sent += 1;
            verified_packets_sender
                .send(BankingPacketBatch::new((single_validator_votes, None)))?;
        }
        filter_gossip_votes_timing.stop();
        bank_send_votes_stats.total_elapsed += filter_gossip_votes_timing.as_us();

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_votes_loop(
        exit: Arc<AtomicBool>,
        gossip_vote_txs_receiver: VerifiedVoteTransactionsReceiver,
        vote_tracker: Arc<VoteTracker>,
        bank_forks: Arc<RwLock<BankForks>>,
        subscriptions: Arc<RpcSubscriptions>,
        gossip_verified_vote_hash_sender: GossipVerifiedVoteHashSender,
        verified_vote_sender: VerifiedVoteSender,
        replay_votes_receiver: ReplayVoteReceiver,
        blockstore: Arc<Blockstore>,
        bank_notification_sender: Option<BankNotificationSender>,
        cluster_confirmed_slot_sender: GossipDuplicateConfirmedSlotsSender,
    ) -> Result<()> {
        let mut confirmation_verifier =
            OptimisticConfirmationVerifier::new(bank_forks.read().unwrap().root());
        let mut last_process_root = Instant::now();
        let cluster_confirmed_slot_sender = Some(cluster_confirmed_slot_sender);
        let mut vote_processing_time = Some(VoteProcessingTiming::default());
        loop {
            if exit.load(Ordering::Relaxed) {
                return Ok(());
            }

            let root_bank = bank_forks.read().unwrap().root_bank();
            if last_process_root.elapsed().as_millis() > DEFAULT_MS_PER_SLOT as u128 {
                let unrooted_optimistic_slots = confirmation_verifier
                    .verify_for_unrooted_optimistic_slots(&root_bank, &blockstore);
                // SlotVoteTracker's for all `slots` in `unrooted_optimistic_slots`
                // should still be available because we haven't purged in
                // `progress_with_new_root_bank()` yet, which is called below
                OptimisticConfirmationVerifier::log_unrooted_optimistic_slots(
                    &root_bank,
                    &vote_tracker,
                    &unrooted_optimistic_slots,
                );
                vote_tracker.progress_with_new_root_bank(&root_bank);
                last_process_root = Instant::now();
            }
            let confirmed_slots = Self::listen_and_confirm_votes(
                &gossip_vote_txs_receiver,
                &vote_tracker,
                &root_bank,
                &subscriptions,
                &gossip_verified_vote_hash_sender,
                &verified_vote_sender,
                &replay_votes_receiver,
                &bank_notification_sender,
                &cluster_confirmed_slot_sender,
                &mut vote_processing_time,
            );
            match confirmed_slots {
                Ok(confirmed_slots) => {
                    confirmation_verifier
                        .add_new_optimistic_confirmed_slots(confirmed_slots.clone(), &blockstore);
                }
                Err(e) => match e {
                    Error::RecvTimeout(RecvTimeoutError::Disconnected) => {
                        return Ok(());
                    }
                    Error::ReadyTimeout => (),
                    _ => {
                        error!("thread {:?} error {:?}", thread::current().name(), e);
                    }
                },
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn listen_and_confirm_votes(
        gossip_vote_txs_receiver: &VerifiedVoteTransactionsReceiver,
        vote_tracker: &VoteTracker,
        root_bank: &Bank,
        subscriptions: &RpcSubscriptions,
        gossip_verified_vote_hash_sender: &GossipVerifiedVoteHashSender,
        verified_vote_sender: &VerifiedVoteSender,
        replay_votes_receiver: &ReplayVoteReceiver,
        bank_notification_sender: &Option<BankNotificationSender>,
        cluster_confirmed_slot_sender: &Option<GossipDuplicateConfirmedSlotsSender>,
        vote_processing_time: &mut Option<VoteProcessingTiming>,
    ) -> Result<ThresholdConfirmedSlots> {
        let mut sel = Select::new();
        sel.recv(gossip_vote_txs_receiver);
        sel.recv(replay_votes_receiver);
        let mut remaining_wait_time = Duration::from_millis(200);
        while remaining_wait_time > Duration::ZERO {
            let start = Instant::now();
            // Wait for one of the receivers to be ready. `ready_timeout`
            // will return if channels either have something, or are
            // disconnected. `ready_timeout` can wake up spuriously,
            // hence the loop
            let _ = sel.ready_timeout(remaining_wait_time)?;

            // Should not early return from this point onwards until `process_votes()`
            // returns below to avoid missing any potential `optimistic_confirmed_slots`
            let gossip_vote_txs: Vec<_> = gossip_vote_txs_receiver.try_iter().flatten().collect();
            let replay_votes: Vec<_> = replay_votes_receiver.try_iter().collect();
            if !gossip_vote_txs.is_empty() || !replay_votes.is_empty() {
                return Ok(Self::filter_and_confirm_with_new_votes(
                    vote_tracker,
                    gossip_vote_txs,
                    replay_votes,
                    root_bank,
                    subscriptions,
                    gossip_verified_vote_hash_sender,
                    verified_vote_sender,
                    bank_notification_sender,
                    cluster_confirmed_slot_sender,
                    vote_processing_time,
                ));
            }
            remaining_wait_time = remaining_wait_time.saturating_sub(start.elapsed());
        }
        Ok(vec![])
    }

    #[allow(clippy::too_many_arguments)]
    fn track_new_votes_and_notify_confirmations(
        vote: VoteTransaction,
        vote_pubkey: &Pubkey,
        vote_transaction_signature: Signature,
        vote_tracker: &VoteTracker,
        root_bank: &Bank,
        subscriptions: &RpcSubscriptions,
        verified_vote_sender: &VerifiedVoteSender,
        gossip_verified_vote_hash_sender: &GossipVerifiedVoteHashSender,
        diff: &mut HashMap<Slot, HashMap<Pubkey, bool>>,
        new_optimistic_confirmed_slots: &mut ThresholdConfirmedSlots,
        is_gossip_vote: bool,
        bank_notification_sender: &Option<BankNotificationSender>,
        cluster_confirmed_slot_sender: &Option<GossipDuplicateConfirmedSlotsSender>,
    ) {
        if vote.is_empty() {
            return;
        }

        let (last_vote_slot, last_vote_hash) = vote.last_voted_slot_hash().unwrap();

        let root = root_bank.slot();
        let mut is_new_vote = false;
        let vote_slots = vote.slots();
        // If slot is before the root, ignore it
        for slot in vote_slots.iter().filter(|slot| **slot > root).rev() {
            let slot = *slot;

            // if we don't have stake information, ignore it
            let epoch = root_bank.epoch_schedule().get_epoch(slot);
            let epoch_stakes = root_bank.epoch_stakes(epoch);
            if epoch_stakes.is_none() {
                continue;
            }
            let epoch_stakes = epoch_stakes.unwrap();

            // The last vote slot, which is the greatest slot in the stack
            // of votes in a vote transaction, qualifies for optimistic confirmation.
            // We cannot count any other slots in this vote toward optimistic confirmation because:
            // 1) There may have been a switch between the earlier vote and the last vote
            // 2) We do not know the hash of the earlier slot
            if slot == last_vote_slot {
                let vote_accounts = epoch_stakes.stakes().vote_accounts();
                let stake = vote_accounts.get_delegated_stake(vote_pubkey);
                let total_stake = epoch_stakes.total_stake();

                // Fast track processing of the last slot in a vote transactions
                // so that notifications for optimistic confirmation can be sent
                // as soon as possible.
                let (reached_threshold_results, is_new) = Self::track_optimistic_confirmation_vote(
                    vote_tracker,
                    last_vote_slot,
                    last_vote_hash,
                    *vote_pubkey,
                    stake,
                    total_stake,
                );

                if is_gossip_vote && is_new && stake > 0 {
                    let _ = gossip_verified_vote_hash_sender.send((
                        *vote_pubkey,
                        last_vote_slot,
                        last_vote_hash,
                    ));
                }

                if reached_threshold_results[0] {
                    if let Some(sender) = cluster_confirmed_slot_sender {
                        let _ = sender.send(vec![(last_vote_slot, last_vote_hash)]);
                    }
                }
                if reached_threshold_results[1] {
                    new_optimistic_confirmed_slots.push((last_vote_slot, last_vote_hash));
                    // Notify subscribers about new optimistic confirmation
                    if let Some(sender) = bank_notification_sender {
                        sender
                            .send(BankNotification::OptimisticallyConfirmed(last_vote_slot))
                            .unwrap_or_else(|err| {
                                warn!("bank_notification_sender failed: {:?}", err)
                            });
                    }
                }

                if !is_new && !is_gossip_vote {
                    // By now:
                    // 1) The vote must have come from ReplayStage,
                    // 2) We've seen this vote from replay for this hash before
                    // (`track_optimistic_confirmation_vote()` will not set `is_new == true`
                    // for same slot different hash), so short circuit because this vote
                    // has no new information

                    // Note gossip votes will always be processed because those should be unique
                    // and we need to update the gossip-only stake in the `VoteTracker`.
                    return;
                }

                is_new_vote = is_new;
            }

            diff.entry(slot)
                .or_default()
                .entry(*vote_pubkey)
                .and_modify(|seen_in_gossip_previously| {
                    *seen_in_gossip_previously = *seen_in_gossip_previously || is_gossip_vote
                })
                .or_insert(is_gossip_vote);
        }

        if is_new_vote {
            subscriptions.notify_vote(*vote_pubkey, vote, vote_transaction_signature);
            let _ = verified_vote_sender.send((*vote_pubkey, vote_slots));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn filter_and_confirm_with_new_votes(
        vote_tracker: &VoteTracker,
        gossip_vote_txs: Vec<Transaction>,
        replayed_votes: Vec<ParsedVote>,
        root_bank: &Bank,
        subscriptions: &RpcSubscriptions,
        gossip_verified_vote_hash_sender: &GossipVerifiedVoteHashSender,
        verified_vote_sender: &VerifiedVoteSender,
        bank_notification_sender: &Option<BankNotificationSender>,
        cluster_confirmed_slot_sender: &Option<GossipDuplicateConfirmedSlotsSender>,
        vote_processing_time: &mut Option<VoteProcessingTiming>,
    ) -> ThresholdConfirmedSlots {
        let mut diff: HashMap<Slot, HashMap<Pubkey, bool>> = HashMap::new();
        let mut new_optimistic_confirmed_slots = vec![];

        // Process votes from gossip and ReplayStage
        let mut gossip_vote_txn_processing_time = Measure::start("gossip_vote_processing_time");
        let votes = gossip_vote_txs
            .iter()
            .filter_map(vote_parser::parse_vote_transaction)
            .zip(repeat(/*is_gossip:*/ true))
            .chain(replayed_votes.into_iter().zip(repeat(/*is_gossip:*/ false)));
        for ((vote_pubkey, vote, _switch_proof, signature), is_gossip) in votes {
            Self::track_new_votes_and_notify_confirmations(
                vote,
                &vote_pubkey,
                signature,
                vote_tracker,
                root_bank,
                subscriptions,
                verified_vote_sender,
                gossip_verified_vote_hash_sender,
                &mut diff,
                &mut new_optimistic_confirmed_slots,
                is_gossip,
                bank_notification_sender,
                cluster_confirmed_slot_sender,
            );
        }
        gossip_vote_txn_processing_time.stop();
        let gossip_vote_txn_processing_time_us = gossip_vote_txn_processing_time.as_us();

        // Process all the slots accumulated from replay and gossip.
        let mut gossip_vote_slot_confirming_time = Measure::start("gossip_vote_slot_confirm_time");
        for (slot, mut slot_diff) in diff {
            let slot_tracker = vote_tracker.get_or_insert_slot_tracker(slot);
            {
                let r_slot_tracker = slot_tracker.read().unwrap();
                // Only keep the pubkeys we haven't seen voting for this slot
                slot_diff.retain(|pubkey, seen_in_gossip_above| {
                    let seen_in_gossip_previously = r_slot_tracker.voted.get(pubkey);
                    let is_new = seen_in_gossip_previously.is_none();
                    // `is_new_from_gossip` means we observed a vote for this slot
                    // for the first time in gossip
                    let is_new_from_gossip = !seen_in_gossip_previously.cloned().unwrap_or(false)
                        && *seen_in_gossip_above;
                    is_new || is_new_from_gossip
                });
            }
            let mut w_slot_tracker = slot_tracker.write().unwrap();
            if w_slot_tracker.voted_slot_updates.is_none() {
                w_slot_tracker.voted_slot_updates = Some(vec![]);
            }
            let mut gossip_only_stake = 0;
            let epoch = root_bank.epoch_schedule().get_epoch(slot);
            let epoch_stakes = root_bank.epoch_stakes(epoch);

            for (pubkey, seen_in_gossip_above) in slot_diff {
                if seen_in_gossip_above {
                    // By this point we know if the vote was seen in gossip above,
                    // it was not seen in gossip at any point in the past (if it was seen
                    // in gossip in the past, `is_new` would be false and it would have
                    // been filtered out above), so it's safe to increment the gossip-only
                    // stake
                    Self::sum_stake(&mut gossip_only_stake, epoch_stakes, &pubkey);
                }

                // From the `slot_diff.retain` earlier, we know because there are
                // no other writers to `slot_vote_tracker` that
                // `is_new || is_new_from_gossip`. In both cases we want to record
                // `is_new_from_gossip` for the `pubkey` entry.
                w_slot_tracker.voted.insert(pubkey, seen_in_gossip_above);
                w_slot_tracker
                    .voted_slot_updates
                    .as_mut()
                    .unwrap()
                    .push(pubkey);
            }

            w_slot_tracker.gossip_only_stake += gossip_only_stake
        }
        gossip_vote_slot_confirming_time.stop();
        let gossip_vote_slot_confirming_time_us = gossip_vote_slot_confirming_time.as_us();

        match vote_processing_time {
            Some(ref mut vote_processing_time) => vote_processing_time.update(
                gossip_vote_txn_processing_time_us,
                gossip_vote_slot_confirming_time_us,
            ),
            None => {}
        }
        new_optimistic_confirmed_slots
    }

    // Returns if the slot was optimistically confirmed, and whether
    // the slot was new
    fn track_optimistic_confirmation_vote(
        vote_tracker: &VoteTracker,
        slot: Slot,
        hash: Hash,
        pubkey: Pubkey,
        stake: u64,
        total_epoch_stake: u64,
    ) -> (Vec<bool>, bool) {
        let slot_tracker = vote_tracker.get_or_insert_slot_tracker(slot);
        // Insert vote and check for optimistic confirmation
        let mut w_slot_tracker = slot_tracker.write().unwrap();

        w_slot_tracker
            .get_or_insert_optimistic_votes_tracker(hash)
            .add_vote_pubkey(pubkey, stake, total_epoch_stake, &THRESHOLDS_TO_CHECK)
    }

    fn sum_stake(sum: &mut u64, epoch_stakes: Option<&EpochStakes>, pubkey: &Pubkey) {
        if let Some(stakes) = epoch_stakes {
            *sum += stakes.stakes().vote_accounts().get_delegated_stake(pubkey)
        }
    }
}
