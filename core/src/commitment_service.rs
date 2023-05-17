use {
    crate::consensus::Stake,
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender},
    solana_measure::measure::Measure,
    solana_metrics::datapoint_info,
    solana_rpc::rpc_subscriptions::RpcSubscriptions,
    solana_runtime::{
        bank::Bank,
        commitment::{BlockCommitment, BlockCommitmentCache, CommitmentSlots, VOTE_THRESHOLD_SIZE},
    },
    solana_sdk::clock::Slot,
    solana_vote_program::vote_state::VoteState,
    std::{
        cmp::max,
        collections::HashMap,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct CommitmentAggregationData {
    bank: Arc<Bank>,
    root: Slot,
    total_stake: Stake,
}

impl CommitmentAggregationData {
    pub fn new(bank: Arc<Bank>, root: Slot, total_stake: Stake) -> Self {
        Self {
            bank,
            root,
            total_stake,
        }
    }
}

fn get_highest_confirmed_root(mut rooted_stake: Vec<(Slot, u64)>, total_stake: u64) -> Slot {
    rooted_stake.sort_by(|a, b| a.0.cmp(&b.0).reverse());
    let mut stake_sum = 0;
    for (root, stake) in rooted_stake {
        stake_sum += stake;
        if (stake_sum as f64 / total_stake as f64) > VOTE_THRESHOLD_SIZE {
            return root;
        }
    }
    0
}

pub struct AggregateCommitmentService {
    t_commitment: JoinHandle<()>,
}

impl AggregateCommitmentService {
    pub fn new(
        exit: &Arc<AtomicBool>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        subscriptions: Arc<RpcSubscriptions>,
    ) -> (Sender<CommitmentAggregationData>, Self) {
        let (sender, receiver): (
            Sender<CommitmentAggregationData>,
            Receiver<CommitmentAggregationData>,
        ) = unbounded();
        let exit_ = exit.clone();
        (
            sender,
            Self {
                t_commitment: Builder::new()
                    .name("solAggCommitSvc".to_string())
                    .spawn(move || loop {
                        if exit_.load(Ordering::Relaxed) {
                            break;
                        }

                        if let Err(RecvTimeoutError::Disconnected) =
                            Self::run(&receiver, &block_commitment_cache, &subscriptions, &exit_)
                        {
                            break;
                        }
                    })
                    .unwrap(),
            },
        )
    }

    fn run(
        receiver: &Receiver<CommitmentAggregationData>,
        block_commitment_cache: &RwLock<BlockCommitmentCache>,
        subscriptions: &Arc<RpcSubscriptions>,
        exit: &Arc<AtomicBool>,
    ) -> Result<(), RecvTimeoutError> {
        loop {
            if exit.load(Ordering::Relaxed) {
                return Ok(());
            }

            let aggregation_data = receiver.recv_timeout(Duration::from_secs(1))?;
            let aggregation_data = receiver.try_iter().last().unwrap_or(aggregation_data);

            let ancestors = aggregation_data.bank.status_cache_ancestors();
            if ancestors.is_empty() {
                continue;
            }

            let mut aggregate_commitment_time = Measure::start("aggregate-commitment-ms");
            let update_commitment_slots =
                Self::update_commitment_cache(block_commitment_cache, aggregation_data, ancestors);
            aggregate_commitment_time.stop();
            datapoint_info!(
                "block-commitment-cache",
                (
                    "aggregate-commitment-ms",
                    aggregate_commitment_time.as_ms() as i64,
                    i64
                ),
                (
                    "highest-confirmed-root",
                    update_commitment_slots.highest_confirmed_root as i64,
                    i64
                ),
                (
                    "highest-confirmed-slot",
                    update_commitment_slots.highest_confirmed_slot as i64,
                    i64
                ),
            );

            // Triggers rpc_subscription notifications as soon as new commitment data is available,
            // sending just the commitment cache slot information that the notifications thread
            // needs
            subscriptions.notify_subscribers(update_commitment_slots);
        }
    }

    fn update_commitment_cache(
        block_commitment_cache: &RwLock<BlockCommitmentCache>,
        aggregation_data: CommitmentAggregationData,
        ancestors: Vec<u64>,
    ) -> CommitmentSlots {
        let (block_commitment, rooted_stake) =
            Self::aggregate_commitment(&ancestors, &aggregation_data.bank);

        let highest_confirmed_root =
            get_highest_confirmed_root(rooted_stake, aggregation_data.total_stake);

        let mut new_block_commitment = BlockCommitmentCache::new(
            block_commitment,
            aggregation_data.total_stake,
            CommitmentSlots {
                slot: aggregation_data.bank.slot(),
                root: aggregation_data.root,
                highest_confirmed_slot: aggregation_data.root,
                highest_confirmed_root,
            },
        );
        let highest_confirmed_slot = new_block_commitment.calculate_highest_confirmed_slot();
        new_block_commitment.set_highest_confirmed_slot(highest_confirmed_slot);

        let mut w_block_commitment_cache = block_commitment_cache.write().unwrap();

        let highest_confirmed_root = max(
            new_block_commitment.highest_confirmed_root(),
            w_block_commitment_cache.highest_confirmed_root(),
        );
        new_block_commitment.set_highest_confirmed_root(highest_confirmed_root);

        *w_block_commitment_cache = new_block_commitment;
        w_block_commitment_cache.commitment_slots()
    }

    pub fn aggregate_commitment(
        ancestors: &[Slot],
        bank: &Bank,
    ) -> (HashMap<Slot, BlockCommitment>, Vec<(Slot, u64)>) {
        assert!(!ancestors.is_empty());

        // Check ancestors is sorted
        for a in ancestors.windows(2) {
            assert!(a[0] < a[1]);
        }

        let mut commitment = HashMap::new();
        let mut rooted_stake: Vec<(Slot, u64)> = Vec::new();
        for (lamports, account) in bank.vote_accounts().values() {
            if *lamports == 0 {
                continue;
            }
            if let Ok(vote_state) = account.vote_state().as_ref() {
                Self::aggregate_commitment_for_vote_account(
                    &mut commitment,
                    &mut rooted_stake,
                    vote_state,
                    ancestors,
                    *lamports,
                );
            }
        }

        (commitment, rooted_stake)
    }

    fn aggregate_commitment_for_vote_account(
        commitment: &mut HashMap<Slot, BlockCommitment>,
        rooted_stake: &mut Vec<(Slot, u64)>,
        vote_state: &VoteState,
        ancestors: &[Slot],
        lamports: u64,
    ) {
        assert!(!ancestors.is_empty());
        let mut ancestors_index = 0;
        if let Some(root) = vote_state.root_slot {
            for (i, a) in ancestors.iter().enumerate() {
                if *a <= root {
                    commitment
                        .entry(*a)
                        .or_insert_with(BlockCommitment::default)
                        .increase_rooted_stake(lamports);
                } else {
                    ancestors_index = i;
                    break;
                }
            }
            rooted_stake.push((root, lamports));
        }

        for vote in &vote_state.votes {
            while ancestors[ancestors_index] <= vote.slot() {
                commitment
                    .entry(ancestors[ancestors_index])
                    .or_insert_with(BlockCommitment::default)
                    .increase_confirmation_stake(vote.confirmation_count() as usize, lamports);
                ancestors_index += 1;

                if ancestors_index == ancestors.len() {
                    return;
                }
            }
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_commitment.join()
    }
}
