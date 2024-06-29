use {
    crate::solana::wen_restart_proto::HeaviestForkRecord,
    anyhow::Result,
    log::*,
    solana_gossip::restart_crds_values::RestartHeaviestFork,
    solana_runtime::epoch_stakes::EpochStakes,
    solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey},
    std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    },
};

pub(crate) struct HeaviestForkAggregate {
    supermajority_threshold: f64,
    my_shred_version: u16,
    my_pubkey: Pubkey,
    // TODO(wen): using local root's EpochStakes, need to fix if crossing Epoch boundary.
    epoch_stakes: EpochStakes,
    heaviest_forks: HashMap<Pubkey, RestartHeaviestFork>,
    block_stake_map: HashMap<(Slot, Hash), u64>,
    active_peers: HashSet<Pubkey>,
    active_peers_seen_supermajority: HashSet<Pubkey>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HeaviestForkFinalResult {
    pub block_stake_map: HashMap<(Slot, Hash), u64>,
    pub total_active_stake: u64,
    pub total_active_stake_seen_supermajority: u64,
}

impl HeaviestForkAggregate {
    pub(crate) fn new(
        wait_for_supermajority_threshold_percent: u64,
        my_shred_version: u16,
        epoch_stakes: &EpochStakes,
        my_heaviest_fork_slot: Slot,
        my_heaviest_fork_hash: Hash,
        my_pubkey: &Pubkey,
    ) -> Self {
        let mut active_peers = HashSet::new();
        active_peers.insert(*my_pubkey);
        let mut block_stake_map = HashMap::new();
        block_stake_map.insert(
            (my_heaviest_fork_slot, my_heaviest_fork_hash),
            Self::validator_stake(epoch_stakes, my_pubkey),
        );
        Self {
            supermajority_threshold: wait_for_supermajority_threshold_percent as f64 / 100.0,
            my_shred_version,
            my_pubkey: *my_pubkey,
            epoch_stakes: epoch_stakes.clone(),
            heaviest_forks: HashMap::new(),
            block_stake_map,
            active_peers,
            active_peers_seen_supermajority: HashSet::new(),
        }
    }

    // TODO(wen): this will a function in separate EpochStakesMap class later.
    fn validator_stake(epoch_stakes: &EpochStakes, pubkey: &Pubkey) -> u64 {
        epoch_stakes
            .node_id_to_vote_accounts()
            .get(pubkey)
            .map(|x| x.total_stake)
            .unwrap_or_default()
    }

    pub(crate) fn aggregate_from_record(
        &mut self,
        key_string: &str,
        record: &HeaviestForkRecord,
    ) -> Result<Option<HeaviestForkRecord>> {
        let from = Pubkey::from_str(key_string)?;
        let bankhash = Hash::from_str(&record.bankhash)?;
        let restart_heaviest_fork = RestartHeaviestFork {
            from,
            wallclock: record.wallclock,
            last_slot: record.slot,
            last_slot_hash: bankhash,
            observed_stake: record.total_active_stake,
            shred_version: record.shred_version as u16,
        };
        Ok(self.aggregate(restart_heaviest_fork))
    }

    fn should_replace(
        current_heaviest_fork: &RestartHeaviestFork,
        new_heaviest_fork: &RestartHeaviestFork,
    ) -> bool {
        if current_heaviest_fork == new_heaviest_fork {
            return false;
        }
        if current_heaviest_fork.wallclock > new_heaviest_fork.wallclock {
            return false;
        }
        if current_heaviest_fork.last_slot == new_heaviest_fork.last_slot
            && current_heaviest_fork.last_slot_hash == new_heaviest_fork.last_slot_hash
            && current_heaviest_fork.observed_stake == new_heaviest_fork.observed_stake
        {
            return false;
        }
        true
    }

    pub(crate) fn aggregate(
        &mut self,
        received_heaviest_fork: RestartHeaviestFork,
    ) -> Option<HeaviestForkRecord> {
        let total_stake = self.epoch_stakes.total_stake();
        let from = &received_heaviest_fork.from;
        let sender_stake = Self::validator_stake(&self.epoch_stakes, from);
        if sender_stake == 0 {
            warn!(
                "Gossip should not accept zero-stake RestartLastVotedFork from {:?}",
                from
            );
            return None;
        }
        if from == &self.my_pubkey {
            return None;
        }
        if received_heaviest_fork.shred_version != self.my_shred_version {
            warn!(
                "Gossip should not accept RestartLastVotedFork with different shred version {} from {:?}",
                received_heaviest_fork.shred_version, from
            );
            return None;
        }
        let record = HeaviestForkRecord {
            slot: received_heaviest_fork.last_slot,
            bankhash: received_heaviest_fork.last_slot_hash.to_string(),
            total_active_stake: received_heaviest_fork.observed_stake,
            shred_version: received_heaviest_fork.shred_version as u32,
            wallclock: received_heaviest_fork.wallclock,
        };
        if let Some(old_heaviest_fork) = self
            .heaviest_forks
            .insert(*from, received_heaviest_fork.clone())
        {
            if Self::should_replace(&old_heaviest_fork, &received_heaviest_fork) {
                let entry = self
                    .block_stake_map
                    .get_mut(&(
                        old_heaviest_fork.last_slot,
                        old_heaviest_fork.last_slot_hash,
                    ))
                    .unwrap();
                info!(
                    "{:?} Replacing old heaviest fork from {:?} with {:?}",
                    from, old_heaviest_fork, received_heaviest_fork
                );
                *entry = entry.saturating_sub(sender_stake);
            } else {
                return None;
            }
        }
        let entry = self
            .block_stake_map
            .entry((
                received_heaviest_fork.last_slot,
                received_heaviest_fork.last_slot_hash,
            ))
            .or_insert(0);
        *entry = entry.saturating_add(sender_stake);
        self.active_peers.insert(*from);
        if received_heaviest_fork.observed_stake as f64 / total_stake as f64
            >= self.supermajority_threshold
        {
            self.active_peers_seen_supermajority.insert(*from);
        }
        if !self
            .active_peers_seen_supermajority
            .contains(&self.my_pubkey)
            && self.total_active_stake() as f64 / total_stake as f64 >= self.supermajority_threshold
        {
            self.active_peers_seen_supermajority.insert(self.my_pubkey);
        }
        Some(record)
    }

    // TODO(wen): use better epoch stake and add a test later.
    pub(crate) fn total_active_stake(&self) -> u64 {
        self.active_peers.iter().fold(0, |sum: u64, pubkey| {
            sum.saturating_add(Self::validator_stake(&self.epoch_stakes, pubkey))
        })
    }

    pub(crate) fn total_active_stake_seen_supermajority(&self) -> u64 {
        self.active_peers_seen_supermajority
            .iter()
            .fold(0, |sum: u64, pubkey| {
                sum.saturating_add(Self::validator_stake(&self.epoch_stakes, pubkey))
            })
    }

    pub(crate) fn block_stake_map(self) -> HashMap<(Slot, Hash), u64> {
        self.block_stake_map
    }
}
