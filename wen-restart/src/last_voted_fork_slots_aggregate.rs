use {
    crate::solana::wen_restart_proto::LastVotedForkSlotsRecord,
    anyhow::Result,
    log::*,
    solana_gossip::restart_crds_values::RestartLastVotedForkSlots,
    solana_runtime::epoch_stakes::EpochStakes,
    solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey},
    std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    },
};

pub(crate) struct LastVotedForkSlotsAggregate {
    root_slot: Slot,
    repair_threshold: f64,
    // TODO(wen): using local root's EpochStakes, need to fix if crossing Epoch boundary.
    epoch_stakes: EpochStakes,
    last_voted_fork_slots: HashMap<Pubkey, RestartLastVotedForkSlots>,
    slots_stake_map: HashMap<Slot, u64>,
    active_peers: HashSet<Pubkey>,
    slots_to_repair: HashSet<Slot>,
    my_pubkey: Pubkey,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LastVotedForkSlotsFinalResult {
    pub slots_stake_map: HashMap<Slot, u64>,
    pub total_active_stake: u64,
}

impl LastVotedForkSlotsAggregate {
    pub(crate) fn new(
        root_slot: Slot,
        repair_threshold: f64,
        epoch_stakes: &EpochStakes,
        last_voted_fork_slots: &Vec<Slot>,
        my_pubkey: &Pubkey,
    ) -> Self {
        let mut active_peers = HashSet::new();
        let sender_stake = Self::validator_stake(epoch_stakes, my_pubkey);
        active_peers.insert(*my_pubkey);
        let mut slots_stake_map = HashMap::new();
        for slot in last_voted_fork_slots {
            if slot >= &root_slot {
                slots_stake_map.insert(*slot, sender_stake);
            }
        }
        Self {
            root_slot,
            repair_threshold,
            epoch_stakes: epoch_stakes.clone(),
            last_voted_fork_slots: HashMap::new(),
            slots_stake_map,
            active_peers,
            slots_to_repair: HashSet::new(),
            my_pubkey: *my_pubkey,
        }
    }

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
        record: &LastVotedForkSlotsRecord,
    ) -> Result<Option<LastVotedForkSlotsRecord>> {
        let from = Pubkey::from_str(key_string)?;
        if from == self.my_pubkey {
            return Ok(None);
        }
        let last_voted_hash = Hash::from_str(&record.last_vote_bankhash)?;
        let converted_record = RestartLastVotedForkSlots::new(
            from,
            record.wallclock,
            &record.last_voted_fork_slots,
            last_voted_hash,
            record.shred_version as u16,
        )?;
        Ok(self.aggregate(converted_record))
    }

    pub(crate) fn aggregate(
        &mut self,
        new_slots: RestartLastVotedForkSlots,
    ) -> Option<LastVotedForkSlotsRecord> {
        let total_stake = self.epoch_stakes.total_stake();
        let threshold_stake = (total_stake as f64 * self.repair_threshold) as u64;
        let from = &new_slots.from;
        if from == &self.my_pubkey {
            return None;
        }
        let sender_stake = Self::validator_stake(&self.epoch_stakes, from);
        if sender_stake == 0 {
            warn!(
                "Gossip should not accept zero-stake RestartLastVotedFork from {:?}",
                from
            );
            return None;
        }
        self.active_peers.insert(*from);
        let new_slots_vec = new_slots.to_slots(self.root_slot);
        let record = LastVotedForkSlotsRecord {
            last_voted_fork_slots: new_slots_vec.clone(),
            last_vote_bankhash: new_slots.last_voted_hash.to_string(),
            shred_version: new_slots.shred_version as u32,
            wallclock: new_slots.wallclock,
        };
        let new_slots_set: HashSet<Slot> = HashSet::from_iter(new_slots_vec);
        let old_slots_set = match self.last_voted_fork_slots.insert(*from, new_slots.clone()) {
            Some(old_slots) => {
                if old_slots == new_slots {
                    return None;
                } else {
                    HashSet::from_iter(old_slots.to_slots(self.root_slot))
                }
            }
            None => HashSet::new(),
        };
        for slot in old_slots_set.difference(&new_slots_set) {
            let entry = self.slots_stake_map.get_mut(slot).unwrap();
            *entry = entry.saturating_sub(sender_stake);
            if *entry < threshold_stake {
                self.slots_to_repair.remove(slot);
            }
        }
        for slot in new_slots_set.difference(&old_slots_set) {
            let entry = self.slots_stake_map.entry(*slot).or_insert(0);
            *entry = entry.saturating_add(sender_stake);
            if *entry >= threshold_stake {
                self.slots_to_repair.insert(*slot);
            }
        }
        Some(record)
    }

    pub(crate) fn active_percent(&self) -> f64 {
        let total_stake = self.epoch_stakes.total_stake();
        let total_active_stake = self.active_peers.iter().fold(0, |sum: u64, pubkey| {
            sum.saturating_add(Self::validator_stake(&self.epoch_stakes, pubkey))
        });
        total_active_stake as f64 / total_stake as f64 * 100.0
    }

    pub(crate) fn slots_to_repair_iter(&self) -> impl Iterator<Item = &Slot> {
        self.slots_to_repair.iter()
    }

    // TODO(wen): use better epoch stake and add a test later.
    fn total_active_stake(&self) -> u64 {
        self.active_peers.iter().fold(0, |sum: u64, pubkey| {
            sum.saturating_add(Self::validator_stake(&self.epoch_stakes, pubkey))
        })
    }

    pub(crate) fn get_final_result(self) -> LastVotedForkSlotsFinalResult {
        let total_active_stake = self.total_active_stake();
        LastVotedForkSlotsFinalResult {
            slots_stake_map: self.slots_stake_map,
            total_active_stake,
        }
    }
}
