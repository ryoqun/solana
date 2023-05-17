use {
    itertools::Itertools,
    solana_gossip::{
        cluster_info::ClusterInfo, crds::Cursor, epoch_slots::EpochSlots,
        legacy_contact_info::LegacyContactInfo as ContactInfo,
    },
    solana_runtime::{bank::Bank, epoch_stakes::NodeIdToVoteAccounts},
    solana_sdk::{
        clock::{Slot, DEFAULT_SLOTS_PER_EPOCH},
        pubkey::Pubkey,
        timing::AtomicInterval,
    },
    std::{
        collections::{BTreeMap, HashMap},
        sync::{Arc, Mutex, RwLock},
    },
};

// Limit the size of cluster-slots map in case
// of receiving bogus epoch slots values.
const CLUSTER_SLOTS_TRIM_SIZE: usize = 524_288; // 512K

pub(crate) type SlotPubkeys = HashMap</*node:*/ Pubkey, /*stake:*/ u64>;

#[derive(Default)]
pub struct ClusterSlots {
    cluster_slots: RwLock<BTreeMap<Slot, Arc<RwLock<SlotPubkeys>>>>,
    validator_stakes: RwLock<Arc<NodeIdToVoteAccounts>>,
    epoch: RwLock<Option<u64>>,
    cursor: Mutex<Cursor>,
    last_report: AtomicInterval,
}

impl ClusterSlots {
    pub(crate) fn lookup(&self, slot: Slot) -> Option<Arc<RwLock<SlotPubkeys>>> {
        self.cluster_slots.read().unwrap().get(&slot).cloned()
    }

    pub(crate) fn update(&self, root_bank: &Bank, cluster_info: &ClusterInfo) {
        self.update_peers(root_bank);
        let epoch_slots = {
            let mut cursor = self.cursor.lock().unwrap();
            cluster_info.get_epoch_slots(&mut cursor)
        };
        let num_epoch_slots = root_bank.get_slots_in_epoch(root_bank.epoch());
        self.update_internal(root_bank.slot(), epoch_slots, num_epoch_slots);
    }

    fn update_internal(&self, root: Slot, epoch_slots_list: Vec<EpochSlots>, num_epoch_slots: u64) {
        // Attach validator's total stake.
        let epoch_slots_list: Vec<_> = {
            let validator_stakes = self.validator_stakes.read().unwrap();
            epoch_slots_list
                .into_iter()
                .map(|epoch_slots| {
                    let stake = match validator_stakes.get(&epoch_slots.from) {
                        Some(v) => v.total_stake,
                        None => 0,
                    };
                    (epoch_slots, stake)
                })
                .collect()
        };
        // Discard slots at or before current root or epochs ahead.
        let slot_range = (root + 1)
            ..root.saturating_add(
                num_epoch_slots
                    .max(DEFAULT_SLOTS_PER_EPOCH)
                    .saturating_mul(2),
            );
        let slot_nodes_stakes = epoch_slots_list
            .into_iter()
            .flat_map(|(epoch_slots, stake)| {
                epoch_slots
                    .to_slots(root)
                    .into_iter()
                    .filter(|slot| slot_range.contains(slot))
                    .zip(std::iter::repeat((epoch_slots.from, stake)))
            })
            .into_group_map();
        let slot_nodes_stakes: Vec<_> = {
            let mut cluster_slots = self.cluster_slots.write().unwrap();
            slot_nodes_stakes
                .into_iter()
                .map(|(slot, nodes_stakes)| {
                    let slot_nodes = cluster_slots.entry(slot).or_default().clone();
                    (slot_nodes, nodes_stakes)
                })
                .collect()
        };
        for (slot_nodes, nodes_stakes) in slot_nodes_stakes {
            slot_nodes.write().unwrap().extend(nodes_stakes);
        }
        {
            let mut cluster_slots = self.cluster_slots.write().unwrap();
            *cluster_slots = cluster_slots.split_off(&(root + 1));
            // Allow 10% overshoot so that the computation cost is amortized
            // down. The slots furthest away from the root are discarded.
            if 10 * cluster_slots.len() > 11 * CLUSTER_SLOTS_TRIM_SIZE {
                warn!("trimming cluster slots");
                let key = *cluster_slots.keys().nth(CLUSTER_SLOTS_TRIM_SIZE).unwrap();
                cluster_slots.split_off(&key);
            }
        }
        self.report_cluster_slots_size();
    }

    fn report_cluster_slots_size(&self) {
        if self.last_report.should_update(10_000) {
            let (cluster_slots_cap, pubkeys_capacity) = {
                let cluster_slots = self.cluster_slots.read().unwrap();
                let cluster_slots_cap = cluster_slots.len();
                let pubkeys_capacity = cluster_slots
                    .iter()
                    .map(|(_slot, slot_pubkeys)| slot_pubkeys.read().unwrap().capacity())
                    .sum::<usize>();
                (cluster_slots_cap, pubkeys_capacity)
            };
            let (validator_stakes_cap, validator_pubkeys_len) = {
                let validator_stakes = self.validator_stakes.read().unwrap();
                let validator_len = validator_stakes
                    .iter()
                    .map(|(_pubkey, vote_accounts)| vote_accounts.vote_accounts.capacity())
                    .sum::<usize>();
                (validator_stakes.capacity(), validator_len)
            };
            datapoint_info!(
                "cluster-slots-size",
                ("cluster_slots_capacity", cluster_slots_cap, i64),
                ("pubkeys_capacity", pubkeys_capacity, i64),
                ("validator_stakes_capacity", validator_stakes_cap, i64),
                ("validator_pubkeys_len", validator_pubkeys_len, i64),
            );
        }
    }

    fn update_peers(&self, root_bank: &Bank) {
        let root_epoch = root_bank.epoch();
        let my_epoch = *self.epoch.read().unwrap();

        if Some(root_epoch) != my_epoch {
            let validator_stakes = root_bank
                .epoch_stakes(root_epoch)
                .expect("Bank must have epoch stakes for its own epoch")
                .node_id_to_vote_accounts()
                .clone();

            *self.validator_stakes.write().unwrap() = validator_stakes;
            *self.epoch.write().unwrap() = Some(root_epoch);
        }
    }

    pub(crate) fn compute_weights(&self, slot: Slot, repair_peers: &[ContactInfo]) -> Vec<u64> {
        if repair_peers.is_empty() {
            return Vec::default();
        }
        let stakes = {
            let validator_stakes = self.validator_stakes.read().unwrap();
            repair_peers
                .iter()
                .map(|peer| {
                    validator_stakes
                        .get(peer.pubkey())
                        .map(|node| node.total_stake)
                        .unwrap_or(0)
                        + 1
                })
                .collect()
        };
        let slot_peers = match self.lookup(slot) {
            None => return stakes,
            Some(slot_peers) => slot_peers,
        };
        let slot_peers = slot_peers.read().unwrap();
        repair_peers
            .iter()
            .map(|peer| slot_peers.get(peer.pubkey()).cloned().unwrap_or(0))
            .zip(stakes)
            .map(|(a, b)| (a / 2 + b / 2).max(1u64))
            .collect()
    }

    pub(crate) fn compute_weights_exclude_nonfrozen(
        &self,
        slot: Slot,
        repair_peers: &[ContactInfo],
    ) -> Vec<(u64, usize)> {
        self.lookup(slot)
            .map(|slot_peers| {
                let slot_peers = slot_peers.read().unwrap();
                repair_peers
                    .iter()
                    .enumerate()
                    .filter_map(|(i, ci)| Some((slot_peers.get(ci.pubkey())? + 1, i)))
                    .collect()
            })
            .unwrap_or_default()
    }
}
