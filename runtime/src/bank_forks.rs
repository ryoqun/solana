//! The `bank_forks` module implements BankForks a DAG of checkpointed Banks

use crate::{
    accounts_background_service::{AbsRequestSender, SnapshotRequest},
    bank::Bank,
};
use log::*;
use solana_metrics::inc_new_counter_info;
use solana_sdk::{clock::Slot, timing};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    ops::Index,
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

pub use crate::snapshot_utils::SnapshotVersion;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArchiveFormat {
    TarBzip2,
    TarGzip,
    TarZstd,
    Tar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotConfig {
    // Generate a new snapshot every this many slots
    pub snapshot_interval_slots: u64,

    // Where to store the latest packaged snapshot
    pub snapshot_package_output_path: PathBuf,

    // Where to place the snapshots for recent slots
    pub snapshot_path: PathBuf,

    pub archive_format: ArchiveFormat,

    // Snapshot version to generate
    pub snapshot_version: SnapshotVersion,
}

pub struct BankForks {
    banks: HashMap<Slot, Arc<Bank>>,
    descendants: HashMap<Slot, HashSet<Slot>>,
    root: Slot,
    pub snapshot_config: Option<SnapshotConfig>,

    pub accounts_hash_interval_slots: Slot,
    last_accounts_hash_slot: Slot,
}

impl Index<u64> for BankForks {
    type Output = Arc<Bank>;
    fn index(&self, bank_slot: Slot) -> &Self::Output {
        &self.banks[&bank_slot]
    }
}

impl BankForks {
    pub fn new(bank: Bank) -> Self {
        let root = bank.slot();
        Self::new_from_banks(&[Arc::new(bank)], root)
    }

    pub fn banks(&self) -> &HashMap<Slot, Arc<Bank>> {
        &self.banks
    }

    /// Create a map of bank slot id to the set of ancestors for the bank slot.
    pub fn ancestors(&self) -> HashMap<Slot, HashSet<Slot>> {
        let root = self.root;
        self.banks
            .iter()
            .map(|(slot, bank)| {
                let ancestors = bank.proper_ancestors().filter(|k| *k >= root);
                (*slot, ancestors.collect())
            })
            .collect()
    }

    /// Create a map of bank slot id to the set of all of its descendants
    pub fn descendants(&self) -> &HashMap<Slot, HashSet<Slot>> {
        &self.descendants
    }

    pub fn frozen_banks(&self) -> HashMap<Slot, Arc<Bank>> {
        self.banks
            .iter()
            .filter(|(_, b)| b.is_frozen())
            .map(|(k, b)| (*k, b.clone()))
            .collect()
    }

    pub fn active_banks(&self) -> Vec<Slot> {
        self.banks
            .iter()
            .filter(|(_, v)| !v.is_frozen())
            .map(|(k, _v)| *k)
            .collect()
    }

    pub fn get(&self, bank_slot: Slot) -> Option<&Arc<Bank>> {
        self.banks.get(&bank_slot)
    }

    pub fn root_bank(&self) -> Arc<Bank> {
        self[self.root()].clone()
    }

    pub fn new_from_banks(initial_forks: &[Arc<Bank>], root: Slot) -> Self {
        let mut banks = HashMap::new();

        // Iterate through the heads of all the different forks
        for bank in initial_forks {
            banks.insert(bank.slot(), bank.clone());
            let parents = bank.parents();
            for parent in parents {
                if banks.contains_key(&parent.slot()) {
                    // All ancestors have already been inserted by another fork
                    break;
                }
                banks.insert(parent.slot(), parent.clone());
            }
        }
        let mut descendants = HashMap::<_, HashSet<_>>::new();
        for (slot, bank) in &banks {
            descendants.entry(*slot).or_default();
            for parent in bank.proper_ancestors() {
                descendants.entry(parent).or_default().insert(*slot);
            }
        }
        Self {
            root,
            banks,
            descendants,
            snapshot_config: None,
            accounts_hash_interval_slots: std::u64::MAX,
            last_accounts_hash_slot: root,
        }
    }

    pub fn insert(&mut self, bank: Bank) -> Arc<Bank> {
        let bank = Arc::new(bank);
        let prev = self.banks.insert(bank.slot(), bank.clone());
        assert!(prev.is_none());
        let slot = bank.slot();
        self.descendants.entry(slot).or_default();
        for parent in bank.proper_ancestors() {
            self.descendants.entry(parent).or_default().insert(slot);
        }
        bank
    }

    pub fn remove(&mut self, slot: Slot) -> Option<Arc<Bank>> {
        let bank = self.banks.remove(&slot)?;
        for parent in bank.proper_ancestors() {
            let mut entry = match self.descendants.entry(parent) {
                Entry::Vacant(_) => panic!("this should not happen!"),
                Entry::Occupied(entry) => entry,
            };
            entry.get_mut().remove(&slot);
            if entry.get().is_empty() && !self.banks.contains_key(&parent) {
                entry.remove_entry();
            }
        }
        let entry = match self.descendants.entry(slot) {
            Entry::Vacant(_) => panic!("this should not happen!"),
            Entry::Occupied(entry) => entry,
        };
        if entry.get().is_empty() {
            entry.remove_entry();
        }
        Some(bank)
    }

    pub fn highest_slot(&self) -> Slot {
        self.banks.values().map(|bank| bank.slot()).max().unwrap()
    }

    pub fn working_bank(&self) -> Arc<Bank> {
        self[self.highest_slot()].clone()
    }

    pub fn set_root(
        &mut self,
        root: Slot,
        accounts_background_request_sender: &AbsRequestSender,
        highest_confirmed_root: Option<Slot>,
    ) {
        let old_epoch = self.root_bank().epoch();
        self.root = root;
        let set_root_start = Instant::now();
        let root_bank = self
            .banks
            .get(&root)
            .expect("root bank didn't exist in bank_forks");
        let new_epoch = root_bank.epoch();
        if old_epoch != new_epoch {
            info!(
                "Root entering
                epoch: {},
                next_epoch_start_slot: {},
                epoch_stakes: {:#?}",
                new_epoch,
                root_bank
                    .epoch_schedule()
                    .get_first_slot_in_epoch(new_epoch + 1),
                root_bank
                    .epoch_stakes(new_epoch)
                    .unwrap()
                    .node_id_to_vote_accounts()
            );
        }
        let root_tx_count = root_bank
            .parents()
            .last()
            .map(|bank| bank.transaction_count())
            .unwrap_or(0);
        // Calculate the accounts hash at a fixed interval
        let mut is_root_bank_squashed = false;
        let mut banks = vec![root_bank];
        let parents = root_bank.parents();
        banks.extend(parents.iter());
        for bank in banks.iter() {
            let bank_slot = bank.slot();
            if bank.block_height() % self.accounts_hash_interval_slots == 0
                && bank_slot > self.last_accounts_hash_slot
            {
                self.last_accounts_hash_slot = bank_slot;
                bank.squash();
                is_root_bank_squashed = bank_slot == root;

                if self.snapshot_config.is_some()
                    && accounts_background_request_sender.is_snapshot_creation_enabled()
                {
                    let snapshot_root_bank = self.root_bank();
                    let root_slot = snapshot_root_bank.slot();
                    if let Err(e) =
                        accounts_background_request_sender.send_snapshot_request(SnapshotRequest {
                            snapshot_root_bank,
                            // Save off the status cache because these may get pruned
                            // if another `set_root()` is called before the snapshots package
                            // can be generated
                            status_cache_slot_deltas: bank.src.slot_deltas(&bank.src.roots()),
                        })
                    {
                        warn!(
                            "Error sending snapshot request for bank: {}, err: {:?}",
                            root_slot, e
                        );
                    }
                }
                break;
            }
        }
        if !is_root_bank_squashed {
            root_bank.squash();
        }
        let new_tx_count = root_bank.transaction_count();
        self.prune_non_root(root, highest_confirmed_root);

        inc_new_counter_info!(
            "bank-forks_set_root_ms",
            timing::duration_as_ms(&set_root_start.elapsed()) as usize
        );
        inc_new_counter_info!(
            "bank-forks_set_root_tx_count",
            (new_tx_count - root_tx_count) as usize
        );
    }

    pub fn root(&self) -> Slot {
        self.root
    }

    fn prune_non_root(&mut self, root: Slot, highest_confirmed_root: Option<Slot>) {
        let highest_confirmed_root = highest_confirmed_root.unwrap_or(root);
        let prune_slots: Vec<_> = self
            .banks
            .keys()
            .copied()
            .filter(|slot| {
                let keep = *slot == root
                    || self.descendants[&root].contains(slot)
                    || (*slot < root
                        && *slot >= highest_confirmed_root
                        && self.descendants[slot].contains(&root));
                !keep
            })
            .collect();
        for slot in prune_slots {
            self.remove(slot);
        }
        datapoint_debug!(
            "bank_forks_purge_non_root",
            ("num_banks_retained", self.banks.len(), i64),
        );
    }

    pub fn set_snapshot_config(&mut self, snapshot_config: Option<SnapshotConfig>) {
        self.snapshot_config = snapshot_config;
    }

    pub fn snapshot_config(&self) -> &Option<SnapshotConfig> {
        &self.snapshot_config
    }

    pub fn set_accounts_hash_interval_slots(&mut self, accounts_interval_slots: u64) {
        self.accounts_hash_interval_slots = accounts_interval_slots;
    }
}
