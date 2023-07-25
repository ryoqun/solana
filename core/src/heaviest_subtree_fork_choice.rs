use {
    crate::{
        consensus::Tower, fork_choice::ForkChoice,
        latest_validator_votes_for_frozen_banks::LatestValidatorVotesForFrozenBanks,
        progress_map::ProgressMap, tree_diff::TreeDiff,
    },
    solana_measure::measure::Measure,
    solana_runtime::{bank::Bank, bank_forks::BankForks, epoch_stakes::EpochStakes},
    solana_sdk::{
        clock::{Epoch, Slot},
        epoch_schedule::EpochSchedule,
        hash::Hash,
        pubkey::Pubkey,
    },
    std::{
        borrow::Borrow,
        collections::{
            btree_set::Iter, hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet, VecDeque,
        },
        sync::{Arc, RwLock},
        time::Instant,
    },
};

pub type ForkWeight = u64;
pub type SlotHashKey = (Slot, Hash);
type UpdateOperations = BTreeMap<(SlotHashKey, UpdateLabel), UpdateOperation>;

const MAX_ROOT_PRINT_SECONDS: u64 = 30;

#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord)]
enum UpdateLabel {
    Aggregate,
    Add,

    // Notify a fork in the tree that a particular slot in that fork is now
    // marked as valid. If there are multiple MarkValid operations for
    // a single node, should apply the one with the smaller slot first (hence
    // why the actual slot is included here).
    MarkValid(Slot),
    // Notify a fork in the tree that a particular slot in that fork is now
    // marked as invalid. If there are multiple MarkInvalid operations for
    // a single node, should apply the one with the smaller slot first (hence
    // why the actual slot is included here).
    MarkInvalid(Slot),
    Subtract,
}

pub trait GetSlotHash {
    fn slot_hash(&self) -> SlotHashKey;
}

impl GetSlotHash for SlotHashKey {
    fn slot_hash(&self) -> SlotHashKey {
        *self
    }
}

impl GetSlotHash for Slot {
    fn slot_hash(&self) -> SlotHashKey {
        (*self, Hash::default())
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
enum UpdateOperation {
    Add(u64),
    MarkValid(Slot),
    // Notify a fork in the tree that a particular slot in that fork is now
    // marked as invalid.
    MarkInvalid(Slot),
    Subtract(u64),
    Aggregate,
}

impl UpdateOperation {
    fn update_stake(&mut self, new_stake: u64) {
        match self {
            Self::Aggregate => panic!("Should not get here"),
            Self::Add(stake) => *stake += new_stake,
            Self::MarkValid(_slot) => panic!("Should not get here"),
            Self::MarkInvalid(_slot) => panic!("Should not get here"),
            Self::Subtract(stake) => *stake += new_stake,
        }
    }
}

#[derive(Clone, Debug)]
struct ForkInfo {
    // Amount of stake that has voted for exactly this slot
    stake_voted_at: ForkWeight,
    // Amount of stake that has voted for this slot and the subtree
    // rooted at this slot
    stake_voted_subtree: ForkWeight,
    // Best slot in the subtree rooted at this slot, does not
    // have to be a direct child in `children`. This is the slot whose subtree
    // is the heaviest.
    best_slot: SlotHashKey,
    parent: Option<SlotHashKey>,
    children: BTreeSet<SlotHashKey>,
    // The latest ancestor of this node that has been marked invalid. If the slot
    // itself is a duplicate, this is set to the slot itself.
    latest_invalid_ancestor: Option<Slot>,
    // Set to true if this slot or a child node was duplicate confirmed.
    is_duplicate_confirmed: bool,
}

impl ForkInfo {
    /// Returns if this node has been explicitly marked as a duplicate
    /// slot
    fn is_unconfirmed_duplicate(&self, my_slot: Slot) -> bool {
        self.latest_invalid_ancestor
            .map(|ancestor| ancestor == my_slot)
            .unwrap_or(false)
    }

    /// Returns if the fork rooted at this node is included in fork choice
    fn is_candidate(&self) -> bool {
        self.latest_invalid_ancestor.is_none()
    }

    fn is_duplicate_confirmed(&self) -> bool {
        self.is_duplicate_confirmed
    }

    fn set_duplicate_confirmed(&mut self) {
        self.is_duplicate_confirmed = true;
        self.latest_invalid_ancestor = None;
    }

    fn update_with_newly_valid_ancestor(
        &mut self,
        my_key: &SlotHashKey,
        newly_valid_ancestor: Slot,
    ) {
        if let Some(latest_invalid_ancestor) = self.latest_invalid_ancestor {
            if latest_invalid_ancestor <= newly_valid_ancestor {
                info!("Fork choice for {:?} clearing latest invalid ancestor {:?} because {:?} was duplicate confirmed", my_key, latest_invalid_ancestor, newly_valid_ancestor);
                self.latest_invalid_ancestor = None;
            }
        }
    }

    fn update_with_newly_invalid_ancestor(
        &mut self,
        my_key: &SlotHashKey,
        newly_invalid_ancestor: Slot,
    ) {
        // Should not be marking a duplicate confirmed slot as invalid
        assert!(!self.is_duplicate_confirmed);
        if self
            .latest_invalid_ancestor
            .map(|latest_invalid_ancestor| newly_invalid_ancestor > latest_invalid_ancestor)
            .unwrap_or(true)
        {
            info!(
                "Fork choice for {:?} setting latest invalid ancestor from {:?} to {}",
                my_key, self.latest_invalid_ancestor, newly_invalid_ancestor
            );
            self.latest_invalid_ancestor = Some(newly_invalid_ancestor);
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeaviestSubtreeForkChoice {
    fork_infos: HashMap<SlotHashKey, ForkInfo>,
    latest_votes: HashMap<Pubkey, SlotHashKey>,
    tree_root: SlotHashKey,
    last_root_time: Instant,
}

impl HeaviestSubtreeForkChoice {
    pub fn new(tree_root: SlotHashKey) -> Self {
        let mut heaviest_subtree_fork_choice = Self {
            tree_root,
            // Doesn't implement default because `root` must
            // exist in all the fields
            fork_infos: HashMap::new(),
            latest_votes: HashMap::new(),
            last_root_time: Instant::now(),
        };
        heaviest_subtree_fork_choice.add_new_leaf_slot(tree_root, None);
        heaviest_subtree_fork_choice
    }

    // Given a root and a list of `frozen_banks` sorted smallest to greatest by slot,
    // return a new HeaviestSubtreeForkChoice
    pub fn new_from_frozen_banks(root: SlotHashKey, frozen_banks: &[Arc<Bank>]) -> Self {
        let mut heaviest_subtree_fork_choice = HeaviestSubtreeForkChoice::new(root);
        let mut prev_slot = root.0;
        for bank in frozen_banks.iter() {
            assert!(bank.is_frozen());
            if bank.slot() > root.0 {
                // Make sure the list is sorted
                assert!(bank.slot() > prev_slot);
                prev_slot = bank.slot();
                let bank_hash = bank.hash();
                assert_ne!(bank_hash, Hash::default());
                let parent_bank_hash = bank.parent_hash();
                assert_ne!(parent_bank_hash, Hash::default());
                heaviest_subtree_fork_choice.add_new_leaf_slot(
                    (bank.slot(), bank_hash),
                    Some((bank.parent_slot(), parent_bank_hash)),
                );
            }
        }

        heaviest_subtree_fork_choice
    }

    pub fn new_from_bank_forks(bank_forks: &BankForks) -> Self {
        let mut frozen_banks: Vec<_> = bank_forks.frozen_banks().values().cloned().collect();

        frozen_banks.sort_by_key(|bank| bank.slot());
        let root_bank = bank_forks.root_bank();
        Self::new_from_frozen_banks((root_bank.slot(), root_bank.hash()), &frozen_banks)
    }

    pub fn contains_block(&self, key: &SlotHashKey) -> bool {
        self.fork_infos.contains_key(key)
    }

    pub fn best_slot(&self, key: &SlotHashKey) -> Option<SlotHashKey> {
        self.fork_infos
            .get(key)
            .map(|fork_info| fork_info.best_slot)
    }

    pub fn best_overall_slot(&self) -> SlotHashKey {
        self.best_slot(&self.tree_root).unwrap()
    }

    pub fn stake_voted_subtree(&self, key: &SlotHashKey) -> Option<u64> {
        self.fork_infos
            .get(key)
            .map(|fork_info| fork_info.stake_voted_subtree)
    }

    pub fn tree_root(&self) -> SlotHashKey {
        self.tree_root
    }

    pub fn max_by_weight(&self, slot1: SlotHashKey, slot2: SlotHashKey) -> std::cmp::Ordering {
        let weight1 = self.stake_voted_subtree(&slot1).unwrap();
        let weight2 = self.stake_voted_subtree(&slot2).unwrap();
        if weight1 == weight2 {
            slot1.cmp(&slot2).reverse()
        } else {
            weight1.cmp(&weight2)
        }
    }

    // Add new votes, returns the best slot
    pub fn add_votes<'a, 'b>(
        &'a mut self,
        // newly updated votes on a fork
        pubkey_votes: impl Iterator<Item = impl Borrow<(Pubkey, SlotHashKey)> + 'b>,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
    ) -> SlotHashKey {
        // Generate the set of updates
        let update_operations_batch =
            self.generate_update_operations(pubkey_votes, epoch_stakes, epoch_schedule);

        // Finalize all updates
        self.process_update_operations(update_operations_batch);
        self.best_overall_slot()
    }

    pub fn is_empty(&self) -> bool {
        self.fork_infos.is_empty()
    }

    pub fn set_tree_root(&mut self, new_root: SlotHashKey) {
        // Remove everything reachable from `self.tree_root` but not `new_root`,
        // as those are now unrooted.
        let remove_set = (&*self).subtree_diff(self.tree_root, new_root);
        for node_key in remove_set {
            self.fork_infos
                .remove(&node_key)
                .expect("Slots reachable from old root must exist in tree");
        }
        let root_fork_info = self.fork_infos.get_mut(&new_root);

        root_fork_info
            .unwrap_or_else(|| panic!("New root: {new_root:?}, didn't exist in fork choice"))
            .parent = None;
        self.tree_root = new_root;
        self.last_root_time = Instant::now();
    }

    /// Purges all slots < `new_root` and prunes subtrees with slots > `new_root` not descending from `new_root`.
    /// Also if the resulting tree is non-empty, updates `self.tree_root` to `new_root`
    /// Returns (purged slots, pruned subtrees)
    pub fn purge_prune(&mut self, new_root: SlotHashKey) -> (Vec<SlotHashKey>, Vec<Self>) {
        let mut pruned_subtrees = vec![];
        let mut purged_slots = vec![];
        let mut tree_root = None;
        // Find the subtrees to prune
        let mut to_visit = vec![self.tree_root];
        while !to_visit.is_empty() {
            let cur_slot = to_visit.pop().unwrap();
            if cur_slot == new_root {
                tree_root = Some(new_root);
                continue;
            }
            if cur_slot < new_root {
                for child in (&*self)
                    .children(&cur_slot)
                    .expect("slot was discovered earlier, must exist")
                {
                    to_visit.push(*child);
                }
                // Purge this slot since it's < `new_root`
                purged_slots.push(cur_slot);
            } else {
                // The start of a pruned subtree. Split it out and stop traversing this subtree.
                pruned_subtrees.push(self.split_off(&cur_slot));
            }
        }

        for slot in purged_slots.iter() {
            self.fork_infos
                .remove(slot)
                .expect("Slots reachable from old root must exist in tree");
        }
        if let Some(tree_root) = tree_root {
            self.fork_infos
                .get_mut(&tree_root)
                .expect("New tree_root must exist in fork_infos")
                .parent = None;
            self.tree_root = tree_root;
            self.last_root_time = Instant::now();
        }
        (purged_slots, pruned_subtrees)
    }

    pub fn add_root_parent(&mut self, root_parent: SlotHashKey) {
        assert!(root_parent.0 < self.tree_root.0);
        assert!(self.fork_infos.get(&root_parent).is_none());
        let root_info = self
            .fork_infos
            .get_mut(&self.tree_root)
            .expect("entry for root must exist");
        root_info.parent = Some(root_parent);
        let root_parent_info = ForkInfo {
            stake_voted_at: 0,
            stake_voted_subtree: root_info.stake_voted_subtree,
            // The `best_slot` does not change
            best_slot: root_info.best_slot,
            children: BTreeSet::from([self.tree_root]),
            parent: None,
            latest_invalid_ancestor: None,
            is_duplicate_confirmed: root_info.is_duplicate_confirmed,
        };
        self.fork_infos.insert(root_parent, root_parent_info);
        self.tree_root = root_parent;
    }

    pub fn add_new_leaf_slot(&mut self, slot_hash_key: SlotHashKey, parent: Option<SlotHashKey>) {
        if self.last_root_time.elapsed().as_secs() > MAX_ROOT_PRINT_SECONDS {
            self.print_state();
            self.last_root_time = Instant::now();
        }

        if self.fork_infos.contains_key(&slot_hash_key) {
            // Can potentially happen if we repair the same version of the duplicate slot, after
            // dumping the original version
            return;
        }

        let parent_latest_invalid_ancestor =
            parent.and_then(|parent| self.latest_invalid_ancestor(&parent));
        self.fork_infos
            .entry(slot_hash_key)
            .and_modify(|fork_info| fork_info.parent = parent)
            .or_insert(ForkInfo {
                stake_voted_at: 0,
                stake_voted_subtree: 0,
                // The `best_slot` of a leaf is itself
                best_slot: slot_hash_key,
                children: BTreeSet::new(),
                parent,
                latest_invalid_ancestor: parent_latest_invalid_ancestor,
                // If the parent is none, then this is the root, which implies this must
                // have reached the duplicate confirmed threshold
                is_duplicate_confirmed: parent.is_none(),
            });

        if parent.is_none() {
            return;
        }

        let parent = parent.unwrap();

        // Parent must already exist by time child is being added
        self.fork_infos
            .get_mut(&parent)
            .unwrap()
            .children
            .insert(slot_hash_key);

        // Propagate leaf up the tree to any ancestors who considered the previous leaf
        // the `best_slot`
        self.propagate_new_leaf(&slot_hash_key, &parent)
    }

    // Returns true if the given `maybe_best_child` is the heaviest among the children
    // of the parent. Breaks ties by slot # (lower is heavier).
    fn is_best_child(&self, maybe_best_child: &SlotHashKey) -> bool {
        let maybe_best_child_weight = self.stake_voted_subtree(maybe_best_child).unwrap();
        let parent = self.parent(maybe_best_child);
        // If there's no parent, this must be the root
        if parent.is_none() {
            return true;
        }
        for child in self.children(&parent.unwrap()).unwrap() {
            let child_weight = self
                .stake_voted_subtree(child)
                .expect("child must exist in `self.fork_infos`");

            // Don't count children currently marked as invalid
            if !self.is_candidate(child).expect("child must exist in tree") {
                continue;
            }

            if child_weight > maybe_best_child_weight
                || (maybe_best_child_weight == child_weight && *child < *maybe_best_child)
            {
                return false;
            }
        }

        true
    }

    pub fn all_slots_stake_voted_subtree(&self) -> impl Iterator<Item = (&SlotHashKey, u64)> {
        self.fork_infos
            .iter()
            .map(|(slot_hash, fork_info)| (slot_hash, fork_info.stake_voted_subtree))
    }

    /// Split off the node at `slot_hash_key` and propagate the stake subtraction up to the root of the
    /// tree.
    ///
    /// Assumes that `slot_hash_key` is not the `tree_root`
    /// Returns the subtree originating from `slot_hash_key`
    pub fn split_off(&mut self, slot_hash_key: &SlotHashKey) -> Self {
        assert_ne!(self.tree_root, *slot_hash_key);
        let mut split_tree_root = {
            let mut node_to_split_at = self
                .fork_infos
                .get_mut(slot_hash_key)
                .expect("Slot hash key must exist in tree");
            let split_tree_fork_info = node_to_split_at.clone();
            // Remove stake to be aggregated up the tree
            node_to_split_at.stake_voted_subtree = 0;
            node_to_split_at.stake_voted_at = 0;
            // Mark this node as invalid so that it cannot be chosen as best child
            node_to_split_at.latest_invalid_ancestor = Some(slot_hash_key.0);
            split_tree_fork_info
        };

        let mut update_operations: UpdateOperations = BTreeMap::new();
        // Aggregate up to the root
        self.insert_aggregate_operations(&mut update_operations, *slot_hash_key);
        self.process_update_operations(update_operations);

        // Remove node + all children and add to new tree
        let mut split_tree_fork_infos = HashMap::new();
        let mut to_visit = vec![*slot_hash_key];

        while !to_visit.is_empty() {
            let current_node = to_visit.pop().unwrap();
            let current_fork_info = self
                .fork_infos
                .remove(&current_node)
                .expect("Node must exist in tree");

            to_visit.extend(current_fork_info.children.iter());
            split_tree_fork_infos.insert(current_node, current_fork_info);
        }

        // Remove link from parent
        let parent_fork_info = self
            .fork_infos
            .get_mut(&split_tree_root.parent.expect("Cannot split off from root"))
            .expect("Parent must exist in fork infos");
        parent_fork_info.children.remove(slot_hash_key);

        // Update the root of the new tree with the proper info, now that we have finished
        // aggregating
        split_tree_root.parent = None;
        split_tree_fork_infos.insert(*slot_hash_key, split_tree_root);

        // Split off the relevant votes to the new tree
        let mut split_tree_latest_votes = self.latest_votes.clone();
        split_tree_latest_votes.retain(|_, node| split_tree_fork_infos.contains_key(node));
        self.latest_votes
            .retain(|_, node| self.fork_infos.contains_key(node));

        // Create a new tree from the split
        HeaviestSubtreeForkChoice {
            tree_root: *slot_hash_key,
            fork_infos: split_tree_fork_infos,
            latest_votes: split_tree_latest_votes,
            last_root_time: Instant::now(),
        }
    }

    pub fn merge(
        &mut self,
        other: HeaviestSubtreeForkChoice,
        merge_leaf: &SlotHashKey,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
    ) {
        assert!(self.fork_infos.contains_key(merge_leaf));

        // Add all the nodes from `other` into our tree
        let mut other_slots_nodes: Vec<_> = other
            .fork_infos
            .iter()
            .map(|(slot_hash_key, fork_info)| {
                (slot_hash_key, fork_info.parent.unwrap_or(*merge_leaf))
            })
            .collect();

        other_slots_nodes.sort_by_key(|(slot_hash_key, _)| *slot_hash_key);
        for (slot_hash_key, parent) in other_slots_nodes {
            self.add_new_leaf_slot(*slot_hash_key, Some(parent));
        }

        // Add all votes, the outdated ones should be filtered out by
        // self.add_votes()
        self.add_votes(other.latest_votes.into_iter(), epoch_stakes, epoch_schedule);
    }

    pub fn stake_voted_at(&self, slot: &SlotHashKey) -> Option<u64> {
        self.fork_infos
            .get(slot)
            .map(|fork_info| fork_info.stake_voted_at)
    }

    pub fn latest_invalid_ancestor(&self, slot_hash_key: &SlotHashKey) -> Option<Slot> {
        self.fork_infos
            .get(slot_hash_key)
            .map(|fork_info| fork_info.latest_invalid_ancestor)
            .unwrap_or(None)
    }

    pub fn is_duplicate_confirmed(&self, slot_hash_key: &SlotHashKey) -> Option<bool> {
        self.fork_infos
            .get(slot_hash_key)
            .map(|fork_info| fork_info.is_duplicate_confirmed())
    }

    /// Returns if the exact node with the specified key has been explicitly marked as a duplicate
    /// slot (doesn't count ancestors being marked as duplicate).
    pub fn is_unconfirmed_duplicate(&self, slot_hash_key: &SlotHashKey) -> Option<bool> {
        self.fork_infos
            .get(slot_hash_key)
            .map(|fork_info| fork_info.is_unconfirmed_duplicate(slot_hash_key.0))
    }

    /// Returns false if the node or any of its ancestors have been marked as duplicate
    pub fn is_candidate(&self, slot_hash_key: &SlotHashKey) -> Option<bool> {
        self.fork_infos
            .get(slot_hash_key)
            .map(|fork_info| fork_info.is_candidate())
    }

    /// Returns if a node with slot `maybe_ancestor_slot` is an ancestor of the node with
    /// key `node_key`
    pub fn is_strict_ancestor(
        &self,
        maybe_ancestor_key: &SlotHashKey,
        node_key: &SlotHashKey,
    ) -> bool {
        if maybe_ancestor_key == node_key {
            return false;
        }

        if maybe_ancestor_key.0 > node_key.0 {
            return false;
        }

        let mut ancestor_iterator = self.ancestor_iterator(*node_key);
        ancestor_iterator.any(|(ancestor_slot, ancestor_hash)| {
            ancestor_slot == maybe_ancestor_key.0 && ancestor_hash == maybe_ancestor_key.1
        })
    }

    fn propagate_new_leaf(
        &mut self,
        slot_hash_key: &SlotHashKey,
        parent_slot_hash_key: &SlotHashKey,
    ) {
        let parent_best_slot_hash_key = self
            .best_slot(parent_slot_hash_key)
            .expect("parent must exist in self.fork_infos after its child leaf was created");

        // If this new leaf is the direct parent's best child, then propagate
        // it up the tree
        if self.is_best_child(slot_hash_key) {
            let mut ancestor = Some(*parent_slot_hash_key);
            loop {
                if ancestor.is_none() {
                    break;
                }
                let ancestor_fork_info = self.fork_infos.get_mut(&ancestor.unwrap()).unwrap();
                if ancestor_fork_info.best_slot == parent_best_slot_hash_key {
                    ancestor_fork_info.best_slot = *slot_hash_key;
                } else {
                    break;
                }
                ancestor = ancestor_fork_info.parent;
            }
        }
    }

    fn insert_aggregate_operations(
        &self,
        update_operations: &mut BTreeMap<(SlotHashKey, UpdateLabel), UpdateOperation>,
        slot_hash_key: SlotHashKey,
    ) {
        self.do_insert_aggregate_operations_across_ancestors(
            update_operations,
            None,
            slot_hash_key,
        );
    }

    #[allow(clippy::map_entry)]
    fn do_insert_aggregate_operations_across_ancestors(
        &self,
        update_operations: &mut BTreeMap<(SlotHashKey, UpdateLabel), UpdateOperation>,
        modify_fork_validity: Option<UpdateOperation>,
        slot_hash_key: SlotHashKey,
    ) {
        for parent_slot_hash_key in self.ancestor_iterator(slot_hash_key) {
            if !self.do_insert_aggregate_operation(
                update_operations,
                &modify_fork_validity,
                parent_slot_hash_key,
            ) {
                // If this parent was already inserted, we assume all the other parents have also
                // already been inserted. This is to prevent iterating over the parents multiple times
                // when we are aggregating leaves that have a lot of shared ancestors
                break;
            }
        }
    }

    #[allow(clippy::map_entry)]
    fn do_insert_aggregate_operation(
        &self,
        update_operations: &mut BTreeMap<(SlotHashKey, UpdateLabel), UpdateOperation>,
        modify_fork_validity: &Option<UpdateOperation>,
        slot_hash_key: SlotHashKey,
    ) -> bool {
        let aggregate_label = (slot_hash_key, UpdateLabel::Aggregate);
        if update_operations.contains_key(&aggregate_label) {
            false
        } else {
            if let Some(mark_fork_validity) = modify_fork_validity {
                match mark_fork_validity {
                    UpdateOperation::MarkValid(slot) => {
                        update_operations.insert(
                            (slot_hash_key, UpdateLabel::MarkValid(*slot)),
                            UpdateOperation::MarkValid(*slot),
                        );
                    }
                    UpdateOperation::MarkInvalid(slot) => {
                        update_operations.insert(
                            (slot_hash_key, UpdateLabel::MarkInvalid(*slot)),
                            UpdateOperation::MarkInvalid(*slot),
                        );
                    }
                    _ => (),
                }
            }
            update_operations.insert(aggregate_label, UpdateOperation::Aggregate);
            true
        }
    }

    fn ancestor_iterator(&self, start_slot_hash_key: SlotHashKey) -> AncestorIterator {
        AncestorIterator::new(start_slot_hash_key, &self.fork_infos)
    }

    fn aggregate_slot(&mut self, slot_hash_key: SlotHashKey) {
        let mut stake_voted_subtree;
        let mut best_slot_hash_key = slot_hash_key;
        let mut is_duplicate_confirmed = false;
        if let Some(fork_info) = self.fork_infos.get(&slot_hash_key) {
            stake_voted_subtree = fork_info.stake_voted_at;
            let mut best_child_stake_voted_subtree = 0;
            let mut best_child_slot_key = slot_hash_key;
            for child_key in &fork_info.children {
                let child_fork_info = self
                    .fork_infos
                    .get(child_key)
                    .expect("Child must exist in fork_info map");
                let child_stake_voted_subtree = child_fork_info.stake_voted_subtree;
                is_duplicate_confirmed |= child_fork_info.is_duplicate_confirmed;

                // Child forks that are not candidates still contribute to the weight
                // of the subtree rooted at `slot_hash_key`. For instance:
                /*
                    Build fork structure:
                          slot 0
                            |
                          slot 1
                          /    \
                    slot 2     |
                        |     slot 3 (34%)
                slot 4 (66%)

                    If slot 4 is a duplicate slot, so no longer qualifies as a candidate until
                    the slot is confirmed, the weight of votes on slot 4 should still count towards
                    slot 2, otherwise we might pick slot 3 as the heaviest fork to build blocks on
                    instead of slot 2.
                */

                // See comment above for why this check is outside of the `is_candidate` check.
                stake_voted_subtree += child_stake_voted_subtree;

                // Note: If there's no valid children, then the best slot should default to the
                // input `slot` itself.
                if child_fork_info.is_candidate()
                    && (best_child_slot_key == slot_hash_key ||
                    child_stake_voted_subtree > best_child_stake_voted_subtree ||
                // tiebreaker by slot height, prioritize earlier slot
                (child_stake_voted_subtree == best_child_stake_voted_subtree && child_key < &best_child_slot_key))
                {
                    best_child_stake_voted_subtree = child_stake_voted_subtree;
                    best_child_slot_key = *child_key;
                    best_slot_hash_key = child_fork_info.best_slot;
                }
            }
        } else {
            return;
        }

        let fork_info = self.fork_infos.get_mut(&slot_hash_key).unwrap();
        if is_duplicate_confirmed {
            if !fork_info.is_duplicate_confirmed {
                info!(
                    "Fork choice setting {:?} to duplicate confirmed",
                    slot_hash_key
                );
            }
            fork_info.set_duplicate_confirmed();
        }
        fork_info.stake_voted_subtree = stake_voted_subtree;
        fork_info.best_slot = best_slot_hash_key;
    }

    /// Mark that `valid_slot` on the fork starting at `fork_to_modify` has been marked
    /// valid. Note we don't need the hash for `valid_slot` because slot number uniquely
    /// identifies a node on a single fork.
    fn mark_fork_valid(&mut self, fork_to_modify_key: SlotHashKey, valid_slot: Slot) {
        if let Some(fork_info_to_modify) = self.fork_infos.get_mut(&fork_to_modify_key) {
            fork_info_to_modify.update_with_newly_valid_ancestor(&fork_to_modify_key, valid_slot);
            if fork_to_modify_key.0 == valid_slot {
                fork_info_to_modify.is_duplicate_confirmed = true;
            }
        }
    }

    /// Mark that `invalid_slot` on the fork starting at `fork_to_modify` has been marked
    /// invalid. Note we don't need the hash for `invalid_slot` because slot number uniquely
    /// identifies a node on a single fork.
    fn mark_fork_invalid(&mut self, fork_to_modify_key: SlotHashKey, invalid_slot: Slot) {
        if let Some(fork_info_to_modify) = self.fork_infos.get_mut(&fork_to_modify_key) {
            fork_info_to_modify
                .update_with_newly_invalid_ancestor(&fork_to_modify_key, invalid_slot);
        }
    }

    fn generate_update_operations<'a, 'b>(
        &'a mut self,
        pubkey_votes: impl Iterator<Item = impl Borrow<(Pubkey, SlotHashKey)> + 'b>,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
    ) -> UpdateOperations {
        let mut update_operations: BTreeMap<(SlotHashKey, UpdateLabel), UpdateOperation> =
            BTreeMap::new();
        let mut observed_pubkeys: HashMap<Pubkey, Slot> = HashMap::new();
        // Sort the `pubkey_votes` in a BTreeMap by the slot voted
        for pubkey_vote in pubkey_votes {
            let (pubkey, new_vote_slot_hash) = pubkey_vote.borrow();
            let (new_vote_slot, new_vote_hash) = *new_vote_slot_hash;
            if new_vote_slot < self.tree_root.0 {
                // If the new vote is less than the root we can ignore it. This is because there
                // are two cases. Either:
                // 1) The validator's latest vote was bigger than the new vote, so we can ignore it
                // 2) The validator's latest vote was less than the new vote, then the validator's latest
                // vote was also less than root. This means either every node in the current tree has the
                // validators stake counted toward it (if the latest vote was an ancestor of the current root),
                // OR every node doesn't have this validator's vote counting toward it (if the latest vote
                // was not an ancestor of the current root). Thus this validator is essentially a no-op
                // and won't affect fork choice.
                continue;
            }

            // A pubkey cannot appear in pubkey votes more than once.
            match observed_pubkeys.entry(*pubkey) {
                Entry::Occupied(_occupied_entry) => {
                    panic!("Should not get multiple votes for same pubkey in the same batch");
                }
                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(new_vote_slot);
                    false
                }
            };

            let mut pubkey_latest_vote = self.latest_votes.get_mut(pubkey);

            // Filter out any votes or slots < any slot this pubkey has
            // already voted for, we only care about the latest votes.
            //
            // If the new vote is for the same slot, but a different, smaller hash,
            // then allow processing to continue as this is a duplicate version
            // of the same slot.
            match pubkey_latest_vote.as_mut() {
                Some((pubkey_latest_vote_slot, pubkey_latest_vote_hash))
                    if (new_vote_slot < *pubkey_latest_vote_slot)
                        || (new_vote_slot == *pubkey_latest_vote_slot
                            && &new_vote_hash >= pubkey_latest_vote_hash) =>
                {
                    continue;
                }

                _ => {
                    // We either:
                    // 1) don't have a vote yet for this pubkey,
                    // 2) or the new vote slot is bigger than the old vote slot
                    // 3) or the new vote slot == old_vote slot, but for a smaller bank hash.
                    // In all above cases, we need to remove this pubkey stake from the previous fork
                    // of the previous vote

                    if let Some((old_latest_vote_slot, old_latest_vote_hash)) =
                        self.latest_votes.insert(*pubkey, *new_vote_slot_hash)
                    {
                        assert!(if new_vote_slot == old_latest_vote_slot {
                            warn!(
                                "Got a duplicate vote for
                                    validator: {},
                                    slot_hash: {:?}",
                                pubkey, new_vote_slot_hash
                            );
                            // If the slots are equal, then the new
                            // vote must be for a smaller hash
                            new_vote_hash < old_latest_vote_hash
                        } else {
                            new_vote_slot > old_latest_vote_slot
                        });

                        let epoch = epoch_schedule.get_epoch(old_latest_vote_slot);
                        let stake_update = epoch_stakes
                            .get(&epoch)
                            .map(|epoch_stakes| epoch_stakes.vote_account_stake(pubkey))
                            .unwrap_or(0);

                        if stake_update > 0 {
                            update_operations
                                .entry((
                                    (old_latest_vote_slot, old_latest_vote_hash),
                                    UpdateLabel::Subtract,
                                ))
                                .and_modify(|update| update.update_stake(stake_update))
                                .or_insert(UpdateOperation::Subtract(stake_update));
                            self.insert_aggregate_operations(
                                &mut update_operations,
                                (old_latest_vote_slot, old_latest_vote_hash),
                            );
                        }
                    }
                }
            }

            // Add this pubkey stake to new fork
            let epoch = epoch_schedule.get_epoch(new_vote_slot_hash.0);
            let stake_update = epoch_stakes
                .get(&epoch)
                .map(|epoch_stakes| epoch_stakes.vote_account_stake(pubkey))
                .unwrap_or(0);

            update_operations
                .entry((*new_vote_slot_hash, UpdateLabel::Add))
                .and_modify(|update| update.update_stake(stake_update))
                .or_insert(UpdateOperation::Add(stake_update));
            self.insert_aggregate_operations(&mut update_operations, *new_vote_slot_hash);
        }

        update_operations
    }

    fn process_update_operations(&mut self, update_operations: UpdateOperations) {
        // Iterate through the update operations from greatest to smallest slot
        for ((slot_hash_key, _), operation) in update_operations.into_iter().rev() {
            match operation {
                UpdateOperation::MarkValid(valid_slot) => {
                    self.mark_fork_valid(slot_hash_key, valid_slot)
                }
                UpdateOperation::MarkInvalid(invalid_slot) => {
                    self.mark_fork_invalid(slot_hash_key, invalid_slot)
                }
                UpdateOperation::Aggregate => self.aggregate_slot(slot_hash_key),
                UpdateOperation::Add(stake) => self.add_slot_stake(&slot_hash_key, stake),
                UpdateOperation::Subtract(stake) => self.subtract_slot_stake(&slot_hash_key, stake),
            }
        }
    }

    fn add_slot_stake(&mut self, slot_hash_key: &SlotHashKey, stake: u64) {
        if let Some(fork_info) = self.fork_infos.get_mut(slot_hash_key) {
            fork_info.stake_voted_at += stake;
            fork_info.stake_voted_subtree += stake;
        }
    }

    fn subtract_slot_stake(&mut self, slot_hash_key: &SlotHashKey, stake: u64) {
        if let Some(fork_info) = self.fork_infos.get_mut(slot_hash_key) {
            fork_info.stake_voted_at -= stake;
            fork_info.stake_voted_subtree -= stake;
        }
    }

    fn parent(&self, slot_hash_key: &SlotHashKey) -> Option<SlotHashKey> {
        self.fork_infos
            .get(slot_hash_key)
            .map(|fork_info| fork_info.parent)
            .unwrap_or(None)
    }

    fn print_state(&self) {
        let best_slot_hash_key = self.best_overall_slot();
        let mut best_path: VecDeque<_> = self.ancestor_iterator(best_slot_hash_key).collect();
        best_path.push_front(best_slot_hash_key);
        info!(
            "Latest known votes by vote pubkey: {:#?}, best path: {:?}",
            self.latest_votes,
            best_path.iter().rev().collect::<Vec<&SlotHashKey>>()
        );
    }

    fn heaviest_slot_on_same_voted_fork(&self, tower: &Tower) -> Option<SlotHashKey> {
        tower
            .last_voted_slot_hash()
            .and_then(|last_voted_slot_hash| {
                match self.is_candidate(&last_voted_slot_hash) {
                    Some(true) => self.best_slot(&last_voted_slot_hash),
                    Some(false) => None,
                    None => {
                        if !tower.is_stray_last_vote() {
                            // Unless last vote is stray and stale, self.is_candidate(last_voted_slot_hash) must return
                            // Some(_), justifying to panic! here.
                            // Also, adjust_lockouts_after_replay() correctly makes last_voted_slot None,
                            // if all saved votes are ancestors of replayed_root_slot. So this code shouldn't be
                            // touched in that case as well.
                            // In other words, except being stray, all other slots have been voted on while this
                            // validator has been running, so we must be able to fetch best_slots for all of
                            // them.
                            panic!(
                                "a bank at last_voted_slot({last_voted_slot_hash:?}) is a frozen bank so must have been \
                                        added to heaviest_subtree_fork_choice at time of freezing",
                            )
                        } else {
                            // fork_infos doesn't have corresponding data for the stale stray last vote,
                            // meaning some inconsistency between saved tower and ledger.
                            // (newer snapshot, or only a saved tower is moved over to new setup?)
                            None
                        }
                    }
                }
            })
    }
}

impl<'a> TreeDiff<'a> for &'a HeaviestSubtreeForkChoice {
    type TreeKey = SlotHashKey;
    type ChildIter = Iter<'a, SlotHashKey>;

    fn contains_slot(&self, slot_hash_key: &SlotHashKey) -> bool {
        self.fork_infos.contains_key(slot_hash_key)
    }

    fn children(&self, slot_hash_key: &SlotHashKey) -> Option<Self::ChildIter> {
        self.fork_infos
            .get(slot_hash_key)
            .map(|fork_info| fork_info.children.iter())
    }
}

impl ForkChoice for HeaviestSubtreeForkChoice {
    type ForkChoiceKey = SlotHashKey;
    fn compute_bank_stats(
        &mut self,
        bank: &Bank,
        _tower: &Tower,
        latest_validator_votes_for_frozen_banks: &mut LatestValidatorVotesForFrozenBanks,
    ) {
        let mut start = Measure::start("compute_bank_stats_time");
        // Update `heaviest_subtree_fork_choice` to find the best fork to build on
        let root = self.tree_root.0;
        let new_votes = latest_validator_votes_for_frozen_banks.take_votes_dirty_set(root);
        let (best_overall_slot, best_overall_hash) = self.add_votes(
            new_votes.into_iter(),
            bank.epoch_stakes_map(),
            bank.epoch_schedule(),
        );
        start.stop();

        datapoint_info!(
            "compute_bank_stats-best_slot",
            ("computed_slot", bank.slot(), i64),
            ("overall_best_slot", best_overall_slot, i64),
            ("overall_best_hash", best_overall_hash.to_string(), String),
            ("elapsed", start.as_us(), i64),
        );
    }

    // Returns:
    // 1) The heaviest overall bank
    // 2) The heaviest bank on the same fork as the last vote (doesn't require a
    // switching proof to vote for)
    fn select_forks(
        &self,
        _frozen_banks: &[Arc<Bank>],
        tower: &Tower,
        _progress: &ProgressMap,
        _ancestors: &HashMap<u64, HashSet<u64>>,
        bank_forks: &RwLock<BankForks>,
    ) -> (Arc<Bank>, Option<Arc<Bank>>) {
        let r_bank_forks = bank_forks.read().unwrap();

        // BankForks should only contain one valid version of this slot
        (
            r_bank_forks
                .get_with_checked_hash(self.best_overall_slot())
                .unwrap(),
            self.heaviest_slot_on_same_voted_fork(tower)
                .map(|slot_hash| {
                    // BankForks should only contain one valid version of this slot
                    r_bank_forks.get_with_checked_hash(slot_hash).unwrap()
                }),
        )
    }

    fn mark_fork_invalid_candidate(&mut self, invalid_slot_hash_key: &SlotHashKey) {
        info!(
            "marking fork starting at: {:?} invalid candidate",
            invalid_slot_hash_key
        );
        let fork_info = self.fork_infos.get_mut(invalid_slot_hash_key);
        if let Some(fork_info) = fork_info {
            // Should not be marking duplicate confirmed blocks as invalid candidates
            assert!(!fork_info.is_duplicate_confirmed);
            let mut update_operations = UpdateOperations::default();

            // Notify all the children of this node that a parent was marked as invalid
            for child_hash_key in
                (&*self).subtree_diff(*invalid_slot_hash_key, SlotHashKey::default())
            {
                self.do_insert_aggregate_operation(
                    &mut update_operations,
                    &Some(UpdateOperation::MarkInvalid(invalid_slot_hash_key.0)),
                    child_hash_key,
                );
            }

            // Aggregate across all ancestors to find the new best slots excluding this fork
            self.insert_aggregate_operations(&mut update_operations, *invalid_slot_hash_key);
            self.process_update_operations(update_operations);
        }
    }

    fn mark_fork_valid_candidate(&mut self, valid_slot_hash_key: &SlotHashKey) -> Vec<SlotHashKey> {
        info!(
            "marking fork starting at: {:?} valid candidate",
            valid_slot_hash_key
        );
        let mut newly_duplicate_confirmed_ancestors = vec![];

        for ancestor_key in std::iter::once(*valid_slot_hash_key)
            .chain(self.ancestor_iterator(*valid_slot_hash_key))
        {
            if !self.is_duplicate_confirmed(&ancestor_key).unwrap() {
                newly_duplicate_confirmed_ancestors.push(ancestor_key);
            }
        }

        let mut update_operations = UpdateOperations::default();
        // Notify all the children of this node that a parent was marked as valid
        for child_hash_key in (&*self).subtree_diff(*valid_slot_hash_key, SlotHashKey::default()) {
            self.do_insert_aggregate_operation(
                &mut update_operations,
                &Some(UpdateOperation::MarkValid(valid_slot_hash_key.0)),
                child_hash_key,
            );
        }

        // Aggregate across all ancestors to find the new best slots including this fork
        self.insert_aggregate_operations(&mut update_operations, *valid_slot_hash_key);
        self.process_update_operations(update_operations);
        newly_duplicate_confirmed_ancestors
    }
}

struct AncestorIterator<'a> {
    current_slot_hash_key: SlotHashKey,
    fork_infos: &'a HashMap<SlotHashKey, ForkInfo>,
}

impl<'a> AncestorIterator<'a> {
    fn new(
        start_slot_hash_key: SlotHashKey,
        fork_infos: &'a HashMap<SlotHashKey, ForkInfo>,
    ) -> Self {
        Self {
            current_slot_hash_key: start_slot_hash_key,
            fork_infos,
        }
    }
}

impl<'a> Iterator for AncestorIterator<'a> {
    type Item = SlotHashKey;
    fn next(&mut self) -> Option<Self::Item> {
        let parent_slot_hash_key = self
            .fork_infos
            .get(&self.current_slot_hash_key)
            .map(|fork_info| fork_info.parent)
            .unwrap_or(None);

        parent_slot_hash_key
            .map(|parent_slot_hash_key| {
                self.current_slot_hash_key = parent_slot_hash_key;
                Some(self.current_slot_hash_key)
            })
            .unwrap_or(None)
    }
}
