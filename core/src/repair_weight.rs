use {
    crate::{
        heaviest_subtree_fork_choice::HeaviestSubtreeForkChoice,
        repair_generic_traversal::{get_closest_completion, get_unknown_last_index},
        repair_service::{BestRepairsStats, RepairTiming},
        repair_weighted_traversal,
        serve_repair::ShredRepairType,
        tree_diff::TreeDiff,
    },
    solana_ledger::{
        ancestor_iterator::AncestorIterator, blockstore::Blockstore, blockstore_meta::SlotMeta,
    },
    solana_measure::measure::Measure,
    solana_runtime::{contains::Contains, epoch_stakes::EpochStakes},
    solana_sdk::{
        clock::Slot,
        epoch_schedule::{Epoch, EpochSchedule},
        hash::Hash,
        pubkey::Pubkey,
    },
    std::collections::{BTreeSet, HashMap, HashSet, VecDeque},
};

pub struct RepairWeight {
    // Map from root -> a subtree rooted at that `root`
    trees: HashMap<Slot, HeaviestSubtreeForkChoice>,
    // Maps each slot to the root of the tree that contains it
    slot_to_tree: HashMap<Slot, Slot>,
    // Prevents spam attacks that send votes for long chains of
    // unrooted slots, which would incur high cost of blockstore
    // lookup/iteration to resolve ancestry.

    // Must maintain invariant that any slot in `unrooted_slots`
    // does not exist in `slot_to_tree` and any descendants of
    // slots in the set `unrooted_slots` must also be in the set
    unrooted_slots: BTreeSet<Slot>,
    root: Slot,
}

impl RepairWeight {
    pub fn new(root: Slot) -> Self {
        let root_tree = HeaviestSubtreeForkChoice::new((root, Hash::default()));
        let slot_to_tree: HashMap<Slot, Slot> = vec![(root, root)].into_iter().collect();
        let trees: HashMap<Slot, HeaviestSubtreeForkChoice> =
            vec![(root, root_tree)].into_iter().collect();
        Self {
            trees,
            slot_to_tree,
            root,
            unrooted_slots: BTreeSet::new(),
        }
    }

    pub fn add_votes<I>(
        &mut self,
        blockstore: &Blockstore,
        votes: I,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
    ) where
        I: Iterator<Item = (Slot, Vec<Pubkey>)>,
    {
        let mut all_subtree_updates: HashMap<Slot, HashMap<Pubkey, Slot>> = HashMap::new();
        for (slot, pubkey_votes) in votes {
            if slot < self.root || self.unrooted_slots.contains(&slot) {
                continue;
            }
            let mut tree_root = self.slot_to_tree.get(&slot).cloned();
            let mut new_ancestors = VecDeque::new();
            // If we don't know know  how this slot chains to any existing trees
            // in `self.trees`, then use `blockstore` to see if this chains
            // any existing trees in `self.trees`
            if tree_root.is_none() {
                let (discovered_ancestors, existing_subtree_root) =
                    self.find_ancestor_subtree_of_slot(blockstore, slot);
                new_ancestors = discovered_ancestors;
                tree_root = existing_subtree_root;
            }

            let should_create_new_subtree = tree_root.is_none();

            let tree_root = tree_root.unwrap_or(
                // If `tree_root` is still None, then there is no known
                // subtree that contains `slot`. Thus, create a new
                // subtree rooted at the earliest known ancestor of `slot`
                *new_ancestors.front().unwrap_or(&slot),
            );

            // If the discovered root of this tree is unrooted, mark all
            // ancestors in `new_ancestors` and this slot as unrooted
            if self.is_unrooted_slot(tree_root) {
                for ancestor in new_ancestors.into_iter().chain(std::iter::once(slot)) {
                    self.unrooted_slots.insert(ancestor);
                }

                continue;
            }

            if should_create_new_subtree {
                self.insert_new_tree(tree_root);
            }

            let tree = self
                .trees
                .get_mut(&tree_root)
                .expect("If tree root was found, it must exist in `self.trees`");

            // First element in `ancestors` must be either:
            // 1) Leaf of some existing subtree
            // 2) Root of new subtree that was just created above through `self.insert_new_tree`
            new_ancestors.push_back(slot);
            if new_ancestors.len() > 1 {
                for i in 0..new_ancestors.len() - 1 {
                    // TODO: Repair right now does not distinguish between votes for different
                    // versions of the same slot.
                    tree.add_new_leaf_slot(
                        (new_ancestors[i + 1], Hash::default()),
                        Some((new_ancestors[i], Hash::default())),
                    );
                    self.slot_to_tree.insert(new_ancestors[i + 1], tree_root);
                }
            }

            // Now we know which subtree this slot chains to,
            // add the votes to the list of updates
            let subtree_updates = all_subtree_updates.entry(tree_root).or_default();
            for pubkey in pubkey_votes {
                let cur_max = subtree_updates.entry(pubkey).or_default();
                *cur_max = std::cmp::max(*cur_max, slot);
            }
        }

        for (tree_root, updates) in all_subtree_updates {
            let tree = self
                .trees
                .get_mut(&tree_root)
                .expect("`slot_to_tree` and `self.trees` must be in sync");
            let updates: Vec<_> = updates.into_iter().collect();
            tree.add_votes(
                updates
                    .iter()
                    .map(|(pubkey, slot)| (*pubkey, (*slot, Hash::default()))),
                epoch_stakes,
                epoch_schedule,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn get_best_weighted_repairs<'a>(
        &mut self,
        blockstore: &Blockstore,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
        max_new_orphans: usize,
        max_new_shreds: usize,
        max_unknown_last_index_repairs: usize,
        max_closest_completion_repairs: usize,
        ignore_slots: &impl Contains<'a, Slot>,
        repair_timing: Option<&mut RepairTiming>,
        stats: Option<&mut BestRepairsStats>,
    ) -> Vec<ShredRepairType> {
        let mut repairs = vec![];
        let mut processed_slots: HashSet<Slot> = vec![self.root].into_iter().collect();
        let mut slot_meta_cache = HashMap::default();

        let mut get_best_orphans_elapsed = Measure::start("get_best_orphans");
        // Update the orphans in order from heaviest to least heavy
        self.get_best_orphans(
            blockstore,
            &mut processed_slots,
            &mut repairs,
            epoch_stakes,
            epoch_schedule,
            max_new_orphans,
        );
        let num_orphan_slots = processed_slots.len() - 1;
        let num_orphan_repairs = repairs.len();
        get_best_orphans_elapsed.stop();

        let mut get_best_shreds_elapsed = Measure::start("get_best_shreds");
        let mut best_shreds_repairs = Vec::default();
        // Find the best incomplete slots in rooted subtree
        self.get_best_shreds(
            blockstore,
            &mut slot_meta_cache,
            &mut best_shreds_repairs,
            max_new_shreds,
            ignore_slots,
        );
        let num_best_shreds_repairs = best_shreds_repairs.len();
        let repair_slots_set: HashSet<Slot> =
            best_shreds_repairs.iter().map(|r| r.slot()).collect();
        let num_best_shreds_slots = repair_slots_set.len();
        processed_slots.extend(repair_slots_set);
        repairs.extend(best_shreds_repairs);
        get_best_shreds_elapsed.stop();

        // Although we have generated repairs for orphan roots and slots in the rooted subtree,
        // if we have space we should generate repairs for slots in orphan trees in preparation for
        // when they are no longer rooted. Here we generate repairs for slots with unknown last
        // indices as well as slots that are close to completion.

        let mut get_unknown_last_index_elapsed = Measure::start("get_unknown_last_index");
        let pre_num_slots = processed_slots.len();
        let unknown_last_index_repairs = self.get_best_unknown_last_index(
            blockstore,
            &mut slot_meta_cache,
            &mut processed_slots,
            max_unknown_last_index_repairs,
        );
        let num_unknown_last_index_repairs = unknown_last_index_repairs.len();
        let num_unknown_last_index_slots = processed_slots.len() - pre_num_slots;
        repairs.extend(unknown_last_index_repairs);
        get_unknown_last_index_elapsed.stop();

        let mut get_closest_completion_elapsed = Measure::start("get_closest_completion");
        let pre_num_slots = processed_slots.len();
        let closest_completion_repairs = self.get_best_closest_completion(
            blockstore,
            &mut slot_meta_cache,
            &mut processed_slots,
            max_closest_completion_repairs,
        );
        let num_closest_completion_repairs = closest_completion_repairs.len();
        let num_closest_completion_slots = processed_slots.len() - pre_num_slots;
        repairs.extend(closest_completion_repairs);
        get_closest_completion_elapsed.stop();

        if let Some(stats) = stats {
            stats.update(
                num_orphan_slots as u64,
                num_orphan_repairs as u64,
                num_best_shreds_slots as u64,
                num_best_shreds_repairs as u64,
                num_unknown_last_index_slots as u64,
                num_unknown_last_index_repairs as u64,
                num_closest_completion_slots as u64,
                num_closest_completion_repairs as u64,
            );
        }
        if let Some(repair_timing) = repair_timing {
            repair_timing.get_best_orphans_elapsed += get_best_orphans_elapsed.as_us();
            repair_timing.get_best_shreds_elapsed += get_best_shreds_elapsed.as_us();
            repair_timing.get_unknown_last_index_elapsed += get_unknown_last_index_elapsed.as_us();
            repair_timing.get_closest_completion_elapsed += get_closest_completion_elapsed.as_us();
        }
        repairs
    }

    pub fn set_root(&mut self, new_root: Slot) {
        // Roots should be monotonically increasing
        assert!(self.root <= new_root);

        if new_root == self.root {
            return;
        }

        // Root slot of the tree that contains `new_root`, if one exists
        let new_root_tree_root = self.slot_to_tree.get(&new_root).cloned();

        // Purge outdated trees from `self.trees`
        let subtrees_to_purge: Vec<_> = self
            .trees
            .keys()
            .filter(|subtree_root| {
                **subtree_root < new_root
                    && new_root_tree_root
                        .map(|new_root_tree_root| **subtree_root != new_root_tree_root)
                        .unwrap_or(true)
            })
            .cloned()
            .collect();
        for subtree_root in subtrees_to_purge {
            let subtree = self
                .trees
                .remove(&subtree_root)
                .expect("Must exist, was found in `self.trees` above");
            self.remove_tree_slots(
                subtree
                    .all_slots_stake_voted_subtree()
                    .map(|((slot, _), _)| slot),
                new_root,
            );
        }

        if let Some(new_root_tree_root) = new_root_tree_root {
            let mut new_root_tree = self
                .trees
                .remove(&new_root_tree_root)
                .expect("Found slot root earlier in self.slot_to_trees, treee must exist");
            // Find all descendants of `self.root` that are not reachable from `new_root`.
            // These are exactly the unrooted slots, which can be purged and added to
            // `self.unrooted_slots`.
            let unrooted_slots = (&new_root_tree).subtree_diff(
                (new_root_tree_root, Hash::default()),
                (new_root, Hash::default()),
            );
            self.remove_tree_slots(
                unrooted_slots.iter().map(|slot_hash| &slot_hash.0),
                new_root,
            );

            new_root_tree.set_tree_root((new_root, Hash::default()));

            // Update `self.slot_to_tree` to reflect new root
            self.rename_tree_root(&new_root_tree, new_root);

            // Insert the tree for the new root
            self.trees.insert(new_root, new_root_tree);
        } else {
            self.insert_new_tree(new_root);
        }

        // Purge `self.unrooted_slots` of slots less than `new_root` as we know any
        // unrooted votes for slots < `new_root` will now be rejected, so we won't
        // need to check `self.unrooted_slots` to see if those slots are unrooted.
        self.unrooted_slots = self.unrooted_slots.split_off(&new_root);
        self.root = new_root;
    }

    // Generate shred repairs for main subtree rooted at `self.root`
    fn get_best_shreds<'a>(
        &mut self,
        blockstore: &Blockstore,
        slot_meta_cache: &mut HashMap<Slot, Option<SlotMeta>>,
        repairs: &mut Vec<ShredRepairType>,
        max_new_shreds: usize,
        ignore_slots: &impl Contains<'a, Slot>,
    ) {
        let root_tree = self.trees.get(&self.root).expect("Root tree must exist");
        repair_weighted_traversal::get_best_repair_shreds(
            root_tree,
            blockstore,
            slot_meta_cache,
            repairs,
            max_new_shreds,
            ignore_slots,
        );
    }

    fn get_best_orphans(
        &mut self,
        blockstore: &Blockstore,
        processed_slots: &mut HashSet<Slot>,
        repairs: &mut Vec<ShredRepairType>,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
        max_new_orphans: usize,
    ) {
        // Sort each tree in `self.trees`, by the amount of stake that has voted on each,
        // tiebreaker going to earlier slots, thus prioritizing earlier slots on the same fork
        // to ensure replay can continue as soon as possible.
        let mut stake_weighted_trees: Vec<(Slot, u64)> = self
            .trees
            .iter()
            .map(|(slot, tree)| {
                (
                    *slot,
                    tree.stake_voted_subtree(&(*slot, Hash::default()))
                        .expect("Tree must have weight at its own root"),
                )
            })
            .collect();

        // Heavier, smaller slots come first
        Self::sort_by_stake_weight_slot(&mut stake_weighted_trees);
        let mut best_orphans: HashSet<Slot> = HashSet::new();
        for (heaviest_tree_root, _) in stake_weighted_trees {
            if best_orphans.len() >= max_new_orphans {
                break;
            }
            if processed_slots.contains(&heaviest_tree_root) {
                continue;
            }
            // Ignore trees that were merged in a previous iteration
            if self.trees.contains_key(&heaviest_tree_root) {
                let new_orphan_root = self.update_orphan_ancestors(
                    blockstore,
                    heaviest_tree_root,
                    epoch_stakes,
                    epoch_schedule,
                );
                if let Some(new_orphan_root) = new_orphan_root {
                    if new_orphan_root != self.root && !best_orphans.contains(&new_orphan_root) {
                        best_orphans.insert(new_orphan_root);
                        repairs.push(ShredRepairType::Orphan(new_orphan_root));
                        processed_slots.insert(new_orphan_root);
                    }
                }
            }
        }

        // If there are fewer than `max_new_orphans`, just grab the next
        // available ones
        if best_orphans.len() < max_new_orphans {
            for new_orphan in blockstore.orphans_iterator(self.root + 1).unwrap() {
                if !best_orphans.contains(&new_orphan) {
                    repairs.push(ShredRepairType::Orphan(new_orphan));
                    best_orphans.insert(new_orphan);
                    processed_slots.insert(new_orphan);
                }

                if best_orphans.len() == max_new_orphans {
                    break;
                }
            }
        }
    }

    /// For all remaining trees (orphan and rooted), generate repairs for slots missing last_index info
    /// prioritized by # shreds received.
    fn get_best_unknown_last_index(
        &mut self,
        blockstore: &Blockstore,
        slot_meta_cache: &mut HashMap<Slot, Option<SlotMeta>>,
        processed_slots: &mut HashSet<Slot>,
        max_new_repairs: usize,
    ) -> Vec<ShredRepairType> {
        let mut repairs = Vec::default();
        for (_slot, tree) in self.trees.iter() {
            if repairs.len() >= max_new_repairs {
                break;
            }
            let new_repairs = get_unknown_last_index(
                tree,
                blockstore,
                slot_meta_cache,
                processed_slots,
                max_new_repairs - repairs.len(),
            );
            repairs.extend(new_repairs);
        }
        repairs
    }

    /// For all remaining trees (orphan and rooted), generate repairs for subtrees that have last
    /// index info but are missing shreds prioritized by how close to completion they are. These
    /// repairs are also prioritized by age of ancestors, so slots close to completion will first
    /// start by repairing broken ancestors.
    fn get_best_closest_completion(
        &mut self,
        blockstore: &Blockstore,
        slot_meta_cache: &mut HashMap<Slot, Option<SlotMeta>>,
        processed_slots: &mut HashSet<Slot>,
        max_new_repairs: usize,
    ) -> Vec<ShredRepairType> {
        let mut repairs = Vec::default();
        for (_slot, tree) in self.trees.iter() {
            if repairs.len() >= max_new_repairs {
                break;
            }
            let new_repairs = get_closest_completion(
                tree,
                blockstore,
                slot_meta_cache,
                processed_slots,
                max_new_repairs - repairs.len(),
            );
            repairs.extend(new_repairs);
        }
        repairs
    }

    /// Attempts to chain the orphan subtree rooted at `orphan_tree_root`
    /// to any earlier subtree with new ancestry information in `blockstore`.
    /// Returns the earliest known ancestor of `heaviest_tree_root`.
    fn update_orphan_ancestors(
        &mut self,
        blockstore: &Blockstore,
        mut orphan_tree_root: Slot,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
    ) -> Option<Slot> {
        // Must only be called on existing orphan trees
        assert!(self.trees.contains_key(&orphan_tree_root));

        // Check blockstore for any new parents of the heaviest orphan tree. Attempt
        // to chain the orphan back to the main fork rooted at `self.root`.
        while orphan_tree_root != self.root {
            let (new_ancestors, parent_tree_root) =
                self.find_ancestor_subtree_of_slot(blockstore, orphan_tree_root);
            {
                let heaviest_tree = self
                    .trees
                    .get_mut(&orphan_tree_root)
                    .expect("Orphan must exist");

                // Skip the leaf of the parent tree that the orphan would merge
                // with later in a call to `merge_trees`
                let num_skip = usize::from(parent_tree_root.is_some());

                for ancestor in new_ancestors.iter().skip(num_skip).rev() {
                    // We temporarily use orphan_tree_root as the tree root and later
                    // rename tree root to either the parent_tree_root or the earliest_ancestor
                    self.slot_to_tree.insert(*ancestor, orphan_tree_root);
                    heaviest_tree.add_root_parent((*ancestor, Hash::default()));
                }
            }
            if let Some(parent_tree_root) = parent_tree_root {
                // If another subtree is discovered to be the parent
                // of this subtree, merge the two.
                self.merge_trees(
                    orphan_tree_root,
                    parent_tree_root,
                    *new_ancestors
                        .front()
                        .expect("Must exist leaf to merge to if `tree_to_merge`.is_some()"),
                    epoch_stakes,
                    epoch_schedule,
                );
                orphan_tree_root = parent_tree_root;
            } else {
                // If there's no other subtree to merge with, then return
                // the current known earliest ancestor of this branch
                if let Some(earliest_ancestor) = new_ancestors.front() {
                    let orphan_tree = self
                        .trees
                        .remove(&orphan_tree_root)
                        .expect("orphan tree must exist");
                    self.rename_tree_root(&orphan_tree, *earliest_ancestor);
                    assert!(self.trees.insert(*earliest_ancestor, orphan_tree).is_none());
                    orphan_tree_root = *earliest_ancestor;
                }
                break;
            }
        }

        if self.is_unrooted_slot(orphan_tree_root) {
            // If this orphan branch chained down to an unrooted
            // slot, then purge the entire subtree as we know the
            // entire subtree is unrooted
            let orphan_tree = self
                .trees
                .remove(&orphan_tree_root)
                .expect("Must exist, was found in `self.trees` above");
            self.remove_tree_slots(
                orphan_tree
                    .all_slots_stake_voted_subtree()
                    .map(|((slot, _), _)| slot),
                self.root,
            );
            None
        } else {
            // Return the (potentially new in the case of some merges)
            // root of this orphan subtree
            Some(orphan_tree_root)
        }
    }

    fn insert_new_tree(&mut self, new_tree_root: Slot) {
        assert!(!self.trees.contains_key(&new_tree_root));

        // Update `self.slot_to_tree`
        self.slot_to_tree.insert(new_tree_root, new_tree_root);
        self.trees.insert(
            new_tree_root,
            HeaviestSubtreeForkChoice::new((new_tree_root, Hash::default())),
        );
    }

    fn find_ancestor_subtree_of_slot(
        &self,
        blockstore: &Blockstore,
        slot: Slot,
    ) -> (VecDeque<Slot>, Option<Slot>) {
        let ancestors = AncestorIterator::new(slot, blockstore);
        let mut ancestors_to_add = VecDeque::new();
        let mut tree_to_merge = None;
        // This means `heaviest_tree_root` has not been
        // chained back to slots currently being replayed
        // in BankForks. Try to see if blockstore has sufficient
        // information to link this slot back
        for a in ancestors {
            ancestors_to_add.push_front(a);
            // If this tree chains to some unrooted fork, purge it
            if self.is_unrooted_slot(a) {
                break;
            }
            // If an ancestor chains back to another subtree, then return
            let other_tree_root = self.slot_to_tree.get(&a).cloned();
            tree_to_merge = other_tree_root;
            if tree_to_merge.is_some() {
                break;
            }
        }

        (ancestors_to_add, tree_to_merge)
    }

    fn is_unrooted_slot(&self, slot: Slot) -> bool {
        slot < self.root || self.unrooted_slots.contains(&slot)
    }

    // Attaches `tree1` rooted at `root1` to `tree2` rooted at `root2`
    // at the leaf in `tree2` given by `merge_leaf`
    fn merge_trees(
        &mut self,
        root1: Slot,
        root2: Slot,
        merge_leaf: Slot,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
    ) {
        // Update self.slot_to_tree to reflect the merge
        let tree1 = self.trees.remove(&root1).expect("tree to merge must exist");
        self.rename_tree_root(&tree1, root2);

        // Merge trees
        let tree2 = self
            .trees
            .get_mut(&root2)
            .expect("tree to be merged into must exist");

        tree2.merge(
            tree1,
            &(merge_leaf, Hash::default()),
            epoch_stakes,
            epoch_schedule,
        );
    }

    // Update all slots in the `tree1` to point to `root2`,
    fn rename_tree_root(&mut self, tree1: &HeaviestSubtreeForkChoice, root2: Slot) {
        let all_slots = tree1.all_slots_stake_voted_subtree();
        for ((slot, _), _) in all_slots {
            *self
                .slot_to_tree
                .get_mut(slot)
                .expect("Nodes in tree must exist in `self.slot_to_tree`") = root2;
        }
    }

    // For all slots `s` in `tree1`
    // 1) If `s` < min, purge `s` from `self.slot_to_tree`
    // 2) Else add `s` to `self.unrooted_slots`
    fn remove_tree_slots<'a, I>(&'a mut self, slots_to_remove: I, min: Slot)
    where
        I: Iterator<Item = &'a Slot>,
    {
        for slot in slots_to_remove {
            self.slot_to_tree
                .remove(slot)
                .expect("Item in tree must exist in `slot_to_tree`");
            if *slot >= min {
                self.unrooted_slots.insert(*slot);
            }
        }
    }

    // Heavier, smaller slots come first
    fn sort_by_stake_weight_slot(slot_stake_voted: &mut [(Slot, u64)]) {
        slot_stake_voted.sort_by(|(slot, stake_voted), (slot_, stake_voted_)| {
            if stake_voted == stake_voted_ {
                slot.cmp(slot_)
            } else {
                stake_voted.cmp(stake_voted_).reverse()
            }
        });
    }
}
