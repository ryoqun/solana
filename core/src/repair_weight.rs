use {
    crate::{
        heaviest_subtree_fork_choice::HeaviestSubtreeForkChoice,
        repair_generic_traversal::{get_closest_completion, get_unknown_last_index},
        repair_service::{BestRepairsStats, RepairTiming},
        repair_weighted_traversal,
        serve_repair::ShredRepairType,
    },
    solana_ledger::{
        ancestor_iterator::AncestorIterator, blockstore::Blockstore, blockstore_meta::SlotMeta,
    },
    solana_measure::measure::Measure,
    solana_runtime::epoch_stakes::EpochStakes,
    solana_sdk::{
        clock::Slot,
        epoch_schedule::{Epoch, EpochSchedule},
        hash::Hash,
        pubkey::Pubkey,
    },
    std::{
        collections::{HashMap, HashSet, VecDeque},
        iter,
    },
};

#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
enum TreeRoot {
    Root(Slot),
    PrunedRoot(Slot),
}

impl TreeRoot {
    pub fn is_pruned(&self) -> bool {
        matches!(self, Self::PrunedRoot(_))
    }
}

impl From<TreeRoot> for Slot {
    fn from(val: TreeRoot) -> Self {
        match val {
            TreeRoot::Root(slot) => slot,
            TreeRoot::PrunedRoot(slot) => slot,
        }
    }
}
pub struct RepairWeight {
    // Map from root -> a subtree rooted at that `root`
    trees: HashMap<Slot, HeaviestSubtreeForkChoice>,
    // Map from root -> pruned subtree
    // We manage the size by removing slots < root
    pruned_trees: HashMap<Slot, HeaviestSubtreeForkChoice>,

    // Maps each slot to the root of the tree that contains it
    slot_to_tree: HashMap<Slot, TreeRoot>,
    root: Slot,
}

impl RepairWeight {
    pub fn new(root: Slot) -> Self {
        let root_tree = HeaviestSubtreeForkChoice::new((root, Hash::default()));
        let slot_to_tree = HashMap::from([(root, TreeRoot::Root(root))]);
        let trees = HashMap::from([(root, root_tree)]);
        Self {
            trees,
            slot_to_tree,
            root,
            pruned_trees: HashMap::new(),
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
        let mut all_subtree_updates: HashMap<TreeRoot, HashMap<Pubkey, Slot>> = HashMap::new();
        for (slot, pubkey_votes) in votes {
            if slot < self.root {
                continue;
            }
            let mut tree_root = self.get_tree_root(slot);
            let mut new_ancestors = VecDeque::new();
            // If we don't know know  how this slot chains to any existing trees
            // in `self.trees` or `self.pruned_trees`, then use `blockstore` to see if this chains
            // any existing trees in `self.trees`
            if tree_root.is_none() {
                let (discovered_ancestors, existing_subtree_root) =
                    self.find_ancestor_subtree_of_slot(blockstore, slot);
                new_ancestors = discovered_ancestors;
                tree_root = existing_subtree_root;
            }

            let (tree_root, tree) = {
                match (tree_root, *new_ancestors.front().unwrap_or(&slot)) {
                    (Some(tree_root), _) if !tree_root.is_pruned() => (
                        tree_root,
                        self.trees
                            .get_mut(&tree_root.into())
                            .expect("If tree root was found, it must exist in `self.trees`"),
                    ),
                    (Some(tree_root), _) => (
                        tree_root,
                        self.pruned_trees.get_mut(&tree_root.into()).expect(
                            "If a pruned tree root was found, it must exist in `self.pruned_trees`",
                        ),
                    ),
                    (None, earliest_ancestor) => {
                        // There is no known subtree that contains `slot`. Thus, create a new
                        // subtree rooted at the earliest known ancestor of `slot`.
                        // If this earliest known ancestor is not part of the rooted path, create a new
                        // pruned tree from the ancestor that is `> self.root` instead.
                        if earliest_ancestor < self.root {
                            // If the next ancestor exists, it is guaranteed to be `> self.root` because
                            // `find_ancestor_subtree_of_slot` can return at max one ancestor `<
                            // self.root`.
                            let next_earliest_ancestor = *new_ancestors.get(1).unwrap_or(&slot);
                            assert!(next_earliest_ancestor > self.root);
                            // We also guarantee that next_earliest_ancestor does not
                            // already exist as a pruned tree (pre condition for inserting a new
                            // pruned tree) otherwise `tree_root` would not be None.
                            self.insert_new_pruned_tree(next_earliest_ancestor);
                            // Remove `earliest_ancestor` as it should not be added to the tree (we
                            // maintain the invariant that the tree only contains slots >=
                            // `self.root` by checking before `add_new_leaf_slot` and `set_root`)
                            assert_eq!(Some(earliest_ancestor), new_ancestors.pop_front());
                            (
                                TreeRoot::PrunedRoot(next_earliest_ancestor),
                                self.pruned_trees.get_mut(&next_earliest_ancestor).unwrap(),
                            )
                        } else {
                            // We guarantee that `earliest_ancestor` does not already exist in
                            // `self.trees` otherwise `tree_root` would not be None
                            self.insert_new_tree(earliest_ancestor);
                            (
                                TreeRoot::Root(earliest_ancestor),
                                self.trees.get_mut(&earliest_ancestor).unwrap(),
                            )
                        }
                    }
                }
            };

            // First element in `ancestors` must be either:
            // 1) Leaf of some existing subtree
            // 2) Root of new subtree that was just created above through `self.insert_new_tree` or
            //    `self.insert_new_pruned_tree`
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
                .get_tree(&tree_root)
                .expect("Tree for `tree_root` must exist here");
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
    pub fn get_best_weighted_repairs(
        &mut self,
        blockstore: &Blockstore,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
        max_new_orphans: usize,
        max_new_shreds: usize,
        max_unknown_last_index_repairs: usize,
        max_closest_completion_repairs: usize,
        repair_timing: &mut RepairTiming,
        stats: &mut BestRepairsStats,
    ) -> Vec<ShredRepairType> {
        let mut repairs = vec![];
        let mut processed_slots = HashSet::from([self.root]);
        let mut slot_meta_cache = HashMap::default();

        let mut get_best_orphans_elapsed = Measure::start("get_best_orphans");
        // Find the best orphans in order from heaviest stake to least heavy
        self.get_best_orphans(
            blockstore,
            &mut processed_slots,
            &mut repairs,
            epoch_stakes,
            epoch_schedule,
            max_new_orphans,
        );
        // Subtract 1 because the root is not processed as an orphan
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
        let (closest_completion_repairs, total_slots_processed) = self.get_best_closest_completion(
            blockstore,
            &mut slot_meta_cache,
            &mut processed_slots,
            max_closest_completion_repairs,
        );
        let num_closest_completion_repairs = closest_completion_repairs.len();
        let num_closest_completion_slots = processed_slots.len() - pre_num_slots;
        let num_closest_completion_slots_path =
            total_slots_processed.saturating_sub(num_closest_completion_slots);
        repairs.extend(closest_completion_repairs);
        get_closest_completion_elapsed.stop();

        stats.update(
            num_orphan_slots as u64,
            num_orphan_repairs as u64,
            num_best_shreds_slots as u64,
            num_best_shreds_repairs as u64,
            num_unknown_last_index_slots as u64,
            num_unknown_last_index_repairs as u64,
            num_closest_completion_slots as u64,
            num_closest_completion_slots_path as u64,
            num_closest_completion_repairs as u64,
            self.trees.len() as u64,
        );
        repair_timing.get_best_orphans_elapsed += get_best_orphans_elapsed.as_us();
        repair_timing.get_best_shreds_elapsed += get_best_shreds_elapsed.as_us();
        repair_timing.get_unknown_last_index_elapsed += get_unknown_last_index_elapsed.as_us();
        repair_timing.get_closest_completion_elapsed += get_closest_completion_elapsed.as_us();

        repairs
    }

    /// Split `slot` and descendants into an orphan tree in repair weighting.
    ///
    /// If repair holds a subtree `ST` which contains `slot`, we split `ST` into `(T, T')` where `T'` is
    /// a subtree rooted at `slot` and `T` is what remains (if anything) of `ST` after the split.
    /// If `T` is non-empty, it is inserted back into the set which held the original `ST`
    /// (self.trees for potentially rootable trees, or self.pruned_trees for pruned trees).
    /// `T'` is always inserted into the potentially rootable set `self.trees`.
    /// This function removes and destroys the original `ST`.
    ///
    /// Assumes that `slot` is greater than `self.root`.
    pub fn split_off(&mut self, slot: Slot) {
        assert!(slot >= self.root);
        if slot == self.root {
            error!("Trying to orphan root of repair tree {}", slot);
            return;
        }
        match self.slot_to_tree.get(&slot).copied() {
            Some(TreeRoot::Root(subtree_root)) => {
                if subtree_root == slot {
                    info!("{} is already orphan, skipping", slot);
                    return;
                }
                let subtree = self
                    .trees
                    .get_mut(&subtree_root)
                    .expect("`self.slot_to_tree` and `self.trees` must be in sync");
                let orphaned_tree = subtree.split_off(&(slot, Hash::default()));
                self.rename_tree_root(&orphaned_tree, TreeRoot::Root(slot));
                self.trees.insert(slot, orphaned_tree);
            }
            Some(TreeRoot::PrunedRoot(subtree_root)) => {
                // Even if these orphaned slots were previously pruned, they should be added back to
                // `self.trees` as we are no longer sure of their ancestory.
                // After they are repaired there is a chance that they  are now part of the rooted path.
                // This is possible for a duplicate slot with multiple ancestors, if the
                // version we had pruned before had the wrong ancestor, and the correct version is
                // descended from the rooted path.
                // If not they will once again be attached to the pruned set in
                // `update_orphan_ancestors`.

                info!(
                    "Dumping pruned slot {} of tree {} in repair",
                    slot, subtree_root
                );
                let mut subtree = self
                    .pruned_trees
                    .remove(&subtree_root)
                    .expect("`self.slot_to_tree` and `self.pruned_trees` must be in sync");

                if subtree_root == slot {
                    // In this case we simply unprune the entire subtree by adding this subtree
                    // back into the main set of trees, self.trees
                    self.rename_tree_root(&subtree, TreeRoot::Root(subtree_root));
                    self.trees.insert(subtree_root, subtree);
                } else {
                    let orphaned_tree = subtree.split_off(&(slot, Hash::default()));
                    self.pruned_trees.insert(subtree_root, subtree);
                    self.rename_tree_root(&orphaned_tree, TreeRoot::Root(slot));
                    self.trees.insert(slot, orphaned_tree);
                }
            }
            None => {
                warn!(
                    "Trying to split off slot {} which doesn't currently exist in repair",
                    slot
                );
            }
        }
    }

    pub fn set_root(&mut self, new_root: Slot) {
        // Roots should be monotonically increasing
        assert!(self.root <= new_root);

        if new_root == self.root {
            return;
        }

        // Root slot of the tree that contains `new_root`, if one exists
        let new_root_tree_root = self
            .slot_to_tree
            .get(&new_root)
            .copied()
            .map(|root| match root {
                TreeRoot::Root(r) => r,
                TreeRoot::PrunedRoot(r) => {
                    panic!("New root {new_root} chains to a pruned tree with root {r}")
                }
            });

        // Purge outdated trees from `self.trees`
        // These are all subtrees that have a `tree_root` < `new_root` and are not part of the
        // rooted subtree
        let subtrees_to_purge: Vec<_> = self
            .trees
            .keys()
            .filter(|subtree_root| {
                **subtree_root < new_root
                    && new_root_tree_root
                        .map(|new_root_tree_root| **subtree_root != new_root_tree_root)
                        .unwrap_or(true)
            })
            .copied()
            .collect();
        for subtree_root in subtrees_to_purge {
            let subtree = self
                .trees
                .remove(&subtree_root)
                .expect("Must exist, was found in `self.trees` above");

            // Track these trees as part of the pruned set
            self.rename_tree_root(&subtree, TreeRoot::PrunedRoot(subtree_root));
            self.pruned_trees.insert(subtree_root, subtree);
        }

        if let Some(new_root_tree_root) = new_root_tree_root {
            let mut new_root_tree = self
                .trees
                .remove(&new_root_tree_root)
                .expect("Found slot root earlier in self.slot_to_trees, tree must exist");

            // Find all descendants of `self.root` that are not reachable from `new_root`.
            // Prune these out and add to `self.pruned_trees`
            trace!("pruning tree {} with {}", new_root_tree_root, new_root);
            let (removed, pruned) = new_root_tree.purge_prune((new_root, Hash::default()));
            for pruned_tree in pruned {
                let pruned_tree_root = pruned_tree.tree_root().0;
                self.rename_tree_root(&pruned_tree, TreeRoot::PrunedRoot(pruned_tree_root));
                self.pruned_trees.insert(pruned_tree_root, pruned_tree);
            }

            for (slot, _) in removed {
                self.slot_to_tree.remove(&slot);
            }

            // Update `self.slot_to_tree` to reflect new root
            new_root_tree.set_tree_root((new_root, Hash::default()));
            self.rename_tree_root(&new_root_tree, TreeRoot::Root(new_root));

            // Insert the tree for the new root
            self.trees.insert(new_root, new_root_tree);
        } else {
            // Guaranteed that `new_root` is not part of `self.trees` because `new_root_tree_root`
            // is None
            self.insert_new_tree(new_root);
        }

        // Clean up the pruned set by trimming slots that are less than `new_root` and removing
        // empty trees
        self.pruned_trees = self
            .pruned_trees
            .drain()
            .flat_map(|(tree_root, mut pruned_tree)| {
                if tree_root < new_root {
                    trace!("pruning tree {} with {}", tree_root, new_root);
                    let (removed, pruned) = pruned_tree.purge_prune((new_root, Hash::default()));
                    for (slot, _) in removed {
                        self.slot_to_tree.remove(&slot);
                    }
                    pruned
                        .into_iter()
                        .chain(iter::once(pruned_tree)) // Add back the original pruned tree
                        .filter(|pruned_tree| !pruned_tree.is_empty()) // Clean up empty trees
                        .map(|new_pruned_subtree| {
                            let new_pruned_tree_root = new_pruned_subtree.tree_root().0;
                            // Resync `self.slot_to_tree`
                            for ((slot, _), _) in new_pruned_subtree.all_slots_stake_voted_subtree()
                            {
                                *self.slot_to_tree.get_mut(slot).unwrap() =
                                    TreeRoot::PrunedRoot(new_pruned_tree_root);
                            }
                            (new_pruned_tree_root, new_pruned_subtree)
                        })
                        .collect()
                } else {
                    vec![(tree_root, pruned_tree)]
                }
            })
            .collect::<HashMap<u64, HeaviestSubtreeForkChoice>>();
        self.root = new_root;
    }

    pub fn root(&self) -> Slot {
        self.root
    }

    // Generate shred repairs for main subtree rooted at `self.root`
    fn get_best_shreds(
        &mut self,
        blockstore: &Blockstore,
        slot_meta_cache: &mut HashMap<Slot, Option<SlotMeta>>,
        repairs: &mut Vec<ShredRepairType>,
        max_new_shreds: usize,
    ) {
        let root_tree = self.trees.get(&self.root).expect("Root tree must exist");
        repair_weighted_traversal::get_best_repair_shreds(
            root_tree,
            blockstore,
            slot_meta_cache,
            repairs,
            max_new_shreds,
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
    ) -> (Vec<ShredRepairType>, /* processed slots */ usize) {
        let mut repairs = Vec::default();
        let mut total_processed_slots = 0;
        for (_slot, tree) in self.trees.iter() {
            if repairs.len() >= max_new_repairs {
                break;
            }
            let (new_repairs, new_processed_slots) = get_closest_completion(
                tree,
                blockstore,
                self.root,
                slot_meta_cache,
                processed_slots,
                max_new_repairs - repairs.len(),
            );
            repairs.extend(new_repairs);
            total_processed_slots += new_processed_slots;
        }
        (repairs, total_processed_slots)
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
                    if *ancestor >= self.root {
                        self.slot_to_tree
                            .insert(*ancestor, TreeRoot::Root(orphan_tree_root));
                        heaviest_tree.add_root_parent((*ancestor, Hash::default()));
                    }
                }
            }
            if let Some(parent_tree_root) = parent_tree_root {
                // If another subtree is discovered to be the parent
                // of this subtree, merge the two.
                self.merge_trees(
                    TreeRoot::Root(orphan_tree_root),
                    parent_tree_root,
                    *new_ancestors
                        .front()
                        .expect("Must exist leaf to merge to if `tree_to_merge`.is_some()"),
                    epoch_stakes,
                    epoch_schedule,
                );
                if let TreeRoot::Root(parent_tree_root) = parent_tree_root {
                    orphan_tree_root = parent_tree_root;
                } else {
                    // This orphan is now part of a pruned tree, no need to chain further
                    return None;
                }
            } else {
                // If there's no other subtree to merge with, then return
                // the current known earliest ancestor of this branch
                if let Some(earliest_ancestor) = new_ancestors.front() {
                    assert!(*earliest_ancestor != self.root); // In this case we would merge above
                    let orphan_tree = self
                        .trees
                        .remove(&orphan_tree_root)
                        .expect("orphan tree must exist");
                    if *earliest_ancestor > self.root {
                        self.rename_tree_root(&orphan_tree, TreeRoot::Root(*earliest_ancestor));
                        assert!(self.trees.insert(*earliest_ancestor, orphan_tree).is_none());
                        orphan_tree_root = *earliest_ancestor;
                    } else {
                        // In this case we should create a new pruned subtree
                        let next_earliest_ancestor =
                            new_ancestors.get(1).unwrap_or(&orphan_tree_root);
                        self.rename_tree_root(
                            &orphan_tree,
                            TreeRoot::PrunedRoot(*next_earliest_ancestor),
                        );
                        assert!(self
                            .pruned_trees
                            .insert(*next_earliest_ancestor, orphan_tree)
                            .is_none());
                        return None;
                    }
                }
                break;
            }
        }

        // Return the (potentially new in the case of some merges)
        // root of this orphan subtree
        Some(orphan_tree_root)
    }

    fn get_tree(&mut self, tree_root: &TreeRoot) -> Option<&mut HeaviestSubtreeForkChoice> {
        match tree_root {
            TreeRoot::Root(r) => self.trees.get_mut(r),
            TreeRoot::PrunedRoot(r) => self.pruned_trees.get_mut(r),
        }
    }

    fn remove_tree(&mut self, tree_root: &TreeRoot) -> Option<HeaviestSubtreeForkChoice> {
        match tree_root {
            TreeRoot::Root(r) => self.trees.remove(r),
            TreeRoot::PrunedRoot(r) => self.pruned_trees.remove(r),
        }
    }

    fn get_tree_root(&self, slot: Slot) -> Option<TreeRoot> {
        self.slot_to_tree.get(&slot).copied()
    }

    /// Assumes that `new_tree_root` does not already exist in `self.trees`
    fn insert_new_tree(&mut self, new_tree_root: Slot) {
        assert!(!self.trees.contains_key(&new_tree_root));

        // Update `self.slot_to_tree`
        self.slot_to_tree
            .insert(new_tree_root, TreeRoot::Root(new_tree_root));
        self.trees.insert(
            new_tree_root,
            HeaviestSubtreeForkChoice::new((new_tree_root, Hash::default())),
        );
    }

    /// Assumes that `new_pruned_tree_root` does not already exist in `self.pruned_trees`
    fn insert_new_pruned_tree(&mut self, new_pruned_tree_root: Slot) {
        assert!(!self.pruned_trees.contains_key(&new_pruned_tree_root));

        // Update `self.slot_to_tree`
        self.slot_to_tree.insert(
            new_pruned_tree_root,
            TreeRoot::PrunedRoot(new_pruned_tree_root),
        );
        self.pruned_trees.insert(
            new_pruned_tree_root,
            HeaviestSubtreeForkChoice::new((new_pruned_tree_root, Hash::default())),
        );
    }

    /// Finds any ancestors avaiable from `blockstore` for `slot`.
    /// Ancestor search is stopped when finding one that chains to any
    /// tree in `self.trees` or `self.pruned_trees` or if the ancestor is < self.root.
    ///
    /// Returns ancestors (including the one that triggered the search stop condition),
    /// and possibly the tree_root that `slot` belongs to
    fn find_ancestor_subtree_of_slot(
        &self,
        blockstore: &Blockstore,
        slot: Slot,
    ) -> (VecDeque<Slot>, Option<TreeRoot>) {
        let ancestors = AncestorIterator::new(slot, blockstore);
        let mut ancestors_to_add = VecDeque::new();
        let mut tree = None;
        // This means `heaviest_tree_root` has not been
        // chained back to slots currently being replayed
        // in BankForks. Try to see if blockstore has sufficient
        // information to link this slot back
        for a in ancestors {
            ancestors_to_add.push_front(a);
            // If an ancestor chains back to another subtree or pruned, then return
            tree = self.get_tree_root(a);
            if tree.is_some() || a < self.root {
                break;
            }
        }

        (ancestors_to_add, tree)
    }

    /// Attaches `tree1` rooted at `root1` to `tree2` rooted at `root2`
    /// at the leaf in `tree2` given by `merge_leaf`
    /// Expects `root1` and `root2` to exist in `self.trees` or `self.pruned_trees`
    fn merge_trees(
        &mut self,
        root1: TreeRoot,
        root2: TreeRoot,
        merge_leaf: Slot,
        epoch_stakes: &HashMap<Epoch, EpochStakes>,
        epoch_schedule: &EpochSchedule,
    ) {
        // Update self.slot_to_tree to reflect the merge
        let tree1 = self.remove_tree(&root1).expect("tree to merge must exist");
        self.rename_tree_root(&tree1, root2);

        // Merge trees
        let tree2 = self
            .get_tree(&root2)
            .expect("tree to be merged into must exist");

        tree2.merge(
            tree1,
            &(merge_leaf, Hash::default()),
            epoch_stakes,
            epoch_schedule,
        );
    }

    // Update all slots in the `tree1` to point to `root2`,
    fn rename_tree_root(&mut self, tree1: &HeaviestSubtreeForkChoice, root2: TreeRoot) {
        let all_slots = tree1.all_slots_stake_voted_subtree();
        for ((slot, _), _) in all_slots {
            *self
                .slot_to_tree
                .get_mut(slot)
                .expect("Nodes in tree must exist in `self.slot_to_tree`") = root2;
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
