use {
    crate::{
        heaviest_subtree_fork_choice::HeaviestSubtreeForkChoice, repair_service::RepairService,
        serve_repair::ShredRepairType, tree_diff::TreeDiff,
    },
    solana_ledger::{blockstore::Blockstore, blockstore_meta::SlotMeta},
    solana_sdk::{clock::Slot, hash::Hash},
    std::collections::{HashMap, HashSet},
};

#[derive(Debug, PartialEq, Eq)]
enum Visit {
    Visited(Slot),
    Unvisited(Slot),
}

impl Visit {
    pub fn slot(&self) -> Slot {
        match self {
            Visit::Visited(slot) => *slot,
            Visit::Unvisited(slot) => *slot,
        }
    }
}

// Iterates through slots in order of weight
struct RepairWeightTraversal<'a> {
    tree: &'a HeaviestSubtreeForkChoice,
    pending: Vec<Visit>,
}

impl<'a> RepairWeightTraversal<'a> {
    fn new(tree: &'a HeaviestSubtreeForkChoice) -> Self {
        Self {
            tree,
            pending: vec![Visit::Unvisited(tree.tree_root().0)],
        }
    }
}

impl<'a> Iterator for RepairWeightTraversal<'a> {
    type Item = Visit;
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.pending.pop();
        next.map(|next| {
            if let Visit::Unvisited(slot) = next {
                // Add a bookmark to communicate all child
                // slots have been visited
                self.pending.push(Visit::Visited(slot));
                let mut children: Vec<_> = self
                    .tree
                    .children(&(slot, Hash::default()))
                    .unwrap()
                    .map(|(child_slot, _)| Visit::Unvisited(*child_slot))
                    .collect();

                // Sort children by weight to prioritize visiting the heaviest
                // ones first
                children.sort_by(|slot1, slot2| {
                    self.tree.max_by_weight(
                        (slot1.slot(), Hash::default()),
                        (slot2.slot(), Hash::default()),
                    )
                });
                self.pending.extend(children);
            }
            next
        })
    }
}

/// Generate shred repairs for `tree` starting at `tree.root`.
/// Prioritized by stake weight, additionally considers children not present in `tree` but in
/// blockstore.
pub fn get_best_repair_shreds(
    tree: &HeaviestSubtreeForkChoice,
    blockstore: &Blockstore,
    slot_meta_cache: &mut HashMap<Slot, Option<SlotMeta>>,
    repairs: &mut Vec<ShredRepairType>,
    max_new_shreds: usize,
) {
    let initial_len = repairs.len();
    let max_repairs = initial_len + max_new_shreds;
    let weighted_iter = RepairWeightTraversal::new(tree);
    let mut visited_set = HashSet::new();
    for next in weighted_iter {
        if repairs.len() > max_repairs {
            break;
        }

        let slot_meta = slot_meta_cache
            .entry(next.slot())
            .or_insert_with(|| blockstore.meta(next.slot()).unwrap());

        // May not exist if blockstore purged the SlotMeta due to something
        // like duplicate slots. TODO: Account for duplicate slot may be in orphans, especially
        // if earlier duplicate was already removed
        if let Some(slot_meta) = slot_meta {
            match next {
                Visit::Unvisited(slot) => {
                    let new_repairs = RepairService::generate_repairs_for_slot(
                        blockstore,
                        slot,
                        slot_meta,
                        max_repairs - repairs.len(),
                    );
                    repairs.extend(new_repairs);
                    visited_set.insert(slot);
                }
                Visit::Visited(_) => {
                    // By the time we reach here, this means all the children of this slot
                    // have been explored/repaired. Although this slot has already been visited,
                    // this slot is still the heaviest slot left in the traversal. Thus any
                    // remaining children that have not been explored should now be repaired.
                    for new_child_slot in &slot_meta.next_slots {
                        // If the `new_child_slot` has not been visited by now, it must
                        // not exist in `tree`
                        if !visited_set.contains(new_child_slot) {
                            // Generate repairs for entire subtree rooted at `new_child_slot`
                            RepairService::generate_repairs_for_fork(
                                blockstore,
                                repairs,
                                max_repairs,
                                *new_child_slot,
                            );
                        }
                        visited_set.insert(*new_child_slot);
                    }
                }
            }
        }
    }
}
