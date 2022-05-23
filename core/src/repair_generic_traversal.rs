use {
    crate::{
        heaviest_subtree_fork_choice::HeaviestSubtreeForkChoice, repair_service::RepairService,
        serve_repair::ShredRepairType, tree_diff::TreeDiff,
    },
    solana_ledger::{blockstore::Blockstore, blockstore_meta::SlotMeta},
    solana_sdk::{clock::Slot, hash::Hash},
    std::collections::{HashMap, HashSet},
};

struct GenericTraversal<'a> {
    tree: &'a HeaviestSubtreeForkChoice,
    pending: Vec<Slot>,
}

impl<'a> GenericTraversal<'a> {
    pub fn new(tree: &'a HeaviestSubtreeForkChoice) -> Self {
        Self {
            tree,
            pending: vec![tree.root().0],
        }
    }
}

impl<'a> Iterator for GenericTraversal<'a> {
    type Item = Slot;
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.pending.pop();
        if let Some(slot) = next {
            let children: Vec<_> = self
                .tree
                .children(&(slot, Hash::default()))
                .unwrap()
                .iter()
                .map(|(child_slot, _)| *child_slot)
                .collect();
            self.pending.extend(children);
        }
        next
    }
}

pub fn get_unknown_last_index(
    tree: &HeaviestSubtreeForkChoice,
    blockstore: &Blockstore,
    slot_meta_cache: &mut HashMap<Slot, Option<SlotMeta>>,
    processed_slots: &mut HashSet<Slot>,
    limit: usize,
) -> Vec<ShredRepairType> {
    let iter = GenericTraversal::new(tree);
    let mut unknown_last = Vec::new();
    for slot in iter {
        if processed_slots.contains(&slot) {
            continue;
        }
        let slot_meta = slot_meta_cache
            .entry(slot)
            .or_insert_with(|| blockstore.meta(slot).unwrap());
        if let Some(slot_meta) = slot_meta {
            if slot_meta.last_index.is_none() {
                let shred_index = blockstore.get_index(slot).unwrap();
                let num_processed_shreds = if let Some(shred_index) = shred_index {
                    shred_index.data().num_shreds() as u64
                } else {
                    slot_meta.consumed
                };
                unknown_last.push((slot, slot_meta.received, num_processed_shreds));
                processed_slots.insert(slot);
            }
        }
    }
    // prioritize slots with more received shreds
    unknown_last.sort_by(|(_, _, count1), (_, _, count2)| count2.cmp(count1));
    unknown_last
        .iter()
        .take(limit)
        .map(|(slot, received, _)| ShredRepairType::HighestShred(*slot, *received))
        .collect()
}

fn get_unrepaired_path(
    start_slot: Slot,
    blockstore: &Blockstore,
    slot_meta_cache: &mut HashMap<Slot, Option<SlotMeta>>,
    visited: &mut HashSet<Slot>,
) -> Vec<Slot> {
    let mut path = Vec::new();
    let mut slot = start_slot;
    while visited.insert(slot) {
        let slot_meta = slot_meta_cache
            .entry(slot)
            .or_insert_with(|| blockstore.meta(slot).unwrap());
        if let Some(slot_meta) = slot_meta {
            if !slot_meta.is_full() {
                path.push(slot);
                if let Some(parent_slot) = slot_meta.parent_slot {
                    slot = parent_slot
                }
            }
        }
    }
    path.reverse();
    path
}

pub fn get_closest_completion(
    tree: &HeaviestSubtreeForkChoice,
    blockstore: &Blockstore,
    slot_meta_cache: &mut HashMap<Slot, Option<SlotMeta>>,
    processed_slots: &mut HashSet<Slot>,
    limit: usize,
) -> Vec<ShredRepairType> {
    let mut v: Vec<(Slot, u64)> = Vec::default();
    let iter = GenericTraversal::new(tree);
    for slot in iter {
        if processed_slots.contains(&slot) {
            continue;
        }
        let slot_meta = slot_meta_cache
            .entry(slot)
            .or_insert_with(|| blockstore.meta(slot).unwrap());
        if let Some(slot_meta) = slot_meta {
            if slot_meta.is_full() {
                continue;
            }
            if let Some(last_index) = slot_meta.last_index {
                let shred_index = blockstore.get_index(slot).unwrap();
                let dist = if let Some(shred_index) = shred_index {
                    let shred_count = shred_index.data().num_shreds() as u64;
                    if last_index.saturating_add(1) < shred_count {
                        datapoint_error!(
                            "repair_generic_traversal_error",
                            (
                                "error",
                                format!(
                                    "last_index + 1 < shred_count. last_index={} shred_count={}",
                                    last_index, shred_count,
                                ),
                                String
                            ),
                        );
                    }
                    last_index.saturating_add(1).saturating_sub(shred_count)
                } else {
                    if last_index < slot_meta.consumed {
                        datapoint_error!(
                            "repair_generic_traversal_error",
                            (
                                "error",
                                format!(
                                    "last_index < slot_meta.consumed. last_index={} slot_meta.consumed={}",
                                    last_index,
                                    slot_meta.consumed,
                                ),
                                String
                            ),
                        );
                    }
                    last_index.saturating_sub(slot_meta.consumed)
                };
                v.push((slot, dist));
                processed_slots.insert(slot);
            }
        }
    }
    v.sort_by(|(_, d1), (_, d2)| d1.cmp(d2));

    let mut visited = HashSet::new();
    let mut repairs = Vec::new();
    for (slot, _) in v {
        if repairs.len() >= limit {
            break;
        }
        // attempt to repair heaviest slots starting with their parents
        let path = get_unrepaired_path(slot, blockstore, slot_meta_cache, &mut visited);
        for slot in path {
            if repairs.len() >= limit {
                break;
            }
            let slot_meta = slot_meta_cache.get(&slot).unwrap().as_ref().unwrap();
            let new_repairs = RepairService::generate_repairs_for_slot(
                blockstore,
                slot,
                slot_meta,
                limit - repairs.len(),
            );
            repairs.extend(new_repairs);
        }
    }

    repairs
}

