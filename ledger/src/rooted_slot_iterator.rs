use {
    crate::{blockstore::*, blockstore_db::Result, blockstore_meta::SlotMeta},
    log::*,
    solana_sdk::clock::Slot,
};

pub struct RootedSlotIterator<'a> {
    next_slots: Vec<Slot>,
    prev_root: Slot,
    blockstore: &'a Blockstore,
}

impl<'a> RootedSlotIterator<'a> {
    pub fn new(start_slot: Slot, blockstore: &'a Blockstore) -> Result<Self> {
        if blockstore.is_root(start_slot) {
            Ok(Self {
                next_slots: vec![start_slot],
                prev_root: start_slot,
                blockstore,
            })
        } else {
            Err(BlockstoreError::SlotNotRooted)
        }
    }
}
impl<'a> Iterator for RootedSlotIterator<'a> {
    type Item = (Slot, Option<SlotMeta>);

    fn next(&mut self) -> Option<Self::Item> {
        // Clone b/c passing the closure to the map below requires exclusive access to
        // `self`, which is borrowed here if we don't clone.
        let (rooted_slot, slot_skipped) = self
            .next_slots
            .iter()
            .find(|x| self.blockstore.is_root(**x))
            .map(|x| (Some(*x), false))
            .unwrap_or_else(|| {
                let mut iter = self
                    .blockstore
                    .rooted_slot_iterator(
                        // First iteration the root always exists as guaranteed by the constructor,
                        // so this unwrap_or_else cases won't be hit. Every subsequent iteration
                        // of this iterator must thereafter have a valid `prev_root`
                        self.prev_root,
                    )
                    .expect("Database failure, couldn't fetch rooted slots iterator");
                iter.next();
                (iter.next(), true)
            });

        let slot_meta = rooted_slot
            .map(|r| {
                self.blockstore
                    .meta(r)
                    .expect("Database failure, couldn't fetch SlotMeta")
            })
            .unwrap_or(None);

        if let Some(ref slot_meta) = slot_meta {
            self.next_slots = slot_meta.next_slots.clone();
        }

        if slot_meta.is_none() && slot_skipped {
            warn!("Rooted SlotMeta was deleted in between checking is_root and fetch");
        }

        rooted_slot.map(|r| {
            self.prev_root = r;
            if slot_skipped {
                (r, None)
            } else {
                (r, slot_meta)
            }
        })
    }
}
