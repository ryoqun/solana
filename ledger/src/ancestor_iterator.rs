use {
    crate::blockstore::*,
    solana_sdk::{clock::Slot, hash::Hash},
};

pub struct AncestorIterator<'a> {
    current: Option<Slot>,
    blockstore: &'a Blockstore,
}

impl<'a> AncestorIterator<'a> {
    pub fn new(start_slot: Slot, blockstore: &'a Blockstore) -> Self {
        let current = blockstore.meta(start_slot).unwrap().and_then(|slot_meta| {
            if start_slot != 0 {
                slot_meta.parent_slot
            } else {
                None
            }
        });
        Self {
            current,
            blockstore,
        }
    }

    pub fn new_inclusive(start_slot: Slot, blockstore: &'a Blockstore) -> Self {
        Self {
            current: blockstore.meta(start_slot).unwrap().map(|_| start_slot),
            blockstore,
        }
    }
}
impl<'a> Iterator for AncestorIterator<'a> {
    type Item = Slot;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current;
        current.map(|slot| {
            if slot != 0 {
                self.current = self
                    .blockstore
                    .meta(slot)
                    .unwrap()
                    .and_then(|slot_meta| slot_meta.parent_slot);
            } else {
                self.current = None;
            }
            slot
        })
    }
}

pub struct AncestorIteratorWithHash<'a> {
    ancestor_iterator: AncestorIterator<'a>,
}
impl<'a> From<AncestorIterator<'a>> for AncestorIteratorWithHash<'a> {
    fn from(ancestor_iterator: AncestorIterator<'a>) -> Self {
        Self { ancestor_iterator }
    }
}
impl<'a> Iterator for AncestorIteratorWithHash<'a> {
    type Item = (Slot, Hash);
    fn next(&mut self) -> Option<Self::Item> {
        self.ancestor_iterator
            .next()
            .and_then(|next_ancestor_slot| {
                self.ancestor_iterator
                    .blockstore
                    .get_bank_hash(next_ancestor_slot)
                    .map(|next_ancestor_hash| (next_ancestor_slot, next_ancestor_hash))
            })
    }
}
