#![allow(clippy::integer_arithmetic)]
//!
//! slot history
//!
pub use crate::clock::Slot;
use bv::{BitVec, BitsMut};

#[repr(C)]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SlotHistory {
    pub bits: BitVec<u64>,
    pub next_slot: Slot,
}

impl Default for SlotHistory {
    fn default() -> Self {
        let mut bits = BitVec::new_fill(false, MAX_ENTRIES);
        bits.set(0, true);
        Self { bits, next_slot: 1 }
    }
}

impl std::fmt::Debug for SlotHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SlotHistory {{ slot: {} bits:", self.next_slot)?;
        for i in 0..MAX_ENTRIES {
            if self.bits.get(i) {
                write!(f, "1")?;
            } else {
                write!(f, "0")?;
            }
        }
        Ok(())
    }
}

pub const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days

#[derive(PartialEq, Debug)]
pub enum Check {
    Future,
    TooOld,
    Found,
    NotFound,
}

impl SlotHistory {
    pub fn add(&mut self, slot: Slot) {
        if slot > self.next_slot && slot - self.next_slot >= MAX_ENTRIES {
            // Wrapped past current history,
            // clear entire bitvec.
            let full_blocks = (MAX_ENTRIES as usize) / 64;
            for i in 0..full_blocks {
                self.bits.set_block(i, 0);
            }
        } else {
            for skipped in self.next_slot..slot {
                self.bits.set(skipped % MAX_ENTRIES, false);
            }
        }
        self.bits.set(slot % MAX_ENTRIES, true);
        self.next_slot = slot + 1;
    }

    pub fn check(&self, slot: Slot) -> Check {
        if slot > self.newest() {
            Check::Future
        } else if slot < self.oldest() {
            Check::TooOld
        } else if self.bits.get(slot % MAX_ENTRIES) {
            Check::Found
        } else {
            Check::NotFound
        }
    }

    pub fn oldest(&self) -> Slot {
        self.next_slot.saturating_sub(MAX_ENTRIES)
    }

    pub fn newest(&self) -> Slot {
        self.next_slot - 1
    }
}
