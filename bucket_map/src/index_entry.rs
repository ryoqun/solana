#![allow(dead_code)]

use {
    crate::{
        bucket::Bucket,
        bucket_storage::{BucketStorage, Uid},
        RefCount,
    },
    modular_bitfield::prelude::*,
    solana_sdk::{clock::Slot, pubkey::Pubkey},
    std::{
        collections::hash_map::DefaultHasher,
        fmt::Debug,
        hash::{Hash, Hasher},
    },
};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
// one instance of this per item in the index
// stored in the index bucket
pub struct IndexEntry {
    pub key: Pubkey, // can this be smaller if we have reduced the keys into buckets already?
    pub ref_count: RefCount, // can this be smaller? Do we ever need more than 4B refcounts?
    storage_cap_and_offset: PackedStorage,
    // if the bucket doubled, the index can be recomputed using create_bucket_capacity_pow2
    pub num_slots: Slot, // can this be smaller? epoch size should ~ be the max len. this is the num elements in the slot list
}

/// Pack the storage offset and capacity-when-crated-pow2 fields into a single u64
#[bitfield(bits = 64)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
struct PackedStorage {
    capacity_when_created_pow2: B8,
    offset: B56,
}

impl IndexEntry {
    pub fn init(&mut self, pubkey: &Pubkey) {
        self.key = *pubkey;
        self.ref_count = 0;
        self.storage_cap_and_offset = PackedStorage::default();
        self.num_slots = 0;
    }

    pub fn set_storage_capacity_when_created_pow2(
        &mut self,
        storage_capacity_when_created_pow2: u8,
    ) {
        self.storage_cap_and_offset
            .set_capacity_when_created_pow2(storage_capacity_when_created_pow2)
    }

    pub fn set_storage_offset(&mut self, storage_offset: u64) {
        self.storage_cap_and_offset
            .set_offset_checked(storage_offset)
            .expect("New storage offset must fit into 7 bytes!")
    }

    /// return closest bucket index fit for the slot slice.
    /// Since bucket size is 2^index, the return value is
    ///     min index, such that 2^index >= num_slots
    ///     index = ceiling(log2(num_slots))
    /// special case, when slot slice empty, return 0th index.
    pub fn data_bucket_from_num_slots(num_slots: Slot) -> u64 {
        // Compute the ceiling of log2 for integer
        if num_slots == 0 {
            0
        } else {
            (Slot::BITS - (num_slots - 1).leading_zeros()) as u64
        }
    }

    pub fn data_bucket_ix(&self) -> u64 {
        Self::data_bucket_from_num_slots(self.num_slots)
    }

    pub fn ref_count(&self) -> RefCount {
        self.ref_count
    }

    fn storage_capacity_when_created_pow2(&self) -> u8 {
        self.storage_cap_and_offset.capacity_when_created_pow2()
    }

    fn storage_offset(&self) -> u64 {
        self.storage_cap_and_offset.offset()
    }

    // This function maps the original data location into an index in the current bucket storage.
    // This is coupled with how we resize bucket storages.
    pub fn data_loc(&self, storage: &BucketStorage) -> u64 {
        self.storage_offset() << (storage.capacity_pow2 - self.storage_capacity_when_created_pow2())
    }

    pub fn read_value<'a, T>(&self, bucket: &'a Bucket<T>) -> Option<(&'a [T], RefCount)> {
        let data_bucket_ix = self.data_bucket_ix();
        let data_bucket = &bucket.data[data_bucket_ix as usize];
        let slice = if self.num_slots > 0 {
            let loc = self.data_loc(data_bucket);
            let uid = Self::key_uid(&self.key);
            assert_eq!(Some(uid), bucket.data[data_bucket_ix as usize].uid(loc));
            bucket.data[data_bucket_ix as usize].get_cell_slice(loc, self.num_slots)
        } else {
            // num_slots is 0. This means we don't have an actual allocation.
            // can we trust that the data_bucket is even safe?
            bucket.data[data_bucket_ix as usize].get_empty_cell_slice()
        };
        Some((slice, self.ref_count))
    }

    pub fn key_uid(key: &Pubkey) -> Uid {
        let mut s = DefaultHasher::new();
        key.hash(&mut s);
        s.finish().max(1u64)
    }
}
