#[allow(deprecated)]
use solana_sdk::sysvar::recent_blockhashes;
use {
    serde::{Deserialize, Serialize},
    solana_sdk::{fee_calculator::FeeCalculator, hash::Hash, timing::timestamp},
    std::collections::HashMap,
};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, AbiExample)]
struct HashAge {
    fee_calculator: FeeCalculator,
    hash_height: u64,
    timestamp: u64,
}

/// Low memory overhead, so can be cloned for every checkpoint
#[frozen_abi(digest = "J1fGiMHyiKEBcWE6mfm7grAEGJgYEaVLzcrNZvd37iA2")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, AbiExample)]
pub struct BlockhashQueue {
    /// updated whenever an hash is registered
    hash_height: u64,

    /// last hash to be registered
    last_hash: Option<Hash>,

    ages: HashMap<Hash, HashAge>,

    /// hashes older than `max_age` will be dropped from the queue
    max_age: usize,
}

impl BlockhashQueue {
    pub fn new(max_age: usize) -> Self {
        Self {
            ages: HashMap::new(),
            hash_height: 0,
            last_hash: None,
            max_age,
        }
    }

    #[allow(dead_code)]
    pub fn hash_height(&self) -> u64 {
        self.hash_height
    }

    pub fn last_hash(&self) -> Hash {
        self.last_hash.expect("no hash has been set")
    }

    pub fn get_lamports_per_signature(&self, hash: &Hash) -> Option<u64> {
        self.ages
            .get(hash)
            .map(|hash_age| hash_age.fee_calculator.lamports_per_signature)
    }

    /// Check if the age of the hash is within the max_age
    /// return false for any hashes with an age above max_age
    /// return None for any hashes that were not found
    pub fn check_hash_age(&self, hash: &Hash, max_age: usize) -> Option<bool> {
        self.ages
            .get(hash)
            .map(|age| self.hash_height - age.hash_height <= max_age as u64)
    }

    pub fn get_hash_age(&self, hash: &Hash) -> Option<u64> {
        self.ages
            .get(hash)
            .map(|age| self.hash_height - age.hash_height)
    }

    /// check if hash is valid
    pub fn check_hash(&self, hash: &Hash) -> bool {
        self.ages.get(hash).is_some()
    }

    pub fn genesis_hash(&mut self, hash: &Hash, lamports_per_signature: u64) {
        self.ages.insert(
            *hash,
            HashAge {
                fee_calculator: FeeCalculator::new(lamports_per_signature),
                hash_height: 0,
                timestamp: timestamp(),
            },
        );

        self.last_hash = Some(*hash);
    }

    fn check_age(hash_height: u64, max_age: usize, age: &HashAge) -> bool {
        hash_height - age.hash_height <= max_age as u64
    }

    pub fn register_hash(&mut self, hash: &Hash, lamports_per_signature: u64) {
        self.hash_height += 1;
        let hash_height = self.hash_height;

        // this clean up can be deferred until sigs gets larger
        //  because we verify age.nth every place we check for validity
        let max_age = self.max_age;
        if self.ages.len() >= max_age {
            self.ages
                .retain(|_, age| Self::check_age(hash_height, max_age, age));
        }
        self.ages.insert(
            *hash,
            HashAge {
                fee_calculator: FeeCalculator::new(lamports_per_signature),
                hash_height,
                timestamp: timestamp(),
            },
        );

        self.last_hash = Some(*hash);
    }

    /// Maps a hash height to a timestamp
    pub fn hash_height_to_timestamp(&self, hash_height: u64) -> Option<u64> {
        for age in self.ages.values() {
            if age.hash_height == hash_height {
                return Some(age.timestamp);
            }
        }
        None
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please do not use, will no longer be available in the future"
    )]
    #[allow(deprecated)]
    pub fn get_recent_blockhashes(&self) -> impl Iterator<Item = recent_blockhashes::IterItem> {
        (self.ages).iter().map(|(k, v)| {
            recent_blockhashes::IterItem(v.hash_height, k, v.fee_calculator.lamports_per_signature)
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.max_age
    }
}
