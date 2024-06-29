#[allow(deprecated)]
use solana_sdk::sysvar::recent_blockhashes;
use {
    serde::{Deserialize, Serialize},
    solana_sdk::{
        clock::MAX_RECENT_BLOCKHASHES, fee_calculator::FeeCalculator, hash::Hash, timing::timestamp,
    },
    std::collections::HashMap,
};

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct HashInfo {
    fee_calculator: FeeCalculator,
    hash_index: u64,
    timestamp: u64,
}

impl HashInfo {
    pub fn lamports_per_signature(&self) -> u64 {
        self.fee_calculator.lamports_per_signature
    }
}

/// Low memory overhead, so can be cloned for every checkpoint
#[cfg_attr(
    feature = "frozen-abi",
    derive(AbiExample),
    frozen_abi(digest = "HzbCqb1YtCodkx6Fu57SpzkgaLp9WSrtw8texsjBhEDH")
)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockhashQueue {
    /// index of last hash to be registered
    last_hash_index: u64,

    /// last hash to be registered
    last_hash: Option<Hash>,

    hashes: HashMap<Hash, HashInfo>,

    /// hashes older than `max_age` will be dropped from the queue
    max_age: usize,
}

impl Default for BlockhashQueue {
    fn default() -> Self {
        Self::new(MAX_RECENT_BLOCKHASHES)
    }
}

impl BlockhashQueue {
    pub fn new(max_age: usize) -> Self {
        Self {
            hashes: HashMap::new(),
            last_hash_index: 0,
            last_hash: None,
            max_age,
        }
    }

    pub fn last_hash(&self) -> Hash {
        self.last_hash.expect("no hash has been set")
    }

    pub fn get_lamports_per_signature(&self, hash: &Hash) -> Option<u64> {
        self.hashes
            .get(hash)
            .map(|hash_age| hash_age.fee_calculator.lamports_per_signature)
    }

    /// Check if the age of the hash is within the queue's max age
    #[deprecated(since = "2.0.0", note = "Please use `is_hash_valid_for_age` instead")]
    pub fn is_hash_valid(&self, hash: &Hash) -> bool {
        self.hashes.contains_key(hash)
    }

    /// Check if the age of the hash is within the specified age
    pub fn is_hash_valid_for_age(&self, hash: &Hash, max_age: usize) -> bool {
        self.get_hash_info_if_valid(hash, max_age).is_some()
    }

    /// Get hash info for the specified hash if it is in the queue and its age
    /// of the hash is within the specified age
    pub fn get_hash_info_if_valid(&self, hash: &Hash, max_age: usize) -> Option<&HashInfo> {
        self.hashes.get(hash).filter(|info| {
            Self::is_hash_index_valid(self.last_hash_index, max_age, info.hash_index)
        })
    }

    pub fn get_hash_age(&self, hash: &Hash) -> Option<u64> {
        self.hashes
            .get(hash)
            .map(|info| self.last_hash_index - info.hash_index)
    }

    pub fn genesis_hash(&mut self, hash: &Hash, lamports_per_signature: u64) {
        self.hashes.insert(
            *hash,
            HashInfo {
                fee_calculator: FeeCalculator::new(lamports_per_signature),
                hash_index: 0,
                timestamp: timestamp(),
            },
        );

        self.last_hash = Some(*hash);
    }

    fn is_hash_index_valid(last_hash_index: u64, max_age: usize, hash_index: u64) -> bool {
        last_hash_index - hash_index <= max_age as u64
    }

    pub fn register_hash(&mut self, hash: &Hash, lamports_per_signature: u64) {
        self.last_hash_index += 1;
        if self.hashes.len() >= self.max_age {
            self.hashes.retain(|_, info| {
                Self::is_hash_index_valid(self.last_hash_index, self.max_age, info.hash_index)
            });
        }

        self.hashes.insert(
            *hash,
            HashInfo {
                fee_calculator: FeeCalculator::new(lamports_per_signature),
                hash_index: self.last_hash_index,
                timestamp: timestamp(),
            },
        );

        self.last_hash = Some(*hash);
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please do not use, will no longer be available in the future"
    )]
    #[allow(deprecated)]
    pub fn get_recent_blockhashes(&self) -> impl Iterator<Item = recent_blockhashes::IterItem> {
        (self.hashes).iter().map(|(k, v)| {
            recent_blockhashes::IterItem(v.hash_index, k, v.fee_calculator.lamports_per_signature)
        })
    }

    #[deprecated(
        since = "2.0.0",
        note = "Please use `solana_program::clock::MAX_PROCESSING_AGE`"
    )]
    pub fn get_max_age(&self) -> usize {
        self.max_age
    }
}
