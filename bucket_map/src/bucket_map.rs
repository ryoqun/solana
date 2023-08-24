//! BucketMap is a mostly contention free concurrent map backed by MmapMut

use {
    crate::{bucket_api::BucketApi, bucket_stats::BucketMapStats, MaxSearch, RefCount},
    solana_sdk::pubkey::Pubkey,
    std::{convert::TryInto, fmt::Debug, fs, path::PathBuf, sync::Arc},
    tempfile::TempDir,
};

#[derive(Debug, Default, Clone)]
pub struct BucketMapConfig {
    pub max_buckets: usize,
    pub drives: Option<Vec<PathBuf>>,
    pub max_search: Option<MaxSearch>,
}

impl BucketMapConfig {
    /// Create a new BucketMapConfig
    /// NOTE: BucketMap requires that max_buckets is a power of two
    pub fn new(max_buckets: usize) -> BucketMapConfig {
        BucketMapConfig {
            max_buckets,
            ..BucketMapConfig::default()
        }
    }
}

pub struct BucketMap<T: Clone + Copy + Debug + 'static> {
    buckets: Vec<Arc<BucketApi<T>>>,
    drives: Arc<Vec<PathBuf>>,
    max_buckets_pow2: u8,
    pub stats: Arc<BucketMapStats>,
    pub temp_dir: Option<TempDir>,
}

impl<T: Clone + Copy + Debug> Drop for BucketMap<T> {
    fn drop(&mut self) {
        if self.temp_dir.is_none() {
            BucketMap::<T>::erase_previous_drives(&self.drives);
        }
    }
}

impl<T: Clone + Copy + Debug> std::fmt::Debug for BucketMap<T> {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

/// used to communicate resize necessary and current size.
#[derive(Debug)]
pub enum BucketMapError {
    /// (bucket_index, current_capacity_pow2)
    /// Note that this is specific to data buckets, which grow in powers of 2
    DataNoSpace((u64, u8)),

    /// current_capacity_entries
    /// Note that this is specific to index buckets, which can be 'Actual' sizes
    IndexNoSpace(u64),
}

impl<T: Clone + Copy + Debug> BucketMap<T> {
    pub fn new(config: BucketMapConfig) -> Self {
        assert_ne!(
            config.max_buckets, 0,
            "Max number of buckets must be non-zero"
        );
        assert!(
            config.max_buckets.is_power_of_two(),
            "Max number of buckets must be a power of two"
        );
        // this should be <= 1 << DEFAULT_CAPACITY or we end up searching the same items over and over - probably not a big deal since it is so small anyway
        const MAX_SEARCH: MaxSearch = 32;
        let max_search = config.max_search.unwrap_or(MAX_SEARCH);

        if let Some(drives) = config.drives.as_ref() {
            Self::erase_previous_drives(drives);
        }
        let mut temp_dir = None;
        let drives = config.drives.unwrap_or_else(|| {
            temp_dir = Some(TempDir::new().unwrap());
            vec![temp_dir.as_ref().unwrap().path().to_path_buf()]
        });
        let drives = Arc::new(drives);

        let stats = Arc::default();
        let buckets = (0..config.max_buckets)
            .map(|_| {
                Arc::new(BucketApi::new(
                    Arc::clone(&drives),
                    max_search,
                    Arc::clone(&stats),
                ))
            })
            .collect();

        // A simple log2 function that is correct if x is a power of two
        let log2 = |x: usize| usize::BITS - x.leading_zeros() - 1;

        Self {
            buckets,
            drives,
            max_buckets_pow2: log2(config.max_buckets) as u8,
            stats,
            temp_dir,
        }
    }

    fn erase_previous_drives(drives: &[PathBuf]) {
        drives.iter().for_each(|folder| {
            let _ = fs::remove_dir_all(folder);
            let _ = fs::create_dir_all(folder);
        })
    }

    pub fn num_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Get the values for Pubkey `key`
    pub fn read_value(&self, key: &Pubkey) -> Option<(Vec<T>, RefCount)> {
        self.get_bucket(key).read_value(key)
    }

    /// Delete the Pubkey `key`
    pub fn delete_key(&self, key: &Pubkey) {
        self.get_bucket(key).delete_key(key);
    }

    /// Update Pubkey `key`'s value with 'value'
    pub fn insert(&self, key: &Pubkey, value: (&[T], RefCount)) {
        self.get_bucket(key).insert(key, value)
    }

    /// Update Pubkey `key`'s value with 'value'
    pub fn try_insert(&self, key: &Pubkey, value: (&[T], RefCount)) -> Result<(), BucketMapError> {
        self.get_bucket(key).try_write(key, value)
    }

    /// Update Pubkey `key`'s value with function `updatefn`
    pub fn update<F>(&self, key: &Pubkey, updatefn: F)
    where
        F: FnMut(Option<(&[T], RefCount)>) -> Option<(Vec<T>, RefCount)>,
    {
        self.get_bucket(key).update(key, updatefn)
    }

    pub fn get_bucket(&self, key: &Pubkey) -> &Arc<BucketApi<T>> {
        self.get_bucket_from_index(self.bucket_ix(key))
    }

    pub fn get_bucket_from_index(&self, ix: usize) -> &Arc<BucketApi<T>> {
        &self.buckets[ix]
    }

    /// Get the bucket index for Pubkey `key`
    pub fn bucket_ix(&self, key: &Pubkey) -> usize {
        if self.max_buckets_pow2 > 0 {
            let location = read_be_u64(key.as_ref());
            (location >> (u64::BITS - self.max_buckets_pow2 as u32)) as usize
        } else {
            0
        }
    }
}

/// Look at the first 8 bytes of the input and reinterpret them as a u64
fn read_be_u64(input: &[u8]) -> u64 {
    assert!(input.len() >= std::mem::size_of::<u64>());
    u64::from_be_bytes(input[0..std::mem::size_of::<u64>()].try_into().unwrap())
}
