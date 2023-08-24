use {
    crate::{
        accounts_db::{AccountStorageEntry, IncludeSlotInHash, PUBKEY_BINS_FOR_CALCULATING_HASHES},
        active_stats::{ActiveStatItem, ActiveStats},
        ancestors::Ancestors,
        pubkey_bins::PubkeyBinCalculator24,
        rent_collector::RentCollector,
    },
    log::*,
    memmap2::MmapMut,
    rayon::prelude::*,
    solana_measure::{measure::Measure, measure_us},
    solana_sdk::{
        hash::{Hash, Hasher},
        pubkey::Pubkey,
        slot_history::Slot,
        sysvar::epoch_schedule::EpochSchedule,
    },
    std::{
        borrow::Borrow,
        convert::TryInto,
        fs::File,
        io::{BufWriter, Write},
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc,
        },
    },
    tempfile::tempfile_in,
};
pub const MERKLE_FANOUT: usize = 16;

/// 1 file containing account hashes sorted by pubkey, mapped into memory
struct MmapAccountHashesFile {
    mmap: MmapMut,
}

impl MmapAccountHashesFile {
    /// return a slice of account hashes starting at 'index'
    fn read(&self, index: usize) -> &[Hash] {
        let start = std::mem::size_of::<Hash>() * index;
        let item_slice: &[u8] = &self.mmap[start..];
        let remaining_elements = item_slice.len() / std::mem::size_of::<Hash>();
        unsafe {
            let item = item_slice.as_ptr() as *const Hash;
            std::slice::from_raw_parts(item, remaining_elements)
        }
    }
}

/// 1 file containing account hashes sorted by pubkey
pub struct AccountHashesFile {
    /// # hashes and an open file that will be deleted on drop. None if there are zero hashes to represent, and thus, no file.
    count_and_writer: Option<(usize, BufWriter<File>)>,
    /// The directory where temporary cache files are put
    dir_for_temp_cache_files: PathBuf,
}

impl AccountHashesFile {
    /// map the file into memory and return a reader that can access it by slice
    fn get_reader(&mut self) -> Option<(usize, MmapAccountHashesFile)> {
        std::mem::take(&mut self.count_and_writer).map(|(count, writer)| {
            let file = Some(writer.into_inner().unwrap());
            (
                count,
                MmapAccountHashesFile {
                    mmap: unsafe { MmapMut::map_mut(file.as_ref().unwrap()).unwrap() },
                },
            )
        })
    }

    /// # hashes stored in this file
    pub fn count(&self) -> usize {
        self.count_and_writer
            .as_ref()
            .map(|(count, _)| *count)
            .unwrap_or_default()
    }

    /// write 'hash' to the file
    /// If the file isn't open, create it first.
    pub fn write(&mut self, hash: &Hash) {
        if self.count_and_writer.is_none() {
            // we have hashes to write but no file yet, so create a file that will auto-delete on drop
            self.count_and_writer = Some((
                0,
                BufWriter::new(
                    tempfile_in(&self.dir_for_temp_cache_files).unwrap_or_else(|err| {
                        panic!(
                            "Unable to create file within {}: {err}",
                            self.dir_for_temp_cache_files.display()
                        )
                    }),
                ),
            ));
        }
        let count_and_writer = self.count_and_writer.as_mut().unwrap();
        assert_eq!(
            std::mem::size_of::<Hash>(),
            count_and_writer
                .1
                .write(hash.as_ref())
                .unwrap_or_else(|err| {
                    panic!(
                        "Unable to write file within {}: {err}",
                        self.dir_for_temp_cache_files.display()
                    )
                })
        );
        count_and_writer.0 += 1;
    }
}

/// parameters to calculate accounts hash
#[derive(Debug)]
pub struct CalcAccountsHashConfig<'a> {
    /// true to use a thread pool dedicated to bg operations
    pub use_bg_thread_pool: bool,
    /// verify every hash in append vec/write cache with a recalculated hash
    pub check_hash: bool,
    /// 'ancestors' is used to get storages
    pub ancestors: Option<&'a Ancestors>,
    /// does hash calc need to consider account data that exists in the write cache?
    /// if so, 'ancestors' will be used for this purpose as well as storages.
    pub epoch_schedule: &'a EpochSchedule,
    pub rent_collector: &'a RentCollector,
    /// used for tracking down hash mismatches after the fact
    pub store_detailed_debug_info_on_failure: bool,
    pub include_slot_in_hash: IncludeSlotInHash,
}

// smallest, 3 quartiles, largest, average
pub type StorageSizeQuartileStats = [usize; 6];

#[derive(Debug, Default)]
pub struct HashStats {
    pub total_us: u64,
    pub mark_time_us: u64,
    pub cache_hash_data_us: u64,
    pub scan_time_total_us: u64,
    pub zeros_time_total_us: u64,
    pub hash_time_total_us: u64,
    pub sort_time_total_us: u64,
    pub hash_total: usize,
    pub num_snapshot_storage: usize,
    pub scan_chunks: usize,
    pub num_slots: usize,
    pub num_dirty_slots: usize,
    pub collect_snapshots_us: u64,
    pub storage_sort_us: u64,
    pub storage_size_quartiles: StorageSizeQuartileStats,
    pub oldest_root: Slot,
    pub roots_older_than_epoch: AtomicUsize,
    pub accounts_in_roots_older_than_epoch: AtomicUsize,
    pub append_vec_sizes_older_than_epoch: AtomicUsize,
    pub longest_ancient_scan_us: AtomicU64,
    pub sum_ancient_scans_us: AtomicU64,
    pub count_ancient_scans: AtomicU64,
    pub pubkey_bin_search_us: AtomicU64,
}
impl HashStats {
    pub fn calc_storage_size_quartiles(&mut self, storages: &[Arc<AccountStorageEntry>]) {
        let mut sum = 0;
        let mut sizes = storages
            .iter()
            .map(|storage| {
                let cap = storage.accounts.capacity() as usize;
                sum += cap;
                cap
            })
            .collect::<Vec<_>>();
        sizes.sort_unstable();
        let len = sizes.len();
        self.storage_size_quartiles = if len == 0 {
            StorageSizeQuartileStats::default()
        } else {
            [
                *sizes.first().unwrap(),
                sizes[len / 4],
                sizes[len * 2 / 4],
                sizes[len * 3 / 4],
                *sizes.last().unwrap(),
                sum / len,
            ]
        };
    }

    pub fn log(&self) {
        datapoint_info!(
            "calculate_accounts_hash_from_storages",
            ("total_us", self.total_us, i64),
            ("mark_time_us", self.mark_time_us, i64),
            ("cache_hash_data_us", self.cache_hash_data_us, i64),
            ("accounts_scan_us", self.scan_time_total_us, i64),
            ("eliminate_zeros_us", self.zeros_time_total_us, i64),
            ("hash_us", self.hash_time_total_us, i64),
            ("sort_us", self.sort_time_total_us, i64),
            ("hash_total", self.hash_total, i64),
            ("storage_sort_us", self.storage_sort_us, i64),
            ("collect_snapshots_us", self.collect_snapshots_us, i64),
            ("num_snapshot_storage", self.num_snapshot_storage, i64),
            ("scan_chunks", self.scan_chunks, i64),
            ("num_slots", self.num_slots, i64),
            ("num_dirty_slots", self.num_dirty_slots, i64),
            ("storage_size_min", self.storage_size_quartiles[0], i64),
            (
                "storage_size_quartile_1",
                self.storage_size_quartiles[1],
                i64
            ),
            (
                "storage_size_quartile_2",
                self.storage_size_quartiles[2],
                i64
            ),
            (
                "storage_size_quartile_3",
                self.storage_size_quartiles[3],
                i64
            ),
            ("storage_size_max", self.storage_size_quartiles[4], i64),
            ("storage_size_avg", self.storage_size_quartiles[5], i64),
            (
                "roots_older_than_epoch",
                self.roots_older_than_epoch.load(Ordering::Relaxed),
                i64
            ),
            ("oldest_root", self.oldest_root, i64),
            (
                "longest_ancient_scan_us",
                self.longest_ancient_scan_us.load(Ordering::Relaxed),
                i64
            ),
            (
                "sum_ancient_scans_us",
                self.sum_ancient_scans_us.load(Ordering::Relaxed),
                i64
            ),
            (
                "count_ancient_scans",
                self.count_ancient_scans.load(Ordering::Relaxed),
                i64
            ),
            (
                "append_vec_sizes_older_than_epoch",
                self.append_vec_sizes_older_than_epoch
                    .load(Ordering::Relaxed),
                i64
            ),
            (
                "accounts_in_roots_older_than_epoch",
                self.accounts_in_roots_older_than_epoch
                    .load(Ordering::Relaxed),
                i64
            ),
            (
                "pubkey_bin_search_us",
                self.pubkey_bin_search_us.load(Ordering::Relaxed),
                i64
            ),
        );
    }
}

/// While scanning appendvecs, this is the info that needs to be extracted, de-duped, and sorted from what is stored in an append vec.
/// Note this can be saved/loaded during hash calculation to a memory mapped file whose contents are
/// [CalculateHashIntermediate]
#[repr(C)]
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct CalculateHashIntermediate {
    pub hash: Hash,
    pub lamports: u64,
    pub pubkey: Pubkey,
}

impl CalculateHashIntermediate {
    pub fn new(hash: Hash, lamports: u64, pubkey: Pubkey) -> Self {
        Self {
            hash,
            lamports,
            pubkey,
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct CumulativeOffset {
    pub index: Vec<usize>,
    pub start_offset: usize,
}

impl CumulativeOffset {
    pub fn new(index: Vec<usize>, start_offset: usize) -> CumulativeOffset {
        Self {
            index,
            start_offset,
        }
    }
}

pub trait ExtractSliceFromRawData<'b, T: 'b> {
    fn extract<'a>(&'b self, offset: &'a CumulativeOffset, start: usize) -> &'b [T];
}

impl<'b, T: 'b> ExtractSliceFromRawData<'b, T> for Vec<Vec<T>> {
    fn extract<'a>(&'b self, offset: &'a CumulativeOffset, start: usize) -> &'b [T] {
        &self[offset.index[0]][start..]
    }
}

impl<'b, T: 'b> ExtractSliceFromRawData<'b, T> for Vec<Vec<Vec<T>>> {
    fn extract<'a>(&'b self, offset: &'a CumulativeOffset, start: usize) -> &'b [T] {
        &self[offset.index[0]][offset.index[1]][start..]
    }
}

// Allow retrieving &[start..end] from a logical src: Vec<T>, where src is really Vec<Vec<T>> (or later Vec<Vec<Vec<T>>>)
// This model prevents callers from having to flatten which saves both working memory and time.
#[derive(Default, Debug)]
pub struct CumulativeOffsets {
    cumulative_offsets: Vec<CumulativeOffset>,
    total_count: usize,
}

/// used by merkle tree calculation to lookup account hashes by overall index
#[derive(Default)]
pub struct CumulativeHashesFromFiles {
    /// source of hashes in order
    readers: Vec<MmapAccountHashesFile>,
    /// look up reader index and offset by overall index
    cumulative: CumulativeOffsets,
}

impl CumulativeHashesFromFiles {
    /// Calculate offset from overall index to which file and offset within that file based on the length of each hash file.
    /// Also collect readers to access the data.
    pub fn from_files(hashes: Vec<AccountHashesFile>) -> Self {
        let mut readers = Vec::with_capacity(hashes.len());
        let cumulative = CumulativeOffsets::new(hashes.into_iter().filter_map(|mut hash_file| {
            // ignores all hashfiles that have zero entries
            hash_file.get_reader().map(|(count, reader)| {
                readers.push(reader);
                count
            })
        }));
        Self {
            cumulative,
            readers,
        }
    }

    /// total # of items referenced
    pub fn total_count(&self) -> usize {
        self.cumulative.total_count
    }

    // return the biggest slice possible that starts at the overall index 'start'
    pub fn get_slice(&self, start: usize) -> &[Hash] {
        let (start, offset) = self.cumulative.find(start);
        let data_source_index = offset.index[0];
        let data = &self.readers[data_source_index];
        // unwrap here because we should never ask for data that doesn't exist. If we do, then cumulative calculated incorrectly.
        data.read(start)
    }
}

impl CumulativeOffsets {
    pub fn new<I>(iter: I) -> Self
    where
        I: Iterator<Item = usize>,
    {
        let mut total_count: usize = 0;
        let cumulative_offsets: Vec<_> = iter
            .enumerate()
            .filter_map(|(i, len)| {
                if len > 0 {
                    let result = CumulativeOffset::new(vec![i], total_count);
                    total_count += len;
                    Some(result)
                } else {
                    None
                }
            })
            .collect();

        Self {
            cumulative_offsets,
            total_count,
        }
    }

    pub fn from_raw<T>(raw: &[Vec<T>]) -> Self {
        Self::new(raw.iter().map(|v| v.len()))
    }

    pub fn from_raw_2d<T>(raw: &[Vec<Vec<T>>]) -> Self {
        let mut total_count: usize = 0;
        let mut cumulative_offsets = Vec::with_capacity(0);
        for (i, v_outer) in raw.iter().enumerate() {
            for (j, v) in v_outer.iter().enumerate() {
                let len = v.len();
                if len > 0 {
                    if cumulative_offsets.is_empty() {
                        // the first inner, non-empty vector we find gives us an approximate rectangular shape
                        cumulative_offsets = Vec::with_capacity(raw.len() * v_outer.len());
                    }
                    cumulative_offsets.push(CumulativeOffset::new(vec![i, j], total_count));
                    total_count += len;
                }
            }
        }

        Self {
            cumulative_offsets,
            total_count,
        }
    }

    /// find the index of the data source that contains 'start'
    fn find_index(&self, start: usize) -> usize {
        assert!(!self.cumulative_offsets.is_empty());
        match self.cumulative_offsets[..].binary_search_by(|index| index.start_offset.cmp(&start)) {
            Ok(index) => index,
            Err(index) => index - 1, // we would insert at index so we are before the item at index
        }
    }

    /// given overall start index 'start'
    /// return ('start', which is the offset into the data source at 'index',
    ///     and 'index', which is the data source to use)
    fn find(&self, start: usize) -> (usize, &CumulativeOffset) {
        let index = self.find_index(start);
        let index = &self.cumulative_offsets[index];
        let start = start - index.start_offset;
        (start, index)
    }

    // return the biggest slice possible that starts at 'start'
    pub fn get_slice<'a, 'b, T, U>(&'a self, raw: &'b U, start: usize) -> &'b [T]
    where
        U: ExtractSliceFromRawData<'b, T> + 'b,
    {
        let (start, index) = self.find(start);
        raw.extract(index, start)
    }
}

#[derive(Debug)]
pub struct AccountsHasher<'a> {
    pub filler_account_suffix: Option<Pubkey>,
    pub zero_lamport_accounts: ZeroLamportAccounts,
    /// The directory where temporary cache files are put
    pub dir_for_temp_cache_files: PathBuf,
    pub(crate) active_stats: &'a ActiveStats,
}

impl<'a> AccountsHasher<'a> {
    /// true if it is possible that there are filler accounts present
    pub fn filler_accounts_enabled(&self) -> bool {
        self.filler_account_suffix.is_some()
    }

    pub fn calculate_hash(hashes: Vec<Vec<Hash>>) -> (Hash, usize) {
        let cumulative_offsets = CumulativeOffsets::from_raw(&hashes);

        let hash_total = cumulative_offsets.total_count;
        let result = AccountsHasher::compute_merkle_root_from_slices(
            hash_total,
            MERKLE_FANOUT,
            None,
            |start: usize| cumulative_offsets.get_slice(&hashes, start),
            None,
        );
        (result.0, hash_total)
    }

    pub fn compute_merkle_root(hashes: Vec<(Pubkey, Hash)>, fanout: usize) -> Hash {
        Self::compute_merkle_root_loop(hashes, fanout, |t| &t.1)
    }

    // this function avoids an infinite recursion compiler error
    pub fn compute_merkle_root_recurse(hashes: Vec<Hash>, fanout: usize) -> Hash {
        Self::compute_merkle_root_loop(hashes, fanout, |t| t)
    }

    pub fn div_ceil(x: usize, y: usize) -> usize {
        let mut result = x / y;
        if x % y != 0 {
            result += 1;
        }
        result
    }

    // For the first iteration, there could be more items in the tuple than just hash and lamports.
    // Using extractor allows us to avoid an unnecessary array copy on the first iteration.
    pub fn compute_merkle_root_loop<T, F>(hashes: Vec<T>, fanout: usize, extractor: F) -> Hash
    where
        F: Fn(&T) -> &Hash + std::marker::Sync,
        T: std::marker::Sync,
    {
        if hashes.is_empty() {
            return Hasher::default().result();
        }

        let mut time = Measure::start("time");

        let total_hashes = hashes.len();
        let chunks = Self::div_ceil(total_hashes, fanout);

        let result: Vec<_> = (0..chunks)
            .into_par_iter()
            .map(|i| {
                let start_index = i * fanout;
                let end_index = std::cmp::min(start_index + fanout, total_hashes);

                let mut hasher = Hasher::default();
                for item in hashes.iter().take(end_index).skip(start_index) {
                    let h = extractor(item);
                    hasher.hash(h.as_ref());
                }

                hasher.result()
            })
            .collect();
        time.stop();
        debug!("hashing {} {}", total_hashes, time);

        if result.len() == 1 {
            result[0]
        } else {
            Self::compute_merkle_root_recurse(result, fanout)
        }
    }

    fn calculate_three_level_chunks(
        total_hashes: usize,
        fanout: usize,
        max_levels_per_pass: Option<usize>,
        specific_level_count: Option<usize>,
    ) -> (usize, usize, bool) {
        const THREE_LEVEL_OPTIMIZATION: usize = 3; // this '3' is dependent on the code structure below where we manually unroll
        let target = fanout.pow(THREE_LEVEL_OPTIMIZATION as u32);

        // Only use the 3 level optimization if we have at least 4 levels of data.
        // Otherwise, we'll be serializing a parallel operation.
        let threshold = target * fanout;
        let mut three_level = max_levels_per_pass.unwrap_or(usize::MAX) >= THREE_LEVEL_OPTIMIZATION
            && total_hashes >= threshold;
        if three_level {
            if let Some(specific_level_count_value) = specific_level_count {
                three_level = specific_level_count_value >= THREE_LEVEL_OPTIMIZATION;
            }
        }
        let (num_hashes_per_chunk, levels_hashed) = if three_level {
            (target, THREE_LEVEL_OPTIMIZATION)
        } else {
            (fanout, 1)
        };
        (num_hashes_per_chunk, levels_hashed, three_level)
    }

    // This function is designed to allow hashes to be located in multiple, perhaps multiply deep vecs.
    // The caller provides a function to return a slice from the source data.
    pub fn compute_merkle_root_from_slices<'b, F, T>(
        total_hashes: usize,
        fanout: usize,
        max_levels_per_pass: Option<usize>,
        get_hash_slice_starting_at_index: F,
        specific_level_count: Option<usize>,
    ) -> (Hash, Vec<Hash>)
    where
        // returns a slice of hashes starting at the given overall index
        F: Fn(usize) -> &'b [T] + std::marker::Sync,
        T: Borrow<Hash> + std::marker::Sync + 'b,
    {
        if total_hashes == 0 {
            return (Hasher::default().result(), vec![]);
        }

        let mut time = Measure::start("time");

        let (num_hashes_per_chunk, levels_hashed, three_level) = Self::calculate_three_level_chunks(
            total_hashes,
            fanout,
            max_levels_per_pass,
            specific_level_count,
        );

        let chunks = Self::div_ceil(total_hashes, num_hashes_per_chunk);

        // initial fetch - could return entire slice
        let data = get_hash_slice_starting_at_index(0);
        let data_len = data.len();

        let result: Vec<_> = (0..chunks)
            .into_par_iter()
            .map(|i| {
                // summary:
                // this closure computes 1 or 3 levels of merkle tree (all chunks will be 1 or all will be 3)
                // for a subset (our chunk) of the input data [start_index..end_index]

                // index into get_hash_slice_starting_at_index where this chunk's range begins
                let start_index = i * num_hashes_per_chunk;
                // index into get_hash_slice_starting_at_index where this chunk's range ends
                let end_index = std::cmp::min(start_index + num_hashes_per_chunk, total_hashes);

                // will compute the final result for this closure
                let mut hasher = Hasher::default();

                // index into 'data' where we are currently pulling data
                // if we exhaust our data, then we will request a new slice, and data_index resets to 0, the beginning of the new slice
                let mut data_index = start_index;
                // source data, which we may refresh when we exhaust
                let mut data = data;
                // len of the source data
                let mut data_len = data_len;

                if !three_level {
                    // 1 group of fanout
                    // The result of this loop is a single hash value from fanout input hashes.
                    for i in start_index..end_index {
                        if data_index >= data_len {
                            // we exhausted our data, fetch next slice starting at i
                            data = get_hash_slice_starting_at_index(i);
                            data_len = data.len();
                            data_index = 0;
                        }
                        hasher.hash(data[data_index].borrow().as_ref());
                        data_index += 1;
                    }
                } else {
                    // hash 3 levels of fanout simultaneously.
                    // This codepath produces 1 hash value for between 1..=fanout^3 input hashes.
                    // It is equivalent to running the normal merkle tree calculation 3 iterations on the input.
                    //
                    // big idea:
                    //  merkle trees usually reduce the input vector by a factor of fanout with each iteration
                    //  example with fanout 2:
                    //   start:     [0,1,2,3,4,5,6,7]      in our case: [...16M...] or really, 1B
                    //   iteration0 [.5, 2.5, 4.5, 6.5]                 [... 1M...]
                    //   iteration1 [1.5, 5.5]                          [...65k...]
                    //   iteration2 3.5                                 [...4k... ]
                    //  So iteration 0 consumes N elements, hashes them in groups of 'fanout' and produces a vector of N/fanout elements
                    //   and the process repeats until there is only 1 hash left.
                    //
                    //  With the three_level code path, we make each chunk we iterate of size fanout^3 (4096)
                    //  So, the input could be 16M hashes and the output will be 4k hashes, or N/fanout^3
                    //  The goal is to reduce the amount of data that has to be constructed and held in memory.
                    //  When we know we have enough hashes, then, in 1 pass, we hash 3 levels simultaneously, storing far fewer intermediate hashes.
                    //
                    // Now, some details:
                    // The result of this loop is a single hash value from fanout^3 input hashes.
                    // concepts:
                    //  what we're conceptually hashing: "raw_hashes"[start_index..end_index]
                    //   example: [a,b,c,d,e,f]
                    //   but... hashes[] may really be multiple vectors that are pieced together.
                    //   example: [[a,b],[c],[d,e,f]]
                    //   get_hash_slice_starting_at_index(any_index) abstracts that and returns a slice starting at raw_hashes[any_index..]
                    //   such that the end of get_hash_slice_starting_at_index may be <, >, or = end_index
                    //   example: get_hash_slice_starting_at_index(1) returns [b]
                    //            get_hash_slice_starting_at_index(3) returns [d,e,f]
                    // This code is basically 3 iterations of merkle tree hashing occurring simultaneously.
                    // The first fanout raw hashes are hashed in hasher_k. This is iteration0
                    // Once hasher_k has hashed fanout hashes, hasher_k's result hash is hashed in hasher_j and then discarded
                    // hasher_k then starts over fresh and hashes the next fanout raw hashes. This is iteration0 again for a new set of data.
                    // Once hasher_j has hashed fanout hashes (from k), hasher_j's result hash is hashed in hasher and then discarded
                    // Once hasher has hashed fanout hashes (from j), then the result of hasher is the hash for fanout^3 raw hashes.
                    // If there are < fanout^3 hashes, then this code stops when it runs out of raw hashes and returns whatever it hashed.
                    // This is always how the very last elements work in a merkle tree.
                    let mut i = start_index;
                    while i < end_index {
                        let mut hasher_j = Hasher::default();
                        for _j in 0..fanout {
                            let mut hasher_k = Hasher::default();
                            let end = std::cmp::min(end_index - i, fanout);
                            for _k in 0..end {
                                if data_index >= data_len {
                                    // we exhausted our data, fetch next slice starting at i
                                    data = get_hash_slice_starting_at_index(i);
                                    data_len = data.len();
                                    data_index = 0;
                                }
                                hasher_k.hash(data[data_index].borrow().as_ref());
                                data_index += 1;
                                i += 1;
                            }
                            hasher_j.hash(hasher_k.result().as_ref());
                            if i >= end_index {
                                break;
                            }
                        }
                        hasher.hash(hasher_j.result().as_ref());
                    }
                }

                hasher.result()
            })
            .collect();
        time.stop();
        debug!("hashing {} {}", total_hashes, time);

        if let Some(mut specific_level_count_value) = specific_level_count {
            specific_level_count_value -= levels_hashed;
            if specific_level_count_value == 0 {
                (Hash::default(), result)
            } else {
                assert!(specific_level_count_value > 0);
                // We did not hash the number of levels required by 'specific_level_count', so repeat
                Self::compute_merkle_root_from_slices_recurse(
                    result,
                    fanout,
                    max_levels_per_pass,
                    Some(specific_level_count_value),
                )
            }
        } else {
            (
                if result.len() == 1 {
                    result[0]
                } else {
                    Self::compute_merkle_root_recurse(result, fanout)
                },
                vec![], // no intermediate results needed by caller
            )
        }
    }

    pub fn compute_merkle_root_from_slices_recurse(
        hashes: Vec<Hash>,
        fanout: usize,
        max_levels_per_pass: Option<usize>,
        specific_level_count: Option<usize>,
    ) -> (Hash, Vec<Hash>) {
        Self::compute_merkle_root_from_slices(
            hashes.len(),
            fanout,
            max_levels_per_pass,
            |start| &hashes[start..],
            specific_level_count,
        )
    }

    pub fn accumulate_account_hashes(mut hashes: Vec<(Pubkey, Hash)>) -> Hash {
        Self::sort_hashes_by_pubkey(&mut hashes);

        Self::compute_merkle_root_loop(hashes, MERKLE_FANOUT, |i| &i.1)
    }

    pub fn sort_hashes_by_pubkey(hashes: &mut Vec<(Pubkey, Hash)>) {
        hashes.par_sort_unstable_by(|a, b| a.0.cmp(&b.0));
    }

    pub fn compare_two_hash_entries(
        a: &CalculateHashIntermediate,
        b: &CalculateHashIntermediate,
    ) -> std::cmp::Ordering {
        // note partial_cmp only returns None with floating point comparisons
        a.pubkey.partial_cmp(&b.pubkey).unwrap()
    }

    pub fn checked_cast_for_capitalization(balance: u128) -> u64 {
        balance.try_into().unwrap_or_else(|_| {
            panic!("overflow is detected while summing capitalization: {balance}")
        })
    }

    /// returns:
    /// Vec, with one entry per bin
    ///  for each entry, Vec<Hash> in pubkey order
    /// If return Vec<AccountHashesFile> was flattened, it would be all hashes, in pubkey order.
    fn de_dup_accounts(
        &self,
        sorted_data_by_pubkey: &[&[CalculateHashIntermediate]],
        stats: &mut HashStats,
        max_bin: usize,
    ) -> (Vec<AccountHashesFile>, u64) {
        // 1. eliminate zero lamport accounts
        // 2. pick the highest slot or (slot = and highest version) of each pubkey
        // 3. produce this output:
        // a. vec: PUBKEY_BINS_FOR_CALCULATING_HASHES in pubkey order
        //      vec: individual hashes in pubkey order, 1 hash per
        // b. lamports
        let _guard = self.active_stats.activate(ActiveStatItem::HashDeDup);

        let mut zeros = Measure::start("eliminate zeros");
        let (hashes, hash_total, lamports_total) = (0..max_bin)
            .into_par_iter()
            .fold(
                || {
                    (
                        /*hashes files*/ Vec::with_capacity(max_bin),
                        /*hashes count*/ 0_usize,
                        /*lamports sum*/ 0_u64,
                    )
                },
                |mut accum, bin| {
                    let (hashes_file, lamports_bin) = self.de_dup_accounts_in_parallel(
                        sorted_data_by_pubkey,
                        bin,
                        max_bin,
                        stats,
                    );
                    accum.2 = accum
                        .2
                        .checked_add(lamports_bin)
                        .expect("summing capitalization cannot overflow");
                    accum.1 += hashes_file.count();
                    accum.0.push(hashes_file);
                    accum
                },
            )
            .reduce(
                || {
                    (
                        /*hashes files*/ Vec::with_capacity(max_bin),
                        /*hashes count*/ 0,
                        /*lamports sum*/ 0,
                    )
                },
                |mut a, mut b| {
                    a.2 =
                        a.2.checked_add(b.2)
                            .expect("summing capitalization cannot overflow");
                    a.1 += b.1;
                    a.0.append(&mut b.0);
                    a
                },
            );
        zeros.stop();
        stats.zeros_time_total_us += zeros.as_us();
        stats.hash_total += hash_total;
        (hashes, lamports_total)
    }

    /// returns the item referenced by `min_index`
    ///   updates `indexes` to skip over the pubkey and its duplicates
    ///   updates `first_items` to point to the next pubkey
    /// or removes the entire pubkey division entries (for `min_index`) if the referenced pubkey is the last entry in the same `bin`
    ///     removed from: `first_items`, `indexes`, and `first_item_pubkey_division`
    fn get_item<'b>(
        min_index: usize,
        bin: usize,
        first_items: &mut Vec<Pubkey>,
        sorted_data_by_pubkey: &[&'b [CalculateHashIntermediate]],
        indexes: &mut Vec<usize>,
        first_item_to_pubkey_division: &mut Vec<usize>,
        binner: &PubkeyBinCalculator24,
    ) -> &'b CalculateHashIntermediate {
        let first_item = first_items[min_index];
        let key = &first_item;
        let division_index = first_item_to_pubkey_division[min_index];
        let division_data = &sorted_data_by_pubkey[division_index];
        let mut index = indexes[min_index];
        index += 1;
        let mut end;
        loop {
            end = index >= division_data.len();
            if end {
                break;
            }
            // still more items where we found the previous key, so just increment the index for that slot group, skipping all pubkeys that are equal
            let next_key = &division_data[index].pubkey;
            if next_key == key {
                index += 1;
                continue; // duplicate entries of same pubkey, so keep skipping
            }

            if binner.bin_from_pubkey(next_key) > bin {
                // the next pubkey is not in our bin
                end = true;
                break;
            }

            // point to the next pubkey > key
            first_items[min_index] = *next_key;
            indexes[min_index] = index;
            break;
        }
        if end {
            // stop looking in this vector - we exhausted it
            first_items.remove(min_index);
            first_item_to_pubkey_division.remove(min_index);
            indexes.remove(min_index);
        }

        // this is the previous first item that was requested
        &division_data[index - 1]
    }

    /// `hash_data` must be sorted by `binner.bin_from_pubkey()`
    /// return index in `hash_data` of first pubkey that is in `bin`, based on `binner`
    fn binary_search_for_first_pubkey_in_bin(
        hash_data: &[CalculateHashIntermediate],
        bin: usize,
        binner: &PubkeyBinCalculator24,
    ) -> Option<usize> {
        let potential_index = if bin == 0 {
            // `bin` == 0 is special because there cannot be `bin`-1
            // so either element[0] is in bin 0 or there is nothing in bin 0.
            0
        } else {
            // search for the first pubkey that is in `bin`
            // There could be many keys in a row with the same `bin`.
            // So, for each pubkey, use calculated_bin * 2 + 1 as the bin of a given pubkey for binary search.
            // And compare the bin of each pubkey with `bin` * 2.
            // So all keys that are in `bin` will compare as `bin` * 2 + 1
            // all keys that are in `bin`-1 will compare as ((`bin` - 1) * 2 + 1), which is (`bin` * 2 - 1)
            // NO keys will compare as `bin` * 2 because we add 1.
            // So, the binary search will NEVER return Ok(found_index), but will always return Err(index of first key in `bin`).
            // Note that if NO key is in `bin`, then the key at the found index will be in a bin > `bin`, so return None.
            let just_prior_to_desired_bin = bin * 2;
            let search = hash_data.binary_search_by(|data| {
                (1 + 2 * binner.bin_from_pubkey(&data.pubkey)).cmp(&just_prior_to_desired_bin)
            });
            // returns Err(index where item should be) since the desired item will never exist
            search.expect_err("it is impossible to find a matching bin")
        };
        // note that `potential_index` could be == hash_data.len(). This indicates the first key in `bin` would be
        // after the data we have. Thus, no key is in `bin`.
        // This also handles the case where `hash_data` is empty, since len() will be 0 and `get` will return None.
        hash_data.get(potential_index).and_then(|potential_data| {
            (binner.bin_from_pubkey(&potential_data.pubkey) == bin).then_some(potential_index)
        })
    }

    /// `hash_data` must be sorted by `binner.bin_from_pubkey()`
    /// return index in `hash_data` of first pubkey that is in `bin`, based on `binner`
    fn find_first_pubkey_in_bin(
        hash_data: &[CalculateHashIntermediate],
        bin: usize,
        bins: usize,
        binner: &PubkeyBinCalculator24,
        stats: &HashStats,
    ) -> Option<usize> {
        if hash_data.is_empty() {
            return None;
        }
        let (result, us) = measure_us!({
            // assume uniform distribution of pubkeys and choose first guess based on bin we're looking for
            let i = hash_data.len() * bin / bins;
            let estimate = &hash_data[i];

            let pubkey_bin = binner.bin_from_pubkey(&estimate.pubkey);
            let range = if pubkey_bin >= bin {
                // i pubkey matches or is too large, so look <= i for the first pubkey in the right bin
                // i+1 could be the first pubkey in the right bin
                0..(i + 1)
            } else {
                // i pubkey is too small, so look after i
                (i + 1)..hash_data.len()
            };
            Some(
                range.start +
                // binary search the subset
                Self::binary_search_for_first_pubkey_in_bin(
                    &hash_data[range],
                    bin,
                    binner,
                )?,
            )
        });
        stats.pubkey_bin_search_us.fetch_add(us, Ordering::Relaxed);
        result
    }

    // go through: [..][pubkey_bin][..] and return hashes and lamport sum
    //   slot groups^                ^accounts found in a slot group, sorted by pubkey, higher slot, write_version
    // 1. handle zero lamport accounts
    // 2. pick the highest slot or (slot = and highest version) of each pubkey
    // 3. produce this output:
    //   a. AccountHashesFile: individual account hashes in pubkey order
    //   b. lamport sum
    fn de_dup_accounts_in_parallel(
        &self,
        sorted_data_by_pubkey: &[&[CalculateHashIntermediate]],
        pubkey_bin: usize,
        bins: usize,
        stats: &HashStats,
    ) -> (AccountHashesFile, u64) {
        let binner = PubkeyBinCalculator24::new(bins);

        let len = sorted_data_by_pubkey.len();
        let mut indexes = Vec::with_capacity(len);
        let mut first_items = Vec::with_capacity(len);
        // map from index of an item in first_items[] to index of the corresponding item in sorted_data_by_pubkey[]
        // this will change as items in sorted_data_by_pubkey[] are exhausted
        let mut first_item_to_pubkey_division = Vec::with_capacity(len);
        let mut hashes = AccountHashesFile {
            count_and_writer: None,
            dir_for_temp_cache_files: self.dir_for_temp_cache_files.clone(),
        };
        // initialize 'first_items', which holds the current lowest item in each slot group
        sorted_data_by_pubkey
            .iter()
            .enumerate()
            .for_each(|(i, hash_data)| {
                let first_pubkey_in_bin =
                    Self::find_first_pubkey_in_bin(hash_data, pubkey_bin, bins, &binner, stats);
                if let Some(first_pubkey_in_bin) = first_pubkey_in_bin {
                    let k = hash_data[first_pubkey_in_bin].pubkey;
                    first_items.push(k);
                    first_item_to_pubkey_division.push(i);
                    indexes.push(first_pubkey_in_bin);
                }
            });
        let mut overall_sum = 0;
        let mut duplicate_pubkey_indexes = Vec::with_capacity(len);
        let filler_accounts_enabled = self.filler_accounts_enabled();

        // this loop runs once per unique pubkey contained in any slot group
        while !first_items.is_empty() {
            let loop_stop = { first_items.len() - 1 }; // we increment at the beginning of the loop
            let mut min_index = 0;
            let mut min_pubkey = first_items[min_index];
            let mut first_item_index = 0; // we will start iterating at item 1. +=1 is first instruction in loop

            // this loop iterates over each slot group to find the minimum pubkey at the maximum slot
            // it also identifies duplicate pubkey entries at lower slots and remembers those to skip them after
            while first_item_index < loop_stop {
                first_item_index += 1;
                let key = &first_items[first_item_index];
                let cmp = min_pubkey.cmp(key);
                match cmp {
                    std::cmp::Ordering::Less => {
                        continue; // we still have the min item
                    }
                    std::cmp::Ordering::Equal => {
                        // we found the same pubkey in a later slot, so remember the lower slot as a duplicate
                        duplicate_pubkey_indexes.push(min_index);
                    }
                    std::cmp::Ordering::Greater => {
                        // this is the new min pubkey
                        min_pubkey = *key;
                    }
                }
                // this is the new index of the min entry
                min_index = first_item_index;
            }
            // get the min item, add lamports, get hash
            let item = Self::get_item(
                min_index,
                pubkey_bin,
                &mut first_items,
                sorted_data_by_pubkey,
                &mut indexes,
                &mut first_item_to_pubkey_division,
                &binner,
            );

            // add lamports and get hash
            if item.lamports != 0 {
                // do not include filler accounts in the hash
                if !(filler_accounts_enabled && self.is_filler_account(&item.pubkey)) {
                    overall_sum = Self::checked_cast_for_capitalization(
                        item.lamports as u128 + overall_sum as u128,
                    );
                    hashes.write(&item.hash);
                }
            } else {
                // if lamports == 0, check if they should be included
                if self.zero_lamport_accounts == ZeroLamportAccounts::Included {
                    // For incremental accounts hash, the hash of a zero lamport account is
                    // the hash of its pubkey
                    let hash = blake3::hash(bytemuck::bytes_of(&item.pubkey));
                    let hash = Hash::new_from_array(hash.into());
                    hashes.write(&hash);
                }
            }

            if !duplicate_pubkey_indexes.is_empty() {
                // skip past duplicate keys in earlier slots
                // reverse this list because get_item can remove first_items[*i] when *i is exhausted
                //  and that would mess up subsequent *i values
                duplicate_pubkey_indexes.iter().rev().for_each(|i| {
                    Self::get_item(
                        *i,
                        pubkey_bin,
                        &mut first_items,
                        sorted_data_by_pubkey,
                        &mut indexes,
                        &mut first_item_to_pubkey_division,
                        &binner,
                    );
                });
                duplicate_pubkey_indexes.clear();
            }
        }

        (hashes, overall_sum)
    }

    fn is_filler_account(&self, pubkey: &Pubkey) -> bool {
        crate::accounts_db::AccountsDb::is_filler_account_helper(
            pubkey,
            self.filler_account_suffix.as_ref(),
        )
    }

    /// input:
    /// vec: group of slot data, ordered by Slot (low to high)
    ///   vec: [..] - items found in that slot range Sorted by: Pubkey, higher Slot, higher Write version (if pubkey =)
    pub fn rest_of_hash_calculation(
        &self,
        sorted_data_by_pubkey: &[&[CalculateHashIntermediate]],
        stats: &mut HashStats,
    ) -> (Hash, u64) {
        let (hashes, total_lamports) = self.de_dup_accounts(
            sorted_data_by_pubkey,
            stats,
            PUBKEY_BINS_FOR_CALCULATING_HASHES,
        );

        let cumulative = CumulativeHashesFromFiles::from_files(hashes);

        let _guard = self.active_stats.activate(ActiveStatItem::HashMerkleTree);
        let mut hash_time = Measure::start("hash");
        let (hash, _) = Self::compute_merkle_root_from_slices(
            cumulative.total_count(),
            MERKLE_FANOUT,
            None,
            |start| cumulative.get_slice(start),
            None,
        );
        hash_time.stop();
        stats.hash_time_total_us += hash_time.as_us();
        (hash, total_lamports)
    }
}

/// How should zero-lamport accounts be treated by the accounts hasher?
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ZeroLamportAccounts {
    Excluded,
    Included,
}

/// Hash of accounts
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AccountsHashKind {
    Full(AccountsHash),
    Incremental(IncrementalAccountsHash),
}
impl AccountsHashKind {
    pub fn as_hash(&self) -> &Hash {
        match self {
            AccountsHashKind::Full(AccountsHash(hash))
            | AccountsHashKind::Incremental(IncrementalAccountsHash(hash)) => hash,
        }
    }
}
impl From<AccountsHash> for AccountsHashKind {
    fn from(accounts_hash: AccountsHash) -> Self {
        AccountsHashKind::Full(accounts_hash)
    }
}
impl From<IncrementalAccountsHash> for AccountsHashKind {
    fn from(incremental_accounts_hash: IncrementalAccountsHash) -> Self {
        AccountsHashKind::Incremental(incremental_accounts_hash)
    }
}

/// Hash of accounts
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AccountsHash(pub Hash);
/// Hash of accounts that includes zero-lamport accounts
/// Used with incremental snapshots
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct IncrementalAccountsHash(pub Hash);

/// Hash of accounts written in a single slot
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AccountsDeltaHash(pub Hash);

/// Snapshot serde-safe accounts delta hash
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq, AbiExample)]
pub struct SerdeAccountsDeltaHash(pub Hash);

impl From<SerdeAccountsDeltaHash> for AccountsDeltaHash {
    fn from(accounts_delta_hash: SerdeAccountsDeltaHash) -> Self {
        Self(accounts_delta_hash.0)
    }
}
impl From<AccountsDeltaHash> for SerdeAccountsDeltaHash {
    fn from(accounts_delta_hash: AccountsDeltaHash) -> Self {
        Self(accounts_delta_hash.0)
    }
}

/// Snapshot serde-safe accounts hash
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq, AbiExample)]
pub struct SerdeAccountsHash(pub Hash);

impl From<SerdeAccountsHash> for AccountsHash {
    fn from(accounts_hash: SerdeAccountsHash) -> Self {
        Self(accounts_hash.0)
    }
}
impl From<AccountsHash> for SerdeAccountsHash {
    fn from(accounts_hash: AccountsHash) -> Self {
        Self(accounts_hash.0)
    }
}

/// Snapshot serde-safe incremental accounts hash
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq, AbiExample)]
pub struct SerdeIncrementalAccountsHash(pub Hash);

impl From<SerdeIncrementalAccountsHash> for IncrementalAccountsHash {
    fn from(incremental_accounts_hash: SerdeIncrementalAccountsHash) -> Self {
        Self(incremental_accounts_hash.0)
    }
}
impl From<IncrementalAccountsHash> for SerdeIncrementalAccountsHash {
    fn from(incremental_accounts_hash: IncrementalAccountsHash) -> Self {
        Self(incremental_accounts_hash.0)
    }
}
