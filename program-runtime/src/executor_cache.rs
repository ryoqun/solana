use {
    crate::invoke_context::InvokeContext,
    log::*,
    rand::Rng,
    solana_sdk::{
        instruction::InstructionError, pubkey::Pubkey, saturating_add_assign, slot_history::Slot,
        stake_history::Epoch,
    },
    std::{
        collections::HashMap,
        fmt::Debug,
        ops::Div,
        sync::{
            atomic::{AtomicU64, Ordering::Relaxed},
            Arc,
        },
    },
};

/// Program executor
pub trait Executor: Debug + Send + Sync {
    /// Execute the program
    fn execute(
        &self,
        first_instruction_account: usize,
        invoke_context: &mut InvokeContext,
    ) -> Result<(), InstructionError>;
}

pub type Executors = HashMap<Pubkey, TransactionExecutor>;

#[repr(u8)]
#[derive(PartialEq, Debug)]
enum TransactionExecutorStatus {
    /// Executor was already in the cache, no update needed
    Cached,
    /// Executor was missing from the cache, but not updated
    Missing,
    /// Executor is for an updated program
    Updated,
}

/// Tracks whether a given executor is "dirty" and needs to updated in the
/// executors cache
#[derive(Debug)]
pub struct TransactionExecutor {
    pub(crate) executor: Arc<dyn Executor>,
    status: TransactionExecutorStatus,
}

impl TransactionExecutor {
    /// Wraps an executor and tracks that it doesn't need to be updated in the
    /// executors cache.
    pub fn new_cached(executor: Arc<dyn Executor>) -> Self {
        Self {
            executor,
            status: TransactionExecutorStatus::Cached,
        }
    }

    /// Wraps an executor and tracks that it needs to be updated in the
    /// executors cache.
    pub fn new_miss(executor: Arc<dyn Executor>) -> Self {
        Self {
            executor,
            status: TransactionExecutorStatus::Missing,
        }
    }

    /// Wraps an executor and tracks that it needs to be updated in the
    /// executors cache only if the transaction succeeded.
    pub fn new_updated(executor: Arc<dyn Executor>) -> Self {
        Self {
            executor,
            status: TransactionExecutorStatus::Updated,
        }
    }

    pub fn is_missing(&self) -> bool {
        self.status == TransactionExecutorStatus::Missing
    }

    pub fn is_updated(&self) -> bool {
        self.status == TransactionExecutorStatus::Updated
    }

    pub fn get(&self) -> Arc<dyn Executor> {
        self.executor.clone()
    }
}

/// Capacity of `CachedExecutors`
pub const MAX_CACHED_EXECUTORS: usize = 256;

/// An `Executor` and its statistics tracked in `CachedExecutors`
#[derive(Debug)]
pub struct CachedExecutorsEntry {
    prev_epoch_count: u64,
    epoch_count: AtomicU64,
    executor: Arc<dyn Executor>,
    pub hit_count: AtomicU64,
}

impl Clone for CachedExecutorsEntry {
    fn clone(&self) -> Self {
        Self {
            prev_epoch_count: self.prev_epoch_count,
            epoch_count: AtomicU64::new(self.epoch_count.load(Relaxed)),
            executor: self.executor.clone(),
            hit_count: AtomicU64::new(self.hit_count.load(Relaxed)),
        }
    }
}

/// LFU Cache of executors with single-epoch memory of usage counts
#[derive(Debug)]
pub struct CachedExecutors {
    capacity: usize,
    current_epoch: Epoch,
    pub executors: HashMap<Pubkey, CachedExecutorsEntry>,
    pub stats: Stats,
}

impl Default for CachedExecutors {
    fn default() -> Self {
        Self {
            capacity: MAX_CACHED_EXECUTORS,
            current_epoch: Epoch::default(),
            executors: HashMap::default(),
            stats: Stats::default(),
        }
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl solana_frozen_abi::abi_example::AbiExample for CachedExecutors {
    fn example() -> Self {
        // Delegate AbiExample impl to Default before going deep and stuck with
        // not easily impl-able Arc<dyn Executor> due to rust's coherence issue
        // This is safe because CachedExecutors isn't serializable by definition.
        Self::default()
    }
}

impl CachedExecutors {
    pub fn new(max_capacity: usize, current_epoch: Epoch) -> Self {
        Self {
            capacity: max_capacity,
            current_epoch,
            executors: HashMap::new(),
            stats: Stats::default(),
        }
    }

    pub fn new_from_parent_bank_executors(
        parent_bank_executors: &CachedExecutors,
        current_epoch: Epoch,
    ) -> Self {
        let executors = if parent_bank_executors.current_epoch == current_epoch {
            parent_bank_executors.executors.clone()
        } else {
            parent_bank_executors
                .executors
                .iter()
                .map(|(&key, entry)| {
                    let entry = CachedExecutorsEntry {
                        prev_epoch_count: entry.epoch_count.load(Relaxed),
                        epoch_count: AtomicU64::default(),
                        executor: entry.executor.clone(),
                        hit_count: AtomicU64::new(entry.hit_count.load(Relaxed)),
                    };
                    (key, entry)
                })
                .collect()
        };

        Self {
            capacity: parent_bank_executors.capacity,
            current_epoch,
            executors,
            stats: Stats::default(),
        }
    }

    pub fn get(&self, pubkey: &Pubkey) -> Option<Arc<dyn Executor>> {
        if let Some(entry) = self.executors.get(pubkey) {
            self.stats.hits.fetch_add(1, Relaxed);
            entry.epoch_count.fetch_add(1, Relaxed);
            entry.hit_count.fetch_add(1, Relaxed);
            Some(entry.executor.clone())
        } else {
            self.stats.misses.fetch_add(1, Relaxed);
            None
        }
    }

    pub fn put(&mut self, executors: &[(&Pubkey, Arc<dyn Executor>)]) {
        let mut new_executors: Vec<_> = executors
            .iter()
            .filter_map(|(key, executor)| {
                if let Some(mut entry) = self.remove(key) {
                    self.stats.replacements.fetch_add(1, Relaxed);
                    entry.executor = executor.clone();
                    let _ = self.executors.insert(**key, entry);
                    None
                } else {
                    self.stats.insertions.fetch_add(1, Relaxed);
                    Some((*key, executor))
                }
            })
            .collect();

        if !new_executors.is_empty() {
            let mut counts = self
                .executors
                .iter()
                .map(|(key, entry)| {
                    let count = entry
                        .prev_epoch_count
                        .saturating_add(entry.epoch_count.load(Relaxed));
                    (key, count)
                })
                .collect::<Vec<_>>();
            counts.sort_unstable_by_key(|(_, count)| *count);

            let primer_counts = Self::get_primer_counts(counts.as_slice(), new_executors.len());

            if self.executors.len() >= self.capacity {
                let mut least_keys = counts
                    .iter()
                    .take(new_executors.len())
                    .map(|least| *least.0)
                    .collect::<Vec<_>>();
                for least_key in least_keys.drain(..) {
                    let _ = self.remove(&least_key);
                    self.stats
                        .evictions
                        .entry(least_key)
                        .and_modify(|c| saturating_add_assign!(*c, 1))
                        .or_insert(1);
                }
            }

            for ((key, executor), primer_count) in new_executors.drain(..).zip(primer_counts) {
                let entry = CachedExecutorsEntry {
                    prev_epoch_count: 0,
                    epoch_count: AtomicU64::new(primer_count),
                    executor: executor.clone(),
                    hit_count: AtomicU64::new(1),
                };
                let _ = self.executors.insert(*key, entry);
            }
        }
    }

    pub fn remove(&mut self, pubkey: &Pubkey) -> Option<CachedExecutorsEntry> {
        let maybe_entry = self.executors.remove(pubkey);
        if let Some(entry) = maybe_entry.as_ref() {
            if entry.hit_count.load(Relaxed) == 1 {
                self.stats.one_hit_wonders.fetch_add(1, Relaxed);
            }
        }
        maybe_entry
    }

    pub fn clear(&mut self) {
        *self = CachedExecutors::default();
    }

    pub fn get_primer_count_upper_bound_inclusive(counts: &[(&Pubkey, u64)]) -> u64 {
        const PRIMER_COUNT_TARGET_PERCENTILE: u64 = 85;
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(PRIMER_COUNT_TARGET_PERCENTILE <= 100);
        }
        // Executor use-frequencies are assumed to fit a Pareto distribution.  Choose an
        // upper-bound for our primer count as the actual count at the target rank to avoid
        // an upward bias

        let target_index = u64::try_from(counts.len().saturating_sub(1))
            .ok()
            .and_then(|counts| {
                let index = counts
                    .saturating_mul(PRIMER_COUNT_TARGET_PERCENTILE)
                    .div(100); // switch to u64::saturating_div once stable
                usize::try_from(index).ok()
            })
            .unwrap_or(0);

        counts
            .get(target_index)
            .map(|(_, count)| *count)
            .unwrap_or(0)
    }

    pub fn get_primer_counts(counts: &[(&Pubkey, u64)], num_counts: usize) -> Vec<u64> {
        let max_primer_count = Self::get_primer_count_upper_bound_inclusive(counts);
        let mut rng = rand::thread_rng();

        (0..num_counts)
            .map(|_| rng.gen_range(0, max_primer_count.saturating_add(1)))
            .collect::<Vec<_>>()
    }
}

/// Statistics of the entrie `CachedExecutors`
#[derive(Debug, Default)]
pub struct Stats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: HashMap<Pubkey, u64>,
    pub insertions: AtomicU64,
    pub replacements: AtomicU64,
    pub one_hit_wonders: AtomicU64,
}

impl Stats {
    /// Logs the measurement values
    pub fn submit(&self, slot: Slot) {
        let hits = self.hits.load(Relaxed);
        let misses = self.misses.load(Relaxed);
        let insertions = self.insertions.load(Relaxed);
        let replacements = self.replacements.load(Relaxed);
        let one_hit_wonders = self.one_hit_wonders.load(Relaxed);
        let evictions: u64 = self.evictions.values().sum();
        datapoint_info!(
            "bank-executor-cache-stats",
            ("slot", slot, i64),
            ("hits", hits, i64),
            ("misses", misses, i64),
            ("evictions", evictions, i64),
            ("insertions", insertions, i64),
            ("replacements", replacements, i64),
            ("one_hit_wonders", one_hit_wonders, i64),
        );
        debug!(
            "Executor Cache Stats -- Hits: {}, Misses: {}, Evictions: {}, Insertions: {}, Replacements: {}, One-Hit-Wonders: {}",
            hits, misses, evictions, insertions, replacements, one_hit_wonders,
        );
        if log_enabled!(log::Level::Trace) && !self.evictions.is_empty() {
            let mut evictions = self.evictions.iter().collect::<Vec<_>>();
            evictions.sort_by_key(|e| e.1);
            let evictions = evictions
                .into_iter()
                .rev()
                .map(|(program_id, evictions)| {
                    format!("  {:<44}  {}", program_id.to_string(), evictions)
                })
                .collect::<Vec<_>>();
            let evictions = evictions.join("\n");
            trace!(
                "Eviction Details:\n  {:<44}  {}\n{}",
                "Program",
                "Count",
                evictions
            );
        }
    }
}
