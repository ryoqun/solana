use {
    crate::{
        bank::Bank, prioritization_fee::*,
        transaction_priority_details::GetTransactionPriorityDetails,
    },
    crossbeam_channel::{unbounded, Receiver, Sender},
    log::*,
    lru::LruCache,
    solana_measure::measure,
    solana_sdk::{
        clock::Slot, pubkey::Pubkey, saturating_add_assign, transaction::SanitizedTransaction,
    },
    std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex, RwLock,
        },
        thread::{Builder, JoinHandle},
    },
};

/// The maximum number of blocks to keep in `PrioritizationFeeCache`, ie.
/// the amount of history generally desired to estimate the prioritization fee needed to
/// land a transaction in the current block.
const MAX_NUM_RECENT_BLOCKS: u64 = 150;

#[derive(Debug, Default)]
struct PrioritizationFeeCacheMetrics {
    // Count of transactions that successfully updated each slot's prioritization fee cache.
    successful_transaction_update_count: AtomicU64,

    // Accumulated time spent on tracking prioritization fee for each slot.
    total_update_elapsed_us: AtomicU64,

    // Accumulated time spent on acquiring cache write lock.
    total_cache_lock_elapsed_us: AtomicU64,

    // Accumulated time spent on acquiring each block entry's lock..
    total_entry_lock_elapsed_us: AtomicU64,

    // Accumulated time spent on updating block prioritization fees.
    total_entry_update_elapsed_us: AtomicU64,

    // Accumulated time spent on finalizing block prioritization fees.
    total_block_finalize_elapsed_us: AtomicU64,
}

impl PrioritizationFeeCacheMetrics {
    fn accumulate_successful_transaction_update_count(&self, val: u64) {
        self.successful_transaction_update_count
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_update_elapsed_us(&self, val: u64) {
        self.total_update_elapsed_us
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_cache_lock_elapsed_us(&self, val: u64) {
        self.total_cache_lock_elapsed_us
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_entry_lock_elapsed_us(&self, val: u64) {
        self.total_entry_lock_elapsed_us
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_entry_update_elapsed_us(&self, val: u64) {
        self.total_entry_update_elapsed_us
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_block_finalize_elapsed_us(&self, val: u64) {
        self.total_block_finalize_elapsed_us
            .fetch_add(val, Ordering::Relaxed);
    }

    fn report(&self, slot: Slot) {
        datapoint_info!(
            "block_prioritization_fee_counters",
            ("slot", slot as i64, i64),
            (
                "successful_transaction_update_count",
                self.successful_transaction_update_count
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_update_elapsed_us",
                self.total_update_elapsed_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_cache_lock_elapsed_us",
                self.total_cache_lock_elapsed_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_entry_lock_elapsed_us",
                self.total_entry_lock_elapsed_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_entry_update_elapsed_us",
                self.total_entry_update_elapsed_us
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_block_finalize_elapsed_us",
                self.total_block_finalize_elapsed_us
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
        );
    }
}

enum CacheServiceUpdate {
    TransactionUpdate {
        slot: Slot,
        transaction_fee: u64,
        writable_accounts: Arc<Vec<Pubkey>>,
    },
    BankFrozen {
        slot: Slot,
    },
    Exit,
}

/// Stores up to MAX_NUM_RECENT_BLOCKS recent block's prioritization fee,
/// A separate internal thread `service_thread` handles additional tasks when a bank is frozen,
/// and collecting stats and reporting metrics.
pub struct PrioritizationFeeCache {
    cache: Arc<RwLock<LruCache<Slot, Arc<Mutex<PrioritizationFee>>>>>,
    service_thread: Option<JoinHandle<()>>,
    sender: Sender<CacheServiceUpdate>,
    metrics: Arc<PrioritizationFeeCacheMetrics>,
}

impl Default for PrioritizationFeeCache {
    fn default() -> Self {
        Self::new(MAX_NUM_RECENT_BLOCKS)
    }
}

impl Drop for PrioritizationFeeCache {
    fn drop(&mut self) {
        let _ = self.sender.send(CacheServiceUpdate::Exit);
        self.service_thread
            .take()
            .unwrap()
            .join()
            .expect("Prioritization fee cache servicing thread failed to join");
    }
}

impl PrioritizationFeeCache {
    pub fn new(capacity: u64) -> Self {
        let metrics = Arc::new(PrioritizationFeeCacheMetrics::default());
        let (sender, receiver) = unbounded();
        let cache = Arc::new(RwLock::new(LruCache::new(capacity as usize)));

        let cache_clone = cache.clone();
        let metrics_clone = metrics.clone();
        let service_thread = Some(
            Builder::new()
                .name("solPrFeeCachSvc".to_string())
                .spawn(move || {
                    Self::service_loop(cache_clone, receiver, metrics_clone);
                })
                .unwrap(),
        );

        PrioritizationFeeCache {
            cache,
            service_thread,
            sender,
            metrics,
        }
    }

    /// Get prioritization fee entry, create new entry if necessary
    fn get_prioritization_fee(
        cache: Arc<RwLock<LruCache<Slot, Arc<Mutex<PrioritizationFee>>>>>,
        slot: &Slot,
    ) -> Arc<Mutex<PrioritizationFee>> {
        let mut cache = cache.write().unwrap();
        match cache.get(slot) {
            Some(entry) => Arc::clone(entry),
            None => {
                let entry = Arc::new(Mutex::new(PrioritizationFee::default()));
                cache.put(*slot, Arc::clone(&entry));
                entry
            }
        }
    }

    /// Update with a list of non-vote transactions' tx_priority_details and tx_account_locks; Only
    /// transactions have both valid priority_detail and account_locks will be used to update
    /// fee_cache asynchronously.
    pub fn update<'a>(&self, bank: &Bank, txs: impl Iterator<Item = &'a SanitizedTransaction>) {
        let mut successful_transaction_update_count: u64 = 0;
        let (_, send_updates_time) = measure!(
            {
                for sanitized_transaction in txs {
                    // Vote transactions are not prioritized, therefore they are excluded from
                    // updating fee_cache.
                    if sanitized_transaction.is_simple_vote_transaction() {
                        continue;
                    }

                    let round_compute_unit_price_enabled = false; // TODO: bank.feture_set.is_active(round_compute_unit_price)
                    let priority_details = sanitized_transaction
                        .get_transaction_priority_details(round_compute_unit_price_enabled);
                    let account_locks = sanitized_transaction
                        .get_account_locks(bank.get_transaction_account_lock_limit());

                    if priority_details.is_none() || account_locks.is_err() {
                        continue;
                    }
                    let priority_details = priority_details.unwrap();

                    // filter out any transaction that requests zero compute_unit_limit
                    // since its priority fee amount is not instructive
                    if priority_details.compute_unit_limit == 0 {
                        continue;
                    }

                    let writable_accounts = Arc::new(
                        account_locks
                            .unwrap()
                            .writable
                            .iter()
                            .map(|key| **key)
                            .collect::<Vec<_>>(),
                    );

                    self.sender
                        .send(CacheServiceUpdate::TransactionUpdate {
                            slot: bank.slot(),
                            transaction_fee: priority_details.priority,
                            writable_accounts,
                        })
                        .unwrap_or_else(|err| {
                            warn!(
                                "prioritization fee cache transaction updates failed: {:?}",
                                err
                            );
                        });
                    saturating_add_assign!(successful_transaction_update_count, 1)
                }
            },
            "send_updates",
        );

        self.metrics
            .accumulate_total_update_elapsed_us(send_updates_time.as_us());
        self.metrics
            .accumulate_successful_transaction_update_count(successful_transaction_update_count);
    }

    /// Finalize prioritization fee when it's bank is completely replayed from blockstore,
    /// by pruning irrelevant accounts to save space, and marking its availability for queries.
    pub fn finalize_priority_fee(&self, slot: Slot) {
        self.sender
            .send(CacheServiceUpdate::BankFrozen { slot })
            .unwrap_or_else(|err| {
                warn!(
                    "prioritization fee cache signalling bank frozen failed: {:?}",
                    err
                )
            });
    }

    /// Internal function is invoked by worker thread to update slot's minimum prioritization fee,
    /// Cache lock contends here.
    fn update_cache(
        cache: Arc<RwLock<LruCache<Slot, Arc<Mutex<PrioritizationFee>>>>>,
        slot: &Slot,
        transaction_fee: u64,
        writable_accounts: Arc<Vec<Pubkey>>,
        metrics: Arc<PrioritizationFeeCacheMetrics>,
    ) {
        let (block_prioritization_fee, cache_lock_time) =
            measure!(Self::get_prioritization_fee(cache, slot), "cache_lock_time");

        let (mut block_prioritization_fee, entry_lock_time) =
            measure!(block_prioritization_fee.lock().unwrap(), "entry_lock_time");

        let (_, entry_update_time) = measure!(
            block_prioritization_fee.update(transaction_fee, &writable_accounts),
            "entry_update_time"
        );
        metrics.accumulate_total_cache_lock_elapsed_us(cache_lock_time.as_us());
        metrics.accumulate_total_entry_lock_elapsed_us(entry_lock_time.as_us());
        metrics.accumulate_total_entry_update_elapsed_us(entry_update_time.as_us());
    }

    fn finalize_slot(
        cache: Arc<RwLock<LruCache<Slot, Arc<Mutex<PrioritizationFee>>>>>,
        slot: &Slot,
        metrics: Arc<PrioritizationFeeCacheMetrics>,
    ) {
        let (block_prioritization_fee, cache_lock_time) =
            measure!(Self::get_prioritization_fee(cache, slot), "cache_lock_time");

        let (mut block_prioritization_fee, entry_lock_time) =
            measure!(block_prioritization_fee.lock().unwrap(), "entry_lock_time");

        // prune cache by evicting write account entry from prioritization fee if its fee is less
        // or equal to block's minimum transaction fee, because they are irrelevant in calculating
        // block minimum fee.
        let (_, slot_finalize_time) = measure!(
            block_prioritization_fee.mark_block_completed(),
            "slot_finalize_time"
        );
        block_prioritization_fee.report_metrics(*slot);
        metrics.accumulate_total_cache_lock_elapsed_us(cache_lock_time.as_us());
        metrics.accumulate_total_entry_lock_elapsed_us(entry_lock_time.as_us());
        metrics.accumulate_total_block_finalize_elapsed_us(slot_finalize_time.as_us());
    }

    fn service_loop(
        cache: Arc<RwLock<LruCache<Slot, Arc<Mutex<PrioritizationFee>>>>>,
        receiver: Receiver<CacheServiceUpdate>,
        metrics: Arc<PrioritizationFeeCacheMetrics>,
    ) {
        for update in receiver.iter() {
            match update {
                CacheServiceUpdate::TransactionUpdate {
                    slot,
                    transaction_fee,
                    writable_accounts,
                } => Self::update_cache(
                    cache.clone(),
                    &slot,
                    transaction_fee,
                    writable_accounts,
                    metrics.clone(),
                ),
                CacheServiceUpdate::BankFrozen { slot } => {
                    Self::finalize_slot(cache.clone(), &slot, metrics.clone());

                    metrics.report(slot);
                }
                CacheServiceUpdate::Exit => {
                    break;
                }
            }
        }
    }

    /// Returns number of blocks that have finalized minimum fees collection
    pub fn available_block_count(&self) -> usize {
        self.cache
            .read()
            .unwrap()
            .iter()
            .filter(|(_slot, prioritization_fee)| prioritization_fee.lock().unwrap().is_finalized())
            .count()
    }

    pub fn get_prioritization_fees(&self, account_keys: &[Pubkey]) -> HashMap<Slot, u64> {
        self.cache
            .read()
            .unwrap()
            .iter()
            .filter_map(|(slot, prioritization_fee)| {
                let prioritization_fee_read = prioritization_fee.lock().unwrap();
                prioritization_fee_read.is_finalized().then(|| {
                    let mut fee = prioritization_fee_read
                        .get_min_transaction_fee()
                        .unwrap_or_default();
                    for account_key in account_keys {
                        if let Some(account_fee) =
                            prioritization_fee_read.get_writable_account_fee(account_key)
                        {
                            fee = std::cmp::max(fee, account_fee);
                        }
                    }
                    Some((*slot, fee))
                })
            })
            .flatten()
            .collect()
    }
}
