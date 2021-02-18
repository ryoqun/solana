use rand::{thread_rng, Rng};
use solana_measure::measure::Measure;
use solana_sdk::timing::timestamp;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

pub const DEFAULT_MINIMUM_OBJECT_COUNT: u32 = 1000;
pub const DEFAULT_SHRINK_RATIO: f64 = 0.80;
pub const DEFAULT_MAX_ABOVE_SHRINK_RATIO_COUNT: u32 = 10;
pub const DEFAULT_CHECK_SHRINK_INTERVAL_MS: u32 = 10000;

#[derive(Debug, Default)]
struct RecyclerStats {
    total: AtomicUsize,
    freed: AtomicUsize,
    reuse: AtomicUsize,
    max_gc: AtomicUsize,
}

#[derive(Debug, Default)]
struct RecyclerShrinkStats {
    resulting_size: u32,
    target_size: u32,
    ideal_num_to_remove: u32,
    shrink_elapsed: u64,
    drop_elapsed: u64,
}

impl RecyclerShrinkStats {
    fn report(&self, shrink_metric_name: &'static str) {
        datapoint_info!(
            shrink_metric_name,
            ("target_size", self.target_size as i64, i64),
            ("resulting_size", self.resulting_size as i64, i64),
            ("ideal_num_to_remove", self.ideal_num_to_remove as i64, i64),
            ("recycler_shrink_elapsed", self.shrink_elapsed as i64, i64),
            ("drop_elapsed", self.drop_elapsed as i64, i64)
        );
    }
}

#[derive(Clone)]
pub struct Recycler<T: Reset> {
    recycler: Arc<RecyclerX<T>>,
    shrink_metric_name: &'static str,
}

impl<T: Default + Reset> Recycler<T> {
    pub fn new(shrink_metric_name: &'static str) -> Self {
        Self {
            recycler: Arc::new(RecyclerX::default()),
            shrink_metric_name,
        }
    }

    pub fn new_with_limit(shrink_metric_name: &'static str, limit: u32) -> Self {
        Self {
            recycler: Arc::new(RecyclerX::new(Some(limit))),
            shrink_metric_name,
        }
    }
}

#[derive(Debug)]
pub struct ObjectPool<T: Reset> {
    object_pool: Vec<T>,
    shrink_ratio: f64,
    minimum_object_count: u32,
    above_shrink_ratio_count: u32,
    max_above_shrink_ratio_count: u32,
    check_shrink_interval_ms: u32,
    last_shrink_check_ts: u64,
    pub total_allocated_count: u32,
    limit: Option<u32>,
}
impl<T: Default + Reset> Default for ObjectPool<T> {
    fn default() -> Self {
        ObjectPool {
            object_pool: vec![],
            shrink_ratio: DEFAULT_SHRINK_RATIO,
            minimum_object_count: DEFAULT_MINIMUM_OBJECT_COUNT,
            above_shrink_ratio_count: 0,
            max_above_shrink_ratio_count: DEFAULT_MAX_ABOVE_SHRINK_RATIO_COUNT,
            check_shrink_interval_ms: DEFAULT_CHECK_SHRINK_INTERVAL_MS,
            last_shrink_check_ts: timestamp(),
            total_allocated_count: 0,
            limit: None,
        }
    }
}

impl<T: Default + Reset> ObjectPool<T> {
    fn new(limit: Option<u32>) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    fn len(&self) -> usize {
        self.object_pool.len()
    }
}

#[derive(Debug)]
pub struct RecyclerX<T: Reset> {
    gc: Mutex<ObjectPool<T>>,
    stats: RecyclerStats,
    id: usize,
}

impl<T: Default + Reset> Default for RecyclerX<T> {
    fn default() -> RecyclerX<T> {
        let id = thread_rng().gen_range(0, 1000);
        trace!("new recycler..{}", id);
        RecyclerX {
            gc: Mutex::new(ObjectPool::default()),
            stats: RecyclerStats::default(),
            id,
        }
    }
}

impl<T: Default + Reset> RecyclerX<T> {
    fn new(limit: Option<u32>) -> Self {
        RecyclerX {
            gc: Mutex::new(ObjectPool::new(limit)),
            ..Self::default()
        }
    }
}

pub trait Reset {
    fn reset(&mut self);
    fn warm(&mut self, size_hint: usize);
    fn set_recycler(&mut self, recycler: Weak<RecyclerX<Self>>)
    where
        Self: std::marker::Sized;
    fn unset_recycler(&mut self)
    where
        Self: std::marker::Sized;
}

lazy_static! {
    static ref WARM_RECYCLERS: AtomicBool = AtomicBool::new(false);
}

pub fn enable_recycler_warming() {
    WARM_RECYCLERS.store(true, Ordering::Relaxed);
}

fn warm_recyclers() -> bool {
    WARM_RECYCLERS.load(Ordering::Relaxed)
}

impl<T: Default + Reset + Sized> Recycler<T> {
    pub fn warmed(
        num: u32,
        size_hint: usize,
        limit: Option<u32>,
        shrink_metric_name: &'static str,
    ) -> Self {
        assert!(num <= limit.unwrap_or(std::u32::MAX));
        let new = Self {
            recycler: Arc::new(RecyclerX::new(limit)),
            shrink_metric_name,
        };
        if warm_recyclers() {
            let warmed_items: Vec<_> = (0..num)
                .map(|_| {
                    let mut item = new.allocate().unwrap();
                    item.warm(size_hint);
                    item
                })
                .collect();
            warmed_items
                .into_iter()
                .for_each(|i| new.recycler.recycle(i));
        }
        new
    }

    pub fn allocate(&self) -> Option<T> {
        let mut shrink_removed_objects = vec![];
        let (mut allocated_object, did_reuse, should_allocate_new, mut shrink_stats) = {
            let mut object_pool = self
                .recycler
                .gc
                .lock()
                .expect("recycler lock in pb fn allocate");

            let now = timestamp();
            let mut shrink_stats = None;

            if now.saturating_sub(object_pool.last_shrink_check_ts)
                > object_pool.check_shrink_interval_ms as u64
            {
                object_pool.last_shrink_check_ts = now;
                let shrink_threshold_count = Self::get_shrink_target(
                    object_pool.shrink_ratio,
                    object_pool.total_allocated_count,
                );

                // If more than the shrink threshold of all allocated objects are sitting doing nothing,
                // increment the `above_shrink_ratio_count`.
                if object_pool.len() > object_pool.minimum_object_count as usize
                    && object_pool.len() > shrink_threshold_count as usize
                {
                    object_pool.above_shrink_ratio_count += 1;
                } else {
                    object_pool.above_shrink_ratio_count = 0;
                }

                if object_pool.above_shrink_ratio_count as usize
                    >= object_pool.max_above_shrink_ratio_count as usize
                {
                    let mut recycler_shrink_elapsed = Measure::start("recycler_shrink");
                    // Do the shrink
                    let target_size =
                        std::cmp::max(object_pool.minimum_object_count, shrink_threshold_count);
                    let ideal_num_to_remove = object_pool.total_allocated_count - target_size;
                    for _ in 0..ideal_num_to_remove {
                        if let Some(mut expired_object) = object_pool.object_pool.pop() {
                            expired_object.unset_recycler();
                            // Drop these outside of the lock because the Drop() implmentation for
                            // certain objects like PinnedVec's can be expensive
                            shrink_removed_objects.push(expired_object);
                            // May not be able to shrink exactly `ideal_num_to_remove` objects sinc
                            // in the case of new allocations, `total_allocated_count` is incremented
                            // before the object is allocated (see `should_allocate_new` logic below).
                            // This race allows a difference of up to the number of threads allocating
                            // with this recycler.
                            object_pool.total_allocated_count -= 1;
                        } else {
                            break;
                        }
                    }
                    recycler_shrink_elapsed.stop();
                    object_pool.above_shrink_ratio_count = 0;
                    shrink_stats = Some(RecyclerShrinkStats {
                        resulting_size: object_pool.total_allocated_count,
                        target_size,
                        ideal_num_to_remove,
                        shrink_elapsed: recycler_shrink_elapsed.as_us(),
                        // Filled in later
                        drop_elapsed: 0,
                    })
                }
            }

            let reused_object = object_pool.object_pool.pop();
            if reused_object.is_some() {
                (reused_object, true, false, shrink_stats)
            } else if let Some(limit) = object_pool.limit {
                let should_allocate_new = object_pool.total_allocated_count < limit;
                if should_allocate_new {
                    object_pool.total_allocated_count += 1;
                }
                (None, false, should_allocate_new, shrink_stats)
            } else {
                (None, false, true, shrink_stats)
            }
        };

        let mut shrink_removed_object_elapsed = Measure::start("shrink_removed_object_elapsed");
        drop(shrink_removed_objects);
        shrink_removed_object_elapsed.stop();

        if let Some(shrink_stats) = shrink_stats.as_mut() {
            shrink_stats.drop_elapsed = shrink_removed_object_elapsed.as_us();
            shrink_stats.report(self.shrink_metric_name);
        }

        if did_reuse {
            if let Some(reused) = allocated_object.as_mut() {
                self.recycler.stats.reuse.fetch_add(1, Ordering::Relaxed);
                reused.reset();
                return allocated_object;
            }
        }

        if should_allocate_new {
            let mut t = T::default();
            t.set_recycler(Arc::downgrade(&self.recycler));
            Some(t)
        } else {
            None
        }
    }

    fn get_shrink_target(shrink_ratio: f64, current_size: u32) -> u32 {
        (shrink_ratio * current_size as f64).ceil() as u32
    }
}

impl<T: Default + Reset> RecyclerX<T> {
    pub fn recycle(&self, x: T) {
        let len = {
            let mut gc = self.gc.lock().expect("recycler lock in pub fn recycle");
            gc.object_pool.push(x);
            gc.len()
        };

        let max_gc = self.stats.max_gc.load(Ordering::Relaxed);
        if len > max_gc {
            // this is not completely accurate, but for most cases should be fine.
            let _ = self.stats.max_gc.compare_exchange(
                max_gc,
                len,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        let total = self.stats.total.load(Ordering::Relaxed);
        let reuse = self.stats.reuse.load(Ordering::Relaxed);
        let freed = self.stats.total.fetch_add(1, Ordering::Relaxed);
        datapoint_debug!(
            "recycler",
            ("gc_len", len as i64, i64),
            ("total", total as i64, i64),
            ("freed", freed as i64, i64),
            ("reuse", reuse as i64, i64),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketsRecycler;
    use std::{thread::sleep, time::Duration};

    impl Reset for u64 {
        fn reset(&mut self) {
            *self = 10;
        }
        fn warm(&mut self, _size_hint: usize) {}
        fn set_recycler(&mut self, _recycler: Weak<RecyclerX<Self>>) {}
        fn unset_recycler(&mut self) {}
    }

    #[test]
    fn test_recycler() {
        let recycler = Recycler::new("");
        let mut y: u64 = recycler.allocate().unwrap();
        assert_eq!(y, 0);
        y = 20;
        let recycler2 = recycler.clone();
        recycler2.recycler.recycle(y);
        assert_eq!(recycler.recycler.gc.lock().unwrap().len(), 1);
        let z = recycler.allocate().unwrap();
        assert_eq!(z, 10);
        assert_eq!(recycler.recycler.gc.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_recycler_limit() {
        let limit = 10;
        assert!(limit <= DEFAULT_MINIMUM_OBJECT_COUNT);
        // Use PacketRecycler so that dropping the allocated object
        // actually recycles
        let recycler = PacketsRecycler::new_with_limit("", limit);
        let mut allocated_items = vec![];
        for i in 0..limit * 2 {
            let x = recycler.allocate();
            if i >= limit {
                assert!(x.is_none());
            } else {
                allocated_items.push(x.unwrap());
            }
        }
        assert_eq!(
            recycler.recycler.gc.lock().unwrap().total_allocated_count,
            limit
        );
        assert_eq!(recycler.recycler.gc.lock().unwrap().len(), 0_usize);
        drop(allocated_items);
        assert_eq!(
            recycler.recycler.gc.lock().unwrap().total_allocated_count,
            limit
        );
        assert_eq!(recycler.recycler.gc.lock().unwrap().len(), limit as usize);
    }

    #[test]
    fn test_recycler_shrink() {
        let limit = DEFAULT_MINIMUM_OBJECT_COUNT * 2;
        let max_above_shrink_ratio_count = 2;
        let shrink_ratio = 0.80;
        let recycler = PacketsRecycler::new_with_limit("", limit);
        {
            let mut locked_recycler = recycler.recycler.gc.lock().unwrap();
            // Make the shrink interval a long time so shrinking doesn't happen yet
            locked_recycler.check_shrink_interval_ms = std::u32::MAX;
            // Set the count to one so that we shrink on every other allocation later.
            locked_recycler.max_above_shrink_ratio_count = max_above_shrink_ratio_count;
            locked_recycler.shrink_ratio = shrink_ratio;
        }

        let mut allocated_items = vec![];
        for _ in 0..limit {
            allocated_items.push(recycler.allocate().unwrap());
        }
        assert_eq!(
            recycler.recycler.gc.lock().unwrap().total_allocated_count,
            limit
        );
        assert_eq!(recycler.recycler.gc.lock().unwrap().len(), 0);
        drop(allocated_items);
        assert_eq!(recycler.recycler.gc.lock().unwrap().len(), limit as usize);

        let shrink_interval = 10;
        {
            let mut locked_recycler = recycler.recycler.gc.lock().unwrap();
            locked_recycler.check_shrink_interval_ms = shrink_interval;
        }

        let mut current_total_allocated_count =
            recycler.recycler.gc.lock().unwrap().total_allocated_count;

        // Shrink the recycler until it hits the minimum
        let mut i = 0;
        while current_total_allocated_count != DEFAULT_MINIMUM_OBJECT_COUNT {
            sleep(Duration::from_millis(shrink_interval as u64 * 2));
            recycler.allocate().unwrap();
            let expected_above_shrink_ratio_count = (i + 1) % max_above_shrink_ratio_count;
            assert_eq!(
                recycler
                    .recycler
                    .gc
                    .lock()
                    .unwrap()
                    .above_shrink_ratio_count,
                (i + 1) % max_above_shrink_ratio_count
            );
            if expected_above_shrink_ratio_count == 0 {
                // Shrink happened, update the expected `current_total_allocated_count`;
                current_total_allocated_count = std::cmp::max(
                    Recycler::<u64>::get_shrink_target(shrink_ratio, current_total_allocated_count),
                    DEFAULT_MINIMUM_OBJECT_COUNT,
                );
                assert_eq!(
                    recycler.recycler.gc.lock().unwrap().total_allocated_count,
                    current_total_allocated_count
                );
                assert_eq!(
                    recycler.recycler.gc.lock().unwrap().len(),
                    current_total_allocated_count as usize
                );
            }

            i += 1;
        }
    }
}
