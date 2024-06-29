use {
    crate::nonblocking::rate_limiter::RateLimiter,
    dashmap::DashMap,
    std::{hash::Hash, time::Duration},
};

pub struct KeyedRateLimiter<K> {
    limiters: DashMap<K, RateLimiter>,
    interval: Duration,
    limit: u64,
}

impl<K> KeyedRateLimiter<K>
where
    K: Eq + Hash,
{
    /// Create a keyed rate limiter with `limit` count with a rate limit `interval`
    pub fn new(limit: u64, interval: Duration) -> Self {
        Self {
            limiters: DashMap::default(),
            interval,
            limit,
        }
    }

    /// Check if the connection from the said `key` is allowed to pass through the rate limiter.
    /// When it is allowed, the rate limiter state is updated to reflect it has been
    /// allowed. For a unique request, the caller should call it only once when it is allowed.
    pub fn check_and_update(&self, key: K) -> bool {
        let allowed = match self.limiters.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let limiter = entry.get_mut();
                limiter.check_and_update()
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => entry
                .insert(RateLimiter::new(self.limit, self.interval))
                .value_mut()
                .check_and_update(),
        };
        allowed
    }

    /// retain only keys whose throttle start date is within the throttle interval.
    /// Otherwise drop them as inactive
    pub fn retain_recent(&self) {
        let now = tokio::time::Instant::now();
        self.limiters.retain(|_key, limiter| {
            now.duration_since(*limiter.throttle_start_instant()) <= self.interval
        });
    }

    /// Returns the number of "live" keys in the rate limiter.
    pub fn len(&self) -> usize {
        self.limiters.len()
    }

    /// Returns `true` if the rate limiter has no keys in it.
    pub fn is_empty(&self) -> bool {
        self.limiters.is_empty()
    }
}
