use {std::time::Duration, tokio::time::Instant};

#[derive(Debug)]
pub struct RateLimiter {
    /// count of requests in an interval
    pub(crate) count: u64,

    /// Throttle start time
    throttle_start_instant: Instant,
    interval: Duration,
    limit: u64,
}

/// A naive rate limiter, to be replaced by using governor which has more even
/// distribution of requests passing through using GCRA algroithm.
impl RateLimiter {
    pub fn new(limit: u64, interval: Duration) -> Self {
        Self {
            count: 0,
            throttle_start_instant: Instant::now(),
            interval,
            limit,
        }
    }

    /// Reset the counter and throttling start instant if needed.
    pub fn reset_throttling_params_if_needed(&mut self) {
        if Instant::now().duration_since(self.throttle_start_instant) > self.interval {
            self.throttle_start_instant = Instant::now();
            self.count = 0;
        }
    }

    /// Check if a single request should be allowed to pass through the rate limiter
    /// When it is allowed, the rate limiter state is updated to reflect it has been
    /// allowed. For a unique request, the caller should call it only once when it is allowed.
    pub fn check_and_update(&mut self) -> bool {
        self.reset_throttling_params_if_needed();
        if self.count >= self.limit {
            return false;
        }

        self.count = self.count.saturating_add(1);
        true
    }

    /// Return the start instant for the current throttle interval.
    pub fn throttle_start_instant(&self) -> &Instant {
        &self.throttle_start_instant
    }
}
