use {
    solana_sdk::timing::duration_as_ns,
    std::{
        fmt,
        time::{Duration, Instant},
    },
};

#[derive(Debug)]
pub struct Measure {
    name: &'static str,
    start: Instant,
    duration: u64,
}

impl Measure {
    pub fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Instant::now(),
            duration: 0,
        }
    }

    pub fn stop(&mut self) {
        self.duration = duration_as_ns(&self.start.elapsed());
    }

    pub fn as_ns(&self) -> u64 {
        self.duration
    }

    pub fn as_us(&self) -> u64 {
        self.duration / 1000
    }

    pub fn as_ms(&self) -> u64 {
        self.duration / (1000 * 1000)
    }

    pub fn as_s(&self) -> f32 {
        self.duration as f32 / (1000.0f32 * 1000.0f32 * 1000.0f32)
    }

    pub fn as_duration(&self) -> Duration {
        Duration::from_nanos(self.as_ns())
    }
}

impl fmt::Display for Measure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.duration == 0 {
            write!(f, "{} running", self.name)
        } else if self.as_us() < 1 {
            write!(f, "{} took {}ns", self.name, self.duration)
        } else if self.as_ms() < 1 {
            write!(f, "{} took {}us", self.name, self.as_us())
        } else if self.as_s() < 1. {
            write!(f, "{} took {}ms", self.name, self.as_ms())
        } else {
            write!(f, "{} took {:.1}s", self.name, self.as_s())
        }
    }
}
