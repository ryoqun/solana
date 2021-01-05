pub fn datapoint(_name: &'static str) {
}

pub struct Allocatedp {
}

impl Allocatedp {
    pub fn default() -> Self {
        Self {}
    }

    /// Return current thread heap usage
    pub fn get(&self) -> u64 {
        0
    }

    /// Return the difference in thread heap usage since a previous `get()`
    pub fn since(&self, previous: u64) -> i64 {
        self.get() as i64 - previous as i64
    }
}
