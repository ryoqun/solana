/// ExecuteCostTable is aggregated by Cost Model, it keeps each program's
/// average cost in its HashMap, with fixed capacity to avoid from growing
/// unchecked.
/// When its capacity limit is reached, it prunes old and less-used programs
/// to make room for new ones.
use {
    log::*, solana_program_runtime::compute_budget::DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
    solana_sdk::pubkey::Pubkey, std::collections::HashMap,
};

// prune is rather expensive op, free up bulk space in each operation
// would be more efficient. PRUNE_RATIO defines the after prune table
// size will be original_size * PRUNE_RATIO.
const PRUNE_RATIO: f64 = 0.75;
// with 50_000 TPS as norm, weights occurrences '100' per microsec
const OCCURRENCES_WEIGHT: i64 = 100;

const DEFAULT_CAPACITY: usize = 1024;

#[derive(AbiExample, Debug)]
pub struct ExecuteCostTable {
    capacity: usize,
    table: HashMap<Pubkey, u64>,
    occurrences: HashMap<Pubkey, (usize, u128)>,
}

impl Default for ExecuteCostTable {
    fn default() -> Self {
        ExecuteCostTable::new(DEFAULT_CAPACITY)
    }
}

impl ExecuteCostTable {
    pub fn new(cap: usize) -> Self {
        Self {
            capacity: cap,
            table: HashMap::with_capacity(cap),
            occurrences: HashMap::with_capacity(cap),
        }
    }

    pub fn get_count(&self) -> usize {
        self.table.len()
    }

    /// default program cost, set to ComputeBudget::DEFAULT_COMPUTE_UNIT_LIMIT
    pub fn get_default_compute_unit_limit(&self) -> u64 {
        DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT as u64
    }

    /// average cost of all recorded programs
    pub fn get_global_average_program_cost(&self) -> u64 {
        if self.table.is_empty() {
            self.get_default_compute_unit_limit()
        } else {
            self.table.iter().map(|(_, value)| value).sum::<u64>() / self.get_count() as u64
        }
    }

    /// the most frequently occurring program's cost
    pub fn get_statistical_mode_program_cost(&self) -> u64 {
        if self.occurrences.is_empty() {
            self.get_default_compute_unit_limit()
        } else {
            let key = self
                .occurrences
                .iter()
                .max_by_key(|&(_, count)| count)
                .map(|(key, _)| key)
                .expect("cannot find mode from cost table");

            *self.table.get(key).unwrap()
        }
    }

    /// returns None if program doesn't exist in table. In this case,
    /// `get_default_compute_unit_limit()`, `get_global_average_program_cost()`
    /// or `get_statistical_mode_program_cost()` can be used to assign a value
    /// to new program.
    pub fn get_cost(&self, key: &Pubkey) -> Option<&u64> {
        self.table.get(key)
    }

    /// update-or-insert should be infallible. Query the result of upsert,
    /// often requires additional calculation, should be lazy.
    pub fn upsert(&mut self, key: &Pubkey, value: u64) {
        let need_to_add = !self.table.contains_key(key);
        let current_size = self.get_count();
        if current_size == self.capacity && need_to_add {
            self.prune_to(&((current_size as f64 * PRUNE_RATIO) as usize));
        }

        let program_cost = self.table.entry(*key).or_insert(value);
        *program_cost = (*program_cost + value) / 2;

        let (count, timestamp) = self
            .occurrences
            .entry(*key)
            .or_insert((0, Self::micros_since_epoch()));
        *count += 1;
        *timestamp = Self::micros_since_epoch();
    }

    /// prune the old programs so the table contains `new_size` of records,
    /// where `old` is defined as weighted age, which is negatively correlated
    /// with program's age and how frequently the program is occurrenced.
    fn prune_to(&mut self, new_size: &usize) {
        debug!(
            "prune cost table, current size {}, new size {}",
            self.get_count(),
            new_size
        );

        if *new_size == self.get_count() {
            return;
        }

        if *new_size == 0 {
            self.table.clear();
            self.occurrences.clear();
            return;
        }

        let now = Self::micros_since_epoch();
        let mut sorted_by_weighted_age: Vec<_> = self
            .occurrences
            .iter()
            .map(|(key, (count, timestamp))| {
                let age = now - timestamp;
                let weighted_age = *count as i64 * OCCURRENCES_WEIGHT + -(age as i64);
                (weighted_age, *key)
            })
            .collect();
        sorted_by_weighted_age.sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());

        for i in sorted_by_weighted_age.iter() {
            self.table.remove(&i.1);
            self.occurrences.remove(&i.1);
            if *new_size == self.get_count() {
                break;
            }
        }
    }

    fn micros_since_epoch() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
    }
}
