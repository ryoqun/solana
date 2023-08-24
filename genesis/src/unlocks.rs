//! lockups generator
use {
    solana_sdk::{clock::Epoch, epoch_schedule::EpochSchedule, timing::years_as_slots},
    std::time::Duration,
};

#[derive(Debug)]
pub struct UnlockInfo {
    pub cliff_fraction: f64,
    pub cliff_years: f64,
    pub unlocks: usize,
    pub unlock_years: f64,
    pub custodian: &'static str,
}

#[derive(Debug, Default, Clone)]
pub struct Unlocks {
    /// where in iteration over unlocks, loop var
    i: usize,
    /// number of unlocks after the first cliff
    unlocks: usize,
    /// fraction unlocked as of last event
    prev_fraction: f64,

    /// first cliff
    /// fraction of unlocked at first cliff
    cliff_fraction: f64,
    /// time of cliff, in epochs, 0-based
    cliff_epoch: Epoch,

    /// post cliff
    /// fraction unlocked at each post-cliff unlock
    unlock_fraction: f64,
    /// time between each post-cliff unlock, in Epochs
    unlock_epochs: Epoch,
}

impl Unlocks {
    pub fn new(
        cliff_fraction: f64, // first cliff fraction
        cliff_year: f64,     // first cliff time, starting from genesis, in years
        unlocks: usize,      // number of follow-on unlocks
        unlock_years: f64,   // years between each following unlock
        epoch_schedule: &EpochSchedule,
        tick_duration: &Duration,
        ticks_per_slot: u64,
    ) -> Self {
        // convert cliff year to a slot height, as the cliff_year is considered from genesis
        let cliff_slot = years_as_slots(cliff_year, tick_duration, ticks_per_slot) as u64;

        // get the first cliff epoch from that slot height
        let cliff_epoch = epoch_schedule.get_epoch(cliff_slot);

        // assumes that the first cliff is after any epoch warmup and that follow-on
        //  epochs are uniform in length
        let first_unlock_slot =
            years_as_slots(cliff_year + unlock_years, tick_duration, ticks_per_slot) as u64;
        let unlock_epochs = epoch_schedule.get_epoch(first_unlock_slot) - cliff_epoch;

        Self::from_epochs(cliff_fraction, cliff_epoch, unlocks, unlock_epochs)
    }

    pub fn from_epochs(
        cliff_fraction: f64,  // first cliff fraction
        cliff_epoch: Epoch,   // first cliff epoch
        unlocks: usize,       //  number of follow-on unlocks
        unlock_epochs: Epoch, // epochs between each following unlock
    ) -> Self {
        let unlock_fraction = if unlocks != 0 {
            (1.0 - cliff_fraction) / unlocks as f64
        } else {
            0.0
        };

        Self {
            prev_fraction: 0.0,
            i: 0,
            unlocks,
            cliff_fraction,
            cliff_epoch,
            unlock_fraction,
            unlock_epochs,
        }
    }
}

impl Iterator for Unlocks {
    type Item = Unlock;

    fn next(&mut self) -> Option<Self::Item> {
        let i = self.i;
        if i == 0 {
            self.i += 1;
            self.prev_fraction = self.cliff_fraction;

            Some(Unlock {
                prev_fraction: 0.0,
                fraction: self.cliff_fraction,
                epoch: self.cliff_epoch,
            })
        } else if i <= self.unlocks {
            self.i += 1;

            let prev_fraction = self.prev_fraction;
            // move forward, tortured-looking math comes from wanting to reach 1.0 by the last
            //  unlock
            self.prev_fraction = 1.0 - (self.unlocks - i) as f64 * self.unlock_fraction;

            Some(Unlock {
                prev_fraction,
                fraction: self.prev_fraction,
                epoch: self.cliff_epoch + i as u64 * self.unlock_epochs,
            })
        } else {
            None
        }
    }
}

/// describes an unlock event
#[derive(Debug, Default)]
pub struct Unlock {
    /// the epoch height at which this unlock occurs
    pub epoch: Epoch,
    /// the fraction that was unlocked last iteration
    pub prev_fraction: f64,
    /// the fraction unlocked this iteration
    pub fraction: f64,
}

impl Unlock {
    /// the number of lamports unlocked at this event
    #[allow(clippy::float_cmp)]
    pub fn amount(&self, total: u64) -> u64 {
        if self.fraction == 1.0 {
            total - (self.prev_fraction * total as f64) as u64
        } else {
            (self.fraction * total as f64) as u64 - (self.prev_fraction * total as f64) as u64
        }
    }
}
