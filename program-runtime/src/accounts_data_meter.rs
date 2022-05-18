//! The accounts data space has a maximum size it is permitted to grow to.  This module contains
//! the constants and types for tracking and metering the accounts data space during program
//! runtime.
use solana_sdk::instruction::InstructionError;

/// The maximum allowed size, in bytes, of the accounts data
/// 128 GB was chosen because it is the RAM amount listed under Hardware Recommendations on
/// [Validator Requirements](https://docs.solana.com/running-validator/validator-reqs), and
/// validators often put the ledger on a RAM disk (i.e. tmpfs).
pub const MAX_ACCOUNTS_DATA_LEN: u64 = 128_000_000_000;

/// Meter and track the amount of available accounts data space
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct AccountsDataMeter {
    /// The maximum amount of accounts data space that can be used (in bytes)
    maximum: u64,

    /// The initial amount of accounts data space used (in bytes)
    initial: u64,

    /// The amount of accounts data space that has changed since `initial` (in bytes)
    delta: i64,
}

impl AccountsDataMeter {
    /// Make a new AccountsDataMeter
    #[must_use]
    pub fn new(initial_accounts_data_len: u64) -> Self {
        let accounts_data_meter = Self {
            maximum: MAX_ACCOUNTS_DATA_LEN,
            initial: initial_accounts_data_len,
            delta: 0,
        };
        debug_assert!(accounts_data_meter.initial <= accounts_data_meter.maximum);
        accounts_data_meter
    }

    /// Return the maximum amount of accounts data space that can be used (in bytes)
    pub fn maximum(&self) -> u64 {
        self.maximum
    }

    /// Return the initial amount of accounts data space used (in bytes)
    pub fn initial(&self) -> u64 {
        self.initial
    }

    /// Return the amount of accounts data space that has changed (in bytes)
    pub fn delta(&self) -> i64 {
        self.delta
    }

    /// Return the current amount of accounts data space used (in bytes)
    pub fn current(&self) -> u64 {
        /// NOTE: Mixed integer ops currently not stable, so copying the impl.
        /// * https://github.com/rust-lang/rust/issues/87840
        /// * https://github.com/a1phyr/rust/blob/47edde1086412b36e9efd6098b191ec15a2a760a/library/core/src/num/uint_macros.rs#L1039-L1048
        const fn saturating_add_signed(lhs: u64, rhs: i64) -> u64 {
            let (res, overflow) = lhs.overflowing_add(rhs as u64);
            if overflow == (rhs < 0) {
                res
            } else if overflow {
                u64::MAX
            } else {
                u64::MIN
            }
        }
        saturating_add_signed(self.initial, self.delta)
    }

    /// Get the remaining amount of accounts data space (in bytes)
    pub fn remaining(&self) -> u64 {
        self.maximum.saturating_sub(self.current())
    }

    /// Adjust the space used by accounts data by `amount` (in bytes).
    ///
    /// If `amount` is *positive*, we *increase* the space used by accounts data.  If `amount` is
    /// *negative*, we *decrease* the space used by accounts data.  If `amount` is greater than
    /// the remaining space, return an error and *do not* adjust accounts data space.
    pub fn adjust_delta(&mut self, amount: i64) -> Result<(), InstructionError> {
        if amount > self.remaining() as i64 {
            return Err(InstructionError::MaxAccountsDataSizeExceeded);
        }
        self.adjust_delta_unchecked(amount);
        Ok(())
    }

    /// Unconditionally adjust accounts data space.  Refer to `adjust_delta()` for more
    /// documentation.
    pub fn adjust_delta_unchecked(&mut self, amount: i64) {
        self.delta = self.delta.saturating_add(amount);
    }
}

#[cfg(test)]
impl AccountsDataMeter {
    pub fn set_maximum(&mut self, maximum: u64) {
        self.maximum = maximum;
    }
    pub fn set_initial(&mut self, initial: u64) {
        self.initial = initial;
    }
}

