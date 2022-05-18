//! calculate and collect rent from Accounts
use {
    log::*,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        clock::Epoch,
        epoch_schedule::EpochSchedule,
        genesis_config::GenesisConfig,
        incinerator,
        pubkey::Pubkey,
        rent::{Rent, RentDue},
    },
};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, AbiExample)]
pub struct RentCollector {
    pub epoch: Epoch,
    pub epoch_schedule: EpochSchedule,
    pub slots_per_year: f64,
    pub rent: Rent,
}

impl Default for RentCollector {
    fn default() -> Self {
        Self {
            epoch: Epoch::default(),
            epoch_schedule: EpochSchedule::default(),
            // derive default value using GenesisConfig::default()
            slots_per_year: GenesisConfig::default().slots_per_year(),
            rent: Rent::default(),
        }
    }
}

/// when rent is collected for this account, this is the action to apply to the account
#[derive(Debug)]
pub enum RentResult {
    /// maybe collect rent later, leave account alone
    LeaveAloneNoRent,
    /// collect rent
    /// value is (new rent epoch, lamports of rent_due)
    CollectRent((Epoch, u64)),
}

impl RentCollector {
    pub fn new(
        epoch: Epoch,
        epoch_schedule: &EpochSchedule,
        slots_per_year: f64,
        rent: &Rent,
    ) -> Self {
        Self {
            epoch,
            epoch_schedule: *epoch_schedule,
            slots_per_year,
            rent: *rent,
        }
    }

    pub fn clone_with_epoch(&self, epoch: Epoch) -> Self {
        self.clone_with_epoch_and_rate(epoch, self.rent.lamports_per_byte_year)
    }

    pub fn clone_with_epoch_and_rate(&self, epoch: Epoch, lamports_per_byte_year: u64) -> Self {
        let rent = if lamports_per_byte_year != self.rent.lamports_per_byte_year {
            Rent {
                lamports_per_byte_year,
                ..self.rent
            }
        } else {
            self.rent
        };
        Self {
            rent,
            epoch,
            ..self.clone()
        }
    }

    /// true if it is easy to determine this account should consider having rent collected from it
    pub fn should_collect_rent(&self, address: &Pubkey, account: &impl ReadableAccount) -> bool {
        !(account.executable() // executable accounts must be rent-exempt balance
            || *address == incinerator::id())
    }

    /// given an account that 'should_collect_rent'
    /// returns (amount rent due, is_exempt_from_rent)
    pub fn get_rent_due(&self, account: &impl ReadableAccount) -> RentDue {
        if self
            .rent
            .is_exempt(account.lamports(), account.data().len())
        {
            RentDue::Exempt
        } else {
            let account_rent_epoch = account.rent_epoch();
            let slots_elapsed: u64 = (account_rent_epoch..=self.epoch)
                .map(|epoch| self.epoch_schedule.get_slots_in_epoch(epoch + 1))
                .sum();

            // avoid infinite rent in rust 1.45
            let years_elapsed = if self.slots_per_year != 0.0 {
                slots_elapsed as f64 / self.slots_per_year
            } else {
                0.0
            };

            // we know this account is not exempt
            let due = self.rent.due_amount(account.data().len(), years_elapsed);

            // we expect rent_epoch to always be one of: {0, self.epoch-1, self.epoch, self.epoch+1}
            if account_rent_epoch != 0
                && (account_rent_epoch + 1 < self.epoch || account_rent_epoch > self.epoch + 1)
            {
                // this should not occur in a running validator
                if due == 0 {
                    inc_new_counter_info!("rent-collector-rent-epoch-range-large-exempt", 1);
                } else {
                    inc_new_counter_info!("rent-collector-rent-epoch-range-large-paying", 1);
                }
            }

            RentDue::Paying(due)
        }
    }

    // Updates the account's lamports and status, and returns the amount of rent collected, if any.
    // This is NOT thread safe at some level. If we try to collect from the same account in
    // parallel, we may collect twice.
    #[must_use = "add to Bank::collected_rent"]
    pub fn collect_from_existing_account(
        &self,
        address: &Pubkey,
        account: &mut AccountSharedData,
        filler_account_suffix: Option<&Pubkey>,
    ) -> CollectedInfo {
        match self.calculate_rent_result(address, account, filler_account_suffix) {
            RentResult::LeaveAloneNoRent => CollectedInfo::default(),
            RentResult::CollectRent((next_epoch, rent_due)) => {
                account.set_rent_epoch(next_epoch);

                let begin_lamports = account.lamports();
                account.saturating_sub_lamports(rent_due);
                let end_lamports = account.lamports();
                let mut account_data_len_reclaimed = 0;
                if end_lamports == 0 {
                    account_data_len_reclaimed = account.data().len() as u64;
                    *account = AccountSharedData::default();
                }
                CollectedInfo {
                    rent_amount: begin_lamports - end_lamports,
                    account_data_len_reclaimed,
                }
            }
        }
    }

    /// determine what should happen to collect rent from this account
    #[must_use]
    pub fn calculate_rent_result(
        &self,
        address: &Pubkey,
        account: &impl ReadableAccount,
        filler_account_suffix: Option<&Pubkey>,
    ) -> RentResult {
        if self.can_skip_rent_collection(address, account, filler_account_suffix) {
            return RentResult::LeaveAloneNoRent;
        }

        let rent_due = self.get_rent_due(account);
        if let RentDue::Paying(0) = rent_due {
            // maybe collect rent later, leave account alone
            return RentResult::LeaveAloneNoRent;
        }

        let epoch_increment = match rent_due {
            // Rent isn't collected for the next epoch
            // Make sure to check exempt status again later in current epoch
            RentDue::Exempt => 0,
            // Rent is collected for next epoch
            RentDue::Paying(_) => 1,
        };
        RentResult::CollectRent((self.epoch + epoch_increment, rent_due.lamports()))
    }

    #[must_use = "add to Bank::collected_rent"]
    pub fn collect_from_created_account(
        &self,
        address: &Pubkey,
        account: &mut AccountSharedData,
    ) -> CollectedInfo {
        // initialize rent_epoch as created at this epoch
        account.set_rent_epoch(self.epoch);
        self.collect_from_existing_account(address, account, None)
    }

    /// Performs easy checks to see if rent collection can be skipped
    fn can_skip_rent_collection(
        &self,
        address: &Pubkey,
        account: &impl ReadableAccount,
        filler_account_suffix: Option<&Pubkey>,
    ) -> bool {
        !self.should_collect_rent(address, account)
            || account.rent_epoch() > self.epoch
            || crate::accounts_db::AccountsDb::is_filler_account_helper(
                address,
                filler_account_suffix,
            )
    }
}

/// Information computed during rent collection
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct CollectedInfo {
    /// Amount of rent collected from account
    pub rent_amount: u64,
    /// Size of data reclaimed from account (happens when account's lamports go to zero)
    pub account_data_len_reclaimed: u64,
}

impl std::ops::Add for CollectedInfo {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self {
            rent_amount: self.rent_amount + other.rent_amount,
            account_data_len_reclaimed: self.account_data_len_reclaimed
                + other.account_data_len_reclaimed,
        }
    }
}

impl std::ops::AddAssign for CollectedInfo {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

