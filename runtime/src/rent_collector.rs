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
enum RentResult {
    /// maybe collect rent later, leave account alone
    LeaveAloneNoRent,
    /// collect rent
    CollectRent {
        new_rent_epoch: Epoch,
        rent_due: u64, // lamports
    },
}

impl RentCollector {
    pub(crate) fn new(
        epoch: Epoch,
        epoch_schedule: EpochSchedule,
        slots_per_year: f64,
        rent: Rent,
    ) -> Self {
        Self {
            epoch,
            epoch_schedule,
            slots_per_year,
            rent,
        }
    }

    pub(crate) fn clone_with_epoch(&self, epoch: Epoch) -> Self {
        Self {
            epoch,
            ..self.clone()
        }
    }

    /// true if it is easy to determine this account should consider having rent collected from it
    pub(crate) fn should_collect_rent(
        &self,
        address: &Pubkey,
        account: &impl ReadableAccount,
    ) -> bool {
        !(account.executable() // executable accounts must be rent-exempt balance
            || *address == incinerator::id())
    }

    /// given an account that 'should_collect_rent'
    /// returns (amount rent due, is_exempt_from_rent)
    pub(crate) fn get_rent_due(&self, account: &impl ReadableAccount) -> RentDue {
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
    pub(crate) fn collect_from_existing_account(
        &self,
        address: &Pubkey,
        account: &mut AccountSharedData,
        filler_account_suffix: Option<&Pubkey>,
    ) -> CollectedInfo {
        match self.calculate_rent_result(address, account, filler_account_suffix) {
            RentResult::LeaveAloneNoRent => CollectedInfo::default(),
            RentResult::CollectRent {
                new_rent_epoch,
                rent_due,
            } => match account.lamports().checked_sub(rent_due) {
                None | Some(0) => {
                    let account = std::mem::take(account);
                    CollectedInfo {
                        rent_amount: account.lamports(),
                        account_data_len_reclaimed: account.data().len() as u64,
                    }
                }
                Some(lamports) => {
                    account.set_lamports(lamports);
                    account.set_rent_epoch(new_rent_epoch);
                    CollectedInfo {
                        rent_amount: rent_due,
                        account_data_len_reclaimed: 0u64,
                    }
                }
            },
        }
    }

    /// determine what should happen to collect rent from this account
    #[must_use]
    fn calculate_rent_result(
        &self,
        address: &Pubkey,
        account: &impl ReadableAccount,
        filler_account_suffix: Option<&Pubkey>,
    ) -> RentResult {
        if self.can_skip_rent_collection(address, account, filler_account_suffix) {
            return RentResult::LeaveAloneNoRent;
        }
        match self.get_rent_due(account) {
            // Rent isn't collected for the next epoch.
            // Make sure to check exempt status again later in current epoch.
            RentDue::Exempt => RentResult::LeaveAloneNoRent,
            // Maybe collect rent later, leave account alone.
            RentDue::Paying(0) => RentResult::LeaveAloneNoRent,
            // Rent is collected for next epoch.
            RentDue::Paying(rent_due) => RentResult::CollectRent {
                new_rent_epoch: self.epoch + 1,
                rent_due,
            },
        }
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
pub(crate) struct CollectedInfo {
    /// Amount of rent collected from account
    pub(crate) rent_amount: u64,
    /// Size of data reclaimed from account (happens when account's lamports go to zero)
    pub(crate) account_data_len_reclaimed: u64,
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
