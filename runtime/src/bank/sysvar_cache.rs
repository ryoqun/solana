use {
    super::Bank,
    solana_program_runtime::sysvar_cache::SysvarCache,
    solana_sdk::{account::ReadableAccount, sysvar::Sysvar},
};

impl Bank {
    pub(crate) fn fill_missing_sysvar_cache_entries(&self) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        if sysvar_cache.get_clock().is_err() {
            if let Some(clock) = self.load_sysvar_account() {
                sysvar_cache.set_clock(clock);
            }
        }
        if sysvar_cache.get_epoch_schedule().is_err() {
            if let Some(epoch_schedule) = self.load_sysvar_account() {
                sysvar_cache.set_epoch_schedule(epoch_schedule);
            }
        }
        #[allow(deprecated)]
        if sysvar_cache.get_fees().is_err() {
            if let Some(fees) = self.load_sysvar_account() {
                sysvar_cache.set_fees(fees);
            }
        }
        if sysvar_cache.get_rent().is_err() {
            if let Some(rent) = self.load_sysvar_account() {
                sysvar_cache.set_rent(rent);
            }
        }
        if sysvar_cache.get_slot_hashes().is_err() {
            if let Some(slot_hashes) = self.load_sysvar_account() {
                sysvar_cache.set_slot_hashes(slot_hashes);
            }
        }
    }

    pub(crate) fn reset_sysvar_cache(&self) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        *sysvar_cache = SysvarCache::default();
    }

    fn load_sysvar_account<T: Sysvar>(&self) -> Option<T> {
        if let Some(account) = self.get_account_with_fixed_root(&T::id()) {
            bincode::deserialize(account.data()).ok()
        } else {
            None
        }
    }
}

