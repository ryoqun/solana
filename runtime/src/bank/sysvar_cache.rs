use {super::Bank, solana_program_runtime::sysvar_cache::SysvarCache};

impl Bank {
    pub(crate) fn fill_missing_sysvar_cache_entries(&self) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        sysvar_cache.fill_missing_entries(|pubkey| self.get_account_with_fixed_root(pubkey));
    }

    pub(crate) fn reset_sysvar_cache(&self) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        sysvar_cache.reset();
    }

    pub fn get_sysvar_cache_for_tests(&self) -> SysvarCache {
        self.sysvar_cache.read().unwrap().clone()
    }
}
