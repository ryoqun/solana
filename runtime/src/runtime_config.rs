use solana_program_runtime::compute_budget::ComputeBudget;

/// Encapsulates flags that can be used to tweak the runtime behavior.
#[derive(AbiExample, Debug, Default, Clone)]
pub struct RuntimeConfig {
    pub bpf_jit: bool,
    pub skip_check_age: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub compute_budget: Option<ComputeBudget>,
    pub log_messages_bytes_limit: Option<usize>,
    pub transaction_account_lock_limit: Option<usize>,
}

impl RuntimeConfig {
    fn skip_check_age(&self) {
        self.skip_check_age.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}
