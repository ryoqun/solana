//! `cost_tracker` keeps tracking transaction cost per chained accounts as well as for entire block
//! The main functions are:
//! - would_fit(&tx_cost), immutable function to test if tx with tx_cost would fit into current block
//! - add_transaction_cost(&tx_cost), mutable function to accumulate tx_cost to tracker.
//!
use {
    crate::{block_cost_limits::*, cost_model::TransactionCost},
    solana_sdk::{clock::Slot, pubkey::Pubkey, saturating_add_assign},
    std::{cmp::Ordering, collections::HashMap},
};

const WRITABLE_ACCOUNTS_PER_BLOCK: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostTrackerError {
    /// would exceed block max limit
    WouldExceedBlockMaxLimit,

    /// would exceed vote max limit
    WouldExceedVoteMaxLimit,

    /// would exceed account max limit
    WouldExceedAccountMaxLimit,

    /// would exceed account data block limit
    WouldExceedAccountDataBlockLimit,

    /// would exceed account data total limit
    WouldExceedAccountDataTotalLimit,
}

#[derive(AbiExample, Debug)]
pub struct CostTracker {
    account_cost_limit: u64,
    block_cost_limit: u64,
    vote_cost_limit: u64,
    cost_by_writable_accounts: HashMap<Pubkey, u64>,
    block_cost: u64,
    vote_cost: u64,
    transaction_count: u64,
    account_data_size: u64,

    /// The amount of total account data size remaining.  If `Some`, then do not add transactions
    /// that would cause `account_data_size` to exceed this limit.
    account_data_size_limit: Option<u64>,
}

impl Default for CostTracker {
    fn default() -> Self {
        // Clippy doesn't like asserts in const contexts, so need to explicitly allow them.  For
        // more info, see this issue: https://github.com/rust-lang/rust-clippy/issues/8159
        #![allow(clippy::assertions_on_constants)]
        const _: () = assert!(MAX_WRITABLE_ACCOUNT_UNITS <= MAX_BLOCK_UNITS);
        const _: () = assert!(MAX_VOTE_UNITS <= MAX_BLOCK_UNITS);

        Self {
            account_cost_limit: MAX_WRITABLE_ACCOUNT_UNITS,
            block_cost_limit: MAX_BLOCK_UNITS,
            vote_cost_limit: MAX_VOTE_UNITS,
            cost_by_writable_accounts: HashMap::with_capacity(WRITABLE_ACCOUNTS_PER_BLOCK),
            block_cost: 0,
            vote_cost: 0,
            transaction_count: 0,
            account_data_size: 0,
            account_data_size_limit: None,
        }
    }
}

impl CostTracker {
    /// Construct and new CostTracker and set the account data size limit.
    #[must_use]
    pub fn new_with_account_data_size_limit(account_data_size_limit: Option<u64>) -> Self {
        Self {
            account_data_size_limit,
            ..Self::default()
        }
    }

    /// allows to adjust limits initiated during construction
    pub fn set_limits(
        &mut self,
        account_cost_limit: u64,
        block_cost_limit: u64,
        vote_cost_limit: u64,
    ) {
        self.account_cost_limit = account_cost_limit;
        self.block_cost_limit = block_cost_limit;
        self.vote_cost_limit = vote_cost_limit;
    }

    pub fn try_add(&mut self, tx_cost: &TransactionCost) -> Result<u64, CostTrackerError> {
        self.would_fit(tx_cost)?;
        self.add_transaction_cost(tx_cost);
        Ok(self.block_cost)
    }

    /// Using user requested compute-units to track cost.
    pub fn try_add_requested_cus(
        &mut self,
        write_lock_accounts: &[Pubkey],
        requested_cus: u64,
        is_vote: bool,
    ) -> Result<u64, CostTrackerError> {
        self.would_fit_internal(write_lock_accounts.iter(), requested_cus, is_vote, 0)?;
        self.add_transaction_cost_internal(write_lock_accounts.iter(), requested_cus, is_vote, 0);
        Ok(self.block_cost)
    }

    pub fn update_execution_cost(
        &mut self,
        estimated_tx_cost: &TransactionCost,
        actual_execution_units: u64,
    ) {
        let estimated_execution_units = estimated_tx_cost.bpf_execution_cost;
        match actual_execution_units.cmp(&estimated_execution_units) {
            Ordering::Equal => (),
            Ordering::Greater => {
                self.add_transaction_execution_cost(
                    estimated_tx_cost,
                    actual_execution_units - estimated_execution_units,
                );
            }
            Ordering::Less => {
                self.sub_transaction_execution_cost(
                    estimated_tx_cost,
                    estimated_execution_units - actual_execution_units,
                );
            }
        }
    }

    pub fn remove(&mut self, tx_cost: &TransactionCost) {
        self.remove_transaction_cost(tx_cost);
    }

    pub fn block_cost(&self) -> u64 {
        self.block_cost
    }

    pub fn transaction_count(&self) -> u64 {
        self.transaction_count
    }

    pub fn report_stats(&self, bank_slot: Slot) {
        // skip reporting if block is empty
        if self.transaction_count == 0 {
            return;
        }

        let (costliest_account, costliest_account_cost) = self.find_costliest_account();

        datapoint_info!(
            "cost_tracker_stats",
            ("bank_slot", bank_slot as i64, i64),
            ("block_cost", self.block_cost as i64, i64),
            ("vote_cost", self.vote_cost as i64, i64),
            ("transaction_count", self.transaction_count as i64, i64),
            ("number_of_accounts", self.number_of_accounts() as i64, i64),
            ("costliest_account", costliest_account.to_string(), String),
            ("costliest_account_cost", costliest_account_cost as i64, i64),
            ("account_data_size", self.account_data_size, i64),
        );
    }

    fn find_costliest_account(&self) -> (Pubkey, u64) {
        let mut costliest_account = Pubkey::default();
        let mut costliest_account_cost = 0;
        for (key, cost) in self.cost_by_writable_accounts.iter() {
            if *cost > costliest_account_cost {
                costliest_account = *key;
                costliest_account_cost = *cost;
            }
        }

        (costliest_account, costliest_account_cost)
    }

    fn would_fit(&self, tx_cost: &TransactionCost) -> Result<(), CostTrackerError> {
        self.would_fit_internal(
            tx_cost.writable_accounts.iter(),
            tx_cost.sum(),
            tx_cost.is_simple_vote,
            tx_cost.account_data_size,
        )
    }

    fn would_fit_internal<'a>(
        &self,
        write_lock_accounts: impl Iterator<Item = &'a Pubkey>,
        cost: u64,
        is_vote: bool,
        account_data_size: u64,
    ) -> Result<(), CostTrackerError> {
        let vote_cost = if is_vote { cost } else { 0 };

        // check against the total package cost
        if self.block_cost.saturating_add(cost) > self.block_cost_limit {
            return Err(CostTrackerError::WouldExceedBlockMaxLimit);
        }

        // if vote transaction, check if it exceeds vote_transaction_limit
        if self.vote_cost.saturating_add(vote_cost) > self.vote_cost_limit {
            return Err(CostTrackerError::WouldExceedVoteMaxLimit);
        }

        // check if the transaction itself is more costly than the account_cost_limit
        if cost > self.account_cost_limit {
            return Err(CostTrackerError::WouldExceedAccountMaxLimit);
        }

        // NOTE: Check if the total accounts data size is exceeded *before* the block accounts data
        // size.  This way, transactions are not unnecessarily retried.
        let account_data_size = self.account_data_size.saturating_add(account_data_size);
        if let Some(account_data_size_limit) = self.account_data_size_limit {
            if account_data_size > account_data_size_limit {
                return Err(CostTrackerError::WouldExceedAccountDataTotalLimit);
            }
        }

        if account_data_size > MAX_ACCOUNT_DATA_BLOCK_LEN {
            return Err(CostTrackerError::WouldExceedAccountDataBlockLimit);
        }

        // check each account against account_cost_limit,
        for account_key in write_lock_accounts {
            match self.cost_by_writable_accounts.get(account_key) {
                Some(chained_cost) => {
                    if chained_cost.saturating_add(cost) > self.account_cost_limit {
                        return Err(CostTrackerError::WouldExceedAccountMaxLimit);
                    } else {
                        continue;
                    }
                }
                None => continue,
            }
        }

        Ok(())
    }

    fn add_transaction_cost(&mut self, tx_cost: &TransactionCost) {
        self.add_transaction_cost_internal(
            tx_cost.writable_accounts.iter(),
            tx_cost.sum(),
            tx_cost.is_simple_vote,
            tx_cost.account_data_size,
        )
    }

    fn add_transaction_cost_internal<'a>(
        &mut self,
        write_lock_accounts: impl Iterator<Item = &'a Pubkey>,
        cost: u64,
        is_vote: bool,
        account_data_size: u64,
    ) {
        self.add_transaction_execution_cost_internal(write_lock_accounts, is_vote, cost);
        saturating_add_assign!(self.account_data_size, account_data_size);
        saturating_add_assign!(self.transaction_count, 1);
    }

    fn remove_transaction_cost(&mut self, tx_cost: &TransactionCost) {
        let cost = tx_cost.sum();
        self.sub_transaction_execution_cost(tx_cost, cost);
        self.account_data_size = self
            .account_data_size
            .saturating_sub(tx_cost.account_data_size);
        self.transaction_count = self.transaction_count.saturating_sub(1);
    }

    /// Apply additional actual execution units to cost_tracker
    fn add_transaction_execution_cost(&mut self, tx_cost: &TransactionCost, adjustment: u64) {
        self.add_transaction_execution_cost_internal(
            tx_cost.writable_accounts.iter(),
            tx_cost.is_simple_vote,
            adjustment,
        )
    }

    fn add_transaction_execution_cost_internal<'a>(
        &mut self,
        write_lock_accounts: impl Iterator<Item = &'a Pubkey>,
        is_vote: bool,
        adjustment: u64,
    ) {
        for account_key in write_lock_accounts {
            let account_cost = self
                .cost_by_writable_accounts
                .entry(*account_key)
                .or_insert(0);
            *account_cost = account_cost.saturating_add(adjustment);
        }
        self.block_cost = self.block_cost.saturating_add(adjustment);
        if is_vote {
            self.vote_cost = self.vote_cost.saturating_add(adjustment);
        }
    }

    /// Substract extra execution units from cost_tracker
    fn sub_transaction_execution_cost(&mut self, tx_cost: &TransactionCost, adjustment: u64) {
        for account_key in tx_cost.writable_accounts.iter() {
            let account_cost = self
                .cost_by_writable_accounts
                .entry(*account_key)
                .or_insert(0);
            *account_cost = account_cost.saturating_sub(adjustment);
        }
        self.block_cost = self.block_cost.saturating_sub(adjustment);
        if tx_cost.is_simple_vote {
            self.vote_cost = self.vote_cost.saturating_sub(adjustment);
        }
    }

    /// count number of none-zero CU accounts
    fn number_of_accounts(&self) -> usize {
        self.cost_by_writable_accounts
            .iter()
            .map(|(_key, units)| if *units > 0 { 1 } else { 0 })
            .sum()
    }
}
