//! `cost_tracker` keeps tracking transaction cost per chained accounts as well as for entire block
//! The main functions are:
//! - would_fit(&tx_cost), immutable function to test if tx with tx_cost would fit into current block
//! - add_transaction_cost(&tx_cost), mutable function to accumulate tx_cost to tracker.
//!
use {
    crate::{block_cost_limits::*, transaction_cost::TransactionCost},
    solana_metrics::datapoint_info,
    solana_sdk::{
        clock::Slot, pubkey::Pubkey, saturating_add_assign, transaction::TransactionError,
    },
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

impl From<CostTrackerError> for TransactionError {
    fn from(err: CostTrackerError) -> Self {
        match err {
            CostTrackerError::WouldExceedBlockMaxLimit => Self::WouldExceedMaxBlockCostLimit,
            CostTrackerError::WouldExceedVoteMaxLimit => Self::WouldExceedMaxVoteCostLimit,
            CostTrackerError::WouldExceedAccountMaxLimit => Self::WouldExceedMaxAccountCostLimit,
            CostTrackerError::WouldExceedAccountDataBlockLimit => {
                Self::WouldExceedAccountDataBlockLimit
            }
            CostTrackerError::WouldExceedAccountDataTotalLimit => {
                Self::WouldExceedAccountDataTotalLimit
            }
        }
    }
}

/// Relevant block costs that were updated after successful `try_add()`
#[derive(Debug, Default)]
pub struct UpdatedCosts {
    pub updated_block_cost: u64,
    // for all write-locked accounts `try_add()` successfully updated, the highest account cost
    // can be useful info.
    pub updated_costliest_account_cost: u64,
}

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[derive(Debug)]
pub struct CostTracker {
    account_cost_limit: u64,
    block_cost_limit: u64,
    vote_cost_limit: u64,
    cost_by_writable_accounts: HashMap<Pubkey, u64, ahash::RandomState>,
    block_cost: u64,
    vote_cost: u64,
    transaction_count: u64,
    allocated_accounts_data_size: u64,
    transaction_signature_count: u64,
    secp256k1_instruction_signature_count: u64,
    ed25519_instruction_signature_count: u64,
    /// The number of transactions that have had their estimated cost added to
    /// the tracker, but are still waiting for an update with actual usage or
    /// removal if the transaction does not end up getting committed.
    in_flight_transaction_count: usize,
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
            cost_by_writable_accounts: HashMap::with_capacity_and_hasher(
                WRITABLE_ACCOUNTS_PER_BLOCK,
                ahash::RandomState::new(),
            ),
            block_cost: 0,
            vote_cost: 0,
            transaction_count: 0,
            allocated_accounts_data_size: 0,
            transaction_signature_count: 0,
            secp256k1_instruction_signature_count: 0,
            ed25519_instruction_signature_count: 0,
            in_flight_transaction_count: 0,
        }
    }
}

impl CostTracker {
    pub fn reset(&mut self) {
        self.cost_by_writable_accounts.clear();
        self.block_cost = 0;
        self.vote_cost = 0;
        self.transaction_count = 0;
        self.allocated_accounts_data_size = 0;
        self.transaction_signature_count = 0;
        self.secp256k1_instruction_signature_count = 0;
        self.ed25519_instruction_signature_count = 0;
        self.in_flight_transaction_count = 0;
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

    pub fn in_flight_transaction_count(&self) -> usize {
        self.in_flight_transaction_count
    }

    pub fn add_transactions_in_flight(&mut self, in_flight_transaction_count: usize) {
        saturating_add_assign!(
            self.in_flight_transaction_count,
            in_flight_transaction_count
        );
    }

    pub fn sub_transactions_in_flight(&mut self, in_flight_transaction_count: usize) {
        self.in_flight_transaction_count = self
            .in_flight_transaction_count
            .saturating_sub(in_flight_transaction_count);
    }

    pub fn try_add(&mut self, tx_cost: &TransactionCost) -> Result<UpdatedCosts, CostTrackerError> {
        self.would_fit(tx_cost)?;
        let updated_costliest_account_cost = self.add_transaction_cost(tx_cost);
        Ok(UpdatedCosts {
            updated_block_cost: self.block_cost,
            updated_costliest_account_cost,
        })
    }

    pub fn update_execution_cost(
        &mut self,
        estimated_tx_cost: &TransactionCost,
        actual_execution_units: u64,
        actual_loaded_accounts_data_size_cost: u64,
    ) {
        let actual_load_and_execution_units =
            actual_execution_units.saturating_add(actual_loaded_accounts_data_size_cost);
        let estimated_load_and_execution_units = estimated_tx_cost
            .programs_execution_cost()
            .saturating_add(estimated_tx_cost.loaded_accounts_data_size_cost());
        match actual_load_and_execution_units.cmp(&estimated_load_and_execution_units) {
            Ordering::Equal => (),
            Ordering::Greater => {
                self.add_transaction_execution_cost(
                    estimated_tx_cost,
                    actual_load_and_execution_units - estimated_load_and_execution_units,
                );
            }
            Ordering::Less => {
                self.sub_transaction_execution_cost(
                    estimated_tx_cost,
                    estimated_load_and_execution_units - actual_load_and_execution_units,
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
            (
                "allocated_accounts_data_size",
                self.allocated_accounts_data_size,
                i64
            ),
            (
                "transaction_signature_count",
                self.transaction_signature_count,
                i64
            ),
            (
                "secp256k1_instruction_signature_count",
                self.secp256k1_instruction_signature_count,
                i64
            ),
            (
                "ed25519_instruction_signature_count",
                self.ed25519_instruction_signature_count,
                i64
            ),
            (
                "inflight_transaction_count",
                self.in_flight_transaction_count,
                i64
            ),
        );
    }

    fn find_costliest_account(&self) -> (Pubkey, u64) {
        self.cost_by_writable_accounts
            .iter()
            .max_by_key(|(_, &cost)| cost)
            .map(|(&pubkey, &cost)| (pubkey, cost))
            .unwrap_or_default()
    }

    fn would_fit(&self, tx_cost: &TransactionCost) -> Result<(), CostTrackerError> {
        let cost: u64 = tx_cost.sum();

        if tx_cost.is_simple_vote() {
            // if vote transaction, check if it exceeds vote_transaction_limit
            if self.vote_cost.saturating_add(cost) > self.vote_cost_limit {
                return Err(CostTrackerError::WouldExceedVoteMaxLimit);
            }
        }

        if self.block_cost.saturating_add(cost) > self.block_cost_limit {
            // check against the total package cost
            return Err(CostTrackerError::WouldExceedBlockMaxLimit);
        }

        // check if the transaction itself is more costly than the account_cost_limit
        if cost > self.account_cost_limit {
            return Err(CostTrackerError::WouldExceedAccountMaxLimit);
        }

        let allocated_accounts_data_size = self
            .allocated_accounts_data_size
            .saturating_add(tx_cost.allocated_accounts_data_size());

        if allocated_accounts_data_size > MAX_BLOCK_ACCOUNTS_DATA_SIZE_DELTA {
            return Err(CostTrackerError::WouldExceedAccountDataBlockLimit);
        }

        // check each account against account_cost_limit,
        for account_key in tx_cost.writable_accounts().iter() {
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

    // Returns the highest account cost for all write-lock accounts `TransactionCost` updated
    fn add_transaction_cost(&mut self, tx_cost: &TransactionCost) -> u64 {
        saturating_add_assign!(
            self.allocated_accounts_data_size,
            tx_cost.allocated_accounts_data_size()
        );
        saturating_add_assign!(self.transaction_count, 1);
        saturating_add_assign!(
            self.transaction_signature_count,
            tx_cost.num_transaction_signatures()
        );
        saturating_add_assign!(
            self.secp256k1_instruction_signature_count,
            tx_cost.num_secp256k1_instruction_signatures()
        );
        saturating_add_assign!(
            self.ed25519_instruction_signature_count,
            tx_cost.num_ed25519_instruction_signatures()
        );
        self.add_transaction_execution_cost(tx_cost, tx_cost.sum())
    }

    fn remove_transaction_cost(&mut self, tx_cost: &TransactionCost) {
        let cost = tx_cost.sum();
        self.sub_transaction_execution_cost(tx_cost, cost);
        self.allocated_accounts_data_size = self
            .allocated_accounts_data_size
            .saturating_sub(tx_cost.allocated_accounts_data_size());
        self.transaction_count = self.transaction_count.saturating_sub(1);
        self.transaction_signature_count = self
            .transaction_signature_count
            .saturating_sub(tx_cost.num_transaction_signatures());
        self.secp256k1_instruction_signature_count = self
            .secp256k1_instruction_signature_count
            .saturating_sub(tx_cost.num_secp256k1_instruction_signatures());
        self.ed25519_instruction_signature_count = self
            .ed25519_instruction_signature_count
            .saturating_sub(tx_cost.num_ed25519_instruction_signatures());
    }

    /// Apply additional actual execution units to cost_tracker
    /// Return the costliest account cost that were updated by `TransactionCost`
    fn add_transaction_execution_cost(
        &mut self,
        tx_cost: &TransactionCost,
        adjustment: u64,
    ) -> u64 {
        let mut costliest_account_cost = 0;
        for account_key in tx_cost.writable_accounts().iter() {
            let account_cost = self
                .cost_by_writable_accounts
                .entry(*account_key)
                .or_insert(0);
            *account_cost = account_cost.saturating_add(adjustment);
            costliest_account_cost = costliest_account_cost.max(*account_cost);
        }
        self.block_cost = self.block_cost.saturating_add(adjustment);
        if tx_cost.is_simple_vote() {
            self.vote_cost = self.vote_cost.saturating_add(adjustment);
        }

        costliest_account_cost
    }

    /// Subtract extra execution units from cost_tracker
    fn sub_transaction_execution_cost(&mut self, tx_cost: &TransactionCost, adjustment: u64) {
        for account_key in tx_cost.writable_accounts().iter() {
            let account_cost = self
                .cost_by_writable_accounts
                .entry(*account_key)
                .or_insert(0);
            *account_cost = account_cost.saturating_sub(adjustment);
        }
        self.block_cost = self.block_cost.saturating_sub(adjustment);
        if tx_cost.is_simple_vote() {
            self.vote_cost = self.vote_cost.saturating_sub(adjustment);
        }
    }

    /// count number of none-zero CU accounts
    fn number_of_accounts(&self) -> usize {
        self.cost_by_writable_accounts
            .values()
            .filter(|units| **units > 0)
            .count()
    }
}
