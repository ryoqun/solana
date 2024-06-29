use {
    crate::bank::Bank,
    solana_sdk::transaction::{Result, SanitizedTransaction},
    std::borrow::Cow,
};

// Represents the results of trying to lock a set of accounts
pub struct TransactionBatch<'a, 'b> {
    lock_results: Vec<Result<()>>,
    bank: &'a Bank,
    sanitized_txs: Cow<'b, [SanitizedTransaction]>,
    needs_unlock: bool,
}

impl<'a, 'b> TransactionBatch<'a, 'b> {
    pub fn new(
        lock_results: Vec<Result<()>>,
        bank: &'a Bank,
        sanitized_txs: Cow<'b, [SanitizedTransaction]>,
    ) -> Self {
        assert_eq!(lock_results.len(), sanitized_txs.len());
        Self {
            lock_results,
            bank,
            sanitized_txs,
            needs_unlock: true,
        }
    }

    pub fn lock_results(&self) -> &Vec<Result<()>> {
        &self.lock_results
    }

    pub fn sanitized_transactions(&self) -> &[SanitizedTransaction] {
        &self.sanitized_txs
    }

    pub fn bank(&self) -> &Bank {
        self.bank
    }

    pub fn set_needs_unlock(&mut self, needs_unlock: bool) {
        self.needs_unlock = needs_unlock;
    }

    pub fn needs_unlock(&self) -> bool {
        self.needs_unlock
    }

    /// For every error result, if the corresponding transaction is
    /// still locked, unlock the transaction and then record the new error.
    pub fn unlock_failures(&mut self, transaction_results: Vec<Result<()>>) {
        assert_eq!(self.lock_results.len(), transaction_results.len());
        // Shouldn't happen but if a batch was marked as not needing an unlock,
        // don't unlock failures.
        if !self.needs_unlock() {
            return;
        }

        let txs_and_results = transaction_results
            .iter()
            .enumerate()
            .inspect(|(index, result)| {
                // It's not valid to update a previously recorded lock error to
                // become an "ok" result because this could lead to serious
                // account lock violations where accounts are later unlocked
                // when they were not currently locked.
                assert!(!(result.is_ok() && self.lock_results[*index].is_err()))
            })
            .filter(|(index, result)| result.is_err() && self.lock_results[*index].is_ok())
            .map(|(index, _)| (&self.sanitized_txs[index], &self.lock_results[index]));

        // Unlock the accounts for all transactions which will be updated to an
        // lock error below.
        self.bank.unlock_accounts(txs_and_results);

        // Record all new errors by overwriting lock results. Note that it's
        // not valid to update from err -> ok and the assertion above enforces
        // that validity constraint.
        self.lock_results = transaction_results;
    }
}

// Unlock all locked accounts in destructor.
impl<'a, 'b> Drop for TransactionBatch<'a, 'b> {
    fn drop(&mut self) {
        if self.needs_unlock() {
            self.set_needs_unlock(false);
            self.bank.unlock_accounts(
                self.sanitized_transactions()
                    .iter()
                    .zip(self.lock_results()),
            )
        }
    }
}
