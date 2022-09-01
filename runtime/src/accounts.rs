use {
    crate::{
        account_overrides::AccountOverrides,
        account_rent_state::{check_rent_state_with_account, RentState},
        accounts_db::{
            AccountShrinkThreshold, AccountsAddRootTiming, AccountsDb, AccountsDbConfig,
            BankHashInfo, LoadHint, LoadedAccount, ScanStorageResult,
            ACCOUNTS_DB_CONFIG_FOR_BENCHMARKS, ACCOUNTS_DB_CONFIG_FOR_TESTING,
        },
        accounts_index::{AccountSecondaryIndexes, IndexKey, ScanConfig, ScanError, ScanResult},
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        ancestors::Ancestors,
        bank::{
            Bank, NonceFull, NonceInfo, RentDebits, TransactionCheckResult,
            TransactionExecutionResult,
        },
        blockhash_queue::BlockhashQueue,
        rent_collector::RentCollector,
        system_instruction_processor::{get_system_account_kind, SystemAccountKind},
        transaction_error_metrics::TransactionErrorMetrics,
    },
    dashmap::{
        mapref::entry::Entry::{Occupied, Vacant},
        DashMap,
    },
    log::*,
    rand::{thread_rng, Rng},
    solana_address_lookup_table_program::{error::AddressLookupError, state::AddressLookupTable},
    solana_sdk::{
        account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
        account_utils::StateMut,
        bpf_loader_upgradeable::{self, UpgradeableLoaderState},
        clock::{BankId, Slot, INITIAL_RENT_EPOCH},
        feature_set::{self, add_set_compute_unit_price_ix, tx_wide_compute_cap, FeatureSet},
        fee::FeeStructure,
        genesis_config::ClusterType,
        hash::Hash,
        message::{
            v0::{LoadedAddresses, MessageAddressTableLookup},
            SanitizedMessage,
        },
        native_loader,
        nonce::{
            state::{DurableNonce, Versions as NonceVersions},
            State as NonceState,
        },
        pubkey::Pubkey,
        slot_hashes::SlotHashes,
        system_program,
        sysvar::{self, instructions::construct_instructions_data},
        transaction::{Result, SanitizedTransaction, TransactionAccountLocks, TransactionError},
        transaction_context::TransactionAccount,
    },
    std::{
        cmp::Reverse,
        collections::{hash_map, BinaryHeap, HashMap, HashSet},
        ops::RangeBounds,
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    },
};

#[derive(Debug, Default, AbiExample)]
pub struct AccountLocks {
    write_locks: HashSet<Pubkey>,
    readonly_locks: HashMap<Pubkey, u64>,
}

impl AccountLocks {
    fn is_locked_readonly(&self, key: &Pubkey) -> bool {
        self.readonly_locks
            .get(key)
            .map_or(false, |count| *count > 0)
    }

    fn is_locked_write(&self, key: &Pubkey) -> bool {
        self.write_locks.contains(key)
    }

    fn insert_new_readonly(&mut self, key: &Pubkey) {
        assert!(self.readonly_locks.insert(*key, 1).is_none());
    }

    fn lock_readonly(&mut self, key: &Pubkey) -> bool {
        self.readonly_locks.get_mut(key).map_or(false, |count| {
            *count += 1;
            true
        })
    }

    fn unlock_readonly(&mut self, key: &Pubkey) {
        if let hash_map::Entry::Occupied(mut occupied_entry) = self.readonly_locks.entry(*key) {
            let count = occupied_entry.get_mut();
            *count -= 1;
            if *count == 0 {
                occupied_entry.remove_entry();
            }
        }
    }

    fn unlock_write(&mut self, key: &Pubkey) {
        self.write_locks.remove(key);
    }
}

/// This structure handles synchronization for db
#[derive(Debug, AbiExample)]
pub struct Accounts {
    /// Single global AccountsDb
    pub accounts_db: Arc<AccountsDb>,

    /// set of read-only and writable accounts which are currently
    /// being processed by banking/replay threads
    pub(crate) account_locks: Mutex<AccountLocks>,
}

// for the load instructions
pub type TransactionRent = u64;
pub type TransactionProgramIndices = Vec<Vec<usize>>;
#[derive(PartialEq, Debug, Clone)]
pub struct LoadedTransaction {
    pub accounts: Vec<TransactionAccount>,
    pub program_indices: TransactionProgramIndices,
    pub rent: TransactionRent,
    pub rent_debits: RentDebits,
}

pub type TransactionLoadResult = (Result<LoadedTransaction>, Option<NonceFull>);

pub enum AccountAddressFilter {
    Exclude, // exclude all addresses matching the filter
    Include, // only include addresses matching the filter
}

impl Accounts {
    pub fn default_for_tests() -> Self {
        Self {
            accounts_db: Arc::new(AccountsDb::default_for_tests()),
            account_locks: Mutex::default(),
        }
    }

    pub fn new_with_config_for_tests(
        paths: Vec<PathBuf>,
        cluster_type: &ClusterType,
        account_indexes: AccountSecondaryIndexes,
        caching_enabled: bool,
        shrink_ratio: AccountShrinkThreshold,
    ) -> Self {
        Self::new_with_config(
            paths,
            cluster_type,
            account_indexes,
            caching_enabled,
            shrink_ratio,
            Some(ACCOUNTS_DB_CONFIG_FOR_TESTING),
            None,
        )
    }

    pub fn new_with_config_for_benches(
        paths: Vec<PathBuf>,
        cluster_type: &ClusterType,
        account_indexes: AccountSecondaryIndexes,
        caching_enabled: bool,
        shrink_ratio: AccountShrinkThreshold,
    ) -> Self {
        Self::new_with_config(
            paths,
            cluster_type,
            account_indexes,
            caching_enabled,
            shrink_ratio,
            Some(ACCOUNTS_DB_CONFIG_FOR_BENCHMARKS),
            None,
        )
    }

    pub fn new_with_config(
        paths: Vec<PathBuf>,
        cluster_type: &ClusterType,
        account_indexes: AccountSecondaryIndexes,
        caching_enabled: bool,
        shrink_ratio: AccountShrinkThreshold,
        accounts_db_config: Option<AccountsDbConfig>,
        accounts_update_notifier: Option<AccountsUpdateNotifier>,
    ) -> Self {
        Self {
            accounts_db: Arc::new(AccountsDb::new_with_config(
                paths,
                cluster_type,
                account_indexes,
                caching_enabled,
                shrink_ratio,
                accounts_db_config,
                accounts_update_notifier,
            )),
            account_locks: Mutex::new(AccountLocks::default()),
        }
    }

    pub fn new_from_parent(parent: &Accounts, slot: Slot, parent_slot: Slot) -> Self {
        let accounts_db = parent.accounts_db.clone();
        accounts_db.set_hash(slot, parent_slot);
        Self {
            accounts_db,
            account_locks: Mutex::new(AccountLocks::default()),
        }
    }

    pub(crate) fn new_empty(accounts_db: AccountsDb) -> Self {
        Self {
            accounts_db: Arc::new(accounts_db),
            account_locks: Mutex::new(AccountLocks::default()),
        }
    }

    fn construct_instructions_account(
        message: &SanitizedMessage,
        is_owned_by_sysvar: bool,
    ) -> AccountSharedData {
        let data = construct_instructions_data(&message.decompile_instructions());
        let owner = if is_owned_by_sysvar {
            sysvar::id()
        } else {
            system_program::id()
        };
        AccountSharedData::from(Account {
            data,
            owner,
            ..Account::default()
        })
    }

    fn load_transaction(
        &self,
        ancestors: &Ancestors,
        tx: &SanitizedTransaction,
        fee: u64,
        error_counters: &mut TransactionErrorMetrics,
        rent_collector: &RentCollector,
        feature_set: &FeatureSet,
        account_overrides: Option<&AccountOverrides>,
    ) -> Result<LoadedTransaction> {
        // Copy all the accounts
        let message = tx.message();
        // NOTE: this check will never fail because `tx` is sanitized
        if tx.signatures().is_empty() && fee != 0 {
            Err(TransactionError::MissingSignatureForFee)
        } else {
            // There is no way to predict what program will execute without an error
            // If a fee can pay for execution then the program will be scheduled
            let mut validated_fee_payer = false;
            let mut tx_rent: TransactionRent = 0;
            let account_keys = message.account_keys();
            let mut accounts = Vec::with_capacity(account_keys.len());
            let mut account_deps = Vec::with_capacity(account_keys.len());
            let mut rent_debits = RentDebits::default();
            let preserve_rent_epoch_for_rent_exempt_accounts = feature_set
                .is_active(&feature_set::preserve_rent_epoch_for_rent_exempt_accounts::id());
            for (i, key) in account_keys.iter().enumerate() {
                let account = if !message.is_non_loader_key(i) {
                    // Fill in an empty account for the program slots.
                    AccountSharedData::default()
                } else {
                    #[allow(clippy::collapsible_else_if)]
                    if solana_sdk::sysvar::instructions::check_id(key) {
                        Self::construct_instructions_account(
                            message,
                            feature_set
                                .is_active(&feature_set::instructions_sysvar_owned_by_sysvar::id()),
                        )
                    } else {
                        let (mut account, rent) = if let Some(account_override) =
                            account_overrides.and_then(|overrides| overrides.get(key))
                        {
                            (account_override.clone(), 0)
                        } else {
                            self.accounts_db
                                .load_with_fixed_root(ancestors, key)
                                .map(|(mut account, _)| {
                                    if message.is_writable(i) {
                                        let rent_due = rent_collector
                                            .collect_from_existing_account(
                                                key,
                                                &mut account,
                                                self.accounts_db.filler_account_suffix.as_ref(),
                                                preserve_rent_epoch_for_rent_exempt_accounts,
                                            )
                                            .rent_amount;
                                        (account, rent_due)
                                    } else {
                                        (account, 0)
                                    }
                                })
                                .unwrap_or_default()
                        };

                        if !validated_fee_payer {
                            if i != 0 {
                                warn!("Payer index should be 0! {:?}", tx);
                            }

                            Self::validate_fee_payer(
                                key,
                                &mut account,
                                i,
                                error_counters,
                                rent_collector,
                                feature_set,
                                fee,
                            )?;

                            validated_fee_payer = true;
                        }

                        if bpf_loader_upgradeable::check_id(account.owner()) {
                            if message.is_writable(i) && !message.is_upgradeable_loader_present() {
                                error_counters.invalid_writable_account += 1;
                                return Err(TransactionError::InvalidWritableAccount);
                            }

                            if account.executable() {
                                // The upgradeable loader requires the derived ProgramData account
                                if let Ok(UpgradeableLoaderState::Program {
                                    programdata_address,
                                }) = account.state()
                                {
                                    if let Some((programdata_account, _)) = self
                                        .accounts_db
                                        .load_with_fixed_root(ancestors, &programdata_address)
                                    {
                                        account_deps
                                            .push((programdata_address, programdata_account));
                                    } else {
                                        error_counters.account_not_found += 1;
                                        return Err(TransactionError::ProgramAccountNotFound);
                                    }
                                } else {
                                    error_counters.invalid_program_for_execution += 1;
                                    return Err(TransactionError::InvalidProgramForExecution);
                                }
                            }
                        } else if account.executable() && message.is_writable(i) {
                            error_counters.invalid_writable_account += 1;
                            return Err(TransactionError::InvalidWritableAccount);
                        }

                        tx_rent += rent;
                        rent_debits.insert(key, rent, account.lamports());

                        account
                    }
                };
                accounts.push((*key, account));
            }
            debug_assert_eq!(accounts.len(), account_keys.len());
            // Appends the account_deps at the end of the accounts,
            // this way they can be accessed in a uniform way.
            // At places where only the accounts are needed,
            // the account_deps are truncated using e.g:
            // accounts.iter().take(message.account_keys.len())
            accounts.append(&mut account_deps);

            if validated_fee_payer {
                let program_indices = message
                    .instructions()
                    .iter()
                    .map(|instruction| {
                        self.load_executable_accounts(
                            ancestors,
                            &mut accounts,
                            instruction.program_id_index as usize,
                            error_counters,
                        )
                    })
                    .collect::<Result<Vec<Vec<usize>>>>()?;

                Ok(LoadedTransaction {
                    accounts,
                    program_indices,
                    rent: tx_rent,
                    rent_debits,
                })
            } else {
                error_counters.account_not_found += 1;
                Err(TransactionError::AccountNotFound)
            }
        }
    }

    fn validate_fee_payer(
        payer_address: &Pubkey,
        payer_account: &mut AccountSharedData,
        payer_index: usize,
        error_counters: &mut TransactionErrorMetrics,
        rent_collector: &RentCollector,
        feature_set: &FeatureSet,
        fee: u64,
    ) -> Result<()> {
        if payer_account.lamports() == 0 {
            error_counters.account_not_found += 1;
            return Err(TransactionError::AccountNotFound);
        }
        let min_balance = match get_system_account_kind(payer_account).ok_or_else(|| {
            error_counters.invalid_account_for_fee += 1;
            TransactionError::InvalidAccountForFee
        })? {
            SystemAccountKind::System => 0,
            SystemAccountKind::Nonce => {
                // Should we ever allow a fees charge to zero a nonce account's
                // balance. The state MUST be set to uninitialized in that case
                rent_collector.rent.minimum_balance(NonceState::size())
            }
        };

        if payer_account.lamports() < fee + min_balance {
            error_counters.insufficient_funds += 1;
            return Err(TransactionError::InsufficientFundsForFee);
        }
        let payer_pre_rent_state = RentState::from_account(payer_account, &rent_collector.rent);
        payer_account
            .checked_sub_lamports(fee)
            .map_err(|_| TransactionError::InsufficientFundsForFee)?;

        let payer_post_rent_state = RentState::from_account(payer_account, &rent_collector.rent);
        let rent_state_result = check_rent_state_with_account(
            &payer_pre_rent_state,
            &payer_post_rent_state,
            payer_address,
            payer_account,
            feature_set.is_active(&feature_set::do_support_realloc::id()),
            feature_set
                .is_active(&feature_set::include_account_index_in_rent_error::ID)
                .then(|| payer_index),
            feature_set
                .is_active(&feature_set::prevent_crediting_accounts_that_end_rent_paying::id()),
        );
        // Feature gate only wraps the actual error return so that the metrics and debug
        // logging generated by `check_rent_state_with_account()` can be examined before
        // feature activation
        if feature_set.is_active(&feature_set::require_rent_exempt_accounts::id()) {
            rent_state_result?;
        }
        Ok(())
    }

    fn load_executable_accounts(
        &self,
        ancestors: &Ancestors,
        accounts: &mut Vec<TransactionAccount>,
        mut program_account_index: usize,
        error_counters: &mut TransactionErrorMetrics,
    ) -> Result<Vec<usize>> {
        let mut account_indices = Vec::new();
        let mut program_id = accounts[program_account_index].0;
        let mut depth = 0;
        while !native_loader::check_id(&program_id) {
            if depth >= 5 {
                error_counters.call_chain_too_deep += 1;
                return Err(TransactionError::CallChainTooDeep);
            }
            depth += 1;

            program_account_index = match self
                .accounts_db
                .load_with_fixed_root(ancestors, &program_id)
            {
                Some((program_account, _)) => {
                    let account_index = accounts.len();
                    accounts.push((program_id, program_account));
                    account_index
                }
                None => {
                    error_counters.account_not_found += 1;
                    return Err(TransactionError::ProgramAccountNotFound);
                }
            };
            let program = &accounts[program_account_index].1;
            if !program.executable() {
                error_counters.invalid_program_for_execution += 1;
                return Err(TransactionError::InvalidProgramForExecution);
            }

            // Add loader to chain
            let program_owner = *program.owner();
            account_indices.insert(0, program_account_index);
            if bpf_loader_upgradeable::check_id(&program_owner) {
                // The upgradeable loader requires the derived ProgramData account
                if let Ok(UpgradeableLoaderState::Program {
                    programdata_address,
                }) = program.state()
                {
                    let programdata_account_index = match self
                        .accounts_db
                        .load_with_fixed_root(ancestors, &programdata_address)
                    {
                        Some((programdata_account, _)) => {
                            let account_index = accounts.len();
                            accounts.push((programdata_address, programdata_account));
                            account_index
                        }
                        None => {
                            error_counters.account_not_found += 1;
                            return Err(TransactionError::ProgramAccountNotFound);
                        }
                    };
                    account_indices.insert(0, programdata_account_index);
                } else {
                    error_counters.invalid_program_for_execution += 1;
                    return Err(TransactionError::InvalidProgramForExecution);
                }
            }

            program_id = program_owner;
        }
        Ok(account_indices)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn load_accounts(
        &self,
        ancestors: &Ancestors,
        txs: &[SanitizedTransaction],
        lock_results: Vec<TransactionCheckResult>,
        hash_queue: &BlockhashQueue,
        error_counters: &mut TransactionErrorMetrics,
        rent_collector: &RentCollector,
        feature_set: &FeatureSet,
        fee_structure: &FeeStructure,
        account_overrides: Option<&AccountOverrides>,
    ) -> Vec<TransactionLoadResult> {
        txs.iter()
            .zip(lock_results)
            .map(|etx| match etx {
                (tx, (Ok(()), nonce)) => {
                    let lamports_per_signature = nonce
                        .as_ref()
                        .map(|nonce| nonce.lamports_per_signature())
                        .unwrap_or_else(|| {
                            hash_queue.get_lamports_per_signature(tx.message().recent_blockhash())
                        });
                    let fee = if let Some(lamports_per_signature) = lamports_per_signature {
                        Bank::calculate_fee(
                            tx.message(),
                            lamports_per_signature,
                            fee_structure,
                            feature_set.is_active(&tx_wide_compute_cap::id()),
                            feature_set.is_active(&add_set_compute_unit_price_ix::id()),
                        )
                    } else {
                        return (Err(TransactionError::BlockhashNotFound), None);
                    };

                    let loaded_transaction = match self.load_transaction(
                        ancestors,
                        tx,
                        fee,
                        error_counters,
                        rent_collector,
                        feature_set,
                        account_overrides,
                    ) {
                        Ok(loaded_transaction) => loaded_transaction,
                        Err(e) => return (Err(e), None),
                    };

                    // Update nonce with fee-subtracted accounts
                    let nonce = if let Some(nonce) = nonce {
                        match NonceFull::from_partial(
                            nonce,
                            tx.message(),
                            &loaded_transaction.accounts,
                            &loaded_transaction.rent_debits,
                        ) {
                            Ok(nonce) => Some(nonce),
                            Err(e) => return (Err(e), None),
                        }
                    } else {
                        None
                    };

                    (Ok(loaded_transaction), nonce)
                }
                (_, (Err(e), _nonce)) => (Err(e), None),
            })
            .collect()
    }

    pub fn load_lookup_table_addresses(
        &self,
        ancestors: &Ancestors,
        address_table_lookup: &MessageAddressTableLookup,
        slot_hashes: &SlotHashes,
    ) -> std::result::Result<LoadedAddresses, AddressLookupError> {
        let table_account = self
            .accounts_db
            .load_with_fixed_root(ancestors, &address_table_lookup.account_key)
            .map(|(account, _rent)| account)
            .ok_or(AddressLookupError::LookupTableAccountNotFound)?;

        if table_account.owner() == &solana_address_lookup_table_program::id() {
            let current_slot = ancestors.max_slot();
            let lookup_table = AddressLookupTable::deserialize(table_account.data())
                .map_err(|_ix_err| AddressLookupError::InvalidAccountData)?;

            Ok(LoadedAddresses {
                writable: lookup_table.lookup(
                    current_slot,
                    &address_table_lookup.writable_indexes,
                    slot_hashes,
                )?,
                readonly: lookup_table.lookup(
                    current_slot,
                    &address_table_lookup.readonly_indexes,
                    slot_hashes,
                )?,
            })
        } else {
            Err(AddressLookupError::InvalidAccountOwner)
        }
    }

    fn filter_zero_lamport_account(
        account: AccountSharedData,
        slot: Slot,
    ) -> Option<(AccountSharedData, Slot)> {
        if account.lamports() > 0 {
            Some((account, slot))
        } else {
            None
        }
    }

    /// Slow because lock is held for 1 operation instead of many
    fn load_slow(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        load_hint: LoadHint,
    ) -> Option<(AccountSharedData, Slot)> {
        let (account, slot) = self.accounts_db.load(ancestors, pubkey, load_hint)?;
        Self::filter_zero_lamport_account(account, slot)
    }

    pub fn load_with_fixed_root(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        self.load_slow(ancestors, pubkey, LoadHint::FixedMaxRoot)
    }

    pub fn load_without_fixed_root(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        self.load_slow(ancestors, pubkey, LoadHint::Unspecified)
    }

    /// scans underlying accounts_db for this delta (slot) with a map function
    ///   from LoadedAccount to B
    /// returns only the latest/current version of B for this slot
    pub fn scan_slot<F, B>(&self, slot: Slot, func: F) -> Vec<B>
    where
        F: Fn(LoadedAccount) -> Option<B> + Send + Sync,
        B: Sync + Send + Default + std::cmp::Eq,
    {
        let scan_result = self.accounts_db.scan_account_storage(
            slot,
            |loaded_account: LoadedAccount| {
                // Cache only has one version per key, don't need to worry about versioning
                func(loaded_account)
            },
            |accum: &DashMap<Pubkey, (u64, B)>, loaded_account: LoadedAccount| {
                let loaded_account_pubkey = *loaded_account.pubkey();
                let loaded_write_version = loaded_account.write_version();
                let should_insert = accum
                    .get(&loaded_account_pubkey)
                    .map(|existing_entry| loaded_write_version > existing_entry.value().0)
                    .unwrap_or(true);
                if should_insert {
                    if let Some(val) = func(loaded_account) {
                        // Detected insertion is necessary, grabs the write lock to commit the write,
                        match accum.entry(loaded_account_pubkey) {
                            // Double check in case another thread interleaved a write between the read + write.
                            Occupied(mut occupied_entry) => {
                                if loaded_write_version > occupied_entry.get().0 {
                                    occupied_entry.insert((loaded_write_version, val));
                                }
                            }

                            Vacant(vacant_entry) => {
                                vacant_entry.insert((loaded_write_version, val));
                            }
                        }
                    }
                }
            },
        );

        match scan_result {
            ScanStorageResult::Cached(cached_result) => cached_result,
            ScanStorageResult::Stored(stored_result) => stored_result
                .into_iter()
                .map(|(_pubkey, (_latest_write_version, val))| val)
                .collect(),
        }
    }

    pub fn load_by_program_slot(
        &self,
        slot: Slot,
        program_id: Option<&Pubkey>,
    ) -> Vec<TransactionAccount> {
        self.scan_slot(slot, |stored_account| {
            let hit = match program_id {
                None => true,
                Some(program_id) => stored_account.owner() == program_id,
            };

            if hit {
                Some((*stored_account.pubkey(), stored_account.take_account()))
            } else {
                None
            }
        })
    }

    pub fn load_largest_accounts(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        num: usize,
        filter_by_address: &HashSet<Pubkey>,
        filter: AccountAddressFilter,
    ) -> ScanResult<Vec<(Pubkey, u64)>> {
        if num == 0 {
            return Ok(vec![]);
        }
        let account_balances = self.accounts_db.scan_accounts(
            ancestors,
            bank_id,
            |collector: &mut BinaryHeap<Reverse<(u64, Pubkey)>>, option| {
                if let Some((pubkey, account, _slot)) = option {
                    if account.lamports() == 0 {
                        return;
                    }
                    let contains_address = filter_by_address.contains(pubkey);
                    let collect = match filter {
                        AccountAddressFilter::Exclude => !contains_address,
                        AccountAddressFilter::Include => contains_address,
                    };
                    if !collect {
                        return;
                    }
                    if collector.len() == num {
                        let Reverse(entry) = collector
                            .peek()
                            .expect("BinaryHeap::peek should succeed when len > 0");
                        if *entry >= (account.lamports(), *pubkey) {
                            return;
                        }
                        collector.pop();
                    }
                    collector.push(Reverse((account.lamports(), *pubkey)));
                }
            },
            &ScanConfig::default(),
        )?;
        Ok(account_balances
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse((balance, pubkey))| (pubkey, balance))
            .collect())
    }

    pub fn calculate_capitalization(
        &self,
        ancestors: &Ancestors,
        slot: Slot,
        can_cached_slot_be_unflushed: bool,
        debug_verify: bool,
    ) -> u64 {
        let use_index = false;
        let is_startup = false; // there may be conditions where this is called at startup.
        self.accounts_db
            .update_accounts_hash_with_index_option(
                use_index,
                debug_verify,
                slot,
                ancestors,
                None,
                can_cached_slot_be_unflushed,
                None,
                is_startup,
            )
            .1
    }

    /// Only called from startup or test code.
    #[must_use]
    pub fn verify_bank_hash_and_lamports(
        &self,
        slot: Slot,
        ancestors: &Ancestors,
        total_lamports: u64,
        test_hash_calculation: bool,
        ignore_mismatch: bool,
    ) -> bool {
        if let Err(err) = self.accounts_db.verify_bank_hash_and_lamports(
            slot,
            ancestors,
            total_lamports,
            test_hash_calculation,
            ignore_mismatch,
        ) {
            warn!("verify_bank_hash failed: {:?}", err);
            false
        } else {
            true
        }
    }

    fn is_loadable(lamports: u64) -> bool {
        // Don't ever load zero lamport accounts into runtime because
        // the existence of zero-lamport accounts are never deterministic!!
        lamports > 0
    }

    fn load_while_filtering<F: Fn(&AccountSharedData) -> bool>(
        collector: &mut Vec<TransactionAccount>,
        some_account_tuple: Option<(&Pubkey, AccountSharedData, Slot)>,
        filter: F,
    ) {
        if let Some(mapped_account_tuple) = some_account_tuple
            .filter(|(_, account, _)| Self::is_loadable(account.lamports()) && filter(account))
            .map(|(pubkey, account, _slot)| (*pubkey, account))
        {
            collector.push(mapped_account_tuple)
        }
    }

    pub fn load_by_program(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        program_id: &Pubkey,
        config: &ScanConfig,
    ) -> ScanResult<Vec<TransactionAccount>> {
        self.accounts_db.scan_accounts(
            ancestors,
            bank_id,
            |collector: &mut Vec<TransactionAccount>, some_account_tuple| {
                Self::load_while_filtering(collector, some_account_tuple, |account| {
                    account.owner() == program_id
                })
            },
            config,
        )
    }

    pub fn load_by_program_with_filter<F: Fn(&AccountSharedData) -> bool>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        program_id: &Pubkey,
        filter: F,
        config: &ScanConfig,
    ) -> ScanResult<Vec<TransactionAccount>> {
        self.accounts_db.scan_accounts(
            ancestors,
            bank_id,
            |collector: &mut Vec<TransactionAccount>, some_account_tuple| {
                Self::load_while_filtering(collector, some_account_tuple, |account| {
                    account.owner() == program_id && filter(account)
                })
            },
            config,
        )
    }

    fn calc_scan_result_size(account: &AccountSharedData) -> usize {
        account.data().len()
            + std::mem::size_of::<AccountSharedData>()
            + std::mem::size_of::<Pubkey>()
    }

    /// Accumulate size of (pubkey + account) into sum.
    /// Return true iff sum > 'byte_limit_for_scan'
    fn accumulate_and_check_scan_result_size(
        sum: &AtomicUsize,
        account: &AccountSharedData,
        byte_limit_for_scan: &Option<usize>,
    ) -> bool {
        if let Some(byte_limit_for_scan) = byte_limit_for_scan.as_ref() {
            let added = Self::calc_scan_result_size(account);
            sum.fetch_add(added, Ordering::Relaxed)
                .saturating_add(added)
                > *byte_limit_for_scan
        } else {
            false
        }
    }

    fn maybe_abort_scan(
        result: ScanResult<Vec<TransactionAccount>>,
        config: &ScanConfig,
    ) -> ScanResult<Vec<TransactionAccount>> {
        if config.is_aborted() {
            ScanResult::Err(ScanError::Aborted(
                "The accumulated scan results exceeded the limit".to_string(),
            ))
        } else {
            result
        }
    }

    pub fn load_by_index_key_with_filter<F: Fn(&AccountSharedData) -> bool>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        index_key: &IndexKey,
        filter: F,
        config: &ScanConfig,
        byte_limit_for_scan: Option<usize>,
    ) -> ScanResult<Vec<TransactionAccount>> {
        let sum = AtomicUsize::default();
        let config = config.recreate_with_abort();
        let result = self
            .accounts_db
            .index_scan_accounts(
                ancestors,
                bank_id,
                *index_key,
                |collector: &mut Vec<TransactionAccount>, some_account_tuple| {
                    Self::load_while_filtering(collector, some_account_tuple, |account| {
                        let use_account = filter(account);
                        if use_account
                            && Self::accumulate_and_check_scan_result_size(
                                &sum,
                                account,
                                &byte_limit_for_scan,
                            )
                        {
                            // total size of results exceeds size limit, so abort scan
                            config.abort();
                        }
                        use_account
                    });
                },
                &config,
            )
            .map(|result| result.0);
        Self::maybe_abort_scan(result, &config)
    }

    pub fn account_indexes_include_key(&self, key: &Pubkey) -> bool {
        self.accounts_db.account_indexes.include_key(key)
    }

    pub fn load_all(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
    ) -> ScanResult<Vec<(Pubkey, AccountSharedData, Slot)>> {
        self.accounts_db.scan_accounts(
            ancestors,
            bank_id,
            |collector: &mut Vec<(Pubkey, AccountSharedData, Slot)>, some_account_tuple| {
                if let Some((pubkey, account, slot)) = some_account_tuple
                    .filter(|(_, account, _)| Self::is_loadable(account.lamports()))
                {
                    collector.push((*pubkey, account, slot))
                }
            },
            &ScanConfig::default(),
        )
    }

    pub fn hold_range_in_memory<R>(
        &self,
        range: &R,
        start_holding: bool,
        thread_pool: &rayon::ThreadPool,
    ) where
        R: RangeBounds<Pubkey> + std::fmt::Debug + Sync,
    {
        self.accounts_db
            .accounts_index
            .hold_range_in_memory(range, start_holding, thread_pool)
    }

    pub fn load_to_collect_rent_eagerly<R: RangeBounds<Pubkey> + std::fmt::Debug>(
        &self,
        ancestors: &Ancestors,
        range: R,
    ) -> Vec<TransactionAccount> {
        self.accounts_db.range_scan_accounts(
            "load_to_collect_rent_eagerly_scan_elapsed",
            ancestors,
            range,
            &ScanConfig::new(true),
            |collector: &mut Vec<TransactionAccount>, option| {
                Self::load_while_filtering(collector, option, |_| true)
            },
        )
    }

    /// Slow because lock is held for 1 operation instead of many.
    /// WARNING: This noncached version is only to be used for tests/benchmarking
    /// as bypassing the cache in general is not supported
    pub fn store_slow_uncached(&self, slot: Slot, pubkey: &Pubkey, account: &AccountSharedData) {
        self.accounts_db.store_uncached(slot, &[(pubkey, account)]);
    }

    pub fn store_slow_cached(&self, slot: Slot, pubkey: &Pubkey, account: &AccountSharedData) {
        self.accounts_db.store_cached(slot, &[(pubkey, account)]);
    }

    fn lock_account(
        &self,
        account_locks: &mut AccountLocks,
        writable_keys: Vec<&Pubkey>,
        readonly_keys: Vec<&Pubkey>,
    ) -> Result<()> {
        for k in writable_keys.iter() {
            if account_locks.is_locked_write(k) || account_locks.is_locked_readonly(k) {
                debug!("Writable account in use: {:?}", k);
                return Err(TransactionError::AccountInUse);
            }
        }
        for k in readonly_keys.iter() {
            if account_locks.is_locked_write(k) {
                debug!("Read-only account in use: {:?}", k);
                return Err(TransactionError::AccountInUse);
            }
        }

        for k in writable_keys {
            account_locks.write_locks.insert(*k);
        }

        for k in readonly_keys {
            if !account_locks.lock_readonly(k) {
                account_locks.insert_new_readonly(k);
            }
        }

        Ok(())
    }

    fn unlock_account(
        &self,
        account_locks: &mut AccountLocks,
        writable_keys: Vec<&Pubkey>,
        readonly_keys: Vec<&Pubkey>,
    ) {
        for k in writable_keys {
            account_locks.unlock_write(k);
        }
        for k in readonly_keys {
            account_locks.unlock_readonly(k);
        }
    }

    pub fn bank_hash_at(&self, slot: Slot) -> Hash {
        self.bank_hash_info_at(slot).hash
    }

    pub fn bank_hash_info_at(&self, slot: Slot) -> BankHashInfo {
        let delta_hash = self.accounts_db.get_accounts_delta_hash(slot);
        let bank_hashes = self.accounts_db.bank_hashes.read().unwrap();
        let mut hash_info = bank_hashes
            .get(&slot)
            .expect("No bank hash was found for this bank, that should not be possible")
            .clone();
        hash_info.hash = delta_hash;
        hash_info
    }

    /// This function will prevent multiple threads from modifying the same account state at the
    /// same time
    #[must_use]
    #[allow(clippy::needless_collect)]
    pub fn lock_accounts<'a>(
        &self,
        txs: impl Iterator<Item = &'a SanitizedTransaction>,
        feature_set: &FeatureSet,
    ) -> Vec<Result<()>> {
        let tx_account_locks_results: Vec<Result<_>> =
            txs.map(|tx| tx.get_account_locks(feature_set)).collect();
        self.lock_accounts_inner(tx_account_locks_results)
    }

    #[must_use]
    #[allow(clippy::needless_collect)]
    pub fn lock_accounts_with_results<'a>(
        &self,
        txs: impl Iterator<Item = &'a SanitizedTransaction>,
        results: impl Iterator<Item = &'a Result<()>>,
        feature_set: &FeatureSet,
    ) -> Vec<Result<()>> {
        let tx_account_locks_results: Vec<Result<_>> = txs
            .zip(results)
            .map(|(tx, result)| match result {
                Ok(()) => tx.get_account_locks(feature_set),
                Err(err) => Err(err.clone()),
            })
            .collect();
        self.lock_accounts_inner(tx_account_locks_results)
    }

    #[must_use]
    fn lock_accounts_inner(
        &self,
        tx_account_locks_results: Vec<Result<TransactionAccountLocks>>,
    ) -> Vec<Result<()>> {
        let account_locks = &mut self.account_locks.lock().unwrap();
        tx_account_locks_results
            .into_iter()
            .map(|tx_account_locks_result| match tx_account_locks_result {
                Ok(tx_account_locks) => self.lock_account(
                    account_locks,
                    tx_account_locks.writable,
                    tx_account_locks.readonly,
                ),
                Err(err) => Err(err),
            })
            .collect()
    }

    /// Once accounts are unlocked, new transactions that modify that state can enter the pipeline
    #[allow(clippy::needless_collect)]
    pub fn unlock_accounts<'a>(
        &self,
        txs: impl Iterator<Item = &'a SanitizedTransaction>,
        results: &[Result<()>],
    ) {
        let keys: Vec<_> = txs
            .zip(results)
            .filter_map(|(tx, res)| match res {
                Err(TransactionError::AccountLoadedTwice)
                | Err(TransactionError::AccountInUse)
                | Err(TransactionError::SanitizeFailure)
                | Err(TransactionError::TooManyAccountLocks)
                | Err(TransactionError::WouldExceedMaxBlockCostLimit)
                | Err(TransactionError::WouldExceedMaxVoteCostLimit)
                | Err(TransactionError::WouldExceedMaxAccountCostLimit)
                | Err(TransactionError::WouldExceedAccountDataBlockLimit)
                | Err(TransactionError::WouldExceedAccountDataTotalLimit) => None,
                _ => Some(tx.get_account_locks_unchecked()),
            })
            .collect();
        let mut account_locks = self.account_locks.lock().unwrap();
        debug!("bank unlock accounts");
        keys.into_iter().for_each(|keys| {
            self.unlock_account(&mut account_locks, keys.writable, keys.readonly);
        });
    }

    /// Store the accounts into the DB
    // allow(clippy) needed for various gating flags
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_cached(
        &self,
        slot: Slot,
        txs: &[SanitizedTransaction],
        res: &[TransactionExecutionResult],
        loaded: &mut [TransactionLoadResult],
        rent_collector: &RentCollector,
        durable_nonce: &(DurableNonce, /*separate_domains:*/ bool),
        lamports_per_signature: u64,
        leave_nonce_on_success: bool,
        preserve_rent_epoch_for_rent_exempt_accounts: bool,
    ) {
        let accounts_to_store = self.collect_accounts_to_store(
            txs,
            res,
            loaded,
            rent_collector,
            durable_nonce,
            lamports_per_signature,
            leave_nonce_on_success,
            preserve_rent_epoch_for_rent_exempt_accounts,
        );
        self.accounts_db.store_cached(slot, &accounts_to_store);
    }

    /// Purge a slot if it is not a root
    /// Root slots cannot be purged
    /// `is_from_abs` is true if the caller is the AccountsBackgroundService
    pub fn purge_slot(&self, slot: Slot, bank_id: BankId, is_from_abs: bool) {
        self.accounts_db.purge_slot(slot, bank_id, is_from_abs);
    }

    /// Add a slot to root.  Root slots cannot be purged
    pub fn add_root(&self, slot: Slot) -> AccountsAddRootTiming {
        self.accounts_db.add_root(slot)
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_accounts_to_store<'a>(
        &self,
        txs: &'a [SanitizedTransaction],
        execution_results: &'a [TransactionExecutionResult],
        load_results: &'a mut [TransactionLoadResult],
        rent_collector: &RentCollector,
        durable_nonce: &(DurableNonce, /*separate_domains:*/ bool),
        lamports_per_signature: u64,
        leave_nonce_on_success: bool,
        preserve_rent_epoch_for_rent_exempt_accounts: bool,
    ) -> Vec<(&'a Pubkey, &'a AccountSharedData)> {
        let mut accounts = Vec::with_capacity(load_results.len());
        for (i, ((tx_load_result, nonce), tx)) in load_results.iter_mut().zip(txs).enumerate() {
            if tx_load_result.is_err() {
                // Don't store any accounts if tx failed to load
                continue;
            }

            let execution_status = match &execution_results[i] {
                TransactionExecutionResult::Executed { details, .. } => &details.status,
                // Don't store any accounts if tx wasn't executed
                TransactionExecutionResult::NotExecuted(_) => continue,
            };

            let maybe_nonce = match (execution_status, &*nonce) {
                (Ok(()), Some(nonce)) => {
                    if leave_nonce_on_success {
                        None
                    } else {
                        Some((nonce, false /* rollback */))
                    }
                }
                (Err(_), Some(nonce)) => {
                    Some((nonce, true /* rollback */))
                }
                (Ok(_), None) => None, // Success, don't do any additional nonce processing
                (Err(_), None) => {
                    // Fees for failed transactions which don't use durable nonces are
                    // deducted in Bank::filter_program_errors_and_collect_fee
                    continue;
                }
            };

            let message = tx.message();
            let loaded_transaction = tx_load_result.as_mut().unwrap();
            let mut fee_payer_index = None;
            for (i, (address, account)) in (0..message.account_keys().len())
                .zip(loaded_transaction.accounts.iter_mut())
                .filter(|(i, _)| message.is_non_loader_key(*i))
            {
                if fee_payer_index.is_none() {
                    fee_payer_index = Some(i);
                }
                let is_fee_payer = Some(i) == fee_payer_index;
                if message.is_writable(i) {
                    let is_nonce_account = prepare_if_nonce_account(
                        address,
                        account,
                        execution_status,
                        is_fee_payer,
                        maybe_nonce,
                        durable_nonce,
                        lamports_per_signature,
                    );

                    if execution_status.is_ok() || is_nonce_account || is_fee_payer {
                        if !preserve_rent_epoch_for_rent_exempt_accounts
                            && account.rent_epoch() == INITIAL_RENT_EPOCH
                        {
                            let rent = rent_collector
                                .collect_from_created_account(
                                    address,
                                    account,
                                    preserve_rent_epoch_for_rent_exempt_accounts,
                                )
                                .rent_amount;
                            loaded_transaction.rent += rent;
                            loaded_transaction.rent_debits.insert(
                                address,
                                rent,
                                account.lamports(),
                            );
                        }

                        // Add to the accounts to store
                        accounts.push((&*address, &*account));
                    }
                }
            }
        }
        accounts
    }
}

fn prepare_if_nonce_account<'a>(
    address: &Pubkey,
    account: &mut AccountSharedData,
    execution_result: &Result<()>,
    is_fee_payer: bool,
    maybe_nonce: Option<(&'a NonceFull, bool)>,
    &(durable_nonce, separate_domains): &(DurableNonce, bool),
    lamports_per_signature: u64,
) -> bool {
    if let Some((nonce, rollback)) = maybe_nonce {
        if address == nonce.address() {
            if rollback {
                // The transaction failed which would normally drop the account
                // processing changes, since this account is now being included
                // in the accounts written back to the db, roll it back to
                // pre-processing state.
                *account = nonce.account().clone();
            }

            // Advance the stored blockhash to prevent fee theft by someone
            // replaying nonce transactions that have failed with an
            // `InstructionError`.
            //
            // Since we know we are dealing with a valid nonce account,
            // unwrap is safe here
            let nonce_versions = StateMut::<NonceVersions>::state(nonce.account()).unwrap();
            if let NonceState::Initialized(ref data) = nonce_versions.state() {
                let nonce_state = NonceState::new_initialized(
                    &data.authority,
                    durable_nonce,
                    lamports_per_signature,
                );
                let nonce_versions = NonceVersions::new(nonce_state, separate_domains);
                account.set_state(&nonce_versions).unwrap();
            }
            true
        } else {
            if execution_result.is_err() && is_fee_payer {
                if let Some(fee_payer_account) = nonce.fee_payer_account() {
                    // Instruction error and fee-payer for this nonce tx is not
                    // the nonce account itself, rollback the fee payer to the
                    // fee-paid original state.
                    *account = fee_payer_account.clone();
                }
            }

            false
        }
    } else {
        false
    }
}

pub fn create_test_accounts(
    accounts: &Accounts,
    pubkeys: &mut Vec<Pubkey>,
    num: usize,
    slot: Slot,
) {
    for t in 0..num {
        let pubkey = solana_sdk::pubkey::new_rand();
        let account =
            AccountSharedData::new((t + 1) as u64, 0, AccountSharedData::default().owner());
        accounts.store_slow_uncached(slot, &pubkey, &account);
        pubkeys.push(pubkey);
    }
}

// Only used by bench, not safe to call otherwise accounts can conflict with the
// accounts cache!
pub fn update_accounts_bench(accounts: &Accounts, pubkeys: &[Pubkey], slot: u64) {
    for pubkey in pubkeys {
        let amount = thread_rng().gen_range(0, 10);
        let account = AccountSharedData::new(amount, 0, AccountSharedData::default().owner());
        accounts.store_slow_uncached(slot, pubkey, &account);
    }
}
