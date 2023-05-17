use {
    crate::{
        account_overrides::AccountOverrides,
        account_rent_state::{check_rent_state_with_account, RentState},
        accounts_db::{
            AccountShrinkThreshold, AccountsAddRootTiming, AccountsDb, AccountsDbConfig,
            IncludeSlotInHash, LoadHint, LoadedAccount, ScanStorageResult,
            VerifyAccountsHashAndLamportsConfig, ACCOUNTS_DB_CONFIG_FOR_BENCHMARKS,
            ACCOUNTS_DB_CONFIG_FOR_TESTING,
        },
        accounts_index::{
            AccountSecondaryIndexes, IndexKey, ScanConfig, ScanError, ScanResult, ZeroLamport,
        },
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        ancestors::Ancestors,
        bank::{Bank, NonceFull, NonceInfo, TransactionCheckResult, TransactionExecutionResult},
        blockhash_queue::BlockhashQueue,
        rent_collector::RentCollector,
        rent_debits::RentDebits,
        storable_accounts::StorableAccounts,
        transaction_error_metrics::TransactionErrorMetrics,
    },
    dashmap::DashMap,
    itertools::Itertools,
    log::*,
    solana_address_lookup_table_program::{error::AddressLookupError, state::AddressLookupTable},
    solana_program_runtime::{
        compute_budget::{self, ComputeBudget},
        loaded_programs::{LoadedProgram, LoadedProgramType, LoadedProgramsForTxBatch},
    },
    solana_sdk::{
        account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
        account_utils::StateMut,
        bpf_loader_upgradeable,
        clock::{BankId, Slot},
        feature_set::{
            self, add_set_tx_loaded_accounts_data_size_instruction,
            delay_visibility_of_program_deployment, enable_request_heap_frame_ix,
            include_loaded_accounts_data_size_in_fee_calculation,
            remove_congestion_multiplier_from_fee_calculation, remove_deprecated_request_unit_ix,
            simplify_writable_program_account_check, use_default_units_in_fee_calculation,
            FeatureSet,
        },
        fee::FeeStructure,
        genesis_config::ClusterType,
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
        saturating_add_assign,
        slot_hashes::SlotHashes,
        system_program,
        sysvar::{self, instructions::construct_instructions_data},
        transaction::{Result, SanitizedTransaction, TransactionAccountLocks, TransactionError},
        transaction_context::{IndexOfAccount, TransactionAccount},
    },
    solana_system_program::{get_system_account_kind, SystemAccountKind},
    std::{
        cmp::Reverse,
        collections::{hash_map, BinaryHeap, HashMap, HashSet},
        num::NonZeroUsize,
        ops::RangeBounds,
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
    },
};

pub type PubkeyAccountSlot = (Pubkey, AccountSharedData, Slot);

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
pub type TransactionProgramIndices = Vec<Vec<IndexOfAccount>>;
#[derive(PartialEq, Eq, Debug, Clone)]
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
        Self::new_empty(AccountsDb::default_for_tests())
    }

    pub fn new_with_config_for_tests(
        paths: Vec<PathBuf>,
        cluster_type: &ClusterType,
        account_indexes: AccountSecondaryIndexes,
        shrink_ratio: AccountShrinkThreshold,
    ) -> Self {
        Self::new_with_config(
            paths,
            cluster_type,
            account_indexes,
            shrink_ratio,
            Some(ACCOUNTS_DB_CONFIG_FOR_TESTING),
            None,
            &Arc::default(),
        )
    }

    pub fn new_with_config_for_benches(
        paths: Vec<PathBuf>,
        cluster_type: &ClusterType,
        account_indexes: AccountSecondaryIndexes,
        shrink_ratio: AccountShrinkThreshold,
    ) -> Self {
        Self::new_with_config(
            paths,
            cluster_type,
            account_indexes,
            shrink_ratio,
            Some(ACCOUNTS_DB_CONFIG_FOR_BENCHMARKS),
            None,
            &Arc::default(),
        )
    }

    pub fn new_with_config(
        paths: Vec<PathBuf>,
        cluster_type: &ClusterType,
        account_indexes: AccountSecondaryIndexes,
        shrink_ratio: AccountShrinkThreshold,
        accounts_db_config: Option<AccountsDbConfig>,
        accounts_update_notifier: Option<AccountsUpdateNotifier>,
        exit: &Arc<AtomicBool>,
    ) -> Self {
        Self::new_empty(AccountsDb::new_with_config(
            paths,
            cluster_type,
            account_indexes,
            shrink_ratio,
            accounts_db_config,
            accounts_update_notifier,
            exit,
        ))
    }

    pub(crate) fn new_empty(accounts_db: AccountsDb) -> Self {
        Self::new(Arc::new(accounts_db))
    }

    pub(crate) fn new(accounts_db: Arc<AccountsDb>) -> Self {
        Self {
            accounts_db,
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

    /// If feature `cap_transaction_accounts_data_size` is active, total accounts data a
    /// transaction can load is limited to
    ///   if `set_tx_loaded_accounts_data_size` instruction is not activated or not used, then
    ///     default value of 64MiB to not break anyone in Mainnet-beta today
    ///   else
    ///     user requested loaded accounts size.
    ///     Note, requesting zero bytes will result transaction error
    fn get_requested_loaded_accounts_data_size_limit(
        tx: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) -> Result<Option<NonZeroUsize>> {
        if feature_set.is_active(&feature_set::cap_transaction_accounts_data_size::id()) {
            let mut compute_budget =
                ComputeBudget::new(compute_budget::MAX_COMPUTE_UNIT_LIMIT as u64);
            let _process_transaction_result = compute_budget.process_instructions(
                tx.message().program_instructions_iter(),
                feature_set.is_active(&use_default_units_in_fee_calculation::id()),
                !feature_set.is_active(&remove_deprecated_request_unit_ix::id()),
                true, // don't reject txs that use request heap size ix
                feature_set.is_active(&add_set_tx_loaded_accounts_data_size_instruction::id()),
            );
            // sanitize against setting size limit to zero
            NonZeroUsize::new(compute_budget.loaded_accounts_data_size_limit).map_or(
                Err(TransactionError::InvalidLoadedAccountsDataSizeLimit),
                |v| Ok(Some(v)),
            )
        } else {
            // feature not activated, no loaded accounts data limit imposed.
            Ok(None)
        }
    }

    /// Accumulate loaded account data size into `accumulated_accounts_data_size`.
    /// Returns TransactionErr::MaxLoadedAccountsDataSizeExceeded if
    /// `requested_loaded_accounts_data_size_limit` is specified and
    /// `accumulated_accounts_data_size` exceeds it.
    fn accumulate_and_check_loaded_account_data_size(
        accumulated_loaded_accounts_data_size: &mut usize,
        account_data_size: usize,
        requested_loaded_accounts_data_size_limit: Option<NonZeroUsize>,
        error_counters: &mut TransactionErrorMetrics,
    ) -> Result<()> {
        if let Some(requested_loaded_accounts_data_size) = requested_loaded_accounts_data_size_limit
        {
            saturating_add_assign!(*accumulated_loaded_accounts_data_size, account_data_size);
            if *accumulated_loaded_accounts_data_size > requested_loaded_accounts_data_size.get() {
                error_counters.max_loaded_accounts_data_size_exceeded += 1;
                Err(TransactionError::MaxLoadedAccountsDataSizeExceeded)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn account_shared_data_from_program(
        key: &Pubkey,
        feature_set: &FeatureSet,
        program: &LoadedProgram,
        program_accounts: &HashMap<Pubkey, &Pubkey>,
    ) -> Result<AccountSharedData> {
        // Check for tombstone
        let result = match &program.program {
            LoadedProgramType::FailedVerification | LoadedProgramType::Closed => {
                Err(TransactionError::InvalidProgramForExecution)
            }
            LoadedProgramType::DelayVisibility => {
                debug_assert!(feature_set.is_active(&delay_visibility_of_program_deployment::id()));
                Err(TransactionError::InvalidProgramForExecution)
            }
            _ => Ok(()),
        };
        if feature_set.is_active(&simplify_writable_program_account_check::id()) {
            // Currently CPI only fails if an execution is actually attempted. With this check it
            // would also fail if a transaction just references an invalid program. So the checking
            // of the result is being feature gated.
            result?;
        }
        // It's an executable program account. The program is already loaded in the cache.
        // So the account data is not needed. Return a dummy AccountSharedData with meta
        // information.
        let mut program_account = AccountSharedData::default();
        let program_owner = program_accounts
            .get(key)
            .ok_or(TransactionError::AccountNotFound)?;
        program_account.set_owner(**program_owner);
        program_account.set_executable(true);
        Ok(program_account)
    }

    #[allow(clippy::too_many_arguments)]
    fn load_transaction_accounts(
        &self,
        ancestors: &Ancestors,
        tx: &SanitizedTransaction,
        fee: u64,
        error_counters: &mut TransactionErrorMetrics,
        rent_collector: &RentCollector,
        feature_set: &FeatureSet,
        account_overrides: Option<&AccountOverrides>,
        program_accounts: &HashMap<Pubkey, &Pubkey>,
        loaded_programs: &LoadedProgramsForTxBatch,
    ) -> Result<LoadedTransaction> {
        // NOTE: this check will never fail because `tx` is sanitized
        if tx.signatures().is_empty() && fee != 0 {
            return Err(TransactionError::MissingSignatureForFee);
        }

        // There is no way to predict what program will execute without an error
        // If a fee can pay for execution then the program will be scheduled
        let mut validated_fee_payer = false;
        let mut tx_rent: TransactionRent = 0;
        let message = tx.message();
        let account_keys = message.account_keys();
        let mut accounts_found = Vec::with_capacity(account_keys.len());
        let mut account_deps = Vec::with_capacity(account_keys.len());
        let mut rent_debits = RentDebits::default();

        let set_exempt_rent_epoch_max =
            feature_set.is_active(&solana_sdk::feature_set::set_exempt_rent_epoch_max::id());

        let requested_loaded_accounts_data_size_limit =
            Self::get_requested_loaded_accounts_data_size_limit(tx, feature_set)?;
        let mut accumulated_accounts_data_size: usize = 0;

        let instruction_accounts = message
            .instructions()
            .iter()
            .flat_map(|instruction| &instruction.accounts)
            .unique()
            .collect::<Vec<&u8>>();

        let mut accounts = account_keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let mut account_found = true;
                #[allow(clippy::collapsible_else_if)]
                let account = if solana_sdk::sysvar::instructions::check_id(key) {
                    Self::construct_instructions_account(
                        message,
                        feature_set
                            .is_active(&feature_set::instructions_sysvar_owned_by_sysvar::id()),
                    )
                } else {
                    let instruction_account = u8::try_from(i)
                        .map(|i| instruction_accounts.contains(&&i))
                        .unwrap_or(false);
                    let (account_size, mut account, rent) = if let Some(account_override) =
                        account_overrides.and_then(|overrides| overrides.get(key))
                    {
                        (account_override.data().len(), account_override.clone(), 0)
                    } else if let Some(program) = (!instruction_account && !message.is_writable(i))
                        .then_some(())
                        .and_then(|_| loaded_programs.find(key))
                    {
                        // This condition block does special handling for accounts that are passed
                        // as instruction account to any of the instructions in the transaction.
                        // It's been noticed that some programs are reading other program accounts
                        // (that are passed to the program as instruction accounts). So such accounts
                        // are needed to be loaded even though corresponding compiled program may
                        // already be present in the cache.
                        Self::account_shared_data_from_program(
                            key,
                            feature_set,
                            program.as_ref(),
                            program_accounts,
                        )
                        .map(|program_account| (program.account_size, program_account, 0))?
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
                                            set_exempt_rent_epoch_max,
                                        )
                                        .rent_amount;
                                    (account.data().len(), account, rent_due)
                                } else {
                                    (account.data().len(), account, 0)
                                }
                            })
                            .unwrap_or_else(|| {
                                account_found = false;
                                let mut default_account = AccountSharedData::default();
                                if set_exempt_rent_epoch_max {
                                    // All new accounts must be rent-exempt (enforced in Bank::execute_loaded_transaction).
                                    // Currently, rent collection sets rent_epoch to u64::MAX, but initializing the account
                                    // with this field already set would allow us to skip rent collection for these accounts.
                                    default_account.set_rent_epoch(u64::MAX);
                                }
                                (default_account.data().len(), default_account, 0)
                            })
                    };
                    Self::accumulate_and_check_loaded_account_data_size(
                        &mut accumulated_accounts_data_size,
                        account_size,
                        requested_loaded_accounts_data_size_limit,
                        error_counters,
                    )?;

                    if !validated_fee_payer && message.is_non_loader_key(i) {
                        if i != 0 {
                            warn!("Payer index should be 0! {:?}", tx);
                        }

                        Self::validate_fee_payer(
                            key,
                            &mut account,
                            i as IndexOfAccount,
                            error_counters,
                            rent_collector,
                            feature_set,
                            fee,
                        )?;

                        validated_fee_payer = true;
                    }

                    if bpf_loader_upgradeable::check_id(account.owner()) {
                        if !feature_set.is_active(&simplify_writable_program_account_check::id())
                            && message.is_writable(i)
                            && !message.is_upgradeable_loader_present()
                        {
                            error_counters.invalid_writable_account += 1;
                            return Err(TransactionError::InvalidWritableAccount);
                        }
                    } else if account.executable() && message.is_writable(i) {
                        error_counters.invalid_writable_account += 1;
                        return Err(TransactionError::InvalidWritableAccount);
                    }

                    tx_rent += rent;
                    rent_debits.insert(key, rent, account.lamports());

                    account
                };

                accounts_found.push(account_found);
                Ok((*key, account))
            })
            .collect::<Result<Vec<_>>>()?;

        if !validated_fee_payer {
            error_counters.account_not_found += 1;
            return Err(TransactionError::AccountNotFound);
        }

        // Appends the account_deps at the end of the accounts,
        // this way they can be accessed in a uniform way.
        // At places where only the accounts are needed,
        // the account_deps are truncated using e.g:
        // accounts.iter().take(message.account_keys.len())
        accounts.append(&mut account_deps);

        let disable_builtin_loader_ownership_chains =
            feature_set.is_active(&feature_set::disable_builtin_loader_ownership_chains::ID);
        let builtins_start_index = accounts.len();
        let program_indices = message
            .instructions()
            .iter()
            .map(|instruction| {
                let mut account_indices = Vec::new();
                let mut program_index = instruction.program_id_index as usize;
                for _ in 0..5 {
                    let (program_id, program_account) = accounts
                        .get(program_index)
                        .ok_or(TransactionError::ProgramAccountNotFound)?;
                    let account_found = accounts_found.get(program_index).unwrap_or(&true);
                    if native_loader::check_id(program_id) {
                        return Ok(account_indices);
                    }
                    if !account_found {
                        error_counters.account_not_found += 1;
                        return Err(TransactionError::ProgramAccountNotFound);
                    }
                    if !program_account.executable() {
                        error_counters.invalid_program_for_execution += 1;
                        return Err(TransactionError::InvalidProgramForExecution);
                    }
                    account_indices.insert(0, program_index as IndexOfAccount);
                    let owner_id = program_account.owner();
                    if native_loader::check_id(owner_id) {
                        return Ok(account_indices);
                    }
                    program_index = if let Some(owner_index) = accounts
                        .get(builtins_start_index..)
                        .ok_or(TransactionError::ProgramAccountNotFound)?
                        .iter()
                        .position(|(key, _)| key == owner_id)
                    {
                        builtins_start_index.saturating_add(owner_index)
                    } else {
                        let owner_index = accounts.len();
                        if let Some((owner_account, _)) =
                            self.accounts_db.load_with_fixed_root(ancestors, owner_id)
                        {
                            if disable_builtin_loader_ownership_chains
                                && !native_loader::check_id(owner_account.owner())
                                || !owner_account.executable()
                            {
                                error_counters.invalid_program_for_execution += 1;
                                return Err(TransactionError::InvalidProgramForExecution);
                            }
                            Self::accumulate_and_check_loaded_account_data_size(
                                &mut accumulated_accounts_data_size,
                                owner_account.data().len(),
                                requested_loaded_accounts_data_size_limit,
                                error_counters,
                            )?;
                            accounts.push((*owner_id, owner_account));
                        } else {
                            error_counters.account_not_found += 1;
                            return Err(TransactionError::ProgramAccountNotFound);
                        }
                        owner_index
                    };
                    if disable_builtin_loader_ownership_chains {
                        account_indices.insert(0, program_index as IndexOfAccount);
                        return Ok(account_indices);
                    }
                }
                error_counters.call_chain_too_deep += 1;
                Err(TransactionError::CallChainTooDeep)
            })
            .collect::<Result<Vec<Vec<IndexOfAccount>>>>()?;

        Ok(LoadedTransaction {
            accounts,
            program_indices,
            rent: tx_rent,
            rent_debits,
        })
    }

    fn validate_fee_payer(
        payer_address: &Pubkey,
        payer_account: &mut AccountSharedData,
        payer_index: IndexOfAccount,
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

        // allow collapsible-else-if to make removing the feature gate safer once activated
        #[allow(clippy::collapsible_else_if)]
        if feature_set.is_active(&feature_set::checked_arithmetic_in_fee_validation::id()) {
            payer_account
                .lamports()
                .checked_sub(min_balance)
                .and_then(|v| v.checked_sub(fee))
                .ok_or_else(|| {
                    error_counters.insufficient_funds += 1;
                    TransactionError::InsufficientFundsForFee
                })?;
        } else {
            if payer_account.lamports() < fee + min_balance {
                error_counters.insufficient_funds += 1;
                return Err(TransactionError::InsufficientFundsForFee);
            }
        }

        let payer_pre_rent_state = RentState::from_account(payer_account, &rent_collector.rent);
        payer_account
            .checked_sub_lamports(fee)
            .map_err(|_| TransactionError::InsufficientFundsForFee)?;

        let payer_post_rent_state = RentState::from_account(payer_account, &rent_collector.rent);
        check_rent_state_with_account(
            &payer_pre_rent_state,
            &payer_post_rent_state,
            payer_address,
            payer_account,
            feature_set
                .is_active(&feature_set::include_account_index_in_rent_error::ID)
                .then_some(payer_index),
        )
    }

    /// Returns a hash map of executable program accounts (program accounts that are not writable
    /// in the given transactions), and their owners, for the transactions with a valid
    /// blockhash or nonce.
    pub fn filter_executable_program_accounts<'a>(
        &self,
        ancestors: &Ancestors,
        txs: &[SanitizedTransaction],
        lock_results: &mut [TransactionCheckResult],
        program_owners: &[&'a Pubkey],
        hash_queue: &BlockhashQueue,
    ) -> HashMap<Pubkey, &'a Pubkey> {
        let mut result = HashMap::new();
        lock_results.iter_mut().zip(txs).for_each(|etx| {
            if let ((Ok(()), nonce), tx) = etx {
                if nonce
                    .as_ref()
                    .map(|nonce| nonce.lamports_per_signature())
                    .unwrap_or_else(|| {
                        hash_queue.get_lamports_per_signature(tx.message().recent_blockhash())
                    })
                    .is_some()
                {
                    tx.message().account_keys().iter().for_each(|key| {
                        if !result.contains_key(key) {
                            if let Ok(index) = self.accounts_db.account_matches_owners(
                                ancestors,
                                key,
                                program_owners,
                            ) {
                                program_owners
                                    .get(index)
                                    .and_then(|owner| result.insert(*key, *owner));
                            }
                        }
                    });
                } else {
                    // If the transaction's nonce account was not valid, and blockhash is not found,
                    // the transaction will fail to process. Let's not load any programs from the
                    // transaction, and update the status of the transaction.
                    *etx.0 = (Err(TransactionError::BlockhashNotFound), None);
                }
            }
        });
        result
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
        program_accounts: &HashMap<Pubkey, &Pubkey>,
        loaded_programs: &LoadedProgramsForTxBatch,
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
                            feature_set.is_active(&use_default_units_in_fee_calculation::id()),
                            !feature_set.is_active(&remove_deprecated_request_unit_ix::id()),
                            feature_set.is_active(&remove_congestion_multiplier_from_fee_calculation::id()),
                            feature_set.is_active(&enable_request_heap_frame_ix::id()) || self.accounts_db.expected_cluster_type() != ClusterType::MainnetBeta,
                            feature_set.is_active(&add_set_tx_loaded_accounts_data_size_instruction::id()),
                            feature_set.is_active(&include_loaded_accounts_data_size_in_fee_calculation::id()),
                        )
                    } else {
                        return (Err(TransactionError::BlockhashNotFound), None);
                    };

                    let loaded_transaction = match self.load_transaction_accounts(
                        ancestors,
                        tx,
                        fee,
                        error_counters,
                        rent_collector,
                        feature_set,
                        account_overrides,
                        program_accounts,
                        loaded_programs,
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

    /// Slow because lock is held for 1 operation instead of many
    /// This always returns None for zero-lamport accounts.
    fn load_slow(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        load_hint: LoadHint,
    ) -> Option<(AccountSharedData, Slot)> {
        self.accounts_db.load(ancestors, pubkey, load_hint)
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
            |accum: &DashMap<Pubkey, B>, loaded_account: LoadedAccount| {
                let loaded_account_pubkey = *loaded_account.pubkey();
                if let Some(val) = func(loaded_account) {
                    accum.insert(loaded_account_pubkey, val);
                }
            },
        );

        match scan_result {
            ScanStorageResult::Cached(cached_result) => cached_result,
            ScanStorageResult::Stored(stored_result) => stored_result
                .into_iter()
                .map(|(_pubkey, val)| val)
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
        let mut account_balances = BinaryHeap::new();
        self.accounts_db.scan_accounts(
            ancestors,
            bank_id,
            |option| {
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
                    if account_balances.len() == num {
                        let Reverse(entry) = account_balances
                            .peek()
                            .expect("BinaryHeap::peek should succeed when len > 0");
                        if *entry >= (account.lamports(), *pubkey) {
                            return;
                        }
                        account_balances.pop();
                    }
                    account_balances.push(Reverse((account.lamports(), *pubkey)));
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

    /// Only called from startup or test code.
    #[must_use]
    pub fn verify_accounts_hash_and_lamports(
        &self,
        slot: Slot,
        total_lamports: u64,
        base: Option<(Slot, /*capitalization*/ u64)>,
        config: VerifyAccountsHashAndLamportsConfig,
    ) -> bool {
        if let Err(err) =
            self.accounts_db
                .verify_accounts_hash_and_lamports(slot, total_lamports, base, config)
        {
            warn!("verify_accounts_hash failed: {err:?}, slot: {slot}");
            false
        } else {
            true
        }
    }

    pub fn is_loadable(lamports: u64) -> bool {
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

    fn load_with_slot(
        collector: &mut Vec<PubkeyAccountSlot>,
        some_account_tuple: Option<(&Pubkey, AccountSharedData, Slot)>,
    ) {
        if let Some(mapped_account_tuple) = some_account_tuple
            .filter(|(_, account, _)| Self::is_loadable(account.lamports()))
            .map(|(pubkey, account, slot)| (*pubkey, account, slot))
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
        let mut collector = Vec::new();
        self.accounts_db
            .scan_accounts(
                ancestors,
                bank_id,
                |some_account_tuple| {
                    Self::load_while_filtering(&mut collector, some_account_tuple, |account| {
                        account.owner() == program_id
                    })
                },
                config,
            )
            .map(|_| collector)
    }

    pub fn load_by_program_with_filter<F: Fn(&AccountSharedData) -> bool>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        program_id: &Pubkey,
        filter: F,
        config: &ScanConfig,
    ) -> ScanResult<Vec<TransactionAccount>> {
        let mut collector = Vec::new();
        self.accounts_db
            .scan_accounts(
                ancestors,
                bank_id,
                |some_account_tuple| {
                    Self::load_while_filtering(&mut collector, some_account_tuple, |account| {
                        account.owner() == program_id && filter(account)
                    })
                },
                config,
            )
            .map(|_| collector)
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
        let mut collector = Vec::new();
        let result = self
            .accounts_db
            .index_scan_accounts(
                ancestors,
                bank_id,
                *index_key,
                |some_account_tuple| {
                    Self::load_while_filtering(&mut collector, some_account_tuple, |account| {
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
            .map(|_| collector);
        Self::maybe_abort_scan(result, &config)
    }

    pub fn account_indexes_include_key(&self, key: &Pubkey) -> bool {
        self.accounts_db.account_indexes.include_key(key)
    }

    pub fn load_all(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
    ) -> ScanResult<Vec<PubkeyAccountSlot>> {
        let mut collector = Vec::new();
        self.accounts_db
            .scan_accounts(
                ancestors,
                bank_id,
                |some_account_tuple| {
                    if let Some((pubkey, account, slot)) = some_account_tuple
                        .filter(|(_, account, _)| Self::is_loadable(account.lamports()))
                    {
                        collector.push((*pubkey, account, slot))
                    }
                },
                &ScanConfig::default(),
            )
            .map(|_| collector)
    }

    pub fn scan_all<F>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        scan_func: F,
    ) -> ScanResult<()>
    where
        F: FnMut(Option<(&Pubkey, AccountSharedData, Slot)>),
    {
        self.accounts_db
            .scan_accounts(ancestors, bank_id, scan_func, &ScanConfig::default())
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
    ) -> Vec<PubkeyAccountSlot> {
        let mut collector = Vec::new();
        self.accounts_db.range_scan_accounts(
            "", // disable logging of this. We now parallelize it and this results in multiple parallel logs
            ancestors,
            range,
            &ScanConfig::new(true),
            |option| Self::load_with_slot(&mut collector, option),
        );
        collector
    }

    /// Slow because lock is held for 1 operation instead of many.
    /// WARNING: This noncached version is only to be used for tests/benchmarking
    /// as bypassing the cache in general is not supported
    pub fn store_slow_uncached(&self, slot: Slot, pubkey: &Pubkey, account: &AccountSharedData) {
        self.accounts_db.store_uncached(slot, &[(pubkey, account)]);
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

    /// This function will prevent multiple threads from modifying the same account state at the
    /// same time
    #[must_use]
    #[allow(clippy::needless_collect)]
    pub fn lock_accounts<'a>(
        &self,
        txs: impl Iterator<Item = &'a SanitizedTransaction>,
        tx_account_lock_limit: usize,
    ) -> Vec<Result<()>> {
        let tx_account_locks_results: Vec<Result<_>> = txs
            .map(|tx| tx.get_account_locks(tx_account_lock_limit))
            .collect();
        self.lock_accounts_inner(tx_account_locks_results)
    }

    #[must_use]
    #[allow(clippy::needless_collect)]
    pub fn lock_accounts_with_results<'a>(
        &self,
        txs: impl Iterator<Item = &'a SanitizedTransaction>,
        results: impl Iterator<Item = Result<()>>,
        tx_account_lock_limit: usize,
    ) -> Vec<Result<()>> {
        let tx_account_locks_results: Vec<Result<_>> = txs
            .zip(results)
            .map(|(tx, result)| match result {
                Ok(()) => tx.get_account_locks(tx_account_lock_limit),
                Err(err) => Err(err),
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
        durable_nonce: &DurableNonce,
        lamports_per_signature: u64,
        include_slot_in_hash: IncludeSlotInHash,
    ) {
        let (accounts_to_store, transactions) = self.collect_accounts_to_store(
            txs,
            res,
            loaded,
            rent_collector,
            durable_nonce,
            lamports_per_signature,
        );
        self.accounts_db.store_cached(
            (slot, &accounts_to_store[..], include_slot_in_hash),
            Some(&transactions),
        );
    }

    pub fn store_accounts_cached<'a, T: ReadableAccount + Sync + ZeroLamport + 'a>(
        &self,
        accounts: impl StorableAccounts<'a, T>,
    ) {
        self.accounts_db.store_cached(accounts, None)
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
        _rent_collector: &RentCollector,
        durable_nonce: &DurableNonce,
        lamports_per_signature: u64,
    ) -> (
        Vec<(&'a Pubkey, &'a AccountSharedData)>,
        Vec<Option<&'a SanitizedTransaction>>,
    ) {
        let mut accounts = Vec::with_capacity(load_results.len());
        let mut transactions = Vec::with_capacity(load_results.len());
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
                (Ok(_), _) => None, // Success, don't do any additional nonce processing
                (Err(_), Some(nonce)) => {
                    Some((nonce, true /* rollback */))
                }
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
                        // Add to the accounts to store
                        accounts.push((&*address, &*account));
                        transactions.push(Some(tx));
                    }
                }
            }
        }
        (accounts, transactions)
    }
}

fn prepare_if_nonce_account(
    address: &Pubkey,
    account: &mut AccountSharedData,
    execution_result: &Result<()>,
    is_fee_payer: bool,
    maybe_nonce: Option<(&NonceFull, bool)>,
    &durable_nonce: &DurableNonce,
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
                let nonce_versions = NonceVersions::new(nonce_state);
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
