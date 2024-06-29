#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::qualifiers;
use {
    crate::{
        account_loader::{
            collect_rent_from_account, load_accounts, validate_fee_payer,
            CheckedTransactionDetails, LoadedTransaction, TransactionCheckResult,
            TransactionLoadResult, TransactionValidationResult, ValidatedTransactionDetails,
        },
        account_overrides::AccountOverrides,
        message_processor::MessageProcessor,
        program_loader::{get_program_modification_slot, load_program_with_pubkey},
        rollback_accounts::RollbackAccounts,
        transaction_account_state_info::TransactionAccountStateInfo,
        transaction_error_metrics::TransactionErrorMetrics,
        transaction_processing_callback::TransactionProcessingCallback,
        transaction_results::{TransactionExecutionDetails, TransactionExecutionResult},
    },
    log::debug,
    percentage::Percentage,
    solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1,
    solana_compute_budget::{
        compute_budget::ComputeBudget,
        compute_budget_processor::process_compute_budget_instructions,
    },
    solana_loader_v4_program::create_program_runtime_environment_v2,
    solana_measure::{measure, measure::Measure},
    solana_program_runtime::{
        invoke_context::{EnvironmentConfig, InvokeContext},
        loaded_programs::{
            ForkGraph, ProgramCache, ProgramCacheEntry, ProgramCacheForTxBatch,
            ProgramCacheMatchCriteria, ProgramRuntimeEnvironments,
        },
        log_collector::LogCollector,
        sysvar_cache::SysvarCache,
        timings::{ExecuteTimingType, ExecuteTimings},
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, PROGRAM_OWNERS},
        clock::{Epoch, Slot},
        feature_set::{
            include_loaded_accounts_data_size_in_fee_calculation,
            remove_rounding_in_fee_calculation, FeatureSet,
        },
        fee::{FeeBudgetLimits, FeeStructure},
        hash::Hash,
        inner_instruction::{InnerInstruction, InnerInstructionsList},
        instruction::{CompiledInstruction, TRANSACTION_LEVEL_STACK_HEIGHT},
        message::SanitizedMessage,
        pubkey::Pubkey,
        rent_collector::RentCollector,
        saturating_add_assign,
        transaction::{self, SanitizedTransaction, TransactionError},
        transaction_context::{ExecutionRecord, TransactionContext},
    },
    solana_type_overrides::sync::{atomic::Ordering, Arc, RwLock, RwLockReadGuard},
    solana_vote::vote_account::VoteAccountsHashMap,
    std::{
        cell::RefCell,
        collections::{hash_map::Entry, HashMap, HashSet},
        fmt::{Debug, Formatter},
        rc::Rc,
    },
};

/// A list of log messages emitted during a transaction
pub type TransactionLogMessages = Vec<String>;

/// The output of the transaction batch processor's
/// `load_and_execute_sanitized_transactions` method.
pub struct LoadAndExecuteSanitizedTransactionsOutput {
    /// Error metrics for transactions that were processed.
    pub error_metrics: TransactionErrorMetrics,
    /// Timings for transaction batch execution.
    pub execute_timings: ExecuteTimings,
    // Vector of results indicating whether a transaction was executed or could not
    // be executed. Note executed transactions can still have failed!
    pub execution_results: Vec<TransactionExecutionResult>,
    // Vector of loaded transactions from transactions that were processed.
    pub loaded_transactions: Vec<TransactionLoadResult>,
}

/// Configuration of the recording capabilities for transaction execution
#[derive(Copy, Clone, Default)]
pub struct ExecutionRecordingConfig {
    pub enable_cpi_recording: bool,
    pub enable_log_recording: bool,
    pub enable_return_data_recording: bool,
}

impl ExecutionRecordingConfig {
    pub fn new_single_setting(option: bool) -> Self {
        ExecutionRecordingConfig {
            enable_return_data_recording: option,
            enable_log_recording: option,
            enable_cpi_recording: option,
        }
    }
}

/// Configurations for processing transactions.
#[derive(Default)]
pub struct TransactionProcessingConfig<'a> {
    /// Encapsulates overridden accounts, typically used for transaction
    /// simulation.
    pub account_overrides: Option<&'a AccountOverrides>,
    /// Whether or not to check a program's modification slot when replenishing
    /// a program cache instance.
    pub check_program_modification_slot: bool,
    /// The compute budget to use for transaction execution.
    pub compute_budget: Option<ComputeBudget>,
    /// The maximum number of bytes that log messages can consume.
    pub log_messages_bytes_limit: Option<usize>,
    /// Whether to limit the number of programs loaded for the transaction
    /// batch.
    pub limit_to_load_programs: bool,
    /// Recording capabilities for transaction execution.
    pub recording_config: ExecutionRecordingConfig,
    /// The max number of accounts that a transaction may lock.
    pub transaction_account_lock_limit: Option<usize>,
}

/// Runtime environment for transaction batch processing.
#[derive(Default)]
pub struct TransactionProcessingEnvironment<'a> {
    /// The blockhash to use for the transaction batch.
    pub blockhash: Hash,
    /// The total stake for the current epoch.
    pub epoch_total_stake: Option<u64>,
    /// The vote accounts for the current epoch.
    pub epoch_vote_accounts: Option<&'a VoteAccountsHashMap>,
    /// Runtime feature set to use for the transaction batch.
    pub feature_set: Arc<FeatureSet>,
    /// Fee structure to use for assessing transaction fees.
    pub fee_structure: Option<&'a FeeStructure>,
    /// Lamports per signature to charge per transaction.
    pub lamports_per_signature: u64,
    /// Rent collector to use for the transaction batch.
    pub rent_collector: Option<&'a RentCollector>,
}

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
pub struct TransactionBatchProcessor<FG: ForkGraph> {
    /// Bank slot (i.e. block)
    slot: Slot,

    /// Bank epoch
    epoch: Epoch,

    /// SysvarCache is a collection of system variables that are
    /// accessible from on chain programs. It is passed to SVM from
    /// client code (e.g. Bank) and forwarded to the MessageProcessor.
    sysvar_cache: RwLock<SysvarCache>,

    /// Programs required for transaction batch processing
    pub program_cache: Arc<RwLock<ProgramCache<FG>>>,

    /// Builtin program ids
    pub builtin_program_ids: RwLock<HashSet<Pubkey>>,
}

impl<FG: ForkGraph> Debug for TransactionBatchProcessor<FG> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionBatchProcessor")
            .field("slot", &self.slot)
            .field("epoch", &self.epoch)
            .field("sysvar_cache", &self.sysvar_cache)
            .field("program_cache", &self.program_cache)
            .finish()
    }
}

impl<FG: ForkGraph> Default for TransactionBatchProcessor<FG> {
    fn default() -> Self {
        Self {
            slot: Slot::default(),
            epoch: Epoch::default(),
            sysvar_cache: RwLock::<SysvarCache>::default(),
            program_cache: Arc::new(RwLock::new(ProgramCache::new(
                Slot::default(),
                Epoch::default(),
            ))),
            builtin_program_ids: RwLock::new(HashSet::new()),
        }
    }
}

impl<FG: ForkGraph> TransactionBatchProcessor<FG> {
    pub fn new(slot: Slot, epoch: Epoch, builtin_program_ids: HashSet<Pubkey>) -> Self {
        Self {
            slot,
            epoch,
            sysvar_cache: RwLock::<SysvarCache>::default(),
            program_cache: Arc::new(RwLock::new(ProgramCache::new(slot, epoch))),
            builtin_program_ids: RwLock::new(builtin_program_ids),
        }
    }

    pub fn new_from(&self, slot: Slot, epoch: Epoch) -> Self {
        Self {
            slot,
            epoch,
            sysvar_cache: RwLock::<SysvarCache>::default(),
            program_cache: self.program_cache.clone(),
            builtin_program_ids: RwLock::new(self.builtin_program_ids.read().unwrap().clone()),
        }
    }

    /// Returns the current environments depending on the given epoch
    /// Returns None if the call could result in a deadlock
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    pub fn get_environments_for_epoch(&self, epoch: Epoch) -> Option<ProgramRuntimeEnvironments> {
        self.program_cache
            .try_read()
            .ok()
            .map(|cache| cache.get_environments_for_epoch(epoch))
    }

    pub fn sysvar_cache(&self) -> RwLockReadGuard<SysvarCache> {
        self.sysvar_cache.read().unwrap()
    }

    /// Main entrypoint to the SVM.
    pub fn load_and_execute_sanitized_transactions<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
        sanitized_txs: &[SanitizedTransaction],
        check_results: Vec<TransactionCheckResult>,
        environment: &TransactionProcessingEnvironment,
        config: &TransactionProcessingConfig,
    ) -> LoadAndExecuteSanitizedTransactionsOutput {
        // Initialize metrics.
        let mut error_metrics = TransactionErrorMetrics::default();
        let mut execute_timings = ExecuteTimings::default();

        let (validation_results, validate_fees_time) = measure!(self.validate_fees(
            callbacks,
            sanitized_txs,
            check_results,
            &environment.feature_set,
            environment
                .fee_structure
                .unwrap_or(&FeeStructure::default()),
            environment
                .rent_collector
                .unwrap_or(&RentCollector::default()),
            &mut error_metrics
        ));

        let mut program_cache_time = Measure::start("program_cache");
        let mut program_accounts_map = Self::filter_executable_program_accounts(
            callbacks,
            sanitized_txs,
            &validation_results,
            PROGRAM_OWNERS,
        );
        for builtin_program in self.builtin_program_ids.read().unwrap().iter() {
            program_accounts_map.insert(*builtin_program, 0);
        }

        let program_cache_for_tx_batch = Rc::new(RefCell::new(self.replenish_program_cache(
            callbacks,
            &program_accounts_map,
            config.check_program_modification_slot,
            config.limit_to_load_programs,
        )));

        if program_cache_for_tx_batch.borrow().hit_max_limit {
            const ERROR: TransactionError = TransactionError::ProgramCacheHitMaxLimit;
            let loaded_transactions = vec![Err(ERROR); sanitized_txs.len()];
            let execution_results =
                vec![TransactionExecutionResult::NotExecuted(ERROR); sanitized_txs.len()];
            return LoadAndExecuteSanitizedTransactionsOutput {
                error_metrics,
                execute_timings,
                execution_results,
                loaded_transactions,
            };
        }
        program_cache_time.stop();

        let mut load_time = Measure::start("accounts_load");
        let mut loaded_transactions = load_accounts(
            callbacks,
            sanitized_txs,
            validation_results,
            &mut error_metrics,
            config.account_overrides,
            &environment.feature_set,
            environment
                .rent_collector
                .unwrap_or(&RentCollector::default()),
            &program_cache_for_tx_batch.borrow(),
        );
        load_time.stop();

        let mut execution_time = Measure::start("execution_time");

        let execution_results: Vec<TransactionExecutionResult> = loaded_transactions
            .iter_mut()
            .zip(sanitized_txs.iter())
            .map(|(load_result, tx)| match load_result {
                Err(e) => TransactionExecutionResult::NotExecuted(e.clone()),
                Ok(loaded_transaction) => {
                    let result = self.execute_loaded_transaction(
                        tx,
                        loaded_transaction,
                        &mut execute_timings,
                        &mut error_metrics,
                        &mut program_cache_for_tx_batch.borrow_mut(),
                        environment,
                        config,
                    );

                    if let TransactionExecutionResult::Executed {
                        details,
                        programs_modified_by_tx,
                    } = &result
                    {
                        // Update batch specific cache of the loaded programs with the modifications
                        // made by the transaction, if it executed successfully.
                        if details.status.is_ok() {
                            program_cache_for_tx_batch
                                .borrow_mut()
                                .merge(programs_modified_by_tx);
                        }
                    }

                    result
                }
            })
            .collect();

        execution_time.stop();

        // Skip eviction when there's no chance this particular tx batch has increased the size of
        // ProgramCache entries. Note that loaded_missing is deliberately defined, so that there's
        // still at least one other batch, which will evict the program cache, even after the
        // occurrences of cooperative loading.
        if program_cache_for_tx_batch.borrow().loaded_missing
            || program_cache_for_tx_batch.borrow().merged_modified
        {
            const SHRINK_LOADED_PROGRAMS_TO_PERCENTAGE: u8 = 90;
            self.program_cache
                .write()
                .unwrap()
                .evict_using_2s_random_selection(
                    Percentage::from(SHRINK_LOADED_PROGRAMS_TO_PERCENTAGE),
                    self.slot,
                );
        }

        debug!(
            "load: {}us execute: {}us txs_len={}",
            load_time.as_us(),
            execution_time.as_us(),
            sanitized_txs.len(),
        );

        execute_timings.saturating_add_in_place(
            ExecuteTimingType::ValidateFeesUs,
            validate_fees_time.as_us(),
        );
        execute_timings.saturating_add_in_place(
            ExecuteTimingType::ProgramCacheUs,
            program_cache_time.as_us(),
        );
        execute_timings.saturating_add_in_place(ExecuteTimingType::LoadUs, load_time.as_us());
        execute_timings
            .saturating_add_in_place(ExecuteTimingType::ExecuteUs, execution_time.as_us());

        LoadAndExecuteSanitizedTransactionsOutput {
            error_metrics,
            execute_timings,
            execution_results,
            loaded_transactions,
        }
    }

    fn validate_fees<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
        sanitized_txs: &[impl core::borrow::Borrow<SanitizedTransaction>],
        check_results: Vec<TransactionCheckResult>,
        feature_set: &FeatureSet,
        fee_structure: &FeeStructure,
        rent_collector: &RentCollector,
        error_counters: &mut TransactionErrorMetrics,
    ) -> Vec<TransactionValidationResult> {
        sanitized_txs
            .iter()
            .zip(check_results)
            .map(|(sanitized_tx, check_result)| {
                check_result.and_then(|checked_details| {
                    let message = sanitized_tx.borrow().message();
                    self.validate_transaction_fee_payer(
                        callbacks,
                        message,
                        checked_details,
                        feature_set,
                        fee_structure,
                        rent_collector,
                        error_counters,
                    )
                })
            })
            .collect()
    }

    // Loads transaction fee payer, collects rent if necessary, then calculates
    // transaction fees, and deducts them from the fee payer balance. If the
    // account is not found or has insufficient funds, an error is returned.
    fn validate_transaction_fee_payer<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
        message: &SanitizedMessage,
        checked_details: CheckedTransactionDetails,
        feature_set: &FeatureSet,
        fee_structure: &FeeStructure,
        rent_collector: &RentCollector,
        error_counters: &mut TransactionErrorMetrics,
    ) -> transaction::Result<ValidatedTransactionDetails> {
        let compute_budget_limits = process_compute_budget_instructions(
            message.program_instructions_iter(),
        )
        .map_err(|err| {
            error_counters.invalid_compute_budget += 1;
            err
        })?;

        let fee_payer_address = message.fee_payer();
        let Some(mut fee_payer_account) = callbacks.get_account_shared_data(fee_payer_address)
        else {
            error_counters.account_not_found += 1;
            return Err(TransactionError::AccountNotFound);
        };

        let fee_payer_loaded_rent_epoch = fee_payer_account.rent_epoch();
        let fee_payer_rent_debit = collect_rent_from_account(
            feature_set,
            rent_collector,
            fee_payer_address,
            &mut fee_payer_account,
        )
        .rent_amount;

        let CheckedTransactionDetails {
            nonce,
            lamports_per_signature,
        } = checked_details;

        let fee_budget_limits = FeeBudgetLimits::from(compute_budget_limits);
        let fee_details = fee_structure.calculate_fee_details(
            message,
            lamports_per_signature,
            &fee_budget_limits,
            feature_set.is_active(&include_loaded_accounts_data_size_in_fee_calculation::id()),
            feature_set.is_active(&remove_rounding_in_fee_calculation::id()),
        );

        let fee_payer_index = 0;
        validate_fee_payer(
            fee_payer_address,
            &mut fee_payer_account,
            fee_payer_index,
            error_counters,
            rent_collector,
            fee_details.total_fee(),
        )?;

        // Capture fee-subtracted fee payer account and original nonce account state
        // to rollback to if transaction execution fails.
        let rollback_accounts = RollbackAccounts::new(
            nonce,
            *fee_payer_address,
            fee_payer_account.clone(),
            fee_payer_rent_debit,
            fee_payer_loaded_rent_epoch,
        );

        Ok(ValidatedTransactionDetails {
            fee_details,
            fee_payer_account,
            fee_payer_rent_debit,
            rollback_accounts,
            compute_budget_limits,
        })
    }

    /// Returns a map from executable program accounts (all accounts owned by any loader)
    /// to their usage counters, for the transactions with a valid blockhash or nonce.
    fn filter_executable_program_accounts<CB: TransactionProcessingCallback>(
        callbacks: &CB,
        txs: &[SanitizedTransaction],
        validation_results: &[TransactionValidationResult],
        program_owners: &[Pubkey],
    ) -> HashMap<Pubkey, u64> {
        let mut result: HashMap<Pubkey, u64> = HashMap::new();
        validation_results.iter().zip(txs).for_each(|etx| {
            if let (Ok(_), tx) = etx {
                tx.message()
                    .account_keys()
                    .iter()
                    .for_each(|key| match result.entry(*key) {
                        Entry::Occupied(mut entry) => {
                            let count = entry.get_mut();
                            saturating_add_assign!(*count, 1);
                        }
                        Entry::Vacant(entry) => {
                            if callbacks
                                .account_matches_owners(key, program_owners)
                                .is_some()
                            {
                                entry.insert(1);
                            }
                        }
                    });
            }
        });
        result
    }

    fn replenish_program_cache<CB: TransactionProcessingCallback>(
        &self,
        callback: &CB,
        program_accounts_map: &HashMap<Pubkey, u64>,
        check_program_modification_slot: bool,
        limit_to_load_programs: bool,
    ) -> ProgramCacheForTxBatch {
        let mut missing_programs: Vec<(Pubkey, (ProgramCacheMatchCriteria, u64))> =
            program_accounts_map
                .iter()
                .map(|(pubkey, count)| {
                    let match_criteria = if check_program_modification_slot {
                        get_program_modification_slot(callback, pubkey)
                            .map_or(ProgramCacheMatchCriteria::Tombstone, |slot| {
                                ProgramCacheMatchCriteria::DeployedOnOrAfterSlot(slot)
                            })
                    } else {
                        ProgramCacheMatchCriteria::NoCriteria
                    };
                    (*pubkey, (match_criteria, *count))
                })
                .collect();

        let mut loaded_programs_for_txs = None;
        loop {
            let (program_to_store, task_cookie, task_waiter) = {
                // Lock the global cache.
                let program_cache = self.program_cache.read().unwrap();
                // Initialize our local cache.
                let is_first_round = loaded_programs_for_txs.is_none();
                if is_first_round {
                    loaded_programs_for_txs = Some(ProgramCacheForTxBatch::new_from_cache(
                        self.slot,
                        self.epoch,
                        &program_cache,
                    ));
                }
                // Figure out which program needs to be loaded next.
                let program_to_load = program_cache.extract(
                    &mut missing_programs,
                    loaded_programs_for_txs.as_mut().unwrap(),
                    is_first_round,
                );

                let program_to_store = program_to_load.map(|(key, count)| {
                    // Load, verify and compile one program.
                    let program = load_program_with_pubkey(
                        callback,
                        &program_cache.get_environments_for_epoch(self.epoch),
                        &key,
                        self.slot,
                        false,
                    )
                    .expect("called load_program_with_pubkey() with nonexistent account");
                    program.tx_usage_counter.store(count, Ordering::Relaxed);
                    (key, program)
                });

                let task_waiter = Arc::clone(&program_cache.loading_task_waiter);
                (program_to_store, task_waiter.cookie(), task_waiter)
                // Unlock the global cache again.
            };

            if let Some((key, program)) = program_to_store {
                let mut program_cache = self.program_cache.write().unwrap();
                // Submit our last completed loading task.
                if program_cache.finish_cooperative_loading_task(self.slot, key, program)
                    && limit_to_load_programs
                {
                    // This branch is taken when there is an error in assigning a program to a
                    // cache slot. It is not possible to mock this error for SVM unit
                    // tests purposes.
                    let mut ret = ProgramCacheForTxBatch::new_from_cache(
                        self.slot,
                        self.epoch,
                        &program_cache,
                    );
                    ret.hit_max_limit = true;
                    return ret;
                }
            } else if missing_programs.is_empty() {
                break;
            } else {
                // Sleep until the next finish_cooperative_loading_task() call.
                // Once a task completes we'll wake up and try to load the
                // missing programs inside the tx batch again.
                let _new_cookie = task_waiter.wait(task_cookie);
            }
        }

        loaded_programs_for_txs.unwrap()
    }

    pub fn prepare_program_cache_for_upcoming_feature_set<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
        upcoming_feature_set: &FeatureSet,
        compute_budget: &ComputeBudget,
        slot_index: u64,
        slots_in_epoch: u64,
    ) {
        // Recompile loaded programs one at a time before the next epoch hits
        let slots_in_recompilation_phase =
            (solana_program_runtime::loaded_programs::MAX_LOADED_ENTRY_COUNT as u64)
                .min(slots_in_epoch)
                .checked_div(2)
                .unwrap();
        let mut program_cache = self.program_cache.write().unwrap();
        if program_cache.upcoming_environments.is_some() {
            if let Some((key, program_to_recompile)) = program_cache.programs_to_recompile.pop() {
                let effective_epoch = program_cache.latest_root_epoch.saturating_add(1);
                drop(program_cache);
                let environments_for_epoch = self
                    .program_cache
                    .read()
                    .unwrap()
                    .get_environments_for_epoch(effective_epoch);
                if let Some(recompiled) = load_program_with_pubkey(
                    callbacks,
                    &environments_for_epoch,
                    &key,
                    self.slot,
                    false,
                ) {
                    recompiled.tx_usage_counter.fetch_add(
                        program_to_recompile
                            .tx_usage_counter
                            .load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    recompiled.ix_usage_counter.fetch_add(
                        program_to_recompile
                            .ix_usage_counter
                            .load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    let mut program_cache = self.program_cache.write().unwrap();
                    program_cache.assign_program(key, recompiled);
                }
            }
        } else if self.epoch != program_cache.latest_root_epoch
            || slot_index.saturating_add(slots_in_recompilation_phase) >= slots_in_epoch
        {
            // Anticipate the upcoming program runtime environment for the next epoch,
            // so we can try to recompile loaded programs before the feature transition hits.
            drop(program_cache);
            let mut program_cache = self.program_cache.write().unwrap();
            let program_runtime_environment_v1 = create_program_runtime_environment_v1(
                upcoming_feature_set,
                compute_budget,
                false, /* deployment */
                false, /* debugging_features */
            )
            .unwrap();
            let program_runtime_environment_v2 = create_program_runtime_environment_v2(
                compute_budget,
                false, /* debugging_features */
            );
            let mut upcoming_environments = program_cache.environments.clone();
            let changed_program_runtime_v1 =
                *upcoming_environments.program_runtime_v1 != program_runtime_environment_v1;
            let changed_program_runtime_v2 =
                *upcoming_environments.program_runtime_v2 != program_runtime_environment_v2;
            if changed_program_runtime_v1 {
                upcoming_environments.program_runtime_v1 = Arc::new(program_runtime_environment_v1);
            }
            if changed_program_runtime_v2 {
                upcoming_environments.program_runtime_v2 = Arc::new(program_runtime_environment_v2);
            }
            program_cache.upcoming_environments = Some(upcoming_environments);
            program_cache.programs_to_recompile = program_cache
                .get_flattened_entries(changed_program_runtime_v1, changed_program_runtime_v2);
            program_cache
                .programs_to_recompile
                .sort_by_cached_key(|(_id, program)| program.decayed_usage_counter(self.slot));
        }
    }

    /// Execute a transaction using the provided loaded accounts and update
    /// the executors cache if the transaction was successful.
    #[allow(clippy::too_many_arguments)]
    fn execute_loaded_transaction(
        &self,
        tx: &SanitizedTransaction,
        loaded_transaction: &mut LoadedTransaction,
        execute_timings: &mut ExecuteTimings,
        error_metrics: &mut TransactionErrorMetrics,
        program_cache_for_tx_batch: &mut ProgramCacheForTxBatch,
        environment: &TransactionProcessingEnvironment,
        config: &TransactionProcessingConfig,
    ) -> TransactionExecutionResult {
        let transaction_accounts = std::mem::take(&mut loaded_transaction.accounts);

        fn transaction_accounts_lamports_sum(
            accounts: &[(Pubkey, AccountSharedData)],
            message: &SanitizedMessage,
        ) -> Option<u128> {
            let mut lamports_sum = 0u128;
            for i in 0..message.account_keys().len() {
                let (_, account) = accounts.get(i)?;
                lamports_sum = lamports_sum.checked_add(u128::from(account.lamports()))?;
            }
            Some(lamports_sum)
        }

        let rent = environment
            .rent_collector
            .map(|rent_collector| rent_collector.rent.clone())
            .unwrap_or_default();

        let lamports_before_tx =
            transaction_accounts_lamports_sum(&transaction_accounts, tx.message()).unwrap_or(0);

        let compute_budget = config
            .compute_budget
            .unwrap_or_else(|| ComputeBudget::from(loaded_transaction.compute_budget_limits));

        let mut transaction_context = TransactionContext::new(
            transaction_accounts,
            rent.clone(),
            compute_budget.max_instruction_stack_depth,
            compute_budget.max_instruction_trace_length,
        );
        #[cfg(debug_assertions)]
        transaction_context.set_signature(tx.signature());

        let pre_account_state_info =
            TransactionAccountStateInfo::new(&rent, &transaction_context, tx.message());

        let log_collector = if config.recording_config.enable_log_recording {
            match config.log_messages_bytes_limit {
                None => Some(LogCollector::new_ref()),
                Some(log_messages_bytes_limit) => Some(LogCollector::new_ref_with_limit(Some(
                    log_messages_bytes_limit,
                ))),
            }
        } else {
            None
        };

        let blockhash = environment.blockhash;
        let lamports_per_signature = environment.lamports_per_signature;

        let mut executed_units = 0u64;
        let sysvar_cache = &self.sysvar_cache.read().unwrap();

        let mut invoke_context = InvokeContext::new(
            &mut transaction_context,
            program_cache_for_tx_batch,
            EnvironmentConfig::new(
                blockhash,
                environment.epoch_total_stake,
                environment.epoch_vote_accounts,
                Arc::clone(&environment.feature_set),
                lamports_per_signature,
                sysvar_cache,
            ),
            log_collector.clone(),
            compute_budget,
        );

        let mut process_message_time = Measure::start("process_message_time");
        let process_result = MessageProcessor::process_message(
            tx.message(),
            &loaded_transaction.program_indices,
            &mut invoke_context,
            execute_timings,
            &mut executed_units,
        );
        process_message_time.stop();

        drop(invoke_context);

        saturating_add_assign!(
            execute_timings.execute_accessories.process_message_us,
            process_message_time.as_us()
        );

        let mut status = process_result
            .and_then(|info| {
                let post_account_state_info =
                    TransactionAccountStateInfo::new(&rent, &transaction_context, tx.message());
                TransactionAccountStateInfo::verify_changes(
                    &pre_account_state_info,
                    &post_account_state_info,
                    &transaction_context,
                )
                .map(|_| info)
            })
            .map_err(|err| {
                match err {
                    TransactionError::InvalidRentPayingAccount
                    | TransactionError::InsufficientFundsForRent { .. } => {
                        error_metrics.invalid_rent_paying_account += 1;
                    }
                    TransactionError::InvalidAccountIndex => {
                        error_metrics.invalid_account_index += 1;
                    }
                    _ => {
                        error_metrics.instruction_error += 1;
                    }
                }
                err
            });

        let log_messages: Option<TransactionLogMessages> =
            log_collector.and_then(|log_collector| {
                Rc::try_unwrap(log_collector)
                    .map(|log_collector| log_collector.into_inner().into_messages())
                    .ok()
            });

        let inner_instructions = if config.recording_config.enable_cpi_recording {
            Some(Self::inner_instructions_list_from_instruction_trace(
                &transaction_context,
            ))
        } else {
            None
        };

        let ExecutionRecord {
            accounts,
            return_data,
            touched_account_count,
            accounts_resize_delta: accounts_data_len_delta,
        } = transaction_context.into();

        if status.is_ok()
            && transaction_accounts_lamports_sum(&accounts, tx.message())
                .filter(|lamports_after_tx| lamports_before_tx == *lamports_after_tx)
                .is_none()
        {
            status = Err(TransactionError::UnbalancedTransaction);
        }
        let status = status.map(|_| ());

        loaded_transaction.accounts = accounts;
        saturating_add_assign!(
            execute_timings.execute_accounts_details.total_account_count,
            loaded_transaction.accounts.len() as u64
        );
        saturating_add_assign!(
            execute_timings
                .execute_accounts_details
                .changed_account_count,
            touched_account_count
        );

        let return_data = if config.recording_config.enable_return_data_recording
            && !return_data.data.is_empty()
        {
            Some(return_data)
        } else {
            None
        };

        TransactionExecutionResult::Executed {
            details: TransactionExecutionDetails {
                status,
                log_messages,
                inner_instructions,
                fee_details: loaded_transaction.fee_details,
                return_data,
                executed_units,
                accounts_data_len_delta,
            },
            programs_modified_by_tx: program_cache_for_tx_batch.drain_modified_entries(),
        }
    }

    /// Extract the InnerInstructionsList from a TransactionContext
    fn inner_instructions_list_from_instruction_trace(
        transaction_context: &TransactionContext,
    ) -> InnerInstructionsList {
        debug_assert!(transaction_context
            .get_instruction_context_at_index_in_trace(0)
            .map(|instruction_context| instruction_context.get_stack_height()
                == TRANSACTION_LEVEL_STACK_HEIGHT)
            .unwrap_or(true));
        let mut outer_instructions = Vec::new();
        for index_in_trace in 0..transaction_context.get_instruction_trace_length() {
            if let Ok(instruction_context) =
                transaction_context.get_instruction_context_at_index_in_trace(index_in_trace)
            {
                let stack_height = instruction_context.get_stack_height();
                if stack_height == TRANSACTION_LEVEL_STACK_HEIGHT {
                    outer_instructions.push(Vec::new());
                } else if let Some(inner_instructions) = outer_instructions.last_mut() {
                    let stack_height = u8::try_from(stack_height).unwrap_or(u8::MAX);
                    let instruction = CompiledInstruction::new_from_raw_parts(
                        instruction_context
                            .get_index_of_program_account_in_transaction(
                                instruction_context
                                    .get_number_of_program_accounts()
                                    .saturating_sub(1),
                            )
                            .unwrap_or_default() as u8,
                        instruction_context.get_instruction_data().to_vec(),
                        (0..instruction_context.get_number_of_instruction_accounts())
                            .map(|instruction_account_index| {
                                instruction_context
                                    .get_index_of_instruction_account_in_transaction(
                                        instruction_account_index,
                                    )
                                    .unwrap_or_default() as u8
                            })
                            .collect(),
                    );
                    inner_instructions.push(InnerInstruction {
                        instruction,
                        stack_height,
                    });
                } else {
                    debug_assert!(false);
                }
            } else {
                debug_assert!(false);
            }
        }
        outer_instructions
    }

    pub fn fill_missing_sysvar_cache_entries<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
    ) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        sysvar_cache.fill_missing_entries(|pubkey, set_sysvar| {
            if let Some(account) = callbacks.get_account_shared_data(pubkey) {
                set_sysvar(account.data());
            }
        });
    }

    pub fn reset_sysvar_cache(&self) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        sysvar_cache.reset();
    }

    pub fn get_sysvar_cache_for_tests(&self) -> SysvarCache {
        self.sysvar_cache.read().unwrap().clone()
    }

    /// Add a built-in program
    pub fn add_builtin<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
        program_id: Pubkey,
        name: &str,
        builtin: ProgramCacheEntry,
    ) {
        debug!("Adding program {} under {:?}", name, program_id);
        callbacks.add_builtin_account(name, &program_id);
        self.builtin_program_ids.write().unwrap().insert(program_id);
        self.program_cache
            .write()
            .unwrap()
            .assign_program(program_id, Arc::new(builtin));
        debug!("Added program {} under {:?}", name, program_id);
    }
}
