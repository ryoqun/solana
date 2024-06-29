use {
    crate::{
        block_error::BlockError,
        blockstore::Blockstore,
        blockstore_db::BlockstoreError,
        blockstore_meta::SlotMeta,
        entry_notifier_service::{EntryNotification, EntryNotifierSender},
        leader_schedule_cache::LeaderScheduleCache,
        token_balances::collect_token_balances,
        use_snapshot_archives_at_startup::UseSnapshotArchivesAtStartup,
    },
    chrono_humanize::{Accuracy, HumanTime, Tense},
    crossbeam_channel::Sender,
    itertools::Itertools,
    log::*,
    rayon::{prelude::*, ThreadPool},
    scopeguard::defer,
    solana_accounts_db::{
        accounts_db::{AccountShrinkThreshold, AccountsDbConfig},
        accounts_index::AccountSecondaryIndexes,
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        epoch_accounts_hash::EpochAccountsHash,
    },
    solana_cost_model::cost_model::CostModel,
    solana_entry::entry::{
        self, create_ticks, Entry, EntrySlice, EntryType, EntryVerificationStatus, VerifyRecyclers,
    },
    solana_measure::{measure, measure::Measure},
    solana_metrics::datapoint_error,
    solana_program_runtime::{
        report_execute_timings,
        timings::{ExecuteTimingType, ExecuteTimings},
    },
    solana_rayon_threadlimit::{get_max_thread_count, get_thread_count},
    solana_runtime::{
        accounts_background_service::{AbsRequestSender, SnapshotRequestKind},
        bank::{Bank, TransactionBalancesSet},
        bank_forks::{BankForks, SetRootError},
        bank_utils,
        commitment::VOTE_THRESHOLD_SIZE,
        installed_scheduler_pool::BankWithScheduler,
        prioritization_fee_cache::PrioritizationFeeCache,
        runtime_config::RuntimeConfig,
        transaction_batch::TransactionBatch,
        vote_sender_types::ReplayVoteSender,
    },
    solana_sdk::{
        clock::{Slot, MAX_PROCESSING_AGE},
        feature_set,
        genesis_config::GenesisConfig,
        hash::Hash,
        pubkey::Pubkey,
        rent_debits::RentDebits,
        saturating_add_assign,
        signature::{Keypair, Signature},
        timing,
        transaction::{
            Result, SanitizedTransaction, TransactionError, TransactionVerificationMode,
            VersionedTransaction,
        },
    },
    solana_svm::{
        transaction_processor::ExecutionRecordingConfig,
        transaction_results::{
            TransactionExecutionDetails, TransactionExecutionResult,
            TransactionLoadedAccountsStats, TransactionResults,
        },
    },
    solana_transaction_status::token_balances::TransactionTokenBalancesSet,
    solana_vote::vote_account::VoteAccountsHashMap,
    std::{
        borrow::Cow,
        collections::{HashMap, HashSet},
        ops::Index,
        path::PathBuf,
        result,
        sync::{
            atomic::{AtomicBool, Ordering::Relaxed},
            Arc, Mutex, RwLock,
        },
        time::{Duration, Instant},
    },
    thiserror::Error,
    ExecuteTimingType::{NumExecuteBatches, TotalBatchesLen},
};

pub struct TransactionBatchWithIndexes<'a, 'b> {
    pub batch: TransactionBatch<'a, 'b>,
    pub transaction_indexes: Vec<usize>,
}

struct ReplayEntry {
    entry: EntryType,
    starting_index: usize,
}

fn first_err(results: &[Result<()>]) -> Result<()> {
    for r in results {
        if r.is_err() {
            return r.clone();
        }
    }
    Ok(())
}

// Includes transaction signature for unit-testing
fn get_first_error(
    batch: &TransactionBatch,
    fee_collection_results: Vec<Result<()>>,
) -> Option<(Result<()>, Signature)> {
    let mut first_err = None;
    for (result, transaction) in fee_collection_results
        .iter()
        .zip(batch.sanitized_transactions())
    {
        if let Err(ref err) = result {
            if first_err.is_none() {
                first_err = Some((result.clone(), *transaction.signature()));
            }
            warn!(
                "Unexpected validator error: {:?}, transaction: {:?}",
                err, transaction
            );
            datapoint_error!(
                "validator_process_entry_error",
                (
                    "error",
                    format!("error: {err:?}, transaction: {transaction:?}"),
                    String
                )
            );
        }
    }
    first_err
}

fn create_thread_pool(num_threads: usize) -> ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .thread_name(|i| format!("solReplayTx{i:02}"))
        .build()
        .expect("new rayon threadpool")
}

pub fn execute_batch(
    batch: &TransactionBatchWithIndexes,
    bank: &Arc<Bank>,
    transaction_status_sender: Option<&TransactionStatusSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    timings: &mut ExecuteTimings,
    log_messages_bytes_limit: Option<usize>,
    prioritization_fee_cache: &PrioritizationFeeCache,
    pre_commit_callback: impl FnOnce(),
) -> Result<()> {
    let TransactionBatchWithIndexes {
        batch,
        transaction_indexes,
    } = batch;
    let record_token_balances = transaction_status_sender.is_some();

    let mut mint_decimals: HashMap<Pubkey, u8> = HashMap::new();

    let pre_token_balances = if record_token_balances {
        collect_token_balances(bank, batch, &mut mint_decimals)
    } else {
        vec![]
    };

    let (tx_results, balances) = batch.bank().load_execute_and_commit_transactions(
        batch,
        MAX_PROCESSING_AGE,
        transaction_status_sender.is_some(),
        ExecutionRecordingConfig::new_single_setting(transaction_status_sender.is_some()),
        timings,
        log_messages_bytes_limit,
        pre_commit_callback,
    );

    bank_utils::find_and_send_votes(
        batch.sanitized_transactions(),
        &tx_results,
        replay_vote_sender,
    );

    let TransactionResults {
        fee_collection_results,
        loaded_accounts_stats,
        execution_results,
        rent_debits,
        ..
    } = tx_results;

    let (check_block_cost_limits_result, check_block_cost_limits_time): (Result<()>, Measure) =
        measure!(if bank
            .feature_set
            .is_active(&feature_set::apply_cost_tracker_during_replay::id())
        {
            check_block_cost_limits(
                bank,
                &loaded_accounts_stats,
                &execution_results,
                batch.sanitized_transactions(),
            )
        } else {
            Ok(())
        });

    timings.saturating_add_in_place(
        ExecuteTimingType::CheckBlockLimitsUs,
        check_block_cost_limits_time.as_us(),
    );
    for tx_loaded_accounts_stats in loaded_accounts_stats.iter().flatten() {
        timings
            .execute_accounts_details
            .increment_loaded_accounts_data_size(
                tx_loaded_accounts_stats.loaded_accounts_data_size as u64,
            );
    }
    check_block_cost_limits_result?;

    let executed_transactions = execution_results
        .iter()
        .zip(batch.sanitized_transactions())
        .filter_map(|(execution_result, tx)| execution_result.was_executed().then_some(tx))
        .collect_vec();

    if let Some(transaction_status_sender) = transaction_status_sender {
        let transactions = batch.sanitized_transactions().to_vec();
        let post_token_balances = if record_token_balances {
            collect_token_balances(bank, batch, &mut mint_decimals)
        } else {
            vec![]
        };

        let token_balances =
            TransactionTokenBalancesSet::new(pre_token_balances, post_token_balances);

        transaction_status_sender.send_transaction_status_batch(
            bank.clone(),
            transactions,
            execution_results,
            balances,
            token_balances,
            rent_debits,
            transaction_indexes.to_vec(),
        );
    }

    prioritization_fee_cache.update(bank, executed_transactions.into_iter());

    let first_err = get_first_error(batch, fee_collection_results);
    first_err.map(|(result, _)| result).unwrap_or(Ok(()))
}

// collect transactions actual execution costs, subject to block limits;
// block will be marked as dead if exceeds cost limits, details will be
// reported to metric `replay-stage-mark_dead_slot`
fn check_block_cost_limits(
    bank: &Bank,
    loaded_accounts_stats: &[Result<TransactionLoadedAccountsStats>],
    execution_results: &[TransactionExecutionResult],
    sanitized_transactions: &[SanitizedTransaction],
) -> Result<()> {
    assert_eq!(loaded_accounts_stats.len(), execution_results.len());

    let tx_costs_with_actual_execution_units: Vec<_> = execution_results
        .iter()
        .zip(loaded_accounts_stats)
        .zip(sanitized_transactions)
        .filter_map(|((execution_result, loaded_accounts_stats), tx)| {
            if let Some(details) = execution_result.details() {
                let tx_cost = CostModel::calculate_cost_for_executed_transaction(
                    tx,
                    details.executed_units,
                    loaded_accounts_stats
                        .as_ref()
                        .map_or(0, |stats| stats.loaded_accounts_data_size),
                    &bank.feature_set,
                );
                Some(tx_cost)
            } else {
                None
            }
        })
        .collect();

    {
        let mut cost_tracker = bank.write_cost_tracker().unwrap();
        for tx_cost in &tx_costs_with_actual_execution_units {
            cost_tracker
                .try_add(tx_cost)
                .map_err(TransactionError::from)?;
        }
    }
    Ok(())
}

#[derive(Default)]
pub struct ExecuteBatchesInternalMetrics {
    execution_timings_per_thread: HashMap<usize, ThreadExecuteTimings>,
    total_batches_len: u64,
    execute_batches_us: u64,
}

impl ExecuteBatchesInternalMetrics {
    pub fn new_with_timings_from_all_threads(execute_timings: ExecuteTimings) -> Self {
        const DUMMY_THREAD_INDEX: usize = 999;
        let mut new = Self::default();
        new.execution_timings_per_thread.insert(
            DUMMY_THREAD_INDEX,
            ThreadExecuteTimings {
                execute_timings,
                ..ThreadExecuteTimings::default()
            },
        );
        new
    }
}

fn execute_batches_internal(
    bank: &Arc<Bank>,
    replay_tx_thread_pool: &ThreadPool,
    batches: &[TransactionBatchWithIndexes],
    transaction_status_sender: Option<&TransactionStatusSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    log_messages_bytes_limit: Option<usize>,
    prioritization_fee_cache: &PrioritizationFeeCache,
) -> Result<ExecuteBatchesInternalMetrics> {
    assert!(!batches.is_empty());
    let execution_timings_per_thread: Mutex<HashMap<usize, ThreadExecuteTimings>> =
        Mutex::new(HashMap::new());

    let mut execute_batches_elapsed = Measure::start("execute_batches_elapsed");
    let results: Vec<Result<()>> = replay_tx_thread_pool.install(|| {
        batches
            .into_par_iter()
            .map(|transaction_batch| {
                let transaction_count =
                    transaction_batch.batch.sanitized_transactions().len() as u64;
                let mut timings = ExecuteTimings::default();
                let (result, execute_batches_time): (Result<()>, Measure) = measure!(
                    {
                        execute_batch(
                            transaction_batch,
                            bank,
                            transaction_status_sender,
                            replay_vote_sender,
                            &mut timings,
                            log_messages_bytes_limit,
                            prioritization_fee_cache,
                            || {},
                        )
                    },
                    "execute_batch",
                );

                let thread_index = replay_tx_thread_pool.current_thread_index().unwrap();
                execution_timings_per_thread
                    .lock()
                    .unwrap()
                    .entry(thread_index)
                    .and_modify(|thread_execution_time| {
                        let ThreadExecuteTimings {
                            total_thread_us,
                            total_transactions_executed,
                            execute_timings: total_thread_execute_timings,
                        } = thread_execution_time;
                        *total_thread_us += execute_batches_time.as_us();
                        *total_transactions_executed += transaction_count;
                        total_thread_execute_timings
                            .saturating_add_in_place(ExecuteTimingType::TotalBatchesLen, 1);
                        total_thread_execute_timings.accumulate(&timings);
                    })
                    .or_insert(ThreadExecuteTimings {
                        total_thread_us: execute_batches_time.as_us(),
                        total_transactions_executed: transaction_count,
                        execute_timings: timings,
                    });
                result
            })
            .collect()
    });
    execute_batches_elapsed.stop();

    first_err(&results)?;

    Ok(ExecuteBatchesInternalMetrics {
        execution_timings_per_thread: execution_timings_per_thread.into_inner().unwrap(),
        total_batches_len: batches.len() as u64,
        execute_batches_us: execute_batches_elapsed.as_us(),
    })
}

// This fn diverts the code-path into two variants. Both must provide exactly the same set of
// validations. For this reason, this fn is deliberately inserted into the code path to be called
// inside process_entries(), so that Bank::prepare_sanitized_batch() has been called on all of
// batches already, while minimizing code duplication (thus divergent behavior risk) at the cost of
// acceptable overhead of meaningless buffering of batches for the scheduler variant.
//
// Also note that the scheduler variant can't implement the batch-level sanitization naively, due
// to the nature of individual tx processing. That's another reason of this particular placement of
// divergent point in the code-path (i.e. not one layer up with its own prepare_sanitized_batch()
// invocation).
fn process_batches(
    bank: &BankWithScheduler,
    replay_tx_thread_pool: &ThreadPool,
    batches: &[TransactionBatchWithIndexes],
    transaction_status_sender: Option<&TransactionStatusSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    batch_execution_timing: &mut BatchExecutionTiming,
    log_messages_bytes_limit: Option<usize>,
    prioritization_fee_cache: &PrioritizationFeeCache,
) -> Result<()> {
    if bank.has_installed_scheduler() {
        debug!(
            "process_batches()/schedule_batches_for_execution({} batches)",
            batches.len()
        );
        // Scheduling usually succeeds (immediately returns `Ok(())`) here without being blocked on
        // the actual transaction executions.
        //
        // As an exception, this code path could propagate the transaction execution _errors of
        // previously-scheduled transactions_ to notify the replay stage. Then, the replay stage
        // will bail out the further processing of the malformed (possibly malicious) block
        // immediately, not to waste any system resources. Note that this propagation is of early
        // hints. Even if errors won't be propagated in this way, they are guaranteed to be
        // propagated eventually via the blocking fn called
        // BankWithScheduler::wait_for_completed_scheduler().
        //
        // To recite, the returned error is completely unrelated to the argument's `batches` at the
        // hand. While being awkward, the _async_ unified scheduler is abusing this existing error
        // propagation code path to the replay stage for compatibility and ease of integration,
        // exploiting the fact that the replay stage doesn't care _which transaction the returned
        // error is originating from_.
        //
        // In the future, more proper error propagation mechanism will be introduced once after we
        // fully transition to the unified scheduler for the block verification. That one would be
        // a push based one from the unified scheduler to the replay stage to eliminate the current
        // overhead: 1 read lock per batch in
        // `BankWithScheduler::schedule_transaction_executions()`.
        schedule_batches_for_execution(bank, batches)
    } else {
        debug!(
            "process_batches()/rebatch_and_execute_batches({} batches)",
            batches.len()
        );
        rebatch_and_execute_batches(
            bank,
            replay_tx_thread_pool,
            batches,
            transaction_status_sender,
            replay_vote_sender,
            batch_execution_timing,
            log_messages_bytes_limit,
            prioritization_fee_cache,
        )
    }
}

fn schedule_batches_for_execution(
    bank: &BankWithScheduler,
    batches: &[TransactionBatchWithIndexes],
) -> Result<()> {
    for TransactionBatchWithIndexes {
        batch,
        transaction_indexes,
    } in batches
    {
        bank.schedule_transaction_executions(
            batch
                .sanitized_transactions()
                .iter()
                .zip(transaction_indexes.iter()),
        )?;
    }
    Ok(())
}

fn rebatch_transactions<'a>(
    lock_results: &'a [Result<()>],
    bank: &'a Arc<Bank>,
    sanitized_txs: &'a [SanitizedTransaction],
    start: usize,
    end: usize,
    transaction_indexes: &'a [usize],
) -> TransactionBatchWithIndexes<'a, 'a> {
    let txs = &sanitized_txs[start..=end];
    let results = &lock_results[start..=end];
    let mut tx_batch = TransactionBatch::new(results.to_vec(), bank, Cow::from(txs));
    tx_batch.set_needs_unlock(false);

    let transaction_indexes = transaction_indexes[start..=end].to_vec();
    TransactionBatchWithIndexes {
        batch: tx_batch,
        transaction_indexes,
    }
}

fn rebatch_and_execute_batches(
    bank: &Arc<Bank>,
    replay_tx_thread_pool: &ThreadPool,
    batches: &[TransactionBatchWithIndexes],
    transaction_status_sender: Option<&TransactionStatusSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    timing: &mut BatchExecutionTiming,
    log_messages_bytes_limit: Option<usize>,
    prioritization_fee_cache: &PrioritizationFeeCache,
) -> Result<()> {
    if batches.is_empty() {
        return Ok(());
    }

    let ((lock_results, sanitized_txs), transaction_indexes): ((Vec<_>, Vec<_>), Vec<_>) = batches
        .iter()
        .flat_map(|batch| {
            batch
                .batch
                .lock_results()
                .iter()
                .cloned()
                .zip(batch.batch.sanitized_transactions().to_vec())
                .zip(batch.transaction_indexes.to_vec())
        })
        .unzip();

    let mut minimal_tx_cost = u64::MAX;
    let mut total_cost: u64 = 0;
    let tx_costs = sanitized_txs
        .iter()
        .map(|tx| {
            let tx_cost = CostModel::calculate_cost(tx, &bank.feature_set);
            let cost = tx_cost.sum();
            minimal_tx_cost = std::cmp::min(minimal_tx_cost, cost);
            total_cost = total_cost.saturating_add(cost);
            cost
        })
        .collect::<Vec<_>>();

    let target_batch_count = get_thread_count() as u64;

    let mut tx_batches: Vec<TransactionBatchWithIndexes> = vec![];
    let rebatched_txs = if total_cost > target_batch_count.saturating_mul(minimal_tx_cost) {
        let target_batch_cost = total_cost / target_batch_count;
        let mut batch_cost: u64 = 0;
        let mut slice_start = 0;
        tx_costs.into_iter().enumerate().for_each(|(index, cost)| {
            let next_index = index + 1;
            batch_cost = batch_cost.saturating_add(cost);
            if batch_cost >= target_batch_cost || next_index == sanitized_txs.len() {
                let tx_batch = rebatch_transactions(
                    &lock_results,
                    bank,
                    &sanitized_txs,
                    slice_start,
                    index,
                    &transaction_indexes,
                );
                slice_start = next_index;
                tx_batches.push(tx_batch);
                batch_cost = 0;
            }
        });
        &tx_batches[..]
    } else {
        batches
    };

    let execute_batches_internal_metrics = execute_batches_internal(
        bank,
        replay_tx_thread_pool,
        rebatched_txs,
        transaction_status_sender,
        replay_vote_sender,
        log_messages_bytes_limit,
        prioritization_fee_cache,
    )?;

    // Pass false because this code-path is never touched by unified scheduler.
    timing.accumulate(execute_batches_internal_metrics, false);
    Ok(())
}

/// Process an ordered list of entries in parallel
/// 1. In order lock accounts for each entry while the lock succeeds, up to a Tick entry
/// 2. Process the locked group in parallel
/// 3. Register the `Tick` if it's available
/// 4. Update the leader scheduler, goto 1
///
/// This method is for use testing against a single Bank, and assumes `Bank::transaction_count()`
/// represents the number of transactions executed in this Bank
pub fn process_entries_for_tests(
    bank: &BankWithScheduler,
    entries: Vec<Entry>,
    transaction_status_sender: Option<&TransactionStatusSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
) -> Result<()> {
    let replay_tx_thread_pool = create_thread_pool(1);
    let verify_transaction = {
        let bank = bank.clone_with_scheduler();
        move |versioned_tx: VersionedTransaction| -> Result<SanitizedTransaction> {
            bank.verify_transaction(versioned_tx, TransactionVerificationMode::FullVerification)
        }
    };

    let mut entry_starting_index: usize = bank.transaction_count().try_into().unwrap();
    let mut batch_timing = BatchExecutionTiming::default();
    let mut replay_entries: Vec<_> = entry::verify_transactions(
        entries,
        &replay_tx_thread_pool,
        Arc::new(verify_transaction),
    )?
    .into_iter()
    .map(|entry| {
        let starting_index = entry_starting_index;
        if let EntryType::Transactions(ref transactions) = entry {
            entry_starting_index = entry_starting_index.saturating_add(transactions.len());
        }
        ReplayEntry {
            entry,
            starting_index,
        }
    })
    .collect();

    let ignored_prioritization_fee_cache = PrioritizationFeeCache::new(0u64);
    let result = process_entries(
        bank,
        &replay_tx_thread_pool,
        &mut replay_entries,
        transaction_status_sender,
        replay_vote_sender,
        &mut batch_timing,
        None,
        &ignored_prioritization_fee_cache,
    );

    debug!("process_entries: {:?}", batch_timing);
    result
}

fn process_entries(
    bank: &BankWithScheduler,
    replay_tx_thread_pool: &ThreadPool,
    entries: &mut [ReplayEntry],
    transaction_status_sender: Option<&TransactionStatusSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    batch_timing: &mut BatchExecutionTiming,
    log_messages_bytes_limit: Option<usize>,
    prioritization_fee_cache: &PrioritizationFeeCache,
) -> Result<()> {
    // accumulator for entries that can be processed in parallel
    let mut batches = vec![];
    let mut tick_hashes = vec![];

    for ReplayEntry {
        entry,
        starting_index,
    } in entries
    {
        match entry {
            EntryType::Tick(hash) => {
                // If it's a tick, save it for later
                tick_hashes.push(hash);
                if bank.is_block_boundary(bank.tick_height() + tick_hashes.len() as u64) {
                    // If it's a tick that will cause a new blockhash to be created,
                    // execute the group and register the tick
                    process_batches(
                        bank,
                        replay_tx_thread_pool,
                        &batches,
                        transaction_status_sender,
                        replay_vote_sender,
                        batch_timing,
                        log_messages_bytes_limit,
                        prioritization_fee_cache,
                    )?;
                    batches.clear();
                    for hash in &tick_hashes {
                        bank.register_tick(hash);
                    }
                    tick_hashes.clear();
                }
            }
            EntryType::Transactions(transactions) => {
                let starting_index = *starting_index;
                let transaction_indexes =
                    (starting_index..starting_index.saturating_add(transactions.len())).collect();
                loop {
                    // try to lock the accounts
                    let batch = bank.prepare_sanitized_batch(transactions);
                    let first_lock_err = first_err(batch.lock_results());

                    // if locking worked
                    if first_lock_err.is_ok() {
                        batches.push(TransactionBatchWithIndexes {
                            batch,
                            transaction_indexes,
                        });
                        // done with this entry
                        break;
                    }
                    // else we failed to lock, 2 possible reasons
                    if batches.is_empty() {
                        // An entry has account lock conflicts with *itself*, which should not happen
                        // if generated by a properly functioning leader
                        datapoint_error!(
                            "validator_process_entry_error",
                            (
                                "error",
                                format!(
                                    "Lock accounts error, entry conflicts with itself, txs: \
                                     {transactions:?}"
                                ),
                                String
                            )
                        );
                        // bail
                        first_lock_err?;
                    } else {
                        // else we have an entry that conflicts with a prior entry
                        // execute the current queue and try to process this entry again
                        process_batches(
                            bank,
                            replay_tx_thread_pool,
                            &batches,
                            transaction_status_sender,
                            replay_vote_sender,
                            batch_timing,
                            log_messages_bytes_limit,
                            prioritization_fee_cache,
                        )?;
                        batches.clear();
                    }
                }
            }
        }
    }
    process_batches(
        bank,
        replay_tx_thread_pool,
        &batches,
        transaction_status_sender,
        replay_vote_sender,
        batch_timing,
        log_messages_bytes_limit,
        prioritization_fee_cache,
    )?;
    for hash in tick_hashes {
        bank.register_tick(hash);
    }
    Ok(())
}

#[derive(Error, Debug)]
pub enum BlockstoreProcessorError {
    #[error("failed to load entries, error: {0}")]
    FailedToLoadEntries(#[from] BlockstoreError),

    #[error("failed to load meta")]
    FailedToLoadMeta,

    #[error("invalid block error: {0}")]
    InvalidBlock(#[from] BlockError),

    #[error("invalid transaction error: {0}")]
    InvalidTransaction(#[from] TransactionError),

    #[error("no valid forks found")]
    NoValidForksFound,

    #[error("invalid hard fork slot {0}")]
    InvalidHardFork(Slot),

    #[error("root bank with mismatched capitalization at {0}")]
    RootBankWithMismatchedCapitalization(Slot),

    #[error("set root error {0}")]
    SetRootError(#[from] SetRootError),

    #[error("incomplete final fec set")]
    IncompleteFinalFecSet,
}

/// Callback for accessing bank state after each slot is confirmed while
/// processing the blockstore
pub type ProcessSlotCallback = Arc<dyn Fn(&Bank) + Sync + Send>;

#[derive(Default, Clone)]
pub struct ProcessOptions {
    /// Run PoH, transaction signature and other transaction verifications on the entries.
    pub run_verification: bool,
    pub full_leader_cache: bool,
    pub halt_at_slot: Option<Slot>,
    pub slot_callback: Option<ProcessSlotCallback>,
    pub new_hard_forks: Option<Vec<Slot>>,
    pub debug_keys: Option<Arc<HashSet<Pubkey>>>,
    pub account_indexes: AccountSecondaryIndexes,
    pub limit_load_slot_count_from_snapshot: Option<usize>,
    pub allow_dead_slots: bool,
    pub accounts_db_test_hash_calculation: bool,
    pub accounts_db_skip_shrink: bool,
    pub accounts_db_force_initial_clean: bool,
    pub accounts_db_config: Option<AccountsDbConfig>,
    pub verify_index: bool,
    pub shrink_ratio: AccountShrinkThreshold,
    pub runtime_config: RuntimeConfig,
    pub on_halt_store_hash_raw_data_for_debug: bool,
    /// true if after processing the contents of the blockstore at startup, we should run an accounts hash calc
    /// This is useful for debugging.
    pub run_final_accounts_hash_calc: bool,
    pub use_snapshot_archives_at_startup: UseSnapshotArchivesAtStartup,
}

pub fn test_process_blockstore(
    genesis_config: &GenesisConfig,
    blockstore: &Blockstore,
    opts: &ProcessOptions,
    exit: Arc<AtomicBool>,
) -> (Arc<RwLock<BankForks>>, LeaderScheduleCache) {
    // Spin up a thread to be a fake Accounts Background Service.  Need to intercept and handle all
    // EpochAccountsHash requests so future rooted banks do not hang in Bank::freeze() waiting for
    // an in-flight EAH calculation to complete.
    let (snapshot_request_sender, snapshot_request_receiver) = crossbeam_channel::unbounded();
    let abs_request_sender = AbsRequestSender::new(snapshot_request_sender);
    let bg_exit = Arc::new(AtomicBool::new(false));
    let bg_thread = {
        let exit = Arc::clone(&bg_exit);
        std::thread::spawn(move || {
            while !exit.load(Relaxed) {
                snapshot_request_receiver
                    .try_iter()
                    .filter(|snapshot_request| {
                        snapshot_request.request_kind == SnapshotRequestKind::EpochAccountsHash
                    })
                    .for_each(|snapshot_request| {
                        snapshot_request
                            .snapshot_root_bank
                            .rc
                            .accounts
                            .accounts_db
                            .epoch_accounts_hash_manager
                            .set_valid(
                                EpochAccountsHash::new(Hash::new_unique()),
                                snapshot_request.snapshot_root_bank.slot(),
                            )
                    });
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };

    let (bank_forks, leader_schedule_cache, ..) = crate::bank_forks_utils::load_bank_forks(
        genesis_config,
        blockstore,
        Vec::new(),
        None,
        opts,
        None,
        None,
        None,
        exit,
    )
    .unwrap();

    process_blockstore_from_root(
        blockstore,
        &bank_forks,
        &leader_schedule_cache,
        opts,
        None,
        None,
        None,
        &abs_request_sender,
    )
    .unwrap();

    bg_exit.store(true, Relaxed);
    bg_thread.join().unwrap();

    (bank_forks, leader_schedule_cache)
}

pub(crate) fn process_blockstore_for_bank_0(
    genesis_config: &GenesisConfig,
    blockstore: &Blockstore,
    account_paths: Vec<PathBuf>,
    opts: &ProcessOptions,
    cache_block_meta_sender: Option<&CacheBlockMetaSender>,
    entry_notification_sender: Option<&EntryNotifierSender>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> Arc<RwLock<BankForks>> {
    // Setup bank for slot 0
    let bank0 = Bank::new_with_paths(
        genesis_config,
        Arc::new(opts.runtime_config.clone()),
        account_paths,
        opts.debug_keys.clone(),
        None,
        opts.account_indexes.clone(),
        opts.shrink_ratio,
        false,
        opts.accounts_db_config.clone(),
        accounts_update_notifier,
        None,
        exit,
        None,
    );
    let bank0_slot = bank0.slot();
    let bank_forks = BankForks::new_rw_arc(bank0);

    info!("Processing ledger for slot 0...");
    let replay_tx_thread_pool = create_thread_pool(get_max_thread_count());
    process_bank_0(
        &bank_forks
            .read()
            .unwrap()
            .get_with_scheduler(bank0_slot)
            .unwrap(),
        blockstore,
        &replay_tx_thread_pool,
        opts,
        &VerifyRecyclers::default(),
        cache_block_meta_sender,
        entry_notification_sender,
    );
    bank_forks
}

/// Process blockstore from a known root bank
#[allow(clippy::too_many_arguments)]
pub fn process_blockstore_from_root(
    blockstore: &Blockstore,
    bank_forks: &RwLock<BankForks>,
    leader_schedule_cache: &LeaderScheduleCache,
    opts: &ProcessOptions,
    transaction_status_sender: Option<&TransactionStatusSender>,
    cache_block_meta_sender: Option<&CacheBlockMetaSender>,
    entry_notification_sender: Option<&EntryNotifierSender>,
    accounts_background_request_sender: &AbsRequestSender,
) -> result::Result<(), BlockstoreProcessorError> {
    let (start_slot, start_slot_hash) = {
        // Starting slot must be a root, and thus has no parents
        assert_eq!(bank_forks.read().unwrap().banks().len(), 1);
        let bank = bank_forks.read().unwrap().root_bank();
        assert!(bank.parent().is_none());
        (bank.slot(), bank.hash())
    };

    info!("Processing ledger from slot {}...", start_slot);
    let now = Instant::now();

    // Ensure start_slot is rooted for correct replay; also ensure start_slot and
    // qualifying children are marked as connected
    if blockstore.is_primary_access() {
        blockstore
            .mark_slots_as_if_rooted_normally_at_startup(
                vec![(start_slot, Some(start_slot_hash))],
                true,
            )
            .expect("Couldn't mark start_slot as root in startup");
        blockstore
            .set_and_chain_connected_on_root_and_next_slots(start_slot)
            .expect("Couldn't mark start_slot as connected during startup")
    } else {
        info!(
            "Start slot {} isn't a root, and won't be updated due to secondary blockstore access",
            start_slot
        );
    }

    if let Ok(Some(highest_slot)) = blockstore.highest_slot() {
        info!("ledger holds data through slot {}", highest_slot);
    }

    let mut timing = ExecuteTimings::default();
    let (num_slots_processed, num_new_roots_found) = if let Some(start_slot_meta) = blockstore
        .meta(start_slot)
        .unwrap_or_else(|_| panic!("Failed to get meta for slot {start_slot}"))
    {
        let replay_tx_thread_pool = create_thread_pool(get_max_thread_count());
        load_frozen_forks(
            bank_forks,
            &start_slot_meta,
            blockstore,
            &replay_tx_thread_pool,
            leader_schedule_cache,
            opts,
            transaction_status_sender,
            cache_block_meta_sender,
            entry_notification_sender,
            &mut timing,
            accounts_background_request_sender,
        )?
    } else {
        // If there's no meta in the blockstore for the input `start_slot`,
        // then we started from a snapshot and are unable to process anything.
        //
        // If the ledger has any data at all, the snapshot was likely taken at
        // a slot that is not within the range of ledger min/max slot(s).
        warn!(
            "Starting slot {} is not in Blockstore, unable to process",
            start_slot
        );
        (0, 0)
    };

    let processing_time = now.elapsed();

    datapoint_info!(
        "process_blockstore_from_root",
        ("total_time_us", processing_time.as_micros(), i64),
        (
            "frozen_banks",
            bank_forks.read().unwrap().frozen_banks().len(),
            i64
        ),
        ("slot", bank_forks.read().unwrap().root(), i64),
        ("num_slots_processed", num_slots_processed, i64),
        ("num_new_roots_found", num_new_roots_found, i64),
        ("forks", bank_forks.read().unwrap().banks().len(), i64),
    );

    info!("ledger processing timing: {:?}", timing);
    {
        let bank_forks = bank_forks.read().unwrap();
        let mut bank_slots = bank_forks.banks().keys().copied().collect::<Vec<_>>();
        bank_slots.sort_unstable();

        info!(
            "ledger processed in {}. root slot is {}, {} bank{}: {}",
            HumanTime::from(chrono::Duration::from_std(processing_time).unwrap())
                .to_text_en(Accuracy::Precise, Tense::Present),
            bank_forks.root(),
            bank_slots.len(),
            if bank_slots.len() > 1 { "s" } else { "" },
            bank_slots.iter().map(|slot| slot.to_string()).join(", "),
        );
        assert!(bank_forks.active_bank_slots().is_empty());
    }

    Ok(())
}

/// Verify that a segment of entries has the correct number of ticks and hashes
fn verify_ticks(
    bank: &Bank,
    entries: &[Entry],
    slot_full: bool,
    tick_hash_count: &mut u64,
) -> std::result::Result<(), BlockError> {
    let next_bank_tick_height = bank.tick_height() + entries.tick_count();
    let max_bank_tick_height = bank.max_tick_height();

    if next_bank_tick_height > max_bank_tick_height {
        warn!("Too many entry ticks found in slot: {}", bank.slot());
        return Err(BlockError::TooManyTicks);
    }

    if next_bank_tick_height < max_bank_tick_height && slot_full {
        info!("Too few entry ticks found in slot: {}", bank.slot());
        return Err(BlockError::TooFewTicks);
    }

    if next_bank_tick_height == max_bank_tick_height {
        let has_trailing_entry = entries.last().map(|e| !e.is_tick()).unwrap_or_default();
        if has_trailing_entry {
            warn!("Slot: {} did not end with a tick entry", bank.slot());
            return Err(BlockError::TrailingEntry);
        }

        if !slot_full {
            warn!("Slot: {} was not marked full", bank.slot());
            return Err(BlockError::InvalidLastTick);
        }
    }

    let hashes_per_tick = bank.hashes_per_tick().unwrap_or(0);
    if !entries.verify_tick_hash_count(tick_hash_count, hashes_per_tick) {
        warn!(
            "Tick with invalid number of hashes found in slot: {}",
            bank.slot()
        );
        return Err(BlockError::InvalidTickHashCount);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn confirm_full_slot(
    blockstore: &Blockstore,
    bank: &BankWithScheduler,
    replay_tx_thread_pool: &ThreadPool,
    opts: &ProcessOptions,
    recyclers: &VerifyRecyclers,
    progress: &mut ConfirmationProgress,
    transaction_status_sender: Option<&TransactionStatusSender>,
    entry_notification_sender: Option<&EntryNotifierSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    timing: &mut ExecuteTimings,
) -> result::Result<(), BlockstoreProcessorError> {
    let mut confirmation_timing = ConfirmationTiming::default();
    let skip_verification = !opts.run_verification;
    let ignored_prioritization_fee_cache = PrioritizationFeeCache::new(0u64);

    confirm_slot(
        blockstore,
        bank,
        replay_tx_thread_pool,
        &mut confirmation_timing,
        progress,
        skip_verification,
        transaction_status_sender,
        entry_notification_sender,
        replay_vote_sender,
        recyclers,
        opts.allow_dead_slots,
        opts.runtime_config.log_messages_bytes_limit,
        &ignored_prioritization_fee_cache,
    )?;

    timing.accumulate(&confirmation_timing.batch_execute.totals);

    if !bank.is_complete() {
        Err(BlockstoreProcessorError::InvalidBlock(
            BlockError::Incomplete,
        ))
    } else {
        Ok(())
    }
}

/// Measures different parts of the slot confirmation processing pipeline.
#[derive(Debug)]
pub struct ConfirmationTiming {
    /// Moment when the `ConfirmationTiming` instance was created.  Used to track the total wall
    /// clock time from the moment the first shard for the slot is received and to the moment the
    /// slot is complete.
    pub started: Instant,

    /// Wall clock time used by the slot confirmation code, including PoH/signature verification,
    /// and replay.  As replay can run in parallel with the verification, this value can not be
    /// recovered from the `replay_elapsed` and or `{poh,transaction}_verify_elapsed`.  This
    /// includes failed cases, when `confirm_slot_entries` exist with an error.  In microseconds.
    /// When unified scheduler is enabled, replay excludes the transaction execution, only
    /// accounting for task creation and submission to the scheduler.
    pub confirmation_elapsed: u64,

    /// Wall clock time used by the entry replay code.  Does not include the PoH or the transaction
    /// signature/precompiles verification, but can overlap with the PoH and signature verification.
    /// In microseconds.
    /// When unified scheduler is enabled, replay excludes the transaction execution, only
    /// accounting for task creation and submission to the scheduler.
    pub replay_elapsed: u64,

    /// Wall clock times, used for the PoH verification of entries.  In microseconds.
    pub poh_verify_elapsed: u64,

    /// Wall clock time, used for the signature verification as well as precompiles verification.
    /// In microseconds.
    pub transaction_verify_elapsed: u64,

    /// Wall clock time spent loading data sets (and entries) from the blockstore.  This does not
    /// include the case when the blockstore load failed.  In microseconds.
    pub fetch_elapsed: u64,

    /// Same as `fetch_elapsed` above, but for the case when the blockstore load fails.  In
    /// microseconds.
    pub fetch_fail_elapsed: u64,

    /// `batch_execute()` measurements.
    pub batch_execute: BatchExecutionTiming,
}

impl Default for ConfirmationTiming {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            confirmation_elapsed: 0,
            replay_elapsed: 0,
            poh_verify_elapsed: 0,
            transaction_verify_elapsed: 0,
            fetch_elapsed: 0,
            fetch_fail_elapsed: 0,
            batch_execute: BatchExecutionTiming::default(),
        }
    }
}

/// Measures times related to transaction execution in a slot.
#[derive(Debug, Default)]
pub struct BatchExecutionTiming {
    /// Time used by transaction execution.  Accumulated across multiple threads that are running
    /// `execute_batch()`.
    pub totals: ExecuteTimings,

    /// Wall clock time used by the transaction execution part of pipeline.
    /// [`ConfirmationTiming::replay_elapsed`] includes this time.  In microseconds.
    wall_clock_us: u64,

    /// Time used to execute transactions, via `execute_batch()`, in the thread that consumed the
    /// most time (in terms of total_thread_us) among rayon threads. Note that the slowest thread
    /// is determined each time a given group of batches is newly processed. So, this is a coarse
    /// approximation of wall-time single-threaded linearized metrics, discarding all metrics other
    /// than the arbitrary set of batches mixed with various transactions, which replayed slowest
    /// as a whole for each rayon processing session, also after blockstore_processor's rebatching.
    ///
    /// When unified scheduler is enabled, this field isn't maintained, because it's not batched at
    /// all.
    slowest_thread: ThreadExecuteTimings,
}

impl BatchExecutionTiming {
    pub fn accumulate(
        &mut self,
        new_batch: ExecuteBatchesInternalMetrics,
        is_unified_scheduler_enabled: bool,
    ) {
        let Self {
            totals,
            wall_clock_us,
            slowest_thread,
        } = self;

        // These metric fields aren't applicable for the unified scheduler
        if !is_unified_scheduler_enabled {
            saturating_add_assign!(*wall_clock_us, new_batch.execute_batches_us);

            totals.saturating_add_in_place(TotalBatchesLen, new_batch.total_batches_len);
            totals.saturating_add_in_place(NumExecuteBatches, 1);
        }

        for thread_times in new_batch.execution_timings_per_thread.values() {
            totals.accumulate(&thread_times.execute_timings);
        }

        // This whole metric (replay-slot-end-to-end-stats) isn't applicable for the unified
        // scheduler.
        if !is_unified_scheduler_enabled {
            let slowest = new_batch
                .execution_timings_per_thread
                .values()
                .max_by_key(|thread_times| thread_times.total_thread_us);

            if let Some(slowest) = slowest {
                slowest_thread.accumulate(slowest);
                slowest_thread
                    .execute_timings
                    .saturating_add_in_place(NumExecuteBatches, 1);
            };
        }
    }
}

#[derive(Debug, Default)]
pub struct ThreadExecuteTimings {
    pub total_thread_us: u64,
    pub total_transactions_executed: u64,
    pub execute_timings: ExecuteTimings,
}

impl ThreadExecuteTimings {
    pub fn report_stats(&self, slot: Slot) {
        lazy! {
            datapoint_info!(
                "replay-slot-end-to-end-stats",
                ("slot", slot as i64, i64),
                ("total_thread_us", self.total_thread_us as i64, i64),
                ("total_transactions_executed", self.total_transactions_executed as i64, i64),
                // Everything inside the `eager!` block will be eagerly expanded before
                // evaluation of the rest of the surrounding macro.
                // Pass false because this code-path is never touched by unified scheduler.
                eager!{report_execute_timings!(self.execute_timings, false)}
            );
        };
    }

    pub fn accumulate(&mut self, other: &ThreadExecuteTimings) {
        self.execute_timings.accumulate(&other.execute_timings);
        saturating_add_assign!(self.total_thread_us, other.total_thread_us);
        saturating_add_assign!(
            self.total_transactions_executed,
            other.total_transactions_executed
        );
    }
}

#[derive(Default)]
pub struct ReplaySlotStats(ConfirmationTiming);
impl std::ops::Deref for ReplaySlotStats {
    type Target = ConfirmationTiming;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ReplaySlotStats {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ReplaySlotStats {
    pub fn report_stats(
        &self,
        slot: Slot,
        num_txs: usize,
        num_entries: usize,
        num_shreds: u64,
        bank_complete_time_us: u64,
        is_unified_scheduler_enabled: bool,
    ) {
        let confirmation_elapsed = if is_unified_scheduler_enabled {
            "confirmation_without_replay_us"
        } else {
            "confirmation_time_us"
        };
        let replay_elapsed = if is_unified_scheduler_enabled {
            "task_submission_us"
        } else {
            "replay_time"
        };
        let execute_batches_us = if is_unified_scheduler_enabled {
            None
        } else {
            Some(self.batch_execute.wall_clock_us as i64)
        };

        lazy! {
            datapoint_info!(
                "replay-slot-stats",
                ("slot", slot as i64, i64),
                ("fetch_entries_time", self.fetch_elapsed as i64, i64),
                (
                    "fetch_entries_fail_time",
                    self.fetch_fail_elapsed as i64,
                    i64
                ),
                (
                    "entry_poh_verification_time",
                    self.poh_verify_elapsed as i64,
                    i64
                ),
                (
                    "entry_transaction_verification_time",
                    self.transaction_verify_elapsed as i64,
                    i64
                ),
                (confirmation_elapsed, self.confirmation_elapsed as i64, i64),
                (replay_elapsed, self.replay_elapsed as i64, i64),
                ("execute_batches_us", execute_batches_us, Option<i64>),
                (
                    "replay_total_elapsed",
                    self.started.elapsed().as_micros() as i64,
                    i64
                ),
                ("bank_complete_time_us", bank_complete_time_us, i64),
                ("total_transactions", num_txs as i64, i64),
                ("total_entries", num_entries as i64, i64),
                ("total_shreds", num_shreds as i64, i64),
                // Everything inside the `eager!` block will be eagerly expanded before
                // evaluation of the rest of the surrounding macro.
                eager!{report_execute_timings!(self.batch_execute.totals, is_unified_scheduler_enabled)}
            );
        };

        // Skip reporting replay-slot-end-to-end-stats entirely if unified scheduler is enabled,
        // because the whole metrics itself is only meaningful for rayon-based worker threads.
        //
        // See slowest_thread doc comment for details.
        if !is_unified_scheduler_enabled {
            self.batch_execute.slowest_thread.report_stats(slot);
        }

        let mut per_pubkey_timings: Vec<_> = self
            .batch_execute
            .totals
            .details
            .per_program_timings
            .iter()
            .collect();
        per_pubkey_timings.sort_by(|a, b| b.1.accumulated_us.cmp(&a.1.accumulated_us));
        let (total_us, total_units, total_count, total_errored_units, total_errored_count) =
            per_pubkey_timings.iter().fold(
                (0, 0, 0, 0, 0),
                |(sum_us, sum_units, sum_count, sum_errored_units, sum_errored_count), a| {
                    (
                        sum_us + a.1.accumulated_us,
                        sum_units + a.1.accumulated_units,
                        sum_count + a.1.count,
                        sum_errored_units + a.1.total_errored_units,
                        sum_errored_count + a.1.errored_txs_compute_consumed.len(),
                    )
                },
            );

        for (pubkey, time) in per_pubkey_timings.iter().take(5) {
            datapoint_trace!(
                "per_program_timings",
                ("slot", slot as i64, i64),
                ("pubkey", pubkey.to_string(), String),
                ("execute_us", time.accumulated_us, i64),
                ("accumulated_units", time.accumulated_units, i64),
                ("errored_units", time.total_errored_units, i64),
                ("count", time.count, i64),
                (
                    "errored_count",
                    time.errored_txs_compute_consumed.len(),
                    i64
                ),
            );
        }
        datapoint_info!(
            "per_program_timings",
            ("slot", slot as i64, i64),
            ("pubkey", "all", String),
            ("execute_us", total_us, i64),
            ("accumulated_units", total_units, i64),
            ("count", total_count, i64),
            ("errored_units", total_errored_units, i64),
            ("errored_count", total_errored_count, i64)
        );
    }
}

#[derive(Default)]
pub struct ConfirmationProgress {
    pub last_entry: Hash,
    pub tick_hash_count: u64,
    pub num_shreds: u64,
    pub num_entries: usize,
    pub num_txs: usize,
}

impl ConfirmationProgress {
    pub fn new(last_entry: Hash) -> Self {
        Self {
            last_entry,
            ..Self::default()
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn confirm_slot(
    blockstore: &Blockstore,
    bank: &BankWithScheduler,
    replay_tx_thread_pool: &ThreadPool,
    timing: &mut ConfirmationTiming,
    progress: &mut ConfirmationProgress,
    skip_verification: bool,
    transaction_status_sender: Option<&TransactionStatusSender>,
    entry_notification_sender: Option<&EntryNotifierSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    recyclers: &VerifyRecyclers,
    allow_dead_slots: bool,
    log_messages_bytes_limit: Option<usize>,
    prioritization_fee_cache: &PrioritizationFeeCache,
) -> result::Result<(), BlockstoreProcessorError> {
    let slot = bank.slot();

    let slot_entries_load_result = {
        let mut load_elapsed = Measure::start("load_elapsed");
        let load_result = blockstore
            .get_slot_entries_with_shred_info(slot, progress.num_shreds, allow_dead_slots)
            .map_err(BlockstoreProcessorError::FailedToLoadEntries);
        load_elapsed.stop();
        if load_result.is_err() {
            timing.fetch_fail_elapsed += load_elapsed.as_us();
        } else {
            timing.fetch_elapsed += load_elapsed.as_us();
        }
        load_result
    }?;

    confirm_slot_entries(
        bank,
        replay_tx_thread_pool,
        slot_entries_load_result,
        timing,
        progress,
        skip_verification,
        transaction_status_sender,
        entry_notification_sender,
        replay_vote_sender,
        recyclers,
        log_messages_bytes_limit,
        prioritization_fee_cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn confirm_slot_entries(
    bank: &BankWithScheduler,
    replay_tx_thread_pool: &ThreadPool,
    slot_entries_load_result: (Vec<Entry>, u64, bool),
    timing: &mut ConfirmationTiming,
    progress: &mut ConfirmationProgress,
    skip_verification: bool,
    transaction_status_sender: Option<&TransactionStatusSender>,
    entry_notification_sender: Option<&EntryNotifierSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    recyclers: &VerifyRecyclers,
    log_messages_bytes_limit: Option<usize>,
    prioritization_fee_cache: &PrioritizationFeeCache,
) -> result::Result<(), BlockstoreProcessorError> {
    let ConfirmationTiming {
        confirmation_elapsed,
        replay_elapsed,
        poh_verify_elapsed,
        transaction_verify_elapsed,
        batch_execute: batch_execute_timing,
        ..
    } = timing;

    let confirmation_elapsed_timer = Measure::start("confirmation_elapsed");
    defer! {
        *confirmation_elapsed += confirmation_elapsed_timer.end_as_us();
    };

    let slot = bank.slot();
    let (entries, num_shreds, slot_full) = slot_entries_load_result;
    let num_entries = entries.len();
    let mut entry_tx_starting_indexes = Vec::with_capacity(num_entries);
    let mut entry_tx_starting_index = progress.num_txs;
    let num_txs = entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            if let Some(entry_notification_sender) = entry_notification_sender {
                let entry_index = progress.num_entries.saturating_add(i);
                if let Err(err) = entry_notification_sender.send(EntryNotification {
                    slot,
                    index: entry_index,
                    entry: entry.into(),
                    starting_transaction_index: entry_tx_starting_index,
                }) {
                    warn!(
                        "Slot {}, entry {} entry_notification_sender send failed: {:?}",
                        slot, entry_index, err
                    );
                }
            }
            let num_txs = entry.transactions.len();
            let next_tx_starting_index = entry_tx_starting_index.saturating_add(num_txs);
            entry_tx_starting_indexes.push(entry_tx_starting_index);
            entry_tx_starting_index = next_tx_starting_index;
            num_txs
        })
        .sum::<usize>();
    trace!(
        "Fetched entries for slot {}, num_entries: {}, num_shreds: {}, num_txs: {}, slot_full: {}",
        slot,
        num_entries,
        num_shreds,
        num_txs,
        slot_full,
    );

    if !skip_verification {
        let tick_hash_count = &mut progress.tick_hash_count;
        verify_ticks(bank, &entries, slot_full, tick_hash_count).map_err(|err| {
            warn!(
                "{:#?}, slot: {}, entry len: {}, tick_height: {}, last entry: {}, last_blockhash: \
                 {}, shred_index: {}, slot_full: {}",
                err,
                slot,
                num_entries,
                bank.tick_height(),
                progress.last_entry,
                bank.last_blockhash(),
                num_shreds,
                slot_full,
            );
            err
        })?;
    }

    let last_entry_hash = entries.last().map(|e| e.hash);
    let verifier = if !skip_verification {
        datapoint_debug!("verify-batch-size", ("size", num_entries as i64, i64));
        let entry_state = entries.start_verify(
            &progress.last_entry,
            replay_tx_thread_pool,
            recyclers.clone(),
        );
        if entry_state.status() == EntryVerificationStatus::Failure {
            warn!("Ledger proof of history failed at slot: {}", slot);
            return Err(BlockError::InvalidEntryHash.into());
        }
        Some(entry_state)
    } else {
        None
    };

    let verify_transaction = {
        let bank = bank.clone_with_scheduler();
        move |versioned_tx: VersionedTransaction,
              verification_mode: TransactionVerificationMode|
              -> Result<SanitizedTransaction> {
            bank.verify_transaction(versioned_tx, verification_mode)
        }
    };

    let transaction_verification_start = Instant::now();
    let transaction_verification_result = entry::start_verify_transactions(
        entries,
        skip_verification,
        replay_tx_thread_pool,
        recyclers.clone(),
        Arc::new(verify_transaction),
    );
    let transaction_cpu_duration_us =
        timing::duration_as_us(&transaction_verification_start.elapsed());

    let mut transaction_verification_result = match transaction_verification_result {
        Ok(transaction_verification_result) => transaction_verification_result,
        Err(err) => {
            warn!(
                "Ledger transaction signature verification failed at slot: {}",
                bank.slot()
            );
            return Err(err.into());
        }
    };

    let entries = transaction_verification_result
        .entries()
        .expect("Transaction verification generates entries");

    let mut replay_timer = Measure::start("replay_elapsed");
    let mut replay_entries: Vec<_> = entries
        .into_iter()
        .zip(entry_tx_starting_indexes)
        .map(|(entry, tx_starting_index)| ReplayEntry {
            entry,
            starting_index: tx_starting_index,
        })
        .collect();
    let process_result = process_entries(
        bank,
        replay_tx_thread_pool,
        &mut replay_entries,
        transaction_status_sender,
        replay_vote_sender,
        batch_execute_timing,
        log_messages_bytes_limit,
        prioritization_fee_cache,
    )
    .map_err(BlockstoreProcessorError::from);
    replay_timer.stop();
    *replay_elapsed += replay_timer.as_us();

    {
        // If running signature verification on the GPU, wait for that computation to finish, and
        // get the result of it. If we did the signature verification on the CPU, this just returns
        // the already-computed result produced in start_verify_transactions.  Either way, check the
        // result of the signature verification.
        let valid = transaction_verification_result.finish_verify();

        // The GPU Entry verification (if any) is kicked off right when the CPU-side Entry
        // verification finishes, so these times should be disjoint
        *transaction_verify_elapsed +=
            transaction_cpu_duration_us + transaction_verification_result.gpu_verify_duration();

        if !valid {
            warn!(
                "Ledger transaction signature verification failed at slot: {}",
                bank.slot()
            );
            return Err(TransactionError::SignatureFailure.into());
        }
    }

    if let Some(mut verifier) = verifier {
        let verified = verifier.finish_verify(replay_tx_thread_pool);
        *poh_verify_elapsed += verifier.poh_duration_us();
        if !verified {
            warn!("Ledger proof of history failed at slot: {}", bank.slot());
            return Err(BlockError::InvalidEntryHash.into());
        }
    }

    process_result?;

    progress.num_shreds += num_shreds;
    progress.num_entries += num_entries;
    progress.num_txs += num_txs;
    if let Some(last_entry_hash) = last_entry_hash {
        progress.last_entry = last_entry_hash;
    }

    Ok(())
}

// Special handling required for processing the entries in slot 0
fn process_bank_0(
    bank0: &BankWithScheduler,
    blockstore: &Blockstore,
    replay_tx_thread_pool: &ThreadPool,
    opts: &ProcessOptions,
    recyclers: &VerifyRecyclers,
    cache_block_meta_sender: Option<&CacheBlockMetaSender>,
    entry_notification_sender: Option<&EntryNotifierSender>,
) {
    assert_eq!(bank0.slot(), 0);
    let mut progress = ConfirmationProgress::new(bank0.last_blockhash());
    confirm_full_slot(
        blockstore,
        bank0,
        replay_tx_thread_pool,
        opts,
        recyclers,
        &mut progress,
        None,
        entry_notification_sender,
        None,
        &mut ExecuteTimings::default(),
    )
    .expect("Failed to process bank 0 from ledger. Did you forget to provide a snapshot?");
    if let Some((result, _timings)) = bank0.wait_for_completed_scheduler() {
        result.unwrap();
    }
    bank0.freeze();
    if blockstore.is_primary_access() {
        blockstore.insert_bank_hash(bank0.slot(), bank0.hash(), false);
    }
    cache_block_meta(bank0, cache_block_meta_sender);
}

// Given a bank, add its children to the pending slots queue if those children slots are
// complete
fn process_next_slots(
    bank: &Arc<Bank>,
    meta: &SlotMeta,
    blockstore: &Blockstore,
    leader_schedule_cache: &LeaderScheduleCache,
    pending_slots: &mut Vec<(SlotMeta, Bank, Hash)>,
    halt_at_slot: Option<Slot>,
) -> result::Result<(), BlockstoreProcessorError> {
    if meta.next_slots.is_empty() {
        return Ok(());
    }

    // This is a fork point if there are multiple children, create a new child bank for each fork
    for next_slot in &meta.next_slots {
        let skip_next_slot = halt_at_slot
            .map(|halt_at_slot| *next_slot > halt_at_slot)
            .unwrap_or(false);
        if skip_next_slot {
            continue;
        }

        let next_meta = blockstore
            .meta(*next_slot)
            .map_err(|err| {
                warn!("Failed to load meta for slot {}: {:?}", next_slot, err);
                BlockstoreProcessorError::FailedToLoadMeta
            })?
            .unwrap();

        // Only process full slots in blockstore_processor, replay_stage
        // handles any partials
        if next_meta.is_full() {
            let next_bank = Bank::new_from_parent(
                bank.clone(),
                &leader_schedule_cache
                    .slot_leader_at(*next_slot, Some(bank))
                    .unwrap(),
                *next_slot,
            );
            trace!(
                "New bank for slot {}, parent slot is {}",
                next_slot,
                bank.slot(),
            );
            pending_slots.push((next_meta, next_bank, bank.last_blockhash()));
        }
    }

    // Reverse sort by slot, so the next slot to be processed can be popped
    pending_slots.sort_by(|a, b| b.1.slot().cmp(&a.1.slot()));
    Ok(())
}

/// Starting with the root slot corresponding to `start_slot_meta`, iteratively
/// find and process children slots from the blockstore.
///
/// Returns a tuple (a, b) where a is the number of slots processed and b is
/// the number of newly found cluster roots.
#[allow(clippy::too_many_arguments)]
fn load_frozen_forks(
    bank_forks: &RwLock<BankForks>,
    start_slot_meta: &SlotMeta,
    blockstore: &Blockstore,
    replay_tx_thread_pool: &ThreadPool,
    leader_schedule_cache: &LeaderScheduleCache,
    opts: &ProcessOptions,
    transaction_status_sender: Option<&TransactionStatusSender>,
    cache_block_meta_sender: Option<&CacheBlockMetaSender>,
    entry_notification_sender: Option<&EntryNotifierSender>,
    timing: &mut ExecuteTimings,
    accounts_background_request_sender: &AbsRequestSender,
) -> result::Result<(u64, usize), BlockstoreProcessorError> {
    let blockstore_max_root = blockstore.max_root();
    let mut root = bank_forks.read().unwrap().root();
    let max_root = std::cmp::max(root, blockstore_max_root);
    info!(
        "load_frozen_forks() latest root from blockstore: {}, max_root: {}",
        blockstore_max_root, max_root,
    );

    // The total number of slots processed
    let mut total_slots_processed = 0;
    // The total number of newly identified root slots
    let mut total_rooted_slots = 0;

    let mut pending_slots = vec![];
    process_next_slots(
        &bank_forks
            .read()
            .unwrap()
            .get(start_slot_meta.slot)
            .unwrap(),
        start_slot_meta,
        blockstore,
        leader_schedule_cache,
        &mut pending_slots,
        opts.halt_at_slot,
    )?;

    let on_halt_store_hash_raw_data_for_debug = opts.on_halt_store_hash_raw_data_for_debug;
    if Some(bank_forks.read().unwrap().root()) != opts.halt_at_slot {
        let recyclers = VerifyRecyclers::default();
        let mut all_banks = HashMap::new();

        const STATUS_REPORT_INTERVAL: Duration = Duration::from_secs(2);
        let mut last_status_report = Instant::now();
        let mut slots_processed = 0;
        let mut txs = 0;
        let mut set_root_us = 0;
        let mut root_retain_us = 0;
        let mut process_single_slot_us = 0;
        let mut voting_us = 0;

        while !pending_slots.is_empty() {
            timing.details.per_program_timings.clear();
            let (meta, bank, last_entry_hash) = pending_slots.pop().unwrap();
            let slot = bank.slot();
            if last_status_report.elapsed() > STATUS_REPORT_INTERVAL {
                let secs = last_status_report.elapsed().as_secs() as f32;
                let slots_per_sec = slots_processed as f32 / secs;
                let txs_per_sec = txs as f32 / secs;
                info!(
                    "processing ledger: slot={slot}, root_slot={root} slots={slots_processed}, \
                     slots/s={slots_per_sec}, txs/s={txs_per_sec}"
                );
                debug!(
                    "processing ledger timing: set_root_us={set_root_us}, \
                     root_retain_us={root_retain_us}, \
                     process_single_slot_us:{process_single_slot_us}, voting_us: {voting_us}"
                );

                last_status_report = Instant::now();
                slots_processed = 0;
                txs = 0;
                set_root_us = 0;
                root_retain_us = 0;
                process_single_slot_us = 0;
                voting_us = 0;
            }

            let mut progress = ConfirmationProgress::new(last_entry_hash);
            let mut m = Measure::start("process_single_slot");
            let bank = bank_forks.write().unwrap().insert_from_ledger(bank);
            if process_single_slot(
                blockstore,
                &bank,
                replay_tx_thread_pool,
                opts,
                &recyclers,
                &mut progress,
                transaction_status_sender,
                cache_block_meta_sender,
                entry_notification_sender,
                None,
                timing,
            )
            .is_err()
            {
                assert!(bank_forks.write().unwrap().remove(bank.slot()).is_some());
                continue;
            }
            txs += progress.num_txs;

            // Block must be frozen by this point; otherwise,
            // process_single_slot() would have errored above.
            assert!(bank.is_frozen());
            all_banks.insert(bank.slot(), bank.clone_with_scheduler());
            m.stop();
            process_single_slot_us += m.as_us();

            let mut m = Measure::start("voting");
            // If we've reached the last known root in blockstore, start looking
            // for newer cluster confirmed roots
            let new_root_bank = {
                if bank_forks.read().unwrap().root() >= max_root {
                    supermajority_root_from_vote_accounts(
                        bank.slot(),
                        bank.total_epoch_stake(),
                        &bank.vote_accounts(),
                    ).and_then(|supermajority_root| {
                        if supermajority_root > root {
                            // If there's a cluster confirmed root greater than our last
                            // replayed root, then because the cluster confirmed root should
                            // be descended from our last root, it must exist in `all_banks`
                            let cluster_root_bank = all_banks.get(&supermajority_root).unwrap();

                            // cluster root must be a descendant of our root, otherwise something
                            // is drastically wrong
                            assert!(cluster_root_bank.ancestors.contains_key(&root));
                            info!(
                                "blockstore processor found new cluster confirmed root: {}, observed in bank: {}",
                                cluster_root_bank.slot(), bank.slot()
                            );

                            // Ensure cluster-confirmed root and parents are set as root in blockstore
                            let mut rooted_slots = vec![];
                            let mut new_root_bank = cluster_root_bank.clone_without_scheduler();
                            loop {
                                if new_root_bank.slot() == root { break; } // Found the last root in the chain, yay!
                                assert!(new_root_bank.slot() > root);

                                rooted_slots.push((new_root_bank.slot(), Some(new_root_bank.hash())));
                                // As noted, the cluster confirmed root should be descended from
                                // our last root; therefore parent should be set
                                new_root_bank = new_root_bank.parent().unwrap();
                            }
                            total_rooted_slots += rooted_slots.len();
                            if blockstore.is_primary_access() {
                                blockstore
                                    .mark_slots_as_if_rooted_normally_at_startup(rooted_slots, true)
                                    .expect("Blockstore::mark_slots_as_if_rooted_normally_at_startup() should succeed");
                            }
                            Some(cluster_root_bank)
                        } else {
                            None
                        }
                    })
                } else if blockstore.is_root(slot) {
                    Some(&bank)
                } else {
                    None
                }
            };
            m.stop();
            voting_us += m.as_us();

            if let Some(new_root_bank) = new_root_bank {
                let mut m = Measure::start("set_root");
                root = new_root_bank.slot();

                leader_schedule_cache.set_root(new_root_bank);
                new_root_bank.prune_program_cache(root, new_root_bank.epoch());
                let _ = bank_forks.write().unwrap().set_root(
                    root,
                    accounts_background_request_sender,
                    None,
                )?;
                m.stop();
                set_root_us += m.as_us();

                // Filter out all non descendants of the new root
                let mut m = Measure::start("filter pending slots");
                pending_slots
                    .retain(|(_, pending_bank, _)| pending_bank.ancestors.contains_key(&root));
                all_banks.retain(|_, bank| bank.ancestors.contains_key(&root));
                m.stop();
                root_retain_us += m.as_us();
            }

            slots_processed += 1;
            total_slots_processed += 1;

            trace!(
                "Bank for {}slot {} is complete",
                if root == slot { "root " } else { "" },
                slot,
            );

            let done_processing = opts
                .halt_at_slot
                .map(|halt_at_slot| slot >= halt_at_slot)
                .unwrap_or(false);
            if done_processing {
                if opts.run_final_accounts_hash_calc {
                    bank.run_final_hash_calc(on_halt_store_hash_raw_data_for_debug);
                }
                break;
            }

            process_next_slots(
                &bank,
                &meta,
                blockstore,
                leader_schedule_cache,
                &mut pending_slots,
                opts.halt_at_slot,
            )?;
        }
    } else if on_halt_store_hash_raw_data_for_debug {
        bank_forks
            .read()
            .unwrap()
            .root_bank()
            .run_final_hash_calc(on_halt_store_hash_raw_data_for_debug);
    }

    Ok((total_slots_processed, total_rooted_slots))
}

// `roots` is sorted largest to smallest by root slot
fn supermajority_root(roots: &[(Slot, u64)], total_epoch_stake: u64) -> Option<Slot> {
    if roots.is_empty() {
        return None;
    }

    // Find latest root
    let mut total = 0;
    let mut prev_root = roots[0].0;
    for (root, stake) in roots.iter() {
        assert!(*root <= prev_root);
        total += stake;
        if total as f64 / total_epoch_stake as f64 > VOTE_THRESHOLD_SIZE {
            return Some(*root);
        }
        prev_root = *root;
    }

    None
}

fn supermajority_root_from_vote_accounts(
    bank_slot: Slot,
    total_epoch_stake: u64,
    vote_accounts: &VoteAccountsHashMap,
) -> Option<Slot> {
    let mut roots_stakes: Vec<(Slot, u64)> = vote_accounts
        .iter()
        .filter_map(|(key, (stake, account))| {
            if *stake == 0 {
                return None;
            }

            match account.vote_state().as_ref() {
                Err(_) => {
                    warn!(
                        "Unable to get vote_state from account {} in bank: {}",
                        key, bank_slot
                    );
                    None
                }
                Ok(vote_state) => Some((vote_state.root_slot?, *stake)),
            }
        })
        .collect();

    // Sort from greatest to smallest slot
    roots_stakes.sort_unstable_by(|a, b| a.0.cmp(&b.0).reverse());

    // Find latest root
    supermajority_root(&roots_stakes, total_epoch_stake)
}

// Processes and replays the contents of a single slot, returns Error
// if failed to play the slot
#[allow(clippy::too_many_arguments)]
pub fn process_single_slot(
    blockstore: &Blockstore,
    bank: &BankWithScheduler,
    replay_tx_thread_pool: &ThreadPool,
    opts: &ProcessOptions,
    recyclers: &VerifyRecyclers,
    progress: &mut ConfirmationProgress,
    transaction_status_sender: Option<&TransactionStatusSender>,
    cache_block_meta_sender: Option<&CacheBlockMetaSender>,
    entry_notification_sender: Option<&EntryNotifierSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    timing: &mut ExecuteTimings,
) -> result::Result<(), BlockstoreProcessorError> {
    // Mark corrupt slots as dead so validators don't replay this slot and
    // see AlreadyProcessed errors later in ReplayStage
    confirm_full_slot(
        blockstore,
        bank,
        replay_tx_thread_pool,
        opts,
        recyclers,
        progress,
        transaction_status_sender,
        entry_notification_sender,
        replay_vote_sender,
        timing,
    )
    .map_err(|err| {
        let slot = bank.slot();
        warn!("slot {} failed to verify: {}", slot, err);
        if blockstore.is_primary_access() {
            blockstore
                .set_dead_slot(slot)
                .expect("Failed to mark slot as dead in blockstore");
        } else {
            info!(
                "Failed slot {} won't be marked dead due to being secondary blockstore access",
                slot
            );
        }
        err
    })?;

    if let Some((result, _timings)) = bank.wait_for_completed_scheduler() {
        result?
    }
    bank.freeze(); // all banks handled by this routine are created from complete slots

    if let Some(slot_callback) = &opts.slot_callback {
        slot_callback(bank);
    }

    if blockstore.is_primary_access() {
        blockstore.insert_bank_hash(bank.slot(), bank.hash(), false);
    }
    cache_block_meta(bank, cache_block_meta_sender);

    Ok(())
}

#[allow(clippy::large_enum_variant)]
pub enum TransactionStatusMessage {
    Batch(TransactionStatusBatch),
    Freeze(Slot),
}

pub struct TransactionStatusBatch {
    pub bank: Arc<Bank>,
    pub transactions: Vec<SanitizedTransaction>,
    pub execution_results: Vec<Option<TransactionExecutionDetails>>,
    pub balances: TransactionBalancesSet,
    pub token_balances: TransactionTokenBalancesSet,
    pub rent_debits: Vec<RentDebits>,
    pub transaction_indexes: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct TransactionStatusSender {
    pub sender: Sender<TransactionStatusMessage>,
}

impl TransactionStatusSender {
    pub fn send_transaction_status_batch(
        &self,
        bank: Arc<Bank>,
        transactions: Vec<SanitizedTransaction>,
        execution_results: Vec<TransactionExecutionResult>,
        balances: TransactionBalancesSet,
        token_balances: TransactionTokenBalancesSet,
        rent_debits: Vec<RentDebits>,
        transaction_indexes: Vec<usize>,
    ) {
        let slot = bank.slot();

        if let Err(e) = self
            .sender
            .send(TransactionStatusMessage::Batch(TransactionStatusBatch {
                bank,
                transactions,
                execution_results: execution_results
                    .into_iter()
                    .map(|result| match result {
                        TransactionExecutionResult::Executed { details, .. } => Some(details),
                        TransactionExecutionResult::NotExecuted(_) => None,
                    })
                    .collect(),
                balances,
                token_balances,
                rent_debits,
                transaction_indexes,
            }))
        {
            trace!(
                "Slot {} transaction_status send batch failed: {:?}",
                slot,
                e
            );
        }
    }

    pub fn send_transaction_status_freeze_message(&self, bank: &Arc<Bank>) {
        let slot = bank.slot();
        if let Err(e) = self.sender.send(TransactionStatusMessage::Freeze(slot)) {
            trace!(
                "Slot {} transaction_status send freeze message failed: {:?}",
                slot,
                e
            );
        }
    }
}

pub type CacheBlockMetaSender = Sender<Arc<Bank>>;

pub fn cache_block_meta(bank: &Arc<Bank>, cache_block_meta_sender: Option<&CacheBlockMetaSender>) {
    if let Some(cache_block_meta_sender) = cache_block_meta_sender {
        cache_block_meta_sender
            .send(bank.clone())
            .unwrap_or_else(|err| warn!("cache_block_meta_sender failed: {:?}", err));
    }
}

// used for tests only
pub fn fill_blockstore_slot_with_ticks(
    blockstore: &Blockstore,
    ticks_per_slot: u64,
    slot: u64,
    parent_slot: u64,
    last_entry_hash: Hash,
) -> Hash {
    // Only slot 0 can be equal to the parent_slot
    assert!(slot.saturating_sub(1) >= parent_slot);
    let num_slots = (slot - parent_slot).max(1);
    let entries = create_ticks(num_slots * ticks_per_slot, 0, last_entry_hash);
    let last_entry_hash = entries.last().unwrap().hash;

    blockstore
        .write_entries(
            slot,
            0,
            0,
            ticks_per_slot,
            Some(parent_slot),
            true,
            &Arc::new(Keypair::new()),
            entries,
            0,
        )
        .unwrap();

    last_entry_hash
}
