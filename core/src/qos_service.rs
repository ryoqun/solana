//! Quality of service for block producer.
//! Provides logic and functions to allow a Leader to prioritize
//! how transactions are included in blocks, and optimize those blocks.
//!
use {
    crate::banking_stage::{BatchedTransactionCostDetails, CommitTransactionDetails},
    solana_measure::measure::Measure,
    solana_runtime::{
        bank::Bank,
        cost_model::{CostModel, TransactionCost},
        cost_tracker::CostTrackerError,
    },
    solana_sdk::{
        timing::AtomicInterval,
        transaction::{self, SanitizedTransaction, TransactionError},
    },
    std::{
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct QosService {
    // cost_model instance is owned by validator, shared between replay_stage and
    // banking_stage. replay_stage writes the latest on-chain program timings to
    // it; banking_stage's qos_service reads that information to calculate
    // transaction cost, hence RwLock wrapped.
    cost_model: Arc<RwLock<CostModel>>,
    metrics: Arc<QosServiceMetrics>,
    reporting_thread: Option<JoinHandle<()>>,
    running_flag: Arc<AtomicBool>,
}

impl Drop for QosService {
    fn drop(&mut self) {
        self.running_flag.store(false, Ordering::Relaxed);
        self.reporting_thread
            .take()
            .unwrap()
            .join()
            .expect("qos service metrics reporting thread failed to join");
    }
}

impl QosService {
    pub fn new(cost_model: Arc<RwLock<CostModel>>) -> Self {
        Self::new_with_reporting_duration(cost_model, 1000u64)
    }

    pub fn new_with_reporting_duration(
        cost_model: Arc<RwLock<CostModel>>,
        reporting_duration_ms: u64,
    ) -> Self {
        let running_flag = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(QosServiceMetrics::default());

        let running_flag_clone = running_flag.clone();
        let metrics_clone = metrics.clone();
        let reporting_thread = Some(
            Builder::new()
                .name("solana-qos-service-metrics-repoting".to_string())
                .spawn(move || {
                    Self::reporting_loop(running_flag_clone, metrics_clone, reporting_duration_ms);
                })
                .unwrap(),
        );
        Self {
            cost_model,
            metrics,
            reporting_thread,
            running_flag,
        }
    }

    pub fn compute_transaction_costs<'a>(
        &self,
        transactions: impl Iterator<Item = &'a SanitizedTransaction>,
    ) -> Vec<TransactionCost> {
        let mut compute_cost_time = Measure::start("compute_cost_time");
        let cost_model = self.cost_model.read().unwrap();
        let txs_costs: Vec<_> = transactions
            .map(|tx| {
                let cost = cost_model.calculate_cost(tx);
                debug!(
                    "transaction {:?}, cost {:?}, cost sum {}",
                    tx,
                    cost,
                    cost.sum()
                );
                cost
            })
            .collect();
        compute_cost_time.stop();
        self.metrics
            .compute_cost_time
            .fetch_add(compute_cost_time.as_us(), Ordering::Relaxed);
        self.metrics
            .compute_cost_count
            .fetch_add(txs_costs.len() as u64, Ordering::Relaxed);
        txs_costs
    }

    /// Given a list of transactions and their costs, this function returns a corresponding
    /// list of Results that indicate if a transaction is selected to be included in the current block,
    /// and a count of the number of transactions that would fit in the block
    pub fn select_transactions_per_cost<'a>(
        &self,
        transactions: impl Iterator<Item = &'a SanitizedTransaction>,
        transactions_costs: impl Iterator<Item = &'a TransactionCost>,
        bank: &Arc<Bank>,
    ) -> (Vec<transaction::Result<()>>, usize) {
        let mut cost_tracking_time = Measure::start("cost_tracking_time");
        let mut cost_tracker = bank.write_cost_tracker().unwrap();
        let mut num_included = 0;
        let select_results = transactions
            .zip(transactions_costs)
            .map(|(tx, cost)| match cost_tracker.try_add(cost) {
                Ok(current_block_cost) => {
                    debug!("slot {:?}, transaction {:?}, cost {:?}, fit into current block, current block cost {}", bank.slot(), tx, cost, current_block_cost);
                    self.metrics.selected_txs_count.fetch_add(1, Ordering::Relaxed);
                    num_included += 1;
                    Ok(())
                },
                Err(e) => {
                    debug!("slot {:?}, transaction {:?}, cost {:?}, not fit into current block, '{:?}'", bank.slot(), tx, cost, e);
                    match e {
                        CostTrackerError::WouldExceedBlockMaxLimit => {
                            self.metrics.retried_txs_per_block_limit_count.fetch_add(1, Ordering::Relaxed);
                            Err(TransactionError::WouldExceedMaxBlockCostLimit)
                        }
                        CostTrackerError::WouldExceedVoteMaxLimit => {
                            self.metrics.retried_txs_per_vote_limit_count.fetch_add(1, Ordering::Relaxed);
                            Err(TransactionError::WouldExceedMaxVoteCostLimit)
                        }
                        CostTrackerError::WouldExceedAccountMaxLimit => {
                            self.metrics.retried_txs_per_account_limit_count.fetch_add(1, Ordering::Relaxed);
                            Err(TransactionError::WouldExceedMaxAccountCostLimit)
                        }
                    }
                }
            })
            .collect();
        cost_tracking_time.stop();
        self.metrics
            .cost_tracking_time
            .fetch_add(cost_tracking_time.as_us(), Ordering::Relaxed);
        (select_results, num_included)
    }

    /// Update the transaction cost in the cost_tracker with the real cost for
    /// transactions that were executed successfully;
    /// Otherwise remove the cost from the cost tracker, therefore preventing cost_tracker
    /// being inflated with unsuccessfully executed transactions.
    pub fn update_or_remove_transaction_costs<'a>(
        transaction_costs: impl Iterator<Item = &'a TransactionCost>,
        transaction_qos_results: impl Iterator<Item = &'a transaction::Result<()>>,
        transaction_committed_status: Option<&Vec<CommitTransactionDetails>>,
        bank: &Arc<Bank>,
    ) {
        match transaction_committed_status {
            Some(transaction_committed_status) => Self::update_transaction_costs(
                transaction_costs,
                transaction_qos_results,
                transaction_committed_status,
                bank,
            ),
            None => {
                Self::remove_transaction_costs(transaction_costs, transaction_qos_results, bank)
            }
        }
    }

    fn update_transaction_costs<'a>(
        transaction_costs: impl Iterator<Item = &'a TransactionCost>,
        transaction_qos_results: impl Iterator<Item = &'a transaction::Result<()>>,
        transaction_committed_status: &[CommitTransactionDetails],
        bank: &Arc<Bank>,
    ) {
        let mut cost_tracker = bank.write_cost_tracker().unwrap();
        transaction_costs
            .zip(transaction_qos_results)
            .zip(transaction_committed_status)
            .for_each(
                |((tx_cost, qos_inclusion_result), transaction_committed_details)| {
                    // Only transactions that the qos service included have to be
                    // checked for update
                    if qos_inclusion_result.is_ok() {
                        match transaction_committed_details {
                            CommitTransactionDetails::Committed { compute_units } => {
                                cost_tracker.update_execution_cost(tx_cost, *compute_units)
                            }
                            CommitTransactionDetails::NotCommitted => cost_tracker.remove(tx_cost),
                        }
                    }
                },
            );
    }

    fn remove_transaction_costs<'a>(
        transaction_costs: impl Iterator<Item = &'a TransactionCost>,
        transaction_qos_results: impl Iterator<Item = &'a transaction::Result<()>>,
        bank: &Arc<Bank>,
    ) {
        let mut cost_tracker = bank.write_cost_tracker().unwrap();
        transaction_costs.zip(transaction_qos_results).for_each(
            |(tx_cost, qos_inclusion_result)| {
                // Only transactions that the qos service included have to be
                // removed
                if qos_inclusion_result.is_ok() {
                    cost_tracker.remove(tx_cost);
                }
            },
        );
    }

    pub fn accumulate_estimated_transaction_costs(
        &self,
        cost_details: &BatchedTransactionCostDetails,
    ) {
        self.metrics
            .estimated_signature_cu
            .fetch_add(cost_details.batched_signature_cost, Ordering::Relaxed);
        self.metrics
            .estimated_write_lock_cu
            .fetch_add(cost_details.batched_write_lock_cost, Ordering::Relaxed);
        self.metrics
            .estimated_data_bytes_cu
            .fetch_add(cost_details.batched_data_bytes_cost, Ordering::Relaxed);
        self.metrics.estimated_builtins_execute_cu.fetch_add(
            cost_details.batched_builtins_execute_cost,
            Ordering::Relaxed,
        );
        self.metrics
            .estimated_bpf_execute_cu
            .fetch_add(cost_details.batched_bpf_execute_cost, Ordering::Relaxed);
    }

    pub fn accumulate_actual_execute_cu(&self, units: u64) {
        self.metrics
            .actual_bpf_execute_cu
            .fetch_add(units, Ordering::Relaxed);
    }

    pub fn accumulate_actual_execute_time(&self, micro_sec: u64) {
        self.metrics
            .actual_execute_time_us
            .fetch_add(micro_sec, Ordering::Relaxed);
    }

    fn reporting_loop(
        running_flag: Arc<AtomicBool>,
        metrics: Arc<QosServiceMetrics>,
        reporting_duration_ms: u64,
    ) {
        while running_flag.load(Ordering::Relaxed) {
            metrics.report(reporting_duration_ms);
            thread::sleep(Duration::from_millis(100));
        }
    }
}

#[derive(Default)]
struct QosServiceMetrics {
    last_report: AtomicInterval,
    compute_cost_time: AtomicU64,
    compute_cost_count: AtomicU64,
    cost_tracking_time: AtomicU64,
    selected_txs_count: AtomicU64,
    retried_txs_per_block_limit_count: AtomicU64,
    retried_txs_per_vote_limit_count: AtomicU64,
    retried_txs_per_account_limit_count: AtomicU64,

    // accumulated estimated signature Compute Unites to be packed into block
    estimated_signature_cu: AtomicU64,

    // accumulated estimated write locks Compute Units to be packed into block
    estimated_write_lock_cu: AtomicU64,

    // accumulated estimated instructino data Compute Units to be packed into block
    estimated_data_bytes_cu: AtomicU64,

    // accumulated estimated builtin programs Compute Units to be packed into block
    estimated_builtins_execute_cu: AtomicU64,

    // accumulated estimated BPF program Compute Units to be packed into block
    estimated_bpf_execute_cu: AtomicU64,

    // accumulated actual program Compute Units that have been packed into block
    actual_bpf_execute_cu: AtomicU64,

    // accumulated actual program execute micro-sec that have been packed into block
    actual_execute_time_us: AtomicU64,
}

impl QosServiceMetrics {
    pub fn report(&self, report_interval_ms: u64) {
        if self.last_report.should_update(report_interval_ms) {
            datapoint_info!(
                "qos-service-stats",
                (
                    "compute_cost_time",
                    self.compute_cost_time.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "compute_cost_count",
                    self.compute_cost_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "cost_tracking_time",
                    self.cost_tracking_time.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "selected_txs_count",
                    self.selected_txs_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "retried_txs_per_block_limit_count",
                    self.retried_txs_per_block_limit_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "retried_txs_per_vote_limit_count",
                    self.retried_txs_per_vote_limit_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "retried_txs_per_account_limit_count",
                    self.retried_txs_per_account_limit_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "estimated_signature_cu",
                    self.estimated_signature_cu.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "estimated_write_lock_cu",
                    self.estimated_write_lock_cu.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "estimated_data_bytes_cu",
                    self.estimated_data_bytes_cu.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "estimated_builtins_execute_cu",
                    self.estimated_builtins_execute_cu
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "estimated_bpf_execute_cu",
                    self.estimated_bpf_execute_cu.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "actual_bpf_execute_cu",
                    self.actual_bpf_execute_cu.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "actual_execute_time_us",
                    self.actual_execute_time_us.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
            );
        }
    }
}

