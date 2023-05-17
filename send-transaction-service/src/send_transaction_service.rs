use {
    crate::tpu_info::TpuInfo,
    crossbeam_channel::{Receiver, RecvTimeoutError},
    log::*,
    solana_client::{connection_cache::ConnectionCache, tpu_connection::TpuConnection},
    solana_measure::measure::Measure,
    solana_metrics::datapoint_warn,
    solana_runtime::{bank::Bank, bank_forks::BankForks},
    solana_sdk::{
        hash::Hash, nonce_account, pubkey::Pubkey, saturating_add_assign, signature::Signature,
        timing::AtomicInterval, transport::TransportError,
    },
    std::{
        collections::{
            hash_map::{Entry, HashMap},
            HashSet,
        },
        net::SocketAddr,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex, RwLock,
        },
        thread::{self, sleep, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

/// Maximum size of the transaction queue
const MAX_TRANSACTION_QUEUE_SIZE: usize = 10_000; // This seems like a lot but maybe it needs to be bigger one day

/// Default retry interval
const DEFAULT_RETRY_RATE_MS: u64 = 2_000;

/// Default number of leaders to forward transactions to
const DEFAULT_LEADER_FORWARD_COUNT: u64 = 2;
/// Default max number of time the service will retry broadcast
const DEFAULT_SERVICE_MAX_RETRIES: usize = usize::MAX;

/// Default batch size for sending transaction in batch
/// When this size is reached, send out the transactions.
const DEFAULT_TRANSACTION_BATCH_SIZE: usize = 1;

// The maximum transaction batch size
pub const MAX_TRANSACTION_BATCH_SIZE: usize = 10_000;

/// Maximum transaction sends per second
pub const MAX_TRANSACTION_SENDS_PER_SECOND: u64 = 1_000;

/// Default maximum batch waiting time in ms. If this time is reached,
/// whatever transactions are cached will be sent.
const DEFAULT_BATCH_SEND_RATE_MS: u64 = 1;

// The maximum transaction batch send rate in MS
pub const MAX_BATCH_SEND_RATE_MS: usize = 100_000;

pub struct SendTransactionService {
    receive_txn_thread: JoinHandle<()>,
    retry_thread: JoinHandle<()>,
    exit: Arc<AtomicBool>,
}

pub struct TransactionInfo {
    pub signature: Signature,
    pub wire_transaction: Vec<u8>,
    pub last_valid_block_height: u64,
    pub durable_nonce_info: Option<(Pubkey, Hash)>,
    pub max_retries: Option<usize>,
    retries: usize,
    /// Last time the transaction was sent
    last_sent_time: Option<Instant>,
}

impl TransactionInfo {
    pub fn new(
        signature: Signature,
        wire_transaction: Vec<u8>,
        last_valid_block_height: u64,
        durable_nonce_info: Option<(Pubkey, Hash)>,
        max_retries: Option<usize>,
        last_sent_time: Option<Instant>,
    ) -> Self {
        Self {
            signature,
            wire_transaction,
            last_valid_block_height,
            durable_nonce_info,
            max_retries,
            retries: 0,
            last_sent_time,
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
struct ProcessTransactionsResult {
    rooted: u64,
    expired: u64,
    retried: u64,
    max_retries_elapsed: u64,
    failed: u64,
    retained: u64,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub retry_rate_ms: u64,
    pub leader_forward_count: u64,
    pub default_max_retries: Option<usize>,
    pub service_max_retries: usize,
    /// The batch size for sending transactions in batches
    pub batch_size: usize,
    /// How frequently batches are sent
    pub batch_send_rate_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            retry_rate_ms: DEFAULT_RETRY_RATE_MS,
            leader_forward_count: DEFAULT_LEADER_FORWARD_COUNT,
            default_max_retries: None,
            service_max_retries: DEFAULT_SERVICE_MAX_RETRIES,
            batch_size: DEFAULT_TRANSACTION_BATCH_SIZE,
            batch_send_rate_ms: DEFAULT_BATCH_SEND_RATE_MS,
        }
    }
}

/// The maximum duration the retry thread may be configured to sleep before
/// processing the transactions that need to be retried.
pub const MAX_RETRY_SLEEP_MS: u64 = 1000;

/// The leader info refresh rate.
pub const LEADER_INFO_REFRESH_RATE_MS: u64 = 1000;

/// A struct responsible for holding up-to-date leader information
/// used for sending transactions.
pub struct CurrentLeaderInfo<T>
where
    T: TpuInfo + std::marker::Send + 'static,
{
    /// The last time the leader info was refreshed
    last_leader_refresh: Option<Instant>,

    /// The leader info
    leader_info: Option<T>,

    /// How often to refresh the leader info
    refresh_rate: Duration,
}

impl<T> CurrentLeaderInfo<T>
where
    T: TpuInfo + std::marker::Send + 'static,
{
    /// Get the leader info, refresh if expired
    pub fn get_leader_info(&mut self) -> Option<&T> {
        if let Some(leader_info) = self.leader_info.as_mut() {
            let now = Instant::now();
            let need_refresh = self
                .last_leader_refresh
                .map(|last| now.duration_since(last) >= self.refresh_rate)
                .unwrap_or(true);

            if need_refresh {
                leader_info.refresh_recent_peers();
                self.last_leader_refresh = Some(now);
            }
        }
        self.leader_info.as_ref()
    }

    pub fn new(leader_info: Option<T>) -> Self {
        Self {
            last_leader_refresh: None,
            leader_info,
            refresh_rate: Duration::from_millis(LEADER_INFO_REFRESH_RATE_MS),
        }
    }
}

/// Metrics of the send-transaction-service.
#[derive(Default)]
struct SendTransactionServiceStats {
    /// Count of the received transactions
    received_transactions: AtomicU64,

    /// Count of the received duplicate transactions
    received_duplicate_transactions: AtomicU64,

    /// Count of transactions sent in batch
    sent_transactions: AtomicU64,

    /// Count of transactions not being added to retry queue
    /// due to queue size limit
    retry_queue_overflow: AtomicU64,

    /// retry queue size
    retry_queue_size: AtomicU64,

    /// The count of calls of sending transactions which can be in batch or single.
    send_attempt_count: AtomicU64,

    /// Time spent on transactions in micro seconds
    send_us: AtomicU64,

    /// Send failure count
    send_failure_count: AtomicU64,

    /// Count of nonced transactions
    nonced_transactions: AtomicU64,

    /// Count of rooted transactions
    rooted_transactions: AtomicU64,

    /// Count of expired transactions
    expired_transactions: AtomicU64,

    /// Count of transactions exceeding max retries
    transactions_exceeding_max_retries: AtomicU64,

    /// Count of retries of transactions
    retries: AtomicU64,

    /// Count of transactions failed
    failed_transactions: AtomicU64,
}

#[derive(Default)]
struct SendTransactionServiceStatsReport {
    stats: SendTransactionServiceStats,
    last_report: AtomicInterval,
}

impl SendTransactionServiceStatsReport {
    /// report metrics of the send transaction service
    fn report(&self) {
        if self
            .last_report
            .should_update(SEND_TRANSACTION_METRICS_REPORT_RATE_MS)
        {
            datapoint_info!(
                "send_transaction_service",
                (
                    "recv-tx",
                    self.stats.received_transactions.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "recv-duplicate",
                    self.stats
                        .received_duplicate_transactions
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "sent-tx",
                    self.stats.sent_transactions.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "retry-queue-overflow",
                    self.stats.retry_queue_overflow.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "retry-queue-size",
                    self.stats.retry_queue_size.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "send-us",
                    self.stats.send_us.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "send-attempt-count",
                    self.stats.send_attempt_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "send-failure-count",
                    self.stats.send_failure_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "nonced-tx",
                    self.stats.nonced_transactions.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "rooted-tx",
                    self.stats.rooted_transactions.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "expired-tx",
                    self.stats.expired_transactions.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "max-retries-exceeded-tx",
                    self.stats
                        .transactions_exceeding_max_retries
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "retries",
                    self.stats.retries.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "failed-tx",
                    self.stats.failed_transactions.swap(0, Ordering::Relaxed),
                    i64
                )
            );
        }
    }
}

/// Report the send transaction memtrics for every 5 seconds.
const SEND_TRANSACTION_METRICS_REPORT_RATE_MS: u64 = 5000;

impl SendTransactionService {
    pub fn new<T: TpuInfo + std::marker::Send + 'static>(
        tpu_address: SocketAddr,
        bank_forks: &Arc<RwLock<BankForks>>,
        leader_info: Option<T>,
        receiver: Receiver<TransactionInfo>,
        connection_cache: &Arc<ConnectionCache>,
        retry_rate_ms: u64,
        leader_forward_count: u64,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let config = Config {
            retry_rate_ms,
            leader_forward_count,
            ..Config::default()
        };
        Self::new_with_config(
            tpu_address,
            bank_forks,
            leader_info,
            receiver,
            connection_cache,
            config,
            exit,
        )
    }

    pub fn new_with_config<T: TpuInfo + std::marker::Send + 'static>(
        tpu_address: SocketAddr,
        bank_forks: &Arc<RwLock<BankForks>>,
        leader_info: Option<T>,
        receiver: Receiver<TransactionInfo>,
        connection_cache: &Arc<ConnectionCache>,
        config: Config,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let stats_report = Arc::new(SendTransactionServiceStatsReport::default());

        let retry_transactions = Arc::new(Mutex::new(HashMap::new()));

        let leader_info_provider = Arc::new(Mutex::new(CurrentLeaderInfo::new(leader_info)));

        let receive_txn_thread = Self::receive_txn_thread(
            tpu_address,
            receiver,
            leader_info_provider.clone(),
            connection_cache.clone(),
            config.clone(),
            retry_transactions.clone(),
            stats_report.clone(),
            exit.clone(),
        );

        let retry_thread = Self::retry_thread(
            tpu_address,
            bank_forks.clone(),
            leader_info_provider,
            connection_cache.clone(),
            config,
            retry_transactions,
            stats_report,
            exit.clone(),
        );
        Self {
            receive_txn_thread,
            retry_thread,
            exit,
        }
    }

    /// Thread responsible for receiving transactions from RPC clients.
    fn receive_txn_thread<T: TpuInfo + std::marker::Send + 'static>(
        tpu_address: SocketAddr,
        receiver: Receiver<TransactionInfo>,
        leader_info_provider: Arc<Mutex<CurrentLeaderInfo<T>>>,
        connection_cache: Arc<ConnectionCache>,
        config: Config,
        retry_transactions: Arc<Mutex<HashMap<Signature, TransactionInfo>>>,
        stats_report: Arc<SendTransactionServiceStatsReport>,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let mut last_batch_sent = Instant::now();
        let mut transactions = HashMap::new();

        info!(
            "Starting send-transaction-service::receive_txn_thread with config {:?}",
            config
        );
        Builder::new()
            .name("solStxReceive".to_string())
            .spawn(move || loop {
                let recv_timeout_ms = config.batch_send_rate_ms;
                let stats = &stats_report.stats;
                let recv_result = receiver.recv_timeout(Duration::from_millis(recv_timeout_ms));
                if exit.load(Ordering::Relaxed) {
                    break;
                }
                match recv_result {
                    Err(RecvTimeoutError::Disconnected) => {
                        info!("Terminating send-transaction-service.");
                        exit.store(true, Ordering::Relaxed);
                        break;
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Ok(transaction_info) => {
                        stats.received_transactions.fetch_add(1, Ordering::Relaxed);
                        let entry = transactions.entry(transaction_info.signature);
                        let mut new_transaction = false;
                        if let Entry::Vacant(_) = entry {
                            if !retry_transactions
                                .lock()
                                .unwrap()
                                .contains_key(&transaction_info.signature)
                            {
                                entry.or_insert(transaction_info);
                                new_transaction = true;
                            }
                        }
                        if !new_transaction {
                            stats
                                .received_duplicate_transactions
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                if (!transactions.is_empty()
                    && last_batch_sent.elapsed().as_millis() as u64 >= config.batch_send_rate_ms)
                    || transactions.len() >= config.batch_size
                {
                    stats
                        .sent_transactions
                        .fetch_add(transactions.len() as u64, Ordering::Relaxed);
                    Self::send_transactions_in_batch(
                        &tpu_address,
                        &mut transactions,
                        leader_info_provider.lock().unwrap().get_leader_info(),
                        &connection_cache,
                        &config,
                        stats,
                    );
                    let last_sent_time = Instant::now();
                    {
                        // take a lock of retry_transactions and move the batch to the retry set.
                        let mut retry_transactions = retry_transactions.lock().unwrap();
                        let transactions_to_retry = transactions.len();
                        let mut transactions_added_to_retry: usize = 0;
                        for (signature, mut transaction_info) in transactions.drain() {
                            let retry_len = retry_transactions.len();
                            let entry = retry_transactions.entry(signature);
                            if let Entry::Vacant(_) = entry {
                                if retry_len >= MAX_TRANSACTION_QUEUE_SIZE {
                                    datapoint_warn!("send_transaction_service-queue-overflow");
                                    break;
                                } else {
                                    transaction_info.last_sent_time = Some(last_sent_time);
                                    saturating_add_assign!(transactions_added_to_retry, 1);
                                    entry.or_insert(transaction_info);
                                }
                            }
                        }
                        stats.retry_queue_overflow.fetch_add(
                            transactions_to_retry.saturating_sub(transactions_added_to_retry)
                                as u64,
                            Ordering::Relaxed,
                        );
                        stats
                            .retry_queue_size
                            .store(retry_transactions.len() as u64, Ordering::Relaxed);
                    }
                    last_batch_sent = Instant::now();
                }
                stats_report.report();
            })
            .unwrap()
    }

    /// Thread responsible for retrying transactions
    fn retry_thread<T: TpuInfo + std::marker::Send + 'static>(
        tpu_address: SocketAddr,
        bank_forks: Arc<RwLock<BankForks>>,
        leader_info_provider: Arc<Mutex<CurrentLeaderInfo<T>>>,
        connection_cache: Arc<ConnectionCache>,
        config: Config,
        retry_transactions: Arc<Mutex<HashMap<Signature, TransactionInfo>>>,
        stats_report: Arc<SendTransactionServiceStatsReport>,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        info!(
            "Starting send-transaction-service::retry_thread with config {:?}",
            config
        );
        Builder::new()
            .name("solStxRetry".to_string())
            .spawn(move || loop {
                let retry_interval_ms = config.retry_rate_ms;
                let stats = &stats_report.stats;
                sleep(Duration::from_millis(
                    MAX_RETRY_SLEEP_MS.min(retry_interval_ms),
                ));
                if exit.load(Ordering::Relaxed) {
                    break;
                }
                let mut transactions = retry_transactions.lock().unwrap();
                if !transactions.is_empty() {
                    stats
                        .retry_queue_size
                        .store(transactions.len() as u64, Ordering::Relaxed);
                    let (root_bank, working_bank) = {
                        let bank_forks = bank_forks.read().unwrap();
                        (
                            bank_forks.root_bank().clone(),
                            bank_forks.working_bank().clone(),
                        )
                    };

                    let _result = Self::process_transactions(
                        &working_bank,
                        &root_bank,
                        &tpu_address,
                        &mut transactions,
                        &leader_info_provider,
                        &connection_cache,
                        &config,
                        stats,
                    );
                    stats_report.report();
                }
            })
            .unwrap()
    }

    /// Process transactions in batch.
    fn send_transactions_in_batch<T: TpuInfo>(
        tpu_address: &SocketAddr,
        transactions: &mut HashMap<Signature, TransactionInfo>,
        leader_info: Option<&T>,
        connection_cache: &Arc<ConnectionCache>,
        config: &Config,
        stats: &SendTransactionServiceStats,
    ) {
        // Processing the transactions in batch
        let addresses = Self::get_tpu_addresses(tpu_address, leader_info, config);

        let wire_transactions = transactions
            .iter()
            .map(|(_, transaction_info)| transaction_info.wire_transaction.as_ref())
            .collect::<Vec<&[u8]>>();

        for address in &addresses {
            Self::send_transactions(address, &wire_transactions, connection_cache, stats);
        }
    }

    /// Retry transactions sent before.
    fn process_transactions<T: TpuInfo + std::marker::Send + 'static>(
        working_bank: &Arc<Bank>,
        root_bank: &Arc<Bank>,
        tpu_address: &SocketAddr,
        transactions: &mut HashMap<Signature, TransactionInfo>,
        leader_info_provider: &Arc<Mutex<CurrentLeaderInfo<T>>>,
        connection_cache: &Arc<ConnectionCache>,
        config: &Config,
        stats: &SendTransactionServiceStats,
    ) -> ProcessTransactionsResult {
        let mut result = ProcessTransactionsResult::default();

        let mut batched_transactions = HashSet::new();
        let retry_rate = Duration::from_millis(config.retry_rate_ms);

        transactions.retain(|signature, mut transaction_info| {
            if transaction_info.durable_nonce_info.is_some() {
                stats.nonced_transactions.fetch_add(1, Ordering::Relaxed);
            }
            if root_bank.has_signature(signature) {
                info!("Transaction is rooted: {}", signature);
                result.rooted += 1;
                stats.rooted_transactions.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            let signature_status = working_bank.get_signature_status_slot(signature);
            if let Some((nonce_pubkey, durable_nonce)) = transaction_info.durable_nonce_info {
                let nonce_account = working_bank.get_account(&nonce_pubkey).unwrap_or_default();
                let now = Instant::now();
                let expired = transaction_info
                    .last_sent_time
                    .map(|last| now.duration_since(last) >= retry_rate)
                    .unwrap_or(false);
                let verify_nonce_account =
                    nonce_account::verify_nonce_account(&nonce_account, &durable_nonce);
                if verify_nonce_account.is_none() && signature_status.is_none() && expired {
                    info!("Dropping expired durable-nonce transaction: {}", signature);
                    result.expired += 1;
                    stats.expired_transactions.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
            if transaction_info.last_valid_block_height < root_bank.block_height() {
                info!("Dropping expired transaction: {}", signature);
                result.expired += 1;
                stats.expired_transactions.fetch_add(1, Ordering::Relaxed);
                return false;
            }

            let max_retries = transaction_info
                .max_retries
                .or(config.default_max_retries)
                .map(|max_retries| max_retries.min(config.service_max_retries));

            if let Some(max_retries) = max_retries {
                if transaction_info.retries >= max_retries {
                    info!("Dropping transaction due to max retries: {}", signature);
                    result.max_retries_elapsed += 1;
                    stats
                        .transactions_exceeding_max_retries
                        .fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }

            match signature_status {
                None => {
                    let now = Instant::now();
                    let need_send = transaction_info
                        .last_sent_time
                        .map(|last| now.duration_since(last) >= retry_rate)
                        .unwrap_or(true);
                    if need_send {
                        if transaction_info.last_sent_time.is_some() {
                            // Transaction sent before is unknown to the working bank, it might have been
                            // dropped or landed in another fork.  Re-send it

                            info!("Retrying transaction: {}", signature);
                            result.retried += 1;
                            transaction_info.retries += 1;
                            stats.retries.fetch_add(1, Ordering::Relaxed);
                        }

                        batched_transactions.insert(*signature);
                        transaction_info.last_sent_time = Some(now);
                    }
                    true
                }
                Some((_slot, status)) => {
                    if status.is_err() {
                        info!("Dropping failed transaction: {}", signature);
                        result.failed += 1;
                        stats.failed_transactions.fetch_add(1, Ordering::Relaxed);
                        false
                    } else {
                        result.retained += 1;
                        true
                    }
                }
            }
        });

        if !batched_transactions.is_empty() {
            // Processing the transactions in batch
            let wire_transactions = transactions
                .iter()
                .filter(|(signature, _)| batched_transactions.contains(signature))
                .map(|(_, transaction_info)| transaction_info.wire_transaction.as_ref())
                .collect::<Vec<&[u8]>>();

            let iter = wire_transactions.chunks(config.batch_size);
            for chunk in iter {
                let mut leader_info_provider = leader_info_provider.lock().unwrap();
                let leader_info = leader_info_provider.get_leader_info();
                let addresses = Self::get_tpu_addresses(tpu_address, leader_info, config);

                for address in &addresses {
                    Self::send_transactions(address, chunk, connection_cache, stats);
                }
            }
        }
        result
    }

    fn send_transaction(
        tpu_address: &SocketAddr,
        wire_transaction: &[u8],
        connection_cache: &Arc<ConnectionCache>,
    ) -> Result<(), TransportError> {
        let conn = connection_cache.get_connection(tpu_address);
        conn.send_data_async(wire_transaction.to_vec())
    }

    fn send_transactions_with_metrics(
        tpu_address: &SocketAddr,
        wire_transactions: &[&[u8]],
        connection_cache: &Arc<ConnectionCache>,
    ) -> Result<(), TransportError> {
        let wire_transactions = wire_transactions.iter().map(|t| t.to_vec()).collect();
        let conn = connection_cache.get_connection(tpu_address);
        conn.send_data_batch_async(wire_transactions)
    }

    fn send_transactions(
        tpu_address: &SocketAddr,
        wire_transactions: &[&[u8]],
        connection_cache: &Arc<ConnectionCache>,
        stats: &SendTransactionServiceStats,
    ) {
        let mut measure = Measure::start("send-us");
        let result = if wire_transactions.len() == 1 {
            Self::send_transaction(tpu_address, wire_transactions[0], connection_cache)
        } else {
            Self::send_transactions_with_metrics(tpu_address, wire_transactions, connection_cache)
        };

        if let Err(err) = result {
            warn!(
                "Failed to send transaction transaction to {}: {:?}",
                tpu_address, err
            );
            stats.send_failure_count.fetch_add(1, Ordering::Relaxed);
        }

        measure.stop();
        stats.send_us.fetch_add(measure.as_us(), Ordering::Relaxed);
        stats.send_attempt_count.fetch_add(1, Ordering::Relaxed);
    }

    fn get_tpu_addresses<'a, T: TpuInfo>(
        tpu_address: &'a SocketAddr,
        leader_info: Option<&'a T>,
        config: &'a Config,
    ) -> Vec<&'a SocketAddr> {
        let addresses = leader_info
            .as_ref()
            .map(|leader_info| leader_info.get_leader_tpus(config.leader_forward_count));
        addresses
            .map(|address_list| {
                if address_list.is_empty() {
                    vec![tpu_address]
                } else {
                    address_list
                }
            })
            .unwrap_or_else(|| vec![tpu_address])
    }

    pub fn join(self) -> thread::Result<()> {
        self.receive_txn_thread.join()?;
        self.exit.store(true, Ordering::Relaxed);
        self.retry_thread.join()
    }
}
