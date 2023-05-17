//! The `pubsub` module implements a threaded subscription service on client RPC request

use {
    crate::{
        optimistically_confirmed_bank_tracker::OptimisticallyConfirmedBank,
        parsed_token_accounts::{get_parsed_token_account, get_parsed_token_accounts},
        rpc_pubsub_service::PubSubConfig,
        rpc_subscription_tracker::{
            AccountSubscriptionParams, BlockSubscriptionKind, BlockSubscriptionParams,
            LogsSubscriptionKind, LogsSubscriptionParams, ProgramSubscriptionParams,
            SignatureSubscriptionParams, SubscriptionControl, SubscriptionId, SubscriptionInfo,
            SubscriptionParams, SubscriptionsTracker,
        },
    },
    crossbeam_channel::{Receiver, RecvTimeoutError, SendError, Sender},
    itertools::Either,
    rayon::prelude::*,
    serde::Serialize,
    solana_account_decoder::{parse_token::is_known_spl_token_id, UiAccount, UiAccountEncoding},
    solana_ledger::{blockstore::Blockstore, get_tmp_ledger_path},
    solana_measure::measure::Measure,
    solana_rayon_threadlimit::get_thread_count,
    solana_rpc_client_api::response::{
        ProcessedSignatureResult, ReceivedSignatureResult, Response as RpcResponse, RpcBlockUpdate,
        RpcBlockUpdateError, RpcKeyedAccount, RpcLogsResponse, RpcResponseContext,
        RpcSignatureResult, RpcVote, SlotInfo, SlotUpdate,
    },
    solana_runtime::{
        bank::{Bank, TransactionLogInfo},
        bank_forks::BankForks,
        commitment::{BlockCommitmentCache, CommitmentSlots},
        vote_transaction::VoteTransaction,
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        clock::Slot,
        pubkey::Pubkey,
        signature::Signature,
        timing::timestamp,
        transaction,
    },
    solana_transaction_status::{
        BlockEncodingOptions, ConfirmedBlock, EncodeError, VersionedConfirmedBlock,
    },
    std::{
        cell::RefCell,
        collections::{HashMap, VecDeque},
        io::Cursor,
        str,
        sync::{
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
            Arc, Mutex, RwLock, Weak,
        },
        thread::{Builder, JoinHandle},
        time::{Duration, Instant},
    },
    tokio::sync::broadcast,
};

const RECEIVE_DELAY_MILLIS: u64 = 100;

fn get_transaction_logs(
    bank: &Bank,
    params: &LogsSubscriptionParams,
) -> Option<Vec<TransactionLogInfo>> {
    let pubkey = match &params.kind {
        LogsSubscriptionKind::All | LogsSubscriptionKind::AllWithVotes => None,
        LogsSubscriptionKind::Single(pubkey) => Some(pubkey),
    };
    let mut logs = bank.get_transaction_logs(pubkey);
    if matches!(params.kind, LogsSubscriptionKind::All) {
        // Filter out votes if the subscriber doesn't want them
        if let Some(logs) = &mut logs {
            logs.retain(|log| !log.is_vote);
        }
    }
    logs
}
#[derive(Debug)]
pub struct TimestampedNotificationEntry {
    pub entry: NotificationEntry,
    pub queued_at: Instant,
}

impl From<NotificationEntry> for TimestampedNotificationEntry {
    fn from(entry: NotificationEntry) -> Self {
        TimestampedNotificationEntry {
            entry,
            queued_at: Instant::now(),
        }
    }
}

pub enum NotificationEntry {
    Slot(SlotInfo),
    SlotUpdate(SlotUpdate),
    Vote((Pubkey, VoteTransaction, Signature)),
    Root(Slot),
    Bank(CommitmentSlots),
    Gossip(Slot),
    SignaturesReceived((Slot, Vec<Signature>)),
    Subscribed(SubscriptionParams, SubscriptionId),
    Unsubscribed(SubscriptionParams, SubscriptionId),
}

impl std::fmt::Debug for NotificationEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            NotificationEntry::Root(root) => write!(f, "Root({root})"),
            NotificationEntry::Vote(vote) => write!(f, "Vote({vote:?})"),
            NotificationEntry::Slot(slot_info) => write!(f, "Slot({slot_info:?})"),
            NotificationEntry::SlotUpdate(slot_update) => {
                write!(f, "SlotUpdate({slot_update:?})")
            }
            NotificationEntry::Bank(commitment_slots) => {
                write!(f, "Bank({{slot: {:?}}})", commitment_slots.slot)
            }
            NotificationEntry::SignaturesReceived(slot_signatures) => {
                write!(f, "SignaturesReceived({slot_signatures:?})")
            }
            NotificationEntry::Gossip(slot) => write!(f, "Gossip({slot:?})"),
            NotificationEntry::Subscribed(params, id) => {
                write!(f, "Subscribed({params:?}, {id:?})")
            }
            NotificationEntry::Unsubscribed(params, id) => {
                write!(f, "Unsubscribed({params:?}, {id:?})")
            }
        }
    }
}

#[allow(clippy::type_complexity)]
fn check_commitment_and_notify<P, S, B, F, X, I>(
    params: &P,
    subscription: &SubscriptionInfo,
    bank_forks: &Arc<RwLock<BankForks>>,
    slot: Slot,
    bank_method: B,
    filter_results: F,
    notifier: &RpcNotifier,
    is_final: bool,
) -> bool
where
    S: Clone + Serialize,
    B: Fn(&Bank, &P) -> X,
    F: Fn(X, &P, Slot, Arc<Bank>) -> (I, Slot),
    X: Clone + Default,
    I: IntoIterator<Item = S>,
{
    let mut notified = false;
    let bank = bank_forks.read().unwrap().get(slot);
    if let Some(bank) = bank {
        let results = bank_method(&bank, params);
        let mut w_last_notified_slot = subscription.last_notified_slot.write().unwrap();
        let (filter_results, result_slot) =
            filter_results(results, params, *w_last_notified_slot, bank);
        for result in filter_results {
            notifier.notify(
                RpcResponse::from(RpcNotificationResponse {
                    context: RpcNotificationContext { slot },
                    value: result,
                }),
                subscription,
                is_final,
            );
            *w_last_notified_slot = result_slot;
            notified = true;
        }
    }

    notified
}

#[derive(Debug, Clone)]
pub struct RpcNotification {
    pub subscription_id: SubscriptionId,
    pub is_final: bool,
    pub json: Weak<String>,
    pub created_at: Instant,
}

#[derive(Debug, Clone, PartialEq)]
struct RpcNotificationResponse<T> {
    context: RpcNotificationContext,
    value: T,
}

impl<T> From<RpcNotificationResponse<T>> for RpcResponse<T> {
    fn from(notification: RpcNotificationResponse<T>) -> Self {
        let RpcNotificationResponse {
            context: RpcNotificationContext { slot },
            value,
        } = notification;
        Self {
            context: RpcResponseContext {
                slot,
                api_version: None,
            },
            value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RpcNotificationContext {
    slot: Slot,
}

const RPC_NOTIFICATIONS_METRICS_SUBMISSION_INTERVAL_MS: Duration = Duration::from_millis(2_000);

struct RecentItems {
    queue: VecDeque<Arc<String>>,
    total_bytes: usize,
    max_len: usize,
    max_total_bytes: usize,
    last_metrics_submission: Instant,
}

impl RecentItems {
    fn new(max_len: usize, max_total_bytes: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            total_bytes: 0,
            max_len,
            max_total_bytes,
            last_metrics_submission: Instant::now(),
        }
    }

    fn push(&mut self, item: Arc<String>) {
        self.total_bytes = self
            .total_bytes
            .checked_add(item.len())
            .expect("total bytes overflow");
        self.queue.push_back(item);

        while self.total_bytes > self.max_total_bytes || self.queue.len() > self.max_len {
            let item = self.queue.pop_front().expect("can't be empty");
            self.total_bytes = self
                .total_bytes
                .checked_sub(item.len())
                .expect("total bytes underflow");
        }

        let now = Instant::now();
        let last_metrics_ago = now.duration_since(self.last_metrics_submission);
        if last_metrics_ago > RPC_NOTIFICATIONS_METRICS_SUBMISSION_INTERVAL_MS {
            datapoint_info!(
                "rpc_subscriptions_recent_items",
                ("num", self.queue.len(), i64),
                ("total_bytes", self.total_bytes, i64),
            );
            self.last_metrics_submission = now;
        } else {
            trace!(
                "rpc_subscriptions_recent_items num={} total_bytes={}",
                self.queue.len(),
                self.total_bytes,
            );
        }
    }
}

struct RpcNotifier {
    sender: broadcast::Sender<RpcNotification>,
    recent_items: Mutex<RecentItems>,
}

thread_local! {
    static RPC_NOTIFIER_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

#[derive(Debug, Serialize)]
struct NotificationParams<T> {
    result: T,
    subscription: SubscriptionId,
}

#[derive(Debug, Serialize)]
struct Notification<T> {
    jsonrpc: Option<jsonrpc_core::Version>,
    method: &'static str,
    params: NotificationParams<T>,
}

impl RpcNotifier {
    fn notify<T>(&self, value: T, subscription: &SubscriptionInfo, is_final: bool)
    where
        T: serde::Serialize,
    {
        let buf_arc = RPC_NOTIFIER_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            let notification = Notification {
                jsonrpc: Some(jsonrpc_core::Version::V2),
                method: subscription.method(),
                params: NotificationParams {
                    result: value,
                    subscription: subscription.id(),
                },
            };
            serde_json::to_writer(Cursor::new(&mut *buf), &notification)
                .expect("serialization never fails");
            let buf_str = str::from_utf8(&buf).expect("json is always utf-8");
            Arc::new(String::from(buf_str))
        });

        let notification = RpcNotification {
            subscription_id: subscription.id(),
            json: Arc::downgrade(&buf_arc),
            is_final,
            created_at: Instant::now(),
        };
        // There is an unlikely case where this can fail: if the last subscription is closed
        // just as the notifier generates a notification for it.
        let _ = self.sender.send(notification);

        inc_new_counter_info!("rpc-pubsub-messages", 1);
        inc_new_counter_info!("rpc-pubsub-bytes", buf_arc.len());

        self.recent_items.lock().unwrap().push(buf_arc);
    }
}

fn filter_block_result_txs(
    mut block: VersionedConfirmedBlock,
    last_modified_slot: Slot,
    params: &BlockSubscriptionParams,
) -> Result<Option<RpcBlockUpdate>, RpcBlockUpdateError> {
    block.transactions = match params.kind {
        BlockSubscriptionKind::All => block.transactions,
        BlockSubscriptionKind::MentionsAccountOrProgram(pk) => block
            .transactions
            .into_iter()
            .filter(|tx| tx.account_keys().iter().any(|key| key == &pk))
            .collect(),
    };

    if block.transactions.is_empty() {
        if let BlockSubscriptionKind::MentionsAccountOrProgram(_) = params.kind {
            return Ok(None);
        }
    }

    let block = ConfirmedBlock::from(block)
        .encode_with_options(
            params.encoding,
            BlockEncodingOptions {
                transaction_details: params.transaction_details,
                show_rewards: params.show_rewards,
                max_supported_transaction_version: params.max_supported_transaction_version,
            },
        )
        .map_err(|err| match err {
            EncodeError::UnsupportedTransactionVersion(version) => {
                RpcBlockUpdateError::UnsupportedTransactionVersion(version)
            }
        })?;

    // If last_modified_slot < last_notified_slot, then the last notif was for a fork.
    // That's the risk clients take when subscribing to non-finalized commitments.
    // This code lets the logic for dealing with forks live on the client side.
    Ok(Some(RpcBlockUpdate {
        slot: last_modified_slot,
        block: Some(block),
        err: None,
    }))
}

fn filter_account_result(
    result: Option<(AccountSharedData, Slot)>,
    params: &AccountSubscriptionParams,
    last_notified_slot: Slot,
    bank: Arc<Bank>,
) -> (Option<UiAccount>, Slot) {
    // If the account is not found, `last_modified_slot` will default to zero and
    // we will notify clients that the account no longer exists if we haven't already
    let (account, last_modified_slot) = result.unwrap_or_default();

    // If last_modified_slot < last_notified_slot this means that we last notified for a fork
    // and should notify that the account state has been reverted.
    let account = (last_modified_slot != last_notified_slot).then(|| {
        if is_known_spl_token_id(account.owner())
            && params.encoding == UiAccountEncoding::JsonParsed
        {
            get_parsed_token_account(bank, &params.pubkey, account)
        } else {
            UiAccount::encode(&params.pubkey, &account, params.encoding, None, None)
        }
    });
    (account, last_modified_slot)
}

fn filter_signature_result(
    result: Option<transaction::Result<()>>,
    _params: &SignatureSubscriptionParams,
    last_notified_slot: Slot,
    _bank: Arc<Bank>,
) -> (Option<RpcSignatureResult>, Slot) {
    (
        result.map(|result| {
            RpcSignatureResult::ProcessedSignature(ProcessedSignatureResult { err: result.err() })
        }),
        last_notified_slot,
    )
}

fn filter_program_results(
    accounts: Vec<(Pubkey, AccountSharedData)>,
    params: &ProgramSubscriptionParams,
    last_notified_slot: Slot,
    bank: Arc<Bank>,
) -> (impl Iterator<Item = RpcKeyedAccount>, Slot) {
    let accounts_is_empty = accounts.is_empty();
    let encoding = params.encoding;
    let filters = params.filters.clone();
    let keyed_accounts = accounts.into_iter().filter(move |(_, account)| {
        filters
            .iter()
            .all(|filter_type| filter_type.allows(account))
    });
    let accounts = if is_known_spl_token_id(&params.pubkey)
        && params.encoding == UiAccountEncoding::JsonParsed
        && !accounts_is_empty
    {
        let accounts = get_parsed_token_accounts(bank, keyed_accounts);
        Either::Left(accounts)
    } else {
        let accounts = keyed_accounts.map(move |(pubkey, account)| RpcKeyedAccount {
            pubkey: pubkey.to_string(),
            account: UiAccount::encode(&pubkey, &account, encoding, None, None),
        });
        Either::Right(accounts)
    };
    (accounts, last_notified_slot)
}

fn filter_logs_results(
    logs: Option<Vec<TransactionLogInfo>>,
    _params: &LogsSubscriptionParams,
    last_notified_slot: Slot,
    _bank: Arc<Bank>,
) -> (impl Iterator<Item = RpcLogsResponse>, Slot) {
    let responses = logs.into_iter().flatten().map(|log| RpcLogsResponse {
        signature: log.signature.to_string(),
        err: log.result.err(),
        logs: log.log_messages,
    });
    (responses, last_notified_slot)
}

fn initial_last_notified_slot(
    params: &SubscriptionParams,
    bank_forks: &RwLock<BankForks>,
    block_commitment_cache: &RwLock<BlockCommitmentCache>,
    optimistically_confirmed_bank: &RwLock<OptimisticallyConfirmedBank>,
) -> Option<Slot> {
    match params {
        SubscriptionParams::Account(params) => {
            let slot = if params.commitment.is_finalized() {
                block_commitment_cache
                    .read()
                    .unwrap()
                    .highest_confirmed_root()
            } else if params.commitment.is_confirmed() {
                optimistically_confirmed_bank.read().unwrap().bank.slot()
            } else {
                block_commitment_cache.read().unwrap().slot()
            };

            let bank = bank_forks.read().unwrap().get(slot)?;
            Some(bank.get_account_modified_slot(&params.pubkey)?.1)
        }
        _ => None,
    }
}

#[derive(Default)]
struct PubsubNotificationStats {
    since: Option<Instant>,
    notification_entry_processing_count: u64,
    notification_entry_processing_time_us: u64,
}

impl PubsubNotificationStats {
    fn maybe_submit(&mut self) {
        const SUBMIT_CADENCE: Duration = RPC_NOTIFICATIONS_METRICS_SUBMISSION_INTERVAL_MS;
        let elapsed = self.since.as_ref().map(Instant::elapsed);
        if elapsed.unwrap_or(Duration::MAX) < SUBMIT_CADENCE {
            return;
        }
        datapoint_info!(
            "pubsub_notification_entries",
            (
                "notification_entry_processing_count",
                self.notification_entry_processing_count,
                i64
            ),
            (
                "notification_entry_processing_time_us",
                self.notification_entry_processing_time_us,
                i64
            ),
        );
        *self = Self {
            since: Some(Instant::now()),
            ..Self::default()
        };
    }
}

pub struct RpcSubscriptions {
    notification_sender: Option<Sender<TimestampedNotificationEntry>>,
    t_cleanup: Option<JoinHandle<()>>,

    exit: Arc<AtomicBool>,
    control: SubscriptionControl,
}

impl Drop for RpcSubscriptions {
    fn drop(&mut self) {
        self.shutdown().unwrap_or_else(|err| {
            warn!("RPC Notification - shutdown error: {:?}", err);
        });
    }
}

impl RpcSubscriptions {
    pub fn new(
        exit: &Arc<AtomicBool>,
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        max_complete_rewards_slot: Arc<AtomicU64>,
        blockstore: Arc<Blockstore>,
        bank_forks: Arc<RwLock<BankForks>>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
    ) -> Self {
        Self::new_with_config(
            exit,
            max_complete_transaction_status_slot,
            max_complete_rewards_slot,
            blockstore,
            bank_forks,
            block_commitment_cache,
            optimistically_confirmed_bank,
            &PubSubConfig::default(),
            None,
        )
    }

    pub fn new_for_tests(
        exit: &Arc<AtomicBool>,
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        max_complete_rewards_slot: Arc<AtomicU64>,
        bank_forks: Arc<RwLock<BankForks>>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
    ) -> Self {
        let ledger_path = get_tmp_ledger_path!();
        let blockstore = Blockstore::open(&ledger_path).unwrap();
        let blockstore = Arc::new(blockstore);

        Self::new_for_tests_with_blockstore(
            exit,
            max_complete_transaction_status_slot,
            max_complete_rewards_slot,
            blockstore,
            bank_forks,
            block_commitment_cache,
            optimistically_confirmed_bank,
        )
    }

    pub fn new_for_tests_with_blockstore(
        exit: &Arc<AtomicBool>,
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        max_complete_rewards_slot: Arc<AtomicU64>,
        blockstore: Arc<Blockstore>,
        bank_forks: Arc<RwLock<BankForks>>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
    ) -> Self {
        let rpc_notifier_ready = Arc::new(AtomicBool::new(false));

        let rpc_subscriptions = Self::new_with_config(
            exit,
            max_complete_transaction_status_slot,
            max_complete_rewards_slot,
            blockstore,
            bank_forks,
            block_commitment_cache,
            optimistically_confirmed_bank,
            &PubSubConfig::default_for_tests(),
            Some(rpc_notifier_ready.clone()),
        );

        // Ensure RPC notifier is ready to receive notifications before proceeding
        let start_time = Instant::now();
        loop {
            if rpc_notifier_ready.load(Ordering::Relaxed) {
                break;
            } else if (Instant::now() - start_time).as_millis() > 5000 {
                panic!("RPC notifier thread setup took too long");
            }
        }

        rpc_subscriptions
    }

    pub fn new_with_config(
        exit: &Arc<AtomicBool>,
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        max_complete_rewards_slot: Arc<AtomicU64>,
        blockstore: Arc<Blockstore>,
        bank_forks: Arc<RwLock<BankForks>>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
        config: &PubSubConfig,
        rpc_notifier_ready: Option<Arc<AtomicBool>>,
    ) -> Self {
        let (notification_sender, notification_receiver) = crossbeam_channel::unbounded();

        let exit_clone = exit.clone();
        let subscriptions = SubscriptionsTracker::new(bank_forks.clone());

        let (broadcast_sender, _) = broadcast::channel(config.queue_capacity_items);

        let notifier = RpcNotifier {
            sender: broadcast_sender.clone(),
            recent_items: Mutex::new(RecentItems::new(
                config.queue_capacity_items,
                config.queue_capacity_bytes,
            )),
        };
        let notification_threads = config.notification_threads.unwrap_or_else(get_thread_count);
        let t_cleanup = if notification_threads == 0 {
            None
        } else {
            Some(
                Builder::new()
                    .name("solRpcNotifier".to_string())
                    .spawn(move || {
                        let pool = rayon::ThreadPoolBuilder::new()
                            .num_threads(notification_threads)
                            .thread_name(|i| format!("solRpcNotify{i:02}"))
                            .build()
                            .unwrap();
                        pool.install(|| {
                            if let Some(rpc_notifier_ready) = rpc_notifier_ready {
                                rpc_notifier_ready.fetch_or(true, Ordering::Relaxed);
                            }
                            Self::process_notifications(
                                exit_clone,
                                max_complete_transaction_status_slot,
                                max_complete_rewards_slot,
                                blockstore,
                                notifier,
                                notification_receiver,
                                subscriptions,
                                bank_forks,
                                block_commitment_cache,
                                optimistically_confirmed_bank,
                            )
                        });
                    })
                    .unwrap(),
            )
        };

        let control = SubscriptionControl::new(
            config.max_active_subscriptions,
            notification_sender.clone(),
            broadcast_sender,
        );

        Self {
            notification_sender: if notification_threads == 0 {
                None
            } else {
                Some(notification_sender)
            },
            t_cleanup,
            exit: exit.clone(),
            control,
        }
    }

    // For tests only...
    pub fn default_with_bank_forks(
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        max_complete_rewards_slot: Arc<AtomicU64>,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> Self {
        let ledger_path = get_tmp_ledger_path!();
        let blockstore = Blockstore::open(&ledger_path).unwrap();
        let blockstore = Arc::new(blockstore);
        let optimistically_confirmed_bank =
            OptimisticallyConfirmedBank::locked_from_bank_forks_root(&bank_forks);
        Self::new(
            &Arc::new(AtomicBool::new(false)),
            max_complete_transaction_status_slot,
            max_complete_rewards_slot,
            blockstore,
            bank_forks,
            Arc::new(RwLock::new(BlockCommitmentCache::default())),
            optimistically_confirmed_bank,
        )
    }

    pub fn control(&self) -> &SubscriptionControl {
        &self.control
    }

    /// Notify subscribers of changes to any accounts or new signatures since
    /// the bank's last checkpoint.
    pub fn notify_subscribers(&self, commitment_slots: CommitmentSlots) {
        self.enqueue_notification(NotificationEntry::Bank(commitment_slots));
    }

    /// Notify Confirmed commitment-level subscribers of changes to any accounts or new
    /// signatures.
    pub fn notify_gossip_subscribers(&self, slot: Slot) {
        self.enqueue_notification(NotificationEntry::Gossip(slot));
    }

    pub fn notify_slot_update(&self, slot_update: SlotUpdate) {
        self.enqueue_notification(NotificationEntry::SlotUpdate(slot_update));
    }

    pub fn notify_slot(&self, slot: Slot, parent: Slot, root: Slot) {
        self.enqueue_notification(NotificationEntry::Slot(SlotInfo { slot, parent, root }));
        self.enqueue_notification(NotificationEntry::SlotUpdate(SlotUpdate::CreatedBank {
            slot,
            parent,
            timestamp: timestamp(),
        }));
    }

    pub fn notify_signatures_received(&self, slot_signatures: (Slot, Vec<Signature>)) {
        self.enqueue_notification(NotificationEntry::SignaturesReceived(slot_signatures));
    }

    pub fn notify_vote(&self, vote_pubkey: Pubkey, vote: VoteTransaction, signature: Signature) {
        self.enqueue_notification(NotificationEntry::Vote((vote_pubkey, vote, signature)));
    }

    pub fn notify_roots(&self, mut rooted_slots: Vec<Slot>) {
        rooted_slots.sort_unstable();
        rooted_slots.into_iter().for_each(|root| {
            self.enqueue_notification(NotificationEntry::SlotUpdate(SlotUpdate::Root {
                slot: root,
                timestamp: timestamp(),
            }));
            self.enqueue_notification(NotificationEntry::Root(root));
        });
    }

    fn enqueue_notification(&self, notification_entry: NotificationEntry) {
        if let Some(ref notification_sender) = self.notification_sender {
            match notification_sender.send(notification_entry.into()) {
                Ok(()) => (),
                Err(SendError(notification)) => {
                    warn!(
                        "Dropped RPC Notification - receiver disconnected : {:?}",
                        notification
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_notifications(
        exit: Arc<AtomicBool>,
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        max_complete_rewards_slot: Arc<AtomicU64>,
        blockstore: Arc<Blockstore>,
        notifier: RpcNotifier,
        notification_receiver: Receiver<TimestampedNotificationEntry>,
        mut subscriptions: SubscriptionsTracker,
        bank_forks: Arc<RwLock<BankForks>>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
    ) {
        let mut stats = PubsubNotificationStats::default();

        loop {
            if exit.load(Ordering::Relaxed) {
                break;
            }
            match notification_receiver.recv_timeout(Duration::from_millis(RECEIVE_DELAY_MILLIS)) {
                Ok(notification_entry) => {
                    let TimestampedNotificationEntry { entry, queued_at } = notification_entry;
                    match entry {
                        NotificationEntry::Subscribed(params, id) => {
                            subscriptions.subscribe(params.clone(), id, || {
                                initial_last_notified_slot(
                                    &params,
                                    &bank_forks,
                                    &block_commitment_cache,
                                    &optimistically_confirmed_bank,
                                )
                                .unwrap_or(0)
                            });
                        }
                        NotificationEntry::Unsubscribed(params, id) => {
                            subscriptions.unsubscribe(params, id);
                        }
                        NotificationEntry::Slot(slot_info) => {
                            if let Some(sub) = subscriptions
                                .node_progress_watchers()
                                .get(&SubscriptionParams::Slot)
                            {
                                debug!("slot notify: {:?}", slot_info);
                                inc_new_counter_info!("rpc-subscription-notify-slot", 1);
                                notifier.notify(slot_info, sub, false);
                            }
                        }
                        NotificationEntry::SlotUpdate(slot_update) => {
                            if let Some(sub) = subscriptions
                                .node_progress_watchers()
                                .get(&SubscriptionParams::SlotsUpdates)
                            {
                                inc_new_counter_info!("rpc-subscription-notify-slots-updates", 1);
                                notifier.notify(slot_update, sub, false);
                            }
                        }
                        // These notifications are only triggered by votes observed on gossip,
                        // unlike `NotificationEntry::Gossip`, which also accounts for slots seen
                        // in VoteState's from bank states built in ReplayStage.
                        NotificationEntry::Vote((vote_pubkey, ref vote_info, signature)) => {
                            if let Some(sub) = subscriptions
                                .node_progress_watchers()
                                .get(&SubscriptionParams::Vote)
                            {
                                let rpc_vote = RpcVote {
                                    vote_pubkey: vote_pubkey.to_string(),
                                    slots: vote_info.slots(),
                                    hash: bs58::encode(vote_info.hash()).into_string(),
                                    timestamp: vote_info.timestamp(),
                                    signature: signature.to_string(),
                                };
                                debug!("vote notify: {:?}", vote_info);
                                inc_new_counter_info!("rpc-subscription-notify-vote", 1);
                                notifier.notify(&rpc_vote, sub, false);
                            }
                        }
                        NotificationEntry::Root(root) => {
                            if let Some(sub) = subscriptions
                                .node_progress_watchers()
                                .get(&SubscriptionParams::Root)
                            {
                                debug!("root notify: {:?}", root);
                                inc_new_counter_info!("rpc-subscription-notify-root", 1);
                                notifier.notify(root, sub, false);
                            }
                        }
                        NotificationEntry::Bank(commitment_slots) => {
                            const SOURCE: &str = "bank";
                            RpcSubscriptions::notify_watchers(
                                max_complete_transaction_status_slot.clone(),
                                max_complete_rewards_slot.clone(),
                                subscriptions.commitment_watchers(),
                                &bank_forks,
                                &blockstore,
                                &commitment_slots,
                                &notifier,
                                SOURCE,
                            );
                        }
                        NotificationEntry::Gossip(slot) => {
                            let commitment_slots = CommitmentSlots {
                                highest_confirmed_slot: slot,
                                ..CommitmentSlots::default()
                            };
                            const SOURCE: &str = "gossip";
                            RpcSubscriptions::notify_watchers(
                                max_complete_transaction_status_slot.clone(),
                                max_complete_rewards_slot.clone(),
                                subscriptions.gossip_watchers(),
                                &bank_forks,
                                &blockstore,
                                &commitment_slots,
                                &notifier,
                                SOURCE,
                            );
                        }
                        NotificationEntry::SignaturesReceived((slot, slot_signatures)) => {
                            for slot_signature in &slot_signatures {
                                if let Some(subs) = subscriptions.by_signature().get(slot_signature)
                                {
                                    for subscription in subs.values() {
                                        if let SubscriptionParams::Signature(params) =
                                            subscription.params()
                                        {
                                            if params.enable_received_notification {
                                                notifier.notify(
                                                    RpcResponse::from(RpcNotificationResponse {
                                                        context: RpcNotificationContext { slot },
                                                        value: RpcSignatureResult::ReceivedSignature(
                                                            ReceivedSignatureResult::ReceivedSignature,
                                                        ),
                                                    }),
                                                    subscription,
                                                    false,
                                                );
                                            }
                                        } else {
                                            error!("invalid params type in visit_by_signature");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    stats.notification_entry_processing_time_us +=
                        queued_at.elapsed().as_micros() as u64;
                    stats.notification_entry_processing_count += 1;
                }
                Err(RecvTimeoutError::Timeout) => {
                    // not a problem - try reading again
                }
                Err(RecvTimeoutError::Disconnected) => {
                    warn!("RPC Notification thread - sender disconnected");
                    break;
                }
            }
            stats.maybe_submit();
        }
    }

    fn notify_watchers(
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        max_complete_rewards_slot: Arc<AtomicU64>,
        subscriptions: &HashMap<SubscriptionId, Arc<SubscriptionInfo>>,
        bank_forks: &Arc<RwLock<BankForks>>,
        blockstore: &Blockstore,
        commitment_slots: &CommitmentSlots,
        notifier: &RpcNotifier,
        source: &'static str,
    ) {
        let mut total_time = Measure::start("notify_watchers");

        let num_accounts_found = AtomicUsize::new(0);
        let num_accounts_notified = AtomicUsize::new(0);

        let num_blocks_found = AtomicUsize::new(0);
        let num_blocks_notified = AtomicUsize::new(0);

        let num_logs_found = AtomicUsize::new(0);
        let num_logs_notified = AtomicUsize::new(0);

        let num_programs_found = AtomicUsize::new(0);
        let num_programs_notified = AtomicUsize::new(0);

        let num_signatures_found = AtomicUsize::new(0);
        let num_signatures_notified = AtomicUsize::new(0);

        let subscriptions = subscriptions.into_par_iter();
        subscriptions.for_each(|(_id, subscription)| {
            let slot = if let Some(commitment) = subscription.commitment() {
                if commitment.is_finalized() {
                    Some(commitment_slots.highest_confirmed_root)
                } else if commitment.is_confirmed() {
                    Some(commitment_slots.highest_confirmed_slot)
                } else {
                    Some(commitment_slots.slot)
                }
            } else {
                error!("missing commitment in notify_watchers");
                None
            };
            match subscription.params() {
                SubscriptionParams::Account(params) => {
                    num_accounts_found.fetch_add(1, Ordering::Relaxed);
                    if let Some(slot) = slot {
                        let notified = check_commitment_and_notify(
                            params,
                            subscription,
                            bank_forks,
                            slot,
                            |bank, params| bank.get_account_modified_slot(&params.pubkey),
                            filter_account_result,
                            notifier,
                            false,
                        );

                        if notified {
                            num_accounts_notified.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                SubscriptionParams::Block(params) => {
                    num_blocks_found.fetch_add(1, Ordering::Relaxed);
                    if let Some(slot) = slot {
                        let bank = bank_forks.read().unwrap().get(slot);
                        if let Some(bank) = bank {
                            // We're calling it unnotified in this context
                            // because, logically, it gets set to `last_notified_slot + 1`
                            // on the final iteration of the loop down below.
                            // This is used to notify blocks for slots that were
                            // potentially missed due to upstream transient errors
                            // that led to this notification not being triggered for
                            // a slot.
                            //
                            // e.g.
                            // notify_watchers is triggered for Slot 1
                            // some time passes
                            // notify_watchers is triggered for Slot 4
                            // this will try to fetch blocks for slots 2, 3, and 4
                            // as long as they are ancestors of `slot`
                            let mut w_last_unnotified_slot =
                                subscription.last_notified_slot.write().unwrap();
                            // would mean it's the first notification for this subscription connection
                            if *w_last_unnotified_slot == 0 {
                                *w_last_unnotified_slot = slot;
                            }
                            let mut slots_to_notify: Vec<_> =
                                (*w_last_unnotified_slot..slot).collect();
                            let ancestors = bank.proper_ancestors_set();
                            slots_to_notify.retain(|slot| ancestors.contains(slot));
                            slots_to_notify.push(slot);
                            for s in slots_to_notify {
                                // To avoid skipping a slot that fails this condition,
                                // caused by non-deterministic concurrency accesses, we
                                // break out of the loop. Besides if the current `s` is
                                // greater, then any `s + K` is also greater.
                                if s > max_complete_transaction_status_slot.load(Ordering::SeqCst)
                                    || s > max_complete_rewards_slot.load(Ordering::SeqCst)
                                {
                                    break;
                                }

                                let block_update_result = blockstore
                                    .get_complete_block(s, false)
                                    .map_err(|e| {
                                        error!("get_complete_block error: {}", e);
                                        RpcBlockUpdateError::BlockStoreError
                                    })
                                    .and_then(|block| filter_block_result_txs(block, s, params));

                                match block_update_result {
                                    Ok(block_update) => {
                                        if let Some(block_update) = block_update {
                                            notifier.notify(
                                                RpcResponse::from(RpcNotificationResponse {
                                                    context: RpcNotificationContext { slot: s },
                                                    value: block_update,
                                                }),
                                                subscription,
                                                false,
                                            );
                                            num_blocks_notified.fetch_add(1, Ordering::Relaxed);
                                            // the next time this subscription is notified it will
                                            // try to fetch all slots between (s + 1) to `slot`, inclusively
                                            *w_last_unnotified_slot = s + 1;
                                        }
                                    }
                                    Err(err) => {
                                        // we don't advance `w_last_unnotified_slot` so that
                                        // it'll retry on the next notification trigger
                                        notifier.notify(
                                            RpcResponse::from(RpcNotificationResponse {
                                                context: RpcNotificationContext { slot: s },
                                                value: RpcBlockUpdate {
                                                    slot,
                                                    block: None,
                                                    err: Some(err),
                                                },
                                            }),
                                            subscription,
                                            false,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                SubscriptionParams::Logs(params) => {
                    num_logs_found.fetch_add(1, Ordering::Relaxed);
                    if let Some(slot) = slot {
                        let notified = check_commitment_and_notify(
                            params,
                            subscription,
                            bank_forks,
                            slot,
                            get_transaction_logs,
                            filter_logs_results,
                            notifier,
                            false,
                        );

                        if notified {
                            num_logs_notified.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                SubscriptionParams::Program(params) => {
                    num_programs_found.fetch_add(1, Ordering::Relaxed);
                    if let Some(slot) = slot {
                        let notified = check_commitment_and_notify(
                            params,
                            subscription,
                            bank_forks,
                            slot,
                            |bank, params| {
                                bank.get_program_accounts_modified_since_parent(&params.pubkey)
                            },
                            filter_program_results,
                            notifier,
                            false,
                        );

                        if notified {
                            num_programs_notified.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                SubscriptionParams::Signature(params) => {
                    num_signatures_found.fetch_add(1, Ordering::Relaxed);
                    if let Some(slot) = slot {
                        let notified = check_commitment_and_notify(
                            params,
                            subscription,
                            bank_forks,
                            slot,
                            |bank, params| {
                                bank.get_signature_status_processed_since_parent(&params.signature)
                            },
                            filter_signature_result,
                            notifier,
                            true, // Unsubscribe.
                        );

                        if notified {
                            num_signatures_notified.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                _ => error!("wrong subscription type in alps map"),
            }
        });

        total_time.stop();

        let total_notified = num_accounts_notified.load(Ordering::Relaxed)
            + num_logs_notified.load(Ordering::Relaxed)
            + num_programs_notified.load(Ordering::Relaxed)
            + num_signatures_notified.load(Ordering::Relaxed);
        let total_ms = total_time.as_ms();
        if total_notified > 0 || total_ms > 10 {
            debug!(
                "notified({}): accounts: {} / {} logs: {} / {} programs: {} / {} signatures: {} / {}",
                source,
                num_accounts_found.load(Ordering::Relaxed),
                num_accounts_notified.load(Ordering::Relaxed),
                num_logs_found.load(Ordering::Relaxed),
                num_logs_notified.load(Ordering::Relaxed),
                num_programs_found.load(Ordering::Relaxed),
                num_programs_notified.load(Ordering::Relaxed),
                num_signatures_found.load(Ordering::Relaxed),
                num_signatures_notified.load(Ordering::Relaxed),
            );
            inc_new_counter_info!("rpc-subscription-notify-bank-or-gossip", total_notified);
            datapoint_info!(
                "rpc_subscriptions",
                ("source", source, String),
                (
                    "num_account_subscriptions",
                    num_accounts_found.load(Ordering::Relaxed),
                    i64
                ),
                (
                    "num_account_pubkeys_notified",
                    num_accounts_notified.load(Ordering::Relaxed),
                    i64
                ),
                (
                    "num_logs_subscriptions",
                    num_logs_found.load(Ordering::Relaxed),
                    i64
                ),
                (
                    "num_logs_notified",
                    num_logs_notified.load(Ordering::Relaxed),
                    i64
                ),
                (
                    "num_program_subscriptions",
                    num_programs_found.load(Ordering::Relaxed),
                    i64
                ),
                (
                    "num_programs_notified",
                    num_programs_notified.load(Ordering::Relaxed),
                    i64
                ),
                (
                    "num_signature_subscriptions",
                    num_signatures_found.load(Ordering::Relaxed),
                    i64
                ),
                (
                    "num_signatures_notified",
                    num_signatures_notified.load(Ordering::Relaxed),
                    i64
                ),
                ("notifications_time", total_time.as_us() as i64, i64),
            );
            inc_new_counter_info!(
                "rpc-subscription-counter-num_accounts_notified",
                num_accounts_notified.load(Ordering::Relaxed)
            );
            inc_new_counter_info!(
                "rpc-subscription-counter-num_logs_notified",
                num_logs_notified.load(Ordering::Relaxed)
            );
            inc_new_counter_info!(
                "rpc-subscription-counter-num_programs_notified",
                num_programs_notified.load(Ordering::Relaxed)
            );
            inc_new_counter_info!(
                "rpc-subscription-counter-num_signatures_notified",
                num_signatures_notified.load(Ordering::Relaxed)
            );
        }
    }

    fn shutdown(&mut self) -> std::thread::Result<()> {
        if self.t_cleanup.is_some() {
            info!("RPC Notification thread - shutting down");
            self.exit.store(true, Ordering::Relaxed);
            let x = self.t_cleanup.take().unwrap().join();
            info!("RPC Notification thread - shut down.");
            x
        } else {
            warn!("RPC Notification thread - already shut down.");
            Ok(())
        }
    }
}
