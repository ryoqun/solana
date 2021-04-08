//! The `bank` module tracks client accounts and the progress of on-chain
//! programs. It offers a high-level API that signs transactions
//! on behalf of the caller, and a low-level API for when they have
//! already been signed and verified.

// this is a bit leaky abstraction, but we have to make distinction between banking/replaying and
// rpc/others
pub use crate::accounts_db::LoadSafety;

use crate::{
    accounts::{
        AccountAddressFilter, Accounts, TransactionAccountDeps, TransactionAccounts,
        TransactionLoadResult, TransactionLoaders,
    },
    accounts_db::{ErrorCounters, SnapshotStorages},
    accounts_index::{AccountIndex, Ancestors, IndexKey},
    blockhash_queue::BlockhashQueue,
    builtins::{self, ActivationType},
    epoch_stakes::{EpochStakes, NodeVoteAccounts},
    inline_spl_token_v2_0,
    instruction_recorder::InstructionRecorder,
    log_collector::LogCollector,
    message_processor::{ExecuteDetailsTimings, Executors, MessageProcessor},
    rent_collector::RentCollector,
    stakes::Stakes,
    status_cache::{SlotDelta, StatusCache},
    system_instruction_processor::{get_system_account_kind, SystemAccountKind},
    transaction_batch::TransactionBatch,
    vote_account::ArcVoteAccount,
};
use byteorder::{ByteOrder, LittleEndian};
use itertools::Itertools;
use log::*;
use rayon::ThreadPool;
use solana_measure::measure::Measure;
use solana_metrics::{datapoint_debug, inc_new_counter_debug, inc_new_counter_info};
use solana_sdk::{
    account::{
        create_account_shared_data_with_fields as create_account, from_account, Account,
        AccountSharedData, InheritableAccountFields, ReadableAccount,
    },
    clock::{
        Epoch, Slot, SlotCount, SlotIndex, UnixTimestamp, DEFAULT_TICKS_PER_SECOND,
        INITIAL_RENT_EPOCH, MAX_PROCESSING_AGE, MAX_RECENT_BLOCKHASHES,
        MAX_TRANSACTION_FORWARDING_DELAY, SECONDS_PER_DAY,
    },
    epoch_info::EpochInfo,
    epoch_schedule::EpochSchedule,
    feature,
    feature_set::{self, FeatureSet},
    fee_calculator::{FeeCalculator, FeeConfig, FeeRateGovernor},
    genesis_config::{ClusterType, GenesisConfig},
    hard_forks::HardForks,
    hash::{extend_and_hash, hashv, Hash},
    incinerator,
    inflation::Inflation,
    instruction::CompiledInstruction,
    message::Message,
    native_loader,
    native_token::sol_to_lamports,
    nonce, nonce_account,
    process_instruction::{BpfComputeBudget, Executor, ProcessInstructionWithContext},
    program_utils::limited_deserialize,
    pubkey::Pubkey,
    recent_blockhashes_account,
    sanitize::Sanitize,
    signature::{Keypair, Signature},
    slot_hashes::SlotHashes,
    slot_history::SlotHistory,
    stake_weighted_timestamp::{
        calculate_stake_weighted_timestamp, MaxAllowableDrift, MAX_ALLOWABLE_DRIFT_PERCENTAGE,
        MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST, MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW,
    },
    system_transaction,
    sysvar::{self},
    timing::years_as_slots,
    transaction::{self, Result, Transaction, TransactionError},
};
use solana_stake_program::stake_state::{
    self, Delegation, InflationPointCalculationEvent, PointValue,
};
use solana_vote_program::vote_instruction::VoteInstruction;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    fmt, mem,
    ops::RangeInclusive,
    path::PathBuf,
    ptr,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        LockResult, RwLockWriteGuard, {Arc, RwLock, RwLockReadGuard},
    },
    time::Duration,
    time::Instant,
};

pub const SECONDS_PER_YEAR: f64 = 365.25 * 24.0 * 60.0 * 60.0;

pub const MAX_LEADER_SCHEDULE_STAKES: Epoch = 5;

#[derive(Default, Debug)]
pub struct ExecuteTimings {
    pub load_us: u64,
    pub execute_us: u64,
    pub store_us: u64,
    pub details: ExecuteDetailsTimings,
}

impl ExecuteTimings {
    pub fn accumulate(&mut self, other: &ExecuteTimings) {
        self.load_us += other.load_us;
        self.execute_us += other.execute_us;
        self.store_us += other.store_us;
        self.details.accumulate(&other.details);
    }
}

type BankStatusCache = StatusCache<Signature, Result<()>>;
#[frozen_abi(digest = "EcB9J7sm37t1R47vLcvGuNeiRciB4Efq1EDWDWL6Bp5h")]
pub type BankSlotDelta = SlotDelta<Result<()>>;
type TransactionAccountRefCells = Vec<Rc<RefCell<AccountSharedData>>>;
type TransactionAccountDepRefCells = Vec<(Pubkey, Rc<RefCell<AccountSharedData>>)>;
type TransactionLoaderRefCells = Vec<Vec<(Pubkey, Rc<RefCell<AccountSharedData>>)>>;

// Eager rent collection repeats in cyclic manner.
// Each cycle is composed of <partition_count> number of tiny pubkey subranges
// to scan, which is always multiple of the number of slots in epoch.
type PartitionIndex = u64;
type PartitionsPerCycle = u64;
type Partition = (PartitionIndex, PartitionIndex, PartitionsPerCycle);
type RentCollectionCycleParams = (
    Epoch,
    SlotCount,
    bool,
    Epoch,
    EpochCount,
    PartitionsPerCycle,
);

type EpochCount = u64;

#[derive(Clone)]
pub struct Builtin {
    pub name: String,
    pub id: Pubkey,
    pub process_instruction_with_context: ProcessInstructionWithContext,
}

impl Builtin {
    pub fn new(
        name: &str,
        id: Pubkey,
        process_instruction_with_context: ProcessInstructionWithContext,
    ) -> Self {
        Self {
            name: name.to_string(),
            id,
            process_instruction_with_context,
        }
    }
}

impl fmt::Debug for Builtin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Builtin [name={}, id={}]", self.name, self.id)
    }
}

/// Copy-on-write holder of CachedExecutors
#[derive(AbiExample, Debug, Default)]
struct CowCachedExecutors {
    shared: bool,
    executors: Arc<RwLock<CachedExecutors>>,
}
impl Clone for CowCachedExecutors {
    fn clone(&self) -> Self {
        Self {
            shared: true,
            executors: self.executors.clone(),
        }
    }
}
impl CowCachedExecutors {
    fn new(executors: Arc<RwLock<CachedExecutors>>) -> Self {
        Self {
            shared: true,
            executors,
        }
    }
    fn read(&self) -> LockResult<RwLockReadGuard<CachedExecutors>> {
        self.executors.read()
    }
    fn write(&mut self) -> LockResult<RwLockWriteGuard<CachedExecutors>> {
        if self.shared {
            self.shared = false;
            let local_cache = (*self.executors.read().unwrap()).clone();
            self.executors = Arc::new(RwLock::new(local_cache));
        }
        self.executors.write()
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl AbiExample for Builtin {
    fn example() -> Self {
        Self {
            name: String::default(),
            id: Pubkey::default(),
            process_instruction_with_context: |_, _, _, _| Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Builtins {
    /// Builtin programs that are always available
    pub genesis_builtins: Vec<Builtin>,

    /// Builtin programs activated dynamically by feature
    pub feature_builtins: Vec<(Builtin, Pubkey, ActivationType)>,
}

const MAX_CACHED_EXECUTORS: usize = 100; // 10 MB assuming programs are around 100k

/// LFU Cache of executors
#[derive(Debug)]
struct CachedExecutors {
    max: usize,
    executors: HashMap<Pubkey, (AtomicU64, Arc<dyn Executor>)>,
}
impl Default for CachedExecutors {
    fn default() -> Self {
        Self {
            max: MAX_CACHED_EXECUTORS,
            executors: HashMap::new(),
        }
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl AbiExample for CachedExecutors {
    fn example() -> Self {
        // Delegate AbiExample impl to Default before going deep and stuck with
        // not easily impl-able Arc<dyn Executor> due to rust's coherence issue
        // This is safe because CachedExecutors isn't serializable by definition.
        Self::default()
    }
}

impl Clone for CachedExecutors {
    fn clone(&self) -> Self {
        let mut executors = HashMap::new();
        for (key, (count, executor)) in self.executors.iter() {
            executors.insert(
                *key,
                (AtomicU64::new(count.load(Relaxed)), executor.clone()),
            );
        }
        Self {
            max: self.max,
            executors,
        }
    }
}
impl CachedExecutors {
    fn new(max: usize) -> Self {
        Self {
            max,
            executors: HashMap::new(),
        }
    }
    fn get(&self, pubkey: &Pubkey) -> Option<Arc<dyn Executor>> {
        self.executors.get(pubkey).map(|(count, executor)| {
            count.fetch_add(1, Relaxed);
            executor.clone()
        })
    }
    fn put(&mut self, pubkey: &Pubkey, executor: Arc<dyn Executor>) {
        if !self.executors.contains_key(pubkey) && self.executors.len() >= self.max {
            let mut least = u64::MAX;
            let default_key = Pubkey::default();
            let mut least_key = &default_key;
            for (key, (count, _)) in self.executors.iter() {
                let count = count.load(Relaxed);
                if count < least {
                    least = count;
                    least_key = key;
                }
            }
            let least_key = *least_key;
            let _ = self.executors.remove(&least_key);
        }
        let _ = self
            .executors
            .insert(*pubkey, (AtomicU64::new(0), executor));
    }
    fn remove(&mut self, pubkey: &Pubkey) {
        let _ = self.executors.remove(pubkey);
    }
}

#[derive(Default, Debug)]
pub struct BankRc {
    /// where all the Accounts are stored
    pub accounts: Arc<Accounts>,

    /// Previous checkpoint of this bank
    pub(crate) parent: RwLock<Option<Arc<Bank>>>,

    /// Current slot
    pub(crate) slot: Slot,
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
use solana_frozen_abi::abi_example::AbiExample;

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl AbiExample for BankRc {
    fn example() -> Self {
        BankRc {
            // Set parent to None to cut the recursion into another Bank
            parent: RwLock::new(None),
            // AbiExample for Accounts is specially implemented to contain a storage example
            accounts: AbiExample::example(),
            slot: AbiExample::example(),
        }
    }
}

impl BankRc {
    pub(crate) fn new(accounts: Accounts, slot: Slot) -> Self {
        Self {
            accounts: Arc::new(accounts),
            parent: RwLock::new(None),
            slot,
        }
    }

    pub fn get_snapshot_storages(&self, slot: Slot) -> SnapshotStorages {
        self.accounts.accounts_db.get_snapshot_storages(slot)
    }
}

#[derive(Default, Debug, AbiExample)]
pub struct StatusCacheRc {
    /// where all the Accounts are stored
    /// A cache of signature statuses
    pub status_cache: Arc<RwLock<BankStatusCache>>,
}

impl StatusCacheRc {
    pub fn slot_deltas(&self, slots: &[Slot]) -> Vec<BankSlotDelta> {
        let sc = self.status_cache.read().unwrap();
        sc.slot_deltas(slots)
    }

    pub fn roots(&self) -> Vec<Slot> {
        self.status_cache
            .read()
            .unwrap()
            .roots()
            .iter()
            .cloned()
            .sorted()
            .collect()
    }

    pub fn append(&self, slot_deltas: &[BankSlotDelta]) {
        let mut sc = self.status_cache.write().unwrap();
        sc.append(slot_deltas);
    }
}

pub type TransactionCheckResult = (Result<()>, Option<NonceRollbackPartial>);
pub type TransactionExecutionResult = (Result<()>, Option<NonceRollbackFull>);
pub struct TransactionResults {
    pub fee_collection_results: Vec<Result<()>>,
    pub execution_results: Vec<TransactionExecutionResult>,
    pub overwritten_vote_accounts: Vec<OverwrittenVoteAccount>,
}
pub struct TransactionBalancesSet {
    pub pre_balances: TransactionBalances,
    pub post_balances: TransactionBalances,
}
pub struct OverwrittenVoteAccount {
    pub account: ArcVoteAccount,
    pub transaction_index: usize,
    pub transaction_result_index: usize,
}

impl TransactionBalancesSet {
    pub fn new(pre_balances: TransactionBalances, post_balances: TransactionBalances) -> Self {
        assert_eq!(pre_balances.len(), post_balances.len());
        Self {
            pre_balances,
            post_balances,
        }
    }
}
pub type TransactionBalances = Vec<Vec<u64>>;

/// An ordered list of instructions that were invoked during a transaction instruction
pub type InnerInstructions = Vec<CompiledInstruction>;

/// A list of instructions that were invoked during each instruction of a transaction
pub type InnerInstructionsList = Vec<InnerInstructions>;

/// A list of log messages emitted during a transaction
pub type TransactionLogMessages = Vec<String>;

#[derive(Serialize, Deserialize, AbiExample, AbiEnumVisitor, Debug, PartialEq)]
pub enum TransactionLogCollectorFilter {
    All,
    AllWithVotes,
    None,
    OnlyMentionedAddresses,
}

impl Default for TransactionLogCollectorFilter {
    fn default() -> Self {
        Self::None
    }
}

#[derive(AbiExample, Debug, Default)]
pub struct TransactionLogCollectorConfig {
    pub mentioned_addresses: HashSet<Pubkey>,
    pub filter: TransactionLogCollectorFilter,
}

#[derive(AbiExample, Clone, Debug)]
pub struct TransactionLogInfo {
    pub signature: Signature,
    pub result: Result<()>,
    pub is_vote: bool,
    pub log_messages: TransactionLogMessages,
}

#[derive(AbiExample, Default, Debug)]
pub struct TransactionLogCollector {
    // All the logs collected for from this Bank.  Exact contents depend on the
    // active `TransactionLogCollectorFilter`
    pub logs: Vec<TransactionLogInfo>,

    // For each `mentioned_addresses`, maintain a list of indices into `logs` to easily
    // locate the logs from transactions that included the mentioned addresses.
    pub mentioned_address_map: HashMap<Pubkey, Vec<usize>>,
}

pub trait NonceRollbackInfo {
    fn nonce_address(&self) -> &Pubkey;
    fn nonce_account(&self) -> &AccountSharedData;
    fn fee_calculator(&self) -> Option<FeeCalculator>;
    fn fee_account(&self) -> Option<&AccountSharedData>;
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NonceRollbackPartial {
    nonce_address: Pubkey,
    nonce_account: AccountSharedData,
}

impl NonceRollbackPartial {
    pub fn new(nonce_address: Pubkey, nonce_account: AccountSharedData) -> Self {
        Self {
            nonce_address,
            nonce_account,
        }
    }
}

impl NonceRollbackInfo for NonceRollbackPartial {
    fn nonce_address(&self) -> &Pubkey {
        &self.nonce_address
    }
    fn nonce_account(&self) -> &AccountSharedData {
        &self.nonce_account
    }
    fn fee_calculator(&self) -> Option<FeeCalculator> {
        nonce_account::fee_calculator_of(&self.nonce_account)
    }
    fn fee_account(&self) -> Option<&AccountSharedData> {
        None
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NonceRollbackFull {
    nonce_address: Pubkey,
    nonce_account: AccountSharedData,
    fee_account: Option<AccountSharedData>,
}

impl NonceRollbackFull {
    #[cfg(test)]
    pub fn new(
        nonce_address: Pubkey,
        nonce_account: AccountSharedData,
        fee_account: Option<AccountSharedData>,
    ) -> Self {
        Self {
            nonce_address,
            nonce_account,
            fee_account,
        }
    }
    pub fn from_partial(
        partial: NonceRollbackPartial,
        message: &Message,
        accounts: &[AccountSharedData],
    ) -> Result<Self> {
        let NonceRollbackPartial {
            nonce_address,
            nonce_account,
        } = partial;
        let fee_payer = message
            .account_keys
            .iter()
            .enumerate()
            .find(|(i, k)| message.is_non_loader_key(k, *i))
            .and_then(|(i, k)| accounts.get(i).cloned().map(|a| (*k, a)));
        if let Some((fee_pubkey, fee_account)) = fee_payer {
            if fee_pubkey == nonce_address {
                Ok(Self {
                    nonce_address,
                    nonce_account: fee_account,
                    fee_account: None,
                })
            } else {
                Ok(Self {
                    nonce_address,
                    nonce_account,
                    fee_account: Some(fee_account),
                })
            }
        } else {
            Err(TransactionError::AccountNotFound)
        }
    }
}

impl NonceRollbackInfo for NonceRollbackFull {
    fn nonce_address(&self) -> &Pubkey {
        &self.nonce_address
    }
    fn nonce_account(&self) -> &AccountSharedData {
        &self.nonce_account
    }
    fn fee_calculator(&self) -> Option<FeeCalculator> {
        nonce_account::fee_calculator_of(&self.nonce_account)
    }
    fn fee_account(&self) -> Option<&AccountSharedData> {
        self.fee_account.as_ref()
    }
}

// Bank's common fields shared by all supported snapshot versions for deserialization.
// Sync fields with BankFieldsToSerialize! This is paired with it.
// All members are made public to remain Bank's members private and to make versioned deserializer workable on this
#[derive(Clone, Debug, Default)]
pub(crate) struct BankFieldsToDeserialize {
    pub(crate) blockhash_queue: BlockhashQueue,
    pub(crate) ancestors: Ancestors,
    pub(crate) hash: Hash,
    pub(crate) parent_hash: Hash,
    pub(crate) parent_slot: Slot,
    pub(crate) hard_forks: HardForks,
    pub(crate) transaction_count: u64,
    pub(crate) tick_height: u64,
    pub(crate) signature_count: u64,
    pub(crate) capitalization: u64,
    pub(crate) max_tick_height: u64,
    pub(crate) hashes_per_tick: Option<u64>,
    pub(crate) ticks_per_slot: u64,
    pub(crate) ns_per_slot: u128,
    pub(crate) genesis_creation_time: UnixTimestamp,
    pub(crate) slots_per_year: f64,
    pub(crate) unused: u64,
    pub(crate) slot: Slot,
    pub(crate) epoch: Epoch,
    pub(crate) block_height: u64,
    pub(crate) collector_id: Pubkey,
    pub(crate) collector_fees: u64,
    pub(crate) fee_calculator: FeeCalculator,
    pub(crate) fee_rate_governor: FeeRateGovernor,
    pub(crate) collected_rent: u64,
    pub(crate) rent_collector: RentCollector,
    pub(crate) epoch_schedule: EpochSchedule,
    pub(crate) inflation: Inflation,
    pub(crate) stakes: Stakes,
    pub(crate) epoch_stakes: HashMap<Epoch, EpochStakes>,
    pub(crate) is_delta: bool,
}

// Bank's common fields shared by all supported snapshot versions for serialization.
// This is separated from BankFieldsToDeserialize to avoid cloning by using refs.
// So, sync fields with BankFieldsToDeserialize!
// all members are made public to remain Bank private and to make versioned serializer workable on this
#[derive(Debug)]
pub(crate) struct BankFieldsToSerialize<'a> {
    pub(crate) blockhash_queue: &'a RwLock<BlockhashQueue>,
    pub(crate) ancestors: &'a Ancestors,
    pub(crate) hash: Hash,
    pub(crate) parent_hash: Hash,
    pub(crate) parent_slot: Slot,
    pub(crate) hard_forks: &'a RwLock<HardForks>,
    pub(crate) transaction_count: u64,
    pub(crate) tick_height: u64,
    pub(crate) signature_count: u64,
    pub(crate) capitalization: u64,
    pub(crate) max_tick_height: u64,
    pub(crate) hashes_per_tick: Option<u64>,
    pub(crate) ticks_per_slot: u64,
    pub(crate) ns_per_slot: u128,
    pub(crate) genesis_creation_time: UnixTimestamp,
    pub(crate) slots_per_year: f64,
    pub(crate) unused: u64,
    pub(crate) slot: Slot,
    pub(crate) epoch: Epoch,
    pub(crate) block_height: u64,
    pub(crate) collector_id: Pubkey,
    pub(crate) collector_fees: u64,
    pub(crate) fee_calculator: FeeCalculator,
    pub(crate) fee_rate_governor: FeeRateGovernor,
    pub(crate) collected_rent: u64,
    pub(crate) rent_collector: RentCollector,
    pub(crate) epoch_schedule: EpochSchedule,
    pub(crate) inflation: Inflation,
    pub(crate) stakes: &'a RwLock<Stakes>,
    pub(crate) epoch_stakes: &'a HashMap<Epoch, EpochStakes>,
    pub(crate) is_delta: bool,
}

// Can't derive PartialEq because RwLock doesn't implement PartialEq
impl PartialEq for Bank {
    fn eq(&self, other: &Self) -> bool {
        if ptr::eq(self, other) {
            return true;
        }
        *self.blockhash_queue.read().unwrap() == *other.blockhash_queue.read().unwrap()
            && self.ancestors == other.ancestors
            && *self.hash.read().unwrap() == *other.hash.read().unwrap()
            && self.parent_hash == other.parent_hash
            && self.parent_slot == other.parent_slot
            && *self.hard_forks.read().unwrap() == *other.hard_forks.read().unwrap()
            && self.transaction_count.load(Relaxed) == other.transaction_count.load(Relaxed)
            && self.tick_height.load(Relaxed) == other.tick_height.load(Relaxed)
            && self.signature_count.load(Relaxed) == other.signature_count.load(Relaxed)
            && self.capitalization.load(Relaxed) == other.capitalization.load(Relaxed)
            && self.max_tick_height == other.max_tick_height
            && self.hashes_per_tick == other.hashes_per_tick
            && self.ticks_per_slot == other.ticks_per_slot
            && self.ns_per_slot == other.ns_per_slot
            && self.genesis_creation_time == other.genesis_creation_time
            && self.slots_per_year == other.slots_per_year
            && self.unused == other.unused
            && self.slot == other.slot
            && self.epoch == other.epoch
            && self.block_height == other.block_height
            && self.collector_id == other.collector_id
            && self.collector_fees.load(Relaxed) == other.collector_fees.load(Relaxed)
            && self.fee_calculator == other.fee_calculator
            && self.fee_rate_governor == other.fee_rate_governor
            && self.collected_rent.load(Relaxed) == other.collected_rent.load(Relaxed)
            && self.rent_collector == other.rent_collector
            && self.epoch_schedule == other.epoch_schedule
            && *self.inflation.read().unwrap() == *other.inflation.read().unwrap()
            && *self.stakes.read().unwrap() == *other.stakes.read().unwrap()
            && self.epoch_stakes == other.epoch_stakes
            && self.is_delta.load(Relaxed) == other.is_delta.load(Relaxed)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, AbiExample, AbiEnumVisitor, Clone, Copy)]
pub enum RewardType {
    Fee,
    Rent,
    Staking,
    Voting,
}

#[derive(Debug)]
pub enum RewardCalculationEvent<'a, 'b> {
    Staking(&'a Pubkey, &'b InflationPointCalculationEvent),
}

fn null_tracer() -> Option<impl FnMut(&RewardCalculationEvent)> {
    None::<fn(&RewardCalculationEvent)>
}

impl fmt::Display for RewardType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RewardType::Fee => "fee",
                RewardType::Rent => "rent",
                RewardType::Staking => "staking",
                RewardType::Voting => "voting",
            }
        )
    }
}

pub trait DropCallback: fmt::Debug {
    fn callback(&self, b: &Bank);
    fn clone_box(&self) -> Box<dyn DropCallback + Send + Sync>;
}

#[derive(Debug, PartialEq, Serialize, Deserialize, AbiExample, Clone, Copy)]
pub struct RewardInfo {
    pub reward_type: RewardType,
    pub lamports: i64,     // Reward amount
    pub post_balance: u64, // Account balance in lamports after `lamports` was applied
}

#[derive(Debug, Default)]
pub struct OptionalDropCallback(Option<Box<dyn DropCallback + Send + Sync>>);

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl AbiExample for OptionalDropCallback {
    fn example() -> Self {
        Self(None)
    }
}

/// Manager for the state of all accounts and programs after processing its entries.
/// AbiExample is needed even without Serialize/Deserialize; actual (de-)serialization
/// are implemented elsewhere for versioning
#[derive(AbiExample, Debug, Default)]
pub struct Bank {
    /// References to accounts, parent and signature status
    pub rc: BankRc,

    pub src: StatusCacheRc,

    /// FIFO queue of `recent_blockhash` items
    blockhash_queue: RwLock<BlockhashQueue>,

    /// The set of parents including this bank
    pub ancestors: Ancestors,

    /// Hash of this Bank's state. Only meaningful after freezing.
    hash: RwLock<Hash>,

    /// Hash of this Bank's parent's state
    parent_hash: Hash,

    /// parent's slot
    parent_slot: Slot,

    /// slots to hard fork at
    hard_forks: Arc<RwLock<HardForks>>,

    /// The number of transactions processed without error
    transaction_count: AtomicU64,

    /// The number of transaction errors in this slot
    transaction_error_count: AtomicU64,

    /// The number of transaction entries in this slot
    transaction_entries_count: AtomicU64,

    /// The max number of transaction in an entry in this slot
    transactions_per_entry_max: AtomicU64,

    /// Bank tick height
    tick_height: AtomicU64,

    /// The number of signatures from valid transactions in this slot
    signature_count: AtomicU64,

    /// Total capitalization, used to calculate inflation
    capitalization: AtomicU64,

    // Bank max_tick_height
    max_tick_height: u64,

    /// The number of hashes in each tick. None value means hashing is disabled.
    hashes_per_tick: Option<u64>,

    /// The number of ticks in each slot.
    ticks_per_slot: u64,

    /// length of a slot in ns
    pub ns_per_slot: u128,

    /// genesis time, used for computed clock
    genesis_creation_time: UnixTimestamp,

    /// The number of slots per year, used for inflation
    slots_per_year: f64,

    /// Unused
    unused: u64,

    /// Bank slot (i.e. block)
    slot: Slot,

    /// Bank epoch
    epoch: Epoch,

    /// Bank block_height
    block_height: u64,

    /// The pubkey to send transactions fees to.
    collector_id: Pubkey,

    /// Fees that have been collected
    collector_fees: AtomicU64,

    /// Latest transaction fees for transactions processed by this bank
    fee_calculator: FeeCalculator,

    /// Track cluster signature throughput and adjust fee rate
    fee_rate_governor: FeeRateGovernor,

    /// Rent that has been collected
    collected_rent: AtomicU64,

    /// latest rent collector, knows the epoch
    rent_collector: RentCollector,

    /// initialized from genesis
    epoch_schedule: EpochSchedule,

    /// inflation specs
    inflation: Arc<RwLock<Inflation>>,

    /// cache of vote_account and stake_account state for this fork
    stakes: RwLock<Stakes>,

    /// staked nodes on epoch boundaries, saved off when a bank.slot() is at
    ///   a leader schedule calculation boundary
    epoch_stakes: HashMap<Epoch, EpochStakes>,

    /// A boolean reflecting whether any entries were recorded into the PoH
    /// stream for the slot == self.slot
    is_delta: AtomicBool,

    /// The Message processor
    message_processor: MessageProcessor,

    bpf_compute_budget: Option<BpfComputeBudget>,

    /// Builtin programs activated dynamically by feature
    #[allow(clippy::rc_buffer)]
    feature_builtins: Arc<Vec<(Builtin, Pubkey, ActivationType)>>,

    /// Last time when the cluster info vote listener has synced with this bank
    pub last_vote_sync: AtomicU64,

    /// Protocol-level rewards that were distributed by this bank
    pub rewards: RwLock<Vec<(Pubkey, RewardInfo)>>,

    pub skip_drop: AtomicBool,

    pub cluster_type: Option<ClusterType>,

    pub lazy_rent_collection: AtomicBool,

    pub no_stake_rewrite: AtomicBool,

    // this is temporary field only to remove rewards_pool entirely
    pub rewards_pool_pubkeys: Arc<HashSet<Pubkey>>,

    /// Cached executors
    cached_executors: RwLock<CowCachedExecutors>,

    transaction_debug_keys: Option<Arc<HashSet<Pubkey>>>,

    // Global configuration for how transaction logs should be collected across all banks
    pub transaction_log_collector_config: Arc<RwLock<TransactionLogCollectorConfig>>,

    // Logs from transactions that this Bank executed collected according to the criteria in
    // `transaction_log_collector_config`
    pub transaction_log_collector: Arc<RwLock<TransactionLogCollector>>,

    pub feature_set: Arc<FeatureSet>,

    pub drop_callback: RwLock<OptionalDropCallback>,

    pub freeze_started: AtomicBool,
}

impl Default for BlockhashQueue {
    fn default() -> Self {
        Self::new(MAX_RECENT_BLOCKHASHES)
    }
}

impl Bank {
    pub fn new(genesis_config: &GenesisConfig) -> Self {
        Self::new_with_paths(
            &genesis_config,
            Vec::new(),
            &[],
            None,
            None,
            HashSet::new(),
            false,
        )
    }

    pub fn new_no_wallclock_throttle(genesis_config: &GenesisConfig) -> Self {
        let mut bank = Self::new_with_paths(
            &genesis_config,
            Vec::new(),
            &[],
            None,
            None,
            HashSet::new(),
            false,
        );

        bank.ns_per_slot = std::u128::MAX;
        bank
    }

    #[cfg(test)]
    pub(crate) fn new_with_config(
        genesis_config: &GenesisConfig,
        account_indexes: HashSet<AccountIndex>,
        accounts_db_caching_enabled: bool,
    ) -> Self {
        Self::new_with_paths(
            &genesis_config,
            Vec::new(),
            &[],
            None,
            None,
            account_indexes,
            accounts_db_caching_enabled,
        )
    }

    pub fn new_with_paths(
        genesis_config: &GenesisConfig,
        paths: Vec<PathBuf>,
        frozen_account_pubkeys: &[Pubkey],
        debug_keys: Option<Arc<HashSet<Pubkey>>>,
        additional_builtins: Option<&Builtins>,
        account_indexes: HashSet<AccountIndex>,
        accounts_db_caching_enabled: bool,
    ) -> Self {
        let mut bank = Self::default();
        bank.ancestors.insert(bank.slot(), 0);
        bank.transaction_debug_keys = debug_keys;
        bank.cluster_type = Some(genesis_config.cluster_type);

        bank.rc.accounts = Arc::new(Accounts::new_with_config(
            paths,
            &genesis_config.cluster_type,
            account_indexes,
            accounts_db_caching_enabled,
        ));
        bank.process_genesis_config(genesis_config);
        bank.finish_init(genesis_config, additional_builtins);

        // Freeze accounts after process_genesis_config creates the initial append vecs
        Arc::get_mut(&mut Arc::get_mut(&mut bank.rc.accounts).unwrap().accounts_db)
            .unwrap()
            .freeze_accounts(&bank.ancestors, frozen_account_pubkeys);

        // genesis needs stakes for all epochs up to the epoch implied by
        //  slot = 0 and genesis configuration
        {
            let stakes = bank.stakes.read().unwrap();
            for epoch in 0..=bank.get_leader_schedule_epoch(bank.slot) {
                bank.epoch_stakes
                    .insert(epoch, EpochStakes::new(&stakes, epoch));
            }
            bank.update_stake_history(None);
        }
        bank.update_clock(None, LoadSafety::FixedMaxRoot);
        bank.update_rent();
        bank.update_epoch_schedule();
        bank.update_recent_blockhashes();
        bank
    }

    /// Create a new bank that points to an immutable checkpoint of another bank.
    pub fn new_from_parent(parent: &Arc<Bank>, collector_id: &Pubkey, slot: Slot) -> Self {
        Self::_new_from_parent(parent, collector_id, slot, &mut null_tracer())
    }

    pub fn new_from_parent_with_tracer(
        parent: &Arc<Bank>,
        collector_id: &Pubkey,
        slot: Slot,
        reward_calc_tracer: impl FnMut(&RewardCalculationEvent),
    ) -> Self {
        Self::_new_from_parent(parent, collector_id, slot, &mut Some(reward_calc_tracer))
    }

    fn _new_from_parent(
        parent: &Arc<Bank>,
        collector_id: &Pubkey,
        slot: Slot,
        reward_calc_tracer: &mut Option<impl FnMut(&RewardCalculationEvent)>,
    ) -> Self {
        parent.freeze();
        assert_ne!(slot, parent.slot());

        let epoch_schedule = parent.epoch_schedule;
        let epoch = epoch_schedule.get_epoch(slot);

        let rc = BankRc {
            accounts: Arc::new(Accounts::new_from_parent(
                &parent.rc.accounts,
                slot,
                parent.slot(),
            )),
            parent: RwLock::new(Some(parent.clone())),
            slot,
        };
        let src = StatusCacheRc {
            status_cache: parent.src.status_cache.clone(),
        };

        let fee_rate_governor =
            FeeRateGovernor::new_derived(&parent.fee_rate_governor, parent.signature_count());

        let mut new = Bank {
            rc,
            src,
            slot,
            epoch,
            blockhash_queue: RwLock::new(parent.blockhash_queue.read().unwrap().clone()),

            // TODO: clean this up, so much special-case copying...
            hashes_per_tick: parent.hashes_per_tick,
            ticks_per_slot: parent.ticks_per_slot,
            ns_per_slot: parent.ns_per_slot,
            genesis_creation_time: parent.genesis_creation_time,
            unused: parent.unused,
            slots_per_year: parent.slots_per_year,
            epoch_schedule,
            collected_rent: AtomicU64::new(0),
            rent_collector: parent.rent_collector.clone_with_epoch(epoch),
            max_tick_height: (slot + 1) * parent.ticks_per_slot,
            block_height: parent.block_height + 1,
            fee_calculator: fee_rate_governor.create_fee_calculator(),
            fee_rate_governor,
            capitalization: AtomicU64::new(parent.capitalization()),
            inflation: parent.inflation.clone(),
            transaction_count: AtomicU64::new(parent.transaction_count()),
            transaction_error_count: AtomicU64::new(0),
            transaction_entries_count: AtomicU64::new(0),
            transactions_per_entry_max: AtomicU64::new(0),
            // we will .clone_with_epoch() this soon after stake data update; so just .clone() for now
            stakes: RwLock::new(parent.stakes.read().unwrap().clone()),
            epoch_stakes: parent.epoch_stakes.clone(),
            parent_hash: parent.hash(),
            parent_slot: parent.slot(),
            collector_id: *collector_id,
            collector_fees: AtomicU64::new(0),
            ancestors: HashMap::new(),
            hash: RwLock::new(Hash::default()),
            is_delta: AtomicBool::new(false),
            tick_height: AtomicU64::new(parent.tick_height.load(Relaxed)),
            signature_count: AtomicU64::new(0),
            message_processor: parent.message_processor.clone(),
            bpf_compute_budget: parent.bpf_compute_budget,
            feature_builtins: parent.feature_builtins.clone(),
            hard_forks: parent.hard_forks.clone(),
            last_vote_sync: AtomicU64::new(parent.last_vote_sync.load(Relaxed)),
            rewards: RwLock::new(vec![]),
            skip_drop: AtomicBool::new(false),
            cluster_type: parent.cluster_type,
            lazy_rent_collection: AtomicBool::new(parent.lazy_rent_collection.load(Relaxed)),
            no_stake_rewrite: AtomicBool::new(parent.no_stake_rewrite.load(Relaxed)),
            rewards_pool_pubkeys: parent.rewards_pool_pubkeys.clone(),
            cached_executors: RwLock::new((*parent.cached_executors.read().unwrap()).clone()),
            transaction_debug_keys: parent.transaction_debug_keys.clone(),
            transaction_log_collector_config: parent.transaction_log_collector_config.clone(),
            transaction_log_collector: Arc::new(RwLock::new(TransactionLogCollector::default())),
            feature_set: parent.feature_set.clone(),
            drop_callback: RwLock::new(OptionalDropCallback(
                parent
                    .drop_callback
                    .read()
                    .unwrap()
                    .0
                    .as_ref()
                    .map(|drop_callback| drop_callback.clone_box()),
            )),
            freeze_started: AtomicBool::new(false),
        };

        datapoint_info!(
            "bank-new_from_parent-heights",
            ("slot_height", slot, i64),
            ("block_height", new.block_height, i64)
        );

        new.ancestors.insert(new.slot(), 0);
        new.parents().iter().enumerate().for_each(|(i, p)| {
            new.ancestors.insert(p.slot(), i + 1);
        });

        // Following code may touch AccountsDb, requiring proper ancestors
        let parent_epoch = parent.epoch();
        if parent_epoch < new.epoch() {
            new.apply_feature_activations(false);
        }

        let cloned = new
            .stakes
            .read()
            .unwrap()
            .clone_with_epoch(epoch, new.stake_program_v2_enabled());
        *new.stakes.write().unwrap() = cloned;

        let leader_schedule_epoch = epoch_schedule.get_leader_schedule_epoch(slot);
        new.update_epoch_stakes(leader_schedule_epoch);
        new.update_slot_hashes();
        new.update_rewards(parent_epoch, reward_calc_tracer);
        new.update_stake_history(Some(parent_epoch));
        new.update_clock(Some(parent_epoch), LoadSafety::FixedMaxRoot);
        new.update_fees();
        if !new.fix_recent_blockhashes_sysvar_delay() {
            new.update_recent_blockhashes();
        }

        new
    }

    /// Returns all ancestors excluding self.slot.
    pub(crate) fn proper_ancestors(&self) -> impl Iterator<Item = Slot> + '_ {
        self.ancestors
            .keys()
            .copied()
            .filter(move |slot| *slot != self.slot)
    }

    pub fn set_callback(&self, callback: Option<Box<dyn DropCallback + Send + Sync>>) {
        *self.drop_callback.write().unwrap() = OptionalDropCallback(callback);
    }

    /// Like `new_from_parent` but additionally:
    /// * Doesn't assume that the parent is anywhere near `slot`, parent could be millions of slots
    /// in the past
    /// * Adjusts the new bank's tick height to avoid having to run PoH for millions of slots
    /// * Freezes the new bank, assuming that the user will `Bank::new_from_parent` from this bank
    pub fn warp_from_parent(parent: &Arc<Bank>, collector_id: &Pubkey, slot: Slot) -> Self {
        // FixedMaxRoot is ok because this is usually called from ledger-tool
        let parent_timestamp = parent.clock(LoadSafety::FixedMaxRoot).unix_timestamp;
        let mut new = Bank::new_from_parent(parent, collector_id, slot);
        new.apply_feature_activations(true);
        new.update_epoch_stakes(new.epoch_schedule().get_epoch(slot));
        new.tick_height.store(new.max_tick_height(), Relaxed);

        let mut clock = new.clock(LoadSafety::FixedMaxRoot);
        clock.epoch_start_timestamp = parent_timestamp;
        clock.unix_timestamp = parent_timestamp;
        new.update_sysvar_account(&sysvar::clock::id(), |account| {
            create_account(
                &clock,
                new.inherit_specially_retained_account_fields(account),
            )
        });

        new.freeze();
        new
    }

    /// Create a bank from explicit arguments and deserialized fields from snapshot
    #[allow(clippy::float_cmp)]
    pub(crate) fn new_from_fields(
        bank_rc: BankRc,
        genesis_config: &GenesisConfig,
        fields: BankFieldsToDeserialize,
        debug_keys: Option<Arc<HashSet<Pubkey>>>,
        additional_builtins: Option<&Builtins>,
    ) -> Self {
        fn new<T: Default>() -> T {
            T::default()
        }
        let mut bank = Self {
            rc: bank_rc,
            src: new(),
            blockhash_queue: RwLock::new(fields.blockhash_queue),
            ancestors: fields.ancestors,
            hash: RwLock::new(fields.hash),
            parent_hash: fields.parent_hash,
            parent_slot: fields.parent_slot,
            hard_forks: Arc::new(RwLock::new(fields.hard_forks)),
            transaction_count: AtomicU64::new(fields.transaction_count),
            transaction_error_count: new(),
            transaction_entries_count: new(),
            transactions_per_entry_max: new(),
            tick_height: AtomicU64::new(fields.tick_height),
            signature_count: AtomicU64::new(fields.signature_count),
            capitalization: AtomicU64::new(fields.capitalization),
            max_tick_height: fields.max_tick_height,
            hashes_per_tick: fields.hashes_per_tick,
            ticks_per_slot: fields.ticks_per_slot,
            ns_per_slot: fields.ns_per_slot,
            genesis_creation_time: fields.genesis_creation_time,
            slots_per_year: fields.slots_per_year,
            unused: genesis_config.unused,
            slot: fields.slot,
            epoch: fields.epoch,
            block_height: fields.block_height,
            collector_id: fields.collector_id,
            collector_fees: AtomicU64::new(fields.collector_fees),
            fee_calculator: fields.fee_calculator,
            fee_rate_governor: fields.fee_rate_governor,
            collected_rent: AtomicU64::new(fields.collected_rent),
            // clone()-ing is needed to consider a gated behavior in rent_collector
            rent_collector: fields.rent_collector.clone_with_epoch(fields.epoch),
            epoch_schedule: fields.epoch_schedule,
            inflation: Arc::new(RwLock::new(fields.inflation)),
            stakes: RwLock::new(fields.stakes),
            epoch_stakes: fields.epoch_stakes,
            is_delta: AtomicBool::new(fields.is_delta),
            message_processor: new(),
            bpf_compute_budget: None,
            feature_builtins: new(),
            last_vote_sync: new(),
            rewards: new(),
            skip_drop: new(),
            cluster_type: Some(genesis_config.cluster_type),
            lazy_rent_collection: new(),
            no_stake_rewrite: new(),
            rewards_pool_pubkeys: new(),
            cached_executors: RwLock::new(CowCachedExecutors::new(Arc::new(RwLock::new(
                CachedExecutors::new(MAX_CACHED_EXECUTORS),
            )))),
            transaction_debug_keys: debug_keys,
            transaction_log_collector_config: new(),
            transaction_log_collector: new(),
            feature_set: new(),
            drop_callback: RwLock::new(OptionalDropCallback(None)),
            freeze_started: AtomicBool::new(fields.hash != Hash::default()),
        };
        bank.finish_init(genesis_config, additional_builtins);

        // Sanity assertions between bank snapshot and genesis config
        // Consider removing from serializable bank state
        // (BankFieldsToSerialize/BankFieldsToDeserialize) and initializing
        // from the passed in genesis_config instead (as new()/new_with_paths() already do)
        assert_eq!(
            bank.hashes_per_tick,
            genesis_config.poh_config.hashes_per_tick
        );
        assert_eq!(bank.ticks_per_slot, genesis_config.ticks_per_slot);
        assert_eq!(
            bank.ns_per_slot,
            genesis_config.poh_config.target_tick_duration.as_nanos()
                * genesis_config.ticks_per_slot as u128
        );
        assert_eq!(bank.genesis_creation_time, genesis_config.creation_time);
        assert_eq!(bank.unused, genesis_config.unused);
        assert_eq!(bank.max_tick_height, (bank.slot + 1) * bank.ticks_per_slot);
        assert_eq!(
            bank.slots_per_year,
            years_as_slots(
                1.0,
                &genesis_config.poh_config.target_tick_duration,
                bank.ticks_per_slot,
            )
        );
        assert_eq!(bank.epoch_schedule, genesis_config.epoch_schedule);
        assert_eq!(bank.epoch, bank.epoch_schedule.get_epoch(bank.slot));
        bank.fee_rate_governor.lamports_per_signature = bank.fee_calculator.lamports_per_signature;
        assert_eq!(
            bank.fee_rate_governor.create_fee_calculator(),
            bank.fee_calculator
        );
        bank
    }

    /// Return subset of bank fields representing serializable state
    pub(crate) fn get_fields_to_serialize(&self) -> BankFieldsToSerialize {
        BankFieldsToSerialize {
            blockhash_queue: &self.blockhash_queue,
            ancestors: &self.ancestors,
            hash: *self.hash.read().unwrap(),
            parent_hash: self.parent_hash,
            parent_slot: self.parent_slot,
            hard_forks: &*self.hard_forks,
            transaction_count: self.transaction_count.load(Relaxed),
            tick_height: self.tick_height.load(Relaxed),
            signature_count: self.signature_count.load(Relaxed),
            capitalization: self.capitalization.load(Relaxed),
            max_tick_height: self.max_tick_height,
            hashes_per_tick: self.hashes_per_tick,
            ticks_per_slot: self.ticks_per_slot,
            ns_per_slot: self.ns_per_slot,
            genesis_creation_time: self.genesis_creation_time,
            slots_per_year: self.slots_per_year,
            unused: self.unused,
            slot: self.slot,
            epoch: self.epoch,
            block_height: self.block_height,
            collector_id: self.collector_id,
            collector_fees: self.collector_fees.load(Relaxed),
            fee_calculator: self.fee_calculator.clone(),
            fee_rate_governor: self.fee_rate_governor.clone(),
            collected_rent: self.collected_rent.load(Relaxed),
            rent_collector: self.rent_collector.clone(),
            epoch_schedule: self.epoch_schedule,
            inflation: *self.inflation.read().unwrap(),
            stakes: &self.stakes,
            epoch_stakes: &self.epoch_stakes,
            is_delta: self.is_delta.load(Relaxed),
        }
    }

    pub fn collector_id(&self) -> &Pubkey {
        &self.collector_id
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn first_normal_epoch(&self) -> Epoch {
        self.epoch_schedule.first_normal_epoch
    }

    pub fn freeze_lock(&self) -> RwLockReadGuard<Hash> {
        self.hash.read().unwrap()
    }

    pub fn hash(&self) -> Hash {
        *self.hash.read().unwrap()
    }

    pub fn is_frozen(&self) -> bool {
        *self.hash.read().unwrap() != Hash::default()
    }

    pub fn freeze_started(&self) -> bool {
        self.freeze_started.load(Relaxed)
    }

    pub fn status_cache_ancestors(&self) -> Vec<u64> {
        let mut roots = self.src.status_cache.read().unwrap().roots().clone();
        let min = roots.iter().min().cloned().unwrap_or(0);
        for ancestor in self.ancestors.keys() {
            if *ancestor >= min {
                roots.insert(*ancestor);
            }
        }

        let mut ancestors: Vec<_> = roots.into_iter().collect();
        #[allow(clippy::stable_sort_primitive)]
        ancestors.sort();
        ancestors
    }

    /// computed unix_timestamp at this slot height
    pub fn unix_timestamp_from_genesis(&self) -> i64 {
        self.genesis_creation_time + ((self.slot as u128 * self.ns_per_slot) / 1_000_000_000) as i64
    }

    fn update_sysvar_account<F>(&self, pubkey: &Pubkey, updater: F)
    where
        F: Fn(&Option<AccountSharedData>) -> AccountSharedData,
    {
        let old_account = self.get_sysvar_account_with_fixed_root(pubkey);
        let new_account = updater(&old_account);

        self.store_account_and_update_capitalization(pubkey, &new_account, LoadSafety::FixedMaxRoot);
    }

    fn inherit_specially_retained_account_fields(
        &self,
        old_account: &Option<AccountSharedData>,
    ) -> InheritableAccountFields {
        (
            old_account.as_ref().map(|a| a.lamports).unwrap_or(1),
            INITIAL_RENT_EPOCH,
        )
    }

    /// Unused conversion
    pub fn get_unused_from_slot(rooted_slot: Slot, unused: u64) -> u64 {
        (rooted_slot + (unused - 1)) / unused
    }

    pub fn clock(&self, load_safety: LoadSafety) -> sysvar::clock::Clock {
        from_account(&self.get_account(&sysvar::clock::id(), load_safety).unwrap_or_default())
            .unwrap_or_default()
    }

    fn update_clock(&self, parent_epoch: Option<Epoch>, load_safety: LoadSafety) {
        let mut unix_timestamp = self.clock(load_safety).unix_timestamp;
        let warp_timestamp_again = self
            .feature_set
            .activated_slot(&feature_set::warp_timestamp_again::id());
        let epoch_start_timestamp = if warp_timestamp_again == Some(self.slot()) {
            None
        } else {
            let epoch = if let Some(epoch) = parent_epoch {
                epoch
            } else {
                self.epoch()
            };
            let first_slot_in_epoch = self.epoch_schedule.get_first_slot_in_epoch(epoch);
            Some((first_slot_in_epoch, self.clock(load_safety).epoch_start_timestamp))
        };
        let max_allowable_drift = if self
            .feature_set
            .is_active(&feature_set::warp_timestamp_again::id())
        {
            MaxAllowableDrift {
                fast: MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST,
                slow: MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW,
            }
        } else {
            MaxAllowableDrift {
                fast: MAX_ALLOWABLE_DRIFT_PERCENTAGE,
                slow: MAX_ALLOWABLE_DRIFT_PERCENTAGE,
            }
        };

        let ancestor_timestamp = self.clock(load_safety).unix_timestamp;
        if let Some(timestamp_estimate) =
            self.get_timestamp_estimate(max_allowable_drift, epoch_start_timestamp)
        {
            unix_timestamp = timestamp_estimate;
            if timestamp_estimate < ancestor_timestamp {
                unix_timestamp = ancestor_timestamp;
            }
        }
        datapoint_info!(
            "bank-timestamp-correction",
            ("slot", self.slot(), i64),
            ("from_genesis", self.unix_timestamp_from_genesis(), i64),
            ("corrected", unix_timestamp, i64),
            ("ancestor_timestamp", ancestor_timestamp, i64),
        );
        let mut epoch_start_timestamp =
            // On epoch boundaries, update epoch_start_timestamp
            if parent_epoch.is_some() && parent_epoch.unwrap() != self.epoch() {
                unix_timestamp
            } else {
                self.clock(load_safety).epoch_start_timestamp
            };
        if self.slot == 0 {
            unix_timestamp = self.unix_timestamp_from_genesis();
            epoch_start_timestamp = self.unix_timestamp_from_genesis();
        }
        let clock = sysvar::clock::Clock {
            slot: self.slot,
            epoch_start_timestamp,
            epoch: self.epoch_schedule.get_epoch(self.slot),
            leader_schedule_epoch: self.epoch_schedule.get_leader_schedule_epoch(self.slot),
            unix_timestamp,
        };
        self.update_sysvar_account(&sysvar::clock::id(), |account| {
            create_account(
                &clock,
                self.inherit_specially_retained_account_fields(account),
            )
        });
    }

    fn update_slot_history(&self) {
        self.update_sysvar_account(&sysvar::slot_history::id(), |account| {
            let mut slot_history = account
                .as_ref()
                .map(|account| from_account::<SlotHistory, _>(account).unwrap())
                .unwrap_or_default();
            slot_history.add(self.slot());
            create_account(
                &slot_history,
                self.inherit_specially_retained_account_fields(account),
            )
        });
    }

    fn update_slot_hashes(&self) {
        self.update_sysvar_account(&sysvar::slot_hashes::id(), |account| {
            let mut slot_hashes = account
                .as_ref()
                .map(|account| from_account::<SlotHashes, _>(account).unwrap())
                .unwrap_or_default();
            slot_hashes.add(self.parent_slot, self.parent_hash);
            create_account(
                &slot_hashes,
                self.inherit_specially_retained_account_fields(account),
            )
        });
    }

    pub fn get_slot_history(&self, load_safety: LoadSafety) -> SlotHistory {
        from_account(&self.get_account(&sysvar::slot_history::id(), load_safety).unwrap()).unwrap()
    }

    fn update_epoch_stakes(&mut self, leader_schedule_epoch: Epoch) {
        // update epoch_stakes cache
        //  if my parent didn't populate for this staker's epoch, we've
        //  crossed a boundary
        if self.epoch_stakes.get(&leader_schedule_epoch).is_none() {
            self.epoch_stakes.retain(|&epoch, _| {
                epoch >= leader_schedule_epoch.saturating_sub(MAX_LEADER_SCHEDULE_STAKES)
            });

            let new_epoch_stakes =
                EpochStakes::new(&self.stakes.read().unwrap(), leader_schedule_epoch);
            {
                let vote_stakes: HashMap<_, _> = self
                    .stakes
                    .read()
                    .unwrap()
                    .vote_accounts()
                    .iter()
                    .map(|(pubkey, (stake, _))| (*pubkey, *stake))
                    .collect();
                info!(
                    "new epoch stakes, epoch: {}, stakes: {:#?}, total_stake: {}",
                    leader_schedule_epoch,
                    vote_stakes,
                    new_epoch_stakes.total_stake(),
                );
            }
            self.epoch_stakes
                .insert(leader_schedule_epoch, new_epoch_stakes);
        }
    }

    fn update_fees(&self) {
        self.update_sysvar_account(&sysvar::fees::id(), |account| {
            create_account(
                &sysvar::fees::Fees::new(&self.fee_calculator),
                self.inherit_specially_retained_account_fields(account),
            )
        });
    }

    fn update_rent(&self) {
        self.update_sysvar_account(&sysvar::rent::id(), |account| {
            create_account(
                &self.rent_collector.rent,
                self.inherit_specially_retained_account_fields(account),
            )
        });
    }

    fn update_epoch_schedule(&self) {
        self.update_sysvar_account(&sysvar::epoch_schedule::id(), |account| {
            create_account(
                &self.epoch_schedule,
                self.inherit_specially_retained_account_fields(account),
            )
        });
    }

    fn update_stake_history(&self, epoch: Option<Epoch>) {
        if epoch == Some(self.epoch()) {
            return;
        }
        // if I'm the first Bank in an epoch, ensure stake_history is updated
        self.update_sysvar_account(&sysvar::stake_history::id(), |account| {
            create_account::<sysvar::stake_history::StakeHistory>(
                &self.stakes.read().unwrap().history(),
                self.inherit_specially_retained_account_fields(account),
            )
        });
    }

    pub fn epoch_duration_in_years(&self, prev_epoch: Epoch) -> f64 {
        // period: time that has passed as a fraction of a year, basically the length of
        //  an epoch as a fraction of a year
        //  calculated as: slots_elapsed / (slots / year)
        self.epoch_schedule.get_slots_in_epoch(prev_epoch) as f64 / self.slots_per_year
    }

    fn rewrite_stakes(&self) -> (usize, usize) {
        let mut examined_count = 0;
        let mut rewritten_count = 0;
        self.cloned_stake_delegations()
            .into_iter()
            .for_each(|(stake_pubkey, _delegation)| {
                examined_count += 1;
                if let Some(mut stake_account) = self.get_account(&stake_pubkey, LoadSafety::FixedMaxRoot) {
                    if let Ok(result) =
                        stake_state::rewrite_stakes(&mut stake_account, &self.rent_collector.rent)
                    {
                        self.store_account(&stake_pubkey, &stake_account);
                        let message = format!("rewrote stake: {}, {:?}", stake_pubkey, result);
                        info!("{}", message);
                        datapoint_info!("stake_info", ("info", message, String));
                        rewritten_count += 1;
                    }
                }
            });

        info!(
            "bank (slot: {}): rewrite_stakes: {} accounts rewritten / {} accounts examined",
            self.slot(),
            rewritten_count,
            examined_count,
        );
        datapoint_info!(
            "rewrite-stakes",
            ("examined_count", examined_count, i64),
            ("rewritten_count", rewritten_count, i64)
        );

        (examined_count, rewritten_count)
    }

    // Calculates the starting-slot for inflation from the activation slot.
    // This method assumes that `pico_inflation` will be enabled before `full_inflation`, giving
    // precedence to the latter. However, since `pico_inflation` is fixed-rate Inflation, should
    // `pico_inflation` be enabled 2nd, the incorrect start slot provided here should have no
    // effect on the inflation calculation.
    fn get_inflation_start_slot(&self) -> Slot {
        let mut slots = self
            .feature_set
            .full_inflation_features_enabled()
            .iter()
            .filter_map(|id| self.feature_set.activated_slot(&id))
            .collect::<Vec<_>>();
        slots.sort_unstable();
        slots.get(0).cloned().unwrap_or_else(|| {
            self.feature_set
                .activated_slot(&feature_set::pico_inflation::id())
                .unwrap_or(0)
        })
    }

    fn get_inflation_num_slots(&self) -> u64 {
        let inflation_activation_slot = self.get_inflation_start_slot();
        // Normalize inflation_start to align with the start of rewards accrual.
        let inflation_start_slot = self.epoch_schedule.get_first_slot_in_epoch(
            self.epoch_schedule
                .get_epoch(inflation_activation_slot)
                .saturating_sub(1),
        );
        self.epoch_schedule.get_first_slot_in_epoch(self.epoch()) - inflation_start_slot
    }

    pub fn slot_in_year_for_inflation(&self) -> f64 {
        let num_slots = self.get_inflation_num_slots();

        // calculated as: num_slots / (slots / year)
        num_slots as f64 / self.slots_per_year
    }

    // update rewards based on the previous epoch
    fn update_rewards(
        &mut self,
        prev_epoch: Epoch,
        reward_calc_tracer: &mut Option<impl FnMut(&RewardCalculationEvent)>,
    ) {
        if prev_epoch == self.epoch() {
            return;
        }
        // if I'm the first Bank in an epoch, count, claim, disburse rewards from Inflation

        let slot_in_year = self.slot_in_year_for_inflation();
        let epoch_duration_in_years = self.epoch_duration_in_years(prev_epoch);

        let (validator_rate, foundation_rate) = {
            let inflation = self.inflation.read().unwrap();
            (
                (*inflation).validator(slot_in_year),
                (*inflation).foundation(slot_in_year),
            )
        };

        let capitalization = self.capitalization();
        let validator_rewards =
            (validator_rate * capitalization as f64 * epoch_duration_in_years) as u64;

        let old_vote_balance_and_staked = self.stakes.read().unwrap().vote_balance_and_staked();

        let validator_point_value = self.pay_validator_rewards(
            prev_epoch,
            validator_rewards,
            reward_calc_tracer,
            self.stake_program_v2_enabled(),
        );

        if !self
            .feature_set
            .is_active(&feature_set::deprecate_rewards_sysvar::id())
        {
            // this sysvar can be retired once `pico_inflation` is enabled on all clusters
            self.update_sysvar_account(&sysvar::rewards::id(), |account| {
                create_account(
                    &sysvar::rewards::Rewards::new(validator_point_value),
                    self.inherit_specially_retained_account_fields(account),
                )
            });
        }

        let new_vote_balance_and_staked = self.stakes.read().unwrap().vote_balance_and_staked();
        let validator_rewards_paid = new_vote_balance_and_staked - old_vote_balance_and_staked;
        assert_eq!(
            validator_rewards_paid,
            u64::try_from(
                self.rewards
                    .read()
                    .unwrap()
                    .iter()
                    .map(|(_address, reward_info)| {
                        match reward_info.reward_type {
                            RewardType::Voting | RewardType::Staking => reward_info.lamports,
                            _ => 0,
                        }
                    })
                    .sum::<i64>()
            )
            .unwrap()
        );

        // verify that we didn't pay any more than we expected to
        assert!(validator_rewards >= validator_rewards_paid);

        info!(
            "distributed inflation: {} (rounded from: {})",
            validator_rewards_paid, validator_rewards
        );

        self.capitalization
            .fetch_add(validator_rewards_paid, Relaxed);

        let active_stake = if let Some(stake_history_entry) =
            self.stakes.read().unwrap().history().get(&prev_epoch)
        {
            stake_history_entry.effective
        } else {
            0
        };

        datapoint_warn!(
            "epoch_rewards",
            ("slot", self.slot, i64),
            ("epoch", prev_epoch, i64),
            ("validator_rate", validator_rate, f64),
            ("foundation_rate", foundation_rate, f64),
            ("epoch_duration_in_years", epoch_duration_in_years, f64),
            ("validator_rewards", validator_rewards_paid, i64),
            ("active_stake", active_stake, i64),
            ("pre_capitalization", capitalization, i64),
            ("post_capitalization", self.capitalization(), i64)
        );
    }

    /// map stake delegations into resolved (pubkey, account) pairs
    ///  returns a map (has to be copied) of loaded
    ///   ( Vec<(staker info)> (voter account) ) keyed by voter pubkey
    ///
    /// Filters out invalid pairs
    fn stake_delegation_accounts(
        &self,
        reward_calc_tracer: &mut Option<impl FnMut(&RewardCalculationEvent)>,
        load_safety: LoadSafety
    ) -> HashMap<Pubkey, (Vec<(Pubkey, AccountSharedData)>, AccountSharedData)> {
        let mut accounts = HashMap::new();

        self.stakes
            .read()
            .unwrap()
            .stake_delegations()
            .iter()
            .for_each(|(stake_pubkey, delegation)| {
                match (
                    self.get_account(&stake_pubkey, load_safety),
                    self.get_account(&delegation.voter_pubkey, load_safety),
                ) {
                    (Some(stake_account), Some(vote_account)) => {
                        // call tracer to catch any illegal data if any
                        if let Some(reward_calc_tracer) = reward_calc_tracer {
                            reward_calc_tracer(&RewardCalculationEvent::Staking(
                                stake_pubkey,
                                &InflationPointCalculationEvent::Delegation(
                                    *delegation,
                                    vote_account.owner,
                                ),
                            ));
                        }
                        if self
                            .feature_set
                            .is_active(&feature_set::filter_stake_delegation_accounts::id())
                            && (stake_account.owner != solana_stake_program::id()
                                || vote_account.owner != solana_vote_program::id())
                        {
                            datapoint_warn!(
                                "bank-stake_delegation_accounts-invalid-account",
                                ("slot", self.slot() as i64, i64),
                                ("stake-address", format!("{:?}", stake_pubkey), String),
                                (
                                    "vote-address",
                                    format!("{:?}", delegation.voter_pubkey),
                                    String
                                ),
                            );
                            return;
                        }
                        let entry = accounts
                            .entry(delegation.voter_pubkey)
                            .or_insert((Vec::new(), vote_account));
                        entry.0.push((*stake_pubkey, stake_account));
                    }
                    (_, _) => {}
                }
            });

        accounts
    }

    /// iterate over all stakes, redeem vote credits for each stake we can
    ///   successfully load and parse, return the lamport value of one point
    fn pay_validator_rewards(
        &mut self,
        rewarded_epoch: Epoch,
        rewards: u64,
        reward_calc_tracer: &mut Option<impl FnMut(&RewardCalculationEvent)>,
        fix_stake_deactivate: bool,
    ) -> f64 {
        let stake_history = self.stakes.read().unwrap().history().clone();

        let mut stake_delegation_accounts = self.stake_delegation_accounts(reward_calc_tracer, LoadSafety::FixedMaxRoot);

        let points: u128 = stake_delegation_accounts
            .iter()
            .flat_map(|(_vote_pubkey, (stake_group, vote_account))| {
                stake_group
                    .iter()
                    .map(move |(_stake_pubkey, stake_account)| (stake_account, vote_account))
            })
            .map(|(stake_account, vote_account)| {
                stake_state::calculate_points(
                    &stake_account,
                    &vote_account,
                    Some(&stake_history),
                    fix_stake_deactivate,
                )
                .unwrap_or(0)
            })
            .sum();

        if points == 0 {
            return 0.0;
        }

        let point_value = PointValue { rewards, points };

        let mut rewards = vec![];
        // pay according to point value
        for (vote_pubkey, (stake_group, vote_account)) in stake_delegation_accounts.iter_mut() {
            let mut vote_account_changed = false;
            let voters_account_pre_balance = vote_account.lamports;

            for (stake_pubkey, stake_account) in stake_group.iter_mut() {
                // curry closure to add the contextual stake_pubkey
                let mut reward_calc_tracer = reward_calc_tracer.as_mut().map(|outer| {
                    let stake_pubkey = *stake_pubkey;
                    // inner
                    move |inner_event: &_| {
                        outer(&RewardCalculationEvent::Staking(&stake_pubkey, inner_event))
                    }
                });
                let redeemed = stake_state::redeem_rewards(
                    rewarded_epoch,
                    stake_account,
                    vote_account,
                    &point_value,
                    Some(&stake_history),
                    &mut reward_calc_tracer.as_mut(),
                    fix_stake_deactivate,
                );
                if let Ok((stakers_reward, _voters_reward)) = redeemed {
                    self.store_account(&stake_pubkey, &stake_account);
                    vote_account_changed = true;

                    if stakers_reward > 0 {
                        rewards.push((
                            *stake_pubkey,
                            RewardInfo {
                                reward_type: RewardType::Staking,
                                lamports: stakers_reward as i64,
                                post_balance: stake_account.lamports,
                            },
                        ));
                    }
                } else {
                    debug!(
                        "stake_state::redeem_rewards() failed for {}: {:?}",
                        stake_pubkey, redeemed
                    );
                }
            }

            if vote_account_changed {
                let post_balance = vote_account.lamports;
                let lamports = (post_balance - voters_account_pre_balance) as i64;
                if lamports != 0 {
                    rewards.push((
                        *vote_pubkey,
                        RewardInfo {
                            reward_type: RewardType::Voting,
                            lamports,
                            post_balance,
                        },
                    ));
                }
                self.store_account(&vote_pubkey, &vote_account);
            }
        }
        self.rewards.write().unwrap().append(&mut rewards);

        point_value.rewards as f64 / point_value.points as f64
    }

    fn update_recent_blockhashes_locked(&self, locked_blockhash_queue: &BlockhashQueue) {
        self.update_sysvar_account(&sysvar::recent_blockhashes::id(), |account| {
            let recent_blockhash_iter = locked_blockhash_queue.get_recent_blockhashes();
            recent_blockhashes_account::create_account_with_data_and_fields(
                recent_blockhash_iter,
                self.inherit_specially_retained_account_fields(account),
            )
        });
    }

    pub fn update_recent_blockhashes(&self) {
        let blockhash_queue = self.blockhash_queue.read().unwrap();
        self.update_recent_blockhashes_locked(&blockhash_queue);
    }

    fn get_timestamp_estimate(
        &self,
        max_allowable_drift: MaxAllowableDrift,
        epoch_start_timestamp: Option<(Slot, UnixTimestamp)>,
    ) -> Option<UnixTimestamp> {
        let mut get_timestamp_estimate_time = Measure::start("get_timestamp_estimate");
        let slots_per_epoch = self.epoch_schedule().slots_per_epoch;
        let recent_timestamps =
            self.vote_accounts()
                .into_iter()
                .filter_map(|(pubkey, (_, account))| {
                    let vote_state = account.vote_state();
                    let vote_state = vote_state.as_ref().ok()?;
                    let slot_delta = self.slot().checked_sub(vote_state.last_timestamp.slot)?;
                    if slot_delta <= slots_per_epoch {
                        Some((
                            pubkey,
                            (
                                vote_state.last_timestamp.slot,
                                vote_state.last_timestamp.timestamp,
                            ),
                        ))
                    } else {
                        None
                    }
                });
        let slot_duration = Duration::from_nanos(self.ns_per_slot as u64);
        let epoch = self.epoch_schedule().get_epoch(self.slot());
        let stakes = self.epoch_vote_accounts(epoch)?;
        let stake_weighted_timestamp = calculate_stake_weighted_timestamp(
            recent_timestamps,
            stakes,
            self.slot(),
            slot_duration,
            epoch_start_timestamp,
            max_allowable_drift,
            self.feature_set
                .is_active(&feature_set::warp_timestamp_again::id()),
        );
        get_timestamp_estimate_time.stop();
        datapoint_info!(
            "bank-timestamp",
            (
                "get_timestamp_estimate_us",
                get_timestamp_estimate_time.as_us(),
                i64
            ),
        );
        stake_weighted_timestamp
    }

    // Distribute collected transaction fees for this slot to collector_id (= current leader).
    //
    // Each validator is incentivized to process more transactions to earn more transaction fees.
    // Transaction fees are rewarded for the computing resource utilization cost, directly
    // proportional to their actual processing power.
    //
    // collector_id is rotated according to stake-weighted leader schedule. So the opportunity of
    // earning transaction fees are fairly distributed by stake. And missing the opportunity
    // (not producing a block as a leader) earns nothing. So, being online is incentivized as a
    // form of transaction fees as well.
    //
    // On the other hand, rent fees are distributed under slightly different philosophy, while
    // still being stake-weighted.
    // Ref: distribute_rent_to_validators
    fn collect_fees(&self) {
        let collector_fees = self.collector_fees.load(Relaxed) as u64;

        if collector_fees != 0 {
            let (unburned, burned) = self.fee_rate_governor.burn(collector_fees);
            // burn a portion of fees
            debug!(
                "distributed fee: {} (rounded from: {}, burned: {})",
                unburned, collector_fees, burned
            );

            let post_balance = self.deposit(&self.collector_id, unburned);
            if unburned != 0 {
                self.rewards.write().unwrap().push((
                    self.collector_id,
                    RewardInfo {
                        reward_type: RewardType::Fee,
                        lamports: unburned as i64,
                        post_balance,
                    },
                ));
            }
            self.capitalization.fetch_sub(burned, Relaxed);
        }
    }

    pub fn rehash(&self) {
        let mut hash = self.hash.write().unwrap();
        let new = self.hash_internal_state();
        if new != *hash {
            warn!("Updating bank hash to {}", new);
            *hash = new;
        }
    }

    pub fn freeze(&self) {
        // This lock prevents any new commits from BankingStage
        // `process_and_record_transactions_locked()` from coming
        // in after the last tick is observed. This is because in
        // BankingStage, any transaction successfully recorded in
        // `record_transactions()` is recorded after this `hash` lock
        // is grabbed. At the time of the successful record,
        // this means the PoH has not yet reached the last tick,
        // so this means freeze() hasn't been called yet. And because
        // BankingStage doesn't release this hash lock until both
        // record and commit are finished, those transactions will be
        // committed before this write lock can be obtained here.
        let mut hash = self.hash.write().unwrap();
        if *hash == Hash::default() {
            // finish up any deferred changes to account state
            self.collect_rent_eagerly();
            self.collect_fees();
            self.distribute_rent();
            self.update_slot_history();
            self.run_incinerator();

            // freeze is a one-way trip, idempotent
            self.freeze_started.store(true, Relaxed);
            *hash = self.hash_internal_state();
            self.rc.accounts.accounts_db.mark_slot_frozen(self.slot());
        }
    }

    // Should not be called outside of startup, will race with
    // concurrent cleaning logic in AccountsBackgroundService
    pub fn exhaustively_free_unused_resource(&self) {
        let mut flush = Measure::start("flush");
        // Flush all the rooted accounts. Must be called after `squash()`,
        // so that AccountsDb knows what the roots are.
        self.force_flush_accounts_cache();
        flush.stop();

        let mut clean = Measure::start("clean");
        // Don't clean the slot we're snapshotting because it may have zero-lamport
        // accounts that were included in the bank delta hash when the bank was frozen,
        // and if we clean them here, any newly created snapshot's hash for this bank
        // may not match the frozen hash.
        self.clean_accounts(true);
        clean.stop();

        let mut shrink = Measure::start("shrink");
        self.shrink_all_slots();
        shrink.stop();

        info!(
            "exhaustively_free_unused_resource() {} {} {}",
            flush, clean, shrink,
        );
    }

    pub fn epoch_schedule(&self) -> &EpochSchedule {
        &self.epoch_schedule
    }

    /// squash the parent's state up into this Bank,
    ///   this Bank becomes a root
    pub fn squash(&self) {
        self.freeze();

        //this bank and all its parents are now on the rooted path
        let mut roots = vec![self.slot()];
        roots.append(&mut self.parents().iter().map(|p| p.slot()).collect());

        let mut squash_accounts_time = Measure::start("squash_accounts_time");
        for slot in roots.iter().rev() {
            // root forks cannot be purged
            self.rc.accounts.add_root(*slot);
        }
        squash_accounts_time.stop();

        *self.rc.parent.write().unwrap() = None;

        let mut squash_cache_time = Measure::start("squash_cache_time");
        roots
            .iter()
            .for_each(|slot| self.src.status_cache.write().unwrap().add_root(*slot));
        squash_cache_time.stop();

        datapoint_debug!(
            "tower-observed",
            ("squash_accounts_ms", squash_accounts_time.as_ms(), i64),
            ("squash_cache_ms", squash_cache_time.as_ms(), i64)
        );
    }

    /// Return the more recent checkpoint of this bank instance.
    pub fn parent(&self) -> Option<Arc<Bank>> {
        self.rc.parent.read().unwrap().clone()
    }

    pub fn parent_slot(&self) -> Slot {
        self.parent_slot
    }

    fn process_genesis_config(&mut self, genesis_config: &GenesisConfig) {
        let load_safety = LoadSafety::FixedMaxRoot;

        // Bootstrap validator collects fees until `new_from_parent` is called.
        self.fee_rate_governor = genesis_config.fee_rate_governor.clone();
        self.fee_calculator = self.fee_rate_governor.create_fee_calculator();

        for (pubkey, account) in genesis_config.accounts.iter() {
            if self.get_account(&pubkey, load_safety).is_some() {
                panic!("{} repeated in genesis config", pubkey);
            }
            self.store_account(pubkey, &AccountSharedData::from(account.clone()));
            self.capitalization.fetch_add(account.lamports, Relaxed);
        }
        // updating sysvars (the fees sysvar in this case) now depends on feature activations in
        // genesis_config.accounts above
        self.update_fees();

        for (pubkey, account) in genesis_config.rewards_pools.iter() {
            if self.get_account(&pubkey, load_safety).is_some() {
                panic!("{} repeated in genesis config", pubkey);
            }
            self.store_account(pubkey, &AccountSharedData::from(account.clone()));
        }

        // highest staked node is the first collector
        self.collector_id = self
            .stakes
            .read()
            .unwrap()
            .highest_staked_node()
            .unwrap_or_default();

        self.blockhash_queue
            .write()
            .unwrap()
            .genesis_hash(&genesis_config.hash(), &self.fee_calculator);

        self.hashes_per_tick = genesis_config.hashes_per_tick();
        self.ticks_per_slot = genesis_config.ticks_per_slot();
        self.ns_per_slot = genesis_config.ns_per_slot();
        self.genesis_creation_time = genesis_config.creation_time;
        self.unused = genesis_config.unused;
        self.max_tick_height = (self.slot + 1) * self.ticks_per_slot;
        self.slots_per_year = genesis_config.slots_per_year();

        self.epoch_schedule = genesis_config.epoch_schedule;

        self.inflation = Arc::new(RwLock::new(genesis_config.inflation));

        self.rent_collector = RentCollector::new(
            self.epoch,
            &self.epoch_schedule,
            self.slots_per_year,
            &genesis_config.rent,
        );

        // Add additional native programs specified in the genesis config
        for (name, program_id) in &genesis_config.native_instruction_processors {
            self.add_native_program(name, program_id, false, LoadSafety::FixedMaxRoot);
        }
    }

    // NOTE: must hold idempotent for the same set of arguments
    pub fn add_native_program(&self, name: &str, program_id: &Pubkey, must_replace: bool, load_safety: LoadSafety) {
        let existing_genuine_program = if let Some(mut account) = self.get_account(&program_id, load_safety) {
            // it's very unlikely to be squatted at program_id as non-system account because of burden to
            // find victim's pubkey/hash. So, when account.owner is indeed native_loader's, it's
            // safe to assume it's a genuine program.
            if native_loader::check_id(&account.owner) {
                Some(account)
            } else {
                // malicious account is pre-occupying at program_id
                // forcibly burn and purge it

                self.capitalization.fetch_sub(account.lamports, Relaxed);

                // Resetting account balance to 0 is needed to really purge from AccountsDb and
                // flush the Stakes cache
                account.lamports = 0;
                self.store_account(&program_id, &account);
                None
            }
        } else {
            None
        };

        if must_replace {
            // updating native program

            match &existing_genuine_program {
                None => panic!(
                    "There is no account to replace with native program ({}, {}).",
                    name, program_id
                ),
                Some(account) => {
                    if *name == String::from_utf8_lossy(&account.data()) {
                        // nop; it seems that already AccountsDb is updated.
                        return;
                    }
                    // continue to replace account
                }
            }
        } else {
            // introducing native program

            match &existing_genuine_program {
                None => (), // continue to add account
                Some(_account) => {
                    // nop; it seems that we already have account

                    // before returning here to retain idempotent just make sure
                    // the existing native program name is same with what we're
                    // supposed to add here (but skipping) But I can't:
                    // following assertion already catches several different names for same
                    // program_id
                    // depending on clusters...
                    // assert_eq!(name.to_owned(), String::from_utf8_lossy(&account.data));
                    return;
                }
            }
        }

        assert!(
            !self.freeze_started(),
            "Can't change frozen bank by adding not-existing new native program ({}, {}). \
            Maybe, inconsistent program activation is detected on snapshot restore?",
            name,
            program_id
        );

        // Add a bogus executable native account, which will be loaded and ignored.
        let account = native_loader::create_loadable_account_with_fields(
            name,
            self.inherit_specially_retained_account_fields(&existing_genuine_program),
        );
        self.store_account_and_update_capitalization(&program_id, &account, load_safety);

        debug!("Added native program {} under {:?}", name, program_id);
    }

    pub fn set_rent_burn_percentage(&mut self, burn_percent: u8) {
        self.rent_collector.rent.burn_percent = burn_percent;
    }

    pub fn set_hashes_per_tick(&mut self, hashes_per_tick: Option<u64>) {
        self.hashes_per_tick = hashes_per_tick;
    }

    /// Return the last block hash registered.
    pub fn last_blockhash(&self) -> Hash {
        self.blockhash_queue.read().unwrap().last_hash()
    }

    pub fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> u64 {
        self.rent_collector.rent.minimum_balance(data_len)
    }

    pub fn last_blockhash_with_fee_calculator(&self) -> (Hash, FeeCalculator) {
        let blockhash_queue = self.blockhash_queue.read().unwrap();
        let last_hash = blockhash_queue.last_hash();
        (
            last_hash,
            blockhash_queue
                .get_fee_calculator(&last_hash)
                .unwrap()
                .clone(),
        )
    }

    pub fn get_fee_calculator(&self, hash: &Hash) -> Option<FeeCalculator> {
        let blockhash_queue = self.blockhash_queue.read().unwrap();
        blockhash_queue.get_fee_calculator(hash).cloned()
    }

    pub fn get_fee_rate_governor(&self) -> &FeeRateGovernor {
        &self.fee_rate_governor
    }

    pub fn get_blockhash_last_valid_slot(&self, blockhash: &Hash) -> Option<Slot> {
        let blockhash_queue = self.blockhash_queue.read().unwrap();
        // This calculation will need to be updated to consider epoch boundaries if BlockhashQueue
        // length is made variable by epoch
        blockhash_queue
            .get_hash_age(blockhash)
            .map(|age| self.slot + blockhash_queue.len() as u64 - age)
    }

    pub fn confirmed_last_blockhash(&self) -> (Hash, FeeCalculator) {
        const NUM_BLOCKHASH_CONFIRMATIONS: usize = 3;

        let parents = self.parents();
        if parents.is_empty() {
            self.last_blockhash_with_fee_calculator()
        } else {
            let index = NUM_BLOCKHASH_CONFIRMATIONS.min(parents.len() - 1);
            parents[index].last_blockhash_with_fee_calculator()
        }
    }

    /// Forget all signatures. Useful for benchmarking.
    pub fn clear_signatures(&self) {
        self.src.status_cache.write().unwrap().clear();
    }

    pub fn clear_slot_signatures(&self, slot: Slot) {
        self.src
            .status_cache
            .write()
            .unwrap()
            .clear_slot_entries(slot);
    }

    pub fn can_commit(result: &Result<()>) -> bool {
        match result {
            Ok(_) => true,
            Err(TransactionError::InstructionError(_, _)) => true,
            Err(_) => false,
        }
    }

    fn update_transaction_statuses(&self, txs: &[Transaction], res: &[TransactionExecutionResult]) {
        let mut status_cache = self.src.status_cache.write().unwrap();
        assert_eq!(txs.len(), res.len());
        for (tx, (res, _nonce_rollback)) in txs.iter().zip(res) {
            if Self::can_commit(res) && !tx.signatures.is_empty() {
                status_cache.insert(
                    &tx.message().recent_blockhash,
                    &tx.signatures[0],
                    self.slot(),
                    res.clone(),
                );
            }
        }
    }

    /// Tell the bank which Entry IDs exist on the ledger. This function
    /// assumes subsequent calls correspond to later entries, and will boot
    /// the oldest ones once its internal cache is full. Once boot, the
    /// bank will reject transactions using that `hash`.
    pub fn register_tick(&self, hash: &Hash) {
        assert!(
            !self.freeze_started(),
            "register_tick() working on a bank that is already frozen or is undergoing freezing!"
        );

        inc_new_counter_debug!("bank-register_tick-registered", 1);
        let mut w_blockhash_queue = self.blockhash_queue.write().unwrap();
        if self.is_block_boundary(self.tick_height.load(Relaxed) + 1) {
            w_blockhash_queue.register_hash(hash, &self.fee_calculator);
            if self.fix_recent_blockhashes_sysvar_delay() {
                self.update_recent_blockhashes_locked(&w_blockhash_queue);
            }
        }
        // ReplayStage will start computing the accounts delta hash when it
        // detects the tick height has reached the boundary, so the system
        // needs to guarantee all account updates for the slot have been
        // committed before this tick height is incremented (like the blockhash
        // sysvar above)
        self.tick_height.fetch_add(1, Relaxed);
    }

    pub fn is_complete(&self) -> bool {
        self.tick_height() == self.max_tick_height()
    }

    pub fn is_block_boundary(&self, tick_height: u64) -> bool {
        tick_height % self.ticks_per_slot == 0
    }

    /// Process a Transaction. This is used for unit tests and simply calls the vector
    /// Bank::process_transactions method
    pub fn process_transaction(&self, tx: &Transaction) -> Result<()> {
        let txs = vec![tx.clone()];
        self.process_transactions(&txs)[0].clone()?;
        tx.signatures
            .get(0)
            .map_or(Ok(()), |sig| self.get_signature_status(sig).unwrap())
    }

    pub fn demote_sysvar_write_locks(&self) -> bool {
        self.feature_set
            .is_active(&feature_set::demote_sysvar_write_locks::id())
    }

    pub fn prepare_batch<'a, 'b>(&'a self, txs: &'b [Transaction]) -> TransactionBatch<'a, 'b> {
        let lock_results = self
            .rc
            .accounts
            .lock_accounts(txs, self.demote_sysvar_write_locks());
        TransactionBatch::new(lock_results, &self, txs)
    }

    pub fn prepare_simulation_batch<'a, 'b>(
        &'a self,
        txs: &'b [Transaction],
    ) -> TransactionBatch<'a, 'b> {
        let lock_results: Vec<_> = txs
            .iter()
            .map(|tx| tx.sanitize().map_err(|e| e.into()))
            .collect();
        let mut batch = TransactionBatch::new(lock_results, &self, txs);
        batch.needs_unlock = false;
        batch
    }

    /// Run transactions against a frozen bank without committing the results
    pub fn simulate_transaction(
        &self,
        transaction: Transaction,
    ) -> (Result<()>, TransactionLogMessages) {
        assert!(self.is_frozen(), "simulation bank must be frozen");

        let txs = &[transaction];
        let batch = self.prepare_simulation_batch(txs);

        let mut timings = ExecuteTimings::default();

        let (
            _loaded_accounts,
            executed,
            _inner_instructions,
            log_messages,
            _retryable_transactions,
            _transaction_count,
            _signature_count,
        ) = self.load_and_execute_transactions(
            &batch,
            // After simulation, transactions will need to be forwarded to the leader
            // for processing. During forwarding, the transaction could expire if the
            // delay is not accounted for.
            MAX_PROCESSING_AGE - MAX_TRANSACTION_FORWARDING_DELAY,
            false,
            true,
            &mut timings,
            LoadSafety::Unspecified, // Ideally we want to use FixedMaxRoot but can't
        );

        let transaction_result = executed[0].0.clone().map(|_| ());
        let log_messages = log_messages
            .get(0)
            .map_or(vec![], |messages| messages.to_vec());

        debug!("simulate_transaction: {:?}", timings);

        (transaction_result, log_messages)
    }

    pub fn unlock_accounts(&self, batch: &mut TransactionBatch) {
        if batch.needs_unlock {
            batch.needs_unlock = false;
            self.rc.accounts.unlock_accounts(
                batch.transactions(),
                batch.lock_results(),
                self.demote_sysvar_write_locks(),
            )
        }
    }

    pub fn remove_unrooted_slot(&self, slot: Slot) {
        self.rc.accounts.accounts_db.remove_unrooted_slot(slot)
    }

    pub fn set_shrink_paths(&self, paths: Vec<PathBuf>) {
        self.rc.accounts.accounts_db.set_shrink_paths(paths);
    }

    fn check_age(
        &self,
        txs: &[Transaction],
        lock_results: Vec<Result<()>>,
        max_age: usize,
        error_counters: &mut ErrorCounters,
        load_safety: LoadSafety,
    ) -> Vec<TransactionCheckResult> {
        let hash_queue = self.blockhash_queue.read().unwrap();
        txs.iter()
            .zip(lock_results)
            .map(|(tx, lock_res)| match lock_res {
                Ok(()) => {
                    let message = tx.message();
                    let hash_age = hash_queue.check_hash_age(&message.recent_blockhash, max_age);
                    if hash_age == Some(true) {
                        (Ok(()), None)
                    } else if let Some((pubkey, acc)) = self.check_tx_durable_nonce(&tx, load_safety) {
                        (Ok(()), Some(NonceRollbackPartial::new(pubkey, acc)))
                    } else if hash_age == Some(false) {
                        error_counters.blockhash_too_old += 1;
                        (Err(TransactionError::BlockhashNotFound), None)
                    } else {
                        error_counters.blockhash_not_found += 1;
                        (Err(TransactionError::BlockhashNotFound), None)
                    }
                }
                Err(e) => (Err(e), None),
            })
            .collect()
    }

    fn check_signatures(
        &self,
        txs: &[Transaction],
        lock_results: Vec<TransactionCheckResult>,
        error_counters: &mut ErrorCounters,
    ) -> Vec<TransactionCheckResult> {
        let rcache = self.src.status_cache.read().unwrap();
        txs.iter()
            .zip(lock_results)
            .map(|(tx, lock_res)| {
                if tx.signatures.is_empty() {
                    return lock_res;
                }
                {
                    let (lock_res, _nonce_rollback) = &lock_res;
                    if lock_res.is_ok()
                        && rcache
                            .get_status(
                                &tx.signatures[0],
                                &tx.message().recent_blockhash,
                                &self.ancestors,
                            )
                            .is_some()
                    {
                        error_counters.duplicate_signature += 1;
                        return (Err(TransactionError::DuplicateSignature), None);
                    }
                }
                lock_res
            })
            .collect()
    }

    fn filter_by_vote_transactions(
        &self,
        txs: &[Transaction],
        lock_results: Vec<TransactionCheckResult>,
        error_counters: &mut ErrorCounters,
    ) -> Vec<TransactionCheckResult> {
        txs.iter()
            .zip(lock_results)
            .map(|(tx, lock_res)| {
                if lock_res.0.is_ok() {
                    if is_simple_vote_transaction(tx) {
                        return lock_res;
                    }

                    error_counters.not_allowed_during_cluster_maintenance += 1;
                    return (Err(TransactionError::ClusterMaintenance), lock_res.1);
                }
                lock_res
            })
            .collect()
    }

    pub fn check_hash_age(&self, hash: &Hash, max_age: usize) -> Option<bool> {
        self.blockhash_queue
            .read()
            .unwrap()
            .check_hash_age(hash, max_age)
    }

    pub fn check_tx_durable_nonce(&self, tx: &Transaction, load_safety: LoadSafety) -> Option<(Pubkey, AccountSharedData)> {
        transaction::uses_durable_nonce(&tx)
            .and_then(|nonce_ix| transaction::get_nonce_pubkey_from_instruction(&nonce_ix, &tx))
            .and_then(|nonce_pubkey| {
                self.get_account(&nonce_pubkey, load_safety)
                    .map(|acc| (*nonce_pubkey, acc))
            })
            .filter(|(_pubkey, nonce_account)| {
                nonce_account::verify_nonce_account(nonce_account, &tx.message().recent_blockhash)
            })
    }

    // Determine if the bank is currently in an upgrade epoch, where only votes are permitted
    fn upgrade_epoch(&self) -> bool {
        match self.cluster_type() {
            #[cfg(test)]
            ClusterType::Development => self.epoch == 0xdead, // Value assumed by `test_upgrade_epoch()`
            #[cfg(not(test))]
            ClusterType::Development => false,
            ClusterType::Devnet => false,
            ClusterType::Testnet => false,
            ClusterType::MainnetBeta => self.epoch == 61,
        }
    }

    pub fn check_transactions(
        &self,
        txs: &[Transaction],
        lock_results: &[Result<()>],
        max_age: usize,
        mut error_counters: &mut ErrorCounters,
        load_safety: LoadSafety,
    ) -> Vec<TransactionCheckResult> {
        let age_results = self.check_age(txs, lock_results.to_vec(), max_age, &mut error_counters, load_safety);
        let sigcheck_results = self.check_signatures(txs, age_results, &mut error_counters);
        if self.upgrade_epoch() {
            // Reject all non-vote transactions
            self.filter_by_vote_transactions(txs, sigcheck_results, &mut error_counters)
        } else {
            sigcheck_results
        }
    }

    pub fn collect_balances(&self, batch: &TransactionBatch, load_safety: LoadSafety) -> TransactionBalances {
        let mut balances: TransactionBalances = vec![];
        for transaction in batch.transactions() {
            let mut transaction_balances: Vec<u64> = vec![];
            for account_key in transaction.message.account_keys.iter() {
                transaction_balances.push(self.get_balance(account_key, load_safety));
            }
            balances.push(transaction_balances);
        }
        balances
    }

    #[allow(clippy::cognitive_complexity)]
    fn update_error_counters(error_counters: &ErrorCounters) {
        if 0 != error_counters.total {
            inc_new_counter_info!(
                "bank-process_transactions-error_count",
                error_counters.total
            );
        }
        if 0 != error_counters.account_not_found {
            inc_new_counter_info!(
                "bank-process_transactions-account_not_found",
                error_counters.account_not_found
            );
        }
        if 0 != error_counters.account_in_use {
            inc_new_counter_info!(
                "bank-process_transactions-account_in_use",
                error_counters.account_in_use
            );
        }
        if 0 != error_counters.account_loaded_twice {
            inc_new_counter_info!(
                "bank-process_transactions-account_loaded_twice",
                error_counters.account_loaded_twice
            );
        }
        if 0 != error_counters.blockhash_not_found {
            inc_new_counter_info!(
                "bank-process_transactions-error-blockhash_not_found",
                error_counters.blockhash_not_found
            );
        }
        if 0 != error_counters.blockhash_too_old {
            inc_new_counter_info!(
                "bank-process_transactions-error-blockhash_too_old",
                error_counters.blockhash_too_old
            );
        }
        if 0 != error_counters.invalid_account_index {
            inc_new_counter_info!(
                "bank-process_transactions-error-invalid_account_index",
                error_counters.invalid_account_index
            );
        }
        if 0 != error_counters.invalid_account_for_fee {
            inc_new_counter_info!(
                "bank-process_transactions-error-invalid_account_for_fee",
                error_counters.invalid_account_for_fee
            );
        }
        if 0 != error_counters.insufficient_funds {
            inc_new_counter_info!(
                "bank-process_transactions-error-insufficient_funds",
                error_counters.insufficient_funds
            );
        }
        if 0 != error_counters.instruction_error {
            inc_new_counter_info!(
                "bank-process_transactions-error-instruction_error",
                error_counters.instruction_error
            );
        }
        if 0 != error_counters.duplicate_signature {
            inc_new_counter_info!(
                "bank-process_transactions-error-duplicate_signature",
                error_counters.duplicate_signature
            );
        }
        if 0 != error_counters.not_allowed_during_cluster_maintenance {
            inc_new_counter_info!(
                "bank-process_transactions-error-cluster-maintenance",
                error_counters.not_allowed_during_cluster_maintenance
            );
        }
    }

    /// Converts Accounts into RefCell<AccountSharedData>, this involves moving
    /// ownership by draining the source
    fn accounts_to_refcells(
        accounts: &mut TransactionAccounts,
        account_deps: &mut TransactionAccountDeps,
        loaders: &mut TransactionLoaders,
    ) -> (
        TransactionAccountRefCells,
        TransactionAccountDepRefCells,
        TransactionLoaderRefCells,
    ) {
        let account_refcells: Vec<_> = accounts
            .drain(..)
            .map(|account| Rc::new(RefCell::new(account)))
            .collect();
        let account_dep_refcells: Vec<_> = account_deps
            .drain(..)
            .map(|(pubkey, account_dep)| (pubkey, Rc::new(RefCell::new(account_dep))))
            .collect();
        let loader_refcells: Vec<Vec<_>> = loaders
            .iter_mut()
            .map(|v| {
                v.drain(..)
                    .map(|(pubkey, account)| (pubkey, Rc::new(RefCell::new(account))))
                    .collect()
            })
            .collect();
        (account_refcells, account_dep_refcells, loader_refcells)
    }

    /// Converts back from RefCell<AccountSharedData> to AccountSharedData, this involves moving
    /// ownership by draining the sources
    fn refcells_to_accounts(
        accounts: &mut TransactionAccounts,
        loaders: &mut TransactionLoaders,
        mut account_refcells: TransactionAccountRefCells,
        loader_refcells: TransactionLoaderRefCells,
    ) {
        account_refcells.drain(..).for_each(|account_refcell| {
            accounts.push(Rc::try_unwrap(account_refcell).unwrap().into_inner())
        });
        loaders
            .iter_mut()
            .zip(loader_refcells)
            .for_each(|(ls, mut lrcs)| {
                lrcs.drain(..).for_each(|(pubkey, lrc)| {
                    ls.push((pubkey, Rc::try_unwrap(lrc).unwrap().into_inner()))
                })
            });
    }

    fn compile_recorded_instructions(
        inner_instructions: &mut Vec<Option<InnerInstructionsList>>,
        instruction_recorders: Option<Vec<InstructionRecorder>>,
        message: &Message,
    ) {
        inner_instructions.push(instruction_recorders.map(|instruction_recorders| {
            instruction_recorders
                .into_iter()
                .map(|r| r.compile_instructions(message))
                .collect()
        }));
    }

    /// Get any cached executors needed by the transaction
    fn get_executors(
        &self,
        message: &Message,
        loaders: &[Vec<(Pubkey, AccountSharedData)>],
    ) -> Rc<RefCell<Executors>> {
        let mut num_executors = message.account_keys.len();
        for instruction_loaders in loaders.iter() {
            num_executors += instruction_loaders.len();
        }
        let mut executors = HashMap::with_capacity(num_executors);
        let cow_cache = self.cached_executors.read().unwrap();
        let cache = cow_cache.read().unwrap();

        for key in message.account_keys.iter() {
            if let Some(executor) = cache.get(key) {
                executors.insert(*key, executor);
            }
        }
        for instruction_loaders in loaders.iter() {
            for (key, _) in instruction_loaders.iter() {
                if let Some(executor) = cache.get(key) {
                    executors.insert(*key, executor);
                }
            }
        }

        Rc::new(RefCell::new(Executors {
            executors,
            is_dirty: false,
        }))
    }

    /// Add executors back to the bank's cache if modified
    fn update_executors(&self, executors: Rc<RefCell<Executors>>) {
        let executors = executors.borrow();
        if executors.is_dirty {
            let mut cow_cache = self.cached_executors.write().unwrap();
            let mut cache = cow_cache.write().unwrap();
            for (key, executor) in executors.executors.iter() {
                cache.put(key, (*executor).clone());
            }
        }
    }

    /// Remove an executor from the bank's cache
    pub fn remove_executor(&self, pubkey: &Pubkey) {
        let mut cow_cache = self.cached_executors.write().unwrap();
        let mut cache = cow_cache.write().unwrap();
        cache.remove(pubkey);
    }

    #[allow(clippy::type_complexity)]
    pub fn load_and_execute_transactions(
        &self,
        batch: &TransactionBatch,
        max_age: usize,
        enable_cpi_recording: bool,
        enable_log_recording: bool,
        timings: &mut ExecuteTimings,
        load_safety: LoadSafety,
    ) -> (
        Vec<TransactionLoadResult>,
        Vec<TransactionExecutionResult>,
        Vec<Option<InnerInstructionsList>>,
        Vec<TransactionLogMessages>,
        Vec<usize>,
        u64,
        u64,
    ) {
        let txs = batch.transactions();
        debug!("processing transactions: {}", txs.len());
        inc_new_counter_info!("bank-process_transactions", txs.len());
        let mut error_counters = ErrorCounters::default();
        let mut load_time = Measure::start("accounts_load");

        let retryable_txs: Vec<_> = batch
            .lock_results()
            .iter()
            .enumerate()
            .filter_map(|(index, res)| match res {
                Err(TransactionError::AccountInUse) => {
                    error_counters.account_in_use += 1;
                    Some(index)
                }
                Err(_) => None,
                Ok(_) => None,
            })
            .collect();

        let sig_results =
            self.check_transactions(txs, batch.lock_results(), max_age, &mut error_counters, load_safety);
        let mut loaded_accounts = self.rc.accounts.load_accounts(
            &self.ancestors,
            txs,
            sig_results,
            &self.blockhash_queue.read().unwrap(),
            &mut error_counters,
            &self.rent_collector,
            &self.feature_set,
        );
        load_time.stop();

        let mut execution_time = Measure::start("execution_time");
        let mut signature_count: u64 = 0;
        let mut inner_instructions: Vec<Option<InnerInstructionsList>> =
            Vec::with_capacity(txs.len());
        let mut transaction_log_messages = Vec::with_capacity(txs.len());
        let bpf_compute_budget = self
            .bpf_compute_budget
            .unwrap_or_else(BpfComputeBudget::new);

        let executed: Vec<TransactionExecutionResult> = loaded_accounts
            .iter_mut()
            .zip(txs)
            .map(|(accs, tx)| match accs {
                (Err(e), _nonce_rollback) => (Err(e.clone()), None),
                (Ok(loaded_transaction), nonce_rollback) => {
                    signature_count += u64::from(tx.message().header.num_required_signatures);

                    let executors = self.get_executors(&tx.message, &loaded_transaction.loaders);

                    let (account_refcells, account_dep_refcells, loader_refcells) =
                        Self::accounts_to_refcells(
                            &mut loaded_transaction.accounts,
                            &mut loaded_transaction.account_deps,
                            &mut loaded_transaction.loaders,
                        );

                    let instruction_recorders = if enable_cpi_recording {
                        let ix_count = tx.message.instructions.len();
                        let mut recorders = Vec::with_capacity(ix_count);
                        recorders.resize_with(ix_count, InstructionRecorder::default);
                        Some(recorders)
                    } else {
                        None
                    };

                    let log_collector = if enable_log_recording {
                        Some(Rc::new(LogCollector::default()))
                    } else {
                        None
                    };

                    let process_result = self.message_processor.process_message(
                        tx.message(),
                        &loader_refcells,
                        &account_refcells,
                        &account_dep_refcells,
                        &self.rent_collector,
                        log_collector.clone(),
                        executors.clone(),
                        instruction_recorders.as_deref(),
                        self.feature_set.clone(),
                        bpf_compute_budget,
                        &mut timings.details,
                    );

                    if enable_log_recording {
                        let log_messages: TransactionLogMessages =
                            Rc::try_unwrap(log_collector.unwrap_or_default())
                                .unwrap_or_default()
                                .into();

                        transaction_log_messages.push(log_messages);
                    }

                    Self::compile_recorded_instructions(
                        &mut inner_instructions,
                        instruction_recorders,
                        &tx.message,
                    );

                    Self::refcells_to_accounts(
                        &mut loaded_transaction.accounts,
                        &mut loaded_transaction.loaders,
                        account_refcells,
                        loader_refcells,
                    );

                    if process_result.is_ok() {
                        self.update_executors(executors);
                    }

                    let nonce_rollback =
                        if let Err(TransactionError::InstructionError(_, _)) = &process_result {
                            error_counters.instruction_error += 1;
                            nonce_rollback.clone()
                        } else if process_result.is_err() {
                            None
                        } else {
                            nonce_rollback.clone()
                        };
                    (process_result, nonce_rollback)
                }
            })
            .collect();

        execution_time.stop();

        debug!(
            "load: {}us execute: {}us txs_len={}",
            load_time.as_us(),
            execution_time.as_us(),
            txs.len(),
        );
        timings.load_us += load_time.as_us();
        timings.execute_us += execution_time.as_us();

        let mut tx_count: u64 = 0;
        let err_count = &mut error_counters.total;
        let transaction_log_collector_config =
            self.transaction_log_collector_config.read().unwrap();

        for (i, ((r, _nonce_rollback), tx)) in executed.iter().zip(txs).enumerate() {
            if let Some(debug_keys) = &self.transaction_debug_keys {
                for key in &tx.message.account_keys {
                    if debug_keys.contains(key) {
                        info!("slot: {} result: {:?} tx: {:?}", self.slot, r, tx);
                        break;
                    }
                }
            }
            if transaction_log_collector_config.filter != TransactionLogCollectorFilter::None {
                let mut transaction_log_collector = self.transaction_log_collector.write().unwrap();
                let transaction_log_index = transaction_log_collector.logs.len();

                let mut mentioned_address = false;
                if !transaction_log_collector_config
                    .mentioned_addresses
                    .is_empty()
                {
                    for key in &tx.message.account_keys {
                        if transaction_log_collector_config
                            .mentioned_addresses
                            .contains(key)
                        {
                            transaction_log_collector
                                .mentioned_address_map
                                .entry(*key)
                                .or_default()
                                .push(transaction_log_index);
                            mentioned_address = true;
                        }
                    }
                }

                let is_vote = is_simple_vote_transaction(tx);

                let store = match transaction_log_collector_config.filter {
                    TransactionLogCollectorFilter::All => !is_vote || mentioned_address,
                    TransactionLogCollectorFilter::AllWithVotes => true,
                    TransactionLogCollectorFilter::None => false,
                    TransactionLogCollectorFilter::OnlyMentionedAddresses => mentioned_address,
                };

                if store {
                    transaction_log_collector.logs.push(TransactionLogInfo {
                        signature: tx.signatures[0],
                        result: r.clone(),
                        is_vote,
                        log_messages: transaction_log_messages.get(i).cloned().unwrap_or_default(),
                    });
                }
            }

            if r.is_ok() {
                tx_count += 1;
            } else {
                if *err_count == 0 {
                    debug!("tx error: {:?} {:?}", r, tx);
                }
                *err_count += 1;
            }
        }
        if *err_count > 0 {
            debug!(
                "{} errors of {} txs",
                *err_count,
                *err_count as u64 + tx_count
            );
        }
        Self::update_error_counters(&error_counters);
        (
            loaded_accounts,
            executed,
            inner_instructions,
            transaction_log_messages,
            retryable_txs,
            tx_count,
            signature_count,
        )
    }

    fn filter_program_errors_and_collect_fee(
        &self,
        txs: &[Transaction],
        executed: &[TransactionExecutionResult],
    ) -> Vec<Result<()>> {
        let hash_queue = self.blockhash_queue.read().unwrap();
        let mut fees = 0;

        let fee_config = FeeConfig {
            secp256k1_program_enabled: self.secp256k1_program_enabled(),
        };

        let results = txs
            .iter()
            .zip(executed)
            .map(|(tx, (res, nonce_rollback))| {
                let (fee_calculator, is_durable_nonce) = nonce_rollback
                    .as_ref()
                    .map(|nonce_rollback| nonce_rollback.fee_calculator())
                    .map(|maybe_fee_calculator| (maybe_fee_calculator, true))
                    .unwrap_or_else(|| {
                        (
                            hash_queue
                                .get_fee_calculator(&tx.message().recent_blockhash)
                                .cloned(),
                            false,
                        )
                    });
                let fee_calculator = fee_calculator.ok_or(TransactionError::BlockhashNotFound)?;

                let fee = fee_calculator.calculate_fee_with_config(tx.message(), &fee_config);

                let message = tx.message();
                match *res {
                    Err(TransactionError::InstructionError(_, _)) => {
                        // credit the transaction fee even in case of InstructionError
                        // necessary to withdraw from account[0] here because previous
                        // work of doing so (in accounts.load()) is ignored by store_account()
                        //
                        // ...except nonce accounts, which will have their post-load,
                        // pre-execute account state stored
                        if !is_durable_nonce {
                            self.withdraw(&message.account_keys[0], fee)?;
                        }
                        fees += fee;
                        Ok(())
                    }
                    Ok(()) => {
                        fees += fee;
                        Ok(())
                    }
                    _ => res.clone(),
                }
            })
            .collect();

        self.collector_fees.fetch_add(fees, Relaxed);
        results
    }

    pub fn commit_transactions(
        &self,
        txs: &[Transaction],
        loaded_accounts: &mut [TransactionLoadResult],
        executed: &[TransactionExecutionResult],
        tx_count: u64,
        signature_count: u64,
        timings: &mut ExecuteTimings,
    ) -> TransactionResults {
        assert!(
            !self.freeze_started(),
            "commit_transactions() working on a bank that is already frozen or is undergoing freezing!"
        );

        self.increment_transaction_count(tx_count);
        self.increment_signature_count(signature_count);

        inc_new_counter_info!("bank-process_transactions-txs", tx_count as usize);
        inc_new_counter_info!("bank-process_transactions-sigs", signature_count as usize);

        if !txs.is_empty() {
            let processed_tx_count = txs.len() as u64;
            let failed_tx_count = processed_tx_count.saturating_sub(tx_count);
            self.transaction_error_count
                .fetch_add(failed_tx_count, Relaxed);
            self.transaction_entries_count.fetch_add(1, Relaxed);
            self.transactions_per_entry_max
                .fetch_max(processed_tx_count, Relaxed);
        }

        if executed
            .iter()
            .any(|(res, _nonce_rollback)| Self::can_commit(res))
        {
            self.is_delta.store(true, Relaxed);
        }

        let mut write_time = Measure::start("write_time");
        self.rc.accounts.store_cached(
            self.slot(),
            txs,
            executed,
            loaded_accounts,
            &self.rent_collector,
            &self.last_blockhash_with_fee_calculator(),
            self.fix_recent_blockhashes_sysvar_delay(),
            self.demote_sysvar_write_locks(),
        );
        self.collect_rent(executed, loaded_accounts);

        let overwritten_vote_accounts = self.update_cached_accounts(txs, executed, loaded_accounts);

        // once committed there is no way to unroll
        write_time.stop();
        debug!("store: {}us txs_len={}", write_time.as_us(), txs.len(),);
        timings.store_us += write_time.as_us();
        self.update_transaction_statuses(txs, &executed);
        let fee_collection_results = self.filter_program_errors_and_collect_fee(txs, executed);

        TransactionResults {
            fee_collection_results,
            execution_results: executed.to_vec(),
            overwritten_vote_accounts,
        }
    }

    // Distribute collected rent fees for this slot to staked validators (excluding stakers)
    // according to stake.
    //
    // The nature of rent fee is the cost of doing business, every validator has to hold (or have
    // access to) the same list of accounts, so we pay according to stake, which is a rough proxy for
    // value to the network.
    //
    // Currently, rent distribution doesn't consider given validator's uptime at all (this might
    // change). That's because rent should be rewarded for the storage resource utilization cost.
    // It's treated differently from transaction fees, which is for the computing resource
    // utilization cost.
    //
    // We can't use collector_id (which is rotated according to stake-weighted leader schedule)
    // as an approximation to the ideal rent distribution to simplify and avoid this per-slot
    // computation for the distribution (time: N log N, space: N acct. stores; N = # of
    // validators).
    // The reason is that rent fee doesn't need to be incentivized for throughput unlike transaction
    // fees
    //
    // Ref: collect_fees
    #[allow(clippy::needless_collect)]
    fn distribute_rent_to_validators<I>(&self, vote_accounts: I, rent_to_be_distributed: u64)
    where
        I: IntoIterator<Item = (Pubkey, (u64, ArcVoteAccount))>,
    {
        let mut total_staked = 0;

        // Collect the stake associated with each validator.
        // Note that a validator may be present in this vector multiple times if it happens to have
        // more than one staked vote account somehow
        let mut validator_stakes = vote_accounts
            .into_iter()
            .filter_map(|(_vote_pubkey, (staked, account))| {
                if staked == 0 {
                    None
                } else {
                    total_staked += staked;
                    let node_pubkey = account.vote_state().as_ref().ok()?.node_pubkey;
                    Some((node_pubkey, staked))
                }
            })
            .collect::<Vec<(Pubkey, u64)>>();

        #[cfg(test)]
        if validator_stakes.is_empty() {
            // some tests bank.freezes() with bad staking state
            self.capitalization
                .fetch_sub(rent_to_be_distributed, Relaxed);
            return;
        }
        #[cfg(not(test))]
        assert!(!validator_stakes.is_empty());

        // Sort first by stake and then by validator identity pubkey for determinism
        validator_stakes.sort_by(|(pubkey1, staked1), (pubkey2, staked2)| {
            match staked2.cmp(staked1) {
                std::cmp::Ordering::Equal => pubkey2.cmp(pubkey1),
                other => other,
            }
        });

        let enforce_fix = self.no_overflow_rent_distribution_enabled();

        let mut rent_distributed_in_initial_round = 0;
        let validator_rent_shares = validator_stakes
            .into_iter()
            .map(|(pubkey, staked)| {
                let rent_share = if !enforce_fix {
                    (((staked * rent_to_be_distributed) as f64) / (total_staked as f64)) as u64
                } else {
                    (((staked as u128) * (rent_to_be_distributed as u128)) / (total_staked as u128))
                        .try_into()
                        .unwrap()
                };
                rent_distributed_in_initial_round += rent_share;
                (pubkey, rent_share)
            })
            .collect::<Vec<(Pubkey, u64)>>();

        // Leftover lamports after fraction calculation, will be paid to validators starting from highest stake
        // holder
        let mut leftover_lamports = rent_to_be_distributed - rent_distributed_in_initial_round;

        let mut rewards = vec![];
        validator_rent_shares
            .into_iter()
            .for_each(|(pubkey, rent_share)| {
                let rent_to_be_paid = if leftover_lamports > 0 {
                    leftover_lamports -= 1;
                    rent_share + 1
                } else {
                    rent_share
                };
                if !enforce_fix || rent_to_be_paid > 0 {
                    let mut account = self.get_account(&pubkey, LoadSafety::FixedMaxRoot).unwrap_or_default();
                    account.lamports += rent_to_be_paid;
                    self.store_account(&pubkey, &account);
                    rewards.push((
                        pubkey,
                        RewardInfo {
                            reward_type: RewardType::Rent,
                            lamports: rent_to_be_paid as i64,
                            post_balance: account.lamports,
                        },
                    ));
                }
            });
        self.rewards.write().unwrap().append(&mut rewards);

        if enforce_fix {
            assert_eq!(leftover_lamports, 0);
        } else if leftover_lamports != 0 {
            warn!(
                "There was leftover from rent distribution: {}",
                leftover_lamports
            );
            self.capitalization.fetch_sub(leftover_lamports, Relaxed);
        }
    }

    fn distribute_rent(&self) {
        let total_rent_collected = self.collected_rent.load(Relaxed);

        let (burned_portion, rent_to_be_distributed) = self
            .rent_collector
            .rent
            .calculate_burn(total_rent_collected);

        debug!(
            "distributed rent: {} (rounded from: {}, burned: {})",
            rent_to_be_distributed, total_rent_collected, burned_portion
        );
        self.capitalization.fetch_sub(burned_portion, Relaxed);

        if rent_to_be_distributed == 0 {
            return;
        }

        self.distribute_rent_to_validators(self.vote_accounts(), rent_to_be_distributed);
    }

    fn collect_rent(
        &self,
        res: &[TransactionExecutionResult],
        loaded_accounts: &[TransactionLoadResult],
    ) {
        let mut collected_rent: u64 = 0;
        for (i, (raccs, _nonce_rollback)) in loaded_accounts.iter().enumerate() {
            let (res, _nonce_rollback) = &res[i];
            if res.is_err() || raccs.is_err() {
                continue;
            }

            let loaded_transaction = raccs.as_ref().unwrap();

            collected_rent += loaded_transaction.rent;
        }

        self.collected_rent.fetch_add(collected_rent, Relaxed);
    }

    fn run_incinerator(&self) {
        if let Some((account, _)) = self.get_account_modified_since_parent(&incinerator::id(), LoadSafety::FixedMaxRoot) {
            self.capitalization.fetch_sub(account.lamports, Relaxed);
            self.store_account(&incinerator::id(), &AccountSharedData::default());
        }
    }

    fn collect_rent_eagerly(&self) {
        if !self.enable_eager_rent_collection() {
            return;
        }

        let mut measure = Measure::start("collect_rent_eagerly-ms");
        for partition in self.rent_collection_partitions() {
            self.collect_rent_in_partition(partition);
        }
        measure.stop();
        inc_new_counter_info!("collect_rent_eagerly-ms", measure.as_ms() as usize);
    }

    #[cfg(test)]
    fn restore_old_behavior_for_fragile_tests(&self) {
        self.lazy_rent_collection.store(true, Relaxed);
        self.no_stake_rewrite.store(true, Relaxed);
    }

    fn enable_eager_rent_collection(&self) -> bool {
        if self.lazy_rent_collection.load(Relaxed) {
            return false;
        }

        true
    }

    fn rent_collection_partitions(&self) -> Vec<Partition> {
        if !self.use_fixed_collection_cycle() {
            // This mode is for production/development/testing.
            // In this mode, we iterate over the whole pubkey value range for each epochs
            // including warm-up epochs.
            // The only exception is the situation where normal epochs are relatively short
            // (currently less than 2 day). In that case, we arrange a single collection
            // cycle to be multiple of epochs so that a cycle could be greater than the 2 day.
            self.variable_cycle_partitions()
        } else {
            // This mode is mainly for benchmarking only.
            // In this mode, we always iterate over the whole pubkey value range with
            // <slot_count_in_two_day> slots as a collection cycle, regardless warm-up or
            // alignment between collection cycles and epochs.
            // Thus, we can simulate stable processing load of eager rent collection,
            // strictly proportional to the number of pubkeys since genesis.
            self.fixed_cycle_partitions()
        }
    }

    fn collect_rent_in_partition(&self, partition: Partition) {
        let subrange = Self::pubkey_range_from_partition(partition);

        let accounts = self
            .rc
            .accounts
            .load_to_collect_rent_eagerly(&self.ancestors, subrange);
        let account_count = accounts.len();

        // parallelize?
        let mut rent = 0;
        for (pubkey, mut account) in accounts {
            rent += self
                .rent_collector
                .collect_from_existing_account(&pubkey, &mut account);
            // Store all of them unconditionally to purge old AppendVec,
            // even if collected rent is 0 (= not updated).
            self.store_account(&pubkey, &account);
        }
        self.collected_rent.fetch_add(rent, Relaxed);

        datapoint_info!("collect_rent_eagerly", ("accounts", account_count, i64));
    }

    // Mostly, the pair (start_index & end_index) is equivalent to this range:
    // start_index..=end_index. But it has some exceptional cases, including
    // this important and valid one:
    //   0..=0: the first partition in the new epoch when crossing epochs
    fn pubkey_range_from_partition(
        (start_index, end_index, partition_count): Partition,
    ) -> RangeInclusive<Pubkey> {
        assert!(start_index <= end_index);
        assert!(start_index < partition_count);
        assert!(end_index < partition_count);
        assert!(0 < partition_count);

        type Prefix = u64;
        const PREFIX_SIZE: usize = mem::size_of::<Prefix>();
        const PREFIX_MAX: Prefix = Prefix::max_value();

        let mut start_pubkey = [0x00u8; 32];
        let mut end_pubkey = [0xffu8; 32];

        if partition_count == 1 {
            assert_eq!(start_index, 0);
            assert_eq!(end_index, 0);
            return Pubkey::new_from_array(start_pubkey)..=Pubkey::new_from_array(end_pubkey);
        }

        // not-overflowing way of `(Prefix::max_value() + 1) / partition_count`
        let partition_width = (PREFIX_MAX - partition_count + 1) / partition_count + 1;
        let mut start_key_prefix = if start_index == 0 && end_index == 0 {
            0
        } else if start_index + 1 == partition_count {
            PREFIX_MAX
        } else {
            (start_index + 1) * partition_width
        };

        let mut end_key_prefix = if end_index + 1 == partition_count {
            PREFIX_MAX
        } else {
            (end_index + 1) * partition_width - 1
        };

        if start_index != 0 && start_index == end_index {
            // n..=n (n != 0): a noop pair across epochs without a gap under
            // multi_epoch_cycle, just nullify it.
            if end_key_prefix == PREFIX_MAX {
                start_key_prefix = end_key_prefix;
                start_pubkey = end_pubkey;
            } else {
                end_key_prefix = start_key_prefix;
                end_pubkey = start_pubkey;
            }
        }

        start_pubkey[0..PREFIX_SIZE].copy_from_slice(&start_key_prefix.to_be_bytes());
        end_pubkey[0..PREFIX_SIZE].copy_from_slice(&end_key_prefix.to_be_bytes());
        trace!(
            "pubkey_range_from_partition: ({}-{})/{} [{}]: {}-{}",
            start_index,
            end_index,
            partition_count,
            (end_key_prefix - start_key_prefix),
            start_pubkey.iter().map(|x| format!("{:02x}", x)).join(""),
            end_pubkey.iter().map(|x| format!("{:02x}", x)).join(""),
        );
        // should be an inclusive range (a closed interval) like this:
        // [0xgg00-0xhhff], [0xii00-0xjjff], ... (where 0xii00 == 0xhhff + 1)
        Pubkey::new_from_array(start_pubkey)..=Pubkey::new_from_array(end_pubkey)
    }

    fn fixed_cycle_partitions(&self) -> Vec<Partition> {
        let slot_count_in_two_day = self.slot_count_in_two_day();

        let parent_cycle = self.parent_slot() / slot_count_in_two_day;
        let current_cycle = self.slot() / slot_count_in_two_day;
        let mut parent_cycle_index = self.parent_slot() % slot_count_in_two_day;
        let current_cycle_index = self.slot() % slot_count_in_two_day;
        let mut partitions = vec![];
        if parent_cycle < current_cycle {
            if current_cycle_index > 0 {
                // generate and push gapped partitions because some slots are skipped
                let parent_last_cycle_index = slot_count_in_two_day - 1;

                // ... for parent cycle
                partitions.push((
                    parent_cycle_index,
                    parent_last_cycle_index,
                    slot_count_in_two_day,
                ));

                // ... for current cycle
                partitions.push((0, 0, slot_count_in_two_day));
            }
            parent_cycle_index = 0;
        }

        partitions.push((
            parent_cycle_index,
            current_cycle_index,
            slot_count_in_two_day,
        ));

        partitions
    }

    fn variable_cycle_partitions(&self) -> Vec<Partition> {
        let (current_epoch, current_slot_index) = self.get_epoch_and_slot_index(self.slot());
        let (parent_epoch, mut parent_slot_index) =
            self.get_epoch_and_slot_index(self.parent_slot());

        let mut partitions = vec![];
        if parent_epoch < current_epoch {
            let slot_skipped = (self.slot() - self.parent_slot()) > 1;
            if slot_skipped {
                // Generate special partitions because there are skipped slots
                // exactly at the epoch transition.

                let parent_last_slot_index = self.get_slots_in_epoch(parent_epoch) - 1;

                // ... for parent epoch
                partitions.push(self.partition_from_slot_indexes_with_gapped_epochs(
                    parent_slot_index,
                    parent_last_slot_index,
                    parent_epoch,
                ));

                if current_slot_index > 0 {
                    // ... for current epoch
                    partitions.push(self.partition_from_slot_indexes_with_gapped_epochs(
                        0,
                        0,
                        current_epoch,
                    ));
                }
            }
            parent_slot_index = 0;
        }

        partitions.push(self.partition_from_normal_slot_indexes(
            parent_slot_index,
            current_slot_index,
            current_epoch,
        ));

        partitions
    }

    fn do_partition_from_slot_indexes(
        &self,
        start_slot_index: SlotIndex,
        end_slot_index: SlotIndex,
        epoch: Epoch,
        generated_for_gapped_epochs: bool,
    ) -> Partition {
        let cycle_params = self.determine_collection_cycle_params(epoch);
        let (_, _, in_multi_epoch_cycle, _, _, partition_count) = cycle_params;

        // use common codepath for both very likely and very unlikely for the sake of minimized
        // risk of any miscalculation instead of negligibly faster computation per slot for the
        // likely case.
        let mut start_partition_index =
            Self::partition_index_from_slot_index(start_slot_index, cycle_params);
        let mut end_partition_index =
            Self::partition_index_from_slot_index(end_slot_index, cycle_params);

        // Adjust partition index for some edge cases
        let is_special_new_epoch = start_slot_index == 0 && end_slot_index != 1;
        let in_middle_of_cycle = start_partition_index > 0;
        if in_multi_epoch_cycle && is_special_new_epoch && in_middle_of_cycle {
            // Adjust slot indexes so that the final partition ranges are continuous!
            // This is need because the caller gives us off-by-one indexes when
            // an epoch boundary is crossed.
            // Usually there is no need for this adjustment because cycles are aligned
            // with epochs. But for multi-epoch cycles, adjust the indexes if it
            // happens in the middle of a cycle for both gapped and not-gapped cases:
            //
            // epoch (slot range)|slot idx.*1|raw part. idx.|adj. part. idx.|epoch boundary
            // ------------------+-----------+--------------+---------------+--------------
            // 3 (20..30)        | [7..8]    |   7.. 8      |   7.. 8
            //                   | [8..9]    |   8.. 9      |   8.. 9
            // 4 (30..40)        | [0..0]    |<10>..10      | <9>..10      <--- not gapped
            //                   | [0..1]    |  10..11      |  10..12
            //                   | [1..2]    |  11..12      |  11..12
            //                   | [2..9   *2|  12..19      |  12..19      <-+
            // 5 (40..50)        |  0..0   *2|<20>..<20>    |<19>..<19> *3 <-+- gapped
            //                   |  0..4]    |<20>..24      |<19>..24      <-+
            //                   | [4..5]    |  24..25      |  24..25
            //                   | [5..6]    |  25..26      |  25..26
            //
            // NOTE: <..> means the adjusted slots
            //
            // *1: The range of parent_bank.slot() and current_bank.slot() is firstly
            //     split by the epoch boundaries and then the split ones are given to us.
            //     The original ranges are denoted as [...]
            // *2: These are marked with generated_for_gapped_epochs = true.
            // *3: This becomes no-op partition
            start_partition_index -= 1;
            if generated_for_gapped_epochs {
                assert_eq!(start_slot_index, end_slot_index);
                end_partition_index -= 1;
            }
        }

        (start_partition_index, end_partition_index, partition_count)
    }

    fn partition_from_normal_slot_indexes(
        &self,
        start_slot_index: SlotIndex,
        end_slot_index: SlotIndex,
        epoch: Epoch,
    ) -> Partition {
        self.do_partition_from_slot_indexes(start_slot_index, end_slot_index, epoch, false)
    }

    fn partition_from_slot_indexes_with_gapped_epochs(
        &self,
        start_slot_index: SlotIndex,
        end_slot_index: SlotIndex,
        epoch: Epoch,
    ) -> Partition {
        self.do_partition_from_slot_indexes(start_slot_index, end_slot_index, epoch, true)
    }

    fn determine_collection_cycle_params(&self, epoch: Epoch) -> RentCollectionCycleParams {
        let slot_count_per_epoch = self.get_slots_in_epoch(epoch);

        if !self.use_multi_epoch_collection_cycle(epoch) {
            (
                epoch,
                slot_count_per_epoch,
                false,
                0,
                1,
                slot_count_per_epoch,
            )
        } else {
            let epoch_count_in_cycle = self.slot_count_in_two_day() / slot_count_per_epoch;
            let partition_count = slot_count_per_epoch * epoch_count_in_cycle;

            (
                epoch,
                slot_count_per_epoch,
                true,
                self.first_normal_epoch(),
                epoch_count_in_cycle,
                partition_count,
            )
        }
    }

    fn partition_index_from_slot_index(
        slot_index_in_epoch: SlotIndex,
        (
            epoch,
            slot_count_per_epoch,
            _,
            base_epoch,
            epoch_count_per_cycle,
            _,
        ): RentCollectionCycleParams,
    ) -> PartitionIndex {
        let epoch_offset = epoch - base_epoch;
        let epoch_index_in_cycle = epoch_offset % epoch_count_per_cycle;
        slot_index_in_epoch + epoch_index_in_cycle * slot_count_per_epoch
    }

    // Given short epochs, it's too costly to collect rent eagerly
    // within an epoch, so lower the frequency of it.
    // These logic isn't strictly eager anymore and should only be used
    // for development/performance purpose.
    // Absolutely not under ClusterType::MainnetBeta!!!!
    fn use_multi_epoch_collection_cycle(&self, epoch: Epoch) -> bool {
        // Force normal behavior, disabling multi epoch collection cycle for manual local testing
        #[cfg(not(test))]
        if self.slot_count_per_normal_epoch() == solana_sdk::epoch_schedule::MINIMUM_SLOTS_PER_EPOCH
        {
            return false;
        }

        epoch >= self.first_normal_epoch()
            && self.slot_count_per_normal_epoch() < self.slot_count_in_two_day()
    }

    fn use_fixed_collection_cycle(&self) -> bool {
        // Force normal behavior, disabling fixed collection cycle for manual local testing
        #[cfg(not(test))]
        if self.slot_count_per_normal_epoch() == solana_sdk::epoch_schedule::MINIMUM_SLOTS_PER_EPOCH
        {
            return false;
        }

        self.cluster_type() != ClusterType::MainnetBeta
            && self.slot_count_per_normal_epoch() < self.slot_count_in_two_day()
    }

    // This value is specially chosen to align with slots per epoch in mainnet-beta and testnet
    // Also, assume 500GB account data set as the extreme, then for 2 day (=48 hours) to collect
    // rent eagerly, we'll consume 5.7 MB/s IO bandwidth, bidirectionally.
    fn slot_count_in_two_day(&self) -> SlotCount {
        2 * DEFAULT_TICKS_PER_SECOND * SECONDS_PER_DAY / self.ticks_per_slot
    }

    fn slot_count_per_normal_epoch(&self) -> SlotCount {
        self.get_slots_in_epoch(self.first_normal_epoch())
    }

    pub fn cluster_type(&self) -> ClusterType {
        // unwrap is safe; self.cluster_type is ensured to be Some() always...
        // we only using Option here for ABI compatibility...
        self.cluster_type.unwrap()
    }

    /// Process a batch of transactions.
    #[must_use]
    pub fn load_execute_and_commit_transactions(
        &self,
        batch: &TransactionBatch,
        max_age: usize,
        collect_balances: bool,
        enable_cpi_recording: bool,
        enable_log_recording: bool,
        timings: &mut ExecuteTimings,
    ) -> (
        TransactionResults,
        TransactionBalancesSet,
        Vec<Option<InnerInstructionsList>>,
        Vec<TransactionLogMessages>,
    ) {
        let pre_balances = if collect_balances {
            self.collect_balances(batch, LoadSafety::FixedMaxRoot)
        } else {
            vec![]
        };

        let (
            mut loaded_accounts,
            executed,
            inner_instructions,
            transaction_logs,
            _,
            tx_count,
            signature_count,
        ) = self.load_and_execute_transactions(
            batch,
            max_age,
            enable_cpi_recording,
            enable_log_recording,
            timings,
            LoadSafety::FixedMaxRoot,
        );

        let results = self.commit_transactions(
            batch.transactions(),
            &mut loaded_accounts,
            &executed,
            tx_count,
            signature_count,
            timings,
        );
        let post_balances = if collect_balances {
            self.collect_balances(batch, LoadSafety::FixedMaxRoot)
        } else {
            vec![]
        };
        (
            results,
            TransactionBalancesSet::new(pre_balances, post_balances),
            inner_instructions,
            transaction_logs,
        )
    }

    #[must_use]
    pub fn process_transactions(&self, txs: &[Transaction]) -> Vec<Result<()>> {
        let batch = self.prepare_batch(txs);
        self.load_execute_and_commit_transactions(
            &batch,
            MAX_PROCESSING_AGE,
            false,
            false,
            false,
            &mut ExecuteTimings::default(),
        )
        .0
        .fee_collection_results
    }

    /// Create, sign, and process a Transaction from `keypair` to `to` of
    /// `n` lamports where `blockhash` is the last Entry ID observed by the client.
    pub fn transfer(&self, n: u64, keypair: &Keypair, to: &Pubkey) -> Result<Signature> {
        let blockhash = self.last_blockhash();
        let tx = system_transaction::transfer(keypair, to, n, blockhash);
        let signature = tx.signatures[0];
        self.process_transaction(&tx).map(|_| signature)
    }

    pub fn read_balance(account: &AccountSharedData) -> u64 {
        account.lamports
    }
    /// Each program would need to be able to introspect its own state
    /// this is hard-coded to the Budget language
    pub fn get_balance(&self, pubkey: &Pubkey, load_safety: LoadSafety) -> u64 {
        self.get_account(pubkey, load_safety)
            .map(|x| Self::read_balance(&x))
            .unwrap_or(0)
    }

    pub fn get_balance_for_test(&self, pubkey: &Pubkey) -> u64 {
        self.get_balance(pubkey, LoadSafety::FixedMaxRoot)
    }

    /// Compute all the parents of the bank in order
    pub fn parents(&self) -> Vec<Arc<Bank>> {
        let mut parents = vec![];
        let mut bank = self.parent();
        while let Some(parent) = bank {
            parents.push(parent.clone());
            bank = parent.parent();
        }
        parents
    }

    /// Compute all the parents of the bank including this bank itself
    pub fn parents_inclusive(self: Arc<Self>) -> Vec<Arc<Bank>> {
        let mut parents = self.parents();
        parents.insert(0, self);
        parents
    }

    pub fn store_account(&self, pubkey: &Pubkey, account: &AccountSharedData) {
        assert!(!self.freeze_started());
        self.rc
            .accounts
            .store_slow_cached(self.slot(), pubkey, account);

        if Stakes::is_stake(account) {
            self.stakes.write().unwrap().store(
                pubkey,
                account,
                self.stake_program_v2_enabled(),
                self.check_init_vote_data_enabled(),
            );
        }
    }

    pub fn force_flush_accounts_cache(&self) {
        self.rc
            .accounts
            .accounts_db
            .flush_accounts_cache(true, Some(self.slot()))
    }

    pub fn flush_accounts_cache_if_needed(&self) {
        self.rc
            .accounts
            .accounts_db
            .flush_accounts_cache(false, Some(self.slot()))
    }

    pub fn expire_old_recycle_stores(&self) {
        self.rc.accounts.accounts_db.expire_old_recycle_stores()
    }

    /// Technically this issues (or even burns!) new lamports,
    /// so be extra careful for its usage
    fn store_account_and_update_capitalization(
        &self,
        pubkey: &Pubkey,
        new_account: &AccountSharedData,
        load_safety: LoadSafety,
    ) {
        if let Some(old_account) = self.get_account(&pubkey, load_safety) {
            match new_account.lamports.cmp(&old_account.lamports) {
                std::cmp::Ordering::Greater => {
                    self.capitalization
                        .fetch_add(new_account.lamports - old_account.lamports, Relaxed);
                }
                std::cmp::Ordering::Less => {
                    self.capitalization
                        .fetch_sub(old_account.lamports - new_account.lamports, Relaxed);
                }
                std::cmp::Ordering::Equal => {}
            }
        } else {
            self.capitalization.fetch_add(new_account.lamports, Relaxed);
        }

        self.store_account(pubkey, new_account);
    }

    pub fn withdraw(&self, pubkey: &Pubkey, lamports: u64) -> Result<()> {
        match self.get_account(pubkey, LoadSafety::FixedMaxRoot) {
            Some(mut account) => {
                let min_balance = match get_system_account_kind(&account) {
                    Some(SystemAccountKind::Nonce) => self
                        .rent_collector
                        .rent
                        .minimum_balance(nonce::State::size()),
                    _ => 0,
                };
                if lamports + min_balance > account.lamports {
                    return Err(TransactionError::InsufficientFundsForFee);
                }

                account.lamports -= lamports;
                self.store_account(pubkey, &account);

                Ok(())
            }
            None => Err(TransactionError::AccountNotFound),
        }
    }

    pub fn deposit(&self, pubkey: &Pubkey, lamports: u64) -> u64 {
        // This doesn't collect rents intentionally.
        // Rents should only be applied to actual TXes
        let mut account = self.get_account(pubkey, LoadSafety::FixedMaxRoot).unwrap_or_default();
        account.lamports += lamports;
        self.store_account(pubkey, &account);
        account.lamports
    }

    pub fn accounts(&self) -> Arc<Accounts> {
        self.rc.accounts.clone()
    }

    fn finish_init(
        &mut self,
        genesis_config: &GenesisConfig,
        additional_builtins: Option<&Builtins>,
    ) {
        self.rewards_pool_pubkeys =
            Arc::new(genesis_config.rewards_pools.keys().cloned().collect());

        let mut builtins = builtins::get();
        if let Some(additional_builtins) = additional_builtins {
            builtins
                .genesis_builtins
                .extend_from_slice(&additional_builtins.genesis_builtins);
            builtins
                .feature_builtins
                .extend_from_slice(&additional_builtins.feature_builtins);
        }
        for builtin in builtins.genesis_builtins {
            self.add_builtin(
                &builtin.name,
                builtin.id,
                builtin.process_instruction_with_context,
                LoadSafety::FixedMaxRoot,
            );
        }
        self.feature_builtins = Arc::new(builtins.feature_builtins);

        self.apply_feature_activations(true);
    }

    pub fn set_inflation(&self, inflation: Inflation) {
        *self.inflation.write().unwrap() = inflation;
    }

    pub fn set_bpf_compute_budget(&mut self, bpf_compute_budget: Option<BpfComputeBudget>) {
        self.bpf_compute_budget = bpf_compute_budget;
    }

    pub fn hard_forks(&self) -> Arc<RwLock<HardForks>> {
        self.hard_forks.clone()
    }

    pub fn get_account(&self, pubkey: &Pubkey, load_safety: LoadSafety) -> Option<AccountSharedData> {
        self.get_account_modified_slot(pubkey, load_safety)
            .map(|(acc, _slot)| acc)
    }

    pub fn get_account_for_test(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        self.get_account_modified_slot(pubkey, LoadSafety::FixedMaxRoot)
            .map(|(acc, _slot)| acc)
    }

    pub fn get_account_modified_slot(&self, pubkey: &Pubkey, load_safety: LoadSafety) -> Option<(AccountSharedData, Slot)> {
        self.load_slow(&self.ancestors, pubkey, load_safety)
    }

    fn load_slow(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        load_safety: LoadSafety,
    ) -> Option<(AccountSharedData, Slot)> {
        self.rc
            .accounts
            .load_slow(ancestors, pubkey, load_safety)
    }

    // Exclude self to really fetch the parent Bank's account hash and data.
    //
    // Being idempotent is needed to make the lazy initialization possible,
    // especially for update_slot_hashes at the moment, which can be called
    // multiple times with the same parent_slot in the case of forking.
    //
    // Generally, all of sysvar update granularity should be slot boundaries.
    fn get_sysvar_account_with_fixed_root(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        let mut ancestors = self.ancestors.clone();
        ancestors.remove(&self.slot());
        self.rc
            .accounts
            .load_with_fixed_root(&ancestors, pubkey)
            .map(|(acc, _slot)| acc)
    }

    pub fn get_program_accounts(&self, program_id: &Pubkey) -> Vec<(Pubkey, AccountSharedData)> {
        self.rc
            .accounts
            .load_by_program(&self.ancestors, program_id)
    }

    pub fn get_filtered_program_accounts<F: Fn(&AccountSharedData) -> bool>(
        &self,
        program_id: &Pubkey,
        filter: F,
    ) -> Vec<(Pubkey, AccountSharedData)> {
        self.rc
            .accounts
            .load_by_program_with_filter(&self.ancestors, program_id, filter)
    }

    pub fn get_filtered_indexed_accounts<F: Fn(&AccountSharedData) -> bool>(
        &self,
        index_key: &IndexKey,
        filter: F,
    ) -> Vec<(Pubkey, AccountSharedData)> {
        self.rc
            .accounts
            .load_by_index_key_with_filter(&self.ancestors, index_key, filter)
    }

    pub fn get_all_accounts_with_modified_slots(&self) -> Vec<(Pubkey, AccountSharedData, Slot)> {
        self.rc.accounts.load_all(&self.ancestors)
    }

    pub fn get_program_accounts_modified_since_parent(
        &self,
        program_id: &Pubkey,
    ) -> Vec<(Pubkey, AccountSharedData)> {
        self.rc
            .accounts
            .load_by_program_slot(self.slot(), Some(program_id))
    }

    pub fn get_transaction_logs(
        &self,
        address: Option<&Pubkey>,
    ) -> Option<Vec<TransactionLogInfo>> {
        let transaction_log_collector = self.transaction_log_collector.read().unwrap();

        match address {
            None => Some(transaction_log_collector.logs.clone()),
            Some(address) => transaction_log_collector
                .mentioned_address_map
                .get(address)
                .map(|log_indices| {
                    log_indices
                        .iter()
                        .map(|i| transaction_log_collector.logs[*i].clone())
                        .collect()
                }),
        }
    }

    pub fn get_all_accounts_modified_since_parent(&self) -> Vec<(Pubkey, AccountSharedData)> {
        self.rc.accounts.load_by_program_slot(self.slot(), None)
    }

    pub fn get_account_modified_since_parent(
        &self,
        pubkey: &Pubkey,
        load_safety: LoadSafety,
    ) -> Option<(AccountSharedData, Slot)> {
        let just_self: Ancestors = vec![(self.slot(), 0)].into_iter().collect();
        if let Some((account, slot)) = self.load_slow(&just_self, pubkey, load_safety) {
            if slot == self.slot() {
                return Some((account, slot));
            }
        }
        None
    }

    pub fn get_largest_accounts(
        &self,
        num: usize,
        filter_by_address: &HashSet<Pubkey>,
        filter: AccountAddressFilter,
    ) -> Vec<(Pubkey, u64)> {
        self.rc
            .accounts
            .load_largest_accounts(&self.ancestors, num, filter_by_address, filter)
    }

    pub fn transaction_count(&self) -> u64 {
        self.transaction_count.load(Relaxed)
    }

    pub fn transaction_error_count(&self) -> u64 {
        self.transaction_error_count.load(Relaxed)
    }

    pub fn transaction_entries_count(&self) -> u64 {
        self.transaction_entries_count.load(Relaxed)
    }

    pub fn transactions_per_entry_max(&self) -> u64 {
        self.transactions_per_entry_max.load(Relaxed)
    }

    fn increment_transaction_count(&self, tx_count: u64) {
        self.transaction_count.fetch_add(tx_count, Relaxed);
    }

    pub fn signature_count(&self) -> u64 {
        self.signature_count.load(Relaxed)
    }

    fn increment_signature_count(&self, signature_count: u64) {
        self.signature_count.fetch_add(signature_count, Relaxed);
    }

    pub fn get_signature_status_processed_since_parent(
        &self,
        signature: &Signature,
    ) -> Option<Result<()>> {
        if let Some((slot, status)) = self.get_signature_status_slot(signature) {
            if slot <= self.slot() {
                return Some(status);
            }
        }
        None
    }

    pub fn get_signature_status_with_blockhash(
        &self,
        signature: &Signature,
        blockhash: &Hash,
    ) -> Option<Result<()>> {
        let rcache = self.src.status_cache.read().unwrap();
        rcache
            .get_status(signature, blockhash, &self.ancestors)
            .map(|v| v.1)
    }

    pub fn get_signature_status_slot(&self, signature: &Signature) -> Option<(Slot, Result<()>)> {
        let rcache = self.src.status_cache.read().unwrap();
        rcache.get_status_any_blockhash(signature, &self.ancestors)
    }

    pub fn get_signature_status(&self, signature: &Signature) -> Option<Result<()>> {
        self.get_signature_status_slot(signature).map(|v| v.1)
    }

    pub fn has_signature(&self, signature: &Signature) -> bool {
        self.get_signature_status_slot(signature).is_some()
    }

    /// Hash the `accounts` HashMap. This represents a validator's interpretation
    ///  of the delta of the ledger since the last vote and up to now
    fn hash_internal_state(&self) -> Hash {
        // If there are no accounts, return the hash of the previous state and the latest blockhash
        let accounts_delta_hash = self.rc.accounts.bank_hash_info_at(self.slot());
        let mut signature_count_buf = [0u8; 8];
        LittleEndian::write_u64(&mut signature_count_buf[..], self.signature_count() as u64);

        let mut hash = hashv(&[
            self.parent_hash.as_ref(),
            accounts_delta_hash.hash.as_ref(),
            &signature_count_buf,
            self.last_blockhash().as_ref(),
        ]);

        if let Some(buf) = self
            .hard_forks
            .read()
            .unwrap()
            .get_hash_data(self.slot(), self.parent_slot())
        {
            info!("hard fork at bank {}", self.slot());
            hash = extend_and_hash(&hash, &buf)
        }

        info!(
            "bank frozen: {} hash: {} accounts_delta: {} signature_count: {} last_blockhash: {} capitalization: {}",
            self.slot(),
            hash,
            accounts_delta_hash.hash,
            self.signature_count(),
            self.last_blockhash(),
            self.capitalization(),
        );

        info!(
            "accounts hash slot: {} stats: {:?}",
            self.slot(),
            accounts_delta_hash.stats,
        );
        hash
    }

    /// Recalculate the hash_internal_state from the account stores. Would be used to verify a
    /// snapshot.
    #[must_use]
    fn verify_bank_hash(&self) -> bool {
        self.rc.accounts.verify_bank_hash_and_lamports(
            self.slot(),
            &self.ancestors,
            self.capitalization(),
        )
    }

    pub fn get_snapshot_storages(&self) -> SnapshotStorages {
        self.rc
            .get_snapshot_storages(self.slot())
            .into_iter()
            .collect()
    }

    #[must_use]
    fn verify_hash(&self) -> bool {
        assert!(self.is_frozen());
        let calculated_hash = self.hash_internal_state();
        let expected_hash = self.hash();

        if calculated_hash == expected_hash {
            true
        } else {
            warn!(
                "verify failed: slot: {}, {} (calculated) != {} (expected)",
                self.slot(),
                calculated_hash,
                expected_hash
            );
            false
        }
    }

    pub fn calculate_capitalization(&self) -> u64 {
        self.rc.accounts.calculate_capitalization(&self.ancestors)
    }

    pub fn calculate_and_verify_capitalization(&self) -> bool {
        let calculated = self.calculate_capitalization();
        let expected = self.capitalization();
        if calculated == expected {
            true
        } else {
            warn!(
                "Capitalization mismatch: calculated: {} != expected: {}",
                calculated, expected
            );
            false
        }
    }

    /// Forcibly overwrites current capitalization by actually recalculating accounts' balances.
    /// This should only be used for developing purposes.
    pub fn set_capitalization(&self) -> u64 {
        let old = self.capitalization();
        self.capitalization
            .store(self.calculate_capitalization(), Relaxed);
        old
    }

    pub fn get_accounts_hash(&self) -> Hash {
        self.rc.accounts.accounts_db.get_accounts_hash(self.slot)
    }

    pub fn get_thread_pool(&self) -> &ThreadPool {
        &self.rc.accounts.accounts_db.thread_pool_clean
    }

    pub fn update_accounts_hash_with_index_option(
        &self,
        use_index: bool,
        debug_verify: bool,
    ) -> Hash {
        let (hash, total_lamports) = self
            .rc
            .accounts
            .accounts_db
            .update_accounts_hash_with_index_option(
                use_index,
                debug_verify,
                self.slot(),
                &self.ancestors,
                Some(self.capitalization()),
            );
        assert_eq!(total_lamports, self.capitalization());
        hash
    }

    pub fn update_accounts_hash(&self) -> Hash {
        self.update_accounts_hash_with_index_option(true, false)
    }

    /// A snapshot bank should be purged of 0 lamport accounts which are not part of the hash
    /// calculation and could shield other real accounts.
    pub fn verify_snapshot_bank(&self) -> bool {
        if self.slot() > 0 {
            self.clean_accounts(true);
            self.shrink_all_slots();
        }
        // Order and short-circuiting is significant; verify_hash requires a valid bank hash
        self.verify_bank_hash() && self.verify_hash()
    }

    /// Return the number of hashes per tick
    pub fn hashes_per_tick(&self) -> &Option<u64> {
        &self.hashes_per_tick
    }

    /// Return the number of ticks per slot
    pub fn ticks_per_slot(&self) -> u64 {
        self.ticks_per_slot
    }

    /// Return the number of slots per year
    pub fn slots_per_year(&self) -> f64 {
        self.slots_per_year
    }

    /// Return the number of ticks since genesis.
    pub fn tick_height(&self) -> u64 {
        self.tick_height.load(Relaxed)
    }

    /// Return the inflation parameters of the Bank
    pub fn inflation(&self) -> Inflation {
        *self.inflation.read().unwrap()
    }

    /// Return the total capitalization of the Bank
    pub fn capitalization(&self) -> u64 {
        self.capitalization.load(Relaxed)
    }

    /// Return this bank's max_tick_height
    pub fn max_tick_height(&self) -> u64 {
        self.max_tick_height
    }

    /// Return the block_height of this bank
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Return the number of slots per epoch for the given epoch
    pub fn get_slots_in_epoch(&self, epoch: Epoch) -> u64 {
        self.epoch_schedule.get_slots_in_epoch(epoch)
    }

    /// returns the epoch for which this bank's leader_schedule_slot_offset and slot would
    ///  need to cache leader_schedule
    pub fn get_leader_schedule_epoch(&self, slot: Slot) -> Epoch {
        self.epoch_schedule.get_leader_schedule_epoch(slot)
    }

    /// a bank-level cache of vote accounts
    fn update_cached_accounts(
        &self,
        txs: &[Transaction],
        res: &[TransactionExecutionResult],
        loaded: &[TransactionLoadResult],
    ) -> Vec<OverwrittenVoteAccount> {
        let mut overwritten_vote_accounts = vec![];
        for (i, ((raccs, _load_nonce_rollback), tx)) in loaded.iter().zip(txs).enumerate() {
            let (res, _res_nonce_rollback) = &res[i];
            if res.is_err() || raccs.is_err() {
                continue;
            }

            let message = &tx.message();
            let loaded_transaction = raccs.as_ref().unwrap();

            for (pubkey, account) in message
                .account_keys
                .iter()
                .zip(loaded_transaction.accounts.iter())
                .filter(|(_key, account)| (Stakes::is_stake(account)))
            {
                if Stakes::is_stake(account) {
                    if let Some(old_vote_account) = self.stakes.write().unwrap().store(
                        pubkey,
                        account,
                        self.stake_program_v2_enabled(),
                        self.check_init_vote_data_enabled(),
                    ) {
                        // TODO: one of the indices is redundant.
                        overwritten_vote_accounts.push(OverwrittenVoteAccount {
                            account: old_vote_account,
                            transaction_index: i,
                            transaction_result_index: i,
                        });
                    }
                }
            }
        }

        overwritten_vote_accounts
    }

    /// current stake delegations for this bank
    pub fn cloned_stake_delegations(&self) -> HashMap<Pubkey, Delegation> {
        self.stakes.read().unwrap().stake_delegations().clone()
    }

    pub fn staked_nodes(&self) -> HashMap<Pubkey, u64> {
        self.stakes.read().unwrap().staked_nodes()
    }

    /// current vote accounts for this bank along with the stake
    ///   attributed to each account
    /// Note: This clones the entire vote-accounts hashmap. For a single
    /// account lookup use get_vote_account instead.
    pub fn vote_accounts(&self) -> Vec<(Pubkey, (u64 /*stake*/, ArcVoteAccount))> {
        self.stakes
            .read()
            .unwrap()
            .vote_accounts()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Vote account for the given vote account pubkey along with the stake.
    pub fn get_vote_account(
        &self,
        vote_account: &Pubkey,
    ) -> Option<(u64 /*stake*/, ArcVoteAccount)> {
        self.stakes
            .read()
            .unwrap()
            .vote_accounts()
            .get(vote_account)
            .cloned()
    }

    /// Get the EpochStakes for a given epoch
    pub fn epoch_stakes(&self, epoch: Epoch) -> Option<&EpochStakes> {
        self.epoch_stakes.get(&epoch)
    }

    pub fn epoch_stakes_map(&self) -> &HashMap<Epoch, EpochStakes> {
        &self.epoch_stakes
    }

    pub fn epoch_staked_nodes(&self, epoch: Epoch) -> Option<HashMap<Pubkey, u64>> {
        Some(self.epoch_stakes.get(&epoch)?.stakes().staked_nodes())
    }

    /// vote accounts for the specific epoch along with the stake
    ///   attributed to each account
    pub fn epoch_vote_accounts(
        &self,
        epoch: Epoch,
    ) -> Option<&HashMap<Pubkey, (u64, ArcVoteAccount)>> {
        self.epoch_stakes
            .get(&epoch)
            .map(|epoch_stakes| Stakes::vote_accounts(epoch_stakes.stakes()))
    }

    /// Get the fixed authorized voter for the given vote account for the
    /// current epoch
    pub fn epoch_authorized_voter(&self, vote_account: &Pubkey) -> Option<&Pubkey> {
        self.epoch_stakes
            .get(&self.epoch)
            .expect("Epoch stakes for bank's own epoch must exist")
            .epoch_authorized_voters()
            .get(vote_account)
    }

    /// Get the fixed set of vote accounts for the given node id for the
    /// current epoch
    pub fn epoch_vote_accounts_for_node_id(&self, node_id: &Pubkey) -> Option<&NodeVoteAccounts> {
        self.epoch_stakes
            .get(&self.epoch)
            .expect("Epoch stakes for bank's own epoch must exist")
            .node_id_to_vote_accounts()
            .get(node_id)
    }

    /// Get the fixed total stake of all vote accounts for current epoch
    pub fn total_epoch_stake(&self) -> u64 {
        self.epoch_stakes
            .get(&self.epoch)
            .expect("Epoch stakes for bank's own epoch must exist")
            .total_stake()
    }

    /// Get the fixed stake of the given vote account for the current epoch
    pub fn epoch_vote_account_stake(&self, vote_account: &Pubkey) -> u64 {
        *self
            .epoch_vote_accounts(self.epoch())
            .expect("Bank epoch vote accounts must contain entry for the bank's own epoch")
            .get(vote_account)
            .map(|(stake, _)| stake)
            .unwrap_or(&0)
    }

    /// given a slot, return the epoch and offset into the epoch this slot falls
    /// e.g. with a fixed number for slots_per_epoch, the calculation is simply:
    ///
    ///  ( slot/slots_per_epoch, slot % slots_per_epoch )
    ///
    pub fn get_epoch_and_slot_index(&self, slot: Slot) -> (Epoch, SlotIndex) {
        self.epoch_schedule.get_epoch_and_slot_index(slot)
    }

    pub fn get_epoch_info(&self) -> EpochInfo {
        let absolute_slot = self.slot();
        let block_height = self.block_height();
        let (epoch, slot_index) = self.get_epoch_and_slot_index(absolute_slot);
        let slots_in_epoch = self.get_slots_in_epoch(epoch);
        let transaction_count = Some(self.transaction_count());
        EpochInfo {
            epoch,
            slot_index,
            slots_in_epoch,
            absolute_slot,
            block_height,
            transaction_count,
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.is_delta.load(Relaxed)
    }

    /// Add an instruction processor to intercept instructions before the dynamic loader.
    pub fn add_builtin(
        &mut self,
        name: &str,
        program_id: Pubkey,
        process_instruction_with_context: ProcessInstructionWithContext,
        load_safety: LoadSafety,
    ) {
        debug!("Adding program {} under {:?}", name, program_id);
        self.add_native_program(name, &program_id, false, load_safety);
        self.message_processor
            .add_program(program_id, process_instruction_with_context);
    }

    pub fn add_builtin_for_test(
        &mut self,
        name: &str,
        program_id: Pubkey,
        process_instruction_with_context: ProcessInstructionWithContext,
    ) {
        self.add_builtin(name, program_id, process_instruction_with_context, LoadSafety::FixedMaxRoot)
    }

    /// Replace a builtin instruction processor if it already exists
    pub fn replace_builtin(
        &mut self,
        name: &str,
        program_id: Pubkey,
        process_instruction_with_context: ProcessInstructionWithContext,
        load_safety: LoadSafety,
    ) {
        debug!("Replacing program {} under {:?}", name, program_id);
        self.add_native_program(name, &program_id, true, load_safety);
        self.message_processor
            .add_program(program_id, process_instruction_with_context);
    }

    pub fn clean_accounts(&self, skip_last: bool) {
        let max_clean_slot = if skip_last {
            // Don't clean the slot we're snapshotting because it may have zero-lamport
            // accounts that were included in the bank delta hash when the bank was frozen,
            // and if we clean them here, any newly created snapshot's hash for this bank
            // may not match the frozen hash.
            Some(self.slot().saturating_sub(1))
        } else {
            None
        };
        self.rc.accounts.accounts_db.clean_accounts(max_clean_slot);
    }

    pub fn shrink_all_slots(&self) {
        self.rc.accounts.accounts_db.shrink_all_slots();
    }

    pub fn print_accounts_stats(&self) {
        self.rc.accounts.accounts_db.print_accounts_stats("");
    }

    pub fn process_stale_slot_with_budget(
        &self,
        mut consumed_budget: usize,
        budget_recovery_delta: usize,
    ) -> usize {
        if consumed_budget == 0 {
            let shrunken_account_count = self.rc.accounts.accounts_db.process_stale_slot_v1();
            if shrunken_account_count > 0 {
                datapoint_info!(
                    "stale_slot_shrink",
                    ("accounts", shrunken_account_count, i64)
                );
                consumed_budget += shrunken_account_count;
            }
        }
        consumed_budget.saturating_sub(budget_recovery_delta)
    }

    pub fn shrink_candidate_slots(&self) -> usize {
        self.rc.accounts.accounts_db.shrink_candidate_slots()
    }

    pub fn secp256k1_program_enabled(&self) -> bool {
        self.feature_set
            .is_active(&feature_set::secp256k1_program_enabled::id())
    }

    pub fn no_overflow_rent_distribution_enabled(&self) -> bool {
        self.feature_set
            .is_active(&feature_set::no_overflow_rent_distribution::id())
    }

    pub fn stake_program_v2_enabled(&self) -> bool {
        self.feature_set
            .is_active(&feature_set::stake_program_v2::id())
    }

    pub fn check_init_vote_data_enabled(&self) -> bool {
        self.feature_set
            .is_active(&feature_set::check_init_vote_data::id())
    }

    // Check if the wallclock time from bank creation to now has exceeded the allotted
    // time for transaction processing
    pub fn should_bank_still_be_processing_txs(
        bank_creation_time: &Instant,
        max_tx_ingestion_nanos: u128,
    ) -> bool {
        // Do this check outside of the poh lock, hence not a method on PohRecorder
        bank_creation_time.elapsed().as_nanos() <= max_tx_ingestion_nanos
    }

    pub fn deactivate_feature(&mut self, id: &Pubkey) {
        let mut feature_set = Arc::make_mut(&mut self.feature_set).clone();
        feature_set.active.remove(&id);
        feature_set.inactive.insert(*id);
        self.feature_set = Arc::new(feature_set);
    }

    pub fn activate_feature(&mut self, id: &Pubkey) {
        let mut feature_set = Arc::make_mut(&mut self.feature_set).clone();
        feature_set.inactive.remove(id);
        feature_set.active.insert(*id, 0);
        self.feature_set = Arc::new(feature_set);
    }

    // This is called from snapshot restore AND for each epoch boundary
    // The entire code path herein must be idempotent
    fn apply_feature_activations(&mut self, init_finish_or_warp: bool) {
        let new_feature_activations = self.compute_active_feature_set(!init_finish_or_warp);

        if new_feature_activations.contains(&feature_set::pico_inflation::id()) {
            *self.inflation.write().unwrap() = Inflation::pico();
            self.fee_rate_governor.burn_percent = 50; // 50% fee burn
            self.rent_collector.rent.burn_percent = 50; // 50% rent burn
        }

        if !new_feature_activations.is_disjoint(&self.feature_set.full_inflation_features_enabled())
        {
            *self.inflation.write().unwrap() = Inflation::full();
            self.fee_rate_governor.burn_percent = 50; // 50% fee burn
            self.rent_collector.rent.burn_percent = 50; // 50% rent burn
        }

        if new_feature_activations.contains(&feature_set::spl_token_v2_self_transfer_fix::id()) {
            self.apply_spl_token_v2_self_transfer_fix();
        }
        // Remove me after a while around v1.6
        if !self.no_stake_rewrite.load(Relaxed)
            && new_feature_activations.contains(&feature_set::rewrite_stake::id())
        {
            // to avoid any potential risk of wrongly rewriting accounts in the future,
            // only do this once, taking small risk of unknown
            // bugs which again creates bad stake accounts..

            self.rewrite_stakes();
        }

        self.ensure_feature_builtins(init_finish_or_warp, &new_feature_activations);
        self.reconfigure_token2_native_mint();
        self.ensure_no_storage_rewards_pool();
    }

    // Compute the active feature set based on the current bank state, and return the set of newly activated features
    fn compute_active_feature_set(&mut self, allow_new_activations: bool) -> HashSet<Pubkey> {
        let mut active = self.feature_set.active.clone();
        let mut inactive = HashSet::new();
        let mut newly_activated = HashSet::new();
        let slot = self.slot();

        for feature_id in &self.feature_set.inactive {
            let mut activated = None;
            if let Some(mut account) = self.get_account(feature_id, LoadSafety::FixedMaxRoot) {
                if let Some(mut feature) = feature::from_account(&account) {
                    match feature.activated_at {
                        None => {
                            if allow_new_activations {
                                // Feature has been requested, activate it now
                                feature.activated_at = Some(slot);
                                if feature::to_account(&feature, &mut account).is_some() {
                                    self.store_account(feature_id, &account);
                                }
                                newly_activated.insert(*feature_id);
                                activated = Some(slot);
                                info!("Feature {} activated at slot {}", feature_id, slot);
                            }
                        }
                        Some(activation_slot) => {
                            if slot >= activation_slot {
                                // Feature is already active
                                activated = Some(activation_slot);
                            }
                        }
                    }
                }
            }
            if let Some(slot) = activated {
                active.insert(*feature_id, slot);
            } else {
                inactive.insert(*feature_id);
            }
        }

        self.feature_set = Arc::new(FeatureSet { active, inactive });
        newly_activated
    }

    fn ensure_feature_builtins(
        &mut self,
        init_or_warp: bool,
        new_feature_activations: &HashSet<Pubkey>,
    ) {
        let feature_builtins = self.feature_builtins.clone();
        for (builtin, feature, activation_type) in feature_builtins.iter() {
            let should_populate = init_or_warp && self.feature_set.is_active(&feature)
                || !init_or_warp && new_feature_activations.contains(&feature);
            if should_populate {
                match activation_type {
                    ActivationType::NewProgram => self.add_builtin(
                        &builtin.name,
                        builtin.id,
                        builtin.process_instruction_with_context,
                        LoadSafety::FixedMaxRoot,
                    ),
                    ActivationType::NewVersion => self.replace_builtin(
                        &builtin.name,
                        builtin.id,
                        builtin.process_instruction_with_context,
                        LoadSafety::FixedMaxRoot,
                    ),
                }
            }
        }
    }

    fn apply_spl_token_v2_self_transfer_fix(&mut self) {
        if let Some(old_account) = self.get_account(&inline_spl_token_v2_0::id(), LoadSafety::FixedMaxRoot) {
            if let Some(new_account) =
                self.get_account(&inline_spl_token_v2_0::new_token_program::id(), LoadSafety::FixedMaxRoot)
            {
                datapoint_info!(
                    "bank-apply_spl_token_v2_self_transfer_fix",
                    ("slot", self.slot, i64),
                );

                // Burn lamports in the old token account
                self.capitalization.fetch_sub(old_account.lamports, Relaxed);

                // Transfer new token account to old token account
                self.store_account(&inline_spl_token_v2_0::id(), &new_account);

                // Clear new token account
                self.store_account(
                    &inline_spl_token_v2_0::new_token_program::id(),
                    &AccountSharedData::default(),
                );

                self.remove_executor(&inline_spl_token_v2_0::id());
            }
        }
    }
    fn reconfigure_token2_native_mint(&mut self) {
        let reconfigure_token2_native_mint = match self.cluster_type() {
            ClusterType::Development => true,
            ClusterType::Devnet => true,
            ClusterType::Testnet => self.epoch() == 93,
            ClusterType::MainnetBeta => self.epoch() == 75,
        };

        if reconfigure_token2_native_mint {
            let mut native_mint_account = solana_sdk::account::AccountSharedData::from(Account {
                owner: inline_spl_token_v2_0::id(),
                data: inline_spl_token_v2_0::native_mint::ACCOUNT_DATA.to_vec(),
                lamports: sol_to_lamports(1.),
                executable: false,
                rent_epoch: self.epoch() + 1,
            });

            // As a workaround for
            // https://github.com/solana-labs/solana-program-library/issues/374, ensure that the
            // spl-token 2 native mint account is owned by the spl-token 2 program.
            let store = if let Some(existing_native_mint_account) =
                self.get_account(&inline_spl_token_v2_0::native_mint::id(), LoadSafety::FixedMaxRoot)
            {
                if existing_native_mint_account.owner == solana_sdk::system_program::id() {
                    native_mint_account.lamports = existing_native_mint_account.lamports;
                    true
                } else {
                    false
                }
            } else {
                self.capitalization
                    .fetch_add(native_mint_account.lamports, Relaxed);
                true
            };

            if store {
                self.store_account(
                    &inline_spl_token_v2_0::native_mint::id(),
                    &native_mint_account,
                );
            }
        }
    }

    fn ensure_no_storage_rewards_pool(&mut self) {
        let purge_window_epoch = match self.cluster_type() {
            ClusterType::Development => false,
            // never do this for devnet; we're pristine here. :)
            ClusterType::Devnet => false,
            // schedule to remove at testnet/tds
            ClusterType::Testnet => self.epoch() == 93,
            // never do this for stable; we're pristine here. :)
            ClusterType::MainnetBeta => false,
        };

        if purge_window_epoch {
            for reward_pubkey in self.rewards_pool_pubkeys.iter() {
                if let Some(mut reward_account) = self.get_account(&reward_pubkey, LoadSafety::FixedMaxRoot) {
                    if reward_account.lamports == u64::MAX {
                        reward_account.lamports = 0;
                        self.store_account(&reward_pubkey, &reward_account);
                        // Adjust capitalization.... it has been wrapping, reducing the real capitalization by 1-lamport
                        self.capitalization.fetch_add(1, Relaxed);
                        info!(
                            "purged rewards pool accont: {}, new capitalization: {}",
                            reward_pubkey,
                            self.capitalization()
                        );
                    }
                };
            }
        }
    }

    fn fix_recent_blockhashes_sysvar_delay(&self) -> bool {
        match self.cluster_type() {
            ClusterType::Development | ClusterType::Devnet | ClusterType::Testnet => true,
            ClusterType::MainnetBeta => self
                .feature_set
                .is_active(&feature_set::consistent_recent_blockhashes_sysvar::id()),
        }
    }
}

impl Drop for Bank {
    fn drop(&mut self) {
        if !self.skip_drop.load(Relaxed) {
            if let Some(drop_callback) = self.drop_callback.read().unwrap().0.as_ref() {
                drop_callback.callback(self);
            } else {
                // Default case
                // 1. Tests
                // 2. At startup when replaying blockstore and there's no
                // AccountsBackgroundService to perform cleanups yet.
                self.rc.accounts.purge_slot(self.slot());
            }
        }
    }
}

pub fn goto_end_of_slot(bank: &mut Bank) {
    let mut tick_hash = bank.last_blockhash();
    loop {
        tick_hash = hashv(&[&tick_hash.as_ref(), &[42]]);
        bank.register_tick(&tick_hash);
        if tick_hash == bank.last_blockhash() {
            bank.freeze();
            return;
        }
    }
}

fn is_simple_vote_transaction(transaction: &Transaction) -> bool {
    if transaction.message.instructions.len() == 1 {
        let instruction = &transaction.message.instructions[0];
        let program_pubkey =
            transaction.message.account_keys[instruction.program_id_index as usize];
        if program_pubkey == solana_vote_program::id() {
            if let Ok(vote_instruction) = limited_deserialize::<VoteInstruction>(&instruction.data)
            {
                return matches!(
                    vote_instruction,
                    VoteInstruction::Vote(_) | VoteInstruction::VoteSwitch(_, _)
                );
            }
        }
    }
    false
}

