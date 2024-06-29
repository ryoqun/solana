//! The `blockstore` module provides functions for parallel verification of the
//! Proof of History ledger as well as iterative read, append write, and random
//! access read to a persistent file-based ledger.

use {
    crate::{
        ancestor_iterator::AncestorIterator,
        blockstore_db::{
            columns as cf, Column, ColumnIndexDeprecation, Database, IteratorDirection,
            IteratorMode, LedgerColumn, Result, WriteBatch,
        },
        blockstore_meta::*,
        blockstore_metrics::BlockstoreRpcApiMetrics,
        blockstore_options::{
            AccessType, BlockstoreOptions, LedgerColumnOptions, BLOCKSTORE_DIRECTORY_ROCKS_FIFO,
            BLOCKSTORE_DIRECTORY_ROCKS_LEVEL,
        },
        leader_schedule_cache::LeaderScheduleCache,
        next_slots_iterator::NextSlotsIterator,
        shred::{
            self, max_ticks_per_n_shreds, ErasureSetId, ProcessShredsStats, ReedSolomonCache,
            Shred, ShredData, ShredId, ShredType, Shredder, DATA_SHREDS_PER_FEC_BLOCK,
        },
        slot_stats::{ShredSource, SlotsStats},
        transaction_address_lookup_table_scanner::scan_transaction,
    },
    assert_matches::debug_assert_matches,
    bincode::{deserialize, serialize},
    crossbeam_channel::{bounded, Receiver, Sender, TrySendError},
    dashmap::DashSet,
    itertools::Itertools,
    log::*,
    rand::Rng,
    rayon::iter::{IntoParallelIterator, ParallelIterator},
    rocksdb::{DBRawIterator, LiveFile},
    solana_accounts_db::hardened_unpack::{
        unpack_genesis_archive, MAX_GENESIS_ARCHIVE_UNPACKED_SIZE,
    },
    solana_entry::entry::{create_ticks, Entry},
    solana_measure::measure::Measure,
    solana_metrics::{
        datapoint_debug, datapoint_error,
        poh_timing_point::{send_poh_timing_point, PohTimingSender, SlotPohTimingInfo},
    },
    solana_runtime::bank::Bank,
    solana_sdk::{
        account::ReadableAccount,
        address_lookup_table::state::AddressLookupTable,
        clock::{Slot, UnixTimestamp, DEFAULT_TICKS_PER_SECOND},
        genesis_config::{GenesisConfig, DEFAULT_GENESIS_ARCHIVE, DEFAULT_GENESIS_FILE},
        hash::Hash,
        pubkey::Pubkey,
        signature::{Keypair, Signature, Signer},
        timing::timestamp,
        transaction::{SanitizedVersionedTransaction, VersionedTransaction},
    },
    solana_storage_proto::{StoredExtendedRewards, StoredTransactionStatusMeta},
    solana_transaction_status::{
        ConfirmedTransactionStatusWithSignature, ConfirmedTransactionWithStatusMeta, Rewards,
        RewardsAndNumPartitions, TransactionStatusMeta, TransactionWithStatusMeta,
        VersionedConfirmedBlock, VersionedConfirmedBlockWithEntries,
        VersionedTransactionWithStatusMeta,
    },
    std::{
        borrow::Cow,
        cell::RefCell,
        cmp,
        collections::{
            btree_map::Entry as BTreeMapEntry, hash_map::Entry as HashMapEntry, BTreeMap, BTreeSet,
            HashMap, HashSet, VecDeque,
        },
        convert::TryInto,
        fmt::Write,
        fs,
        io::{Error as IoError, ErrorKind},
        ops::Bound,
        path::{Path, PathBuf},
        rc::Rc,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex, RwLock,
        },
    },
    tempfile::{Builder, TempDir},
    thiserror::Error,
    trees::{Tree, TreeWalk},
};
pub mod blockstore_purge;
pub use {
    crate::{
        blockstore_db::BlockstoreError,
        blockstore_meta::{OptimisticSlotMetaVersioned, SlotMeta},
        blockstore_metrics::BlockstoreInsertionMetrics,
    },
    blockstore_purge::PurgeType,
    rocksdb::properties as RocksProperties,
};

pub const MAX_REPLAY_WAKE_UP_SIGNALS: usize = 1;
pub const MAX_COMPLETED_SLOTS_IN_CHANNEL: usize = 100_000;

// An upper bound on maximum number of data shreds we can handle in a slot
// 32K shreds would allow ~320K peak TPS
// (32K shreds per slot * 4 TX per shred * 2.5 slots per sec)
pub const MAX_DATA_SHREDS_PER_SLOT: usize = 32_768;

pub type CompletedSlotsSender = Sender<Vec<Slot>>;
pub type CompletedSlotsReceiver = Receiver<Vec<Slot>>;
type CompletedRanges = Vec<(u32, u32)>;

#[derive(Default)]
pub struct SignatureInfosForAddress {
    pub infos: Vec<ConfirmedTransactionStatusWithSignature>,
    pub found_before: bool,
}

#[derive(Error, Debug)]
pub enum InsertDataShredError {
    Exists,
    InvalidShred,
    BlockstoreError(#[from] BlockstoreError),
}

impl std::fmt::Display for InsertDataShredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "insert data shred error")
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum PossibleDuplicateShred {
    Exists(Shred), // Blockstore has another shred in its spot
    LastIndexConflict(/* original */ Shred, /* conflict */ Vec<u8>), // The index of this shred conflicts with `slot_meta.last_index`
    ErasureConflict(/* original */ Shred, /* conflict */ Vec<u8>), // The coding shred has a conflict in the erasure_meta
    MerkleRootConflict(/* original */ Shred, /* conflict */ Vec<u8>), // Merkle root conflict in the same fec set
    ChainedMerkleRootConflict(/* original */ Shred, /* conflict */ Vec<u8>), // Merkle root chaining conflict with previous fec set
}

impl PossibleDuplicateShred {
    pub fn slot(&self) -> Slot {
        match self {
            Self::Exists(shred) => shred.slot(),
            Self::LastIndexConflict(shred, _) => shred.slot(),
            Self::ErasureConflict(shred, _) => shred.slot(),
            Self::MerkleRootConflict(shred, _) => shred.slot(),
            Self::ChainedMerkleRootConflict(shred, _) => shred.slot(),
        }
    }
}

enum WorkingEntry<T> {
    Dirty(T), // Value has been modified with respect to the blockstore column
    Clean(T), // Value matches what is currently in the blockstore column
}

impl<T> WorkingEntry<T> {
    fn should_write(&self) -> bool {
        matches!(self, Self::Dirty(_))
    }
}

impl<T> AsRef<T> for WorkingEntry<T> {
    fn as_ref(&self) -> &T {
        match self {
            Self::Dirty(value) => value,
            Self::Clean(value) => value,
        }
    }
}

pub struct InsertResults {
    completed_data_set_infos: Vec<CompletedDataSetInfo>,
    duplicate_shreds: Vec<PossibleDuplicateShred>,
}

/// A "complete data set" is a range of [`Shred`]s that combined in sequence carry a single
/// serialized [`Vec<Entry>`].
///
/// Services such as the `WindowService` for a TVU, and `ReplayStage` for a TPU, piece together
/// these sets by inserting shreds via direct or indirect calls to
/// [`Blockstore::insert_shreds_handle_duplicate()`].
///
/// `solana_core::completed_data_sets_service::CompletedDataSetsService` is the main receiver of
/// `CompletedDataSetInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletedDataSetInfo {
    /// [`Slot`] to which the [`Shred`]s in this set belong.
    pub slot: Slot,

    /// Index of the first [`Shred`] in the range of shreds that belong to this set.
    /// Range is inclusive, `start_index..=end_index`.
    pub start_index: u32,

    /// Index of the last [`Shred`] in the range of shreds that belong to this set.
    /// Range is inclusive, `start_index..=end_index`.
    pub end_index: u32,
}

pub struct BlockstoreSignals {
    pub blockstore: Blockstore,
    pub ledger_signal_receiver: Receiver<bool>,
    pub completed_slots_receiver: CompletedSlotsReceiver,
}

// ledger window
pub struct Blockstore {
    ledger_path: PathBuf,
    db: Arc<Database>,
    meta_cf: LedgerColumn<cf::SlotMeta>,
    dead_slots_cf: LedgerColumn<cf::DeadSlots>,
    duplicate_slots_cf: LedgerColumn<cf::DuplicateSlots>,
    roots_cf: LedgerColumn<cf::Root>,
    erasure_meta_cf: LedgerColumn<cf::ErasureMeta>,
    orphans_cf: LedgerColumn<cf::Orphans>,
    index_cf: LedgerColumn<cf::Index>,
    data_shred_cf: LedgerColumn<cf::ShredData>,
    code_shred_cf: LedgerColumn<cf::ShredCode>,
    transaction_status_cf: LedgerColumn<cf::TransactionStatus>,
    address_signatures_cf: LedgerColumn<cf::AddressSignatures>,
    transaction_memos_cf: LedgerColumn<cf::TransactionMemos>,
    transaction_status_index_cf: LedgerColumn<cf::TransactionStatusIndex>,
    highest_primary_index_slot: RwLock<Option<Slot>>,
    rewards_cf: LedgerColumn<cf::Rewards>,
    blocktime_cf: LedgerColumn<cf::Blocktime>,
    perf_samples_cf: LedgerColumn<cf::PerfSamples>,
    block_height_cf: LedgerColumn<cf::BlockHeight>,
    program_costs_cf: LedgerColumn<cf::ProgramCosts>,
    bank_hash_cf: LedgerColumn<cf::BankHash>,
    optimistic_slots_cf: LedgerColumn<cf::OptimisticSlots>,
    max_root: AtomicU64,
    merkle_root_meta_cf: LedgerColumn<cf::MerkleRootMeta>,
    insert_shreds_lock: Mutex<()>,
    new_shreds_signals: Mutex<Vec<Sender<bool>>>,
    completed_slots_senders: Mutex<Vec<CompletedSlotsSender>>,
    pub shred_timing_point_sender: Option<PohTimingSender>,
    pub lowest_cleanup_slot: RwLock<Slot>,
    pub slots_stats: SlotsStats,
    rpc_api_metrics: BlockstoreRpcApiMetrics,
}

pub struct IndexMetaWorkingSetEntry {
    index: Index,
    // true only if at least one shred for this Index was inserted since the time this
    // struct was created
    did_insert_occur: bool,
}

/// The in-memory data structure for updating entries in the column family
/// [`cf::SlotMeta`].
pub struct SlotMetaWorkingSetEntry {
    /// The dirty version of the `SlotMeta` which might not be persisted
    /// to the blockstore yet.
    new_slot_meta: Rc<RefCell<SlotMeta>>,
    /// The latest version of the `SlotMeta` that was persisted in the
    /// blockstore.  If None, it means the current slot is new to the
    /// blockstore.
    old_slot_meta: Option<SlotMeta>,
    /// True only if at least one shred for this SlotMeta was inserted since
    /// this struct was created.
    did_insert_occur: bool,
}

impl SlotMetaWorkingSetEntry {
    /// Construct a new SlotMetaWorkingSetEntry with the specified `new_slot_meta`
    /// and `old_slot_meta`.  `did_insert_occur` is set to false.
    fn new(new_slot_meta: Rc<RefCell<SlotMeta>>, old_slot_meta: Option<SlotMeta>) -> Self {
        Self {
            new_slot_meta,
            old_slot_meta,
            did_insert_occur: false,
        }
    }
}

impl Blockstore {
    pub fn db(self) -> Arc<Database> {
        self.db
    }

    pub fn ledger_path(&self) -> &PathBuf {
        &self.ledger_path
    }

    pub fn banking_trace_path(&self) -> PathBuf {
        self.ledger_path.join("banking_trace")
    }

    /// Opens a Ledger in directory, provides "infinite" window of shreds
    pub fn open(ledger_path: &Path) -> Result<Blockstore> {
        Self::do_open(ledger_path, BlockstoreOptions::default())
    }

    pub fn open_with_options(ledger_path: &Path, options: BlockstoreOptions) -> Result<Blockstore> {
        Self::do_open(ledger_path, options)
    }

    fn do_open(ledger_path: &Path, options: BlockstoreOptions) -> Result<Blockstore> {
        fs::create_dir_all(ledger_path)?;
        let blockstore_path = ledger_path.join(
            options
                .column_options
                .shred_storage_type
                .blockstore_directory(),
        );

        adjust_ulimit_nofile(options.enforce_ulimit_nofile)?;

        // Open the database
        let mut measure = Measure::start("blockstore open");
        info!("Opening blockstore at {:?}", blockstore_path);
        let db = Database::open(&blockstore_path, options)?;

        let meta_cf = db.column();
        let dead_slots_cf = db.column();
        let duplicate_slots_cf = db.column();
        let roots_cf = db.column();
        let erasure_meta_cf = db.column();
        let orphans_cf = db.column();
        let index_cf = db.column();
        let data_shred_cf = db.column();
        let code_shred_cf = db.column();
        let transaction_status_cf = db.column();
        let address_signatures_cf = db.column();
        let transaction_memos_cf = db.column();
        let transaction_status_index_cf = db.column();
        let rewards_cf = db.column();
        let blocktime_cf = db.column();
        let perf_samples_cf = db.column();
        let block_height_cf = db.column();
        let program_costs_cf = db.column();
        let bank_hash_cf = db.column();
        let optimistic_slots_cf = db.column();
        let merkle_root_meta_cf = db.column();

        let db = Arc::new(db);

        // Get max root or 0 if it doesn't exist
        let max_root = db
            .iter::<cf::Root>(IteratorMode::End)?
            .next()
            .map(|(slot, _)| slot)
            .unwrap_or(0);
        let max_root = AtomicU64::new(max_root);

        measure.stop();
        info!("Opening blockstore done; {measure}");
        let blockstore = Blockstore {
            ledger_path: ledger_path.to_path_buf(),
            db,
            meta_cf,
            dead_slots_cf,
            duplicate_slots_cf,
            roots_cf,
            erasure_meta_cf,
            orphans_cf,
            index_cf,
            data_shred_cf,
            code_shred_cf,
            transaction_status_cf,
            address_signatures_cf,
            transaction_memos_cf,
            transaction_status_index_cf,
            highest_primary_index_slot: RwLock::<Option<Slot>>::default(),
            rewards_cf,
            blocktime_cf,
            perf_samples_cf,
            block_height_cf,
            program_costs_cf,
            bank_hash_cf,
            optimistic_slots_cf,
            merkle_root_meta_cf,
            new_shreds_signals: Mutex::default(),
            completed_slots_senders: Mutex::default(),
            shred_timing_point_sender: None,
            insert_shreds_lock: Mutex::<()>::default(),
            max_root,
            lowest_cleanup_slot: RwLock::<Slot>::default(),
            slots_stats: SlotsStats::default(),
            rpc_api_metrics: BlockstoreRpcApiMetrics::default(),
        };
        blockstore.cleanup_old_entries()?;
        blockstore.update_highest_primary_index_slot()?;

        Ok(blockstore)
    }

    pub fn open_with_signal(
        ledger_path: &Path,
        options: BlockstoreOptions,
    ) -> Result<BlockstoreSignals> {
        let blockstore = Self::open_with_options(ledger_path, options)?;
        let (ledger_signal_sender, ledger_signal_receiver) = bounded(MAX_REPLAY_WAKE_UP_SIGNALS);
        let (completed_slots_sender, completed_slots_receiver) =
            bounded(MAX_COMPLETED_SLOTS_IN_CHANNEL);

        blockstore.add_new_shred_signal(ledger_signal_sender);
        blockstore.add_completed_slots_signal(completed_slots_sender);

        Ok(BlockstoreSignals {
            blockstore,
            ledger_signal_receiver,
            completed_slots_receiver,
        })
    }

    pub fn add_tree(
        &self,
        forks: Tree<Slot>,
        is_orphan: bool,
        is_slot_complete: bool,
        num_ticks: u64,
        starting_hash: Hash,
    ) {
        let mut walk = TreeWalk::from(forks);
        let mut blockhashes = HashMap::new();
        while let Some(visit) = walk.get() {
            let slot = *visit.node().data();
            if self.meta(slot).unwrap().is_some() && self.orphan(slot).unwrap().is_none() {
                // If slot exists in blockstore and is not an orphan, then skip it
                walk.forward();
                continue;
            }
            let parent = walk.get_parent().map(|n| *n.data());
            if parent.is_some() || !is_orphan {
                let parent_hash = parent
                    // parent won't exist for first node in a tree where
                    // `is_orphan == true`
                    .and_then(|parent| blockhashes.get(&parent))
                    .unwrap_or(&starting_hash);
                let mut entries = create_ticks(
                    num_ticks * (std::cmp::max(1, slot - parent.unwrap_or(slot))),
                    0,
                    *parent_hash,
                );
                blockhashes.insert(slot, entries.last().unwrap().hash);
                if !is_slot_complete {
                    entries.pop().unwrap();
                }
                let shreds = entries_to_test_shreds(
                    &entries,
                    slot,
                    parent.unwrap_or(slot),
                    is_slot_complete,
                    0,
                    true, // merkle_variant
                );
                self.insert_shreds(shreds, None, false).unwrap();
            }
            walk.forward();
        }
    }

    /// Deletes the blockstore at the specified path.
    ///
    /// Note that if the `ledger_path` has multiple rocksdb instances, this
    /// function will destroy all.
    pub fn destroy(ledger_path: &Path) -> Result<()> {
        // Database::destroy() fails if the root directory doesn't exist
        fs::create_dir_all(ledger_path)?;
        Database::destroy(&Path::new(ledger_path).join(BLOCKSTORE_DIRECTORY_ROCKS_LEVEL)).and(
            Database::destroy(&Path::new(ledger_path).join(BLOCKSTORE_DIRECTORY_ROCKS_FIFO)),
        )
    }

    /// Returns the SlotMeta of the specified slot.
    pub fn meta(&self, slot: Slot) -> Result<Option<SlotMeta>> {
        self.meta_cf.get(slot)
    }

    /// Returns true if the specified slot is full.
    pub fn is_full(&self, slot: Slot) -> bool {
        if let Ok(Some(meta)) = self.meta_cf.get(slot) {
            return meta.is_full();
        }
        false
    }

    fn erasure_meta(&self, erasure_set: ErasureSetId) -> Result<Option<ErasureMeta>> {
        let (slot, fec_set_index) = erasure_set.store_key();
        self.erasure_meta_cf.get((slot, u64::from(fec_set_index)))
    }

    /// Attempts to find the previous consecutive erasure set for `erasure_set`.
    ///
    /// Checks the map `erasure_metas`, if not present scans blockstore. Returns None
    /// if the previous consecutive erasure set is not present in either.
    fn previous_erasure_set<'a>(
        &'a self,
        erasure_set: ErasureSetId,
        erasure_metas: &'a BTreeMap<ErasureSetId, WorkingEntry<ErasureMeta>>,
    ) -> Result<Option<(ErasureSetId, Cow<ErasureMeta>)>> {
        let (slot, fec_set_index) = erasure_set.store_key();

        // Check the previous entry from the in memory map to see if it is the consecutive
        // set to `erasure set`
        let candidate_erasure_entry = erasure_metas
            .range((
                Bound::Included(ErasureSetId::new(slot, 0)),
                Bound::Excluded(erasure_set),
            ))
            .next_back();
        let candidate_erasure_set_and_meta = candidate_erasure_entry
            .filter(|(_, candidate_erasure_meta)| {
                candidate_erasure_meta.as_ref().next_fec_set_index() == Some(fec_set_index)
            })
            .map(|(erasure_set, erasure_meta)| {
                (*erasure_set, Cow::Borrowed(erasure_meta.as_ref()))
            });
        if candidate_erasure_set_and_meta.is_some() {
            return Ok(candidate_erasure_set_and_meta);
        }

        // Consecutive set was not found in memory, scan blockstore for a potential candidate
        let Some(((_, candidate_fec_set_index), candidate_erasure_meta)) = self
            .erasure_meta_cf
            .iter(IteratorMode::From(
                (slot, u64::from(fec_set_index)),
                IteratorDirection::Reverse,
            ))?
            // `find` here, to skip the first element in case the erasure meta for fec_set_index is already present
            .find(|((_, candidate_fec_set_index), _)| {
                *candidate_fec_set_index != u64::from(fec_set_index)
            })
            // Do not consider sets from the previous slot
            .filter(|((candidate_slot, _), _)| *candidate_slot == slot)
        else {
            // No potential candidates
            return Ok(None);
        };
        let candidate_fec_set_index = u32::try_from(candidate_fec_set_index)
            .expect("fec_set_index from a previously inserted shred should fit in u32");
        let candidate_erasure_set = ErasureSetId::new(slot, candidate_fec_set_index);
        let candidate_erasure_meta: ErasureMeta = deserialize(candidate_erasure_meta.as_ref())?;

        // Check if this is actually the consecutive erasure set
        let Some(next_fec_set_index) = candidate_erasure_meta.next_fec_set_index() else {
            return Err(BlockstoreError::InvalidErasureConfig);
        };
        if next_fec_set_index == fec_set_index {
            return Ok(Some((
                candidate_erasure_set,
                Cow::Owned(candidate_erasure_meta),
            )));
        }
        Ok(None)
    }

    fn merkle_root_meta(&self, erasure_set: ErasureSetId) -> Result<Option<MerkleRootMeta>> {
        self.merkle_root_meta_cf.get(erasure_set.store_key())
    }

    /// Check whether the specified slot is an orphan slot which does not
    /// have a parent slot.
    ///
    /// Returns true if the specified slot does not have a parent slot.
    /// For other return values, it means either the slot is not in the
    /// blockstore or the slot isn't an orphan slot.
    pub fn orphan(&self, slot: Slot) -> Result<Option<bool>> {
        self.orphans_cf.get(slot)
    }

    pub fn slot_meta_iterator(
        &self,
        slot: Slot,
    ) -> Result<impl Iterator<Item = (Slot, SlotMeta)> + '_> {
        let meta_iter = self
            .db
            .iter::<cf::SlotMeta>(IteratorMode::From(slot, IteratorDirection::Forward))?;
        Ok(meta_iter.map(|(slot, slot_meta_bytes)| {
            (
                slot,
                deserialize(&slot_meta_bytes).unwrap_or_else(|e| {
                    panic!("Could not deserialize SlotMeta for slot {slot}: {e:?}")
                }),
            )
        }))
    }

    pub fn live_slots_iterator(&self, root: Slot) -> impl Iterator<Item = (Slot, SlotMeta)> + '_ {
        let root_forks = NextSlotsIterator::new(root, self);

        let orphans_iter = self.orphans_iterator(root + 1).unwrap();
        root_forks.chain(orphans_iter.flat_map(move |orphan| NextSlotsIterator::new(orphan, self)))
    }

    pub fn live_files_metadata(&self) -> Result<Vec<LiveFile>> {
        self.db.live_files_metadata()
    }

    pub fn slot_data_iterator(
        &self,
        slot: Slot,
        index: u64,
    ) -> Result<impl Iterator<Item = ((u64, u64), Box<[u8]>)> + '_> {
        let slot_iterator = self.db.iter::<cf::ShredData>(IteratorMode::From(
            (slot, index),
            IteratorDirection::Forward,
        ))?;
        Ok(slot_iterator.take_while(move |((shred_slot, _), _)| *shred_slot == slot))
    }

    pub fn slot_coding_iterator(
        &self,
        slot: Slot,
        index: u64,
    ) -> Result<impl Iterator<Item = ((u64, u64), Box<[u8]>)> + '_> {
        let slot_iterator = self.db.iter::<cf::ShredCode>(IteratorMode::From(
            (slot, index),
            IteratorDirection::Forward,
        ))?;
        Ok(slot_iterator.take_while(move |((shred_slot, _), _)| *shred_slot == slot))
    }

    fn prepare_rooted_slot_iterator(
        &self,
        slot: Slot,
        direction: IteratorDirection,
    ) -> Result<impl Iterator<Item = Slot> + '_> {
        let slot_iterator = self
            .db
            .iter::<cf::Root>(IteratorMode::From(slot, direction))?;
        Ok(slot_iterator.map(move |(rooted_slot, _)| rooted_slot))
    }

    pub fn rooted_slot_iterator(&self, slot: Slot) -> Result<impl Iterator<Item = Slot> + '_> {
        self.prepare_rooted_slot_iterator(slot, IteratorDirection::Forward)
    }

    pub fn reversed_rooted_slot_iterator(
        &self,
        slot: Slot,
    ) -> Result<impl Iterator<Item = Slot> + '_> {
        self.prepare_rooted_slot_iterator(slot, IteratorDirection::Reverse)
    }

    pub fn reversed_optimistic_slots_iterator(
        &self,
    ) -> Result<impl Iterator<Item = (Slot, Hash, UnixTimestamp)> + '_> {
        let iter = self.db.iter::<cf::OptimisticSlots>(IteratorMode::End)?;
        Ok(iter.map(|(slot, bytes)| {
            let meta: OptimisticSlotMetaVersioned = deserialize(&bytes).unwrap();
            (slot, meta.hash(), meta.timestamp())
        }))
    }

    /// Determines if we can iterate from `starting_slot` to >= `ending_slot` by full slots
    /// `starting_slot` is excluded from the `is_full()` check
    pub fn slot_range_connected(&self, starting_slot: Slot, ending_slot: Slot) -> bool {
        if starting_slot == ending_slot {
            return true;
        }

        let mut next_slots: VecDeque<_> = match self.meta(starting_slot) {
            Ok(Some(starting_slot_meta)) => starting_slot_meta.next_slots.into(),
            _ => return false,
        };
        while let Some(slot) = next_slots.pop_front() {
            if let Ok(Some(slot_meta)) = self.meta(slot) {
                if slot_meta.is_full() {
                    match slot.cmp(&ending_slot) {
                        cmp::Ordering::Less => next_slots.extend(slot_meta.next_slots),
                        _ => return true,
                    }
                }
            }
        }

        false
    }

    fn get_recovery_data_shreds<'a>(
        index: &'a Index,
        slot: Slot,
        erasure_meta: &'a ErasureMeta,
        prev_inserted_shreds: &'a HashMap<ShredId, Shred>,
        data_cf: &'a LedgerColumn<cf::ShredData>,
    ) -> impl Iterator<Item = Shred> + 'a {
        erasure_meta.data_shreds_indices().filter_map(move |i| {
            let key = ShredId::new(slot, u32::try_from(i).unwrap(), ShredType::Data);
            if let Some(shred) = prev_inserted_shreds.get(&key) {
                return Some(shred.clone());
            }
            if !index.data().contains(i) {
                return None;
            }
            match data_cf.get_bytes((slot, i)).unwrap() {
                None => {
                    error!(
                        "Unable to read the data shred with slot {slot}, index {i} for shred \
                         recovery. The shred is marked present in the slot's data shred index, \
                         but the shred could not be found in the data shred column."
                    );
                    None
                }
                Some(data) => Shred::new_from_serialized_shred(data).ok(),
            }
        })
    }

    fn get_recovery_coding_shreds<'a>(
        index: &'a Index,
        slot: Slot,
        erasure_meta: &'a ErasureMeta,
        prev_inserted_shreds: &'a HashMap<ShredId, Shred>,
        code_cf: &'a LedgerColumn<cf::ShredCode>,
    ) -> impl Iterator<Item = Shred> + 'a {
        erasure_meta.coding_shreds_indices().filter_map(move |i| {
            let key = ShredId::new(slot, u32::try_from(i).unwrap(), ShredType::Code);
            if let Some(shred) = prev_inserted_shreds.get(&key) {
                return Some(shred.clone());
            }
            if !index.coding().contains(i) {
                return None;
            }
            match code_cf.get_bytes((slot, i)).unwrap() {
                None => {
                    error!(
                        "Unable to read the coding shred with slot {slot}, index {i} for shred \
                         recovery. The shred is marked present in the slot's coding shred index, \
                         but the shred could not be found in the coding shred column."
                    );
                    None
                }
                Some(code) => Shred::new_from_serialized_shred(code).ok(),
            }
        })
    }

    fn recover_shreds(
        index: &Index,
        erasure_meta: &ErasureMeta,
        prev_inserted_shreds: &HashMap<ShredId, Shred>,
        recovered_shreds: &mut Vec<Shred>,
        data_cf: &LedgerColumn<cf::ShredData>,
        code_cf: &LedgerColumn<cf::ShredCode>,
        reed_solomon_cache: &ReedSolomonCache,
    ) {
        // Find shreds for this erasure set and try recovery
        let slot = index.slot;
        let available_shreds: Vec<_> = Self::get_recovery_data_shreds(
            index,
            slot,
            erasure_meta,
            prev_inserted_shreds,
            data_cf,
        )
        .chain(Self::get_recovery_coding_shreds(
            index,
            slot,
            erasure_meta,
            prev_inserted_shreds,
            code_cf,
        ))
        .collect();
        if let Ok(mut result) = shred::recover(available_shreds, reed_solomon_cache) {
            Self::submit_metrics(slot, erasure_meta, true, "complete".into(), result.len());
            recovered_shreds.append(&mut result);
        } else {
            Self::submit_metrics(slot, erasure_meta, true, "incomplete".into(), 0);
        }
    }

    fn submit_metrics(
        slot: Slot,
        erasure_meta: &ErasureMeta,
        attempted: bool,
        status: String,
        recovered: usize,
    ) {
        let mut data_shreds_indices = erasure_meta.data_shreds_indices();
        let start_index = data_shreds_indices.next().unwrap_or_default();
        let end_index = data_shreds_indices.last().unwrap_or(start_index);
        datapoint_debug!(
            "blockstore-erasure",
            ("slot", slot as i64, i64),
            ("start_index", start_index, i64),
            ("end_index", end_index + 1, i64),
            ("recovery_attempted", attempted, bool),
            ("recovery_status", status, String),
            ("recovered", recovered as i64, i64),
        );
    }

    /// Collects and reports [`BlockstoreRocksDbColumnFamilyMetrics`] for the
    /// all the column families.
    ///
    /// [`BlockstoreRocksDbColumnFamilyMetrics`]: crate::blockstore_metrics::BlockstoreRocksDbColumnFamilyMetrics
    pub fn submit_rocksdb_cf_metrics_for_all_cfs(&self) {
        self.meta_cf.submit_rocksdb_cf_metrics();
        self.dead_slots_cf.submit_rocksdb_cf_metrics();
        self.duplicate_slots_cf.submit_rocksdb_cf_metrics();
        self.roots_cf.submit_rocksdb_cf_metrics();
        self.erasure_meta_cf.submit_rocksdb_cf_metrics();
        self.orphans_cf.submit_rocksdb_cf_metrics();
        self.index_cf.submit_rocksdb_cf_metrics();
        self.data_shred_cf.submit_rocksdb_cf_metrics();
        self.code_shred_cf.submit_rocksdb_cf_metrics();
        self.transaction_status_cf.submit_rocksdb_cf_metrics();
        self.address_signatures_cf.submit_rocksdb_cf_metrics();
        self.transaction_memos_cf.submit_rocksdb_cf_metrics();
        self.transaction_status_index_cf.submit_rocksdb_cf_metrics();
        self.rewards_cf.submit_rocksdb_cf_metrics();
        self.blocktime_cf.submit_rocksdb_cf_metrics();
        self.perf_samples_cf.submit_rocksdb_cf_metrics();
        self.block_height_cf.submit_rocksdb_cf_metrics();
        self.program_costs_cf.submit_rocksdb_cf_metrics();
        self.bank_hash_cf.submit_rocksdb_cf_metrics();
        self.optimistic_slots_cf.submit_rocksdb_cf_metrics();
        self.merkle_root_meta_cf.submit_rocksdb_cf_metrics();
    }

    /// Report the accumulated RPC API metrics
    pub(crate) fn report_rpc_api_metrics(&self) {
        self.rpc_api_metrics.report();
    }

    fn try_shred_recovery(
        &self,
        erasure_metas: &BTreeMap<ErasureSetId, WorkingEntry<ErasureMeta>>,
        index_working_set: &mut HashMap<u64, IndexMetaWorkingSetEntry>,
        prev_inserted_shreds: &HashMap<ShredId, Shred>,
        reed_solomon_cache: &ReedSolomonCache,
    ) -> Vec<Shred> {
        let mut recovered_shreds = vec![];
        // Recovery rules:
        // 1. Only try recovery around indexes for which new data or coding shreds are received
        // 2. For new data shreds, check if an erasure set exists. If not, don't try recovery
        // 3. Before trying recovery, check if enough number of shreds have been received
        // 3a. Enough number of shreds = (#data + #coding shreds) > erasure.num_data
        for (erasure_set, working_erasure_meta) in erasure_metas.iter() {
            let erasure_meta = working_erasure_meta.as_ref();
            let slot = erasure_set.slot();
            let index_meta_entry = index_working_set.get_mut(&slot).expect("Index");
            let index = &mut index_meta_entry.index;
            match erasure_meta.status(index) {
                ErasureMetaStatus::CanRecover => {
                    Self::recover_shreds(
                        index,
                        erasure_meta,
                        prev_inserted_shreds,
                        &mut recovered_shreds,
                        &self.data_shred_cf,
                        &self.code_shred_cf,
                        reed_solomon_cache,
                    );
                }
                ErasureMetaStatus::DataFull => {
                    Self::submit_metrics(slot, erasure_meta, false, "complete".into(), 0);
                }
                ErasureMetaStatus::StillNeed(needed) => {
                    Self::submit_metrics(
                        slot,
                        erasure_meta,
                        false,
                        format!("still need: {needed}"),
                        0,
                    );
                }
            };
        }
        recovered_shreds
    }

    /// The main helper function that performs the shred insertion logic
    /// and updates corresponding meta-data.
    ///
    /// This function updates the following column families:
    ///   - [`cf::DeadSlots`]: mark a shred as "dead" if its meta-data indicates
    ///     there is no need to replay this shred.  Specifically when both the
    ///     following conditions satisfy,
    ///     - We get a new shred N marked as the last shred in the slot S,
    ///       but N.index() is less than the current slot_meta.received
    ///       for slot S.
    ///     - The slot is not currently full
    ///     It means there's an alternate version of this slot. See
    ///     `check_insert_data_shred` for more details.
    ///   - [`cf::ShredData`]: stores data shreds (in check_insert_data_shreds).
    ///   - [`cf::ShredCode`]: stores coding shreds (in check_insert_coding_shreds).
    ///   - [`cf::SlotMeta`]: the SlotMeta of the input `shreds` and their related
    ///     shreds are updated.  Specifically:
    ///     - `handle_chaining()` updates `cf::SlotMeta` in two ways.  First, it
    ///       updates the in-memory slot_meta_working_set, which will later be
    ///       persisted in commit_slot_meta_working_set().  Second, for the newly
    ///       chained slots (updated inside handle_chaining_for_slot()), it will
    ///       directly persist their slot-meta into `cf::SlotMeta`.
    ///     - In `commit_slot_meta_working_set()`, persists everything stored
    ///       in the in-memory structure slot_meta_working_set, which is updated
    ///       by both `check_insert_data_shred()` and `handle_chaining()`.
    ///   - [`cf::Orphans`]: add or remove the ID of a slot to `cf::Orphans`
    ///     if it becomes / is no longer an orphan slot in `handle_chaining()`.
    ///   - [`cf::ErasureMeta`]: the associated ErasureMeta of the coding and data
    ///     shreds inside `shreds` will be updated and committed to
    ///     `cf::ErasureMeta`.
    ///   - [`cf::MerkleRootMeta`]: the associated MerkleRootMeta of the coding and data
    ///     shreds inside `shreds` will be updated and committed to
    ///     `cf::MerkleRootMeta`.
    ///   - [`cf::Index`]: stores (slot id, index to the index_working_set_entry)
    ///     pair to the `cf::Index` column family for each index_working_set_entry
    ///     which insert did occur in this function call.
    ///
    /// Arguments:
    ///  - `shreds`: the shreds to be inserted.
    ///  - `is_repaired`: a boolean vector aligned with `shreds` where each
    ///    boolean indicates whether the corresponding shred is repaired or not.
    ///  - `leader_schedule`: the leader schedule
    ///  - `is_trusted`: whether the shreds come from a trusted source. If this
    ///    is set to true, then the function will skip the shred duplication and
    ///    integrity checks.
    ///  - `retransmit_sender`: the sender for transmitting any recovered
    ///    data shreds.
    ///  - `handle_duplicate`: a function for handling shreds that have the same slot
    ///    and index.
    ///  - `metrics`: the metric for reporting detailed stats
    ///
    /// On success, the function returns an Ok result with a vector of
    /// `CompletedDataSetInfo` and a vector of its corresponding index in the
    /// input `shreds` vector.
    fn do_insert_shreds(
        &self,
        shreds: Vec<Shred>,
        is_repaired: Vec<bool>,
        leader_schedule: Option<&LeaderScheduleCache>,
        is_trusted: bool,
        retransmit_sender: Option<&Sender<Vec</*shred:*/ Vec<u8>>>>,
        reed_solomon_cache: &ReedSolomonCache,
        metrics: &mut BlockstoreInsertionMetrics,
    ) -> Result<InsertResults> {
        assert_eq!(shreds.len(), is_repaired.len());
        let mut total_start = Measure::start("Total elapsed");
        let mut start = Measure::start("Blockstore lock");
        let _lock = self.insert_shreds_lock.lock().unwrap();
        start.stop();
        metrics.insert_lock_elapsed_us += start.as_us();

        let mut write_batch = self.db.batch()?;

        let mut just_inserted_shreds = HashMap::with_capacity(shreds.len());
        let mut erasure_metas = BTreeMap::new();
        let mut merkle_root_metas = HashMap::new();
        let mut slot_meta_working_set = HashMap::new();
        let mut index_working_set = HashMap::new();
        let mut duplicate_shreds = vec![];

        metrics.num_shreds += shreds.len();
        let mut start = Measure::start("Shred insertion");
        let mut index_meta_time_us = 0;
        let mut newly_completed_data_sets: Vec<CompletedDataSetInfo> = vec![];
        for (shred, is_repaired) in shreds.into_iter().zip(is_repaired) {
            let shred_source = if is_repaired {
                ShredSource::Repaired
            } else {
                ShredSource::Turbine
            };
            match shred.shred_type() {
                ShredType::Data => {
                    match self.check_insert_data_shred(
                        shred,
                        &mut erasure_metas,
                        &mut merkle_root_metas,
                        &mut index_working_set,
                        &mut slot_meta_working_set,
                        &mut write_batch,
                        &mut just_inserted_shreds,
                        &mut index_meta_time_us,
                        is_trusted,
                        &mut duplicate_shreds,
                        leader_schedule,
                        shred_source,
                    ) {
                        Err(InsertDataShredError::Exists) => {
                            if is_repaired {
                                metrics.num_repaired_data_shreds_exists += 1;
                            } else {
                                metrics.num_turbine_data_shreds_exists += 1;
                            }
                        }
                        Err(InsertDataShredError::InvalidShred) => {
                            metrics.num_data_shreds_invalid += 1
                        }
                        Err(InsertDataShredError::BlockstoreError(err)) => {
                            metrics.num_data_shreds_blockstore_error += 1;
                            error!("blockstore error: {}", err);
                        }
                        Ok(completed_data_sets) => {
                            if is_repaired {
                                metrics.num_repair += 1;
                            }
                            newly_completed_data_sets.extend(completed_data_sets);
                            metrics.num_inserted += 1;
                        }
                    };
                }
                ShredType::Code => {
                    self.check_insert_coding_shred(
                        shred,
                        &mut erasure_metas,
                        &mut merkle_root_metas,
                        &mut index_working_set,
                        &mut write_batch,
                        &mut just_inserted_shreds,
                        &mut index_meta_time_us,
                        &mut duplicate_shreds,
                        is_trusted,
                        shred_source,
                        metrics,
                    );
                }
            };
        }
        start.stop();

        metrics.insert_shreds_elapsed_us += start.as_us();
        let mut start = Measure::start("Shred recovery");
        if let Some(leader_schedule_cache) = leader_schedule {
            let recovered_shreds = self.try_shred_recovery(
                &erasure_metas,
                &mut index_working_set,
                &just_inserted_shreds,
                reed_solomon_cache,
            );

            metrics.num_recovered += recovered_shreds
                .iter()
                .filter(|shred| shred.is_data())
                .count();
            let recovered_shreds: Vec<_> = recovered_shreds
                .into_iter()
                .filter_map(|shred| {
                    let leader =
                        leader_schedule_cache.slot_leader_at(shred.slot(), /*bank=*/ None)?;
                    if !shred.verify(&leader) {
                        metrics.num_recovered_failed_sig += 1;
                        return None;
                    }
                    // Since the data shreds are fully recovered from the
                    // erasure batch, no need to store coding shreds in
                    // blockstore.
                    if shred.is_code() {
                        return Some(shred);
                    }
                    match self.check_insert_data_shred(
                        shred.clone(),
                        &mut erasure_metas,
                        &mut merkle_root_metas,
                        &mut index_working_set,
                        &mut slot_meta_working_set,
                        &mut write_batch,
                        &mut just_inserted_shreds,
                        &mut index_meta_time_us,
                        is_trusted,
                        &mut duplicate_shreds,
                        leader_schedule,
                        ShredSource::Recovered,
                    ) {
                        Err(InsertDataShredError::Exists) => {
                            metrics.num_recovered_exists += 1;
                            None
                        }
                        Err(InsertDataShredError::InvalidShred) => {
                            metrics.num_recovered_failed_invalid += 1;
                            None
                        }
                        Err(InsertDataShredError::BlockstoreError(err)) => {
                            metrics.num_recovered_blockstore_error += 1;
                            error!("blockstore error: {}", err);
                            None
                        }
                        Ok(completed_data_sets) => {
                            newly_completed_data_sets.extend(completed_data_sets);
                            metrics.num_recovered_inserted += 1;
                            Some(shred)
                        }
                    }
                })
                // Always collect recovered-shreds so that above insert code is
                // executed even if retransmit-sender is None.
                .collect();
            if !recovered_shreds.is_empty() {
                if let Some(retransmit_sender) = retransmit_sender {
                    let _ = retransmit_sender.send(
                        recovered_shreds
                            .into_iter()
                            .map(Shred::into_payload)
                            .collect(),
                    );
                }
            }
        }
        start.stop();
        metrics.shred_recovery_elapsed_us += start.as_us();

        let mut start = Measure::start("Shred recovery");
        // Handle chaining for the members of the slot_meta_working_set that were inserted into,
        // drop the others
        self.handle_chaining(&mut write_batch, &mut slot_meta_working_set)?;
        start.stop();
        metrics.chaining_elapsed_us += start.as_us();

        let mut start = Measure::start("Commit Working Sets");
        let (should_signal, newly_completed_slots) = commit_slot_meta_working_set(
            &slot_meta_working_set,
            &self.completed_slots_senders.lock().unwrap(),
            &mut write_batch,
        )?;

        for (erasure_set, working_erasure_meta) in erasure_metas.iter() {
            if !working_erasure_meta.should_write() {
                // Not a new erasure meta
                continue;
            }
            let (slot, _) = erasure_set.store_key();
            if self.has_duplicate_shreds_in_slot(slot) {
                continue;
            }
            // First coding shred from this erasure batch, check the forward merkle root chaining
            let erasure_meta = working_erasure_meta.as_ref();
            let shred_id = ShredId::new(
                slot,
                erasure_meta
                    .first_received_coding_shred_index()
                    .expect("First received coding index must fit in u32"),
                ShredType::Code,
            );
            let shred = just_inserted_shreds
                .get(&shred_id)
                .expect("Erasure meta was just created, initial shred must exist");

            self.check_forward_chained_merkle_root_consistency(
                shred,
                erasure_meta,
                &just_inserted_shreds,
                &mut merkle_root_metas,
                &mut duplicate_shreds,
            );
        }

        for (erasure_set, working_merkle_root_meta) in merkle_root_metas.iter() {
            if !working_merkle_root_meta.should_write() {
                // Not a new merkle root meta
                continue;
            }
            let (slot, _) = erasure_set.store_key();
            if self.has_duplicate_shreds_in_slot(slot) {
                continue;
            }
            // First shred from this erasure batch, check the backwards merkle root chaining
            let merkle_root_meta = working_merkle_root_meta.as_ref();
            let shred_id = ShredId::new(
                slot,
                merkle_root_meta.first_received_shred_index(),
                merkle_root_meta.first_received_shred_type(),
            );
            let shred = just_inserted_shreds
                .get(&shred_id)
                .expect("Merkle root meta was just created, initial shred must exist");

            self.check_backwards_chained_merkle_root_consistency(
                shred,
                &just_inserted_shreds,
                &erasure_metas,
                &mut duplicate_shreds,
            );
        }

        for (erasure_set, working_erasure_meta) in erasure_metas {
            if !working_erasure_meta.should_write() {
                // No need to rewrite the column
                continue;
            }
            let (slot, fec_set_index) = erasure_set.store_key();
            write_batch.put::<cf::ErasureMeta>(
                (slot, u64::from(fec_set_index)),
                working_erasure_meta.as_ref(),
            )?;
        }

        for (erasure_set, working_merkle_root_meta) in merkle_root_metas {
            if !working_merkle_root_meta.should_write() {
                // No need to rewrite the column
                continue;
            }
            write_batch.put::<cf::MerkleRootMeta>(
                erasure_set.store_key(),
                working_merkle_root_meta.as_ref(),
            )?;
        }

        for (&slot, index_working_set_entry) in index_working_set.iter() {
            if index_working_set_entry.did_insert_occur {
                write_batch.put::<cf::Index>(slot, &index_working_set_entry.index)?;
            }
        }
        start.stop();
        metrics.commit_working_sets_elapsed_us += start.as_us();

        let mut start = Measure::start("Write Batch");
        self.db.write(write_batch)?;
        start.stop();
        metrics.write_batch_elapsed_us += start.as_us();

        send_signals(
            &self.new_shreds_signals.lock().unwrap(),
            &self.completed_slots_senders.lock().unwrap(),
            should_signal,
            newly_completed_slots,
        );

        total_start.stop();

        metrics.total_elapsed_us += total_start.as_us();
        metrics.index_meta_time_us += index_meta_time_us;

        Ok(InsertResults {
            completed_data_set_infos: newly_completed_data_sets,
            duplicate_shreds,
        })
    }

    pub fn insert_shreds_handle_duplicate<F>(
        &self,
        shreds: Vec<Shred>,
        is_repaired: Vec<bool>,
        leader_schedule: Option<&LeaderScheduleCache>,
        is_trusted: bool,
        retransmit_sender: Option<&Sender<Vec</*shred:*/ Vec<u8>>>>,
        handle_duplicate: &F,
        reed_solomon_cache: &ReedSolomonCache,
        metrics: &mut BlockstoreInsertionMetrics,
    ) -> Result<Vec<CompletedDataSetInfo>>
    where
        F: Fn(PossibleDuplicateShred),
    {
        let InsertResults {
            completed_data_set_infos,
            duplicate_shreds,
        } = self.do_insert_shreds(
            shreds,
            is_repaired,
            leader_schedule,
            is_trusted,
            retransmit_sender,
            reed_solomon_cache,
            metrics,
        )?;

        for shred in duplicate_shreds {
            handle_duplicate(shred);
        }

        Ok(completed_data_set_infos)
    }

    pub fn add_new_shred_signal(&self, s: Sender<bool>) {
        self.new_shreds_signals.lock().unwrap().push(s);
    }

    pub fn add_completed_slots_signal(&self, s: CompletedSlotsSender) {
        self.completed_slots_senders.lock().unwrap().push(s);
    }

    pub fn get_new_shred_signals_len(&self) -> usize {
        self.new_shreds_signals.lock().unwrap().len()
    }

    pub fn get_new_shred_signal(&self, index: usize) -> Option<Sender<bool>> {
        self.new_shreds_signals.lock().unwrap().get(index).cloned()
    }

    pub fn drop_signal(&self) {
        self.new_shreds_signals.lock().unwrap().clear();
        self.completed_slots_senders.lock().unwrap().clear();
    }

    /// Clear `slot` from the Blockstore, see ``Blockstore::purge_slot_cleanup_chaining`
    /// for more details.
    ///
    /// This function currently requires `insert_shreds_lock`, as both
    /// `clear_unconfirmed_slot()` and `insert_shreds_handle_duplicate()`
    /// try to perform read-modify-write operation on [`cf::SlotMeta`] column
    /// family.
    pub fn clear_unconfirmed_slot(&self, slot: Slot) {
        let _lock = self.insert_shreds_lock.lock().unwrap();
        // Purge the slot and insert an empty `SlotMeta` with only the `next_slots` field preserved.
        // Shreds inherently know their parent slot, and a parent's SlotMeta `next_slots` list
        // will be updated when the child is inserted (see `Blockstore::handle_chaining()`).
        // However, we are only purging and repairing the parent slot here. Since the child will not be
        // reinserted the chaining will be lost. In order for bank forks discovery to ingest the child,
        // we must retain the chain by preserving `next_slots`.
        match self.purge_slot_cleanup_chaining(slot) {
            Ok(_) => {}
            Err(BlockstoreError::SlotUnavailable) => error!(
                "clear_unconfirmed_slot() called on slot {} with no SlotMeta",
                slot
            ),
            Err(e) => panic!("Purge database operations failed {}", e),
        }
    }

    pub fn insert_shreds(
        &self,
        shreds: Vec<Shred>,
        leader_schedule: Option<&LeaderScheduleCache>,
        is_trusted: bool,
    ) -> Result<Vec<CompletedDataSetInfo>> {
        let shreds_len = shreds.len();
        let insert_results = self.do_insert_shreds(
            shreds,
            vec![false; shreds_len],
            leader_schedule,
            is_trusted,
            None, // retransmit-sender
            &ReedSolomonCache::default(),
            &mut BlockstoreInsertionMetrics::default(),
        )?;
        Ok(insert_results.completed_data_set_infos)
    }

    #[allow(clippy::too_many_arguments)]
    fn check_insert_coding_shred(
        &self,
        shred: Shred,
        erasure_metas: &mut BTreeMap<ErasureSetId, WorkingEntry<ErasureMeta>>,
        merkle_root_metas: &mut HashMap<ErasureSetId, WorkingEntry<MerkleRootMeta>>,
        index_working_set: &mut HashMap<u64, IndexMetaWorkingSetEntry>,
        write_batch: &mut WriteBatch,
        just_received_shreds: &mut HashMap<ShredId, Shred>,
        index_meta_time_us: &mut u64,
        duplicate_shreds: &mut Vec<PossibleDuplicateShred>,
        is_trusted: bool,
        shred_source: ShredSource,
        metrics: &mut BlockstoreInsertionMetrics,
    ) -> bool {
        let slot = shred.slot();
        let shred_index = u64::from(shred.index());

        let index_meta_working_set_entry =
            self.get_index_meta_entry(slot, index_working_set, index_meta_time_us);

        let index_meta = &mut index_meta_working_set_entry.index;
        let erasure_set = shred.erasure_set();

        if let HashMapEntry::Vacant(entry) = merkle_root_metas.entry(erasure_set) {
            if let Some(meta) = self.merkle_root_meta(erasure_set).unwrap() {
                entry.insert(WorkingEntry::Clean(meta));
            }
        }

        // This gives the index of first coding shred in this FEC block
        // So, all coding shreds in a given FEC block will have the same set index
        if !is_trusted {
            if index_meta.coding().contains(shred_index) {
                metrics.num_coding_shreds_exists += 1;
                duplicate_shreds.push(PossibleDuplicateShred::Exists(shred));
                return false;
            }

            if !Blockstore::should_insert_coding_shred(&shred, self.max_root()) {
                metrics.num_coding_shreds_invalid += 1;
                return false;
            }

            if let Some(merkle_root_meta) = merkle_root_metas.get(&erasure_set) {
                // A previous shred has been inserted in this batch or in blockstore
                // Compare our current shred against the previous shred for potential
                // conflicts
                if !self.check_merkle_root_consistency(
                    just_received_shreds,
                    slot,
                    merkle_root_meta.as_ref(),
                    &shred,
                    duplicate_shreds,
                ) {
                    return false;
                }
            }
        }

        let erasure_meta_entry = erasure_metas.entry(erasure_set).or_insert_with(|| {
            self.erasure_meta(erasure_set)
                .expect("Expect database get to succeed")
                .map(WorkingEntry::Clean)
                .unwrap_or_else(|| {
                    WorkingEntry::Dirty(ErasureMeta::from_coding_shred(&shred).unwrap())
                })
        });
        let erasure_meta = erasure_meta_entry.as_ref();

        if !erasure_meta.check_coding_shred(&shred) {
            metrics.num_coding_shreds_invalid_erasure_config += 1;
            if !self.has_duplicate_shreds_in_slot(slot) {
                if let Some(conflicting_shred) = self
                    .find_conflicting_coding_shred(&shred, slot, erasure_meta, just_received_shreds)
                    .map(Cow::into_owned)
                {
                    if let Err(e) = self.store_duplicate_slot(
                        slot,
                        conflicting_shred.clone(),
                        shred.payload().clone(),
                    ) {
                        warn!(
                            "Unable to store conflicting erasure meta duplicate proof for {slot} \
                             {erasure_set:?} {e}"
                        );
                    }

                    duplicate_shreds.push(PossibleDuplicateShred::ErasureConflict(
                        shred.clone(),
                        conflicting_shred,
                    ));
                } else {
                    error!(
                        "Unable to find the conflicting coding shred that set {erasure_meta:?}. \
                         This should only happen in extreme cases where blockstore cleanup has \
                         caught up to the root. Skipping the erasure meta duplicate shred check"
                    );
                }
            }

            // ToDo: This is a potential slashing condition
            warn!("Received multiple erasure configs for the same erasure set!!!");
            warn!(
                "Slot: {}, shred index: {}, erasure_set: {:?}, is_duplicate: {}, stored config: \
                 {:#?}, new shred: {:#?}",
                slot,
                shred.index(),
                erasure_set,
                self.has_duplicate_shreds_in_slot(slot),
                erasure_meta.config(),
                shred,
            );
            return false;
        }

        self.slots_stats
            .record_shred(shred.slot(), shred.fec_set_index(), shred_source, None);

        // insert coding shred into rocks
        let result = self
            .insert_coding_shred(index_meta, &shred, write_batch)
            .is_ok();

        if result {
            index_meta_working_set_entry.did_insert_occur = true;
            metrics.num_inserted += 1;

            merkle_root_metas
                .entry(erasure_set)
                .or_insert(WorkingEntry::Dirty(MerkleRootMeta::from_shred(&shred)));
        }

        if let HashMapEntry::Vacant(entry) = just_received_shreds.entry(shred.id()) {
            metrics.num_coding_shreds_inserted += 1;
            entry.insert(shred);
        }

        result
    }

    fn find_conflicting_coding_shred<'a>(
        &'a self,
        shred: &Shred,
        slot: Slot,
        erasure_meta: &ErasureMeta,
        just_received_shreds: &'a HashMap<ShredId, Shred>,
    ) -> Option<Cow<Vec<u8>>> {
        // Search for the shred which set the initial erasure config, either inserted,
        // or in the current batch in just_received_shreds.
        let index = erasure_meta.first_received_coding_shred_index()?;
        let shred_id = ShredId::new(slot, index, ShredType::Code);
        let maybe_shred = self.get_shred_from_just_inserted_or_db(just_received_shreds, shred_id);

        if index != 0 || maybe_shred.is_some() {
            return maybe_shred;
        }

        // If we are using a blockstore created from an earlier version than 1.18.12,
        // `index` will be 0 as it was not yet populated, revert to a scan until  we no longer support
        // those blockstore versions.
        for coding_index in erasure_meta.coding_shreds_indices() {
            let maybe_shred = self.get_coding_shred(slot, coding_index);
            if let Ok(Some(shred_data)) = maybe_shred {
                let potential_shred = Shred::new_from_serialized_shred(shred_data).unwrap();
                if shred.erasure_mismatch(&potential_shred).unwrap() {
                    return Some(Cow::Owned(potential_shred.into_payload()));
                }
            } else if let Some(potential_shred) = {
                let key = ShredId::new(slot, u32::try_from(coding_index).unwrap(), ShredType::Code);
                just_received_shreds.get(&key)
            } {
                if shred.erasure_mismatch(potential_shred).unwrap() {
                    return Some(Cow::Borrowed(potential_shred.payload()));
                }
            }
        }
        None
    }

    /// Create an entry to the specified `write_batch` that performs shred
    /// insertion and associated metadata update.  The function also updates
    /// its in-memory copy of the associated metadata.
    ///
    /// Currently, this function must be invoked while holding
    /// `insert_shreds_lock` as it performs read-modify-write operations
    /// on multiple column families.
    ///
    /// The resulting `write_batch` may include updates to [`cf::DeadSlots`]
    /// and [`cf::ShredData`].  Note that it will also update the in-memory copy
    /// of `erasure_metas`, `merkle_root_metas`, and `index_working_set`, which will
    /// later be used to update other column families such as [`cf::ErasureMeta`] and
    /// [`cf::Index`].
    ///
    /// Arguments:
    /// - `shred`: the shred to be inserted
    /// - `erasure_metas`: the in-memory hash-map that maintains the dirty
    ///     copy of the erasure meta.  It will later be written to
    ///     `cf::ErasureMeta` in insert_shreds_handle_duplicate().
    /// - `merkle_root_metas`: the in-memory hash-map that maintains the dirty
    ///     copy of the merkle root meta. It will later be written to
    ///     `cf::MerkleRootMeta` in `insert_shreds_handle_duplicate()`.
    /// - `index_working_set`: the in-memory hash-map that maintains the
    ///     dirty copy of the index meta.  It will later be written to
    ///     `cf::Index` in insert_shreds_handle_duplicate().
    /// - `slot_meta_working_set`: the in-memory hash-map that maintains
    ///     the dirty copy of the index meta.  It will later be written to
    ///     `cf::SlotMeta` in insert_shreds_handle_duplicate().
    /// - `write_batch`: the collection of the current writes which will
    ///     be committed atomically.
    /// - `just_inserted_data_shreds`: a (slot, shred index within the slot)
    ///     to shred map which maintains which data shreds have been inserted.
    /// - `index_meta_time_us`: the time spent on loading or creating the
    ///     index meta entry from the db.
    /// - `is_trusted`: if false, this function will check whether the
    ///     input shred is duplicate.
    /// - `handle_duplicate`: the function that handles duplication.
    /// - `leader_schedule`: the leader schedule will be used to check
    ///     whether it is okay to insert the input shred.
    /// - `shred_source`: the source of the shred.
    #[allow(clippy::too_many_arguments)]
    fn check_insert_data_shred(
        &self,
        shred: Shred,
        erasure_metas: &mut BTreeMap<ErasureSetId, WorkingEntry<ErasureMeta>>,
        merkle_root_metas: &mut HashMap<ErasureSetId, WorkingEntry<MerkleRootMeta>>,
        index_working_set: &mut HashMap<u64, IndexMetaWorkingSetEntry>,
        slot_meta_working_set: &mut HashMap<u64, SlotMetaWorkingSetEntry>,
        write_batch: &mut WriteBatch,
        just_inserted_shreds: &mut HashMap<ShredId, Shred>,
        index_meta_time_us: &mut u64,
        is_trusted: bool,
        duplicate_shreds: &mut Vec<PossibleDuplicateShred>,
        leader_schedule: Option<&LeaderScheduleCache>,
        shred_source: ShredSource,
    ) -> std::result::Result<Vec<CompletedDataSetInfo>, InsertDataShredError> {
        let slot = shred.slot();
        let shred_index = u64::from(shred.index());

        let index_meta_working_set_entry =
            self.get_index_meta_entry(slot, index_working_set, index_meta_time_us);
        let index_meta = &mut index_meta_working_set_entry.index;
        let slot_meta_entry = self.get_slot_meta_entry(
            slot_meta_working_set,
            slot,
            shred
                .parent()
                .map_err(|_| InsertDataShredError::InvalidShred)?,
        );

        let slot_meta = &mut slot_meta_entry.new_slot_meta.borrow_mut();
        let erasure_set = shred.erasure_set();
        if let HashMapEntry::Vacant(entry) = merkle_root_metas.entry(erasure_set) {
            if let Some(meta) = self.merkle_root_meta(erasure_set).unwrap() {
                entry.insert(WorkingEntry::Clean(meta));
            }
        }

        if !is_trusted {
            if Self::is_data_shred_present(&shred, slot_meta, index_meta.data()) {
                duplicate_shreds.push(PossibleDuplicateShred::Exists(shred));
                return Err(InsertDataShredError::Exists);
            }

            if shred.last_in_slot() && shred_index < slot_meta.received && !slot_meta.is_full() {
                // We got a last shred < slot_meta.received, which signals there's an alternative,
                // shorter version of the slot. Because also `!slot_meta.is_full()`, then this
                // means, for the current version of the slot, we might never get all the
                // shreds < the current last index, never replay this slot, and make no
                // progress (for instance if a leader sends an additional detached "last index"
                // shred with a very high index, but none of the intermediate shreds). Ideally, we would
                // just purge all shreds > the new last index slot, but because replay may have already
                // replayed entries past the newly detected "last" shred, then mark the slot as dead
                // and wait for replay to dump and repair the correct version.
                warn!(
                    "Received *last* shred index {} less than previous shred index {}, and slot \
                     {} is not full, marking slot dead",
                    shred_index, slot_meta.received, slot
                );
                write_batch.put::<cf::DeadSlots>(slot, &true).unwrap();
            }

            if !self.should_insert_data_shred(
                &shred,
                slot_meta,
                just_inserted_shreds,
                self.max_root(),
                leader_schedule,
                shred_source,
                duplicate_shreds,
            ) {
                return Err(InsertDataShredError::InvalidShred);
            }

            if let Some(merkle_root_meta) = merkle_root_metas.get(&erasure_set) {
                // A previous shred has been inserted in this batch or in blockstore
                // Compare our current shred against the previous shred for potential
                // conflicts
                if !self.check_merkle_root_consistency(
                    just_inserted_shreds,
                    slot,
                    merkle_root_meta.as_ref(),
                    &shred,
                    duplicate_shreds,
                ) {
                    return Err(InsertDataShredError::InvalidShred);
                }
            }
        }

        let newly_completed_data_sets = self.insert_data_shred(
            slot_meta,
            index_meta.data_mut(),
            &shred,
            write_batch,
            shred_source,
        )?;
        merkle_root_metas
            .entry(erasure_set)
            .or_insert(WorkingEntry::Dirty(MerkleRootMeta::from_shred(&shred)));
        just_inserted_shreds.insert(shred.id(), shred);
        index_meta_working_set_entry.did_insert_occur = true;
        slot_meta_entry.did_insert_occur = true;
        if let BTreeMapEntry::Vacant(entry) = erasure_metas.entry(erasure_set) {
            if let Some(meta) = self.erasure_meta(erasure_set).unwrap() {
                entry.insert(WorkingEntry::Clean(meta));
            }
        }
        Ok(newly_completed_data_sets)
    }

    fn should_insert_coding_shred(shred: &Shred, max_root: Slot) -> bool {
        debug_assert_matches!(shred.sanitize(), Ok(()));
        shred.is_code() && shred.slot() > max_root
    }

    fn insert_coding_shred(
        &self,
        index_meta: &mut Index,
        shred: &Shred,
        write_batch: &mut WriteBatch,
    ) -> Result<()> {
        let slot = shred.slot();
        let shred_index = u64::from(shred.index());

        // Assert guaranteed by integrity checks on the shred that happen before
        // `insert_coding_shred` is called
        debug_assert_matches!(shred.sanitize(), Ok(()));
        assert!(shred.is_code());

        // Commit step: commit all changes to the mutable structures at once, or none at all.
        // We don't want only a subset of these changes going through.
        write_batch.put_bytes::<cf::ShredCode>((slot, shred_index), shred.payload())?;
        index_meta.coding_mut().insert(shred_index);

        Ok(())
    }

    fn is_data_shred_present(shred: &Shred, slot_meta: &SlotMeta, data_index: &ShredIndex) -> bool {
        let shred_index = u64::from(shred.index());
        // Check that the shred doesn't already exist in blockstore
        shred_index < slot_meta.consumed || data_index.contains(shred_index)
    }

    /// Finds the corresponding shred at `shred_id` in the just inserted
    /// shreds or the backing store. Returns None if there is no shred.
    fn get_shred_from_just_inserted_or_db<'a>(
        &'a self,
        just_inserted_shreds: &'a HashMap<ShredId, Shred>,
        shred_id: ShredId,
    ) -> Option<Cow<'a, Vec<u8>>> {
        let (slot, index, shred_type) = shred_id.unpack();
        match (just_inserted_shreds.get(&shred_id), shred_type) {
            (Some(shred), _) => Some(Cow::Borrowed(shred.payload())),
            // If it doesn't exist in the just inserted set, it must exist in
            // the backing store
            (_, ShredType::Data) => self
                .get_data_shred(slot, u64::from(index))
                .unwrap()
                .map(Cow::Owned),
            (_, ShredType::Code) => self
                .get_coding_shred(slot, u64::from(index))
                .unwrap()
                .map(Cow::Owned),
        }
    }

    /// Returns true if there is no merkle root conflict between
    /// the existing `merkle_root_meta` and `shred`
    ///
    /// Otherwise return false and if not already present, add duplicate proof to
    /// `duplicate_shreds`.
    fn check_merkle_root_consistency(
        &self,
        just_inserted_shreds: &HashMap<ShredId, Shred>,
        slot: Slot,
        merkle_root_meta: &MerkleRootMeta,
        shred: &Shred,
        duplicate_shreds: &mut Vec<PossibleDuplicateShred>,
    ) -> bool {
        let new_merkle_root = shred.merkle_root().ok();
        if merkle_root_meta.merkle_root() == new_merkle_root {
            // No conflict, either both merkle shreds with same merkle root
            // or both legacy shreds with merkle_root `None`
            return true;
        }

        warn!(
            "Received conflicting merkle roots for slot: {}, erasure_set: {:?} original merkle \
             root meta {:?} vs conflicting merkle root {:?} shred index {} type {:?}. Reporting \
             as duplicate",
            slot,
            shred.erasure_set(),
            merkle_root_meta,
            new_merkle_root,
            shred.index(),
            shred.shred_type(),
        );

        if !self.has_duplicate_shreds_in_slot(slot) {
            let shred_id = ShredId::new(
                slot,
                merkle_root_meta.first_received_shred_index(),
                merkle_root_meta.first_received_shred_type(),
            );
            let Some(conflicting_shred) = self
                .get_shred_from_just_inserted_or_db(just_inserted_shreds, shred_id)
                .map(Cow::into_owned)
            else {
                error!(
                    "Shred {shred_id:?} indiciated by merkle root meta {merkle_root_meta:?} is \
                     missing from blockstore. This should only happen in extreme cases where \
                     blockstore cleanup has caught up to the root. Skipping the merkle root \
                     consistency check"
                );
                return true;
            };
            duplicate_shreds.push(PossibleDuplicateShred::MerkleRootConflict(
                shred.clone(),
                conflicting_shred,
            ));
        }
        false
    }

    /// Returns true if there is no chaining conflict between
    /// the `shred` and `merkle_root_meta` of the next FEC set,
    /// or if shreds from the next set are yet to be received.
    ///
    /// Otherwise return false and add duplicate proof to
    /// `duplicate_shreds`.
    ///
    /// This is intended to be used right after `shred`'s `erasure_meta`
    /// has been created for the first time.
    fn check_forward_chained_merkle_root_consistency(
        &self,
        shred: &Shred,
        erasure_meta: &ErasureMeta,
        just_inserted_shreds: &HashMap<ShredId, Shred>,
        merkle_root_metas: &mut HashMap<ErasureSetId, WorkingEntry<MerkleRootMeta>>,
        duplicate_shreds: &mut Vec<PossibleDuplicateShred>,
    ) -> bool {
        debug_assert!(erasure_meta.check_coding_shred(shred));
        let slot = shred.slot();
        let erasure_set = shred.erasure_set();

        // If a shred from the next fec set has already been inserted, check the chaining
        let Some(next_fec_set_index) = erasure_meta.next_fec_set_index() else {
            error!("Invalid erasure meta, unable to compute next fec set index {erasure_meta:?}");
            return false;
        };
        let next_erasure_set = ErasureSetId::new(slot, next_fec_set_index);
        let Some(next_merkle_root_meta) = merkle_root_metas
            .get(&next_erasure_set)
            .map(WorkingEntry::as_ref)
            .map(Cow::Borrowed)
            .or_else(|| {
                self.merkle_root_meta(next_erasure_set)
                    .unwrap()
                    .map(Cow::Owned)
            })
        else {
            // No shred from the next fec set has been received
            return true;
        };
        let next_shred_id = ShredId::new(
            slot,
            next_merkle_root_meta.first_received_shred_index(),
            next_merkle_root_meta.first_received_shred_type(),
        );
        let Some(next_shred) =
            Self::get_shred_from_just_inserted_or_db(self, just_inserted_shreds, next_shred_id)
                .map(Cow::into_owned)
        else {
            error!(
                "Shred {next_shred_id:?} indicated by merkle root meta {next_merkle_root_meta:?} \
                 is missing from blockstore. This should only happen in extreme cases where \
                 blockstore cleanup has caught up to the root. Skipping the forward chained \
                 merkle root consistency check"
            );
            return true;
        };
        let merkle_root = shred.merkle_root().ok();
        let chained_merkle_root = shred::layout::get_chained_merkle_root(&next_shred);

        if !self.check_chaining(merkle_root, chained_merkle_root) {
            warn!(
                "Received conflicting chained merkle roots for slot: {slot}, shred \
                 {erasure_set:?} type {:?} has merkle root {merkle_root:?}, however next fec set \
                 shred {next_erasure_set:?} type {:?} chains to merkle root \
                 {chained_merkle_root:?}. Reporting as duplicate",
                shred.shred_type(),
                next_merkle_root_meta.first_received_shred_type(),
            );

            if !self.has_duplicate_shreds_in_slot(shred.slot()) {
                duplicate_shreds.push(PossibleDuplicateShred::ChainedMerkleRootConflict(
                    shred.clone(),
                    next_shred,
                ));
            }
            return false;
        }

        true
    }

    /// Returns true if there is no chaining conflict between
    /// the `shred` and `merkle_root_meta` of the previous FEC set,
    /// or if shreds from the previous set are yet to be received.
    ///
    /// Otherwise return false and add duplicate proof to
    /// `duplicate_shreds`.
    ///
    /// This is intended to be used right after `shred`'s `merkle_root_meta`
    /// has been created for the first time.
    fn check_backwards_chained_merkle_root_consistency(
        &self,
        shred: &Shred,
        just_inserted_shreds: &HashMap<ShredId, Shred>,
        erasure_metas: &BTreeMap<ErasureSetId, WorkingEntry<ErasureMeta>>,
        duplicate_shreds: &mut Vec<PossibleDuplicateShred>,
    ) -> bool {
        let slot = shred.slot();
        let erasure_set = shred.erasure_set();
        let fec_set_index = shred.fec_set_index();

        if fec_set_index == 0 {
            // Although the first fec set chains to the last fec set of the parent block,
            // if this chain is incorrect we do not know which block is the duplicate until votes
            // are received. We instead delay this check until the block reaches duplicate
            // confirmation.
            return true;
        }

        // If a shred from the previous fec set has already been inserted, check the chaining.
        // Since we cannot compute the previous fec set index, we check the in memory map, otherwise
        // check the previous key from blockstore to see if it is consecutive with our current set.
        let Some((prev_erasure_set, prev_erasure_meta)) = self
            .previous_erasure_set(erasure_set, erasure_metas)
            .expect("Expect database operations to succeed")
        else {
            // No shreds from the previous erasure batch have been received,
            // so nothing to check. Once the previous erasure batch is received,
            // we will verify this chain through the forward check above.
            return true;
        };

        let prev_shred_id = ShredId::new(
            slot,
            prev_erasure_meta
                .first_received_coding_shred_index()
                .expect("First received coding index must fit in u32"),
            ShredType::Code,
        );
        let Some(prev_shred) =
            Self::get_shred_from_just_inserted_or_db(self, just_inserted_shreds, prev_shred_id)
                .map(Cow::into_owned)
        else {
            warn!(
                "Shred {prev_shred_id:?} indicated by the erasure meta {prev_erasure_meta:?} \
                 is missing from blockstore. This can happen if you have recently upgraded \
                 from a version < v1.18.13, or if blockstore cleanup has caught up to the root. \
                 Skipping the backwards chained merkle root consistency check"
            );
            return true;
        };
        let merkle_root = shred::layout::get_merkle_root(&prev_shred);
        let chained_merkle_root = shred.chained_merkle_root().ok();

        if !self.check_chaining(merkle_root, chained_merkle_root) {
            warn!(
                "Received conflicting chained merkle roots for slot: {slot}, shred {:?} type {:?} \
                 chains to merkle root {chained_merkle_root:?}, however previous fec set coding \
                 shred {prev_erasure_set:?} has merkle root {merkle_root:?}. Reporting as duplicate",
                shred.erasure_set(),
                shred.shred_type(),
            );

            if !self.has_duplicate_shreds_in_slot(shred.slot()) {
                duplicate_shreds.push(PossibleDuplicateShred::ChainedMerkleRootConflict(
                    shred.clone(),
                    prev_shred,
                ));
            }
            return false;
        }

        true
    }

    /// Checks if the chained merkle root == merkle root
    ///
    /// Returns true if no conflict, or if chained merkle roots are not enabled
    fn check_chaining(&self, merkle_root: Option<Hash>, chained_merkle_root: Option<Hash>) -> bool {
        chained_merkle_root.is_none()  // Chained merkle roots have not been enabled yet
            || chained_merkle_root == merkle_root
    }

    fn should_insert_data_shred(
        &self,
        shred: &Shred,
        slot_meta: &SlotMeta,
        just_inserted_shreds: &HashMap<ShredId, Shred>,
        max_root: Slot,
        leader_schedule: Option<&LeaderScheduleCache>,
        shred_source: ShredSource,
        duplicate_shreds: &mut Vec<PossibleDuplicateShred>,
    ) -> bool {
        let shred_index = u64::from(shred.index());
        let slot = shred.slot();
        let last_in_slot = if shred.last_in_slot() {
            debug!("got last in slot");
            true
        } else {
            false
        };
        debug_assert_matches!(shred.sanitize(), Ok(()));
        // Check that we do not receive shred_index >= than the last_index
        // for the slot
        let last_index = slot_meta.last_index;
        if last_index.map(|ix| shred_index >= ix).unwrap_or_default() {
            let leader_pubkey = leader_schedule
                .and_then(|leader_schedule| leader_schedule.slot_leader_at(slot, None));

            if !self.has_duplicate_shreds_in_slot(slot) {
                let shred_id = ShredId::new(
                    slot,
                    u32::try_from(last_index.unwrap()).unwrap(),
                    ShredType::Data,
                );
                let Some(ending_shred) = self
                    .get_shred_from_just_inserted_or_db(just_inserted_shreds, shred_id)
                    .map(Cow::into_owned)
                else {
                    error!(
                        "Last index data shred {shred_id:?} indiciated by slot meta {slot_meta:?} \
                         is missing from blockstore. This should only happen in extreme cases \
                         where blockstore cleanup has caught up to the root. Skipping data shred \
                         insertion"
                    );
                    return false;
                };

                if self
                    .store_duplicate_slot(slot, ending_shred.clone(), shred.payload().clone())
                    .is_err()
                {
                    warn!("store duplicate error");
                }
                duplicate_shreds.push(PossibleDuplicateShred::LastIndexConflict(
                    shred.clone(),
                    ending_shred,
                ));
            }

            datapoint_error!(
                "blockstore_error",
                (
                    "error",
                    format!(
                        "Leader {leader_pubkey:?}, slot {slot}: received index {shred_index} >= \
                         slot.last_index {last_index:?}, shred_source: {shred_source:?}"
                    ),
                    String
                )
            );
            return false;
        }
        // Check that we do not receive a shred with "last_index" true, but shred_index
        // less than our current received
        if last_in_slot && shred_index < slot_meta.received {
            let leader_pubkey = leader_schedule
                .and_then(|leader_schedule| leader_schedule.slot_leader_at(slot, None));

            if !self.has_duplicate_shreds_in_slot(slot) {
                let shred_id = ShredId::new(
                    slot,
                    u32::try_from(slot_meta.received - 1).unwrap(),
                    ShredType::Data,
                );
                let Some(ending_shred) = self
                    .get_shred_from_just_inserted_or_db(just_inserted_shreds, shred_id)
                    .map(Cow::into_owned)
                else {
                    error!(
                        "Last received data shred {shred_id:?} indiciated by slot meta \
                         {slot_meta:?} is missing from blockstore. This should only happen in \
                         extreme cases where blockstore cleanup has caught up to the root. \
                         Skipping data shred insertion"
                    );
                    return false;
                };

                if self
                    .store_duplicate_slot(slot, ending_shred.clone(), shred.payload().clone())
                    .is_err()
                {
                    warn!("store duplicate error");
                }
                duplicate_shreds.push(PossibleDuplicateShred::LastIndexConflict(
                    shred.clone(),
                    ending_shred,
                ));
            }

            datapoint_error!(
                "blockstore_error",
                (
                    "error",
                    format!(
                        "Leader {:?}, slot {}: received shred_index {} < slot.received {}, \
                         shred_source: {:?}",
                        leader_pubkey, slot, shred_index, slot_meta.received, shred_source
                    ),
                    String
                )
            );
            return false;
        }

        // TODO Shouldn't this use shred.parent() instead and update
        // slot_meta.parent_slot accordingly?
        slot_meta
            .parent_slot
            .map(|parent_slot| verify_shred_slots(slot, parent_slot, max_root))
            .unwrap_or_default()
    }

    /// send slot full timing point to poh_timing_report service
    fn send_slot_full_timing(&self, slot: Slot) {
        if let Some(ref sender) = self.shred_timing_point_sender {
            send_poh_timing_point(
                sender,
                SlotPohTimingInfo::new_slot_full_poh_time_point(
                    slot,
                    Some(self.max_root()),
                    solana_sdk::timing::timestamp(),
                ),
            );
        }
    }

    fn insert_data_shred(
        &self,
        slot_meta: &mut SlotMeta,
        data_index: &mut ShredIndex,
        shred: &Shred,
        write_batch: &mut WriteBatch,
        shred_source: ShredSource,
    ) -> Result<Vec<CompletedDataSetInfo>> {
        let slot = shred.slot();
        let index = u64::from(shred.index());

        let last_in_slot = if shred.last_in_slot() {
            debug!("got last in slot");
            true
        } else {
            false
        };

        let last_in_data = if shred.data_complete() {
            debug!("got last in data");
            true
        } else {
            false
        };

        // Parent for slot meta should have been set by this point
        assert!(!slot_meta.is_orphan());

        let new_consumed = if slot_meta.consumed == index {
            let mut current_index = index + 1;

            while data_index.contains(current_index) {
                current_index += 1;
            }
            current_index
        } else {
            slot_meta.consumed
        };

        // Commit step: commit all changes to the mutable structures at once, or none at all.
        // We don't want only a subset of these changes going through.
        write_batch.put_bytes::<cf::ShredData>((slot, index), shred.bytes_to_store())?;
        data_index.insert(index);
        let newly_completed_data_sets = update_slot_meta(
            last_in_slot,
            last_in_data,
            slot_meta,
            index as u32,
            new_consumed,
            shred.reference_tick(),
            data_index,
        )
        .into_iter()
        .map(|(start_index, end_index)| CompletedDataSetInfo {
            slot,
            start_index,
            end_index,
        })
        .collect();

        self.slots_stats.record_shred(
            shred.slot(),
            shred.fec_set_index(),
            shred_source,
            Some(slot_meta),
        );

        // slot is full, send slot full timing to poh_timing_report service.
        if slot_meta.is_full() {
            self.send_slot_full_timing(slot);
        }

        trace!("inserted shred into slot {:?} and index {:?}", slot, index);

        Ok(newly_completed_data_sets)
    }

    pub fn get_data_shred(&self, slot: Slot, index: u64) -> Result<Option<Vec<u8>>> {
        let shred = self.data_shred_cf.get_bytes((slot, index))?;
        let shred = shred.map(ShredData::resize_stored_shred).transpose();
        shred.map_err(|err| {
            let err = format!("Invalid stored shred: {err}");
            let err = Box::new(bincode::ErrorKind::Custom(err));
            BlockstoreError::InvalidShredData(err)
        })
    }

    pub fn get_data_shreds_for_slot(&self, slot: Slot, start_index: u64) -> Result<Vec<Shred>> {
        self.slot_data_iterator(slot, start_index)
            .expect("blockstore couldn't fetch iterator")
            .map(|(_, bytes)| {
                Shred::new_from_serialized_shred(bytes.to_vec()).map_err(|err| {
                    BlockstoreError::InvalidShredData(Box::new(bincode::ErrorKind::Custom(
                        format!("Could not reconstruct shred from shred payload: {err:?}"),
                    )))
                })
            })
            .collect()
    }

    pub fn get_coding_shred(&self, slot: Slot, index: u64) -> Result<Option<Vec<u8>>> {
        self.code_shred_cf.get_bytes((slot, index))
    }

    pub fn get_coding_shreds_for_slot(
        &self,
        slot: Slot,
        start_index: u64,
    ) -> std::result::Result<Vec<Shred>, shred::Error> {
        self.slot_coding_iterator(slot, start_index)
            .expect("blockstore couldn't fetch iterator")
            .map(|code| Shred::new_from_serialized_shred(code.1.to_vec()))
            .collect()
    }

    // Only used by tests
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn write_entries(
        &self,
        start_slot: Slot,
        num_ticks_in_start_slot: u64,
        start_index: u32,
        ticks_per_slot: u64,
        parent: Option<u64>,
        is_full_slot: bool,
        keypair: &Keypair,
        entries: Vec<Entry>,
        version: u16,
    ) -> Result<usize /*num of data shreds*/> {
        let mut parent_slot = parent.map_or(start_slot.saturating_sub(1), |v| v);
        let num_slots = (start_slot - parent_slot).max(1); // Note: slot 0 has parent slot 0
        assert!(num_ticks_in_start_slot < num_slots * ticks_per_slot);
        let mut remaining_ticks_in_slot = num_slots * ticks_per_slot - num_ticks_in_start_slot;

        let mut current_slot = start_slot;
        let mut shredder = Shredder::new(current_slot, parent_slot, 0, version).unwrap();
        let mut all_shreds = vec![];
        let mut slot_entries = vec![];
        let reed_solomon_cache = ReedSolomonCache::default();
        let mut chained_merkle_root = Some(Hash::new_from_array(rand::thread_rng().gen()));
        // Find all the entries for start_slot
        for entry in entries.into_iter() {
            if remaining_ticks_in_slot == 0 {
                current_slot += 1;
                parent_slot = current_slot - 1;
                remaining_ticks_in_slot = ticks_per_slot;
                let current_entries = std::mem::take(&mut slot_entries);
                let start_index = {
                    if all_shreds.is_empty() {
                        start_index
                    } else {
                        0
                    }
                };
                let (mut data_shreds, mut coding_shreds) = shredder.entries_to_shreds(
                    keypair,
                    &current_entries,
                    true, // is_last_in_slot
                    chained_merkle_root,
                    start_index, // next_shred_index
                    start_index, // next_code_index
                    true,        // merkle_variant
                    &reed_solomon_cache,
                    &mut ProcessShredsStats::default(),
                );
                all_shreds.append(&mut data_shreds);
                all_shreds.append(&mut coding_shreds);
                chained_merkle_root = Some(coding_shreds.last().unwrap().merkle_root().unwrap());
                shredder = Shredder::new(
                    current_slot,
                    parent_slot,
                    (ticks_per_slot - remaining_ticks_in_slot) as u8,
                    version,
                )
                .unwrap();
            }

            if entry.is_tick() {
                remaining_ticks_in_slot -= 1;
            }
            slot_entries.push(entry);
        }

        if !slot_entries.is_empty() {
            let (mut data_shreds, mut coding_shreds) = shredder.entries_to_shreds(
                keypair,
                &slot_entries,
                is_full_slot,
                chained_merkle_root,
                0,    // next_shred_index
                0,    // next_code_index
                true, // merkle_variant
                &reed_solomon_cache,
                &mut ProcessShredsStats::default(),
            );
            all_shreds.append(&mut data_shreds);
            all_shreds.append(&mut coding_shreds);
        }
        let num_data = all_shreds.iter().filter(|shred| shred.is_data()).count();
        self.insert_shreds(all_shreds, None, false)?;
        Ok(num_data)
    }

    pub fn get_index(&self, slot: Slot) -> Result<Option<Index>> {
        self.index_cf.get(slot)
    }

    /// Manually update the meta for a slot.
    /// Can interfere with automatic meta update and potentially break chaining.
    /// Dangerous. Use with care.
    pub fn put_meta_bytes(&self, slot: Slot, bytes: &[u8]) -> Result<()> {
        self.meta_cf.put_bytes(slot, bytes)
    }

    /// Manually update the meta for a slot.
    /// Can interfere with automatic meta update and potentially break chaining.
    /// Dangerous. Use with care.
    pub fn put_meta(&self, slot: Slot, meta: &SlotMeta) -> Result<()> {
        self.put_meta_bytes(slot, &bincode::serialize(meta)?)
    }

    /// Find missing shred indices for a given `slot` within the range
    /// [`start_index`, `end_index`]. Missing shreds will only be reported as
    /// missing if they should be present by the time this function is called,
    /// as controlled by`first_timestamp` and `defer_threshold_ticks`.
    ///
    /// Arguments:
    ///  - `db_iterator`: Iterator to run search over.
    ///  - `slot`: The slot to search for missing shreds for.
    ///  - 'first_timestamp`: Timestamp (ms) for slot's first shred insertion.
    ///  - `defer_threshold_ticks`: A grace period to allow shreds that are
    ///    missing to be excluded from the reported missing list. This allows
    ///    tuning on how aggressively missing shreds should be reported and
    ///    acted upon.
    ///  - `start_index`: Begin search (inclusively) at this shred index.
    ///  - `end_index`: Finish search (exclusively) at this shred index.
    ///  - `max_missing`: Limit result to this many indices.
    fn find_missing_indexes<C>(
        db_iterator: &mut DBRawIterator,
        slot: Slot,
        first_timestamp: u64,
        defer_threshold_ticks: u64,
        start_index: u64,
        end_index: u64,
        max_missing: usize,
    ) -> Vec<u64>
    where
        C: Column<Index = (u64, u64)>,
    {
        if start_index >= end_index || max_missing == 0 {
            return vec![];
        }

        let mut missing_indexes = vec![];
        // System time is not monotonic
        let ticks_since_first_insert =
            DEFAULT_TICKS_PER_SECOND * timestamp().saturating_sub(first_timestamp) / 1000;

        // Seek to the first shred with index >= start_index
        db_iterator.seek(&C::key((slot, start_index)));

        // The index of the first missing shred in the slot
        let mut prev_index = start_index;
        loop {
            if !db_iterator.valid() {
                let num_to_take = max_missing - missing_indexes.len();
                missing_indexes.extend((prev_index..end_index).take(num_to_take));
                break;
            }
            let (current_slot, index) = C::index(db_iterator.key().expect("Expect a valid key"));

            let current_index = {
                if current_slot > slot {
                    end_index
                } else {
                    index
                }
            };

            let upper_index = cmp::min(current_index, end_index);
            // the tick that will be used to figure out the timeout for this hole
            let data = db_iterator.value().expect("couldn't read value");
            let reference_tick = u64::from(shred::layout::get_reference_tick(data).unwrap());
            if ticks_since_first_insert < reference_tick + defer_threshold_ticks {
                // The higher index holes have not timed out yet
                break;
            }

            let num_to_take = max_missing - missing_indexes.len();
            missing_indexes.extend((prev_index..upper_index).take(num_to_take));

            if missing_indexes.len() == max_missing
                || current_slot > slot
                || current_index >= end_index
            {
                break;
            }

            prev_index = current_index + 1;
            db_iterator.next();
        }

        missing_indexes
    }

    /// Find missing data shreds for the given `slot`.
    ///
    /// For more details on the arguments, see [`find_missing_indexes`].
    pub fn find_missing_data_indexes(
        &self,
        slot: Slot,
        first_timestamp: u64,
        defer_threshold_ticks: u64,
        start_index: u64,
        end_index: u64,
        max_missing: usize,
    ) -> Vec<u64> {
        if let Ok(mut db_iterator) = self
            .db
            .raw_iterator_cf(self.db.cf_handle::<cf::ShredData>())
        {
            Self::find_missing_indexes::<cf::ShredData>(
                &mut db_iterator,
                slot,
                first_timestamp,
                defer_threshold_ticks,
                start_index,
                end_index,
                max_missing,
            )
        } else {
            vec![]
        }
    }

    fn get_block_time(&self, slot: Slot) -> Result<Option<UnixTimestamp>> {
        let _lock = self.check_lowest_cleanup_slot(slot)?;
        self.blocktime_cf.get(slot)
    }

    pub fn get_rooted_block_time(&self, slot: Slot) -> Result<UnixTimestamp> {
        self.rpc_api_metrics
            .num_get_rooted_block_time
            .fetch_add(1, Ordering::Relaxed);
        let _lock = self.check_lowest_cleanup_slot(slot)?;

        if self.is_root(slot) {
            return self
                .blocktime_cf
                .get(slot)?
                .ok_or(BlockstoreError::SlotUnavailable);
        }
        Err(BlockstoreError::SlotNotRooted)
    }

    pub fn cache_block_time(&self, slot: Slot, timestamp: UnixTimestamp) -> Result<()> {
        self.blocktime_cf.put(slot, &timestamp)
    }

    pub fn get_block_height(&self, slot: Slot) -> Result<Option<u64>> {
        self.rpc_api_metrics
            .num_get_block_height
            .fetch_add(1, Ordering::Relaxed);
        let _lock = self.check_lowest_cleanup_slot(slot)?;

        self.block_height_cf.get(slot)
    }

    pub fn cache_block_height(&self, slot: Slot, block_height: u64) -> Result<()> {
        self.block_height_cf.put(slot, &block_height)
    }

    /// The first complete block that is available in the Blockstore ledger
    pub fn get_first_available_block(&self) -> Result<Slot> {
        let mut root_iterator = self.rooted_slot_iterator(self.lowest_slot_with_genesis())?;
        let first_root = root_iterator.next().unwrap_or_default();
        // If the first root is slot 0, it is genesis. Genesis is always complete, so it is correct
        // to return it as first-available.
        if first_root == 0 {
            return Ok(first_root);
        }
        // Otherwise, the block at root-index 0 cannot ever be complete, because it is missing its
        // parent blockhash. A parent blockhash must be calculated from the entries of the previous
        // block. Therefore, the first available complete block is that at root-index 1.
        Ok(root_iterator.next().unwrap_or_default())
    }

    pub fn get_rooted_block(
        &self,
        slot: Slot,
        require_previous_blockhash: bool,
    ) -> Result<VersionedConfirmedBlock> {
        self.rpc_api_metrics
            .num_get_rooted_block
            .fetch_add(1, Ordering::Relaxed);
        let _lock = self.check_lowest_cleanup_slot(slot)?;

        if self.is_root(slot) {
            return self.get_complete_block(slot, require_previous_blockhash);
        }
        Err(BlockstoreError::SlotNotRooted)
    }

    pub fn get_complete_block(
        &self,
        slot: Slot,
        require_previous_blockhash: bool,
    ) -> Result<VersionedConfirmedBlock> {
        self.do_get_complete_block_with_entries(
            slot,
            require_previous_blockhash,
            false,
            /*allow_dead_slots:*/ false,
        )
        .map(|result| result.block)
    }

    pub fn get_rooted_block_with_entries(
        &self,
        slot: Slot,
        require_previous_blockhash: bool,
    ) -> Result<VersionedConfirmedBlockWithEntries> {
        self.rpc_api_metrics
            .num_get_rooted_block_with_entries
            .fetch_add(1, Ordering::Relaxed);
        let _lock = self.check_lowest_cleanup_slot(slot)?;

        if self.is_root(slot) {
            return self.do_get_complete_block_with_entries(
                slot,
                require_previous_blockhash,
                true,
                /*allow_dead_slots:*/ false,
            );
        }
        Err(BlockstoreError::SlotNotRooted)
    }

    #[cfg(feature = "dev-context-only-utils")]
    pub fn get_complete_block_with_entries(
        &self,
        slot: Slot,
        require_previous_blockhash: bool,
        populate_entries: bool,
        allow_dead_slots: bool,
    ) -> Result<VersionedConfirmedBlockWithEntries> {
        self.do_get_complete_block_with_entries(
            slot,
            require_previous_blockhash,
            populate_entries,
            allow_dead_slots,
        )
    }

    fn do_get_complete_block_with_entries(
        &self,
        slot: Slot,
        require_previous_blockhash: bool,
        populate_entries: bool,
        allow_dead_slots: bool,
    ) -> Result<VersionedConfirmedBlockWithEntries> {
        let Some(slot_meta) = self.meta_cf.get(slot)? else {
            trace!("do_get_complete_block_with_entries() failed for {slot} (missing SlotMeta)");
            return Err(BlockstoreError::SlotUnavailable);
        };
        if slot_meta.is_full() {
            let (slot_entries, _, _) = self.get_slot_entries_with_shred_info(
                slot,
                /*shred_start_index:*/ 0,
                allow_dead_slots,
            )?;
            if !slot_entries.is_empty() {
                let blockhash = slot_entries
                    .last()
                    .map(|entry| entry.hash)
                    .unwrap_or_else(|| panic!("Rooted slot {slot:?} must have blockhash"));
                let mut starting_transaction_index = 0;
                let mut entries = if populate_entries {
                    Vec::with_capacity(slot_entries.len())
                } else {
                    Vec::new()
                };
                let slot_transaction_iterator = slot_entries
                    .into_iter()
                    .flat_map(|entry| {
                        if populate_entries {
                            entries.push(solana_transaction_status::EntrySummary {
                                num_hashes: entry.num_hashes,
                                hash: entry.hash,
                                num_transactions: entry.transactions.len() as u64,
                                starting_transaction_index,
                            });
                            starting_transaction_index += entry.transactions.len();
                        }
                        entry.transactions
                    })
                    .map(|transaction| {
                        if let Err(err) = transaction.sanitize() {
                            warn!(
                                "Blockstore::get_block sanitize failed: {:?}, slot: {:?}, {:?}",
                                err, slot, transaction,
                            );
                        }
                        transaction
                    });
                let parent_slot_entries = slot_meta
                    .parent_slot
                    .and_then(|parent_slot| {
                        self.get_slot_entries_with_shred_info(
                            parent_slot,
                            /*shred_start_index:*/ 0,
                            allow_dead_slots,
                        )
                        .ok()
                        .map(|(entries, _, _)| entries)
                    })
                    .unwrap_or_default();
                if parent_slot_entries.is_empty() && require_previous_blockhash {
                    return Err(BlockstoreError::ParentEntriesUnavailable);
                }
                let previous_blockhash = if !parent_slot_entries.is_empty() {
                    get_last_hash(parent_slot_entries.iter()).unwrap()
                } else {
                    Hash::default()
                };

                let (rewards, num_partitions) = self
                    .rewards_cf
                    .get_protobuf_or_bincode::<StoredExtendedRewards>(slot)?
                    .unwrap_or_default()
                    .into();

                // The Blocktime and BlockHeight column families are updated asynchronously; they
                // may not be written by the time the complete slot entries are available. In this
                // case, these fields will be `None`.
                let block_time = self.blocktime_cf.get(slot)?;
                let block_height = self.block_height_cf.get(slot)?;

                let block = VersionedConfirmedBlock {
                    previous_blockhash: previous_blockhash.to_string(),
                    blockhash: blockhash.to_string(),
                    // If the slot is full it should have parent_slot populated
                    // from shreds received.
                    parent_slot: slot_meta.parent_slot.unwrap(),
                    transactions: self
                        .map_transactions_to_statuses(slot, slot_transaction_iterator)?,
                    rewards,
                    num_partitions,
                    block_time,
                    block_height,
                };
                return Ok(VersionedConfirmedBlockWithEntries { block, entries });
            }
        }
        trace!("do_get_complete_block_with_entries() failed for {slot} (slot not full)");
        Err(BlockstoreError::SlotUnavailable)
    }

    pub fn map_transactions_to_statuses(
        &self,
        slot: Slot,
        iterator: impl Iterator<Item = VersionedTransaction>,
    ) -> Result<Vec<VersionedTransactionWithStatusMeta>> {
        iterator
            .map(|transaction| {
                let signature = transaction.signatures[0];
                Ok(VersionedTransactionWithStatusMeta {
                    transaction,
                    meta: self
                        .read_transaction_status((signature, slot))?
                        .ok_or(BlockstoreError::MissingTransactionMetadata)?,
                })
            })
            .collect()
    }

    fn cleanup_old_entries(&self) -> Result<()> {
        if !self.is_primary_access() {
            return Ok(());
        }

        // Initialize TransactionStatusIndexMeta if they are not present already
        if self.transaction_status_index_cf.get(0)?.is_none() {
            self.transaction_status_index_cf
                .put(0, &TransactionStatusIndexMeta::default())?;
        }
        if self.transaction_status_index_cf.get(1)?.is_none() {
            self.transaction_status_index_cf
                .put(1, &TransactionStatusIndexMeta::default())?;
        }

        // If present, delete dummy entries inserted by old software
        // https://github.com/solana-labs/solana/blob/bc2b372/ledger/src/blockstore.rs#L2130-L2137
        let transaction_status_dummy_key = cf::TransactionStatus::as_index(2);
        if self
            .transaction_status_cf
            .get_protobuf_or_bincode::<StoredTransactionStatusMeta>(transaction_status_dummy_key)?
            .is_some()
        {
            self.transaction_status_cf
                .delete(transaction_status_dummy_key)?;
        };
        let address_signatures_dummy_key = cf::AddressSignatures::as_index(2);
        if self
            .address_signatures_cf
            .get(address_signatures_dummy_key)?
            .is_some()
        {
            self.address_signatures_cf
                .delete(address_signatures_dummy_key)?;
        };

        Ok(())
    }

    fn get_highest_primary_index_slot(&self) -> Option<Slot> {
        *self.highest_primary_index_slot.read().unwrap()
    }

    fn set_highest_primary_index_slot(&self, slot: Option<Slot>) {
        *self.highest_primary_index_slot.write().unwrap() = slot;
    }

    fn update_highest_primary_index_slot(&self) -> Result<()> {
        let iterator = self.transaction_status_index_cf.iter(IteratorMode::Start)?;
        let mut highest_primary_index_slot = None;
        for (_, data) in iterator {
            let meta: TransactionStatusIndexMeta = deserialize(&data).unwrap();
            if highest_primary_index_slot.is_none()
                || highest_primary_index_slot.is_some_and(|slot| slot < meta.max_slot)
            {
                highest_primary_index_slot = Some(meta.max_slot);
            }
        }
        if highest_primary_index_slot.is_some_and(|slot| slot != 0) {
            self.set_highest_primary_index_slot(highest_primary_index_slot);
        } else {
            self.db.set_clean_slot_0(true);
        }
        Ok(())
    }

    fn maybe_cleanup_highest_primary_index_slot(&self, oldest_slot: Slot) -> Result<()> {
        let mut w_highest_primary_index_slot = self.highest_primary_index_slot.write().unwrap();
        if let Some(highest_primary_index_slot) = *w_highest_primary_index_slot {
            if oldest_slot > highest_primary_index_slot {
                *w_highest_primary_index_slot = None;
                self.db.set_clean_slot_0(true);
            }
        }
        Ok(())
    }

    fn read_deprecated_transaction_status(
        &self,
        index: (Signature, Slot),
    ) -> Result<Option<TransactionStatusMeta>> {
        let (signature, slot) = index;
        let result = self
            .transaction_status_cf
            .get_raw_protobuf_or_bincode::<StoredTransactionStatusMeta>(
                &cf::TransactionStatus::deprecated_key((0, signature, slot)),
            )?;
        if result.is_none() {
            Ok(self
                .transaction_status_cf
                .get_raw_protobuf_or_bincode::<StoredTransactionStatusMeta>(
                    &cf::TransactionStatus::deprecated_key((1, signature, slot)),
                )?
                .and_then(|meta| meta.try_into().ok()))
        } else {
            Ok(result.and_then(|meta| meta.try_into().ok()))
        }
    }

    pub fn read_transaction_status(
        &self,
        index: (Signature, Slot),
    ) -> Result<Option<TransactionStatusMeta>> {
        let result = self.transaction_status_cf.get_protobuf(index)?;
        if result.is_none()
            && self
                .get_highest_primary_index_slot()
                .is_some_and(|highest_slot| highest_slot >= index.1)
        {
            self.read_deprecated_transaction_status(index)
        } else {
            Ok(result.and_then(|meta| meta.try_into().ok()))
        }
    }

    pub fn write_transaction_status(
        &self,
        slot: Slot,
        signature: Signature,
        writable_keys: Vec<&Pubkey>,
        readonly_keys: Vec<&Pubkey>,
        status: TransactionStatusMeta,
        transaction_index: usize,
    ) -> Result<()> {
        let status = status.into();
        let transaction_index = u32::try_from(transaction_index)
            .map_err(|_| BlockstoreError::TransactionIndexOverflow)?;
        self.transaction_status_cf
            .put_protobuf((signature, slot), &status)?;
        for address in writable_keys {
            self.address_signatures_cf.put(
                (*address, slot, transaction_index, signature),
                &AddressSignatureMeta { writeable: true },
            )?;
        }
        for address in readonly_keys {
            self.address_signatures_cf.put(
                (*address, slot, transaction_index, signature),
                &AddressSignatureMeta { writeable: false },
            )?;
        }
        Ok(())
    }

    pub fn read_transaction_memos(
        &self,
        signature: Signature,
        slot: Slot,
    ) -> Result<Option<String>> {
        let memos = self.transaction_memos_cf.get((signature, slot))?;
        if memos.is_none()
            && self
                .get_highest_primary_index_slot()
                .is_some_and(|highest_slot| highest_slot >= slot)
        {
            self.transaction_memos_cf
                .get_raw(&cf::TransactionMemos::deprecated_key(signature))
        } else {
            Ok(memos)
        }
    }

    pub fn write_transaction_memos(
        &self,
        signature: &Signature,
        slot: Slot,
        memos: String,
    ) -> Result<()> {
        self.transaction_memos_cf.put((*signature, slot), &memos)
    }

    /// Acquires the `lowest_cleanup_slot` lock and returns a tuple of the held lock
    /// and lowest available slot.
    ///
    /// The function will return BlockstoreError::SlotCleanedUp if the input
    /// `slot` has already been cleaned-up.
    fn check_lowest_cleanup_slot(&self, slot: Slot) -> Result<std::sync::RwLockReadGuard<Slot>> {
        // lowest_cleanup_slot is the last slot that was not cleaned up by LedgerCleanupService
        let lowest_cleanup_slot = self.lowest_cleanup_slot.read().unwrap();
        if *lowest_cleanup_slot > 0 && *lowest_cleanup_slot >= slot {
            return Err(BlockstoreError::SlotCleanedUp);
        }
        // Make caller hold this lock properly; otherwise LedgerCleanupService can purge/compact
        // needed slots here at any given moment
        Ok(lowest_cleanup_slot)
    }

    /// Acquires the lock of `lowest_cleanup_slot` and returns the tuple of
    /// the held lock and the lowest available slot.
    ///
    /// This function ensures a consistent result by using lowest_cleanup_slot
    /// as the lower bound for reading columns that do not employ strong read
    /// consistency with slot-based delete_range.
    fn ensure_lowest_cleanup_slot(&self) -> (std::sync::RwLockReadGuard<Slot>, Slot) {
        let lowest_cleanup_slot = self.lowest_cleanup_slot.read().unwrap();
        let lowest_available_slot = (*lowest_cleanup_slot)
            .checked_add(1)
            .expect("overflow from trusted value");

        // Make caller hold this lock properly; otherwise LedgerCleanupService can purge/compact
        // needed slots here at any given moment.
        // Blockstore callers, like rpc, can process concurrent read queries
        (lowest_cleanup_slot, lowest_available_slot)
    }

    // Returns a transaction status, as well as a loop counter for unit testing
    fn get_transaction_status_with_counter(
        &self,
        signature: Signature,
        confirmed_unrooted_slots: &HashSet<Slot>,
    ) -> Result<(Option<(Slot, TransactionStatusMeta)>, u64)> {
        let mut counter = 0;
        let (lock, _) = self.ensure_lowest_cleanup_slot();
        let first_available_block = self.get_first_available_block()?;

        let iterator =
            self.transaction_status_cf
                .iter_current_index_filtered(IteratorMode::From(
                    (signature, first_available_block),
                    IteratorDirection::Forward,
                ))?;

        for ((sig, slot), _data) in iterator {
            counter += 1;
            if sig != signature {
                break;
            }
            if !self.is_root(slot) && !confirmed_unrooted_slots.contains(&slot) {
                continue;
            }
            let status = self
                .transaction_status_cf
                .get_protobuf((signature, slot))?
                .and_then(|status| status.try_into().ok())
                .map(|status| (slot, status));
            return Ok((status, counter));
        }

        if self.get_highest_primary_index_slot().is_none() {
            return Ok((None, counter));
        }
        for transaction_status_cf_primary_index in 0..=1 {
            let index_iterator =
                self.transaction_status_cf
                    .iter_deprecated_index_filtered(IteratorMode::From(
                        (
                            transaction_status_cf_primary_index,
                            signature,
                            first_available_block,
                        ),
                        IteratorDirection::Forward,
                    ))?;
            for ((i, sig, slot), _data) in index_iterator {
                counter += 1;
                if i != transaction_status_cf_primary_index || sig != signature {
                    break;
                }
                if !self.is_root(slot) && !confirmed_unrooted_slots.contains(&slot) {
                    continue;
                }
                let status = self
                    .transaction_status_cf
                    .get_raw_protobuf_or_bincode::<StoredTransactionStatusMeta>(
                        &cf::TransactionStatus::deprecated_key((i, signature, slot)),
                    )?
                    .and_then(|status| status.try_into().ok())
                    .map(|status| (slot, status));
                return Ok((status, counter));
            }
        }
        drop(lock);

        Ok((None, counter))
    }

    /// Returns a transaction status
    pub fn get_rooted_transaction_status(
        &self,
        signature: Signature,
    ) -> Result<Option<(Slot, TransactionStatusMeta)>> {
        self.rpc_api_metrics
            .num_get_rooted_transaction_status
            .fetch_add(1, Ordering::Relaxed);

        self.get_transaction_status(signature, &HashSet::default())
    }

    /// Returns a transaction status
    pub fn get_transaction_status(
        &self,
        signature: Signature,
        confirmed_unrooted_slots: &HashSet<Slot>,
    ) -> Result<Option<(Slot, TransactionStatusMeta)>> {
        self.rpc_api_metrics
            .num_get_transaction_status
            .fetch_add(1, Ordering::Relaxed);

        self.get_transaction_status_with_counter(signature, confirmed_unrooted_slots)
            .map(|(status, _)| status)
    }

    /// Returns a complete transaction if it was processed in a root
    pub fn get_rooted_transaction(
        &self,
        signature: Signature,
    ) -> Result<Option<ConfirmedTransactionWithStatusMeta>> {
        self.rpc_api_metrics
            .num_get_rooted_transaction
            .fetch_add(1, Ordering::Relaxed);

        self.get_transaction_with_status(signature, &HashSet::default())
    }

    /// Returns a complete transaction
    pub fn get_complete_transaction(
        &self,
        signature: Signature,
        highest_confirmed_slot: Slot,
    ) -> Result<Option<ConfirmedTransactionWithStatusMeta>> {
        self.rpc_api_metrics
            .num_get_complete_transaction
            .fetch_add(1, Ordering::Relaxed);

        let max_root = self.max_root();
        let confirmed_unrooted_slots: HashSet<_> =
            AncestorIterator::new_inclusive(highest_confirmed_slot, self)
                .take_while(|&slot| slot > max_root)
                .collect();
        self.get_transaction_with_status(signature, &confirmed_unrooted_slots)
    }

    fn get_transaction_with_status(
        &self,
        signature: Signature,
        confirmed_unrooted_slots: &HashSet<Slot>,
    ) -> Result<Option<ConfirmedTransactionWithStatusMeta>> {
        if let Some((slot, meta)) =
            self.get_transaction_status(signature, confirmed_unrooted_slots)?
        {
            let transaction = self
                .find_transaction_in_slot(slot, signature)?
                .ok_or(BlockstoreError::TransactionStatusSlotMismatch)?; // Should not happen

            let block_time = self.get_block_time(slot)?;
            Ok(Some(ConfirmedTransactionWithStatusMeta {
                slot,
                tx_with_meta: TransactionWithStatusMeta::Complete(
                    VersionedTransactionWithStatusMeta { transaction, meta },
                ),
                block_time,
            }))
        } else {
            Ok(None)
        }
    }

    fn find_transaction_in_slot(
        &self,
        slot: Slot,
        signature: Signature,
    ) -> Result<Option<VersionedTransaction>> {
        let slot_entries = self.get_slot_entries(slot, 0)?;
        Ok(slot_entries
            .iter()
            .cloned()
            .flat_map(|entry| entry.transactions)
            .map(|transaction| {
                if let Err(err) = transaction.sanitize() {
                    warn!(
                        "Blockstore::find_transaction_in_slot sanitize failed: {:?}, slot: {:?}, \
                         {:?}",
                        err, slot, transaction,
                    );
                }
                transaction
            })
            .find(|transaction| transaction.signatures[0] == signature))
    }

    // DEPRECATED and decommissioned
    // This method always returns an empty Vec
    fn find_address_signatures(
        &self,
        _pubkey: Pubkey,
        _start_slot: Slot,
        _end_slot: Slot,
    ) -> Result<Vec<(Slot, Signature)>> {
        Ok(vec![])
    }

    // Returns all signatures for an address in a particular slot, regardless of whether that slot
    // has been rooted. The transactions will be ordered by their occurrence in the block
    fn find_address_signatures_for_slot(
        &self,
        pubkey: Pubkey,
        slot: Slot,
    ) -> Result<Vec<(Slot, Signature)>> {
        let (lock, lowest_available_slot) = self.ensure_lowest_cleanup_slot();
        let mut signatures: Vec<(Slot, Signature)> = vec![];
        if slot < lowest_available_slot {
            return Ok(signatures);
        }
        let index_iterator =
            self.address_signatures_cf
                .iter_current_index_filtered(IteratorMode::From(
                    (
                        pubkey,
                        slot.max(lowest_available_slot),
                        0,
                        Signature::default(),
                    ),
                    IteratorDirection::Forward,
                ))?;
        for ((address, transaction_slot, _transaction_index, signature), _) in index_iterator {
            if transaction_slot > slot || address != pubkey {
                break;
            }
            signatures.push((slot, signature));
        }
        drop(lock);
        Ok(signatures)
    }

    // DEPRECATED and decommissioned
    // This method always returns an empty Vec
    pub fn get_confirmed_signatures_for_address(
        &self,
        pubkey: Pubkey,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<Signature>> {
        self.rpc_api_metrics
            .num_get_confirmed_signatures_for_address
            .fetch_add(1, Ordering::Relaxed);

        self.find_address_signatures(pubkey, start_slot, end_slot)
            .map(|signatures| signatures.iter().map(|(_, signature)| *signature).collect())
    }

    fn get_block_signatures_rev(&self, slot: Slot) -> Result<Vec<Signature>> {
        let block = self.get_complete_block(slot, false).map_err(|err| {
            BlockstoreError::Io(IoError::new(
                ErrorKind::Other,
                format!("Unable to get block: {err}"),
            ))
        })?;

        Ok(block
            .transactions
            .into_iter()
            .rev()
            .filter_map(|transaction_with_meta| {
                transaction_with_meta
                    .transaction
                    .signatures
                    .into_iter()
                    .next()
            })
            .collect())
    }

    pub fn get_confirmed_signatures_for_address2(
        &self,
        address: Pubkey,
        highest_slot: Slot, // highest_super_majority_root or highest_confirmed_slot
        before: Option<Signature>,
        until: Option<Signature>,
        limit: usize,
    ) -> Result<SignatureInfosForAddress> {
        self.rpc_api_metrics
            .num_get_confirmed_signatures_for_address2
            .fetch_add(1, Ordering::Relaxed);

        let max_root = self.max_root();
        let confirmed_unrooted_slots: HashSet<_> =
            AncestorIterator::new_inclusive(highest_slot, self)
                .take_while(|&slot| slot > max_root)
                .collect();

        // Figure the `slot` to start listing signatures at, based on the ledger location of the
        // `before` signature if present.  Also generate a HashSet of signatures that should
        // be excluded from the results.
        let mut get_before_slot_timer = Measure::start("get_before_slot_timer");
        let (slot, mut before_excluded_signatures) = match before {
            None => (highest_slot, None),
            Some(before) => {
                let transaction_status =
                    self.get_transaction_status(before, &confirmed_unrooted_slots)?;
                match transaction_status {
                    None => return Ok(SignatureInfosForAddress::default()),
                    Some((slot, _)) => {
                        let mut slot_signatures = self.get_block_signatures_rev(slot)?;
                        if let Some(pos) = slot_signatures.iter().position(|&x| x == before) {
                            slot_signatures.truncate(pos + 1);
                        }

                        (
                            slot,
                            Some(slot_signatures.into_iter().collect::<HashSet<_>>()),
                        )
                    }
                }
            }
        };
        get_before_slot_timer.stop();

        let first_available_block = self.get_first_available_block()?;
        // Generate a HashSet of signatures that should be excluded from the results based on
        // `until` signature
        let mut get_until_slot_timer = Measure::start("get_until_slot_timer");
        let (lowest_slot, until_excluded_signatures) = match until {
            None => (first_available_block, HashSet::new()),
            Some(until) => {
                let transaction_status =
                    self.get_transaction_status(until, &confirmed_unrooted_slots)?;
                match transaction_status {
                    None => (first_available_block, HashSet::new()),
                    Some((slot, _)) => {
                        let mut slot_signatures = self.get_block_signatures_rev(slot)?;
                        if let Some(pos) = slot_signatures.iter().position(|&x| x == until) {
                            slot_signatures = slot_signatures.split_off(pos);
                        }

                        (slot, slot_signatures.into_iter().collect::<HashSet<_>>())
                    }
                }
            }
        };
        get_until_slot_timer.stop();

        // Fetch the list of signatures that affect the given address
        let mut address_signatures = vec![];

        // Get signatures in `slot`
        let mut get_initial_slot_timer = Measure::start("get_initial_slot_timer");
        let mut signatures = self.find_address_signatures_for_slot(address, slot)?;
        signatures.reverse();
        if let Some(excluded_signatures) = before_excluded_signatures.take() {
            address_signatures.extend(
                signatures
                    .into_iter()
                    .filter(|(_, signature)| !excluded_signatures.contains(signature)),
            )
        } else {
            address_signatures.append(&mut signatures);
        }
        get_initial_slot_timer.stop();

        let mut address_signatures_iter_timer = Measure::start("iter_timer");
        let mut iterator =
            self.address_signatures_cf
                .iter_current_index_filtered(IteratorMode::From(
                    // Regardless of whether a `before` signature is provided, the latest relevant
                    // `slot` is queried directly with the `find_address_signatures_for_slot()`
                    // call above. Thus, this iterator starts at the lowest entry of `address,
                    // slot` and iterates backwards to continue reporting the next earliest
                    // signatures.
                    (address, slot, 0, Signature::default()),
                    IteratorDirection::Reverse,
                ))?;

        // Iterate until limit is reached
        while address_signatures.len() < limit {
            if let Some(((key_address, slot, _transaction_index, signature), _)) = iterator.next() {
                if slot < lowest_slot {
                    break;
                }
                if key_address == address {
                    if self.is_root(slot) || confirmed_unrooted_slots.contains(&slot) {
                        address_signatures.push((slot, signature));
                    }
                    continue;
                }
            }
            break;
        }
        address_signatures_iter_timer.stop();

        let mut address_signatures: Vec<(Slot, Signature)> = address_signatures
            .into_iter()
            .filter(|(_, signature)| !until_excluded_signatures.contains(signature))
            .collect();
        address_signatures.truncate(limit);

        // Fill in the status information for each found transaction
        let mut get_status_info_timer = Measure::start("get_status_info_timer");
        let mut infos = vec![];
        for (slot, signature) in address_signatures.into_iter() {
            let transaction_status =
                self.get_transaction_status(signature, &confirmed_unrooted_slots)?;
            let err = transaction_status.and_then(|(_slot, status)| status.status.err());
            let memo = self.read_transaction_memos(signature, slot)?;
            let block_time = self.get_block_time(slot)?;
            infos.push(ConfirmedTransactionStatusWithSignature {
                signature,
                slot,
                err,
                memo,
                block_time,
            });
        }
        get_status_info_timer.stop();

        datapoint_info!(
            "blockstore-get-conf-sigs-for-addr-2",
            (
                "get_before_slot_us",
                get_before_slot_timer.as_us() as i64,
                i64
            ),
            (
                "get_initial_slot_us",
                get_initial_slot_timer.as_us() as i64,
                i64
            ),
            (
                "address_signatures_iter_us",
                address_signatures_iter_timer.as_us() as i64,
                i64
            ),
            (
                "get_status_info_us",
                get_status_info_timer.as_us() as i64,
                i64
            ),
            (
                "get_until_slot_us",
                get_until_slot_timer.as_us() as i64,
                i64
            )
        );

        Ok(SignatureInfosForAddress {
            infos,
            found_before: true, // if `before` signature was not found, this method returned early
        })
    }

    pub fn read_rewards(&self, index: Slot) -> Result<Option<Rewards>> {
        self.rewards_cf
            .get_protobuf_or_bincode::<Rewards>(index)
            .map(|result| result.map(|option| option.into()))
    }

    pub fn write_rewards(&self, index: Slot, rewards: RewardsAndNumPartitions) -> Result<()> {
        let rewards = rewards.into();
        self.rewards_cf.put_protobuf(index, &rewards)
    }

    pub fn get_recent_perf_samples(&self, num: usize) -> Result<Vec<(Slot, PerfSample)>> {
        // When reading `PerfSamples`, the database may contain samples with either `PerfSampleV1`
        // or `PerfSampleV2` encoding.  We expect `PerfSampleV1` to be a prefix of the
        // `PerfSampleV2` encoding (see [`perf_sample_v1_is_prefix_of_perf_sample_v2`]), so we try
        // them in order.
        let samples = self
            .db
            .iter::<cf::PerfSamples>(IteratorMode::End)?
            .take(num)
            .map(|(slot, data)| {
                deserialize::<PerfSampleV2>(&data)
                    .map(|sample| (slot, sample.into()))
                    .or_else(|err| {
                        match &*err {
                            bincode::ErrorKind::Io(io_err)
                                if matches!(io_err.kind(), ErrorKind::UnexpectedEof) =>
                            {
                                // Not enough bytes to deserialize as `PerfSampleV2`.
                            }
                            _ => return Err(err),
                        }

                        deserialize::<PerfSampleV1>(&data).map(|sample| (slot, sample.into()))
                    })
                    .map_err(Into::into)
            });

        samples.collect()
    }

    pub fn write_perf_sample(&self, index: Slot, perf_sample: &PerfSampleV2) -> Result<()> {
        // Always write as the current version.
        let bytes =
            serialize(&perf_sample).expect("`PerfSampleV2` can be serialized with `bincode`");
        self.perf_samples_cf.put_bytes(index, &bytes)
    }

    pub fn read_program_costs(&self) -> Result<Vec<(Pubkey, u64)>> {
        Ok(self
            .db
            .iter::<cf::ProgramCosts>(IteratorMode::End)?
            .map(|(pubkey, data)| {
                let program_cost: ProgramCost = deserialize(&data).unwrap();
                (pubkey, program_cost.cost)
            })
            .collect())
    }

    pub fn write_program_cost(&self, key: &Pubkey, value: &u64) -> Result<()> {
        self.program_costs_cf
            .put(*key, &ProgramCost { cost: *value })
    }

    pub fn delete_program_cost(&self, key: &Pubkey) -> Result<()> {
        self.program_costs_cf.delete(*key)
    }

    /// Returns the entry vector for the slot starting with `shred_start_index`
    pub fn get_slot_entries(&self, slot: Slot, shred_start_index: u64) -> Result<Vec<Entry>> {
        self.get_slot_entries_with_shred_info(slot, shred_start_index, false)
            .map(|x| x.0)
    }

    /// Returns the entry vector for the slot starting with `shred_start_index`, the number of
    /// shreds that comprise the entry vector, and whether the slot is full (consumed all shreds).
    pub fn get_slot_entries_with_shred_info(
        &self,
        slot: Slot,
        start_index: u64,
        allow_dead_slots: bool,
    ) -> Result<(Vec<Entry>, u64, bool)> {
        let (completed_ranges, slot_meta) = self.get_completed_ranges(slot, start_index)?;

        // Check if the slot is dead *after* fetching completed ranges to avoid a race
        // where a slot is marked dead by another thread before the completed range query finishes.
        // This should be sufficient because full slots will never be marked dead from another thread,
        // this can only happen during entry processing during replay stage.
        if self.is_dead(slot) && !allow_dead_slots {
            return Err(BlockstoreError::DeadSlot);
        } else if completed_ranges.is_empty() {
            return Ok((vec![], 0, false));
        }

        let slot_meta = slot_meta.unwrap();
        let num_shreds = completed_ranges
            .last()
            .map(|(_, end_index)| u64::from(*end_index) - start_index + 1)
            .unwrap_or(0);

        let entries = self.get_slot_entries_in_block(slot, completed_ranges, Some(&slot_meta))?;
        Ok((entries, num_shreds, slot_meta.is_full()))
    }

    /// Gets accounts used in transactions in the slot range [starting_slot, ending_slot].
    /// Additionally returns a bool indicating if the set may be incomplete.
    /// Used by ledger-tool to create a minimized snapshot
    pub fn get_accounts_used_in_range(
        &self,
        bank: &Bank,
        starting_slot: Slot,
        ending_slot: Slot,
    ) -> (DashSet<Pubkey>, bool) {
        let result = DashSet::new();
        let lookup_tables = DashSet::new();
        let possible_cpi_alt_extend = AtomicBool::new(false);

        fn add_to_set<'a>(set: &DashSet<Pubkey>, iter: impl IntoIterator<Item = &'a Pubkey>) {
            iter.into_iter().for_each(|key| {
                set.insert(*key);
            });
        }

        (starting_slot..=ending_slot)
            .into_par_iter()
            .for_each(|slot| {
                if let Ok(entries) = self.get_slot_entries(slot, 0) {
                    entries.into_par_iter().for_each(|entry| {
                        entry.transactions.into_iter().for_each(|tx| {
                            if let Some(lookups) = tx.message.address_table_lookups() {
                                add_to_set(
                                    &lookup_tables,
                                    lookups.iter().map(|lookup| &lookup.account_key),
                                );
                            }
                            // Attempt to verify transaction and load addresses from the current bank,
                            // or manually scan the transaction for addresses if the transaction.
                            if let Ok(tx) = bank.fully_verify_transaction(tx.clone()) {
                                add_to_set(&result, tx.message().account_keys().iter());
                            } else {
                                add_to_set(&result, tx.message.static_account_keys());

                                let tx = SanitizedVersionedTransaction::try_from(tx)
                                    .expect("transaction failed to sanitize");

                                let alt_scan_extensions = scan_transaction(&tx);
                                add_to_set(&result, &alt_scan_extensions.accounts);
                                if alt_scan_extensions.possibly_incomplete {
                                    possible_cpi_alt_extend.store(true, Ordering::Relaxed);
                                }
                            }
                        });
                    });
                }
            });

        // For each unique lookup table add all accounts to the minimized set.
        lookup_tables.into_par_iter().for_each(|lookup_table_key| {
            bank.get_account(&lookup_table_key)
                .map(|lookup_table_account| {
                    add_to_set(&result, &[lookup_table_key]);
                    AddressLookupTable::deserialize(lookup_table_account.data()).map(|t| {
                        add_to_set(&result, &t.addresses[..]);
                    })
                });
        });

        (result, possible_cpi_alt_extend.into_inner())
    }

    fn get_completed_ranges(
        &self,
        slot: Slot,
        start_index: u64,
    ) -> Result<(CompletedRanges, Option<SlotMeta>)> {
        let slot_meta = self.meta_cf.get(slot)?;
        if slot_meta.is_none() {
            return Ok((vec![], slot_meta));
        }

        let slot_meta = slot_meta.unwrap();
        // Find all the ranges for the completed data blocks
        let completed_ranges = Self::get_completed_data_ranges(
            start_index as u32,
            &slot_meta.completed_data_indexes,
            slot_meta.consumed as u32,
        );

        Ok((completed_ranges, Some(slot_meta)))
    }

    // Get the range of indexes [start_index, end_index] of every completed data block
    fn get_completed_data_ranges(
        start_index: u32,
        completed_data_indexes: &BTreeSet<u32>,
        consumed: u32,
    ) -> CompletedRanges {
        // `consumed` is the next missing shred index, but shred `i` existing in
        // completed_data_end_indexes implies it's not missing
        assert!(!completed_data_indexes.contains(&consumed));
        completed_data_indexes
            .range(start_index..consumed)
            .scan(start_index, |begin, index| {
                let out = (*begin, *index);
                *begin = index + 1;
                Some(out)
            })
            .collect()
    }

    /// Fetch the entries corresponding to all of the shred indices in `completed_ranges`
    /// This function takes advantage of the fact that `completed_ranges` are both
    /// contiguous and in sorted order. To clarify, suppose completed_ranges is as follows:
    ///   completed_ranges = [..., (s_i, e_i), (s_i+1, e_i+1), ...]
    /// Then, the following statements are true:
    ///   s_i < e_i < s_i+1 < e_i+1
    ///   e_i == s_i+1 + 1
    fn get_slot_entries_in_block(
        &self,
        slot: Slot,
        completed_ranges: CompletedRanges,
        slot_meta: Option<&SlotMeta>,
    ) -> Result<Vec<Entry>> {
        let Some((all_ranges_start_index, _)) = completed_ranges.first().copied() else {
            return Ok(vec![]);
        };
        let Some((_, all_ranges_end_index)) = completed_ranges.last().copied() else {
            return Ok(vec![]);
        };
        let keys =
            (all_ranges_start_index..=all_ranges_end_index).map(|index| (slot, u64::from(index)));

        let data_shreds: Result<Vec<Option<Vec<u8>>>> = self
            .data_shred_cf
            .multi_get_bytes(keys)
            .into_iter()
            .collect();
        let data_shreds = data_shreds?;
        let data_shreds: Result<Vec<Shred>> = data_shreds
            .into_iter()
            .enumerate()
            .map(|(idx, shred_bytes)| {
                if shred_bytes.is_none() {
                    if let Some(slot_meta) = slot_meta {
                        if slot > self.lowest_cleanup_slot() {
                            panic!(
                                "Shred with slot: {}, index: {}, consumed: {}, completed_indexes: \
                                 {:?} must exist if shred index was included in a range: {} {}",
                                slot,
                                idx,
                                slot_meta.consumed,
                                slot_meta.completed_data_indexes,
                                all_ranges_start_index,
                                all_ranges_end_index
                            );
                        }
                    }
                    return Err(BlockstoreError::InvalidShredData(Box::new(
                        bincode::ErrorKind::Custom(format!(
                            "Missing shred for slot {slot}, index {idx}"
                        )),
                    )));
                }
                Shred::new_from_serialized_shred(shred_bytes.unwrap()).map_err(|err| {
                    BlockstoreError::InvalidShredData(Box::new(bincode::ErrorKind::Custom(
                        format!("Could not reconstruct shred from shred payload: {err:?}"),
                    )))
                })
            })
            .collect();
        let data_shreds = data_shreds?;

        completed_ranges
            .into_iter()
            .map(|(start_index, end_index)| {
                // The indices from completed_ranges refer to shred indices in the
                // entire block; map those indices to indices within data_shreds
                let range_start_index = (start_index - all_ranges_start_index) as usize;
                let range_end_index = (end_index - all_ranges_start_index) as usize;
                let range_shreds = &data_shreds[range_start_index..=range_end_index];

                let last_shred = range_shreds.last().unwrap();
                assert!(last_shred.data_complete() || last_shred.last_in_slot());
                trace!("{:?} data shreds in last FEC set", data_shreds.len());

                Shredder::deshred(range_shreds)
                    .map_err(|e| {
                        BlockstoreError::InvalidShredData(Box::new(bincode::ErrorKind::Custom(
                            format!("could not reconstruct entries buffer from shreds: {e:?}"),
                        )))
                    })
                    .and_then(|payload| {
                        bincode::deserialize::<Vec<Entry>>(&payload).map_err(|e| {
                            BlockstoreError::InvalidShredData(Box::new(bincode::ErrorKind::Custom(
                                format!("could not reconstruct entries: {e:?}"),
                            )))
                        })
                    })
            })
            .flatten_ok()
            .collect()
    }

    pub fn get_entries_in_data_block(
        &self,
        slot: Slot,
        start_index: u32,
        end_index: u32,
        slot_meta: Option<&SlotMeta>,
    ) -> Result<Vec<Entry>> {
        self.get_slot_entries_in_block(slot, vec![(start_index, end_index)], slot_meta)
    }

    /// Returns true if the last `DATA_SHREDS_PER_FEC_BLOCK` data shreds of a
    /// slot have the same merkle root, indicating they are a part of the same
    /// FEC set.
    /// Will fail if:
    ///     - Slot meta is missing
    ///     - LAST_SHRED_IN_SLOT flag has not been received
    ///     - There are missing shreds in the last fec set
    ///     - The block contains legacy shreds
    pub fn is_last_fec_set_full(&self, slot: Slot) -> Result<bool> {
        // We need to check if the last FEC set index contains at least `DATA_SHREDS_PER_FEC_BLOCK` data shreds.
        // We compare the merkle roots of the last `DATA_SHREDS_PER_FEC_BLOCK` shreds in this block.
        // Since the merkle root contains the fec_set_index, if all of them match, we know that the last fec set has
        // at least `DATA_SHREDS_PER_FEC_BLOCK` shreds.
        let slot_meta = self.meta(slot)?.ok_or(BlockstoreError::SlotUnavailable)?;
        let last_shred_index = slot_meta
            .last_index
            .ok_or(BlockstoreError::UnknownLastIndex(slot))?;

        const MINIMUM_INDEX: u64 = DATA_SHREDS_PER_FEC_BLOCK as u64 - 1;
        let Some(start_index) = last_shred_index.checked_sub(MINIMUM_INDEX) else {
            warn!("Slot {slot} has only {} shreds, fewer than the {DATA_SHREDS_PER_FEC_BLOCK} required", last_shred_index + 1);
            return Ok(false);
        };
        let keys = (start_index..=last_shred_index).map(|index| (slot, index));

        let last_merkle_roots: Vec<Hash> = self
            .data_shred_cf
            .multi_get_bytes(keys)
            .into_iter()
            .enumerate()
            .map(|(offset, shred_bytes)| {
                let shred_bytes = shred_bytes.ok().flatten().ok_or_else(|| {
                    let shred_index = start_index + u64::try_from(offset).unwrap();
                    warn!("Missing shred for {slot} index {shred_index}");
                    BlockstoreError::MissingShred(slot, shred_index)
                })?;
                shred::layout::get_merkle_root(&shred_bytes).ok_or_else(|| {
                    let shred_index = start_index + u64::try_from(offset).unwrap();
                    warn!("Found legacy shred for {slot}, index {shred_index}");
                    BlockstoreError::LegacyShred(slot, shred_index)
                })
            })
            .dedup_by(|res1, res2| res1.as_ref().ok() == res2.as_ref().ok())
            .collect::<Result<Vec<Hash>>>()?;

        // After the dedup there should be exactly one Hash left if the shreds were part of the same FEC set.
        Ok(last_merkle_roots.len() == 1)
    }

    /// Returns a mapping from each elements of `slots` to a list of the
    /// element's children slots.
    pub fn get_slots_since(&self, slots: &[Slot]) -> Result<HashMap<Slot, Vec<Slot>>> {
        let slot_metas: Result<Vec<Option<SlotMeta>>> = self
            .meta_cf
            .multi_get(slots.iter().copied())
            .into_iter()
            .collect();
        let slot_metas = slot_metas?;

        let result: HashMap<Slot, Vec<Slot>> = slots
            .iter()
            .zip(slot_metas)
            .filter_map(|(slot, meta)| meta.map(|meta| (*slot, meta.next_slots.to_vec())))
            .collect();

        Ok(result)
    }

    pub fn is_root(&self, slot: Slot) -> bool {
        matches!(self.db.get::<cf::Root>(slot), Ok(Some(true)))
    }

    /// Returns true if a slot is between the rooted slot bounds of the ledger, but has not itself
    /// been rooted. This is either because the slot was skipped, or due to a gap in ledger data,
    /// as when booting from a newer snapshot.
    pub fn is_skipped(&self, slot: Slot) -> bool {
        let lowest_root = self
            .rooted_slot_iterator(0)
            .ok()
            .and_then(|mut iter| iter.next())
            .unwrap_or_default();
        match self.db.get::<cf::Root>(slot).ok().flatten() {
            Some(_) => false,
            None => slot < self.max_root() && slot > lowest_root,
        }
    }

    pub fn insert_bank_hash(&self, slot: Slot, frozen_hash: Hash, is_duplicate_confirmed: bool) {
        if let Some(prev_value) = self.bank_hash_cf.get(slot).unwrap() {
            if prev_value.frozen_hash() == frozen_hash && prev_value.is_duplicate_confirmed() {
                // Don't overwrite is_duplicate_confirmed == true with is_duplicate_confirmed == false,
                // which may happen on startup when procesing from blockstore processor because the
                // blocks may not reflect earlier observed gossip votes from before the restart.
                return;
            }
        }
        let data = FrozenHashVersioned::Current(FrozenHashStatus {
            frozen_hash,
            is_duplicate_confirmed,
        });
        self.bank_hash_cf.put(slot, &data).unwrap()
    }

    pub fn get_bank_hash(&self, slot: Slot) -> Option<Hash> {
        self.bank_hash_cf
            .get(slot)
            .unwrap()
            .map(|versioned| versioned.frozen_hash())
    }

    pub fn is_duplicate_confirmed(&self, slot: Slot) -> bool {
        self.bank_hash_cf
            .get(slot)
            .unwrap()
            .map(|versioned| versioned.is_duplicate_confirmed())
            .unwrap_or(false)
    }

    pub fn insert_optimistic_slot(
        &self,
        slot: Slot,
        hash: &Hash,
        timestamp: UnixTimestamp,
    ) -> Result<()> {
        let slot_data = OptimisticSlotMetaVersioned::new(*hash, timestamp);
        self.optimistic_slots_cf.put(slot, &slot_data)
    }

    /// Returns information about a single optimistically confirmed slot
    pub fn get_optimistic_slot(&self, slot: Slot) -> Result<Option<(Hash, UnixTimestamp)>> {
        Ok(self
            .optimistic_slots_cf
            .get(slot)?
            .map(|meta| (meta.hash(), meta.timestamp())))
    }

    /// Returns information about the `num` latest optimistically confirmed slot
    pub fn get_latest_optimistic_slots(
        &self,
        num: usize,
    ) -> Result<Vec<(Slot, Hash, UnixTimestamp)>> {
        let iter = self.reversed_optimistic_slots_iterator()?;
        Ok(iter.take(num).collect())
    }

    pub fn set_duplicate_confirmed_slots_and_hashes(
        &self,
        duplicate_confirmed_slot_hashes: impl Iterator<Item = (Slot, Hash)>,
    ) -> Result<()> {
        let mut write_batch = self.db.batch()?;
        for (slot, frozen_hash) in duplicate_confirmed_slot_hashes {
            let data = FrozenHashVersioned::Current(FrozenHashStatus {
                frozen_hash,
                is_duplicate_confirmed: true,
            });
            write_batch.put::<cf::BankHash>(slot, &data)?;
        }

        self.db.write(write_batch)?;
        Ok(())
    }

    pub fn set_roots<'a>(&self, rooted_slots: impl Iterator<Item = &'a Slot>) -> Result<()> {
        let mut write_batch = self.db.batch()?;
        let mut max_new_rooted_slot = 0;
        for slot in rooted_slots {
            max_new_rooted_slot = std::cmp::max(max_new_rooted_slot, *slot);
            write_batch.put::<cf::Root>(*slot, &true)?;
        }

        self.db.write(write_batch)?;
        self.max_root
            .fetch_max(max_new_rooted_slot, Ordering::Relaxed);
        Ok(())
    }

    pub fn mark_slots_as_if_rooted_normally_at_startup(
        &self,
        slots: Vec<(Slot, Option<Hash>)>,
        with_hash: bool,
    ) -> Result<()> {
        self.set_roots(slots.iter().map(|(slot, _hash)| slot))?;
        if with_hash {
            self.set_duplicate_confirmed_slots_and_hashes(
                slots
                    .into_iter()
                    .map(|(slot, maybe_hash)| (slot, maybe_hash.unwrap())),
            )?;
        }
        Ok(())
    }

    pub fn is_dead(&self, slot: Slot) -> bool {
        matches!(
            self.db
                .get::<cf::DeadSlots>(slot)
                .expect("fetch from DeadSlots column family failed"),
            Some(true)
        )
    }

    pub fn set_dead_slot(&self, slot: Slot) -> Result<()> {
        self.dead_slots_cf.put(slot, &true)
    }

    pub fn remove_dead_slot(&self, slot: Slot) -> Result<()> {
        self.dead_slots_cf.delete(slot)
    }

    pub fn remove_slot_duplicate_proof(&self, slot: Slot) -> Result<()> {
        self.duplicate_slots_cf.delete(slot)
    }

    pub fn get_first_duplicate_proof(&self) -> Option<(Slot, DuplicateSlotProof)> {
        let mut iter = self
            .db
            .iter::<cf::DuplicateSlots>(IteratorMode::From(0, IteratorDirection::Forward))
            .unwrap();
        iter.next()
            .map(|(slot, proof_bytes)| (slot, deserialize(&proof_bytes).unwrap()))
    }

    pub fn store_duplicate_slot(&self, slot: Slot, shred1: Vec<u8>, shred2: Vec<u8>) -> Result<()> {
        let duplicate_slot_proof = DuplicateSlotProof::new(shred1, shred2);
        self.duplicate_slots_cf.put(slot, &duplicate_slot_proof)
    }

    pub fn get_duplicate_slot(&self, slot: u64) -> Option<DuplicateSlotProof> {
        self.duplicate_slots_cf
            .get(slot)
            .expect("fetch from DuplicateSlots column family failed")
    }

    /// Returns the shred already stored in blockstore if it has a different
    /// payload than the given `shred` but the same (slot, index, shred-type).
    /// This implies the leader generated two different shreds with the same
    /// slot, index and shred-type.
    /// The payload is modified so that it has the same retransmitter's
    /// signature as the `shred` argument.
    pub fn is_shred_duplicate(&self, shred: &Shred) -> Option<Vec<u8>> {
        let (slot, index, shred_type) = shred.id().unpack();
        let mut other = match shred_type {
            ShredType::Data => self.get_data_shred(slot, u64::from(index)),
            ShredType::Code => self.get_coding_shred(slot, u64::from(index)),
        }
        .expect("fetch from DuplicateSlots column family failed")?;
        if let Ok(signature) = shred.retransmitter_signature() {
            if let Err(err) = shred::layout::set_retransmitter_signature(&mut other, &signature) {
                error!("set retransmitter signature failed: {err:?}");
            }
        }
        (&other != shred.payload()).then_some(other)
    }

    pub fn has_duplicate_shreds_in_slot(&self, slot: Slot) -> bool {
        self.duplicate_slots_cf
            .get(slot)
            .expect("fetch from DuplicateSlots column family failed")
            .is_some()
    }

    pub fn orphans_iterator(&self, slot: Slot) -> Result<impl Iterator<Item = u64> + '_> {
        let orphans_iter = self
            .db
            .iter::<cf::Orphans>(IteratorMode::From(slot, IteratorDirection::Forward))?;
        Ok(orphans_iter.map(|(slot, _)| slot))
    }

    pub fn dead_slots_iterator(&self, slot: Slot) -> Result<impl Iterator<Item = Slot> + '_> {
        let dead_slots_iterator = self
            .db
            .iter::<cf::DeadSlots>(IteratorMode::From(slot, IteratorDirection::Forward))?;
        Ok(dead_slots_iterator.map(|(slot, _)| slot))
    }

    pub fn duplicate_slots_iterator(&self, slot: Slot) -> Result<impl Iterator<Item = Slot> + '_> {
        let duplicate_slots_iterator = self
            .db
            .iter::<cf::DuplicateSlots>(IteratorMode::From(slot, IteratorDirection::Forward))?;
        Ok(duplicate_slots_iterator.map(|(slot, _)| slot))
    }

    /// Returns the max root or 0 if it does not exist
    pub fn max_root(&self) -> Slot {
        self.max_root.load(Ordering::Relaxed)
    }

    #[deprecated(
        since = "1.18.0",
        note = "Please use `solana_ledger::blockstore::Blockstore::max_root()` instead"
    )]
    pub fn last_root(&self) -> Slot {
        self.max_root()
    }

    // find the first available slot in blockstore that has some data in it
    pub fn lowest_slot(&self) -> Slot {
        for (slot, meta) in self
            .slot_meta_iterator(0)
            .expect("unable to iterate over meta")
        {
            if slot > 0 && meta.received > 0 {
                return slot;
            }
        }
        // This means blockstore is empty, should never get here aside from right at boot.
        self.max_root()
    }

    fn lowest_slot_with_genesis(&self) -> Slot {
        for (slot, meta) in self
            .slot_meta_iterator(0)
            .expect("unable to iterate over meta")
        {
            if meta.received > 0 {
                return slot;
            }
        }
        // This means blockstore is empty, should never get here aside from right at boot.
        self.max_root()
    }

    /// Returns the highest available slot in the blockstore
    pub fn highest_slot(&self) -> Result<Option<Slot>> {
        let highest_slot = self
            .db
            .iter::<cf::SlotMeta>(IteratorMode::End)?
            .next()
            .map(|(slot, _)| slot);
        Ok(highest_slot)
    }

    pub fn lowest_cleanup_slot(&self) -> Slot {
        *self.lowest_cleanup_slot.read().unwrap()
    }

    pub fn storage_size(&self) -> Result<u64> {
        self.db.storage_size()
    }

    /// Returns the total physical storage size contributed by all data shreds.
    ///
    /// Note that the reported size does not include those recently inserted
    /// shreds that are still in memory.
    pub fn total_data_shred_storage_size(&self) -> Result<i64> {
        self.data_shred_cf
            .get_int_property(RocksProperties::TOTAL_SST_FILES_SIZE)
    }

    /// Returns the total physical storage size contributed by all coding shreds.
    ///
    /// Note that the reported size does not include those recently inserted
    /// shreds that are still in memory.
    pub fn total_coding_shred_storage_size(&self) -> Result<i64> {
        self.code_shred_cf
            .get_int_property(RocksProperties::TOTAL_SST_FILES_SIZE)
    }

    /// Returns whether the blockstore has primary (read and write) access
    pub fn is_primary_access(&self) -> bool {
        self.db.is_primary_access()
    }

    /// Scan for any ancestors of the supplied `start_root` that are not
    /// marked as roots themselves. Mark any found slots as roots since
    /// the ancestor of a root is also inherently a root. Returns the
    /// number of slots that were actually updated.
    ///
    /// Arguments:
    ///  - `start_root`: The root to start scan from, or the highest root in
    ///    the blockstore if this value is `None`. This slot must be a root.
    ///  - `end_slot``: The slot to stop the scan at; the scan will continue to
    ///    the earliest slot in the Blockstore if this value is `None`.
    ///  - `exit`: Exit early if this flag is set to `true`.
    pub fn scan_and_fix_roots(
        &self,
        start_root: Option<Slot>,
        end_slot: Option<Slot>,
        exit: &AtomicBool,
    ) -> Result<usize> {
        // Hold the lowest_cleanup_slot read lock to prevent any cleaning of
        // the blockstore from another thread. Doing so will prevent a
        // possible inconsistency across column families where a slot is:
        //  - Identified as needing root repair by this thread
        //  - Cleaned from the blockstore by another thread (LedgerCleanupSerivce)
        //  - Marked as root via Self::set_root() by this this thread
        let lowest_cleanup_slot = self.lowest_cleanup_slot.read().unwrap();

        let start_root = if let Some(slot) = start_root {
            if !self.is_root(slot) {
                return Err(BlockstoreError::SlotNotRooted);
            }
            slot
        } else {
            self.max_root()
        };
        let end_slot = end_slot.unwrap_or(*lowest_cleanup_slot);
        let ancestor_iterator =
            AncestorIterator::new(start_root, self).take_while(|&slot| slot >= end_slot);

        let mut find_missing_roots = Measure::start("find_missing_roots");
        let mut roots_to_fix = vec![];
        for slot in ancestor_iterator.filter(|slot| !self.is_root(*slot)) {
            if exit.load(Ordering::Relaxed) {
                return Ok(0);
            }
            roots_to_fix.push(slot);
        }
        find_missing_roots.stop();
        let mut fix_roots = Measure::start("fix_roots");
        if !roots_to_fix.is_empty() {
            info!("{} slots to be rooted", roots_to_fix.len());
            let chunk_size = 100;
            for (i, chunk) in roots_to_fix.chunks(chunk_size).enumerate() {
                if exit.load(Ordering::Relaxed) {
                    return Ok(i * chunk_size);
                }
                trace!("{:?}", chunk);
                self.set_roots(chunk.iter())?;
            }
        } else {
            debug!("No missing roots found in range {start_root} to {end_slot}");
        }
        fix_roots.stop();
        datapoint_info!(
            "blockstore-scan_and_fix_roots",
            (
                "find_missing_roots_us",
                find_missing_roots.as_us() as i64,
                i64
            ),
            ("num_roots_to_fix", roots_to_fix.len() as i64, i64),
            ("fix_roots_us", fix_roots.as_us() as i64, i64),
        );
        Ok(roots_to_fix.len())
    }

    /// Mark a root `slot` as connected, traverse `slot`'s children and update
    /// the children's connected status if appropriate.
    ///
    /// A ledger with a full path of blocks from genesis to the latest root will
    /// have all of the rooted blocks marked as connected such that new blocks
    /// could also be connected. However, starting from some root (such as from
    /// a snapshot) is a valid way to join a cluster. For this case, mark this
    /// root as connected such that the node that joined midway through can
    /// have their slots considered connected.
    pub fn set_and_chain_connected_on_root_and_next_slots(&self, root: Slot) -> Result<()> {
        let mut root_meta = self
            .meta(root)?
            .unwrap_or_else(|| SlotMeta::new(root, None));
        // If the slot was already connected, there is nothing to do as this slot's
        // children are also assumed to be appropriately connected
        if root_meta.is_connected() {
            return Ok(());
        }
        info!(
            "Marking slot {} and any full children slots as connected",
            root
        );
        let mut write_batch = self.db.batch()?;

        // Mark both connected bits on the root slot so that the flags for this
        // slot match the flags of slots that become connected the typical way.
        root_meta.set_parent_connected();
        root_meta.set_connected();
        write_batch.put::<cf::SlotMeta>(root_meta.slot, &root_meta)?;

        let mut next_slots = VecDeque::from(root_meta.next_slots);
        while !next_slots.is_empty() {
            let slot = next_slots.pop_front().unwrap();
            let mut meta = self.meta(slot)?.unwrap_or_else(|| {
                panic!("Slot {slot} is a child but has no SlotMeta in blockstore")
            });

            if meta.set_parent_connected() {
                next_slots.extend(meta.next_slots.iter());
            }
            write_batch.put::<cf::SlotMeta>(meta.slot, &meta)?;
        }

        self.db.write(write_batch)?;
        Ok(())
    }

    /// For each entry in `working_set` whose `did_insert_occur` is true, this
    /// function handles its chaining effect by updating the SlotMeta of both
    /// the slot and its parent slot to reflect the slot descends from the
    /// parent slot.  In addition, when a slot is newly connected, it also
    /// checks whether any of its direct and indirect children slots are connected
    /// or not.
    ///
    /// This function may update column families [`cf::SlotMeta`] and
    /// [`cf::Orphans`].
    ///
    /// For more information about the chaining, check the previous discussion here:
    /// https://github.com/solana-labs/solana/pull/2253
    ///
    /// Arguments:
    /// - `db`: the blockstore db that stores both shreds and their metadata.
    /// - `write_batch`: the write batch which includes all the updates of the
    ///   the current write and ensures their atomicity.
    /// - `working_set`: a slot-id to SlotMetaWorkingSetEntry map.  This function
    ///   will remove all entries which insertion did not actually occur.
    fn handle_chaining(
        &self,
        write_batch: &mut WriteBatch,
        working_set: &mut HashMap<u64, SlotMetaWorkingSetEntry>,
    ) -> Result<()> {
        // Handle chaining for all the SlotMetas that were inserted into
        working_set.retain(|_, entry| entry.did_insert_occur);
        let mut new_chained_slots = HashMap::new();
        let working_set_slots: Vec<_> = working_set.keys().collect();
        for slot in working_set_slots {
            self.handle_chaining_for_slot(write_batch, working_set, &mut new_chained_slots, *slot)?;
        }

        // Write all the newly changed slots in new_chained_slots to the write_batch
        for (slot, meta) in new_chained_slots.iter() {
            let meta: &SlotMeta = &RefCell::borrow(meta);
            write_batch.put::<cf::SlotMeta>(*slot, meta)?;
        }
        Ok(())
    }

    /// A helper function of handle_chaining which handles the chaining based
    /// on the `SlotMetaWorkingSetEntry` of the specified `slot`.  Specifically,
    /// it handles the following two things:
    ///
    /// 1. based on the `SlotMetaWorkingSetEntry` for `slot`, check if `slot`
    /// did not previously have a parent slot but does now.  If `slot` satisfies
    /// this condition, update the Orphan property of both `slot` and its parent
    /// slot based on their current orphan status.  Specifically:
    ///  - updates the orphan property of slot to no longer be an orphan because
    ///    it has a parent.
    ///  - adds the parent to the orphan column family if the parent's parent is
    ///    currently unknown.
    ///
    /// 2. if the `SlotMetaWorkingSetEntry` for `slot` indicates this slot
    /// is newly connected to a parent slot, then this function will update
    /// the is_connected property of all its direct and indirect children slots.
    ///
    /// This function may update column family [`cf::Orphans`] and indirectly
    /// update SlotMeta from its output parameter `new_chained_slots`.
    ///
    /// Arguments:
    /// `db`: the underlying db for blockstore
    /// `write_batch`: the write batch which includes all the updates of the
    ///   the current write and ensures their atomicity.
    /// `working_set`: the working set which include the specified `slot`
    /// `new_chained_slots`: an output parameter which includes all the slots
    ///   which connectivity have been updated.
    /// `slot`: the slot which we want to handle its chaining effect.
    fn handle_chaining_for_slot(
        &self,
        write_batch: &mut WriteBatch,
        working_set: &HashMap<u64, SlotMetaWorkingSetEntry>,
        new_chained_slots: &mut HashMap<u64, Rc<RefCell<SlotMeta>>>,
        slot: Slot,
    ) -> Result<()> {
        let slot_meta_entry = working_set
            .get(&slot)
            .expect("Slot must exist in the working_set hashmap");

        let meta = &slot_meta_entry.new_slot_meta;
        let meta_backup = &slot_meta_entry.old_slot_meta;
        {
            let mut meta_mut = meta.borrow_mut();
            let was_orphan_slot =
                meta_backup.is_some() && meta_backup.as_ref().unwrap().is_orphan();

            // If:
            // 1) This is a new slot
            // 2) slot != 0
            // then try to chain this slot to a previous slot
            if slot != 0 && meta_mut.parent_slot.is_some() {
                let prev_slot = meta_mut.parent_slot.unwrap();

                // Check if the slot represented by meta_mut is either a new slot or a orphan.
                // In both cases we need to run the chaining logic b/c the parent on the slot was
                // previously unknown.
                if meta_backup.is_none() || was_orphan_slot {
                    let prev_slot_meta =
                        self.find_slot_meta_else_create(working_set, new_chained_slots, prev_slot)?;

                    // This is a newly inserted slot/orphan so run the chaining logic to link it to a
                    // newly discovered parent
                    chain_new_slot_to_prev_slot(
                        &mut prev_slot_meta.borrow_mut(),
                        slot,
                        &mut meta_mut,
                    );

                    // If the parent of `slot` is a newly inserted orphan, insert it into the orphans
                    // column family
                    if RefCell::borrow(&*prev_slot_meta).is_orphan() {
                        write_batch.put::<cf::Orphans>(prev_slot, &true)?;
                    }
                }
            }

            // At this point this slot has received a parent, so it's no longer an orphan
            if was_orphan_slot {
                write_batch.delete::<cf::Orphans>(slot)?;
            }
        }

        // If this is a newly completed slot and the parent is connected, then the
        // slot is now connected. Mark the slot as connected, and then traverse the
        // children to update their parent_connected and connected status.
        let should_propagate_is_connected =
            is_newly_completed_slot(&RefCell::borrow(meta), meta_backup)
                && RefCell::borrow(meta).is_parent_connected();

        if should_propagate_is_connected {
            meta.borrow_mut().set_connected();
            self.traverse_children_mut(
                meta,
                working_set,
                new_chained_slots,
                SlotMeta::set_parent_connected,
            )?;
        }

        Ok(())
    }

    /// Traverse all the children (direct and indirect) of `slot_meta`, and apply
    /// `slot_function` to each of the children (but not `slot_meta`).
    ///
    /// Arguments:
    /// `db`: the blockstore db that stores shreds and their metadata.
    /// `slot_meta`: the SlotMeta of the above `slot`.
    /// `working_set`: a slot-id to SlotMetaWorkingSetEntry map which is used
    ///   to traverse the graph.
    /// `passed_visited_slots`: all the traversed slots which have passed the
    ///   slot_function.  This may also include the input `slot`.
    /// `slot_function`: a function which updates the SlotMeta of the visisted
    ///   slots and determine whether to further traverse the children slots of
    ///   a given slot.
    fn traverse_children_mut<F>(
        &self,
        slot_meta: &Rc<RefCell<SlotMeta>>,
        working_set: &HashMap<u64, SlotMetaWorkingSetEntry>,
        passed_visisted_slots: &mut HashMap<u64, Rc<RefCell<SlotMeta>>>,
        slot_function: F,
    ) -> Result<()>
    where
        F: Fn(&mut SlotMeta) -> bool,
    {
        let slot_meta = slot_meta.borrow();
        let mut next_slots: VecDeque<u64> = slot_meta.next_slots.to_vec().into();
        while !next_slots.is_empty() {
            let slot = next_slots.pop_front().unwrap();
            let meta_ref =
                self.find_slot_meta_else_create(working_set, passed_visisted_slots, slot)?;
            let mut meta = meta_ref.borrow_mut();
            if slot_function(&mut meta) {
                meta.next_slots
                    .iter()
                    .for_each(|slot| next_slots.push_back(*slot));
            }
        }
        Ok(())
    }

    /// Obtain the SlotMeta from the in-memory slot_meta_working_set or load
    /// it from the database if it does not exist in slot_meta_working_set.
    ///
    /// In case none of the above has the specified SlotMeta, a new one will
    /// be created.
    ///
    /// Note that this function will also update the parent slot of the specified
    /// slot.
    ///
    /// Arguments:
    /// - `db`: the database
    /// - `slot_meta_working_set`: a in-memory structure for storing the cached
    ///   SlotMeta.
    /// - `slot`: the slot for loading its meta.
    /// - `parent_slot`: the parent slot to be assigned to the specified slot meta
    ///
    /// This function returns the matched `SlotMetaWorkingSetEntry`.  If such entry
    /// does not exist in the database, a new entry will be created.
    fn get_slot_meta_entry<'a>(
        &self,
        slot_meta_working_set: &'a mut HashMap<u64, SlotMetaWorkingSetEntry>,
        slot: Slot,
        parent_slot: Slot,
    ) -> &'a mut SlotMetaWorkingSetEntry {
        // Check if we've already inserted the slot metadata for this shred's slot
        slot_meta_working_set.entry(slot).or_insert_with(|| {
            // Store a 2-tuple of the metadata (working copy, backup copy)
            if let Some(mut meta) = self
                .meta_cf
                .get(slot)
                .expect("Expect database get to succeed")
            {
                let backup = Some(meta.clone());
                // If parent_slot == None, then this is one of the orphans inserted
                // during the chaining process, see the function find_slot_meta_in_cached_state()
                // for details. Slots that are orphans are missing a parent_slot, so we should
                // fill in the parent now that we know it.
                if meta.is_orphan() {
                    meta.parent_slot = Some(parent_slot);
                }

                SlotMetaWorkingSetEntry::new(Rc::new(RefCell::new(meta)), backup)
            } else {
                SlotMetaWorkingSetEntry::new(
                    Rc::new(RefCell::new(SlotMeta::new(slot, Some(parent_slot)))),
                    None,
                )
            }
        })
    }

    /// Returns the `SlotMeta` with the specified `slot_index`.  The resulting
    /// `SlotMeta` could be either from the cache or from the DB.  Specifically,
    /// the function:
    ///
    /// 1) Finds the slot metadata in the cache of dirty slot metadata we've
    ///    previously touched, otherwise:
    /// 2) Searches the database for that slot metadata. If still no luck, then:
    /// 3) Create a dummy orphan slot in the database.
    ///
    /// Also see [`find_slot_meta_in_cached_state`] and [`find_slot_meta_in_db_else_create`].
    fn find_slot_meta_else_create<'a>(
        &self,
        working_set: &'a HashMap<u64, SlotMetaWorkingSetEntry>,
        chained_slots: &'a mut HashMap<u64, Rc<RefCell<SlotMeta>>>,
        slot_index: u64,
    ) -> Result<Rc<RefCell<SlotMeta>>> {
        let result = find_slot_meta_in_cached_state(working_set, chained_slots, slot_index);
        if let Some(slot) = result {
            Ok(slot)
        } else {
            self.find_slot_meta_in_db_else_create(slot_index, chained_slots)
        }
    }

    /// A helper function to [`find_slot_meta_else_create`] that searches the
    /// `SlotMeta` based on the specified `slot` in `db` and updates `insert_map`.
    ///
    /// If the specified `db` does not contain a matched entry, then it will create
    /// a dummy orphan slot in the database.
    fn find_slot_meta_in_db_else_create(
        &self,
        slot: Slot,
        insert_map: &mut HashMap<u64, Rc<RefCell<SlotMeta>>>,
    ) -> Result<Rc<RefCell<SlotMeta>>> {
        if let Some(slot_meta) = self.meta_cf.get(slot)? {
            insert_map.insert(slot, Rc::new(RefCell::new(slot_meta)));
        } else {
            // If this slot doesn't exist, make a orphan slot. This way we
            // remember which slots chained to this one when we eventually get a real shred
            // for this slot
            insert_map.insert(slot, Rc::new(RefCell::new(SlotMeta::new_orphan(slot))));
        }
        Ok(insert_map.get(&slot).unwrap().clone())
    }

    fn get_index_meta_entry<'a>(
        &self,
        slot: Slot,
        index_working_set: &'a mut HashMap<u64, IndexMetaWorkingSetEntry>,
        index_meta_time_us: &mut u64,
    ) -> &'a mut IndexMetaWorkingSetEntry {
        let mut total_start = Measure::start("Total elapsed");
        let res = index_working_set.entry(slot).or_insert_with(|| {
            let newly_inserted_meta = self
                .index_cf
                .get(slot)
                .unwrap()
                .unwrap_or_else(|| Index::new(slot));
            IndexMetaWorkingSetEntry {
                index: newly_inserted_meta,
                did_insert_occur: false,
            }
        });
        total_start.stop();
        *index_meta_time_us += total_start.as_us();
        res
    }
}

// Update the `completed_data_indexes` with a new shred `new_shred_index`. If a
// data set is complete, return the range of shred indexes [start_index, end_index]
// for that completed data set.
fn update_completed_data_indexes(
    is_last_in_data: bool,
    new_shred_index: u32,
    received_data_shreds: &ShredIndex,
    // Shreds indices which are marked data complete.
    completed_data_indexes: &mut BTreeSet<u32>,
) -> Vec<(u32, u32)> {
    let start_shred_index = completed_data_indexes
        .range(..new_shred_index)
        .next_back()
        .map(|index| index + 1)
        .unwrap_or_default();
    // Consecutive entries i, k, j in this vector represent potential ranges [i, k),
    // [k, j) that could be completed data ranges
    let mut shred_indices = vec![start_shred_index];
    // `new_shred_index` is data complete, so need to insert here into the
    // `completed_data_indexes`
    if is_last_in_data {
        completed_data_indexes.insert(new_shred_index);
        shred_indices.push(new_shred_index + 1);
    }
    if let Some(index) = completed_data_indexes.range(new_shred_index + 1..).next() {
        shred_indices.push(index + 1);
    }
    shred_indices
        .windows(2)
        .filter(|ix| {
            let (begin, end) = (ix[0] as u64, ix[1] as u64);
            let num_shreds = (end - begin) as usize;
            received_data_shreds.range(begin..end).count() == num_shreds
        })
        .map(|ix| (ix[0], ix[1] - 1))
        .collect()
}

fn update_slot_meta(
    is_last_in_slot: bool,
    is_last_in_data: bool,
    slot_meta: &mut SlotMeta,
    index: u32,
    new_consumed: u64,
    reference_tick: u8,
    received_data_shreds: &ShredIndex,
) -> Vec<(u32, u32)> {
    let first_insert = slot_meta.received == 0;
    // Index is zero-indexed, while the "received" height starts from 1,
    // so received = index + 1 for the same shred.
    slot_meta.received = cmp::max(u64::from(index) + 1, slot_meta.received);
    if first_insert {
        // predict the timestamp of what would have been the first shred in this slot
        let slot_time_elapsed = u64::from(reference_tick) * 1000 / DEFAULT_TICKS_PER_SECOND;
        slot_meta.first_shred_timestamp = timestamp() - slot_time_elapsed;
    }
    slot_meta.consumed = new_consumed;
    // If the last index in the slot hasn't been set before, then
    // set it to this shred index
    if is_last_in_slot && slot_meta.last_index.is_none() {
        slot_meta.last_index = Some(u64::from(index));
    }
    update_completed_data_indexes(
        is_last_in_slot || is_last_in_data,
        index,
        received_data_shreds,
        &mut slot_meta.completed_data_indexes,
    )
}

fn get_last_hash<'a>(iterator: impl Iterator<Item = &'a Entry> + 'a) -> Option<Hash> {
    iterator.last().map(|entry| entry.hash)
}

fn send_signals(
    new_shreds_signals: &[Sender<bool>],
    completed_slots_senders: &[Sender<Vec<u64>>],
    should_signal: bool,
    newly_completed_slots: Vec<u64>,
) {
    if should_signal {
        for signal in new_shreds_signals {
            match signal.try_send(true) {
                Ok(_) => {}
                Err(TrySendError::Full(_)) => {
                    trace!("replay wake up signal channel is full.")
                }
                Err(TrySendError::Disconnected(_)) => {
                    trace!("replay wake up signal channel is disconnected.")
                }
            }
        }
    }

    if !completed_slots_senders.is_empty() && !newly_completed_slots.is_empty() {
        let mut slots: Vec<_> = (0..completed_slots_senders.len() - 1)
            .map(|_| newly_completed_slots.clone())
            .collect();

        slots.push(newly_completed_slots);

        for (signal, slots) in completed_slots_senders.iter().zip(slots.into_iter()) {
            let res = signal.try_send(slots);
            if let Err(TrySendError::Full(_)) = res {
                datapoint_error!(
                    "blockstore_error",
                    (
                        "error",
                        "Unable to send newly completed slot because channel is full",
                        String
                    ),
                );
            }
        }
    }
}

/// For each slot in the slot_meta_working_set which has any change, include
/// corresponding updates to cf::SlotMeta via the specified `write_batch`.
/// The `write_batch` will later be atomically committed to the blockstore.
///
/// Arguments:
/// - `slot_meta_working_set`: a map that maintains slot-id to its `SlotMeta`
///   mapping.
/// - `completed_slot_senders`: the units which are responsible for sending
///   signals for completed slots.
/// - `write_batch`: the write batch which includes all the updates of the
///   the current write and ensures their atomicity.
///
/// On success, the function returns an Ok result with <should_signal,
/// newly_completed_slots> pair where:
///  - `should_signal`: a boolean flag indicating whether to send signal.
///  - `newly_completed_slots`: a subset of slot_meta_working_set which are
///    newly completed.
fn commit_slot_meta_working_set(
    slot_meta_working_set: &HashMap<u64, SlotMetaWorkingSetEntry>,
    completed_slots_senders: &[Sender<Vec<u64>>],
    write_batch: &mut WriteBatch,
) -> Result<(bool, Vec<u64>)> {
    let mut should_signal = false;
    let mut newly_completed_slots = vec![];

    // Check if any metadata was changed, if so, insert the new version of the
    // metadata into the write batch
    for (slot, slot_meta_entry) in slot_meta_working_set.iter() {
        // Any slot that wasn't written to should have been filtered out by now.
        assert!(slot_meta_entry.did_insert_occur);
        let meta: &SlotMeta = &RefCell::borrow(&*slot_meta_entry.new_slot_meta);
        let meta_backup = &slot_meta_entry.old_slot_meta;
        if !completed_slots_senders.is_empty() && is_newly_completed_slot(meta, meta_backup) {
            newly_completed_slots.push(*slot);
        }
        // Check if the working copy of the metadata has changed
        if Some(meta) != meta_backup.as_ref() {
            should_signal = should_signal || slot_has_updates(meta, meta_backup);
            write_batch.put::<cf::SlotMeta>(*slot, meta)?;
        }
    }

    Ok((should_signal, newly_completed_slots))
}

/// Returns the `SlotMeta` of the specified `slot` from the two cached states:
/// `working_set` and `chained_slots`.  If both contain the `SlotMeta`, then
/// the latest one from the `working_set` will be returned.
fn find_slot_meta_in_cached_state<'a>(
    working_set: &'a HashMap<u64, SlotMetaWorkingSetEntry>,
    chained_slots: &'a HashMap<u64, Rc<RefCell<SlotMeta>>>,
    slot: Slot,
) -> Option<Rc<RefCell<SlotMeta>>> {
    if let Some(entry) = working_set.get(&slot) {
        Some(entry.new_slot_meta.clone())
    } else {
        chained_slots.get(&slot).cloned()
    }
}

// 1) Chain current_slot to the previous slot defined by prev_slot_meta
fn chain_new_slot_to_prev_slot(
    prev_slot_meta: &mut SlotMeta,
    current_slot: Slot,
    current_slot_meta: &mut SlotMeta,
) {
    prev_slot_meta.next_slots.push(current_slot);
    if prev_slot_meta.is_connected() {
        current_slot_meta.set_parent_connected();
    }
}

fn is_newly_completed_slot(slot_meta: &SlotMeta, backup_slot_meta: &Option<SlotMeta>) -> bool {
    slot_meta.is_full()
        && (backup_slot_meta.is_none()
            || slot_meta.consumed != backup_slot_meta.as_ref().unwrap().consumed)
}

/// Returns a boolean indicating whether a slot has received additional shreds
/// that can be replayed since the previous update to the slot's SlotMeta.
fn slot_has_updates(slot_meta: &SlotMeta, slot_meta_backup: &Option<SlotMeta>) -> bool {
    // First, this slot's parent must be connected in order to even consider
    // starting replay; otherwise, the replayed results may not be valid.
    slot_meta.is_parent_connected() &&
        // Then,
        // If the slot didn't exist in the db before, any consecutive shreds
        // at the start of the slot are ready to be replayed.
        ((slot_meta_backup.is_none() && slot_meta.consumed != 0) ||
        // Or,
        // If the slot has more consecutive shreds than it last did from the
        // last update, those shreds are new and also ready to be replayed.
        (slot_meta_backup.is_some() && slot_meta_backup.as_ref().unwrap().consumed != slot_meta.consumed))
}

// Creates a new ledger with slot 0 full of ticks (and only ticks).
//
// Returns the blockhash that can be used to append entries with.
pub fn create_new_ledger(
    ledger_path: &Path,
    genesis_config: &GenesisConfig,
    max_genesis_archive_unpacked_size: u64,
    column_options: LedgerColumnOptions,
) -> Result<Hash> {
    Blockstore::destroy(ledger_path)?;
    genesis_config.write(ledger_path)?;

    // Fill slot 0 with ticks that link back to the genesis_config to bootstrap the ledger.
    let blockstore_dir = column_options.shred_storage_type.blockstore_directory();
    let blockstore = Blockstore::open_with_options(
        ledger_path,
        BlockstoreOptions {
            access_type: AccessType::Primary,
            recovery_mode: None,
            enforce_ulimit_nofile: false,
            column_options: column_options.clone(),
        },
    )?;
    let ticks_per_slot = genesis_config.ticks_per_slot;
    let hashes_per_tick = genesis_config.poh_config.hashes_per_tick.unwrap_or(0);
    let entries = create_ticks(ticks_per_slot, hashes_per_tick, genesis_config.hash());
    let last_hash = entries.last().unwrap().hash;
    let version = solana_sdk::shred_version::version_from_hash(&last_hash);

    let shredder = Shredder::new(0, 0, 0, version).unwrap();
    let (shreds, _) = shredder.entries_to_shreds(
        &Keypair::new(),
        &entries,
        true, // is_last_in_slot
        // chained_merkle_root
        Some(Hash::new_from_array(rand::thread_rng().gen())),
        0,    // next_shred_index
        0,    // next_code_index
        true, // merkle_variant
        &ReedSolomonCache::default(),
        &mut ProcessShredsStats::default(),
    );
    assert!(shreds.last().unwrap().last_in_slot());

    blockstore.insert_shreds(shreds, None, false)?;
    blockstore.set_roots(std::iter::once(&0))?;
    // Explicitly close the blockstore before we create the archived genesis file
    drop(blockstore);

    let archive_path = ledger_path.join(DEFAULT_GENESIS_ARCHIVE);
    let args = vec![
        "jcfhS",
        archive_path.to_str().unwrap(),
        "-C",
        ledger_path.to_str().unwrap(),
        DEFAULT_GENESIS_FILE,
        blockstore_dir,
    ];
    let output = std::process::Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .args(args)
        .output()
        .unwrap();
    if !output.status.success() {
        use std::str::from_utf8;
        error!("tar stdout: {}", from_utf8(&output.stdout).unwrap_or("?"));
        error!("tar stderr: {}", from_utf8(&output.stderr).unwrap_or("?"));

        return Err(BlockstoreError::Io(IoError::new(
            ErrorKind::Other,
            format!(
                "Error trying to generate snapshot archive: {}",
                output.status
            ),
        )));
    }

    // ensure the genesis archive can be unpacked and it is under
    // max_genesis_archive_unpacked_size, immediately after creating it above.
    {
        let temp_dir = tempfile::tempdir_in(ledger_path).unwrap();
        // unpack into a temp dir, while completely discarding the unpacked files
        let unpack_check = unpack_genesis_archive(
            &archive_path,
            temp_dir.path(),
            max_genesis_archive_unpacked_size,
        );
        if let Err(unpack_err) = unpack_check {
            // stash problematic original archived genesis related files to
            // examine them later and to prevent validator and ledger-tool from
            // naively consuming them
            let mut error_messages = String::new();

            fs::rename(
                ledger_path.join(DEFAULT_GENESIS_ARCHIVE),
                ledger_path.join(format!("{DEFAULT_GENESIS_ARCHIVE}.failed")),
            )
            .unwrap_or_else(|e| {
                let _ = write!(
                    &mut error_messages,
                    "/failed to stash problematic {DEFAULT_GENESIS_ARCHIVE}: {e}"
                );
            });
            fs::rename(
                ledger_path.join(DEFAULT_GENESIS_FILE),
                ledger_path.join(format!("{DEFAULT_GENESIS_FILE}.failed")),
            )
            .unwrap_or_else(|e| {
                let _ = write!(
                    &mut error_messages,
                    "/failed to stash problematic {DEFAULT_GENESIS_FILE}: {e}"
                );
            });
            fs::rename(
                ledger_path.join(blockstore_dir),
                ledger_path.join(format!("{blockstore_dir}.failed")),
            )
            .unwrap_or_else(|e| {
                let _ = write!(
                    &mut error_messages,
                    "/failed to stash problematic {blockstore_dir}: {e}"
                );
            });

            return Err(BlockstoreError::Io(IoError::new(
                ErrorKind::Other,
                format!("Error checking to unpack genesis archive: {unpack_err}{error_messages}"),
            )));
        }
    }

    Ok(last_hash)
}

#[macro_export]
macro_rules! tmp_ledger_name {
    () => {
        &format!("{}-{}", file!(), line!())
    };
}

#[macro_export]
macro_rules! get_tmp_ledger_path {
    () => {
        $crate::blockstore::get_ledger_path_from_name($crate::tmp_ledger_name!())
    };
}

#[macro_export]
macro_rules! get_tmp_ledger_path_auto_delete {
    () => {
        $crate::blockstore::get_ledger_path_from_name_auto_delete($crate::tmp_ledger_name!())
    };
}

pub fn get_ledger_path_from_name_auto_delete(name: &str) -> TempDir {
    let mut path = get_ledger_path_from_name(name);
    // path is a directory so .file_name() returns the last component of the path
    let last = path.file_name().unwrap().to_str().unwrap().to_string();
    path.pop();
    fs::create_dir_all(&path).unwrap();
    Builder::new()
        .prefix(&last)
        .rand_bytes(0)
        .tempdir_in(path)
        .unwrap()
}

pub fn get_ledger_path_from_name(name: &str) -> PathBuf {
    use std::env;
    let out_dir = env::var("FARF_DIR").unwrap_or_else(|_| "farf".to_string());
    let keypair = Keypair::new();

    let path = [
        out_dir,
        "ledger".to_string(),
        format!("{}-{}", name, keypair.pubkey()),
    ]
    .iter()
    .collect();

    // whack any possible collision
    let _ignored = fs::remove_dir_all(&path);

    path
}

#[macro_export]
macro_rules! create_new_tmp_ledger {
    ($genesis_config:expr) => {
        $crate::blockstore::create_new_ledger_from_name(
            $crate::tmp_ledger_name!(),
            $genesis_config,
            $crate::blockstore_options::LedgerColumnOptions::default(),
        )
    };
}

#[macro_export]
macro_rules! create_new_tmp_ledger_fifo {
    ($genesis_config:expr) => {
        $crate::blockstore::create_new_ledger_from_name(
            $crate::tmp_ledger_name!(),
            $genesis_config,
            $crate::blockstore_options::LedgerColumnOptions {
                shred_storage_type: $crate::blockstore_options::ShredStorageType::RocksFifo(
                    $crate::blockstore_options::BlockstoreRocksFifoOptions::new_for_tests(),
                ),
                ..$crate::blockstore_options::LedgerColumnOptions::default()
            },
        )
    };
}

#[macro_export]
macro_rules! create_new_tmp_ledger_auto_delete {
    ($genesis_config:expr) => {
        $crate::blockstore::create_new_ledger_from_name_auto_delete(
            $crate::tmp_ledger_name!(),
            $genesis_config,
            $crate::blockstore_options::LedgerColumnOptions::default(),
        )
    };
}

#[macro_export]
macro_rules! create_new_tmp_ledger_fifo_auto_delete {
    ($genesis_config:expr) => {
        $crate::blockstore::create_new_ledger_from_name_auto_delete(
            $crate::tmp_ledger_name!(),
            $genesis_config,
            $crate::blockstore_options::LedgerColumnOptions {
                shred_storage_type: $crate::blockstore_options::ShredStorageType::RocksFifo(
                    $crate::blockstore_options::BlockstoreRocksFifoOptions::new_for_tests(),
                ),
                ..$crate::blockstore_options::LedgerColumnOptions::default()
            },
        )
    };
}

pub(crate) fn verify_shred_slots(slot: Slot, parent: Slot, root: Slot) -> bool {
    if slot == 0 && parent == 0 && root == 0 {
        return true; // valid write to slot zero.
    }
    // Ignore shreds that chain to slots before the root,
    // or have invalid parent >= slot.
    root <= parent && parent < slot
}

// Same as `create_new_ledger()` but use a temporary ledger name based on the provided `name`
//
// Note: like `create_new_ledger` the returned ledger will have slot 0 full of ticks (and only
// ticks)
pub fn create_new_ledger_from_name(
    name: &str,
    genesis_config: &GenesisConfig,
    column_options: LedgerColumnOptions,
) -> (PathBuf, Hash) {
    let (ledger_path, blockhash) =
        create_new_ledger_from_name_auto_delete(name, genesis_config, column_options);
    (ledger_path.into_path(), blockhash)
}

// Same as `create_new_ledger()` but use a temporary ledger name based on the provided `name`
//
// Note: like `create_new_ledger` the returned ledger will have slot 0 full of ticks (and only
// ticks)
pub fn create_new_ledger_from_name_auto_delete(
    name: &str,
    genesis_config: &GenesisConfig,
    column_options: LedgerColumnOptions,
) -> (TempDir, Hash) {
    let ledger_path = get_ledger_path_from_name_auto_delete(name);
    let blockhash = create_new_ledger(
        ledger_path.path(),
        genesis_config,
        MAX_GENESIS_ARCHIVE_UNPACKED_SIZE,
        column_options,
    )
    .unwrap();
    (ledger_path, blockhash)
}

pub fn entries_to_test_shreds(
    entries: &[Entry],
    slot: Slot,
    parent_slot: Slot,
    is_full_slot: bool,
    version: u16,
    merkle_variant: bool,
) -> Vec<Shred> {
    Shredder::new(slot, parent_slot, 0, version)
        .unwrap()
        .entries_to_shreds(
            &Keypair::new(),
            entries,
            is_full_slot,
            // chained_merkle_root
            Some(Hash::new_from_array(rand::thread_rng().gen())),
            0, // next_shred_index,
            0, // next_code_index
            merkle_variant,
            &ReedSolomonCache::default(),
            &mut ProcessShredsStats::default(),
        )
        .0
}

// used for tests only
pub fn make_slot_entries(
    slot: Slot,
    parent_slot: Slot,
    num_entries: u64,
    merkle_variant: bool,
) -> (Vec<Shred>, Vec<Entry>) {
    let entries = create_ticks(num_entries, 1, Hash::new_unique());
    let shreds = entries_to_test_shreds(&entries, slot, parent_slot, true, 0, merkle_variant);
    (shreds, entries)
}

// used for tests only
pub fn make_many_slot_entries(
    start_slot: Slot,
    num_slots: u64,
    entries_per_slot: u64,
) -> (Vec<Shred>, Vec<Entry>) {
    let mut shreds = vec![];
    let mut entries = vec![];
    for slot in start_slot..start_slot + num_slots {
        let parent_slot = if slot == 0 { 0 } else { slot - 1 };

        let (slot_shreds, slot_entries) = make_slot_entries(
            slot,
            parent_slot,
            entries_per_slot,
            true, // merkle_variant
        );
        shreds.extend(slot_shreds);
        entries.extend(slot_entries);
    }

    (shreds, entries)
}

// test-only: check that all columns are either empty or start at `min_slot`
pub fn test_all_empty_or_min(blockstore: &Blockstore, min_slot: Slot) {
    let condition_met = blockstore
        .db
        .iter::<cf::SlotMeta>(IteratorMode::Start)
        .unwrap()
        .next()
        .map(|(slot, _)| slot >= min_slot)
        .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::Root>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|(slot, _)| slot >= min_slot)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::ShredData>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|((slot, _), _)| slot >= min_slot)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::ShredCode>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|((slot, _), _)| slot >= min_slot)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::DeadSlots>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|(slot, _)| slot >= min_slot)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::DuplicateSlots>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|(slot, _)| slot >= min_slot)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::ErasureMeta>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|((slot, _), _)| slot >= min_slot)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::Orphans>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|(slot, _)| slot >= min_slot)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::Index>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|(slot, _)| slot >= min_slot)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::TransactionStatus>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|((_, slot), _)| slot >= min_slot || slot == 0)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::AddressSignatures>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|((_, slot, _, _), _)| slot >= min_slot || slot == 0)
            .unwrap_or(true)
        & blockstore
            .db
            .iter::<cf::Rewards>(IteratorMode::Start)
            .unwrap()
            .next()
            .map(|(slot, _)| slot >= min_slot)
            .unwrap_or(true);
    assert!(condition_met);
}

// used for tests only
// Create `num_shreds` shreds for [start_slot, start_slot + num_slot) slots
pub fn make_many_slot_shreds(
    start_slot: u64,
    num_slots: u64,
    num_shreds_per_slot: u64,
) -> (Vec<Shred>, Vec<Entry>) {
    // Use `None` as shred_size so the default (full) value is used
    let num_entries = max_ticks_per_n_shreds(num_shreds_per_slot, None);
    make_many_slot_entries(start_slot, num_slots, num_entries)
}

// Create shreds for slots that have a parent-child relationship defined by the input `chain`
// used for tests only
pub fn make_chaining_slot_entries(
    chain: &[u64],
    entries_per_slot: u64,
    first_parent: u64,
) -> Vec<(Vec<Shred>, Vec<Entry>)> {
    let mut slots_shreds_and_entries = vec![];
    for (i, slot) in chain.iter().enumerate() {
        let parent_slot = {
            if *slot == 0 || i == 0 {
                first_parent
            } else {
                chain[i - 1]
            }
        };

        let result = make_slot_entries(
            *slot,
            parent_slot,
            entries_per_slot,
            true, // merkle_variant
        );
        slots_shreds_and_entries.push(result);
    }

    slots_shreds_and_entries
}

#[cfg(not(unix))]
fn adjust_ulimit_nofile(_enforce_ulimit_nofile: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn adjust_ulimit_nofile(enforce_ulimit_nofile: bool) -> Result<()> {
    // Rocks DB likes to have many open files.  The default open file descriptor limit is
    // usually not enough
    // AppendVecs and disk Account Index are also heavy users of mmapped files.
    // This should be kept in sync with published validator instructions.
    // https://docs.solanalabs.com/operations/guides/validator-start#increased-memory-mapped-files-limit
    let desired_nofile = 1_000_000;

    fn get_nofile() -> libc::rlimit {
        let mut nofile = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut nofile) } != 0 {
            warn!("getrlimit(RLIMIT_NOFILE) failed");
        }
        nofile
    }

    let mut nofile = get_nofile();
    let current = nofile.rlim_cur;
    if current < desired_nofile {
        nofile.rlim_cur = desired_nofile;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &nofile) } != 0 {
            error!(
                "Unable to increase the maximum open file descriptor limit to {} from {}",
                nofile.rlim_cur, current,
            );

            if cfg!(target_os = "macos") {
                error!(
                    "On mac OS you may need to run |sudo launchctl limit maxfiles {} {}| first",
                    desired_nofile, desired_nofile,
                );
            }
            if enforce_ulimit_nofile {
                return Err(BlockstoreError::UnableToSetOpenFileDescriptorLimit);
            }
        }

        nofile = get_nofile();
    }
    info!("Maximum open file descriptors: {}", nofile.rlim_cur);
    Ok(())
}
