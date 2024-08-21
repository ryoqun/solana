use {
    crate::{
        banking_stage::{BankingStage, NUM_THREADS},
        sigverify::SigverifyTracerPacketStats,
        validator::BlockProductionMethod,
    },
    bincode::{deserialize_from, serialize_into},
    chrono::{DateTime, Local},
    crossbeam_channel::{unbounded, Receiver, SendError, Sender, TryRecvError},
    log::*,
    rolling_file::{RollingCondition, RollingConditionBasic, RollingFileAppender},
    solana_client::connection_cache::ConnectionCache,
    solana_gossip::cluster_info::{ClusterInfo, Node},
    solana_ledger::{
        blockstore::{Blockstore, PurgeType},
        leader_schedule_cache::LeaderScheduleCache,
    },
    solana_perf::packet::PacketBatch,
    solana_poh::{
        poh_recorder::{PohRecorder, GRACE_TICKS_FACTOR, MAX_GRACE_SLOTS},
        poh_service::PohService,
    },
    solana_runtime::{
        bank::{Bank, NewBankOptions},
        bank_forks::BankForks,
        prioritization_fee_cache::PrioritizationFeeCache,
    },
    solana_sdk::{
        genesis_config::GenesisConfig, hash::Hash, shred_version::compute_shred_version,
        signature::Keypair, slot_history::Slot,
    },
    solana_streamer::socket::SocketAddrSpace,
    solana_turbine::broadcast_stage::BroadcastStageType,
    std::{
        collections::{BTreeMap, HashMap},
        fs::{create_dir_all, remove_dir_all, File},
        io::{self, BufRead, BufReader, Write},
        net::UdpSocket,
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, sleep, JoinHandle},
        time::{Duration, SystemTime},
    },
    thiserror::Error,
};

pub type BankingPacketBatch = Arc<(Vec<PacketBatch>, Option<SigverifyTracerPacketStats>)>;
pub type BankingPacketSender = TracedSender;
pub type BankingPacketReceiver = Receiver<BankingPacketBatch>;
pub type TracerThreadResult = Result<(), TraceError>;
pub type TracerThread = Option<JoinHandle<TracerThreadResult>>;
pub type DirByteLimit = u64;

#[derive(Error, Debug)]
pub enum TraceError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization Error: {0}")]
    SerializeError(#[from] bincode::Error),

    #[error("Integer Cast Error: {0}")]
    IntegerCastError(#[from] std::num::TryFromIntError),

    #[error("Trace directory's byte limit is too small (must be larger than {1}): {0}")]
    TooSmallDirByteLimit(DirByteLimit, DirByteLimit),
}

const BASENAME: &str = "events";
const TRACE_FILE_ROTATE_COUNT: u64 = 14; // target 2 weeks retention under normal load
const TRACE_FILE_WRITE_INTERVAL_MS: u64 = 100;
const BUF_WRITER_CAPACITY: usize = 10 * 1024 * 1024;
pub const TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD: u64 = 1024 * 1024 * 1024;
pub const DISABLED_BAKING_TRACE_DIR: DirByteLimit = 0;
pub const BANKING_TRACE_DIR_DEFAULT_BYTE_LIMIT: DirByteLimit =
    TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD * TRACE_FILE_ROTATE_COUNT;

#[derive(Clone, Debug)]
struct ActiveTracer {
    trace_sender: Sender<TimedTracedEvent>,
    exit: Arc<AtomicBool>,
}

#[derive(Debug)]
pub struct BankingTracer {
    active_tracer: Option<ActiveTracer>,
}

#[cfg_attr(
    feature = "frozen-abi",
    derive(AbiExample),
    frozen_abi(digest = "Eq6YrAFtTbtPrCEvh6Et1mZZDCARUg1gcK2qiZdqyjUz")
)]
#[derive(Serialize, Deserialize, Debug)]
pub struct TimedTracedEvent(pub std::time::SystemTime, pub TracedEvent);

#[cfg_attr(feature = "frozen-abi", derive(AbiExample, AbiEnumVisitor))]
#[derive(Serialize, Deserialize, Debug)]
pub enum TracedEvent {
    PacketBatch(ChannelLabel, BankingPacketBatch),
    BlockAndBankHash(Slot, Hash, Hash),
}

#[cfg_attr(feature = "frozen-abi", derive(AbiExample, AbiEnumVisitor))]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum ChannelLabel {
    NonVote,
    TpuVote,
    GossipVote,
    Dummy,
}

struct RollingConditionGrouped {
    basic: RollingConditionBasic,
    tried_rollover_after_opened: bool,
    is_checked: bool,
}

impl RollingConditionGrouped {
    fn new(basic: RollingConditionBasic) -> Self {
        Self {
            basic,
            tried_rollover_after_opened: bool::default(),
            is_checked: bool::default(),
        }
    }

    fn reset(&mut self) {
        self.is_checked = false;
    }
}

struct GroupedWriter<'a> {
    now: DateTime<Local>,
    underlying: &'a mut RollingFileAppender<RollingConditionGrouped>,
}

impl<'a> GroupedWriter<'a> {
    fn new(underlying: &'a mut RollingFileAppender<RollingConditionGrouped>) -> Self {
        Self {
            now: Local::now(),
            underlying,
        }
    }
}

impl RollingCondition for RollingConditionGrouped {
    fn should_rollover(&mut self, now: &DateTime<Local>, current_filesize: u64) -> bool {
        if !self.tried_rollover_after_opened {
            self.tried_rollover_after_opened = true;

            // rollover normally if empty to reuse it if possible
            if current_filesize > 0 {
                // forcibly rollover anew, so that we always avoid to append
                // to a possibly-damaged tracing file even after unclean
                // restarts
                return true;
            }
        }

        if !self.is_checked {
            self.is_checked = true;
            self.basic.should_rollover(now, current_filesize)
        } else {
            false
        }
    }
}

impl<'a> Write for GroupedWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, io::Error> {
        self.underlying.write_with_datetime(buf, &self.now)
    }
    fn flush(&mut self) -> std::result::Result<(), io::Error> {
        self.underlying.flush()
    }
}

pub fn receiving_loop_with_minimized_sender_overhead<T, E, const SLEEP_MS: u64>(
    exit: Arc<AtomicBool>,
    receiver: Receiver<T>,
    mut on_recv: impl FnMut(T) -> Result<(), E>,
) -> Result<(), E> {
    'outer: while !exit.load(Ordering::Relaxed) {
        'inner: loop {
            // avoid futex-based blocking here, otherwise a sender would have to
            // wake me up at a syscall cost...
            match receiver.try_recv() {
                Ok(message) => on_recv(message)?,
                Err(TryRecvError::Empty) => break 'inner,
                Err(TryRecvError::Disconnected) => {
                    break 'outer;
                }
            };
            if exit.load(Ordering::Relaxed) {
                break 'outer;
            }
        }
        sleep(Duration::from_millis(SLEEP_MS));
    }

    Ok(())
}

impl BankingTracer {
    pub fn new(
        maybe_config: Option<(&PathBuf, Arc<AtomicBool>, DirByteLimit)>,
    ) -> Result<(Arc<Self>, TracerThread), TraceError> {
        match maybe_config {
            None => Ok((Self::new_disabled(), None)),
            Some((events_dir_path, exit, dir_byte_limit)) => {
                let rotate_threshold_size = dir_byte_limit / TRACE_FILE_ROTATE_COUNT;
                if rotate_threshold_size == 0 {
                    return Err(TraceError::TooSmallDirByteLimit(
                        dir_byte_limit,
                        TRACE_FILE_ROTATE_COUNT,
                    ));
                }

                let (trace_sender, trace_receiver) = unbounded();

                let file_appender =
                    Self::create_file_appender(events_dir_path, rotate_threshold_size)?;

                let tracer_thread =
                    Self::spawn_background_thread(trace_receiver, file_appender, exit.clone())?;

                Ok((
                    Arc::new(Self {
                        active_tracer: Some(ActiveTracer { trace_sender, exit }),
                    }),
                    Some(tracer_thread),
                ))
            }
        }
    }

    pub fn new_disabled() -> Arc<Self> {
        Arc::new(Self {
            active_tracer: None,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.active_tracer.is_some()
    }

    fn create_channel(&self, label: ChannelLabel) -> (BankingPacketSender, BankingPacketReceiver) {
        Self::channel(label, self.active_tracer.as_ref().cloned())
    }

    pub fn create_channel_non_vote(&self) -> (BankingPacketSender, BankingPacketReceiver) {
        self.create_channel(ChannelLabel::NonVote)
    }

    pub fn create_channel_tpu_vote(&self) -> (BankingPacketSender, BankingPacketReceiver) {
        self.create_channel(ChannelLabel::TpuVote)
    }

    pub fn create_channel_gossip_vote(&self) -> (BankingPacketSender, BankingPacketReceiver) {
        self.create_channel(ChannelLabel::GossipVote)
    }

    pub fn hash_event(&self, slot: Slot, blockhash: &Hash, bank_hash: &Hash) {
        self.trace_event(|| {
            TimedTracedEvent(
                SystemTime::now(),
                TracedEvent::BlockAndBankHash(slot, *blockhash, *bank_hash),
            )
        })
    }

    fn trace_event(&self, on_trace: impl Fn() -> TimedTracedEvent) {
        if let Some(ActiveTracer { trace_sender, exit }) = &self.active_tracer {
            if !exit.load(Ordering::Relaxed) {
                trace_sender
                    .send(on_trace())
                    .expect("active tracer thread unless exited");
            }
        }
    }

    pub fn channel_for_test() -> (TracedSender, Receiver<BankingPacketBatch>) {
        Self::channel(ChannelLabel::Dummy, None)
    }

    fn channel(
        label: ChannelLabel,
        active_tracer: Option<ActiveTracer>,
    ) -> (TracedSender, Receiver<BankingPacketBatch>) {
        let (sender, receiver) = unbounded();
        (TracedSender::new(label, sender, active_tracer), receiver)
    }

    pub fn ensure_cleanup_path(path: &PathBuf) -> Result<(), io::Error> {
        remove_dir_all(path).or_else(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(err)
            }
        })
    }

    fn create_file_appender(
        path: &PathBuf,
        rotate_threshold_size: u64,
    ) -> Result<RollingFileAppender<RollingConditionGrouped>, TraceError> {
        create_dir_all(path)?;
        let grouped = RollingConditionGrouped::new(
            RollingConditionBasic::new()
                .daily()
                .max_size(rotate_threshold_size),
        );
        let appender = RollingFileAppender::new_with_buffer_capacity(
            path.join(BASENAME),
            grouped,
            (TRACE_FILE_ROTATE_COUNT - 1).try_into()?,
            BUF_WRITER_CAPACITY,
        )?;
        Ok(appender)
    }

    fn spawn_background_thread(
        trace_receiver: Receiver<TimedTracedEvent>,
        mut file_appender: RollingFileAppender<RollingConditionGrouped>,
        exit: Arc<AtomicBool>,
    ) -> Result<JoinHandle<TracerThreadResult>, TraceError> {
        let thread = thread::Builder::new().name("solBanknTracer".into()).spawn(
            move || -> TracerThreadResult {
                receiving_loop_with_minimized_sender_overhead::<_, _, TRACE_FILE_WRITE_INTERVAL_MS>(
                    exit,
                    trace_receiver,
                    |event| -> Result<(), TraceError> {
                        file_appender.condition_mut().reset();
                        serialize_into(&mut GroupedWriter::new(&mut file_appender), &event)?;
                        Ok(())
                    },
                )?;
                file_appender.flush()?;
                Ok(())
            },
        )?;

        Ok(thread)
    }
}

pub struct TracedSender {
    label: ChannelLabel,
    sender: Sender<BankingPacketBatch>,
    active_tracer: Option<ActiveTracer>,
}

impl TracedSender {
    fn new(
        label: ChannelLabel,
        sender: Sender<BankingPacketBatch>,
        active_tracer: Option<ActiveTracer>,
    ) -> Self {
        Self {
            label,
            sender,
            active_tracer,
        }
    }

    pub fn send(&self, batch: BankingPacketBatch) -> Result<(), SendError<BankingPacketBatch>> {
        if let Some(ActiveTracer { trace_sender, exit }) = &self.active_tracer {
            if !exit.load(Ordering::Relaxed) {
                trace_sender
                    .send(TimedTracedEvent(
                        SystemTime::now(),
                        TracedEvent::PacketBatch(self.label, BankingPacketBatch::clone(&batch)),
                    ))
                    .map_err(|err| {
                        error!(
                            "unexpected error when tracing a banking event...: {:?}",
                            err
                        );
                        SendError(BankingPacketBatch::clone(&batch))
                    })?;
            }
        }
        self.sender.send(batch)
    }

    pub fn len(&self) -> usize {
        self.sender.len()
    }
}

#[cfg(any(test, feature = "dev-context-only-utils"))]
pub mod for_test {
    use {
        super::*,
        solana_perf::{packet::to_packet_batches, test_tx::test_tx},
        tempfile::TempDir,
    };

    pub fn sample_packet_batch() -> BankingPacketBatch {
        BankingPacketBatch::new((to_packet_batches(&vec![test_tx(); 4], 10), None))
    }

    pub fn drop_and_clean_temp_dir_unless_suppressed(temp_dir: TempDir) {
        std::env::var("BANKING_TRACE_LEAVE_FILES").is_ok().then(|| {
            warn!("prevented to remove {:?}", temp_dir.path());
            drop(temp_dir.into_path());
        });
    }

    pub fn terminate_tracer(
        tracer: Arc<BankingTracer>,
        tracer_thread: TracerThread,
        main_thread: JoinHandle<TracerThreadResult>,
        sender: TracedSender,
        exit: Option<Arc<AtomicBool>>,
    ) {
        if let Some(exit) = exit {
            exit.store(true, Ordering::Relaxed);
        }
        drop((sender, tracer));
        main_thread.join().unwrap().unwrap();
        if let Some(tracer_thread) = tracer_thread {
            tracer_thread.join().unwrap().unwrap();
        }
    }
}

// This creates a simulated environment around the banking stage to reproduce leader's blocks based
// on recorded banking trace events (`TimedTracedEvent`).
//
// The task of banking stage at the highest level is to pack transactions into their blocks as much
// as possible for scheduled fixed duration. So, there's 3 abstract inputs to simulate: blocks,
// time, and transactions.
//
// In the context of simulation, the first two are simple; both are well defined.
//
// For ancestor blocks, we firstly replay certain number of blocks immediately up to target
// simulation leader's slot with halt_at_slot mechanism, possibly priming various caches,
// ultimately freezing the ancestor block with expected and deterministic hashes.
//
// After replay, a minor tweak is applied during simulation: we forcibly override leader's hashes
// as simulated banking stage creates them, using recorded `BlockAndBankHash` events. This is to
// provide undistinguishable sysvars to TX execution and identical TX age resolution as the
// simulation goes on. Otherwise, vast majority of tx processing would differ because simulated
// block's hashes would definitely differ than the recorded ones as slight block composition
// difference is inevitable.
//
// For poh time, we just use PohRecorder as same as the real environment, which is just 400ms
// timer, external to banking stage and thus mostly irrelevant to banking stage performance. For
// wall time, we use the first BankStatus::BlockAndBankHash and `SystemTime::now()` to define T=0
// for simulation. Then, simulation progress is timed accordingly. As a context, this syncing is
// needed because all trace events are recorded in UTC, not relative to poh nor to leader schedule
// for simplicity at recording.
//
// Lastly, here's the last and most complicated input to simulate: transactions.
//
// A bit closer look of transaction load profile is like below, regardless of internal banking
// implementation and simulation:
//
// There's ever `BufferedPacketsDecision::Hold`-ed transactions to be processed as the first leader
// slot nears. This is due to solana's general tx broadcast strategy of node's forwarding and
// client's submission, which are unlikely to chabge soon. So, we take this as granted. Then, any
// initial leader block creation starts with rather large number of schedule-able transactions.
// Also, note that additional transactions arrive for the 4 leader slot window (roughly ~1.6
// seconds).
//
// Simulation have to mimic this load pattern while being agnostic to internal bnaking impl as much
// as possible. For that agnostic objective, `TracedSender`s are sneaked into the SigVerify stage
// and gossip subsystem by `BankingTracer` to trace **all** of `BankingPacketBatch`s' exact payload
// and _sender_'s timing with `SystemTime::now()` for all `ChannelLabel`s. This deliberate tracing
// placement is not to be affected by any banking-tage's capping (if any) and its channel
// consumption pattern.
//
// BankingSimulator consists of 2 phases chronologically: warm-up and on-the-fly. The 2 phases are
// segregated by the aforementioned T=0.
//
// Both phases just sends BankingPacketBatch in the same fashion, pretending to be sigveirfy
// stage/gossip while burning 1 thread to busy loop for precise T=N at ~1us granularity.
//
// Warm up is defined as T=-N secs using slot distance between immediate ancestor of first
// simulated block and root block. As soon as warm up is initiated, we invoke
// `BankingStage::new_num_threads()` as well to simulate the pre-leader slot's tx-buffering time.
pub struct BankingSimulator {
    event_file_pathes: Vec<PathBuf>,
    first_simulated_slot: Slot,
}

#[derive(Error, Debug)]
pub enum SimulateError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Deserialization Error: {0}")]
    SerializeError(#[from] bincode::Error),
}

struct BankingTraceEvents {
}

impl BankingTraceEvents {
    fn load(event_file_pathes: Vec<PathBuf>) -> Self {
        Self {}
    }
}

impl BankingSimulator {
    pub fn new(
        event_file_pathes: Vec<PathBuf>,
        first_simulated_slot: Slot,
    ) -> Self {
        Self {
            event_file_pathes,
            first_simulated_slot,
        }
    }

    fn read_event_file(
        events: &mut Vec<TimedTracedEvent>,
        event_file_path: &PathBuf,
    ) -> Result<(), SimulateError> {
        let mut reader = BufReader::new(File::open(event_file_path)?);

        // flag to ignore deserialize error? and what if the file is empty?
        loop {
            events.push(deserialize_from(&mut reader)?);

            if reader.fill_buf()?.is_empty() {
                // EOF is reached at a correct deserialization boundary.
                // We're looking-ahead the buf, so NOT calling reader.consume(..) is correct.
                break;
            }
        }

        Ok(())
    }

    fn read_event_files(
        &self,
    ) -> Result<
        (
            BTreeMap<SystemTime, (ChannelLabel, BankingPacketBatch)>,
            BTreeMap<Slot, (SystemTime, Hash, Hash)>,
        ),
        SimulateError,
    > {
        let mut events = vec![];
        for event_file_path in &self.event_file_pathes {
            let old_len = events.len();
            let _ = Self::read_event_file(&mut events, event_file_path).inspect_err(|error| {
                error!(
                    "Reading {event_file_path:?} failed after {} events: {:?} due to file corruption or unclearn validator shutdown",
                    events.len() - old_len,
                    error
                );
            });
            info!(
                "Read {} events from {:?}",
                events.len() - old_len,
                event_file_path
            );
        }

        let mut packet_batches_by_time = BTreeMap::new();
        let mut timed_hashes_by_slot = BTreeMap::new();
        for TimedTracedEvent(event_time, event) in events {
            match event {
                TracedEvent::PacketBatch(label, batch) => {
                    // Somewhat naively assume that event_times (nanosecond resolution) won't
                    // collide.
                    let is_new = packet_batches_by_time
                        .insert(event_time, (label, batch))
                        .is_none();
                    assert!(is_new);
                }
                TracedEvent::BlockAndBankHash(slot, blockhash, bank_hash) => {
                    let is_new = timed_hashes_by_slot
                        .insert(slot, (event_time, blockhash, bank_hash))
                        .is_none();
                    assert!(is_new);
                }
            }
        }

        Ok((packet_batches_by_time, timed_hashes_by_slot))
    }

    pub fn start(
        self,
        genesis_config: GenesisConfig,
        bank_forks: Arc<RwLock<BankForks>>,
        blockstore: Arc<Blockstore>,
        block_production_method: BlockProductionMethod,
        block_cost_limits: bool,
    ) -> Result<(), SimulateError> {
        let mut bank = bank_forks
            .read()
            .unwrap()
            .working_bank_with_scheduler()
            .clone_with_scheduler();

        if block_cost_limits {
            info!("setting block cost limits to MAX");
            bank.write_cost_tracker()
                .unwrap()
                .set_limits(u64::MAX, u64::MAX, u64::MAX);
        }

        let (packet_batches_by_time, timed_hashes_by_slot) = self.read_event_files()?;

        let leader_schedule_cache = Arc::new(LeaderScheduleCache::new_from_bank(&bank));
        let skipped_slot_offset = 1;
        let start_slot = bank.slot();
        let simulated_slot = start_slot + skipped_slot_offset;
        let simulated_leader = leader_schedule_cache
            .slot_leader_at(simulated_slot, None)
            .unwrap();
        info!("simulated leader and slot: {simulated_leader}, {simulated_slot}");

        let exit = Arc::new(AtomicBool::default());

        if let Some(end_slot) = blockstore
            .slot_meta_iterator(self.first_simulated_slot)
            .unwrap()
            .map(|(s, _)| s)
            .last()
        {
            info!("purging slots {}, {}", self.first_simulated_slot, end_slot);
            blockstore
                .purge_from_next_slots(self.first_simulated_slot, end_slot);
            blockstore
                .purge_slots(self.first_simulated_slot, end_slot, PurgeType::Exact);
            info!("done: purging");
        } else {
            info!("skipping purging...");
        }

        info!("poh is starting!");

        let (poh_recorder, entry_receiver, record_receiver) = PohRecorder::new_with_clear_signal(
            bank.tick_height(),
            bank.last_blockhash(),
            bank.clone(),
            Some((simulated_slot, simulated_slot + 4)),
            bank.ticks_per_slot(),
            false,
            blockstore.clone(),
            blockstore.get_new_shred_signal(0),
            &leader_schedule_cache,
            &genesis_config.poh_config,
            None,
            exit.clone(),
        );
        let poh_recorder = Arc::new(RwLock::new(poh_recorder));
        solana_unified_scheduler_pool::MY_POH.lock().unwrap().insert(poh_recorder.read().unwrap().new_recorder());
        let poh_service = PohService::new(
            poh_recorder.clone(),
            &genesis_config.poh_config,
            exit.clone(),
            bank.ticks_per_slot(),
            solana_poh::poh_service::DEFAULT_PINNED_CPU_CORE + 4,
            solana_poh::poh_service::DEFAULT_HASHES_PER_BATCH,
            record_receiver,
        );
        let warmup_duration = Duration::from_secs(12);

        let (banking_retracer, retracer_thread) = BankingTracer::new(Some((
            &blockstore.banking_retracer_path(),
            exit.clone(),
            BANKING_TRACE_DIR_DEFAULT_BYTE_LIMIT,
        )))
        .unwrap();
        if banking_retracer.is_enabled() {
            info!(
                "Enabled banking retracer (dir_byte_limit: {})",
                BANKING_TRACE_DIR_DEFAULT_BYTE_LIMIT,
            );
        } else {
            info!("Disabled banking retracer");
        }

        let (non_vote_sender, non_vote_receiver) = banking_retracer.create_channel_non_vote();
        let (tpu_vote_sender, tpu_vote_receiver) = banking_retracer.create_channel_tpu_vote();
        let (gossip_vote_sender, gossip_vote_receiver) =
            banking_retracer.create_channel_gossip_vote();

        let cluster_info = Arc::new(ClusterInfo::new(
            Node::new_localhost_with_pubkey(&simulated_leader).info,
            Arc::new(Keypair::new()),
            SocketAddrSpace::Unspecified,
        ));
        let connection_cache = Arc::new(ConnectionCache::new("connection_kache!"));
        let (replay_vote_sender, _replay_vote_receiver) = unbounded();
        let (retransmit_slots_sender, retransmit_slots_receiver) = unbounded();
        let shred_version = compute_shred_version(
            &genesis_config.hash(),
            Some(&bank_forks.read().unwrap().root_bank().hard_forks()),
        );
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let broadcast_stage = BroadcastStageType::Standard.new_broadcast_stage(
            vec![UdpSocket::bind("127.0.0.1:0").unwrap()],
            cluster_info.clone(),
            entry_receiver,
            retransmit_slots_receiver,
            exit.clone(),
            blockstore.clone(),
            bank_forks.clone(),
            shred_version,
            sender,
        );

        info!("start banking stage!...");
        let prioritization_fee_cache = &Arc::new(PrioritizationFeeCache::new(0u64));
        let banking_stage = BankingStage::new_num_threads(
            block_production_method.clone(),
            &cluster_info,
            &poh_recorder,
            non_vote_receiver,
            tpu_vote_receiver,
            gossip_vote_receiver,
            BankingStage::num_threads(),
            None,
            replay_vote_sender,
            None,
            connection_cache,
            bank_forks.clone(),
            prioritization_fee_cache,
            false,
        );

        let (&slot_before_next_leader_slot, &(raw_base_event_time, _, _)) = timed_hashes_by_slot
            .range(start_slot..)
            .next()
            .expect("timed hashes");

        let base_event_time = raw_base_event_time - warmup_duration;
        let base_simulation_time = SystemTime::now();

        let sender_thread = thread::Builder::new().name("solSimSender".into()).spawn({
            let exit = exit.clone();

            move || {
                let (mut non_vote_count, mut non_vote_tx_count) = (0, 0);
                let (mut tpu_vote_count, mut tpu_vote_tx_count) = (0, 0);
                let (mut gossip_vote_count, mut gossip_vote_tx_count) = (0, 0);

                info!("start sending!...");
                let timed_batches_to_send = packet_batches_by_time.range(base_event_time..);
                info!(
                    "simulating banking trace events: {} out of {}, starting at slot {} (based on {} from traced event slot: {}) (warmup: -{:?})",
                    timed_batches_to_send.clone().count(),
                    packet_batches_by_time.len(),
                    start_slot,
                    {
                        let raw_base_event_time: chrono::DateTime<chrono::Utc> = raw_base_event_time.into();
                        raw_base_event_time.format("%Y-%m-%d %H:%M:%S.%f")
                    },
                    slot_before_next_leader_slot,
                    warmup_duration,
                );
                let mut simulation_duration_since_base = Duration::default();
                let (mut last_log_duration, mut last_tx_count) = (Duration::default(), 0);
                for (&event_time, (label, batches_with_stats)) in timed_batches_to_send {
                    let required_duration_since_base =
                        event_time.duration_since(base_event_time).unwrap();

                    // Busy loop for most accurate sending timings
                    loop {
                        if simulation_duration_since_base > required_duration_since_base {
                            break;
                        }
                        let current_simulation_time = SystemTime::now();
                        simulation_duration_since_base = current_simulation_time
                            .duration_since(base_simulation_time)
                            .unwrap();
                    }

                    let sender = match label {
                        ChannelLabel::NonVote => &non_vote_sender,
                        ChannelLabel::TpuVote => &tpu_vote_sender,
                        ChannelLabel::GossipVote => &gossip_vote_sender,
                        ChannelLabel::Dummy => unreachable!(),
                    };
                    sender.send(batches_with_stats.clone()).unwrap();

                    let batches = &batches_with_stats.0;
                    let (batch_count, tx_count) = (
                        batches.len(),
                        batches.iter().map(|batch| batch.len()).sum::<usize>(),
                    );
                    debug!(
                        "sent {:?} {} batches ({} txes)",
                        label, batch_count, tx_count
                    );
                    let (total_batch_count, total_tx_count) = match label {
                        ChannelLabel::NonVote => (&mut non_vote_count, &mut non_vote_tx_count),
                        ChannelLabel::TpuVote => (&mut tpu_vote_count, &mut tpu_vote_tx_count),
                        ChannelLabel::GossipVote => (&mut gossip_vote_count, &mut gossip_vote_tx_count),
                        ChannelLabel::Dummy => unreachable!(),
                    };
                    *total_batch_count += batch_count;
                    *total_tx_count += tx_count;

                    let log_interval = simulation_duration_since_base - last_log_duration;
                    if log_interval > Duration::from_millis(100) {
                        let current_tx_count = non_vote_tx_count + tpu_vote_tx_count + gossip_vote_tx_count;
                        let tps = ((current_tx_count - last_tx_count) as f64 / log_interval.as_secs_f64()) as u64;
                        info!(
                            "tps: {} (over {:?}) buffered batches: {} (non-vote) {} (tpu-vote) {} (gossip-vote)",
                            tps,
                            log_interval,
                            non_vote_sender.len(),
                            tpu_vote_sender.len(),
                            gossip_vote_sender.len(),
                        );
                        last_log_duration = simulation_duration_since_base;
                        last_tx_count = current_tx_count;
                    }

                    if exit.load(Ordering::Relaxed) {
                        break;
                    }
                }
                info!(
                    "terminating to send...: non_vote: {} ({}), tpu_vote: {} ({}), gossip_vote: {} ({})",
                    non_vote_count,
                    non_vote_tx_count,
                    tpu_vote_count,
                    tpu_vote_tx_count,
                    gossip_vote_count,
                    gossip_vote_tx_count
                );
                // hold these senders in join_handle to control banking stage termination!
                (non_vote_sender, tpu_vote_sender, gossip_vote_sender)
            }
        })?;

        sleep(warmup_duration);
        info!("warmup done!");

        for _ in 0..500 {
            if poh_recorder.read().unwrap().bank().is_none() {
                let next_leader_slot = leader_schedule_cache.next_leader_slot(
                    &simulated_leader,
                    bank.slot(),
                    &bank,
                    Some(&blockstore),
                    GRACE_TICKS_FACTOR * MAX_GRACE_SLOTS,
                );
                debug!("{next_leader_slot:?}");
                poh_recorder
                    .write()
                    .unwrap()
                    .reset(bank.clone_without_scheduler(), next_leader_slot);
                info!("Bank::new_from_parent()!");

                let old_slot = bank.slot();
                if let Some((event_time, _blockhash, _bank_hash)) =
                    timed_hashes_by_slot.get(&old_slot)
                {
                    if log_enabled!(log::Level::Info) {
                        let current_simulation_time = SystemTime::now();
                        let elapsed_simulation_time = current_simulation_time.duration_since(base_simulation_time).unwrap();
                        let elapsed_event_time = event_time.duration_since(base_event_time).unwrap();
                        info!(
                            "jitter(parent_slot: {}): {}{:?} (sim: {:?} event: {:?})",
                            old_slot,
                            if elapsed_simulation_time > elapsed_event_time { "+" } else { "-" },
                            if elapsed_simulation_time > elapsed_event_time {
                                elapsed_simulation_time - elapsed_event_time
                            } else {
                                elapsed_event_time - elapsed_simulation_time
                            },
                            elapsed_simulation_time,
                            elapsed_event_time,
                        );
                    }
                }
                bank.freeze();
                let new_slot = if bank.slot() == start_slot {
                    info!("initial leader block!");
                    bank.slot() + skipped_slot_offset
                } else {
                    info!("next leader block!");
                    bank.slot() + 1
                };
                info!("new leader bank slot: {new_slot}");
                let new_leader = leader_schedule_cache
                    .slot_leader_at(new_slot, None)
                    .unwrap();
                if simulated_leader != new_leader {
                    info!(
                        "{} isn't leader anymore at slot {}; new leader: {}",
                        simulated_leader, new_slot, new_leader
                    );
                    info!("bank cost: slot: {} {:?} (frozen)", bank.slot(), bank.read_cost_tracker().map(|t| (t.block_cost(), t.vote_cost())).unwrap());
                    break;
                } else if sender_thread.is_finished() {
                    warn!("sender thread existed maybe due to completion of sending traced events");
                    break;
                }
                let new_bank = Bank::new_from_parent(
                    bank.clone_without_scheduler(),
                    &simulated_leader,
                    new_slot,
                );
                // make sure parent is frozen for finalized hashes via the above
                // new()-ing of its child bank
                banking_retracer.hash_event(bank.slot(), &bank.last_blockhash(), &bank.hash());
                if *bank.collector_id() == simulated_leader {
                    info!("bank cost: slot: {} {:?} (frozen)", bank.slot(), bank.read_cost_tracker().map(|t| (t.block_cost(), t.vote_cost())).unwrap());
                }
                retransmit_slots_sender.send(bank.slot()).unwrap();
                bank_forks.write().unwrap().insert(solana_sdk::scheduling::SchedulingMode::BlockProduction, new_bank);
                bank = bank_forks
                    .read()
                    .unwrap()
                    .working_bank_with_scheduler()
                    .clone_with_scheduler();
                poh_recorder
                    .write()
                    .unwrap()
                    .set_bank(bank.clone_with_scheduler(), false);
            } else {
                debug!("bank cost: slot: {} {:?} (ongoing)", bank.slot(), bank.read_cost_tracker().map(|t| (t.block_cost(), t.vote_cost())).unwrap());
            }

            sleep(Duration::from_millis(10));
        }

        info!("sleeping a bit before setting the exit AtomicBool to true");
        sleep(Duration::from_millis(100));
        exit.store(true, Ordering::Relaxed);
        // the order is important. consuming sender_thread by joining will terminate banking_stage, in turn
        // banking_retracer thread will termianl
        sender_thread.join().unwrap();
        banking_stage.join().unwrap();
        poh_service.join().unwrap();
        if let Some(retracer_thread) = retracer_thread {
            retracer_thread.join().unwrap().unwrap();
        }

        // TODO: add flag to store shreds into ledger so that we can even benchmark replay stgage with
        // actua blocks created by these simulation
        // also sadly need to feed these overriding hashes into replaying stage for those recreted
        // simulated blocks...
        info!("joining broadcast stage...");
        drop(poh_recorder);
        drop(retransmit_slots_sender);
        broadcast_stage.join().unwrap();

        Ok(())
    }

    pub fn event_file_name(index: usize) -> String {
        if index == 0 {
            BASENAME.to_string()
        } else {
            format!("{BASENAME}.{index}")
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        bincode::ErrorKind::Io as BincodeIoError,
        std::{
            fs::File,
            io::{BufReader, ErrorKind::UnexpectedEof},
            str::FromStr,
        },
        tempfile::TempDir,
    };

    #[test]
    fn test_new_disabled() {
        let exit = Arc::<AtomicBool>::default();

        let tracer = BankingTracer::new_disabled();
        let (non_vote_sender, non_vote_receiver) = tracer.create_channel_non_vote();

        let dummy_main_thread = thread::spawn(move || {
            receiving_loop_with_minimized_sender_overhead::<_, TraceError, 0>(
                exit,
                non_vote_receiver,
                |_packet_batch| Ok(()),
            )
        });

        non_vote_sender
            .send(BankingPacketBatch::new((vec![], None)))
            .unwrap();
        for_test::terminate_tracer(tracer, None, dummy_main_thread, non_vote_sender, None);
    }

    #[test]
    fn test_send_after_exited() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("banking-trace");
        let exit = Arc::<AtomicBool>::default();
        let (tracer, tracer_thread) =
            BankingTracer::new(Some((&path, exit.clone(), DirByteLimit::MAX))).unwrap();
        let (non_vote_sender, non_vote_receiver) = tracer.create_channel_non_vote();

        let exit_for_dummy_thread = Arc::<AtomicBool>::default();
        let exit_for_dummy_thread2 = exit_for_dummy_thread.clone();
        let dummy_main_thread = thread::spawn(move || {
            receiving_loop_with_minimized_sender_overhead::<_, TraceError, 0>(
                exit_for_dummy_thread,
                non_vote_receiver,
                |_packet_batch| Ok(()),
            )
        });

        // kill and join the tracer thread
        exit.store(true, Ordering::Relaxed);
        tracer_thread.unwrap().join().unwrap().unwrap();

        // .hash_event() must succeed even after exit is already set to true
        let blockhash = Hash::from_str("B1ockhash1111111111111111111111111111111111").unwrap();
        let bank_hash = Hash::from_str("BankHash11111111111111111111111111111111111").unwrap();
        tracer.hash_event(4, &blockhash, &bank_hash);

        drop(tracer);

        // .send() must succeed even after exit is already set to true and further tracer is
        // already dropped
        non_vote_sender
            .send(for_test::sample_packet_batch())
            .unwrap();

        // finally terminate and join the main thread
        exit_for_dummy_thread2.store(true, Ordering::Relaxed);
        dummy_main_thread.join().unwrap().unwrap();
    }

    #[test]
    fn test_record_and_restore() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("banking-trace");
        let exit = Arc::<AtomicBool>::default();
        let (tracer, tracer_thread) =
            BankingTracer::new(Some((&path, exit.clone(), DirByteLimit::MAX))).unwrap();
        let (non_vote_sender, non_vote_receiver) = tracer.create_channel_non_vote();

        let dummy_main_thread = thread::spawn(move || {
            receiving_loop_with_minimized_sender_overhead::<_, TraceError, 0>(
                exit,
                non_vote_receiver,
                |_packet_batch| Ok(()),
            )
        });

        non_vote_sender
            .send(for_test::sample_packet_batch())
            .unwrap();
        let blockhash = Hash::from_str("B1ockhash1111111111111111111111111111111111").unwrap();
        let bank_hash = Hash::from_str("BankHash11111111111111111111111111111111111").unwrap();
        tracer.hash_event(4, &blockhash, &bank_hash);

        for_test::terminate_tracer(
            tracer,
            tracer_thread,
            dummy_main_thread,
            non_vote_sender,
            None,
        );

        let mut stream = BufReader::new(File::open(path.join(BASENAME)).unwrap());
        let results = (0..=3)
            .map(|_| bincode::deserialize_from::<_, TimedTracedEvent>(&mut stream))
            .collect::<Vec<_>>();

        let mut i = 0;
        assert_matches!(
            results[i],
            Ok(TimedTracedEvent(
                _,
                TracedEvent::PacketBatch(ChannelLabel::NonVote, _)
            ))
        );
        i += 1;
        assert_matches!(
            results[i],
            Ok(TimedTracedEvent(
                _,
                TracedEvent::BlockAndBankHash(4, actual_blockhash, actual_bank_hash)
            )) if actual_blockhash == blockhash && actual_bank_hash == bank_hash
        );
        i += 1;
        assert_matches!(
            results[i],
            Err(ref err) if matches!(
                **err,
                BincodeIoError(ref error) if error.kind() == UnexpectedEof
            )
        );

        for_test::drop_and_clean_temp_dir_unless_suppressed(temp_dir);
    }

    #[test]
    fn test_spill_over_at_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("banking-trace");
        const REALLY_SMALL_ROTATION_THRESHOLD: u64 = 1;

        let mut file_appender =
            BankingTracer::create_file_appender(&path, REALLY_SMALL_ROTATION_THRESHOLD).unwrap();
        file_appender.write_all(b"foo").unwrap();
        file_appender.condition_mut().reset();
        file_appender.write_all(b"bar").unwrap();
        file_appender.condition_mut().reset();
        file_appender.flush().unwrap();

        assert_eq!(
            [
                std::fs::read_to_string(path.join("events")).ok(),
                std::fs::read_to_string(path.join("events.1")).ok(),
                std::fs::read_to_string(path.join("events.2")).ok(),
            ],
            [Some("bar".into()), Some("foo".into()), None]
        );

        for_test::drop_and_clean_temp_dir_unless_suppressed(temp_dir);
    }

    #[test]
    fn test_reopen_with_blank_file() {
        let temp_dir = TempDir::new().unwrap();

        let path = temp_dir.path().join("banking-trace");

        let mut file_appender =
            BankingTracer::create_file_appender(&path, TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD)
                .unwrap();
        // assume this is unclean write
        file_appender.write_all(b"f").unwrap();
        file_appender.flush().unwrap();

        // reopen while shadow-dropping the old tracer
        let mut file_appender =
            BankingTracer::create_file_appender(&path, TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD)
                .unwrap();
        // new file won't be created as appender is lazy
        assert_eq!(
            [
                std::fs::read_to_string(path.join("events")).ok(),
                std::fs::read_to_string(path.join("events.1")).ok(),
                std::fs::read_to_string(path.join("events.2")).ok(),
            ],
            [Some("f".into()), None, None]
        );

        // initial write actually creates the new blank file
        file_appender.write_all(b"bar").unwrap();
        assert_eq!(
            [
                std::fs::read_to_string(path.join("events")).ok(),
                std::fs::read_to_string(path.join("events.1")).ok(),
                std::fs::read_to_string(path.join("events.2")).ok(),
            ],
            [Some("".into()), Some("f".into()), None]
        );

        // flush actually write the actual data
        file_appender.flush().unwrap();
        assert_eq!(
            [
                std::fs::read_to_string(path.join("events")).ok(),
                std::fs::read_to_string(path.join("events.1")).ok(),
                std::fs::read_to_string(path.join("events.2")).ok(),
            ],
            [Some("bar".into()), Some("f".into()), None]
        );

        for_test::drop_and_clean_temp_dir_unless_suppressed(temp_dir);
    }
}
