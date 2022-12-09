use {
    crate::sigverify::SigverifyTracerPacketStats,
    bincode::serialize_into,
    chrono::{DateTime, Local},
    crossbeam_channel::{unbounded, Receiver, SendError, Sender, TryRecvError},
    rolling_file::{RollingCondition, RollingConditionBasic, RollingFileAppender},
    solana_perf::{packet::{PacketBatch, to_packet_batches}, test_tx::test_tx},
    solana_sdk::slot_history::Slot,
    std::{
        fs::{create_dir_all, remove_dir_all, File},
        io::{self, BufReader, Write},
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, sleep, JoinHandle},
        time::{Duration, SystemTime},
    },
    tempfile::TempDir,
    thiserror::Error,
};

pub type BankingPacketBatch = Arc<(Vec<PacketBatch>, Option<SigverifyTracerPacketStats>)>;
pub type BankingPacketSender = TracedSender;
pub type BankingPacketReceiver = Receiver<BankingPacketBatch>;
pub type TracerThreadResult = Result<(), TraceError>;

#[derive(Error, Debug)]
pub enum TraceError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization Error: {0}")]
    SerializeError(#[from] bincode::Error),
}

const BASENAME: &'static str = "events";
const TRACE_FILE_ROTATE_COUNT: u64 = 14;
const TRACE_FILE_WRITE_INTERVAL_MS: u64 = 100;
const BUF_WRITER_CAPACITY: usize = 10 * 1024 * 1024;
pub const TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD: u64 = 1024 * 1024 * 1024;
pub const EMPTY_BANKING_TRACE_SIZE: u64 = 0;
pub const DEFAULT_BANKING_TRACE_SIZE: u64 =
    TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD * TRACE_FILE_ROTATE_COUNT;

#[allow(clippy::type_complexity)]
#[derive(Debug)]
pub struct BankingTracer {
    enabled_tracer: Option<(
        (Sender<TimedTracedEvent>, Receiver<TimedTracedEvent>),
        Option<JoinHandle<TracerThreadResult>>,
    )>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TimedTracedEvent(std::time::SystemTime, TracedEvent);

#[derive(Serialize, Deserialize, Debug)]
enum TracedEvent {
    Bank(Slot, u32, BankStatus, usize),
    PacketBatch(ChannelLabel, BankingPacketBatch),
}

#[derive(Serialize, Deserialize, Debug)]
enum BankStatus {
    Started,
    Ended,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum ChannelLabel {
    NonVote,
    TpuVote,
    GossipVote,
    Dummy,
}

struct RollingConditionGrouped {
    basic: RollingConditionBasic,
    is_checked: bool,
}

impl RollingConditionGrouped {
    fn new(basic: RollingConditionBasic) -> Self {
        Self {
            basic,
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

pub fn sender_overhead_minimized_receiver_loop<T, E, const SLEEP_MS: u64>(
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
                    assert_eq!(receiver.len(), 0);
                    break 'outer;
                }
            };
        }
        sleep(Duration::from_millis(SLEEP_MS));
    }

    Ok(())
}

impl BankingTracer {
    pub fn new(maybe_config: Option<(PathBuf, Arc<AtomicBool>, u64)>) -> Result<Self, TraceError> {
        let enabled_tracer = maybe_config
            .map(|(path, exit, total_size)| -> Result<_, TraceError> {
                let rotate_threshold_size = total_size / TRACE_FILE_ROTATE_COUNT;
                assert!(rotate_threshold_size > 0);

                let sender_and_receiver = unbounded();
                let trace_receiver = sender_and_receiver.1.clone();

                Self::ensure_prepare_path(&path)?;
                let file_appender = Self::create_file_appender(path, rotate_threshold_size)?;

                let tracing_thread =
                    Self::spawn_background_thread(trace_receiver, file_appender, exit)?;

                Ok((sender_and_receiver, Some(tracing_thread)))
            })
            .transpose()?;

        Ok(Self { enabled_tracer })
    }

    pub fn new_disabled() -> Self {
        Self {
            enabled_tracer: None,
        }
    }

    fn create_channel(&self, label: ChannelLabel) -> (BankingPacketSender, BankingPacketReceiver) {
        Self::channel(
            label,
            self.enabled_tracer
                .as_ref()
                .map(|((sender, _), _)| sender.clone()),
        )
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

    pub fn finalize_under_arc(mut self) -> (Option<JoinHandle<TracerThreadResult>>, Arc<Self>) {
        (
            self.enabled_tracer
                .as_mut()
                .and_then(|(_, tracer)| tracer.take()),
            Arc::new(self),
        )
    }

    fn bank_event(&self, slot: Slot, id: u32, status: BankStatus, unreceived_batch_count: usize) {
        if let Some(((sender, _), _)) = &self.enabled_tracer {
            sender
                .send(TimedTracedEvent(
                    SystemTime::now(),
                    TracedEvent::Bank(slot, id, status, unreceived_batch_count),
                ))
                .unwrap();
        }
    }

    pub fn bank_start(&self, slot: Slot, id: u32, unreceived_batch_count: usize) {
        self.bank_event(slot, id, BankStatus::Started, unreceived_batch_count);
    }

    pub fn bank_end(&self, slot: Slot, id: u32, unreceived_batch_count: usize) {
        self.bank_event(slot, id, BankStatus::Ended, unreceived_batch_count);
    }

    pub fn channel_for_test() -> (TracedSender, Receiver<BankingPacketBatch>) {
        Self::channel(ChannelLabel::Dummy, None)
    }

    pub fn channel(
        label: ChannelLabel,
        trace_sender: Option<Sender<TimedTracedEvent>>,
    ) -> (TracedSender, Receiver<BankingPacketBatch>) {
        let (sender, receiver) = unbounded();
        (TracedSender::new(label, sender, trace_sender), receiver)
    }

    fn ensure_prepare_path(path: &PathBuf) -> Result<(), io::Error> {
        create_dir_all(path)
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
        path: PathBuf,
        rotate_threshold_size: u64,
    ) -> Result<RollingFileAppender<RollingConditionGrouped>, io::Error> {
        let grouped = RollingConditionGrouped::new(
            RollingConditionBasic::new()
                .daily()
                .max_size(rotate_threshold_size),
        );
        RollingFileAppender::new_with_buffer_capacity(
            path.join(BASENAME),
            grouped,
            (TRACE_FILE_ROTATE_COUNT - 1).try_into().unwrap(),
            BUF_WRITER_CAPACITY,
        )
    }

    fn spawn_background_thread(
        trace_receiver: Receiver<TimedTracedEvent>,
        mut file_appender: RollingFileAppender<RollingConditionGrouped>,
        exit: Arc<AtomicBool>,
    ) -> Result<JoinHandle<TracerThreadResult>, TraceError> {
        let thread = thread::Builder::new().name("solBanknTracer".into()).spawn(
            move || -> TracerThreadResult {
                sender_overhead_minimized_receiver_loop::<
                    _,
                    TraceError,
                    TRACE_FILE_WRITE_INTERVAL_MS,
                >(exit, trace_receiver, |event| -> Result<(), TraceError> {
                    file_appender.condition_mut().reset();
                    serialize_into(&mut GroupedWriter::new(&mut file_appender), &event)?;
                    Ok(())
                })?;
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
    trace_sender: Option<Sender<TimedTracedEvent>>,
}

impl TracedSender {
    fn new(
        label: ChannelLabel,
        sender: Sender<BankingPacketBatch>,
        trace_sender: Option<Sender<TimedTracedEvent>>,
    ) -> Self {
        Self {
            label,
            sender,
            trace_sender,
        }
    }

    pub fn send(&self, batch: BankingPacketBatch) -> Result<(), SendError<BankingPacketBatch>> {
        if let Some(trace_sender) = &self.trace_sender {
            trace_sender
                .send(TimedTracedEvent(
                    SystemTime::now(),
                    TracedEvent::PacketBatch(self.label, Arc::clone(&batch)),
                ))
                .unwrap();
        }
        self.sender.send(batch)
    }
}

fn sample_packet_batch() -> BankingPacketBatch {
    BankingPacketBatch::new((to_packet_batches(&vec![test_tx(); 4], 10), None))
}

fn drop_and_clean_temp_dir_unless_suppressed(temp_dir: TempDir) {
    std::env::var("BANKING_TRACE_LEAVE_FILES_FROM_LAST_ITERATION")
        .is_ok()
        .then(|| {
            eprintln!("prevented to remove {:?}", temp_dir.path());
            drop(temp_dir.into_path());
        });
}

fn terminate_tracer(tracer: BankingTracer, main_thread: JoinHandle<TracerThreadResult>, sender: TracedSender) {
    let (tracer_thread, tracer) = tracer.finalize_under_arc();
    drop((sender, tracer));
    main_thread.join().unwrap().unwrap();
    tracer_thread.unwrap().join().unwrap().unwrap();
}

#[cfg(test)]
mod tests {
    use {
        super::*,
    };

    #[test]
    fn test_new_disabled() {
        let exit = Arc::<AtomicBool>::default();

        let tracer = BankingTracer::new_disabled();
        let (non_vote_sender, non_vote_receiver) = tracer.create_channel_non_vote();

        thread::spawn(move || {
            sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
                exit.clone(),
                non_vote_receiver,
                |_packet_batch| Ok(())
            )
        });

        non_vote_sender.send(BankingPacketBatch::new((vec![], None))).unwrap();
    }

    #[test]
    fn test_record_and_restore() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("banking-trace");
        let exit = Arc::<AtomicBool>::default();
        let tracer = BankingTracer::new(Some((
            path,
            exit.clone(),
            u64::max_value(),
        )))
        .unwrap();
        let (non_vote_sender, non_vote_receiver) = tracer.create_channel_non_vote();

        let dummy_main_thread = thread::spawn(move || {
            sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
                exit.clone(),
                non_vote_receiver,
                |_packet_batch| Ok(())
            )
        });

        non_vote_sender.send(sample_packet_batch()).unwrap();
        tracer.bank_start(1, 2, 3);
        terminate_tracer(tracer, dummy_main_thread, non_vote_sender);

        drop_and_clean_temp_dir_unless_suppressed(temp_dir);

        let mut stream = BufReader::new(File::open(path.join(BASENAME)).unwrap());
        let d = bincode::deserialize_from::<_, TimedTracedEvent>(&mut stream);
        dbg!(d);
    }
}

pub struct BankingTraceReplayer {
    path: PathBuf,
    non_vote_channel: (Sender<BankingPacketBatch>, Receiver<BankingPacketBatch>),
    tpu_vote_channel: (Sender<BankingPacketBatch>, Receiver<BankingPacketBatch>),
    gossip_vote_channel: (Sender<BankingPacketBatch>, Receiver<BankingPacketBatch>),
}

impl BankingTraceReplayer {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            non_vote_channel: unbounded(),
            tpu_vote_channel: unbounded(),
            gossip_vote_channel: unbounded(),
        }
    }

    pub fn prepare_receivers(
        &self,
    ) -> (
        Receiver<BankingPacketBatch>,
        Receiver<BankingPacketBatch>,
        Receiver<BankingPacketBatch>,
    ) {
        (
            self.non_vote_channel.1.clone(),
            self.tpu_vote_channel.1.clone(),
            self.gossip_vote_channel.1.clone(),
        )
    }

    pub fn replay(
        &self,
        bank_forks: Arc<std::sync::RwLock<solana_runtime::bank_forks::BankForks>>,
        blockstore: Arc<solana_ledger::blockstore::Blockstore>,
    ) {
        use {
            crate::banking_stage::BankingStage, log::*,
            solana_client::connection_cache::ConnectionCache, solana_gossip::cluster_info::Node,
            solana_ledger::leader_schedule_cache::LeaderScheduleCache,
            solana_poh::poh_recorder::create_test_recorder, solana_runtime::bank::Bank,
            solana_sdk::signature::Keypair, solana_streamer::socket::SocketAddrSpace,
            solana_tpu_client::tpu_connection_cache::DEFAULT_TPU_CONNECTION_POOL_SIZE,
        };

        let mut bank = bank_forks.read().unwrap().working_bank();
        let mut stream = BufReader::new(File::open(&self.path).unwrap());
        let mut bank_starts_by_slot = std::collections::BTreeMap::new();
        let mut packet_batches_by_time = std::collections::BTreeMap::new();

        loop {
            let d = bincode::deserialize_from::<_, TimedTracedEvent>(&mut stream);
            let Ok(event) = d else {
                dbg!(&d);
                break;
            };
            //dbg!(&event);
            let s = event.0;
            match event.1 {
                TracedEvent::Bank(slot, _, BankStatus::Started, _) => {
                    bank_starts_by_slot.insert(slot, s);
                }
                TracedEvent::PacketBatch(label, batch) => {
                    packet_batches_by_time.insert(s, (label, batch));
                }
                _ => {}
            }
        }

        let (non_vote_sender, tpu_vote_sender, gossip_vote_sender) = (
            self.non_vote_channel.0.clone(),
            self.tpu_vote_channel.0.clone(),
            self.gossip_vote_channel.0.clone(),
        );
        let bank_slot = bank.slot();

        std::thread::spawn(move || {
            let range_iter = if let Some(start) = &bank_starts_by_slot.get(&bank_slot) {
                packet_batches_by_time.range(*start..)
            } else {
                packet_batches_by_time.range(..)
            };
            info!(
                "replaying events: {} out of {}",
                range_iter.clone().count(),
                packet_batches_by_time.len()
            );

            loop {
                for (&_key, ref value) in range_iter.clone() {
                    let (label, batch) = &value;
                    info!("sent {:?} {} batches", label, batch.0.len());

                    match label {
                        ChannelLabel::NonVote => non_vote_sender.send(batch.clone()).unwrap(),
                        ChannelLabel::TpuVote => tpu_vote_sender.send(batch.clone()).unwrap(),
                        ChannelLabel::GossipVote => gossip_vote_sender.send(batch.clone()).unwrap(),
                        ChannelLabel::Dummy => unreachable!(),
                    }
                }
            }
        });

        let (non_vote_receiver, tpu_vote_receiver, gossip_vote_receiver) = self.prepare_receivers();

        let collector = solana_sdk::pubkey::new_rand();
        let leader_schedule_cache = Arc::new(LeaderScheduleCache::new_from_bank(&bank));
        let (exit, poh_recorder, poh_service, _signal_receiver) =
            create_test_recorder(&bank, &blockstore, None, Some(leader_schedule_cache));

        let banking_tracer = BankingTracer::new_disabled();
        let cluster_info = solana_gossip::cluster_info::ClusterInfo::new(
            Node::new_localhost().info,
            Arc::new(Keypair::new()),
            SocketAddrSpace::Unspecified,
        );
        let cluster_info = Arc::new(cluster_info);
        let connection_cache = ConnectionCache::new(DEFAULT_TPU_CONNECTION_POOL_SIZE);
        let (replay_vote_sender, _replay_vote_receiver) = unbounded();
        let banking_stage = BankingStage::new_num_threads(
            &cluster_info,
            &poh_recorder,
            non_vote_receiver,
            tpu_vote_receiver,
            gossip_vote_receiver,
            4,
            None,
            replay_vote_sender,
            None,
            Arc::new(connection_cache),
            bank_forks.clone(),
            banking_tracer,
        );

        bank.skip_check_age();

        bank.clear_signatures();
        poh_recorder.write().unwrap().set_bank(&bank, false);

        for _ in 0..10 {
            if poh_recorder.read().unwrap().bank().is_none() {
                poh_recorder
                    .write()
                    .unwrap()
                    .reset(bank.clone(), Some((bank.slot(), bank.slot() + 1)));
                let new_bank = Bank::new_from_parent(&bank, &collector, bank.slot() + 1);
                bank_forks.write().unwrap().insert(new_bank);
                bank = bank_forks.read().unwrap().working_bank();
            }
            // set cost tracker limits to MAX so it will not filter out TXs
            bank.write_cost_tracker().unwrap().set_limits(
                std::u64::MAX,
                std::u64::MAX,
                std::u64::MAX,
            );

            bank.clear_signatures();
            poh_recorder.write().unwrap().set_bank(&bank, false);

            sleep(std::time::Duration::from_millis(100));
        }
        exit.store(true, Ordering::Relaxed);
        banking_stage.join().unwrap();
        poh_service.join().unwrap();
    }
}
