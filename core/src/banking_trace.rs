use {
    crate::sigverify::SigverifyTracerPacketStats,
    bincode::serialize_into,
    chrono::{DateTime, Local},
    crossbeam_channel::{unbounded, Receiver, SendError, Sender, TryRecvError},
    rolling_file::{RollingCondition, RollingConditionBasic, RollingFileAppender},
    solana_perf::packet::PacketBatch,
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
};

pub type BankingPacketBatch = Arc<(Vec<PacketBatch>, Option<SigverifyTracerPacketStats>)>;
pub type BankingPacketSender = TracedBankingPacketSender;
type RealBankingPacketSender = Sender<BankingPacketBatch>;
pub type BankingPacketReceiver = Receiver<BankingPacketBatch>;

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
        Option<JoinHandle<()>>,
    )>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TimedTracedEvent(std::time::SystemTime, TracedEvent);

#[derive(Serialize, Deserialize, Debug)]
enum TracedEvent {
    NewBankStart(u32, Slot), // also copy each channel's `.len()`s?
    PacketBatch(String, BankingPacketBatch),
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

pub fn sender_overhead_minimized_receiver_loop<T, const SLEEP_MS: u64>(
    exit: Arc<AtomicBool>,
    receiver: Receiver<T>,
    mut on_recv: impl FnMut(T),
) {
    'outer: while !exit.load(Ordering::Relaxed) {
        'inner: loop {
            // avoid futex-based blocking here, otherwise a sender would have to
            // wake me up at a syscall cost...
            match receiver.try_recv() {
                Ok(message) => on_recv(message),
                Err(TryRecvError::Empty) => break 'inner,
                Err(TryRecvError::Disconnected) => {
                    assert_eq!(receiver.len(), 0);
                    break 'outer;
                }
            }
        }
        sleep(Duration::from_millis(SLEEP_MS));
    }
}

impl BankingTracer {
    pub fn new_with_config(
        maybe_config: Option<(PathBuf, Arc<AtomicBool>, u64)>,
    ) -> Result<Self, io::Error> {
        let enabled_tracer = maybe_config
            .map(|(path, exit, total_size)| -> Result<_, io::Error> {
                let roll_threshold_size = total_size / TRACE_FILE_ROTATE_COUNT;
                assert!(roll_threshold_size > 0);

                Self::ensure_prepare_path(&path)?;
                let grouped = RollingConditionGrouped::new(
                    RollingConditionBasic::new()
                        .daily()
                        .max_size(roll_threshold_size),
                );
                let sender_and_receiver = unbounded();
                let trace_receiver = sender_and_receiver.1.clone();
                let file_appender = RollingFileAppender::new_with_buffer_capacity(
                    path.join("events"),
                    grouped,
                    (TRACE_FILE_ROTATE_COUNT - 1).try_into().unwrap(),
                    BUF_WRITER_CAPACITY,
                )?;
                let tracing_thread =
                    Self::spawn_background_thread(trace_receiver, file_appender, exit);

                Ok((sender_and_receiver, Some(tracing_thread)))
            })
            .transpose()?;

        Ok(Self { enabled_tracer })
    }

    pub fn new_disabled() -> Self {
        Self::new_with_config(None).unwrap()
    }

    fn create_channel(&self, name: &'static str) -> (BankingPacketSender, BankingPacketReceiver) {
        Self::channel(
            name,
            self.enabled_tracer
                .as_ref()
                .map(|((sender, _), _)| sender.clone()),
        )
    }

    pub fn create_channel_non_vote(&self) -> (BankingPacketSender, BankingPacketReceiver) {
        self.create_channel("non-vote")
    }

    pub fn create_channel_tpu_vote(&self) -> (BankingPacketSender, BankingPacketReceiver) {
        self.create_channel("tpu-vote")
    }

    pub fn create_channel_gossip_vote(&self) -> (BankingPacketSender, BankingPacketReceiver) {
        self.create_channel("gossip-vote")
    }

    pub fn finalize_under_arc(mut self) -> (Option<JoinHandle<()>>, Arc<Self>) {
        (
            self.enabled_tracer
                .as_mut()
                .and_then(|(_, tracer)| tracer.take()),
            Arc::new(self),
        )
    }

    pub fn new_bank_start(&self, id: u32, slot: Slot) {
        if let Some(((sender, _), _)) = &self.enabled_tracer {
            sender
                .send(TimedTracedEvent(
                    SystemTime::now(),
                    TracedEvent::NewBankStart(id, slot),
                ))
                .unwrap();
        }
    }

    pub fn channel_for_test() -> (TracedBankingPacketSender, Receiver<BankingPacketBatch>) {
        Self::channel("_dummy_name_for_test", None)
    }

    pub fn channel(
        name: &'static str,
        trace_sender: Option<Sender<TimedTracedEvent>>,
    ) -> (TracedBankingPacketSender, Receiver<BankingPacketBatch>) {
        let (sender, receiver) = unbounded();
        (
            TracedBankingPacketSender::new(name, sender, trace_sender),
            receiver,
        )
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

    fn spawn_background_thread(
        trace_receiver: Receiver<TimedTracedEvent>,
        mut file_appender: RollingFileAppender<RollingConditionGrouped>,
        exit: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("solBanknTracer".into())
            .spawn(move || {
                sender_overhead_minimized_receiver_loop::<_, TRACE_FILE_WRITE_INTERVAL_MS>(
                    exit,
                    trace_receiver,
                    |event| {
                        file_appender.condition_mut().reset();
                        serialize_into(&mut GroupedWriter::new(&mut file_appender), &event)
                            .unwrap();
                    },
                );
                file_appender.flush().unwrap();
            })
            .unwrap()
    }
}

pub struct TracedBankingPacketSender {
    name: &'static str,
    sender: RealBankingPacketSender,
    trace_sender: Option<Sender<TimedTracedEvent>>,
}

impl TracedBankingPacketSender {
    fn new(
        name: &'static str,
        sender: RealBankingPacketSender,
        trace_sender: Option<Sender<TimedTracedEvent>>,
    ) -> Self {
        Self {
            name,
            sender,
            trace_sender,
        }
    }

    pub fn send(&self, batch: BankingPacketBatch) -> Result<(), SendError<BankingPacketBatch>> {
        if let Some(trace_sender) = &self.trace_sender {
            trace_sender
                .send(TimedTracedEvent(
                    SystemTime::now(),
                    TracedEvent::PacketBatch(self.name.into(), Arc::clone(&batch)),
                ))
                .unwrap();
        }
        self.sender.send(batch)
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
                TracedEvent::NewBankStart(_, slot) => {
                    bank_starts_by_slot.insert(slot, s);
                }
                TracedEvent::PacketBatch(name, batch) => {
                    packet_batches_by_time.insert(s, (name, batch));
                }
            }
        }

        let (non_vote_sender, gossip_vote_sender, tpu_vote_sender) = (
            self.non_vote_channel.0.clone(),
            self.gossip_vote_channel.0.clone(),
            self.tpu_vote_channel.0.clone(),
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
                    let (name, batch) = &value;
                    info!("sent {} {} batches", name, batch.0.len());

                    match name.as_str() {
                        "non-vote" => non_vote_sender.send(batch.clone()).unwrap(),
                        "gossip-vote" => gossip_vote_sender.send(batch.clone()).unwrap(),
                        "tpu-vote" => tpu_vote_sender.send(batch.clone()).unwrap(),
                        a => panic!("unknown: {}", a),
                    }
                }
            }
        });

        let (verified_receiver, tpu_vote_receiver, gossip_vote_receiver) = self.prepare_receivers();

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
            verified_receiver,
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
