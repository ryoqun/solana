use {
    crate::sigverify::SigverifyTracerPacketStats,
    bincode::serialize_into,
    crossbeam_channel::{unbounded, Receiver, SendError, Sender, TryRecvError},
    rolling_file::{RollingCondition, RollingConditionBasic, RollingFileAppender},
    solana_perf::packet::PacketBatch,
    solana_sdk::slot_history::Slot,
    std::{
        fs::{create_dir_all, File},
        io::{BufReader, Write},
        path::PathBuf,
        sync::{atomic::AtomicBool, Arc},
        time::SystemTime,
    },
};

pub type BankingPacketBatch = Arc<(Vec<PacketBatch>, Option<SigverifyTracerPacketStats>)>;
pub type BankingPacketSender = TracedBankingPacketSender;
type RealBankingPacketSender = Sender<BankingPacketBatch>;
pub type BankingPacketReceiver = Receiver<BankingPacketBatch>;

#[derive(Debug)]
pub struct BankingTracer {
    enabled_tracer: Option<(
        (Sender<TimedTracedEvent>, Receiver<TimedTracedEvent>),
        Option<std::thread::JoinHandle<()>>,
    )>,
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
            crate::{banking_stage::BankingStage, banking_trace::BankingTracer},
            crossbeam_channel::unbounded,
            log::*,
            rayon::prelude::*,
            solana_client::connection_cache::ConnectionCache,
            solana_gossip::cluster_info::{Node},
            solana_ledger::{
                leader_schedule_cache::LeaderScheduleCache,
            },
            solana_poh::poh_recorder::create_test_recorder,
            solana_runtime::bank::Bank,
            solana_sdk::{
                signature::Keypair,
            },
            solana_streamer::socket::SocketAddrSpace,
            solana_tpu_client::tpu_connection_cache::DEFAULT_TPU_CONNECTION_POOL_SIZE,
            std::{
                sync::{atomic::Ordering, Arc},
                thread::sleep,
            },
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
            let range_iter = if let Some(start) = &bank_starts_by_slot.get(&bank_slot){
                packet_batches_by_time.range(*start..)
            } else {
                packet_batches_by_time.range(..)
            };
            info!("replaying events: {} out of {}", range_iter.clone().count(), packet_batches_by_time.len());

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
        let (exit, poh_recorder, poh_service, signal_receiver) =
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

#[derive(Serialize, Deserialize, Debug)]
pub struct TimedTracedEvent(std::time::SystemTime, TracedEvent);

#[derive(Serialize, Deserialize, Debug)]
enum TracedEvent {
    NewBankStart(u32, Slot),
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

use chrono::{DateTime, Local};

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
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        self.underlying.write_with_datetime(buf, &self.now)
    }
    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        self.underlying.flush()
    }
}

pub fn sender_overhead_minimized_receiver_loop<T, const SLEEP_MS: u64>(
    exit: Arc<AtomicBool>,
    receiver: Receiver<T>,
    mut on_recv: impl FnMut(T) -> (),
) {
    'outer: while !exit.load(std::sync::atomic::Ordering::Relaxed) {
        'inner: loop {
            // avoid futex-based blocking here, otherwise a sender would have to
            // wake me up at a syscall cost...
            match receiver.try_recv() {
                Ok(message) => on_recv(message),
                Err(TryRecvError::Empty) => break 'inner,
                Err(TryRecvError::Disconnected) => {
                    assert_eq!(receiver.len(), 0);
                    break 'outer;
                },
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(SLEEP_MS));
    };
}

const TRACE_FILE_ROTATE_COUNT: u64 = 14;
const TRACE_FILE_WRITE_INTERVAL_MS: u64 = 100;
const BUF_WRITER_CAPACITY: usize = 10 * 1024 * 1024;
pub const TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD: u64 = 1 * 1024 * 1024 * 1024;
pub const EMPTY_BANKING_TRACE_SIZE: u64 = 0;
pub const DEFAULT_BANKING_TRACE_SIZE: u64 = TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD * TRACE_FILE_ROTATE_COUNT;

impl BankingTracer {
    pub fn new_with_config(
        maybe_config: Option<(PathBuf, Arc<AtomicBool>, u64)>,
    ) -> Result<Self, std::io::Error> {
        let enabled_tracer = maybe_config.map(|(path, exit, total_size)| -> Result<_, std::io::Error> {
            let roll_threshold_size = total_size / TRACE_FILE_ROTATE_COUNT;
            assert!(roll_threshold_size > 0);

            Self::ensure_prepare_path(&path)?;
            let grouped = RollingConditionGrouped::new(
                RollingConditionBasic::new().daily().max_size(roll_threshold_size)
            );
            let mut output = RollingFileAppender::new_with_buffer_capacity(path.join("events"), grouped, (TRACE_FILE_ROTATE_COUNT - 1).try_into().unwrap(), BUF_WRITER_CAPACITY)?;
            let sender_and_receiver = unbounded();
            let trace_receiver = sender_and_receiver.1.clone();
            let tracing_thread = std::thread::Builder::new()
                .name("solBanknTracer".into())
                .spawn(move || {
                    sender_overhead_minimized_receiver_loop::<_, TRACE_FILE_WRITE_INTERVAL_MS>(exit, trace_receiver, |event| {
                        output.condition_mut().reset();
                        serialize_into(&mut GroupedWriter::new(&mut output), &event).unwrap();
                    });
                    output.flush().unwrap();
                })
                .unwrap();

            Ok((sender_and_receiver, Some(tracing_thread)))
        }).transpose()?;

        Ok(Self { enabled_tracer })
    }

    pub fn new_disabled() -> Self {
        Self::new_with_config(None).unwrap()
    }

    pub fn create_channel(
        &self,
        name: &'static str,
    ) -> (BankingPacketSender, BankingPacketReceiver) {
        Self::channel(self.enabled_tracer.as_ref().map(|a| a.0 .0.clone()), name)
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

    pub fn finalize_under_arc(mut self) -> (Option<std::thread::JoinHandle<()>>, Arc<Self>) {
        (
            self.enabled_tracer.as_mut().map(|a| a.1.take()).flatten(),
            Arc::new(self),
        )
    }

    pub fn new_bank_start(&self, id: u32, slot: Slot) {
        if let Some(tracer) = &self.enabled_tracer {
            tracer
                .0
                 .0
                .send(TimedTracedEvent(
                    SystemTime::now(),
                    TracedEvent::NewBankStart(id, slot),
                ))
                .unwrap();
        }
    }

    pub fn channel_for_test() -> (
        TracedBankingPacketSender,
        crossbeam_channel::Receiver<BankingPacketBatch>,
    ) {
        Self::channel(None, "_dummy_name_for_test")
    }

    pub fn channel(
        maybe_mirrored_channel: std::option::Option<crossbeam_channel::Sender<TimedTracedEvent>>,
        name: &'static str,
    ) -> (
        TracedBankingPacketSender,
        crossbeam_channel::Receiver<BankingPacketBatch>,
    ) {
        let channel = unbounded();
        (
            TracedBankingPacketSender::new(channel.0, maybe_mirrored_channel, name),
            channel.1,
        )
    }

    fn ensure_prepare_path(path: &PathBuf) -> Result<(), std::io::Error> {
        create_dir_all(path)
    }

    pub fn ensure_cleanup_path(path: &PathBuf) -> Result<(), std::io::Error> {
        std::fs::remove_dir_all(path).or_else(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(err)
            }
        })
    }
}

// remove Clone derive
#[derive(Clone)]
pub struct TracedBankingPacketSender {
    sender_to_banking: RealBankingPacketSender,
    mirrored_sender_to_trace: Option<Sender<TimedTracedEvent>>,
    name: &'static str,
}

impl TracedBankingPacketSender {
    fn new(
        sender_to_banking: RealBankingPacketSender,
        mirrored_sender_to_trace: Option<Sender<TimedTracedEvent>>,
        name: &'static str,
    ) -> Self {
        Self {
            sender_to_banking,
            mirrored_sender_to_trace,
            name,
        }
    }

    pub fn send(
        &self,
        batch: BankingPacketBatch,
    ) -> std::result::Result<(), SendError<BankingPacketBatch>> {
        if let Some(mirror) = &self.mirrored_sender_to_trace {
            // remove .clone() by using Arc<PacketBatch>
            //let a = Arc::new((batch.0.clone(), None));
            mirror
                .send(TimedTracedEvent(
                    SystemTime::now(),
                    TracedEvent::PacketBatch(self.name.into(), batch.clone() /*a*/),
                ))
                .unwrap();
        }
        self.sender_to_banking.send(batch)
    }
}
