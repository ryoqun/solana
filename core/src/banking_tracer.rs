use {
    crate::sigverify::SigverifyTracerPacketStats,
    bincode::serialize_into,
    crossbeam_channel::{unbounded, Receiver, SendError, Sender},
    rolling_file::{RollingCondition, RollingConditionBasic, RollingFileAppender},
    solana_perf::packet::PacketBatch,
    solana_sdk::slot_history::Slot,
    std::{
        fs::{File, create_dir_all},
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
    trace_output: Option<(
        (Sender<TimedTracedEvent>, Receiver<TimedTracedEvent>),
        Option<std::thread::JoinHandle<()>>,
    )>,
}

pub struct BankingTraceRunner {
    path: PathBuf,
    non_vote_channel: (Sender<BankingPacketBatch>, Receiver<BankingPacketBatch>),
    tpu_vote_channel: (Sender<BankingPacketBatch>, Receiver<BankingPacketBatch>),
    gossip_vote_channel: (Sender<BankingPacketBatch>, Receiver<BankingPacketBatch>),
}

impl BankingTraceRunner {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            non_vote_channel: unbounded(),
            tpu_vote_channel: unbounded(),
            gossip_vote_channel: unbounded(),
        }
    }

    pub fn prepare_receivers(&self) -> (Receiver<BankingPacketBatch>,Receiver<BankingPacketBatch>,  Receiver<BankingPacketBatch>) {
        (self.non_vote_channel.1.clone(),self.tpu_vote_channel.1.clone(),  self.gossip_vote_channel.1.clone())
    }

    pub fn start(&self, bank_forks: Arc<std::sync::RwLock<solana_runtime::bank_forks::BankForks>>, blockstore: Arc<solana_ledger::blockstore::Blockstore>) {
use {
    crossbeam_channel::{unbounded, Receiver},
    log::*,
    rand::{thread_rng, Rng},
    rayon::prelude::*,
    solana_client::connection_cache::ConnectionCache,
    crate::{banking_stage::BankingStage, banking_tracer::BankingTracer},
    solana_gossip::cluster_info::{ClusterInfo, Node},
    solana_ledger::{
        blockstore::Blockstore,
        genesis_utils::{create_genesis_config, GenesisConfigInfo},
        get_tmp_ledger_path,
        leader_schedule_cache::LeaderScheduleCache,
    },
    solana_measure::measure::Measure,
    solana_perf::packet::{to_packet_batches, PacketBatch},
    solana_poh::poh_recorder::{create_test_recorder, PohRecorder, WorkingBankEntry},
    solana_runtime::{bank::Bank, bank_forks::BankForks},
    solana_sdk::{
        compute_budget::ComputeBudgetInstruction,
        hash::Hash,
        message::Message,
        pubkey::{self, Pubkey},
        signature::{Keypair, Signature, Signer},
        system_instruction, system_transaction,
        timing::{duration_as_us, timestamp},
        transaction::Transaction,
    },
    solana_streamer::socket::SocketAddrSpace,
    solana_tpu_client::tpu_connection_cache::DEFAULT_TPU_CONNECTION_POOL_SIZE,
    std::{
        sync::{atomic::Ordering, Arc, RwLock},
        thread::sleep,
        time::{Duration, Instant},
    },
};

        let bank = bank_forks.read().unwrap().working_bank();
        let mut stream = BufReader::new(File::open(&self.path).unwrap());
        let mut bank_starts_by_slot = std::collections::BTreeMap::new();
        let mut packet_batches_by_time = std::collections::BTreeMap::new();

        loop {
            let d = bincode::deserialize_from::<_, TimedTracedEvent>(&mut stream);
            let Ok(event) = d else {
                dbg!(&d);
                break;
            };
            dbg!(&event);
            let s = event.0;
            match event.1 {
                TracedEvent::NewBankStart(_, slot) => { bank_starts_by_slot.insert(slot, s); },
                TracedEvent::PacketBatch(name, batch) => { packet_batches_by_time.insert(s, (name, batch)); },
            }
        }

        for (name, batch) in packet_batches_by_time.values() {
            match name.as_str() {
                "non-vote" => self.non_vote_channel.0.send(batch.clone()).unwrap(),
                "gossip" => self.gossip_vote_channel.0.send(batch.clone()).unwrap(),
                "tpu" => self.tpu_vote_channel.0.send(batch.clone()).unwrap(),
                &_ => panic!(),
            }
        }

                let leader_schedule_cache = Arc::new(LeaderScheduleCache::new_from_bank(&bank));
                let (exit, poh_recorder, poh_service, signal_receiver) =
                    create_test_recorder(&bank, &blockstore, None, Some(leader_schedule_cache));

                let system_monitor_service = SystemMonitorService::new(
                    Arc::clone(&exit),
                    false,
                    false,
                    false,
                    false,
                );

                let banking_tracer =
                    BankingTracer::new(blockstore.banking_tracer_path(), false, exit.clone()).unwrap();
                let cluster_info = solana_gossip::cluster_info::ClusterInfo::new(
                    Node::new_localhost().info,
                    Arc::new(Keypair::new()),
                    SocketAddrSpace::Unspecified,
                );
                let cluster_info = Arc::new(cluster_info);
                let tpu_use_quic = matches.is_present("tpu_use_quic");
                let connection_cache = match tpu_use_quic {
                    true => ConnectionCache::new(DEFAULT_TPU_CONNECTION_POOL_SIZE),
                    false => ConnectionCache::with_udp(DEFAULT_TPU_CONNECTION_POOL_SIZE),
                };
                let banking_stage = BankingStage::new_num_threads(
                    &cluster_info,
                    &poh_recorder,
                    verified_receiver,
                    tpu_vote_receiver,
                    vote_receiver,
                    num_banking_threads,
                    None,
                    replay_vote_sender,
                    None,
                    Arc::new(connection_cache),
                    bank_forks.clone(),
                    banking_tracer,
                );
                poh_recorder.write().unwrap().set_bank(&bank, false);
                loop {
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

                    poh_recorder.write().unwrap().set_bank(&bank, false);
                    info!("sleeping...");
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

struct GroupedWrite<'a> {
    now: DateTime<Local>,
    underlying: &'a mut RollingFileAppender<RollingConditionGrouped>,
}

impl<'a> GroupedWrite<'a> {
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

impl<'a> Write for GroupedWrite<'a> {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        self.underlying.write_with_datetime(buf, &self.now)
    }
    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        self.underlying.flush()
    }
}

pub fn sender_overhead_minimized_loop<T>(
    exit: Arc<AtomicBool>,
    receiver: crossbeam_channel::Receiver<T>,
    mut on_recv: impl FnMut(T) -> (),
) {
    while !exit.load(std::sync::atomic::Ordering::Relaxed) {
        while let Ok(mm) = receiver.try_recv() {
            on_recv(mm);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

impl BankingTracer {
    pub fn _new(
        path: PathBuf,
        enable_tracing: bool,
        exit: Arc<AtomicBool>,
        max_size: u64,
    ) -> Result<Self, std::io::Error> {
        create_dir_all(&path)?;
        let basic = RollingConditionBasic::new().daily().max_size(max_size);
        let grouped = RollingConditionGrouped::new(basic);
        let mut output = RollingFileAppender::new(path.join("events"), grouped, 10)?;

        let trace_output = if enable_tracing {
            let a = unbounded();
            let receiver = a.1.clone();
            let join_handle = std::thread::Builder::new()
                .name("solBanknTracer".into())
                .spawn(move || {
                    // custom RollingCondition to memoize the first rolling decision
                    sender_overhead_minimized_loop(exit, receiver, |mm| {
                        output.condition_mut().reset();
                        serialize_into(&mut GroupedWrite::new(&mut output), &mm).unwrap();
                    });
                    output.flush().unwrap();
                })
                .unwrap();

            Some((a, Some(join_handle)))
        } else {
            None
        };

        Ok(Self { trace_output })
    }

    pub fn new(
        path: PathBuf,
        enable_tracing: bool,
        exit: Arc<AtomicBool>,
    ) -> Result<Self, std::io::Error> {
        Self::_new(path, enable_tracing, exit, 1024 * 1024 * 1024)
    }

    pub fn new_for_test() -> Self {
        Self::new(PathBuf::new(), false, Arc::default()).unwrap()
    }

    pub fn create_channel(
        &self,
        name: &'static str,
    ) -> (BankingPacketSender, BankingPacketReceiver) {
        Self::channel(self.trace_output.as_ref().map(|a| a.0 .0.clone()), name)
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
            self.trace_output.as_mut().map(|a| a.1.take()).flatten(),
            Arc::new(self),
        )
    }

    pub fn new_bank_start(&self, id: u32, slot: Slot) {
        if let Some(trace_output) = &self.trace_output {
            trace_output
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
                    TracedEvent::PacketBatch(self.name.into(), batch.clone()/*a*/),
                ))
                .unwrap();
        }
        self.sender_to_banking.send(batch)
    }
}
