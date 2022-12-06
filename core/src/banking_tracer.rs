use {
    crate::{
        sigverify::SigverifyTracerPacketStats,
    },
    crossbeam_channel::{
        Receiver, Sender, unbounded, SendError,
    },
};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::SystemTime;
use std::io::Write;
use std::path::PathBuf;
use std::fs::create_dir_all;
use solana_perf::packet::PacketBatch;
use rolling_file::{RollingFileAppender, RollingConditionBasic, RollingCondition};
use bincode::serialize_into;
use solana_sdk::slot_history::Slot;

pub type BankingPacketBatch = (Vec<PacketBatch>, Option<SigverifyTracerPacketStats>);
pub type BankingPacketSender = TracedBankingPacketSender;
type RealBankingPacketSender = Sender<BankingPacketBatch>;
pub type BankingPacketReceiver = Receiver<BankingPacketBatch>;

#[derive(Debug)]
pub struct BankingTracer {
   trace_output: Option<((Sender<TimedTracedEvent>, Receiver<TimedTracedEvent>), Option<std::thread::JoinHandle<()>>)>,
}

#[derive(Serialize, Deserialize)]
struct TimedTracedEvent(std::time::SystemTime, TracedEvent);

#[derive(Serialize, Deserialize)]
enum TracedEvent {
    NewBankStart(Slot),
    PacketBatch(String, Vec<PacketBatch>),
}

struct GroupedWrite {
}

impl RollingCondition for GroupedWrite {
    fn should_rollover(&mut self, _: &DateTime<chrono::Local>, _: u64) -> bool { todo!() }
}

impl Write for GroupedWrite {
}

impl BankingTracer {
    pub fn new(path: PathBuf, enable_tracing: bool, exit: Arc<AtomicBool>) -> Result<Self, std::io::Error> {
        create_dir_all(&path)?;
        let mut output = RollingFileAppender::new(path.join("events"), RollingConditionBasic::new().daily().max_size(1024 * 1024 * 1024), 10)?;

        let trace_output = if enable_tracing {
            let a = unbounded();
            let receiver = a.1.clone();
            let join_handle = std::thread::Builder::new().name("solBanknTracer".into()).spawn(move || {
                // temporary custom Write impl to avoid repeatd current time inqueries =>
                // GroupedWrite
                // custom RollingCondition to memoize the first rolling decision
                while !exit.load(std::sync::atomic::Ordering::Relaxed) {
                    while let Ok(mm) = receiver.try_recv() {
                        serialize_into(&mut output, &mm).unwrap();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                output.flush().unwrap();
            }).unwrap();

            Some((a, Some(join_handle)))
        } else {
            None
        };


        Ok(Self {
            trace_output,
        })
    }

    pub fn create_channel(&self, name: &'static str) -> (BankingPacketSender, BankingPacketReceiver) {
        let channel = unbounded();
        (TracedBankingPacketSender::new(channel.0, self.trace_output.as_ref().map(|a| a.0.0.clone()), name), channel.1)
    }

    pub fn finalize_under_arc(mut self) -> (Option<std::thread::JoinHandle<()>>, Arc<Self>) {
        (self.trace_output.as_mut().map(|a| a.1.take()).flatten(), Arc::new(self))
    }

    pub fn new_bank_start(&self, slot: Slot) {
        if let Some(trace_output) = &self.trace_output {
            trace_output.0.0.send(TimedTracedEvent(SystemTime::now(), TracedEvent::NewBankStart(slot))).unwrap();
        }
    }
}

pub struct TracedBankingPacketSender {
    sender_to_banking: RealBankingPacketSender,
    mirrored_sender_to_trace: Option<Sender<TimedTracedEvent>>,
    name: &'static str,
}

impl TracedBankingPacketSender {
    fn new(sender_to_banking: RealBankingPacketSender, mirrored_sender_to_trace: Option<Sender<TimedTracedEvent>>, name: &'static str) -> Self {
        Self {
            sender_to_banking,
            mirrored_sender_to_trace,
            name,
        }
    }

    pub fn send(&self, batch: BankingPacketBatch) -> std::result::Result<(), SendError<BankingPacketBatch>> {
        // remove .clone() by using Arc<PacketBatch>
        self.sender_to_banking.send(batch.clone()).and_then(|_| {
            if let Some(mirror) = &self.mirrored_sender_to_trace {
                mirror.send(TimedTracedEvent(SystemTime::now(), TracedEvent::PacketBatch(self.name.into(), batch.0))).unwrap();
            }
            Ok(())
        } )
    }
}
