use {
    crate::{
        sigverify::SigverifyTracerPacketStats,
    },
    crossbeam_channel::{
        Receiver as CrossbeamReceiver, RecvTimeoutError, Sender as CrossbeamSender, unbounded,
    },
};
use std::path::Path;
use std::sync::{Arc, atomic::AtomicBool};
use solana_perf::packet::PacketBatch;
use rolling_file::{RollingFileAppender, RollingConditionBasic};
use bincode::serialize_into;

pub type BankingPacketBatch = (Vec<PacketBatch>, Option<SigverifyTracerPacketStats>);
pub type BankingPacketSender = TracedBankingPacketSender;
type RealBankingPacketSender = CrossbeamSender<BankingPacketBatch>;
pub type BankingPacketReceiver = CrossbeamReceiver<BankingPacketBatch>;

pub struct BankingTracer {
   trace_output: Option<((crossbeam_channel::Sender<TimedTracedEvent>, crossbeam_channel::Receiver<TimedTracedEvent>), std::thread::JoinHandle<()>)>,
   exit: Arc<AtomicBool>,
}

#[derive(Serialize)]
struct TimedTracedEvent(u64, TracedEvent);

#[derive(Serialize)]
enum TracedEvent {
    BankStart,
    PacketBatch(Vec<PacketBatch>),
}

impl BankingTracer {
    pub fn new(path: impl AsRef<Path>, enable_tracing: bool, exit: Arc<AtomicBool>) -> Result<Self, std::io::Error> {
        let path: String = path.into();

        let trace_output = if enable_tracing {
            let a = unbounded();
            let aa = a.1.clone();
            let join_handle = std::thread::Builder::new().name("solBanknTrcr".into()).spawn(move || {
                let mut output = RollingFileAppender::new(path, RollingConditionBasic::new().daily().max_size(1024 * 1024 * 1024), 10).unwrap();
                while let Ok(mm) = aa.recv() {
                    serialize_into(&mut output, &mm).unwrap();
                }
            }).unwrap();

            Some((a, join_handle))
        } else {
            None
        };


        Ok(Self {
            trace_output,
            exit,
        })
    }

    pub fn create_channel(&self, name: &'static str) -> (BankingPacketSender, BankingPacketReceiver) {
        let channel = unbounded();
        (TracedBankingPacketSender::new(channel.0, None, name), channel.1)
    }

    pub fn join(&self) -> std::thread::Result<()> {
        //if let Some(thread_handle) = self.thread_handle {
        //    thread_handle.join()
        //} else {
            Ok(())
        //}
    }
}

pub struct TracedBankingPacketSender {
    sender_to_banking: RealBankingPacketSender,
    mirrored_sender_to_trace: Option<CrossbeamSender<TimedTracedEvent>>,
    name: &'static str,
}

impl TracedBankingPacketSender {
    fn new(sender_to_banking: RealBankingPacketSender, mirrored_sender_to_trace: Option<CrossbeamSender<TimedTracedEvent>>, name: &'static str) -> Self {
        Self {
            sender_to_banking,
            mirrored_sender_to_trace,
            name,
        }
    }

    pub fn send(&self, batch: BankingPacketBatch) -> std::result::Result<(), crossbeam_channel::SendError<BankingPacketBatch>> {
        self.sender_to_banking.send(batch.clone()).and_then(|r| {
            if let Some(mirror) = &self.mirrored_sender_to_trace {
                mirror.send(TimedTracedEvent(0, TracedEvent::PacketBatch(batch.0))).unwrap();
            }
            Ok(())
        } )
    }
}
