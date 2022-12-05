use {
    crate::{
        sigverify::SigverifyTracerPacketStats,
    },
    crossbeam_channel::{
        Receiver as CrossbeamReceiver, RecvTimeoutError, Sender as CrossbeamSender, unbounded,
    },
};
use std::path::Path;
use solana_perf::packet::PacketBatch;
use rolling_file::{RollingFileAppender, RollingConditionBasic};

pub type BankingPacketBatch = (Vec<PacketBatch>, Option<SigverifyTracerPacketStats>);
pub type BankingPacketSender = TracedBankingPacketSender;
type RealBankingPacketSender = CrossbeamSender<BankingPacketBatch>;
pub type BankingPacketReceiver = CrossbeamReceiver<BankingPacketBatch>;

pub struct BankingTracer {
   trace_output: Option<((crossbeam_channel::Sender<TimedTracedEvent>, crossbeam_channel::Receiver<TimedTracedEvent>), RollingFileAppender<RollingConditionBasic>)>,
}

struct TimedTracedEvent(u64, TracedEvent);

enum TracedEvent {
    BankStart,
    PacketBatch(BankingPacketBatch),
}

impl BankingTracer {
    pub fn new(path: impl AsRef<Path>, enable_tracing: bool) -> Result<Self, std::io::Error> {
        let trace_output = if enable_tracing {
            let a = unbounded();
            let output = RollingFileAppender::new(path, RollingConditionBasic::new().daily().max_size(1024 * 1024 * 1024), 10)?;

            Some((a, output))
        } else {
            None
        };

        /*
        if let Some(trace_output) = trace_output {
        }
        */

        Ok(Self {
            trace_output,
        })
    }

    pub fn create_channel(&self, name: &'static str) -> (BankingPacketSender, BankingPacketReceiver) {
        let channel = unbounded();
        (TracedBankingPacketSender::new(channel.0, None, name), channel.1)
    }
}

pub struct TracedBankingPacketSender {
    sender_to_banking: RealBankingPacketSender,
    mirrored_sender_to_trace: Option<CrossbeamSender<TimedTracedEvent>>,
    name: &'static str,
}

impl TracedBankingPacketSender {
    fn new(sender_to_banking: RealBankingPacketSender, mirrored_sender_to_trace: Option<RealBankingPacketSender>, name: &'static str) -> Self {
        Self {
            sender_to_banking,
            mirrored_sender_to_trace,
            name,
        }
    }

    pub fn send(&self, batch: BankingPacketBatch) -> std::result::Result<(), crossbeam_channel::SendError<BankingPacketBatch>> {
        self.sender_to_banking.send(batch.clone()).and_then(|r| {
            if let Some(mirror) = &self.mirrored_sender_to_trace {
                mirror.send(batch)
            } else {
                Ok(())
            }
        } )
    }
}
