use {
    crate::{
        sigverify::SigverifyTracerPacketStats,
    },
    crossbeam_channel::{
        Receiver as CrossbeamReceiver, RecvTimeoutError, Sender as CrossbeamSender, unbounded,
    },
};
use solana_perf::packet::PacketBatch;

pub type BankingPacketBatch = (Vec<PacketBatch>, Option<SigverifyTracerPacketStats>);
pub type BankingPacketSender = TracedBankingPacketSender;
type RealBankingPacketSender = CrossbeamSender<BankingPacketBatch>;
pub type BankingPacketReceiver = CrossbeamReceiver<BankingPacketBatch>;

pub struct BankingTracer {
   trace_output: Option<rolling_file::RollingFileAppender<rolling_file::RollingConditionBasic>>,
}

impl BankingTracer {
    pub fn new(enable_tracing: bool) -> Result<Self, std::io::Error> {
        let trace_output = enable_tracing.then(|| rolling_file::RollingFileAppender::new("aaa", rolling_file::RollingConditionBasic::new().daily().max_size(1024 * 1024 * 1024), 10));
        Self {
            trace_output,
        }
    }

    pub fn create_channel(&self, name: &'static str) -> (BankingPacketSender, BankingPacketReceiver) {
        let a = unbounded();
        (TracedBankingPacketSender::new(a.0, None, name), a.1)
    }
}

pub struct TracedBankingPacketSender {
    sender_to_banking: RealBankingPacketSender,
    mirrored_sender_to_trace: Option<RealBankingPacketSender>,
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

    pub fn send(&self, a: BankingPacketBatch) -> std::result::Result<(), crossbeam_channel::SendError<BankingPacketBatch>> {
        self.sender_to_banking.send(a.clone()).and_then(|r| {
            if let Some(c) = &self.mirrored_sender_to_trace {
                c.send(a)
            } else {
                Ok(())
            }
        } )
    }
}
