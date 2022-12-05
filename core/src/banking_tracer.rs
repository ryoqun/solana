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
type RealBankingPacketBatch = std::sync::Arc<(Vec<PacketBatch>, Option<SigverifyTracerPacketStats>)>;
pub type BankingPacketSender = TracedBankingPacketSender;
type RealBankingPacketSender = CrossbeamSender<RealBankingPacketBatch>;
pub type BankingPacketReceiver = CrossbeamReceiver<RealBankingPacketBatch>;

#[derive(Default)]
pub struct BankingTracer {
    tracing_enabled: bool,
}

impl BankingTracer {
    pub fn create_channel(&self, name: &'static str) -> (BankingPacketSender, BankingPacketReceiver) {
        let a = unbounded();
        (TracedBankingPacketSender::new(a.0), a.1)
    }
}

pub struct TracedBankingPacketSender {
    sender_to_banking: RealBankingPacketSender,
    mirrored_sender_to_trace: Option<RealBankingPacketSender>,
}

impl TracedBankingPacketSender {
    fn new(sender_to_banking: RealBankingPacketSender) -> Self {
        Self {
            sender_to_banking,
            mirrored_sender_to_trace: None,
        }
    }

    pub fn send(&self, a: BankingPacketBatch) -> std::result::Result<(), crossbeam_channel::SendError<BankingPacketBatch>> {
        let a = std::sync::Arc::new(a);
        self.sender_to_banking.send(a.clone()).and_then(|r| {
            if let Some(c) = &self.mirrored_sender_to_trace {
                c.send(a);
            };
            Ok(())
        } )
    }
}
