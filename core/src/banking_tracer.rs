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
pub type BankingPacketSender = TracedSender;
pub type RealBankingPacketSender = CrossbeamSender<BankingPacketBatch>;
pub type BankingPacketReceiver = CrossbeamReceiver<BankingPacketBatch>;

#[derive(Default)]
pub struct BankingTracer {
    tracing_enabled: bool,
}

impl BankingTracer {
    pub fn create_channel(&self) -> (BankingPacketSender, BankingPacketReceiver) {
        let a = unbounded();
        (TracedSender::new(a.0), a.1)
    }
}

pub struct TracedSender {
    sender_to_banking: RealBankingPacketSender,
    mirrored_sender_to_trace: Option<RealBankingPacketSender>,
}

impl TracedSender<RealBankingPacketSender> {
    fn new(sender_to_banking: RealBankingPacketSender) -> Self {
        Self {
            sender_to_banking,
            mirrored_sender_to_trace: None,
        }
    }
}
