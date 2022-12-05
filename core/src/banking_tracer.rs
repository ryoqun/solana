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
pub type BankingPacketSender = TracedSender<CrossbeamSender<BankingPacketBatch>>;
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

pub struct TracedSender<T> {
    sender_to_banking: T,
    mirrored_sender_to_trace: Option<T>,
}

impl<T> TracedSender<T> {
    fn new(sender_to_banking: T) -> Self {
        Self {
            sender_to_banking: T,
            mirrored_sender_to_trace: None,
        }
    }
}
