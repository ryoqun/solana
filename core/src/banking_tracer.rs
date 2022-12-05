use {
    crate::{
        sigverify::SigverifyTracerPacketStats,
    },
    crossbeam_channel::{
        Receiver as CrossbeamReceiver, RecvTimeoutError, Sender as CrossbeamSender,
    },
};
use solana_perf::packet::PacketBatch;

pub type BankingPacketBatch = (Vec<PacketBatch>, Option<SigverifyTracerPacketStats>);
pub type BankingPacketSender = CrossbeamSender<BankingPacketBatch>;
pub type BankingPacketReceiver = CrossbeamReceiver<BankingPacketBatch>;

#[derive(Default)]
pub struct BankingTracer {
}

impl BankingTracer {
    pub fn create_channel(&self) -> (BankingPacketSender, BankingPacketReceiver) {
    }
}
