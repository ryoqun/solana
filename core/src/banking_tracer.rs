pub type BankingPacketBatch = (Vec<PacketBatch>, Option<SigverifyTracerPacketStats>);
pub type BankingPacketSender = CrossbeamSender<BankingPacketBatch>;
pub type BankingPacketReceiver = CrossbeamReceiver<BankingPacketBatch>;

#[derive(Default)]
pub struct BankingTracer {
}

impl {
    fn create_channel() -> (BankingPacketSender, BankingPacketReceiver) {
    }
}
