#![allow(clippy::implicit_hasher)]

use {
    crate::{
        sigverify,
        sigverify_stage::{SigVerifier, SigVerifyServiceError},
    },
    crossbeam_channel::Sender,
    solana_ledger::{
        leader_schedule_cache::LeaderScheduleCache, shred::Shred,
        sigverify_shreds::verify_shreds_gpu,
    },
    solana_perf::{self, packet::PacketBatch, recycler_cache::RecyclerCache},
    solana_runtime::bank_forks::BankForks,
    std::{
        collections::{HashMap, HashSet},
        sync::{Arc, RwLock},
    },
};

#[derive(Clone)]
pub struct ShredSigVerifier {
    bank_forks: Arc<RwLock<BankForks>>,
    leader_schedule_cache: Arc<LeaderScheduleCache>,
    recycler_cache: RecyclerCache,
    packet_sender: Sender<Vec<PacketBatch>>,
}

impl ShredSigVerifier {
    pub fn new(
        bank_forks: Arc<RwLock<BankForks>>,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        packet_sender: Sender<Vec<PacketBatch>>,
    ) -> Self {
        sigverify::init();
        Self {
            bank_forks,
            leader_schedule_cache,
            recycler_cache: RecyclerCache::warmed(),
            packet_sender,
        }
    }
    fn read_slots(batches: &[PacketBatch]) -> HashSet<u64> {
        batches
            .iter()
            .flat_map(|batch| batch.iter().filter_map(Shred::get_slot_from_packet))
            .collect()
    }
}

impl SigVerifier for ShredSigVerifier {
    type SendType = Vec<PacketBatch>;

    fn send_packets(
        &mut self,
        packet_batches: Vec<PacketBatch>,
    ) -> Result<(), SigVerifyServiceError<Self::SendType>> {
        self.packet_sender.send(packet_batches)?;
        Ok(())
    }

    fn verify_batches(
        &self,
        mut batches: Vec<PacketBatch>,
        _valid_packets: usize,
    ) -> Vec<PacketBatch> {
        let r_bank = self.bank_forks.read().unwrap().working_bank();
        let slots: HashSet<u64> = Self::read_slots(&batches);
        let mut leader_slots: HashMap<u64, [u8; 32]> = slots
            .into_iter()
            .filter_map(|slot| {
                let key = self
                    .leader_schedule_cache
                    .slot_leader_at(slot, Some(&r_bank))?;
                Some((slot, key.to_bytes()))
            })
            .collect();
        leader_slots.insert(std::u64::MAX, [0u8; 32]);

        let r = verify_shreds_gpu(&batches, &leader_slots, &self.recycler_cache);
        solana_perf::sigverify::mark_disabled(&mut batches, &r);
        batches
    }
}
