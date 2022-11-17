//! The `shred_fetch_stage` pulls shreds from UDP sockets and sends it to a channel.

use {
    crate::{packet_hasher::PacketHasher, serve_repair::ServeRepair},
    crossbeam_channel::{unbounded, Sender},
    lru::LruCache,
    solana_gossip::cluster_info::ClusterInfo,
    solana_ledger::shred::{get_shred_slot_index_type, ShredFetchStats},
    solana_perf::packet::{Packet, PacketBatch, PacketBatchRecycler, PacketFlags},
    solana_runtime::bank_forks::BankForks,
    solana_sdk::clock::{Slot, DEFAULT_MS_PER_SLOT},
    solana_streamer::streamer::{self, PacketBatchReceiver, StreamerReceiveStats},
    std::{
        net::UdpSocket,
        sync::{atomic::AtomicBool, Arc, RwLock},
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

const DEFAULT_LRU_SIZE: usize = 10_000;
pub type ShredsReceived = LruCache<u64, ()>;

pub struct ShredFetchStage {
    thread_hdls: Vec<JoinHandle<()>>,
}

impl ShredFetchStage {
    fn process_packet<F>(
        p: &mut Packet,
        shreds_received: &mut ShredsReceived,
        stats: &mut ShredFetchStats,
        last_root: Slot,
        last_slot: Slot,
        slots_per_epoch: u64,
        modify: &F,
        packet_hasher: &PacketHasher,
    ) where
        F: Fn(&mut Packet),
    {
        p.meta.set_discard(true);
        if let Some((slot, _index, _shred_type)) = get_shred_slot_index_type(p, stats) {
            // Seems reasonable to limit shreds to 2 epochs away
            if slot > last_root && slot < (last_slot + 2 * slots_per_epoch) {
                // Shred filter

                let hash = packet_hasher.hash_packet(p);

                if shreds_received.get(&hash).is_none() {
                    shreds_received.put(hash, ());
                    p.meta.set_discard(false);
                    modify(p);
                } else {
                    stats.duplicate_shred += 1;
                }
            } else {
                stats.slot_out_of_range += 1;
            }
        }
    }

    // updates packets received on a channel and sends them on another channel
    fn modify_packets<F>(
        recvr: PacketBatchReceiver,
        sendr: Sender<Vec<PacketBatch>>,
        bank_forks: Option<Arc<RwLock<BankForks>>>,
        name: &'static str,
        modify: F,
        repair_context: Option<(&UdpSocket, &ClusterInfo)>,
    ) where
        F: Fn(&mut Packet),
    {
        const STATS_SUBMIT_CADENCE: Duration = Duration::from_secs(1);
        let mut shreds_received = LruCache::new(DEFAULT_LRU_SIZE);
        let mut last_updated = Instant::now();
        let mut keypair = repair_context
            .as_ref()
            .map(|(_, cluster_info)| cluster_info.keypair().clone());

        // In the case of bank_forks=None, setup to accept any slot range
        let mut last_root = 0;
        let mut last_slot = std::u64::MAX;
        let mut slots_per_epoch = 0;

        let mut stats = ShredFetchStats::default();
        let mut packet_hasher = PacketHasher::default();

        while let Some(mut packet_batch) = recvr.iter().next() {
            if last_updated.elapsed().as_millis() as u64 > DEFAULT_MS_PER_SLOT {
                last_updated = Instant::now();
                packet_hasher.reset();
                shreds_received.clear();
                if let Some(bank_forks) = bank_forks.as_ref() {
                    let bank_forks_r = bank_forks.read().unwrap();
                    last_root = bank_forks_r.root();
                    let working_bank = bank_forks_r.working_bank();
                    last_slot = working_bank.slot();
                    let root_bank = bank_forks_r.root_bank();
                    slots_per_epoch = root_bank.get_slots_in_epoch(root_bank.epoch());
                }
                keypair = repair_context
                    .as_ref()
                    .map(|(_, cluster_info)| cluster_info.keypair().clone());
            }
            stats.shred_count += packet_batch.len();

            if let Some((udp_socket, _)) = repair_context {
                debug_assert!(keypair.is_some());
                if let Some(ref keypair) = keypair {
                    ServeRepair::handle_repair_response_pings(
                        udp_socket,
                        keypair,
                        &mut packet_batch,
                        &mut stats,
                    );
                }
            }

            packet_batch.iter_mut().for_each(|packet| {
                Self::process_packet(
                    packet,
                    &mut shreds_received,
                    &mut stats,
                    last_root,
                    last_slot,
                    slots_per_epoch,
                    &modify,
                    &packet_hasher,
                );
            });
            stats.maybe_submit(name, STATS_SUBMIT_CADENCE);
            if sendr.send(vec![packet_batch]).is_err() {
                break;
            }
        }
    }

    fn packet_modifier<F>(
        sockets: Vec<Arc<UdpSocket>>,
        exit: &Arc<AtomicBool>,
        sender: Sender<Vec<PacketBatch>>,
        recycler: PacketBatchRecycler,
        bank_forks: Option<Arc<RwLock<BankForks>>>,
        name: &'static str,
        modify: F,
        repair_context: Option<(Arc<UdpSocket>, Arc<ClusterInfo>)>,
    ) -> (Vec<JoinHandle<()>>, JoinHandle<()>)
    where
        F: Fn(&mut Packet) + Send + 'static,
    {
        let (packet_sender, packet_receiver) = unbounded();
        let streamers = sockets
            .into_iter()
            .map(|s| {
                streamer::receiver(
                    s,
                    exit.clone(),
                    packet_sender.clone(),
                    recycler.clone(),
                    Arc::new(StreamerReceiveStats::new("packet_modifier")),
                    1,
                    true,
                    None,
                )
            })
            .collect();
        let modifier_hdl = Builder::new()
            .name("solana-tvu-fetch-stage-packet-modifier".to_string())
            .spawn(move || {
                let repair_context = repair_context
                    .as_ref()
                    .map(|(socket, cluster_info)| (socket.as_ref(), cluster_info.as_ref()));
                Self::modify_packets(
                    packet_receiver,
                    sender,
                    bank_forks,
                    name,
                    modify,
                    repair_context,
                )
            })
            .unwrap();
        (streamers, modifier_hdl)
    }

    pub fn new(
        sockets: Vec<Arc<UdpSocket>>,
        forward_sockets: Vec<Arc<UdpSocket>>,
        repair_socket: Arc<UdpSocket>,
        sender: &Sender<Vec<PacketBatch>>,
        bank_forks: Option<Arc<RwLock<BankForks>>>,
        cluster_info: Arc<ClusterInfo>,
        exit: &Arc<AtomicBool>,
    ) -> Self {
        let recycler = PacketBatchRecycler::warmed(100, 1024);

        let (mut tvu_threads, tvu_filter) = Self::packet_modifier(
            sockets,
            exit,
            sender.clone(),
            recycler.clone(),
            bank_forks.clone(),
            "shred_fetch",
            |_| {},
            None, // repair_context
        );

        let (tvu_forwards_threads, fwd_thread_hdl) = Self::packet_modifier(
            forward_sockets,
            exit,
            sender.clone(),
            recycler.clone(),
            bank_forks.clone(),
            "shred_fetch_tvu_forwards",
            |p| p.meta.flags.insert(PacketFlags::FORWARDED),
            None, // repair_context
        );

        let (repair_receiver, repair_handler) = Self::packet_modifier(
            vec![repair_socket.clone()],
            exit,
            sender.clone(),
            recycler,
            bank_forks,
            "shred_fetch_repair",
            |p| p.meta.flags.insert(PacketFlags::REPAIR),
            Some((repair_socket, cluster_info)),
        );

        tvu_threads.extend(tvu_forwards_threads.into_iter());
        tvu_threads.extend(repair_receiver.into_iter());
        tvu_threads.push(tvu_filter);
        tvu_threads.push(fwd_thread_hdl);
        tvu_threads.push(repair_handler);

        Self {
            thread_hdls: tvu_threads,
        }
    }

    pub fn join(self) -> thread::Result<()> {
        for thread_hdl in self.thread_hdls {
            thread_hdl.join()?;
        }
        Ok(())
    }
}
