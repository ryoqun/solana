use {
    crate::{
        cluster_slots::ClusterSlots,
        duplicate_repair_status::ANCESTOR_HASH_REPAIR_SAMPLE_SIZE,
        packet_threshold::DynamicPacketToProcessThreshold,
        repair_response,
        repair_service::{OutstandingShredRepairs, RepairStats, REPAIR_MS},
        request_response::RequestResponse,
        result::{Error, Result},
    },
    bincode::serialize,
    lru::LruCache,
    rand::{
        distributions::{Distribution, WeightedError, WeightedIndex},
        Rng,
    },
    solana_gossip::{
        cluster_info::{ClusterInfo, ClusterInfoError},
        contact_info::ContactInfo,
        ping_pong::{self, PingCache, Pong},
        weighted_shuffle::WeightedShuffle,
    },
    solana_ledger::{
        ancestor_iterator::{AncestorIterator, AncestorIteratorWithHash},
        blockstore::Blockstore,
        shred::{Nonce, Shred, ShredFetchStats, SIZE_OF_NONCE},
    },
    solana_metrics::inc_new_counter_debug,
    solana_perf::packet::{Packet, PacketBatch, PacketBatchRecycler},
    solana_runtime::{bank::Bank, bank_forks::BankForks},
    solana_sdk::{
        clock::Slot,
        feature_set::sign_repair_requests,
        hash::{Hash, HASH_BYTES},
        packet::PACKET_DATA_SIZE,
        pubkey::{Pubkey, PUBKEY_BYTES},
        signature::{Signable, Signature, Signer, SIGNATURE_BYTES},
        signer::keypair::Keypair,
        stake_history::Epoch,
        timing::{duration_as_ms, timestamp},
    },
    solana_streamer::{
        sendmmsg::{batch_send, SendPktsError},
        streamer::{PacketBatchReceiver, PacketBatchSender},
    },
    std::{
        collections::{HashMap, HashSet},
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

type SlotHash = (Slot, Hash);

/// the number of slots to respond with when responding to `Orphan` requests
pub const MAX_ORPHAN_REPAIR_RESPONSES: usize = 10;
// Number of slots to cache their respective repair peers and sampling weights.
pub(crate) const REPAIR_PEERS_CACHE_CAPACITY: usize = 128;
// Limit cache entries ttl in order to avoid re-using outdated data.
const REPAIR_PEERS_CACHE_TTL: Duration = Duration::from_secs(10);
pub const MAX_ANCESTOR_BYTES_IN_PACKET: usize =
    PACKET_DATA_SIZE -
    SIZE_OF_NONCE -
    4 /*(response version enum discriminator)*/ -
    4 /*slot_hash length*/;
pub const MAX_ANCESTOR_RESPONSES: usize =
    MAX_ANCESTOR_BYTES_IN_PACKET / std::mem::size_of::<SlotHash>();
/// Number of bytes in the randomly generated token sent with ping messages.
pub(crate) const REPAIR_PING_TOKEN_SIZE: usize = HASH_BYTES;
pub const REPAIR_PING_CACHE_CAPACITY: usize = 65536;
pub const REPAIR_PING_CACHE_TTL: Duration = Duration::from_secs(1280);
const REPAIR_PING_CACHE_RATE_LIMIT_DELAY: Duration = Duration::from_secs(2);
pub(crate) const REPAIR_RESPONSE_SERIALIZED_PING_BYTES: usize =
    4 /*enum discriminator*/ + PUBKEY_BYTES + REPAIR_PING_TOKEN_SIZE + SIGNATURE_BYTES;
const SIGNED_REPAIR_TIME_WINDOW: Duration = Duration::from_secs(60 * 10); // 10 min

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ShredRepairType {
    Orphan(Slot),
    HighestShred(Slot, u64),
    Shred(Slot, u64),
}

impl ShredRepairType {
    pub fn slot(&self) -> Slot {
        match self {
            ShredRepairType::Orphan(slot) => *slot,
            ShredRepairType::HighestShred(slot, _) => *slot,
            ShredRepairType::Shred(slot, _) => *slot,
        }
    }
}

impl RequestResponse for ShredRepairType {
    type Response = Shred;
    fn num_expected_responses(&self) -> u32 {
        match self {
            ShredRepairType::Orphan(_) => (MAX_ORPHAN_REPAIR_RESPONSES + 1) as u32, // run_orphan uses <= MAX_ORPHAN_REPAIR_RESPONSES
            ShredRepairType::HighestShred(_, _) => 1,
            ShredRepairType::Shred(_, _) => 1,
        }
    }
    fn verify_response(&self, response_shred: &Shred) -> bool {
        match self {
            ShredRepairType::Orphan(slot) => response_shred.slot() <= *slot,
            ShredRepairType::HighestShred(slot, index) => {
                response_shred.slot() as u64 == *slot && response_shred.index() as u64 >= *index
            }
            ShredRepairType::Shred(slot, index) => {
                response_shred.slot() as u64 == *slot && response_shred.index() as u64 == *index
            }
        }
    }
}

pub struct AncestorHashesRepairType(pub Slot);
impl AncestorHashesRepairType {
    pub fn slot(&self) -> Slot {
        self.0
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AncestorHashesResponse {
    Hashes(Vec<SlotHash>),
    Ping(Ping),
}

impl RequestResponse for AncestorHashesRepairType {
    type Response = AncestorHashesResponse;
    fn num_expected_responses(&self) -> u32 {
        1
    }
    fn verify_response(&self, response: &AncestorHashesResponse) -> bool {
        match response {
            AncestorHashesResponse::Hashes(hashes) => hashes.len() <= MAX_ANCESTOR_RESPONSES,
            AncestorHashesResponse::Ping(ping) => ping.verify(),
        }
    }
}

#[derive(Default)]
struct ServeRepairStats {
    total_requests: usize,
    unsigned_requests: usize,
    dropped_requests: usize,
    total_response_packets: usize,
    total_response_bytes_staked: usize,
    total_response_bytes_unstaked: usize,
    handle_requests_staked: usize,
    handle_requests_unstaked: usize,
    processed: usize,
    self_repair: usize,
    window_index: usize,
    highest_window_index: usize,
    orphan: usize,
    ancestor_hashes: usize,
    pong: usize,
    err_time_skew: usize,
    err_malformed: usize,
    err_sig_verify: usize,
    err_unsigned: usize,
    err_id_mismatch: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepairRequestHeader {
    signature: Signature,
    sender: Pubkey,
    recipient: Pubkey,
    timestamp: u64,
    nonce: Nonce,
}

impl RepairRequestHeader {
    pub fn new(sender: Pubkey, recipient: Pubkey, timestamp: u64, nonce: Nonce) -> Self {
        Self {
            signature: Signature::default(),
            sender,
            recipient,
            timestamp,
            nonce,
        }
    }
}

pub(crate) type Ping = ping_pong::Ping<[u8; REPAIR_PING_TOKEN_SIZE]>;

/// Window protocol messages
#[derive(Serialize, Deserialize, Debug)]
pub enum RepairProtocol {
    LegacyWindowIndex(ContactInfo, Slot, u64),
    LegacyHighestWindowIndex(ContactInfo, Slot, u64),
    LegacyOrphan(ContactInfo, Slot),
    LegacyWindowIndexWithNonce(ContactInfo, Slot, u64, Nonce),
    LegacyHighestWindowIndexWithNonce(ContactInfo, Slot, u64, Nonce),
    LegacyOrphanWithNonce(ContactInfo, Slot, Nonce),
    LegacyAncestorHashes(ContactInfo, Slot, Nonce),
    Pong(ping_pong::Pong),
    WindowIndex {
        header: RepairRequestHeader,
        slot: Slot,
        shred_index: u64,
    },
    HighestWindowIndex {
        header: RepairRequestHeader,
        slot: Slot,
        shred_index: u64,
    },
    Orphan {
        header: RepairRequestHeader,
        slot: Slot,
    },
    AncestorHashes {
        header: RepairRequestHeader,
        slot: Slot,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum RepairResponse {
    Ping(Ping),
}

impl RepairProtocol {
    fn sender(&self) -> &Pubkey {
        match self {
            Self::LegacyWindowIndex(ci, _, _) => &ci.id,
            Self::LegacyHighestWindowIndex(ci, _, _) => &ci.id,
            Self::LegacyOrphan(ci, _) => &ci.id,
            Self::LegacyWindowIndexWithNonce(ci, _, _, _) => &ci.id,
            Self::LegacyHighestWindowIndexWithNonce(ci, _, _, _) => &ci.id,
            Self::LegacyOrphanWithNonce(ci, _, _) => &ci.id,
            Self::LegacyAncestorHashes(ci, _, _) => &ci.id,
            Self::Pong(pong) => pong.from(),
            Self::WindowIndex { header, .. } => &header.sender,
            Self::HighestWindowIndex { header, .. } => &header.sender,
            Self::Orphan { header, .. } => &header.sender,
            Self::AncestorHashes { header, .. } => &header.sender,
        }
    }

    fn supports_signature(&self) -> bool {
        match self {
            Self::LegacyWindowIndex(_, _, _)
            | Self::LegacyHighestWindowIndex(_, _, _)
            | Self::LegacyOrphan(_, _)
            | Self::LegacyWindowIndexWithNonce(_, _, _, _)
            | Self::LegacyHighestWindowIndexWithNonce(_, _, _, _)
            | Self::LegacyOrphanWithNonce(_, _, _)
            | Self::LegacyAncestorHashes(_, _, _) => false,
            Self::Pong(_)
            | Self::WindowIndex { .. }
            | Self::HighestWindowIndex { .. }
            | Self::Orphan { .. }
            | Self::AncestorHashes { .. } => true,
        }
    }
}

#[derive(Clone)]
pub struct ServeRepair {
    cluster_info: Arc<ClusterInfo>,
    bank_forks: Arc<RwLock<BankForks>>,
}

// Cache entry for repair peers for a slot.
pub(crate) struct RepairPeers {
    asof: Instant,
    peers: Vec<(Pubkey, /*ContactInfo.serve_repair:*/ SocketAddr)>,
    weighted_index: WeightedIndex<u64>,
}

impl RepairPeers {
    fn new(asof: Instant, peers: &[ContactInfo], weights: &[u64]) -> Result<Self> {
        if peers.is_empty() {
            return Err(Error::from(ClusterInfoError::NoPeers));
        }
        if peers.len() != weights.len() {
            return Err(Error::from(WeightedError::InvalidWeight));
        }
        let weighted_index = WeightedIndex::new(weights)?;
        let peers = peers
            .iter()
            .map(|peer| (peer.id, peer.serve_repair))
            .collect();
        Ok(Self {
            asof,
            peers,
            weighted_index,
        })
    }

    fn sample<R: Rng>(&self, rng: &mut R) -> (Pubkey, SocketAddr) {
        let index = self.weighted_index.sample(rng);
        self.peers[index]
    }
}

impl ServeRepair {
    pub fn new(cluster_info: Arc<ClusterInfo>, bank_forks: Arc<RwLock<BankForks>>) -> Self {
        Self {
            cluster_info,
            bank_forks,
        }
    }

    fn my_info(&self) -> ContactInfo {
        self.cluster_info.my_contact_info()
    }

    pub(crate) fn my_id(&self) -> Pubkey {
        self.cluster_info.id()
    }

    fn handle_repair(
        recycler: &PacketBatchRecycler,
        from_addr: &SocketAddr,
        blockstore: Option<&Arc<Blockstore>>,
        request: RepairProtocol,
        stats: &mut ServeRepairStats,
        ping_cache: &mut PingCache,
    ) -> Option<PacketBatch> {
        let now = Instant::now();
        let (res, label) = {
            match &request {
                RepairProtocol::WindowIndex {
                    header: RepairRequestHeader { nonce, .. },
                    slot,
                    shred_index,
                }
                | RepairProtocol::LegacyWindowIndexWithNonce(_, slot, shred_index, nonce) => {
                    stats.window_index += 1;
                    (
                        Self::run_window_request(
                            recycler,
                            from_addr,
                            blockstore,
                            *slot,
                            *shred_index,
                            *nonce,
                        ),
                        "WindowIndexWithNonce",
                    )
                }
                RepairProtocol::HighestWindowIndex {
                    header: RepairRequestHeader { nonce, .. },
                    slot,
                    shred_index: highest_index,
                }
                | RepairProtocol::LegacyHighestWindowIndexWithNonce(
                    _,
                    slot,
                    highest_index,
                    nonce,
                ) => {
                    stats.highest_window_index += 1;
                    (
                        Self::run_highest_window_request(
                            recycler,
                            from_addr,
                            blockstore,
                            *slot,
                            *highest_index,
                            *nonce,
                        ),
                        "HighestWindowIndexWithNonce",
                    )
                }
                RepairProtocol::Orphan {
                    header: RepairRequestHeader { nonce, .. },
                    slot,
                }
                | RepairProtocol::LegacyOrphanWithNonce(_, slot, nonce) => {
                    stats.orphan += 1;
                    (
                        Self::run_orphan(
                            recycler,
                            from_addr,
                            blockstore,
                            *slot,
                            MAX_ORPHAN_REPAIR_RESPONSES,
                            *nonce,
                        ),
                        "OrphanWithNonce",
                    )
                }
                RepairProtocol::AncestorHashes {
                    header: RepairRequestHeader { nonce, .. },
                    slot,
                }
                | RepairProtocol::LegacyAncestorHashes(_, slot, nonce) => {
                    stats.ancestor_hashes += 1;
                    (
                        Self::run_ancestor_hashes(recycler, from_addr, blockstore, *slot, *nonce),
                        "AncestorHashes",
                    )
                }
                RepairProtocol::Pong(pong) => {
                    stats.pong += 1;
                    ping_cache.add(pong, *from_addr, Instant::now());
                    (None, "Pong")
                }
                RepairProtocol::LegacyWindowIndex(_, _, _)
                | RepairProtocol::LegacyHighestWindowIndex(_, _, _)
                | RepairProtocol::LegacyOrphan(_, _) => (None, "Unsupported repair type"),
            }
        };
        Self::report_time_spent(label, &now.elapsed(), "");
        res
    }

    fn report_time_spent(label: &str, time: &Duration, extra: &str) {
        let count = duration_as_ms(time);
        if count > 5 {
            info!("{} took: {} ms {}", label, count, extra);
        }
    }

    pub(crate) fn sign_repair_requests_activated_epoch(root_bank: &Bank) -> Option<Epoch> {
        root_bank
            .feature_set
            .activated_slot(&sign_repair_requests::id())
            .map(|slot| root_bank.epoch_schedule().get_epoch(slot))
    }

    pub(crate) fn should_sign_repair_request(
        slot: Slot,
        root_bank: &Bank,
        sign_repairs_epoch: Option<Epoch>,
    ) -> bool {
        match sign_repairs_epoch {
            None => false,
            Some(feature_epoch) => feature_epoch < root_bank.epoch_schedule().get_epoch(slot),
        }
    }

    /// Process messages from the network
    fn run_listen(
        obj: &Arc<RwLock<Self>>,
        ping_cache: &mut PingCache,
        recycler: &PacketBatchRecycler,
        blockstore: Option<&Arc<Blockstore>>,
        requests_receiver: &PacketBatchReceiver,
        response_sender: &PacketBatchSender,
        stats: &mut ServeRepairStats,
        packet_threshold: &mut DynamicPacketToProcessThreshold,
    ) -> Result<()> {
        //TODO cache connections
        let timeout = Duration::new(1, 0);
        let mut reqs_v = vec![requests_receiver.recv_timeout(timeout)?];
        let mut total_requests = reqs_v[0].len();

        let mut dropped_requests = 0;
        while let Ok(more) = requests_receiver.try_recv() {
            total_requests += more.len();
            if packet_threshold.should_drop(total_requests) {
                dropped_requests += more.len();
            } else {
                reqs_v.push(more);
            }
        }

        stats.dropped_requests += dropped_requests;
        stats.total_requests += total_requests;

        let timer = Instant::now();
        let root_bank = obj.read().unwrap().bank_forks.read().unwrap().root_bank();
        let epoch_staked_nodes = root_bank.epoch_staked_nodes(root_bank.epoch());
        for reqs in reqs_v {
            Self::handle_packets(
                obj,
                ping_cache,
                recycler,
                blockstore,
                reqs,
                response_sender,
                stats,
                &epoch_staked_nodes,
            );
        }
        packet_threshold.update(total_requests, timer.elapsed());
        Ok(())
    }

    fn report_reset_stats(me: &Arc<RwLock<Self>>, stats: &mut ServeRepairStats) {
        if stats.self_repair > 0 {
            let my_id = me.read().unwrap().cluster_info.id();
            warn!(
                "{}: Ignored received repair requests from ME: {}",
                my_id, stats.self_repair,
            );
            inc_new_counter_debug!("serve_repair-handle-repair--eq", stats.self_repair);
        }

        datapoint_info!(
            "serve_repair-requests_received",
            ("total_requests", stats.total_requests, i64),
            ("unsigned_requests", stats.unsigned_requests, i64),
            ("dropped_requests", stats.dropped_requests, i64),
            ("total_response_packets", stats.total_response_packets, i64),
            ("handle_requests_staked", stats.handle_requests_staked, i64),
            (
                "handle_requests_unstaked",
                stats.handle_requests_unstaked,
                i64
            ),
            ("processed", stats.processed, i64),
            (
                "total_response_bytes_staked",
                stats.total_response_bytes_staked,
                i64
            ),
            (
                "total_response_bytes_unstaked",
                stats.total_response_bytes_unstaked,
                i64
            ),
            ("self_repair", stats.self_repair, i64),
            ("window_index", stats.window_index, i64),
            (
                "request-highest-window-index",
                stats.highest_window_index,
                i64
            ),
            ("orphan", stats.orphan, i64),
            (
                "serve_repair-request-ancestor-hashes",
                stats.ancestor_hashes,
                i64
            ),
            ("pong", stats.pong, i64),
            ("err_time_skew", stats.err_time_skew, i64),
            ("err_malformed", stats.err_malformed, i64),
            ("err_sig_verify", stats.err_sig_verify, i64),
            ("err_unsigned", stats.err_unsigned, i64),
            ("err_id_mismatch", stats.err_id_mismatch, i64),
        );

        *stats = ServeRepairStats::default();
    }

    pub fn listen(
        me: Arc<RwLock<Self>>,
        blockstore: Option<Arc<Blockstore>>,
        requests_receiver: PacketBatchReceiver,
        response_sender: PacketBatchSender,
        exit: &Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        // rate limit delay should be greater than the repair request iteration delay
        assert!(REPAIR_PING_CACHE_RATE_LIMIT_DELAY > Duration::from_millis(REPAIR_MS));

        let mut ping_cache = PingCache::new(
            REPAIR_PING_CACHE_TTL,
            REPAIR_PING_CACHE_RATE_LIMIT_DELAY,
            REPAIR_PING_CACHE_CAPACITY,
        );
        let exit = exit.clone();

        let recycler = PacketBatchRecycler::default();
        Builder::new()
            .name("solana-repair-listen".to_string())
            .spawn(move || {
                let mut last_print = Instant::now();
                let mut stats = ServeRepairStats::default();
                let mut packet_threshold = DynamicPacketToProcessThreshold::default();
                loop {
                    let result = Self::run_listen(
                        &me,
                        &mut ping_cache,
                        &recycler,
                        blockstore.as_ref(),
                        &requests_receiver,
                        &response_sender,
                        &mut stats,
                        &mut packet_threshold,
                    );
                    match result {
                        Err(Error::RecvTimeout(_)) | Ok(_) => {}
                        Err(err) => info!("repair listener error: {:?}", err),
                    };
                    if exit.load(Ordering::Relaxed) {
                        return;
                    }
                    if last_print.elapsed().as_secs() > 2 {
                        Self::report_reset_stats(&me, &mut stats);
                        last_print = Instant::now();
                    }
                }
            })
            .unwrap()
    }

    fn verify_signed_packet(
        my_id: &Pubkey,
        packet: &Packet,
        request: &RepairProtocol,
        stats: &mut ServeRepairStats,
    ) -> bool {
        match request {
            RepairProtocol::LegacyWindowIndex(_, _, _)
            | RepairProtocol::LegacyHighestWindowIndex(_, _, _)
            | RepairProtocol::LegacyOrphan(_, _)
            | RepairProtocol::LegacyWindowIndexWithNonce(_, _, _, _)
            | RepairProtocol::LegacyHighestWindowIndexWithNonce(_, _, _, _)
            | RepairProtocol::LegacyOrphanWithNonce(_, _, _)
            | RepairProtocol::LegacyAncestorHashes(_, _, _) => {
                debug_assert!(false); // expecting only signed request types
                stats.err_unsigned += 1;
                return false;
            }
            RepairProtocol::Pong(pong) => {
                if !pong.verify() {
                    stats.err_sig_verify += 1;
                    return false;
                }
            }
            RepairProtocol::WindowIndex { header, .. }
            | RepairProtocol::HighestWindowIndex { header, .. }
            | RepairProtocol::Orphan { header, .. }
            | RepairProtocol::AncestorHashes { header, .. } => {
                if &header.recipient != my_id {
                    stats.err_id_mismatch += 1;
                    return false;
                }
                let time_diff_ms = {
                    let ts = timestamp();
                    if ts < header.timestamp {
                        header.timestamp - ts
                    } else {
                        ts - header.timestamp
                    }
                };
                if u128::from(time_diff_ms) > SIGNED_REPAIR_TIME_WINDOW.as_millis() {
                    stats.err_time_skew += 1;
                    return false;
                }
                let leading_buf = match packet.data(..4) {
                    Some(buf) => buf,
                    None => {
                        debug_assert!(false); // should have failed deserialize
                        stats.err_malformed += 1;
                        return false;
                    }
                };
                let trailing_buf = match packet.data(4 + SIGNATURE_BYTES..) {
                    Some(buf) => buf,
                    None => {
                        debug_assert!(false); // should have failed deserialize
                        stats.err_malformed += 1;
                        return false;
                    }
                };
                let from_id = request.sender();
                let signed_data = [leading_buf, trailing_buf].concat();
                if !header.signature.verify(from_id.as_ref(), &signed_data) {
                    stats.err_sig_verify += 1;
                    return false;
                }
            }
        }
        true
    }

    fn handle_packets(
        me: &Arc<RwLock<Self>>,
        ping_cache: &mut PingCache,
        recycler: &PacketBatchRecycler,
        blockstore: Option<&Arc<Blockstore>>,
        packet_batch: PacketBatch,
        response_sender: &PacketBatchSender,
        stats: &mut ServeRepairStats,
        epoch_staked_nodes: &Option<Arc<HashMap<Pubkey, u64>>>,
    ) {
        let identity_keypair = me.read().unwrap().cluster_info.keypair().clone();
        let my_id = identity_keypair.pubkey();

        // iter over the packets
        for packet in packet_batch.iter() {
            let request: RepairProtocol = match packet.deserialize_slice(..) {
                Ok(request) => request,
                Err(_) => {
                    stats.err_malformed += 1;
                    continue;
                }
            };

            let staked = epoch_staked_nodes
                .as_ref()
                .map(|nodes| nodes.contains_key(request.sender()))
                .unwrap_or_default();
            match staked {
                true => stats.handle_requests_staked += 1,
                false => stats.handle_requests_unstaked += 1,
            }

            if request.sender() == &my_id {
                stats.self_repair += 1;
                continue;
            }

            if request.supports_signature() {
                // collect stats for signature verification
                Self::verify_signed_packet(&my_id, packet, &request, stats);
            } else {
                stats.unsigned_requests += 1;
            }

            let from_addr = packet.meta.socket_addr();
            stats.processed += 1;
            let rsp = match Self::handle_repair(
                recycler, &from_addr, blockstore, request, stats, ping_cache,
            ) {
                None => continue,
                Some(rsp) => rsp,
            };
            stats.total_response_packets += rsp.len();
            let num_response_bytes: usize = rsp.iter().map(|p| p.meta.size).sum();
            match staked {
                true => stats.total_response_bytes_staked += num_response_bytes,
                false => stats.total_response_bytes_unstaked += num_response_bytes,
            }
            let _ignore_disconnect = response_sender.send(rsp);
        }
    }

    pub fn ancestor_repair_request_bytes(
        &self,
        keypair: &Keypair,
        root_bank: &Bank,
        repair_peer_id: &Pubkey,
        request_slot: Slot,
        nonce: Nonce,
    ) -> Result<Vec<u8>> {
        let sign_repairs_epoch = Self::sign_repair_requests_activated_epoch(root_bank);
        let require_sig =
            Self::should_sign_repair_request(request_slot, root_bank, sign_repairs_epoch);

        let (request_proto, maybe_keypair) = if require_sig {
            let header = RepairRequestHeader {
                signature: Signature::default(),
                sender: self.my_id(),
                recipient: *repair_peer_id,
                timestamp: timestamp(),
                nonce,
            };
            (
                RepairProtocol::AncestorHashes {
                    header,
                    slot: request_slot,
                },
                Some(keypair),
            )
        } else {
            (
                RepairProtocol::LegacyAncestorHashes(self.my_info(), request_slot, nonce),
                None,
            )
        };

        Self::repair_proto_to_bytes(&request_proto, maybe_keypair)
    }

    pub(crate) fn repair_request(
        &self,
        cluster_slots: &ClusterSlots,
        repair_request: ShredRepairType,
        peers_cache: &mut LruCache<Slot, RepairPeers>,
        repair_stats: &mut RepairStats,
        repair_validators: &Option<HashSet<Pubkey>>,
        outstanding_requests: &mut OutstandingShredRepairs,
        identity_keypair: Option<&Keypair>,
    ) -> Result<(SocketAddr, Vec<u8>)> {
        // find a peer that appears to be accepting replication and has the desired slot, as indicated
        // by a valid tvu port location
        let slot = repair_request.slot();
        let repair_peers = match peers_cache.get(&slot) {
            Some(entry) if entry.asof.elapsed() < REPAIR_PEERS_CACHE_TTL => entry,
            _ => {
                peers_cache.pop(&slot);
                let repair_peers = self.repair_peers(repair_validators, slot);
                let weights = cluster_slots.compute_weights(slot, &repair_peers);
                let repair_peers = RepairPeers::new(Instant::now(), &repair_peers, &weights)?;
                peers_cache.put(slot, repair_peers);
                peers_cache.get(&slot).unwrap()
            }
        };
        let (peer, addr) = repair_peers.sample(&mut rand::thread_rng());
        let nonce = outstanding_requests.add_request(repair_request, timestamp());
        let out = self.map_repair_request(
            &repair_request,
            &peer,
            repair_stats,
            nonce,
            identity_keypair,
        )?;
        Ok((addr, out))
    }

    pub(crate) fn repair_request_ancestor_hashes_sample_peers(
        &self,
        slot: Slot,
        cluster_slots: &ClusterSlots,
        repair_validators: &Option<HashSet<Pubkey>>,
    ) -> Result<Vec<(Pubkey, SocketAddr)>> {
        let repair_peers: Vec<_> = self.repair_peers(repair_validators, slot);
        if repair_peers.is_empty() {
            return Err(ClusterInfoError::NoPeers.into());
        }
        let (weights, index): (Vec<_>, Vec<_>) = cluster_slots
            .compute_weights_exclude_nonfrozen(slot, &repair_peers)
            .into_iter()
            .unzip();
        let peers = WeightedShuffle::new("repair_request_ancestor_hashes", &weights)
            .shuffle(&mut rand::thread_rng())
            .take(ANCESTOR_HASH_REPAIR_SAMPLE_SIZE)
            .map(|i| index[i])
            .map(|i| (repair_peers[i].id, repair_peers[i].serve_repair))
            .collect();
        Ok(peers)
    }

    pub fn repair_request_duplicate_compute_best_peer(
        &self,
        slot: Slot,
        cluster_slots: &ClusterSlots,
        repair_validators: &Option<HashSet<Pubkey>>,
    ) -> Result<(Pubkey, SocketAddr)> {
        let repair_peers: Vec<_> = self.repair_peers(repair_validators, slot);
        if repair_peers.is_empty() {
            return Err(ClusterInfoError::NoPeers.into());
        }
        let (weights, index): (Vec<_>, Vec<_>) = cluster_slots
            .compute_weights_exclude_nonfrozen(slot, &repair_peers)
            .into_iter()
            .unzip();
        let k = WeightedIndex::new(weights)?.sample(&mut rand::thread_rng());
        let n = index[k];
        Ok((repair_peers[n].id, repair_peers[n].serve_repair))
    }

    pub(crate) fn map_repair_request(
        &self,
        repair_request: &ShredRepairType,
        repair_peer_id: &Pubkey,
        repair_stats: &mut RepairStats,
        nonce: Nonce,
        identity_keypair: Option<&Keypair>,
    ) -> Result<Vec<u8>> {
        let header = if identity_keypair.is_some() {
            Some(RepairRequestHeader {
                signature: Signature::default(),
                sender: self.my_id(),
                recipient: *repair_peer_id,
                timestamp: timestamp(),
                nonce,
            })
        } else {
            None
        };
        let request_proto = match repair_request {
            ShredRepairType::Shred(slot, shred_index) => {
                repair_stats
                    .shred
                    .update(repair_peer_id, *slot, *shred_index);
                if let Some(header) = header {
                    RepairProtocol::WindowIndex {
                        header,
                        slot: *slot,
                        shred_index: *shred_index,
                    }
                } else {
                    RepairProtocol::LegacyWindowIndexWithNonce(
                        self.my_info(),
                        *slot,
                        *shred_index,
                        nonce,
                    )
                }
            }
            ShredRepairType::HighestShred(slot, shred_index) => {
                repair_stats
                    .highest_shred
                    .update(repair_peer_id, *slot, *shred_index);
                if let Some(header) = header {
                    RepairProtocol::HighestWindowIndex {
                        header,
                        slot: *slot,
                        shred_index: *shred_index,
                    }
                } else {
                    RepairProtocol::LegacyHighestWindowIndexWithNonce(
                        self.my_info(),
                        *slot,
                        *shred_index,
                        nonce,
                    )
                }
            }
            ShredRepairType::Orphan(slot) => {
                repair_stats.orphan.update(repair_peer_id, *slot, 0);
                if let Some(header) = header {
                    RepairProtocol::Orphan {
                        header,
                        slot: *slot,
                    }
                } else {
                    RepairProtocol::LegacyOrphanWithNonce(self.my_info(), *slot, nonce)
                }
            }
        };
        Self::repair_proto_to_bytes(&request_proto, identity_keypair)
    }

    /// Distinguish and process `RepairResponse` ping packets ignoring other
    /// packets in the batch.
    pub(crate) fn handle_repair_response_pings(
        repair_socket: &UdpSocket,
        keypair: &Keypair,
        packet_batch: &mut PacketBatch,
        stats: &mut ShredFetchStats,
    ) {
        let mut pending_pongs = Vec::default();
        for packet in packet_batch.iter_mut() {
            if packet.meta.size != REPAIR_RESPONSE_SERIALIZED_PING_BYTES {
                continue;
            }
            if let Ok(RepairResponse::Ping(ping)) = packet.deserialize_slice(..) {
                if !ping.verify() {
                    // Do _not_ set `discard` to allow shred processing to attempt to
                    // handle the packet.
                    // Ping error count may include false posities for shreds of size
                    // `REPAIR_RESPONSE_SERIALIZED_PING_BYTES` whose first 4 bytes
                    // match `RepairResponse` discriminator (these 4 bytes overlap
                    // with the shred signature field).
                    stats.ping_err_verify_count += 1;
                    continue;
                }
                packet.meta.set_discard(true);
                stats.ping_count += 1;
                // Respond both with and without domain so that the other node
                // will accept the response regardless of its upgrade status.
                // TODO: remove domain = false once cluster is upgraded.
                for domain in [false, true] {
                    if let Ok(pong) = Pong::new(domain, &ping, keypair) {
                        let pong = RepairProtocol::Pong(pong);
                        if let Ok(pong_bytes) = serialize(&pong) {
                            let from_addr = packet.meta.socket_addr();
                            pending_pongs.push((pong_bytes, from_addr));
                        }
                    }
                }
            }
        }
        if !pending_pongs.is_empty() {
            if let Err(SendPktsError::IoError(err, num_failed)) =
                batch_send(repair_socket, &pending_pongs)
            {
                warn!(
                    "batch_send failed to send {}/{} packets. First error: {:?}",
                    num_failed,
                    pending_pongs.len(),
                    err
                );
            }
        }
    }

    pub fn repair_proto_to_bytes(
        request: &RepairProtocol,
        keypair: Option<&Keypair>,
    ) -> Result<Vec<u8>> {
        let mut payload = serialize(&request)?;
        if let Some(keypair) = keypair {
            debug_assert!(request.supports_signature());
            let signable_data = [&payload[..4], &payload[4 + SIGNATURE_BYTES..]].concat();
            let signature = keypair.sign_message(&signable_data[..]);
            payload[4..4 + SIGNATURE_BYTES].copy_from_slice(signature.as_ref());
        }
        Ok(payload)
    }

    fn repair_peers(
        &self,
        repair_validators: &Option<HashSet<Pubkey>>,
        slot: Slot,
    ) -> Vec<ContactInfo> {
        if let Some(repair_validators) = repair_validators {
            repair_validators
                .iter()
                .filter_map(|key| {
                    if *key != self.my_id() {
                        self.cluster_info.lookup_contact_info(key, |ci| ci.clone())
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            self.cluster_info.repair_peers(slot)
        }
    }

    fn run_window_request(
        recycler: &PacketBatchRecycler,
        from_addr: &SocketAddr,
        blockstore: Option<&Arc<Blockstore>>,
        slot: Slot,
        shred_index: u64,
        nonce: Nonce,
    ) -> Option<PacketBatch> {
        if let Some(blockstore) = blockstore {
            // Try to find the requested index in one of the slots
            let packet = repair_response::repair_response_packet(
                blockstore,
                slot,
                shred_index,
                from_addr,
                nonce,
            );

            if let Some(packet) = packet {
                inc_new_counter_debug!("serve_repair-window-request-ledger", 1);
                return Some(PacketBatch::new_unpinned_with_recycler_data(
                    recycler,
                    "run_window_request",
                    vec![packet],
                ));
            }
        }

        inc_new_counter_debug!("serve_repair-window-request-fail", 1);
        None
    }

    fn run_highest_window_request(
        recycler: &PacketBatchRecycler,
        from_addr: &SocketAddr,
        blockstore: Option<&Arc<Blockstore>>,
        slot: Slot,
        highest_index: u64,
        nonce: Nonce,
    ) -> Option<PacketBatch> {
        let blockstore = blockstore?;
        // Try to find the requested index in one of the slots
        let meta = blockstore.meta(slot).ok()??;
        if meta.received > highest_index {
            // meta.received must be at least 1 by this point
            let packet = repair_response::repair_response_packet(
                blockstore,
                slot,
                meta.received - 1,
                from_addr,
                nonce,
            )?;
            return Some(PacketBatch::new_unpinned_with_recycler_data(
                recycler,
                "run_highest_window_request",
                vec![packet],
            ));
        }
        None
    }

    fn run_orphan(
        recycler: &PacketBatchRecycler,
        from_addr: &SocketAddr,
        blockstore: Option<&Arc<Blockstore>>,
        mut slot: Slot,
        max_responses: usize,
        nonce: Nonce,
    ) -> Option<PacketBatch> {
        let mut res = PacketBatch::new_unpinned_with_recycler(recycler.clone(), 64, "run_orphan");
        if let Some(blockstore) = blockstore {
            // Try to find the next "n" parent slots of the input slot
            while let Ok(Some(meta)) = blockstore.meta(slot) {
                if meta.received == 0 {
                    break;
                }
                let packet = repair_response::repair_response_packet(
                    blockstore,
                    slot,
                    meta.received - 1,
                    from_addr,
                    nonce,
                );
                if let Some(packet) = packet {
                    res.push(packet);
                } else {
                    break;
                }

                if meta.parent_slot.is_some() && res.len() <= max_responses {
                    slot = meta.parent_slot.unwrap();
                } else {
                    break;
                }
            }
        }
        if res.is_empty() {
            return None;
        }
        Some(res)
    }

    fn run_ancestor_hashes(
        recycler: &PacketBatchRecycler,
        from_addr: &SocketAddr,
        blockstore: Option<&Arc<Blockstore>>,
        slot: Slot,
        nonce: Nonce,
    ) -> Option<PacketBatch> {
        let blockstore = blockstore?;
        let ancestor_slot_hashes = if blockstore.is_duplicate_confirmed(slot) {
            let ancestor_iterator =
                AncestorIteratorWithHash::from(AncestorIterator::new_inclusive(slot, blockstore));
            ancestor_iterator.take(MAX_ANCESTOR_RESPONSES).collect()
        } else {
            // If this slot is not duplicate confirmed, return nothing
            vec![]
        };
        let response = AncestorHashesResponse::Hashes(ancestor_slot_hashes);
        let serialized_response = serialize(&response).ok()?;

        // Could probably directly write response into packet via `serialize_into()`
        // instead of incurring extra copy in `repair_response_packet_from_bytes`, but
        // serialize_into doesn't return the written size...
        let packet = repair_response::repair_response_packet_from_bytes(
            serialized_response,
            from_addr,
            nonce,
        )?;
        Some(PacketBatch::new_unpinned_with_recycler_data(
            recycler,
            "run_ancestor_hashes",
            vec![packet],
        ))
    }
}
