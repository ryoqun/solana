use {
    crate::{
        cluster_slots_service::cluster_slots::ClusterSlots,
        repair::{
            duplicate_repair_status::get_ancestor_hash_repair_sample_size,
            quic_endpoint::{LocalRequest, RemoteRequest},
            repair_response,
            repair_service::{OutstandingShredRepairs, RepairStats, REPAIR_MS},
            request_response::RequestResponse,
            result::{Error, RepairVerifyError, Result},
        },
    },
    bincode::{serialize, Options},
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender},
    lru::LruCache,
    rand::{
        distributions::{Distribution, WeightedError, WeightedIndex},
        Rng,
    },
    solana_gossip::{
        cluster_info::{ClusterInfo, ClusterInfoError},
        contact_info::{ContactInfo, Protocol},
        ping_pong::{self, PingCache, Pong},
        weighted_shuffle::WeightedShuffle,
    },
    solana_ledger::{
        ancestor_iterator::{AncestorIterator, AncestorIteratorWithHash},
        blockstore::Blockstore,
        shred::{Nonce, Shred, ShredFetchStats, SIZE_OF_NONCE},
    },
    solana_perf::{
        data_budget::DataBudget,
        packet::{Packet, PacketBatch, PacketBatchRecycler},
    },
    solana_runtime::bank_forks::BankForks,
    solana_sdk::{
        clock::Slot,
        genesis_config::ClusterType,
        hash::{Hash, HASH_BYTES},
        packet::PACKET_DATA_SIZE,
        pubkey::{Pubkey, PUBKEY_BYTES},
        signature::{Signable, Signature, Signer, SIGNATURE_BYTES},
        signer::keypair::Keypair,
        timing::{duration_as_ms, timestamp},
    },
    solana_streamer::{
        sendmmsg::{batch_send, SendPktsError},
        socket::SocketAddrSpace,
        streamer::PacketBatchSender,
    },
    std::{
        cmp::Reverse,
        collections::{HashMap, HashSet},
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{Builder, JoinHandle},
        time::{Duration, Instant},
    },
    tokio::sync::{mpsc::Sender as AsyncSender, oneshot::Sender as OneShotSender},
};

/// the number of slots to respond with when responding to `Orphan` requests
pub const MAX_ORPHAN_REPAIR_RESPONSES: usize = 11;
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
    MAX_ANCESTOR_BYTES_IN_PACKET / std::mem::size_of::<(Slot, Hash)>();
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
    /// Requesting `MAX_ORPHAN_REPAIR_RESPONSES ` parent shreds
    Orphan(Slot),
    /// Requesting any shred with index greater than or equal to the particular index
    HighestShred(Slot, u64),
    /// Requesting the missing shred at a particular index
    Shred(Slot, u64),
}

impl ShredRepairType {
    pub fn slot(&self) -> Slot {
        match self {
            ShredRepairType::Orphan(slot)
            | ShredRepairType::HighestShred(slot, _)
            | ShredRepairType::Shred(slot, _) => *slot,
        }
    }
}

impl RequestResponse for ShredRepairType {
    type Response = Shred;
    fn num_expected_responses(&self) -> u32 {
        match self {
            ShredRepairType::Orphan(_) => MAX_ORPHAN_REPAIR_RESPONSES as u32,
            ShredRepairType::Shred(_, _) | ShredRepairType::HighestShred(_, _) => 1,
        }
    }
    fn verify_response(&self, response_shred: &Shred) -> bool {
        match self {
            ShredRepairType::Orphan(slot) => response_shred.slot() <= *slot,
            ShredRepairType::HighestShred(slot, index) => {
                response_shred.slot() == *slot && response_shred.index() as u64 >= *index
            }
            ShredRepairType::Shred(slot, index) => {
                response_shred.slot() == *slot && response_shred.index() as u64 == *index
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct AncestorHashesRepairType(pub Slot);
impl AncestorHashesRepairType {
    pub fn slot(&self) -> Slot {
        self.0
    }
}

#[cfg_attr(
    feature = "frozen-abi",
    derive(AbiEnumVisitor, AbiExample),
    frozen_abi(digest = "AKpurCovzn6rsji4aQrP3hUdEHxjtXUfT7AatZXN7Rpz")
)]
#[derive(Debug, Deserialize, Serialize)]
pub enum AncestorHashesResponse {
    Hashes(Vec<(Slot, Hash)>),
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
    dropped_requests_outbound_bandwidth: usize,
    dropped_requests_load_shed: usize,
    dropped_requests_low_stake: usize,
    whitelisted_requests: usize,
    total_dropped_response_packets: usize,
    total_response_packets: usize,
    total_response_bytes_staked: usize,
    total_response_bytes_unstaked: usize,
    processed: usize,
    window_index: usize,
    highest_window_index: usize,
    orphan: usize,
    pong: usize,
    ancestor_hashes: usize,
    window_index_misses: usize,
    ping_cache_check_failed: usize,
    pings_sent: usize,
    decode_time_us: u64,
    handle_requests_time_us: u64,
    handle_requests_staked: usize,
    handle_requests_unstaked: usize,
    err_self_repair: usize,
    err_time_skew: usize,
    err_malformed: usize,
    err_sig_verify: usize,
    err_unsigned: usize,
    err_id_mismatch: usize,
}

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[derive(Debug, Deserialize, Serialize)]
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
#[cfg_attr(
    feature = "frozen-abi",
    derive(AbiEnumVisitor, AbiExample),
    frozen_abi(digest = "5cmSdmXMgkpUH5ZCmYYjxUVQfULe9iJqCqqfrADfsEmK")
)]
#[derive(Debug, Deserialize, Serialize)]
pub enum RepairProtocol {
    LegacyWindowIndex,
    LegacyHighestWindowIndex,
    LegacyOrphan,
    LegacyWindowIndexWithNonce,
    LegacyHighestWindowIndexWithNonce,
    LegacyOrphanWithNonce,
    LegacyAncestorHashes,
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

const REPAIR_REQUEST_PONG_SERIALIZED_BYTES: usize = PUBKEY_BYTES + HASH_BYTES + SIGNATURE_BYTES;
const REPAIR_REQUEST_MIN_BYTES: usize = REPAIR_REQUEST_PONG_SERIALIZED_BYTES;

fn discard_malformed_repair_requests(
    requests: &mut Vec<RemoteRequest>,
    stats: &mut ServeRepairStats,
) -> usize {
    let num_requests = requests.len();
    requests.retain(|request| request.bytes.len() >= REPAIR_REQUEST_MIN_BYTES);
    stats.err_malformed += num_requests - requests.len();
    requests.len()
}

#[cfg_attr(
    feature = "frozen-abi",
    derive(AbiEnumVisitor, AbiExample),
    frozen_abi(digest = "CkffjyMPCwuJgk9NiCMELXLCecAnTPZqpKEnUCb3VyVf")
)]
#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum RepairResponse {
    Ping(Ping),
}

impl RepairProtocol {
    fn sender(&self) -> Option<&Pubkey> {
        match self {
            Self::LegacyWindowIndex
            | Self::LegacyHighestWindowIndex
            | Self::LegacyOrphan
            | Self::LegacyWindowIndexWithNonce
            | Self::LegacyHighestWindowIndexWithNonce
            | Self::LegacyOrphanWithNonce
            | Self::LegacyAncestorHashes => None,
            Self::Pong(pong) => Some(pong.from()),
            Self::WindowIndex { header, .. } => Some(&header.sender),
            Self::HighestWindowIndex { header, .. } => Some(&header.sender),
            Self::Orphan { header, .. } => Some(&header.sender),
            Self::AncestorHashes { header, .. } => Some(&header.sender),
        }
    }

    fn supports_signature(&self) -> bool {
        match self {
            Self::LegacyWindowIndex
            | Self::LegacyHighestWindowIndex
            | Self::LegacyOrphan
            | Self::LegacyWindowIndexWithNonce
            | Self::LegacyHighestWindowIndexWithNonce
            | Self::LegacyOrphanWithNonce
            | Self::LegacyAncestorHashes => false,
            Self::Pong(_)
            | Self::WindowIndex { .. }
            | Self::HighestWindowIndex { .. }
            | Self::Orphan { .. }
            | Self::AncestorHashes { .. } => true,
        }
    }

    fn max_response_packets(&self) -> usize {
        match self {
            RepairProtocol::WindowIndex { .. }
            | RepairProtocol::HighestWindowIndex { .. }
            | RepairProtocol::AncestorHashes { .. } => 1,
            RepairProtocol::Orphan { .. } => MAX_ORPHAN_REPAIR_RESPONSES,
            RepairProtocol::Pong(_) => 0, // no response
            RepairProtocol::LegacyWindowIndex
            | RepairProtocol::LegacyHighestWindowIndex
            | RepairProtocol::LegacyOrphan
            | RepairProtocol::LegacyWindowIndexWithNonce
            | RepairProtocol::LegacyHighestWindowIndexWithNonce
            | RepairProtocol::LegacyOrphanWithNonce
            | RepairProtocol::LegacyAncestorHashes => 0, // unsupported
        }
    }

    fn max_response_bytes(&self) -> usize {
        self.max_response_packets() * PACKET_DATA_SIZE
    }
}

#[derive(Clone)]
pub struct ServeRepair {
    cluster_info: Arc<ClusterInfo>,
    bank_forks: Arc<RwLock<BankForks>>,
    repair_whitelist: Arc<RwLock<HashSet<Pubkey>>>,
}

// Cache entry for repair peers for a slot.
pub(crate) struct RepairPeers {
    asof: Instant,
    peers: Vec<Node>,
    weighted_index: WeightedIndex<u64>,
}

struct Node {
    pubkey: Pubkey,
    serve_repair: SocketAddr,
    serve_repair_quic: SocketAddr,
}

impl RepairPeers {
    fn new(asof: Instant, peers: &[ContactInfo], weights: &[u64]) -> Result<Self> {
        if peers.len() != weights.len() {
            return Err(Error::from(WeightedError::InvalidWeight));
        }
        let (peers, weights): (Vec<_>, Vec<u64>) = peers
            .iter()
            .zip(weights)
            .filter_map(|(peer, &weight)| {
                let node = Node {
                    pubkey: *peer.pubkey(),
                    serve_repair: peer.serve_repair(Protocol::UDP).ok()?,
                    serve_repair_quic: peer.serve_repair(Protocol::QUIC).ok()?,
                };
                Some((node, weight))
            })
            .unzip();
        if peers.is_empty() {
            return Err(Error::from(ClusterInfoError::NoPeers));
        }
        let weighted_index = WeightedIndex::new(weights)?;
        Ok(Self {
            asof,
            peers,
            weighted_index,
        })
    }

    fn sample<R: Rng>(&self, rng: &mut R) -> &Node {
        let index = self.weighted_index.sample(rng);
        &self.peers[index]
    }
}

struct RepairRequestWithMeta {
    request: RepairProtocol,
    from_addr: SocketAddr,
    stake: u64,
    whitelisted: bool,
    response_sender: Option<OneShotSender<Vec<Vec<u8>>>>,
}

impl ServeRepair {
    pub fn new(
        cluster_info: Arc<ClusterInfo>,
        bank_forks: Arc<RwLock<BankForks>>,
        repair_whitelist: Arc<RwLock<HashSet<Pubkey>>>,
    ) -> Self {
        Self {
            cluster_info,
            bank_forks,
            repair_whitelist,
        }
    }

    pub(crate) fn my_id(&self) -> Pubkey {
        self.cluster_info.id()
    }

    fn handle_repair(
        recycler: &PacketBatchRecycler,
        from_addr: &SocketAddr,
        blockstore: &Blockstore,
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
                } => {
                    stats.window_index += 1;
                    let batch = Self::run_window_request(
                        recycler,
                        from_addr,
                        blockstore,
                        *slot,
                        *shred_index,
                        *nonce,
                    );
                    if batch.is_none() {
                        stats.window_index_misses += 1;
                    }
                    (batch, "WindowIndexWithNonce")
                }
                RepairProtocol::HighestWindowIndex {
                    header: RepairRequestHeader { nonce, .. },
                    slot,
                    shred_index: highest_index,
                } => {
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
                } => {
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
                } => {
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
                RepairProtocol::LegacyWindowIndex
                | RepairProtocol::LegacyWindowIndexWithNonce
                | RepairProtocol::LegacyHighestWindowIndex
                | RepairProtocol::LegacyHighestWindowIndexWithNonce
                | RepairProtocol::LegacyOrphan
                | RepairProtocol::LegacyOrphanWithNonce
                | RepairProtocol::LegacyAncestorHashes => {
                    error!("Unexpected legacy request: {request:?}");
                    debug_assert!(
                        false,
                        "Legacy requests should have been filtered out during signature
                        verification. {request:?}"
                    );
                    (None, "Legacy")
                }
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

    fn decode_request(
        remote_request: RemoteRequest,
        epoch_staked_nodes: &Option<Arc<HashMap<Pubkey, u64>>>,
        whitelist: &HashSet<Pubkey>,
        my_id: &Pubkey,
        socket_addr_space: &SocketAddrSpace,
    ) -> Result<RepairRequestWithMeta> {
        let Ok(request) = deserialize_request::<RepairProtocol>(&remote_request) else {
            return Err(Error::from(RepairVerifyError::Malformed));
        };
        let from_addr = remote_request.remote_address;
        if !ContactInfo::is_valid_address(&from_addr, socket_addr_space) {
            return Err(Error::from(RepairVerifyError::Malformed));
        }
        Self::verify_signed_packet(my_id, &remote_request.bytes, &request)?;
        if let Some(remote_pubkey) = remote_request.remote_pubkey {
            if Some(&remote_pubkey) != request.sender() {
                error!(
                    "remote pubkey {remote_pubkey} != request sender {:?}",
                    request.sender()
                );
            }
        }
        if request.sender() == Some(my_id) {
            error!("self repair: from_addr={from_addr} my_id={my_id} request={request:?}");
            return Err(Error::from(RepairVerifyError::SelfRepair));
        }
        let stake = *epoch_staked_nodes
            .as_ref()
            .and_then(|stakes| stakes.get(request.sender()?))
            .unwrap_or(&0);

        let whitelisted = request
            .sender()
            .map(|pubkey| whitelist.contains(pubkey))
            .unwrap_or_default();

        Ok(RepairRequestWithMeta {
            request,
            from_addr,
            stake,
            whitelisted,
            response_sender: remote_request.response_sender,
        })
    }

    fn record_request_decode_error(error: &Error, stats: &mut ServeRepairStats) {
        match error {
            Error::RepairVerify(RepairVerifyError::IdMismatch) => {
                stats.err_id_mismatch += 1;
            }
            Error::RepairVerify(RepairVerifyError::Malformed) => {
                stats.err_malformed += 1;
            }
            Error::RepairVerify(RepairVerifyError::SelfRepair) => {
                stats.err_self_repair += 1;
            }
            Error::RepairVerify(RepairVerifyError::SigVerify) => {
                stats.err_sig_verify += 1;
            }
            Error::RepairVerify(RepairVerifyError::TimeSkew) => {
                stats.err_time_skew += 1;
            }
            Error::RepairVerify(RepairVerifyError::Unsigned) => {
                stats.err_unsigned += 1;
            }
            _ => {
                debug_assert!(false, "unhandled error {error:?}");
            }
        }
    }

    fn decode_requests(
        requests: Vec<RemoteRequest>,
        epoch_staked_nodes: &Option<Arc<HashMap<Pubkey, u64>>>,
        whitelist: &HashSet<Pubkey>,
        my_id: &Pubkey,
        socket_addr_space: &SocketAddrSpace,
        stats: &mut ServeRepairStats,
    ) -> Vec<RepairRequestWithMeta> {
        let decode_request = |request| {
            let result = Self::decode_request(
                request,
                epoch_staked_nodes,
                whitelist,
                my_id,
                socket_addr_space,
            );
            match &result {
                Ok(req) => {
                    if req.stake == 0 {
                        stats.handle_requests_unstaked += 1;
                    } else {
                        stats.handle_requests_staked += 1;
                    }
                }
                Err(e) => {
                    Self::record_request_decode_error(e, stats);
                }
            }
            result.ok()
        };
        requests.into_iter().filter_map(decode_request).collect()
    }

    /// Process messages from the network
    fn run_listen(
        &self,
        ping_cache: &mut PingCache,
        recycler: &PacketBatchRecycler,
        blockstore: &Blockstore,
        requests_receiver: &Receiver<RemoteRequest>,
        response_sender: &PacketBatchSender,
        stats: &mut ServeRepairStats,
        data_budget: &DataBudget,
    ) -> std::result::Result<(), RecvTimeoutError> {
        const TIMEOUT: Duration = Duration::from_secs(1);
        let mut requests = vec![requests_receiver.recv_timeout(TIMEOUT)?];
        const MAX_REQUESTS_PER_ITERATION: usize = 1024;
        let mut total_requests = requests.len();

        let socket_addr_space = *self.cluster_info.socket_addr_space();
        let root_bank = self.bank_forks.read().unwrap().root_bank();
        let epoch_staked_nodes = root_bank.epoch_staked_nodes(root_bank.epoch());
        let identity_keypair = self.cluster_info.keypair().clone();
        let my_id = identity_keypair.pubkey();

        let max_buffered_packets = if self.repair_whitelist.read().unwrap().len() > 0 {
            4 * MAX_REQUESTS_PER_ITERATION
        } else {
            2 * MAX_REQUESTS_PER_ITERATION
        };

        let mut dropped_requests = 0;
        let mut well_formed_requests = discard_malformed_repair_requests(&mut requests, stats);
        loop {
            let mut more: Vec<_> = requests_receiver.try_iter().collect();
            if more.is_empty() {
                break;
            }
            total_requests += more.len();
            if well_formed_requests > max_buffered_packets {
                // Already exceeded max. Don't waste time discarding
                dropped_requests += more.len();
                continue;
            }
            let retained = discard_malformed_repair_requests(&mut more, stats);
            well_formed_requests += retained;
            if retained > 0 && well_formed_requests <= max_buffered_packets {
                requests.extend(more);
            } else {
                dropped_requests += more.len();
            }
        }

        stats.dropped_requests_load_shed += dropped_requests;
        stats.total_requests += total_requests;

        let decode_start = Instant::now();
        let mut decoded_requests = {
            let whitelist = self.repair_whitelist.read().unwrap();
            Self::decode_requests(
                requests,
                &epoch_staked_nodes,
                &whitelist,
                &my_id,
                &socket_addr_space,
                stats,
            )
        };
        let whitelisted_request_count = decoded_requests.iter().filter(|r| r.whitelisted).count();
        stats.decode_time_us += decode_start.elapsed().as_micros() as u64;
        stats.whitelisted_requests += whitelisted_request_count.min(MAX_REQUESTS_PER_ITERATION);

        if decoded_requests.len() > MAX_REQUESTS_PER_ITERATION {
            stats.dropped_requests_low_stake += decoded_requests.len() - MAX_REQUESTS_PER_ITERATION;
            decoded_requests.sort_unstable_by_key(|r| Reverse((r.whitelisted, r.stake)));
            decoded_requests.truncate(MAX_REQUESTS_PER_ITERATION);
        }

        let handle_requests_start = Instant::now();
        self.handle_requests(
            ping_cache,
            recycler,
            blockstore,
            decoded_requests,
            response_sender,
            stats,
            data_budget,
        );
        stats.handle_requests_time_us += handle_requests_start.elapsed().as_micros() as u64;

        Ok(())
    }

    fn report_reset_stats(&self, stats: &mut ServeRepairStats) {
        if stats.err_self_repair > 0 {
            let my_id = self.cluster_info.id();
            warn!(
                "{}: Ignored received repair requests from ME: {}",
                my_id, stats.err_self_repair,
            );
        }

        datapoint_info!(
            "serve_repair-requests_received",
            ("total_requests", stats.total_requests, i64),
            (
                "dropped_requests_outbound_bandwidth",
                stats.dropped_requests_outbound_bandwidth,
                i64
            ),
            (
                "dropped_requests_load_shed",
                stats.dropped_requests_load_shed,
                i64
            ),
            (
                "dropped_requests_low_stake",
                stats.dropped_requests_low_stake,
                i64
            ),
            ("whitelisted_requests", stats.whitelisted_requests, i64),
            (
                "total_dropped_response_packets",
                stats.total_dropped_response_packets,
                i64
            ),
            ("handle_requests_staked", stats.handle_requests_staked, i64),
            (
                "handle_requests_unstaked",
                stats.handle_requests_unstaked,
                i64
            ),
            ("processed", stats.processed, i64),
            ("total_response_packets", stats.total_response_packets, i64),
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
            ("self_repair", stats.err_self_repair, i64),
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
            ("window_index_misses", stats.window_index_misses, i64),
            (
                "ping_cache_check_failed",
                stats.ping_cache_check_failed,
                i64
            ),
            ("pings_sent", stats.pings_sent, i64),
            ("decode_time_us", stats.decode_time_us, i64),
            (
                "handle_requests_time_us",
                stats.handle_requests_time_us,
                i64
            ),
            ("err_time_skew", stats.err_time_skew, i64),
            ("err_malformed", stats.err_malformed, i64),
            ("err_sig_verify", stats.err_sig_verify, i64),
            ("err_unsigned", stats.err_unsigned, i64),
            ("err_id_mismatch", stats.err_id_mismatch, i64),
        );

        *stats = ServeRepairStats::default();
    }

    pub fn listen(
        self,
        blockstore: Arc<Blockstore>,
        requests_receiver: Receiver<RemoteRequest>,
        response_sender: PacketBatchSender,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        const INTERVAL_MS: u64 = 1000;
        const MAX_BYTES_PER_SECOND: usize = 12_000_000;
        const MAX_BYTES_PER_INTERVAL: usize = MAX_BYTES_PER_SECOND * INTERVAL_MS as usize / 1000;

        // rate limit delay should be greater than the repair request iteration delay
        assert!(REPAIR_PING_CACHE_RATE_LIMIT_DELAY > Duration::from_millis(REPAIR_MS));

        let mut ping_cache = PingCache::new(
            REPAIR_PING_CACHE_TTL,
            REPAIR_PING_CACHE_RATE_LIMIT_DELAY,
            REPAIR_PING_CACHE_CAPACITY,
        );

        let recycler = PacketBatchRecycler::default();
        Builder::new()
            .name("solRepairListen".to_string())
            .spawn(move || {
                let mut last_print = Instant::now();
                let mut stats = ServeRepairStats::default();
                let data_budget = DataBudget::default();
                while !exit.load(Ordering::Relaxed) {
                    let result = self.run_listen(
                        &mut ping_cache,
                        &recycler,
                        &blockstore,
                        &requests_receiver,
                        &response_sender,
                        &mut stats,
                        &data_budget,
                    );
                    match result {
                        Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => {
                            info!("repair listener disconnected");
                            return;
                        }
                    };
                    if last_print.elapsed().as_secs() > 2 {
                        self.report_reset_stats(&mut stats);
                        last_print = Instant::now();
                    }
                    data_budget.update(INTERVAL_MS, |_bytes| MAX_BYTES_PER_INTERVAL);
                }
            })
            .unwrap()
    }

    fn verify_signed_packet(my_id: &Pubkey, bytes: &[u8], request: &RepairProtocol) -> Result<()> {
        match request {
            RepairProtocol::LegacyWindowIndex
            | RepairProtocol::LegacyHighestWindowIndex
            | RepairProtocol::LegacyOrphan
            | RepairProtocol::LegacyWindowIndexWithNonce
            | RepairProtocol::LegacyHighestWindowIndexWithNonce
            | RepairProtocol::LegacyOrphanWithNonce
            | RepairProtocol::LegacyAncestorHashes => {
                return Err(Error::from(RepairVerifyError::Unsigned));
            }
            RepairProtocol::Pong(pong) => {
                if !pong.verify() {
                    return Err(Error::from(RepairVerifyError::SigVerify));
                }
            }
            RepairProtocol::WindowIndex { header, .. }
            | RepairProtocol::HighestWindowIndex { header, .. }
            | RepairProtocol::Orphan { header, .. }
            | RepairProtocol::AncestorHashes { header, .. } => {
                if &header.recipient != my_id {
                    return Err(Error::from(RepairVerifyError::IdMismatch));
                }
                let time_diff_ms = timestamp().abs_diff(header.timestamp);
                if u128::from(time_diff_ms) > SIGNED_REPAIR_TIME_WINDOW.as_millis() {
                    return Err(Error::from(RepairVerifyError::TimeSkew));
                }
                let Some(leading_buf) = bytes.get(..4) else {
                    debug_assert!(
                        false,
                        "request should have failed deserialization: {request:?}",
                    );
                    return Err(Error::from(RepairVerifyError::Malformed));
                };
                let Some(trailing_buf) = bytes.get(4 + SIGNATURE_BYTES..) else {
                    debug_assert!(
                        false,
                        "request should have failed deserialization: {request:?}",
                    );
                    return Err(Error::from(RepairVerifyError::Malformed));
                };
                let Some(from_id) = request.sender() else {
                    return Err(Error::from(RepairVerifyError::SigVerify));
                };
                let signed_data = [leading_buf, trailing_buf].concat();
                if !header.signature.verify(from_id.as_ref(), &signed_data) {
                    return Err(Error::from(RepairVerifyError::SigVerify));
                }
            }
        }
        Ok(())
    }

    fn check_ping_cache(
        ping_cache: &mut PingCache,
        request: &RepairProtocol,
        from_addr: &SocketAddr,
        identity_keypair: &Keypair,
    ) -> (bool, Option<Packet>) {
        let mut rng = rand::thread_rng();
        let mut pingf = move || Ping::new_rand(&mut rng, identity_keypair).ok();
        let (check, ping) = request
            .sender()
            .map(|&sender| ping_cache.check(Instant::now(), (sender, *from_addr), &mut pingf))
            .unwrap_or_default();
        let ping_pkt = if let Some(ping) = ping {
            match request {
                RepairProtocol::WindowIndex { .. }
                | RepairProtocol::HighestWindowIndex { .. }
                | RepairProtocol::Orphan { .. } => {
                    let ping = RepairResponse::Ping(ping);
                    Packet::from_data(Some(from_addr), ping).ok()
                }
                RepairProtocol::AncestorHashes { .. } => {
                    let ping = AncestorHashesResponse::Ping(ping);
                    Packet::from_data(Some(from_addr), ping).ok()
                }
                RepairProtocol::Pong(_) => None,
                RepairProtocol::LegacyWindowIndex
                | RepairProtocol::LegacyHighestWindowIndex
                | RepairProtocol::LegacyOrphan
                | RepairProtocol::LegacyWindowIndexWithNonce
                | RepairProtocol::LegacyHighestWindowIndexWithNonce
                | RepairProtocol::LegacyOrphanWithNonce
                | RepairProtocol::LegacyAncestorHashes => {
                    error!("Unexpected legacy request: {request:?}");
                    debug_assert!(
                        false,
                        "Legacy requests should have been filtered out during signature
                        verification. {request:?}"
                    );
                    None
                }
            }
        } else {
            None
        };
        (check, ping_pkt)
    }

    fn handle_requests(
        &self,
        ping_cache: &mut PingCache,
        recycler: &PacketBatchRecycler,
        blockstore: &Blockstore,
        requests: Vec<RepairRequestWithMeta>,
        packet_batch_sender: &PacketBatchSender,
        stats: &mut ServeRepairStats,
        data_budget: &DataBudget,
    ) {
        let identity_keypair = self.cluster_info.keypair().clone();
        let mut pending_pings = Vec::default();

        for RepairRequestWithMeta {
            request,
            from_addr,
            stake,
            whitelisted: _,
            response_sender,
        } in requests.into_iter()
        {
            if !data_budget.check(request.max_response_bytes()) {
                stats.dropped_requests_outbound_bandwidth += 1;
                continue;
            }
            // Bypass ping/pong check for requests coming from QUIC endpoint.
            if !matches!(&request, RepairProtocol::Pong(_)) && response_sender.is_none() {
                let (check, ping_pkt) =
                    Self::check_ping_cache(ping_cache, &request, &from_addr, &identity_keypair);
                if let Some(ping_pkt) = ping_pkt {
                    pending_pings.push(ping_pkt);
                }
                if !check {
                    stats.ping_cache_check_failed += 1;
                    continue;
                }
            }
            stats.processed += 1;
            let Some(rsp) =
                Self::handle_repair(recycler, &from_addr, blockstore, request, stats, ping_cache)
            else {
                continue;
            };
            let num_response_packets = rsp.len();
            let num_response_bytes = rsp.iter().map(|p| p.meta().size).sum();
            if data_budget.take(num_response_bytes)
                && send_response(rsp, packet_batch_sender, response_sender)
            {
                stats.total_response_packets += num_response_packets;
                match stake > 0 {
                    true => stats.total_response_bytes_staked += num_response_bytes,
                    false => stats.total_response_bytes_unstaked += num_response_bytes,
                }
            } else {
                stats.dropped_requests_outbound_bandwidth += 1;
                stats.total_dropped_response_packets += num_response_packets;
            }
        }

        if !pending_pings.is_empty() {
            stats.pings_sent += pending_pings.len();
            let batch = PacketBatch::new(pending_pings);
            let _ = packet_batch_sender.send(batch);
        }
    }

    pub fn ancestor_repair_request_bytes(
        &self,
        keypair: &Keypair,
        repair_peer_id: &Pubkey,
        request_slot: Slot,
        nonce: Nonce,
    ) -> Result<Vec<u8>> {
        let header = RepairRequestHeader {
            signature: Signature::default(),
            sender: self.my_id(),
            recipient: *repair_peer_id,
            timestamp: timestamp(),
            nonce,
        };
        let request = RepairProtocol::AncestorHashes {
            header,
            slot: request_slot,
        };
        Self::repair_proto_to_bytes(&request, keypair)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn repair_request(
        &self,
        cluster_slots: &ClusterSlots,
        repair_request: ShredRepairType,
        peers_cache: &mut LruCache<Slot, RepairPeers>,
        repair_stats: &mut RepairStats,
        repair_validators: &Option<HashSet<Pubkey>>,
        outstanding_requests: &mut OutstandingShredRepairs,
        identity_keypair: &Keypair,
        quic_endpoint_sender: &AsyncSender<LocalRequest>,
        quic_endpoint_response_sender: &Sender<(SocketAddr, Vec<u8>)>,
        repair_protocol: Protocol,
    ) -> Result<Option<(SocketAddr, Vec<u8>)>> {
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
        let peer = repair_peers.sample(&mut rand::thread_rng());
        let nonce = outstanding_requests.add_request(repair_request, timestamp());
        let out = self.map_repair_request(
            &repair_request,
            &peer.pubkey,
            repair_stats,
            nonce,
            identity_keypair,
        )?;
        debug!(
            "Sending repair request from {} for {:#?}",
            identity_keypair.pubkey(),
            repair_request
        );
        match repair_protocol {
            Protocol::UDP => Ok(Some((peer.serve_repair, out))),
            Protocol::QUIC => {
                let num_expected_responses =
                    usize::try_from(repair_request.num_expected_responses()).unwrap();
                let request = LocalRequest {
                    remote_address: peer.serve_repair_quic,
                    bytes: out,
                    num_expected_responses,
                    response_sender: quic_endpoint_response_sender.clone(),
                };
                quic_endpoint_sender
                    .blocking_send(request)
                    .map_err(|_| Error::SendError)
                    .map(|()| None)
            }
        }
    }

    pub(crate) fn repair_request_ancestor_hashes_sample_peers(
        &self,
        slot: Slot,
        cluster_slots: &ClusterSlots,
        repair_validators: &Option<HashSet<Pubkey>>,
        repair_protocol: Protocol,
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
            .map(|i| index[i])
            .filter_map(|i| {
                let addr = repair_peers[i].serve_repair(repair_protocol).ok()?;
                Some((*repair_peers[i].pubkey(), addr))
            })
            .take(get_ancestor_hash_repair_sample_size())
            .collect();
        Ok(peers)
    }

    pub(crate) fn map_repair_request(
        &self,
        repair_request: &ShredRepairType,
        repair_peer_id: &Pubkey,
        repair_stats: &mut RepairStats,
        nonce: Nonce,
        identity_keypair: &Keypair,
    ) -> Result<Vec<u8>> {
        let header = RepairRequestHeader {
            signature: Signature::default(),
            sender: self.my_id(),
            recipient: *repair_peer_id,
            timestamp: timestamp(),
            nonce,
        };
        let request_proto = match repair_request {
            ShredRepairType::Shred(slot, shred_index) => {
                repair_stats
                    .shred
                    .update(repair_peer_id, *slot, *shred_index);
                RepairProtocol::WindowIndex {
                    header,
                    slot: *slot,
                    shred_index: *shred_index,
                }
            }
            ShredRepairType::HighestShred(slot, shred_index) => {
                repair_stats
                    .highest_shred
                    .update(repair_peer_id, *slot, *shred_index);
                RepairProtocol::HighestWindowIndex {
                    header,
                    slot: *slot,
                    shred_index: *shred_index,
                }
            }
            ShredRepairType::Orphan(slot) => {
                repair_stats.orphan.update(repair_peer_id, *slot, 0);
                RepairProtocol::Orphan {
                    header,
                    slot: *slot,
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
            if packet.meta().size != REPAIR_RESPONSE_SERIALIZED_PING_BYTES {
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
                packet.meta_mut().set_discard(true);
                stats.ping_count += 1;
                if let Ok(pong) = Pong::new(&ping, keypair) {
                    let pong = RepairProtocol::Pong(pong);
                    if let Ok(pong_bytes) = serialize(&pong) {
                        let from_addr = packet.meta().socket_addr();
                        pending_pongs.push((pong_bytes, from_addr));
                    }
                }
            }
        }
        if !pending_pongs.is_empty() {
            match batch_send(repair_socket, &pending_pongs) {
                Ok(()) => (),
                Err(SendPktsError::IoError(err, num_failed)) => {
                    warn!(
                        "batch_send failed to send {}/{} packets. First error: {:?}",
                        num_failed,
                        pending_pongs.len(),
                        err
                    );
                }
            }
        }
    }

    pub fn repair_proto_to_bytes(request: &RepairProtocol, keypair: &Keypair) -> Result<Vec<u8>> {
        debug_assert!(request.supports_signature());
        let mut payload = serialize(&request)?;
        let signable_data = [&payload[..4], &payload[4 + SIGNATURE_BYTES..]].concat();
        let signature = keypair.sign_message(&signable_data[..]);
        payload[4..4 + SIGNATURE_BYTES].copy_from_slice(signature.as_ref());
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
        blockstore: &Blockstore,
        slot: Slot,
        shred_index: u64,
        nonce: Nonce,
    ) -> Option<PacketBatch> {
        // Try to find the requested index in one of the slots
        let packet = repair_response::repair_response_packet(
            blockstore,
            slot,
            shred_index,
            from_addr,
            nonce,
        )?;
        Some(PacketBatch::new_unpinned_with_recycler_data(
            recycler,
            "run_window_request",
            vec![packet],
        ))
    }

    fn run_highest_window_request(
        recycler: &PacketBatchRecycler,
        from_addr: &SocketAddr,
        blockstore: &Blockstore,
        slot: Slot,
        highest_index: u64,
        nonce: Nonce,
    ) -> Option<PacketBatch> {
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
        blockstore: &Blockstore,
        slot: Slot,
        max_responses: usize,
        nonce: Nonce,
    ) -> Option<PacketBatch> {
        let mut res =
            PacketBatch::new_unpinned_with_recycler(recycler, max_responses, "run_orphan");
        // Try to find the next "n" parent slots of the input slot
        let packets = std::iter::successors(blockstore.meta(slot).ok()?, |meta| {
            blockstore.meta(meta.parent_slot?).ok()?
        })
        .map_while(|meta| {
            repair_response::repair_response_packet(
                blockstore,
                meta.slot,
                meta.received.checked_sub(1u64)?,
                from_addr,
                nonce,
            )
        });
        for packet in packets.take(max_responses) {
            res.push(packet);
        }
        (!res.is_empty()).then_some(res)
    }

    fn run_ancestor_hashes(
        recycler: &PacketBatchRecycler,
        from_addr: &SocketAddr,
        blockstore: &Blockstore,
        slot: Slot,
        nonce: Nonce,
    ) -> Option<PacketBatch> {
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

#[inline]
pub(crate) fn get_repair_protocol(_: ClusterType) -> Protocol {
    Protocol::UDP
}

pub(crate) fn deserialize_request<T>(
    request: &RemoteRequest,
) -> std::result::Result<T, bincode::Error>
where
    T: serde::de::DeserializeOwned,
{
    bincode::options()
        .with_limit(request.bytes.len() as u64)
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&request.bytes)
}

// Returns true on success.
fn send_response(
    packets: PacketBatch,
    packet_batch_sender: &PacketBatchSender,
    response_sender: Option<OneShotSender<Vec<Vec<u8>>>>,
) -> bool {
    match response_sender {
        None => packet_batch_sender.send(packets).is_ok(),
        Some(response_sender) => {
            let response = packets
                .iter()
                .filter_map(|packet| packet.data(..))
                .map(Vec::from)
                .collect();
            response_sender.send(response).is_ok()
        }
    }
}
