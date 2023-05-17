//! The `cluster_info` module defines a data structure that is shared by all the nodes in the network over
//! a gossip control plane.  The goal is to share small bits of off-chain information and detect and
//! repair partitions.
//!
//! This CRDT only supports a very limited set of types.  A map of Pubkey -> Versioned Struct.
//! The last version is always picked during an update.
//!
//! The network is arranged in layers:
//!
//! * layer 0 - Leader.
//! * layer 1 - As many nodes as we can fit
//! * layer 2 - Everyone else, if layer 1 is `2^10`, layer 2 should be able to fit `2^20` number of nodes.
//!
//! Bank needs to provide an interface for us to query the stake weight

#[deprecated(
    since = "1.10.6",
    note = "Please use `solana_net_utils::{MINIMUM_VALIDATOR_PORT_RANGE_WIDTH, VALIDATOR_PORT_RANGE}` instead"
)]
#[allow(deprecated)]
pub use solana_net_utils::{MINIMUM_VALIDATOR_PORT_RANGE_WIDTH, VALIDATOR_PORT_RANGE};
use {
    crate::{
        cluster_info_metrics::{
            submit_gossip_stats, Counter, GossipStats, ScopedTimer, TimedGuard,
        },
        contact_info::{self, ContactInfo, Error as ContactInfoError, LegacyContactInfo},
        crds::{Crds, Cursor, GossipRoute},
        crds_gossip::CrdsGossip,
        crds_gossip_error::CrdsGossipError,
        crds_gossip_pull::{
            CrdsFilter, CrdsTimeouts, ProcessPullStats, CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS,
        },
        crds_value::{
            self, AccountsHashes, CrdsData, CrdsValue, CrdsValueLabel, EpochSlotsIndex,
            LegacySnapshotHashes, LowestSlot, NodeInstance, SnapshotHashes, Version, Vote,
            MAX_WALLCLOCK,
        },
        duplicate_shred::DuplicateShred,
        epoch_slots::EpochSlots,
        gossip_error::GossipError,
        ping_pong::{self, PingCache, Pong},
        socketaddr, socketaddr_any,
        weighted_shuffle::WeightedShuffle,
    },
    bincode::{serialize, serialized_size},
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender},
    itertools::Itertools,
    rand::{seq::SliceRandom, thread_rng, CryptoRng, Rng},
    rayon::{prelude::*, ThreadPool, ThreadPoolBuilder},
    serde::ser::Serialize,
    solana_ledger::shred::Shred,
    solana_measure::measure::Measure,
    solana_net_utils::{
        bind_common, bind_common_in_range, bind_in_range, bind_two_in_range_with_offset,
        find_available_port_in_range, multi_bind_in_range, PortRange,
    },
    solana_perf::{
        data_budget::DataBudget,
        packet::{Packet, PacketBatch, PacketBatchRecycler, PACKET_DATA_SIZE},
    },
    solana_rayon_threadlimit::get_thread_count,
    solana_runtime::{bank_forks::BankForks, vote_parser},
    solana_sdk::{
        clock::{Slot, DEFAULT_MS_PER_SLOT, DEFAULT_SLOTS_PER_EPOCH},
        feature_set::FeatureSet,
        hash::Hash,
        pubkey::Pubkey,
        quic::QUIC_PORT_OFFSET,
        sanitize::{Sanitize, SanitizeError},
        signature::{Keypair, Signable, Signature, Signer},
        timing::timestamp,
        transaction::Transaction,
    },
    solana_streamer::{
        packet,
        socket::SocketAddrSpace,
        streamer::{PacketBatchReceiver, PacketBatchSender},
    },
    solana_vote_program::vote_state::MAX_LOCKOUT_HISTORY,
    std::{
        borrow::Cow,
        collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
        fmt::Debug,
        fs::{self, File},
        io::BufReader,
        iter::repeat,
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
        ops::{Deref, Div},
        path::{Path, PathBuf},
        result::Result,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex, RwLock, RwLockReadGuard,
        },
        thread::{sleep, Builder, JoinHandle},
        time::{Duration, Instant},
    },
    thiserror::Error,
};

/// The Data plane fanout size, also used as the neighborhood size
pub const DATA_PLANE_FANOUT: usize = 200;
/// milliseconds we sleep for between gossip requests
pub const GOSSIP_SLEEP_MILLIS: u64 = 100;
/// The maximum size of a bloom filter
pub const MAX_BLOOM_SIZE: usize = MAX_CRDS_OBJECT_SIZE;
pub const MAX_CRDS_OBJECT_SIZE: usize = 928;
/// A hard limit on incoming gossip messages
/// Chosen to be able to handle 1Gbps of pure gossip traffic
/// 128MB/PACKET_DATA_SIZE
const MAX_GOSSIP_TRAFFIC: usize = 128_000_000 / PACKET_DATA_SIZE;
/// Max size of serialized crds-values in a Protocol::PushMessage packet. This
/// is equal to PACKET_DATA_SIZE minus serialized size of an empty push
/// message: Protocol::PushMessage(Pubkey::default(), Vec::default())
const PUSH_MESSAGE_MAX_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;
pub(crate) const DUPLICATE_SHRED_MAX_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 115;
/// Maximum number of hashes in AccountsHashes a node publishes
/// such that the serialized size of the push/pull message stays below
/// PACKET_DATA_SIZE.
pub const MAX_ACCOUNTS_HASHES: usize = 16;
/// Maximum number of hashes in LegacySnapshotHashes a node publishes
/// such that the serialized size of the push/pull message stays below
/// PACKET_DATA_SIZE.
pub const MAX_LEGACY_SNAPSHOT_HASHES: usize = 16;
/// Maximum number of incremental hashes in SnapshotHashes a node publishes
/// such that the serialized size of the push/pull message stays below
/// PACKET_DATA_SIZE.
pub const MAX_INCREMENTAL_SNAPSHOT_HASHES: usize = 25;
/// Maximum number of origin nodes that a PruneData may contain, such that the
/// serialized size of the PruneMessage stays below PACKET_DATA_SIZE.
const MAX_PRUNE_DATA_NODES: usize = 32;
/// Number of bytes in the randomly generated token sent with ping messages.
const GOSSIP_PING_TOKEN_SIZE: usize = 32;
const GOSSIP_PING_CACHE_CAPACITY: usize = 65536;
const GOSSIP_PING_CACHE_TTL: Duration = Duration::from_secs(1280);
const GOSSIP_PING_CACHE_RATE_LIMIT_DELAY: Duration = Duration::from_secs(1280 / 64);
pub const DEFAULT_CONTACT_DEBUG_INTERVAL_MILLIS: u64 = 10_000;
pub const DEFAULT_CONTACT_SAVE_INTERVAL_MILLIS: u64 = 60_000;
/// Minimum serialized size of a Protocol::PullResponse packet.
const PULL_RESPONSE_MIN_SERIALIZED_SIZE: usize = 161;
// Limit number of unique pubkeys in the crds table.
pub(crate) const CRDS_UNIQUE_PUBKEY_CAPACITY: usize = 8192;
/// Minimum stake that a node should have so that its CRDS values are
/// propagated through gossip (few types are exempted).
const MIN_STAKE_FOR_GOSSIP: u64 = solana_sdk::native_token::LAMPORTS_PER_SOL;
/// Minimum number of staked nodes for enforcing stakes in gossip.
const MIN_NUM_STAKED_NODES: usize = 500;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ClusterInfoError {
    #[error("NoPeers")]
    NoPeers,
    #[error("NoLeader")]
    NoLeader,
    #[error("BadContactInfo")]
    BadContactInfo,
    #[error("BadGossipAddress")]
    BadGossipAddress,
    #[error("TooManyIncrementalSnapshotHashes")]
    TooManyIncrementalSnapshotHashes,
}

pub struct ClusterInfo {
    /// The network
    pub gossip: CrdsGossip,
    /// set the keypair that will be used to sign crds values generated. It is unset only in tests.
    keypair: RwLock<Arc<Keypair>>,
    /// Network entrypoints
    entrypoints: RwLock<Vec<LegacyContactInfo>>,
    outbound_budget: DataBudget,
    my_contact_info: RwLock<ContactInfo>,
    ping_cache: Mutex<PingCache>,
    stats: GossipStats,
    socket: UdpSocket,
    local_message_pending_push_queue: Mutex<Vec<CrdsValue>>,
    contact_debug_interval: u64, // milliseconds, 0 = disabled
    contact_save_interval: u64,  // milliseconds, 0 = disabled
    instance: RwLock<NodeInstance>,
    contact_info_path: PathBuf,
    socket_addr_space: SocketAddrSpace,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, AbiExample)]
pub(crate) struct PruneData {
    /// Pubkey of the node that sent this prune data
    pubkey: Pubkey,
    /// Pubkeys of nodes that should be pruned
    prunes: Vec<Pubkey>,
    /// Signature of this Prune Message
    signature: Signature,
    /// The Pubkey of the intended node/destination for this message
    destination: Pubkey,
    /// Wallclock of the node that generated this message
    wallclock: u64,
}

impl PruneData {
}

impl Sanitize for PruneData {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        if self.wallclock >= MAX_WALLCLOCK {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        Ok(())
    }
}

impl Signable for PruneData {
    fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    fn signable_data(&self) -> Cow<[u8]> {
        #[derive(Serialize)]
        struct SignData<'a> {
            pubkey: &'a Pubkey,
            prunes: &'a [Pubkey],
            destination: &'a Pubkey,
            wallclock: u64,
        }
        let data = SignData {
            pubkey: &self.pubkey,
            prunes: &self.prunes,
            destination: &self.destination,
            wallclock: self.wallclock,
        };
        Cow::Owned(serialize(&data).expect("serialize PruneData"))
    }

    fn get_signature(&self) -> Signature {
        self.signature
    }

    fn set_signature(&mut self, signature: Signature) {
        self.signature = signature
    }
}

struct PullData {
    from_addr: SocketAddr,
    caller: CrdsValue,
    filter: CrdsFilter,
}

pub fn make_accounts_hashes_message(
    keypair: &Keypair,
    accounts_hashes: Vec<(Slot, Hash)>,
) -> Option<CrdsValue> {
    let message = CrdsData::AccountsHashes(AccountsHashes::new(keypair.pubkey(), accounts_hashes));
    Some(CrdsValue::new_signed(message, keypair))
}

pub(crate) type Ping = ping_pong::Ping<[u8; GOSSIP_PING_TOKEN_SIZE]>;

// TODO These messages should go through the gpu pipeline for spam filtering
#[frozen_abi(digest = "Ctxue3UVFXXqnHoMVAPmfBoCy3Cyg7gNCYBY7Cg9P3so")]
#[derive(Serialize, Deserialize, Debug, AbiEnumVisitor, AbiExample)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Protocol {
    /// Gossip protocol messages
    PullRequest(CrdsFilter, CrdsValue),
    PullResponse(Pubkey, Vec<CrdsValue>),
    PushMessage(Pubkey, Vec<CrdsValue>),
    // TODO: Remove the redundant outer pubkey here,
    // and use the inner PruneData.pubkey instead.
    PruneMessage(Pubkey, PruneData),
    PingMessage(Ping),
    PongMessage(Pong),
    // Update count_packets_received if new variants are added here.
}

impl Protocol {
    fn par_verify(self, stats: &GossipStats) -> Option<Self> {
        match self {
            Protocol::PullRequest(_, ref caller) => {
                if caller.verify() {
                    Some(self)
                } else {
                    stats.gossip_pull_request_verify_fail.add_relaxed(1);
                    None
                }
            }
            Protocol::PullResponse(from, data) => {
                let size = data.len();
                let data: Vec<_> = data.into_par_iter().filter(Signable::verify).collect();
                if size != data.len() {
                    stats
                        .gossip_pull_response_verify_fail
                        .add_relaxed((size - data.len()) as u64);
                }
                if data.is_empty() {
                    None
                } else {
                    Some(Protocol::PullResponse(from, data))
                }
            }
            Protocol::PushMessage(from, data) => {
                let size = data.len();
                let data: Vec<_> = data.into_par_iter().filter(Signable::verify).collect();
                if size != data.len() {
                    stats
                        .gossip_push_msg_verify_fail
                        .add_relaxed((size - data.len()) as u64);
                }
                if data.is_empty() {
                    None
                } else {
                    Some(Protocol::PushMessage(from, data))
                }
            }
            Protocol::PruneMessage(_, ref data) => {
                if data.verify() {
                    Some(self)
                } else {
                    stats.gossip_prune_msg_verify_fail.add_relaxed(1);
                    None
                }
            }
            Protocol::PingMessage(ref ping) => {
                if ping.verify() {
                    Some(self)
                } else {
                    stats.gossip_ping_msg_verify_fail.add_relaxed(1);
                    None
                }
            }
            Protocol::PongMessage(ref pong) => {
                if pong.verify() {
                    Some(self)
                } else {
                    stats.gossip_pong_msg_verify_fail.add_relaxed(1);
                    None
                }
            }
        }
    }
}

impl Sanitize for Protocol {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        match self {
            Protocol::PullRequest(filter, val) => {
                filter.sanitize()?;
                val.sanitize()
            }
            Protocol::PullResponse(_, val) => val.sanitize(),
            Protocol::PushMessage(_, val) => val.sanitize(),
            Protocol::PruneMessage(from, val) => {
                if *from != val.pubkey {
                    Err(SanitizeError::InvalidValue)
                } else {
                    val.sanitize()
                }
            }
            Protocol::PingMessage(ping) => ping.sanitize(),
            Protocol::PongMessage(pong) => pong.sanitize(),
        }
    }
}

// Retains only CRDS values associated with nodes with enough stake.
// (some crds types are exempted)
fn retain_staked(values: &mut Vec<CrdsValue>, stakes: &HashMap<Pubkey, u64>) {
    values.retain(|value| {
        match value.data {
            CrdsData::ContactInfo(_) => true,
            CrdsData::LegacyContactInfo(_) => true,
            // May Impact new validators starting up without any stake yet.
            CrdsData::Vote(_, _) => true,
            // Unstaked nodes can still help repair.
            CrdsData::EpochSlots(_, _) => true,
            // Unstaked nodes can still serve snapshots.
            CrdsData::LegacySnapshotHashes(_) | CrdsData::SnapshotHashes(_) => true,
            // Otherwise unstaked voting nodes will show up with no version in
            // the various dashboards.
            CrdsData::Version(_) => true,
            CrdsData::NodeInstance(_) => true,
            // getHealth fails if account hashes are not propagated.
            CrdsData::AccountsHashes(_) => true,
            CrdsData::LowestSlot(_, _)
            | CrdsData::LegacyVersion(_)
            | CrdsData::DuplicateShred(_, _) => {
                let stake = stakes.get(&value.pubkey()).copied();
                stake.unwrap_or_default() >= MIN_STAKE_FOR_GOSSIP
            }
        }
    })
}

impl ClusterInfo {
    pub fn new(
        contact_info: ContactInfo,
        keypair: Arc<Keypair>,
        socket_addr_space: SocketAddrSpace,
    ) -> Self {
        assert_eq!(contact_info.pubkey(), &keypair.pubkey());
        let id = *contact_info.pubkey();
        let me = Self {
            gossip: CrdsGossip::default(),
            keypair: RwLock::new(keypair),
            entrypoints: RwLock::default(),
            outbound_budget: DataBudget::default(),
            my_contact_info: RwLock::new(contact_info),
            ping_cache: Mutex::new(PingCache::new(
                GOSSIP_PING_CACHE_TTL,
                GOSSIP_PING_CACHE_RATE_LIMIT_DELAY,
                GOSSIP_PING_CACHE_CAPACITY,
            )),
            stats: GossipStats::default(),
            socket: UdpSocket::bind("0.0.0.0:0").unwrap(),
            local_message_pending_push_queue: Mutex::default(),
            contact_debug_interval: DEFAULT_CONTACT_DEBUG_INTERVAL_MILLIS,
            instance: RwLock::new(NodeInstance::new(&mut thread_rng(), id, timestamp())),
            contact_info_path: PathBuf::default(),
            contact_save_interval: 0, // disabled
            socket_addr_space,
        };
        me.insert_self();
        me.push_self();
        me
    }

    pub fn set_contact_debug_interval(&mut self, new: u64) {
        self.contact_debug_interval = new;
    }

    pub fn socket_addr_space(&self) -> &SocketAddrSpace {
        &self.socket_addr_space
    }

    fn push_self(&self) {
        let now = timestamp();
        let node = {
            let mut node = self.my_contact_info.write().unwrap();
            node.set_wallclock(now);
            node.clone()
        };
        let entries: Vec<_> = [
            LegacyContactInfo::try_from(&node)
                .map(CrdsData::LegacyContactInfo)
                .expect("Operator must spin up node with valid contact-info"),
            CrdsData::ContactInfo(node),
            CrdsData::NodeInstance(self.instance.read().unwrap().with_wallclock(now)),
        ]
        .into_iter()
        .map(|v| CrdsValue::new_signed(v, &self.keypair()))
        .collect();
        self.local_message_pending_push_queue
            .lock()
            .unwrap()
            .extend(entries);
    }

    fn refresh_push_active_set(
        &self,
        recycler: &PacketBatchRecycler,
        stakes: &HashMap<Pubkey, u64>,
        gossip_validators: Option<&HashSet<Pubkey>>,
        sender: &PacketBatchSender,
    ) {
        let shred_version = self.my_contact_info.read().unwrap().shred_version();
        let self_keypair: Arc<Keypair> = self.keypair().clone();
        let mut pings = Vec::new();
        self.gossip.refresh_push_active_set(
            &self_keypair,
            shred_version,
            stakes,
            gossip_validators,
            &self.ping_cache,
            &mut pings,
            &self.socket_addr_space,
        );
        self.stats
            .new_pull_requests_pings_count
            .add_relaxed(pings.len() as u64);
        let pings: Vec<_> = pings
            .into_iter()
            .map(|(addr, ping)| (addr, Protocol::PingMessage(ping)))
            .collect();
        if !pings.is_empty() {
            self.stats
                .packets_sent_gossip_requests_count
                .add_relaxed(pings.len() as u64);
            let packet_batch = PacketBatch::new_unpinned_with_recycler_data_and_dests(
                recycler.clone(),
                "refresh_push_active_set",
                &pings,
            );
            let _ = sender.send(packet_batch);
        }
    }

    // TODO kill insert_info, only used by tests
    pub fn insert_legacy_info(&self, contact_info: LegacyContactInfo) {
        let value =
            CrdsValue::new_signed(CrdsData::LegacyContactInfo(contact_info), &self.keypair());
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        let _ = gossip_crds.insert(value, timestamp(), GossipRoute::LocalMessage);
    }

    pub fn insert_info(&self, node: ContactInfo) {
        let entries: Vec<_> = [
            LegacyContactInfo::try_from(&node)
                .map(CrdsData::LegacyContactInfo)
                .expect("Operator must spin up node with valid contact-info"),
            CrdsData::ContactInfo(node),
        ]
        .into_iter()
        .map(|entry| CrdsValue::new_signed(entry, &self.keypair()))
        .collect();
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        for entry in entries {
            let _ = gossip_crds.insert(entry, timestamp(), GossipRoute::LocalMessage);
        }
    }

    pub fn set_entrypoint(&self, entrypoint: LegacyContactInfo) {
        self.set_entrypoints(vec![entrypoint]);
    }

    pub fn set_entrypoints(&self, entrypoints: Vec<LegacyContactInfo>) {
        *self.entrypoints.write().unwrap() = entrypoints;
    }

    pub fn save_contact_info(&self) {
        let nodes = {
            let entrypoint_gossip_addrs = self
                .entrypoints
                .read()
                .unwrap()
                .iter()
                .filter_map(|node| node.gossip().ok())
                .collect::<HashSet<_>>();
            let self_pubkey = self.id();
            let gossip_crds = self.gossip.crds.read().unwrap();
            gossip_crds
                .get_nodes()
                .filter_map(|v| {
                    // Don't save:
                    // 1. Our ContactInfo. No point
                    // 2. Entrypoint ContactInfo. This will avoid adopting the incorrect shred
                    //    version on restart if the entrypoint shred version changes.  Also
                    //    there's not much point in saving entrypoint ContactInfo since by
                    //    definition that information is already available
                    let contact_info = v.value.contact_info().unwrap();
                    if contact_info.pubkey() != &self_pubkey
                        && contact_info
                            .gossip()
                            .map(|addr| !entrypoint_gossip_addrs.contains(&addr))
                            .unwrap_or_default()
                    {
                        return Some(v.value.clone());
                    }
                    None
                })
                .collect::<Vec<_>>()
        };

        if nodes.is_empty() {
            return;
        }

        let filename = self.contact_info_path.join("contact-info.bin");
        let tmp_filename = &filename.with_extension("tmp");

        match File::create(tmp_filename) {
            Ok(mut file) => {
                if let Err(err) = bincode::serialize_into(&mut file, &nodes) {
                    warn!(
                        "Failed to serialize contact info info {}: {}",
                        tmp_filename.display(),
                        err
                    );
                    return;
                }
            }
            Err(err) => {
                warn!("Failed to create {}: {}", tmp_filename.display(), err);
                return;
            }
        }

        match fs::rename(tmp_filename, &filename) {
            Ok(()) => {
                info!(
                    "Saved contact info for {} nodes into {}",
                    nodes.len(),
                    filename.display()
                );
            }
            Err(err) => {
                warn!(
                    "Failed to rename {} to {}: {}",
                    tmp_filename.display(),
                    filename.display(),
                    err
                );
            }
        }
    }

    pub fn restore_contact_info(&mut self, contact_info_path: &Path, contact_save_interval: u64) {
        self.contact_info_path = contact_info_path.into();
        self.contact_save_interval = contact_save_interval;

        let filename = contact_info_path.join("contact-info.bin");
        if !filename.exists() {
            return;
        }

        let nodes: Vec<CrdsValue> = match File::open(&filename) {
            Ok(file) => {
                bincode::deserialize_from(&mut BufReader::new(file)).unwrap_or_else(|err| {
                    warn!("Failed to deserialize {}: {}", filename.display(), err);
                    vec![]
                })
            }
            Err(err) => {
                warn!("Failed to open {}: {}", filename.display(), err);
                vec![]
            }
        };

        info!(
            "Loaded contact info for {} nodes from {}",
            nodes.len(),
            filename.display()
        );
        let now = timestamp();
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        for node in nodes {
            if let Err(err) = gossip_crds.insert(node, now, GossipRoute::LocalMessage) {
                warn!("crds insert failed {:?}", err);
            }
        }
    }

    pub fn id(&self) -> Pubkey {
        self.keypair.read().unwrap().pubkey()
    }

    pub fn keypair(&self) -> RwLockReadGuard<Arc<Keypair>> {
        self.keypair.read().unwrap()
    }

    pub fn set_keypair(&self, new_keypair: Arc<Keypair>) {
        let id = new_keypair.pubkey();
        {
            let mut instance = self.instance.write().unwrap();
            *instance = NodeInstance::new(&mut thread_rng(), id, timestamp());
        }
        *self.keypair.write().unwrap() = new_keypair;
        self.my_contact_info.write().unwrap().set_pubkey(id);

        self.insert_self();
        self.push_message(CrdsValue::new_signed(
            CrdsData::Version(Version::new(self.id())),
            &self.keypair(),
        ));
        self.push_self();
    }

    pub fn set_tpu(&self, tpu_addr: SocketAddr) -> Result<(), ContactInfoError> {
        self.my_contact_info.write().unwrap().set_tpu(tpu_addr)?;
        self.insert_self();
        self.push_self();
        Ok(())
    }

    pub fn set_tpu_forwards(&self, tpu_forwards_addr: SocketAddr) -> Result<(), ContactInfoError> {
        self.my_contact_info
            .write()
            .unwrap()
            .set_tpu_forwards(tpu_forwards_addr)?;
        self.insert_self();
        self.push_self();
        Ok(())
    }

    pub fn lookup_contact_info<F, Y>(&self, id: &Pubkey, map: F) -> Option<Y>
    where
        F: FnOnce(&LegacyContactInfo) -> Y,
    {
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds.get(*id).map(map)
    }

    pub fn lookup_contact_info_by_gossip_addr(
        &self,
        gossip_addr: &SocketAddr,
    ) -> Option<LegacyContactInfo> {
        let gossip_crds = self.gossip.crds.read().unwrap();
        let mut nodes = gossip_crds.get_nodes_contact_info();
        nodes
            .find(|node| node.gossip().ok() == Some(*gossip_addr))
            .cloned()
    }

    pub fn my_contact_info(&self) -> ContactInfo {
        self.my_contact_info.read().unwrap().clone()
    }

    pub fn my_shred_version(&self) -> u16 {
        self.my_contact_info.read().unwrap().shred_version()
    }

    fn lookup_epoch_slots(&self, ix: EpochSlotsIndex) -> EpochSlots {
        let self_pubkey = self.id();
        let label = CrdsValueLabel::EpochSlots(ix, self_pubkey);
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get::<&CrdsValue>(&label)
            .and_then(|v| v.epoch_slots())
            .cloned()
            .unwrap_or_else(|| EpochSlots::new(self_pubkey, timestamp()))
    }

    fn addr_to_string(&self, default_ip: &Option<IpAddr>, addr: &Option<SocketAddr>) -> String {
        addr.filter(|addr| self.socket_addr_space.check(addr))
            .map(|addr| {
                if &Some(addr.ip()) == default_ip {
                    addr.port().to_string()
                } else {
                    addr.to_string()
                }
            })
            .unwrap_or_else(|| String::from("none"))
    }

    pub fn rpc_info_trace(&self) -> String {
        let now = timestamp();
        let my_pubkey = self.id();
        let my_shred_version = self.my_shred_version();
        let nodes: Vec<_> = self
            .all_peers()
            .into_iter()
            .filter_map(|(node, last_updated)| {
                let node_rpc = node
                    .rpc()
                    .ok()
                    .filter(|addr| self.socket_addr_space.check(addr))?;
                let node_version = self.get_node_version(node.pubkey());
                if my_shred_version != 0
                    && (node.shred_version() != 0 && node.shred_version() != my_shred_version)
                {
                    return None;
                }
                let rpc_addr = node_rpc.ip();
                Some(format!(
                    "{:15} {:2}| {:5} | {:44} |{:^9}| {:5}| {:5}| {}\n",
                    rpc_addr.to_string(),
                    if node.pubkey() == &my_pubkey {
                        "me"
                    } else {
                        ""
                    },
                    now.saturating_sub(last_updated),
                    node.pubkey(),
                    if let Some(node_version) = node_version {
                        node_version.to_string()
                    } else {
                        "-".to_string()
                    },
                    self.addr_to_string(&Some(rpc_addr), &node.rpc().ok()),
                    self.addr_to_string(&Some(rpc_addr), &node.rpc_pubsub().ok()),
                    node.shred_version(),
                ))
            })
            .collect();

        format!(
            "RPC Address       |Age(ms)| Node identifier                              \
             | Version | RPC  |PubSub|ShredVer\n\
             ------------------+-------+----------------------------------------------\
             +---------+------+------+--------\n\
             {}\
             RPC Enabled Nodes: {}",
            nodes.join(""),
            nodes.len(),
        )
    }

    pub fn contact_info_trace(&self) -> String {
        let now = timestamp();
        let mut shred_spy_nodes = 0usize;
        let mut total_spy_nodes = 0usize;
        let mut different_shred_nodes = 0usize;
        let my_pubkey = self.id();
        let my_shred_version = self.my_shred_version();
        let nodes: Vec<_> = self
            .all_peers()
            .into_iter()
            .filter_map(|(node, last_updated)| {
                let is_spy_node = Self::is_spy_node(&node, &self.socket_addr_space);
                if is_spy_node {
                    total_spy_nodes = total_spy_nodes.saturating_add(1);
                }

                let node_version = self.get_node_version(node.pubkey());
                if my_shred_version != 0 && (node.shred_version() != 0 && node.shred_version() != my_shred_version) {
                    different_shred_nodes = different_shred_nodes.saturating_add(1);
                    None
                } else {
                    if is_spy_node {
                        shred_spy_nodes = shred_spy_nodes.saturating_add(1);
                    }
                    let ip_addr = node.gossip().as_ref().map(SocketAddr::ip).ok();
                    Some(format!(
                        "{:15} {:2}| {:5} | {:44} |{:^9}| {:5}|  {:5}| {:5}| {:5}| {:5}| {:5}| {:5}| {:5}| {}\n",
                        node.gossip()
                            .ok()
                            .filter(|addr| self.socket_addr_space.check(addr))
                            .as_ref()
                            .map(SocketAddr::ip)
                            .as_ref()
                            .map(IpAddr::to_string)
                            .unwrap_or_else(|| String::from("none")),
                        if node.pubkey() == &my_pubkey { "me" } else { "" },
                        now.saturating_sub(last_updated),
                        node.pubkey(),
                        if let Some(node_version) = node_version {
                            node_version.to_string()
                        } else {
                            "-".to_string()
                        },
                        self.addr_to_string(&ip_addr, &node.gossip().ok()),
                        self.addr_to_string(&ip_addr, &node.tpu_vote().ok()),
                        self.addr_to_string(&ip_addr, &node.tpu(contact_info::Protocol::UDP).ok()),
                        self.addr_to_string(&ip_addr, &node.tpu_forwards(contact_info::Protocol::UDP).ok()),
                        self.addr_to_string(&ip_addr, &node.tvu().ok()),
                        self.addr_to_string(&ip_addr, &node.tvu_forwards().ok()),
                        self.addr_to_string(&ip_addr, &node.repair().ok()),
                        self.addr_to_string(&ip_addr, &node.serve_repair().ok()),
                        node.shred_version(),
                    ))
                }
            })
            .collect();

        format!(
            "IP Address        |Age(ms)| Node identifier                              \
             | Version |Gossip|TPUvote| TPU  |TPUfwd| TVU  |TVUfwd|Repair|ServeR|ShredVer\n\
             ------------------+-------+----------------------------------------------\
             +---------+------+-------+------+------+------+------+------+------+--------\n\
             {}\
             Nodes: {}{}{}",
            nodes.join(""),
            nodes.len().saturating_sub(shred_spy_nodes),
            if total_spy_nodes > 0 {
                format!("\nSpies: {total_spy_nodes}")
            } else {
                "".to_string()
            },
            if different_shred_nodes > 0 {
                format!("\nNodes with different shred version: {different_shred_nodes}")
            } else {
                "".to_string()
            }
        )
    }

    // TODO: This has a race condition if called from more than one thread.
    pub fn push_lowest_slot(&self, min: Slot) {
        let self_pubkey = self.id();
        let last = {
            let gossip_crds = self.gossip.crds.read().unwrap();
            gossip_crds
                .get::<&LowestSlot>(self_pubkey)
                .map(|x| x.lowest)
                .unwrap_or_default()
        };
        if min > last {
            let now = timestamp();
            let entry = CrdsValue::new_signed(
                CrdsData::LowestSlot(0, LowestSlot::new(self_pubkey, min, now)),
                &self.keypair(),
            );
            self.local_message_pending_push_queue
                .lock()
                .unwrap()
                .push(entry);
        }
    }

    // TODO: If two threads call into this function then epoch_slot_index has a
    // race condition and the threads will overwrite each other in crds table.
    pub fn push_epoch_slots(&self, mut update: &[Slot]) {
        let self_pubkey = self.id();
        let current_slots: Vec<_> = {
            let gossip_crds =
                self.time_gossip_read_lock("lookup_epoch_slots", &self.stats.epoch_slots_lookup);
            (0..crds_value::MAX_EPOCH_SLOTS)
                .filter_map(|ix| {
                    let label = CrdsValueLabel::EpochSlots(ix, self_pubkey);
                    let crds_value = gossip_crds.get::<&CrdsValue>(&label)?;
                    let epoch_slots = crds_value.epoch_slots()?;
                    let first_slot = epoch_slots.first_slot()?;
                    Some((epoch_slots.wallclock, first_slot, ix))
                })
                .collect()
        };
        let min_slot: Slot = current_slots
            .iter()
            .map(|(_wallclock, slot, _index)| *slot)
            .min()
            .unwrap_or_default();
        let max_slot: Slot = update.iter().max().cloned().unwrap_or(0);
        let total_slots = max_slot as isize - min_slot as isize;
        // WARN if CRDS is not storing at least a full epoch worth of slots
        if DEFAULT_SLOTS_PER_EPOCH as isize > total_slots
            && crds_value::MAX_EPOCH_SLOTS as usize <= current_slots.len()
        {
            self.stats.epoch_slots_filled.add_relaxed(1);
            warn!(
                "EPOCH_SLOTS are filling up FAST {}/{}",
                total_slots,
                current_slots.len()
            );
        }
        let mut reset = false;
        let mut epoch_slot_index = match current_slots.iter().max() {
            Some((_wallclock, _slot, index)) => *index,
            None => 0,
        };
        let mut entries = Vec::default();
        let keypair = self.keypair();
        while !update.is_empty() {
            let ix = epoch_slot_index % crds_value::MAX_EPOCH_SLOTS;
            let now = timestamp();
            let mut slots = if !reset {
                self.lookup_epoch_slots(ix)
            } else {
                EpochSlots::new(self_pubkey, now)
            };
            let n = slots.fill(update, now);
            update = &update[n..];
            if n > 0 {
                let epoch_slots = CrdsData::EpochSlots(ix, slots);
                let entry = CrdsValue::new_signed(epoch_slots, &keypair);
                entries.push(entry);
            }
            epoch_slot_index += 1;
            reset = true;
        }
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        let now = timestamp();
        for entry in entries {
            if let Err(err) = gossip_crds.insert(entry, now, GossipRoute::LocalMessage) {
                error!("push_epoch_slots failed: {:?}", err);
            }
        }
    }

    fn time_gossip_read_lock<'a>(
        &'a self,
        label: &'static str,
        counter: &'a Counter,
    ) -> TimedGuard<'a, RwLockReadGuard<Crds>> {
        TimedGuard::new(self.gossip.crds.read().unwrap(), label, counter)
    }

    pub fn push_message(&self, message: CrdsValue) {
        self.local_message_pending_push_queue
            .lock()
            .unwrap()
            .push(message);
    }

    pub fn push_accounts_hashes(&self, accounts_hashes: Vec<(Slot, Hash)>) {
        if accounts_hashes.len() > MAX_ACCOUNTS_HASHES {
            warn!(
                "accounts hashes too large, ignored: {}",
                accounts_hashes.len(),
            );
            return;
        }

        let message = CrdsData::AccountsHashes(AccountsHashes::new(self.id(), accounts_hashes));
        self.push_message(CrdsValue::new_signed(message, &self.keypair()));
    }

    pub fn push_legacy_snapshot_hashes(&self, snapshot_hashes: Vec<(Slot, Hash)>) {
        if snapshot_hashes.len() > MAX_LEGACY_SNAPSHOT_HASHES {
            warn!(
                "snapshot hashes too large, ignored: {}",
                snapshot_hashes.len(),
            );
            return;
        }

        let message =
            CrdsData::LegacySnapshotHashes(LegacySnapshotHashes::new(self.id(), snapshot_hashes));
        self.push_message(CrdsValue::new_signed(message, &self.keypair()));
    }

    pub fn push_snapshot_hashes(
        &self,
        full: (Slot, Hash),
        incremental: Vec<(Slot, Hash)>,
    ) -> Result<(), ClusterInfoError> {
        if incremental.len() > MAX_INCREMENTAL_SNAPSHOT_HASHES {
            return Err(ClusterInfoError::TooManyIncrementalSnapshotHashes);
        }

        let message = CrdsData::SnapshotHashes(SnapshotHashes {
            from: self.id(),
            full,
            incremental,
            wallclock: timestamp(),
        });
        self.push_message(CrdsValue::new_signed(message, &self.keypair()));

        Ok(())
    }

    pub fn push_vote_at_index(&self, vote: Transaction, vote_index: u8) {
        assert!((vote_index as usize) < MAX_LOCKOUT_HISTORY);
        let self_pubkey = self.id();
        let now = timestamp();
        let vote = Vote::new(self_pubkey, vote, now).unwrap();
        let vote = CrdsData::Vote(vote_index, vote);
        let vote = CrdsValue::new_signed(vote, &self.keypair());
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        if let Err(err) = gossip_crds.insert(vote, now, GossipRoute::LocalMessage) {
            error!("push_vote failed: {:?}", err);
        }
    }

    pub fn push_vote(&self, tower: &[Slot], vote: Transaction) {
        debug_assert!(tower.iter().tuple_windows().all(|(a, b)| a < b));
        // Find a crds vote which is evicted from the tower, and recycle its
        // vote-index. This can be either an old vote which is popped off the
        // deque, or recent vote which has expired before getting enough
        // confirmations.
        // If all votes are still in the tower, add a new vote-index. If more
        // than one vote is evicted, the oldest one by wallclock is returned in
        // order to allow more recent votes more time to propagate through
        // gossip.
        // TODO: When there are more than one vote evicted from the tower, only
        // one crds vote is overwritten here. Decide what to do with the rest.
        let mut num_crds_votes = 0;
        let self_pubkey = self.id();
        // Returns true if the tower does not contain the vote.slot.
        let should_evict_vote = |vote: &Vote| -> bool {
            match vote.slot() {
                Some(slot) => !tower.contains(&slot),
                None => {
                    error!("crds vote with no slots!");
                    true
                }
            }
        };
        let vote_index = {
            let gossip_crds =
                self.time_gossip_read_lock("gossip_read_push_vote", &self.stats.push_vote_read);
            (0..MAX_LOCKOUT_HISTORY as u8)
                .filter_map(|ix| {
                    let vote = CrdsValueLabel::Vote(ix, self_pubkey);
                    let vote: &CrdsData = gossip_crds.get(&vote)?;
                    num_crds_votes += 1;
                    match &vote {
                        CrdsData::Vote(_, vote) if should_evict_vote(vote) => {
                            Some((vote.wallclock, ix))
                        }
                        CrdsData::Vote(_, _) => None,
                        _ => panic!("this should not happen!"),
                    }
                })
                .min() // Boot the oldest evicted vote by wallclock.
                .map(|(_ /*wallclock*/, ix)| ix)
        };
        let vote_index = vote_index.unwrap_or(num_crds_votes);
        if (vote_index as usize) >= MAX_LOCKOUT_HISTORY {
            let (_, vote, hash, _) = vote_parser::parse_vote_transaction(&vote).unwrap();
            panic!(
                "invalid vote index: {}, switch: {}, vote slots: {:?}, tower: {:?}",
                vote_index,
                hash.is_some(),
                vote.slots(),
                tower
            );
        }
        self.push_vote_at_index(vote, vote_index);
    }

    pub fn refresh_vote(&self, vote: Transaction, vote_slot: Slot) {
        let vote_index = {
            let self_pubkey = self.id();
            let gossip_crds =
                self.time_gossip_read_lock("gossip_read_push_vote", &self.stats.push_vote_read);
            (0..MAX_LOCKOUT_HISTORY as u8).find(|ix| {
                let vote = CrdsValueLabel::Vote(*ix, self_pubkey);
                if let Some(vote) = gossip_crds.get::<&CrdsData>(&vote) {
                    match &vote {
                        CrdsData::Vote(_, prev_vote) => match prev_vote.slot() {
                            Some(prev_vote_slot) => prev_vote_slot == vote_slot,
                            None => {
                                error!("crds vote with no slots!");
                                false
                            }
                        },
                        _ => panic!("this should not happen!"),
                    }
                } else {
                    false
                }
            })
        };

        // If you don't see a vote with the same slot yet, this means you probably
        // restarted, and need to wait for your oldest vote to propagate back to you.
        //
        // We don't write to an arbitrary index, because it may replace one of this validator's
        // existing votes on the network.
        if let Some(vote_index) = vote_index {
            self.push_vote_at_index(vote, vote_index);
        }
    }

    pub fn send_transaction(
        &self,
        transaction: &Transaction,
        tpu: Option<SocketAddr>,
    ) -> Result<(), GossipError> {
        let tpu = tpu
            .map(Ok)
            .unwrap_or_else(|| self.my_contact_info().tpu(contact_info::Protocol::UDP))?;
        let buf = serialize(transaction)?;
        self.socket.send_to(&buf, tpu)?;
        Ok(())
    }

    /// Returns votes inserted since the given cursor.
    pub fn get_votes(&self, cursor: &mut Cursor) -> Vec<Transaction> {
        let txs: Vec<Transaction> = self
            .time_gossip_read_lock("get_votes", &self.stats.get_votes)
            .get_votes(cursor)
            .map(|vote| {
                let transaction = match &vote.value.data {
                    CrdsData::Vote(_, vote) => vote.transaction().clone(),
                    _ => panic!("this should not happen!"),
                };
                transaction
            })
            .collect();
        self.stats.get_votes_count.add_relaxed(txs.len() as u64);
        txs
    }

    /// Returns votes and the associated labels inserted since the given cursor.
    pub fn get_votes_with_labels(
        &self,
        cursor: &mut Cursor,
    ) -> (Vec<CrdsValueLabel>, Vec<Transaction>) {
        let (labels, txs): (_, Vec<_>) = self
            .time_gossip_read_lock("get_votes", &self.stats.get_votes)
            .get_votes(cursor)
            .map(|vote| {
                let transaction = match &vote.value.data {
                    CrdsData::Vote(_, vote) => vote.transaction().clone(),
                    _ => panic!("this should not happen!"),
                };
                (vote.value.label(), transaction)
            })
            .unzip();
        self.stats.get_votes_count.add_relaxed(txs.len() as u64);
        (labels, txs)
    }

    pub fn push_duplicate_shred(
        &self,
        shred: &Shred,
        other_payload: &[u8],
    ) -> Result<(), GossipError> {
        self.gossip.push_duplicate_shred(
            &self.keypair(),
            shred,
            other_payload,
            None::<fn(Slot) -> Option<Pubkey>>, // Leader schedule
            DUPLICATE_SHRED_MAX_PAYLOAD_SIZE,
        )?;
        Ok(())
    }

    pub fn get_accounts_hash_for_node<F, Y>(&self, pubkey: &Pubkey, map: F) -> Option<Y>
    where
        F: FnOnce(&Vec<(Slot, Hash)>) -> Y,
    {
        self.time_gossip_read_lock("get_accounts_hash", &self.stats.get_accounts_hash)
            .get::<&CrdsValue>(&CrdsValueLabel::AccountsHashes(*pubkey))
            .map(|x| &x.accounts_hash().unwrap().hashes)
            .map(map)
    }

    pub fn get_legacy_snapshot_hash_for_node<F, Y>(&self, pubkey: &Pubkey, map: F) -> Option<Y>
    where
        F: FnOnce(&Vec<(Slot, Hash)>) -> Y,
    {
        let gossip_crds = self.gossip.crds.read().unwrap();
        let hashes = &gossip_crds.get::<&LegacySnapshotHashes>(*pubkey)?.hashes;
        Some(map(hashes))
    }

    pub fn get_snapshot_hashes_for_node(&self, pubkey: &Pubkey) -> Option<SnapshotHashes> {
        self.gossip
            .crds
            .read()
            .unwrap()
            .get::<&SnapshotHashes>(*pubkey)
            .cloned()
    }

    /// Returns epoch-slots inserted since the given cursor.
    /// Excludes entries from nodes with unkown or different shred version.
    pub fn get_epoch_slots(&self, cursor: &mut Cursor) -> Vec<EpochSlots> {
        let self_shred_version = Some(self.my_shred_version());
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_epoch_slots(cursor)
            .filter(|entry| {
                let origin = entry.value.pubkey();
                gossip_crds.get_shred_version(&origin) == self_shred_version
            })
            .map(|entry| match &entry.value.data {
                CrdsData::EpochSlots(_, slots) => slots.clone(),
                _ => panic!("this should not happen!"),
            })
            .collect()
    }

    /// Returns duplicate-shreds inserted since the given cursor.
    pub(crate) fn get_duplicate_shreds(&self, cursor: &mut Cursor) -> Vec<DuplicateShred> {
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_duplicate_shreds(cursor)
            .map(|entry| match &entry.value.data {
                CrdsData::DuplicateShred(_, dup) => dup.clone(),
                _ => panic!("this should not happen!"),
            })
            .collect()
    }

    pub fn get_node_version(&self, pubkey: &Pubkey) -> Option<solana_version::LegacyVersion2> {
        let gossip_crds = self.gossip.crds.read().unwrap();
        if let Some(version) = gossip_crds.get::<&Version>(*pubkey) {
            return Some(version.version.clone());
        }
        let version: &crds_value::LegacyVersion = gossip_crds.get(*pubkey)?;
        Some(version.version.clone().into())
    }

    fn check_socket_addr_space<E>(&self, addr: &Result<SocketAddr, E>) -> bool {
        addr.as_ref()
            .map(|addr| self.socket_addr_space.check(addr))
            .unwrap_or_default()
    }

    /// all validators that have a valid rpc port regardless of `shred_version`.
    pub fn all_rpc_peers(&self) -> Vec<LegacyContactInfo> {
        let self_pubkey = self.id();
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes_contact_info()
            .filter(|node| {
                node.pubkey() != &self_pubkey && self.check_socket_addr_space(&node.rpc())
            })
            .cloned()
            .collect()
    }

    // All nodes in gossip (including spy nodes) and the last time we heard about them
    pub fn all_peers(&self) -> Vec<(LegacyContactInfo, u64)> {
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes()
            .map(|x| (x.value.contact_info().unwrap().clone(), x.local_timestamp))
            .collect()
    }

    pub fn gossip_peers(&self) -> Vec<LegacyContactInfo> {
        let me = self.id();
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes_contact_info()
            // shred_version not considered for gossip peers (ie, spy nodes do not set shred_version)
            .filter(|node| node.pubkey() != &me && self.check_socket_addr_space(&node.gossip()))
            .cloned()
            .collect()
    }

    /// all validators that have a valid tvu port regardless of `shred_version`.
    pub fn all_tvu_peers(&self) -> Vec<LegacyContactInfo> {
        let self_pubkey = self.id();
        self.time_gossip_read_lock("all_tvu_peers", &self.stats.all_tvu_peers)
            .get_nodes_contact_info()
            .filter(|node| {
                node.pubkey() != &self_pubkey && self.check_socket_addr_space(&node.tvu())
            })
            .cloned()
            .collect()
    }

    /// all validators that have a valid tvu port and are on the same `shred_version`.
    pub fn tvu_peers(&self) -> Vec<LegacyContactInfo> {
        let self_pubkey = self.id();
        let self_shred_version = self.my_shred_version();
        self.time_gossip_read_lock("tvu_peers", &self.stats.tvu_peers)
            .get_nodes_contact_info()
            .filter(|node| {
                node.pubkey() != &self_pubkey
                    && node.shred_version() == self_shred_version
                    && self.check_socket_addr_space(&node.tvu())
            })
            .cloned()
            .collect()
    }

    /// all tvu peers with valid gossip addrs that likely have the slot being requested
    pub fn repair_peers(&self, slot: Slot) -> Vec<LegacyContactInfo> {
        let _st = ScopedTimer::from(&self.stats.repair_peers);
        let self_pubkey = self.id();
        let self_shred_version = self.my_shred_version();
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes_contact_info()
            .filter(|node| {
                node.pubkey() != &self_pubkey
                    && node.shred_version() == self_shred_version
                    && self.check_socket_addr_space(&node.tvu())
                    && self.check_socket_addr_space(&node.serve_repair())
                    && match gossip_crds.get::<&LowestSlot>(*node.pubkey()) {
                        None => true, // fallback to legacy behavior
                        Some(lowest_slot) => lowest_slot.lowest <= slot,
                    }
            })
            .cloned()
            .collect()
    }

    fn is_spy_node(node: &LegacyContactInfo, socket_addr_space: &SocketAddrSpace) -> bool {
        ![
            node.tpu(contact_info::Protocol::UDP),
            node.gossip(),
            node.tvu(),
        ]
        .into_iter()
        .all(|addr| {
            addr.map(|addr| socket_addr_space.check(&addr))
                .unwrap_or_default()
        })
    }

    /// compute broadcast table
    pub fn tpu_peers(&self) -> Vec<LegacyContactInfo> {
        let self_pubkey = self.id();
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes_contact_info()
            .filter(|node| {
                node.pubkey() != &self_pubkey
                    && self.check_socket_addr_space(&node.tpu(contact_info::Protocol::UDP))
            })
            .cloned()
            .collect()
    }

    fn insert_self(&self) {
        let node = self.my_contact_info();
        let entries: Vec<_> = [
            LegacyContactInfo::try_from(&node)
                .map(CrdsData::LegacyContactInfo)
                .expect("Operator must spin up node with valid contact-info"),
            CrdsData::ContactInfo(node),
        ]
        .into_iter()
        .map(|entry| CrdsValue::new_signed(entry, &self.keypair()))
        .collect();
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        for entry in entries {
            if let Err(err) = gossip_crds.insert(entry, timestamp(), GossipRoute::LocalMessage) {
                error!("Insert self failed: {err:?}");
            }
        }
    }

    // If the network entrypoint hasn't been discovered yet, add it to the crds table
    fn append_entrypoint_to_pulls(
        &self,
        thread_pool: &ThreadPool,
        pulls: &mut HashMap<LegacyContactInfo, Vec<CrdsFilter>>,
    ) {
        const THROTTLE_DELAY: u64 = CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 2;
        let entrypoint = {
            let mut entrypoints = self.entrypoints.write().unwrap();
            let entrypoint = match entrypoints.choose_mut(&mut rand::thread_rng()) {
                Some(entrypoint) => entrypoint,
                None => return,
            };
            if !pulls.is_empty() {
                let now = timestamp();
                if now <= entrypoint.wallclock().saturating_add(THROTTLE_DELAY) {
                    return;
                }
                entrypoint.set_wallclock(now);
                if let Ok(entrypoint_gossip) = entrypoint.gossip() {
                    if self
                        .time_gossip_read_lock("entrypoint", &self.stats.entrypoint)
                        .get_nodes_contact_info()
                        .any(|node| node.gossip().ok() == Some(entrypoint_gossip))
                    {
                        return; // Found the entrypoint, no need to pull from it
                    }
                }
            }
            entrypoint.clone()
        };
        let filters = if pulls.is_empty() {
            let _st = ScopedTimer::from(&self.stats.entrypoint2);
            self.gossip
                .pull
                .build_crds_filters(thread_pool, &self.gossip.crds, MAX_BLOOM_SIZE)
        } else {
            pulls.values().flatten().cloned().collect()
        };
        self.stats.pull_from_entrypoint_count.add_relaxed(1);
        pulls.insert(entrypoint, filters);
    }

    /// Splits an input feed of serializable data into chunks where the sum of
    /// serialized size of values within each chunk is no larger than
    /// max_chunk_size.
    /// Note: some messages cannot be contained within that size so in the worst case this returns
    /// N nested Vecs with 1 item each.
    fn split_gossip_messages<I, T>(
        max_chunk_size: usize,
        data_feed: I,
    ) -> impl Iterator<Item = Vec<T>>
    where
        T: Serialize + Debug,
        I: IntoIterator<Item = T>,
    {
        let mut data_feed = data_feed.into_iter().fuse();
        let mut buffer = vec![];
        let mut buffer_size = 0; // Serialized size of buffered values.
        std::iter::from_fn(move || loop {
            match data_feed.next() {
                None => {
                    return if buffer.is_empty() {
                        None
                    } else {
                        Some(std::mem::take(&mut buffer))
                    };
                }
                Some(data) => {
                    let data_size = match serialized_size(&data) {
                        Ok(size) => size as usize,
                        Err(err) => {
                            error!("serialized_size failed: {}", err);
                            continue;
                        }
                    };
                    if buffer_size + data_size <= max_chunk_size {
                        buffer_size += data_size;
                        buffer.push(data);
                    } else if data_size <= max_chunk_size {
                        buffer_size = data_size;
                        return Some(std::mem::replace(&mut buffer, vec![data]));
                    } else {
                        error!(
                            "dropping data larger than the maximum chunk size {:?}",
                            data
                        );
                    }
                }
            }
        })
    }

    #[allow(clippy::type_complexity)]
    fn new_pull_requests(
        &self,
        thread_pool: &ThreadPool,
        gossip_validators: Option<&HashSet<Pubkey>>,
        stakes: &HashMap<Pubkey, u64>,
    ) -> (
        Vec<(SocketAddr, Ping)>,     // Ping packets.
        Vec<(SocketAddr, Protocol)>, // Pull requests
    ) {
        let now = timestamp();
        let mut pings = Vec::new();
        let mut pulls = {
            let _st = ScopedTimer::from(&self.stats.new_pull_requests);
            self.gossip
                .new_pull_request(
                    thread_pool,
                    self.keypair().deref(),
                    self.my_shred_version(),
                    now,
                    gossip_validators,
                    stakes,
                    MAX_BLOOM_SIZE,
                    &self.ping_cache,
                    &mut pings,
                    &self.socket_addr_space,
                )
                .unwrap_or_default()
        };
        self.append_entrypoint_to_pulls(thread_pool, &mut pulls);
        let num_requests = pulls.values().map(Vec::len).sum::<usize>() as u64;
        self.stats.new_pull_requests_count.add_relaxed(num_requests);
        let self_info = LegacyContactInfo::try_from(&self.my_contact_info())
            .map(CrdsData::LegacyContactInfo)
            .expect("Operator must spin up node with valid contact-info");
        let self_info = CrdsValue::new_signed(self_info, &self.keypair());
        let pulls = pulls
            .into_iter()
            .filter_map(|(peer, filters)| Some((peer.gossip().ok()?, filters)))
            .flat_map(|(addr, filters)| repeat(addr).zip(filters))
            .map(|(gossip_addr, filter)| {
                let request = Protocol::PullRequest(filter, self_info.clone());
                (gossip_addr, request)
            });
        self.stats
            .new_pull_requests_pings_count
            .add_relaxed(pings.len() as u64);
        (pings, pulls.collect())
    }

    fn drain_push_queue(&self) -> Vec<CrdsValue> {
        let mut push_queue = self.local_message_pending_push_queue.lock().unwrap();
        std::mem::take(&mut *push_queue)
    }
    // Used in tests
    pub fn flush_push_queue(&self) {
        let pending_push_messages = self.drain_push_queue();
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        let now = timestamp();
        for entry in pending_push_messages {
            let _ = gossip_crds.insert(entry, now, GossipRoute::LocalMessage);
        }
    }
    fn new_push_requests(&self, stakes: &HashMap<Pubkey, u64>) -> Vec<(SocketAddr, Protocol)> {
        let self_id = self.id();
        let (mut push_messages, num_entries, num_nodes) = {
            let _st = ScopedTimer::from(&self.stats.new_push_requests);
            self.gossip
                .new_push_messages(&self_id, self.drain_push_queue(), timestamp(), stakes)
        };
        self.stats
            .push_fanout_num_entries
            .add_relaxed(num_entries as u64);
        self.stats
            .push_fanout_num_nodes
            .add_relaxed(num_nodes as u64);
        if self.require_stake_for_gossip(stakes) {
            push_messages.retain(|_, data| {
                retain_staked(data, stakes);
                !data.is_empty()
            })
        }
        let push_messages: Vec<_> = {
            let gossip_crds =
                self.time_gossip_read_lock("push_req_lookup", &self.stats.new_push_requests2);
            push_messages
                .into_iter()
                .filter_map(|(pubkey, messages)| {
                    let peer: &LegacyContactInfo = gossip_crds.get(pubkey)?;
                    Some((peer.gossip().ok()?, messages))
                })
                .collect()
        };
        let messages: Vec<_> = push_messages
            .into_iter()
            .flat_map(|(peer, msgs)| {
                Self::split_gossip_messages(PUSH_MESSAGE_MAX_PAYLOAD_SIZE, msgs)
                    .map(move |payload| (peer, Protocol::PushMessage(self_id, payload)))
            })
            .collect();
        self.stats
            .new_push_requests_num
            .add_relaxed(messages.len() as u64);
        messages
    }

    // Generate new push and pull requests
    fn generate_new_gossip_requests(
        &self,
        thread_pool: &ThreadPool,
        gossip_validators: Option<&HashSet<Pubkey>>,
        stakes: &HashMap<Pubkey, u64>,
        generate_pull_requests: bool,
    ) -> Vec<(SocketAddr, Protocol)> {
        self.trim_crds_table(CRDS_UNIQUE_PUBKEY_CAPACITY, stakes);
        // This will flush local pending push messages before generating
        // pull-request bloom filters, preventing pull responses to return the
        // same values back to the node itself. Note that packets will arrive
        // and are processed out of order.
        let mut out: Vec<_> = self.new_push_requests(stakes);
        self.stats
            .packets_sent_push_messages_count
            .add_relaxed(out.len() as u64);
        if generate_pull_requests {
            let (pings, pull_requests) =
                self.new_pull_requests(thread_pool, gossip_validators, stakes);
            self.stats
                .packets_sent_pull_requests_count
                .add_relaxed(pull_requests.len() as u64);
            let pings = pings
                .into_iter()
                .map(|(addr, ping)| (addr, Protocol::PingMessage(ping)));
            out.extend(pull_requests);
            out.extend(pings);
        }
        out
    }

    /// At random pick a node and try to get updated changes from them
    fn run_gossip(
        &self,
        thread_pool: &ThreadPool,
        gossip_validators: Option<&HashSet<Pubkey>>,
        recycler: &PacketBatchRecycler,
        stakes: &HashMap<Pubkey, u64>,
        sender: &PacketBatchSender,
        generate_pull_requests: bool,
    ) -> Result<(), GossipError> {
        let _st = ScopedTimer::from(&self.stats.gossip_transmit_loop_time);
        let reqs = self.generate_new_gossip_requests(
            thread_pool,
            gossip_validators,
            stakes,
            generate_pull_requests,
        );
        if !reqs.is_empty() {
            let packet_batch = PacketBatch::new_unpinned_with_recycler_data_and_dests(
                recycler.clone(),
                "run_gossip",
                &reqs,
            );
            self.stats
                .packets_sent_gossip_requests_count
                .add_relaxed(packet_batch.len() as u64);
            sender.send(packet_batch)?;
        }
        self.stats
            .gossip_transmit_loop_iterations_since_last_report
            .add_relaxed(1);
        Ok(())
    }

    fn process_entrypoints(&self) -> bool {
        let mut entrypoints = self.entrypoints.write().unwrap();
        if entrypoints.is_empty() {
            // No entrypoint specified.  Nothing more to process
            return true;
        }
        for entrypoint in entrypoints.iter_mut() {
            if entrypoint.pubkey() == &Pubkey::default() {
                // If a pull from the entrypoint was successful it should exist in the CRDS table
                if let Some(entrypoint_from_gossip) = entrypoint
                    .gossip()
                    .ok()
                    .and_then(|addr| self.lookup_contact_info_by_gossip_addr(&addr))
                {
                    // Update the entrypoint's id so future entrypoint pulls correctly reference it
                    *entrypoint = entrypoint_from_gossip;
                }
            }
        }
        // Adopt an entrypoint's `shred_version` if ours is unset
        if self.my_shred_version() == 0 {
            if let Some(entrypoint) = entrypoints
                .iter()
                .find(|entrypoint| entrypoint.shred_version() != 0)
            {
                info!(
                    "Setting shred version to {:?} from entrypoint {:?}",
                    entrypoint.shred_version(),
                    entrypoint.pubkey()
                );
                self.my_contact_info
                    .write()
                    .unwrap()
                    .set_shred_version(entrypoint.shred_version());
            }
        }
        self.my_shred_version() != 0
            && entrypoints
                .iter()
                .all(|entrypoint| entrypoint.pubkey() != &Pubkey::default())
    }

    fn handle_purge(
        &self,
        thread_pool: &ThreadPool,
        bank_forks: Option<&RwLock<BankForks>>,
        stakes: &HashMap<Pubkey, u64>,
    ) {
        let self_pubkey = self.id();
        let epoch_duration = get_epoch_duration(bank_forks, &self.stats);
        let timeouts = self
            .gossip
            .make_timeouts(self_pubkey, stakes, epoch_duration);
        let num_purged = {
            let _st = ScopedTimer::from(&self.stats.purge);
            self.gossip
                .purge(&self_pubkey, thread_pool, timestamp(), &timeouts)
        };
        self.stats.purge_count.add_relaxed(num_purged as u64);
    }

    // Trims the CRDS table by dropping all values associated with the pubkeys
    // with the lowest stake, so that the number of unique pubkeys are bounded.
    fn trim_crds_table(&self, cap: usize, stakes: &HashMap<Pubkey, u64>) {
        if !self.gossip.crds.read().unwrap().should_trim(cap) {
            return;
        }
        let keep: Vec<_> = self
            .entrypoints
            .read()
            .unwrap()
            .iter()
            .map(LegacyContactInfo::pubkey)
            .copied()
            .chain(std::iter::once(self.id()))
            .collect();
        self.stats.trim_crds_table.add_relaxed(1);
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        match gossip_crds.trim(cap, &keep, stakes, timestamp()) {
            Err(err) => {
                self.stats.trim_crds_table_failed.add_relaxed(1);
                // TODO: Stakes are comming from the root-bank. Debug why/when
                // they are empty/zero.
                debug!("crds table trim failed: {:?}", err);
            }
            Ok(num_purged) => {
                self.stats
                    .trim_crds_table_purged_values_count
                    .add_relaxed(num_purged as u64);
            }
        }
    }

    /// randomly pick a node and ask them for updates asynchronously
    pub fn gossip(
        self: Arc<Self>,
        bank_forks: Option<Arc<RwLock<BankForks>>>,
        sender: PacketBatchSender,
        gossip_validators: Option<HashSet<Pubkey>>,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(std::cmp::min(get_thread_count(), 8))
            .thread_name(|i| format!("solRunGossip{i:02}"))
            .build()
            .unwrap();
        Builder::new()
            .name("solGossip".to_string())
            .spawn(move || {
                let mut last_push = 0;
                let mut last_contact_info_trace = timestamp();
                let mut last_contact_info_save = timestamp();
                let mut entrypoints_processed = false;
                let recycler = PacketBatchRecycler::default();
                let crds_data = vec![
                    CrdsData::Version(Version::new(self.id())),
                    CrdsData::NodeInstance(
                        self.instance.read().unwrap().with_wallclock(timestamp()),
                    ),
                ];
                for value in crds_data {
                    let value = CrdsValue::new_signed(value, &self.keypair());
                    self.push_message(value);
                }
                let mut generate_pull_requests = true;
                loop {
                    let start = timestamp();
                    if self.contact_debug_interval != 0
                        && start - last_contact_info_trace > self.contact_debug_interval
                    {
                        // Log contact info
                        info!(
                            "\n{}\n\n{}",
                            self.contact_info_trace(),
                            self.rpc_info_trace()
                        );
                        last_contact_info_trace = start;
                    }

                    if self.contact_save_interval != 0
                        && start - last_contact_info_save > self.contact_save_interval
                    {
                        self.save_contact_info();
                        last_contact_info_save = start;
                    }

                    let (stakes, _feature_set) = match bank_forks {
                        Some(ref bank_forks) => {
                            let root_bank = bank_forks.read().unwrap().root_bank();
                            (
                                root_bank.staked_nodes(),
                                Some(root_bank.feature_set.clone()),
                            )
                        }
                        None => (Arc::default(), None),
                    };
                    let _ = self.run_gossip(
                        &thread_pool,
                        gossip_validators.as_ref(),
                        &recycler,
                        &stakes,
                        &sender,
                        generate_pull_requests,
                    );
                    if exit.load(Ordering::Relaxed) {
                        return;
                    }
                    self.handle_purge(&thread_pool, bank_forks.as_deref(), &stakes);
                    entrypoints_processed = entrypoints_processed || self.process_entrypoints();
                    //TODO: possibly tune this parameter
                    //we saw a deadlock passing an self.read().unwrap().timeout into sleep
                    if start - last_push > CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 2 {
                        self.push_self();
                        self.refresh_push_active_set(
                            &recycler,
                            &stakes,
                            gossip_validators.as_ref(),
                            &sender,
                        );
                        last_push = timestamp();
                    }
                    let elapsed = timestamp() - start;
                    if GOSSIP_SLEEP_MILLIS > elapsed {
                        let time_left = GOSSIP_SLEEP_MILLIS - elapsed;
                        sleep(Duration::from_millis(time_left));
                    }
                    generate_pull_requests = !generate_pull_requests;
                }
            })
            .unwrap()
    }

    fn handle_batch_prune_messages(&self, messages: Vec<PruneData>, stakes: &HashMap<Pubkey, u64>) {
        let _st = ScopedTimer::from(&self.stats.handle_batch_prune_messages_time);
        if messages.is_empty() {
            return;
        }
        self.stats
            .prune_message_count
            .add_relaxed(messages.len() as u64);
        self.stats
            .prune_message_len
            .add_relaxed(messages.iter().map(|data| data.prunes.len() as u64).sum());
        let mut prune_message_timeout = 0;
        let mut bad_prune_destination = 0;
        let self_pubkey = self.id();
        {
            let _st = ScopedTimer::from(&self.stats.process_prune);
            let now = timestamp();
            for data in messages {
                match self.gossip.process_prune_msg(
                    &self_pubkey,
                    &data.pubkey,
                    &data.destination,
                    &data.prunes,
                    data.wallclock,
                    now,
                    stakes,
                ) {
                    Err(CrdsGossipError::PruneMessageTimeout) => {
                        prune_message_timeout += 1;
                    }
                    Err(CrdsGossipError::BadPruneDestination) => {
                        bad_prune_destination += 1;
                    }
                    _ => (),
                }
            }
        }
        if prune_message_timeout != 0 {
            self.stats
                .prune_message_timeout
                .add_relaxed(prune_message_timeout);
        }
        if bad_prune_destination != 0 {
            self.stats
                .bad_prune_destination
                .add_relaxed(bad_prune_destination);
        }
    }

    fn handle_batch_pull_requests(
        &self,
        // from address, crds filter, caller contact info
        requests: Vec<(SocketAddr, CrdsFilter, CrdsValue)>,
        thread_pool: &ThreadPool,
        recycler: &PacketBatchRecycler,
        stakes: &HashMap<Pubkey, u64>,
        response_sender: &PacketBatchSender,
    ) {
        let _st = ScopedTimer::from(&self.stats.handle_batch_pull_requests_time);
        if requests.is_empty() {
            return;
        }
        let self_pubkey = self.id();
        let requests: Vec<_> = thread_pool.install(|| {
            requests
                .into_par_iter()
                .with_min_len(1024)
                .filter(|(_, _, caller)| match caller.contact_info() {
                    None => false,
                    Some(caller) if caller.pubkey() == &self_pubkey => {
                        warn!("PullRequest ignored, I'm talking to myself");
                        self.stats.window_request_loopback.add_relaxed(1);
                        false
                    }
                    Some(_) => true,
                })
                .map(|(from_addr, filter, caller)| PullData {
                    from_addr,
                    caller,
                    filter,
                })
                .collect()
        });
        if !requests.is_empty() {
            self.stats
                .pull_requests_count
                .add_relaxed(requests.len() as u64);
            let response = self.handle_pull_requests(thread_pool, recycler, requests, stakes);
            if !response.is_empty() {
                self.stats
                    .packets_sent_pull_responses_count
                    .add_relaxed(response.len() as u64);
                let _ = response_sender.send(response);
            }
        }
    }

    fn update_data_budget(&self, num_staked: usize) -> usize {
        const INTERVAL_MS: u64 = 100;
        // epoch slots + votes ~= 1.5kB/slot ~= 4kB/s
        // Allow 10kB/s per staked validator.
        const BYTES_PER_INTERVAL: usize = 1024;
        const MAX_BUDGET_MULTIPLE: usize = 5; // allow budget build-up to 5x the interval default
        let num_staked = num_staked.max(2);
        self.outbound_budget.update(INTERVAL_MS, |bytes| {
            std::cmp::min(
                bytes + num_staked * BYTES_PER_INTERVAL,
                MAX_BUDGET_MULTIPLE * num_staked * BYTES_PER_INTERVAL,
            )
        })
    }

    // Returns a predicate checking if the pull request is from a valid
    // address, and if the address have responded to a ping request. Also
    // appends ping packets for the addresses which need to be (re)verified.
    fn check_pull_request<'a, R>(
        &'a self,
        now: Instant,
        mut rng: &'a mut R,
        packet_batch: &'a mut PacketBatch,
    ) -> impl FnMut(&PullData) -> bool + 'a
    where
        R: Rng + CryptoRng,
    {
        let mut cache = HashMap::<(Pubkey, SocketAddr), bool>::new();
        let mut pingf = move || Ping::new_rand(&mut rng, &self.keypair()).ok();
        let mut ping_cache = self.ping_cache.lock().unwrap();
        let mut hard_check = move |node| {
            let (check, ping) = ping_cache.check(now, node, &mut pingf);
            if let Some(ping) = ping {
                let ping = Protocol::PingMessage(ping);
                match Packet::from_data(Some(&node.1), ping) {
                    Ok(packet) => packet_batch.push(packet),
                    Err(err) => error!("failed to write ping packet: {:?}", err),
                };
            }
            if !check {
                self.stats
                    .pull_request_ping_pong_check_failed_count
                    .add_relaxed(1)
            }
            check
        };
        // Because pull-responses are sent back to packet.meta().socket_addr() of
        // incoming pull-requests, pings are also sent to request.from_addr (as
        // opposed to caller.gossip address).
        move |request| {
            ContactInfo::is_valid_address(&request.from_addr, &self.socket_addr_space) && {
                let node = (request.caller.pubkey(), request.from_addr);
                *cache.entry(node).or_insert_with(|| hard_check(node))
            }
        }
    }

    // Pull requests take an incoming bloom filter of contained entries from a node
    // and tries to send back to them the values it detects are missing.
    fn handle_pull_requests(
        &self,
        thread_pool: &ThreadPool,
        recycler: &PacketBatchRecycler,
        requests: Vec<PullData>,
        stakes: &HashMap<Pubkey, u64>,
    ) -> PacketBatch {
        const DEFAULT_EPOCH_DURATION_MS: u64 = DEFAULT_SLOTS_PER_EPOCH * DEFAULT_MS_PER_SLOT;
        let mut time = Measure::start("handle_pull_requests");
        let callers = crds_value::filter_current(requests.iter().map(|r| &r.caller));
        {
            let _st = ScopedTimer::from(&self.stats.process_pull_requests);
            self.gossip
                .process_pull_requests(callers.cloned(), timestamp());
        }
        let output_size_limit =
            self.update_data_budget(stakes.len()) / PULL_RESPONSE_MIN_SERIALIZED_SIZE;
        let mut packet_batch =
            PacketBatch::new_unpinned_with_recycler(recycler.clone(), 64, "handle_pull_requests");
        let (caller_and_filters, addrs): (Vec<_>, Vec<_>) = {
            let mut rng = rand::thread_rng();
            let check_pull_request =
                self.check_pull_request(Instant::now(), &mut rng, &mut packet_batch);
            requests
                .into_iter()
                .filter(check_pull_request)
                .map(|r| ((r.caller, r.filter), r.from_addr))
                .unzip()
        };
        let now = timestamp();
        let self_id = self.id();
        let mut pull_responses = {
            let _st = ScopedTimer::from(&self.stats.generate_pull_responses);
            self.gossip.generate_pull_responses(
                thread_pool,
                &caller_and_filters,
                output_size_limit,
                now,
                &self.stats,
            )
        };
        if self.require_stake_for_gossip(stakes) {
            for resp in &mut pull_responses {
                retain_staked(resp, stakes);
            }
        }
        let (responses, scores): (Vec<_>, Vec<_>) = addrs
            .iter()
            .zip(pull_responses)
            .flat_map(|(addr, responses)| repeat(addr).zip(responses))
            .map(|(addr, response)| {
                let age = now.saturating_sub(response.wallclock());
                let score = DEFAULT_EPOCH_DURATION_MS
                    .saturating_sub(age)
                    .div(CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS)
                    .max(1);
                let score = if stakes.contains_key(&response.pubkey()) {
                    2 * score
                } else {
                    score
                };
                let score = match response.data {
                    CrdsData::LegacyContactInfo(_) => 2 * score,
                    _ => score,
                };
                ((addr, response), score)
            })
            .unzip();
        if responses.is_empty() {
            return packet_batch;
        }
        let mut rng = rand::thread_rng();
        let shuffle = WeightedShuffle::new("handle-pull-requests", &scores).shuffle(&mut rng);
        let mut total_bytes = 0;
        let mut sent = 0;
        for (addr, response) in shuffle.map(|i| &responses[i]) {
            let response = vec![response.clone()];
            let response = Protocol::PullResponse(self_id, response);
            match Packet::from_data(Some(addr), response) {
                Err(err) => error!("failed to write pull-response packet: {:?}", err),
                Ok(packet) => {
                    if self.outbound_budget.take(packet.meta().size) {
                        total_bytes += packet.meta().size;
                        packet_batch.push(packet);
                        sent += 1;
                    } else {
                        self.stats.gossip_pull_request_no_budget.add_relaxed(1);
                        break;
                    }
                }
            }
        }
        time.stop();
        let dropped_responses = responses.len() - sent;
        self.stats
            .gossip_pull_request_sent_requests
            .add_relaxed(sent as u64);
        self.stats
            .gossip_pull_request_dropped_requests
            .add_relaxed(dropped_responses as u64);
        debug!(
            "handle_pull_requests: {} sent: {} total: {} total_bytes: {}",
            time,
            sent,
            responses.len(),
            total_bytes
        );
        packet_batch
    }

    fn handle_batch_pull_responses(
        &self,
        responses: Vec<(Pubkey, Vec<CrdsValue>)>,
        thread_pool: &ThreadPool,
        stakes: &HashMap<Pubkey, u64>,
        epoch_duration: Duration,
    ) {
        let _st = ScopedTimer::from(&self.stats.handle_batch_pull_responses_time);
        if responses.is_empty() {
            return;
        }
        fn extend<K, V>(hash_map: &mut HashMap<K, Vec<V>>, (key, mut value): (K, Vec<V>))
        where
            K: Eq + std::hash::Hash,
        {
            match hash_map.entry(key) {
                Entry::Occupied(mut entry) => {
                    let entry_value = entry.get_mut();
                    if entry_value.len() < value.len() {
                        std::mem::swap(entry_value, &mut value);
                    }
                    entry_value.extend(value);
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }
        fn merge<K, V>(
            mut hash_map: HashMap<K, Vec<V>>,
            other: HashMap<K, Vec<V>>,
        ) -> HashMap<K, Vec<V>>
        where
            K: Eq + std::hash::Hash,
        {
            if hash_map.len() < other.len() {
                return merge(other, hash_map);
            }
            for kv in other {
                extend(&mut hash_map, kv);
            }
            hash_map
        }
        let responses = thread_pool.install(|| {
            responses
                .into_par_iter()
                .with_min_len(1024)
                .fold(HashMap::new, |mut hash_map, kv| {
                    extend(&mut hash_map, kv);
                    hash_map
                })
                .reduce(HashMap::new, merge)
        });
        if !responses.is_empty() {
            let self_pubkey = self.id();
            let timeouts = self
                .gossip
                .make_timeouts(self_pubkey, stakes, epoch_duration);
            for (from, data) in responses {
                self.handle_pull_response(&from, data, &timeouts);
            }
        }
    }

    // Returns (failed, timeout, success)
    fn handle_pull_response(
        &self,
        from: &Pubkey,
        crds_values: Vec<CrdsValue>,
        timeouts: &CrdsTimeouts,
    ) -> (usize, usize, usize) {
        let len = crds_values.len();
        trace!("PullResponse me: {} from: {} len={}", self.id(), from, len);
        let mut pull_stats = ProcessPullStats::default();
        let (filtered_pulls, filtered_pulls_expired_timeout, failed_inserts) = {
            let _st = ScopedTimer::from(&self.stats.filter_pull_response);
            self.gossip
                .filter_pull_responses(timeouts, crds_values, timestamp(), &mut pull_stats)
        };
        if !filtered_pulls.is_empty()
            || !filtered_pulls_expired_timeout.is_empty()
            || !failed_inserts.is_empty()
        {
            let _st = ScopedTimer::from(&self.stats.process_pull_response);
            self.gossip.process_pull_responses(
                from,
                filtered_pulls,
                filtered_pulls_expired_timeout,
                failed_inserts,
                timestamp(),
                &mut pull_stats,
            );
        }
        self.stats.process_pull_response_count.add_relaxed(1);
        self.stats.process_pull_response_len.add_relaxed(len as u64);
        self.stats
            .process_pull_response_timeout
            .add_relaxed(pull_stats.timeout_count as u64);
        self.stats
            .process_pull_response_fail_insert
            .add_relaxed(pull_stats.failed_insert as u64);
        self.stats
            .process_pull_response_fail_timeout
            .add_relaxed(pull_stats.failed_timeout as u64);
        self.stats
            .process_pull_response_success
            .add_relaxed(pull_stats.success as u64);

        (
            pull_stats.failed_insert + pull_stats.failed_timeout,
            pull_stats.timeout_count,
            pull_stats.success,
        )
    }

    fn handle_batch_ping_messages<I>(
        &self,
        pings: I,
        recycler: &PacketBatchRecycler,
        response_sender: &PacketBatchSender,
    ) where
        I: IntoIterator<Item = (SocketAddr, Ping)>,
    {
        let _st = ScopedTimer::from(&self.stats.handle_batch_ping_messages_time);
        if let Some(response) = self.handle_ping_messages(pings, recycler) {
            let _ = response_sender.send(response);
        }
    }

    fn handle_ping_messages<I>(
        &self,
        pings: I,
        recycler: &PacketBatchRecycler,
    ) -> Option<PacketBatch>
    where
        I: IntoIterator<Item = (SocketAddr, Ping)>,
    {
        let keypair = self.keypair();
        let pongs_and_dests: Vec<_> = pings
            .into_iter()
            .filter_map(|(addr, ping)| {
                let pong = Pong::new(&ping, &keypair).ok()?;
                let pong = Protocol::PongMessage(pong);
                Some((addr, pong))
            })
            .collect();
        if pongs_and_dests.is_empty() {
            None
        } else {
            let packet_batch = PacketBatch::new_unpinned_with_recycler_data_and_dests(
                recycler.clone(),
                "handle_ping_messages",
                &pongs_and_dests,
            );
            Some(packet_batch)
        }
    }

    fn handle_batch_pong_messages<I>(&self, pongs: I, now: Instant)
    where
        I: IntoIterator<Item = (SocketAddr, Pong)>,
    {
        let _st = ScopedTimer::from(&self.stats.handle_batch_pong_messages_time);
        let mut pongs = pongs.into_iter().peekable();
        if pongs.peek().is_some() {
            let mut ping_cache = self.ping_cache.lock().unwrap();
            for (addr, pong) in pongs {
                ping_cache.add(&pong, addr, now);
            }
        }
    }

    #[allow(clippy::needless_collect)]
    fn handle_batch_push_messages(
        &self,
        messages: Vec<(Pubkey, Vec<CrdsValue>)>,
        thread_pool: &ThreadPool,
        recycler: &PacketBatchRecycler,
        stakes: &HashMap<Pubkey, u64>,
        response_sender: &PacketBatchSender,
    ) {
        let _st = ScopedTimer::from(&self.stats.handle_batch_push_messages_time);
        if messages.is_empty() {
            return;
        }
        self.stats
            .push_message_count
            .add_relaxed(messages.len() as u64);
        let num_crds_values: u64 = messages.iter().map(|(_, data)| data.len() as u64).sum();
        self.stats
            .push_message_value_count
            .add_relaxed(num_crds_values);
        // Origins' pubkeys of upserted crds values.
        let origins: HashSet<_> = {
            let _st = ScopedTimer::from(&self.stats.process_push_message);
            let now = timestamp();
            self.gossip.process_push_message(messages, now)
        };
        // Generate prune messages.
        let self_pubkey = self.id();
        let prunes = {
            let _st = ScopedTimer::from(&self.stats.prune_received_cache);
            self.gossip
                .prune_received_cache(&self_pubkey, origins, stakes)
        };
        let prunes: Vec<(Pubkey /*from*/, Vec<Pubkey> /*origins*/)> = prunes
            .into_iter()
            .flat_map(|(from, prunes)| {
                repeat(from).zip(
                    prunes
                        .into_iter()
                        .chunks(MAX_PRUNE_DATA_NODES)
                        .into_iter()
                        .map(Iterator::collect)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let prune_messages: Vec<_> = {
            let gossip_crds = self.gossip.crds.read().unwrap();
            let wallclock = timestamp();
            thread_pool.install(|| {
                prunes
                    .into_par_iter()
                    .with_min_len(256)
                    .filter_map(|(from, prunes)| {
                        let peer: &LegacyContactInfo = gossip_crds.get(from)?;
                        let mut prune_data = PruneData {
                            pubkey: self_pubkey,
                            prunes,
                            signature: Signature::default(),
                            destination: from,
                            wallclock,
                        };
                        prune_data.sign(&self.keypair());
                        let prune_message = Protocol::PruneMessage(self_pubkey, prune_data);
                        Some((peer.gossip().ok()?, prune_message))
                    })
                    .collect()
            })
        };
        if prune_messages.is_empty() {
            return;
        }
        let mut packet_batch = PacketBatch::new_unpinned_with_recycler_data_and_dests(
            recycler.clone(),
            "handle_batch_push_messages",
            &prune_messages,
        );
        let num_prune_packets = packet_batch.len();
        self.stats
            .push_response_count
            .add_relaxed(packet_batch.len() as u64);
        let new_push_requests = self.new_push_requests(stakes);
        self.stats
            .push_message_pushes
            .add_relaxed(new_push_requests.len() as u64);
        for (address, request) in new_push_requests {
            if ContactInfo::is_valid_address(&address, &self.socket_addr_space) {
                match Packet::from_data(Some(&address), &request) {
                    Ok(packet) => packet_batch.push(packet),
                    Err(err) => error!("failed to write push-request packet: {:?}", err),
                }
            } else {
                trace!("Dropping Gossip push response, as destination is unknown");
            }
        }
        self.stats
            .packets_sent_prune_messages_count
            .add_relaxed(num_prune_packets as u64);
        self.stats
            .packets_sent_push_messages_count
            .add_relaxed((packet_batch.len() - num_prune_packets) as u64);
        let _ = response_sender.send(packet_batch);
    }

    fn require_stake_for_gossip(&self, stakes: &HashMap<Pubkey, u64>) -> bool {
        if stakes.len() < MIN_NUM_STAKED_NODES {
            self.stats
                .require_stake_for_gossip_unknown_stakes
                .add_relaxed(1);
            false
        } else {
            true
        }
    }

    fn process_packets(
        &self,
        packets: VecDeque<(/*from:*/ SocketAddr, Protocol)>,
        thread_pool: &ThreadPool,
        recycler: &PacketBatchRecycler,
        response_sender: &PacketBatchSender,
        stakes: &HashMap<Pubkey, u64>,
        _feature_set: Option<&FeatureSet>,
        epoch_duration: Duration,
        should_check_duplicate_instance: bool,
    ) -> Result<(), GossipError> {
        let _st = ScopedTimer::from(&self.stats.process_gossip_packets_time);
        // Filter out values if the shred-versions are different.
        let self_shred_version = self.my_shred_version();
        let packets = if self_shred_version == 0 {
            packets
        } else {
            let gossip_crds = self.gossip.crds.read().unwrap();
            thread_pool.install(|| {
                packets
                    .into_par_iter()
                    .with_min_len(1024)
                    .filter_map(|(from, msg)| {
                        let msg = filter_on_shred_version(
                            msg,
                            self_shred_version,
                            &gossip_crds,
                            &self.stats,
                        )?;
                        Some((from, msg))
                    })
                    .collect()
            })
        };

        // Check if there is a duplicate instance of
        // this node with more recent timestamp.
        let instance = self.instance.read().unwrap();
        let check_duplicate_instance = |values: &[CrdsValue]| {
            if should_check_duplicate_instance {
                for value in values {
                    if instance.check_duplicate(value) {
                        return Err(GossipError::DuplicateNodeInstance);
                    }
                }
            }
            Ok(())
        };
        // Split packets based on their types.
        let mut pull_requests = vec![];
        let mut pull_responses = vec![];
        let mut push_messages = vec![];
        let mut prune_messages = vec![];
        let mut ping_messages = vec![];
        let mut pong_messages = vec![];
        for (from_addr, packet) in packets {
            match packet {
                Protocol::PullRequest(filter, caller) => {
                    pull_requests.push((from_addr, filter, caller))
                }
                Protocol::PullResponse(from, data) => {
                    check_duplicate_instance(&data)?;
                    pull_responses.push((from, data));
                }
                Protocol::PushMessage(from, data) => {
                    check_duplicate_instance(&data)?;
                    push_messages.push((from, data));
                }
                Protocol::PruneMessage(_from, data) => prune_messages.push(data),
                Protocol::PingMessage(ping) => ping_messages.push((from_addr, ping)),
                Protocol::PongMessage(pong) => pong_messages.push((from_addr, pong)),
            }
        }
        if self.require_stake_for_gossip(stakes) {
            for (_, data) in &mut pull_responses {
                retain_staked(data, stakes);
            }
            for (_, data) in &mut push_messages {
                retain_staked(data, stakes);
            }
            pull_responses.retain(|(_, data)| !data.is_empty());
            push_messages.retain(|(_, data)| !data.is_empty());
        }
        self.handle_batch_ping_messages(ping_messages, recycler, response_sender);
        self.handle_batch_prune_messages(prune_messages, stakes);
        self.handle_batch_push_messages(
            push_messages,
            thread_pool,
            recycler,
            stakes,
            response_sender,
        );
        self.handle_batch_pull_responses(pull_responses, thread_pool, stakes, epoch_duration);
        self.trim_crds_table(CRDS_UNIQUE_PUBKEY_CAPACITY, stakes);
        self.handle_batch_pong_messages(pong_messages, Instant::now());
        self.handle_batch_pull_requests(
            pull_requests,
            thread_pool,
            recycler,
            stakes,
            response_sender,
        );
        self.stats
            .process_gossip_packets_iterations_since_last_report
            .add_relaxed(1);
        Ok(())
    }

    // Consumes packets received from the socket, deserializing, sanitizing and
    // verifying them and then sending them down the channel for the actual
    // handling of requests/messages.
    fn run_socket_consume(
        &self,
        receiver: &PacketBatchReceiver,
        sender: &Sender<Vec<(/*from:*/ SocketAddr, Protocol)>>,
        thread_pool: &ThreadPool,
    ) -> Result<(), GossipError> {
        const RECV_TIMEOUT: Duration = Duration::from_secs(1);
        fn count_packets_received(packets: &PacketBatch, counts: &mut [u64; 7]) {
            for packet in packets {
                let k = match packet
                    .data(..4)
                    .and_then(|data| <[u8; 4]>::try_from(data).ok())
                    .map(u32::from_le_bytes)
                {
                    Some(k @ 0..=6) => k as usize,
                    None | Some(_) => 6,
                };
                counts[k] += 1;
            }
        }
        let packets = receiver.recv_timeout(RECV_TIMEOUT)?;
        let mut counts = [0u64; 7];
        count_packets_received(&packets, &mut counts);
        let packets = Vec::from(packets);
        let mut packets = VecDeque::from(packets);
        for packet_batch in receiver.try_iter() {
            count_packets_received(&packet_batch, &mut counts);
            packets.extend(packet_batch.iter().cloned());
            let excess_count = packets.len().saturating_sub(MAX_GOSSIP_TRAFFIC);
            if excess_count > 0 {
                packets.drain(0..excess_count);
                self.stats
                    .gossip_packets_dropped_count
                    .add_relaxed(excess_count as u64);
            }
        }
        let verify_packet = |packet: Packet| {
            let protocol: Protocol = packet.deserialize_slice(..).ok()?;
            protocol.sanitize().ok()?;
            let protocol = protocol.par_verify(&self.stats)?;
            Some((packet.meta().socket_addr(), protocol))
        };
        let packets: Vec<_> = {
            let _st = ScopedTimer::from(&self.stats.verify_gossip_packets_time);
            thread_pool.install(|| packets.into_par_iter().filter_map(verify_packet).collect())
        };
        self.stats
            .packets_received_count
            .add_relaxed(counts.iter().sum::<u64>());
        self.stats
            .packets_received_pull_requests_count
            .add_relaxed(counts[0]);
        self.stats
            .packets_received_pull_responses_count
            .add_relaxed(counts[1]);
        self.stats
            .packets_received_push_messages_count
            .add_relaxed(counts[2]);
        self.stats
            .packets_received_prune_messages_count
            .add_relaxed(counts[3]);
        self.stats
            .packets_received_ping_messages_count
            .add_relaxed(counts[4]);
        self.stats
            .packets_received_pong_messages_count
            .add_relaxed(counts[5]);
        self.stats
            .packets_received_unknown_count
            .add_relaxed(counts[6]);
        self.stats
            .packets_received_verified_count
            .add_relaxed(packets.len() as u64);
        Ok(sender.send(packets)?)
    }

    /// Process messages from the network
    fn run_listen(
        &self,
        recycler: &PacketBatchRecycler,
        bank_forks: Option<&RwLock<BankForks>>,
        receiver: &Receiver<Vec<(/*from:*/ SocketAddr, Protocol)>>,
        response_sender: &PacketBatchSender,
        thread_pool: &ThreadPool,
        last_print: &mut Instant,
        should_check_duplicate_instance: bool,
    ) -> Result<(), GossipError> {
        let _st = ScopedTimer::from(&self.stats.gossip_listen_loop_time);
        const RECV_TIMEOUT: Duration = Duration::from_secs(1);
        const SUBMIT_GOSSIP_STATS_INTERVAL: Duration = Duration::from_secs(2);
        let mut packets = VecDeque::from(receiver.recv_timeout(RECV_TIMEOUT)?);
        for payload in receiver.try_iter() {
            packets.extend(payload);
            let excess_count = packets.len().saturating_sub(MAX_GOSSIP_TRAFFIC);
            if excess_count > 0 {
                packets.drain(0..excess_count);
                self.stats
                    .gossip_packets_dropped_count
                    .add_relaxed(excess_count as u64);
            }
        }
        // Using root_bank instead of working_bank here so that an enbaled
        // feature does not roll back (if the feature happens to get enabled in
        // a minority fork).
        let (feature_set, stakes) = match bank_forks {
            None => (None, Arc::default()),
            Some(bank_forks) => {
                let bank = bank_forks.read().unwrap().root_bank();
                let feature_set = bank.feature_set.clone();
                (Some(feature_set), bank.staked_nodes())
            }
        };
        self.process_packets(
            packets,
            thread_pool,
            recycler,
            response_sender,
            &stakes,
            feature_set.as_deref(),
            get_epoch_duration(bank_forks, &self.stats),
            should_check_duplicate_instance,
        )?;
        if last_print.elapsed() > SUBMIT_GOSSIP_STATS_INTERVAL {
            submit_gossip_stats(&self.stats, &self.gossip, &stakes);
            *last_print = Instant::now();
        }
        self.stats
            .gossip_listen_loop_iterations_since_last_report
            .add_relaxed(1);
        Ok(())
    }

    pub(crate) fn start_socket_consume_thread(
        self: Arc<Self>,
        receiver: PacketBatchReceiver,
        sender: Sender<Vec<(/*from:*/ SocketAddr, Protocol)>>,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(get_thread_count().min(8))
            .thread_name(|i| format!("solGossipCons{i:02}"))
            .build()
            .unwrap();
        let run_consume = move || {
            while !exit.load(Ordering::Relaxed) {
                match self.run_socket_consume(&receiver, &sender, &thread_pool) {
                    Err(GossipError::RecvTimeoutError(RecvTimeoutError::Disconnected)) => break,
                    Err(GossipError::RecvTimeoutError(RecvTimeoutError::Timeout)) => (),
                    // A send operation can only fail if the receiving end of a
                    // channel is disconnected.
                    Err(GossipError::SendError) => break,
                    Err(err) => error!("gossip consume: {}", err),
                    Ok(()) => (),
                }
            }
        };
        let thread_name = String::from("solGossipConsum");
        Builder::new().name(thread_name).spawn(run_consume).unwrap()
    }

    pub(crate) fn listen(
        self: Arc<Self>,
        bank_forks: Option<Arc<RwLock<BankForks>>>,
        requests_receiver: Receiver<Vec<(/*from:*/ SocketAddr, Protocol)>>,
        response_sender: PacketBatchSender,
        should_check_duplicate_instance: bool,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let mut last_print = Instant::now();
        let recycler = PacketBatchRecycler::default();
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(get_thread_count().min(8))
            .thread_name(|i| format!("solGossipWork{i:02}"))
            .build()
            .unwrap();
        Builder::new()
            .name("solGossipListen".to_string())
            .spawn(move || {
                while !exit.load(Ordering::Relaxed) {
                    if let Err(err) = self.run_listen(
                        &recycler,
                        bank_forks.as_deref(),
                        &requests_receiver,
                        &response_sender,
                        &thread_pool,
                        &mut last_print,
                        should_check_duplicate_instance,
                    ) {
                        match err {
                            GossipError::RecvTimeoutError(RecvTimeoutError::Disconnected) => break,
                            GossipError::RecvTimeoutError(RecvTimeoutError::Timeout) => {
                                let table_size = self.gossip.crds.read().unwrap().len();
                                debug!(
                                    "{}: run_listen timeout, table size: {}",
                                    self.id(),
                                    table_size,
                                );
                            }
                            GossipError::DuplicateNodeInstance => {
                                error!(
                                    "duplicate running instances of the same validator node: {}",
                                    self.id()
                                );
                                exit.store(true, Ordering::Relaxed);
                                // TODO: Pass through Exit here so
                                // that this will exit cleanly.
                                std::process::exit(1);
                            }
                            _ => error!("gossip run_listen failed: {}", err),
                        }
                    }
                }
            })
            .unwrap()
    }

    pub fn gossip_contact_info(id: Pubkey, gossip: SocketAddr, shred_version: u16) -> ContactInfo {
        let mut node = ContactInfo::new(id, /*wallclock:*/ timestamp(), shred_version);
        let _ = node.set_gossip(gossip);
        node
    }

    /// An alternative to Spy Node that has a valid gossip address and fully participate in Gossip.
    pub fn gossip_node(
        id: Pubkey,
        gossip_addr: &SocketAddr,
        shred_version: u16,
    ) -> (ContactInfo, UdpSocket, Option<TcpListener>) {
        let bind_ip_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let (port, (gossip_socket, ip_echo)) =
            Node::get_gossip_port(gossip_addr, VALIDATOR_PORT_RANGE, bind_ip_addr);
        let contact_info =
            Self::gossip_contact_info(id, SocketAddr::new(gossip_addr.ip(), port), shred_version);

        (contact_info, gossip_socket, Some(ip_echo))
    }

    /// A Node with dummy ports to spy on gossip via pull requests
    pub fn spy_node(
        id: Pubkey,
        shred_version: u16,
    ) -> (ContactInfo, UdpSocket, Option<TcpListener>) {
        let bind_ip_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let (_, gossip_socket) = bind_in_range(bind_ip_addr, VALIDATOR_PORT_RANGE).unwrap();
        let contact_info = Self::gossip_contact_info(id, socketaddr_any!(), shred_version);

        (contact_info, gossip_socket, None)
    }
}

// Returns root bank's epoch duration. Falls back on
//     DEFAULT_SLOTS_PER_EPOCH * DEFAULT_MS_PER_SLOT
// if there are no working banks.
fn get_epoch_duration(bank_forks: Option<&RwLock<BankForks>>, stats: &GossipStats) -> Duration {
    let num_slots = match bank_forks {
        None => {
            stats.get_epoch_duration_no_working_bank.add_relaxed(1);
            DEFAULT_SLOTS_PER_EPOCH
        }
        Some(bank_forks) => {
            let bank = bank_forks.read().unwrap().root_bank();
            bank.get_slots_in_epoch(bank.epoch())
        }
    };
    Duration::from_millis(num_slots * DEFAULT_MS_PER_SLOT)
}

/// Turbine logic
/// 1 - For the current node find out if it is in layer 1
/// 1.1 - If yes, then broadcast to all layer 1 nodes
///      1 - using the layer 1 index, broadcast to all layer 2 nodes assuming you know neighborhood size
/// 1.2 - If no, then figure out what layer the node is in and who the neighbors are and only broadcast to them
///      1 - also check if there are nodes in the next layer and repeat the layer 1 to layer 2 logic

/// Returns Neighbor Nodes and Children Nodes `(neighbors, children)` for a given node based on its stake
pub fn compute_retransmit_peers<T: Copy>(
    fanout: usize,
    index: usize, // Local node's index withing the nodes slice.
    nodes: &[T],
) -> (Vec<T> /*neighbors*/, Vec<T> /*children*/) {
    // 1st layer: fanout    nodes starting at 0
    // 2nd layer: fanout**2 nodes starting at fanout
    // 3rd layer: fanout**3 nodes starting at fanout + fanout**2
    // ...
    // Each layer is divided into neighborhoods of fanout nodes each.
    let offset = index % fanout; // Node's index within its neighborhood.
    let anchor = index - offset; // First node in the neighborhood.
    let neighbors = (anchor..)
        .take(fanout)
        .map(|i| nodes.get(i).copied())
        .while_some()
        .collect();
    let children = ((anchor + 1) * fanout + offset..)
        .step_by(fanout)
        .take(fanout)
        .map(|i| nodes.get(i).copied())
        .while_some()
        .collect();
    (neighbors, children)
}

#[derive(Debug)]
pub struct Sockets {
    pub gossip: UdpSocket,
    pub ip_echo: Option<TcpListener>,
    pub tvu: Vec<UdpSocket>,
    pub tvu_forwards: Vec<UdpSocket>,
    pub tpu: Vec<UdpSocket>,
    pub tpu_forwards: Vec<UdpSocket>,
    pub tpu_vote: Vec<UdpSocket>,
    pub broadcast: Vec<UdpSocket>,
    pub repair: UdpSocket,
    pub retransmit_sockets: Vec<UdpSocket>,
    pub serve_repair: UdpSocket,
    pub ancestor_hashes_requests: UdpSocket,
    pub tpu_quic: UdpSocket,
    pub tpu_forwards_quic: UdpSocket,
}

#[derive(Debug)]
pub struct Node {
    pub info: ContactInfo,
    pub sockets: Sockets,
}

impl Node {
    pub fn new_localhost() -> Self {
        let pubkey = solana_sdk::pubkey::new_rand();
        Self::new_localhost_with_pubkey(&pubkey)
    }
    pub fn new_localhost_with_pubkey(pubkey: &Pubkey) -> Self {
        let localhost_ip_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let localhost_bind_addr = format!("{localhost_ip_addr:?}:0");
        let unspecified_bind_addr = format!("{:?}:0", IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let port_range = (1024, 65535);

        let ((_tpu_port, tpu), (_tpu_quic_port, tpu_quic)) =
            bind_two_in_range_with_offset(localhost_ip_addr, port_range, QUIC_PORT_OFFSET).unwrap();
        let (gossip_port, (gossip, ip_echo)) =
            bind_common_in_range(localhost_ip_addr, port_range).unwrap();
        let gossip_addr = SocketAddr::new(localhost_ip_addr, gossip_port);
        let tvu = UdpSocket::bind(&localhost_bind_addr).unwrap();
        let tvu_forwards = UdpSocket::bind(&localhost_bind_addr).unwrap();
        let ((_tpu_forwards_port, tpu_forwards), (_tpu_forwards_quic_port, tpu_forwards_quic)) =
            bind_two_in_range_with_offset(localhost_ip_addr, port_range, QUIC_PORT_OFFSET).unwrap();
        let tpu_vote = UdpSocket::bind(&localhost_bind_addr).unwrap();
        let repair = UdpSocket::bind(&localhost_bind_addr).unwrap();
        let rpc_port = find_available_port_in_range(localhost_ip_addr, port_range).unwrap();
        let rpc_addr = SocketAddr::new(localhost_ip_addr, rpc_port);
        let rpc_pubsub_port = find_available_port_in_range(localhost_ip_addr, port_range).unwrap();
        let rpc_pubsub_addr = SocketAddr::new(localhost_ip_addr, rpc_pubsub_port);
        let broadcast = vec![UdpSocket::bind(&unspecified_bind_addr).unwrap()];
        let retransmit_socket = UdpSocket::bind(&unspecified_bind_addr).unwrap();
        let serve_repair = UdpSocket::bind(&localhost_bind_addr).unwrap();
        let ancestor_hashes_requests = UdpSocket::bind(&unspecified_bind_addr).unwrap();

        let mut info = ContactInfo::new(
            *pubkey,
            timestamp(), // wallclock
            0u16,        // shred_version
        );
        macro_rules! set_socket {
            ($method:ident, $addr:expr, $name:literal) => {
                info.$method($addr).expect(&format!(
                    "Operator must spin up node with valid {} address",
                    $name
                ))
            };
        }
        set_socket!(set_gossip, gossip_addr, "gossip");
        set_socket!(set_tvu, tvu.local_addr().unwrap(), "TVU");
        set_socket!(
            set_tvu_forwards,
            tvu_forwards.local_addr().unwrap(),
            "TVU-forwards"
        );
        set_socket!(set_repair, repair.local_addr().unwrap(), "repair");
        set_socket!(set_tpu, tpu.local_addr().unwrap(), "TPU");
        set_socket!(
            set_tpu_forwards,
            tpu_forwards.local_addr().unwrap(),
            "TPU-forwards"
        );
        set_socket!(set_tpu_vote, tpu_vote.local_addr().unwrap(), "TPU-vote");
        set_socket!(set_rpc, rpc_addr, "RPC");
        set_socket!(set_rpc_pubsub, rpc_pubsub_addr, "RPC-pubsub");
        set_socket!(
            set_serve_repair,
            serve_repair.local_addr().unwrap(),
            "serve-repair"
        );
        Node {
            info,
            sockets: Sockets {
                gossip,
                ip_echo: Some(ip_echo),
                tvu: vec![tvu],
                tvu_forwards: vec![tvu_forwards],
                tpu: vec![tpu],
                tpu_forwards: vec![tpu_forwards],
                tpu_vote: vec![tpu_vote],
                broadcast,
                repair,
                retransmit_sockets: vec![retransmit_socket],
                serve_repair,
                ancestor_hashes_requests,
                tpu_quic,
                tpu_forwards_quic,
            },
        }
    }

    fn get_gossip_port(
        gossip_addr: &SocketAddr,
        port_range: PortRange,
        bind_ip_addr: IpAddr,
    ) -> (u16, (UdpSocket, TcpListener)) {
        if gossip_addr.port() != 0 {
            (
                gossip_addr.port(),
                bind_common(bind_ip_addr, gossip_addr.port(), false).unwrap_or_else(|e| {
                    panic!("gossip_addr bind_to port {}: {}", gossip_addr.port(), e)
                }),
            )
        } else {
            bind_common_in_range(bind_ip_addr, port_range).expect("Failed to bind")
        }
    }
    fn bind(bind_ip_addr: IpAddr, port_range: PortRange) -> (u16, UdpSocket) {
        bind_in_range(bind_ip_addr, port_range).expect("Failed to bind")
    }

    pub fn new_single_bind(
        pubkey: &Pubkey,
        gossip_addr: &SocketAddr,
        port_range: PortRange,
        bind_ip_addr: IpAddr,
    ) -> Self {
        let (gossip_port, (gossip, ip_echo)) =
            Self::get_gossip_port(gossip_addr, port_range, bind_ip_addr);
        let (tvu_port, tvu) = Self::bind(bind_ip_addr, port_range);
        let (tvu_forwards_port, tvu_forwards) = Self::bind(bind_ip_addr, port_range);
        let ((tpu_port, tpu), (_tpu_quic_port, tpu_quic)) =
            bind_two_in_range_with_offset(bind_ip_addr, port_range, QUIC_PORT_OFFSET).unwrap();
        let ((tpu_forwards_port, tpu_forwards), (_tpu_forwards_quic_port, tpu_forwards_quic)) =
            bind_two_in_range_with_offset(bind_ip_addr, port_range, QUIC_PORT_OFFSET).unwrap();
        let (tpu_vote_port, tpu_vote) = Self::bind(bind_ip_addr, port_range);
        let (_, retransmit_socket) = Self::bind(bind_ip_addr, port_range);
        let (repair_port, repair) = Self::bind(bind_ip_addr, port_range);
        let (serve_repair_port, serve_repair) = Self::bind(bind_ip_addr, port_range);
        let (_, broadcast) = Self::bind(bind_ip_addr, port_range);
        let (_, ancestor_hashes_requests) = Self::bind(bind_ip_addr, port_range);

        let rpc_port = find_available_port_in_range(bind_ip_addr, port_range).unwrap();
        let rpc_pubsub_port = find_available_port_in_range(bind_ip_addr, port_range).unwrap();

        let addr = gossip_addr.ip();
        let mut info = ContactInfo::new(
            *pubkey,
            timestamp(), // wallclock
            0u16,        // shred_version
        );
        macro_rules! set_socket {
            ($method:ident, $port:ident, $name:literal) => {
                info.$method((addr, $port)).expect(&format!(
                    "Operator must spin up node with valid {} address",
                    $name
                ))
            };
        }
        set_socket!(set_gossip, gossip_port, "gossip");
        set_socket!(set_tvu, tvu_port, "TVU");
        set_socket!(set_tvu_forwards, tvu_forwards_port, "TVU-forwards");
        set_socket!(set_repair, repair_port, "repair");
        set_socket!(set_tpu, tpu_port, "TPU");
        set_socket!(set_tpu_forwards, tpu_forwards_port, "TPU-forwards");
        set_socket!(set_tpu_vote, tpu_vote_port, "TPU-vote");
        set_socket!(set_rpc, rpc_port, "RPC");
        set_socket!(set_rpc_pubsub, rpc_pubsub_port, "RPC-pubsub");
        set_socket!(set_serve_repair, serve_repair_port, "serve-repair");
        trace!("new ContactInfo: {:?}", info);

        Node {
            info,
            sockets: Sockets {
                gossip,
                ip_echo: Some(ip_echo),
                tvu: vec![tvu],
                tvu_forwards: vec![tvu_forwards],
                tpu: vec![tpu],
                tpu_forwards: vec![tpu_forwards],
                tpu_vote: vec![tpu_vote],
                broadcast: vec![broadcast],
                repair,
                retransmit_sockets: vec![retransmit_socket],
                serve_repair,
                ancestor_hashes_requests,
                tpu_quic,
                tpu_forwards_quic,
            },
        }
    }

    pub fn new_with_external_ip(
        pubkey: &Pubkey,
        gossip_addr: &SocketAddr,
        port_range: PortRange,
        bind_ip_addr: IpAddr,
        public_tpu_addr: Option<SocketAddr>,
        public_tpu_forwards_addr: Option<SocketAddr>,
    ) -> Node {
        let (gossip_port, (gossip, ip_echo)) =
            Self::get_gossip_port(gossip_addr, port_range, bind_ip_addr);

        let (tvu_port, tvu_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 8).expect("tvu multi_bind");

        let (tvu_forwards_port, tvu_forwards_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 8).expect("tvu_forwards multi_bind");

        let (tpu_port, tpu_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 32).expect("tpu multi_bind");

        let (_tpu_port_quic, tpu_quic) = Self::bind(
            bind_ip_addr,
            (tpu_port + QUIC_PORT_OFFSET, tpu_port + QUIC_PORT_OFFSET + 1),
        );

        let (tpu_forwards_port, tpu_forwards_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 8).expect("tpu_forwards multi_bind");

        let (_tpu_forwards_port_quic, tpu_forwards_quic) = Self::bind(
            bind_ip_addr,
            (
                tpu_forwards_port + QUIC_PORT_OFFSET,
                tpu_forwards_port + QUIC_PORT_OFFSET + 1,
            ),
        );

        let (tpu_vote_port, tpu_vote_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 1).expect("tpu_vote multi_bind");

        let (_, retransmit_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 8).expect("retransmit multi_bind");

        let (repair_port, repair) = Self::bind(bind_ip_addr, port_range);
        let (serve_repair_port, serve_repair) = Self::bind(bind_ip_addr, port_range);

        let (_, broadcast) =
            multi_bind_in_range(bind_ip_addr, port_range, 4).expect("broadcast multi_bind");

        let (_, ancestor_hashes_requests) = Self::bind(bind_ip_addr, port_range);

        let mut info = ContactInfo::new(
            *pubkey,
            timestamp(), // wallclock
            0u16,        // shred_version
        );
        let addr = gossip_addr.ip();
        let _ = info.set_gossip((addr, gossip_port));
        let _ = info.set_tvu((addr, tvu_port));
        let _ = info.set_tvu_forwards((addr, tvu_forwards_port));
        let _ = info.set_repair((addr, repair_port));
        let _ = info.set_tpu(public_tpu_addr.unwrap_or_else(|| SocketAddr::new(addr, tpu_port)));
        let _ = info.set_tpu_forwards(
            public_tpu_forwards_addr.unwrap_or_else(|| SocketAddr::new(addr, tpu_forwards_port)),
        );
        let _ = info.set_tpu_vote((addr, tpu_vote_port));
        let _ = info.set_serve_repair((addr, serve_repair_port));
        trace!("new ContactInfo: {:?}", info);

        Node {
            info,
            sockets: Sockets {
                gossip,
                tvu: tvu_sockets,
                tvu_forwards: tvu_forwards_sockets,
                tpu: tpu_sockets,
                tpu_forwards: tpu_forwards_sockets,
                tpu_vote: tpu_vote_sockets,
                broadcast,
                repair,
                retransmit_sockets,
                serve_repair,
                ip_echo: Some(ip_echo),
                ancestor_hashes_requests,
                tpu_quic,
                tpu_forwards_quic,
            },
        }
    }
}

pub fn push_messages_to_peer(
    messages: Vec<CrdsValue>,
    self_id: Pubkey,
    peer_gossip: SocketAddr,
    socket_addr_space: &SocketAddrSpace,
) -> Result<(), GossipError> {
    let reqs: Vec<_> = ClusterInfo::split_gossip_messages(PUSH_MESSAGE_MAX_PAYLOAD_SIZE, messages)
        .map(move |payload| (peer_gossip, Protocol::PushMessage(self_id, payload)))
        .collect();
    let packet_batch = PacketBatch::new_unpinned_with_recycler_data_and_dests(
        PacketBatchRecycler::default(),
        "push_messages_to_peer",
        &reqs,
    );
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    packet::send_to(&packet_batch, &sock, socket_addr_space)?;
    Ok(())
}

// Filters out values from nodes with different shred-version.
fn filter_on_shred_version(
    mut msg: Protocol,
    self_shred_version: u16,
    crds: &Crds,
    stats: &GossipStats,
) -> Option<Protocol> {
    let filter_values = |from: &Pubkey, values: &mut Vec<CrdsValue>, skipped_counter: &Counter| {
        let num_values = values.len();
        // Node-instances are always exempted from shred-version check so that:
        // * their propagation across cluster is expedited.
        // * prevent two running instances of the same identity key cross
        //   contaminate gossip between clusters.
        if crds.get_shred_version(from) == Some(self_shred_version) {
            values.retain(|value| match &value.data {
                // Allow contact-infos so that shred-versions are updated.
                CrdsData::LegacyContactInfo(_) => true,
                CrdsData::NodeInstance(_) => true,
                // Only retain values with the same shred version.
                _ => crds.get_shred_version(&value.pubkey()) == Some(self_shred_version),
            })
        } else {
            values.retain(|value| match &value.data {
                // Allow node to update its own contact info in case their
                // shred-version changes
                CrdsData::LegacyContactInfo(node) => node.pubkey() == from,
                CrdsData::NodeInstance(_) => true,
                _ => false,
            })
        }
        let num_skipped = num_values - values.len();
        if num_skipped != 0 {
            skipped_counter.add_relaxed(num_skipped as u64);
        }
    };
    match &mut msg {
        Protocol::PullRequest(_, caller) => match &caller.data {
            // Allow spy nodes with shred-verion == 0 to pull from other nodes.
            CrdsData::LegacyContactInfo(node)
                if node.shred_version() == 0 || node.shred_version() == self_shred_version =>
            {
                Some(msg)
            }
            _ => {
                stats.skip_pull_shred_version.add_relaxed(1);
                None
            }
        },
        Protocol::PullResponse(from, values) => {
            filter_values(from, values, &stats.skip_pull_response_shred_version);
            if values.is_empty() {
                None
            } else {
                Some(msg)
            }
        }
        Protocol::PushMessage(from, values) => {
            filter_values(from, values, &stats.skip_push_message_shred_version);
            if values.is_empty() {
                None
            } else {
                Some(msg)
            }
        }
        Protocol::PruneMessage(_, _) | Protocol::PingMessage(_) | Protocol::PongMessage(_) => {
            Some(msg)
        }
    }
}

