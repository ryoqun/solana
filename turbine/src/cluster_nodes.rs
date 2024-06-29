use {
    crate::{broadcast_stage::BroadcastStage, retransmit_stage::RetransmitStage},
    itertools::Itertools,
    lru::LruCache,
    rand::{seq::SliceRandom, Rng, SeedableRng},
    rand_chacha::ChaChaRng,
    solana_gossip::{
        cluster_info::ClusterInfo,
        contact_info::{ContactInfo, Protocol},
        crds::GossipRoute,
        crds_gossip_pull::CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS,
        crds_value::{CrdsData, CrdsValue},
        weighted_shuffle::WeightedShuffle,
    },
    solana_ledger::shred::ShredId,
    solana_runtime::bank::Bank,
    solana_sdk::{
        clock::{Epoch, Slot},
        feature_set,
        genesis_config::ClusterType,
        native_token::LAMPORTS_PER_SOL,
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        timing::timestamp,
    },
    solana_streamer::socket::SocketAddrSpace,
    std::{
        any::TypeId,
        cmp::Reverse,
        collections::HashMap,
        iter::repeat_with,
        marker::PhantomData,
        net::{IpAddr, SocketAddr},
        sync::{Arc, Mutex, RwLock},
        time::{Duration, Instant},
    },
    thiserror::Error,
};

const DATA_PLANE_FANOUT: usize = 200;
pub(crate) const MAX_NUM_TURBINE_HOPS: usize = 4;

// Limit number of nodes per IP address.
const MAX_NUM_NODES_PER_IP_ADDRESS: usize = 10;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Loopback from slot leader: {leader}, shred: {shred:?}")]
    Loopback { leader: Pubkey, shred: ShredId },
}

#[allow(clippy::large_enum_variant)]
enum NodeId {
    // TVU node obtained through gossip (staked or not).
    ContactInfo(ContactInfo),
    // Staked node with no contact-info in gossip table.
    Pubkey(Pubkey),
}

pub struct Node {
    node: NodeId,
    stake: u64,
}

pub struct ClusterNodes<T> {
    pubkey: Pubkey, // The local node itself.
    // All staked nodes + other known tvu-peers + the node itself;
    // sorted by (stake, pubkey) in descending order.
    nodes: Vec<Node>,
    // Reverse index from nodes pubkey to their index in self.nodes.
    index: HashMap<Pubkey, /*index:*/ usize>,
    weighted_shuffle: WeightedShuffle</*stake:*/ u64>,
    _phantom: PhantomData<T>,
}

type CacheEntry<T> = Option<(/*as of:*/ Instant, Arc<ClusterNodes<T>>)>;

pub struct ClusterNodesCache<T> {
    // Cache entries are wrapped in Arc<RwLock<...>>, so that, when needed, only
    // one thread does the computations to update the entry for the epoch.
    cache: Mutex<LruCache<Epoch, Arc<RwLock<CacheEntry<T>>>>>,
    ttl: Duration, // Time to live.
}

pub struct RetransmitPeers<'a> {
    root_distance: usize, // distance from the root node
    children: Vec<&'a Node>,
    // Maps tvu addresses to the first node
    // in the shuffle with the same address.
    addrs: HashMap<SocketAddr, Pubkey>, // tvu addresses
}

impl Node {
    #[inline]
    fn pubkey(&self) -> Pubkey {
        match &self.node {
            NodeId::Pubkey(pubkey) => *pubkey,
            NodeId::ContactInfo(node) => *node.pubkey(),
        }
    }

    #[inline]
    fn contact_info(&self) -> Option<&ContactInfo> {
        match &self.node {
            NodeId::Pubkey(_) => None,
            NodeId::ContactInfo(node) => Some(node),
        }
    }
}

impl<T> ClusterNodes<T> {
    pub(crate) fn submit_metrics(&self, name: &'static str, now: u64) {
        let mut epoch_stakes = 0;
        let mut num_nodes_dead = 0;
        let mut num_nodes_staked = 0;
        let mut num_nodes_stale = 0;
        let mut stake_dead = 0;
        let mut stake_stale = 0;
        for node in &self.nodes {
            epoch_stakes += node.stake;
            if node.stake != 0u64 {
                num_nodes_staked += 1;
            }
            match node.contact_info().map(ContactInfo::wallclock) {
                None => {
                    num_nodes_dead += 1;
                    stake_dead += node.stake;
                }
                Some(wallclock) => {
                    let age = now.saturating_sub(wallclock);
                    if age > CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS {
                        num_nodes_stale += 1;
                        stake_stale += node.stake;
                    }
                }
            }
        }
        num_nodes_stale += num_nodes_dead;
        stake_stale += stake_dead;
        datapoint_info!(
            name,
            ("epoch_stakes", epoch_stakes / LAMPORTS_PER_SOL, i64),
            ("num_nodes", self.nodes.len(), i64),
            ("num_nodes_dead", num_nodes_dead, i64),
            ("num_nodes_staked", num_nodes_staked, i64),
            ("num_nodes_stale", num_nodes_stale, i64),
            ("stake_dead", stake_dead / LAMPORTS_PER_SOL, i64),
            ("stake_stale", stake_stale / LAMPORTS_PER_SOL, i64),
        );
    }
}

impl ClusterNodes<BroadcastStage> {
    pub fn new(
        cluster_info: &ClusterInfo,
        cluster_type: ClusterType,
        stakes: &HashMap<Pubkey, u64>,
    ) -> Self {
        new_cluster_nodes(cluster_info, cluster_type, stakes)
    }

    pub(crate) fn get_broadcast_peer(&self, shred: &ShredId) -> Option<&ContactInfo> {
        let mut rng = get_seeded_rng(/*leader:*/ &self.pubkey, shred);
        let index = self.weighted_shuffle.first(&mut rng)?;
        self.nodes[index].contact_info()
    }
}

impl ClusterNodes<RetransmitStage> {
    pub(crate) fn get_retransmit_addrs(
        &self,
        slot_leader: &Pubkey,
        shred: &ShredId,
        fanout: usize,
    ) -> Result<(/*root_distance:*/ usize, Vec<SocketAddr>), Error> {
        let RetransmitPeers {
            root_distance,
            children,
            addrs,
        } = self.get_retransmit_peers(slot_leader, shred, fanout)?;
        let protocol = get_broadcast_protocol(shred);
        let peers = children.into_iter().filter_map(|node| {
            node.contact_info()?
                .tvu(protocol)
                .ok()
                .filter(|addr| addrs.get(addr) == Some(&node.pubkey()))
        });
        Ok((root_distance, peers.collect()))
    }

    pub fn get_retransmit_peers(
        &self,
        slot_leader: &Pubkey,
        shred: &ShredId,
        fanout: usize,
    ) -> Result<RetransmitPeers, Error> {
        let mut weighted_shuffle = self.weighted_shuffle.clone();
        // Exclude slot leader from list of nodes.
        if slot_leader == &self.pubkey {
            return Err(Error::Loopback {
                leader: *slot_leader,
                shred: *shred,
            });
        }
        if let Some(index) = self.index.get(slot_leader) {
            weighted_shuffle.remove_index(*index);
        }
        let mut addrs = HashMap::<SocketAddr, Pubkey>::with_capacity(self.nodes.len());
        let mut rng = get_seeded_rng(slot_leader, shred);
        let protocol = get_broadcast_protocol(shred);
        let nodes: Vec<_> = weighted_shuffle
            .shuffle(&mut rng)
            .map(|index| &self.nodes[index])
            .inspect(|node| {
                if let Some(node) = node.contact_info() {
                    if let Ok(addr) = node.tvu(protocol) {
                        addrs.entry(addr).or_insert(*node.pubkey());
                    }
                }
            })
            .collect();
        let self_index = nodes
            .iter()
            .position(|node| node.pubkey() == self.pubkey)
            .unwrap();
        let root_distance = if self_index == 0 {
            0
        } else if self_index <= fanout {
            1
        } else if self_index <= fanout.saturating_add(1).saturating_mul(fanout) {
            2
        } else {
            3 // If changed, update MAX_NUM_TURBINE_HOPS.
        };
        let peers = get_retransmit_peers(fanout, self_index, &nodes);
        Ok(RetransmitPeers {
            root_distance,
            children: peers.collect(),
            addrs,
        })
    }

    // Returns the parent node in the turbine broadcast tree.
    // Returns None if the node is the root of the tree or if it is not staked.
    pub(crate) fn get_retransmit_parent(
        &self,
        leader: &Pubkey,
        shred: &ShredId,
        fanout: usize,
    ) -> Result<Option<Pubkey>, Error> {
        // Exclude slot leader from list of nodes.
        if leader == &self.pubkey {
            return Err(Error::Loopback {
                leader: *leader,
                shred: *shred,
            });
        }
        // Unstaked nodes' position in the turbine tree is not deterministic
        // and depends on gossip propagation of contact-infos. Therefore, if
        // this node is not staked return None.
        if self.nodes[self.index[&self.pubkey]].stake == 0 {
            return Ok(None);
        }
        let mut weighted_shuffle = self.weighted_shuffle.clone();
        if let Some(index) = self.index.get(leader).copied() {
            weighted_shuffle.remove_index(index);
        }
        let mut rng = get_seeded_rng(leader, shred);
        // Only need shuffled nodes until this node itself.
        let nodes: Vec<_> = weighted_shuffle
            .shuffle(&mut rng)
            .map(|index| &self.nodes[index])
            .take_while(|node| node.pubkey() != self.pubkey)
            .collect();
        let parent = get_retransmit_parent(fanout, nodes.len(), &nodes);
        Ok(parent.map(Node::pubkey))
    }
}

pub fn new_cluster_nodes<T: 'static>(
    cluster_info: &ClusterInfo,
    cluster_type: ClusterType,
    stakes: &HashMap<Pubkey, u64>,
) -> ClusterNodes<T> {
    let self_pubkey = cluster_info.id();
    let nodes = get_nodes(cluster_info, cluster_type, stakes);
    let index: HashMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(ix, node)| (node.pubkey(), ix))
        .collect();
    let broadcast = TypeId::of::<T>() == TypeId::of::<BroadcastStage>();
    let stakes: Vec<u64> = nodes.iter().map(|node| node.stake).collect();
    let mut weighted_shuffle = WeightedShuffle::new("cluster-nodes", &stakes);
    if broadcast {
        weighted_shuffle.remove_index(index[&self_pubkey]);
    }
    ClusterNodes {
        pubkey: self_pubkey,
        nodes,
        index,
        weighted_shuffle,
        _phantom: PhantomData,
    }
}

// All staked nodes + other known tvu-peers + the node itself;
// sorted by (stake, pubkey) in descending order.
fn get_nodes(
    cluster_info: &ClusterInfo,
    cluster_type: ClusterType,
    stakes: &HashMap<Pubkey, u64>,
) -> Vec<Node> {
    let self_pubkey = cluster_info.id();
    let should_dedup_addrs = match cluster_type {
        ClusterType::Development => false,
        ClusterType::Devnet | ClusterType::Testnet | ClusterType::MainnetBeta => true,
    };
    // Maps IP addresses to number of nodes at that IP address.
    let mut counts = {
        let capacity = if should_dedup_addrs { stakes.len() } else { 0 };
        HashMap::<IpAddr, usize>::with_capacity(capacity)
    };
    // The local node itself.
    std::iter::once({
        let stake = stakes.get(&self_pubkey).copied().unwrap_or_default();
        let node = NodeId::from(cluster_info.my_contact_info());
        Node { node, stake }
    })
    // All known tvu-peers from gossip.
    .chain(cluster_info.tvu_peers().into_iter().map(|node| {
        let stake = stakes.get(node.pubkey()).copied().unwrap_or_default();
        let node = NodeId::from(node);
        Node { node, stake }
    }))
    // All staked nodes.
    .chain(
        stakes
            .iter()
            .filter(|(_, stake)| **stake > 0)
            .map(|(&pubkey, &stake)| Node {
                node: NodeId::from(pubkey),
                stake,
            }),
    )
    .sorted_by_key(|node| Reverse((node.stake, node.pubkey())))
    // Since sorted_by_key is stable, in case of duplicates, this
    // will keep nodes with contact-info.
    .dedup_by(|a, b| a.pubkey() == b.pubkey())
    .filter_map(|node| {
        if !should_dedup_addrs
            || node
                .contact_info()
                .and_then(|node| node.tvu(Protocol::UDP).ok())
                .map(|addr| {
                    *counts
                        .entry(addr.ip())
                        .and_modify(|count| *count += 1)
                        .or_insert(1)
                })
                <= Some(MAX_NUM_NODES_PER_IP_ADDRESS)
        {
            Some(node)
        } else {
            // If the node is not staked, drop it entirely. Otherwise, keep the
            // pubkey for deterministic shuffle, but strip the contact-info so
            // that no more packets are sent to this node.
            (node.stake > 0u64).then(|| Node {
                node: NodeId::from(node.pubkey()),
                stake: node.stake,
            })
        }
    })
    .collect()
}

fn get_seeded_rng(leader: &Pubkey, shred: &ShredId) -> ChaChaRng {
    let seed = shred.seed(leader);
    ChaChaRng::from_seed(seed)
}

// root     : [0]
// 1st layer: [1, 2, ..., fanout]
// 2nd layer: [[fanout + 1, ..., fanout * 2],
//             [fanout * 2 + 1, ..., fanout * 3],
//             ...
//             [fanout * fanout + 1, ..., fanout * (fanout + 1)]]
// 3rd layer: ...
// ...
// The leader node broadcasts shreds to the root node.
// The root node retransmits the shreds to all nodes in the 1st layer.
// Each other node retransmits shreds to fanout many nodes in the next layer.
// For example the node k in the 1st layer will retransmit to nodes:
// fanout + k, 2*fanout + k, ..., fanout*fanout + k
fn get_retransmit_peers<T: Copy>(
    fanout: usize,
    index: usize, // Local node's index within the nodes slice.
    nodes: &[T],
) -> impl Iterator<Item = T> + '_ {
    // Node's index within its neighborhood.
    let offset = index.saturating_sub(1) % fanout;
    // First node in the neighborhood.
    let anchor = index - offset;
    let step = if index == 0 { 1 } else { fanout };
    (anchor * fanout + offset + 1..)
        .step_by(step)
        .take(fanout)
        .map(|i| nodes.get(i))
        .while_some()
        .copied()
}

// Returns the parent node in the turbine broadcast tree.
// Returns None if the node is the root of the tree.
fn get_retransmit_parent<T: Copy>(
    fanout: usize,
    index: usize, // Local node's index within the nodes slice.
    nodes: &[T],
) -> Option<T> {
    // Node's index within its neighborhood.
    let offset = index.saturating_sub(1) % fanout;
    let index = index.checked_sub(1)? / fanout;
    let index = index - index.saturating_sub(1) % fanout;
    let index = if index == 0 { index } else { index + offset };
    nodes.get(index).copied()
}

impl<T> ClusterNodesCache<T> {
    pub fn new(
        // Capacity of underlying LRU-cache in terms of number of epochs.
        cap: usize,
        // A time-to-live eviction policy is enforced to refresh entries in
        // case gossip contact-infos are updated.
        ttl: Duration,
    ) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(cap)),
            ttl,
        }
    }
}

impl<T: 'static> ClusterNodesCache<T> {
    fn get_cache_entry(&self, epoch: Epoch) -> Arc<RwLock<CacheEntry<T>>> {
        let mut cache = self.cache.lock().unwrap();
        match cache.get(&epoch) {
            Some(entry) => Arc::clone(entry),
            None => {
                let entry = Arc::default();
                cache.put(epoch, Arc::clone(&entry));
                entry
            }
        }
    }

    pub(crate) fn get(
        &self,
        shred_slot: Slot,
        root_bank: &Bank,
        working_bank: &Bank,
        cluster_info: &ClusterInfo,
    ) -> Arc<ClusterNodes<T>> {
        let epoch_schedule = root_bank.epoch_schedule();
        let epoch = epoch_schedule.get_epoch(shred_slot);
        let entry = self.get_cache_entry(epoch);
        if let Some((_, nodes)) = entry
            .read()
            .unwrap()
            .as_ref()
            .filter(|(asof, _)| asof.elapsed() < self.ttl)
        {
            return nodes.clone();
        }
        // Hold the lock on the entry here so that, if needed, only
        // one thread recomputes cluster-nodes for this epoch.
        let mut entry = entry.write().unwrap();
        if let Some((_, nodes)) = entry.as_ref().filter(|(asof, _)| asof.elapsed() < self.ttl) {
            return nodes.clone();
        }
        let epoch_staked_nodes = [root_bank, working_bank]
            .iter()
            .find_map(|bank| bank.epoch_staked_nodes(epoch));
        if epoch_staked_nodes.is_none() {
            inc_new_counter_info!("cluster_nodes-unknown_epoch_staked_nodes", 1);
            if epoch != epoch_schedule.get_epoch(root_bank.slot()) {
                return self.get(root_bank.slot(), root_bank, working_bank, cluster_info);
            }
            inc_new_counter_info!("cluster_nodes-unknown_epoch_staked_nodes_root", 1);
        }
        let nodes = Arc::new(new_cluster_nodes::<T>(
            cluster_info,
            root_bank.cluster_type(),
            &epoch_staked_nodes.unwrap_or_default(),
        ));
        *entry = Some((Instant::now(), Arc::clone(&nodes)));
        nodes
    }
}

impl From<ContactInfo> for NodeId {
    fn from(node: ContactInfo) -> Self {
        NodeId::ContactInfo(node)
    }
}

impl From<Pubkey> for NodeId {
    fn from(pubkey: Pubkey) -> Self {
        NodeId::Pubkey(pubkey)
    }
}

#[inline]
pub(crate) fn get_broadcast_protocol(_: &ShredId) -> Protocol {
    Protocol::UDP
}

pub fn make_test_cluster<R: Rng>(
    rng: &mut R,
    num_nodes: usize,
    unstaked_ratio: Option<(u32, u32)>,
) -> (
    Vec<ContactInfo>,
    HashMap<Pubkey, u64>, // stakes
    ClusterInfo,
) {
    let (unstaked_numerator, unstaked_denominator) = unstaked_ratio.unwrap_or((1, 7));
    let mut nodes: Vec<_> = repeat_with(|| {
        let pubkey = solana_sdk::pubkey::new_rand();
        ContactInfo::new_localhost(&pubkey, /*wallclock:*/ timestamp())
    })
    .take(num_nodes)
    .collect();
    nodes.shuffle(rng);
    let keypair = Arc::new(Keypair::new());
    nodes[0].set_pubkey(keypair.pubkey());
    let this_node = nodes[0].clone();
    let mut stakes: HashMap<Pubkey, u64> = nodes
        .iter()
        .filter_map(|node| {
            if rng.gen_ratio(unstaked_numerator, unstaked_denominator) {
                None // No stake for some of the nodes.
            } else {
                Some((*node.pubkey(), rng.gen_range(0..20)))
            }
        })
        .collect();
    // Add some staked nodes with no contact-info.
    stakes.extend(repeat_with(|| (Pubkey::new_unique(), rng.gen_range(0..20))).take(100));
    let cluster_info = ClusterInfo::new(this_node, keypair, SocketAddrSpace::Unspecified);
    {
        let now = timestamp();
        let mut gossip_crds = cluster_info.gossip.crds.write().unwrap();
        // First node is pushed to crds table by ClusterInfo constructor.
        for node in nodes.iter().skip(1) {
            let node = CrdsData::ContactInfo(node.clone());
            let node = CrdsValue::new_unsigned(node);
            assert_eq!(
                gossip_crds.insert(node, now, GossipRoute::LocalMessage),
                Ok(())
            );
        }
    }
    (nodes, stakes, cluster_info)
}

pub(crate) fn get_data_plane_fanout(shred_slot: Slot, root_bank: &Bank) -> usize {
    if enable_turbine_fanout_experiments(shred_slot, root_bank) {
        // Allocate ~2% of slots to turbine fanout experiments.
        match shred_slot % 359 {
            11 => 64,
            61 => 768,
            111 => 128,
            161 => 640,
            211 => 256,
            261 => 512,
            311 => 384,
            _ => DATA_PLANE_FANOUT,
        }
    } else {
        DATA_PLANE_FANOUT
    }
}

fn enable_turbine_fanout_experiments(shred_slot: Slot, root_bank: &Bank) -> bool {
    check_feature_activation(
        &feature_set::enable_turbine_fanout_experiments::id(),
        shred_slot,
        root_bank,
    ) && !check_feature_activation(
        &feature_set::disable_turbine_fanout_experiments::id(),
        shred_slot,
        root_bank,
    )
}

// Returns true if the feature is effective for the shred slot.
#[must_use]
pub fn check_feature_activation(feature: &Pubkey, shred_slot: Slot, root_bank: &Bank) -> bool {
    match root_bank.feature_set.activated_slot(feature) {
        None => false,
        Some(feature_slot) => {
            let epoch_schedule = root_bank.epoch_schedule();
            let feature_epoch = epoch_schedule.get_epoch(feature_slot);
            let shred_epoch = epoch_schedule.get_epoch(shred_slot);
            feature_epoch < shred_epoch
        }
    }
}
