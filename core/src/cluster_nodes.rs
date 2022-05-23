use {
    crate::{broadcast_stage::BroadcastStage, retransmit_stage::RetransmitStage},
    itertools::Itertools,
    lru::LruCache,
    rand::SeedableRng,
    rand_chacha::ChaChaRng,
    solana_gossip::{
        cluster_info::{compute_retransmit_peers, ClusterInfo},
        contact_info::ContactInfo,
        crds_gossip_pull::CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS,
        weighted_shuffle::WeightedShuffle,
    },
    solana_ledger::shred::Shred,
    solana_runtime::bank::Bank,
    solana_sdk::{
        clock::{Epoch, Slot},
        feature_set,
        pubkey::Pubkey,
        timing::timestamp,
    },
    solana_streamer::socket::SocketAddrSpace,
    std::{
        any::TypeId,
        cmp::Reverse,
        collections::HashMap,
        iter::once,
        marker::PhantomData,
        net::SocketAddr,
        ops::Deref,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    },
};

#[allow(clippy::large_enum_variant)]
enum NodeId {
    // TVU node obtained through gossip (staked or not).
    ContactInfo(ContactInfo),
    // Staked node with no contact-info in gossip table.
    Pubkey(Pubkey),
}

struct Node {
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
    // Cache entries are wrapped in Arc<Mutex<...>>, so that, when needed, only
    // one thread does the computations to update the entry for the epoch.
    cache: Mutex<LruCache<Epoch, Arc<Mutex<CacheEntry<T>>>>>,
    ttl: Duration, // Time to live.
}

impl Node {
    #[inline]
    fn pubkey(&self) -> Pubkey {
        match &self.node {
            NodeId::Pubkey(pubkey) => *pubkey,
            NodeId::ContactInfo(node) => node.id,
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
    pub(crate) fn num_peers(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }

    // A peer is considered live if they generated their contact info recently.
    pub(crate) fn num_peers_live(&self, now: u64) -> usize {
        self.nodes
            .iter()
            .filter(|node| node.pubkey() != self.pubkey)
            .filter_map(|node| node.contact_info())
            .filter(|node| {
                let elapsed = if node.wallclock < now {
                    now - node.wallclock
                } else {
                    node.wallclock - now
                };
                elapsed < CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS
            })
            .count()
    }
}

impl ClusterNodes<BroadcastStage> {
    pub fn new(cluster_info: &ClusterInfo, stakes: &HashMap<Pubkey, u64>) -> Self {
        new_cluster_nodes(cluster_info, stakes)
    }

    pub(crate) fn get_broadcast_addrs(
        &self,
        shred: &Shred,
        root_bank: &Bank,
        fanout: usize,
        socket_addr_space: &SocketAddrSpace,
    ) -> Vec<SocketAddr> {
        const MAX_CONTACT_INFO_AGE: Duration = Duration::from_secs(2 * 60);
        let shred_seed = shred.seed(self.pubkey);
        let mut rng = ChaChaRng::from_seed(shred_seed);
        let index = match self.weighted_shuffle.first(&mut rng) {
            None => return Vec::default(),
            Some(index) => index,
        };
        if let Some(node) = self.nodes[index].contact_info() {
            let now = timestamp();
            let age = Duration::from_millis(now.saturating_sub(node.wallclock));
            if age < MAX_CONTACT_INFO_AGE
                && ContactInfo::is_valid_address(&node.tvu, socket_addr_space)
            {
                return vec![node.tvu];
            }
        }
        let mut rng = ChaChaRng::from_seed(shred_seed);
        let nodes: Vec<&Node> = self
            .weighted_shuffle
            .clone()
            .shuffle(&mut rng)
            .map(|index| &self.nodes[index])
            .collect();
        if nodes.is_empty() {
            return Vec::default();
        }
        if drop_redundant_turbine_path(shred.slot(), root_bank) {
            let peers = once(nodes[0]).chain(get_retransmit_peers(fanout, 0, &nodes));
            let addrs = peers.filter_map(Node::contact_info).map(|peer| peer.tvu);
            return addrs
                .filter(|addr| ContactInfo::is_valid_address(addr, socket_addr_space))
                .collect();
        }
        let (neighbors, children) = compute_retransmit_peers(fanout, 0, &nodes);
        neighbors[..1]
            .iter()
            .filter_map(|node| Some(node.contact_info()?.tvu))
            .chain(
                neighbors[1..]
                    .iter()
                    .filter_map(|node| Some(node.contact_info()?.tvu_forwards)),
            )
            .chain(
                children
                    .iter()
                    .filter_map(|node| Some(node.contact_info()?.tvu)),
            )
            .filter(|addr| ContactInfo::is_valid_address(addr, socket_addr_space))
            .collect()
    }
}

impl ClusterNodes<RetransmitStage> {
    pub(crate) fn get_retransmit_addrs(
        &self,
        slot_leader: Pubkey,
        shred: &Shred,
        root_bank: &Bank,
        fanout: usize,
    ) -> Vec<SocketAddr> {
        let (neighbors, children) =
            self.get_retransmit_peers(slot_leader, shred, root_bank, fanout);
        if neighbors.is_empty() {
            let peers = children.into_iter().filter_map(Node::contact_info);
            return peers.map(|peer| peer.tvu).collect();
        }
        // If the node is on the critical path (i.e. the first node in each
        // neighborhood), it should send the packet to tvu socket of its
        // children and also tvu_forward socket of its neighbors. Otherwise it
        // should only forward to tvu_forwards socket of its children.
        if neighbors[0].pubkey() != self.pubkey {
            return children
                .iter()
                .filter_map(|node| Some(node.contact_info()?.tvu_forwards))
                .collect();
        }
        // First neighbor is this node itself, so skip it.
        neighbors[1..]
            .iter()
            .filter_map(|node| Some(node.contact_info()?.tvu_forwards))
            .chain(
                children
                    .iter()
                    .filter_map(|node| Some(node.contact_info()?.tvu)),
            )
            .collect()
    }

    fn get_retransmit_peers(
        &self,
        slot_leader: Pubkey,
        shred: &Shred,
        root_bank: &Bank,
        fanout: usize,
    ) -> (
        Vec<&Node>, // neighbors
        Vec<&Node>, // children
    ) {
        let shred_seed = shred.seed(slot_leader);
        let mut weighted_shuffle = self.weighted_shuffle.clone();
        // Exclude slot leader from list of nodes.
        if slot_leader == self.pubkey {
            error!("retransmit from slot leader: {}", slot_leader);
        } else if let Some(index) = self.index.get(&slot_leader) {
            weighted_shuffle.remove_index(*index);
        };
        let mut rng = ChaChaRng::from_seed(shred_seed);
        let nodes: Vec<_> = weighted_shuffle
            .shuffle(&mut rng)
            .map(|index| &self.nodes[index])
            .collect();
        let self_index = nodes
            .iter()
            .position(|node| node.pubkey() == self.pubkey)
            .unwrap();
        if drop_redundant_turbine_path(shred.slot(), root_bank) {
            let peers = get_retransmit_peers(fanout, self_index, &nodes);
            return (Vec::default(), peers.collect());
        }
        let (neighbors, children) = compute_retransmit_peers(fanout, self_index, &nodes);
        // Assert that the node itself is included in the set of neighbors, at
        // the right offset.
        debug_assert_eq!(neighbors[self_index % fanout].pubkey(), self.pubkey);
        (neighbors, children)
    }
}

fn new_cluster_nodes<T: 'static>(
    cluster_info: &ClusterInfo,
    stakes: &HashMap<Pubkey, u64>,
) -> ClusterNodes<T> {
    let self_pubkey = cluster_info.id();
    let nodes = get_nodes(cluster_info, stakes);
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
        _phantom: PhantomData::default(),
    }
}

// All staked nodes + other known tvu-peers + the node itself;
// sorted by (stake, pubkey) in descending order.
fn get_nodes(cluster_info: &ClusterInfo, stakes: &HashMap<Pubkey, u64>) -> Vec<Node> {
    let self_pubkey = cluster_info.id();
    // The local node itself.
    std::iter::once({
        let stake = stakes.get(&self_pubkey).copied().unwrap_or_default();
        let node = NodeId::from(cluster_info.my_contact_info());
        Node { node, stake }
    })
    // All known tvu-peers from gossip.
    .chain(cluster_info.tvu_peers().into_iter().map(|node| {
        let stake = stakes.get(&node.id).copied().unwrap_or_default();
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
    .collect()
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
    index: usize, // Local node's index withing the nodes slice.
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
    fn get_cache_entry(&self, epoch: Epoch) -> Arc<Mutex<CacheEntry<T>>> {
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
        let epoch = root_bank.get_leader_schedule_epoch(shred_slot);
        let entry = self.get_cache_entry(epoch);
        // Hold the lock on the entry here so that, if needed, only
        // one thread recomputes cluster-nodes for this epoch.
        let mut entry = entry.lock().unwrap();
        if let Some((asof, nodes)) = entry.deref() {
            if asof.elapsed() < self.ttl {
                return Arc::clone(nodes);
            }
        }
        let epoch_staked_nodes = [root_bank, working_bank]
            .iter()
            .find_map(|bank| bank.epoch_staked_nodes(epoch));
        if epoch_staked_nodes.is_none() {
            inc_new_counter_info!("cluster_nodes-unknown_epoch_staked_nodes", 1);
            if epoch != root_bank.get_leader_schedule_epoch(root_bank.slot()) {
                return self.get(root_bank.slot(), root_bank, working_bank, cluster_info);
            }
            inc_new_counter_info!("cluster_nodes-unknown_epoch_staked_nodes_root", 1);
        }
        let nodes = Arc::new(new_cluster_nodes::<T>(
            cluster_info,
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

fn drop_redundant_turbine_path(shred_slot: Slot, root_bank: &Bank) -> bool {
    let feature_slot = root_bank
        .feature_set
        .activated_slot(&feature_set::drop_redundant_turbine_path::id());
    match feature_slot {
        None => false,
        Some(feature_slot) => {
            let epoch_schedule = root_bank.epoch_schedule();
            let feature_epoch = epoch_schedule.get_epoch(feature_slot);
            let shred_epoch = epoch_schedule.get_epoch(shred_slot);
            feature_epoch < shred_epoch
        }
    }
}

