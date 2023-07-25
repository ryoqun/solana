use {
    crate::{broadcast_stage::BroadcastStage, retransmit_stage::RetransmitStage},
    itertools::Itertools,
    lru::LruCache,
    rand::{seq::SliceRandom, Rng, SeedableRng},
    rand_chacha::ChaChaRng,
    solana_gossip::{
        cluster_info::{compute_retransmit_peers, ClusterInfo, DATA_PLANE_FANOUT},
        crds::GossipRoute,
        crds_gossip_pull::CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS,
        crds_value::{CrdsData, CrdsValue},
        legacy_contact_info::{LegacyContactInfo as ContactInfo, LegacyContactInfo},
        weighted_shuffle::WeightedShuffle,
    },
    solana_ledger::shred::ShredId,
    solana_runtime::bank::Bank,
    solana_sdk::{
        clock::{Epoch, Slot},
        feature_set,
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
        net::SocketAddr,
        ops::Deref,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    },
    thiserror::Error,
};

pub(crate) const MAX_NUM_TURBINE_HOPS: usize = 4;

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
    // Cache entries are wrapped in Arc<Mutex<...>>, so that, when needed, only
    // one thread does the computations to update the entry for the epoch.
    cache: Mutex<LruCache<Epoch, Arc<Mutex<CacheEntry<T>>>>>,
    ttl: Duration, // Time to live.
}

pub struct RetransmitPeers<'a> {
    root_distance: usize, // distance from the root node
    neighbors: Vec<&'a Node>,
    children: Vec<&'a Node>,
    // Maps from tvu/tvu_forwards addresses to the first node
    // in the shuffle with the same address.
    addrs: HashMap<SocketAddr, Pubkey>, // tvu addresses
    frwds: HashMap<SocketAddr, Pubkey>, // tvu_forwards addresses
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
    pub fn new(cluster_info: &ClusterInfo, stakes: &HashMap<Pubkey, u64>) -> Self {
        new_cluster_nodes(cluster_info, stakes)
    }

    pub(crate) fn get_broadcast_peer(&self, shred: &ShredId) -> Option<&ContactInfo> {
        let shred_seed = shred.seed(&self.pubkey);
        let mut rng = ChaChaRng::from_seed(shred_seed);
        let index = self.weighted_shuffle.first(&mut rng)?;
        self.nodes[index].contact_info()
    }
}

impl ClusterNodes<RetransmitStage> {
    pub(crate) fn get_retransmit_addrs(
        &self,
        slot_leader: &Pubkey,
        shred: &ShredId,
        root_bank: &Bank,
        fanout: usize,
    ) -> Result<(/*root_distance:*/ usize, Vec<SocketAddr>), Error> {
        let RetransmitPeers {
            root_distance,
            neighbors,
            children,
            addrs,
            frwds,
        } = self.get_retransmit_peers(slot_leader, shred, root_bank, fanout)?;
        if neighbors.is_empty() {
            let peers = children.into_iter().filter_map(|node| {
                node.contact_info()?
                    .tvu()
                    .ok()
                    .filter(|addr| addrs.get(addr) == Some(&node.pubkey()))
            });
            return Ok((root_distance, peers.collect()));
        }
        // If the node is on the critical path (i.e. the first node in each
        // neighborhood), it should send the packet to tvu socket of its
        // children and also tvu_forward socket of its neighbors. Otherwise it
        // should only forward to tvu_forwards socket of its children.
        if neighbors[0].pubkey() != self.pubkey {
            let peers = children.into_iter().filter_map(|node| {
                node.contact_info()?
                    .tvu_forwards()
                    .ok()
                    .filter(|addr| frwds.get(addr) == Some(&node.pubkey()))
            });
            return Ok((root_distance, peers.collect()));
        }
        // First neighbor is this node itself, so skip it.
        let peers = neighbors[1..]
            .iter()
            .filter_map(|node| {
                node.contact_info()?
                    .tvu_forwards()
                    .ok()
                    .filter(|addr| frwds.get(addr) == Some(&node.pubkey()))
            })
            .chain(children.into_iter().filter_map(|node| {
                node.contact_info()?
                    .tvu()
                    .ok()
                    .filter(|addr| addrs.get(addr) == Some(&node.pubkey()))
            }));
        Ok((root_distance, peers.collect()))
    }

    pub fn get_retransmit_peers(
        &self,
        slot_leader: &Pubkey,
        shred: &ShredId,
        root_bank: &Bank,
        fanout: usize,
    ) -> Result<RetransmitPeers, Error> {
        let shred_seed = shred.seed(slot_leader);
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
        let mut frwds = HashMap::<SocketAddr, Pubkey>::with_capacity(self.nodes.len());
        let mut rng = ChaChaRng::from_seed(shred_seed);
        let drop_redundant_turbine_path = drop_redundant_turbine_path(shred.slot(), root_bank);
        let nodes: Vec<_> = weighted_shuffle
            .shuffle(&mut rng)
            .map(|index| &self.nodes[index])
            .inspect(|node| {
                if let Some(node) = node.contact_info() {
                    if let Ok(addr) = node.tvu() {
                        addrs.entry(addr).or_insert(*node.pubkey());
                    }
                    if !drop_redundant_turbine_path {
                        if let Ok(addr) = node.tvu_forwards() {
                            frwds.entry(addr).or_insert(*node.pubkey());
                        }
                    }
                }
            })
            .collect();
        let self_index = nodes
            .iter()
            .position(|node| node.pubkey() == self.pubkey)
            .unwrap();
        if drop_redundant_turbine_path {
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
            return Ok(RetransmitPeers {
                root_distance,
                neighbors: Vec::default(),
                children: peers.collect(),
                addrs,
                frwds,
            });
        }
        let root_distance = if self_index == 0 {
            0
        } else if self_index < fanout {
            1
        } else if self_index < fanout.saturating_add(1).saturating_mul(fanout) {
            2
        } else {
            3 // If changed, update MAX_NUM_TURBINE_HOPS.
        };
        let (neighbors, children) = compute_retransmit_peers(fanout, self_index, &nodes);
        // Assert that the node itself is included in the set of neighbors, at
        // the right offset.
        debug_assert_eq!(neighbors[self_index % fanout].pubkey(), self.pubkey);
        Ok(RetransmitPeers {
            root_distance,
            neighbors,
            children,
            addrs,
            frwds,
        })
    }
}

pub fn new_cluster_nodes<T: 'static>(
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
        _phantom: PhantomData,
    }
}

// All staked nodes + other known tvu-peers + the node itself;
// sorted by (stake, pubkey) in descending order.
fn get_nodes(cluster_info: &ClusterInfo, stakes: &HashMap<Pubkey, u64>) -> Vec<Node> {
    let self_pubkey = cluster_info.id();
    // The local node itself.
    std::iter::once({
        let stake = stakes.get(&self_pubkey).copied().unwrap_or_default();
        let node = LegacyContactInfo::try_from(&cluster_info.my_contact_info())
            .map(NodeId::from)
            .expect("Operator must spin up node with valid contact-info");
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

pub fn make_test_cluster<R: Rng>(
    rng: &mut R,
    num_nodes: usize,
    unstaked_ratio: Option<(u32, u32)>,
) -> (
    Vec<ContactInfo>,
    HashMap<Pubkey, u64>, // stakes
    ClusterInfo,
) {
    use solana_gossip::contact_info::ContactInfo;
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
                Some((*node.pubkey(), rng.gen_range(0, 20)))
            }
        })
        .collect();
    // Add some staked nodes with no contact-info.
    stakes.extend(repeat_with(|| (Pubkey::new_unique(), rng.gen_range(0, 20))).take(100));
    let cluster_info = ClusterInfo::new(this_node, keypair, SocketAddrSpace::Unspecified);
    let nodes: Vec<_> = nodes
        .iter()
        .map(LegacyContactInfo::try_from)
        .collect::<Result<_, _>>()
        .unwrap();
    {
        let now = timestamp();
        let mut gossip_crds = cluster_info.gossip.crds.write().unwrap();
        // First node is pushed to crds table by ClusterInfo constructor.
        for node in nodes.iter().skip(1) {
            let node = CrdsData::LegacyContactInfo(node.clone());
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

fn drop_redundant_turbine_path(shred_slot: Slot, root_bank: &Bank) -> bool {
    check_feature_activation(
        &feature_set::drop_redundant_turbine_path::id(),
        shred_slot,
        root_bank,
    )
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
pub(crate) fn check_feature_activation(
    feature: &Pubkey,
    shred_slot: Slot,
    root_bank: &Bank,
) -> bool {
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
