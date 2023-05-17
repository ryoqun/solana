use {
    solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol},
    solana_poh::poh_recorder::PohRecorder,
    solana_sdk::{clock::NUM_CONSECUTIVE_LEADER_SLOTS, pubkey::Pubkey},
    solana_send_transaction_service::tpu_info::TpuInfo,
    std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, RwLock},
    },
};

#[derive(Clone)]
pub struct ClusterTpuInfo {
    cluster_info: Arc<ClusterInfo>,
    poh_recorder: Arc<RwLock<PohRecorder>>,
    recent_peers: HashMap<Pubkey, SocketAddr>,
}

impl ClusterTpuInfo {
    pub fn new(cluster_info: Arc<ClusterInfo>, poh_recorder: Arc<RwLock<PohRecorder>>) -> Self {
        Self {
            cluster_info,
            poh_recorder,
            recent_peers: HashMap::new(),
        }
    }
}

impl TpuInfo for ClusterTpuInfo {
    fn refresh_recent_peers(&mut self) {
        self.recent_peers = self
            .cluster_info
            .tpu_peers()
            .into_iter()
            .filter_map(|node| Some((*node.pubkey(), node.tpu(Protocol::UDP).ok()?)))
            .collect();
    }

    fn get_leader_tpus(&self, max_count: u64) -> Vec<&SocketAddr> {
        let recorder = self.poh_recorder.read().unwrap();
        let leaders: Vec<_> = (0..max_count)
            .filter_map(|i| recorder.leader_after_n_slots(i * NUM_CONSECUTIVE_LEADER_SLOTS))
            .collect();
        drop(recorder);
        let mut unique_leaders = vec![];
        for leader in leaders.iter() {
            if let Some(addr) = self.recent_peers.get(leader) {
                if !unique_leaders.contains(&addr) {
                    unique_leaders.push(addr);
                }
            }
        }
        unique_leaders
    }
}
