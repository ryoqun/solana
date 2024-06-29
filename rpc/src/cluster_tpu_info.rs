use {
    solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol},
    solana_poh::poh_recorder::PohRecorder,
    solana_sdk::{
        clock::{Slot, NUM_CONSECUTIVE_LEADER_SLOTS},
        pubkey::Pubkey,
    },
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
    recent_peers: HashMap<Pubkey, (SocketAddr, SocketAddr)>, // values are socket address for UDP and QUIC protocols
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
            .filter_map(|node| {
                Some((
                    *node.pubkey(),
                    (
                        node.tpu(Protocol::UDP).ok()?,
                        node.tpu(Protocol::QUIC).ok()?,
                    ),
                ))
            })
            .collect();
    }

    fn get_leader_tpus(&self, max_count: u64, protocol: Protocol) -> Vec<&SocketAddr> {
        let recorder = self.poh_recorder.read().unwrap();
        let leaders: Vec<_> = (0..max_count)
            .filter_map(|i| recorder.leader_after_n_slots(i * NUM_CONSECUTIVE_LEADER_SLOTS))
            .collect();
        drop(recorder);
        let mut unique_leaders = vec![];
        for leader in leaders.iter() {
            if let Some(addr) = self.recent_peers.get(leader).map(|addr| match protocol {
                Protocol::UDP => &addr.0,
                Protocol::QUIC => &addr.1,
            }) {
                if !unique_leaders.contains(&addr) {
                    unique_leaders.push(addr);
                }
            }
        }
        unique_leaders
    }

    fn get_leader_tpus_with_slots(
        &self,
        max_count: u64,
        protocol: Protocol,
    ) -> Vec<(&SocketAddr, Slot)> {
        let recorder = self.poh_recorder.read().unwrap();
        let leaders: Vec<_> = (0..max_count)
            .filter_map(|future_slot| {
                let future_slot = max_count.wrapping_sub(future_slot);
                NUM_CONSECUTIVE_LEADER_SLOTS
                    .checked_mul(future_slot)
                    .and_then(|slots_in_the_future| {
                        recorder.leader_and_slot_after_n_slots(slots_in_the_future)
                    })
            })
            .collect();
        drop(recorder);
        let addrs_to_slots = leaders
            .into_iter()
            .filter_map(|(leader_id, leader_slot)| {
                self.recent_peers
                    .get(&leader_id)
                    .map(|(udp_tpu, quic_tpu)| match protocol {
                        Protocol::UDP => (udp_tpu, leader_slot),
                        Protocol::QUIC => (quic_tpu, leader_slot),
                    })
            })
            .collect::<HashMap<_, _>>();
        let mut unique_leaders = Vec::from_iter(addrs_to_slots);
        unique_leaders.sort_by_key(|(_addr, slot)| *slot);
        unique_leaders
    }
}
