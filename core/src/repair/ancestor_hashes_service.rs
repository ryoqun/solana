use {
    crate::{
        cluster_slots_service::cluster_slots::ClusterSlots,
        repair::{
            duplicate_repair_status::{
                AncestorRequestDecision, AncestorRequestStatus, AncestorRequestType,
            },
            outstanding_requests::OutstandingRequests,
            packet_threshold::DynamicPacketToProcessThreshold,
            quic_endpoint::LocalRequest,
            repair_service::{AncestorDuplicateSlotsSender, RepairInfo, RepairStatsGroup},
            request_response::RequestResponse,
            serve_repair::{
                self, AncestorHashesRepairType, AncestorHashesResponse, RepairProtocol, ServeRepair,
            },
        },
        replay_stage::DUPLICATE_THRESHOLD,
        shred_fetch_stage::receive_repair_quic_packets,
    },
    bincode::serialize,
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender},
    dashmap::{mapref::entry::Entry::Occupied, DashMap},
    solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol, ping_pong::Pong},
    solana_ledger::blockstore::Blockstore,
    solana_perf::{
        packet::{deserialize_from_with_limit, Packet, PacketBatch},
        recycler::Recycler,
    },
    solana_runtime::bank::Bank,
    solana_sdk::{
        clock::{Slot, DEFAULT_MS_PER_SLOT},
        genesis_config::ClusterType,
        pubkey::Pubkey,
        signature::Signable,
        signer::keypair::Keypair,
        timing::timestamp,
    },
    solana_streamer::streamer::{self, PacketBatchReceiver, StreamerReceiveStats},
    std::{
        collections::HashSet,
        io::{Cursor, Read},
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, sleep, Builder, JoinHandle},
        time::{Duration, Instant},
    },
    tokio::sync::mpsc::Sender as AsyncSender,
};

#[derive(Debug, PartialEq, Eq)]
pub enum AncestorHashesReplayUpdate {
    Dead(Slot),
    DeadDuplicateConfirmed(Slot),
    // `Slot` belongs to a fork we have pruned. We have observed that this fork is "popular" aka
    // reached 52+% stake through votes in turbine/gossip including votes for descendants. These
    // votes are hash agnostic since we have not replayed `Slot` so we can never say for certainty
    // that this fork has reached duplicate confirmation, but it is suspected to have. This
    // indicates that there is most likely a block with invalid ancestry present and thus we
    // collect an ancestor sample to resolve this issue. `Slot` is the deepest slot in this fork
    // that is popular, so any duplicate problems will be for `Slot` or one of it's ancestors.
    PopularPrunedFork(Slot),
}

impl AncestorHashesReplayUpdate {
    fn slot(&self) -> Slot {
        match self {
            AncestorHashesReplayUpdate::Dead(slot) => *slot,
            AncestorHashesReplayUpdate::DeadDuplicateConfirmed(slot) => *slot,
            AncestorHashesReplayUpdate::PopularPrunedFork(slot) => *slot,
        }
    }
}

pub const MAX_ANCESTOR_HASHES_SLOT_REQUESTS_PER_SECOND: usize = 2;

pub type AncestorHashesReplayUpdateSender = Sender<AncestorHashesReplayUpdate>;
pub type AncestorHashesReplayUpdateReceiver = Receiver<AncestorHashesReplayUpdate>;

type RetryableSlotsSender = Sender<(Slot, AncestorRequestType)>;
type RetryableSlotsReceiver = Receiver<(Slot, AncestorRequestType)>;
type OutstandingAncestorHashesRepairs = OutstandingRequests<AncestorHashesRepairType>;

#[derive(Default)]
struct AncestorHashesResponsesStats {
    total_packets: usize,
    processed: usize,
    dropped_packets: usize,
    invalid_packets: usize,
    ping_count: usize,
    ping_err_verify_count: usize,
}

impl AncestorHashesResponsesStats {
    fn report(&mut self) {
        datapoint_info!(
            "ancestor_hashes_responses",
            ("total_packets", self.total_packets, i64),
            ("processed", self.processed, i64),
            ("dropped_packets", self.dropped_packets, i64),
            ("invalid_packets", self.invalid_packets, i64),
            ("ping_count", self.ping_count, i64),
            ("ping_err_verify_count", self.ping_err_verify_count, i64),
        );
        *self = AncestorHashesResponsesStats::default();
    }
}

pub struct AncestorRepairRequestsStats {
    pub ancestor_requests: RepairStatsGroup,
    last_report: Instant,
}

impl Default for AncestorRepairRequestsStats {
    fn default() -> Self {
        AncestorRepairRequestsStats {
            ancestor_requests: RepairStatsGroup::default(),
            last_report: Instant::now(),
        }
    }
}

impl AncestorRepairRequestsStats {
    fn report(&mut self) {
        let slot_to_count: Vec<_> = self
            .ancestor_requests
            .slot_pubkeys
            .iter()
            .map(|(slot, slot_repairs)| (slot, slot_repairs.pubkey_repairs().values().sum::<u64>()))
            .collect();

        let repair_total = self.ancestor_requests.count;
        if self.last_report.elapsed().as_secs() > 2 && repair_total > 0 {
            info!("ancestor_repair_requests_stats: {:?}", slot_to_count);
            datapoint_info!(
                "ancestor-repair",
                ("ancestor-repair-count", self.ancestor_requests.count, i64)
            );

            *self = AncestorRepairRequestsStats::default();
        }
    }
}

pub struct AncestorHashesService {
    thread_hdls: Vec<JoinHandle<()>>,
}

impl AncestorHashesService {
    pub fn new(
        exit: Arc<AtomicBool>,
        blockstore: Arc<Blockstore>,
        ancestor_hashes_request_socket: Arc<UdpSocket>,
        quic_endpoint_sender: AsyncSender<LocalRequest>,
        repair_info: RepairInfo,
        ancestor_hashes_replay_update_receiver: AncestorHashesReplayUpdateReceiver,
    ) -> Self {
        let outstanding_requests = Arc::<RwLock<OutstandingAncestorHashesRepairs>>::default();
        let (response_sender, response_receiver) = unbounded();
        let t_receiver = streamer::receiver(
            "solRcvrAncHash".to_string(),
            ancestor_hashes_request_socket.clone(),
            exit.clone(),
            response_sender.clone(),
            Recycler::default(),
            Arc::new(StreamerReceiveStats::new(
                "ancestor_hashes_response_receiver",
            )),
            Duration::from_millis(1), // coalesce
            false,                    // use_pinned_memory
            None,                     // in_vote_only_mode
            false,                    //  is_staked_service
        );

        let (quic_endpoint_response_sender, quic_endpoint_response_receiver) = unbounded();
        let t_receiver_quic = {
            let exit = exit.clone();
            Builder::new()
                .name(String::from("solAncHashQuic"))
                .spawn(|| {
                    receive_repair_quic_packets(
                        quic_endpoint_response_receiver,
                        response_sender,
                        Recycler::default(),
                        exit,
                    )
                })
                .unwrap()
        };
        let ancestor_hashes_request_statuses: Arc<DashMap<Slot, AncestorRequestStatus>> =
            Arc::new(DashMap::new());
        let (retryable_slots_sender, retryable_slots_receiver) = unbounded();

        // Listen for responses to our ancestor requests
        let t_ancestor_hashes_responses = Self::run_responses_listener(
            ancestor_hashes_request_statuses.clone(),
            response_receiver,
            blockstore,
            outstanding_requests.clone(),
            exit.clone(),
            repair_info.ancestor_duplicate_slots_sender.clone(),
            retryable_slots_sender,
            repair_info.cluster_info.clone(),
            ancestor_hashes_request_socket.clone(),
        );

        // Generate ancestor requests for dead slots that are repairable
        let t_ancestor_requests = Self::run_manage_ancestor_requests(
            ancestor_hashes_request_statuses,
            ancestor_hashes_request_socket,
            quic_endpoint_sender,
            quic_endpoint_response_sender,
            repair_info,
            outstanding_requests,
            exit,
            ancestor_hashes_replay_update_receiver,
            retryable_slots_receiver,
        );
        Self {
            thread_hdls: vec![
                t_receiver,
                t_receiver_quic,
                t_ancestor_hashes_responses,
                t_ancestor_requests,
            ],
        }
    }

    pub(crate) fn join(self) -> thread::Result<()> {
        self.thread_hdls.into_iter().try_for_each(JoinHandle::join)
    }

    /// Listen for responses to our ancestors hashes repair requests
    fn run_responses_listener(
        ancestor_hashes_request_statuses: Arc<DashMap<Slot, AncestorRequestStatus>>,
        response_receiver: PacketBatchReceiver,
        blockstore: Arc<Blockstore>,
        outstanding_requests: Arc<RwLock<OutstandingAncestorHashesRepairs>>,
        exit: Arc<AtomicBool>,
        ancestor_duplicate_slots_sender: AncestorDuplicateSlotsSender,
        retryable_slots_sender: RetryableSlotsSender,
        cluster_info: Arc<ClusterInfo>,
        ancestor_socket: Arc<UdpSocket>,
    ) -> JoinHandle<()> {
        Builder::new()
            .name("solAncHashesSvc".to_string())
            .spawn(move || {
                let mut last_stats_report = Instant::now();
                let mut stats = AncestorHashesResponsesStats::default();
                let mut packet_threshold = DynamicPacketToProcessThreshold::default();
                while !exit.load(Ordering::Relaxed) {
                    let keypair = cluster_info.keypair().clone();
                    let result = Self::process_new_packets_from_channel(
                        &ancestor_hashes_request_statuses,
                        &response_receiver,
                        &blockstore,
                        &outstanding_requests,
                        &mut stats,
                        &mut packet_threshold,
                        &ancestor_duplicate_slots_sender,
                        &retryable_slots_sender,
                        &keypair,
                        &ancestor_socket,
                    );
                    match result {
                        Ok(_) | Err(RecvTimeoutError::Timeout) => (),
                        Err(RecvTimeoutError::Disconnected) => {
                            info!("ancestors hashes responses listener disconnected");
                            return;
                        }
                    };
                    if last_stats_report.elapsed().as_secs() > 2 {
                        stats.report();
                        last_stats_report = Instant::now();
                    }
                }
            })
            .unwrap()
    }

    /// Process messages from the network
    #[allow(clippy::too_many_arguments)]
    fn process_new_packets_from_channel(
        ancestor_hashes_request_statuses: &DashMap<Slot, AncestorRequestStatus>,
        response_receiver: &PacketBatchReceiver,
        blockstore: &Blockstore,
        outstanding_requests: &RwLock<OutstandingAncestorHashesRepairs>,
        stats: &mut AncestorHashesResponsesStats,
        packet_threshold: &mut DynamicPacketToProcessThreshold,
        ancestor_duplicate_slots_sender: &AncestorDuplicateSlotsSender,
        retryable_slots_sender: &RetryableSlotsSender,
        keypair: &Keypair,
        ancestor_socket: &UdpSocket,
    ) -> Result<(), RecvTimeoutError> {
        let timeout = Duration::new(1, 0);
        let mut packet_batches = vec![response_receiver.recv_timeout(timeout)?];
        let mut total_packets = packet_batches[0].len();

        let mut dropped_packets = 0;
        while let Ok(batch) = response_receiver.try_recv() {
            total_packets += batch.len();
            if packet_threshold.should_drop(total_packets) {
                dropped_packets += batch.len();
            } else {
                packet_batches.push(batch);
            }
        }

        stats.dropped_packets += dropped_packets;
        stats.total_packets += total_packets;

        let timer = Instant::now();
        for packet_batch in packet_batches {
            Self::process_packet_batch(
                ancestor_hashes_request_statuses,
                packet_batch,
                stats,
                outstanding_requests,
                blockstore,
                ancestor_duplicate_slots_sender,
                retryable_slots_sender,
                keypair,
                ancestor_socket,
            );
        }
        packet_threshold.update(total_packets, timer.elapsed());
        Ok(())
    }

    fn process_packet_batch(
        ancestor_hashes_request_statuses: &DashMap<Slot, AncestorRequestStatus>,
        packet_batch: PacketBatch,
        stats: &mut AncestorHashesResponsesStats,
        outstanding_requests: &RwLock<OutstandingAncestorHashesRepairs>,
        blockstore: &Blockstore,
        ancestor_duplicate_slots_sender: &AncestorDuplicateSlotsSender,
        retryable_slots_sender: &RetryableSlotsSender,
        keypair: &Keypair,
        ancestor_socket: &UdpSocket,
    ) {
        packet_batch.iter().for_each(|packet| {
            let ancestor_request_decision = Self::verify_and_process_ancestor_response(
                packet,
                ancestor_hashes_request_statuses,
                stats,
                outstanding_requests,
                blockstore,
                keypair,
                ancestor_socket,
            );
            if let Some(ancestor_request_decision) = ancestor_request_decision {
                Self::handle_ancestor_request_decision(
                    ancestor_request_decision,
                    ancestor_duplicate_slots_sender,
                    retryable_slots_sender,
                );
            }
        });
    }

    /// Returns `Some((request_slot, decision))`, where `decision` is an actionable
    /// result after processing sufficient responses for the subject of the query,
    /// `request_slot`
    fn verify_and_process_ancestor_response(
        packet: &Packet,
        ancestor_hashes_request_statuses: &DashMap<Slot, AncestorRequestStatus>,
        stats: &mut AncestorHashesResponsesStats,
        outstanding_requests: &RwLock<OutstandingAncestorHashesRepairs>,
        blockstore: &Blockstore,
        keypair: &Keypair,
        ancestor_socket: &UdpSocket,
    ) -> Option<AncestorRequestDecision> {
        let from_addr = packet.meta().socket_addr();
        let Some(packet_data) = packet.data(..) else {
            stats.invalid_packets += 1;
            return None;
        };
        let mut cursor = Cursor::new(packet_data);
        let Ok(response) = deserialize_from_with_limit(&mut cursor) else {
            stats.invalid_packets += 1;
            return None;
        };

        match response {
            AncestorHashesResponse::Hashes(ref hashes) => {
                // deserialize trailing nonce
                let Ok(nonce) = deserialize_from_with_limit(&mut cursor) else {
                    stats.invalid_packets += 1;
                    return None;
                };

                // verify that packet does not contain extraneous data
                if cursor.bytes().next().is_some() {
                    stats.invalid_packets += 1;
                    return None;
                }

                let request_slot = outstanding_requests.write().unwrap().register_response(
                    nonce,
                    &response,
                    timestamp(),
                    // If the response is valid, return the slot the request
                    // was for
                    |ancestor_hashes_request| ancestor_hashes_request.0,
                );

                if request_slot.is_none() {
                    stats.invalid_packets += 1;
                    return None;
                }

                // If was a valid response, there must be a valid `request_slot`
                let request_slot = request_slot.unwrap();
                stats.processed += 1;

                if let Occupied(mut ancestor_hashes_status_ref) =
                    ancestor_hashes_request_statuses.entry(request_slot)
                {
                    let decision = ancestor_hashes_status_ref.get_mut().add_response(
                        &from_addr,
                        hashes.clone(),
                        blockstore,
                    );
                    let request_type = ancestor_hashes_status_ref.get().request_type();
                    if decision.is_some() {
                        // Once a request is completed, remove it from the map so that new
                        // requests for the same slot can be made again if necessary. It's
                        // important to hold the `write` lock here via
                        // `ancestor_hashes_status_ref` so that we don't race with deletion +
                        // insertion from the `t_ancestor_requests` thread, which may
                        // 1) Remove expired statuses from `ancestor_hashes_request_statuses`
                        // 2) Insert another new one via `manage_ancestor_requests()`.
                        // In which case we wouldn't want to delete the newly inserted entry here.
                        ancestor_hashes_status_ref.remove();
                    }
                    decision.map(|decision| AncestorRequestDecision {
                        slot: request_slot,
                        decision,
                        request_type,
                    })
                } else {
                    None
                }
            }
            AncestorHashesResponse::Ping(ping) => {
                // verify that packet does not contain extraneous data
                if cursor.bytes().next().is_some() {
                    stats.invalid_packets += 1;
                    return None;
                }
                if !ping.verify() {
                    stats.ping_err_verify_count += 1;
                    return None;
                }
                stats.ping_count += 1;
                if let Ok(pong) = Pong::new(&ping, keypair) {
                    let pong = RepairProtocol::Pong(pong);
                    if let Ok(pong_bytes) = serialize(&pong) {
                        let _ignore = ancestor_socket.send_to(&pong_bytes[..], from_addr);
                    }
                }
                None
            }
        }
    }

    fn handle_ancestor_request_decision(
        ancestor_request_decision: AncestorRequestDecision,
        ancestor_duplicate_slots_sender: &AncestorDuplicateSlotsSender,
        retryable_slots_sender: &RetryableSlotsSender,
    ) {
        if ancestor_request_decision.is_retryable() {
            let _ = retryable_slots_sender.send((
                ancestor_request_decision.slot,
                ancestor_request_decision.request_type,
            ));
        }

        // TODO: In the case of DuplicateAncestorDecision::ContinueSearch
        // This means all the ancestors were mismatched, which
        // means the earliest mismatched ancestor has yet to be found.
        //
        // In the best case scenario, this means after ReplayStage dumps
        // the earliest known ancestor `A` here, and then repairs `A`,
        // because we may still have the incorrect version of some ancestor
        // of `A`, we will mark `A` as dead and then continue the search
        // protocol through another round of ancestor repairs.
        //
        // However this process is a bit slow, so in an ideal world, the
        // protocol could be extended to keep searching by making
        // another ancestor repair request from the earliest returned
        // ancestor from this search.

        let potential_slot_to_repair = ancestor_request_decision.slot_to_repair();

        // Now signal ReplayStage about the new updated slot. It's important to do this
        // AFTER we've removed the ancestor_hashes_status_ref in case replay
        // then sends us another dead slot signal based on the updates we are
        // about to send.
        if let Some(slot_to_repair) = potential_slot_to_repair {
            // Signal ReplayStage to dump the fork that is descended from
            // `earliest_mismatched_slot_to_dump`.
            let _ = ancestor_duplicate_slots_sender.send(slot_to_repair);
        }
    }

    fn process_replay_updates(
        ancestor_hashes_replay_update_receiver: &AncestorHashesReplayUpdateReceiver,
        ancestor_hashes_request_statuses: &DashMap<Slot, AncestorRequestStatus>,
        dead_slot_pool: &mut HashSet<Slot>,
        repairable_dead_slot_pool: &mut HashSet<Slot>,
        popular_pruned_slot_pool: &mut HashSet<Slot>,
        root_slot: Slot,
    ) {
        for update in ancestor_hashes_replay_update_receiver.try_iter() {
            let slot = update.slot();
            if slot <= root_slot || ancestor_hashes_request_statuses.contains_key(&slot) {
                return;
            }
            match update {
                AncestorHashesReplayUpdate::Dead(dead_slot) => {
                    if repairable_dead_slot_pool.contains(&dead_slot) {
                        return;
                    } else if popular_pruned_slot_pool.contains(&dead_slot) {
                        // If `dead_slot` is also part of a popular pruned fork, this implies that the slot has
                        // become `EpochSlotsFrozen` as 52% had to have frozen some version of this slot in order
                        // to vote on it / it's descendants as observed in `repair_weight`.
                        // This fits the alternate criteria we use in `find_epoch_slots_frozen_dead_slots`
                        // so we can upgrade it to `repairable_dead_slot_pool`.
                        popular_pruned_slot_pool.remove(&dead_slot);
                        repairable_dead_slot_pool.insert(dead_slot);
                    } else {
                        dead_slot_pool.insert(dead_slot);
                    }
                }
                AncestorHashesReplayUpdate::DeadDuplicateConfirmed(dead_slot) => {
                    // If this slot was previously queued as a popular pruned slot, prefer to
                    // instead process it as dead duplicate confirmed.
                    // In general we prefer to use the dead duplicate confirmed pathway
                    // whenever possible as it allows us to compare frozen hashes of ancestors with
                    // the cluster rather than just comparing ancestry links.
                    popular_pruned_slot_pool.remove(&dead_slot);

                    dead_slot_pool.remove(&dead_slot);
                    repairable_dead_slot_pool.insert(dead_slot);
                }
                AncestorHashesReplayUpdate::PopularPrunedFork(pruned_slot) => {
                    // The `dead_slot_pool` or `repairable_dead_slot_pool` can already contain this slot already
                    // if the below order of events happens:
                    //
                    // 1. Slot is marked dead/duplicate confirmed
                    // 2. Slot is pruned
                    if dead_slot_pool.contains(&pruned_slot) {
                        // Similar to the above case where `pruned_slot` was first pruned and then marked
                        // dead, since `pruned_slot` is part of a popular pruned fork it has become
                        // `EpochSlotsFrozen` as 52% must have frozen a version of this slot in
                        // order to vote.
                        // This fits the alternate criteria we use in `find_epoch_slots_frozen_dead_slots`
                        // so we can upgrade it to `repairable_dead_slot_pool`.
                        info!("{pruned_slot} is part of a popular pruned fork however we previously marked it as dead.
                            Upgrading as dead duplicate confirmed");
                        dead_slot_pool.remove(&pruned_slot);
                        repairable_dead_slot_pool.insert(pruned_slot);
                    } else if repairable_dead_slot_pool.contains(&pruned_slot) {
                        // If we already observed `pruned_slot` as dead duplicate confirmed, we
                        // ignore the additional information that `pruned_slot` is popular pruned.
                        // This is similar to the above case where `pruned_slot` was first pruned
                        // and then marked dead duplicate confirmed.
                        info!("Received pruned duplicate confirmed status for {pruned_slot} that was previously marked
                            dead duplicate confirmed. Ignoring and processing it as dead duplicate confirmed.");
                    } else {
                        popular_pruned_slot_pool.insert(pruned_slot);
                    }
                }
            }
        }
    }

    fn run_manage_ancestor_requests(
        ancestor_hashes_request_statuses: Arc<DashMap<Slot, AncestorRequestStatus>>,
        ancestor_hashes_request_socket: Arc<UdpSocket>,
        quic_endpoint_sender: AsyncSender<LocalRequest>,
        quic_endpoint_response_sender: Sender<(SocketAddr, Vec<u8>)>,
        repair_info: RepairInfo,
        outstanding_requests: Arc<RwLock<OutstandingAncestorHashesRepairs>>,
        exit: Arc<AtomicBool>,
        ancestor_hashes_replay_update_receiver: AncestorHashesReplayUpdateReceiver,
        retryable_slots_receiver: RetryableSlotsReceiver,
    ) -> JoinHandle<()> {
        let serve_repair = ServeRepair::new(
            repair_info.cluster_info.clone(),
            repair_info.bank_forks.clone(),
            repair_info.repair_whitelist.clone(),
        );
        let mut repair_stats = AncestorRepairRequestsStats::default();

        let mut dead_slot_pool = HashSet::new();
        let mut repairable_dead_slot_pool = HashSet::new();
        // We keep a separate pool for slots that are part of popular pruned forks, (reached 52+%
        // in repair weight). Since these slots are pruned, we most likely do not have frozen
        // hashes for the ancestors. Because of this we process responses differently, using only
        // slot number to find the missing/invalid ancestor to dump & repair.
        //
        // However if slots are pruned and also dead/dead duplicate confirmed we give extra priority
        // to the dead pathway, preferring to add the slot to `repairable_dead_slot_pool` instead. This is
        // because if the slot is dead we must have been able to replay the ancestor. If the ancestors
        // have frozen hashes we should compare hashes instead of raw ancestry as hashes give more information
        // in finding missing/invalid ancestors.
        let mut popular_pruned_slot_pool = HashSet::new();

        // Sliding window that limits the number of slots repaired via AncestorRepair
        // to MAX_ANCESTOR_HASHES_SLOT_REQUESTS_PER_SECOND/second
        let mut request_throttle = vec![];
        Builder::new()
            .name("solManAncReqs".to_string())
            .spawn(move || loop {
                if exit.load(Ordering::Relaxed) {
                    return;
                }
                Self::manage_ancestor_requests(
                    &ancestor_hashes_request_statuses,
                    &ancestor_hashes_request_socket,
                    &quic_endpoint_sender,
                    &quic_endpoint_response_sender,
                    &repair_info,
                    &outstanding_requests,
                    &ancestor_hashes_replay_update_receiver,
                    &retryable_slots_receiver,
                    &serve_repair,
                    &mut repair_stats,
                    &mut dead_slot_pool,
                    &mut repairable_dead_slot_pool,
                    &mut popular_pruned_slot_pool,
                    &mut request_throttle,
                );

                sleep(Duration::from_millis(DEFAULT_MS_PER_SLOT));
            })
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn manage_ancestor_requests(
        ancestor_hashes_request_statuses: &DashMap<Slot, AncestorRequestStatus>,
        ancestor_hashes_request_socket: &UdpSocket,
        quic_endpoint_sender: &AsyncSender<LocalRequest>,
        quic_endpoint_response_sender: &Sender<(SocketAddr, Vec<u8>)>,
        repair_info: &RepairInfo,
        outstanding_requests: &RwLock<OutstandingAncestorHashesRepairs>,
        ancestor_hashes_replay_update_receiver: &AncestorHashesReplayUpdateReceiver,
        retryable_slots_receiver: &RetryableSlotsReceiver,
        serve_repair: &ServeRepair,
        repair_stats: &mut AncestorRepairRequestsStats,
        dead_slot_pool: &mut HashSet<Slot>,
        repairable_dead_slot_pool: &mut HashSet<Slot>,
        popular_pruned_slot_pool: &mut HashSet<Slot>,
        request_throttle: &mut Vec<u64>,
    ) {
        let root_bank = repair_info.bank_forks.read().unwrap().root_bank();
        let cluster_type = root_bank.cluster_type();
        for (slot, request_type) in retryable_slots_receiver.try_iter() {
            datapoint_info!("ancestor-repair-retry", ("slot", slot, i64));
            if request_type.is_pruned() {
                popular_pruned_slot_pool.insert(slot);
            } else {
                repairable_dead_slot_pool.insert(slot);
            }
        }

        Self::process_replay_updates(
            ancestor_hashes_replay_update_receiver,
            ancestor_hashes_request_statuses,
            dead_slot_pool,
            repairable_dead_slot_pool,
            popular_pruned_slot_pool,
            root_bank.slot(),
        );

        Self::find_epoch_slots_frozen_dead_slots(
            &repair_info.cluster_slots,
            dead_slot_pool,
            repairable_dead_slot_pool,
            &root_bank,
        );

        dead_slot_pool.retain(|slot| *slot > root_bank.slot());
        repairable_dead_slot_pool.retain(|slot| *slot > root_bank.slot());
        popular_pruned_slot_pool.retain(|slot| *slot > root_bank.slot());

        ancestor_hashes_request_statuses.retain(|slot, status| {
            if *slot <= root_bank.slot() {
                false
            } else if status.is_expired() {
                // Add the slot back to the correct pool to retry
                if status.request_type().is_pruned() {
                    popular_pruned_slot_pool.insert(*slot);
                } else {
                    repairable_dead_slot_pool.insert(*slot);
                }
                false
            } else {
                true
            }
        });

        // Keep around the last second of requests in the throttler.
        request_throttle.retain(|request_time| *request_time > (timestamp() - 1000));

        let identity_keypair: &Keypair = &repair_info.cluster_info.keypair().clone();

        let number_of_allowed_requests =
            MAX_ANCESTOR_HASHES_SLOT_REQUESTS_PER_SECOND.saturating_sub(request_throttle.len());

        // Find dead and pruned slots for which it's worthwhile to ask the network for their
        // ancestors, prioritizing dead slots first.
        let potential_slot_requests = repairable_dead_slot_pool
            .iter()
            .copied()
            .zip(std::iter::repeat(
                AncestorRequestType::DeadDuplicateConfirmed,
            ))
            .chain(
                popular_pruned_slot_pool
                    .iter()
                    .copied()
                    .zip(std::iter::repeat(AncestorRequestType::PopularPruned)),
            )
            .collect::<Vec<_>>()
            .into_iter();

        for (slot, request_type) in potential_slot_requests.take(number_of_allowed_requests) {
            warn!(
                "Cluster froze slot: {}, but we marked it as {}.
                 Initiating protocol to sample cluster for dead slot ancestors.",
                slot,
                if request_type.is_pruned() {
                    "pruned"
                } else {
                    "dead"
                },
            );

            if Self::initiate_ancestor_hashes_requests_for_duplicate_slot(
                ancestor_hashes_request_statuses,
                ancestor_hashes_request_socket,
                quic_endpoint_sender,
                quic_endpoint_response_sender,
                &repair_info.cluster_slots,
                serve_repair,
                &repair_info.repair_validators,
                slot,
                repair_stats,
                outstanding_requests,
                identity_keypair,
                request_type,
                cluster_type,
            ) {
                request_throttle.push(timestamp());
                if request_type.is_pruned() {
                    popular_pruned_slot_pool.take(&slot).unwrap();
                } else {
                    repairable_dead_slot_pool.take(&slot).unwrap();
                }
            }
        }
        repair_stats.report();
    }

    /// Find if any dead slots in `dead_slot_pool` have been frozen by sufficient
    /// number of nodes in the cluster to justify adding to the `repairable_dead_slot_pool`.
    fn find_epoch_slots_frozen_dead_slots(
        cluster_slots: &ClusterSlots,
        dead_slot_pool: &mut HashSet<Slot>,
        repairable_dead_slot_pool: &mut HashSet<Slot>,
        root_bank: &Bank,
    ) {
        dead_slot_pool.retain(|dead_slot| {
            let epoch = root_bank.get_epoch_and_slot_index(*dead_slot).0;
            if let Some(epoch_stakes) = root_bank.epoch_stakes(epoch) {
                let status = cluster_slots.lookup(*dead_slot);
                if let Some(completed_dead_slot_pubkeys) = status {
                    let total_stake = epoch_stakes.total_stake();
                    let node_id_to_vote_accounts = epoch_stakes.node_id_to_vote_accounts();
                    let total_completed_slot_stake: u64 = completed_dead_slot_pubkeys
                        .read()
                        .unwrap()
                        .iter()
                        .map(|(node_key, _)| {
                            node_id_to_vote_accounts
                                .get(node_key)
                                .map(|v| v.total_stake)
                                .unwrap_or(0)
                        })
                        .sum();
                    // If sufficient number of validators froze this slot, then there's a chance
                    // this dead slot was duplicate confirmed and will make it into in the main fork.
                    // This means it's worth asking the cluster to get the correct version.
                    if total_completed_slot_stake as f64 / total_stake as f64 > DUPLICATE_THRESHOLD
                    {
                        repairable_dead_slot_pool.insert(*dead_slot);
                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            } else {
                warn!(
                    "Dead slot {} is too far ahead of root bank {}",
                    dead_slot,
                    root_bank.slot()
                );
                false
            }
        })
    }

    /// Returns true if a request was successfully made and the status
    /// added to `ancestor_hashes_request_statuses`
    #[allow(clippy::too_many_arguments)]
    fn initiate_ancestor_hashes_requests_for_duplicate_slot(
        ancestor_hashes_request_statuses: &DashMap<Slot, AncestorRequestStatus>,
        ancestor_hashes_request_socket: &UdpSocket,
        quic_endpoint_sender: &AsyncSender<LocalRequest>,
        quic_endpoint_response_sender: &Sender<(SocketAddr, Vec<u8>)>,
        cluster_slots: &ClusterSlots,
        serve_repair: &ServeRepair,
        repair_validators: &Option<HashSet<Pubkey>>,
        duplicate_slot: Slot,
        repair_stats: &mut AncestorRepairRequestsStats,
        outstanding_requests: &RwLock<OutstandingAncestorHashesRepairs>,
        identity_keypair: &Keypair,
        request_type: AncestorRequestType,
        cluster_type: ClusterType,
    ) -> bool {
        let repair_protocol = serve_repair::get_repair_protocol(cluster_type);
        let Ok(sampled_validators) = serve_repair.repair_request_ancestor_hashes_sample_peers(
            duplicate_slot,
            cluster_slots,
            repair_validators,
            repair_protocol,
        ) else {
            return false;
        };

        for (pubkey, socket_addr) in &sampled_validators {
            repair_stats
                .ancestor_requests
                .update(pubkey, duplicate_slot, 0);
            let ancestor_hashes_repair_type = AncestorHashesRepairType(duplicate_slot);
            let nonce = outstanding_requests
                .write()
                .unwrap()
                .add_request(ancestor_hashes_repair_type, timestamp());
            let Ok(request_bytes) = serve_repair.ancestor_repair_request_bytes(
                identity_keypair,
                pubkey,
                duplicate_slot,
                nonce,
            ) else {
                continue;
            };
            match repair_protocol {
                Protocol::UDP => {
                    let _ = ancestor_hashes_request_socket.send_to(&request_bytes, socket_addr);
                }
                Protocol::QUIC => {
                    let num_expected_responses =
                        usize::try_from(ancestor_hashes_repair_type.num_expected_responses())
                            .unwrap();
                    let request = LocalRequest {
                        remote_address: *socket_addr,
                        bytes: request_bytes,
                        num_expected_responses,
                        response_sender: quic_endpoint_response_sender.clone(),
                    };
                    if quic_endpoint_sender.blocking_send(request).is_err() {
                        // The receiver end of the channel is disconnected.
                        break;
                    }
                }
            }
        }

        let ancestor_request_status = AncestorRequestStatus::new(
            sampled_validators
                .into_iter()
                .map(|(_pk, socket_addr)| socket_addr),
            duplicate_slot,
            request_type,
        );
        assert!(ancestor_hashes_request_statuses
            .insert(duplicate_slot, ancestor_request_status)
            .is_none());
        true
    }
}
