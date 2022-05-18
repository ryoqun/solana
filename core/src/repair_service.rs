//! The `repair_service` module implements the tools necessary to generate a thread which
//! regularly finds missing shreds in the ledger and sends repair requests for those shreds
use {
    crate::{
        ancestor_hashes_service::{AncestorHashesReplayUpdateReceiver, AncestorHashesService},
        cluster_info_vote_listener::VerifiedVoteReceiver,
        cluster_slots::ClusterSlots,
        duplicate_repair_status::DuplicateSlotRepairStatus,
        outstanding_requests::OutstandingRequests,
        repair_weight::RepairWeight,
        result::Result,
        serve_repair::{ServeRepair, ShredRepairType, REPAIR_PEERS_CACHE_CAPACITY},
    },
    crossbeam_channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender},
    lru::LruCache,
    solana_gossip::cluster_info::ClusterInfo,
    solana_ledger::{
        blockstore::{Blockstore, SlotMeta},
        shred::Nonce,
    },
    solana_measure::measure::Measure,
    solana_runtime::{bank_forks::BankForks, contains::Contains},
    solana_sdk::{
        clock::Slot, epoch_schedule::EpochSchedule, hash::Hash, pubkey::Pubkey, timing::timestamp,
    },
    solana_streamer::sendmmsg::{batch_send, SendPktsError},
    std::{
        collections::{HashMap, HashSet},
        iter::Iterator,
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, sleep, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

pub type DuplicateSlotsResetSender = CrossbeamSender<Vec<(Slot, Hash)>>;
pub type DuplicateSlotsResetReceiver = CrossbeamReceiver<Vec<(Slot, Hash)>>;
pub type ConfirmedSlotsSender = CrossbeamSender<Vec<Slot>>;
pub type ConfirmedSlotsReceiver = CrossbeamReceiver<Vec<Slot>>;
pub type OutstandingShredRepairs = OutstandingRequests<ShredRepairType>;

#[derive(Default, Debug)]
pub struct SlotRepairs {
    highest_shred_index: u64,
    // map from pubkey to total number of requests
    pubkey_repairs: HashMap<Pubkey, u64>,
}

impl SlotRepairs {
    pub fn pubkey_repairs(&self) -> &HashMap<Pubkey, u64> {
        &self.pubkey_repairs
    }
}

#[derive(Default, Debug)]
pub struct RepairStatsGroup {
    pub count: u64,
    pub min: u64,
    pub max: u64,
    pub slot_pubkeys: HashMap<Slot, SlotRepairs>,
}

impl RepairStatsGroup {
    pub fn update(&mut self, repair_peer_id: &Pubkey, slot: Slot, shred_index: u64) {
        self.count += 1;
        let slot_repairs = self.slot_pubkeys.entry(slot).or_default();
        // Increment total number of repairs of this type for this pubkey by 1
        *slot_repairs
            .pubkey_repairs
            .entry(*repair_peer_id)
            .or_default() += 1;
        // Update the max requested shred index for this slot
        slot_repairs.highest_shred_index =
            std::cmp::max(slot_repairs.highest_shred_index, shred_index);
        self.min = std::cmp::min(self.min, slot);
        self.max = std::cmp::max(self.max, slot);
    }
}

#[derive(Default, Debug)]
pub struct RepairStats {
    pub shred: RepairStatsGroup,
    pub highest_shred: RepairStatsGroup,
    pub orphan: RepairStatsGroup,
    pub get_best_orphans_us: u64,
    pub get_best_shreds_us: u64,
}

#[derive(Default, Debug)]
pub struct RepairTiming {
    pub set_root_elapsed: u64,
    pub get_votes_elapsed: u64,
    pub add_votes_elapsed: u64,
    pub get_best_orphans_elapsed: u64,
    pub get_best_shreds_elapsed: u64,
    pub get_unknown_last_index_elapsed: u64,
    pub get_closest_completion_elapsed: u64,
    pub send_repairs_elapsed: u64,
    pub build_repairs_batch_elapsed: u64,
    pub batch_send_repairs_elapsed: u64,
}

impl RepairTiming {
    fn update(
        &mut self,
        set_root_elapsed: u64,
        get_votes_elapsed: u64,
        add_votes_elapsed: u64,
        build_repairs_batch_elapsed: u64,
        batch_send_repairs_elapsed: u64,
    ) {
        self.set_root_elapsed += set_root_elapsed;
        self.get_votes_elapsed += get_votes_elapsed;
        self.add_votes_elapsed += add_votes_elapsed;
        self.build_repairs_batch_elapsed += build_repairs_batch_elapsed;
        self.batch_send_repairs_elapsed += batch_send_repairs_elapsed;
        self.send_repairs_elapsed += build_repairs_batch_elapsed + batch_send_repairs_elapsed;
    }
}

#[derive(Default, Debug)]
pub struct BestRepairsStats {
    pub call_count: u64,
    pub num_orphan_slots: u64,
    pub num_orphan_repairs: u64,
    pub num_best_shreds_slots: u64,
    pub num_best_shreds_repairs: u64,
    pub num_unknown_last_index_slots: u64,
    pub num_unknown_last_index_repairs: u64,
    pub num_closest_completion_slots: u64,
    pub num_closest_completion_repairs: u64,
}

impl BestRepairsStats {
    pub fn update(
        &mut self,
        num_orphan_slots: u64,
        num_orphan_repairs: u64,
        num_best_shreds_slots: u64,
        num_best_shreds_repairs: u64,
        num_unknown_last_index_slots: u64,
        num_unknown_last_index_repairs: u64,
        num_closest_completion_slots: u64,
        num_closest_completion_repairs: u64,
    ) {
        self.call_count += 1;
        self.num_orphan_slots += num_orphan_slots;
        self.num_orphan_repairs += num_orphan_repairs;
        self.num_best_shreds_slots += num_best_shreds_slots;
        self.num_best_shreds_repairs += num_best_shreds_repairs;
        self.num_unknown_last_index_slots += num_unknown_last_index_slots;
        self.num_unknown_last_index_repairs += num_unknown_last_index_repairs;
        self.num_closest_completion_slots += num_closest_completion_slots;
        self.num_closest_completion_repairs += num_closest_completion_repairs;
    }
}

pub const MAX_REPAIR_LENGTH: usize = 512;
pub const MAX_REPAIR_PER_DUPLICATE: usize = 20;
pub const MAX_DUPLICATE_WAIT_MS: usize = 10_000;
pub const REPAIR_MS: u64 = 100;
pub const MAX_ORPHANS: usize = 5;
pub const MAX_UNKNOWN_LAST_INDEX_REPAIRS: usize = 10;
pub const MAX_CLOSEST_COMPLETION_REPAIRS: usize = 100;

#[derive(Clone)]
pub struct RepairInfo {
    pub bank_forks: Arc<RwLock<BankForks>>,
    pub cluster_info: Arc<ClusterInfo>,
    pub cluster_slots: Arc<ClusterSlots>,
    pub epoch_schedule: EpochSchedule,
    pub duplicate_slots_reset_sender: DuplicateSlotsResetSender,
    pub repair_validators: Option<HashSet<Pubkey>>,
}

pub struct RepairSlotRange {
    pub start: Slot,
    pub end: Slot,
}

impl Default for RepairSlotRange {
    fn default() -> Self {
        RepairSlotRange {
            start: 0,
            end: std::u64::MAX,
        }
    }
}

pub struct RepairService {
    t_repair: JoinHandle<()>,
    ancestor_hashes_service: AncestorHashesService,
}

impl RepairService {
    pub fn new(
        blockstore: Arc<Blockstore>,
        exit: Arc<AtomicBool>,
        repair_socket: Arc<UdpSocket>,
        ancestor_hashes_socket: Arc<UdpSocket>,
        repair_info: RepairInfo,
        verified_vote_receiver: VerifiedVoteReceiver,
        outstanding_requests: Arc<RwLock<OutstandingShredRepairs>>,
        ancestor_hashes_replay_update_receiver: AncestorHashesReplayUpdateReceiver,
    ) -> Self {
        let t_repair = {
            let blockstore = blockstore.clone();
            let exit = exit.clone();
            let repair_info = repair_info.clone();
            Builder::new()
                .name("solana-repair-service".to_string())
                .spawn(move || {
                    Self::run(
                        &blockstore,
                        &exit,
                        &repair_socket,
                        repair_info,
                        verified_vote_receiver,
                        &outstanding_requests,
                    )
                })
                .unwrap()
        };

        let ancestor_hashes_service = AncestorHashesService::new(
            exit,
            blockstore,
            ancestor_hashes_socket,
            repair_info,
            ancestor_hashes_replay_update_receiver,
        );

        RepairService {
            t_repair,
            ancestor_hashes_service,
        }
    }

    fn run(
        blockstore: &Blockstore,
        exit: &AtomicBool,
        repair_socket: &UdpSocket,
        repair_info: RepairInfo,
        verified_vote_receiver: VerifiedVoteReceiver,
        outstanding_requests: &RwLock<OutstandingShredRepairs>,
    ) {
        let mut repair_weight = RepairWeight::new(repair_info.bank_forks.read().unwrap().root());
        let serve_repair = ServeRepair::new(repair_info.cluster_info.clone());
        let id = repair_info.cluster_info.id();
        let mut repair_stats = RepairStats::default();
        let mut repair_timing = RepairTiming::default();
        let mut best_repairs_stats = BestRepairsStats::default();
        let mut last_stats = Instant::now();
        let duplicate_slot_repair_statuses: HashMap<Slot, DuplicateSlotRepairStatus> =
            HashMap::new();
        let mut peers_cache = LruCache::new(REPAIR_PEERS_CACHE_CAPACITY);

        loop {
            if exit.load(Ordering::Relaxed) {
                break;
            }

            let mut set_root_elapsed;
            let mut get_votes_elapsed;
            let mut add_votes_elapsed;

            let repairs = {
                let root_bank = repair_info.bank_forks.read().unwrap().root_bank().clone();
                let new_root = root_bank.slot();

                // Purge outdated slots from the weighting heuristic
                set_root_elapsed = Measure::start("set_root_elapsed");
                repair_weight.set_root(new_root);
                set_root_elapsed.stop();

                // Add new votes to the weighting heuristic
                get_votes_elapsed = Measure::start("get_votes_elapsed");
                let mut slot_to_vote_pubkeys: HashMap<Slot, Vec<Pubkey>> = HashMap::new();
                verified_vote_receiver
                    .try_iter()
                    .for_each(|(vote_pubkey, vote_slots)| {
                        for slot in vote_slots {
                            slot_to_vote_pubkeys
                                .entry(slot)
                                .or_default()
                                .push(vote_pubkey);
                        }
                    });
                get_votes_elapsed.stop();

                add_votes_elapsed = Measure::start("add_votes");
                repair_weight.add_votes(
                    blockstore,
                    slot_to_vote_pubkeys.into_iter(),
                    root_bank.epoch_stakes_map(),
                    root_bank.epoch_schedule(),
                );
                add_votes_elapsed.stop();

                let repairs = repair_weight.get_best_weighted_repairs(
                    blockstore,
                    root_bank.epoch_stakes_map(),
                    root_bank.epoch_schedule(),
                    MAX_ORPHANS,
                    MAX_REPAIR_LENGTH,
                    MAX_UNKNOWN_LAST_INDEX_REPAIRS,
                    MAX_CLOSEST_COMPLETION_REPAIRS,
                    &duplicate_slot_repair_statuses,
                    Some(&mut repair_timing),
                    Some(&mut best_repairs_stats),
                );

                repairs
            };

            let mut build_repairs_batch_elapsed = Measure::start("build_repairs_batch_elapsed");
            let batch: Vec<(Vec<u8>, SocketAddr)> = {
                let mut outstanding_requests = outstanding_requests.write().unwrap();
                repairs
                    .iter()
                    .filter_map(|repair_request| {
                        let (to, req) = serve_repair
                            .repair_request(
                                &repair_info.cluster_slots,
                                *repair_request,
                                &mut peers_cache,
                                &mut repair_stats,
                                &repair_info.repair_validators,
                                &mut outstanding_requests,
                            )
                            .ok()?;
                        Some((req, to))
                    })
                    .collect()
            };
            build_repairs_batch_elapsed.stop();

            let mut batch_send_repairs_elapsed = Measure::start("batch_send_repairs_elapsed");
            if !batch.is_empty() {
                if let Err(SendPktsError::IoError(err, num_failed)) =
                    batch_send(repair_socket, &batch)
                {
                    error!(
                        "{} batch_send failed to send {}/{} packets first error {:?}",
                        id,
                        num_failed,
                        batch.len(),
                        err
                    );
                }
            }
            batch_send_repairs_elapsed.stop();

            repair_timing.update(
                set_root_elapsed.as_us(),
                get_votes_elapsed.as_us(),
                add_votes_elapsed.as_us(),
                build_repairs_batch_elapsed.as_us(),
                batch_send_repairs_elapsed.as_us(),
            );

            if last_stats.elapsed().as_secs() > 2 {
                let repair_total = repair_stats.shred.count
                    + repair_stats.highest_shred.count
                    + repair_stats.orphan.count;
                let slot_to_count: Vec<_> = repair_stats
                    .shred
                    .slot_pubkeys
                    .iter()
                    .chain(repair_stats.highest_shred.slot_pubkeys.iter())
                    .chain(repair_stats.orphan.slot_pubkeys.iter())
                    .map(|(slot, slot_repairs)| {
                        (
                            slot,
                            slot_repairs
                                .pubkey_repairs
                                .iter()
                                .map(|(_key, count)| count)
                                .sum::<u64>(),
                        )
                    })
                    .collect();
                info!("repair_stats: {:?}", slot_to_count);
                if repair_total > 0 {
                    datapoint_info!(
                        "serve_repair-repair",
                        ("repair-total", repair_total, i64),
                        ("shred-count", repair_stats.shred.count, i64),
                        ("highest-shred-count", repair_stats.highest_shred.count, i64),
                        ("orphan-count", repair_stats.orphan.count, i64),
                        ("repair-highest-slot", repair_stats.highest_shred.max, i64),
                        ("repair-orphan", repair_stats.orphan.max, i64),
                    );
                }
                datapoint_info!(
                    "serve_repair-repair-timing",
                    ("set-root-elapsed", repair_timing.set_root_elapsed, i64),
                    ("get-votes-elapsed", repair_timing.get_votes_elapsed, i64),
                    ("add-votes-elapsed", repair_timing.add_votes_elapsed, i64),
                    (
                        "get-best-orphans-elapsed",
                        repair_timing.get_best_orphans_elapsed,
                        i64
                    ),
                    (
                        "get-best-shreds-elapsed",
                        repair_timing.get_best_shreds_elapsed,
                        i64
                    ),
                    (
                        "get-unknown-last-index-elapsed",
                        repair_timing.get_unknown_last_index_elapsed,
                        i64
                    ),
                    (
                        "get-closest-completion-elapsed",
                        repair_timing.get_closest_completion_elapsed,
                        i64
                    ),
                    (
                        "send-repairs-elapsed",
                        repair_timing.send_repairs_elapsed,
                        i64
                    ),
                    (
                        "build-repairs-batch-elapsed",
                        repair_timing.build_repairs_batch_elapsed,
                        i64
                    ),
                    (
                        "batch-send-repairs-elapsed",
                        repair_timing.batch_send_repairs_elapsed,
                        i64
                    ),
                );
                datapoint_info!(
                    "serve_repair-best-repairs",
                    ("call-count", best_repairs_stats.call_count, i64),
                    ("orphan-slots", best_repairs_stats.num_orphan_slots, i64),
                    ("orphan-repairs", best_repairs_stats.num_orphan_repairs, i64),
                    (
                        "best-shreds-slots",
                        best_repairs_stats.num_best_shreds_slots,
                        i64
                    ),
                    (
                        "best-shreds-repairs",
                        best_repairs_stats.num_best_shreds_repairs,
                        i64
                    ),
                    (
                        "unknown-last-index-slots",
                        best_repairs_stats.num_unknown_last_index_slots,
                        i64
                    ),
                    (
                        "unknown-last-index-repairs",
                        best_repairs_stats.num_unknown_last_index_repairs,
                        i64
                    ),
                    (
                        "closest-completion-slots",
                        best_repairs_stats.num_closest_completion_slots,
                        i64
                    ),
                    (
                        "closest-completion-repairs",
                        best_repairs_stats.num_closest_completion_repairs,
                        i64
                    ),
                );
                repair_stats = RepairStats::default();
                repair_timing = RepairTiming::default();
                best_repairs_stats = BestRepairsStats::default();
                last_stats = Instant::now();
            }
            sleep(Duration::from_millis(REPAIR_MS));
        }
    }

    // Generate repairs for all slots `x` in the repair_range.start <= x <= repair_range.end
    pub fn generate_repairs_in_range(
        blockstore: &Blockstore,
        max_repairs: usize,
        repair_range: &RepairSlotRange,
    ) -> Result<Vec<ShredRepairType>> {
        // Slot height and shred indexes for shreds we want to repair
        let mut repairs: Vec<ShredRepairType> = vec![];
        for slot in repair_range.start..=repair_range.end {
            if repairs.len() >= max_repairs {
                break;
            }

            let meta = blockstore
                .meta(slot)
                .expect("Unable to lookup slot meta")
                .unwrap_or(SlotMeta {
                    slot,
                    ..SlotMeta::default()
                });

            let new_repairs = Self::generate_repairs_for_slot(
                blockstore,
                slot,
                &meta,
                max_repairs - repairs.len(),
            );
            repairs.extend(new_repairs);
        }

        Ok(repairs)
    }

    pub fn generate_repairs_for_slot(
        blockstore: &Blockstore,
        slot: Slot,
        slot_meta: &SlotMeta,
        max_repairs: usize,
    ) -> Vec<ShredRepairType> {
        if max_repairs == 0 || slot_meta.is_full() {
            vec![]
        } else if slot_meta.consumed == slot_meta.received {
            vec![ShredRepairType::HighestShred(slot, slot_meta.received)]
        } else {
            let reqs = blockstore.find_missing_data_indexes(
                slot,
                slot_meta.first_shred_timestamp,
                slot_meta.consumed,
                slot_meta.received,
                max_repairs,
            );
            reqs.into_iter()
                .map(|i| ShredRepairType::Shred(slot, i))
                .collect()
        }
    }

    /// Repairs any fork starting at the input slot
    pub fn generate_repairs_for_fork<'a>(
        blockstore: &Blockstore,
        repairs: &mut Vec<ShredRepairType>,
        max_repairs: usize,
        slot: Slot,
        duplicate_slot_repair_statuses: &impl Contains<'a, Slot>,
    ) {
        let mut pending_slots = vec![slot];
        while repairs.len() < max_repairs && !pending_slots.is_empty() {
            let slot = pending_slots.pop().unwrap();
            if duplicate_slot_repair_statuses.contains(&slot) {
                // These are repaired through a different path
                continue;
            }
            if let Some(slot_meta) = blockstore.meta(slot).unwrap() {
                let new_repairs = Self::generate_repairs_for_slot(
                    blockstore,
                    slot,
                    &slot_meta,
                    max_repairs - repairs.len(),
                );
                repairs.extend(new_repairs);
                let next_slots = slot_meta.next_slots;
                pending_slots.extend(next_slots);
            } else {
                break;
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn generate_duplicate_repairs_for_slot(
        blockstore: &Blockstore,
        slot: Slot,
    ) -> Option<Vec<ShredRepairType>> {
        if let Some(slot_meta) = blockstore.meta(slot).unwrap() {
            if slot_meta.is_full() {
                // If the slot is full, no further need to repair this slot
                None
            } else {
                Some(Self::generate_repairs_for_slot(
                    blockstore,
                    slot,
                    &slot_meta,
                    MAX_REPAIR_PER_DUPLICATE,
                ))
            }
        } else {
            error!("Slot meta for duplicate slot does not exist, cannot generate repairs");
            // Filter out this slot from the set of duplicates to be repaired as
            // the SlotMeta has to exist for duplicates to be generated
            None
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn generate_and_send_duplicate_repairs(
        duplicate_slot_repair_statuses: &mut HashMap<Slot, DuplicateSlotRepairStatus>,
        cluster_slots: &ClusterSlots,
        blockstore: &Blockstore,
        serve_repair: &ServeRepair,
        repair_stats: &mut RepairStats,
        repair_socket: &UdpSocket,
        repair_validators: &Option<HashSet<Pubkey>>,
        outstanding_requests: &RwLock<OutstandingShredRepairs>,
    ) {
        duplicate_slot_repair_statuses.retain(|slot, status| {
            Self::update_duplicate_slot_repair_addr(
                *slot,
                status,
                cluster_slots,
                serve_repair,
                repair_validators,
            );
            if let Some((repair_pubkey, repair_addr)) = status.repair_pubkey_and_addr {
                let repairs = Self::generate_duplicate_repairs_for_slot(blockstore, *slot);

                if let Some(repairs) = repairs {
                    let mut outstanding_requests = outstanding_requests.write().unwrap();
                    for repair_type in repairs {
                        let nonce = outstanding_requests.add_request(repair_type, timestamp());
                        if let Err(e) = Self::serialize_and_send_request(
                            &repair_type,
                            repair_socket,
                            &repair_pubkey,
                            &repair_addr,
                            serve_repair,
                            repair_stats,
                            nonce,
                        ) {
                            info!(
                                "repair req send_to {} ({}) error {:?}",
                                repair_pubkey, repair_addr, e
                            );
                        }
                    }
                    true
                } else {
                    false
                }
            } else {
                true
            }
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn serialize_and_send_request(
        repair_type: &ShredRepairType,
        repair_socket: &UdpSocket,
        repair_pubkey: &Pubkey,
        to: &SocketAddr,
        serve_repair: &ServeRepair,
        repair_stats: &mut RepairStats,
        nonce: Nonce,
    ) -> Result<()> {
        let req =
            serve_repair.map_repair_request(repair_type, repair_pubkey, repair_stats, nonce)?;
        repair_socket.send_to(&req, to)?;
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn update_duplicate_slot_repair_addr(
        slot: Slot,
        status: &mut DuplicateSlotRepairStatus,
        cluster_slots: &ClusterSlots,
        serve_repair: &ServeRepair,
        repair_validators: &Option<HashSet<Pubkey>>,
    ) {
        let now = timestamp();
        if status.repair_pubkey_and_addr.is_none()
            || now.saturating_sub(status.start_ts) >= MAX_DUPLICATE_WAIT_MS as u64
        {
            let repair_pubkey_and_addr = serve_repair.repair_request_duplicate_compute_best_peer(
                slot,
                cluster_slots,
                repair_validators,
            );
            status.repair_pubkey_and_addr = repair_pubkey_and_addr.ok();
            status.start_ts = timestamp();
        }
    }

    #[allow(dead_code)]
    fn initiate_repair_for_duplicate_slot(
        slot: Slot,
        duplicate_slot_repair_statuses: &mut HashMap<Slot, DuplicateSlotRepairStatus>,
        cluster_slots: &ClusterSlots,
        serve_repair: &ServeRepair,
        repair_validators: &Option<HashSet<Pubkey>>,
    ) {
        // If we're already in the middle of repairing this, ignore the signal.
        if duplicate_slot_repair_statuses.contains_key(&slot) {
            return;
        }
        // Mark this slot as special repair, try to download from single
        // validator to avoid corruption
        let repair_pubkey_and_addr = serve_repair
            .repair_request_duplicate_compute_best_peer(slot, cluster_slots, repair_validators)
            .ok();
        let new_duplicate_slot_repair_status = DuplicateSlotRepairStatus {
            correct_ancestors_to_repair: vec![(slot, Hash::default())],
            repair_pubkey_and_addr,
            start_ts: timestamp(),
        };
        duplicate_slot_repair_statuses.insert(slot, new_duplicate_slot_repair_status);
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_repair.join()?;
        self.ancestor_hashes_service.join()
    }
}

