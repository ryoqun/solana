//! The `wen-restart` module handles automatic repair during a cluster restart

use {
    crate::{
        heaviest_fork_aggregate::HeaviestForkAggregate,
        last_voted_fork_slots_aggregate::{
            LastVotedForkSlotsAggregate, LastVotedForkSlotsFinalResult,
        },
        solana::wen_restart_proto::{
            self, GenerateSnapshotRecord, HeaviestForkAggregateFinal, HeaviestForkAggregateRecord,
            HeaviestForkRecord, LastVotedForkSlotsAggregateFinal,
            LastVotedForkSlotsAggregateRecord, LastVotedForkSlotsRecord, State as RestartState,
            WenRestartProgress,
        },
    },
    anyhow::Result,
    log::*,
    prost::Message,
    solana_entry::entry::VerifyRecyclers,
    solana_gossip::{
        cluster_info::{ClusterInfo, GOSSIP_SLEEP_MILLIS},
        restart_crds_values::RestartLastVotedForkSlots,
    },
    solana_ledger::{
        ancestor_iterator::AncestorIterator,
        blockstore::Blockstore,
        blockstore_processor::{process_single_slot, ConfirmationProgress, ProcessOptions},
        leader_schedule_cache::LeaderScheduleCache,
    },
    solana_program::{clock::Slot, hash::Hash},
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        accounts_background_service::AbsRequestSender,
        bank::Bank,
        bank_forks::BankForks,
        snapshot_archive_info::SnapshotArchiveInfoGetter,
        snapshot_bank_utils::bank_to_incremental_snapshot_archive,
        snapshot_config::SnapshotConfig,
        snapshot_utils::{
            get_highest_full_snapshot_archive_slot, get_highest_incremental_snapshot_archive_slot,
            purge_all_bank_snapshots,
        },
    },
    solana_sdk::{shred_version::compute_shred_version, timing::timestamp},
    solana_vote_program::vote_state::VoteTransaction,
    std::{
        collections::{HashMap, HashSet},
        fs::{read, File},
        io::{Cursor, Write},
        path::{Path, PathBuf},
        str::FromStr,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::sleep,
        time::{Duration, Instant},
    },
};

// If >42% of the validators have this block, repair this block locally.
const REPAIR_THRESHOLD: f64 = 0.42;
// When counting Heaviest Fork, only count those with no less than
// 67% - 5% - (100% - active_stake) = active_stake - 38% stake.
// 67% is the supermajority threshold (2/3), 5% is the assumption we
// made regarding how much non-conforming/offline validators the
// algorithm can tolerate.
const HEAVIEST_FORK_THRESHOLD_DELTA: f64 = 0.38;
// We allow at most 5% of the stake to disagree with us.
const HEAVIEST_FORK_DISAGREE_THRESHOLD_PERCENT: f64 = 5.0;
// We update HeaviestFork every 30 minutes or when we can exit.
const HEAVIEST_REFRESH_INTERVAL_IN_SECONDS: u64 = 1800;

#[derive(Debug, PartialEq)]
pub enum WenRestartError {
    BlockNotFound(Slot),
    BlockNotFull(Slot),
    BlockNotFrozenAfterReplay(Slot, Option<String>),
    BlockNotLinkedToExpectedParent(Slot, Option<Slot>, Slot),
    ChildStakeLargerThanParent(Slot, u64, Slot, u64),
    Exiting,
    FutureSnapshotExists(Slot, Slot, String),
    GenerateSnapshotWhenOneExists(Slot, String),
    MalformedLastVotedForkSlotsProtobuf(Option<LastVotedForkSlotsRecord>),
    MissingLastVotedForkSlots,
    MissingFullSnapshot(String),
    NotEnoughStakeAgreeingWithUs(Slot, Hash, HashMap<(Slot, Hash), u64>),
    UnexpectedState(wen_restart_proto::State),
}

impl std::fmt::Display for WenRestartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WenRestartError::BlockNotFound(slot) => {
                write!(f, "Block not found: {}", slot)
            }
            WenRestartError::BlockNotFull(slot) => {
                write!(f, "Block not full: {}", slot)
            }
            WenRestartError::BlockNotFrozenAfterReplay(slot, err) => {
                write!(f, "Block not frozen after replay: {} {:?}", slot, err)
            }
            WenRestartError::BlockNotLinkedToExpectedParent(slot, parent, expected_parent) => {
                write!(
                    f,
                    "Block {} is not linked to expected parent {} but to {:?}",
                    slot, expected_parent, parent
                )
            }
            WenRestartError::ChildStakeLargerThanParent(
                slot,
                child_stake,
                parent,
                parent_stake,
            ) => {
                write!(
                    f,
                    "Block {} has more stake {} than its parent {} with stake {}",
                    slot, child_stake, parent, parent_stake
                )
            }
            WenRestartError::Exiting => write!(f, "Exiting"),
            WenRestartError::FutureSnapshotExists(slot, highest_slot, directory) => {
                write!(
                    f,
                    "Future snapshot exists for slot: {slot} highest slot: {highest_slot} in directory: {directory}",
                )
            }
            WenRestartError::GenerateSnapshotWhenOneExists(slot, directory) => {
                write!(
                    f,
                    "Generate snapshot when one exists for slot: {slot} in directory: {directory}",
                )
            }
            WenRestartError::MalformedLastVotedForkSlotsProtobuf(record) => {
                write!(f, "Malformed last voted fork slots protobuf: {:?}", record)
            }
            WenRestartError::MissingLastVotedForkSlots => {
                write!(f, "Missing last voted fork slots")
            }
            WenRestartError::MissingFullSnapshot(directory) => {
                write!(f, "Missing full snapshot, please check whether correct directory is supplied {directory}")
            }
            WenRestartError::NotEnoughStakeAgreeingWithUs(slot, hash, block_stake_map) => {
                write!(
                    f,
                    "Not enough stake agreeing with our slot: {} hash: {}\n {:?}",
                    slot, hash, block_stake_map,
                )
            }
            WenRestartError::UnexpectedState(state) => {
                write!(f, "Unexpected state: {:?}", state)
            }
        }
    }
}

impl std::error::Error for WenRestartError {}

// We need a WenRestartProgressInternalState so we can convert the protobuf written in file
// into internal data structure in the initialize function. It should be easily
// convertable to and from WenRestartProgress protobuf.
#[derive(Debug, PartialEq)]
pub(crate) enum WenRestartProgressInternalState {
    Init {
        last_voted_fork_slots: Vec<Slot>,
        last_vote_bankhash: Hash,
    },
    LastVotedForkSlots {
        last_voted_fork_slots: Vec<Slot>,
        aggregate_final_result: Option<LastVotedForkSlotsFinalResult>,
    },
    FindHeaviestFork {
        aggregate_final_result: LastVotedForkSlotsFinalResult,
        my_heaviest_fork: Option<HeaviestForkRecord>,
    },
    HeaviestFork {
        new_root_slot: Slot,
    },
    GenerateSnapshot {
        new_root_slot: Slot,
        my_snapshot: Option<GenerateSnapshotRecord>,
    },
    Done,
}

pub(crate) fn send_restart_last_voted_fork_slots(
    cluster_info: Arc<ClusterInfo>,
    last_voted_fork_slots: &[Slot],
    last_vote_bankhash: Hash,
) -> Result<LastVotedForkSlotsRecord> {
    cluster_info.push_restart_last_voted_fork_slots(last_voted_fork_slots, last_vote_bankhash)?;
    Ok(LastVotedForkSlotsRecord {
        last_voted_fork_slots: last_voted_fork_slots.to_vec(),
        last_vote_bankhash: last_vote_bankhash.to_string(),
        shred_version: cluster_info.my_shred_version() as u32,
        wallclock: timestamp(),
    })
}

pub(crate) fn aggregate_restart_last_voted_fork_slots(
    wen_restart_path: &PathBuf,
    wait_for_supermajority_threshold_percent: u64,
    cluster_info: Arc<ClusterInfo>,
    last_voted_fork_slots: &Vec<Slot>,
    bank_forks: Arc<RwLock<BankForks>>,
    blockstore: Arc<Blockstore>,
    wen_restart_repair_slots: Arc<RwLock<Vec<Slot>>>,
    exit: Arc<AtomicBool>,
    progress: &mut WenRestartProgress,
) -> Result<LastVotedForkSlotsFinalResult> {
    let root_bank = bank_forks.read().unwrap().root_bank();
    let root_slot = root_bank.slot();
    let mut last_voted_fork_slots_aggregate = LastVotedForkSlotsAggregate::new(
        root_slot,
        REPAIR_THRESHOLD,
        root_bank.epoch_stakes(root_bank.epoch()).unwrap(),
        last_voted_fork_slots,
        &cluster_info.id(),
    );
    if let Some(aggregate_record) = &progress.last_voted_fork_slots_aggregate {
        for (key_string, message) in &aggregate_record.received {
            if let Err(e) =
                last_voted_fork_slots_aggregate.aggregate_from_record(key_string, message)
            {
                error!("Failed to aggregate from record: {:?}", e);
            }
        }
    } else {
        progress.last_voted_fork_slots_aggregate = Some(LastVotedForkSlotsAggregateRecord {
            received: HashMap::new(),
            final_result: None,
        });
    }
    let mut cursor = solana_gossip::crds::Cursor::default();
    let mut is_full_slots = HashSet::new();
    loop {
        if exit.load(Ordering::Relaxed) {
            return Err(WenRestartError::Exiting.into());
        }
        let start = timestamp();
        for new_last_voted_fork_slots in cluster_info.get_restart_last_voted_fork_slots(&mut cursor)
        {
            let from = new_last_voted_fork_slots.from.to_string();
            if let Some(record) =
                last_voted_fork_slots_aggregate.aggregate(new_last_voted_fork_slots)
            {
                progress
                    .last_voted_fork_slots_aggregate
                    .as_mut()
                    .unwrap()
                    .received
                    .insert(from, record);
            }
        }
        // Because all operations on the aggregate are called from this single thread, we can
        // fetch all results separately without worrying about them being out of sync. We can
        // also use returned iterator without the vector changing underneath us.
        let active_percent = last_voted_fork_slots_aggregate.active_percent();
        let mut filtered_slots: Vec<Slot>;
        {
            filtered_slots = last_voted_fork_slots_aggregate
                .slots_to_repair_iter()
                .filter(|slot| {
                    if *slot <= &root_slot || is_full_slots.contains(*slot) {
                        return false;
                    }
                    if blockstore.is_full(**slot) {
                        is_full_slots.insert(**slot);
                        false
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();
        }
        filtered_slots.sort();
        info!(
            "Active peers: {} Slots to repair: {:?}",
            active_percent, &filtered_slots
        );
        if filtered_slots.is_empty()
            && active_percent >= wait_for_supermajority_threshold_percent as f64
        {
            *wen_restart_repair_slots.write().unwrap() = vec![];
            break;
        }
        {
            *wen_restart_repair_slots.write().unwrap() = filtered_slots;
        }
        write_wen_restart_records(wen_restart_path, progress)?;
        let elapsed = timestamp().saturating_sub(start);
        let time_left = GOSSIP_SLEEP_MILLIS.saturating_sub(elapsed);
        if time_left > 0 {
            sleep(Duration::from_millis(time_left));
        }
    }
    Ok(last_voted_fork_slots_aggregate.get_final_result())
}

// Verify that all blocks with at least (active_stake_percnet - 38%) of the stake form a
// single chain from the root, and use the highest slot in the blocks as the heaviest fork.
// Please see SIMD 46 "gossip current heaviest fork" for correctness proof.
pub(crate) fn find_heaviest_fork(
    aggregate_final_result: LastVotedForkSlotsFinalResult,
    bank_forks: Arc<RwLock<BankForks>>,
    blockstore: Arc<Blockstore>,
    exit: Arc<AtomicBool>,
) -> Result<(Slot, Hash)> {
    let root_bank = bank_forks.read().unwrap().root_bank();
    let root_slot = root_bank.slot();
    // TODO: Should use better epoch_stakes later.
    let epoch_stake = root_bank.epoch_stakes(root_bank.epoch()).unwrap();
    let total_stake = epoch_stake.total_stake();
    let stake_threshold = aggregate_final_result
        .total_active_stake
        .saturating_sub((HEAVIEST_FORK_THRESHOLD_DELTA * total_stake as f64) as u64);
    let mut slots = aggregate_final_result
        .slots_stake_map
        .iter()
        .filter(|(slot, stake)| **slot > root_slot && **stake > stake_threshold)
        .map(|(slot, _)| *slot)
        .collect::<Vec<Slot>>();
    slots.sort();

    // The heaviest slot we selected will always be the last of the slots list, or root if the list is empty.
    let heaviest_fork_slot = slots.last().map_or(root_slot, |x| *x);

    let mut expected_parent = root_slot;
    for slot in &slots {
        if exit.load(Ordering::Relaxed) {
            return Err(WenRestartError::Exiting.into());
        }
        if let Ok(Some(block_meta)) = blockstore.meta(*slot) {
            if block_meta.parent_slot != Some(expected_parent) {
                if expected_parent == root_slot {
                    error!("First block {} in repair list not linked to local root {}, this could mean our root is too old",
                        slot, root_slot);
                } else {
                    error!(
                        "Block {} in blockstore is not linked to expected parent from Wen Restart {} but to Block {:?}",
                        slot, expected_parent, block_meta.parent_slot
                    );
                }
                return Err(WenRestartError::BlockNotLinkedToExpectedParent(
                    *slot,
                    block_meta.parent_slot,
                    expected_parent,
                )
                .into());
            }
            if !block_meta.is_full() {
                return Err(WenRestartError::BlockNotFull(*slot).into());
            }
            expected_parent = *slot;
        } else {
            return Err(WenRestartError::BlockNotFound(*slot).into());
        }
    }
    let heaviest_fork_bankhash = find_bankhash_of_heaviest_fork(
        heaviest_fork_slot,
        slots,
        blockstore.clone(),
        bank_forks.clone(),
        root_bank,
        &exit,
    )?;
    info!(
        "Heaviest fork found: slot: {}, bankhash: {:?}",
        heaviest_fork_slot, heaviest_fork_bankhash
    );
    Ok((heaviest_fork_slot, heaviest_fork_bankhash))
}

fn check_slot_smaller_than_intended_snapshot_slot(
    slot: Slot,
    intended_snapshot_slot: Slot,
    directory: &Path,
) -> Result<()> {
    match slot.cmp(&intended_snapshot_slot) {
        std::cmp::Ordering::Greater => Err(WenRestartError::FutureSnapshotExists(
            intended_snapshot_slot,
            slot,
            directory.to_string_lossy().to_string(),
        )
        .into()),
        std::cmp::Ordering::Equal => Err(WenRestartError::GenerateSnapshotWhenOneExists(
            slot,
            directory.to_string_lossy().to_string(),
        )
        .into()),
        std::cmp::Ordering::Less => Ok(()),
    }
}

// Given the agreed upon slot, add hard fork and rehash the corresponding bank, then
// generate incremental snapshot. When the new snapshot is ready, it removes any
// incremental snapshot on the same slot, then moves the new snapshot into the
// incremental snapshot directory.
//
// We don't use set_root() explicitly, because it may kick off snapshot requests, we
// can't have multiple snapshot requests in progress. In bank_to_snapshot_archive()
// everything set_root() does will be done (without bank_forks setting root). So
// when we restart from the snapshot bank on new_root_slot will become root.
pub(crate) fn generate_snapshot(
    bank_forks: Arc<RwLock<BankForks>>,
    snapshot_config: &SnapshotConfig,
    accounts_background_request_sender: &AbsRequestSender,
    genesis_config_hash: Hash,
    new_root_slot: Slot,
) -> Result<GenerateSnapshotRecord> {
    let new_root_bank;
    {
        let mut my_bank_forks = bank_forks.write().unwrap();
        let old_root_bank = my_bank_forks.root_bank();
        if !old_root_bank
            .hard_forks()
            .iter()
            .any(|(slot, _)| slot == &new_root_slot)
        {
            old_root_bank.register_hard_fork(new_root_slot);
        }
        // new_root_slot is guaranteed to have a bank in bank_forks, it's checked in
        // find_bankhash_of_heaviest_fork().
        match my_bank_forks.get(new_root_slot) {
            Some(bank) => new_root_bank = bank.clone(),
            None => {
                return Err(WenRestartError::BlockNotFound(new_root_slot).into());
            }
        }
        let mut banks = vec![&new_root_bank];
        let parents = new_root_bank.parents();
        banks.extend(parents.iter());

        let _ = my_bank_forks.send_eah_request_if_needed(
            new_root_slot,
            &banks,
            accounts_background_request_sender,
        )?;
    }
    // There can't be more than one EAH calculation in progress. If new_root is generated
    // within the EAH window (1/4 epoch to 3/4 epoch), the following function will wait for
    // EAH calculation to finish. So if we trigger another EAH when generating snapshots
    // we won't hit a panic.
    let _ = new_root_bank.get_epoch_accounts_hash_to_serialize();
    // Even though generating incremental snapshot is faster, it involves finding a full
    // snapshot to use as base, so the logic is more complicated. For now we always generate
    // an incremental snapshot.
    let mut directory = &snapshot_config.full_snapshot_archives_dir;
    let Some(full_snapshot_slot) = get_highest_full_snapshot_archive_slot(directory) else {
        return Err(WenRestartError::MissingFullSnapshot(
            snapshot_config
                .full_snapshot_archives_dir
                .to_string_lossy()
                .to_string(),
        )
        .into());
    };
    // In very rare cases it's possible that the local root is not on the heaviest fork, so the
    // validator generated snapshot for slots > local root. If the cluster agreed upon restart
    // slot new_root_slot is less than the the current highest full_snapshot_slot, that means the
    // locally rooted full_snapshot_slot will be rolled back. this requires human inspection。
    //
    // In even rarer cases, the selected slot might be the last full snapshot slot. We could
    // just re-generate a new snapshot to make sure the snapshot is up to date after hard fork,
    // but for now we just return an error to keep the code simple.
    check_slot_smaller_than_intended_snapshot_slot(full_snapshot_slot, new_root_slot, directory)?;
    directory = &snapshot_config.incremental_snapshot_archives_dir;
    if let Some(incremental_snapshot_slot) =
        get_highest_incremental_snapshot_archive_slot(directory, full_snapshot_slot)
    {
        check_slot_smaller_than_intended_snapshot_slot(
            incremental_snapshot_slot,
            new_root_slot,
            directory,
        )?;
    }
    let archive_info = bank_to_incremental_snapshot_archive(
        &snapshot_config.bank_snapshots_dir,
        &new_root_bank,
        full_snapshot_slot,
        Some(snapshot_config.snapshot_version),
        &snapshot_config.full_snapshot_archives_dir,
        &snapshot_config.incremental_snapshot_archives_dir,
        snapshot_config.archive_format,
    )?;
    let new_shred_version =
        compute_shred_version(&genesis_config_hash, Some(&new_root_bank.hard_forks()));
    let new_snapshot_path = archive_info.path().display().to_string();
    info!("wen_restart incremental snapshot generated on {new_snapshot_path} base slot {full_snapshot_slot}");
    // We might have bank snapshots past the new_root_slot, we need to purge them.
    purge_all_bank_snapshots(&snapshot_config.bank_snapshots_dir);
    Ok(GenerateSnapshotRecord {
        path: new_snapshot_path,
        slot: new_root_slot,
        bankhash: new_root_bank.hash().to_string(),
        shred_version: new_shred_version as u32,
    })
}

// Find the hash of the heaviest fork, if block hasn't been replayed, replay to get the hash.
pub(crate) fn find_bankhash_of_heaviest_fork(
    heaviest_fork_slot: Slot,
    slots: Vec<Slot>,
    blockstore: Arc<Blockstore>,
    bank_forks: Arc<RwLock<BankForks>>,
    root_bank: Arc<Bank>,
    exit: &AtomicBool,
) -> Result<Hash> {
    let heaviest_fork_bankhash = bank_forks
        .read()
        .unwrap()
        .get(heaviest_fork_slot)
        .map(|bank| bank.hash());
    if let Some(hash) = heaviest_fork_bankhash {
        return Ok(hash);
    }

    let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
    let replay_tx_thread_pool = rayon::ThreadPoolBuilder::new()
        .thread_name(|i| format!("solReplayTx{i:02}"))
        .build()
        .expect("new rayon threadpool");
    let recyclers = VerifyRecyclers::default();
    let mut timing = ExecuteTimings::default();
    let opts = ProcessOptions::default();
    // Grab one write lock until end of function because we are the only one touching bankforks now.
    let mut my_bankforks = bank_forks.write().unwrap();
    // Now replay all the missing blocks.
    let mut parent_bank = root_bank;
    for slot in slots {
        if exit.load(Ordering::Relaxed) {
            return Err(WenRestartError::Exiting.into());
        }
        let bank = match my_bankforks.get(slot) {
            Some(cur_bank) => {
                if !cur_bank.is_frozen() {
                    return Err(WenRestartError::BlockNotFrozenAfterReplay(slot, None).into());
                }
                cur_bank
            }
            None => {
                let new_bank = Bank::new_from_parent(
                    parent_bank.clone(),
                    &leader_schedule_cache
                        .slot_leader_at(slot, Some(&parent_bank))
                        .unwrap(),
                    slot,
                );
                let bank_with_scheduler = my_bankforks.insert_from_ledger(new_bank);
                let mut progress = ConfirmationProgress::new(parent_bank.last_blockhash());
                if let Err(e) = process_single_slot(
                    &blockstore,
                    &bank_with_scheduler,
                    &replay_tx_thread_pool,
                    &opts,
                    &recyclers,
                    &mut progress,
                    None,
                    None,
                    None,
                    None,
                    &mut timing,
                ) {
                    return Err(WenRestartError::BlockNotFrozenAfterReplay(
                        slot,
                        Some(e.to_string()),
                    )
                    .into());
                }
                my_bankforks.get(slot).unwrap()
            }
        };
        parent_bank = bank;
    }
    Ok(parent_bank.hash())
}

// Aggregate the heaviest fork and send updates to the cluster.
pub(crate) fn aggregate_restart_heaviest_fork(
    wen_restart_path: &PathBuf,
    wait_for_supermajority_threshold_percent: u64,
    cluster_info: Arc<ClusterInfo>,
    bank_forks: Arc<RwLock<BankForks>>,
    exit: Arc<AtomicBool>,
    progress: &mut WenRestartProgress,
) -> Result<()> {
    let root_bank = bank_forks.read().unwrap().root_bank();
    let epoch_stakes = root_bank.epoch_stakes(root_bank.epoch()).unwrap();
    let total_stake = epoch_stakes.total_stake();
    if progress.my_heaviest_fork.is_none() {
        return Err(WenRestartError::UnexpectedState(RestartState::HeaviestFork).into());
    }
    let my_heaviest_fork = progress.my_heaviest_fork.clone().unwrap();
    let heaviest_fork_slot = my_heaviest_fork.slot;
    let heaviest_fork_hash = Hash::from_str(&my_heaviest_fork.bankhash)?;
    let adjusted_threshold_percent = wait_for_supermajority_threshold_percent
        .saturating_sub(HEAVIEST_FORK_DISAGREE_THRESHOLD_PERCENT.round() as u64);
    // The threshold for supermajority should definitely be higher than 67%.
    assert!(
        adjusted_threshold_percent > 67,
        "Majority threshold too low"
    );
    let mut heaviest_fork_aggregate = HeaviestForkAggregate::new(
        adjusted_threshold_percent,
        cluster_info.my_shred_version(),
        epoch_stakes,
        heaviest_fork_slot,
        heaviest_fork_hash,
        &cluster_info.id(),
    );
    if let Some(aggregate_record) = &progress.heaviest_fork_aggregate {
        for (key_string, message) in &aggregate_record.received {
            match heaviest_fork_aggregate.aggregate_from_record(key_string, message) {
                Err(e) => error!("Failed to aggregate from record: {:?}", e),
                Ok(None) => info!("Record {:?} ignored", message),
                Ok(_) => (),
            }
        }
    } else {
        progress.heaviest_fork_aggregate = Some(HeaviestForkAggregateRecord {
            received: HashMap::new(),
            final_result: None,
        });
    }

    let mut total_active_stake = heaviest_fork_aggregate.total_active_stake();
    progress
        .my_heaviest_fork
        .as_mut()
        .unwrap()
        .total_active_stake = total_active_stake;
    cluster_info.push_restart_heaviest_fork(
        heaviest_fork_slot,
        heaviest_fork_hash,
        total_active_stake,
    );

    let mut progress_last_sent = Instant::now();
    let mut cursor = solana_gossip::crds::Cursor::default();
    let mut progress_changed = false;
    let majority_stake_required =
        (total_stake as f64 / 100.0 * adjusted_threshold_percent as f64).round() as u64;
    loop {
        if exit.load(Ordering::Relaxed) {
            return Err(WenRestartError::Exiting.into());
        }
        let start = timestamp();
        for new_heaviest_fork in cluster_info.get_restart_heaviest_fork(&mut cursor) {
            info!("Received new heaviest fork: {:?}", new_heaviest_fork);
            let from = new_heaviest_fork.from.to_string();
            if let Some(record) = heaviest_fork_aggregate.aggregate(new_heaviest_fork) {
                info!("Successfully aggregated new heaviest fork: {:?}", record);
                progress
                    .heaviest_fork_aggregate
                    .as_mut()
                    .unwrap()
                    .received
                    .insert(from, record);
                progress_changed = true;
            }
        }
        let current_total_active_stake = heaviest_fork_aggregate.total_active_stake();
        if current_total_active_stake > total_active_stake {
            total_active_stake = current_total_active_stake;
            progress
                .my_heaviest_fork
                .as_mut()
                .unwrap()
                .total_active_stake = current_total_active_stake;
            progress_changed = true;
        }
        if progress_changed {
            progress_changed = false;
            let total_active_stake_seen_supermajority =
                heaviest_fork_aggregate.total_active_stake_seen_supermajority();
            info!(
                "Total active stake seeing supermajority: {} Total active stake: {} Total stake {}",
                total_active_stake_seen_supermajority,
                heaviest_fork_aggregate.total_active_stake(),
                total_stake
            );
            let can_exit = total_active_stake_seen_supermajority >= majority_stake_required;
            // Only send out updates every 30 minutes or when we can exit.
            if progress_last_sent.elapsed().as_secs() >= HEAVIEST_REFRESH_INTERVAL_IN_SECONDS
                || can_exit
            {
                cluster_info.push_restart_heaviest_fork(
                    heaviest_fork_slot,
                    heaviest_fork_hash,
                    current_total_active_stake,
                );
                write_wen_restart_records(wen_restart_path, progress)?;
                progress_last_sent = Instant::now();
            }
            if can_exit {
                break;
            }
        }
        let elapsed = timestamp().saturating_sub(start);
        let time_left = GOSSIP_SLEEP_MILLIS.saturating_sub(elapsed);
        if time_left > 0 {
            sleep(Duration::from_millis(time_left));
        }
    }

    // Final check to see if supermajority agrees with us.
    let total_active_stake = heaviest_fork_aggregate.total_active_stake();
    let total_active_stake_seen_supermajority =
        heaviest_fork_aggregate.total_active_stake_seen_supermajority();
    let block_stake_map = heaviest_fork_aggregate.block_stake_map();
    let total_active_stake_agreed_with_me = *block_stake_map
        .get(&(heaviest_fork_slot, heaviest_fork_hash))
        .unwrap_or(&0);
    // It doesn't matter if 5% disagrees with us.
    let success_threshold =
        wait_for_supermajority_threshold_percent as f64 - HEAVIEST_FORK_DISAGREE_THRESHOLD_PERCENT;
    if total_active_stake_agreed_with_me as f64 * 100.0 / total_stake as f64 >= success_threshold {
        info!(
            "Heaviest fork agreed upon by supermajority: slot: {}, bankhash: {}",
            heaviest_fork_slot, heaviest_fork_hash
        );
        progress
            .heaviest_fork_aggregate
            .as_mut()
            .unwrap()
            .final_result = Some(HeaviestForkAggregateFinal {
            total_active_stake,
            total_active_stake_seen_supermajority,
            total_active_stake_agreed_with_me,
        });
        Ok(())
    } else {
        info!(
            "Not enough stake agreeing with our heaviest fork: slot: {},
            bankhash: {}, stake aggreeing with us {} out of {}",
            heaviest_fork_slot,
            heaviest_fork_hash,
            total_active_stake_agreed_with_me,
            total_active_stake
        );
        let mut max_slot_hash = (0, Hash::default());
        let mut max_stake = 0;
        for (slot, hash) in block_stake_map.keys() {
            let stake = block_stake_map[&(*slot, *hash)];
            if stake > max_stake {
                max_stake = stake;
                max_slot_hash = (*slot, *hash);
            }
            info!(
                "Slot: {}, Hash: {}, Stake: {}",
                slot,
                hash,
                block_stake_map[&(*slot, *hash)]
            );
        }
        let max_stake_percent = max_stake as f64 * 100.0 / total_stake as f64;
        if max_stake_percent >= success_threshold {
            warn!(
                "Max stake slot: {}, hash: {}, stake: {:.2}% does not agree with my
                choice, please go to discord to download the snapshot and restart
                the validator with --wait-for-supermajority.",
                max_slot_hash.0, max_slot_hash.1, max_stake_percent
            );
        } else {
            warn!(
                "Cluster consensus slot: {}, hash: {}, stake: {:.2}% does not agree,
                please go to discord for next steps.",
                max_slot_hash.0, max_slot_hash.1, max_stake_percent
            );
        }
        Err(WenRestartError::NotEnoughStakeAgreeingWithUs(
            heaviest_fork_slot,
            heaviest_fork_hash,
            block_stake_map,
        )
        .into())
    }
}

pub struct WenRestartConfig {
    pub wen_restart_path: PathBuf,
    pub last_vote: VoteTransaction,
    pub blockstore: Arc<Blockstore>,
    pub cluster_info: Arc<ClusterInfo>,
    pub bank_forks: Arc<RwLock<BankForks>>,
    pub wen_restart_repair_slots: Option<Arc<RwLock<Vec<Slot>>>>,
    pub wait_for_supermajority_threshold_percent: u64,
    pub snapshot_config: SnapshotConfig,
    pub accounts_background_request_sender: AbsRequestSender,
    pub genesis_config_hash: Hash,
    pub exit: Arc<AtomicBool>,
}

pub fn wait_for_wen_restart(config: WenRestartConfig) -> Result<()> {
    let (mut state, mut progress) = initialize(
        &config.wen_restart_path,
        config.last_vote.clone(),
        config.blockstore.clone(),
    )?;
    loop {
        state = match state {
            WenRestartProgressInternalState::Init {
                last_voted_fork_slots,
                last_vote_bankhash,
            } => {
                progress.my_last_voted_fork_slots = Some(send_restart_last_voted_fork_slots(
                    config.cluster_info.clone(),
                    &last_voted_fork_slots,
                    last_vote_bankhash,
                )?);
                WenRestartProgressInternalState::Init {
                    last_voted_fork_slots,
                    last_vote_bankhash,
                }
            }
            WenRestartProgressInternalState::LastVotedForkSlots {
                last_voted_fork_slots,
                aggregate_final_result,
            } => {
                let final_result = match aggregate_final_result {
                    Some(result) => result,
                    None => aggregate_restart_last_voted_fork_slots(
                        &config.wen_restart_path,
                        config.wait_for_supermajority_threshold_percent,
                        config.cluster_info.clone(),
                        &last_voted_fork_slots,
                        config.bank_forks.clone(),
                        config.blockstore.clone(),
                        config.wen_restart_repair_slots.clone().unwrap(),
                        config.exit.clone(),
                        &mut progress,
                    )?,
                };
                WenRestartProgressInternalState::LastVotedForkSlots {
                    last_voted_fork_slots,
                    aggregate_final_result: Some(final_result),
                }
            }
            WenRestartProgressInternalState::FindHeaviestFork {
                aggregate_final_result,
                my_heaviest_fork,
            } => {
                let heaviest_fork = match my_heaviest_fork {
                    Some(heaviest_fork) => heaviest_fork,
                    None => {
                        let (slot, bankhash) = find_heaviest_fork(
                            aggregate_final_result.clone(),
                            config.bank_forks.clone(),
                            config.blockstore.clone(),
                            config.exit.clone(),
                        )?;
                        info!(
                            "Heaviest fork found: slot: {}, bankhash: {}",
                            slot, bankhash
                        );
                        HeaviestForkRecord {
                            slot,
                            bankhash: bankhash.to_string(),
                            total_active_stake: 0,
                            wallclock: 0,
                            shred_version: config.cluster_info.my_shred_version() as u32,
                        }
                    }
                };
                WenRestartProgressInternalState::FindHeaviestFork {
                    aggregate_final_result,
                    my_heaviest_fork: Some(heaviest_fork),
                }
            }
            WenRestartProgressInternalState::HeaviestFork { new_root_slot } => {
                aggregate_restart_heaviest_fork(
                    &config.wen_restart_path,
                    config.wait_for_supermajority_threshold_percent,
                    config.cluster_info.clone(),
                    config.bank_forks.clone(),
                    config.exit.clone(),
                    &mut progress,
                )?;
                WenRestartProgressInternalState::HeaviestFork { new_root_slot }
            }
            WenRestartProgressInternalState::GenerateSnapshot {
                new_root_slot,
                my_snapshot,
            } => {
                let snapshot_record = match my_snapshot {
                    Some(record) => record,
                    None => generate_snapshot(
                        config.bank_forks.clone(),
                        &config.snapshot_config,
                        &config.accounts_background_request_sender,
                        config.genesis_config_hash,
                        new_root_slot,
                    )?,
                };
                WenRestartProgressInternalState::GenerateSnapshot {
                    new_root_slot,
                    my_snapshot: Some(snapshot_record),
                }
            }
            WenRestartProgressInternalState::Done => return Ok(()),
        };
        state = increment_and_write_wen_restart_records(
            &config.wen_restart_path,
            state,
            &mut progress,
        )?;
    }
}

pub(crate) fn increment_and_write_wen_restart_records(
    records_path: &PathBuf,
    current_state: WenRestartProgressInternalState,
    progress: &mut WenRestartProgress,
) -> Result<WenRestartProgressInternalState> {
    let new_state = match current_state {
        WenRestartProgressInternalState::Init {
            last_voted_fork_slots,
            last_vote_bankhash: _,
        } => {
            progress.set_state(RestartState::LastVotedForkSlots);
            WenRestartProgressInternalState::LastVotedForkSlots {
                last_voted_fork_slots,
                aggregate_final_result: None,
            }
        }
        WenRestartProgressInternalState::LastVotedForkSlots {
            last_voted_fork_slots: _,
            aggregate_final_result,
        } => {
            if let Some(aggregate_final_result) = aggregate_final_result {
                progress.set_state(RestartState::HeaviestFork);
                if let Some(aggregate_record) = progress.last_voted_fork_slots_aggregate.as_mut() {
                    aggregate_record.final_result = Some(LastVotedForkSlotsAggregateFinal {
                        slots_stake_map: aggregate_final_result.slots_stake_map.clone(),
                        total_active_stake: aggregate_final_result.total_active_stake,
                    });
                }
                WenRestartProgressInternalState::FindHeaviestFork {
                    aggregate_final_result,
                    my_heaviest_fork: None,
                }
            } else {
                return Err(
                    WenRestartError::UnexpectedState(RestartState::LastVotedForkSlots).into(),
                );
            }
        }
        WenRestartProgressInternalState::FindHeaviestFork {
            aggregate_final_result: _,
            my_heaviest_fork,
        } => {
            if let Some(my_heaviest_fork) = my_heaviest_fork {
                progress.my_heaviest_fork = Some(my_heaviest_fork.clone());
                WenRestartProgressInternalState::HeaviestFork {
                    new_root_slot: my_heaviest_fork.slot,
                }
            } else {
                return Err(WenRestartError::UnexpectedState(RestartState::HeaviestFork).into());
            }
        }
        WenRestartProgressInternalState::HeaviestFork { new_root_slot } => {
            progress.set_state(RestartState::GenerateSnapshot);
            WenRestartProgressInternalState::GenerateSnapshot {
                new_root_slot,
                my_snapshot: None,
            }
        }
        WenRestartProgressInternalState::GenerateSnapshot {
            new_root_slot: _,
            my_snapshot,
        } => {
            if let Some(my_snapshot) = my_snapshot {
                progress.set_state(RestartState::Done);
                progress.my_snapshot = Some(my_snapshot.clone());
                WenRestartProgressInternalState::Done
            } else {
                return Err(WenRestartError::UnexpectedState(RestartState::Done).into());
            }
        }
        WenRestartProgressInternalState::Done => {
            return Err(WenRestartError::UnexpectedState(RestartState::Done).into())
        }
    };
    write_wen_restart_records(records_path, progress)?;
    Ok(new_state)
}

pub(crate) fn initialize(
    records_path: &PathBuf,
    last_vote: VoteTransaction,
    blockstore: Arc<Blockstore>,
) -> Result<(WenRestartProgressInternalState, WenRestartProgress)> {
    let progress = match read_wen_restart_records(records_path) {
        Ok(progress) => progress,
        Err(e) => {
            let stdio_err = e.downcast_ref::<std::io::Error>();
            if stdio_err.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
                info!(
                    "wen restart proto file not found at {:?}, write init state",
                    records_path
                );
                let progress = WenRestartProgress {
                    state: RestartState::Init.into(),
                    ..Default::default()
                };
                write_wen_restart_records(records_path, &progress)?;
                progress
            } else {
                return Err(e);
            }
        }
    };
    match progress.state() {
        RestartState::Done => Ok((WenRestartProgressInternalState::Done, progress)),
        RestartState::Init => {
            let last_voted_fork_slots;
            let last_vote_bankhash;
            match &progress.my_last_voted_fork_slots {
                Some(my_last_voted_fork_slots) => {
                    last_voted_fork_slots = my_last_voted_fork_slots.last_voted_fork_slots.clone();
                    last_vote_bankhash =
                        Hash::from_str(&my_last_voted_fork_slots.last_vote_bankhash).unwrap();
                }
                None => {
                    // repair and restart option does not work without last voted slot.
                    if let Some(last_vote_slot) = last_vote.last_voted_slot() {
                        last_vote_bankhash = last_vote.hash();
                        last_voted_fork_slots =
                            AncestorIterator::new_inclusive(last_vote_slot, &blockstore)
                                .take(RestartLastVotedForkSlots::MAX_SLOTS)
                                .collect();
                    } else {
                        error!("
                            Cannot find last voted slot in the tower storage, it either means that this node has never \
                            voted or the tower storage is corrupted. Unfortunately, since WenRestart is a consensus protocol \
                            depending on each participant to send their last voted fork slots, your validator cannot participate.\
                            Please check discord for the conclusion of the WenRestart protocol, then generate a snapshot and use \
                            --wait-for-supermajority to restart the validator.");
                        return Err(WenRestartError::MissingLastVotedForkSlots.into());
                    }
                }
            }
            Ok((
                WenRestartProgressInternalState::Init {
                    last_voted_fork_slots,
                    last_vote_bankhash,
                },
                progress,
            ))
        }
        RestartState::LastVotedForkSlots => {
            if let Some(record) = progress.my_last_voted_fork_slots.as_ref() {
                Ok((
                    WenRestartProgressInternalState::LastVotedForkSlots {
                        last_voted_fork_slots: record.last_voted_fork_slots.clone(),
                        aggregate_final_result: progress
                            .last_voted_fork_slots_aggregate
                            .as_ref()
                            .and_then(|r| {
                                r.final_result.as_ref().map(|result| {
                                    LastVotedForkSlotsFinalResult {
                                        slots_stake_map: result.slots_stake_map.clone(),
                                        total_active_stake: result.total_active_stake,
                                    }
                                })
                            }),
                    },
                    progress,
                ))
            } else {
                Err(WenRestartError::MalformedLastVotedForkSlotsProtobuf(None).into())
            }
        }
        RestartState::HeaviestFork => Ok((
            WenRestartProgressInternalState::FindHeaviestFork {
                aggregate_final_result: progress
                    .last_voted_fork_slots_aggregate
                    .as_ref()
                    .and_then(|r| {
                        r.final_result
                            .as_ref()
                            .map(|result| LastVotedForkSlotsFinalResult {
                                slots_stake_map: result.slots_stake_map.clone(),
                                total_active_stake: result.total_active_stake,
                            })
                    })
                    .unwrap(),
                my_heaviest_fork: progress.my_heaviest_fork.clone(),
            },
            progress,
        )),
        _ => Err(WenRestartError::UnexpectedState(progress.state()).into()),
    }
}

fn read_wen_restart_records(records_path: &PathBuf) -> Result<WenRestartProgress> {
    let buffer = read(records_path)?;
    let progress = WenRestartProgress::decode(&mut Cursor::new(buffer))?;
    info!("read record {:?}", progress);
    Ok(progress)
}

pub(crate) fn write_wen_restart_records(
    records_path: &PathBuf,
    new_progress: &WenRestartProgress,
) -> Result<()> {
    // overwrite anything if exists
    let mut file = File::create(records_path)?;
    info!("writing new record {:?}", new_progress);
    let mut buf = Vec::with_capacity(new_progress.encoded_len());
    new_progress.encode(&mut buf)?;
    file.write_all(&buf)?;
    Ok(())
}
