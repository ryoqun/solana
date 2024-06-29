use {
    crate::{
        bank::{builtins::BuiltinPrototype, Bank, BankFieldsToDeserialize, BankSlotDelta},
        epoch_stakes::EpochStakes,
        runtime_config::RuntimeConfig,
        serde_snapshot::{
            bank_from_streams, fields_from_streams, BankIncrementalSnapshotPersistence,
        },
        snapshot_archive_info::{
            FullSnapshotArchiveInfo, IncrementalSnapshotArchiveInfo, SnapshotArchiveInfoGetter,
        },
        snapshot_config::SnapshotConfig,
        snapshot_hash::SnapshotHash,
        snapshot_package::{AccountsPackage, AccountsPackageKind, SnapshotKind, SnapshotPackage},
        snapshot_utils::{
            self, deserialize_snapshot_data_file, deserialize_snapshot_data_files,
            get_highest_bank_snapshot_post, get_highest_full_snapshot_archive_info,
            get_highest_incremental_snapshot_archive_info, rebuild_storages_from_snapshot_dir,
            serialize_snapshot_data_file, verify_and_unarchive_snapshots,
            verify_unpacked_snapshots_dir_and_version, ArchiveFormat, BankSnapshotInfo,
            SnapshotError, SnapshotRootPaths, SnapshotVersion, StorageAndNextAccountsFileId,
            UnpackedSnapshotsDirAndVersion, VerifyEpochStakesError, VerifySlotDeltasError,
        },
        status_cache,
    },
    bincode::{config::Options, serialize_into},
    log::*,
    solana_accounts_db::{
        accounts_db::{
            AccountShrinkThreshold, AccountStorageEntry, AccountsDbConfig, AtomicAccountsFileId,
            CalcAccountsHashDataSource,
        },
        accounts_file::StorageAccess,
        accounts_index::AccountSecondaryIndexes,
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        utils::delete_contents_of_path,
    },
    solana_measure::{measure, measure::Measure},
    solana_sdk::{
        clock::{Epoch, Slot},
        genesis_config::GenesisConfig,
        pubkey::Pubkey,
        slot_history::{Check, SlotHistory},
    },
    std::{
        collections::{HashMap, HashSet},
        ops::RangeInclusive,
        path::{Path, PathBuf},
        sync::{atomic::AtomicBool, Arc},
    },
    tempfile::TempDir,
};

pub const DEFAULT_FULL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS: Slot = 25_000;
pub const DEFAULT_INCREMENTAL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS: Slot = 100;
pub const DISABLED_SNAPSHOT_ARCHIVE_INTERVAL: Slot = Slot::MAX;

pub fn serialize_status_cache(
    slot_deltas: &[BankSlotDelta],
    status_cache_path: &Path,
) -> snapshot_utils::Result<u64> {
    serialize_snapshot_data_file(status_cache_path, |stream| {
        serialize_into(stream, slot_deltas)?;
        Ok(())
    })
}

#[derive(Debug)]
pub struct BankFromArchivesTimings {
    pub untar_full_snapshot_archive_us: u64,
    pub untar_incremental_snapshot_archive_us: u64,
    pub rebuild_bank_us: u64,
    pub verify_bank_us: u64,
}

#[derive(Debug)]
pub struct BankFromDirTimings {
    pub rebuild_storages_us: u64,
    pub rebuild_bank_us: u64,
}

/// Utility for parsing out bank specific information from a snapshot archive. This utility can be used
/// to parse out bank specific information like the leader schedule, epoch schedule, etc.
pub fn bank_fields_from_snapshot_archives(
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    storage_access: StorageAccess,
) -> snapshot_utils::Result<BankFieldsToDeserialize> {
    let full_snapshot_archive_info =
        get_highest_full_snapshot_archive_info(&full_snapshot_archives_dir).ok_or_else(|| {
            SnapshotError::NoSnapshotArchives(full_snapshot_archives_dir.as_ref().to_path_buf())
        })?;

    let incremental_snapshot_archive_info = get_highest_incremental_snapshot_archive_info(
        &incremental_snapshot_archives_dir,
        full_snapshot_archive_info.slot(),
    );

    let temp_unpack_dir = TempDir::new()?;
    let temp_accounts_dir = TempDir::new()?;

    let account_paths = vec![temp_accounts_dir.path().to_path_buf()];

    let (unarchived_full_snapshot, unarchived_incremental_snapshot, _next_append_vec_id) =
        verify_and_unarchive_snapshots(
            &temp_unpack_dir,
            &full_snapshot_archive_info,
            incremental_snapshot_archive_info.as_ref(),
            &account_paths,
            storage_access,
        )?;

    bank_fields_from_snapshots(
        &unarchived_full_snapshot.unpacked_snapshots_dir_and_version,
        unarchived_incremental_snapshot
            .as_ref()
            .map(|unarchive_preparation_result| {
                &unarchive_preparation_result.unpacked_snapshots_dir_and_version
            }),
    )
}

/// Rebuild bank from snapshot archives.  Handles either just a full snapshot, or both a full
/// snapshot and an incremental snapshot.
#[allow(clippy::too_many_arguments)]
pub fn bank_from_snapshot_archives(
    account_paths: &[PathBuf],
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archive_info: &FullSnapshotArchiveInfo,
    incremental_snapshot_archive_info: Option<&IncrementalSnapshotArchiveInfo>,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    test_hash_calculation: bool,
    accounts_db_skip_shrink: bool,
    accounts_db_force_initial_clean: bool,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<(Bank, BankFromArchivesTimings)> {
    info!(
        "Loading bank from full snapshot archive: {}, and incremental snapshot archive: {:?}",
        full_snapshot_archive_info.path().display(),
        incremental_snapshot_archive_info
            .as_ref()
            .map(
                |incremental_snapshot_archive_info| incremental_snapshot_archive_info
                    .path()
                    .display()
            )
    );

    let (unarchived_full_snapshot, mut unarchived_incremental_snapshot, next_append_vec_id) =
        verify_and_unarchive_snapshots(
            bank_snapshots_dir,
            full_snapshot_archive_info,
            incremental_snapshot_archive_info,
            account_paths,
            accounts_db_config
                .as_ref()
                .map(|config| config.storage_access)
                .unwrap_or_default(),
        )?;

    let mut storage = unarchived_full_snapshot.storage;
    if let Some(ref mut unarchive_preparation_result) = unarchived_incremental_snapshot {
        let incremental_snapshot_storages =
            std::mem::take(&mut unarchive_preparation_result.storage);
        storage.extend(incremental_snapshot_storages);
    }

    let storage_and_next_append_vec_id = StorageAndNextAccountsFileId {
        storage,
        next_append_vec_id,
    };

    let mut measure_rebuild = Measure::start("rebuild bank from snapshots");
    let bank = rebuild_bank_from_unarchived_snapshots(
        &unarchived_full_snapshot.unpacked_snapshots_dir_and_version,
        unarchived_incremental_snapshot
            .as_ref()
            .map(|unarchive_preparation_result| {
                &unarchive_preparation_result.unpacked_snapshots_dir_and_version
            }),
        account_paths,
        storage_and_next_append_vec_id,
        genesis_config,
        runtime_config,
        debug_keys,
        additional_builtins,
        account_secondary_indexes,
        limit_load_slot_count_from_snapshot,
        shrink_ratio,
        verify_index,
        accounts_db_config,
        accounts_update_notifier,
        exit,
    )?;
    measure_rebuild.stop();
    info!("{}", measure_rebuild);

    let snapshot_archive_info = incremental_snapshot_archive_info.map_or_else(
        || full_snapshot_archive_info.snapshot_archive_info(),
        |incremental_snapshot_archive_info| {
            incremental_snapshot_archive_info.snapshot_archive_info()
        },
    );
    verify_bank_against_expected_slot_hash(
        &bank,
        snapshot_archive_info.slot,
        snapshot_archive_info.hash,
    )?;

    let base = incremental_snapshot_archive_info.is_some().then(|| {
        let base_slot = full_snapshot_archive_info.slot();
        let base_capitalization = bank
            .rc
            .accounts
            .accounts_db
            .get_accounts_hash(base_slot)
            .expect("accounts hash must exist at full snapshot's slot")
            .1;
        (base_slot, base_capitalization)
    });

    let mut measure_verify = Measure::start("verify");
    if !bank.verify_snapshot_bank(
        test_hash_calculation,
        accounts_db_skip_shrink || !full_snapshot_archive_info.is_remote(),
        accounts_db_force_initial_clean,
        full_snapshot_archive_info.slot(),
        base,
    ) && limit_load_slot_count_from_snapshot.is_none()
    {
        panic!("Snapshot bank for slot {} failed to verify", bank.slot());
    }
    measure_verify.stop();

    let timings = BankFromArchivesTimings {
        untar_full_snapshot_archive_us: unarchived_full_snapshot.measure_untar.as_us(),
        untar_incremental_snapshot_archive_us: unarchived_incremental_snapshot
            .map_or(0, |unarchive_preparation_result| {
                unarchive_preparation_result.measure_untar.as_us()
            }),
        rebuild_bank_us: measure_rebuild.as_us(),
        verify_bank_us: measure_verify.as_us(),
    };
    datapoint_info!(
        "bank_from_snapshot_archives",
        (
            "untar_full_snapshot_archive_us",
            timings.untar_full_snapshot_archive_us,
            i64
        ),
        (
            "untar_incremental_snapshot_archive_us",
            timings.untar_incremental_snapshot_archive_us,
            i64
        ),
        ("rebuild_bank_us", timings.rebuild_bank_us, i64),
        ("verify_bank_us", timings.verify_bank_us, i64),
    );
    Ok((bank, timings))
}

/// Rebuild bank from snapshot archives
///
/// This function searches `full_snapshot_archives_dir` and `incremental_snapshot_archives_dir` for
/// the highest full snapshot and highest corresponding incremental snapshot, then rebuilds the bank.
#[allow(clippy::too_many_arguments)]
pub fn bank_from_latest_snapshot_archives(
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    account_paths: &[PathBuf],
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    test_hash_calculation: bool,
    accounts_db_skip_shrink: bool,
    accounts_db_force_initial_clean: bool,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<(
    Bank,
    FullSnapshotArchiveInfo,
    Option<IncrementalSnapshotArchiveInfo>,
)> {
    let full_snapshot_archive_info =
        get_highest_full_snapshot_archive_info(&full_snapshot_archives_dir).ok_or_else(|| {
            SnapshotError::NoSnapshotArchives(full_snapshot_archives_dir.as_ref().to_path_buf())
        })?;

    let incremental_snapshot_archive_info = get_highest_incremental_snapshot_archive_info(
        &incremental_snapshot_archives_dir,
        full_snapshot_archive_info.slot(),
    );

    let (bank, _) = bank_from_snapshot_archives(
        account_paths,
        bank_snapshots_dir.as_ref(),
        &full_snapshot_archive_info,
        incremental_snapshot_archive_info.as_ref(),
        genesis_config,
        runtime_config,
        debug_keys,
        additional_builtins,
        account_secondary_indexes,
        limit_load_slot_count_from_snapshot,
        shrink_ratio,
        test_hash_calculation,
        accounts_db_skip_shrink,
        accounts_db_force_initial_clean,
        verify_index,
        accounts_db_config,
        accounts_update_notifier,
        exit,
    )?;

    Ok((
        bank,
        full_snapshot_archive_info,
        incremental_snapshot_archive_info,
    ))
}

/// Build bank from a snapshot (a snapshot directory, not a snapshot archive)
#[allow(clippy::too_many_arguments)]
pub fn bank_from_snapshot_dir(
    account_paths: &[PathBuf],
    bank_snapshot: &BankSnapshotInfo,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<(Bank, BankFromDirTimings)> {
    info!(
        "Loading bank from snapshot dir: {}",
        bank_snapshot.snapshot_dir.display()
    );

    // Clear the contents of the account paths run directories.  When constructing the bank, the appendvec
    // files will be extracted from the snapshot hardlink directories into these run/ directories.
    for path in account_paths {
        delete_contents_of_path(path);
    }

    let next_append_vec_id = Arc::new(AtomicAccountsFileId::new(0));
    let storage_access = accounts_db_config
        .as_ref()
        .map(|config| config.storage_access)
        .unwrap_or_default();

    let (storage, measure_rebuild_storages) = measure!(
        rebuild_storages_from_snapshot_dir(
            bank_snapshot,
            account_paths,
            next_append_vec_id.clone(),
            storage_access,
        )?,
        "rebuild storages from snapshot dir"
    );
    info!("{}", measure_rebuild_storages);

    let next_append_vec_id =
        Arc::try_unwrap(next_append_vec_id).expect("this is the only strong reference");
    let storage_and_next_append_vec_id = StorageAndNextAccountsFileId {
        storage,
        next_append_vec_id,
    };
    let (bank, measure_rebuild_bank) = measure!(
        rebuild_bank_from_snapshot(
            bank_snapshot,
            account_paths,
            storage_and_next_append_vec_id,
            genesis_config,
            runtime_config,
            debug_keys,
            additional_builtins,
            account_secondary_indexes,
            limit_load_slot_count_from_snapshot,
            shrink_ratio,
            verify_index,
            accounts_db_config,
            accounts_update_notifier,
            exit,
        )?,
        "rebuild bank from snapshot"
    );
    info!("{}", measure_rebuild_bank);

    // Skip bank.verify_snapshot_bank.  Subsequent snapshot requests/accounts hash verification requests
    // will calculate and check the accounts hash, so we will still have safety/correctness there.
    bank.set_initial_accounts_hash_verification_completed();

    let timings = BankFromDirTimings {
        rebuild_storages_us: measure_rebuild_storages.as_us(),
        rebuild_bank_us: measure_rebuild_bank.as_us(),
    };
    datapoint_info!(
        "bank_from_snapshot_dir",
        ("rebuild_storages_us", timings.rebuild_storages_us, i64),
        ("rebuild_bank_us", timings.rebuild_bank_us, i64),
    );
    Ok((bank, timings))
}

/// follow the prototype of fn bank_from_latest_snapshot_archives, implement the from_dir case
#[allow(clippy::too_many_arguments)]
pub fn bank_from_latest_snapshot_dir(
    bank_snapshots_dir: impl AsRef<Path>,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    account_paths: &[PathBuf],
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<Bank> {
    let bank_snapshot = get_highest_bank_snapshot_post(&bank_snapshots_dir).ok_or_else(|| {
        SnapshotError::NoSnapshotSlotDir(bank_snapshots_dir.as_ref().to_path_buf())
    })?;
    let (bank, _) = bank_from_snapshot_dir(
        account_paths,
        &bank_snapshot,
        genesis_config,
        runtime_config,
        debug_keys,
        additional_builtins,
        account_secondary_indexes,
        limit_load_slot_count_from_snapshot,
        shrink_ratio,
        verify_index,
        accounts_db_config,
        accounts_update_notifier,
        exit,
    )?;

    Ok(bank)
}

/// Check to make sure the deserialized bank's slot and hash matches the snapshot archive's slot
/// and hash
fn verify_bank_against_expected_slot_hash(
    bank: &Bank,
    expected_slot: Slot,
    expected_hash: SnapshotHash,
) -> snapshot_utils::Result<()> {
    let bank_slot = bank.slot();
    let bank_hash = bank.get_snapshot_hash();

    if bank_slot != expected_slot || bank_hash != expected_hash {
        return Err(SnapshotError::MismatchedSlotHash(
            (bank_slot, bank_hash),
            (expected_slot, expected_hash),
        ));
    }

    Ok(())
}

fn bank_fields_from_snapshots(
    full_snapshot_unpacked_snapshots_dir_and_version: &UnpackedSnapshotsDirAndVersion,
    incremental_snapshot_unpacked_snapshots_dir_and_version: Option<
        &UnpackedSnapshotsDirAndVersion,
    >,
) -> snapshot_utils::Result<BankFieldsToDeserialize> {
    let (full_snapshot_version, full_snapshot_root_paths) =
        verify_unpacked_snapshots_dir_and_version(
            full_snapshot_unpacked_snapshots_dir_and_version,
        )?;
    let (incremental_snapshot_version, incremental_snapshot_root_paths) =
        if let Some(snapshot_unpacked_snapshots_dir_and_version) =
            incremental_snapshot_unpacked_snapshots_dir_and_version
        {
            let (snapshot_version, bank_snapshot_info) = verify_unpacked_snapshots_dir_and_version(
                snapshot_unpacked_snapshots_dir_and_version,
            )?;
            (Some(snapshot_version), Some(bank_snapshot_info))
        } else {
            (None, None)
        };
    info!(
        "Loading bank from full snapshot {} and incremental snapshot {:?}",
        full_snapshot_root_paths.snapshot_path().display(),
        incremental_snapshot_root_paths
            .as_ref()
            .map(|paths| paths.snapshot_path()),
    );

    let snapshot_root_paths = SnapshotRootPaths {
        full_snapshot_root_file_path: full_snapshot_root_paths.snapshot_path(),
        incremental_snapshot_root_file_path: incremental_snapshot_root_paths
            .map(|root_paths| root_paths.snapshot_path()),
    };

    deserialize_snapshot_data_files(&snapshot_root_paths, |snapshot_streams| {
        Ok(
            match incremental_snapshot_version.unwrap_or(full_snapshot_version) {
                SnapshotVersion::V1_2_0 => fields_from_streams(snapshot_streams)
                    .map(|(bank_fields, _accountsdb_fields)| bank_fields.collapse_into()),
            }?,
        )
    })
}

fn deserialize_status_cache(
    status_cache_path: &Path,
) -> snapshot_utils::Result<Vec<BankSlotDelta>> {
    deserialize_snapshot_data_file(status_cache_path, |stream| {
        info!(
            "Rebuilding status cache from {}",
            status_cache_path.display()
        );
        let slot_delta: Vec<BankSlotDelta> = bincode::options()
            .with_limit(snapshot_utils::MAX_SNAPSHOT_DATA_FILE_SIZE)
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .deserialize_from(stream)?;
        Ok(slot_delta)
    })
}

#[allow(clippy::too_many_arguments)]
fn rebuild_bank_from_unarchived_snapshots(
    full_snapshot_unpacked_snapshots_dir_and_version: &UnpackedSnapshotsDirAndVersion,
    incremental_snapshot_unpacked_snapshots_dir_and_version: Option<
        &UnpackedSnapshotsDirAndVersion,
    >,
    account_paths: &[PathBuf],
    storage_and_next_append_vec_id: StorageAndNextAccountsFileId,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<Bank> {
    let (full_snapshot_version, full_snapshot_root_paths) =
        verify_unpacked_snapshots_dir_and_version(
            full_snapshot_unpacked_snapshots_dir_and_version,
        )?;
    let (incremental_snapshot_version, incremental_snapshot_root_paths) =
        if let Some(snapshot_unpacked_snapshots_dir_and_version) =
            incremental_snapshot_unpacked_snapshots_dir_and_version
        {
            Some(verify_unpacked_snapshots_dir_and_version(
                snapshot_unpacked_snapshots_dir_and_version,
            )?)
        } else {
            None
        }
        .unzip();
    info!(
        "Rebuilding bank from full snapshot {} and incremental snapshot {:?}",
        full_snapshot_root_paths.snapshot_path().display(),
        incremental_snapshot_root_paths
            .as_ref()
            .map(|paths| paths.snapshot_path()),
    );

    let snapshot_root_paths = SnapshotRootPaths {
        full_snapshot_root_file_path: full_snapshot_root_paths.snapshot_path(),
        incremental_snapshot_root_file_path: incremental_snapshot_root_paths
            .map(|root_paths| root_paths.snapshot_path()),
    };

    let bank = deserialize_snapshot_data_files(&snapshot_root_paths, |snapshot_streams| {
        Ok(
            match incremental_snapshot_version.unwrap_or(full_snapshot_version) {
                SnapshotVersion::V1_2_0 => bank_from_streams(
                    snapshot_streams,
                    account_paths,
                    storage_and_next_append_vec_id,
                    genesis_config,
                    runtime_config,
                    debug_keys,
                    additional_builtins,
                    account_secondary_indexes,
                    limit_load_slot_count_from_snapshot,
                    shrink_ratio,
                    verify_index,
                    accounts_db_config,
                    accounts_update_notifier,
                    exit,
                ),
            }?,
        )
    })?;

    verify_epoch_stakes(&bank)?;

    // The status cache is rebuilt from the latest snapshot.  So, if there's an incremental
    // snapshot, use that.  Otherwise use the full snapshot.
    let status_cache_path = incremental_snapshot_unpacked_snapshots_dir_and_version
        .map_or_else(
            || {
                full_snapshot_unpacked_snapshots_dir_and_version
                    .unpacked_snapshots_dir
                    .as_path()
            },
            |unpacked_snapshots_dir_and_version| {
                unpacked_snapshots_dir_and_version
                    .unpacked_snapshots_dir
                    .as_path()
            },
        )
        .join(snapshot_utils::SNAPSHOT_STATUS_CACHE_FILENAME);
    let slot_deltas = deserialize_status_cache(&status_cache_path)?;

    verify_slot_deltas(slot_deltas.as_slice(), &bank)?;

    bank.status_cache.write().unwrap().append(&slot_deltas);

    info!("Rebuilt bank for slot: {}", bank.slot());
    Ok(bank)
}

#[allow(clippy::too_many_arguments)]
fn rebuild_bank_from_snapshot(
    bank_snapshot: &BankSnapshotInfo,
    account_paths: &[PathBuf],
    storage_and_next_append_vec_id: StorageAndNextAccountsFileId,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<Bank> {
    info!(
        "Rebuilding bank from snapshot {}",
        bank_snapshot.snapshot_dir.display(),
    );

    let snapshot_root_paths = SnapshotRootPaths {
        full_snapshot_root_file_path: bank_snapshot.snapshot_path(),
        incremental_snapshot_root_file_path: None,
    };

    let bank = deserialize_snapshot_data_files(&snapshot_root_paths, |snapshot_streams| {
        Ok(bank_from_streams(
            snapshot_streams,
            account_paths,
            storage_and_next_append_vec_id,
            genesis_config,
            runtime_config,
            debug_keys,
            additional_builtins,
            account_secondary_indexes,
            limit_load_slot_count_from_snapshot,
            shrink_ratio,
            verify_index,
            accounts_db_config,
            accounts_update_notifier,
            exit,
        )?)
    })?;

    verify_epoch_stakes(&bank)?;

    let status_cache_path = bank_snapshot
        .snapshot_dir
        .join(snapshot_utils::SNAPSHOT_STATUS_CACHE_FILENAME);
    let slot_deltas = deserialize_status_cache(&status_cache_path)?;

    verify_slot_deltas(slot_deltas.as_slice(), &bank)?;

    bank.status_cache.write().unwrap().append(&slot_deltas);

    info!("Rebuilt bank for slot: {}", bank.slot());
    Ok(bank)
}

/// Verify that the snapshot's slot deltas are not corrupt/invalid
fn verify_slot_deltas(
    slot_deltas: &[BankSlotDelta],
    bank: &Bank,
) -> std::result::Result<(), VerifySlotDeltasError> {
    let info = verify_slot_deltas_structural(slot_deltas, bank.slot())?;
    verify_slot_deltas_with_history(&info.slots, &bank.get_slot_history(), bank.slot())
}

/// Verify that the snapshot's slot deltas are not corrupt/invalid
/// These checks are simple/structural
fn verify_slot_deltas_structural(
    slot_deltas: &[BankSlotDelta],
    bank_slot: Slot,
) -> std::result::Result<VerifySlotDeltasStructuralInfo, VerifySlotDeltasError> {
    // there should not be more entries than that status cache's max
    let num_entries = slot_deltas.len();
    if num_entries > status_cache::MAX_CACHE_ENTRIES {
        return Err(VerifySlotDeltasError::TooManyEntries(
            num_entries,
            status_cache::MAX_CACHE_ENTRIES,
        ));
    }

    let mut slots_seen_so_far = HashSet::new();
    for &(slot, is_root, ..) in slot_deltas {
        // all entries should be roots
        if !is_root {
            return Err(VerifySlotDeltasError::SlotIsNotRoot(slot));
        }

        // all entries should be for slots less than or equal to the bank's slot
        if slot > bank_slot {
            return Err(VerifySlotDeltasError::SlotGreaterThanMaxRoot(
                slot, bank_slot,
            ));
        }

        // there should only be one entry per slot
        let is_duplicate = !slots_seen_so_far.insert(slot);
        if is_duplicate {
            return Err(VerifySlotDeltasError::SlotHasMultipleEntries(slot));
        }
    }

    // detect serious logic error for future careless changes. :)
    assert_eq!(slots_seen_so_far.len(), slot_deltas.len());

    Ok(VerifySlotDeltasStructuralInfo {
        slots: slots_seen_so_far,
    })
}

/// Computed information from `verify_slot_deltas_structural()`, that may be reused/useful later.
#[derive(Debug, PartialEq, Eq)]
struct VerifySlotDeltasStructuralInfo {
    /// All the slots in the slot deltas
    slots: HashSet<Slot>,
}

/// Verify that the snapshot's slot deltas are not corrupt/invalid
/// These checks use the slot history for verification
fn verify_slot_deltas_with_history(
    slots_from_slot_deltas: &HashSet<Slot>,
    slot_history: &SlotHistory,
    bank_slot: Slot,
) -> std::result::Result<(), VerifySlotDeltasError> {
    // ensure the slot history is valid (as much as possible), since we're using it to verify the
    // slot deltas
    if slot_history.newest() != bank_slot {
        return Err(VerifySlotDeltasError::BadSlotHistory);
    }

    // all slots in the slot deltas should be in the bank's slot history
    let slot_missing_from_history = slots_from_slot_deltas
        .iter()
        .find(|slot| slot_history.check(**slot) != Check::Found);
    if let Some(slot) = slot_missing_from_history {
        return Err(VerifySlotDeltasError::SlotNotFoundInHistory(*slot));
    }

    // all slots in the history should be in the slot deltas (up to MAX_CACHE_ENTRIES)
    // this ensures nothing was removed from the status cache
    //
    // go through the slot history and make sure there's an entry for each slot
    // note: it's important to go highest-to-lowest since the status cache removes
    // older entries first
    // note: we already checked above that `bank_slot == slot_history.newest()`
    let slot_missing_from_deltas = (slot_history.oldest()..=slot_history.newest())
        .rev()
        .filter(|slot| slot_history.check(*slot) == Check::Found)
        .take(status_cache::MAX_CACHE_ENTRIES)
        .find(|slot| !slots_from_slot_deltas.contains(slot));
    if let Some(slot) = slot_missing_from_deltas {
        return Err(VerifySlotDeltasError::SlotNotFoundInDeltas(slot));
    }

    Ok(())
}

/// Verifies the bank's epoch stakes are valid after rebuilding from a snapshot
fn verify_epoch_stakes(bank: &Bank) -> std::result::Result<(), VerifyEpochStakesError> {
    // Stakes are required for epochs from the current epoch up-to-and-including the
    // leader schedule epoch.  In practice this will only be two epochs: the current and the next.
    // Using a range mirrors how Bank::new_with_paths() seeds the initial epoch stakes.
    let current_epoch = bank.epoch();
    let leader_schedule_epoch = bank.get_leader_schedule_epoch(bank.slot());
    let required_epochs = current_epoch..=leader_schedule_epoch;
    _verify_epoch_stakes(bank.epoch_stakes_map(), required_epochs)
}

/// Verifies the bank's epoch stakes are valid after rebuilding from a snapshot
///
/// This version of the function exists to facilitate testing.
/// Normal callers should use `verify_epoch_stakes()`.
fn _verify_epoch_stakes(
    epoch_stakes_map: &HashMap<Epoch, EpochStakes>,
    required_epochs: RangeInclusive<Epoch>,
) -> std::result::Result<(), VerifyEpochStakesError> {
    // Ensure epoch stakes from the snapshot does not contain entries for invalid epochs.
    // Since epoch stakes are computed for the leader schedule epoch (usually `epoch + 1`),
    // the snapshot's epoch stakes therefor can have entries for epochs at-or-below the
    // leader schedule epoch.
    let max_epoch = *required_epochs.end();
    if let Some(invalid_epoch) = epoch_stakes_map.keys().find(|epoch| **epoch > max_epoch) {
        return Err(VerifyEpochStakesError::EpochGreaterThanMax(
            *invalid_epoch,
            max_epoch,
        ));
    }

    // Ensure epoch stakes contains stakes for all the required epochs
    if let Some(missing_epoch) = required_epochs
        .clone()
        .find(|epoch| !epoch_stakes_map.contains_key(epoch))
    {
        return Err(VerifyEpochStakesError::StakesNotFound(
            missing_epoch,
            required_epochs,
        ));
    }

    Ok(())
}

/// Get the snapshot storages for this bank
pub fn get_snapshot_storages(bank: &Bank) -> Vec<Arc<AccountStorageEntry>> {
    let mut measure_snapshot_storages = Measure::start("snapshot-storages");
    let snapshot_storages = bank.get_snapshot_storages(None);
    measure_snapshot_storages.stop();
    datapoint_info!(
        "get_snapshot_storages",
        (
            "snapshot-storages-time-ms",
            measure_snapshot_storages.as_ms(),
            i64
        ),
    );

    snapshot_storages
}

/// Convenience function to create a full snapshot archive out of any Bank, regardless of state.
/// The Bank will be frozen during the process.
/// This is only called from ledger-tool or tests. Warping is a special case as well.
///
/// Requires:
///     - `bank` is complete
pub fn bank_to_full_snapshot_archive(
    bank_snapshots_dir: impl AsRef<Path>,
    bank: &Bank,
    snapshot_version: Option<SnapshotVersion>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    archive_format: ArchiveFormat,
) -> snapshot_utils::Result<FullSnapshotArchiveInfo> {
    let snapshot_version = snapshot_version.unwrap_or_default();
    let temp_bank_snapshots_dir = tempfile::tempdir_in(bank_snapshots_dir)?;
    bank_to_full_snapshot_archive_with(
        &temp_bank_snapshots_dir,
        bank,
        snapshot_version,
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
        archive_format,
    )
}

/// See bank_to_full_snapshot_archive() for documentation
///
/// This fn does *not* create a tmpdir inside `bank_snapshots_dir`
/// (which is needed by a test)
fn bank_to_full_snapshot_archive_with(
    bank_snapshots_dir: impl AsRef<Path>,
    bank: &Bank,
    snapshot_version: SnapshotVersion,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    archive_format: ArchiveFormat,
) -> snapshot_utils::Result<FullSnapshotArchiveInfo> {
    assert!(bank.is_complete());
    bank.squash(); // Bank may not be a root
    bank.rehash(); // Bank accounts may have been manually modified by the caller
    bank.force_flush_accounts_cache();
    bank.clean_accounts(Some(bank.slot()));
    let calculated_accounts_hash =
        bank.update_accounts_hash(CalcAccountsHashDataSource::Storages, false, false);

    let snapshot_storages = bank.get_snapshot_storages(None);
    let status_cache_slot_deltas = bank.status_cache.read().unwrap().root_slot_deltas();
    let accounts_package = AccountsPackage::new_for_snapshot(
        AccountsPackageKind::Snapshot(SnapshotKind::FullSnapshot),
        bank,
        snapshot_storages,
        status_cache_slot_deltas,
        None,
    );

    let accounts_hash = bank
        .get_accounts_hash()
        .expect("accounts hash is required for snapshot");
    assert_eq!(accounts_hash, calculated_accounts_hash);
    let snapshot_package = SnapshotPackage::new(accounts_package, accounts_hash.into(), None);

    let snapshot_config = SnapshotConfig {
        full_snapshot_archives_dir: full_snapshot_archives_dir.as_ref().to_path_buf(),
        incremental_snapshot_archives_dir: incremental_snapshot_archives_dir.as_ref().to_path_buf(),
        bank_snapshots_dir: bank_snapshots_dir.as_ref().to_path_buf(),
        archive_format,
        snapshot_version,
        ..Default::default()
    };
    let snapshot_archive_info =
        snapshot_utils::serialize_and_archive_snapshot_package(snapshot_package, &snapshot_config)?;

    Ok(FullSnapshotArchiveInfo::new(snapshot_archive_info))
}

/// Convenience function to create an incremental snapshot archive out of any Bank, regardless of
/// state.  The Bank will be frozen during the process.
/// This is only called from ledger-tool or tests. Warping is a special case as well.
///
/// Requires:
///     - `bank` is complete
///     - `bank`'s slot is greater than `full_snapshot_slot`
pub fn bank_to_incremental_snapshot_archive(
    bank_snapshots_dir: impl AsRef<Path>,
    bank: &Bank,
    full_snapshot_slot: Slot,
    snapshot_version: Option<SnapshotVersion>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    archive_format: ArchiveFormat,
) -> snapshot_utils::Result<IncrementalSnapshotArchiveInfo> {
    let snapshot_version = snapshot_version.unwrap_or_default();

    assert!(bank.is_complete());
    assert!(bank.slot() > full_snapshot_slot);
    bank.squash(); // Bank may not be a root
    bank.rehash(); // Bank accounts may have been manually modified by the caller
    bank.force_flush_accounts_cache();
    bank.clean_accounts(Some(full_snapshot_slot));
    let calculated_incremental_accounts_hash =
        bank.update_incremental_accounts_hash(full_snapshot_slot);

    let snapshot_storages = bank.get_snapshot_storages(Some(full_snapshot_slot));
    let status_cache_slot_deltas = bank.status_cache.read().unwrap().root_slot_deltas();
    let accounts_package = AccountsPackage::new_for_snapshot(
        AccountsPackageKind::Snapshot(SnapshotKind::IncrementalSnapshot(full_snapshot_slot)),
        bank,
        snapshot_storages,
        status_cache_slot_deltas,
        None,
    );

    let (full_accounts_hash, full_capitalization) = bank
        .rc
        .accounts
        .accounts_db
        .get_accounts_hash(full_snapshot_slot)
        .expect("base accounts hash is required for incremental snapshot");
    let (incremental_accounts_hash, incremental_capitalization) = bank
        .rc
        .accounts
        .accounts_db
        .get_incremental_accounts_hash(bank.slot())
        .expect("incremental accounts hash is required for incremental snapshot");
    assert_eq!(
        incremental_accounts_hash,
        calculated_incremental_accounts_hash,
    );
    let bank_incremental_snapshot_persistence = BankIncrementalSnapshotPersistence {
        full_slot: full_snapshot_slot,
        full_hash: full_accounts_hash.into(),
        full_capitalization,
        incremental_hash: incremental_accounts_hash.into(),
        incremental_capitalization,
    };
    let snapshot_package = SnapshotPackage::new(
        accounts_package,
        incremental_accounts_hash.into(),
        Some(bank_incremental_snapshot_persistence),
    );

    // Note: Since the snapshot_storages above are *only* the incremental storages,
    // this bank snapshot *cannot* be used by fastboot.
    // Putting the snapshot in a tempdir effectively enforces that.
    let temp_bank_snapshots_dir = tempfile::tempdir_in(bank_snapshots_dir)?;
    let snapshot_config = SnapshotConfig {
        full_snapshot_archives_dir: full_snapshot_archives_dir.as_ref().to_path_buf(),
        incremental_snapshot_archives_dir: incremental_snapshot_archives_dir.as_ref().to_path_buf(),
        bank_snapshots_dir: temp_bank_snapshots_dir.path().to_path_buf(),
        archive_format,
        snapshot_version,
        ..Default::default()
    };
    let snapshot_archive_info =
        snapshot_utils::serialize_and_archive_snapshot_package(snapshot_package, &snapshot_config)?;

    Ok(IncrementalSnapshotArchiveInfo::new(
        full_snapshot_slot,
        snapshot_archive_info,
    ))
}
