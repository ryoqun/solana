use {
    crate::{
        accounts_db::{
            AccountShrinkThreshold, AccountsDbConfig, SnapshotStorage, SnapshotStorages,
        },
        accounts_index::AccountSecondaryIndexes,
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        bank::{Bank, BankSlotDelta},
        builtins::Builtins,
        hardened_unpack::{unpack_snapshot, ParallelSelector, UnpackError, UnpackedAppendVecMap},
        serde_snapshot::{bank_from_streams, bank_to_stream, SerdeStyle, SnapshotStreams},
        shared_buffer_reader::{SharedBuffer, SharedBufferReader},
        snapshot_archive_info::{
            FullSnapshotArchiveInfo, IncrementalSnapshotArchiveInfo, SnapshotArchiveInfoGetter,
        },
        snapshot_package::{
            AccountsPackage, AccountsPackageSendError, AccountsPackageSender, SnapshotPackage,
            SnapshotType,
        },
    },
    bincode::{config::Options, serialize_into},
    bzip2::bufread::BzDecoder,
    flate2::read::GzDecoder,
    lazy_static::lazy_static,
    log::*,
    rayon::prelude::*,
    regex::Regex,
    solana_measure::measure::Measure,
    solana_sdk::{clock::Slot, genesis_config::GenesisConfig, hash::Hash, pubkey::Pubkey},
    std::{
        cmp::{max, Ordering},
        collections::HashSet,
        fmt,
        fs::{self, File},
        io::{BufReader, BufWriter, Error as IoError, ErrorKind, Read, Seek, Write},
        path::{Path, PathBuf},
        process::ExitStatus,
        str::FromStr,
        sync::Arc,
    },
    tar::{self, Archive},
    tempfile::TempDir,
    thiserror::Error,
};

pub const SNAPSHOT_STATUS_CACHE_FILE_NAME: &str = "status_cache";
pub const DEFAULT_FULL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS: Slot = 25_000;
pub const DEFAULT_INCREMENTAL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS: Slot = 100;
const MAX_SNAPSHOT_DATA_FILE_SIZE: u64 = 32 * 1024 * 1024 * 1024; // 32 GiB
const MAX_SNAPSHOT_VERSION_FILE_SIZE: u64 = 8; // byte
const VERSION_STRING_V1_2_0: &str = "1.2.0";
const DEFAULT_SNAPSHOT_VERSION: SnapshotVersion = SnapshotVersion::V1_2_0;
pub(crate) const TMP_BANK_SNAPSHOT_PREFIX: &str = "tmp-bank-snapshot-";
pub const TMP_SNAPSHOT_ARCHIVE_PREFIX: &str = "tmp-snapshot-archive-";
pub const MAX_BANK_SNAPSHOTS_TO_RETAIN: usize = 8; // Save some bank snapshots but not too many
pub const DEFAULT_MAX_FULL_SNAPSHOT_ARCHIVES_TO_RETAIN: usize = 2;
pub const DEFAULT_MAX_INCREMENTAL_SNAPSHOT_ARCHIVES_TO_RETAIN: usize = 4;
pub const FULL_SNAPSHOT_ARCHIVE_FILENAME_REGEX: &str = r"^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar|tar\.bz2|tar\.zst|tar\.gz)$";
pub const INCREMENTAL_SNAPSHOT_ARCHIVE_FILENAME_REGEX: &str = r"^incremental-snapshot-(?P<base>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar|tar\.bz2|tar\.zst|tar\.gz)$";

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SnapshotVersion {
    V1_2_0,
}

impl Default for SnapshotVersion {
    fn default() -> Self {
        DEFAULT_SNAPSHOT_VERSION
    }
}

impl fmt::Display for SnapshotVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(From::from(*self))
    }
}

impl From<SnapshotVersion> for &'static str {
    fn from(snapshot_version: SnapshotVersion) -> &'static str {
        match snapshot_version {
            SnapshotVersion::V1_2_0 => VERSION_STRING_V1_2_0,
        }
    }
}

impl FromStr for SnapshotVersion {
    type Err = &'static str;

    fn from_str(version_string: &str) -> std::result::Result<Self, Self::Err> {
        // Remove leading 'v' or 'V' from slice
        let version_string = if version_string
            .get(..1)
            .map_or(false, |s| s.eq_ignore_ascii_case("v"))
        {
            &version_string[1..]
        } else {
            version_string
        };
        match version_string {
            VERSION_STRING_V1_2_0 => Ok(SnapshotVersion::V1_2_0),
            _ => Err("unsupported snapshot version"),
        }
    }
}

impl SnapshotVersion {
    pub fn as_str(self) -> &'static str {
        <&str as From<Self>>::from(self)
    }

    fn maybe_from_string(version_string: &str) -> Option<SnapshotVersion> {
        version_string.parse::<Self>().ok()
    }
}

/// The different archive formats used for snapshots
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArchiveFormat {
    TarBzip2,
    TarGzip,
    TarZstd,
    Tar,
}

/// A slot and the path to its bank snapshot
#[derive(PartialEq, Eq, Debug)]
pub struct BankSnapshotInfo {
    pub slot: Slot,
    pub snapshot_path: PathBuf,
}

impl PartialOrd for BankSnapshotInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Order BankSnapshotInfo by slot (ascending), which practially is sorting chronologically
impl Ord for BankSnapshotInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.slot.cmp(&other.slot)
    }
}

/// Helper type when rebuilding from snapshots.  Designed to handle when rebuilding from just a
/// full snapshot, or from both a full snapshot and an incremental snapshot.
#[derive(Debug)]
struct SnapshotRootPaths {
    full_snapshot_root_file_path: PathBuf,
    incremental_snapshot_root_file_path: Option<PathBuf>,
}

/// Helper type to bundle up the results from `unarchive_snapshot()`
#[derive(Debug)]
struct UnarchivedSnapshot {
    #[allow(dead_code)]
    unpack_dir: TempDir,
    unpacked_append_vec_map: UnpackedAppendVecMap,
    unpacked_snapshots_dir_and_version: UnpackedSnapshotsDirAndVersion,
    measure_untar: Measure,
}

/// Helper type for passing around the unpacked snapshots dir and the snapshot version together
#[derive(Debug)]
struct UnpackedSnapshotsDirAndVersion {
    unpacked_snapshots_dir: PathBuf,
    snapshot_version: String,
}

#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialize(#[from] bincode::Error),

    #[error("archive generation failure {0}")]
    ArchiveGenerationFailure(ExitStatus),

    #[error("storage path symlink is invalid")]
    StoragePathSymlinkInvalid,

    #[error("Unpack error: {0}")]
    UnpackError(#[from] UnpackError),

    #[error("accounts package send error")]
    AccountsPackageSendError(#[from] AccountsPackageSendError),

    #[error("source({1}) - I/O error: {0}")]
    IoWithSource(std::io::Error, &'static str),

    #[error("could not get file name from path: {}", .0.display())]
    PathToFileNameError(PathBuf),

    #[error("could not get str from file name: {}", .0.display())]
    FileNameToStrError(PathBuf),

    #[error("could not parse snapshot archive's file name: {0}")]
    ParseSnapshotArchiveFileNameError(String),

    #[error("snapshots are incompatible: full snapshot slot ({0}) and incremental snapshot base slot ({1}) do not match")]
    MismatchedBaseSlot(Slot, Slot),

    #[error("no snapshot archives to load from")]
    NoSnapshotArchives,

    #[error("snapshot has mismatch: deserialized bank: {:?}, snapshot archive info: {:?}", .0, .1)]
    MismatchedSlotHash((Slot, Hash), (Slot, Hash)),
}
pub type Result<T> = std::result::Result<T, SnapshotError>;

fn get_archive_ext(archive_format: ArchiveFormat) -> &'static str {
    match archive_format {
        ArchiveFormat::TarBzip2 => "tar.bz2",
        ArchiveFormat::TarGzip => "tar.gz",
        ArchiveFormat::TarZstd => "tar.zst",
        ArchiveFormat::Tar => "tar",
    }
}

/// If the validator halts in the middle of `archive_snapshot_package()`, the temporary staging
/// directory won't be cleaned up.  Call this function to clean them up.
pub fn remove_tmp_snapshot_archives(snapshot_archives_dir: impl AsRef<Path>) {
    if let Ok(entries) = fs::read_dir(snapshot_archives_dir) {
        for entry in entries.filter_map(|entry| entry.ok()) {
            let file_name = entry
                .file_name()
                .into_string()
                .unwrap_or_else(|_| String::new());
            if file_name.starts_with(TMP_SNAPSHOT_ARCHIVE_PREFIX) {
                if entry.path().is_file() {
                    fs::remove_file(entry.path())
                } else {
                    fs::remove_dir_all(entry.path())
                }
                .unwrap_or_else(|err| {
                    warn!("Failed to remove {}: {}", entry.path().display(), err)
                });
            }
        }
    }
}

/// Make a snapshot archive out of the snapshot package
pub fn archive_snapshot_package(
    snapshot_package: &SnapshotPackage,
    maximum_full_snapshot_archives_to_retain: usize,
    maximum_incremental_snapshot_archives_to_retain: usize,
) -> Result<()> {
    info!(
        "Generating snapshot archive for slot {}",
        snapshot_package.slot()
    );

    serialize_status_cache(
        snapshot_package.slot(),
        &snapshot_package.slot_deltas,
        &snapshot_package
            .snapshot_links
            .path()
            .join(SNAPSHOT_STATUS_CACHE_FILE_NAME),
    )?;

    let mut timer = Measure::start("snapshot_package-package_snapshots");
    let tar_dir = snapshot_package
        .path()
        .parent()
        .expect("Tar output path is invalid");

    fs::create_dir_all(tar_dir)
        .map_err(|e| SnapshotError::IoWithSource(e, "create archive path"))?;

    // Create the staging directories
    let staging_dir_prefix = TMP_SNAPSHOT_ARCHIVE_PREFIX;
    let staging_dir = tempfile::Builder::new()
        .prefix(&format!(
            "{}{}-",
            staging_dir_prefix,
            snapshot_package.slot()
        ))
        .tempdir_in(tar_dir)
        .map_err(|e| SnapshotError::IoWithSource(e, "create archive tempdir"))?;

    let staging_accounts_dir = staging_dir.path().join("accounts");
    let staging_snapshots_dir = staging_dir.path().join("snapshots");
    let staging_version_file = staging_dir.path().join("version");
    fs::create_dir_all(&staging_accounts_dir)
        .map_err(|e| SnapshotError::IoWithSource(e, "create staging path"))?;

    // Add the snapshots to the staging directory
    symlink::symlink_dir(
        snapshot_package.snapshot_links.path(),
        &staging_snapshots_dir,
    )
    .map_err(|e| SnapshotError::IoWithSource(e, "create staging symlinks"))?;

    // Add the AppendVecs into the compressible list
    for storage in snapshot_package.snapshot_storages.iter().flatten() {
        storage.flush()?;
        let storage_path = storage.get_path();
        let output_path = staging_accounts_dir.join(crate::append_vec::AppendVec::file_name(
            storage.slot(),
            storage.append_vec_id(),
        ));

        // `storage_path` - The file path where the AppendVec itself is located
        // `output_path` - The file path where the AppendVec will be placed in the staging directory.
        let storage_path =
            fs::canonicalize(storage_path).expect("Could not get absolute path for accounts");
        symlink::symlink_file(storage_path, &output_path)
            .map_err(|e| SnapshotError::IoWithSource(e, "create storage symlink"))?;
        if !output_path.is_file() {
            return Err(SnapshotError::StoragePathSymlinkInvalid);
        }
    }

    // Write version file
    {
        let mut f = fs::File::create(staging_version_file)
            .map_err(|e| SnapshotError::IoWithSource(e, "create version file"))?;
        f.write_all(snapshot_package.snapshot_version.as_str().as_bytes())
            .map_err(|e| SnapshotError::IoWithSource(e, "write version file"))?;
    }

    let file_ext = get_archive_ext(snapshot_package.archive_format());

    // Tar the staging directory into the archive at `archive_path`
    let archive_path = tar_dir.join(format!(
        "{}{}.{}",
        staging_dir_prefix,
        snapshot_package.slot(),
        file_ext
    ));

    {
        let mut archive_file = fs::File::create(&archive_path)?;

        let do_archive_files = |encoder: &mut dyn Write| -> Result<()> {
            let mut archive = tar::Builder::new(encoder);
            for dir in ["accounts", "snapshots"] {
                archive.append_dir_all(dir, staging_dir.as_ref().join(dir))?;
            }
            archive.append_path_with_name(staging_dir.as_ref().join("version"), "version")?;
            archive.into_inner()?;
            Ok(())
        };

        match snapshot_package.archive_format() {
            ArchiveFormat::TarBzip2 => {
                let mut encoder =
                    bzip2::write::BzEncoder::new(archive_file, bzip2::Compression::best());
                do_archive_files(&mut encoder)?;
                encoder.finish()?;
            }
            ArchiveFormat::TarGzip => {
                let mut encoder =
                    flate2::write::GzEncoder::new(archive_file, flate2::Compression::default());
                do_archive_files(&mut encoder)?;
                encoder.finish()?;
            }
            ArchiveFormat::TarZstd => {
                let mut encoder = zstd::stream::Encoder::new(archive_file, 0)?;
                do_archive_files(&mut encoder)?;
                encoder.finish()?;
            }
            ArchiveFormat::Tar => {
                do_archive_files(&mut archive_file)?;
            }
        };
    }

    // Atomically move the archive into position for other validators to find
    let metadata = fs::metadata(&archive_path)
        .map_err(|e| SnapshotError::IoWithSource(e, "archive path stat"))?;
    fs::rename(&archive_path, &snapshot_package.path())
        .map_err(|e| SnapshotError::IoWithSource(e, "archive path rename"))?;

    purge_old_snapshot_archives(
        tar_dir,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    );

    timer.stop();
    info!(
        "Successfully created {:?}. slot: {}, elapsed ms: {}, size={}",
        snapshot_package.path(),
        snapshot_package.slot(),
        timer.as_ms(),
        metadata.len()
    );

    datapoint_info!(
        "archive-snapshot-package",
        ("slot", snapshot_package.slot(), i64),
        ("duration_ms", timer.as_ms(), i64),
        (
            if snapshot_package.snapshot_type.is_full_snapshot() {
                "full-snapshot-archive-size"
            } else {
                "incremental-snapshot-archive-size"
            },
            metadata.len(),
            i64
        ),
    );
    Ok(())
}

/// Get a list of bank snapshots in a directory
pub fn get_bank_snapshots<P>(bank_snapshots_dir: P) -> Vec<BankSnapshotInfo>
where
    P: AsRef<Path>,
{
    match fs::read_dir(&bank_snapshots_dir) {
        Ok(paths) => paths
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    e.path()
                        .file_name()
                        .and_then(|n| n.to_str().map(|s| s.parse::<Slot>().ok()))
                        .unwrap_or(None)
                })
            })
            .map(|slot| {
                let snapshot_file_name = get_snapshot_file_name(slot);
                // So nice I join-ed it twice!  The redundant `snapshot_file_name` is unintentional
                // and should be simplified.  Kept for compatibility.
                let snapshot_path = bank_snapshots_dir
                    .as_ref()
                    .join(&snapshot_file_name)
                    .join(snapshot_file_name);
                BankSnapshotInfo {
                    slot,
                    snapshot_path,
                }
            })
            .collect::<Vec<BankSnapshotInfo>>(),
        Err(err) => {
            info!(
                "Unable to read snapshots directory {}: {}",
                bank_snapshots_dir.as_ref().display(),
                err
            );
            vec![]
        }
    }
}

/// Get the bank snapshot with the highest slot in a directory
pub fn get_highest_bank_snapshot_info<P>(bank_snapshots_dir: P) -> Option<BankSnapshotInfo>
where
    P: AsRef<Path>,
{
    let mut bank_snapshot_infos = get_bank_snapshots(bank_snapshots_dir);
    bank_snapshot_infos.sort_unstable();
    bank_snapshot_infos.into_iter().rev().next()
}

pub fn serialize_snapshot_data_file<F>(data_file_path: &Path, serializer: F) -> Result<u64>
where
    F: FnOnce(&mut BufWriter<File>) -> Result<()>,
{
    serialize_snapshot_data_file_capped::<F>(
        data_file_path,
        MAX_SNAPSHOT_DATA_FILE_SIZE,
        serializer,
    )
}

pub fn deserialize_snapshot_data_file<T: Sized>(
    data_file_path: &Path,
    deserializer: impl FnOnce(&mut BufReader<File>) -> Result<T>,
) -> Result<T> {
    let wrapped_deserializer = move |streams: &mut SnapshotStreams<File>| -> Result<T> {
        deserializer(streams.full_snapshot_stream)
    };

    let wrapped_data_file_path = SnapshotRootPaths {
        full_snapshot_root_file_path: data_file_path.to_path_buf(),
        incremental_snapshot_root_file_path: None,
    };

    deserialize_snapshot_data_files_capped(
        &wrapped_data_file_path,
        MAX_SNAPSHOT_DATA_FILE_SIZE,
        wrapped_deserializer,
    )
}

fn deserialize_snapshot_data_files<T: Sized>(
    snapshot_root_paths: &SnapshotRootPaths,
    deserializer: impl FnOnce(&mut SnapshotStreams<File>) -> Result<T>,
) -> Result<T> {
    deserialize_snapshot_data_files_capped(
        snapshot_root_paths,
        MAX_SNAPSHOT_DATA_FILE_SIZE,
        deserializer,
    )
}

fn serialize_snapshot_data_file_capped<F>(
    data_file_path: &Path,
    maximum_file_size: u64,
    serializer: F,
) -> Result<u64>
where
    F: FnOnce(&mut BufWriter<File>) -> Result<()>,
{
    let data_file = File::create(data_file_path)?;
    let mut data_file_stream = BufWriter::new(data_file);
    serializer(&mut data_file_stream)?;
    data_file_stream.flush()?;

    let consumed_size = data_file_stream.stream_position()?;
    if consumed_size > maximum_file_size {
        let error_message = format!(
            "too large snapshot data file to serialize: {:?} has {} bytes",
            data_file_path, consumed_size
        );
        return Err(get_io_error(&error_message));
    }
    Ok(consumed_size)
}

fn deserialize_snapshot_data_files_capped<T: Sized>(
    snapshot_root_paths: &SnapshotRootPaths,
    maximum_file_size: u64,
    deserializer: impl FnOnce(&mut SnapshotStreams<File>) -> Result<T>,
) -> Result<T> {
    let (full_snapshot_file_size, mut full_snapshot_data_file_stream) =
        create_snapshot_data_file_stream(
            &snapshot_root_paths.full_snapshot_root_file_path,
            maximum_file_size,
        )?;

    let (incremental_snapshot_file_size, mut incremental_snapshot_data_file_stream) =
        if let Some(ref incremental_snapshot_root_file_path) =
            snapshot_root_paths.incremental_snapshot_root_file_path
        {
            let (incremental_snapshot_file_size, incremental_snapshot_data_file_stream) =
                create_snapshot_data_file_stream(
                    incremental_snapshot_root_file_path,
                    maximum_file_size,
                )?;
            (
                Some(incremental_snapshot_file_size),
                Some(incremental_snapshot_data_file_stream),
            )
        } else {
            (None, None)
        };

    let mut snapshot_streams = SnapshotStreams {
        full_snapshot_stream: &mut full_snapshot_data_file_stream,
        incremental_snapshot_stream: incremental_snapshot_data_file_stream.as_mut(),
    };
    let ret = deserializer(&mut snapshot_streams)?;

    check_deserialize_file_consumed(
        full_snapshot_file_size,
        &snapshot_root_paths.full_snapshot_root_file_path,
        &mut full_snapshot_data_file_stream,
    )?;

    if let Some(ref incremental_snapshot_root_file_path) =
        snapshot_root_paths.incremental_snapshot_root_file_path
    {
        check_deserialize_file_consumed(
            incremental_snapshot_file_size.unwrap(),
            incremental_snapshot_root_file_path,
            incremental_snapshot_data_file_stream.as_mut().unwrap(),
        )?;
    }

    Ok(ret)
}

/// Before running the deserializer function, perform common operations on the snapshot archive
/// files, such as checking the file size and opening the file into a stream.
fn create_snapshot_data_file_stream<P>(
    snapshot_root_file_path: P,
    maximum_file_size: u64,
) -> Result<(u64, BufReader<File>)>
where
    P: AsRef<Path>,
{
    let snapshot_file_size = fs::metadata(&snapshot_root_file_path)?.len();

    if snapshot_file_size > maximum_file_size {
        let error_message =
            format!(
            "too large snapshot data file to deserialize: {} has {} bytes (max size is {} bytes)",
            snapshot_root_file_path.as_ref().display(), snapshot_file_size, maximum_file_size
        );
        return Err(get_io_error(&error_message));
    }

    let snapshot_data_file = File::open(&snapshot_root_file_path)?;
    let snapshot_data_file_stream = BufReader::new(snapshot_data_file);

    Ok((snapshot_file_size, snapshot_data_file_stream))
}

/// After running the deserializer function, perform common checks to ensure the snapshot archive
/// files were consumed correctly.
fn check_deserialize_file_consumed<P>(
    file_size: u64,
    file_path: P,
    file_stream: &mut BufReader<File>,
) -> Result<()>
where
    P: AsRef<Path>,
{
    let consumed_size = file_stream.stream_position()?;

    if consumed_size != file_size {
        let error_message =
            format!(
            "invalid snapshot data file: {} has {} bytes, however consumed {} bytes to deserialize",
            file_path.as_ref().display(), file_size, consumed_size
        );
        return Err(get_io_error(&error_message));
    }

    Ok(())
}

/// Serialize a bank to a snapshot
pub fn add_bank_snapshot<P: AsRef<Path>>(
    bank_snapshots_dir: P,
    bank: &Bank,
    snapshot_storages: &[SnapshotStorage],
    snapshot_version: SnapshotVersion,
) -> Result<BankSnapshotInfo> {
    let slot = bank.slot();
    // bank_snapshots_dir/slot
    let bank_snapshots_dir = get_bank_snapshots_dir(bank_snapshots_dir, slot);
    fs::create_dir_all(&bank_snapshots_dir)?;

    // the bank snapshot is stored as bank_snapshots_dir/slot/slot
    let snapshot_bank_file_path = bank_snapshots_dir.join(get_snapshot_file_name(slot));
    info!(
        "Creating snapshot for slot {}, path: {:?}",
        slot, snapshot_bank_file_path,
    );

    let mut bank_serialize = Measure::start("bank-serialize-ms");
    let bank_snapshot_serializer = move |stream: &mut BufWriter<File>| -> Result<()> {
        let serde_style = match snapshot_version {
            SnapshotVersion::V1_2_0 => SerdeStyle::Newer,
        };
        bank_to_stream(serde_style, stream.by_ref(), bank, snapshot_storages)?;
        Ok(())
    };
    let consumed_size =
        serialize_snapshot_data_file(&snapshot_bank_file_path, bank_snapshot_serializer)?;
    bank_serialize.stop();

    // Monitor sizes because they're capped to MAX_SNAPSHOT_DATA_FILE_SIZE
    datapoint_info!(
        "snapshot-bank-file",
        ("slot", slot, i64),
        ("size", consumed_size, i64)
    );

    inc_new_counter_info!("bank-serialize-ms", bank_serialize.as_ms() as usize);

    info!(
        "{} for slot {} at {:?}",
        bank_serialize, slot, snapshot_bank_file_path,
    );

    Ok(BankSnapshotInfo {
        slot,
        snapshot_path: snapshot_bank_file_path,
    })
}

fn serialize_status_cache(
    slot: Slot,
    slot_deltas: &[BankSlotDelta],
    status_cache_path: &Path,
) -> Result<()> {
    let mut status_cache_serialize = Measure::start("status_cache_serialize-ms");
    let consumed_size = serialize_snapshot_data_file(status_cache_path, |stream| {
        serialize_into(stream, slot_deltas)?;
        Ok(())
    })?;
    status_cache_serialize.stop();

    // Monitor sizes because they're capped to MAX_SNAPSHOT_DATA_FILE_SIZE
    datapoint_info!(
        "snapshot-status-cache-file",
        ("slot", slot, i64),
        ("size", consumed_size, i64)
    );

    inc_new_counter_info!(
        "serialize-status-cache-ms",
        status_cache_serialize.as_ms() as usize
    );
    Ok(())
}

/// Remove the snapshot directory for this slot
pub fn remove_bank_snapshot<P>(slot: Slot, bank_snapshots_dir: P) -> Result<()>
where
    P: AsRef<Path>,
{
    let bank_snapshot_dir = get_bank_snapshots_dir(&bank_snapshots_dir, slot);
    fs::remove_dir_all(bank_snapshot_dir)?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct BankFromArchiveTimings {
    pub rebuild_bank_from_snapshots_us: u64,
    pub full_snapshot_untar_us: u64,
    pub incremental_snapshot_untar_us: u64,
    pub verify_snapshot_bank_us: u64,
}

// From testing, 4 seems to be a sweet spot for ranges of 60M-360M accounts and 16-64 cores. This may need to be tuned later.
const PARALLEL_UNTAR_READERS_DEFAULT: usize = 4;

/// Rebuild bank from snapshot archives.  Handles either just a full snapshot, or both a full
/// snapshot and an incremental snapshot.
#[allow(clippy::too_many_arguments)]
pub fn bank_from_snapshot_archives(
    account_paths: &[PathBuf],
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archive_info: &FullSnapshotArchiveInfo,
    incremental_snapshot_archive_info: Option<&IncrementalSnapshotArchiveInfo>,
    genesis_config: &GenesisConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&Builtins>,
    account_secondary_indexes: AccountSecondaryIndexes,
    accounts_db_caching_enabled: bool,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    test_hash_calculation: bool,
    accounts_db_skip_shrink: bool,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
) -> Result<(Bank, BankFromArchiveTimings)> {
    check_are_snapshots_compatible(
        full_snapshot_archive_info,
        incremental_snapshot_archive_info,
    )?;

    let parallel_divisions = std::cmp::min(
        PARALLEL_UNTAR_READERS_DEFAULT,
        std::cmp::max(1, num_cpus::get() / 4),
    );

    let unarchived_full_snapshot = unarchive_snapshot(
        &bank_snapshots_dir,
        TMP_SNAPSHOT_ARCHIVE_PREFIX,
        full_snapshot_archive_info.path(),
        "snapshot untar",
        account_paths,
        full_snapshot_archive_info.archive_format(),
        parallel_divisions,
    )?;

    let mut unarchived_incremental_snapshot =
        if let Some(incremental_snapshot_archive_info) = incremental_snapshot_archive_info {
            let unarchived_incremental_snapshot = unarchive_snapshot(
                &bank_snapshots_dir,
                TMP_SNAPSHOT_ARCHIVE_PREFIX,
                incremental_snapshot_archive_info.path(),
                "incremental snapshot untar",
                account_paths,
                incremental_snapshot_archive_info.archive_format(),
                parallel_divisions,
            )?;
            Some(unarchived_incremental_snapshot)
        } else {
            None
        };

    let mut unpacked_append_vec_map = unarchived_full_snapshot.unpacked_append_vec_map;
    if let Some(ref mut unarchive_preparation_result) = unarchived_incremental_snapshot {
        let incremental_snapshot_unpacked_append_vec_map =
            std::mem::take(&mut unarchive_preparation_result.unpacked_append_vec_map);
        unpacked_append_vec_map.extend(incremental_snapshot_unpacked_append_vec_map.into_iter());
    }

    let mut measure_rebuild = Measure::start("rebuild bank from snapshots");
    let bank = rebuild_bank_from_snapshots(
        &unarchived_full_snapshot.unpacked_snapshots_dir_and_version,
        unarchived_incremental_snapshot
            .as_ref()
            .map(|unarchive_preparation_result| {
                &unarchive_preparation_result.unpacked_snapshots_dir_and_version
            }),
        account_paths,
        unpacked_append_vec_map,
        genesis_config,
        debug_keys,
        additional_builtins,
        account_secondary_indexes,
        accounts_db_caching_enabled,
        limit_load_slot_count_from_snapshot,
        shrink_ratio,
        verify_index,
        accounts_db_config,
        accounts_update_notifier,
    )?;
    measure_rebuild.stop();
    info!("{}", measure_rebuild);

    let mut measure_verify = Measure::start("verify");
    if !bank.verify_snapshot_bank(
        test_hash_calculation,
        accounts_db_skip_shrink,
        Some(full_snapshot_archive_info.slot()),
    ) && limit_load_slot_count_from_snapshot.is_none()
    {
        panic!("Snapshot bank for slot {} failed to verify", bank.slot());
    }
    measure_verify.stop();

    let timings = BankFromArchiveTimings {
        rebuild_bank_from_snapshots_us: measure_rebuild.as_us(),
        full_snapshot_untar_us: unarchived_full_snapshot.measure_untar.as_us(),
        incremental_snapshot_untar_us: unarchived_incremental_snapshot
            .map_or(0, |unarchive_preparation_result| {
                unarchive_preparation_result.measure_untar.as_us()
            }),
        verify_snapshot_bank_us: measure_verify.as_us(),
    };
    Ok((bank, timings))
}

/// Rebuild bank from snapshot archives.  This function searches `snapshot_archives_dir` for the
/// highest full snapshot and highest corresponding incremental snapshot, then rebuilds the bank.
#[allow(clippy::too_many_arguments)]
pub fn bank_from_latest_snapshot_archives(
    bank_snapshots_dir: impl AsRef<Path>,
    snapshot_archives_dir: impl AsRef<Path>,
    account_paths: &[PathBuf],
    genesis_config: &GenesisConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&Builtins>,
    account_secondary_indexes: AccountSecondaryIndexes,
    accounts_db_caching_enabled: bool,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    test_hash_calculation: bool,
    accounts_db_skip_shrink: bool,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
) -> Result<(
    Bank,
    BankFromArchiveTimings,
    FullSnapshotArchiveInfo,
    Option<IncrementalSnapshotArchiveInfo>,
)> {
    let full_snapshot_archive_info = get_highest_full_snapshot_archive_info(&snapshot_archives_dir)
        .ok_or(SnapshotError::NoSnapshotArchives)?;

    let incremental_snapshot_archive_info = get_highest_incremental_snapshot_archive_info(
        &snapshot_archives_dir,
        full_snapshot_archive_info.slot(),
    );

    info!(
        "Loading bank from full snapshot: {}, and incremental snapshot: {:?}",
        full_snapshot_archive_info.path().display(),
        incremental_snapshot_archive_info
            .as_ref()
            .map(
                |incremental_snapshot_archive_info| incremental_snapshot_archive_info
                    .path()
                    .display()
            )
    );

    let (bank, timings) = bank_from_snapshot_archives(
        account_paths,
        bank_snapshots_dir.as_ref(),
        &full_snapshot_archive_info,
        incremental_snapshot_archive_info.as_ref(),
        genesis_config,
        debug_keys,
        additional_builtins,
        account_secondary_indexes,
        accounts_db_caching_enabled,
        limit_load_slot_count_from_snapshot,
        shrink_ratio,
        test_hash_calculation,
        accounts_db_skip_shrink,
        verify_index,
        accounts_db_config,
        accounts_update_notifier,
    )?;

    verify_bank_against_expected_slot_hash(
        &bank,
        incremental_snapshot_archive_info.as_ref().map_or(
            full_snapshot_archive_info.slot(),
            |incremental_snapshot_archive_info| incremental_snapshot_archive_info.slot(),
        ),
        incremental_snapshot_archive_info.as_ref().map_or(
            *full_snapshot_archive_info.hash(),
            |incremental_snapshot_archive_info| *incremental_snapshot_archive_info.hash(),
        ),
    )?;

    Ok((
        bank,
        timings,
        full_snapshot_archive_info,
        incremental_snapshot_archive_info,
    ))
}

/// Check to make sure the deserialized bank's slot and hash matches the snapshot archive's slot
/// and hash
fn verify_bank_against_expected_slot_hash(
    bank: &Bank,
    expected_slot: Slot,
    expected_hash: Hash,
) -> Result<()> {
    let bank_slot = bank.slot();
    let bank_hash = bank.get_accounts_hash();

    if bank_slot != expected_slot || bank_hash != expected_hash {
        return Err(SnapshotError::MismatchedSlotHash(
            (bank_slot, bank_hash),
            (expected_slot, expected_hash),
        ));
    }

    Ok(())
}

/// Perform the common tasks when unarchiving a snapshot.  Handles creating the temporary
/// directories, untaring, reading the version file, and then returning those fields plus the
/// unpacked append vec map.
fn unarchive_snapshot<P, Q>(
    bank_snapshots_dir: P,
    unpacked_snapshots_dir_prefix: &'static str,
    snapshot_archive_path: Q,
    measure_name: &'static str,
    account_paths: &[PathBuf],
    archive_format: ArchiveFormat,
    parallel_divisions: usize,
) -> Result<UnarchivedSnapshot>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let unpack_dir = tempfile::Builder::new()
        .prefix(unpacked_snapshots_dir_prefix)
        .tempdir_in(bank_snapshots_dir)?;
    let unpacked_snapshots_dir = unpack_dir.path().join("snapshots");

    let mut measure_untar = Measure::start(measure_name);
    let unpacked_append_vec_map = untar_snapshot_in(
        snapshot_archive_path,
        unpack_dir.path(),
        account_paths,
        archive_format,
        parallel_divisions,
    )?;
    measure_untar.stop();
    info!("{}", measure_untar);

    let unpacked_version_file = unpack_dir.path().join("version");
    let snapshot_version = snapshot_version_from_file(&unpacked_version_file)?;

    Ok(UnarchivedSnapshot {
        unpack_dir,
        unpacked_append_vec_map,
        unpacked_snapshots_dir_and_version: UnpackedSnapshotsDirAndVersion {
            unpacked_snapshots_dir,
            snapshot_version,
        },
        measure_untar,
    })
}

/// Reads the `snapshot_version` from a file. Before opening the file, its size
/// is compared to `MAX_SNAPSHOT_VERSION_FILE_SIZE`. If the size exceeds this
/// threshold, it is not opened and an error is returned.
fn snapshot_version_from_file(path: impl AsRef<Path>) -> Result<String> {
    // Check file size.
    let file_size = fs::metadata(&path)?.len();
    if file_size > MAX_SNAPSHOT_VERSION_FILE_SIZE {
        let error_message = format!(
            "snapshot version file too large: {} has {} bytes (max size is {} bytes)",
            path.as_ref().display(),
            file_size,
            MAX_SNAPSHOT_VERSION_FILE_SIZE,
        );
        return Err(get_io_error(&error_message));
    }

    // Read snapshot_version from file.
    let mut snapshot_version = String::new();
    File::open(path).and_then(|mut f| f.read_to_string(&mut snapshot_version))?;
    Ok(snapshot_version.trim().to_string())
}

/// Check if an incremental snapshot is compatible with a full snapshot.  This is done by checking
/// if the incremental snapshot's base slot is the same as the full snapshot's slot.
fn check_are_snapshots_compatible(
    full_snapshot_archive_info: &FullSnapshotArchiveInfo,
    incremental_snapshot_archive_info: Option<&IncrementalSnapshotArchiveInfo>,
) -> Result<()> {
    if incremental_snapshot_archive_info.is_none() {
        return Ok(());
    }

    let incremental_snapshot_archive_info = incremental_snapshot_archive_info.unwrap();

    (full_snapshot_archive_info.slot() == incremental_snapshot_archive_info.base_slot())
        .then(|| ())
        .ok_or_else(|| {
            SnapshotError::MismatchedBaseSlot(
                full_snapshot_archive_info.slot(),
                incremental_snapshot_archive_info.base_slot(),
            )
        })
}

/// Get the `&str` from a `&Path`
pub fn path_to_file_name_str(path: &Path) -> Result<&str> {
    path.file_name()
        .ok_or_else(|| SnapshotError::PathToFileNameError(path.to_path_buf()))?
        .to_str()
        .ok_or_else(|| SnapshotError::FileNameToStrError(path.to_path_buf()))
}

/// Build the full snapshot archive path from its components: the snapshot archives directory, the
/// snapshot slot, the accounts hash, and the archive format.
pub fn build_full_snapshot_archive_path(
    snapshot_archives_dir: PathBuf,
    slot: Slot,
    hash: &Hash,
    archive_format: ArchiveFormat,
) -> PathBuf {
    snapshot_archives_dir.join(format!(
        "snapshot-{}-{}.{}",
        slot,
        hash,
        get_archive_ext(archive_format),
    ))
}

/// Build the incremental snapshot archive path from its components: the snapshot archives
/// directory, the snapshot base slot, the snapshot slot, the accounts hash, and the archive
/// format.
pub fn build_incremental_snapshot_archive_path(
    snapshot_archives_dir: PathBuf,
    base_slot: Slot,
    slot: Slot,
    hash: &Hash,
    archive_format: ArchiveFormat,
) -> PathBuf {
    snapshot_archives_dir.join(format!(
        "incremental-snapshot-{}-{}-{}.{}",
        base_slot,
        slot,
        hash,
        get_archive_ext(archive_format),
    ))
}

fn archive_format_from_str(archive_format: &str) -> Option<ArchiveFormat> {
    match archive_format {
        "tar.bz2" => Some(ArchiveFormat::TarBzip2),
        "tar.gz" => Some(ArchiveFormat::TarGzip),
        "tar.zst" => Some(ArchiveFormat::TarZstd),
        "tar" => Some(ArchiveFormat::Tar),
        _ => None,
    }
}

/// Parse a full snapshot archive filename into its Slot, Hash, and Archive Format
pub fn parse_full_snapshot_archive_filename(
    archive_filename: &str,
) -> Result<(Slot, Hash, ArchiveFormat)> {
    lazy_static! {
        static ref RE: Regex = Regex::new(FULL_SNAPSHOT_ARCHIVE_FILENAME_REGEX).unwrap();
    }

    let do_parse = || {
        RE.captures(archive_filename).and_then(|captures| {
            let slot = captures
                .name("slot")
                .map(|x| x.as_str().parse::<Slot>())?
                .ok()?;
            let hash = captures
                .name("hash")
                .map(|x| x.as_str().parse::<Hash>())?
                .ok()?;
            let archive_format = captures
                .name("ext")
                .map(|x| archive_format_from_str(x.as_str()))??;

            Some((slot, hash, archive_format))
        })
    };

    do_parse().ok_or_else(|| {
        SnapshotError::ParseSnapshotArchiveFileNameError(archive_filename.to_string())
    })
}

/// Parse an incremental snapshot archive filename into its base Slot, actual Slot, Hash, and Archive Format
pub fn parse_incremental_snapshot_archive_filename(
    archive_filename: &str,
) -> Result<(Slot, Slot, Hash, ArchiveFormat)> {
    lazy_static! {
        static ref RE: Regex = Regex::new(INCREMENTAL_SNAPSHOT_ARCHIVE_FILENAME_REGEX).unwrap();
    }

    let do_parse = || {
        RE.captures(archive_filename).and_then(|captures| {
            let base_slot = captures
                .name("base")
                .map(|x| x.as_str().parse::<Slot>())?
                .ok()?;
            let slot = captures
                .name("slot")
                .map(|x| x.as_str().parse::<Slot>())?
                .ok()?;
            let hash = captures
                .name("hash")
                .map(|x| x.as_str().parse::<Hash>())?
                .ok()?;
            let archive_format = captures
                .name("ext")
                .map(|x| archive_format_from_str(x.as_str()))??;

            Some((base_slot, slot, hash, archive_format))
        })
    };

    do_parse().ok_or_else(|| {
        SnapshotError::ParseSnapshotArchiveFileNameError(archive_filename.to_string())
    })
}

/// Get a list of the full snapshot archives in a directory
pub fn get_full_snapshot_archives<P>(snapshot_archives_dir: P) -> Vec<FullSnapshotArchiveInfo>
where
    P: AsRef<Path>,
{
    match fs::read_dir(&snapshot_archives_dir) {
        Err(err) => {
            info!(
                "Unable to read snapshot archives directory: err: {}, path: {}",
                err,
                snapshot_archives_dir.as_ref().display()
            );
            vec![]
        }
        Ok(files) => files
            .filter_map(|entry| {
                entry.map_or(None, |entry| {
                    FullSnapshotArchiveInfo::new_from_path(entry.path()).ok()
                })
            })
            .collect(),
    }
}

/// Get a list of the incremental snapshot archives in a directory
pub fn get_incremental_snapshot_archives<P>(
    snapshot_archives_dir: P,
) -> Vec<IncrementalSnapshotArchiveInfo>
where
    P: AsRef<Path>,
{
    match fs::read_dir(&snapshot_archives_dir) {
        Err(err) => {
            info!(
                "Unable to read snapshot archives directory: err: {}, path: {}",
                err,
                snapshot_archives_dir.as_ref().display()
            );
            vec![]
        }
        Ok(files) => files
            .filter_map(|entry| {
                entry.map_or(None, |entry| {
                    IncrementalSnapshotArchiveInfo::new_from_path(entry.path()).ok()
                })
            })
            .collect(),
    }
}

/// Get the highest slot of the full snapshot archives in a directory
pub fn get_highest_full_snapshot_archive_slot<P>(snapshot_archives_dir: P) -> Option<Slot>
where
    P: AsRef<Path>,
{
    get_highest_full_snapshot_archive_info(snapshot_archives_dir)
        .map(|full_snapshot_archive_info| full_snapshot_archive_info.slot())
}

/// Get the highest slot of the incremental snapshot archives in a directory, for a given full
/// snapshot slot
pub fn get_highest_incremental_snapshot_archive_slot<P: AsRef<Path>>(
    snapshot_archives_dir: P,
    full_snapshot_slot: Slot,
) -> Option<Slot> {
    get_highest_incremental_snapshot_archive_info(snapshot_archives_dir, full_snapshot_slot)
        .map(|incremental_snapshot_archive_info| incremental_snapshot_archive_info.slot())
}

/// Get the path (and metadata) for the full snapshot archive with the highest slot in a directory
pub fn get_highest_full_snapshot_archive_info<P>(
    snapshot_archives_dir: P,
) -> Option<FullSnapshotArchiveInfo>
where
    P: AsRef<Path>,
{
    let mut full_snapshot_archives = get_full_snapshot_archives(snapshot_archives_dir);
    full_snapshot_archives.sort_unstable();
    full_snapshot_archives.into_iter().rev().next()
}

/// Get the path for the incremental snapshot archive with the highest slot, for a given full
/// snapshot slot, in a directory
pub fn get_highest_incremental_snapshot_archive_info<P>(
    snapshot_archives_dir: P,
    full_snapshot_slot: Slot,
) -> Option<IncrementalSnapshotArchiveInfo>
where
    P: AsRef<Path>,
{
    // Since we want to filter down to only the incremental snapshot archives that have the same
    // full snapshot slot as the value passed in, perform the filtering before sorting to avoid
    // doing unnecessary work.
    let mut incremental_snapshot_archives =
        get_incremental_snapshot_archives(snapshot_archives_dir)
            .into_iter()
            .filter(|incremental_snapshot_archive_info| {
                incremental_snapshot_archive_info.base_slot() == full_snapshot_slot
            })
            .collect::<Vec<_>>();
    incremental_snapshot_archives.sort_unstable();
    incremental_snapshot_archives.into_iter().rev().next()
}

pub fn purge_old_snapshot_archives<P>(
    snapshot_archives_dir: P,
    maximum_full_snapshot_archives_to_retain: usize,
    maximum_incremental_snapshot_archives_to_retain: usize,
) where
    P: AsRef<Path>,
{
    info!(
        "Purging old snapshot archives in {}, retaining {} full snapshots and {} incremental snapshots",
        snapshot_archives_dir.as_ref().display(),
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain
    );
    let mut snapshot_archives = get_full_snapshot_archives(&snapshot_archives_dir);
    snapshot_archives.sort_unstable();
    snapshot_archives.reverse();
    // Keep the oldest snapshot so we can always play the ledger from it.
    snapshot_archives.pop();
    let max_snaps = max(1, maximum_full_snapshot_archives_to_retain);
    for old_archive in snapshot_archives.into_iter().skip(max_snaps) {
        trace!(
            "Purging old full snapshot archive: {}",
            old_archive.path().display()
        );
        fs::remove_file(old_archive.path())
            .unwrap_or_else(|err| info!("Failed to remove old full snapshot archive: {}", err));
    }

    // Purge incremental snapshots with a different base slot than the highest full snapshot slot.
    // Of the incremental snapshots with the same base slot, purge the oldest ones and retain the
    // latest.
    //
    // First split the incremental snapshot archives into two vectors:
    // - One vector will be all the incremental snapshot archives with a _different_ base slot than
    // the highest full snapshot slot.
    // - The other vector will be all the incremental snapshot archives with the _same_ base slot
    // as the highest full snapshot slot.
    //
    // To find the incremental snapshot archives to retain, first sort the second vector (the
    // _same_ base slot), then reverse (so highest slots are first) and skip the first
    // `maximum_incremental_snapshot_archives_to_retain`.
    //
    // Purge all the rest.
    let highest_full_snapshot_slot = get_highest_full_snapshot_archive_slot(&snapshot_archives_dir);
    let mut incremental_snapshot_archives_with_same_base_slot = vec![];
    let mut incremental_snapshot_archives_with_different_base_slot = vec![];
    get_incremental_snapshot_archives(&snapshot_archives_dir)
        .drain(..)
        .for_each(|incremental_snapshot_archive| {
            if Some(incremental_snapshot_archive.base_slot()) == highest_full_snapshot_slot {
                incremental_snapshot_archives_with_same_base_slot
                    .push(incremental_snapshot_archive);
            } else {
                incremental_snapshot_archives_with_different_base_slot
                    .push(incremental_snapshot_archive);
            }
        });

    incremental_snapshot_archives_with_same_base_slot.sort_unstable();

    incremental_snapshot_archives_with_different_base_slot
        .iter()
        .chain(
            incremental_snapshot_archives_with_same_base_slot
                .iter()
                .rev()
                .skip(maximum_incremental_snapshot_archives_to_retain),
        )
        .for_each(|incremental_snapshot_archive| {
            trace!(
                "Purging old incremental snapshot archive: {}",
                incremental_snapshot_archive.path().display()
            );
            fs::remove_file(incremental_snapshot_archive.path()).unwrap_or_else(|err| {
                info!("Failed to remove old incremental snapshot archive: {}", err)
            })
        });
}

fn unpack_snapshot_local<T: 'static + Read + std::marker::Send, F: Fn() -> T>(
    reader: F,
    ledger_dir: &Path,
    account_paths: &[PathBuf],
    parallel_archivers: usize,
) -> Result<UnpackedAppendVecMap> {
    assert!(parallel_archivers > 0);
    // a shared 'reader' that reads the decompressed stream once, keeps some history, and acts as a reader for multiple parallel archive readers
    let shared_buffer = SharedBuffer::new(reader());

    // allocate all readers before any readers start reading
    let readers = (0..parallel_archivers)
        .into_iter()
        .map(|_| SharedBufferReader::new(&shared_buffer))
        .collect::<Vec<_>>();

    // create 'parallel_archivers' # of parallel workers, each responsible for 1/parallel_archivers of all the files to extract.
    let all_unpacked_append_vec_map = readers
        .into_par_iter()
        .enumerate()
        .map(|(index, reader)| {
            let parallel_selector = Some(ParallelSelector {
                index,
                divisions: parallel_archivers,
            });
            let mut archive = Archive::new(reader);
            unpack_snapshot(&mut archive, ledger_dir, account_paths, parallel_selector)
        })
        .collect::<Vec<_>>();
    let mut unpacked_append_vec_map = UnpackedAppendVecMap::new();
    for h in all_unpacked_append_vec_map {
        unpacked_append_vec_map.extend(h?);
    }

    Ok(unpacked_append_vec_map)
}

fn untar_snapshot_in<P: AsRef<Path>>(
    snapshot_tar: P,
    unpack_dir: &Path,
    account_paths: &[PathBuf],
    archive_format: ArchiveFormat,
    parallel_divisions: usize,
) -> Result<UnpackedAppendVecMap> {
    let open_file = || File::open(&snapshot_tar).unwrap();
    let account_paths_map = match archive_format {
        ArchiveFormat::TarBzip2 => unpack_snapshot_local(
            || BzDecoder::new(BufReader::new(open_file())),
            unpack_dir,
            account_paths,
            parallel_divisions,
        )?,
        ArchiveFormat::TarGzip => unpack_snapshot_local(
            || GzDecoder::new(BufReader::new(open_file())),
            unpack_dir,
            account_paths,
            parallel_divisions,
        )?,
        ArchiveFormat::TarZstd => unpack_snapshot_local(
            || zstd::stream::read::Decoder::new(BufReader::new(open_file())).unwrap(),
            unpack_dir,
            account_paths,
            parallel_divisions,
        )?,
        ArchiveFormat::Tar => unpack_snapshot_local(
            || BufReader::new(open_file()),
            unpack_dir,
            account_paths,
            parallel_divisions,
        )?,
    };
    Ok(account_paths_map)
}

fn verify_unpacked_snapshots_dir_and_version(
    unpacked_snapshots_dir_and_version: &UnpackedSnapshotsDirAndVersion,
) -> Result<(SnapshotVersion, BankSnapshotInfo)> {
    info!(
        "snapshot version: {}",
        &unpacked_snapshots_dir_and_version.snapshot_version
    );

    let snapshot_version =
        SnapshotVersion::maybe_from_string(&unpacked_snapshots_dir_and_version.snapshot_version)
            .ok_or_else(|| {
                get_io_error(&format!(
                    "unsupported snapshot version: {}",
                    &unpacked_snapshots_dir_and_version.snapshot_version,
                ))
            })?;
    let mut bank_snapshot_infos =
        get_bank_snapshots(&unpacked_snapshots_dir_and_version.unpacked_snapshots_dir);
    if bank_snapshot_infos.len() > 1 {
        return Err(get_io_error("invalid snapshot format"));
    }
    bank_snapshot_infos.sort_unstable();
    let root_paths = bank_snapshot_infos
        .pop()
        .ok_or_else(|| get_io_error("No snapshots found in snapshots directory"))?;
    Ok((snapshot_version, root_paths))
}

#[allow(clippy::too_many_arguments)]
fn rebuild_bank_from_snapshots(
    full_snapshot_unpacked_snapshots_dir_and_version: &UnpackedSnapshotsDirAndVersion,
    incremental_snapshot_unpacked_snapshots_dir_and_version: Option<
        &UnpackedSnapshotsDirAndVersion,
    >,
    account_paths: &[PathBuf],
    unpacked_append_vec_map: UnpackedAppendVecMap,
    genesis_config: &GenesisConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&Builtins>,
    account_secondary_indexes: AccountSecondaryIndexes,
    accounts_db_caching_enabled: bool,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
) -> Result<Bank> {
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
        full_snapshot_root_paths.snapshot_path.display(),
        incremental_snapshot_root_paths
            .as_ref()
            .map(|paths| paths.snapshot_path.display()),
    );

    let snapshot_root_paths = SnapshotRootPaths {
        full_snapshot_root_file_path: full_snapshot_root_paths.snapshot_path,
        incremental_snapshot_root_file_path: incremental_snapshot_root_paths
            .map(|root_paths| root_paths.snapshot_path),
    };

    let bank = deserialize_snapshot_data_files(&snapshot_root_paths, |snapshot_streams| {
        Ok(
            match incremental_snapshot_version.unwrap_or(full_snapshot_version) {
                SnapshotVersion::V1_2_0 => bank_from_streams(
                    SerdeStyle::Newer,
                    snapshot_streams,
                    account_paths,
                    unpacked_append_vec_map,
                    genesis_config,
                    debug_keys,
                    additional_builtins,
                    account_secondary_indexes,
                    accounts_db_caching_enabled,
                    limit_load_slot_count_from_snapshot,
                    shrink_ratio,
                    verify_index,
                    accounts_db_config,
                    accounts_update_notifier,
                ),
            }?,
        )
    })?;

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
        .join(SNAPSHOT_STATUS_CACHE_FILE_NAME);
    let slot_deltas = deserialize_snapshot_data_file(&status_cache_path, |stream| {
        info!(
            "Rebuilding status cache from {}",
            status_cache_path.display()
        );
        let slot_deltas: Vec<BankSlotDelta> = bincode::options()
            .with_limit(MAX_SNAPSHOT_DATA_FILE_SIZE)
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .deserialize_from(stream)?;
        Ok(slot_deltas)
    })?;

    bank.src.append(&slot_deltas);

    info!("Loaded bank for slot: {}", bank.slot());
    Ok(bank)
}

fn get_snapshot_file_name(slot: Slot) -> String {
    slot.to_string()
}

fn get_bank_snapshots_dir<P: AsRef<Path>>(path: P, slot: Slot) -> PathBuf {
    path.as_ref().join(slot.to_string())
}

fn get_io_error(error: &str) -> SnapshotError {
    warn!("Snapshot Error: {:?}", error);
    SnapshotError::Io(IoError::new(ErrorKind::Other, error))
}

pub fn verify_snapshot_archive<P, Q, R>(
    snapshot_archive: P,
    snapshots_to_verify: Q,
    storages_to_verify: R,
    archive_format: ArchiveFormat,
) where
    P: AsRef<Path>,
    Q: AsRef<Path>,
    R: AsRef<Path>,
{
    let temp_dir = tempfile::TempDir::new().unwrap();
    let unpack_dir = temp_dir.path();
    untar_snapshot_in(
        snapshot_archive,
        unpack_dir,
        &[unpack_dir.to_path_buf()],
        archive_format,
        1,
    )
    .unwrap();

    // Check snapshots are the same
    let unpacked_snapshots = unpack_dir.join("snapshots");
    assert!(!dir_diff::is_different(&snapshots_to_verify, unpacked_snapshots).unwrap());

    // Check the account entries are the same
    let unpacked_accounts = unpack_dir.join("accounts");
    assert!(!dir_diff::is_different(&storages_to_verify, unpacked_accounts).unwrap());
}

/// Remove outdated bank snapshots
pub fn purge_old_bank_snapshots<P>(bank_snapshots_dir: P)
where
    P: AsRef<Path>,
{
    let mut bank_snapshot_infos = get_bank_snapshots(&bank_snapshots_dir);
    bank_snapshot_infos.sort_unstable();
    bank_snapshot_infos
        .into_iter()
        .rev()
        .skip(MAX_BANK_SNAPSHOTS_TO_RETAIN)
        .for_each(|bank_snapshot_info| {
            let r = remove_bank_snapshot(bank_snapshot_info.slot, &bank_snapshots_dir);
            if r.is_err() {
                warn!(
                    "Couldn't remove bank snapshot at: {}",
                    bank_snapshot_info.snapshot_path.display()
                );
            }
        })
}

/// Gather the necessary elements for a snapshot of the given `root_bank`.
///
/// **DEVELOPER NOTE** Any error that is returned from this function may bring down the node!  This
/// function is called from AccountsBackgroundService to handle snapshot requests.  Since taking a
/// snapshot is not permitted to fail, any errors returned here will trigger the node to shutdown.
/// So, be careful whenever adding new code that may return errors.
pub fn snapshot_bank(
    root_bank: &Bank,
    status_cache_slot_deltas: Vec<BankSlotDelta>,
    accounts_package_sender: &AccountsPackageSender,
    bank_snapshots_dir: impl AsRef<Path>,
    snapshot_archives_dir: impl AsRef<Path>,
    snapshot_version: SnapshotVersion,
    archive_format: ArchiveFormat,
    hash_for_testing: Option<Hash>,
    snapshot_type: Option<SnapshotType>,
) -> Result<()> {
    let snapshot_storages = get_snapshot_storages(root_bank, snapshot_type);

    let mut add_snapshot_time = Measure::start("add-snapshot-ms");
    let bank_snapshot_info = add_bank_snapshot(
        &bank_snapshots_dir,
        root_bank,
        &snapshot_storages,
        snapshot_version,
    )?;
    add_snapshot_time.stop();
    inc_new_counter_info!("add-snapshot-ms", add_snapshot_time.as_ms() as usize);

    let accounts_package = AccountsPackage::new(
        root_bank,
        &bank_snapshot_info,
        bank_snapshots_dir,
        status_cache_slot_deltas,
        snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        hash_for_testing,
        snapshot_type,
    )
    .expect("failed to hard link bank snapshot into a tmpdir");

    accounts_package_sender.send(accounts_package)?;

    Ok(())
}

/// Get the snapshot storages for this bank and snapshot_type
fn get_snapshot_storages(bank: &Bank, snapshot_type: Option<SnapshotType>) -> SnapshotStorages {
    let mut measure_snapshot_storages = Measure::start("snapshot-storages");
    let snapshot_storages = snapshot_type.map_or_else(SnapshotStorages::default, |snapshot_type| {
        let incremental_snapshot_base_slot = match snapshot_type {
            SnapshotType::IncrementalSnapshot(incremental_snapshot_base_slot) => {
                Some(incremental_snapshot_base_slot)
            }
            _ => None,
        };
        bank.get_snapshot_storages(incremental_snapshot_base_slot)
    });
    measure_snapshot_storages.stop();

    if let Some(snapshot_type) = snapshot_type {
        let snapshot_storages_count_name;
        let snapshot_storages_time_name;
        match snapshot_type {
            SnapshotType::FullSnapshot => {
                snapshot_storages_count_name = "full-snapshot-storages-count";
                snapshot_storages_time_name = "full-snapshot-storages-time-ms";
            }
            SnapshotType::IncrementalSnapshot(_) => {
                snapshot_storages_count_name = "incremental-snapshot-storages-count";
                snapshot_storages_time_name = "incremental-snapshot-storages-time-ms";
            }
        }
        let snapshot_storages_count = snapshot_storages.iter().map(Vec::len).sum::<usize>();
        datapoint_info!(
            "get_snapshot_storages",
            (snapshot_storages_count_name, snapshot_storages_count, i64),
            (
                snapshot_storages_time_name,
                measure_snapshot_storages.as_ms(),
                i64
            ),
        );
    }

    snapshot_storages
}

/// Convenience function to create a full snapshot archive out of any Bank, regardless of state.
/// The Bank will be frozen during the process.
///
/// Requires:
///     - `bank` is complete
pub fn bank_to_full_snapshot_archive(
    bank_snapshots_dir: impl AsRef<Path>,
    bank: &Bank,
    snapshot_version: Option<SnapshotVersion>,
    snapshot_archives_dir: impl AsRef<Path>,
    archive_format: ArchiveFormat,
    maximum_full_snapshot_archives_to_retain: usize,
    maximum_incremental_snapshot_archives_to_retain: usize,
) -> Result<FullSnapshotArchiveInfo> {
    let snapshot_version = snapshot_version.unwrap_or_default();

    assert!(bank.is_complete());
    bank.squash(); // Bank may not be a root
    bank.force_flush_accounts_cache();
    bank.clean_accounts(true, false, Some(bank.slot()));
    bank.update_accounts_hash();
    bank.rehash(); // Bank accounts may have been manually modified by the caller

    let temp_dir = tempfile::tempdir_in(bank_snapshots_dir)?;
    let snapshot_storages = bank.get_snapshot_storages(None);
    let bank_snapshot_info =
        add_bank_snapshot(&temp_dir, bank, &snapshot_storages, snapshot_version)?;

    package_and_archive_full_snapshot(
        bank,
        &bank_snapshot_info,
        &temp_dir,
        snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )
}

/// Convenience function to create an incremental snapshot archive out of any Bank, regardless of
/// state.  The Bank will be frozen during the process.
///
/// Requires:
///     - `bank` is complete
///     - `bank`'s slot is greater than `full_snapshot_slot`
pub fn bank_to_incremental_snapshot_archive(
    bank_snapshots_dir: impl AsRef<Path>,
    bank: &Bank,
    full_snapshot_slot: Slot,
    snapshot_version: Option<SnapshotVersion>,
    snapshot_archives_dir: impl AsRef<Path>,
    archive_format: ArchiveFormat,
    maximum_full_snapshot_archives_to_retain: usize,
    maximum_incremental_snapshot_archives_to_retain: usize,
) -> Result<IncrementalSnapshotArchiveInfo> {
    let snapshot_version = snapshot_version.unwrap_or_default();

    assert!(bank.is_complete());
    assert!(bank.slot() > full_snapshot_slot);
    bank.squash(); // Bank may not be a root
    bank.force_flush_accounts_cache();
    bank.clean_accounts(true, false, Some(full_snapshot_slot));
    bank.update_accounts_hash();
    bank.rehash(); // Bank accounts may have been manually modified by the caller

    let temp_dir = tempfile::tempdir_in(bank_snapshots_dir)?;
    let snapshot_storages = bank.get_snapshot_storages(Some(full_snapshot_slot));
    let bank_snapshot_info =
        add_bank_snapshot(&temp_dir, bank, &snapshot_storages, snapshot_version)?;

    package_and_archive_incremental_snapshot(
        bank,
        full_snapshot_slot,
        &bank_snapshot_info,
        &temp_dir,
        snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )
}

/// Helper function to hold shared code to package, process, and archive full snapshots
pub fn package_and_archive_full_snapshot(
    bank: &Bank,
    bank_snapshot_info: &BankSnapshotInfo,
    bank_snapshots_dir: impl AsRef<Path>,
    snapshot_archives_dir: impl AsRef<Path>,
    snapshot_storages: SnapshotStorages,
    archive_format: ArchiveFormat,
    snapshot_version: SnapshotVersion,
    maximum_full_snapshot_archives_to_retain: usize,
    maximum_incremental_snapshot_archives_to_retain: usize,
) -> Result<FullSnapshotArchiveInfo> {
    let accounts_package = AccountsPackage::new(
        bank,
        bank_snapshot_info,
        bank_snapshots_dir,
        bank.src.slot_deltas(&bank.src.roots()),
        snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        None,
        Some(SnapshotType::FullSnapshot),
    )?;

    let snapshot_package = SnapshotPackage::from(accounts_package);
    archive_snapshot_package(
        &snapshot_package,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )?;

    Ok(FullSnapshotArchiveInfo::new(
        snapshot_package.snapshot_archive_info,
    ))
}

/// Helper function to hold shared code to package, process, and archive incremental snapshots
#[allow(clippy::too_many_arguments)]
pub fn package_and_archive_incremental_snapshot(
    bank: &Bank,
    incremental_snapshot_base_slot: Slot,
    bank_snapshot_info: &BankSnapshotInfo,
    bank_snapshots_dir: impl AsRef<Path>,
    snapshot_archives_dir: impl AsRef<Path>,
    snapshot_storages: SnapshotStorages,
    archive_format: ArchiveFormat,
    snapshot_version: SnapshotVersion,
    maximum_full_snapshot_archives_to_retain: usize,
    maximum_incremental_snapshot_archives_to_retain: usize,
) -> Result<IncrementalSnapshotArchiveInfo> {
    let accounts_package = AccountsPackage::new(
        bank,
        bank_snapshot_info,
        bank_snapshots_dir,
        bank.src.slot_deltas(&bank.src.roots()),
        snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        None,
        Some(SnapshotType::IncrementalSnapshot(
            incremental_snapshot_base_slot,
        )),
    )?;

    let snapshot_package = SnapshotPackage::from(accounts_package);
    archive_snapshot_package(
        &snapshot_package,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )?;

    Ok(IncrementalSnapshotArchiveInfo::new(
        incremental_snapshot_base_slot,
        snapshot_package.snapshot_archive_info,
    ))
}

pub fn should_take_full_snapshot(
    block_height: Slot,
    full_snapshot_archive_interval_slots: Slot,
) -> bool {
    block_height % full_snapshot_archive_interval_slots == 0
}

pub fn should_take_incremental_snapshot(
    block_height: Slot,
    incremental_snapshot_archive_interval_slots: Slot,
    last_full_snapshot_slot: Option<Slot>,
) -> bool {
    block_height % incremental_snapshot_archive_interval_slots == 0
        && last_full_snapshot_slot.is_some()
}

