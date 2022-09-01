use {
    crate::{
        accounts_db::{
            AccountShrinkThreshold, AccountsDbConfig, SnapshotStorage, SnapshotStorages,
        },
        accounts_index::AccountSecondaryIndexes,
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        bank::{Bank, BankFieldsToDeserialize, BankSlotDelta},
        builtins::Builtins,
        hardened_unpack::{unpack_snapshot, ParallelSelector, UnpackError, UnpackedAppendVecMap},
        serde_snapshot::{
            bank_from_streams, bank_to_stream, fields_from_streams, SerdeStyle, SnapshotStreams,
        },
        shared_buffer_reader::{SharedBuffer, SharedBufferReader},
        snapshot_archive_info::{
            FullSnapshotArchiveInfo, IncrementalSnapshotArchiveInfo, SnapshotArchiveInfoGetter,
        },
        snapshot_package::{
            AccountsPackage, PendingAccountsPackage, SnapshotPackage, SnapshotType,
        },
        status_cache,
    },
    bincode::{config::Options, serialize_into},
    bzip2::bufread::BzDecoder,
    flate2::read::GzDecoder,
    lazy_static::lazy_static,
    log::*,
    rayon::prelude::*,
    regex::Regex,
    solana_measure::measure::Measure,
    solana_sdk::{
        clock::Slot,
        genesis_config::GenesisConfig,
        hash::Hash,
        pubkey::Pubkey,
        slot_history::{Check, SlotHistory},
    },
    std::{
        cmp::Ordering,
        collections::{HashMap, HashSet},
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

mod archive_format;
pub use archive_format::*;

pub const SNAPSHOT_STATUS_CACHE_FILENAME: &str = "status_cache";
pub const SNAPSHOT_ARCHIVE_DOWNLOAD_DIR: &str = "remote";
pub const DEFAULT_FULL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS: Slot = 25_000;
pub const DEFAULT_INCREMENTAL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS: Slot = 100;
const MAX_SNAPSHOT_DATA_FILE_SIZE: u64 = 32 * 1024 * 1024 * 1024; // 32 GiB
const MAX_SNAPSHOT_VERSION_FILE_SIZE: u64 = 8; // byte
const VERSION_STRING_V1_2_0: &str = "1.2.0";
pub(crate) const TMP_BANK_SNAPSHOT_PREFIX: &str = "tmp-bank-snapshot-";
pub const TMP_SNAPSHOT_ARCHIVE_PREFIX: &str = "tmp-snapshot-archive-";
pub const BANK_SNAPSHOT_PRE_FILENAME_EXTENSION: &str = "pre";
pub const MAX_BANK_SNAPSHOTS_TO_RETAIN: usize = 8; // Save some bank snapshots but not too many
pub const DEFAULT_MAX_FULL_SNAPSHOT_ARCHIVES_TO_RETAIN: usize = 2;
pub const DEFAULT_MAX_INCREMENTAL_SNAPSHOT_ARCHIVES_TO_RETAIN: usize = 4;
pub const FULL_SNAPSHOT_ARCHIVE_FILENAME_REGEX: &str = r"^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar|tar\.bz2|tar\.zst|tar\.gz|tar\.lz4)$";
pub const INCREMENTAL_SNAPSHOT_ARCHIVE_FILENAME_REGEX: &str = r"^incremental-snapshot-(?P<base>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar|tar\.bz2|tar\.zst|tar\.gz|tar\.lz4)$";

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SnapshotVersion {
    V1_2_0,
}

impl Default for SnapshotVersion {
    fn default() -> Self {
        SnapshotVersion::V1_2_0
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

/// Information about a bank snapshot. Namely the slot of the bank, the path to the snapshot, and
/// the type of the snapshot.
#[derive(PartialEq, Eq, Debug)]
pub struct BankSnapshotInfo {
    /// Slot of the bank
    pub slot: Slot,
    /// Path to the snapshot
    pub snapshot_path: PathBuf,
    /// Type of the snapshot
    pub snapshot_type: BankSnapshotType,
}

impl PartialOrd for BankSnapshotInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Order BankSnapshotInfo by slot (ascending), which practically is sorting chronologically
impl Ord for BankSnapshotInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.slot.cmp(&other.slot)
    }
}

/// Bank snapshots traditionally had their accounts hash calculated prior to serialization.  Since
/// the hash calculation takes a long time, an optimization has been put in to offload the accounts
/// hash calculation.  The bank serialization format has not changed, so we need another way to
/// identify if a bank snapshot contains the calculated accounts hash or not.
///
/// When a bank snapshot is first taken, it does not have the calculated accounts hash.  It is said
/// that this bank snapshot is "pre" accounts hash.  Later, when the accounts hash is calculated,
/// the bank snapshot is re-serialized, and is now "post" accounts hash.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BankSnapshotType {
    /// This bank snapshot has *not* yet had its accounts hash calculated
    Pre,
    /// This bank snapshot *has* had its accounts hash calculated
    Post,
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
#[allow(clippy::large_enum_variant)]
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

    #[error("snapshot slot deltas are invalid: {0}")]
    VerifySlotDeltas(#[from] VerifySlotDeltasError),
}
pub type Result<T> = std::result::Result<T, SnapshotError>;

/// Errors that can happen in `verify_slot_deltas()`
#[derive(Error, Debug, PartialEq, Eq)]
pub enum VerifySlotDeltasError {
    #[error("too many entries: {0} (max: {1})")]
    TooManyEntries(usize, usize),

    #[error("slot {0} is not a root")]
    SlotIsNotRoot(Slot),

    #[error("slot {0} is greater than bank slot {1}")]
    SlotGreaterThanMaxRoot(Slot, Slot),

    #[error("slot {0} has multiple entries")]
    SlotHasMultipleEntries(Slot),

    #[error("slot {0} was not found in slot history")]
    SlotNotFoundInHistory(Slot),

    #[error("slot {0} was in history but missing from slot deltas")]
    SlotNotFoundInDeltas(Slot),

    #[error("slot history is bad and cannot be used to verify slot deltas")]
    BadSlotHistory,
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
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
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
            .join(SNAPSHOT_STATUS_CACHE_FILENAME),
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

    // Tar the staging directory into the archive at `archive_path`
    let archive_path = tar_dir.join(format!(
        "{}{}.{}",
        staging_dir_prefix,
        snapshot_package.slot(),
        snapshot_package.archive_format().extension(),
    ));

    {
        let mut archive_file = fs::File::create(&archive_path)?;

        let do_archive_files = |encoder: &mut dyn Write| -> Result<()> {
            let mut archive = tar::Builder::new(encoder);
            // Serialize the version and snapshots files before accounts so we can quickly determine the version
            // and other bank fields. This is necessary if we want to interleave unpacking with reconstruction
            archive.append_path_with_name(staging_dir.as_ref().join("version"), "version")?;
            for dir in ["snapshots", "accounts"] {
                archive.append_dir_all(dir, staging_dir.as_ref().join(dir))?;
            }
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
            ArchiveFormat::TarLz4 => {
                let mut encoder = lz4::EncoderBuilder::new().level(1).build(archive_file)?;
                do_archive_files(&mut encoder)?;
                let (_output, result) = encoder.finish();
                result?
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
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
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
        (
            "archive_format",
            snapshot_package.archive_format().to_string(),
            String
        ),
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

/// Get the bank snapshots in a directory
pub fn get_bank_snapshots(bank_snapshots_dir: impl AsRef<Path>) -> Vec<BankSnapshotInfo> {
    let mut bank_snapshots = Vec::default();
    match fs::read_dir(&bank_snapshots_dir) {
        Err(err) => {
            info!(
                "Unable to read bank snapshots directory {}: {}",
                bank_snapshots_dir.as_ref().display(),
                err
            );
        }
        Ok(paths) => paths
            .filter_map(|entry| {
                // check if this entry is a directory and only a Slot
                // bank snapshots are bank_snapshots_dir/slot/slot(BANK_SNAPSHOT_PRE_FILENAME_EXTENSION)
                entry
                    .ok()
                    .filter(|entry| entry.path().is_dir())
                    .and_then(|entry| {
                        entry
                            .path()
                            .file_name()
                            .and_then(|file_name| file_name.to_str())
                            .and_then(|file_name| file_name.parse::<Slot>().ok())
                    })
            })
            .for_each(|slot| {
                // check this directory to see if there is a BankSnapshotPre and/or
                // BankSnapshotPost file
                let bank_snapshot_outer_dir = get_bank_snapshots_dir(&bank_snapshots_dir, slot);
                let bank_snapshot_post_path =
                    bank_snapshot_outer_dir.join(get_snapshot_file_name(slot));
                let mut bank_snapshot_pre_path = bank_snapshot_post_path.clone();
                bank_snapshot_pre_path.set_extension(BANK_SNAPSHOT_PRE_FILENAME_EXTENSION);

                if bank_snapshot_pre_path.is_file() {
                    bank_snapshots.push(BankSnapshotInfo {
                        slot,
                        snapshot_path: bank_snapshot_pre_path,
                        snapshot_type: BankSnapshotType::Pre,
                    });
                }

                if bank_snapshot_post_path.is_file() {
                    bank_snapshots.push(BankSnapshotInfo {
                        slot,
                        snapshot_path: bank_snapshot_post_path,
                        snapshot_type: BankSnapshotType::Post,
                    });
                }
            }),
    }
    bank_snapshots
}

/// Get the bank snapshots in a directory
///
/// This function retains only the bank snapshots of type BankSnapshotType::Pre
pub fn get_bank_snapshots_pre(bank_snapshots_dir: impl AsRef<Path>) -> Vec<BankSnapshotInfo> {
    let mut bank_snapshots = get_bank_snapshots(bank_snapshots_dir);
    bank_snapshots.retain(|bank_snapshot| bank_snapshot.snapshot_type == BankSnapshotType::Pre);
    bank_snapshots
}

/// Get the bank snapshots in a directory
///
/// This function retains only the bank snapshots of type BankSnapshotType::Post
pub fn get_bank_snapshots_post(bank_snapshots_dir: impl AsRef<Path>) -> Vec<BankSnapshotInfo> {
    let mut bank_snapshots = get_bank_snapshots(bank_snapshots_dir);
    bank_snapshots.retain(|bank_snapshot| bank_snapshot.snapshot_type == BankSnapshotType::Post);
    bank_snapshots
}

/// Get the bank snapshot with the highest slot in a directory
///
/// This function gets the highest bank snapshot of type BankSnapshotType::Pre
pub fn get_highest_bank_snapshot_pre(
    bank_snapshots_dir: impl AsRef<Path>,
) -> Option<BankSnapshotInfo> {
    do_get_highest_bank_snapshot(get_bank_snapshots_pre(bank_snapshots_dir))
}

/// Get the bank snapshot with the highest slot in a directory
///
/// This function gets the highest bank snapshot of type BankSnapshotType::Post
pub fn get_highest_bank_snapshot_post(
    bank_snapshots_dir: impl AsRef<Path>,
) -> Option<BankSnapshotInfo> {
    do_get_highest_bank_snapshot(get_bank_snapshots_post(bank_snapshots_dir))
}

fn do_get_highest_bank_snapshot(
    mut bank_snapshots: Vec<BankSnapshotInfo>,
) -> Option<BankSnapshotInfo> {
    bank_snapshots.sort_unstable();
    bank_snapshots.into_iter().rev().next()
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

    // the bank snapshot is stored as bank_snapshots_dir/slot/slot.BANK_SNAPSHOT_PRE_FILENAME_EXTENSION
    let mut bank_snapshot_path = bank_snapshots_dir.join(get_snapshot_file_name(slot));
    bank_snapshot_path.set_extension(BANK_SNAPSHOT_PRE_FILENAME_EXTENSION);

    info!(
        "Creating bank snapshot for slot {}, path: {}",
        slot,
        bank_snapshot_path.display(),
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
        serialize_snapshot_data_file(&bank_snapshot_path, bank_snapshot_serializer)?;
    bank_serialize.stop();

    // Monitor sizes because they're capped to MAX_SNAPSHOT_DATA_FILE_SIZE
    datapoint_info!(
        "snapshot-bank-file",
        ("slot", slot, i64),
        ("size", consumed_size, i64)
    );

    inc_new_counter_info!("bank-serialize-ms", bank_serialize.as_ms() as usize);

    info!(
        "{} for slot {} at {}",
        bank_serialize,
        slot,
        bank_snapshot_path.display(),
    );

    Ok(BankSnapshotInfo {
        slot,
        snapshot_path: bank_snapshot_path,
        snapshot_type: BankSnapshotType::Pre,
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

fn verify_and_unarchive_snapshots(
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archive_info: &FullSnapshotArchiveInfo,
    incremental_snapshot_archive_info: Option<&IncrementalSnapshotArchiveInfo>,
    account_paths: &[PathBuf],
) -> Result<(UnarchivedSnapshot, Option<UnarchivedSnapshot>)> {
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

    let unarchived_incremental_snapshot =
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

    Ok((unarchived_full_snapshot, unarchived_incremental_snapshot))
}

/// Utility for parsing out bank specific information from a snapshot archive. This utility can be used
/// to parse out bank specific information like the leader schedule, epoch schedule, etc.
pub fn bank_fields_from_snapshot_archives(
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
) -> Result<BankFieldsToDeserialize> {
    let full_snapshot_archive_info =
        get_highest_full_snapshot_archive_info(&full_snapshot_archives_dir)
            .ok_or(SnapshotError::NoSnapshotArchives)?;

    let incremental_snapshot_archive_info = get_highest_incremental_snapshot_archive_info(
        &incremental_snapshot_archives_dir,
        full_snapshot_archive_info.slot(),
    );

    let temp_dir = tempfile::Builder::new()
        .prefix("dummy-accounts-path")
        .tempdir()?;

    let account_paths = vec![temp_dir.path().to_path_buf()];

    let (unarchived_full_snapshot, unarchived_incremental_snapshot) =
        verify_and_unarchive_snapshots(
            &bank_snapshots_dir,
            &full_snapshot_archive_info,
            incremental_snapshot_archive_info.as_ref(),
            &account_paths,
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
    let (unarchived_full_snapshot, mut unarchived_incremental_snapshot) =
        verify_and_unarchive_snapshots(
            bank_snapshots_dir,
            full_snapshot_archive_info,
            incremental_snapshot_archive_info,
            account_paths,
        )?;

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
        accounts_db_skip_shrink || !full_snapshot_archive_info.is_remote(),
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

/// Rebuild bank from snapshot archives.  This function searches `full_snapshot_archives_dir` and `incremental_snapshot_archives_dir` for the
/// highest full snapshot and highest corresponding incremental snapshot, then rebuilds the bank.
#[allow(clippy::too_many_arguments)]
pub fn bank_from_latest_snapshot_archives(
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
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
    FullSnapshotArchiveInfo,
    Option<IncrementalSnapshotArchiveInfo>,
)> {
    let full_snapshot_archive_info =
        get_highest_full_snapshot_archive_info(&full_snapshot_archives_dir)
            .ok_or(SnapshotError::NoSnapshotArchives)?;

    let incremental_snapshot_archive_info = get_highest_incremental_snapshot_archive_info(
        &incremental_snapshot_archives_dir,
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

    datapoint_info!(
        "bank_from_snapshot_archives",
        (
            "full_snapshot_untar_us",
            timings.full_snapshot_untar_us,
            i64
        ),
        (
            "incremental_snapshot_untar_us",
            timings.incremental_snapshot_untar_us,
            i64
        ),
        (
            "rebuild_bank_from_snapshots_us",
            timings.rebuild_bank_from_snapshots_us,
            i64
        ),
        (
            "verify_snapshot_bank_us",
            timings.verify_snapshot_bank_us,
            i64
        ),
    );

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

pub fn build_snapshot_archives_remote_dir(snapshot_archives_dir: impl AsRef<Path>) -> PathBuf {
    snapshot_archives_dir
        .as_ref()
        .join(SNAPSHOT_ARCHIVE_DOWNLOAD_DIR)
}

/// Build the full snapshot archive path from its components: the snapshot archives directory, the
/// snapshot slot, the accounts hash, and the archive format.
pub fn build_full_snapshot_archive_path(
    full_snapshot_archives_dir: impl AsRef<Path>,
    slot: Slot,
    hash: &Hash,
    archive_format: ArchiveFormat,
) -> PathBuf {
    full_snapshot_archives_dir.as_ref().join(format!(
        "snapshot-{}-{}.{}",
        slot,
        hash,
        archive_format.extension(),
    ))
}

/// Build the incremental snapshot archive path from its components: the snapshot archives
/// directory, the snapshot base slot, the snapshot slot, the accounts hash, and the archive
/// format.
pub fn build_incremental_snapshot_archive_path(
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    base_slot: Slot,
    slot: Slot,
    hash: &Hash,
    archive_format: ArchiveFormat,
) -> PathBuf {
    incremental_snapshot_archives_dir.as_ref().join(format!(
        "incremental-snapshot-{}-{}-{}.{}",
        base_slot,
        slot,
        hash,
        archive_format.extension(),
    ))
}

/// Parse a full snapshot archive filename into its Slot, Hash, and Archive Format
pub(crate) fn parse_full_snapshot_archive_filename(
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
                .map(|x| x.as_str().parse::<ArchiveFormat>())?
                .ok()?;

            Some((slot, hash, archive_format))
        })
    };

    do_parse().ok_or_else(|| {
        SnapshotError::ParseSnapshotArchiveFileNameError(archive_filename.to_string())
    })
}

/// Parse an incremental snapshot archive filename into its base Slot, actual Slot, Hash, and Archive Format
pub(crate) fn parse_incremental_snapshot_archive_filename(
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
                .map(|x| x.as_str().parse::<ArchiveFormat>())?
                .ok()?;

            Some((base_slot, slot, hash, archive_format))
        })
    };

    do_parse().ok_or_else(|| {
        SnapshotError::ParseSnapshotArchiveFileNameError(archive_filename.to_string())
    })
}

/// Walk down the snapshot archive to collect snapshot archive file info
fn get_snapshot_archives<T, F>(snapshot_archives_dir: &Path, cb: F) -> Vec<T>
where
    F: Fn(PathBuf) -> Result<T>,
{
    let walk_dir = |dir: &Path| -> Vec<T> {
        let entry_iter = fs::read_dir(dir);
        match entry_iter {
            Err(err) => {
                info!(
                    "Unable to read snapshot archives directory: err: {}, path: {}",
                    err,
                    dir.display()
                );
                vec![]
            }
            Ok(entries) => entries
                .filter_map(|entry| entry.map_or(None, |entry| cb(entry.path()).ok()))
                .collect(),
        }
    };

    let mut ret = walk_dir(snapshot_archives_dir);
    let remote_dir = build_snapshot_archives_remote_dir(snapshot_archives_dir);
    if remote_dir.exists() {
        ret.append(&mut walk_dir(remote_dir.as_ref()));
    }
    ret
}

/// Get a list of the full snapshot archives from a directory
pub fn get_full_snapshot_archives(
    full_snapshot_archives_dir: impl AsRef<Path>,
) -> Vec<FullSnapshotArchiveInfo> {
    get_snapshot_archives(
        full_snapshot_archives_dir.as_ref(),
        FullSnapshotArchiveInfo::new_from_path,
    )
}

/// Get a list of the incremental snapshot archives from a directory
pub fn get_incremental_snapshot_archives(
    incremental_snapshot_archives_dir: impl AsRef<Path>,
) -> Vec<IncrementalSnapshotArchiveInfo> {
    get_snapshot_archives(
        incremental_snapshot_archives_dir.as_ref(),
        IncrementalSnapshotArchiveInfo::new_from_path,
    )
}

/// Get the highest slot of the full snapshot archives in a directory
pub fn get_highest_full_snapshot_archive_slot(
    full_snapshot_archives_dir: impl AsRef<Path>,
) -> Option<Slot> {
    get_highest_full_snapshot_archive_info(full_snapshot_archives_dir)
        .map(|full_snapshot_archive_info| full_snapshot_archive_info.slot())
}

/// Get the highest slot of the incremental snapshot archives in a directory, for a given full
/// snapshot slot
pub fn get_highest_incremental_snapshot_archive_slot(
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    full_snapshot_slot: Slot,
) -> Option<Slot> {
    get_highest_incremental_snapshot_archive_info(
        incremental_snapshot_archives_dir,
        full_snapshot_slot,
    )
    .map(|incremental_snapshot_archive_info| incremental_snapshot_archive_info.slot())
}

/// Get the path (and metadata) for the full snapshot archive with the highest slot in a directory
pub fn get_highest_full_snapshot_archive_info(
    full_snapshot_archives_dir: impl AsRef<Path>,
) -> Option<FullSnapshotArchiveInfo> {
    let mut full_snapshot_archives = get_full_snapshot_archives(full_snapshot_archives_dir);
    full_snapshot_archives.sort_unstable();
    full_snapshot_archives.into_iter().rev().next()
}

/// Get the path for the incremental snapshot archive with the highest slot, for a given full
/// snapshot slot, in a directory
pub fn get_highest_incremental_snapshot_archive_info(
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    full_snapshot_slot: Slot,
) -> Option<IncrementalSnapshotArchiveInfo> {
    // Since we want to filter down to only the incremental snapshot archives that have the same
    // full snapshot slot as the value passed in, perform the filtering before sorting to avoid
    // doing unnecessary work.
    let mut incremental_snapshot_archives =
        get_incremental_snapshot_archives(incremental_snapshot_archives_dir)
            .into_iter()
            .filter(|incremental_snapshot_archive_info| {
                incremental_snapshot_archive_info.base_slot() == full_snapshot_slot
            })
            .collect::<Vec<_>>();
    incremental_snapshot_archives.sort_unstable();
    incremental_snapshot_archives.into_iter().rev().next()
}

pub fn purge_old_snapshot_archives(
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    maximum_full_snapshot_archives_to_retain: usize,
    maximum_incremental_snapshot_archives_to_retain: usize,
) {
    info!(
        "Purging old full snapshot archives in {}, retaining up to {} full snapshots",
        full_snapshot_archives_dir.as_ref().display(),
        maximum_full_snapshot_archives_to_retain
    );

    let mut full_snapshot_archives = get_full_snapshot_archives(&full_snapshot_archives_dir);
    full_snapshot_archives.sort_unstable();
    full_snapshot_archives.reverse();

    let num_to_retain = full_snapshot_archives.len().min(
        maximum_full_snapshot_archives_to_retain
            .max(1 /* Always keep at least one full snapshot */),
    );
    trace!(
        "There are {} full snapshot archives, retaining {}",
        full_snapshot_archives.len(),
        num_to_retain,
    );

    let (full_snapshot_archives_to_retain, full_snapshot_archives_to_remove) =
        if full_snapshot_archives.is_empty() {
            None
        } else {
            Some(full_snapshot_archives.split_at(num_to_retain))
        }
        .unwrap_or_default();

    let retained_full_snapshot_slots = full_snapshot_archives_to_retain
        .iter()
        .map(|ai| ai.slot())
        .collect::<HashSet<_>>();

    fn remove_archives<T: SnapshotArchiveInfoGetter>(archives: &[T]) {
        for path in archives.iter().map(|a| a.path()) {
            trace!("Removing snapshot archive: {}", path.display());
            fs::remove_file(path)
                .unwrap_or_else(|err| info!("Failed to remove {}: {}", path.display(), err));
        }
    }
    remove_archives(full_snapshot_archives_to_remove);

    info!(
        "Purging old incremental snapshot archives in {}, retaining up to {} incremental snapshots",
        incremental_snapshot_archives_dir.as_ref().display(),
        maximum_incremental_snapshot_archives_to_retain
    );
    let mut incremental_snapshot_archives_by_base_slot = HashMap::<Slot, Vec<_>>::new();
    for incremental_snapshot_archive in
        get_incremental_snapshot_archives(&incremental_snapshot_archives_dir)
    {
        incremental_snapshot_archives_by_base_slot
            .entry(incremental_snapshot_archive.base_slot())
            .or_default()
            .push(incremental_snapshot_archive)
    }

    let highest_full_snapshot_slot = retained_full_snapshot_slots.iter().max().copied();
    for (base_slot, mut incremental_snapshot_archives) in incremental_snapshot_archives_by_base_slot
    {
        incremental_snapshot_archives.sort_unstable();
        let num_to_retain = if Some(base_slot) == highest_full_snapshot_slot {
            maximum_incremental_snapshot_archives_to_retain
        } else if retained_full_snapshot_slots.contains(&base_slot) {
            1
        } else {
            0
        };
        trace!(
            "There are {} incremental snapshot archives for base slot {}, removing {} of them",
            incremental_snapshot_archives.len(),
            base_slot,
            incremental_snapshot_archives
                .len()
                .saturating_sub(num_to_retain),
        );

        incremental_snapshot_archives.truncate(
            incremental_snapshot_archives
                .len()
                .saturating_sub(num_to_retain),
        );
        remove_archives(&incremental_snapshot_archives);
    }
}

fn unpack_snapshot_local(
    shared_buffer: SharedBuffer,
    ledger_dir: &Path,
    account_paths: &[PathBuf],
    parallel_divisions: usize,
) -> Result<UnpackedAppendVecMap> {
    assert!(parallel_divisions > 0);

    // allocate all readers before any readers start reading
    let readers = (0..parallel_divisions)
        .into_iter()
        .map(|_| SharedBufferReader::new(&shared_buffer))
        .collect::<Vec<_>>();

    // create 'parallel_divisions' # of parallel workers, each responsible for 1/parallel_divisions of all the files to extract.
    let all_unpacked_append_vec_map = readers
        .into_par_iter()
        .enumerate()
        .map(|(index, reader)| {
            let parallel_selector = Some(ParallelSelector {
                index,
                divisions: parallel_divisions,
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

fn untar_snapshot_create_shared_buffer(
    snapshot_tar: &Path,
    archive_format: ArchiveFormat,
) -> SharedBuffer {
    let open_file = || File::open(&snapshot_tar).unwrap();
    match archive_format {
        ArchiveFormat::TarBzip2 => SharedBuffer::new(BzDecoder::new(BufReader::new(open_file()))),
        ArchiveFormat::TarGzip => SharedBuffer::new(GzDecoder::new(BufReader::new(open_file()))),
        ArchiveFormat::TarZstd => SharedBuffer::new(
            zstd::stream::read::Decoder::new(BufReader::new(open_file())).unwrap(),
        ),
        ArchiveFormat::TarLz4 => {
            SharedBuffer::new(lz4::Decoder::new(BufReader::new(open_file())).unwrap())
        }
        ArchiveFormat::Tar => SharedBuffer::new(BufReader::new(open_file())),
    }
}

fn untar_snapshot_in<P: AsRef<Path>>(
    snapshot_tar: P,
    unpack_dir: &Path,
    account_paths: &[PathBuf],
    archive_format: ArchiveFormat,
    parallel_divisions: usize,
) -> Result<UnpackedAppendVecMap> {
    let shared_buffer = untar_snapshot_create_shared_buffer(snapshot_tar.as_ref(), archive_format);
    unpack_snapshot_local(shared_buffer, unpack_dir, account_paths, parallel_divisions)
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
    let mut bank_snapshots =
        get_bank_snapshots_post(&unpacked_snapshots_dir_and_version.unpacked_snapshots_dir);
    if bank_snapshots.len() > 1 {
        return Err(get_io_error("invalid snapshot format"));
    }
    let root_paths = bank_snapshots
        .pop()
        .ok_or_else(|| get_io_error("No snapshots found in snapshots directory"))?;
    Ok((snapshot_version, root_paths))
}

fn bank_fields_from_snapshots(
    full_snapshot_unpacked_snapshots_dir_and_version: &UnpackedSnapshotsDirAndVersion,
    incremental_snapshot_unpacked_snapshots_dir_and_version: Option<
        &UnpackedSnapshotsDirAndVersion,
    >,
) -> Result<BankFieldsToDeserialize> {
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

    deserialize_snapshot_data_files(&snapshot_root_paths, |snapshot_streams| {
        Ok(
            match incremental_snapshot_version.unwrap_or(full_snapshot_version) {
                SnapshotVersion::V1_2_0 => fields_from_streams(SerdeStyle::Newer, snapshot_streams)
                    .map(|(bank_fields, _accountsdb_fields)| bank_fields),
            }?,
        )
    })
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
        .join(SNAPSHOT_STATUS_CACHE_FILENAME);
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

    verify_slot_deltas(slot_deltas.as_slice(), &bank)?;

    bank.status_cache.write().unwrap().append(&slot_deltas);

    bank.prepare_rewrites_for_hash();

    info!("Loaded bank for slot: {}", bank.slot());
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

pub(crate) fn get_snapshot_file_name(slot: Slot) -> String {
    slot.to_string()
}

pub(crate) fn get_bank_snapshots_dir<P: AsRef<Path>>(path: P, slot: Slot) -> PathBuf {
    path.as_ref().join(slot.to_string())
}

fn get_io_error(error: &str) -> SnapshotError {
    warn!("Snapshot Error: {:?}", error);
    SnapshotError::Io(IoError::new(ErrorKind::Other, error))
}

#[derive(Debug, Copy, Clone)]
/// allow tests to specify what happened to the serialized format
pub enum VerifyBank {
    /// the bank's serialized format is expected to be identical to what we are comparing against
    Deterministic,
    /// the serialized bank was 'reserialized' into a non-deterministic format at the specified slot
    /// so, deserialize both files and compare deserialized results
    NonDeterministic(Slot),
}

pub fn verify_snapshot_archive<P, Q, R>(
    snapshot_archive: P,
    snapshots_to_verify: Q,
    storages_to_verify: R,
    archive_format: ArchiveFormat,
    verify_bank: VerifyBank,
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
    if let VerifyBank::NonDeterministic(slot) = verify_bank {
        // file contents may be different, but deserialized structs should be equal
        let slot = slot.to_string();
        let p1 = snapshots_to_verify.as_ref().join(&slot).join(&slot);
        let p2 = unpacked_snapshots.join(&slot).join(&slot);

        assert!(crate::serde_snapshot::compare_two_serialized_banks(&p1, &p2).unwrap());
        std::fs::remove_file(p1).unwrap();
        std::fs::remove_file(p2).unwrap();
    }

    assert!(!dir_diff::is_different(&snapshots_to_verify, unpacked_snapshots).unwrap());

    // Check the account entries are the same
    let unpacked_accounts = unpack_dir.join("accounts");
    assert!(!dir_diff::is_different(&storages_to_verify, unpacked_accounts).unwrap());
}

/// Remove outdated bank snapshots
pub fn purge_old_bank_snapshots(bank_snapshots_dir: impl AsRef<Path>) {
    let do_purge = |mut bank_snapshots: Vec<BankSnapshotInfo>| {
        bank_snapshots.sort_unstable();
        bank_snapshots
            .into_iter()
            .rev()
            .skip(MAX_BANK_SNAPSHOTS_TO_RETAIN)
            .for_each(|bank_snapshot| {
                let r = remove_bank_snapshot(bank_snapshot.slot, &bank_snapshots_dir);
                if r.is_err() {
                    warn!(
                        "Couldn't remove bank snapshot at: {}",
                        bank_snapshot.snapshot_path.display()
                    );
                }
            })
    };

    do_purge(get_bank_snapshots_pre(&bank_snapshots_dir));
    do_purge(get_bank_snapshots_post(&bank_snapshots_dir));
}

/// Gather the necessary elements for a snapshot of the given `root_bank`.
///
/// **DEVELOPER NOTE** Any error that is returned from this function may bring down the node!  This
/// function is called from AccountsBackgroundService to handle snapshot requests.  Since taking a
/// snapshot is not permitted to fail, any errors returned here will trigger the node to shutdown.
/// So, be careful whenever adding new code that may return errors.
#[allow(clippy::too_many_arguments)]
pub fn snapshot_bank(
    root_bank: &Bank,
    status_cache_slot_deltas: Vec<BankSlotDelta>,
    pending_accounts_package: &PendingAccountsPackage,
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    snapshot_version: SnapshotVersion,
    archive_format: ArchiveFormat,
    hash_for_testing: Option<Hash>,
    snapshot_type: Option<SnapshotType>,
) -> Result<()> {
    let snapshot_storages = get_snapshot_storages(root_bank);

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
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        hash_for_testing,
        snapshot_type,
    )
    .expect("failed to hard link bank snapshot into a tmpdir");

    if can_submit_accounts_package(&accounts_package, pending_accounts_package) {
        let old_accounts_package = pending_accounts_package
            .lock()
            .unwrap()
            .replace(accounts_package);
        if let Some(old_accounts_package) = old_accounts_package {
            debug!(
                "The pending AccountsPackage has been overwritten: \
                \nNew AccountsPackage slot: {}, snapshot type: {:?} \
                \nOld AccountsPackage slot: {}, snapshot type: {:?}",
                root_bank.slot(),
                snapshot_type,
                old_accounts_package.slot,
                old_accounts_package.snapshot_type,
            );
        }
    }

    Ok(())
}

/// Get the snapshot storages for this bank
fn get_snapshot_storages(bank: &Bank) -> SnapshotStorages {
    let mut measure_snapshot_storages = Measure::start("snapshot-storages");
    let snapshot_storages = bank.get_snapshot_storages(None);
    measure_snapshot_storages.stop();
    let snapshot_storages_count = snapshot_storages.iter().map(Vec::len).sum::<usize>();
    datapoint_info!(
        "get_snapshot_storages",
        ("snapshot-storages-count", snapshot_storages_count, i64),
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
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )
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
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )
}

/// Helper function to hold shared code to package, process, and archive full snapshots
#[allow(clippy::too_many_arguments)]
pub fn package_and_archive_full_snapshot(
    bank: &Bank,
    bank_snapshot_info: &BankSnapshotInfo,
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    snapshot_storages: SnapshotStorages,
    archive_format: ArchiveFormat,
    snapshot_version: SnapshotVersion,
    maximum_full_snapshot_archives_to_retain: usize,
    maximum_incremental_snapshot_archives_to_retain: usize,
) -> Result<FullSnapshotArchiveInfo> {
    let slot_deltas = bank.status_cache.read().unwrap().root_slot_deltas();
    let accounts_package = AccountsPackage::new(
        bank,
        bank_snapshot_info,
        bank_snapshots_dir,
        slot_deltas,
        &full_snapshot_archives_dir,
        &incremental_snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        None,
        Some(SnapshotType::FullSnapshot),
    )?;

    crate::serde_snapshot::reserialize_bank_with_new_accounts_hash(
        accounts_package.snapshot_links.path(),
        accounts_package.slot,
        &bank.get_accounts_hash(),
        None,
    );

    let snapshot_package = SnapshotPackage::new(accounts_package, bank.get_accounts_hash());
    archive_snapshot_package(
        &snapshot_package,
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
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
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    snapshot_storages: SnapshotStorages,
    archive_format: ArchiveFormat,
    snapshot_version: SnapshotVersion,
    maximum_full_snapshot_archives_to_retain: usize,
    maximum_incremental_snapshot_archives_to_retain: usize,
) -> Result<IncrementalSnapshotArchiveInfo> {
    let slot_deltas = bank.status_cache.read().unwrap().root_slot_deltas();
    let accounts_package = AccountsPackage::new(
        bank,
        bank_snapshot_info,
        bank_snapshots_dir,
        slot_deltas,
        &full_snapshot_archives_dir,
        &incremental_snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        None,
        Some(SnapshotType::IncrementalSnapshot(
            incremental_snapshot_base_slot,
        )),
    )?;

    crate::serde_snapshot::reserialize_bank_with_new_accounts_hash(
        accounts_package.snapshot_links.path(),
        accounts_package.slot,
        &bank.get_accounts_hash(),
        None,
    );

    let snapshot_package = SnapshotPackage::new(accounts_package, bank.get_accounts_hash());
    archive_snapshot_package(
        &snapshot_package,
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
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

/// Decide if an accounts package can be submitted to the PendingAccountsPackage
///
/// This is based on the values for `snapshot_type` in both the `accounts_package` and the
/// `pending_accounts_package`:
/// - if the new AccountsPackage is for a full snapshot, always submit
/// - if the new AccountsPackage is for an incremental snapshot, submit as long as there isn't a
///   pending full snapshot
/// - otherwise, only submit the new AccountsPackage as long as there's not a pending package
///   destined for a snapshot archive
fn can_submit_accounts_package(
    accounts_package: &AccountsPackage,
    pending_accounts_package: &PendingAccountsPackage,
) -> bool {
    match accounts_package.snapshot_type {
        Some(SnapshotType::FullSnapshot) => true,
        Some(SnapshotType::IncrementalSnapshot(_)) => pending_accounts_package
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|old_accounts_package| old_accounts_package.snapshot_type)
            .map(|old_snapshot_type| !old_snapshot_type.is_full_snapshot())
            .unwrap_or(true),
        None => pending_accounts_package
            .lock()
            .unwrap()
            .as_ref()
            .map(|old_accounts_package| old_accounts_package.snapshot_type.is_none())
            .unwrap_or(true),
    }
}
