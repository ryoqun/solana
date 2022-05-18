use {
    bzip2::bufread::BzDecoder,
    log::*,
    rand::{thread_rng, Rng},
    solana_sdk::genesis_config::{GenesisConfig, DEFAULT_GENESIS_ARCHIVE, DEFAULT_GENESIS_FILE},
    std::{
        collections::HashMap,
        fs::{self, File},
        io::{BufReader, Read},
        path::{
            Component::{self, CurDir, Normal},
            Path, PathBuf,
        },
        time::Instant,
    },
    tar::{
        Archive,
        EntryType::{Directory, GNUSparse, Regular},
    },
    thiserror::Error,
};

#[derive(Error, Debug)]
pub enum UnpackError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Archive error: {0}")]
    Archive(String),
}

pub type Result<T> = std::result::Result<T, UnpackError>;

// 64 TiB; some safe margin to the max 128 TiB in amd64 linux userspace VmSize
// (ref: https://unix.stackexchange.com/a/386555/364236)
// note that this is directly related to the mmaped data size
// so protect against insane value
// This is the file size including holes for sparse files
const MAX_SNAPSHOT_ARCHIVE_UNPACKED_APPARENT_SIZE: u64 = 64 * 1024 * 1024 * 1024 * 1024;

// 4 TiB;
// This is the actually consumed disk usage for sparse files
const MAX_SNAPSHOT_ARCHIVE_UNPACKED_ACTUAL_SIZE: u64 = 4 * 1024 * 1024 * 1024 * 1024;

const MAX_SNAPSHOT_ARCHIVE_UNPACKED_COUNT: u64 = 5_000_000;
pub const MAX_GENESIS_ARCHIVE_UNPACKED_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
const MAX_GENESIS_ARCHIVE_UNPACKED_COUNT: u64 = 100;

fn checked_total_size_sum(total_size: u64, entry_size: u64, limit_size: u64) -> Result<u64> {
    trace!(
        "checked_total_size_sum: {} + {} < {}",
        total_size,
        entry_size,
        limit_size,
    );
    let total_size = total_size.saturating_add(entry_size);
    if total_size > limit_size {
        return Err(UnpackError::Archive(format!(
            "too large archive: {} than limit: {}",
            total_size, limit_size,
        )));
    }
    Ok(total_size)
}

fn checked_total_count_increment(total_count: u64, limit_count: u64) -> Result<u64> {
    let total_count = total_count + 1;
    if total_count > limit_count {
        return Err(UnpackError::Archive(format!(
            "too many files in snapshot: {:?}",
            total_count
        )));
    }
    Ok(total_count)
}

fn check_unpack_result(unpack_result: bool, path: String) -> Result<()> {
    if !unpack_result {
        return Err(UnpackError::Archive(format!(
            "failed to unpack: {:?}",
            path
        )));
    }
    Ok(())
}

pub enum UnpackPath<'a> {
    Valid(&'a Path),
    Ignore,
    Invalid,
}

fn unpack_archive<'a, A: Read, C>(
    archive: &mut Archive<A>,
    apparent_limit_size: u64,
    actual_limit_size: u64,
    limit_count: u64,
    mut entry_checker: C,
) -> Result<()>
where
    C: FnMut(&[&str], tar::EntryType) -> UnpackPath<'a>,
{
    let mut apparent_total_size: u64 = 0;
    let mut actual_total_size: u64 = 0;
    let mut total_count: u64 = 0;

    let mut total_entries = 0;
    let mut last_log_update = Instant::now();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let path_str = path.display().to_string();

        // Although the `tar` crate safely skips at the actual unpacking, fail
        // first by ourselves when there are odd paths like including `..` or /
        // for our clearer pattern matching reasoning:
        //   https://docs.rs/tar/0.4.26/src/tar/entry.rs.html#371
        let parts = path.components().map(|p| match p {
            CurDir => Some("."),
            Normal(c) => c.to_str(),
            _ => None, // Prefix (for Windows) and RootDir are forbidden
        });

        // Reject old-style BSD directory entries that aren't explicitly tagged as directories
        let legacy_dir_entry =
            entry.header().as_ustar().is_none() && entry.path_bytes().ends_with(b"/");
        let kind = entry.header().entry_type();
        let reject_legacy_dir_entry = legacy_dir_entry && (kind != Directory);

        if parts.clone().any(|p| p.is_none()) || reject_legacy_dir_entry {
            return Err(UnpackError::Archive(format!(
                "invalid path found: {:?}",
                path_str
            )));
        }

        let parts: Vec<_> = parts.map(|p| p.unwrap()).collect();
        let unpack_dir = match entry_checker(parts.as_slice(), kind) {
            UnpackPath::Invalid => {
                return Err(UnpackError::Archive(format!(
                    "extra entry found: {:?} {:?}",
                    path_str,
                    entry.header().entry_type(),
                )));
            }
            UnpackPath::Ignore => {
                continue;
            }
            UnpackPath::Valid(unpack_dir) => unpack_dir,
        };

        apparent_total_size = checked_total_size_sum(
            apparent_total_size,
            entry.header().size()?,
            apparent_limit_size,
        )?;
        actual_total_size = checked_total_size_sum(
            actual_total_size,
            entry.header().entry_size()?,
            actual_limit_size,
        )?;
        total_count = checked_total_count_increment(total_count, limit_count)?;

        let target = sanitize_path(&entry.path()?, unpack_dir)?; // ? handles file system errors
        if target.is_none() {
            continue; // skip it
        }
        let target = target.unwrap();

        let unpack = entry.unpack(target);
        check_unpack_result(unpack.map(|_unpack| true)?, path_str)?;

        // Sanitize permissions.
        let mode = match entry.header().entry_type() {
            GNUSparse | Regular => 0o644,
            _ => 0o755,
        };
        set_perms(&unpack_dir.join(entry.path()?), mode)?;

        total_entries += 1;
        let now = Instant::now();
        if now.duration_since(last_log_update).as_secs() >= 10 {
            info!("unpacked {} entries so far...", total_entries);
            last_log_update = now;
        }
    }
    info!("unpacked {} entries total", total_entries);

    return Ok(());

    #[cfg(unix)]
    fn set_perms(dst: &Path, mode: u32) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let perm = fs::Permissions::from_mode(mode as _);
        fs::set_permissions(dst, perm)
    }

    #[cfg(windows)]
    fn set_perms(dst: &Path, _mode: u32) -> std::io::Result<()> {
        let mut perm = fs::metadata(dst)?.permissions();
        perm.set_readonly(false);
        fs::set_permissions(dst, perm)
    }
}

// return Err on file system error
// return Some(path) if path is good
// return None if we should skip this file
fn sanitize_path(entry_path: &Path, dst: &Path) -> Result<Option<PathBuf>> {
    // We cannot call unpack_in because it errors if we try to use 2 account paths.
    // So, this code is borrowed from unpack_in
    // ref: https://docs.rs/tar/*/tar/struct.Entry.html#method.unpack_in
    let mut file_dst = dst.to_path_buf();
    const SKIP: Result<Option<PathBuf>> = Ok(None);
    {
        let path = entry_path;
        for part in path.components() {
            match part {
                // Leading '/' characters, root paths, and '.'
                // components are just ignored and treated as "empty
                // components"
                Component::Prefix(..) | Component::RootDir | Component::CurDir => continue,

                // If any part of the filename is '..', then skip over
                // unpacking the file to prevent directory traversal
                // security issues.  See, e.g.: CVE-2001-1267,
                // CVE-2002-0399, CVE-2005-1918, CVE-2007-4131
                Component::ParentDir => return SKIP,

                Component::Normal(part) => file_dst.push(part),
            }
        }
    }

    // Skip cases where only slashes or '.' parts were seen, because
    // this is effectively an empty filename.
    if *dst == *file_dst {
        return SKIP;
    }

    // Skip entries without a parent (i.e. outside of FS root)
    let parent = match file_dst.parent() {
        Some(p) => p,
        None => return SKIP,
    };

    fs::create_dir_all(parent)?;

    // Here we are different than untar_in. The code for tar::unpack_in internally calling unpack is a little different.
    // ignore return value here
    validate_inside_dst(dst, parent)?;
    let target = parent.join(entry_path.file_name().unwrap());

    Ok(Some(target))
}

// copied from:
// https://github.com/alexcrichton/tar-rs/blob/d90a02f582c03dfa0fd11c78d608d0974625ae5d/src/entry.rs#L781
fn validate_inside_dst(dst: &Path, file_dst: &Path) -> Result<PathBuf> {
    // Abort if target (canonical) parent is outside of `dst`
    let canon_parent = file_dst.canonicalize().map_err(|err| {
        UnpackError::Archive(format!(
            "{} while canonicalizing {}",
            err,
            file_dst.display()
        ))
    })?;
    let canon_target = dst.canonicalize().map_err(|err| {
        UnpackError::Archive(format!("{} while canonicalizing {}", err, dst.display()))
    })?;
    if !canon_parent.starts_with(&canon_target) {
        return Err(UnpackError::Archive(format!(
            "trying to unpack outside of destination path: {}",
            canon_target.display()
        )));
    }
    Ok(canon_target)
}

/// Map from AppendVec file name to unpacked file system location
pub type UnpackedAppendVecMap = HashMap<String, PathBuf>;

// select/choose only 'index' out of each # of 'divisions' of total items.
pub struct ParallelSelector {
    pub index: usize,
    pub divisions: usize,
}

impl ParallelSelector {
    pub fn select_index(&self, index: usize) -> bool {
        index % self.divisions == self.index
    }
}

pub fn unpack_snapshot<A: Read>(
    archive: &mut Archive<A>,
    ledger_dir: &Path,
    account_paths: &[PathBuf],
    parallel_selector: Option<ParallelSelector>,
) -> Result<UnpackedAppendVecMap> {
    assert!(!account_paths.is_empty());
    let mut unpacked_append_vec_map = UnpackedAppendVecMap::new();
    let mut i = 0;

    unpack_archive(
        archive,
        MAX_SNAPSHOT_ARCHIVE_UNPACKED_APPARENT_SIZE,
        MAX_SNAPSHOT_ARCHIVE_UNPACKED_ACTUAL_SIZE,
        MAX_SNAPSHOT_ARCHIVE_UNPACKED_COUNT,
        |parts, kind| {
            if is_valid_snapshot_archive_entry(parts, kind) {
                i += 1;
                match &parallel_selector {
                    Some(parallel_selector) => {
                        if !parallel_selector.select_index(i - 1) {
                            return UnpackPath::Ignore;
                        }
                    }
                    None => {}
                };
                if let ["accounts", file] = parts {
                    // Randomly distribute the accounts files about the available `account_paths`,
                    let path_index = thread_rng().gen_range(0, account_paths.len());
                    match account_paths.get(path_index).map(|path_buf| {
                        unpacked_append_vec_map
                            .insert(file.to_string(), path_buf.join("accounts").join(file));
                        path_buf.as_path()
                    }) {
                        Some(path) => UnpackPath::Valid(path),
                        None => UnpackPath::Invalid,
                    }
                } else {
                    UnpackPath::Valid(ledger_dir)
                }
            } else {
                UnpackPath::Invalid
            }
        },
    )
    .map(|_| unpacked_append_vec_map)
}

fn all_digits(v: &str) -> bool {
    if v.is_empty() {
        return false;
    }
    for x in v.chars() {
        if !x.is_digit(10) {
            return false;
        }
    }
    true
}

fn like_storage(v: &str) -> bool {
    let mut periods = 0;
    let mut saw_numbers = false;
    for x in v.chars() {
        if !x.is_digit(10) {
            if x == '.' {
                if periods > 0 || !saw_numbers {
                    return false;
                }
                saw_numbers = false;
                periods += 1;
            } else {
                return false;
            }
        } else {
            saw_numbers = true;
        }
    }
    saw_numbers && periods == 1
}

fn is_valid_snapshot_archive_entry(parts: &[&str], kind: tar::EntryType) -> bool {
    match (parts, kind) {
        (["version"], Regular) => true,
        (["accounts"], Directory) => true,
        (["accounts", file], GNUSparse) if like_storage(file) => true,
        (["accounts", file], Regular) if like_storage(file) => true,
        (["snapshots"], Directory) => true,
        (["snapshots", "status_cache"], GNUSparse) => true,
        (["snapshots", "status_cache"], Regular) => true,
        (["snapshots", dir, file], GNUSparse) if all_digits(dir) && all_digits(file) => true,
        (["snapshots", dir, file], Regular) if all_digits(dir) && all_digits(file) => true,
        (["snapshots", dir], Directory) if all_digits(dir) => true,
        _ => false,
    }
}

pub fn open_genesis_config(
    ledger_path: &Path,
    max_genesis_archive_unpacked_size: u64,
) -> GenesisConfig {
    GenesisConfig::load(ledger_path).unwrap_or_else(|load_err| {
        let genesis_package = ledger_path.join(DEFAULT_GENESIS_ARCHIVE);
        unpack_genesis_archive(
            &genesis_package,
            ledger_path,
            max_genesis_archive_unpacked_size,
        )
        .unwrap_or_else(|unpack_err| {
            warn!(
                "Failed to open ledger genesis_config at {:?}: {}, {}",
                ledger_path, load_err, unpack_err,
            );
            std::process::exit(1);
        });

        // loading must succeed at this moment
        GenesisConfig::load(ledger_path).unwrap()
    })
}

pub fn unpack_genesis_archive(
    archive_filename: &Path,
    destination_dir: &Path,
    max_genesis_archive_unpacked_size: u64,
) -> std::result::Result<(), UnpackError> {
    info!("Extracting {:?}...", archive_filename);
    let extract_start = Instant::now();

    fs::create_dir_all(destination_dir)?;
    let tar_bz2 = File::open(&archive_filename)?;
    let tar = BzDecoder::new(BufReader::new(tar_bz2));
    let mut archive = Archive::new(tar);
    unpack_genesis(
        &mut archive,
        destination_dir,
        max_genesis_archive_unpacked_size,
    )?;
    info!(
        "Extracted {:?} in {:?}",
        archive_filename,
        Instant::now().duration_since(extract_start)
    );
    Ok(())
}

fn unpack_genesis<A: Read>(
    archive: &mut Archive<A>,
    unpack_dir: &Path,
    max_genesis_archive_unpacked_size: u64,
) -> Result<()> {
    unpack_archive(
        archive,
        max_genesis_archive_unpacked_size,
        max_genesis_archive_unpacked_size,
        MAX_GENESIS_ARCHIVE_UNPACKED_COUNT,
        |p, k| {
            if is_valid_genesis_archive_entry(p, k) {
                UnpackPath::Valid(unpack_dir)
            } else {
                UnpackPath::Invalid
            }
        },
    )
}

fn is_valid_genesis_archive_entry(parts: &[&str], kind: tar::EntryType) -> bool {
    trace!("validating: {:?} {:?}", parts, kind);
    #[allow(clippy::match_like_matches_macro)]
    match (parts, kind) {
        ([DEFAULT_GENESIS_FILE], GNUSparse) => true,
        ([DEFAULT_GENESIS_FILE], Regular) => true,
        (["rocksdb"], Directory) => true,
        (["rocksdb", _], GNUSparse) => true,
        (["rocksdb", _], Regular) => true,
        _ => false,
    }
}

