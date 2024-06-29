#![allow(dead_code)]

pub mod byte_block;
pub mod error;
pub mod file;
pub mod footer;
pub mod hot;
pub mod index;
pub mod meta;
pub mod mmap_utils;
pub mod owners;
pub mod readable;
mod test_utils;

use {
    crate::{accounts_file::StoredAccountsInfo, storable_accounts::StorableAccounts},
    error::TieredStorageError,
    footer::{AccountBlockFormat, AccountMetaFormat},
    hot::{HotStorageWriter, HOT_FORMAT},
    index::IndexBlockFormat,
    owners::OwnersBlockFormat,
    readable::TieredStorageReader,
    std::{
        fs, io,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            OnceLock,
        },
    },
};

pub type TieredStorageResult<T> = Result<T, TieredStorageError>;

const MAX_TIERED_STORAGE_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB;

/// The struct that defines the formats of all building blocks of a
/// TieredStorage.
#[derive(Clone, Debug, PartialEq)]
pub struct TieredStorageFormat {
    pub meta_entry_size: usize,
    pub account_meta_format: AccountMetaFormat,
    pub owners_block_format: OwnersBlockFormat,
    pub index_block_format: IndexBlockFormat,
    pub account_block_format: AccountBlockFormat,
}

/// The implementation of AccountsFile for tiered-storage.
#[derive(Debug)]
pub struct TieredStorage {
    /// The internal reader instance for its accounts file.
    reader: OnceLock<TieredStorageReader>,
    /// A status flag indicating whether its file has been already written.
    already_written: AtomicBool,
    /// The path to the file that stores accounts.
    path: PathBuf,
}

impl Drop for TieredStorage {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            // Here we bypass NotFound error as the focus of the panic is to
            // detect any leakage of storage resource.
            if err.kind() != io::ErrorKind::NotFound {
                panic!(
                    "TieredStorage failed to remove backing storage file '{}': {err}",
                    self.path.display(),
                );
            }
        }
    }
}

impl TieredStorage {
    /// Creates a new writable instance of TieredStorage based on the
    /// specified path and TieredStorageFormat.
    ///
    /// Note that the actual file will not be created until write_accounts
    /// is called.
    pub fn new_writable(path: impl Into<PathBuf>) -> Self {
        Self {
            reader: OnceLock::<TieredStorageReader>::new(),
            already_written: false.into(),
            path: path.into(),
        }
    }

    /// Creates a new read-only instance of TieredStorage from the
    /// specified path.
    pub fn new_readonly(path: impl Into<PathBuf>) -> TieredStorageResult<Self> {
        let path = path.into();
        Ok(Self {
            reader: TieredStorageReader::new_from_path(&path).map(OnceLock::from)?,
            already_written: true.into(),
            path,
        })
    }

    /// Returns the path to this TieredStorage.
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Writes the specified accounts into this TieredStorage.
    ///
    /// Note that this function can only be called once per a TieredStorage
    /// instance.  Otherwise, it will trigger panic.
    pub fn write_accounts<'a>(
        &self,
        accounts: &impl StorableAccounts<'a>,
        skip: usize,
        format: &TieredStorageFormat,
    ) -> TieredStorageResult<StoredAccountsInfo> {
        let was_written = self.already_written.swap(true, Ordering::AcqRel);

        if was_written {
            panic!("cannot write same tiered storage file more than once");
        }

        if format == &HOT_FORMAT {
            let stored_accounts_info = {
                let mut writer = HotStorageWriter::new(&self.path)?;
                let stored_accounts_info = writer.write_accounts(accounts, skip)?;
                writer.flush()?;
                stored_accounts_info
            };

            // panic here if self.reader.get() is not None as self.reader can only be
            // None since a false-value `was_written` indicates the accounts file has
            // not been written previously, implying is_read_only() was also false.
            debug_assert!(!self.is_read_only());
            self.reader
                .set(TieredStorageReader::new_from_path(&self.path)?)
                .unwrap();

            Ok(stored_accounts_info)
        } else {
            Err(TieredStorageError::UnknownFormat(self.path.to_path_buf()))
        }
    }

    /// Returns the underlying reader of the TieredStorage.  None will be
    /// returned if it's is_read_only() returns false.
    pub fn reader(&self) -> Option<&TieredStorageReader> {
        self.reader.get()
    }

    /// Returns true if the TieredStorage instance is read-only.
    pub fn is_read_only(&self) -> bool {
        self.reader.get().is_some()
    }

    /// Returns the size of the underlying accounts file.
    pub fn len(&self) -> usize {
        self.reader().map_or(0, |reader| reader.len())
    }

    /// Returns whether the underlying storage is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> u64 {
        self.reader()
            .map_or(MAX_TIERED_STORAGE_FILE_SIZE, |reader| reader.capacity())
    }
}
