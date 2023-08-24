#![allow(dead_code)]

pub mod byte_block;
pub mod error;
pub mod file;
pub mod footer;
pub mod hot;
pub mod index;
pub mod meta;
pub mod mmap_utils;
pub mod readable;
pub mod writer;

use {
    crate::{
        account_storage::meta::{StorableAccountsWithHashesAndWriteVersions, StoredAccountInfo},
        storable_accounts::StorableAccounts,
    },
    error::TieredStorageError,
    footer::{AccountBlockFormat, AccountMetaFormat, OwnersBlockFormat},
    index::AccountIndexFormat,
    once_cell::sync::OnceCell,
    readable::TieredStorageReader,
    solana_sdk::{account::ReadableAccount, hash::Hash},
    std::{
        borrow::Borrow,
        fs::OpenOptions,
        path::{Path, PathBuf},
    },
    writer::TieredStorageWriter,
};

pub type TieredStorageResult<T> = Result<T, TieredStorageError>;

/// The struct that defines the formats of all building blocks of a
/// TieredStorage.
#[derive(Clone, Debug)]
pub struct TieredStorageFormat {
    pub meta_entry_size: usize,
    pub account_meta_format: AccountMetaFormat,
    pub owners_block_format: OwnersBlockFormat,
    pub account_index_format: AccountIndexFormat,
    pub account_block_format: AccountBlockFormat,
}

#[derive(Debug)]
pub struct TieredStorage {
    reader: OnceCell<TieredStorageReader>,
    format: Option<TieredStorageFormat>,
    path: PathBuf,
}

impl Drop for TieredStorage {
    fn drop(&mut self) {
        if let Err(err) = fs_err::remove_file(&self.path) {
            panic!("TieredStorage failed to remove backing storage file: {err}");
        }
    }
}

impl TieredStorage {
    /// Creates a new writable instance of TieredStorage based on the
    /// specified path and TieredStorageFormat.
    ///
    /// Note that the actual file will not be created until write_accounts
    /// is called.
    pub fn new_writable(path: impl Into<PathBuf>, format: TieredStorageFormat) -> Self {
        Self {
            reader: OnceCell::<TieredStorageReader>::new(),
            format: Some(format),
            path: path.into(),
        }
    }

    /// Creates a new read-only instance of TieredStorage from the
    /// specified path.
    pub fn new_readonly(path: impl Into<PathBuf>) -> TieredStorageResult<Self> {
        let path = path.into();
        Ok(Self {
            reader: OnceCell::with_value(TieredStorageReader::new_from_path(&path)?),
            format: None,
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
    /// instance.  TieredStorageError::AttemptToUpdateReadOnly will be returned
    /// if this function is invoked more than once on the same TieredStorage
    /// instance.
    pub fn write_accounts<
        'a,
        'b,
        T: ReadableAccount + Sync,
        U: StorableAccounts<'a, T>,
        V: Borrow<Hash>,
    >(
        &self,
        accounts: &StorableAccountsWithHashesAndWriteVersions<'a, 'b, T, U, V>,
        skip: usize,
    ) -> TieredStorageResult<Vec<StoredAccountInfo>> {
        if self.is_read_only() {
            return Err(TieredStorageError::AttemptToUpdateReadOnly(
                self.path.to_path_buf(),
            ));
        }

        let result = {
            // self.format must be Some as write_accounts can only be called on a
            // TieredStorage instance created via new_writable() where its format
            // field is required.
            let writer = TieredStorageWriter::new(&self.path, self.format.as_ref().unwrap())?;
            writer.write_accounts(accounts, skip)
        };

        // panic here if self.reader.get() is not None as self.reader can only be
        // None since we have passed `is_read_only()` check previously, indicating
        // self.reader is not yet set.
        self.reader
            .set(TieredStorageReader::new_from_path(&self.path)?)
            .unwrap();

        result
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
    pub fn file_size(&self) -> TieredStorageResult<u64> {
        let file = OpenOptions::new().read(true).open(&self.path);

        Ok(file
            .and_then(|file| file.metadata())
            .map(|metadata| metadata.len())
            .unwrap_or(0))
    }
}
