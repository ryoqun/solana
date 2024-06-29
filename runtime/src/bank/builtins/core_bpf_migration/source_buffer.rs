use {
    super::error::CoreBpfMigrationError,
    crate::bank::Bank,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        bpf_loader_upgradeable::{self, UpgradeableLoaderState},
        pubkey::Pubkey,
    },
};

/// The account details of a buffer account slated to replace a built-in
/// program.
#[derive(Debug)]
pub(crate) struct SourceBuffer {
    pub buffer_address: Pubkey,
    pub buffer_account: AccountSharedData,
}

impl SourceBuffer {
    /// Collects the details of a buffer account and verifies it exists, is
    /// owned by the upgradeable loader, and has the correct state.
    pub(crate) fn new_checked(
        bank: &Bank,
        buffer_address: &Pubkey,
    ) -> Result<Self, CoreBpfMigrationError> {
        // The buffer account should exist.
        let buffer_account = bank
            .get_account_with_fixed_root(buffer_address)
            .ok_or(CoreBpfMigrationError::AccountNotFound(*buffer_address))?;

        // The buffer account should be owned by the upgradeable loader.
        if buffer_account.owner() != &bpf_loader_upgradeable::id() {
            return Err(CoreBpfMigrationError::IncorrectOwner(*buffer_address));
        }

        // The buffer account should have the correct state.
        let buffer_metadata_size = UpgradeableLoaderState::size_of_buffer_metadata();
        if buffer_account.data().len() >= buffer_metadata_size {
            if let UpgradeableLoaderState::Buffer { .. } =
                bincode::deserialize(&buffer_account.data()[..buffer_metadata_size])?
            {
                return Ok(Self {
                    buffer_address: *buffer_address,
                    buffer_account,
                });
            }
        }
        Err(CoreBpfMigrationError::InvalidBufferAccount(*buffer_address))
    }
}
