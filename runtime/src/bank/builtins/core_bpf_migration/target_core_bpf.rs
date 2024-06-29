use {
    super::error::CoreBpfMigrationError,
    crate::bank::Bank,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        bpf_loader_upgradeable::{self, get_program_data_address, UpgradeableLoaderState},
        pubkey::Pubkey,
    },
};

/// The account details of a Core BPF program slated to be upgraded.
#[derive(Debug)]
pub(crate) struct TargetCoreBpf {
    pub program_address: Pubkey,
    pub program_data_address: Pubkey,
    pub program_data_account: AccountSharedData,
    pub upgrade_authority_address: Option<Pubkey>,
}

impl TargetCoreBpf {
    /// Collects the details of a Core BPF program and verifies it is properly
    /// configured.
    /// The program account should exist with a pointer to its data account.
    /// The program data account should exist with the correct state
    /// (a ProgramData header and the program ELF).
    pub(crate) fn new_checked(
        bank: &Bank,
        program_address: &Pubkey,
    ) -> Result<Self, CoreBpfMigrationError> {
        let program_data_address = get_program_data_address(program_address);

        // The program account should exist.
        let program_account = bank
            .get_account_with_fixed_root(program_address)
            .ok_or(CoreBpfMigrationError::AccountNotFound(*program_address))?;

        // The program account should be owned by the upgradeable loader.
        if program_account.owner() != &bpf_loader_upgradeable::id() {
            return Err(CoreBpfMigrationError::IncorrectOwner(*program_address));
        }

        // The program account should have a pointer to its data account.
        match program_account.deserialize_data::<UpgradeableLoaderState>()? {
            UpgradeableLoaderState::Program {
                programdata_address,
            } if programdata_address == program_data_address => (),
            _ => {
                return Err(CoreBpfMigrationError::InvalidProgramAccount(
                    *program_address,
                ))
            }
        }

        // The program data account should exist.
        let program_data_account = bank
            .get_account_with_fixed_root(&program_data_address)
            .ok_or(CoreBpfMigrationError::ProgramHasNoDataAccount(
                *program_address,
            ))?;

        // The program data account should be owned by the upgradeable loader.
        if program_data_account.owner() != &bpf_loader_upgradeable::id() {
            return Err(CoreBpfMigrationError::IncorrectOwner(program_data_address));
        }

        // The program data account should have the correct state.
        let programdata_metadata_size = UpgradeableLoaderState::size_of_programdata_metadata();
        if program_data_account.data().len() >= programdata_metadata_size {
            if let UpgradeableLoaderState::ProgramData {
                upgrade_authority_address,
                ..
            } = bincode::deserialize(&program_data_account.data()[..programdata_metadata_size])?
            {
                return Ok(Self {
                    program_address: *program_address,
                    program_data_address,
                    program_data_account,
                    upgrade_authority_address,
                });
            }
        }
        Err(CoreBpfMigrationError::InvalidProgramDataAccount(
            program_data_address,
        ))
    }
}
