use {
    super::{error::CoreBpfMigrationError, CoreBpfMigrationTargetType},
    crate::bank::Bank,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        bpf_loader_upgradeable::get_program_data_address,
        native_loader::ID as NATIVE_LOADER_ID,
        pubkey::Pubkey,
    },
};

/// The account details of a built-in program to be migrated to Core BPF.
#[derive(Debug)]
pub(crate) struct TargetBuiltin {
    pub program_address: Pubkey,
    pub program_account: AccountSharedData,
    pub program_data_address: Pubkey,
}

impl TargetBuiltin {
    /// Collects the details of a built-in program and verifies it is properly
    /// configured
    pub(crate) fn new_checked(
        bank: &Bank,
        program_address: &Pubkey,
        migration_target: &CoreBpfMigrationTargetType,
    ) -> Result<Self, CoreBpfMigrationError> {
        let program_account = match migration_target {
            CoreBpfMigrationTargetType::Builtin => {
                // The program account should exist.
                let program_account = bank
                    .get_account_with_fixed_root(program_address)
                    .ok_or(CoreBpfMigrationError::AccountNotFound(*program_address))?;

                // The program account should be owned by the native loader.
                if program_account.owner() != &NATIVE_LOADER_ID {
                    return Err(CoreBpfMigrationError::IncorrectOwner(*program_address));
                }

                program_account
            }
            CoreBpfMigrationTargetType::Stateless => {
                // The program account should _not_ exist.
                if bank.get_account_with_fixed_root(program_address).is_some() {
                    return Err(CoreBpfMigrationError::AccountExists(*program_address));
                }

                AccountSharedData::default()
            }
        };

        let program_data_address = get_program_data_address(program_address);

        // The program data account should not exist.
        if bank
            .get_account_with_fixed_root(&program_data_address)
            .is_some()
        {
            return Err(CoreBpfMigrationError::ProgramHasDataAccount(
                *program_address,
            ));
        }

        Ok(Self {
            program_address: *program_address,
            program_account,
            program_data_address,
        })
    }
}
