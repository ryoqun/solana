use {
    crate::nonce_keyed_account::NonceKeyedAccount,
    log::*,
    solana_program_runtime::{
        ic_msg, invoke_context::InvokeContext, sysvar_cache::get_sysvar_with_account_check,
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        account_utils::{State as _, StateMut},
        feature_set,
        instruction::InstructionError,
        keyed_account::{get_signers, keyed_account_at_index, KeyedAccount},
        nonce,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        system_instruction::{
            NonceError, SystemError, SystemInstruction, MAX_PERMITTED_DATA_LENGTH,
        },
        system_program,
    },
    std::collections::HashSet,
};

// represents an address that may or may not have been generated
//  from a seed
#[derive(PartialEq, Default, Debug)]
struct Address {
    address: Pubkey,
    base: Option<Pubkey>,
}

impl Address {
    fn is_signer(&self, signers: &HashSet<Pubkey>) -> bool {
        if let Some(base) = self.base {
            signers.contains(&base)
        } else {
            signers.contains(&self.address)
        }
    }
    fn create(
        address: &Pubkey,
        with_seed: Option<(&Pubkey, &str, &Pubkey)>,
        invoke_context: &InvokeContext,
    ) -> Result<Self, InstructionError> {
        let base = if let Some((base, seed, owner)) = with_seed {
            let address_with_seed = Pubkey::create_with_seed(base, seed, owner)?;
            // re-derive the address, must match the supplied address
            if *address != address_with_seed {
                ic_msg!(
                    invoke_context,
                    "Create: address {} does not match derived address {}",
                    address,
                    address_with_seed
                );
                return Err(SystemError::AddressWithSeedMismatch.into());
            }
            Some(*base)
        } else {
            None
        };

        Ok(Self {
            address: *address,
            base,
        })
    }
}

fn allocate(
    account: &mut AccountSharedData,
    address: &Address,
    space: u64,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    if !address.is_signer(signers) {
        ic_msg!(
            invoke_context,
            "Allocate: 'to' account {:?} must sign",
            address
        );
        return Err(InstructionError::MissingRequiredSignature);
    }

    // if it looks like the `to` account is already in use, bail
    //   (note that the id check is also enforced by message_processor)
    if !account.data().is_empty() || !system_program::check_id(account.owner()) {
        ic_msg!(
            invoke_context,
            "Allocate: account {:?} already in use",
            address
        );
        return Err(SystemError::AccountAlreadyInUse.into());
    }

    if space > MAX_PERMITTED_DATA_LENGTH {
        ic_msg!(
            invoke_context,
            "Allocate: requested {}, max allowed {}",
            space,
            MAX_PERMITTED_DATA_LENGTH
        );
        return Err(SystemError::InvalidAccountDataLength.into());
    }

    account.set_data(vec![0; space as usize]);

    Ok(())
}

fn assign(
    account: &mut AccountSharedData,
    address: &Address,
    owner: &Pubkey,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    // no work to do, just return
    if account.owner() == owner {
        return Ok(());
    }

    if !address.is_signer(signers) {
        ic_msg!(invoke_context, "Assign: account {:?} must sign", address);
        return Err(InstructionError::MissingRequiredSignature);
    }

    account.set_owner(*owner);
    Ok(())
}

fn allocate_and_assign(
    to: &mut AccountSharedData,
    to_address: &Address,
    space: u64,
    owner: &Pubkey,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    allocate(to, to_address, space, signers, invoke_context)?;
    assign(to, to_address, owner, signers, invoke_context)
}

fn create_account(
    from: &KeyedAccount,
    to: &KeyedAccount,
    to_address: &Address,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    // if it looks like the `to` account is already in use, bail
    {
        let to = &mut to.try_account_ref_mut()?;
        if to.lamports() > 0 {
            ic_msg!(
                invoke_context,
                "Create Account: account {:?} already in use",
                to_address
            );
            return Err(SystemError::AccountAlreadyInUse.into());
        }

        allocate_and_assign(to, to_address, space, owner, signers, invoke_context)?;
    }
    transfer(from, to, lamports, invoke_context)
}

fn transfer_verified(
    from: &KeyedAccount,
    to: &KeyedAccount,
    lamports: u64,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    if !from.data_is_empty()? {
        ic_msg!(invoke_context, "Transfer: `from` must not carry data");
        return Err(InstructionError::InvalidArgument);
    }
    if lamports > from.lamports()? {
        ic_msg!(
            invoke_context,
            "Transfer: insufficient lamports {}, need {}",
            from.lamports()?,
            lamports
        );
        return Err(SystemError::ResultWithNegativeLamports.into());
    }

    from.try_account_ref_mut()?.checked_sub_lamports(lamports)?;
    to.try_account_ref_mut()?.checked_add_lamports(lamports)?;
    Ok(())
}

fn transfer(
    from: &KeyedAccount,
    to: &KeyedAccount,
    lamports: u64,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    if !invoke_context
        .feature_set
        .is_active(&feature_set::system_transfer_zero_check::id())
        && lamports == 0
    {
        return Ok(());
    }

    if from.signer_key().is_none() {
        ic_msg!(
            invoke_context,
            "Transfer: `from` account {} must sign",
            from.unsigned_key()
        );
        return Err(InstructionError::MissingRequiredSignature);
    }

    transfer_verified(from, to, lamports, invoke_context)
}

fn transfer_with_seed(
    from: &KeyedAccount,
    from_base: &KeyedAccount,
    from_seed: &str,
    from_owner: &Pubkey,
    to: &KeyedAccount,
    lamports: u64,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    if !invoke_context
        .feature_set
        .is_active(&feature_set::system_transfer_zero_check::id())
        && lamports == 0
    {
        return Ok(());
    }

    if from_base.signer_key().is_none() {
        ic_msg!(
            invoke_context,
            "Transfer: 'from' account {:?} must sign",
            from_base
        );
        return Err(InstructionError::MissingRequiredSignature);
    }

    let address_from_seed =
        Pubkey::create_with_seed(from_base.unsigned_key(), from_seed, from_owner)?;
    if *from.unsigned_key() != address_from_seed {
        ic_msg!(
            invoke_context,
            "Transfer: 'from' address {} does not match derived address {}",
            from.unsigned_key(),
            address_from_seed
        );
        return Err(SystemError::AddressWithSeedMismatch.into());
    }

    transfer_verified(from, to, lamports, invoke_context)
}

pub fn process_instruction(
    first_instruction_account: usize,
    instruction_data: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let keyed_accounts = invoke_context.get_keyed_accounts()?;
    let instruction = limited_deserialize(instruction_data)?;

    trace!("process_instruction: {:?}", instruction);
    trace!("keyed_accounts: {:?}", keyed_accounts);

    let _ = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
    let signers = get_signers(&keyed_accounts[first_instruction_account..]);
    match instruction {
        SystemInstruction::CreateAccount {
            lamports,
            space,
            owner,
        } => {
            let from = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let to_address = Address::create(to.unsigned_key(), None, invoke_context)?;
            create_account(
                from,
                to,
                &to_address,
                lamports,
                space,
                &owner,
                &signers,
                invoke_context,
            )
        }
        SystemInstruction::CreateAccountWithSeed {
            base,
            seed,
            lamports,
            space,
            owner,
        } => {
            let from = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let to_address = Address::create(
                to.unsigned_key(),
                Some((&base, &seed, &owner)),
                invoke_context,
            )?;
            create_account(
                from,
                to,
                &to_address,
                lamports,
                space,
                &owner,
                &signers,
                invoke_context,
            )
        }
        SystemInstruction::Assign { owner } => {
            let keyed_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let mut account = keyed_account.try_account_ref_mut()?;
            let address = Address::create(keyed_account.unsigned_key(), None, invoke_context)?;
            assign(&mut account, &address, &owner, &signers, invoke_context)
        }
        SystemInstruction::Transfer { lamports } => {
            let from = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            transfer(from, to, lamports, invoke_context)
        }
        SystemInstruction::TransferWithSeed {
            lamports,
            from_seed,
            from_owner,
        } => {
            let from = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let base = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?;
            transfer_with_seed(
                from,
                base,
                &from_seed,
                &from_owner,
                to,
                lamports,
                invoke_context,
            )
        }
        SystemInstruction::AdvanceNonceAccount => {
            let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            #[allow(deprecated)]
            let recent_blockhashes = get_sysvar_with_account_check::recent_blockhashes(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            if recent_blockhashes.is_empty() {
                ic_msg!(
                    invoke_context,
                    "Advance nonce account: recent blockhash list is empty",
                );
                return Err(NonceError::NoRecentBlockhashes.into());
            }
            me.advance_nonce_account(&signers, invoke_context)
        }
        SystemInstruction::WithdrawNonceAccount(lamports) => {
            let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let to = &mut keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            #[allow(deprecated)]
            let _recent_blockhashes = get_sysvar_with_account_check::recent_blockhashes(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                invoke_context,
            )?;
            let rent = get_sysvar_with_account_check::rent(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 3)?,
                invoke_context,
            )?;
            me.withdraw_nonce_account(lamports, to, &rent, &signers, invoke_context)
        }
        SystemInstruction::InitializeNonceAccount(authorized) => {
            let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            #[allow(deprecated)]
            let recent_blockhashes = get_sysvar_with_account_check::recent_blockhashes(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            if recent_blockhashes.is_empty() {
                ic_msg!(
                    invoke_context,
                    "Initialize nonce account: recent blockhash list is empty",
                );
                return Err(NonceError::NoRecentBlockhashes.into());
            }
            let rent = get_sysvar_with_account_check::rent(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                invoke_context,
            )?;
            me.initialize_nonce_account(&authorized, &rent, invoke_context)
        }
        SystemInstruction::AuthorizeNonceAccount(nonce_authority) => {
            let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            me.authorize_nonce_account(&nonce_authority, &signers, invoke_context)
        }
        SystemInstruction::UpgradeNonceAccount => {
            let separate_nonce_from_blockhash = invoke_context
                .feature_set
                .is_active(&feature_set::separate_nonce_from_blockhash::id());
            if !separate_nonce_from_blockhash {
                return Err(InstructionError::InvalidInstructionData);
            }
            let nonce_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            if !system_program::check_id(&nonce_account.owner()?) {
                return Err(InstructionError::InvalidAccountOwner);
            }
            if !nonce_account.is_writable() {
                return Err(InstructionError::InvalidArgument);
            }
            let nonce_versions: nonce::state::Versions = nonce_account.state()?;
            match nonce_versions.upgrade() {
                None => Err(InstructionError::InvalidArgument),
                Some(nonce_versions) => nonce_account.set_state(&nonce_versions),
            }
        }
        SystemInstruction::Allocate { space } => {
            let keyed_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let mut account = keyed_account.try_account_ref_mut()?;
            let address = Address::create(keyed_account.unsigned_key(), None, invoke_context)?;
            allocate(&mut account, &address, space, &signers, invoke_context)
        }
        SystemInstruction::AllocateWithSeed {
            base,
            seed,
            space,
            owner,
        } => {
            let keyed_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let mut account = keyed_account.try_account_ref_mut()?;
            let address = Address::create(
                keyed_account.unsigned_key(),
                Some((&base, &seed, &owner)),
                invoke_context,
            )?;
            allocate_and_assign(
                &mut account,
                &address,
                space,
                &owner,
                &signers,
                invoke_context,
            )
        }
        SystemInstruction::AssignWithSeed { base, seed, owner } => {
            let keyed_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let mut account = keyed_account.try_account_ref_mut()?;
            let address = Address::create(
                keyed_account.unsigned_key(),
                Some((&base, &seed, &owner)),
                invoke_context,
            )?;
            assign(&mut account, &address, &owner, &signers, invoke_context)
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SystemAccountKind {
    System,
    Nonce,
}

pub fn get_system_account_kind(account: &AccountSharedData) -> Option<SystemAccountKind> {
    if system_program::check_id(account.owner()) {
        if account.data().is_empty() {
            Some(SystemAccountKind::System)
        } else if account.data().len() == nonce::State::size() {
            let nonce_versions: nonce::state::Versions = account.state().ok()?;
            match nonce_versions.state() {
                nonce::State::Uninitialized => None,
                nonce::State::Initialized(_) => Some(SystemAccountKind::Nonce),
            }
        } else {
            None
        }
    } else {
        None
    }
}
