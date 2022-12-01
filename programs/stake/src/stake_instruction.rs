#[deprecated(
    since = "1.8.0",
    note = "Please use `solana_sdk::stake::instruction` or `solana_program::stake::instruction` instead"
)]
pub use solana_sdk::stake::instruction::*;
use {
    crate::{config, stake_state::StakeAccount},
    log::*,
    solana_program_runtime::{
        invoke_context::InvokeContext, sysvar_cache::get_sysvar_with_account_check,
    },
    solana_sdk::{
        feature_set,
        instruction::InstructionError,
        keyed_account::{get_signers, keyed_account_at_index},
        program_utils::limited_deserialize,
        stake::{
            instruction::StakeInstruction,
            program::id,
            state::{Authorized, Lockup},
        },
        sysvar::clock::Clock,
    },
};

pub fn process_instruction(
    first_instruction_account: usize,
    data: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let keyed_accounts = invoke_context.get_keyed_accounts()?;

    trace!("process_instruction: {:?}", data);
    trace!("keyed_accounts: {:?}", keyed_accounts);

    let me = &keyed_account_at_index(keyed_accounts, first_instruction_account)?;
    if me.owner()? != id() {
        return Err(InstructionError::InvalidAccountOwner);
    }

    let signers = get_signers(&keyed_accounts[first_instruction_account..]);
    match limited_deserialize(data)? {
        StakeInstruction::Initialize(authorized, lockup) => {
            let rent = get_sysvar_with_account_check::rent(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            me.initialize(&authorized, &lockup, &rent)
        }
        StakeInstruction::Authorize(authorized_pubkey, stake_authorize) => {
            let require_custodian_for_locked_stake_authorize = invoke_context
                .feature_set
                .is_active(&feature_set::require_custodian_for_locked_stake_authorize::id());

            if require_custodian_for_locked_stake_authorize {
                let clock = get_sysvar_with_account_check::clock(
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                    invoke_context,
                )?;
                let _current_authority =
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?;
                let custodian =
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 3)
                        .ok()
                        .map(|ka| ka.unsigned_key());

                me.authorize(
                    &signers,
                    &authorized_pubkey,
                    stake_authorize,
                    require_custodian_for_locked_stake_authorize,
                    &clock,
                    custodian,
                )
            } else {
                me.authorize(
                    &signers,
                    &authorized_pubkey,
                    stake_authorize,
                    require_custodian_for_locked_stake_authorize,
                    &Clock::default(),
                    None,
                )
            }
        }
        StakeInstruction::AuthorizeWithSeed(args) => {
            let authority_base =
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let require_custodian_for_locked_stake_authorize = invoke_context
                .feature_set
                .is_active(&feature_set::require_custodian_for_locked_stake_authorize::id());

            if require_custodian_for_locked_stake_authorize {
                let clock = get_sysvar_with_account_check::clock(
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                    invoke_context,
                )?;
                let custodian =
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 3)
                        .ok()
                        .map(|ka| ka.unsigned_key());

                me.authorize_with_seed(
                    authority_base,
                    &args.authority_seed,
                    &args.authority_owner,
                    &args.new_authorized_pubkey,
                    args.stake_authorize,
                    require_custodian_for_locked_stake_authorize,
                    &clock,
                    custodian,
                )
            } else {
                me.authorize_with_seed(
                    authority_base,
                    &args.authority_seed,
                    &args.authority_owner,
                    &args.new_authorized_pubkey,
                    args.stake_authorize,
                    require_custodian_for_locked_stake_authorize,
                    &Clock::default(),
                    None,
                )
            }
        }
        StakeInstruction::DelegateStake => {
            let vote = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                invoke_context,
            )?;
            let stake_history = get_sysvar_with_account_check::stake_history(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 3)?,
                invoke_context,
            )?;
            let config_account =
                keyed_account_at_index(keyed_accounts, first_instruction_account + 4)?;
            if !config::check_id(config_account.unsigned_key()) {
                return Err(InstructionError::InvalidArgument);
            }
            let config = config::from(&*config_account.try_account_ref()?)
                .ok_or(InstructionError::InvalidArgument)?;
            me.delegate(vote, &clock, &stake_history, &config, &signers)
        }
        StakeInstruction::Split(lamports) => {
            let split_stake =
                &keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            me.split(lamports, split_stake, &signers)
        }
        StakeInstruction::Merge => {
            let source_stake =
                &keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                invoke_context,
            )?;
            let stake_history = get_sysvar_with_account_check::stake_history(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 3)?,
                invoke_context,
            )?;
            me.merge(
                invoke_context,
                source_stake,
                &clock,
                &stake_history,
                &signers,
            )
        }
        StakeInstruction::Withdraw(lamports) => {
            let to = &keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                invoke_context,
            )?;
            let stake_history = get_sysvar_with_account_check::stake_history(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 3)?,
                invoke_context,
            )?;
            me.withdraw(
                lamports,
                to,
                &clock,
                &stake_history,
                keyed_account_at_index(keyed_accounts, first_instruction_account + 4)?,
                keyed_account_at_index(keyed_accounts, first_instruction_account + 5).ok(),
            )
        }
        StakeInstruction::Deactivate => {
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            me.deactivate(&clock, &signers)
        }
        StakeInstruction::SetLockup(lockup) => {
            let clock = invoke_context.get_sysvar_cache().get_clock()?;
            me.set_lockup(&lockup, &signers, &clock)
        }
        StakeInstruction::InitializeChecked => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::vote_stake_checked_instructions::id())
            {
                let authorized = Authorized {
                    staker: *keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?
                        .unsigned_key(),
                    withdrawer: *keyed_account_at_index(
                        keyed_accounts,
                        first_instruction_account + 3,
                    )?
                    .signer_key()
                    .ok_or(InstructionError::MissingRequiredSignature)?,
                };

                let rent = get_sysvar_with_account_check::rent(
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                    invoke_context,
                )?;
                me.initialize(&authorized, &Lockup::default(), &rent)
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
        StakeInstruction::AuthorizeChecked(stake_authorize) => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::vote_stake_checked_instructions::id())
            {
                let clock = get_sysvar_with_account_check::clock(
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                    invoke_context,
                )?;
                let _current_authority =
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?;
                let authorized_pubkey =
                    &keyed_account_at_index(keyed_accounts, first_instruction_account + 3)?
                        .signer_key()
                        .ok_or(InstructionError::MissingRequiredSignature)?;
                let custodian =
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 4)
                        .ok()
                        .map(|ka| ka.unsigned_key());

                me.authorize(
                    &signers,
                    authorized_pubkey,
                    stake_authorize,
                    true,
                    &clock,
                    custodian,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
        StakeInstruction::AuthorizeCheckedWithSeed(args) => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::vote_stake_checked_instructions::id())
            {
                let authority_base =
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
                let clock = get_sysvar_with_account_check::clock(
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                    invoke_context,
                )?;
                let authorized_pubkey =
                    &keyed_account_at_index(keyed_accounts, first_instruction_account + 3)?
                        .signer_key()
                        .ok_or(InstructionError::MissingRequiredSignature)?;
                let custodian =
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 4)
                        .ok()
                        .map(|ka| ka.unsigned_key());

                me.authorize_with_seed(
                    authority_base,
                    &args.authority_seed,
                    &args.authority_owner,
                    authorized_pubkey,
                    args.stake_authorize,
                    true,
                    &clock,
                    custodian,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
        StakeInstruction::SetLockupChecked(lockup_checked) => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::vote_stake_checked_instructions::id())
            {
                let custodian = if let Ok(custodian) =
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 2)
                {
                    Some(
                        *custodian
                            .signer_key()
                            .ok_or(InstructionError::MissingRequiredSignature)?,
                    )
                } else {
                    None
                };

                let lockup = LockupArgs {
                    unix_timestamp: lockup_checked.unix_timestamp,
                    epoch: lockup_checked.epoch,
                    custodian,
                };
                let clock = invoke_context.get_sysvar_cache().get_clock()?;
                me.set_lockup(&lockup, &signers, &clock)
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
    }
}
