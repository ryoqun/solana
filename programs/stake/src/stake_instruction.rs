#[deprecated(
    since = "1.8.0",
    note = "Please use `solana_sdk::stake::instruction` or `solana_program::stake::instruction` instead"
)]
pub use solana_sdk::stake::instruction::*;
use {
    crate::{config, stake_state::StakeAccount},
    log::*,
    solana_program_runtime::invoke_context::InvokeContext,
    solana_sdk::{
        feature_set,
        instruction::InstructionError,
        keyed_account::{from_keyed_account, get_signers, keyed_account_at_index},
        program_utils::limited_deserialize,
        stake::{
            instruction::StakeInstruction,
            program::id,
            state::{Authorized, Lockup},
        },
        sysvar::{clock::Clock, rent::Rent, stake_history::StakeHistory},
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
        StakeInstruction::Initialize(authorized, lockup) => me.initialize(
            &authorized,
            &lockup,
            &from_keyed_account::<Rent>(keyed_account_at_index(
                keyed_accounts,
                first_instruction_account + 1,
            )?)?,
        ),
        StakeInstruction::Authorize(authorized_pubkey, stake_authorize) => {
            let require_custodian_for_locked_stake_authorize = invoke_context
                .feature_set
                .is_active(&feature_set::require_custodian_for_locked_stake_authorize::id());

            if require_custodian_for_locked_stake_authorize {
                let clock = from_keyed_account::<Clock>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 1,
                )?)?;
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
                let clock = from_keyed_account::<Clock>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 2,
                )?)?;
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
            let can_reverse_deactivation = invoke_context
                .feature_set
                .is_active(&feature_set::stake_program_v4::id());
            let vote = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;

            me.delegate(
                vote,
                &from_keyed_account::<Clock>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 2,
                )?)?,
                &from_keyed_account::<StakeHistory>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 3,
                )?)?,
                &config::from_keyed_account(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 4,
                )?)?,
                &signers,
                can_reverse_deactivation,
            )
        }
        StakeInstruction::Split(lamports) => {
            let split_stake =
                &keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            me.split(lamports, split_stake, &signers)
        }
        StakeInstruction::Merge => {
            let source_stake =
                &keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let can_merge_expired_lockups = invoke_context
                .feature_set
                .is_active(&feature_set::stake_program_v4::id());
            me.merge(
                invoke_context,
                source_stake,
                &from_keyed_account::<Clock>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 2,
                )?)?,
                &from_keyed_account::<StakeHistory>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 3,
                )?)?,
                &signers,
                can_merge_expired_lockups,
            )
        }
        StakeInstruction::Withdraw(lamports) => {
            let to = &keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            me.withdraw(
                lamports,
                to,
                &from_keyed_account::<Clock>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 2,
                )?)?,
                &from_keyed_account::<StakeHistory>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 3,
                )?)?,
                keyed_account_at_index(keyed_accounts, first_instruction_account + 4)?,
                keyed_account_at_index(keyed_accounts, first_instruction_account + 5).ok(),
                invoke_context
                    .feature_set
                    .is_active(&feature_set::stake_program_v4::id()),
            )
        }
        StakeInstruction::Deactivate => me.deactivate(
            &from_keyed_account::<Clock>(keyed_account_at_index(
                keyed_accounts,
                first_instruction_account + 1,
            )?)?,
            &signers,
        ),
        StakeInstruction::SetLockup(lockup) => {
            let clock = if invoke_context
                .feature_set
                .is_active(&feature_set::stake_program_v4::id())
            {
                Some(invoke_context.get_sysvar_cache().get_clock()?)
            } else {
                None
            };
            me.set_lockup(&lockup, &signers, clock.as_deref())
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

                me.initialize(
                    &authorized,
                    &Lockup::default(),
                    &from_keyed_account::<Rent>(keyed_account_at_index(
                        keyed_accounts,
                        first_instruction_account + 1,
                    )?)?,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
        StakeInstruction::AuthorizeChecked(stake_authorize) => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::vote_stake_checked_instructions::id())
            {
                let clock = from_keyed_account::<Clock>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 1,
                )?)?;
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
                let clock = from_keyed_account::<Clock>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 2,
                )?)?;
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
                let clock = Some(invoke_context.get_sysvar_cache().get_clock()?);
                me.set_lockup(&lockup, &signers, clock.as_deref())
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
    }
}

