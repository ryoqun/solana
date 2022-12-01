//! Vote program processor

use {
    crate::{
        id,
        vote_instruction::VoteInstruction,
        vote_state::{self, VoteAuthorize},
    },
    log::*,
    solana_program_runtime::{
        invoke_context::InvokeContext, sysvar_cache::get_sysvar_with_account_check,
    },
    solana_sdk::{
        feature_set::{self, FeatureSet},
        instruction::InstructionError,
        keyed_account::{get_signers, keyed_account_at_index, KeyedAccount},
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        sysvar::{clock::Clock, rent::Rent},
    },
    std::collections::HashSet,
};

fn process_authorize_with_seed_instruction(
    keyed_accounts: &[KeyedAccount],
    first_instruction_account: usize,
    vote_account: &KeyedAccount,
    new_authority: &Pubkey,
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: &Pubkey,
    current_authority_derived_key_seed: &str,
    clock: &Clock,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    let mut expected_authority_keys: HashSet<Pubkey> = HashSet::default();
    let authority_base_key_index = first_instruction_account + 2;
    let base_account = keyed_account_at_index(keyed_accounts, authority_base_key_index)?;
    if let Some(base_pubkey) = base_account.signer_key() {
        expected_authority_keys.insert(Pubkey::create_with_seed(
            base_pubkey,
            current_authority_derived_key_seed,
            current_authority_derived_key_owner,
        )?);
    };
    vote_state::authorize(
        vote_account,
        new_authority,
        authorization_type,
        &expected_authority_keys,
        clock,
        feature_set,
    )
}

pub fn process_instruction(
    first_instruction_account: usize,
    data: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let keyed_accounts = invoke_context.get_keyed_accounts()?;

    trace!("process_instruction: {:?}", data);
    trace!("keyed_accounts: {:?}", keyed_accounts);

    let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
    if me.owner()? != id() {
        return Err(InstructionError::InvalidAccountOwner);
    }

    let signers: HashSet<Pubkey> = get_signers(&keyed_accounts[first_instruction_account..]);
    match limited_deserialize(data)? {
        VoteInstruction::InitializeAccount(vote_init) => {
            let rent = get_sysvar_with_account_check::rent(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            verify_rent_exemption(me, &rent)?;
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                invoke_context,
            )?;
            vote_state::initialize_account(me, &vote_init, &signers, &clock)
        }
        VoteInstruction::Authorize(voter_pubkey, vote_authorize) => {
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            vote_state::authorize(
                me,
                &voter_pubkey,
                vote_authorize,
                &signers,
                &clock,
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::AuthorizeWithSeed(args) => {
            if !invoke_context
                .feature_set
                .is_active(&feature_set::vote_authorize_with_seed::id())
            {
                return Err(InstructionError::InvalidInstructionData);
            }
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            process_authorize_with_seed_instruction(
                keyed_accounts,
                first_instruction_account,
                me,
                &args.new_authority,
                args.authorization_type,
                &args.current_authority_derived_key_owner,
                args.current_authority_derived_key_seed.as_str(),
                &clock,
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::AuthorizeCheckedWithSeed(args) => {
            if !invoke_context
                .feature_set
                .is_active(&feature_set::vote_authorize_with_seed::id())
            {
                return Err(InstructionError::InvalidInstructionData);
            }
            let new_authority_index = first_instruction_account + 3;
            let new_authority = &keyed_account_at_index(keyed_accounts, new_authority_index)?
                .signer_key()
                .ok_or(InstructionError::MissingRequiredSignature)?;
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            process_authorize_with_seed_instruction(
                keyed_accounts,
                first_instruction_account,
                me,
                new_authority,
                args.authorization_type,
                &args.current_authority_derived_key_owner,
                args.current_authority_derived_key_seed.as_str(),
                &clock,
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::UpdateValidatorIdentity => vote_state::update_validator_identity(
            me,
            keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?.unsigned_key(),
            &signers,
        ),
        VoteInstruction::UpdateCommission(commission) => {
            vote_state::update_commission(me, commission, &signers)
        }
        VoteInstruction::Vote(vote) | VoteInstruction::VoteSwitch(vote, _) => {
            let slot_hashes = get_sysvar_with_account_check::slot_hashes(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            let clock = get_sysvar_with_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                invoke_context,
            )?;
            vote_state::process_vote(
                me,
                &slot_hashes,
                &clock,
                &vote,
                &signers,
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::UpdateVoteState(vote_state_update)
        | VoteInstruction::UpdateVoteStateSwitch(vote_state_update, _) => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::allow_votes_to_directly_update_vote_state::id())
            {
                let sysvar_cache = invoke_context.get_sysvar_cache();
                let slot_hashes = sysvar_cache.get_slot_hashes()?;
                let clock = sysvar_cache.get_clock()?;
                vote_state::process_vote_state_update(
                    me,
                    slot_hashes.slot_hashes(),
                    &clock,
                    vote_state_update,
                    &signers,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
        VoteInstruction::Withdraw(lamports) => {
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let rent_sysvar = if invoke_context
                .feature_set
                .is_active(&feature_set::reject_non_rent_exempt_vote_withdraws::id())
            {
                Some(invoke_context.get_sysvar_cache().get_rent()?)
            } else {
                None
            };

            let clock_if_feature_active = if invoke_context
                .feature_set
                .is_active(&feature_set::reject_vote_account_close_unless_zero_credit_epoch::id())
            {
                Some(invoke_context.get_sysvar_cache().get_clock()?)
            } else {
                None
            };

            vote_state::withdraw(
                me,
                lamports,
                to,
                &signers,
                rent_sysvar.as_deref(),
                clock_if_feature_active.as_deref(),
            )
        }
        VoteInstruction::AuthorizeChecked(vote_authorize) => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::vote_stake_checked_instructions::id())
            {
                let voter_pubkey =
                    &keyed_account_at_index(keyed_accounts, first_instruction_account + 3)?
                        .signer_key()
                        .ok_or(InstructionError::MissingRequiredSignature)?;
                let clock = get_sysvar_with_account_check::clock(
                    keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                    invoke_context,
                )?;
                vote_state::authorize(
                    me,
                    voter_pubkey,
                    vote_authorize,
                    &signers,
                    &clock,
                    &invoke_context.feature_set,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
    }
}

fn verify_rent_exemption(
    keyed_account: &KeyedAccount,
    rent: &Rent,
) -> Result<(), InstructionError> {
    if !rent.is_exempt(keyed_account.lamports()?, keyed_account.data_len()?) {
        Err(InstructionError::InsufficientFunds)
    } else {
        Ok(())
    }
}
