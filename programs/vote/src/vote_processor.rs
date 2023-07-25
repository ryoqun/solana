//! Vote program processor

use {
    crate::{vote_error::VoteError, vote_state},
    log::*,
    solana_program::vote::{instruction::VoteInstruction, program::id, state::VoteAuthorize},
    solana_program_runtime::{
        declare_process_instruction, invoke_context::InvokeContext,
        sysvar_cache::get_sysvar_with_account_check,
    },
    solana_sdk::{
        feature_set,
        instruction::InstructionError,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        transaction_context::{BorrowedAccount, InstructionContext, TransactionContext},
    },
    std::collections::HashSet,
};

fn process_authorize_with_seed_instruction(
    invoke_context: &InvokeContext,
    instruction_context: &InstructionContext,
    transaction_context: &TransactionContext,
    vote_account: &mut BorrowedAccount,
    new_authority: &Pubkey,
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: &Pubkey,
    current_authority_derived_key_seed: &str,
) -> Result<(), InstructionError> {
    if !invoke_context
        .feature_set
        .is_active(&feature_set::vote_authorize_with_seed::id())
    {
        return Err(InstructionError::InvalidInstructionData);
    }
    let clock = get_sysvar_with_account_check::clock(invoke_context, instruction_context, 1)?;
    let mut expected_authority_keys: HashSet<Pubkey> = HashSet::default();
    if instruction_context.is_instruction_account_signer(2)? {
        let base_pubkey = transaction_context.get_key_of_account_at_index(
            instruction_context.get_index_of_instruction_account_in_transaction(2)?,
        )?;
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
        &clock,
        &invoke_context.feature_set,
    )
}

// Citing `runtime/src/block_cost_limit.rs`, vote has statically defined 2100
// units; can consume based on instructions in the future like `bpf_loader` does.
declare_process_instruction!(process_instruction, 2100, |invoke_context| {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let data = instruction_context.get_instruction_data();

    trace!("process_instruction: {:?}", data);

    let mut me = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    if *me.get_owner() != id() {
        return Err(InstructionError::InvalidAccountOwner);
    }

    let signers = instruction_context.get_signers(transaction_context)?;
    match limited_deserialize(data)? {
        VoteInstruction::InitializeAccount(vote_init) => {
            let rent = get_sysvar_with_account_check::rent(invoke_context, instruction_context, 1)?;
            if !rent.is_exempt(me.get_lamports(), me.get_data().len()) {
                return Err(InstructionError::InsufficientFunds);
            }
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 2)?;
            vote_state::initialize_account(
                &mut me,
                &vote_init,
                &signers,
                &clock,
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::Authorize(voter_pubkey, vote_authorize) => {
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 1)?;
            vote_state::authorize(
                &mut me,
                &voter_pubkey,
                vote_authorize,
                &signers,
                &clock,
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::AuthorizeWithSeed(args) => {
            instruction_context.check_number_of_instruction_accounts(3)?;
            process_authorize_with_seed_instruction(
                invoke_context,
                instruction_context,
                transaction_context,
                &mut me,
                &args.new_authority,
                args.authorization_type,
                &args.current_authority_derived_key_owner,
                args.current_authority_derived_key_seed.as_str(),
            )
        }
        VoteInstruction::AuthorizeCheckedWithSeed(args) => {
            instruction_context.check_number_of_instruction_accounts(4)?;
            let new_authority = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(3)?,
            )?;
            if !instruction_context.is_instruction_account_signer(3)? {
                return Err(InstructionError::MissingRequiredSignature);
            }
            process_authorize_with_seed_instruction(
                invoke_context,
                instruction_context,
                transaction_context,
                &mut me,
                new_authority,
                args.authorization_type,
                &args.current_authority_derived_key_owner,
                args.current_authority_derived_key_seed.as_str(),
            )
        }
        VoteInstruction::UpdateValidatorIdentity => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let node_pubkey = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(1)?,
            )?;
            vote_state::update_validator_identity(
                &mut me,
                node_pubkey,
                &signers,
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::UpdateCommission(commission) => {
            if invoke_context.feature_set.is_active(
                &feature_set::commission_updates_only_allowed_in_first_half_of_epoch::id(),
            ) {
                let sysvar_cache = invoke_context.get_sysvar_cache();
                let epoch_schedule = sysvar_cache.get_epoch_schedule()?;
                let clock = sysvar_cache.get_clock()?;
                if !vote_state::is_commission_update_allowed(clock.slot, &epoch_schedule) {
                    return Err(VoteError::CommissionUpdateTooLate.into());
                }
            }
            vote_state::update_commission(
                &mut me,
                commission,
                &signers,
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::Vote(vote) | VoteInstruction::VoteSwitch(vote, _) => {
            let slot_hashes =
                get_sysvar_with_account_check::slot_hashes(invoke_context, instruction_context, 1)?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 2)?;
            vote_state::process_vote_with_account(
                &mut me,
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
                    &mut me,
                    slot_hashes.slot_hashes(),
                    &clock,
                    vote_state_update,
                    &signers,
                    &invoke_context.feature_set,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
        VoteInstruction::CompactUpdateVoteState(vote_state_update)
        | VoteInstruction::CompactUpdateVoteStateSwitch(vote_state_update, _) => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::allow_votes_to_directly_update_vote_state::id())
                && invoke_context
                    .feature_set
                    .is_active(&feature_set::compact_vote_state_updates::id())
            {
                let sysvar_cache = invoke_context.get_sysvar_cache();
                let slot_hashes = sysvar_cache.get_slot_hashes()?;
                let clock = sysvar_cache.get_clock()?;
                vote_state::process_vote_state_update(
                    &mut me,
                    slot_hashes.slot_hashes(),
                    &clock,
                    vote_state_update,
                    &signers,
                    &invoke_context.feature_set,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }

        VoteInstruction::Withdraw(lamports) => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let rent_sysvar = invoke_context.get_sysvar_cache().get_rent()?;

            let clock_if_feature_active = if invoke_context
                .feature_set
                .is_active(&feature_set::reject_vote_account_close_unless_zero_credit_epoch::id())
            {
                Some(invoke_context.get_sysvar_cache().get_clock()?)
            } else {
                None
            };

            drop(me);
            vote_state::withdraw(
                transaction_context,
                instruction_context,
                0,
                lamports,
                1,
                &signers,
                &rent_sysvar,
                clock_if_feature_active.as_deref(),
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::AuthorizeChecked(vote_authorize) => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::vote_stake_checked_instructions::id())
            {
                instruction_context.check_number_of_instruction_accounts(4)?;
                let voter_pubkey = transaction_context.get_key_of_account_at_index(
                    instruction_context.get_index_of_instruction_account_in_transaction(3)?,
                )?;
                if !instruction_context.is_instruction_account_signer(3)? {
                    return Err(InstructionError::MissingRequiredSignature);
                }
                let clock =
                    get_sysvar_with_account_check::clock(invoke_context, instruction_context, 1)?;
                vote_state::authorize(
                    &mut me,
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
});
