//! Stake state
//! * delegate stakes to vote accounts
//! * keep track of rewards
//! * own mining pools

#[deprecated(
    since = "1.8.0",
    note = "Please use `solana_sdk::stake::state` or `solana_program::stake::state` instead"
)]
pub use solana_sdk::stake::state::*;
use {
    solana_program_runtime::{ic_msg, invoke_context::InvokeContext},
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        account_utils::{State, StateMut},
        clock::{Clock, Epoch},
        feature_set::stake_merge_with_unmatched_credits_observed,
        instruction::{checked_add, InstructionError},
        keyed_account::KeyedAccount,
        pubkey::Pubkey,
        rent::{Rent, ACCOUNT_STORAGE_OVERHEAD},
        stake::{
            config::Config,
            instruction::{LockupArgs, StakeError},
            program::id,
        },
        stake_history::{StakeHistory, StakeHistoryEntry},
    },
    solana_vote_program::vote_state::{VoteState, VoteStateVersions},
    std::{collections::HashSet, convert::TryFrom},
};

#[derive(Debug)]
pub enum SkippedReason {
    DisabledInflation,
    JustActivated,
    TooEarlyUnfairSplit,
    ZeroPoints,
    ZeroPointValue,
    ZeroReward,
    ZeroCreditsAndReturnZero,
    ZeroCreditsAndReturnCurrent,
}

impl From<SkippedReason> for InflationPointCalculationEvent {
    fn from(reason: SkippedReason) -> Self {
        InflationPointCalculationEvent::Skipped(reason)
    }
}

#[derive(Debug)]
pub enum InflationPointCalculationEvent {
    CalculatedPoints(u64, u128, u128, u128),
    SplitRewards(u64, u64, u64, PointValue),
    EffectiveStakeAtRewardedEpoch(u64),
    RentExemptReserve(u64),
    Delegation(Delegation, Pubkey),
    Commission(u8),
    CreditsObserved(u64, Option<u64>),
    Skipped(SkippedReason),
}

pub(crate) fn null_tracer() -> Option<impl Fn(&InflationPointCalculationEvent)> {
    None::<fn(&_)>
}

// utility function, used by Stakes, tests
pub fn from<T: ReadableAccount + StateMut<StakeState>>(account: &T) -> Option<StakeState> {
    account.state().ok()
}

pub fn stake_from<T: ReadableAccount + StateMut<StakeState>>(account: &T) -> Option<Stake> {
    from(account).and_then(|state: StakeState| state.stake())
}

pub fn delegation_from(account: &AccountSharedData) -> Option<Delegation> {
    from(account).and_then(|state: StakeState| state.delegation())
}

pub fn authorized_from(account: &AccountSharedData) -> Option<Authorized> {
    from(account).and_then(|state: StakeState| state.authorized())
}

pub fn lockup_from<T: ReadableAccount + StateMut<StakeState>>(account: &T) -> Option<Lockup> {
    from(account).and_then(|state: StakeState| state.lockup())
}

pub fn meta_from(account: &AccountSharedData) -> Option<Meta> {
    from(account).and_then(|state: StakeState| state.meta())
}

fn redelegate(
    stake: &mut Stake,
    stake_lamports: u64,
    voter_pubkey: &Pubkey,
    vote_state: &VoteState,
    clock: &Clock,
    stake_history: &StakeHistory,
    config: &Config,
    can_reverse_deactivation: bool,
) -> Result<(), StakeError> {
    // If stake is currently active:
    if stake.stake(clock.epoch, Some(stake_history)) != 0 {
        // If pubkey of new voter is the same as current,
        // and we are scheduled to start deactivating this epoch,
        // we rescind deactivation
        if stake.delegation.voter_pubkey == *voter_pubkey
            && clock.epoch == stake.delegation.deactivation_epoch
            && can_reverse_deactivation
        {
            stake.delegation.deactivation_epoch = std::u64::MAX;
            return Ok(());
        } else {
            // can't redelegate to another pubkey if stake is active.
            return Err(StakeError::TooSoonToRedelegate);
        }
    }
    // Either the stake is freshly activated, is active but has been
    // deactivated this epoch, or has fully de-activated.
    // Redelegation implies either re-activation or un-deactivation

    stake.delegation.stake = stake_lamports;
    stake.delegation.activation_epoch = clock.epoch;
    stake.delegation.deactivation_epoch = std::u64::MAX;
    stake.delegation.voter_pubkey = *voter_pubkey;
    stake.delegation.warmup_cooldown_rate = config.warmup_cooldown_rate;
    stake.credits_observed = vote_state.credits();
    Ok(())
}

fn new_stake(
    stake: u64,
    voter_pubkey: &Pubkey,
    vote_state: &VoteState,
    activation_epoch: Epoch,
    config: &Config,
) -> Stake {
    Stake {
        delegation: Delegation::new(
            voter_pubkey,
            stake,
            activation_epoch,
            config.warmup_cooldown_rate,
        ),
        credits_observed: vote_state.credits(),
    }
}

/// captures a rewards round as lamports to be awarded
///  and the total points over which those lamports
///  are to be distributed
//  basically read as rewards/points, but in integers instead of as an f64
#[derive(Clone, Debug, PartialEq)]
pub struct PointValue {
    pub rewards: u64, // lamports to split
    pub points: u128, // over these points
}

fn redeem_stake_rewards(
    rewarded_epoch: Epoch,
    stake: &mut Stake,
    point_value: &PointValue,
    vote_state: &VoteState,
    stake_history: Option<&StakeHistory>,
    inflation_point_calc_tracer: Option<impl Fn(&InflationPointCalculationEvent)>,
    fix_activating_credits_observed: bool,
) -> Option<(u64, u64)> {
    if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
        inflation_point_calc_tracer(&InflationPointCalculationEvent::CreditsObserved(
            stake.credits_observed,
            None,
        ));
    }
    calculate_stake_rewards(
        rewarded_epoch,
        stake,
        point_value,
        vote_state,
        stake_history,
        inflation_point_calc_tracer.as_ref(),
        fix_activating_credits_observed,
    )
    .map(|(stakers_reward, voters_reward, credits_observed)| {
        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer {
            inflation_point_calc_tracer(&InflationPointCalculationEvent::CreditsObserved(
                stake.credits_observed,
                Some(credits_observed),
            ));
        }
        stake.credits_observed = credits_observed;
        stake.delegation.stake += stakers_reward;
        (stakers_reward, voters_reward)
    })
}

fn calculate_stake_points(
    stake: &Stake,
    vote_state: &VoteState,
    stake_history: Option<&StakeHistory>,
    inflation_point_calc_tracer: Option<impl Fn(&InflationPointCalculationEvent)>,
) -> u128 {
    calculate_stake_points_and_credits(
        stake,
        vote_state,
        stake_history,
        inflation_point_calc_tracer,
    )
    .0
}

/// for a given stake and vote_state, calculate how many
///   points were earned (credits * stake) and new value
///   for credits_observed were the points paid
fn calculate_stake_points_and_credits(
    stake: &Stake,
    new_vote_state: &VoteState,
    stake_history: Option<&StakeHistory>,
    inflation_point_calc_tracer: Option<impl Fn(&InflationPointCalculationEvent)>,
) -> (u128, u64) {
    let credits_in_stake = stake.credits_observed;
    let credits_in_vote = new_vote_state.credits();
    // if there is no newer credits since observed, return no point
    if credits_in_vote <= credits_in_stake {
        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(&SkippedReason::ZeroCreditsAndReturnCurrent.into());
        }
        return (0, credits_in_stake);
    }

    let mut points = 0;
    let mut new_credits_observed = credits_in_stake;

    for (epoch, final_epoch_credits, initial_epoch_credits) in
        new_vote_state.epoch_credits().iter().copied()
    {
        let stake_amount = u128::from(stake.delegation.stake(epoch, stake_history));

        // figure out how much this stake has seen that
        //   for which the vote account has a record
        let earned_credits = if credits_in_stake < initial_epoch_credits {
            // the staker observed the entire epoch
            final_epoch_credits - initial_epoch_credits
        } else if credits_in_stake < final_epoch_credits {
            // the staker registered sometime during the epoch, partial credit
            final_epoch_credits - new_credits_observed
        } else {
            // the staker has already observed or been redeemed this epoch
            //  or was activated after this epoch
            0
        };
        let earned_credits = u128::from(earned_credits);

        // don't want to assume anything about order of the iterator...
        new_credits_observed = new_credits_observed.max(final_epoch_credits);

        // finally calculate points for this epoch
        let earned_points = stake_amount * earned_credits;
        points += earned_points;

        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(&InflationPointCalculationEvent::CalculatedPoints(
                epoch,
                stake_amount,
                earned_credits,
                earned_points,
            ));
        }
    }

    (points, new_credits_observed)
}

/// for a given stake and vote_state, calculate what distributions and what updates should be made
/// returns a tuple in the case of a payout of:
///   * staker_rewards to be distributed
///   * voter_rewards to be distributed
///   * new value for credits_observed in the stake
/// returns None if there's no payout or if any deserved payout is < 1 lamport
fn calculate_stake_rewards(
    rewarded_epoch: Epoch,
    stake: &Stake,
    point_value: &PointValue,
    vote_state: &VoteState,
    stake_history: Option<&StakeHistory>,
    inflation_point_calc_tracer: Option<impl Fn(&InflationPointCalculationEvent)>,
    _fix_activating_credits_observed: bool, // this unused flag will soon be justified by an upcoming feature pr
) -> Option<(u64, u64, u64)> {
    // ensure to run to trigger (optional) inflation_point_calc_tracer
    // this awkward flag variable will soon be justified by an upcoming feature pr
    let mut forced_credits_update_with_skipped_reward = false;
    let (points, credits_observed) = calculate_stake_points_and_credits(
        stake,
        vote_state,
        stake_history,
        inflation_point_calc_tracer.as_ref(),
    );

    // Drive credits_observed forward unconditionally when rewards are disabled
    // or when this is the stake's activation epoch
    if point_value.rewards == 0 {
        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(&SkippedReason::DisabledInflation.into());
        }
        forced_credits_update_with_skipped_reward = true;
    } else if stake.delegation.activation_epoch == rewarded_epoch {
        // not assert!()-ed; but points should be zero
        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(&SkippedReason::JustActivated.into());
        }
        forced_credits_update_with_skipped_reward = true;
    }

    if forced_credits_update_with_skipped_reward {
        return Some((0, 0, credits_observed));
    }

    if points == 0 {
        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(&SkippedReason::ZeroPoints.into());
        }
        return None;
    }
    if point_value.points == 0 {
        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(&SkippedReason::ZeroPointValue.into());
        }
        return None;
    }

    let rewards = points
        .checked_mul(u128::from(point_value.rewards))
        .unwrap()
        .checked_div(point_value.points)
        .unwrap();

    let rewards = u64::try_from(rewards).unwrap();

    // don't bother trying to split if fractional lamports got truncated
    if rewards == 0 {
        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(&SkippedReason::ZeroReward.into());
        }
        return None;
    }
    let (voter_rewards, staker_rewards, is_split) = vote_state.commission_split(rewards);
    if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
        inflation_point_calc_tracer(&InflationPointCalculationEvent::SplitRewards(
            rewards,
            voter_rewards,
            staker_rewards,
            (*point_value).clone(),
        ));
    }

    if (voter_rewards == 0 || staker_rewards == 0) && is_split {
        // don't collect if we lose a whole lamport somewhere
        //  is_split means there should be tokens on both sides,
        //  uncool to move credits_observed if one side didn't get paid
        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(&SkippedReason::TooEarlyUnfairSplit.into());
        }
        return None;
    }

    Some((staker_rewards, voter_rewards, credits_observed))
}

pub trait StakeAccount {
    fn initialize(
        &self,
        authorized: &Authorized,
        lockup: &Lockup,
        rent: &Rent,
    ) -> Result<(), InstructionError>;
    fn authorize(
        &self,
        signers: &HashSet<Pubkey>,
        new_authority: &Pubkey,
        stake_authorize: StakeAuthorize,
        require_custodian_for_locked_stake_authorize: bool,
        clock: &Clock,
        custodian: Option<&Pubkey>,
    ) -> Result<(), InstructionError>;
    fn authorize_with_seed(
        &self,
        authority_base: &KeyedAccount,
        authority_seed: &str,
        authority_owner: &Pubkey,
        new_authority: &Pubkey,
        stake_authorize: StakeAuthorize,
        require_custodian_for_locked_stake_authorize: bool,
        clock: &Clock,
        custodian: Option<&Pubkey>,
    ) -> Result<(), InstructionError>;
    fn delegate(
        &self,
        vote_account: &KeyedAccount,
        clock: &Clock,
        stake_history: &StakeHistory,
        config: &Config,
        signers: &HashSet<Pubkey>,
        can_reverse_deactivation: bool,
    ) -> Result<(), InstructionError>;
    fn deactivate(&self, clock: &Clock, signers: &HashSet<Pubkey>) -> Result<(), InstructionError>;
    fn set_lockup(
        &self,
        lockup: &LockupArgs,
        signers: &HashSet<Pubkey>,
        clock: Option<&Clock>,
    ) -> Result<(), InstructionError>;
    fn split(
        &self,
        lamports: u64,
        split_stake: &KeyedAccount,
        signers: &HashSet<Pubkey>,
    ) -> Result<(), InstructionError>;
    fn merge(
        &self,
        invoke_context: &InvokeContext,
        source_stake: &KeyedAccount,
        clock: &Clock,
        stake_history: &StakeHistory,
        signers: &HashSet<Pubkey>,
        can_merge_expired_lockups: bool,
    ) -> Result<(), InstructionError>;
    fn withdraw(
        &self,
        lamports: u64,
        to: &KeyedAccount,
        clock: &Clock,
        stake_history: &StakeHistory,
        withdraw_authority: &KeyedAccount,
        custodian: Option<&KeyedAccount>,
        prevent_withdraw_to_zero: bool,
    ) -> Result<(), InstructionError>;
}

impl<'a> StakeAccount for KeyedAccount<'a> {
    fn initialize(
        &self,
        authorized: &Authorized,
        lockup: &Lockup,
        rent: &Rent,
    ) -> Result<(), InstructionError> {
        if self.data_len()? != std::mem::size_of::<StakeState>() {
            return Err(InstructionError::InvalidAccountData);
        }
        if let StakeState::Uninitialized = self.state()? {
            let rent_exempt_reserve = rent.minimum_balance(self.data_len()?);

            if rent_exempt_reserve < self.lamports()? {
                self.set_state(&StakeState::Initialized(Meta {
                    rent_exempt_reserve,
                    authorized: *authorized,
                    lockup: *lockup,
                }))
            } else {
                Err(InstructionError::InsufficientFunds)
            }
        } else {
            Err(InstructionError::InvalidAccountData)
        }
    }

    /// Authorize the given pubkey to manage stake (deactivate, withdraw). This may be called
    /// multiple times, but will implicitly withdraw authorization from the previously authorized
    /// staker. The default staker is the owner of the stake account's pubkey.
    fn authorize(
        &self,
        signers: &HashSet<Pubkey>,
        new_authority: &Pubkey,
        stake_authorize: StakeAuthorize,
        require_custodian_for_locked_stake_authorize: bool,
        clock: &Clock,
        custodian: Option<&Pubkey>,
    ) -> Result<(), InstructionError> {
        match self.state()? {
            StakeState::Stake(mut meta, stake) => {
                meta.authorized.authorize(
                    signers,
                    new_authority,
                    stake_authorize,
                    if require_custodian_for_locked_stake_authorize {
                        Some((&meta.lockup, clock, custodian))
                    } else {
                        None
                    },
                )?;
                self.set_state(&StakeState::Stake(meta, stake))
            }
            StakeState::Initialized(mut meta) => {
                meta.authorized.authorize(
                    signers,
                    new_authority,
                    stake_authorize,
                    if require_custodian_for_locked_stake_authorize {
                        Some((&meta.lockup, clock, custodian))
                    } else {
                        None
                    },
                )?;
                self.set_state(&StakeState::Initialized(meta))
            }
            _ => Err(InstructionError::InvalidAccountData),
        }
    }
    fn authorize_with_seed(
        &self,
        authority_base: &KeyedAccount,
        authority_seed: &str,
        authority_owner: &Pubkey,
        new_authority: &Pubkey,
        stake_authorize: StakeAuthorize,
        require_custodian_for_locked_stake_authorize: bool,
        clock: &Clock,
        custodian: Option<&Pubkey>,
    ) -> Result<(), InstructionError> {
        let mut signers = HashSet::default();
        if let Some(base_pubkey) = authority_base.signer_key() {
            signers.insert(Pubkey::create_with_seed(
                base_pubkey,
                authority_seed,
                authority_owner,
            )?);
        }
        self.authorize(
            &signers,
            new_authority,
            stake_authorize,
            require_custodian_for_locked_stake_authorize,
            clock,
            custodian,
        )
    }
    fn delegate(
        &self,
        vote_account: &KeyedAccount,
        clock: &Clock,
        stake_history: &StakeHistory,
        config: &Config,
        signers: &HashSet<Pubkey>,
        can_reverse_deactivation: bool,
    ) -> Result<(), InstructionError> {
        if vote_account.owner()? != solana_vote_program::id() {
            return Err(InstructionError::IncorrectProgramId);
        }

        match self.state()? {
            StakeState::Initialized(meta) => {
                meta.authorized.check(signers, StakeAuthorize::Staker)?;
                let stake = new_stake(
                    self.lamports()?.saturating_sub(meta.rent_exempt_reserve), // can't stake the rent ;)
                    vote_account.unsigned_key(),
                    &State::<VoteStateVersions>::state(vote_account)?.convert_to_current(),
                    clock.epoch,
                    config,
                );
                self.set_state(&StakeState::Stake(meta, stake))
            }
            StakeState::Stake(meta, mut stake) => {
                meta.authorized.check(signers, StakeAuthorize::Staker)?;
                redelegate(
                    &mut stake,
                    self.lamports()?.saturating_sub(meta.rent_exempt_reserve), // can't stake the rent ;)
                    vote_account.unsigned_key(),
                    &State::<VoteStateVersions>::state(vote_account)?.convert_to_current(),
                    clock,
                    stake_history,
                    config,
                    can_reverse_deactivation,
                )?;
                self.set_state(&StakeState::Stake(meta, stake))
            }
            _ => Err(InstructionError::InvalidAccountData),
        }
    }
    fn deactivate(&self, clock: &Clock, signers: &HashSet<Pubkey>) -> Result<(), InstructionError> {
        if let StakeState::Stake(meta, mut stake) = self.state()? {
            meta.authorized.check(signers, StakeAuthorize::Staker)?;
            stake.deactivate(clock.epoch)?;

            self.set_state(&StakeState::Stake(meta, stake))
        } else {
            Err(InstructionError::InvalidAccountData)
        }
    }
    fn set_lockup(
        &self,
        lockup: &LockupArgs,
        signers: &HashSet<Pubkey>,
        clock: Option<&Clock>,
    ) -> Result<(), InstructionError> {
        match self.state()? {
            StakeState::Initialized(mut meta) => {
                meta.set_lockup(lockup, signers, clock)?;
                self.set_state(&StakeState::Initialized(meta))
            }
            StakeState::Stake(mut meta, stake) => {
                meta.set_lockup(lockup, signers, clock)?;
                self.set_state(&StakeState::Stake(meta, stake))
            }
            _ => Err(InstructionError::InvalidAccountData),
        }
    }

    fn split(
        &self,
        lamports: u64,
        split: &KeyedAccount,
        signers: &HashSet<Pubkey>,
    ) -> Result<(), InstructionError> {
        if split.owner()? != id() {
            return Err(InstructionError::IncorrectProgramId);
        }
        if split.data_len()? != std::mem::size_of::<StakeState>() {
            return Err(InstructionError::InvalidAccountData);
        }

        if let StakeState::Uninitialized = split.state()? {
            // verify enough account lamports
            if lamports > self.lamports()? {
                return Err(InstructionError::InsufficientFunds);
            }

            match self.state()? {
                StakeState::Stake(meta, mut stake) => {
                    meta.authorized.check(signers, StakeAuthorize::Staker)?;
                    let split_rent_exempt_reserve = calculate_split_rent_exempt_reserve(
                        meta.rent_exempt_reserve,
                        self.data_len()? as u64,
                        split.data_len()? as u64,
                    );

                    // verify enough lamports for rent and more than 0 stake in new split account
                    if lamports <= split_rent_exempt_reserve.saturating_sub(split.lamports()?)
                        // if not full withdrawal
                        || (lamports != self.lamports()?
                            // verify more than 0 stake left in previous stake
                            && checked_add(lamports, meta.rent_exempt_reserve)? >= self.lamports()?)
                    {
                        return Err(InstructionError::InsufficientFunds);
                    }
                    // split the stake, subtract rent_exempt_balance unless
                    // the destination account already has those lamports
                    // in place.
                    // this means that the new stake account will have a stake equivalent to
                    // lamports minus rent_exempt_reserve if it starts out with a zero balance
                    let (remaining_stake_delta, split_stake_amount) = if lamports
                        == self.lamports()?
                    {
                        // If split amount equals the full source stake, the new split stake must
                        // equal the same amount, regardless of any current lamport balance in the
                        // split account. Since split accounts retain the state of their source
                        // account, this prevents any magic activation of stake by prefunding the
                        // split account.
                        // The new split stake also needs to ignore any positive delta between the
                        // original rent_exempt_reserve and the split_rent_exempt_reserve, in order
                        // to prevent magic activation of stake by splitting between accounts of
                        // different sizes.
                        let remaining_stake_delta =
                            lamports.saturating_sub(meta.rent_exempt_reserve);
                        (remaining_stake_delta, remaining_stake_delta)
                    } else {
                        // Otherwise, the new split stake should reflect the entire split
                        // requested, less any lamports needed to cover the split_rent_exempt_reserve
                        (
                            lamports,
                            lamports - split_rent_exempt_reserve.saturating_sub(split.lamports()?),
                        )
                    };
                    let split_stake = stake.split(remaining_stake_delta, split_stake_amount)?;
                    let mut split_meta = meta;
                    split_meta.rent_exempt_reserve = split_rent_exempt_reserve;

                    self.set_state(&StakeState::Stake(meta, stake))?;
                    split.set_state(&StakeState::Stake(split_meta, split_stake))?;
                }
                StakeState::Initialized(meta) => {
                    meta.authorized.check(signers, StakeAuthorize::Staker)?;
                    let split_rent_exempt_reserve = calculate_split_rent_exempt_reserve(
                        meta.rent_exempt_reserve,
                        self.data_len()? as u64,
                        split.data_len()? as u64,
                    );

                    // enough lamports for rent and more than 0 stake in new split account
                    if lamports <= split_rent_exempt_reserve.saturating_sub(split.lamports()?)
                        // if not full withdrawal
                        || (lamports != self.lamports()?
                            // verify more than 0 stake left in previous stake
                            && checked_add(lamports, meta.rent_exempt_reserve)? >= self.lamports()?)
                    {
                        return Err(InstructionError::InsufficientFunds);
                    }

                    let mut split_meta = meta;
                    split_meta.rent_exempt_reserve = split_rent_exempt_reserve;
                    split.set_state(&StakeState::Initialized(split_meta))?;
                }
                StakeState::Uninitialized => {
                    if !signers.contains(self.unsigned_key()) {
                        return Err(InstructionError::MissingRequiredSignature);
                    }
                }
                _ => return Err(InstructionError::InvalidAccountData),
            }

            // Deinitialize state upon zero balance
            if lamports == self.lamports()? {
                self.set_state(&StakeState::Uninitialized)?;
            }

            split
                .try_account_ref_mut()?
                .checked_add_lamports(lamports)?;
            self.try_account_ref_mut()?.checked_sub_lamports(lamports)?;
            Ok(())
        } else {
            Err(InstructionError::InvalidAccountData)
        }
    }

    fn merge(
        &self,
        invoke_context: &InvokeContext,
        source_account: &KeyedAccount,
        clock: &Clock,
        stake_history: &StakeHistory,
        signers: &HashSet<Pubkey>,
        can_merge_expired_lockups: bool,
    ) -> Result<(), InstructionError> {
        // Ensure source isn't spoofed
        if source_account.owner()? != id() {
            return Err(InstructionError::IncorrectProgramId);
        }
        // Close the self-reference loophole
        if source_account.unsigned_key() == self.unsigned_key() {
            return Err(InstructionError::InvalidArgument);
        }

        ic_msg!(invoke_context, "Checking if destination stake is mergeable");
        let stake_merge_kind =
            MergeKind::get_if_mergeable(invoke_context, self, clock, stake_history)?;
        let meta = stake_merge_kind.meta();

        // Authorized staker is allowed to split/merge accounts
        meta.authorized.check(signers, StakeAuthorize::Staker)?;

        ic_msg!(invoke_context, "Checking if source stake is mergeable");
        let source_merge_kind =
            MergeKind::get_if_mergeable(invoke_context, source_account, clock, stake_history)?;

        let clock = if can_merge_expired_lockups {
            Some(clock)
        } else {
            None
        };

        ic_msg!(invoke_context, "Merging stake accounts");
        if let Some(merged_state) =
            stake_merge_kind.merge(invoke_context, source_merge_kind, clock)?
        {
            self.set_state(&merged_state)?;
        }

        // Source is about to be drained, deinitialize its state
        source_account.set_state(&StakeState::Uninitialized)?;

        // Drain the source stake account
        let lamports = source_account.lamports()?;
        source_account
            .try_account_ref_mut()?
            .checked_sub_lamports(lamports)?;
        self.try_account_ref_mut()?.checked_add_lamports(lamports)?;
        Ok(())
    }

    fn withdraw(
        &self,
        lamports: u64,
        to: &KeyedAccount,
        clock: &Clock,
        stake_history: &StakeHistory,
        withdraw_authority: &KeyedAccount,
        custodian: Option<&KeyedAccount>,
        prevent_withdraw_to_zero: bool,
    ) -> Result<(), InstructionError> {
        let mut signers = HashSet::new();
        let withdraw_authority_pubkey = withdraw_authority
            .signer_key()
            .ok_or(InstructionError::MissingRequiredSignature)?;
        signers.insert(*withdraw_authority_pubkey);

        let (lockup, reserve, is_staked) = match self.state()? {
            StakeState::Stake(meta, stake) => {
                meta.authorized
                    .check(&signers, StakeAuthorize::Withdrawer)?;
                // if we have a deactivation epoch and we're in cooldown
                let staked = if clock.epoch >= stake.delegation.deactivation_epoch {
                    stake.delegation.stake(clock.epoch, Some(stake_history))
                } else {
                    // Assume full stake if the stake account hasn't been
                    //  de-activated, because in the future the exposed stake
                    //  might be higher than stake.stake() due to warmup
                    stake.delegation.stake
                };

                let staked_and_reserve = checked_add(staked, meta.rent_exempt_reserve)?;
                (meta.lockup, staked_and_reserve, staked != 0)
            }
            StakeState::Initialized(meta) => {
                meta.authorized
                    .check(&signers, StakeAuthorize::Withdrawer)?;
                let reserve = if prevent_withdraw_to_zero {
                    checked_add(meta.rent_exempt_reserve, 1)? // stake accounts must have a balance > rent_exempt_reserve
                } else {
                    meta.rent_exempt_reserve
                };

                (meta.lockup, reserve, false)
            }
            StakeState::Uninitialized => {
                if !signers.contains(self.unsigned_key()) {
                    return Err(InstructionError::MissingRequiredSignature);
                }
                (Lockup::default(), 0, false) // no lockup, no restrictions
            }
            _ => return Err(InstructionError::InvalidAccountData),
        };

        // verify that lockup has expired or that the withdrawal is signed by
        //   the custodian, both epoch and unix_timestamp must have passed
        let custodian_pubkey = custodian.and_then(|keyed_account| keyed_account.signer_key());
        if lockup.is_in_force(clock, custodian_pubkey) {
            return Err(StakeError::LockupInForce.into());
        }

        let lamports_and_reserve = checked_add(lamports, reserve)?;
        // if the stake is active, we mustn't allow the account to go away
        if is_staked // line coverage for branch coverage
            && lamports_and_reserve > self.lamports()?
        {
            return Err(InstructionError::InsufficientFunds);
        }

        if lamports != self.lamports()? // not a full withdrawal
            && lamports_and_reserve > self.lamports()?
        {
            assert!(!is_staked);
            return Err(InstructionError::InsufficientFunds);
        }

        // Deinitialize state upon zero balance
        if lamports == self.lamports()? {
            self.set_state(&StakeState::Uninitialized)?;
        }

        self.try_account_ref_mut()?.checked_sub_lamports(lamports)?;
        to.try_account_ref_mut()?.checked_add_lamports(lamports)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
enum MergeKind {
    Inactive(Meta, u64),
    ActivationEpoch(Meta, Stake),
    FullyActive(Meta, Stake),
}

impl MergeKind {
    fn meta(&self) -> &Meta {
        match self {
            Self::Inactive(meta, _) => meta,
            Self::ActivationEpoch(meta, _) => meta,
            Self::FullyActive(meta, _) => meta,
        }
    }

    fn active_stake(&self) -> Option<&Stake> {
        match self {
            Self::Inactive(_, _) => None,
            Self::ActivationEpoch(_, stake) => Some(stake),
            Self::FullyActive(_, stake) => Some(stake),
        }
    }

    fn get_if_mergeable(
        invoke_context: &InvokeContext,
        stake_keyed_account: &KeyedAccount,
        clock: &Clock,
        stake_history: &StakeHistory,
    ) -> Result<Self, InstructionError> {
        match stake_keyed_account.state()? {
            StakeState::Stake(meta, stake) => {
                // stake must not be in a transient state. Transient here meaning
                // activating or deactivating with non-zero effective stake.
                let status = stake
                    .delegation
                    .stake_activating_and_deactivating(clock.epoch, Some(stake_history));

                match (status.effective, status.activating, status.deactivating) {
                    (0, 0, 0) => Ok(Self::Inactive(meta, stake_keyed_account.lamports()?)),
                    (0, _, _) => Ok(Self::ActivationEpoch(meta, stake)),
                    (_, 0, 0) => Ok(Self::FullyActive(meta, stake)),
                    _ => {
                        let err = StakeError::MergeTransientStake;
                        ic_msg!(invoke_context, "{}", err);
                        Err(err.into())
                    }
                }
            }
            StakeState::Initialized(meta) => {
                Ok(Self::Inactive(meta, stake_keyed_account.lamports()?))
            }
            _ => Err(InstructionError::InvalidAccountData),
        }
    }

    fn metas_can_merge(
        invoke_context: &InvokeContext,
        stake: &Meta,
        source: &Meta,
        clock: Option<&Clock>,
    ) -> Result<(), InstructionError> {
        let can_merge_lockups = match clock {
            // pre-v4 behavior. lockups must match, even when expired
            None => stake.lockup == source.lockup,
            // v4 behavior. lockups may mismatch so long as both have expired
            Some(clock) => {
                stake.lockup == source.lockup
                    || (!stake.lockup.is_in_force(clock, None)
                        && !source.lockup.is_in_force(clock, None))
            }
        };
        // `rent_exempt_reserve` has no bearing on the mergeability of accounts,
        // as the source account will be culled by runtime once the operation
        // succeeds. Considering it here would needlessly prevent merging stake
        // accounts with differing data lengths, which already exist in the wild
        // due to an SDK bug
        if stake.authorized == source.authorized && can_merge_lockups {
            Ok(())
        } else {
            ic_msg!(invoke_context, "Unable to merge due to metadata mismatch");
            Err(StakeError::MergeMismatch.into())
        }
    }

    fn active_delegations_can_merge(
        invoke_context: &InvokeContext,
        stake: &Delegation,
        source: &Delegation,
    ) -> Result<(), InstructionError> {
        if stake.voter_pubkey != source.voter_pubkey {
            ic_msg!(invoke_context, "Unable to merge due to voter mismatch");
            Err(StakeError::MergeMismatch.into())
        } else if (stake.warmup_cooldown_rate - source.warmup_cooldown_rate).abs() < f64::EPSILON
            && stake.deactivation_epoch == Epoch::MAX
            && source.deactivation_epoch == Epoch::MAX
        {
            Ok(())
        } else {
            ic_msg!(invoke_context, "Unable to merge due to stake deactivation");
            Err(StakeError::MergeMismatch.into())
        }
    }

    // Remove this when the `stake_merge_with_unmatched_credits_observed` feature is removed
    fn active_stakes_can_merge(
        invoke_context: &InvokeContext,
        stake: &Stake,
        source: &Stake,
    ) -> Result<(), InstructionError> {
        Self::active_delegations_can_merge(invoke_context, &stake.delegation, &source.delegation)?;
        // `credits_observed` MUST match to prevent earning multiple rewards
        // from a stake account by merging it into another stake account that
        // is small enough to not be paid out every epoch. This would effectively
        // reset the larger stake accounts `credits_observed` to that of the
        // smaller account.
        if stake.credits_observed == source.credits_observed {
            Ok(())
        } else {
            ic_msg!(
                invoke_context,
                "Unable to merge due to credits observed mismatch"
            );
            Err(StakeError::MergeMismatch.into())
        }
    }

    fn merge(
        self,
        invoke_context: &InvokeContext,
        source: Self,
        clock: Option<&Clock>,
    ) -> Result<Option<StakeState>, InstructionError> {
        Self::metas_can_merge(invoke_context, self.meta(), source.meta(), clock)?;
        self.active_stake()
            .zip(source.active_stake())
            .map(|(stake, source)| {
                if invoke_context
                    .feature_set
                    .is_active(&stake_merge_with_unmatched_credits_observed::id())
                {
                    Self::active_delegations_can_merge(
                        invoke_context,
                        &stake.delegation,
                        &source.delegation,
                    )
                } else {
                    Self::active_stakes_can_merge(invoke_context, stake, source)
                }
            })
            .unwrap_or(Ok(()))?;
        let merged_state = match (self, source) {
            (Self::Inactive(_, _), Self::Inactive(_, _)) => None,
            (Self::Inactive(_, _), Self::ActivationEpoch(_, _)) => None,
            (Self::ActivationEpoch(meta, mut stake), Self::Inactive(_, source_lamports)) => {
                stake.delegation.stake = checked_add(stake.delegation.stake, source_lamports)?;
                Some(StakeState::Stake(meta, stake))
            }
            (
                Self::ActivationEpoch(meta, mut stake),
                Self::ActivationEpoch(source_meta, source_stake),
            ) => {
                let source_lamports = checked_add(
                    source_meta.rent_exempt_reserve,
                    source_stake.delegation.stake,
                )?;
                merge_delegation_stake_and_credits_observed(
                    invoke_context,
                    &mut stake,
                    source_lamports,
                    source_stake.credits_observed,
                )?;
                Some(StakeState::Stake(meta, stake))
            }
            (Self::FullyActive(meta, mut stake), Self::FullyActive(_, source_stake)) => {
                // Don't stake the source account's `rent_exempt_reserve` to
                // protect against the magic activation loophole. It will
                // instead be moved into the destination account as extra,
                // withdrawable `lamports`
                merge_delegation_stake_and_credits_observed(
                    invoke_context,
                    &mut stake,
                    source_stake.delegation.stake,
                    source_stake.credits_observed,
                )?;
                Some(StakeState::Stake(meta, stake))
            }
            _ => return Err(StakeError::MergeMismatch.into()),
        };
        Ok(merged_state)
    }
}

fn merge_delegation_stake_and_credits_observed(
    invoke_context: &InvokeContext,
    stake: &mut Stake,
    absorbed_lamports: u64,
    absorbed_credits_observed: u64,
) -> Result<(), InstructionError> {
    if invoke_context
        .feature_set
        .is_active(&stake_merge_with_unmatched_credits_observed::id())
    {
        stake.credits_observed =
            stake_weighted_credits_observed(stake, absorbed_lamports, absorbed_credits_observed)
                .ok_or(InstructionError::ArithmeticOverflow)?;
    }
    stake.delegation.stake = checked_add(stake.delegation.stake, absorbed_lamports)?;
    Ok(())
}

/// Calculate the effective credits observed for two stakes when merging
///
/// When merging two `ActivationEpoch` or `FullyActive` stakes, the credits
/// observed of the merged stake is the weighted average of the two stakes'
/// credits observed.
///
/// This is because we can derive the effective credits_observed by reversing the staking
/// rewards equation, _while keeping the rewards unchanged after merge (i.e. strong
/// requirement)_, like below:
///
/// a(N) => account, r => rewards, s => stake, c => credits:
/// assume:
///   a3 = merge(a1, a2)
/// then:
///   a3.s = a1.s + a2.s
///
/// Next, given:
///   aN.r = aN.c * aN.s (for every N)
/// finally:
///        a3.r = a1.r + a2.r
/// a3.c * a3.s = a1.c * a1.s + a2.c * a2.s
///        a3.c = (a1.c * a1.s + a2.c * a2.s) / (a1.s + a2.s)     // QED
///
/// (For this discussion, we omitted irrelevant variables, including distance
///  calculation against vote_account and point indirection.)
fn stake_weighted_credits_observed(
    stake: &Stake,
    absorbed_lamports: u64,
    absorbed_credits_observed: u64,
) -> Option<u64> {
    if stake.credits_observed == absorbed_credits_observed {
        Some(stake.credits_observed)
    } else {
        let total_stake = u128::from(stake.delegation.stake.checked_add(absorbed_lamports)?);
        let stake_weighted_credits =
            u128::from(stake.credits_observed).checked_mul(u128::from(stake.delegation.stake))?;
        let absorbed_weighted_credits =
            u128::from(absorbed_credits_observed).checked_mul(u128::from(absorbed_lamports))?;
        // Discard fractional credits as a merge side-effect friction by taking
        // the ceiling, done by adding `denominator - 1` to the numerator.
        let total_weighted_credits = stake_weighted_credits
            .checked_add(absorbed_weighted_credits)?
            .checked_add(total_stake)?
            .checked_sub(1)?;
        u64::try_from(total_weighted_credits.checked_div(total_stake)?).ok()
    }
}

// utility function, used by runtime
// returns a tuple of (stakers_reward,voters_reward)
#[doc(hidden)]
pub fn redeem_rewards(
    rewarded_epoch: Epoch,
    stake_state: StakeState,
    stake_account: &mut AccountSharedData,
    vote_state: &VoteState,
    point_value: &PointValue,
    stake_history: Option<&StakeHistory>,
    inflation_point_calc_tracer: Option<impl Fn(&InflationPointCalculationEvent)>,
    fix_activating_credits_observed: bool,
) -> Result<(u64, u64), InstructionError> {
    if let StakeState::Stake(meta, mut stake) = stake_state {
        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(
                &InflationPointCalculationEvent::EffectiveStakeAtRewardedEpoch(
                    stake.stake(rewarded_epoch, stake_history),
                ),
            );
            inflation_point_calc_tracer(&InflationPointCalculationEvent::RentExemptReserve(
                meta.rent_exempt_reserve,
            ));
            inflation_point_calc_tracer(&InflationPointCalculationEvent::Commission(
                vote_state.commission,
            ));
        }

        if let Some((stakers_reward, voters_reward)) = redeem_stake_rewards(
            rewarded_epoch,
            &mut stake,
            point_value,
            vote_state,
            stake_history,
            inflation_point_calc_tracer,
            fix_activating_credits_observed,
        ) {
            stake_account.checked_add_lamports(stakers_reward)?;
            stake_account.set_state(&StakeState::Stake(meta, stake))?;

            Ok((stakers_reward, voters_reward))
        } else {
            Err(StakeError::NoCreditsToRedeem.into())
        }
    } else {
        Err(InstructionError::InvalidAccountData)
    }
}

// utility function, used by runtime
#[doc(hidden)]
pub fn calculate_points(
    stake_state: &StakeState,
    vote_state: &VoteState,
    stake_history: Option<&StakeHistory>,
) -> Result<u128, InstructionError> {
    if let StakeState::Stake(_meta, stake) = stake_state {
        Ok(calculate_stake_points(
            stake,
            vote_state,
            stake_history,
            null_tracer(),
        ))
    } else {
        Err(InstructionError::InvalidAccountData)
    }
}

// utility function, used by Split
//This emulates current Rent math in order to preserve backward compatibility. In the future, and
//to support variable rent, the Split instruction should pass in the Rent sysvar instead.
fn calculate_split_rent_exempt_reserve(
    source_rent_exempt_reserve: u64,
    source_data_len: u64,
    split_data_len: u64,
) -> u64 {
    let lamports_per_byte_year =
        source_rent_exempt_reserve / (source_data_len + ACCOUNT_STORAGE_OVERHEAD);
    lamports_per_byte_year * (split_data_len + ACCOUNT_STORAGE_OVERHEAD)
}

pub type RewriteStakeStatus = (&'static str, (u64, u64), (u64, u64));

// utility function, used by runtime::Stakes, tests
pub fn new_stake_history_entry<'a, I>(
    epoch: Epoch,
    stakes: I,
    history: Option<&StakeHistory>,
) -> StakeHistoryEntry
where
    I: Iterator<Item = &'a Delegation>,
{
    stakes.fold(StakeHistoryEntry::default(), |sum, stake| {
        sum + stake.stake_activating_and_deactivating(epoch, history)
    })
}

// genesis investor accounts
pub fn create_lockup_stake_account(
    authorized: &Authorized,
    lockup: &Lockup,
    rent: &Rent,
    lamports: u64,
) -> AccountSharedData {
    let mut stake_account =
        AccountSharedData::new(lamports, std::mem::size_of::<StakeState>(), &id());

    let rent_exempt_reserve = rent.minimum_balance(stake_account.data().len());
    assert!(
        lamports >= rent_exempt_reserve,
        "lamports: {} is less than rent_exempt_reserve {}",
        lamports,
        rent_exempt_reserve
    );

    stake_account
        .set_state(&StakeState::Initialized(Meta {
            authorized: *authorized,
            lockup: *lockup,
            rent_exempt_reserve,
        }))
        .expect("set_state");

    stake_account
}

// utility function, used by Bank, tests, genesis for bootstrap
pub fn create_account(
    authorized: &Pubkey,
    voter_pubkey: &Pubkey,
    vote_account: &AccountSharedData,
    rent: &Rent,
    lamports: u64,
) -> AccountSharedData {
    do_create_account(
        authorized,
        voter_pubkey,
        vote_account,
        rent,
        lamports,
        Epoch::MAX,
    )
}

// utility function, used by tests
pub fn create_account_with_activation_epoch(
    authorized: &Pubkey,
    voter_pubkey: &Pubkey,
    vote_account: &AccountSharedData,
    rent: &Rent,
    lamports: u64,
    activation_epoch: Epoch,
) -> AccountSharedData {
    do_create_account(
        authorized,
        voter_pubkey,
        vote_account,
        rent,
        lamports,
        activation_epoch,
    )
}

fn do_create_account(
    authorized: &Pubkey,
    voter_pubkey: &Pubkey,
    vote_account: &AccountSharedData,
    rent: &Rent,
    lamports: u64,
    activation_epoch: Epoch,
) -> AccountSharedData {
    let mut stake_account =
        AccountSharedData::new(lamports, std::mem::size_of::<StakeState>(), &id());

    let vote_state = VoteState::from(vote_account).expect("vote_state");

    let rent_exempt_reserve = rent.minimum_balance(stake_account.data().len());

    stake_account
        .set_state(&StakeState::Stake(
            Meta {
                authorized: Authorized::auto(authorized),
                rent_exempt_reserve,
                ..Meta::default()
            },
            new_stake(
                lamports - rent_exempt_reserve, // underflow is an error, is basically: assert!(lamports > rent_exempt_reserve);
                voter_pubkey,
                &vote_state,
                activation_epoch,
                &Config::default(),
            ),
        ))
        .expect("set_state");

    stake_account
}

