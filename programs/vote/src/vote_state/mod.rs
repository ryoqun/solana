//! Vote state, vote program
//! Receive and processes votes from validators
pub use solana_program::vote::state::{vote_state_versions::*, *};
use {
    log::*,
    serde_derive::{Deserialize, Serialize},
    solana_metrics::datapoint_debug,
    solana_program::vote::{error::VoteError, program::id, state::serde_compact_vote_state_update},
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        clock::{Epoch, Slot, UnixTimestamp},
        epoch_schedule::EpochSchedule,
        feature_set::{self, filter_votes_outside_slot_hashes, FeatureSet},
        hash::Hash,
        instruction::InstructionError,
        pubkey::Pubkey,
        rent::Rent,
        slot_hashes::SlotHash,
        sysvar::clock::Clock,
        transaction_context::{
            BorrowedAccount, IndexOfAccount, InstructionContext, TransactionContext,
        },
    },
    std::{
        cmp::Ordering,
        collections::{HashSet, VecDeque},
        fmt::Debug,
    },
};

#[frozen_abi(digest = "2AuJFjx7SYrJ2ugCfH1jFh3Lr9UHMEPfKwwk1NcjqND1")]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, AbiEnumVisitor, AbiExample)]
pub enum VoteTransaction {
    Vote(Vote),
    VoteStateUpdate(VoteStateUpdate),
    #[serde(with = "serde_compact_vote_state_update")]
    CompactVoteStateUpdate(VoteStateUpdate),
}

impl VoteTransaction {
    pub fn slots(&self) -> Vec<Slot> {
        match self {
            VoteTransaction::Vote(vote) => vote.slots.clone(),
            VoteTransaction::VoteStateUpdate(vote_state_update) => vote_state_update.slots(),
            VoteTransaction::CompactVoteStateUpdate(vote_state_update) => vote_state_update.slots(),
        }
    }

    pub fn slot(&self, i: usize) -> Slot {
        match self {
            VoteTransaction::Vote(vote) => vote.slots[i],
            VoteTransaction::VoteStateUpdate(vote_state_update)
            | VoteTransaction::CompactVoteStateUpdate(vote_state_update) => {
                vote_state_update.lockouts[i].slot()
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            VoteTransaction::Vote(vote) => vote.slots.len(),
            VoteTransaction::VoteStateUpdate(vote_state_update)
            | VoteTransaction::CompactVoteStateUpdate(vote_state_update) => {
                vote_state_update.lockouts.len()
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            VoteTransaction::Vote(vote) => vote.slots.is_empty(),
            VoteTransaction::VoteStateUpdate(vote_state_update)
            | VoteTransaction::CompactVoteStateUpdate(vote_state_update) => {
                vote_state_update.lockouts.is_empty()
            }
        }
    }

    pub fn hash(&self) -> Hash {
        match self {
            VoteTransaction::Vote(vote) => vote.hash,
            VoteTransaction::VoteStateUpdate(vote_state_update) => vote_state_update.hash,
            VoteTransaction::CompactVoteStateUpdate(vote_state_update) => vote_state_update.hash,
        }
    }

    pub fn timestamp(&self) -> Option<UnixTimestamp> {
        match self {
            VoteTransaction::Vote(vote) => vote.timestamp,
            VoteTransaction::VoteStateUpdate(vote_state_update)
            | VoteTransaction::CompactVoteStateUpdate(vote_state_update) => {
                vote_state_update.timestamp
            }
        }
    }

    pub fn set_timestamp(&mut self, ts: Option<UnixTimestamp>) {
        match self {
            VoteTransaction::Vote(vote) => vote.timestamp = ts,
            VoteTransaction::VoteStateUpdate(vote_state_update)
            | VoteTransaction::CompactVoteStateUpdate(vote_state_update) => {
                vote_state_update.timestamp = ts
            }
        }
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        match self {
            VoteTransaction::Vote(vote) => vote.last_voted_slot(),
            VoteTransaction::VoteStateUpdate(vote_state_update)
            | VoteTransaction::CompactVoteStateUpdate(vote_state_update) => {
                vote_state_update.last_voted_slot()
            }
        }
    }

    pub fn last_voted_slot_hash(&self) -> Option<(Slot, Hash)> {
        Some((self.last_voted_slot()?, self.hash()))
    }
}

impl From<Vote> for VoteTransaction {
    fn from(vote: Vote) -> Self {
        VoteTransaction::Vote(vote)
    }
}

impl From<VoteStateUpdate> for VoteTransaction {
    fn from(vote_state_update: VoteStateUpdate) -> Self {
        VoteTransaction::VoteStateUpdate(vote_state_update)
    }
}

// utility function, used by Stakes, tests
pub fn from<T: ReadableAccount>(account: &T) -> Option<VoteState> {
    VoteState::deserialize(account.data()).ok()
}

// utility function, used by Stakes, tests
pub fn to<T: WritableAccount>(versioned: &VoteStateVersions, account: &mut T) -> Option<()> {
    VoteState::serialize(versioned, account.data_as_mut_slice()).ok()
}

// Updates the vote account state with a new VoteState instance.  This is required temporarily during the
// upgrade of vote account state from V1_14_11 to Current.
fn set_vote_account_state(
    vote_account: &mut BorrowedAccount,
    vote_state: VoteState,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    // Only if vote_state_add_vote_latency feature is enabled should the new version of vote state be stored
    if feature_set.is_active(&feature_set::vote_state_add_vote_latency::id()) {
        // If the account is not large enough to store the vote state, then attempt a realloc to make it large enough.
        // The realloc can only proceed if the vote account has balance sufficient for rent exemption at the new size.
        if (vote_account.get_data().len() < VoteStateVersions::vote_state_size_of(true))
            && (!vote_account
                .is_rent_exempt_at_data_length(VoteStateVersions::vote_state_size_of(true))
                || vote_account
                    .set_data_length(VoteStateVersions::vote_state_size_of(true))
                    .is_err())
        {
            // Account cannot be resized to the size of a vote state as it will not be rent exempt, or failed to be
            // resized for other reasons.  So store the V1_14_11 version.
            return vote_account.set_state(&VoteStateVersions::V1_14_11(Box::new(
                VoteState1_14_11::from(vote_state),
            )));
        }
        // Vote account is large enough to store the newest version of vote state
        vote_account.set_state(&VoteStateVersions::new_current(vote_state))
    // Else when the vote_state_add_vote_latency feature is not enabled, then the V1_14_11 version is stored
    } else {
        vote_account.set_state(&VoteStateVersions::V1_14_11(Box::new(
            VoteState1_14_11::from(vote_state),
        )))
    }
}

fn check_update_vote_state_slots_are_valid(
    vote_state: &VoteState,
    vote_state_update: &mut VoteStateUpdate,
    slot_hashes: &[(Slot, Hash)],
    feature_set: Option<&FeatureSet>,
) -> Result<(), VoteError> {
    if vote_state_update.lockouts.is_empty() {
        return Err(VoteError::EmptySlots);
    }

    // If the vote state update is not new enough, return
    if let Some(last_vote_slot) = vote_state.votes.back().map(|lockout| lockout.slot()) {
        if vote_state_update.lockouts.back().unwrap().slot() <= last_vote_slot {
            return Err(VoteError::VoteTooOld);
        }
    }

    let last_vote_state_update_slot = vote_state_update
        .lockouts
        .back()
        .expect("must be nonempty, checked above")
        .slot();

    if slot_hashes.is_empty() {
        return Err(VoteError::SlotsMismatch);
    }
    let earliest_slot_hash_in_history = slot_hashes.last().unwrap().0;

    // Check if the proposed vote is too old to be in the SlotHash history
    if last_vote_state_update_slot < earliest_slot_hash_in_history {
        // If this is the last slot in the vote update, it must be in SlotHashes,
        // otherwise we have no way of confirming if the hash matches
        return Err(VoteError::VoteTooOld);
    }

    // Check if the proposed root is too old
    let is_root_fix_enabled = feature_set
        .map(|feature_set| feature_set.is_active(&feature_set::vote_state_update_root_fix::id()))
        .unwrap_or(false);

    let original_proposed_root = vote_state_update.root;
    if let Some(new_proposed_root) = original_proposed_root {
        // If the new proposed root `R` is less than the earliest slot hash in the history
        // such that we cannot verify whether the slot was actually was on this fork, set
        // the root to the latest vote in the current vote that's less than R.
        if earliest_slot_hash_in_history > new_proposed_root {
            vote_state_update.root = vote_state.root_slot;
            if is_root_fix_enabled {
                let mut prev_slot = Slot::MAX;
                let current_root = vote_state_update.root;
                for vote in vote_state.votes.iter().rev() {
                    let is_slot_bigger_than_root = current_root
                        .map(|current_root| vote.slot() > current_root)
                        .unwrap_or(true);
                    // Ensure we're iterating from biggest to smallest vote in the
                    // current vote state
                    assert!(vote.slot() < prev_slot && is_slot_bigger_than_root);
                    if vote.slot() <= new_proposed_root {
                        vote_state_update.root = Some(vote.slot());
                        break;
                    }
                    prev_slot = vote.slot();
                }
            }
        }
    }

    // Index into the new proposed vote state's slots, starting with the root if it exists then
    // we use this mutable root to fold checking the root slot into the below loop
    // for performance
    let mut root_to_check = vote_state_update.root;
    let mut vote_state_update_index = 0;

    // index into the slot_hashes, starting at the oldest known
    // slot hash
    let mut slot_hashes_index = slot_hashes.len();

    let mut vote_state_update_indexes_to_filter = vec![];

    // Note:
    //
    // 1) `vote_state_update.lockouts` is sorted from oldest/smallest vote to newest/largest
    // vote, due to the way votes are applied to the vote state (newest votes
    // pushed to the back).
    //
    // 2) Conversely, `slot_hashes` is sorted from newest/largest vote to
    // the oldest/smallest vote
    //
    // Unlike for vote updates, vote state updates here can't only check votes older than the last vote
    // because have to ensure that every slot is actually part of the history, not just the most
    // recent ones
    while vote_state_update_index < vote_state_update.lockouts.len() && slot_hashes_index > 0 {
        let proposed_vote_slot = if let Some(root) = root_to_check {
            root
        } else {
            vote_state_update.lockouts[vote_state_update_index].slot()
        };
        if root_to_check.is_none()
            && vote_state_update_index > 0
            && proposed_vote_slot
                <= vote_state_update.lockouts[vote_state_update_index.checked_sub(1).expect(
                    "`vote_state_update_index` is positive when checking `SlotsNotOrdered`",
                )]
                .slot()
        {
            return Err(VoteError::SlotsNotOrdered);
        }
        let ancestor_slot = slot_hashes[slot_hashes_index
            .checked_sub(1)
            .expect("`slot_hashes_index` is positive when computing `ancestor_slot`")]
        .0;

        // Find if this slot in the proposed vote state exists in the SlotHashes history
        // to confirm if it was a valid ancestor on this fork
        match proposed_vote_slot.cmp(&ancestor_slot) {
            Ordering::Less => {
                if slot_hashes_index == slot_hashes.len() {
                    // The vote slot does not exist in the SlotHashes history because it's too old,
                    // i.e. older than the oldest slot in the history.
                    assert!(proposed_vote_slot < earliest_slot_hash_in_history);
                    if !vote_state.contains_slot(proposed_vote_slot) && root_to_check.is_none() {
                        // If the vote slot is both:
                        // 1) Too old
                        // 2) Doesn't already exist in vote state
                        //
                        // Then filter it out
                        vote_state_update_indexes_to_filter.push(vote_state_update_index);
                    }
                    if let Some(new_proposed_root) = root_to_check {
                        if is_root_fix_enabled {
                            // 1. Because `root_to_check.is_some()`, then we know that
                            // we haven't checked the root yet in this loop, so
                            // `proposed_vote_slot` == `new_proposed_root` == `vote_state_update.root`.
                            assert_eq!(new_proposed_root, proposed_vote_slot);
                            // 2. We know from the assert earlier in the function that
                            // `proposed_vote_slot < earliest_slot_hash_in_history`,
                            // so from 1. we know that `new_proposed_root < earliest_slot_hash_in_history`.
                            assert!(new_proposed_root < earliest_slot_hash_in_history);
                        } else {
                            // If the vote state update has a root < earliest_slot_hash_in_history
                            // then we use the current root. The only case where this can happen
                            // is if the current root itself is not in slot hashes.
                            assert!(vote_state.root_slot.unwrap() < earliest_slot_hash_in_history);
                        }
                        root_to_check = None;
                    } else {
                        vote_state_update_index = vote_state_update_index.checked_add(1).expect(
                            "`vote_state_update_index` is bounded by `MAX_LOCKOUT_HISTORY` when `proposed_vote_slot` is too old to be in SlotHashes history",
                        );
                    }
                    continue;
                } else {
                    // If the vote slot is new enough to be in the slot history,
                    // but is not part of the slot history, then it must belong to another fork,
                    // which means this vote state update is invalid.
                    if root_to_check.is_some() {
                        return Err(VoteError::RootOnDifferentFork);
                    } else {
                        return Err(VoteError::SlotsMismatch);
                    }
                }
            }
            Ordering::Greater => {
                // Decrement `slot_hashes_index` to find newer slots in the SlotHashes history
                slot_hashes_index = slot_hashes_index
                    .checked_sub(1)
                    .expect("`slot_hashes_index` is positive when finding newer slots in SlotHashes history");
                continue;
            }
            Ordering::Equal => {
                // Once the slot in `vote_state_update.lockouts` is found, bump to the next slot
                // in `vote_state_update.lockouts` and continue. If we were checking the root,
                // start checking the vote state instead.
                if root_to_check.is_some() {
                    root_to_check = None;
                } else {
                    vote_state_update_index = vote_state_update_index
                        .checked_add(1)
                        .expect("`vote_state_update_index` is bounded by `MAX_LOCKOUT_HISTORY` when match is found in SlotHashes history");
                    slot_hashes_index = slot_hashes_index.checked_sub(1).expect(
                        "`slot_hashes_index` is positive when match is found in SlotHashes history",
                    );
                }
            }
        }
    }

    if vote_state_update_index != vote_state_update.lockouts.len() {
        // The last vote slot in the update did not exist in SlotHashes
        return Err(VoteError::SlotsMismatch);
    }

    // This assertion must be true at this point because we can assume by now:
    // 1) vote_state_update_index == vote_state_update.lockouts.len()
    // 2) last_vote_state_update_slot >= earliest_slot_hash_in_history
    // 3) !vote_state_update.lockouts.is_empty()
    //
    // 1) implies that during the last iteration of the loop above,
    // `vote_state_update_index` was equal to `vote_state_update.lockouts.len() - 1`,
    // and was then incremented to `vote_state_update.lockouts.len()`.
    // This means in that last loop iteration,
    // `proposed_vote_slot ==
    //  vote_state_update.lockouts[vote_state_update.lockouts.len() - 1] ==
    //  last_vote_state_update_slot`.
    //
    // Then we know the last comparison `match proposed_vote_slot.cmp(&ancestor_slot)`
    // is equivalent to `match last_vote_state_update_slot.cmp(&ancestor_slot)`. The result
    // of this match to increment `vote_state_update_index` must have been either:
    //
    // 1) The Equal case ran, in which case then we know this assertion must be true
    // 2) The Less case ran, and more specifically the case
    // `proposed_vote_slot < earliest_slot_hash_in_history` ran, which is equivalent to
    // `last_vote_state_update_slot < earliest_slot_hash_in_history`, but this is impossible
    // due to assumption 3) above.
    assert_eq!(
        last_vote_state_update_slot,
        slot_hashes[slot_hashes_index].0
    );

    if slot_hashes[slot_hashes_index].1 != vote_state_update.hash {
        // This means the newest vote in the slot has a match that
        // doesn't match the expected hash for that slot on this
        // fork
        warn!(
            "{} dropped vote {:?} failed to match hash {} {}",
            vote_state.node_pubkey,
            vote_state_update,
            vote_state_update.hash,
            slot_hashes[slot_hashes_index].1
        );
        inc_new_counter_info!("dropped-vote-hash", 1);
        return Err(VoteError::SlotHashMismatch);
    }

    // Filter out the irrelevant votes
    let mut vote_state_update_index = 0;
    let mut filter_votes_index = 0;
    vote_state_update.lockouts.retain(|_lockout| {
        let should_retain = if filter_votes_index == vote_state_update_indexes_to_filter.len() {
            true
        } else if vote_state_update_index == vote_state_update_indexes_to_filter[filter_votes_index]
        {
            filter_votes_index = filter_votes_index.checked_add(1).unwrap();
            false
        } else {
            true
        };

        vote_state_update_index = vote_state_update_index
            .checked_add(1)
            .expect("`vote_state_update_index` is bounded by `MAX_LOCKOUT_HISTORY` when filtering out irrelevant votes");
        should_retain
    });

    Ok(())
}

fn check_slots_are_valid(
    vote_state: &VoteState,
    vote_slots: &[Slot],
    vote_hash: &Hash,
    slot_hashes: &[(Slot, Hash)],
) -> Result<(), VoteError> {
    // index into the vote's slots, starting at the oldest
    // slot
    let mut i = 0;

    // index into the slot_hashes, starting at the oldest known
    // slot hash
    let mut j = slot_hashes.len();

    // Note:
    //
    // 1) `vote_slots` is sorted from oldest/smallest vote to newest/largest
    // vote, due to the way votes are applied to the vote state (newest votes
    // pushed to the back).
    //
    // 2) Conversely, `slot_hashes` is sorted from newest/largest vote to
    // the oldest/smallest vote
    while i < vote_slots.len() && j > 0 {
        // 1) increment `i` to find the smallest slot `s` in `vote_slots`
        // where `s` >= `last_voted_slot`
        if vote_state
            .last_voted_slot()
            .map_or(false, |last_voted_slot| vote_slots[i] <= last_voted_slot)
        {
            i = i
                .checked_add(1)
                .expect("`i` is bounded by `MAX_LOCKOUT_HISTORY` when finding larger slots");
            continue;
        }

        // 2) Find the hash for this slot `s`.
        if vote_slots[i] != slot_hashes[j.checked_sub(1).expect("`j` is positive")].0 {
            // Decrement `j` to find newer slots
            j = j
                .checked_sub(1)
                .expect("`j` is positive when finding newer slots");
            continue;
        }

        // 3) Once the hash for `s` is found, bump `s` to the next slot
        // in `vote_slots` and continue.
        i = i
            .checked_add(1)
            .expect("`i` is bounded by `MAX_LOCKOUT_HISTORY` when hash is found");
        j = j
            .checked_sub(1)
            .expect("`j` is positive when hash is found");
    }

    if j == slot_hashes.len() {
        // This means we never made it to steps 2) or 3) above, otherwise
        // `j` would have been decremented at least once. This means
        // there are not slots in `vote_slots` greater than `last_voted_slot`
        debug!(
            "{} dropped vote slots {:?}, vote hash: {:?} slot hashes:SlotHash {:?}, too old ",
            vote_state.node_pubkey, vote_slots, vote_hash, slot_hashes
        );
        return Err(VoteError::VoteTooOld);
    }
    if i != vote_slots.len() {
        // This means there existed some slot for which we couldn't find
        // a matching slot hash in step 2)
        info!(
            "{} dropped vote slots {:?} failed to match slot hashes: {:?}",
            vote_state.node_pubkey, vote_slots, slot_hashes,
        );
        inc_new_counter_info!("dropped-vote-slot", 1);
        return Err(VoteError::SlotsMismatch);
    }
    if &slot_hashes[j].1 != vote_hash {
        // This means the newest slot in the `vote_slots` has a match that
        // doesn't match the expected hash for that slot on this
        // fork
        warn!(
            "{} dropped vote slots {:?} failed to match hash {} {}",
            vote_state.node_pubkey, vote_slots, vote_hash, slot_hashes[j].1
        );
        inc_new_counter_info!("dropped-vote-hash", 1);
        return Err(VoteError::SlotHashMismatch);
    }
    Ok(())
}

//Ensure `check_update_vote_state_slots_are_valid(&)` runs on the slots in `new_state`
// before `process_new_vote_state()` is called

// This function should guarantee the following about `new_state`:
//
// 1) It's well ordered, i.e. the slots are sorted from smallest to largest,
// and the confirmations sorted from largest to smallest.
// 2) Confirmations `c` on any vote slot satisfy `0 < c <= MAX_LOCKOUT_HISTORY`
// 3) Lockouts are not expired by consecutive votes, i.e. for every consecutive
// `v_i`, `v_{i + 1}` satisfy `v_i.last_locked_out_slot() >= v_{i + 1}`.

// We also guarantee that compared to the current vote state, `new_state`
// introduces no rollback. This means:
//
// 1) The last slot in `new_state` is always greater than any slot in the
// current vote state.
//
// 2) From 1), this means that for every vote `s` in the current state:
//    a) If there exists an `s'` in `new_state` where `s.slot == s'.slot`, then
//    we must guarantee `s.confirmations <= s'.confirmations`
//
//    b) If there does not exist any such `s'` in `new_state`, then there exists
//    some `t` that is the smallest vote in `new_state` where `t.slot > s.slot`.
//    `t` must have expired/popped off s', so it must be guaranteed that
//    `s.last_locked_out_slot() < t`.

// Note these two above checks do not guarantee that the vote state being submitted
// is a vote state that could have been created by iteratively building a tower
// by processing one vote at a time. For instance, the tower:
//
// { slot 0, confirmations: 31 }
// { slot 1, confirmations: 30 }
//
// is a legal tower that could be submitted on top of a previously empty tower. However,
// there is no way to create this tower from the iterative process, because slot 1 would
// have to have at least one other slot on top of it, even if the first 30 votes were all
// popped off.
pub fn process_new_vote_state(
    vote_state: &mut VoteState,
    new_state: VecDeque<Lockout>,
    new_root: Option<Slot>,
    timestamp: Option<i64>,
    epoch: Epoch,
    feature_set: Option<&FeatureSet>,
) -> Result<(), VoteError> {
    assert!(!new_state.is_empty());
    if new_state.len() > MAX_LOCKOUT_HISTORY {
        return Err(VoteError::TooManyVotes);
    }

    match (new_root, vote_state.root_slot) {
        (Some(new_root), Some(current_root)) => {
            if new_root < current_root {
                return Err(VoteError::RootRollBack);
            }
        }
        (None, Some(_)) => {
            return Err(VoteError::RootRollBack);
        }
        _ => (),
    }

    let mut previous_vote: Option<&Lockout> = None;

    // Check that all the votes in the new proposed state are:
    // 1) Strictly sorted from oldest to newest vote
    // 2) The confirmations are strictly decreasing
    // 3) Not zero confirmation votes
    for vote in &new_state {
        if vote.confirmation_count() == 0 {
            return Err(VoteError::ZeroConfirmations);
        } else if vote.confirmation_count() > MAX_LOCKOUT_HISTORY as u32 {
            return Err(VoteError::ConfirmationTooLarge);
        } else if let Some(new_root) = new_root {
            if vote.slot() <= new_root
                &&
                // This check is necessary because
                // https://github.com/ryoqun/solana/blob/df55bfb46af039cbc597cd60042d49b9d90b5961/core/src/consensus.rs#L120
                // always sets a root for even empty towers, which is then hard unwrapped here
                // https://github.com/ryoqun/solana/blob/df55bfb46af039cbc597cd60042d49b9d90b5961/core/src/consensus.rs#L776
                new_root != Slot::default()
            {
                return Err(VoteError::SlotSmallerThanRoot);
            }
        }

        if let Some(previous_vote) = previous_vote {
            if previous_vote.slot() >= vote.slot() {
                return Err(VoteError::SlotsNotOrdered);
            } else if previous_vote.confirmation_count() <= vote.confirmation_count() {
                return Err(VoteError::ConfirmationsNotOrdered);
            } else if vote.slot() > previous_vote.last_locked_out_slot() {
                return Err(VoteError::NewVoteStateLockoutMismatch);
            }
        }
        previous_vote = Some(vote);
    }

    // Find the first vote in the current vote state for a slot greater
    // than the new proposed root
    let mut current_vote_state_index: usize = 0;
    let mut new_vote_state_index = 0;

    // Count the number of slots at and before the new root within the current vote state lockouts.  Start with 1
    // for the new root.  The purpose of this is to know how many slots were rooted by this state update:
    // - The new root was rooted
    // - As were any slots that were in the current state but are not in the new state.  The only slots which
    //   can be in this set are those oldest slots in the current vote state that are not present in the
    //   new vote state; these have been "popped off the back" of the tower and thus represent finalized slots
    let mut finalized_slot_count = 1_u64;

    if let Some(new_root) = new_root {
        for current_vote in &vote_state.votes {
            // Find the first vote in the current vote state for a slot greater
            // than the new proposed root
            if current_vote.slot() <= new_root {
                current_vote_state_index = current_vote_state_index
                    .checked_add(1)
                    .expect("`current_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` when processing new root");
                if current_vote.slot() != new_root {
                    finalized_slot_count = finalized_slot_count
                        .checked_add(1)
                        .expect("`finalized_slot_count` is bounded by `MAX_LOCKOUT_HISTORY` when processing new root");
                }
                continue;
            }

            break;
        }
    }

    // All the votes in our current vote state that are missing from the new vote state
    // must have been expired by later votes. Check that the lockouts match this assumption.
    while current_vote_state_index < vote_state.votes.len()
        && new_vote_state_index < new_state.len()
    {
        let current_vote = &vote_state.votes[current_vote_state_index];
        let new_vote = &new_state[new_vote_state_index];

        // If the current slot is less than the new proposed slot, then the
        // new slot must have popped off the old slot, so check that the
        // lockouts are corrects.
        match current_vote.slot().cmp(&new_vote.slot()) {
            Ordering::Less => {
                if current_vote.lockout.last_locked_out_slot() >= new_vote.slot() {
                    return Err(VoteError::LockoutConflict);
                }
                current_vote_state_index = current_vote_state_index
                    .checked_add(1)
                    .expect("`current_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` when slot is less than proposed");
            }
            Ordering::Equal => {
                // The new vote state should never have less lockout than
                // the previous vote state for the same slot
                if new_vote.confirmation_count() < current_vote.confirmation_count() {
                    return Err(VoteError::ConfirmationRollBack);
                }

                current_vote_state_index = current_vote_state_index
                    .checked_add(1)
                    .expect("`current_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` when slot is equal to proposed");
                new_vote_state_index = new_vote_state_index
                    .checked_add(1)
                    .expect("`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` when slot is equal to proposed");
            }
            Ordering::Greater => {
                new_vote_state_index = new_vote_state_index
                    .checked_add(1)
                    .expect("`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` when slot is greater than proposed");
            }
        }
    }

    // `new_vote_state` passed all the checks, finalize the change by rewriting
    // our state.
    if vote_state.root_slot != new_root {
        // Award vote credits based on the number of slots that were voted on and have reached finality
        if feature_set
            .map(|feature_set| {
                feature_set.is_active(&feature_set::vote_state_update_credit_per_dequeue::id())
            })
            .unwrap_or(false)
        {
            // For each finalized slot, there was one voted-on slot in the new vote state that was responsible for
            // finalizing it. Each of those votes is awarded 1 credit.
            vote_state.increment_credits(epoch, finalized_slot_count);
        } else {
            vote_state.increment_credits(epoch, 1);
        }
    }
    if let Some(timestamp) = timestamp {
        let last_slot = new_state.back().unwrap().slot();
        vote_state.process_timestamp(last_slot, timestamp)?;
    }
    vote_state.root_slot = new_root;
    vote_state.votes = new_state
        .into_iter()
        .map(|lockout| lockout.into())
        .collect();
    Ok(())
}

pub fn process_vote(
    vote_state: &mut VoteState,
    vote: &Vote,
    slot_hashes: &[SlotHash],
    epoch: Epoch,
    feature_set: Option<&FeatureSet>,
) -> Result<(), VoteError> {
    if vote.slots.is_empty() {
        return Err(VoteError::EmptySlots);
    }
    let filtered_vote_slots = feature_set.and_then(|feature_set| {
        if feature_set.is_active(&filter_votes_outside_slot_hashes::id()) {
            let earliest_slot_in_history =
                slot_hashes.last().map(|(slot, _hash)| *slot).unwrap_or(0);
            Some(
                vote.slots
                    .iter()
                    .filter(|slot| **slot >= earliest_slot_in_history)
                    .cloned()
                    .collect::<Vec<Slot>>(),
            )
        } else {
            None
        }
    });

    let vote_slots = filtered_vote_slots.as_ref().unwrap_or(&vote.slots);
    if vote_slots.is_empty() {
        return Err(VoteError::VotesTooOldAllFiltered);
    }

    check_slots_are_valid(vote_state, vote_slots, &vote.hash, slot_hashes)?;

    vote_slots
        .iter()
        .for_each(|s| vote_state.process_next_vote_slot(*s, epoch));
    Ok(())
}

/// "unchecked" functions used by tests and Tower
pub fn process_vote_unchecked(vote_state: &mut VoteState, vote: Vote) {
    let slot_hashes: Vec<_> = vote.slots.iter().rev().map(|x| (*x, vote.hash)).collect();
    let _ignored = process_vote(
        vote_state,
        &vote,
        &slot_hashes,
        vote_state.current_epoch(),
        None,
    );
}

pub fn process_slot_vote_unchecked(vote_state: &mut VoteState, slot: Slot) {
    process_vote_unchecked(vote_state, Vote::new(vec![slot], Hash::default()));
}

/// Authorize the given pubkey to withdraw or sign votes. This may be called multiple times,
/// but will implicitly withdraw authorization from the previously authorized
/// key
pub fn authorize<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedAccount,
    authorized: &Pubkey,
    vote_authorize: VoteAuthorize,
    signers: &HashSet<Pubkey, S>,
    clock: &Clock,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    let mut vote_state: VoteState = vote_account
        .get_state::<VoteStateVersions>()?
        .convert_to_current();

    match vote_authorize {
        VoteAuthorize::Voter => {
            let authorized_withdrawer_signer = if feature_set
                .is_active(&feature_set::vote_withdraw_authority_may_change_authorized_voter::id())
            {
                verify_authorized_signer(&vote_state.authorized_withdrawer, signers).is_ok()
            } else {
                false
            };

            vote_state.set_new_authorized_voter(
                authorized,
                clock.epoch,
                clock
                    .leader_schedule_epoch
                    .checked_add(1)
                    .expect("epoch should be much less than u64::MAX"),
                |epoch_authorized_voter| {
                    // current authorized withdrawer or authorized voter must say "yay"
                    if authorized_withdrawer_signer {
                        Ok(())
                    } else {
                        verify_authorized_signer(&epoch_authorized_voter, signers)
                    }
                },
            )?;
        }
        VoteAuthorize::Withdrawer => {
            // current authorized withdrawer must say "yay"
            verify_authorized_signer(&vote_state.authorized_withdrawer, signers)?;
            vote_state.authorized_withdrawer = *authorized;
        }
    }

    set_vote_account_state(vote_account, vote_state, feature_set)
}

/// Update the node_pubkey, requires signature of the authorized voter
pub fn update_validator_identity<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedAccount,
    node_pubkey: &Pubkey,
    signers: &HashSet<Pubkey, S>,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    let mut vote_state: VoteState = vote_account
        .get_state::<VoteStateVersions>()?
        .convert_to_current();

    // current authorized withdrawer must say "yay"
    verify_authorized_signer(&vote_state.authorized_withdrawer, signers)?;

    // new node must say "yay"
    verify_authorized_signer(node_pubkey, signers)?;

    vote_state.node_pubkey = *node_pubkey;

    set_vote_account_state(vote_account, vote_state, feature_set)
}

/// Update the vote account's commission
pub fn update_commission<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedAccount,
    commission: u8,
    signers: &HashSet<Pubkey, S>,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    let mut vote_state: VoteState = vote_account
        .get_state::<VoteStateVersions>()?
        .convert_to_current();

    // current authorized withdrawer must say "yay"
    verify_authorized_signer(&vote_state.authorized_withdrawer, signers)?;

    vote_state.commission = commission;

    set_vote_account_state(vote_account, vote_state, feature_set)
}

/// Given the current slot and epoch schedule, determine if a commission change
/// is allowed
pub fn is_commission_update_allowed(slot: Slot, epoch_schedule: &EpochSchedule) -> bool {
    // always allowed during warmup epochs
    if let Some(relative_slot) = slot
        .saturating_sub(epoch_schedule.first_normal_slot)
        .checked_rem(epoch_schedule.slots_per_epoch)
    {
        // allowed up to the midpoint of the epoch
        relative_slot.saturating_mul(2) <= epoch_schedule.slots_per_epoch
    } else {
        // no slots per epoch, just allow it, even though this should never happen
        true
    }
}

fn verify_authorized_signer<S: std::hash::BuildHasher>(
    authorized: &Pubkey,
    signers: &HashSet<Pubkey, S>,
) -> Result<(), InstructionError> {
    if signers.contains(authorized) {
        Ok(())
    } else {
        Err(InstructionError::MissingRequiredSignature)
    }
}

/// Withdraw funds from the vote account
pub fn withdraw<S: std::hash::BuildHasher>(
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
    vote_account_index: IndexOfAccount,
    lamports: u64,
    to_account_index: IndexOfAccount,
    signers: &HashSet<Pubkey, S>,
    rent_sysvar: &Rent,
    clock: Option<&Clock>,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    let mut vote_account = instruction_context
        .try_borrow_instruction_account(transaction_context, vote_account_index)?;
    let vote_state: VoteState = vote_account
        .get_state::<VoteStateVersions>()?
        .convert_to_current();

    verify_authorized_signer(&vote_state.authorized_withdrawer, signers)?;

    let remaining_balance = vote_account
        .get_lamports()
        .checked_sub(lamports)
        .ok_or(InstructionError::InsufficientFunds)?;

    if remaining_balance == 0 {
        let reject_active_vote_account_close = clock
            .zip(vote_state.epoch_credits.last())
            .map(|(clock, (last_epoch_with_credits, _, _))| {
                let current_epoch = clock.epoch;
                // if current_epoch - last_epoch_with_credits < 2 then the validator has received credits
                // either in the current epoch or the previous epoch. If it's >= 2 then it has been at least
                // one full epoch since the validator has received credits.
                current_epoch.saturating_sub(*last_epoch_with_credits) < 2
            })
            .unwrap_or(false);

        if reject_active_vote_account_close {
            datapoint_debug!("vote-account-close", ("reject-active", 1, i64));
            return Err(VoteError::ActiveVoteAccountClose.into());
        } else {
            // Deinitialize upon zero-balance
            datapoint_debug!("vote-account-close", ("allow", 1, i64));
            set_vote_account_state(&mut vote_account, VoteState::default(), feature_set)?;
        }
    } else {
        let min_rent_exempt_balance = rent_sysvar.minimum_balance(vote_account.get_data().len());
        if remaining_balance < min_rent_exempt_balance {
            return Err(InstructionError::InsufficientFunds);
        }
    }

    vote_account.checked_sub_lamports(lamports)?;
    drop(vote_account);
    let mut to_account = instruction_context
        .try_borrow_instruction_account(transaction_context, to_account_index)?;
    to_account.checked_add_lamports(lamports)?;
    Ok(())
}

/// Initialize the vote_state for a vote account
/// Assumes that the account is being init as part of a account creation or balance transfer and
/// that the transaction must be signed by the staker's keys
pub fn initialize_account<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedAccount,
    vote_init: &VoteInit,
    signers: &HashSet<Pubkey, S>,
    clock: &Clock,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    if vote_account.get_data().len()
        != VoteStateVersions::vote_state_size_of(
            feature_set.is_active(&feature_set::vote_state_add_vote_latency::id()),
        )
    {
        return Err(InstructionError::InvalidAccountData);
    }
    let versioned = vote_account.get_state::<VoteStateVersions>()?;

    if !versioned.is_uninitialized() {
        return Err(InstructionError::AccountAlreadyInitialized);
    }

    // node must agree to accept this vote account
    verify_authorized_signer(&vote_init.node_pubkey, signers)?;

    set_vote_account_state(vote_account, VoteState::new(vote_init, clock), feature_set)
}

fn verify_and_get_vote_state<S: std::hash::BuildHasher>(
    vote_account: &BorrowedAccount,
    clock: &Clock,
    signers: &HashSet<Pubkey, S>,
) -> Result<VoteState, InstructionError> {
    let versioned = vote_account.get_state::<VoteStateVersions>()?;

    if versioned.is_uninitialized() {
        return Err(InstructionError::UninitializedAccount);
    }

    let mut vote_state = versioned.convert_to_current();
    let authorized_voter = vote_state.get_and_update_authorized_voter(clock.epoch)?;
    verify_authorized_signer(&authorized_voter, signers)?;

    Ok(vote_state)
}

pub fn process_vote_with_account<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedAccount,
    slot_hashes: &[SlotHash],
    clock: &Clock,
    vote: &Vote,
    signers: &HashSet<Pubkey, S>,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    let mut vote_state = verify_and_get_vote_state(vote_account, clock, signers)?;

    process_vote(
        &mut vote_state,
        vote,
        slot_hashes,
        clock.epoch,
        Some(feature_set),
    )?;
    if let Some(timestamp) = vote.timestamp {
        vote.slots
            .iter()
            .max()
            .ok_or(VoteError::EmptySlots)
            .and_then(|slot| vote_state.process_timestamp(*slot, timestamp))?;
    }
    set_vote_account_state(vote_account, vote_state, feature_set)
}

pub fn process_vote_state_update<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedAccount,
    slot_hashes: &[SlotHash],
    clock: &Clock,
    vote_state_update: VoteStateUpdate,
    signers: &HashSet<Pubkey, S>,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    let mut vote_state = verify_and_get_vote_state(vote_account, clock, signers)?;
    do_process_vote_state_update(
        &mut vote_state,
        slot_hashes,
        clock.epoch,
        vote_state_update,
        Some(feature_set),
    )?;
    set_vote_account_state(vote_account, vote_state, feature_set)
}

pub fn do_process_vote_state_update(
    vote_state: &mut VoteState,
    slot_hashes: &[SlotHash],
    epoch: u64,
    mut vote_state_update: VoteStateUpdate,
    feature_set: Option<&FeatureSet>,
) -> Result<(), VoteError> {
    check_update_vote_state_slots_are_valid(
        vote_state,
        &mut vote_state_update,
        slot_hashes,
        feature_set,
    )?;
    process_new_vote_state(
        vote_state,
        vote_state_update.lockouts,
        vote_state_update.root,
        vote_state_update.timestamp,
        epoch,
        feature_set,
    )
}

// This function is used:
// a. In many tests.
// b. In the genesis tool that initializes a cluster to create the bootstrap validator.
// c. In the ledger tool when creating bootstrap vote accounts.
// In all cases, initializing with the 1_14_11 version of VoteState is safest, as this version will in-place upgrade
// the first time it is altered by a vote transaction.
pub fn create_account_with_authorized(
    node_pubkey: &Pubkey,
    authorized_voter: &Pubkey,
    authorized_withdrawer: &Pubkey,
    commission: u8,
    lamports: u64,
) -> AccountSharedData {
    let mut vote_account = AccountSharedData::new(lamports, VoteState1_14_11::size_of(), &id());

    let vote_state = VoteState::new(
        &VoteInit {
            node_pubkey: *node_pubkey,
            authorized_voter: *authorized_voter,
            authorized_withdrawer: *authorized_withdrawer,
            commission,
        },
        &Clock::default(),
    );

    let version1_14_11 = VoteStateVersions::V1_14_11(Box::new(VoteState1_14_11::from(vote_state)));
    VoteState::serialize(&version1_14_11, vote_account.data_as_mut_slice()).unwrap();

    vote_account
}

// create_account() should be removed, use create_account_with_authorized() instead
pub fn create_account(
    vote_pubkey: &Pubkey,
    node_pubkey: &Pubkey,
    commission: u8,
    lamports: u64,
) -> AccountSharedData {
    create_account_with_authorized(node_pubkey, vote_pubkey, vote_pubkey, commission, lamports)
}
