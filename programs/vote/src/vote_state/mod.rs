//! Vote state, vote program
//! Receive and processes votes from validators
use {
    crate::{authorized_voters::AuthorizedVoters, id, vote_error::VoteError},
    bincode::{deserialize, serialize_into, ErrorKind},
    log::*,
    serde_derive::{Deserialize, Serialize},
    solana_metrics::datapoint_debug,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        clock::{Epoch, Slot, UnixTimestamp},
        feature_set::{self, filter_votes_outside_slot_hashes, FeatureSet},
        hash::Hash,
        instruction::InstructionError,
        pubkey::Pubkey,
        rent::Rent,
        short_vec,
        slot_hashes::SlotHash,
        sysvar::clock::Clock,
        transaction_context::{BorrowedAccount, InstructionContext, TransactionContext},
    },
    std::{
        cmp::Ordering,
        collections::{HashSet, VecDeque},
        fmt::Debug,
    },
};

mod vote_state_0_23_5;
pub mod vote_state_versions;
pub use vote_state_versions::*;

// Maximum number of votes to keep around, tightly coupled with epoch_schedule::MINIMUM_SLOTS_PER_EPOCH
pub const MAX_LOCKOUT_HISTORY: usize = 31;
pub const INITIAL_LOCKOUT: usize = 2;

// Maximum number of credits history to keep around
pub const MAX_EPOCH_CREDITS_HISTORY: usize = 64;

// Offset of VoteState::prior_voters, for determining initialization status without deserialization
const DEFAULT_PRIOR_VOTERS_OFFSET: usize = 82;

#[frozen_abi(digest = "EYPXjH9Zn2vLzxyjHejkRkoTh4Tg4sirvb4FX9ye25qF")]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, AbiEnumVisitor, AbiExample)]
pub enum VoteTransaction {
    Vote(Vote),
    VoteStateUpdate(VoteStateUpdate),
    CompactVoteStateUpdate(CompactVoteStateUpdate),
}

impl VoteTransaction {
    pub fn slots(&self) -> Vec<Slot> {
        match self {
            VoteTransaction::Vote(vote) => vote.slots.clone(),
            VoteTransaction::VoteStateUpdate(vote_state_update) => vote_state_update.slots(),
            VoteTransaction::CompactVoteStateUpdate(compact_state_update) => {
                compact_state_update.slots()
            }
        }
    }

    pub fn slot(&self, i: usize) -> Slot {
        match self {
            VoteTransaction::Vote(vote) => vote.slots[i],
            VoteTransaction::VoteStateUpdate(vote_state_update) => {
                vote_state_update.lockouts[i].slot
            }
            VoteTransaction::CompactVoteStateUpdate(compact_state_update) => {
                compact_state_update.slots()[i]
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            VoteTransaction::Vote(vote) => vote.slots.len(),
            VoteTransaction::VoteStateUpdate(vote_state_update) => vote_state_update.lockouts.len(),
            VoteTransaction::CompactVoteStateUpdate(compact_state_update) => {
                1 + compact_state_update.lockouts_32.len()
                    + compact_state_update.lockouts_16.len()
                    + compact_state_update.lockouts_8.len()
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            VoteTransaction::Vote(vote) => vote.slots.is_empty(),
            VoteTransaction::VoteStateUpdate(vote_state_update) => {
                vote_state_update.lockouts.is_empty()
            }
            VoteTransaction::CompactVoteStateUpdate(_) => false,
        }
    }

    pub fn hash(&self) -> Hash {
        match self {
            VoteTransaction::Vote(vote) => vote.hash,
            VoteTransaction::VoteStateUpdate(vote_state_update) => vote_state_update.hash,
            VoteTransaction::CompactVoteStateUpdate(compact_state_update) => {
                compact_state_update.hash
            }
        }
    }

    pub fn timestamp(&self) -> Option<UnixTimestamp> {
        match self {
            VoteTransaction::Vote(vote) => vote.timestamp,
            VoteTransaction::VoteStateUpdate(vote_state_update) => vote_state_update.timestamp,
            VoteTransaction::CompactVoteStateUpdate(compact_state_update) => {
                compact_state_update.timestamp
            }
        }
    }

    pub fn set_timestamp(&mut self, ts: Option<UnixTimestamp>) {
        match self {
            VoteTransaction::Vote(vote) => vote.timestamp = ts,
            VoteTransaction::VoteStateUpdate(vote_state_update) => vote_state_update.timestamp = ts,
            VoteTransaction::CompactVoteStateUpdate(compact_state_update) => {
                compact_state_update.timestamp = ts
            }
        }
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        match self {
            VoteTransaction::Vote(vote) => vote.slots.last().copied(),
            VoteTransaction::VoteStateUpdate(vote_state_update) => {
                Some(vote_state_update.lockouts.back()?.slot)
            }
            VoteTransaction::CompactVoteStateUpdate(compact_state_update) => {
                compact_state_update.slots().last().copied()
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

impl From<CompactVoteStateUpdate> for VoteTransaction {
    fn from(compact_state_update: CompactVoteStateUpdate) -> Self {
        VoteTransaction::CompactVoteStateUpdate(compact_state_update)
    }
}

#[frozen_abi(digest = "Ch2vVEwos2EjAVqSHCyJjnN2MNX1yrpapZTGhMSCjWUH")]
#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq, Clone, AbiExample)]
pub struct Vote {
    /// A stack of votes starting with the oldest vote
    pub slots: Vec<Slot>,
    /// signature of the bank's state at the last slot
    pub hash: Hash,
    /// processing timestamp of last slot
    pub timestamp: Option<UnixTimestamp>,
}

impl Vote {
    pub fn new(slots: Vec<Slot>, hash: Hash) -> Self {
        Self {
            slots,
            hash,
            timestamp: None,
        }
    }
}

#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq, Copy, Clone, AbiExample)]
pub struct Lockout {
    pub slot: Slot,
    pub confirmation_count: u32,
}

impl Lockout {
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            confirmation_count: 1,
        }
    }

    // The number of slots for which this vote is locked
    pub fn lockout(&self) -> u64 {
        (INITIAL_LOCKOUT as u64).pow(self.confirmation_count)
    }

    // The last slot at which a vote is still locked out. Validators should not
    // vote on a slot in another fork which is less than or equal to this slot
    // to avoid having their stake slashed.
    pub fn last_locked_out_slot(&self) -> Slot {
        self.slot + self.lockout()
    }

    pub fn is_locked_out_at_slot(&self, slot: Slot) -> bool {
        self.last_locked_out_slot() >= slot
    }
}

#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq, Copy, Clone, AbiExample)]
pub struct CompactLockout<T: Sized> {
    // Offset to the next vote, 0 if this is the last vote in the tower
    pub offset: T,
    // Confirmation count, guarenteed to be < 32
    pub confirmation_count: u8,
}

impl<T> CompactLockout<T> {
    pub fn new(offset: T) -> Self {
        Self {
            offset,
            confirmation_count: 1,
        }
    }

    // The number of slots for which this vote is locked
    pub fn lockout(&self) -> u64 {
        (INITIAL_LOCKOUT as u64).pow(self.confirmation_count.into())
    }
}

#[frozen_abi(digest = "BctadFJjUKbvPJzr6TszbX6rBfQUNSRKpKKngkzgXgeY")]
#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq, Clone, AbiExample)]
pub struct VoteStateUpdate {
    /// The proposed tower
    pub lockouts: VecDeque<Lockout>,
    /// The proposed root
    pub root: Option<Slot>,
    /// signature of the bank's state at the last slot
    pub hash: Hash,
    /// processing timestamp of last slot
    pub timestamp: Option<UnixTimestamp>,
}

impl From<Vec<(Slot, u32)>> for VoteStateUpdate {
    fn from(recent_slots: Vec<(Slot, u32)>) -> Self {
        let lockouts: VecDeque<Lockout> = recent_slots
            .into_iter()
            .map(|(slot, confirmation_count)| Lockout {
                slot,
                confirmation_count,
            })
            .collect();
        Self {
            lockouts,
            root: None,
            hash: Hash::default(),
            timestamp: None,
        }
    }
}

impl VoteStateUpdate {
    pub fn new(lockouts: VecDeque<Lockout>, root: Option<Slot>, hash: Hash) -> Self {
        Self {
            lockouts,
            root,
            hash,
            timestamp: None,
        }
    }

    pub fn slots(&self) -> Vec<Slot> {
        self.lockouts.iter().map(|lockout| lockout.slot).collect()
    }

    pub fn compact(self) -> Option<CompactVoteStateUpdate> {
        CompactVoteStateUpdate::new(self.lockouts, self.root, self.hash, self.timestamp)
    }
}

/// Ignoring overhead, in a full `VoteStateUpdate` the lockouts take up
/// 31 * (64 + 32) = 2976 bits.
///
/// In this schema we separate the votes into 3 separate lockout structures
/// and store offsets rather than slot number, allowing us to use smaller fields.
///
/// In a full `CompactVoteStateUpdate` the lockouts take up
/// 64 + (32 + 8) * 16 + (16 + 8) * 8 + (8 + 8) * 6 = 992 bits
/// allowing us to greatly reduce block size.
#[frozen_abi(digest = "C8ZrdXqqF3VxgsoCxnqNaYJggV6rr9PC3rtmVudJFmqG")]
#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq, Clone, AbiExample)]
pub struct CompactVoteStateUpdate {
    /// The proposed root, u64::MAX if there is no root
    pub root: Slot,
    /// The offset from the root (or 0 if no root) to the first vote
    pub root_to_first_vote_offset: u64,
    /// Part of the proposed tower, votes with confirmation_count > 15
    #[serde(with = "short_vec")]
    pub lockouts_32: Vec<CompactLockout<u32>>,
    /// Part of the proposed tower, votes with 15 >= confirmation_count > 7
    #[serde(with = "short_vec")]
    pub lockouts_16: Vec<CompactLockout<u16>>,
    /// Part of the proposed tower, votes with 7 >= confirmation_count
    #[serde(with = "short_vec")]
    pub lockouts_8: Vec<CompactLockout<u8>>,

    /// Signature of the bank's state at the last slot
    pub hash: Hash,
    /// Processing timestamp of last slot
    pub timestamp: Option<UnixTimestamp>,
}

impl From<Vec<(Slot, u32)>> for CompactVoteStateUpdate {
    fn from(recent_slots: Vec<(Slot, u32)>) -> Self {
        let lockouts: VecDeque<Lockout> = recent_slots
            .into_iter()
            .map(|(slot, confirmation_count)| Lockout {
                slot,
                confirmation_count,
            })
            .collect();
        Self::new(lockouts, None, Hash::default(), None).unwrap()
    }
}

impl CompactVoteStateUpdate {
    pub fn new(
        mut lockouts: VecDeque<Lockout>,
        root: Option<Slot>,
        hash: Hash,
        timestamp: Option<UnixTimestamp>,
    ) -> Option<Self> {
        if lockouts.is_empty() {
            return Some(Self::default());
        }
        let mut cur_slot = root.unwrap_or(0u64);
        let mut cur_confirmation_count = 0;
        let offset = lockouts
            .pop_front()
            .map(
                |Lockout {
                     slot,
                     confirmation_count,
                 }| {
                    assert!(confirmation_count < 32);

                    slot.checked_sub(cur_slot).map(|offset| {
                        cur_slot = slot;
                        cur_confirmation_count = confirmation_count;
                        offset
                    })
                },
            )
            .expect("Tower should not be empty")?;
        let mut lockouts_32 = Vec::new();
        let mut lockouts_16 = Vec::new();
        let mut lockouts_8 = Vec::new();

        for Lockout {
            slot,
            confirmation_count,
        } in lockouts
        {
            assert!(confirmation_count < 32);
            let offset = slot.checked_sub(cur_slot)?;
            if cur_confirmation_count > 15 {
                lockouts_32.push(CompactLockout {
                    offset: offset.try_into().unwrap(),
                    confirmation_count: cur_confirmation_count.try_into().unwrap(),
                });
            } else if cur_confirmation_count > 7 {
                lockouts_16.push(CompactLockout {
                    offset: offset.try_into().unwrap(),
                    confirmation_count: cur_confirmation_count.try_into().unwrap(),
                });
            } else {
                lockouts_8.push(CompactLockout {
                    offset: offset.try_into().unwrap(),
                    confirmation_count: cur_confirmation_count.try_into().unwrap(),
                })
            }

            cur_slot = slot;
            cur_confirmation_count = confirmation_count;
        }
        // Last vote should be at the top of tower, so we don't have to explicitly store it
        assert!(cur_confirmation_count == 1);
        Some(Self {
            root: root.unwrap_or(u64::MAX),
            root_to_first_vote_offset: offset,
            lockouts_32,
            lockouts_16,
            lockouts_8,
            hash,
            timestamp,
        })
    }

    pub fn root(&self) -> Option<Slot> {
        if self.root == u64::MAX {
            None
        } else {
            Some(self.root)
        }
    }

    pub fn slots(&self) -> Vec<Slot> {
        std::iter::once(self.root_to_first_vote_offset)
            .chain(self.lockouts_32.iter().map(|lockout| lockout.offset.into()))
            .chain(self.lockouts_16.iter().map(|lockout| lockout.offset.into()))
            .chain(self.lockouts_8.iter().map(|lockout| lockout.offset.into()))
            .scan(self.root().unwrap_or(0), |prev_slot, offset| {
                prev_slot.checked_add(offset).map(|slot| {
                    *prev_slot = slot;
                    slot
                })
            })
            .collect()
    }

    pub fn uncompact(self) -> Result<VoteStateUpdate, InstructionError> {
        let first_slot = self
            .root()
            .unwrap_or(0)
            .checked_add(self.root_to_first_vote_offset)
            .ok_or(InstructionError::ArithmeticOverflow)?;
        let mut arithmetic_overflow_occured = false;
        let lockouts = self
            .lockouts_32
            .iter()
            .map(|lockout| (lockout.offset.into(), lockout.confirmation_count))
            .chain(
                self.lockouts_16
                    .iter()
                    .map(|lockout| (lockout.offset.into(), lockout.confirmation_count)),
            )
            .chain(
                self.lockouts_8
                    .iter()
                    .map(|lockout| (lockout.offset.into(), lockout.confirmation_count)),
            )
            .chain(
                // To pick up the last element
                std::iter::once((0, 1)),
            )
            .scan(
                first_slot,
                |slot, (offset, confirmation_count): (u64, u8)| {
                    let cur_slot = *slot;
                    if let Some(new_slot) = slot.checked_add(offset) {
                        *slot = new_slot;
                        Some(Lockout {
                            slot: cur_slot,
                            confirmation_count: confirmation_count.into(),
                        })
                    } else {
                        arithmetic_overflow_occured = true;
                        None
                    }
                },
            )
            .collect();
        if arithmetic_overflow_occured {
            Err(InstructionError::ArithmeticOverflow)
        } else {
            Ok(VoteStateUpdate {
                lockouts,
                root: self.root(),
                hash: self.hash,
                timestamp: self.timestamp,
            })
        }
    }
}

#[derive(Default, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub struct VoteInit {
    pub node_pubkey: Pubkey,
    pub authorized_voter: Pubkey,
    pub authorized_withdrawer: Pubkey,
    pub commission: u8,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum VoteAuthorize {
    Voter,
    Withdrawer,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct VoteAuthorizeWithSeedArgs {
    pub authorization_type: VoteAuthorize,
    pub current_authority_derived_key_owner: Pubkey,
    pub current_authority_derived_key_seed: String,
    pub new_authority: Pubkey,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct VoteAuthorizeCheckedWithSeedArgs {
    pub authorization_type: VoteAuthorize,
    pub current_authority_derived_key_owner: Pubkey,
    pub current_authority_derived_key_seed: String,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, AbiExample)]
pub struct BlockTimestamp {
    pub slot: Slot,
    pub timestamp: UnixTimestamp,
}

// this is how many epochs a voter can be remembered for slashing
const MAX_ITEMS: usize = 32;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, AbiExample)]
pub struct CircBuf<I> {
    buf: [I; MAX_ITEMS],
    /// next pointer
    idx: usize,
    is_empty: bool,
}

impl<I: Default + Copy> Default for CircBuf<I> {
    fn default() -> Self {
        Self {
            buf: [I::default(); MAX_ITEMS],
            idx: MAX_ITEMS - 1,
            is_empty: true,
        }
    }
}

impl<I> CircBuf<I> {
    pub fn append(&mut self, item: I) {
        // remember prior delegate and when we switched, to support later slashing
        self.idx += 1;
        self.idx %= MAX_ITEMS;

        self.buf[self.idx] = item;
        self.is_empty = false;
    }

    pub fn buf(&self) -> &[I; MAX_ITEMS] {
        &self.buf
    }

    pub fn last(&self) -> Option<&I> {
        if !self.is_empty {
            Some(&self.buf[self.idx])
        } else {
            None
        }
    }
}

#[frozen_abi(digest = "331ZmXrmsUcwbKhzR3C1UEU6uNwZr48ExE54JDKGWA4w")]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, AbiExample)]
pub struct VoteState {
    /// the node that votes in this account
    pub node_pubkey: Pubkey,

    /// the signer for withdrawals
    pub authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    pub commission: u8,

    pub votes: VecDeque<Lockout>,

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    pub root_slot: Option<Slot>,

    /// the signer for vote transactions
    authorized_voters: AuthorizedVoters,

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    prior_voters: CircBuf<(Pubkey, Epoch, Epoch)>,

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    pub epoch_credits: Vec<(Epoch, u64, u64)>,

    /// most recent timestamp submitted with a vote
    pub last_timestamp: BlockTimestamp,
}

impl VoteState {
    pub fn new(vote_init: &VoteInit, clock: &Clock) -> Self {
        Self {
            node_pubkey: vote_init.node_pubkey,
            authorized_voters: AuthorizedVoters::new(clock.epoch, vote_init.authorized_voter),
            authorized_withdrawer: vote_init.authorized_withdrawer,
            commission: vote_init.commission,
            ..VoteState::default()
        }
    }

    pub fn get_authorized_voter(&self, epoch: Epoch) -> Option<Pubkey> {
        self.authorized_voters.get_authorized_voter(epoch)
    }

    pub fn authorized_voters(&self) -> &AuthorizedVoters {
        &self.authorized_voters
    }

    pub fn prior_voters(&mut self) -> &CircBuf<(Pubkey, Epoch, Epoch)> {
        &self.prior_voters
    }

    pub fn get_rent_exempt_reserve(rent: &Rent) -> u64 {
        rent.minimum_balance(VoteState::size_of())
    }

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const fn size_of() -> usize {
        3731 // see test_vote_state_size_of.
    }

    // utility function, used by Stakes, tests
    pub fn from<T: ReadableAccount>(account: &T) -> Option<VoteState> {
        Self::deserialize(account.data()).ok()
    }

    // utility function, used by Stakes, tests
    pub fn to<T: WritableAccount>(versioned: &VoteStateVersions, account: &mut T) -> Option<()> {
        Self::serialize(versioned, account.data_as_mut_slice()).ok()
    }

    pub fn deserialize(input: &[u8]) -> Result<Self, InstructionError> {
        deserialize::<VoteStateVersions>(input)
            .map(|versioned| versioned.convert_to_current())
            .map_err(|_| InstructionError::InvalidAccountData)
    }

    pub fn serialize(
        versioned: &VoteStateVersions,
        output: &mut [u8],
    ) -> Result<(), InstructionError> {
        serialize_into(output, versioned).map_err(|err| match *err {
            ErrorKind::SizeLimit => InstructionError::AccountDataTooSmall,
            _ => InstructionError::GenericError,
        })
    }

    pub fn credits_from<T: ReadableAccount>(account: &T) -> Option<u64> {
        Self::from(account).map(|state| state.credits())
    }

    /// returns commission split as (voter_portion, staker_portion, was_split) tuple
    ///
    ///  if commission calculation is 100% one way or other,
    ///   indicate with false for was_split
    pub fn commission_split(&self, on: u64) -> (u64, u64, bool) {
        match self.commission.min(100) {
            0 => (0, on, false),
            100 => (on, 0, false),
            split => {
                let on = u128::from(on);
                // Calculate mine and theirs independently and symmetrically instead of
                // using the remainder of the other to treat them strictly equally.
                // This is also to cancel the rewarding if either of the parties
                // should receive only fractional lamports, resulting in not being rewarded at all.
                // Thus, note that we intentionally discard any residual fractional lamports.
                let mine = on * u128::from(split) / 100u128;
                let theirs = on * u128::from(100 - split) / 100u128;

                (mine as u64, theirs as u64, true)
            }
        }
    }

    /// Returns if the vote state contains a slot `candidate_slot`
    pub fn contains_slot(&self, candidate_slot: Slot) -> bool {
        self.votes
            .binary_search_by(|lockout| lockout.slot.cmp(&candidate_slot))
            .is_ok()
    }

    fn check_update_vote_state_slots_are_valid(
        &self,
        vote_state_update: &mut VoteStateUpdate,
        slot_hashes: &[(Slot, Hash)],
        feature_set: Option<&FeatureSet>,
    ) -> Result<(), VoteError> {
        if vote_state_update.lockouts.is_empty() {
            return Err(VoteError::EmptySlots);
        }

        // If the vote state update is not new enough, return
        if let Some(last_vote_slot) = self.votes.back().map(|lockout| lockout.slot) {
            if vote_state_update.lockouts.back().unwrap().slot <= last_vote_slot {
                return Err(VoteError::VoteTooOld);
            }
        }

        let last_vote_state_update_slot = vote_state_update
            .lockouts
            .back()
            .expect("must be nonempty, checked above")
            .slot;

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
            .map(|feature_set| {
                feature_set.is_active(&feature_set::vote_state_update_root_fix::id())
            })
            .unwrap_or(false);

        let original_proposed_root = vote_state_update.root;
        if let Some(new_proposed_root) = original_proposed_root {
            // If the new proposed root `R` is less than the earliest slot hash in the history
            // such that we cannot verify whether the slot was actually was on this fork, set
            // the root to the latest vote in the current vote that's less than R.
            if earliest_slot_hash_in_history > new_proposed_root {
                vote_state_update.root = self.root_slot;
                if is_root_fix_enabled {
                    let mut prev_slot = Slot::MAX;
                    let current_root = vote_state_update.root;
                    for lockout in self.votes.iter().rev() {
                        let is_slot_bigger_than_root = current_root
                            .map(|current_root| lockout.slot > current_root)
                            .unwrap_or(true);
                        // Ensure we're iterating from biggest to smallest vote in the
                        // current vote state
                        assert!(lockout.slot < prev_slot && is_slot_bigger_than_root);
                        if lockout.slot <= new_proposed_root {
                            vote_state_update.root = Some(lockout.slot);
                            break;
                        }
                        prev_slot = lockout.slot;
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
                vote_state_update.lockouts[vote_state_update_index].slot
            };
            if root_to_check.is_none()
                && vote_state_update_index > 0
                && proposed_vote_slot
                    <= vote_state_update.lockouts[vote_state_update_index - 1].slot
            {
                return Err(VoteError::SlotsNotOrdered);
            }
            let ancestor_slot = slot_hashes[slot_hashes_index - 1].0;

            // Find if this slot in the proposed vote state exists in the SlotHashes history
            // to confirm if it was a valid ancestor on this fork
            match proposed_vote_slot.cmp(&ancestor_slot) {
                Ordering::Less => {
                    if slot_hashes_index == slot_hashes.len() {
                        // The vote slot does not exist in the SlotHashes history because it's too old,
                        // i.e. older than the oldest slot in the history.
                        assert!(proposed_vote_slot < earliest_slot_hash_in_history);
                        if !self.contains_slot(proposed_vote_slot) && root_to_check.is_none() {
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
                                assert!(self.root_slot.unwrap() < earliest_slot_hash_in_history);
                            }
                            root_to_check = None;
                        } else {
                            vote_state_update_index += 1;
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
                    slot_hashes_index -= 1;
                    continue;
                }
                Ordering::Equal => {
                    // Once the slot in `vote_state_update.lockouts` is found, bump to the next slot
                    // in `vote_state_update.lockouts` and continue. If we were checking the root,
                    // start checking the vote state instead.
                    if root_to_check.is_some() {
                        root_to_check = None;
                    } else {
                        vote_state_update_index += 1;
                        slot_hashes_index -= 1;
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
                self.node_pubkey,
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
            } else if vote_state_update_index
                == vote_state_update_indexes_to_filter[filter_votes_index]
            {
                filter_votes_index += 1;
                false
            } else {
                true
            };

            vote_state_update_index += 1;
            should_retain
        });

        Ok(())
    }

    fn check_slots_are_valid(
        &self,
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
            if self
                .last_voted_slot()
                .map_or(false, |last_voted_slot| vote_slots[i] <= last_voted_slot)
            {
                i += 1;
                continue;
            }

            // 2) Find the hash for this slot `s`.
            if vote_slots[i] != slot_hashes[j - 1].0 {
                // Decrement `j` to find newer slots
                j -= 1;
                continue;
            }

            // 3) Once the hash for `s` is found, bump `s` to the next slot
            // in `vote_slots` and continue.
            i += 1;
            j -= 1;
        }

        if j == slot_hashes.len() {
            // This means we never made it to steps 2) or 3) above, otherwise
            // `j` would have been decremented at least once. This means
            // there are not slots in `vote_slots` greater than `last_voted_slot`
            debug!(
                "{} dropped vote slots {:?}, vote hash: {:?} slot hashes:SlotHash {:?}, too old ",
                self.node_pubkey, vote_slots, vote_hash, slot_hashes
            );
            return Err(VoteError::VoteTooOld);
        }
        if i != vote_slots.len() {
            // This means there existed some slot for which we couldn't find
            // a matching slot hash in step 2)
            info!(
                "{} dropped vote slots {:?} failed to match slot hashes: {:?}",
                self.node_pubkey, vote_slots, slot_hashes,
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
                self.node_pubkey, vote_slots, vote_hash, slot_hashes[j].1
            );
            inc_new_counter_info!("dropped-vote-hash", 1);
            return Err(VoteError::SlotHashMismatch);
        }
        Ok(())
    }

    // `Ensure check_update_vote_state_slots_are_valid()` runs on the slots in `new_state`
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
        &mut self,
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

        match (new_root, self.root_slot) {
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
            if vote.confirmation_count == 0 {
                return Err(VoteError::ZeroConfirmations);
            } else if vote.confirmation_count > MAX_LOCKOUT_HISTORY as u32 {
                return Err(VoteError::ConfirmationTooLarge);
            } else if let Some(new_root) = new_root {
                if vote.slot <= new_root
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
                if previous_vote.slot >= vote.slot {
                    return Err(VoteError::SlotsNotOrdered);
                } else if previous_vote.confirmation_count <= vote.confirmation_count {
                    return Err(VoteError::ConfirmationsNotOrdered);
                } else if vote.slot > previous_vote.last_locked_out_slot() {
                    return Err(VoteError::NewVoteStateLockoutMismatch);
                }
            }
            previous_vote = Some(vote);
        }

        // Find the first vote in the current vote state for a slot greater
        // than the new proposed root
        let mut current_vote_state_index = 0;
        let mut new_vote_state_index = 0;

        // Count the number of slots at and before the new root within the current vote state lockouts.  Start with 1
        // for the new root.  The purpose of this is to know how many slots were rooted by this state update:
        // - The new root was rooted
        // - As were any slots that were in the current state but are not in the new state.  The only slots which
        //   can be in this set are those oldest slots in the current vote state that are not present in the
        //   new vote state; these have been "popped off the back" of the tower and thus represent finalized slots
        let mut finalized_slot_count = 1_u64;

        for current_vote in &self.votes {
            // Find the first vote in the current vote state for a slot greater
            // than the new proposed root
            if let Some(new_root) = new_root {
                if current_vote.slot <= new_root {
                    current_vote_state_index += 1;
                    if current_vote.slot != new_root {
                        finalized_slot_count += 1;
                    }
                    continue;
                }
            }

            break;
        }

        // All the votes in our current vote state that are missing from the new vote state
        // must have been expired by later votes. Check that the lockouts match this assumption.
        while current_vote_state_index < self.votes.len() && new_vote_state_index < new_state.len()
        {
            let current_vote = &self.votes[current_vote_state_index];
            let new_vote = &new_state[new_vote_state_index];

            // If the current slot is less than the new proposed slot, then the
            // new slot must have popped off the old slot, so check that the
            // lockouts are corrects.
            match current_vote.slot.cmp(&new_vote.slot) {
                Ordering::Less => {
                    if current_vote.last_locked_out_slot() >= new_vote.slot {
                        return Err(VoteError::LockoutConflict);
                    }
                    current_vote_state_index += 1;
                }
                Ordering::Equal => {
                    // The new vote state should never have less lockout than
                    // the previous vote state for the same slot
                    if new_vote.confirmation_count < current_vote.confirmation_count {
                        return Err(VoteError::ConfirmationRollBack);
                    }

                    current_vote_state_index += 1;
                    new_vote_state_index += 1;
                }
                Ordering::Greater => {
                    new_vote_state_index += 1;
                }
            }
        }

        // `new_vote_state` passed all the checks, finalize the change by rewriting
        // our state.
        if self.root_slot != new_root {
            // Award vote credits based on the number of slots that were voted on and have reached finality
            if feature_set
                .map(|feature_set| {
                    feature_set.is_active(&feature_set::vote_state_update_credit_per_dequeue::id())
                })
                .unwrap_or(false)
            {
                // For each finalized slot, there was one voted-on slot in the new vote state that was responsible for
                // finalizing it. Each of those votes is awarded 1 credit.
                self.increment_credits(epoch, finalized_slot_count);
            } else {
                self.increment_credits(epoch, 1);
            }
        }
        if let Some(timestamp) = timestamp {
            let last_slot = new_state.back().unwrap().slot;
            self.process_timestamp(last_slot, timestamp)?;
        }
        self.root_slot = new_root;
        self.votes = new_state;
        Ok(())
    }

    pub fn process_vote(
        &mut self,
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

        self.check_slots_are_valid(vote_slots, &vote.hash, slot_hashes)?;

        vote_slots
            .iter()
            .for_each(|s| self.process_next_vote_slot(*s, epoch));
        Ok(())
    }

    pub fn process_next_vote_slot(&mut self, next_vote_slot: Slot, epoch: Epoch) {
        // Ignore votes for slots earlier than we already have votes for
        if self
            .last_voted_slot()
            .map_or(false, |last_voted_slot| next_vote_slot <= last_voted_slot)
        {
            return;
        }

        let vote = Lockout::new(next_vote_slot);

        self.pop_expired_votes(next_vote_slot);

        // Once the stack is full, pop the oldest lockout and distribute rewards
        if self.votes.len() == MAX_LOCKOUT_HISTORY {
            let vote = self.votes.pop_front().unwrap();
            self.root_slot = Some(vote.slot);

            self.increment_credits(epoch, 1);
        }
        self.votes.push_back(vote);
        self.double_lockouts();
    }

    /// increment credits, record credits for last epoch if new epoch
    pub fn increment_credits(&mut self, epoch: Epoch, credits: u64) {
        // increment credits, record by epoch

        // never seen a credit
        if self.epoch_credits.is_empty() {
            self.epoch_credits.push((epoch, 0, 0));
        } else if epoch != self.epoch_credits.last().unwrap().0 {
            let (_, credits, prev_credits) = *self.epoch_credits.last().unwrap();

            if credits != prev_credits {
                // if credits were earned previous epoch
                // append entry at end of list for the new epoch
                self.epoch_credits.push((epoch, credits, credits));
            } else {
                // else just move the current epoch
                self.epoch_credits.last_mut().unwrap().0 = epoch;
            }

            // Remove too old epoch_credits
            if self.epoch_credits.len() > MAX_EPOCH_CREDITS_HISTORY {
                self.epoch_credits.remove(0);
            }
        }

        self.epoch_credits.last_mut().unwrap().1 += credits;
    }

    /// "unchecked" functions used by tests and Tower
    pub fn process_vote_unchecked(&mut self, vote: Vote) {
        let slot_hashes: Vec<_> = vote.slots.iter().rev().map(|x| (*x, vote.hash)).collect();
        let _ignored = self.process_vote(&vote, &slot_hashes, self.current_epoch(), None);
    }

    pub fn process_slot_vote_unchecked(&mut self, slot: Slot) {
        self.process_vote_unchecked(Vote::new(vec![slot], Hash::default()));
    }

    pub fn nth_recent_vote(&self, position: usize) -> Option<&Lockout> {
        if position < self.votes.len() {
            let pos = self.votes.len() - 1 - position;
            self.votes.get(pos)
        } else {
            None
        }
    }

    pub fn last_lockout(&self) -> Option<&Lockout> {
        self.votes.back()
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        self.last_lockout().map(|v| v.slot)
    }

    // Upto MAX_LOCKOUT_HISTORY many recent unexpired
    // vote slots pushed onto the stack.
    pub fn tower(&self) -> Vec<Slot> {
        self.votes.iter().map(|v| v.slot).collect()
    }

    pub fn current_epoch(&self) -> Epoch {
        if self.epoch_credits.is_empty() {
            0
        } else {
            self.epoch_credits.last().unwrap().0
        }
    }

    /// Number of "credits" owed to this account from the mining pool. Submit this
    /// VoteState to the Rewards program to trade credits for lamports.
    pub fn credits(&self) -> u64 {
        if self.epoch_credits.is_empty() {
            0
        } else {
            self.epoch_credits.last().unwrap().1
        }
    }

    /// Number of "credits" owed to this account from the mining pool on a per-epoch basis,
    ///  starting from credits observed.
    /// Each tuple of (Epoch, u64, u64) is read as (epoch, credits, prev_credits), where
    ///   credits for each epoch is credits - prev_credits; while redundant this makes
    ///   calculating rewards over partial epochs nice and simple
    pub fn epoch_credits(&self) -> &Vec<(Epoch, u64, u64)> {
        &self.epoch_credits
    }

    fn set_new_authorized_voter<F>(
        &mut self,
        authorized_pubkey: &Pubkey,
        current_epoch: Epoch,
        target_epoch: Epoch,
        verify: F,
    ) -> Result<(), InstructionError>
    where
        F: Fn(Pubkey) -> Result<(), InstructionError>,
    {
        let epoch_authorized_voter = self.get_and_update_authorized_voter(current_epoch)?;
        verify(epoch_authorized_voter)?;

        // The offset in slots `n` on which the target_epoch
        // (default value `DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET`) is
        // calculated is the number of slots available from the
        // first slot `S` of an epoch in which to set a new voter for
        // the epoch at `S` + `n`
        if self.authorized_voters.contains(target_epoch) {
            return Err(VoteError::TooSoonToReauthorize.into());
        }

        // Get the latest authorized_voter
        let (latest_epoch, latest_authorized_pubkey) = self
            .authorized_voters
            .last()
            .ok_or(InstructionError::InvalidAccountData)?;

        // If we're not setting the same pubkey as authorized pubkey again,
        // then update the list of prior voters to mark the expiration
        // of the old authorized pubkey
        if latest_authorized_pubkey != authorized_pubkey {
            // Update the epoch ranges of authorized pubkeys that will be expired
            let epoch_of_last_authorized_switch =
                self.prior_voters.last().map(|range| range.2).unwrap_or(0);

            // target_epoch must:
            // 1) Be monotonically increasing due to the clock always
            //    moving forward
            // 2) not be equal to latest epoch otherwise this
            //    function would have returned TooSoonToReauthorize error
            //    above
            assert!(target_epoch > *latest_epoch);

            // Commit the new state
            self.prior_voters.append((
                *latest_authorized_pubkey,
                epoch_of_last_authorized_switch,
                target_epoch,
            ));
        }

        self.authorized_voters
            .insert(target_epoch, *authorized_pubkey);

        Ok(())
    }

    fn get_and_update_authorized_voter(
        &mut self,
        current_epoch: Epoch,
    ) -> Result<Pubkey, InstructionError> {
        let pubkey = self
            .authorized_voters
            .get_and_cache_authorized_voter_for_epoch(current_epoch)
            .ok_or(InstructionError::InvalidAccountData)?;
        self.authorized_voters
            .purge_authorized_voters(current_epoch);
        Ok(pubkey)
    }

    // Pop all recent votes that are not locked out at the next vote slot.  This
    // allows validators to switch forks once their votes for another fork have
    // expired. This also allows validators continue voting on recent blocks in
    // the same fork without increasing lockouts.
    fn pop_expired_votes(&mut self, next_vote_slot: Slot) {
        while let Some(vote) = self.last_lockout() {
            if !vote.is_locked_out_at_slot(next_vote_slot) {
                self.votes.pop_back();
            } else {
                break;
            }
        }
    }

    fn double_lockouts(&mut self) {
        let stack_depth = self.votes.len();
        for (i, v) in self.votes.iter_mut().enumerate() {
            // Don't increase the lockout for this vote until we get more confirmations
            // than the max number of confirmations this vote has seen
            if stack_depth > i + v.confirmation_count as usize {
                v.confirmation_count += 1;
            }
        }
    }

    pub fn process_timestamp(
        &mut self,
        slot: Slot,
        timestamp: UnixTimestamp,
    ) -> Result<(), VoteError> {
        if (slot < self.last_timestamp.slot || timestamp < self.last_timestamp.timestamp)
            || (slot == self.last_timestamp.slot
                && BlockTimestamp { slot, timestamp } != self.last_timestamp
                && self.last_timestamp.slot != 0)
        {
            return Err(VoteError::TimestampTooOld);
        }
        self.last_timestamp = BlockTimestamp { slot, timestamp };
        Ok(())
    }

    pub fn is_correct_size_and_initialized(data: &[u8]) -> bool {
        const VERSION_OFFSET: usize = 4;
        data.len() == VoteState::size_of()
            && data[VERSION_OFFSET..VERSION_OFFSET + DEFAULT_PRIOR_VOTERS_OFFSET]
                != [0; DEFAULT_PRIOR_VOTERS_OFFSET]
    }
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
                clock.leader_schedule_epoch + 1,
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

    vote_account.set_state(&VoteStateVersions::new_current(vote_state))
}

/// Update the node_pubkey, requires signature of the authorized voter
pub fn update_validator_identity<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedAccount,
    node_pubkey: &Pubkey,
    signers: &HashSet<Pubkey, S>,
) -> Result<(), InstructionError> {
    let mut vote_state: VoteState = vote_account
        .get_state::<VoteStateVersions>()?
        .convert_to_current();

    // current authorized withdrawer must say "yay"
    verify_authorized_signer(&vote_state.authorized_withdrawer, signers)?;

    // new node must say "yay"
    verify_authorized_signer(node_pubkey, signers)?;

    vote_state.node_pubkey = *node_pubkey;

    vote_account.set_state(&VoteStateVersions::new_current(vote_state))
}

/// Update the vote account's commission
pub fn update_commission<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedAccount,
    commission: u8,
    signers: &HashSet<Pubkey, S>,
) -> Result<(), InstructionError> {
    let mut vote_state: VoteState = vote_account
        .get_state::<VoteStateVersions>()?
        .convert_to_current();

    // current authorized withdrawer must say "yay"
    verify_authorized_signer(&vote_state.authorized_withdrawer, signers)?;

    vote_state.commission = commission;

    vote_account.set_state(&VoteStateVersions::new_current(vote_state))
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
    vote_account_index: usize,
    lamports: u64,
    to_account_index: usize,
    signers: &HashSet<Pubkey, S>,
    rent_sysvar: &Rent,
    clock: Option<&Clock>,
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
            vote_account.set_state(&VoteStateVersions::new_current(VoteState::default()))?;
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
) -> Result<(), InstructionError> {
    if vote_account.get_data().len() != VoteState::size_of() {
        return Err(InstructionError::InvalidAccountData);
    }
    let versioned = vote_account.get_state::<VoteStateVersions>()?;

    if !versioned.is_uninitialized() {
        return Err(InstructionError::AccountAlreadyInitialized);
    }

    // node must agree to accept this vote account
    verify_authorized_signer(&vote_init.node_pubkey, signers)?;

    vote_account.set_state(&VoteStateVersions::new_current(VoteState::new(
        vote_init, clock,
    )))
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

pub fn process_vote<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedAccount,
    slot_hashes: &[SlotHash],
    clock: &Clock,
    vote: &Vote,
    signers: &HashSet<Pubkey, S>,
    feature_set: &FeatureSet,
) -> Result<(), InstructionError> {
    let mut vote_state = verify_and_get_vote_state(vote_account, clock, signers)?;

    vote_state.process_vote(vote, slot_hashes, clock.epoch, Some(feature_set))?;
    if let Some(timestamp) = vote.timestamp {
        vote.slots
            .iter()
            .max()
            .ok_or(VoteError::EmptySlots)
            .and_then(|slot| vote_state.process_timestamp(*slot, timestamp))?;
    }
    vote_account.set_state(&VoteStateVersions::new_current(vote_state))
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
    vote_account.set_state(&VoteStateVersions::new_current(vote_state))
}

pub fn do_process_vote_state_update(
    vote_state: &mut VoteState,
    slot_hashes: &[SlotHash],
    epoch: u64,
    mut vote_state_update: VoteStateUpdate,
    feature_set: Option<&FeatureSet>,
) -> Result<(), VoteError> {
    vote_state.check_update_vote_state_slots_are_valid(
        &mut vote_state_update,
        slot_hashes,
        feature_set,
    )?;
    vote_state.process_new_vote_state(
        vote_state_update.lockouts,
        vote_state_update.root,
        vote_state_update.timestamp,
        epoch,
        feature_set,
    )
}

pub fn create_account_with_authorized(
    node_pubkey: &Pubkey,
    authorized_voter: &Pubkey,
    authorized_withdrawer: &Pubkey,
    commission: u8,
    lamports: u64,
) -> AccountSharedData {
    let mut vote_account = AccountSharedData::new(lamports, VoteState::size_of(), &id());

    let vote_state = VoteState::new(
        &VoteInit {
            node_pubkey: *node_pubkey,
            authorized_voter: *authorized_voter,
            authorized_withdrawer: *authorized_withdrawer,
            commission,
        },
        &Clock::default(),
    );

    let versioned = VoteStateVersions::new_current(vote_state);
    VoteState::to(&versioned, &mut vote_account).unwrap();

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
