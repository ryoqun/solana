use {
    solana_ledger::blockstore::Blockstore,
    solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey, timing::timestamp},
    std::{
        collections::HashMap,
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    },
};

// Number of validators to sample for the ancestor repair
// We use static to enable tests from having to spin up 21 validators
static ANCESTOR_HASH_REPAIR_SAMPLE_SIZE: AtomicUsize = AtomicUsize::new(21);

pub fn get_ancestor_hash_repair_sample_size() -> usize {
    ANCESTOR_HASH_REPAIR_SAMPLE_SIZE.load(Ordering::Relaxed)
}

pub fn set_ancestor_hash_repair_sample_size_for_tests_only(sample_size: usize) {
    ANCESTOR_HASH_REPAIR_SAMPLE_SIZE.store(sample_size, Ordering::Relaxed);
}

// Even assuming 20% of validators malicious, the chance that >= 11 of the
// ANCESTOR_HASH_REPAIR_SAMPLE_SIZE = 21 validators is malicious is roughly 1/1000.
// Assuming we send a separate sample every 5 seconds, that's once every hour.

// On the other hand with a 52-48 split of validators with one version of the block vs
// another, the chance of >= 11 of the 21 sampled being from the 52% portion is
// about 57%, so we should be able to find a correct sample in a reasonable amount of time.
pub fn get_minimum_ancestor_agreement_size() -> usize {
    (get_ancestor_hash_repair_sample_size() + 1) / 2
}
const RETRY_INTERVAL_SECONDS: usize = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DuplicateAncestorDecision {
    InvalidSample,
    SampleNotDuplicateConfirmed,
    ContinueSearch(DuplicateSlotRepairStatus),
    EarliestMismatchFound(DuplicateSlotRepairStatus),
    EarliestPrunedMismatchFound(DuplicateSlotRepairStatus),
}

impl DuplicateAncestorDecision {
    pub fn is_retryable(&self) -> bool {
        match self {
            // If we get a bad sample from malicious validators, then retry
            DuplicateAncestorDecision::InvalidSample
            // It may be possible the validators have not yet detected duplicate confirmation
            // so retry
            | DuplicateAncestorDecision::SampleNotDuplicateConfirmed => true,

             DuplicateAncestorDecision::ContinueSearch(_status)
            | DuplicateAncestorDecision::EarliestMismatchFound(_status)
            | DuplicateAncestorDecision::EarliestPrunedMismatchFound(_status) => false,
        }
    }

    pub fn repair_status(&self) -> Option<&DuplicateSlotRepairStatus> {
        match self {
            DuplicateAncestorDecision::InvalidSample
            | DuplicateAncestorDecision::SampleNotDuplicateConfirmed => None,

            DuplicateAncestorDecision::ContinueSearch(status)
            | DuplicateAncestorDecision::EarliestMismatchFound(status)
            | DuplicateAncestorDecision::EarliestPrunedMismatchFound(status) => Some(status),
        }
    }

    pub fn repair_status_mut(&mut self) -> Option<&mut DuplicateSlotRepairStatus> {
        match self {
            DuplicateAncestorDecision::InvalidSample
            | DuplicateAncestorDecision::SampleNotDuplicateConfirmed => None,

            DuplicateAncestorDecision::ContinueSearch(status)
            | DuplicateAncestorDecision::EarliestMismatchFound(status)
            | DuplicateAncestorDecision::EarliestPrunedMismatchFound(status) => Some(status),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DuplicateSlotRepairStatus {
    // The first ancestor slot that is mismatched.
    // A mismatched ancestor slot is one that has been replayed (frozen)
    // that has a different hash than the one agreed upon by the sampled peers.
    //
    //
    // This is the slots that needs to be dumped in order to replay the originally requested slot.
    pub correct_ancestor_to_repair: (Slot, Hash),
    pub repair_pubkey_and_addr: Option<(Pubkey, SocketAddr)>,
    pub start_ts: u64,
}

impl DuplicateSlotRepairStatus {
    fn new(correct_ancestor_to_repair: (Slot, Hash)) -> Self {
        Self {
            correct_ancestor_to_repair,
            repair_pubkey_and_addr: None,
            start_ts: timestamp(),
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AncestorRequestType {
    #[default]
    DeadDuplicateConfirmed,
    PopularPruned,
}

impl AncestorRequestType {
    pub fn is_pruned(&self) -> bool {
        matches!(self, Self::PopularPruned)
    }
}

pub struct AncestorDuplicateSlotToRepair {
    // Slot that `ancestor_hashes_service` found that needs to be repaired
    pub slot_to_repair: (Slot, Hash),
    // Condition that initiated this request
    pub request_type: AncestorRequestType,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AncestorRequestDecision {
    // The slot that initiated this request
    pub slot: Slot,
    // Condition which initiated this request
    pub request_type: AncestorRequestType,
    // Decision
    pub decision: DuplicateAncestorDecision,
}

impl AncestorRequestDecision {
    pub fn slot_to_repair(self) -> Option<AncestorDuplicateSlotToRepair> {
        let Self {
            request_type,
            mut decision,
            ..
        } = self;
        decision
            .repair_status_mut()
            .map(|status| AncestorDuplicateSlotToRepair {
                slot_to_repair: std::mem::take(&mut status.correct_ancestor_to_repair),
                request_type,
            })
    }

    pub fn is_retryable(&self) -> bool {
        self.decision.is_retryable()
    }
}

#[derive(Default, Clone)]
pub struct AncestorRequestStatus {
    // The mismatched slot that was the subject of the AncestorHashes(requested_mismatched_slot)
    // repair request. All responses to this request should be for ancestors of this slot.
    requested_mismatched_slot: Slot,
    // Condition which initiated this request
    request_type: AncestorRequestType,
    // Timestamp at which we sent out the requests
    start_ts: u64,
    // The addresses of the validators we asked for a response, a response is only acceptable
    // from these validators. The boolean represents whether the validator
    // has responded.
    sampled_validators: HashMap<SocketAddr, bool>,
    // The number of sampled validators that have responded
    num_responses: usize,
    // Validators who have responded to our ancestor repair requests. An entry
    // Vec<(Slot, Hash)> -> usize tells us which validators have
    // responded with the same Vec<(Slot, Hash)> set of ancestors.
    //
    // TODO: Trie may be more efficient
    ancestor_request_responses: HashMap<Vec<(Slot, Hash)>, Vec<SocketAddr>>,
}

impl AncestorRequestStatus {
    pub fn new(
        sampled_validators: impl Iterator<Item = SocketAddr>,
        requested_mismatched_slot: Slot,
        request_type: AncestorRequestType,
    ) -> Self {
        AncestorRequestStatus {
            requested_mismatched_slot,
            request_type,
            start_ts: timestamp(),
            sampled_validators: sampled_validators.map(|p| (p, false)).collect(),
            ..AncestorRequestStatus::default()
        }
    }

    /// Record the response from `from_addr`. Returns Some(DuplicateAncestorDecision)
    /// if we have finalized a decision based on the responses. We can finalize a decision when
    /// one of the following conditions is met:
    /// 1) We have heard from all the validators, OR
    /// 2) >= MINIMUM_ANCESTOR_AGREEMENT_SIZE have agreed that we have the correct versions
    /// of nth ancestor, for some `n>0`, AND >= MINIMUM_ANCESTOR_AGREEMENT_SIZE have
    /// agreed we have the wrong version of the `n-1` ancestor.
    pub fn add_response(
        &mut self,
        from_addr: &SocketAddr,
        response_slot_hashes: Vec<(Slot, Hash)>,
        blockstore: &Blockstore,
    ) -> Option<DuplicateAncestorDecision> {
        if let Some(did_get_response) = self.sampled_validators.get_mut(from_addr) {
            if *did_get_response {
                // If we've already received a response from this validator, return.
                return None;
            }
            // Mark we got a response from this validator already
            *did_get_response = true;
            self.num_responses += 1;
        } else {
            // If this is not a response from one of the sampled validators, return.
            return None;
        }

        let validators_with_same_response = self
            .ancestor_request_responses
            .entry(response_slot_hashes.clone())
            .or_default();
        validators_with_same_response.push(*from_addr);

        // If we got enough of the sampled validators to respond, we are confident
        // this is the correct set of ancestors
        if validators_with_same_response.len()
            == get_minimum_ancestor_agreement_size().min(self.sampled_validators.len())
        {
            // When we reach MINIMUM_ANCESTOR_AGREEMENT_SIZE of the same responses,
            // check for mismatches.
            return Some(
                self.handle_sampled_validators_reached_agreement(blockstore, response_slot_hashes),
            );
        }

        // If everyone responded and we still haven't agreed upon a set of
        // ancestors, that means there was a lot of disagreement and we sampled
        // a bad set of validators.
        if self.num_responses
            == get_ancestor_hash_repair_sample_size().min(self.sampled_validators.len())
        {
            info!(
                "{} return invalid sample no agreement",
                self.requested_mismatched_slot
            );
            return Some(DuplicateAncestorDecision::InvalidSample);
        }

        None
    }

    pub fn request_type(&self) -> AncestorRequestType {
        self.request_type
    }

    fn handle_sampled_validators_reached_agreement(
        &mut self,
        blockstore: &Blockstore,
        agreed_response: Vec<(Slot, Hash)>,
    ) -> DuplicateAncestorDecision {
        if agreed_response.is_empty() {
            info!(
                "{} return invalid sample not duplicate confirmed",
                self.requested_mismatched_slot
            );
            return DuplicateAncestorDecision::SampleNotDuplicateConfirmed;
        }

        if agreed_response.first().unwrap().0 != self.requested_mismatched_slot {
            return DuplicateAncestorDecision::InvalidSample;
        }

        // Recall:
        // 1) *correct* validators only respond to `AncestorHashes(slot)` repair requests IFF they
        // saw the ancestors of `slot` get duplicate confirmed, AND
        // 2) *correct* validators respond with the ancestors of slot in sequential order
        // 3) `slot` should get duplicate confirmed on only one fork in the cluster
        //
        // From 1) and 3) we can conclude that it is highly likely at least one correct
        // validator reported `agreed_response` were the duplicate confirmed ancestors of
        // `self.requested_mismatched_slot`. From 2), all the `agreed_response` ancestors
        // are ordered such that the ancestor at index `i+1` is the direct descendant of the
        // ancestor at `i`.
        let mut last_ancestor = 0;
        let mut earliest_erroring_ancestor = None;
        // Iterate from smallest to largest ancestor, performing integrity checks.
        for (i, (ancestor_slot, agreed_upon_hash)) in agreed_response.iter().rev().enumerate() {
            if i != 0 && *ancestor_slot <= last_ancestor {
                info!(
                    "{} return invalid sample out of order",
                    self.requested_mismatched_slot
                );
                // Responses were not properly ordered
                return DuplicateAncestorDecision::InvalidSample;
            }
            if *ancestor_slot > self.requested_mismatched_slot {
                // We should only get ancestors of `self.requested_mismatched_slot`
                // in valid responses
                info!(
                    "{} return invalid sample big ancestor",
                    self.requested_mismatched_slot
                );
                return DuplicateAncestorDecision::InvalidSample;
            }
            let our_frozen_hash = blockstore.get_bank_hash(*ancestor_slot);
            if let Some(our_frozen_hash) = our_frozen_hash {
                match (
                    &earliest_erroring_ancestor,
                    our_frozen_hash == *agreed_upon_hash,
                ) {
                    (
                        Some((mismatch_i, DuplicateAncestorDecision::EarliestMismatchFound(_))),
                        true,
                    ) => {
                        // It's impossible have a different version of an earlier ancestor, but
                        // then also have the same version of a later ancestor.
                        let (mismatch_slot, mismatch_agreed_upon_hash) =
                            agreed_response[*mismatch_i];
                        let mismatch_our_frozen_hash = blockstore.get_bank_hash(mismatch_slot);
                        info!(
                            "When processing the ancestor sample for {}, there was a mismatch
                            for {mismatch_slot}: we had frozen hash {:?} and the cluster agreed upon
                            {mismatch_agreed_upon_hash}. However for a later ancestor {ancestor_slot}
                            we have agreement on {our_frozen_hash} as the bank hash. This should never
                            be possible, something is wrong or the cluster sample is invalid.
                            Rejecting and queuing the ancestor hashes request for retry",
                            self.requested_mismatched_slot,
                            mismatch_our_frozen_hash
                        );
                        return DuplicateAncestorDecision::InvalidSample;
                    }
                    (
                        Some((
                            mismatch_i,
                            DuplicateAncestorDecision::EarliestPrunedMismatchFound(_),
                        )),
                        true,
                    ) => {
                        // In this case an earlier ancestor was not frozen in our blockstore,
                        // however this later ancestor is matching with our version. This most
                        // likely should never happen however it could happen if we initiate an
                        // ancestor_hashes request immediately after startup from snapshot on a
                        // pruned branch, we will have a match for the snapshot bank, however we
                        // don't have any of the ancestors frozen
                        let (mismatch_slot, mismatch_agreed_upon_hash) =
                            agreed_response[*mismatch_i];
                        info!(
                            "When processing the ancestor sample for {}, an earlier ancestor {mismatch_slot}
                            was agreed upon by the cluster with hash {mismatch_agreed_upon_hash} but not
                            frozen in our blockstore. However for a later ancestor {ancestor_slot} we have
                            agreement on {our_frozen_hash} as the bank hash. This should only be possible if
                            we have just started from snapshot and immediately encountered a duplicate block on
                            a popular pruned fork, otherwise something is seriously wrong. Continuing with the
                            repair",
                            self.requested_mismatched_slot
                        );
                    }
                    (Some(decision), true) => panic!(
                        "Programmer error, {:?} should not be set in decision loop",
                        decision
                    ),
                    (Some(_), false) => { /* Already found a mismatch, descendants continue to mismatch as well */
                    }
                    (None, true) => { /* Mismatch hasn't been found yet */ }
                    (None, false) => {
                        // A mismatch has been found
                        earliest_erroring_ancestor = Some((
                            agreed_response.len() - i - 1,
                            DuplicateAncestorDecision::EarliestMismatchFound(
                                DuplicateSlotRepairStatus::default(),
                            ),
                        ));
                    }
                }
            } else if earliest_erroring_ancestor.is_none() && self.request_type.is_pruned() {
                // If the slot we are requesting for is pruned, then the slot and many of its
                // ancestors may not have a frozen hash (unlike dead slots where all the ancestors
                // will have a frozen hash). Thus the best we can do is to compare the slot numbers
                // to find the first ancestor that has the wrong parent, or the first missing
                // ancestor.
                //
                // We return the earliest such mismatch.
                if let Ok(Some(meta)) = blockstore.meta(*ancestor_slot) {
                    if i != 0 && meta.parent_slot != Some(last_ancestor) {
                        earliest_erroring_ancestor = Some((
                            agreed_response.len() - i - 1,
                            DuplicateAncestorDecision::EarliestPrunedMismatchFound(
                                DuplicateSlotRepairStatus::default(),
                            ),
                        ));
                    }
                } else {
                    earliest_erroring_ancestor = Some((
                        agreed_response.len() - i - 1,
                        DuplicateAncestorDecision::EarliestPrunedMismatchFound(
                            DuplicateSlotRepairStatus::default(),
                        ),
                    ));
                }
            } else if earliest_erroring_ancestor.is_none() {
                // If in our current ledger, `ancestor_slot` is actually on the same fork as
                // `self.requested_mismatched_slot`, then the `frozen_hash` should not be None here.
                // This is because we had to freeze `ancestor_slot` in order to replay its descendant
                // `self.requested_mismatched_slot`.
                //
                // However, it's possible that we have a version of
                // `self.requested_mismatched_slot` that is on the wrong fork with the wrong set of
                // ancestors. In this case, we could get responses about ancestors that are not
                // ancestors of our version of `self.requested_mismatched_slot`
                //
                //  ```
                //       1 - 2 - 3 - 5' - 6 (our current fork)
                //     /
                //  0
                //     \
                //       1 - 2 - 4 - 5 - 6 (cluster agreed fork)
                // ```
                //
                // In this case, if we make a AncestorsHashes(6) request for our dead slot 6, we may
                // get a response with slot `4` in it, which is a slot that doesn't have a frozen
                // hash in blockstore yet because either:
                //
                // 1) We haven't replayed that slot yet (it's on a different fork).
                // 2) We don't have that slot yet in our ledger.
                // 3) We have the correct/incorrect version of `4`, but we may have replayed
                // it on the wrong branch and it's dead.
                //
                // We ignore such ancestors in this loop.
                //
                // Note also that besides the missing slot `4`, there are also duplicates between
                // both the forks, namely `1, 2, 5` for which we have different versions of these slots
                // in our ledger. So how do we handle such cases where there are both missing and mismatched
                // ancestors?
                //
                // There are two cases:
                // 1) The first such mismatch `first_mismatch` appears somewhere BEFORE the slot `4` that is
                // missing from our blockstore.
                // 2) The first such mismatch `first_mismatch` appears AFTER the slot `4` that is
                // missing from our blockstore.
                //
                // For (1), the earlier cases in this function will cause us to detect the
                // mismatch, and stop until that slot is dumped and repaired.
                // For (2), we continue searching until we find the mismatch. There must be a
                // mismatch for us to have played the requested slot, and that mismatch will be
                // found or in case of no mismatch the last slot (requested slot) will be dumped
                // and repaired.
                //
                // In the rare case of multiple incorrect ancestry, where multiple cases of (1) and
                // (2) are present, the accompanying code in replay `dump_then_repair`, dumps
                // descendants of the earliest mismatch that also have frozen hashes. Failing that,
                // in extreme cases another round of ancestor or replay dump then repair will be
                // necessary to fix the fork.
                //
                // On example of an extreme case requiring multiple rounds of dump then repair is as follows:
                //
                // ```
                //       1 - 2 - 3 - 5' - 6' (our current fork)
                //     /
                //  0
                //     \
                //       1 - 2 - 4 - 5 - 6 (cluster agreed fork)
                // ```
                //
                // In this case suppose we have the wrong version of 5, the correct version is
                // supposed to chain to 4, and we also have the wrong version of 6, both versions
                // chain to 5 however ours is the duplicate.
                //
                // The first round of ancestor repair will detect 5' using case (2) above, and
                // replay will dump then repair it. Upon successful replay of 5, we see that 6 is
                // still dead or incorrect hash. This will require another round of ancestor or
                // replay dump then repair to fix.

                warn!(
                    "Blockstore is missing frozen hash for slot {},
                which the cluster claims is an ancestor of dead slot {}. Potentially
                our version of the dead slot chains to the wrong fork!",
                    ancestor_slot, self.requested_mismatched_slot
                );
            }
            last_ancestor = *ancestor_slot;
        }

        if let Some((earliest_erroring_ancestor_index, mut decision)) = earliest_erroring_ancestor {
            // We found the earliest mismatch `earliest_erroring_ancestor_index`.
            // We know all slots for indexes > `earliest_erroring_ancestor_index` in
            // `agreed_response` match the version we have replayed.
            if earliest_erroring_ancestor_index == agreed_response.len() - 1 {
                // If the earliest ancestor is missing or a mismatch, then we need to keep searching
                // for earlier mismatches
                let repair_status =
                    DuplicateSlotRepairStatus::new(*agreed_response.last().unwrap());
                DuplicateAncestorDecision::ContinueSearch(repair_status)
            } else {
                // We only need to dump and repair the earliest mismatching ancestor.
                let repair_status = decision.repair_status_mut().unwrap();
                repair_status.correct_ancestor_to_repair =
                    agreed_response[earliest_erroring_ancestor_index];
                decision
            }
        } else {
            // If we haven't returned by now, this implies all the ancestors matched our versions
            // of those ancestors, or are missing or incomplete. Only slot to dump and repair is
            // `self.requested_mismatched_slot`
            let repair_status = DuplicateSlotRepairStatus::new(*agreed_response.first().unwrap());
            if self.request_type.is_pruned() {
                DuplicateAncestorDecision::EarliestPrunedMismatchFound(repair_status)
            } else {
                DuplicateAncestorDecision::EarliestMismatchFound(repair_status)
            }
        }
    }

    /// Given a timestamp in milliseconds, return if we should retry with another sample batch
    /// due to timeout
    pub fn is_expired(&self) -> bool {
        timestamp() - self.start_ts > RETRY_INTERVAL_SECONDS as u64 * 1000
    }
}
