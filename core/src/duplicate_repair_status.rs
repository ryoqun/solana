use {
    solana_ledger::blockstore::Blockstore,
    solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey, timing::timestamp},
    std::{collections::HashMap, net::SocketAddr},
};

// Number of validators to sample for the ancestor repair
pub const ANCESTOR_HASH_REPAIR_SAMPLE_SIZE: usize = 21;

// Even assuming 20% of validators malicious, the chance that >= 11 of the
// ANCESTOR_HASH_REPAIR_SAMPLE_SIZE = 21 validators is malicious is roughly 1/1000.
// Assuming we send a separate sample every 5 seconds, that's once every hour.

// On the other hand with a 52-48 split of validators with one version of the block vs
// another, the chance of >= 11 of the 21 sampled being from the 52% portion is
// about 57%, so we should be able to find a correct sample in a reasonable amount of time.
const MINIMUM_ANCESTOR_AGREEMENT_SIZE: usize = (ANCESTOR_HASH_REPAIR_SAMPLE_SIZE + 1) / 2;
const RETRY_INTERVAL_SECONDS: usize = 5;

#[derive(Debug, PartialEq, Eq)]
pub enum DuplicateAncestorDecision {
    InvalidSample,
    AncestorsAllMatch,
    SampleNotDuplicateConfirmed,
    ContinueSearch(DuplicateSlotRepairStatus),
    EarliestAncestorNotFrozen(DuplicateSlotRepairStatus),
    EarliestMismatchFound(DuplicateSlotRepairStatus),
}

impl DuplicateAncestorDecision {
    pub fn is_retryable(&self) -> bool {
        match self {
            // If we get a bad sample from malicious validators, then retry
            DuplicateAncestorDecision::InvalidSample
            // It may be possible the validators have not yet detected duplicate confirmation
            // so retry
           |  DuplicateAncestorDecision::SampleNotDuplicateConfirmed => true,

            DuplicateAncestorDecision::AncestorsAllMatch => false,

             DuplicateAncestorDecision::ContinueSearch(_status)
            | DuplicateAncestorDecision::EarliestAncestorNotFrozen(_status)
            | DuplicateAncestorDecision::EarliestMismatchFound(_status) => false,
        }
    }

    pub fn repair_status(&self) -> Option<&DuplicateSlotRepairStatus> {
        match self {
            DuplicateAncestorDecision::InvalidSample
            | DuplicateAncestorDecision::AncestorsAllMatch
            | DuplicateAncestorDecision::SampleNotDuplicateConfirmed => None,
            DuplicateAncestorDecision::ContinueSearch(status) => Some(status),
            DuplicateAncestorDecision::EarliestAncestorNotFrozen(status) => Some(status),
            DuplicateAncestorDecision::EarliestMismatchFound(status) => Some(status),
        }
    }

    fn repair_status_mut(&mut self) -> Option<&mut DuplicateSlotRepairStatus> {
        match self {
            DuplicateAncestorDecision::InvalidSample
            | DuplicateAncestorDecision::AncestorsAllMatch
            | DuplicateAncestorDecision::SampleNotDuplicateConfirmed => None,
            DuplicateAncestorDecision::ContinueSearch(status) => Some(status),
            DuplicateAncestorDecision::EarliestAncestorNotFrozen(status) => Some(status),
            DuplicateAncestorDecision::EarliestMismatchFound(status) => Some(status),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DuplicateSlotRepairStatus {
    // Any ancestor slots that are either missing or are mismatched.
    // A mismatched ancestor slot is one that has been replayed (frozen)
    // that has a different hash than the one agreed upon by the sampled peers.
    //
    //
    // These are the slots that need to be dumped in order to repair the correct
    // versions. The hash is None if the slot is not frozen, because it's:
    // 1) Dead
    // 2) Hasn't been replayed
    // 3) We don't have the slot in our Ledger
    pub correct_ancestors_to_repair: Vec<(Slot, Hash)>,
    pub repair_pubkey_and_addr: Option<(Pubkey, SocketAddr)>,
    pub start_ts: u64,
}

impl DuplicateSlotRepairStatus {
    fn new(correct_ancestors_to_repair: Vec<(Slot, Hash)>) -> Self {
        Self {
            correct_ancestors_to_repair,
            repair_pubkey_and_addr: None,
            start_ts: timestamp(),
        }
    }
}

#[derive(Default, Clone)]
pub struct AncestorRequestStatus {
    // The mismatched slot that was the subject of the AncestorHashes(requested_mismatched_slot)
    // repair request. All responses to this request should be for ancestors of this slot.
    requested_mismatched_slot: Slot,
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
    ) -> Self {
        AncestorRequestStatus {
            requested_mismatched_slot,
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
            == MINIMUM_ANCESTOR_AGREEMENT_SIZE.min(self.sampled_validators.len())
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
        if self.num_responses == ANCESTOR_HASH_REPAIR_SAMPLE_SIZE.min(self.sampled_validators.len())
        {
            info!(
                "{} return invalid sample no agreement",
                self.requested_mismatched_slot
            );
            return Some(DuplicateAncestorDecision::InvalidSample);
        }

        None
    }

    fn handle_sampled_validators_reached_agreement(
        &mut self,
        blockstore: &Blockstore,
        mut agreed_response: Vec<(Slot, Hash)>,
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
            last_ancestor = *ancestor_slot;
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
                if earliest_erroring_ancestor.is_some() && our_frozen_hash == *agreed_upon_hash {
                    // It's impossible have a different version of an earlier ancestor, but
                    // then also have the same version of a later ancestor.
                    info!("{} mismatches then matches", self.requested_mismatched_slot);
                    return DuplicateAncestorDecision::InvalidSample;
                } else if our_frozen_hash != *agreed_upon_hash
                    && earliest_erroring_ancestor.is_none()
                {
                    earliest_erroring_ancestor = Some((
                        agreed_response.len() - i - 1,
                        DuplicateAncestorDecision::EarliestMismatchFound(
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
                //       1 - 2 - 3 - 5' - 6' (our current fork)
                //     /
                //  0
                //     \
                //       1 - 2 - 4 - 5 - 6 (cluster agreed fork)
                // ```
                //
                // In this case, if we make a AncestorsHashes(6) request for our dead slot 6', we may
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
                // 1) The first such mismatch `first_mismatch` appears BEFORE the slot `4` that is
                // missing from our blockstore.
                // 2) The first such mismatch `first_mismatch` appears AFTER the slot `4` that is
                // missing from our blockstore.
                //
                // Because we know any mismatches will also trigger the mismatch casing earlier in
                // the function, we will return`EarliestMismatchFound(first_mismatch)`. This will
                // cause us to dump and repair `first_mismatch` and all its descendants, which should
                // be the right behavior in both above cases.
                warn!(
                    "Blockstore is missing frozen hash for slot {},
                which the cluster claims is an ancestor of dead slot {}. Potentially
                our version of the dead slot chains to the wrong fork!",
                    ancestor_slot, self.requested_mismatched_slot
                );
                earliest_erroring_ancestor = Some((
                    agreed_response.len() - i - 1,
                    DuplicateAncestorDecision::EarliestAncestorNotFrozen(
                        DuplicateSlotRepairStatus::default(),
                    ),
                ));
            }
        }

        if let Some((earliest_erroring_ancestor_index, mut decision)) = earliest_erroring_ancestor {
            // We found the earliest mismatch `earliest_erroring_ancestor_index`.
            // We know all slots for indexes > `earliest_erroring_ancestor_index` in
            // `agreed_response` match the version we have replayed.
            if earliest_erroring_ancestor_index == agreed_response.len() - 1 {
                // If the earliest ancestor is missing or a mismatch, then we need to keep searching
                // for earlier mismatches
                let repair_status = DuplicateSlotRepairStatus::new(agreed_response);
                DuplicateAncestorDecision::ContinueSearch(repair_status)
            } else {
                // We only need to look through the first `earliest_erroring_ancestor_index + 1`
                // elements and dump/repair any mismatches.
                agreed_response.truncate(earliest_erroring_ancestor_index + 1);
                let repair_status = decision.repair_status_mut().unwrap();
                repair_status.correct_ancestors_to_repair = agreed_response;
                decision
            }
        } else {
            // If we haven't returned by now, this implies all the ancestors matched our versions
            // of those ancestors. Only slot to dump and repair is `self.requested_mismatched_slot`
            DuplicateAncestorDecision::AncestorsAllMatch
        }
    }

    /// Given a timestamp in milliseconds, return if we should retry with another sample batch
    /// due to timeout
    pub fn is_expired(&self) -> bool {
        timestamp() - self.start_ts > RETRY_INTERVAL_SECONDS as u64 * 1000
    }
}
