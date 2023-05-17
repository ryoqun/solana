use {
    crate::latest_validator_votes_for_frozen_banks::LatestValidatorVotesForFrozenBanks,
    solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey},
    std::collections::{BTreeMap, HashMap},
};

#[derive(Default)]
pub struct UnfrozenGossipVerifiedVoteHashes {
    pub votes_per_slot: BTreeMap<Slot, HashMap<Hash, Vec<Pubkey>>>,
}

impl UnfrozenGossipVerifiedVoteHashes {
    // Update `latest_validator_votes_for_frozen_banks` if gossip has seen a newer vote
    // for a frozen bank.
    pub(crate) fn add_vote(
        &mut self,
        pubkey: Pubkey,
        vote_slot: Slot,
        hash: Hash,
        is_frozen: bool,
        latest_validator_votes_for_frozen_banks: &mut LatestValidatorVotesForFrozenBanks,
    ) {
        // If this is a frozen bank, then we need to update the `latest_validator_votes_for_frozen_banks`
        let frozen_hash = if is_frozen { Some(hash) } else { None };
        let (was_added, latest_frozen_vote_slot) = latest_validator_votes_for_frozen_banks
            .check_add_vote(pubkey, vote_slot, frozen_hash, false);

        if !was_added
            && latest_frozen_vote_slot
                .map(|latest_frozen_vote_slot| vote_slot >= latest_frozen_vote_slot)
                // If there's no latest frozen vote slot yet, then we should also insert
                .unwrap_or(true)
        {
            // At this point it must be that:
            // 1) `vote_slot` was not yet frozen
            // 2) and `vote_slot` >= than the latest frozen vote slot.

            // Thus we want to record this vote for later, in case a slot with this `vote_slot` + hash gets
            // frozen later
            self.votes_per_slot
                .entry(vote_slot)
                .or_default()
                .entry(hash)
                .or_default()
                .push(pubkey);
        }
    }

    // Cleanup `votes_per_slot` based on new roots
    pub fn set_root(&mut self, new_root: Slot) {
        self.votes_per_slot = self.votes_per_slot.split_off(&new_root);
        // `self.votes_per_slot` now only contains entries >= `new_root`
    }

    pub fn remove_slot_hash(&mut self, slot: Slot, hash: &Hash) -> Option<Vec<Pubkey>> {
        self.votes_per_slot.get_mut(&slot).and_then(|slot_hashes| {
            slot_hashes.remove(hash)
            // If `slot_hashes` becomes empty, it'll be removed by `set_root()` later
        })
    }
}
