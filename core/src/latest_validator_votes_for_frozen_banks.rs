use {
    crate::heaviest_subtree_fork_choice::SlotHashKey,
    solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey},
    std::collections::{hash_map::Entry, HashMap},
};

#[derive(Default)]
pub struct LatestValidatorVotesForFrozenBanks {
    // TODO: Clean outdated/unstaked pubkeys from this list.
    max_gossip_frozen_votes: HashMap<Pubkey, (Slot, Vec<Hash>)>,
    max_replay_frozen_votes: HashMap<Pubkey, (Slot, Vec<Hash>)>,
    // Pubkeys that had their `max_frozen_votes` updated since the last
    // fork choice update
    fork_choice_dirty_set: HashMap<Pubkey, (Slot, Vec<Hash>)>,
}

impl LatestValidatorVotesForFrozenBanks {
    // `frozen_hash.is_some()` if the bank with slot == `vote_slot` is frozen
    // Returns whether the vote was actually added, and the latest voted frozen slot
    pub fn check_add_vote(
        &mut self,
        vote_pubkey: Pubkey,
        vote_slot: Slot,
        frozen_hash: Option<Hash>,
        is_replay_vote: bool,
    ) -> (bool, Option<Slot>) {
        let vote_map = if is_replay_vote {
            &mut self.max_replay_frozen_votes
        } else {
            &mut self.max_gossip_frozen_votes
        };
        let pubkey_max_frozen_votes = vote_map.entry(vote_pubkey);
        if let Some(frozen_hash) = frozen_hash {
            match pubkey_max_frozen_votes {
                Entry::Occupied(mut occupied_entry) => {
                    let (latest_frozen_vote_slot, latest_frozen_vote_hashes) =
                        occupied_entry.get_mut();
                    if vote_slot > *latest_frozen_vote_slot {
                        if is_replay_vote {
                            // Only record votes detected through replaying blocks,
                            // because votes in gossip are not consistently observable
                            // if the validator is replacing them.
                            self.fork_choice_dirty_set
                                .insert(vote_pubkey, (vote_slot, vec![frozen_hash]));
                        }
                        *latest_frozen_vote_slot = vote_slot;
                        *latest_frozen_vote_hashes = vec![frozen_hash];
                        return (true, Some(vote_slot));
                    } else if vote_slot == *latest_frozen_vote_slot
                        && !latest_frozen_vote_hashes.contains(&frozen_hash)
                    {
                        if is_replay_vote {
                            // Only record votes detected through replaying blocks,
                            // because votes in gossip are not consistently observable
                            // if the validator is replacing them.
                            let (_, dirty_frozen_hashes) =
                                self.fork_choice_dirty_set.entry(vote_pubkey).or_default();
                            assert!(!dirty_frozen_hashes.contains(&frozen_hash));
                            dirty_frozen_hashes.push(frozen_hash);
                        }
                        latest_frozen_vote_hashes.push(frozen_hash);
                        return (true, Some(vote_slot));
                    } else {
                        // We have newer votes for this validator, we don't care about this vote
                        return (false, Some(*latest_frozen_vote_slot));
                    }
                }

                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert((vote_slot, vec![frozen_hash]));
                    if is_replay_vote {
                        self.fork_choice_dirty_set
                            .insert(vote_pubkey, (vote_slot, vec![frozen_hash]));
                    }
                    return (true, Some(vote_slot));
                }
            }
        }

        // Non-frozen banks are not inserted because we only track frozen votes in this
        // struct
        (
            false,
            match pubkey_max_frozen_votes {
                Entry::Occupied(occupied_entry) => Some(occupied_entry.get().0),
                Entry::Vacant(_) => None,
            },
        )
    }

    pub fn take_votes_dirty_set(&mut self, root: Slot) -> Vec<(Pubkey, SlotHashKey)> {
        let new_votes = std::mem::take(&mut self.fork_choice_dirty_set);
        new_votes
            .into_iter()
            .filter(|(_, (slot, _))| *slot >= root)
            .flat_map(|(pk, (slot, hashes))| {
                hashes
                    .into_iter()
                    .map(|hash| (pk, (slot, hash)))
                    .collect::<Vec<(Pubkey, SlotHashKey)>>()
            })
            .collect()
    }

    pub fn max_gossip_frozen_votes(&self) -> &HashMap<Pubkey, (Slot, Vec<Hash>)> {
        &self.max_gossip_frozen_votes
    }
}
