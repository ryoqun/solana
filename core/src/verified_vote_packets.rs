use {
    crate::{cluster_info_vote_listener::VerifiedLabelVotePacketsReceiver, result::Result},
    itertools::Itertools,
    solana_perf::packet::PacketBatch,
    solana_runtime::{
        bank::Bank,
        vote_transaction::{VoteTransaction, VoteTransaction::VoteStateUpdate},
    },
    solana_sdk::{
        account::from_account,
        clock::Slot,
        feature_set::{allow_votes_to_directly_update_vote_state, FeatureSet},
        hash::Hash,
        pubkey::Pubkey,
        signature::Signature,
        slot_hashes::SlotHashes,
        sysvar,
    },
    std::{
        collections::{BTreeMap, HashMap, HashSet},
        sync::Arc,
        time::Duration,
    },
};

const MAX_VOTES_PER_VALIDATOR: usize = 1000;

pub struct VerifiedVoteMetadata {
    pub vote_account_key: Pubkey,
    pub vote: VoteTransaction,
    pub packet_batch: PacketBatch,
    pub signature: Signature,
}

pub struct ValidatorGossipVotesIterator<'a> {
    my_leader_bank: Arc<Bank>,
    slot_hashes: SlotHashes,
    verified_vote_packets: &'a VerifiedVotePackets,
    vote_account_keys: Vec<Pubkey>,
    previously_sent_to_bank_votes: &'a mut HashSet<Signature>,
}

impl<'a> ValidatorGossipVotesIterator<'a> {
    pub fn new(
        my_leader_bank: Arc<Bank>,
        verified_vote_packets: &'a VerifiedVotePackets,
        previously_sent_to_bank_votes: &'a mut HashSet<Signature>,
    ) -> Self {
        let slot_hashes_account = my_leader_bank.get_account(&sysvar::slot_hashes::id());

        if slot_hashes_account.is_none() {
            warn!(
                "Slot hashes sysvar doesn't exist on bank {}",
                my_leader_bank.slot()
            );
        }

        let slot_hashes_account = slot_hashes_account.unwrap_or_default();
        let slot_hashes = from_account::<SlotHashes, _>(&slot_hashes_account).unwrap_or_default();

        // TODO: my_leader_bank.vote_accounts() may not contain zero-staked validators
        // in this epoch, but those validators may have stake warming up in the next epoch
        // Sort by stake weight so heavier validators' votes are sent first
        let vote_account_keys: Vec<Pubkey> = my_leader_bank
            .vote_accounts()
            .iter()
            .map(|(pubkey, &(stake, _))| (pubkey, stake))
            .sorted_unstable_by_key(|&(_, stake)| std::cmp::Reverse(stake))
            .map(|(&pubkey, _)| pubkey)
            .collect();
        Self {
            my_leader_bank,
            slot_hashes,
            verified_vote_packets,
            vote_account_keys,
            previously_sent_to_bank_votes,
        }
    }

    fn filter_vote(
        &mut self,
        slot: &Slot,
        hash: &Hash,
        packet: &PacketBatch,
        tx_signature: &Signature,
    ) -> Option<PacketBatch> {
        // Don't send the same vote to the same bank multiple times
        if self.previously_sent_to_bank_votes.contains(tx_signature) {
            return None;
        }
        self.previously_sent_to_bank_votes.insert(*tx_signature);
        // Filter out votes on the wrong fork (or too old to be)
        // on this fork
        if self
            .slot_hashes
            .get(slot)
            .map(|found_hash| found_hash == hash)
            .unwrap_or(false)
        {
            Some(packet.clone())
        } else {
            None
        }
    }
}

/// Each iteration returns all of the missing votes for a single validator, the votes
/// ordered from smallest to largest.
///
/// Iterator is done after iterating through all vote accounts
impl<'a> Iterator for ValidatorGossipVotesIterator<'a> {
    type Item = Vec<PacketBatch>;

    fn next(&mut self) -> Option<Self::Item> {
        use SingleValidatorVotes::*;
        while !self.vote_account_keys.is_empty() {
            let vote_account_key = self.vote_account_keys.pop().unwrap();
            // Get all the gossip votes we've queued up for this validator
            // that are:
            // 1) missing from the current leader bank
            // 2) on the same fork
            let validator_votes = self
                .verified_vote_packets
                .0
                .get(&vote_account_key)
                .and_then(|validator_gossip_votes| {
                    // Fetch the validator's vote state from the bank
                    self.my_leader_bank
                        .vote_accounts()
                        .get(&vote_account_key)
                        .and_then(|(_stake, vote_account)| {
                            vote_account.vote_state().as_ref().ok().map(|vote_state| {
                                let start_vote_slot =
                                    vote_state.last_voted_slot().map(|x| x + 1).unwrap_or(0);
                                match validator_gossip_votes {
                                    FullTowerVote(GossipVote {
                                        slot,
                                        hash,
                                        packet_batch,
                                        signature,
                                    }) => self
                                        .filter_vote(slot, hash, packet_batch, signature)
                                        .map(|packet| vec![packet])
                                        .unwrap_or_default(),
                                    IncrementalVotes(validator_gossip_votes) => {
                                        validator_gossip_votes
                                            .range((start_vote_slot, Hash::default())..)
                                            .filter_map(|((slot, hash), (packet, tx_signature))| {
                                                self.filter_vote(slot, hash, packet, tx_signature)
                                            })
                                            .collect::<Vec<PacketBatch>>()
                                    }
                                }
                            })
                        })
                });
            if let Some(validator_votes) = validator_votes {
                if !validator_votes.is_empty() {
                    return Some(validator_votes);
                }
            }
        }
        None
    }
}

#[derive(Debug, Default, Clone)]
pub struct GossipVote {
    slot: Slot,
    hash: Hash,
    packet_batch: PacketBatch,
    signature: Signature,
}

pub enum SingleValidatorVotes {
    FullTowerVote(GossipVote),
    IncrementalVotes(BTreeMap<(Slot, Hash), (PacketBatch, Signature)>),
}

impl SingleValidatorVotes {
    fn get_latest_gossip_slot(&self) -> Slot {
        match self {
            Self::FullTowerVote(vote) => vote.slot,
            _ => 0,
        }
    }
}

#[derive(Default)]
pub struct VerifiedVotePackets(HashMap<Pubkey, SingleValidatorVotes>);

impl VerifiedVotePackets {
    pub fn receive_and_process_vote_packets(
        &mut self,
        vote_packets_receiver: &VerifiedLabelVotePacketsReceiver,
        would_be_leader: bool,
        feature_set: Option<Arc<FeatureSet>>,
    ) -> Result<()> {
        use SingleValidatorVotes::*;
        const RECV_TIMEOUT: Duration = Duration::from_millis(200);
        let vote_packets = vote_packets_receiver.recv_timeout(RECV_TIMEOUT)?;
        let vote_packets = std::iter::once(vote_packets).chain(vote_packets_receiver.try_iter());
        let mut is_full_tower_vote_enabled = false;
        if let Some(feature_set) = feature_set {
            is_full_tower_vote_enabled =
                feature_set.is_active(&allow_votes_to_directly_update_vote_state::id());
        }

        for gossip_votes in vote_packets {
            if would_be_leader {
                for verfied_vote_metadata in gossip_votes {
                    let VerifiedVoteMetadata {
                        vote_account_key,
                        vote,
                        packet_batch,
                        signature,
                    } = verfied_vote_metadata;
                    if vote.is_empty() {
                        error!("Empty votes should have been filtered out earlier in the pipeline");
                        continue;
                    }
                    let slot = vote.last_voted_slot().unwrap();
                    let hash = vote.hash();

                    match (vote, is_full_tower_vote_enabled) {
                        (VoteStateUpdate(_), true) => {
                            let latest_gossip_slot = match self.0.get(&vote_account_key) {
                                Some(vote) => vote.get_latest_gossip_slot(),
                                _ => 0,
                            };
                            // Since votes are not incremental, we keep only the latest vote
                            if slot > latest_gossip_slot {
                                self.0.insert(
                                    vote_account_key,
                                    FullTowerVote(GossipVote {
                                        slot,
                                        hash,
                                        packet_batch,
                                        signature,
                                    }),
                                );
                            }
                        }
                        _ => {
                            if let Some(FullTowerVote(gossip_vote)) =
                                self.0.get_mut(&vote_account_key)
                            {
                                if slot > gossip_vote.slot && is_full_tower_vote_enabled {
                                    warn!(
                                        "Originally {} submitted full tower votes, but now has reverted to incremental votes. Converting back to old format.",
                                        vote_account_key
                                    );
                                    let mut votes = BTreeMap::new();
                                    let GossipVote {
                                        slot,
                                        hash,
                                        packet_batch,
                                        signature,
                                    } = std::mem::take(gossip_vote);
                                    votes.insert((slot, hash), (packet_batch, signature));
                                    self.0.insert(vote_account_key, IncrementalVotes(votes));
                                } else {
                                    continue;
                                }
                            };
                            let validator_votes: &mut BTreeMap<
                                (Slot, Hash),
                                (PacketBatch, Signature),
                            > = match self
                                .0
                                .entry(vote_account_key)
                                .or_insert(IncrementalVotes(BTreeMap::new()))
                            {
                                IncrementalVotes(votes) => votes,
                                FullTowerVote(_) => continue, // Should never happen
                            };
                            validator_votes.insert((slot, hash), (packet_batch, signature));
                            if validator_votes.len() > MAX_VOTES_PER_VALIDATOR {
                                let smallest_key = validator_votes.keys().next().cloned().unwrap();
                                validator_votes.remove(&smallest_key).unwrap();
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
