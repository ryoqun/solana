use {solana_sdk::pubkey::Pubkey, std::collections::HashSet};

#[derive(Default)]
pub struct VoteStakeTracker {
    voted: HashSet<Pubkey>,
    stake: u64,
}

impl VoteStakeTracker {
    // Returns tuple (reached_threshold_results, is_new) where
    // Each index in `reached_threshold_results` is true if the corresponding threshold in the input
    // `thresholds_to_check` was newly reached by adding the stake of the input `vote_pubkey`
    // `is_new` is true if the vote has not been seen before
    pub fn add_vote_pubkey(
        &mut self,
        vote_pubkey: Pubkey,
        stake: u64,
        total_stake: u64,
        thresholds_to_check: &[f64],
    ) -> (Vec<bool>, bool) {
        let is_new = !self.voted.contains(&vote_pubkey);
        if is_new {
            self.voted.insert(vote_pubkey);
            let old_stake = self.stake;
            let new_stake = self.stake + stake;
            self.stake = new_stake;
            let reached_threshold_results: Vec<bool> = thresholds_to_check
                .iter()
                .map(|threshold| {
                    let threshold_stake = (total_stake as f64 * threshold) as u64;
                    old_stake <= threshold_stake && threshold_stake < new_stake
                })
                .collect();
            (reached_threshold_results, is_new)
        } else {
            (vec![false; thresholds_to_check.len()], is_new)
        }
    }

    pub fn voted(&self) -> &HashSet<Pubkey> {
        &self.voted
    }

    pub fn stake(&self) -> u64 {
        self.stake
    }
}
