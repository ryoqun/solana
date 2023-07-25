use {
    crate::weighted_shuffle::WeightedShuffle,
    indexmap::IndexMap,
    rand::Rng,
    solana_bloom::bloom::{AtomicBloom, Bloom},
    solana_sdk::{native_token::LAMPORTS_PER_SOL, pubkey::Pubkey},
    std::collections::HashMap,
};

const NUM_PUSH_ACTIVE_SET_ENTRIES: usize = 25;

// Each entry corresponds to a stake bucket for
//     min stake of { this node, crds value owner }
// The entry represents set of gossip nodes to actively
// push to for crds values belonging to the bucket.
#[derive(Default)]
pub(crate) struct PushActiveSet([PushActiveSetEntry; NUM_PUSH_ACTIVE_SET_ENTRIES]);

// Keys are gossip nodes to push messages to.
// Values are which origins the node has pruned.
#[derive(Default)]
struct PushActiveSetEntry(IndexMap</*node:*/ Pubkey, /*origins:*/ AtomicBloom<Pubkey>>);

impl PushActiveSet {
    #[cfg(debug_assertions)]
    const MIN_NUM_BLOOM_ITEMS: usize = 512;
    #[cfg(not(debug_assertions))]
    const MIN_NUM_BLOOM_ITEMS: usize = crate::cluster_info::CRDS_UNIQUE_PUBKEY_CAPACITY;

    pub(crate) fn get_nodes<'a>(
        &'a self,
        pubkey: &Pubkey,    // This node.
        origin: &'a Pubkey, // CRDS value owner.
        // If true forces gossip push even if the node has pruned the origin.
        should_force_push: impl FnMut(&Pubkey) -> bool + 'a,
        stakes: &HashMap<Pubkey, u64>,
    ) -> impl Iterator<Item = &Pubkey> + 'a {
        let stake = stakes.get(pubkey).min(stakes.get(origin));
        self.get_entry(stake).get_nodes(origin, should_force_push)
    }

    // Prunes origins for the given gossip node.
    // We will stop pushing messages from the specified origins to the node.
    pub(crate) fn prune(
        &self,
        pubkey: &Pubkey,    // This node.
        node: &Pubkey,      // Gossip node.
        origins: &[Pubkey], // CRDS value owners.
        stakes: &HashMap<Pubkey, u64>,
    ) {
        let stake = stakes.get(pubkey);
        for origin in origins {
            if origin == pubkey {
                continue;
            }
            let stake = stake.min(stakes.get(origin));
            self.get_entry(stake).prune(node, origin)
        }
    }

    pub(crate) fn rotate<R: Rng>(
        &mut self,
        rng: &mut R,
        size: usize, // Number of nodes to retain in each active-set entry.
        cluster_size: usize,
        // Gossip nodes to be sampled for each push active set.
        nodes: &[Pubkey],
        stakes: &HashMap<Pubkey, u64>,
    ) {
        let num_bloom_filter_items = cluster_size.max(Self::MIN_NUM_BLOOM_ITEMS);
        // Active set of nodes to push to are sampled from these gossip nodes,
        // using sampling probabilities obtained from the stake bucket of each
        // node.
        let buckets: Vec<_> = nodes
            .iter()
            .map(|node| get_stake_bucket(stakes.get(node)))
            .collect();
        // (k, entry) represents push active set where the stake bucket of
        //     min stake of {this node, crds value owner}
        // is equal to `k`. The `entry` maintains set of gossip nodes to
        // actively push to for crds values belonging to this bucket.
        for (k, entry) in self.0.iter_mut().enumerate() {
            let weights: Vec<u64> = buckets
                .iter()
                .map(|&bucket| {
                    // bucket <- get_stake_bucket(min stake of {
                    //  this node, crds value owner and gossip peer
                    // })
                    // weight <- (bucket + 1)^2
                    // min stake of {...} is a proxy for how much we care about
                    // the link, and tries to mirror similar logic on the
                    // receiving end when pruning incoming links:
                    // https://github.com/solana-labs/solana/blob/81394cf92/gossip/src/received_cache.rs#L100-L105
                    let bucket = bucket.min(k) as u64;
                    bucket.saturating_add(1).saturating_pow(2)
                })
                .collect();
            entry.rotate(rng, size, num_bloom_filter_items, nodes, &weights);
        }
    }

    fn get_entry(&self, stake: Option<&u64>) -> &PushActiveSetEntry {
        &self.0[get_stake_bucket(stake)]
    }
}

impl PushActiveSetEntry {
    const BLOOM_FALSE_RATE: f64 = 0.1;
    const BLOOM_MAX_BITS: usize = 1024 * 8 * 4;

    fn get_nodes<'a>(
        &'a self,
        origin: &'a Pubkey,
        // If true forces gossip push even if the node has pruned the origin.
        mut should_force_push: impl FnMut(&Pubkey) -> bool + 'a,
    ) -> impl Iterator<Item = &Pubkey> + 'a {
        self.0
            .iter()
            .filter(move |(node, bloom_filter)| {
                !bloom_filter.contains(origin) || should_force_push(node)
            })
            .map(|(node, _bloom_filter)| node)
    }

    fn prune(
        &self,
        node: &Pubkey,   // Gossip node.
        origin: &Pubkey, // CRDS value owner
    ) {
        if let Some(bloom_filter) = self.0.get(node) {
            bloom_filter.add(origin);
        }
    }

    fn rotate<R: Rng>(
        &mut self,
        rng: &mut R,
        size: usize, // Number of nodes to retain.
        num_bloom_filter_items: usize,
        nodes: &[Pubkey],
        weights: &[u64],
    ) {
        debug_assert_eq!(nodes.len(), weights.len());
        debug_assert!(weights.iter().all(|&weight| weight != 0u64));
        let shuffle = WeightedShuffle::new("rotate-active-set", weights).shuffle(rng);
        for node in shuffle.map(|k| &nodes[k]) {
            // We intend to discard the oldest/first entry in the index-map.
            if self.0.len() > size {
                break;
            }
            if self.0.contains_key(node) {
                continue;
            }
            let bloom = AtomicBloom::from(Bloom::random(
                num_bloom_filter_items,
                Self::BLOOM_FALSE_RATE,
                Self::BLOOM_MAX_BITS,
            ));
            bloom.add(node);
            self.0.insert(*node, bloom);
        }
        // Drop the oldest entry while preserving the ordering of others.
        while self.0.len() > size {
            self.0.shift_remove_index(0);
        }
    }
}

// Maps stake to bucket index.
fn get_stake_bucket(stake: Option<&u64>) -> usize {
    let stake = stake.copied().unwrap_or_default() / LAMPORTS_PER_SOL;
    let bucket = u64::BITS - stake.leading_zeros();
    (bucket as usize).min(NUM_PUSH_ACTIVE_SET_ENTRIES - 1)
}

