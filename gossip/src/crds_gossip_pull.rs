//! Crds Gossip Pull overlay.
//!
//! This module implements the anti-entropy protocol for the network.
//!
//! The basic strategy is as follows:
//!
//! 1. Construct a bloom filter of the local data set
//! 2. Randomly ask a node on the network for data that is not contained in the bloom filter.
//!
//! Bloom filters have a false positive rate.  Each requests uses a different bloom filter
//! with random hash functions.  So each subsequent request will have a different distribution
//! of false positives.

use {
    crate::{
        cluster_info::{Ping, CRDS_UNIQUE_PUBKEY_CAPACITY},
        cluster_info_metrics::GossipStats,
        contact_info::ContactInfo,
        crds::{Crds, GossipRoute, VersionedCrdsValue},
        crds_gossip::{get_stake, get_weight},
        crds_gossip_error::CrdsGossipError,
        crds_value::CrdsValue,
        ping_pong::PingCache,
    },
    itertools::Itertools,
    lru::LruCache,
    rand::{
        distributions::{Distribution, WeightedIndex},
        Rng,
    },
    rayon::{prelude::*, ThreadPool},
    solana_bloom::bloom::{AtomicBloom, Bloom},
    solana_sdk::{
        hash::{hash, Hash},
        pubkey::Pubkey,
        signature::{Keypair, Signer},
    },
    solana_streamer::socket::SocketAddrSpace,
    std::{
        collections::{HashMap, HashSet, VecDeque},
        convert::TryInto,
        iter::{repeat, repeat_with},
        net::SocketAddr,
        sync::{
            atomic::{AtomicI64, AtomicUsize, Ordering},
            Mutex, RwLock,
        },
        time::{Duration, Instant},
    },
};

pub const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;
// The maximum age of a value received over pull responses
pub const CRDS_GOSSIP_PULL_MSG_TIMEOUT_MS: u64 = 60000;
// Retention period of hashes of received outdated values.
const FAILED_INSERTS_RETENTION_MS: u64 = 20_000;
// Do not pull from peers which have not been updated for this long.
const PULL_ACTIVE_TIMEOUT_MS: u64 = 60_000;
pub const FALSE_RATE: f64 = 0.1f64;
pub const KEYS: f64 = 8f64;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, AbiExample)]
pub struct CrdsFilter {
    pub filter: Bloom<Hash>,
    mask: u64,
    mask_bits: u32,
}

impl Default for CrdsFilter {
    fn default() -> Self {
        CrdsFilter {
            filter: Bloom::default(),
            mask: !0u64,
            mask_bits: 0u32,
        }
    }
}

impl solana_sdk::sanitize::Sanitize for CrdsFilter {
    fn sanitize(&self) -> std::result::Result<(), solana_sdk::sanitize::SanitizeError> {
        self.filter.sanitize()?;
        Ok(())
    }
}

impl CrdsFilter {
    fn compute_mask(seed: u64, mask_bits: u32) -> u64 {
        assert!(seed <= 2u64.pow(mask_bits));
        let seed: u64 = seed.checked_shl(64 - mask_bits).unwrap_or(0x0);
        seed | (!0u64).checked_shr(mask_bits).unwrap_or(!0x0)
    }
    fn max_items(max_bits: f64, false_rate: f64, num_keys: f64) -> f64 {
        let m = max_bits;
        let p = false_rate;
        let k = num_keys;
        (m / (-k / (1f64 - (p.ln() / k).exp()).ln())).ceil()
    }
    fn mask_bits(num_items: f64, max_items: f64) -> u32 {
        // for small ratios this can result in a negative number, ensure it returns 0 instead
        ((num_items / max_items).log2().ceil()).max(0.0) as u32
    }
    pub fn hash_as_u64(item: &Hash) -> u64 {
        let buf = item.as_ref()[..8].try_into().unwrap();
        u64::from_le_bytes(buf)
    }
    fn test_mask(&self, item: &Hash) -> bool {
        // only consider the highest mask_bits bits from the hash and set the rest to 1.
        let ones = (!0u64).checked_shr(self.mask_bits).unwrap_or(!0u64);
        let bits = Self::hash_as_u64(item) | ones;
        bits == self.mask
    }
    fn filter_contains(&self, item: &Hash) -> bool {
        self.filter.contains(item)
    }
}

/// A vector of crds filters that together hold a complete set of Hashes.
struct CrdsFilterSet {
    filters: Vec<AtomicBloom<Hash>>,
    mask_bits: u32,
}

impl CrdsFilterSet {
    fn new(num_items: usize, max_bytes: usize) -> Self {
        let max_bits = (max_bytes * 8) as f64;
        let max_items = CrdsFilter::max_items(max_bits, FALSE_RATE, KEYS);
        let mask_bits = CrdsFilter::mask_bits(num_items as f64, max_items);
        let filters =
            repeat_with(|| Bloom::random(max_items as usize, FALSE_RATE, max_bits as usize).into())
                .take(1 << mask_bits)
                .collect();
        Self { filters, mask_bits }
    }

    fn add(&self, hash_value: Hash) {
        let index = CrdsFilter::hash_as_u64(&hash_value)
            .checked_shr(64 - self.mask_bits)
            .unwrap_or(0);
        self.filters[index as usize].add(&hash_value);
    }
}

impl From<CrdsFilterSet> for Vec<CrdsFilter> {
    fn from(cfs: CrdsFilterSet) -> Self {
        let mask_bits = cfs.mask_bits;
        cfs.filters
            .into_iter()
            .enumerate()
            .map(|(seed, filter)| CrdsFilter {
                filter: filter.into(),
                mask: CrdsFilter::compute_mask(seed as u64, mask_bits),
                mask_bits,
            })
            .collect()
    }
}

#[derive(Default)]
pub struct ProcessPullStats {
    pub success: usize,
    pub failed_insert: usize,
    pub failed_timeout: usize,
    pub timeout_count: usize,
}

pub struct CrdsGossipPull {
    /// Timestamp of last request
    pull_request_time: RwLock<LruCache<Pubkey, /*timestamp:*/ u64>>,
    // Hash value and record time (ms) of the pull responses which failed to be
    // inserted in crds table; Preserved to stop the sender to send back the
    // same outdated payload again by adding them to the filter for the next
    // pull request.
    failed_inserts: RwLock<VecDeque<(Hash, /*timestamp:*/ u64)>>,
    pub crds_timeout: u64,
    msg_timeout: u64,
    pub num_pulls: AtomicUsize,
}

impl Default for CrdsGossipPull {
    fn default() -> Self {
        Self {
            pull_request_time: RwLock::new(LruCache::new(CRDS_UNIQUE_PUBKEY_CAPACITY)),
            failed_inserts: RwLock::default(),
            crds_timeout: CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS,
            msg_timeout: CRDS_GOSSIP_PULL_MSG_TIMEOUT_MS,
            num_pulls: AtomicUsize::default(),
        }
    }
}
impl CrdsGossipPull {
    /// Generate a random request
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_pull_request(
        &self,
        thread_pool: &ThreadPool,
        crds: &RwLock<Crds>,
        self_keypair: &Keypair,
        self_shred_version: u16,
        now: u64,
        gossip_validators: Option<&HashSet<Pubkey>>,
        stakes: &HashMap<Pubkey, u64>,
        bloom_size: usize,
        ping_cache: &Mutex<PingCache>,
        pings: &mut Vec<(SocketAddr, Ping)>,
        socket_addr_space: &SocketAddrSpace,
    ) -> Result<HashMap<ContactInfo, Vec<CrdsFilter>>, CrdsGossipError> {
        // Gossip peers and respective sampling weights.
        let peers = self.pull_options(
            crds,
            &self_keypair.pubkey(),
            self_shred_version,
            now,
            gossip_validators,
            stakes,
            socket_addr_space,
        );
        // Check for nodes which have responded to ping messages.
        let mut rng = rand::thread_rng();
        let (weights, peers): (Vec<_>, Vec<_>) = {
            let mut ping_cache = ping_cache.lock().unwrap();
            let mut pingf = move || Ping::new_rand(&mut rng, self_keypair).ok();
            let now = Instant::now();
            peers
                .into_iter()
                .filter_map(|(weight, peer)| {
                    let node = (peer.id, peer.gossip);
                    let (check, ping) = ping_cache.check(now, node, &mut pingf);
                    if let Some(ping) = ping {
                        pings.push((peer.gossip, ping));
                    }
                    check.then_some((weight, peer))
                })
                .unzip()
        };
        if peers.is_empty() {
            return Err(CrdsGossipError::NoPeers);
        }
        // Associate each pull-request filter with a randomly selected peer.
        let filters = self.build_crds_filters(thread_pool, crds, bloom_size);
        let dist = WeightedIndex::new(&weights).unwrap();
        let peers = repeat_with(|| peers[dist.sample(&mut rng)].clone());
        Ok(peers.zip(filters).into_group_map())
    }

    fn pull_options(
        &self,
        crds: &RwLock<Crds>,
        self_id: &Pubkey,
        self_shred_version: u16,
        now: u64,
        gossip_validators: Option<&HashSet<Pubkey>>,
        stakes: &HashMap<Pubkey, u64>,
        socket_addr_space: &SocketAddrSpace,
    ) -> Vec<(/*weight:*/ u64, ContactInfo)> {
        let mut rng = rand::thread_rng();
        let active_cutoff = now.saturating_sub(PULL_ACTIVE_TIMEOUT_MS);
        let pull_request_time = self.pull_request_time.read().unwrap();
        // crds should be locked last after self.pull_request_time.
        let crds = crds.read().unwrap();
        crds.get_nodes()
            .filter_map(|value| {
                let info = value.value.contact_info().unwrap();
                // Stop pulling from nodes which have not been active recently.
                if value.local_timestamp < active_cutoff {
                    // In order to mitigate eclipse attack, for staked nodes
                    // continue retrying periodically.
                    let stake = stakes.get(&info.id).unwrap_or(&0);
                    if *stake == 0 || !rng.gen_ratio(1, 16) {
                        return None;
                    }
                }
                Some(info)
            })
            .filter(|v| {
                v.id != *self_id
                    && ContactInfo::is_valid_address(&v.gossip, socket_addr_space)
                    && (self_shred_version == 0 || self_shred_version == v.shred_version)
                    && gossip_validators
                        .map_or(true, |gossip_validators| gossip_validators.contains(&v.id))
            })
            .map(|item| {
                let max_weight = f32::from(u16::max_value()) - 1.0;
                let req_time: u64 = pull_request_time
                    .peek(&item.id)
                    .copied()
                    .unwrap_or_default();
                let since = (now.saturating_sub(req_time).min(3600 * 1000) / 1024) as u32;
                let stake = get_stake(&item.id, stakes);
                let weight = get_weight(max_weight, since, stake);
                // Weights are bounded by max_weight defined above.
                // So this type-cast should be safe.
                ((weight * 100.0) as u64, item.clone())
            })
            .collect()
    }

    /// Time when a request to `from` was initiated.
    ///
    /// This is used for weighted random selection during `new_pull_request`
    /// It's important to use the local nodes request creation time as the weight
    /// instead of the response received time otherwise failed nodes will increase their weight.
    pub(crate) fn mark_pull_request_creation_time(&self, from: Pubkey, now: u64) {
        self.pull_request_time.write().unwrap().put(from, now);
    }

    /// Process a pull request
    pub(crate) fn process_pull_requests<I>(crds: &RwLock<Crds>, callers: I, now: u64)
    where
        I: IntoIterator<Item = CrdsValue>,
    {
        let mut crds = crds.write().unwrap();
        for caller in callers {
            let key = caller.pubkey();
            let _ = crds.insert(caller, now, GossipRoute::PullRequest);
            crds.update_record_timestamp(&key, now);
        }
    }

    /// Create gossip responses to pull requests
    pub(crate) fn generate_pull_responses(
        thread_pool: &ThreadPool,
        crds: &RwLock<Crds>,
        requests: &[(CrdsValue, CrdsFilter)],
        output_size_limit: usize, // Limit number of crds values returned.
        now: u64,
        stats: &GossipStats,
    ) -> Vec<Vec<CrdsValue>> {
        Self::filter_crds_values(thread_pool, crds, requests, output_size_limit, now, stats)
    }

    // Checks if responses should be inserted and
    // returns those responses converted to VersionedCrdsValue
    // Separated in three vecs as:
    //  .0 => responses that update the owner timestamp
    //  .1 => responses that do not update the owner timestamp
    //  .2 => hash value of outdated values which will fail to insert.
    pub(crate) fn filter_pull_responses(
        &self,
        crds: &RwLock<Crds>,
        timeouts: &HashMap<Pubkey, u64>,
        responses: Vec<CrdsValue>,
        now: u64,
        stats: &mut ProcessPullStats,
    ) -> (Vec<CrdsValue>, Vec<CrdsValue>, Vec<Hash>) {
        let mut active_values = vec![];
        let mut expired_values = vec![];
        let default_timeout = timeouts
            .get(&Pubkey::default())
            .copied()
            .unwrap_or(self.msg_timeout);
        let crds = crds.read().unwrap();
        let upsert = |response: CrdsValue| {
            let owner = response.label().pubkey();
            // Check if the crds value is older than the msg_timeout
            let timeout = timeouts.get(&owner).copied().unwrap_or(default_timeout);
            // Before discarding this value, check if a ContactInfo for the
            // owner exists in the table. If it doesn't, that implies that this
            // value can be discarded
            if !crds.upserts(&response) {
                Some(response)
            } else if now <= response.wallclock().saturating_add(timeout) {
                active_values.push(response);
                None
            } else if crds.get::<&ContactInfo>(owner).is_some() {
                // Silently insert this old value without bumping record
                // timestamps
                expired_values.push(response);
                None
            } else {
                stats.timeout_count += 1;
                stats.failed_timeout += 1;
                Some(response)
            }
        };
        let failed_inserts = responses
            .into_iter()
            .filter_map(upsert)
            .map(|resp| hash(&bincode::serialize(&resp).unwrap()))
            .collect();
        (active_values, expired_values, failed_inserts)
    }

    /// Process a vec of pull responses
    pub(crate) fn process_pull_responses(
        &self,
        crds: &RwLock<Crds>,
        from: &Pubkey,
        responses: Vec<CrdsValue>,
        responses_expired_timeout: Vec<CrdsValue>,
        failed_inserts: Vec<Hash>,
        now: u64,
        stats: &mut ProcessPullStats,
    ) {
        let mut owners = HashSet::new();
        let mut crds = crds.write().unwrap();
        for response in responses_expired_timeout {
            let _ = crds.insert(response, now, GossipRoute::PullResponse);
        }
        let mut num_inserts = 0;
        for response in responses {
            let owner = response.pubkey();
            if let Ok(()) = crds.insert(response, now, GossipRoute::PullResponse) {
                num_inserts += 1;
                owners.insert(owner);
            }
        }
        stats.success += num_inserts;
        self.num_pulls.fetch_add(num_inserts, Ordering::Relaxed);
        owners.insert(*from);
        for owner in owners {
            crds.update_record_timestamp(&owner, now);
        }
        drop(crds);
        stats.failed_insert += failed_inserts.len();
        self.purge_failed_inserts(now);
        let failed_inserts = failed_inserts.into_iter().zip(repeat(now));
        self.failed_inserts.write().unwrap().extend(failed_inserts);
    }

    pub(crate) fn purge_failed_inserts(&self, now: u64) {
        if FAILED_INSERTS_RETENTION_MS < now {
            let cutoff = now - FAILED_INSERTS_RETENTION_MS;
            let mut failed_inserts = self.failed_inserts.write().unwrap();
            let outdated = failed_inserts
                .iter()
                .take_while(|(_, ts)| *ts < cutoff)
                .count();
            failed_inserts.drain(..outdated);
        }
    }

    pub(crate) fn failed_inserts_size(&self) -> usize {
        self.failed_inserts.read().unwrap().len()
    }

    // build a set of filters of the current crds table
    // num_filters - used to increase the likelihood of a value in crds being added to some filter
    pub fn build_crds_filters(
        &self,
        thread_pool: &ThreadPool,
        crds: &RwLock<Crds>,
        bloom_size: usize,
    ) -> Vec<CrdsFilter> {
        const PAR_MIN_LENGTH: usize = 512;
        #[cfg(debug_assertions)]
        const MIN_NUM_BLOOM_ITEMS: usize = 512;
        #[cfg(not(debug_assertions))]
        const MIN_NUM_BLOOM_ITEMS: usize = 65_536;
        let failed_inserts = self.failed_inserts.read().unwrap();
        // crds should be locked last after self.failed_inserts.
        let crds = crds.read().unwrap();
        let num_items = crds.len() + crds.num_purged() + failed_inserts.len();
        let num_items = MIN_NUM_BLOOM_ITEMS.max(num_items);
        let filters = CrdsFilterSet::new(num_items, bloom_size);
        thread_pool.install(|| {
            crds.par_values()
                .with_min_len(PAR_MIN_LENGTH)
                .map(|v| v.value_hash)
                .chain(crds.purged().with_min_len(PAR_MIN_LENGTH))
                .chain(
                    failed_inserts
                        .par_iter()
                        .with_min_len(PAR_MIN_LENGTH)
                        .map(|(v, _)| *v),
                )
                .for_each(|v| filters.add(v));
        });
        drop(crds);
        drop(failed_inserts);
        filters.into()
    }

    /// Filter values that fail the bloom filter up to `max_bytes`.
    fn filter_crds_values(
        thread_pool: &ThreadPool,
        crds: &RwLock<Crds>,
        filters: &[(CrdsValue, CrdsFilter)],
        output_size_limit: usize, // Limit number of crds values returned.
        now: u64,
        stats: &GossipStats,
    ) -> Vec<Vec<CrdsValue>> {
        let msg_timeout = CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS;
        let jitter = rand::thread_rng().gen_range(0, msg_timeout / 4);
        //skip filters from callers that are too old
        let caller_wallclock_window =
            now.saturating_sub(msg_timeout)..now.saturating_add(msg_timeout);
        let dropped_requests = AtomicUsize::default();
        let total_skipped = AtomicUsize::default();
        let output_size_limit = output_size_limit.try_into().unwrap_or(i64::MAX);
        let output_size_limit = AtomicI64::new(output_size_limit);
        let crds = crds.read().unwrap();
        let apply_filter = |caller: &CrdsValue, filter: &CrdsFilter| {
            if output_size_limit.load(Ordering::Relaxed) <= 0 {
                return Vec::default();
            }
            let caller_wallclock = caller.wallclock();
            if !caller_wallclock_window.contains(&caller_wallclock) {
                dropped_requests.fetch_add(1, Ordering::Relaxed);
                return Vec::default();
            }
            let caller_wallclock = caller_wallclock.checked_add(jitter).unwrap_or(0);
            let pred = |entry: &&VersionedCrdsValue| {
                debug_assert!(filter.test_mask(&entry.value_hash));
                // Skip values that are too new.
                if entry.value.wallclock() > caller_wallclock {
                    total_skipped.fetch_add(1, Ordering::Relaxed);
                    false
                } else {
                    !filter.filter_contains(&entry.value_hash)
                }
            };
            let out: Vec<_> = crds
                .filter_bitmask(filter.mask, filter.mask_bits)
                .filter(pred)
                .map(|entry| entry.value.clone())
                .take(output_size_limit.load(Ordering::Relaxed).max(0) as usize)
                .collect();
            output_size_limit.fetch_sub(out.len() as i64, Ordering::Relaxed);
            out
        };
        let ret: Vec<_> = thread_pool.install(|| {
            filters
                .par_iter()
                .map(|(caller, filter)| apply_filter(caller, filter))
                .collect()
        });
        stats
            .filter_crds_values_dropped_requests
            .add_relaxed(dropped_requests.into_inner() as u64);
        stats
            .filter_crds_values_dropped_values
            .add_relaxed(total_skipped.into_inner() as u64);
        ret
    }

    pub(crate) fn make_timeouts(
        &self,
        self_pubkey: Pubkey,
        stakes: &HashMap<Pubkey, u64>,
        epoch_duration: Duration,
    ) -> HashMap<Pubkey, u64> {
        let extended_timeout = self.crds_timeout.max(epoch_duration.as_millis() as u64);
        let default_timeout = if stakes.values().all(|stake| *stake == 0) {
            extended_timeout
        } else {
            self.crds_timeout
        };
        stakes
            .iter()
            .filter(|(_, stake)| **stake > 0)
            .map(|(pubkey, _)| (*pubkey, extended_timeout))
            .chain(vec![
                (Pubkey::default(), default_timeout),
                (self_pubkey, u64::MAX),
            ])
            .collect()
    }

    /// Purge values from the crds that are older then `active_timeout`
    pub(crate) fn purge_active(
        thread_pool: &ThreadPool,
        crds: &RwLock<Crds>,
        now: u64,
        timeouts: &HashMap<Pubkey, u64>,
    ) -> usize {
        let mut crds = crds.write().unwrap();
        let labels = crds.find_old_labels(thread_pool, now, timeouts);
        for label in &labels {
            crds.remove(label, now);
        }
        labels.len()
    }

    /// For legacy tests

    // Only for tests and simulations.
    pub(crate) fn mock_clone(&self) -> Self {
        let pull_request_time = {
            let pull_request_time = self.pull_request_time.read().unwrap();
            let mut clone = LruCache::new(pull_request_time.cap());
            for (k, v) in pull_request_time.iter().rev() {
                clone.put(*k, *v);
            }
            clone
        };
        let failed_inserts = self.failed_inserts.read().unwrap().clone();
        Self {
            pull_request_time: RwLock::new(pull_request_time),
            failed_inserts: RwLock::new(failed_inserts),
            num_pulls: AtomicUsize::new(self.num_pulls.load(Ordering::Relaxed)),
            ..*self
        }
    }
}
