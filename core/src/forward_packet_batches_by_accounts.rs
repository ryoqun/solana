use {
    crate::immutable_deserialized_packet::ImmutableDeserializedPacket,
    solana_perf::packet::Packet,
    solana_runtime::{
        block_cost_limits,
        cost_model::CostModel,
        cost_tracker::{CostTracker, CostTrackerError},
    },
    solana_sdk::{feature_set::FeatureSet, transaction::SanitizedTransaction},
    std::sync::Arc,
};

/// `ForwardBatch` to have half of default cost_tracker limits, as smaller batch
/// allows better granularity in composing forwarding transactions; e.g.,
/// transactions in each batch are potentially more evenly distributed across accounts.
const FORWARDED_BLOCK_COMPUTE_RATIO: u32 = 2;
/// this number divided by`FORWARDED_BLOCK_COMPUTE_RATIO` is the total blocks to forward.
/// To accommodate transactions without `compute_budget` instruction, which will
/// have default 200_000 compute units, it has 100 batches as default to forward
/// up to 12_000 such transaction. (120 such transactions fill up a batch, 100
/// batches allows 12_000 transactions)
const DEFAULT_NUMBER_OF_BATCHES: u32 = 100;

/// `ForwardBatch` represents one forwardable batch of transactions with a
/// limited number of total compute units
#[derive(Debug)]
pub struct ForwardBatch {
    cost_tracker: CostTracker,
    // `forwardable_packets` keeps forwardable packets in a vector in its
    // original fee prioritized order
    forwardable_packets: Vec<Arc<ImmutableDeserializedPacket>>,
}

impl Default for ForwardBatch {
    /// default ForwardBatch has cost_tracker with default limits
    fn default() -> Self {
        Self::new(1)
    }
}

impl ForwardBatch {
    /// `ForwardBatch` keeps forwardable packets in a vector in its original fee prioritized order,
    /// Number of packets are limited by `cost_tracker` with customized `limit_ratio` to lower
    /// (when `limit_ratio` > 1) `cost_tracker`'s default limits.
    /// Lower limits yield smaller batch for forwarding.
    fn new(limit_ratio: u32) -> Self {
        let mut cost_tracker = CostTracker::default();
        cost_tracker.set_limits(
            block_cost_limits::MAX_WRITABLE_ACCOUNT_UNITS.saturating_div(limit_ratio as u64),
            block_cost_limits::MAX_BLOCK_UNITS.saturating_div(limit_ratio as u64),
            block_cost_limits::MAX_VOTE_UNITS.saturating_div(limit_ratio as u64),
        );
        Self {
            cost_tracker,
            forwardable_packets: Vec::default(),
        }
    }

    fn try_add(
        &mut self,
        sanitized_transaction: &SanitizedTransaction,
        immutable_packet: Arc<ImmutableDeserializedPacket>,
        feature_set: &FeatureSet,
    ) -> Result<u64, CostTrackerError> {
        let tx_cost = CostModel::calculate_cost(sanitized_transaction, feature_set);
        let res = self.cost_tracker.try_add(&tx_cost);
        if res.is_ok() {
            self.forwardable_packets.push(immutable_packet);
        }
        res
    }

    pub fn get_forwardable_packets(&self) -> impl Iterator<Item = &Packet> {
        self.forwardable_packets
            .iter()
            .map(|immutable_packet| immutable_packet.original_packet())
    }

    pub fn len(&self) -> usize {
        self.forwardable_packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forwardable_packets.is_empty()
    }
}

/// To avoid forward queue being saturated by transactions for single hot account,
/// the forwarder will group and send prioritized transactions by account limit
/// to allow transactions on non-congested accounts to be forwarded alongside higher fee
/// transactions that saturate those highly demanded accounts.
#[derive(Debug)]
pub struct ForwardPacketBatchesByAccounts {
    // Forwardable packets are staged in number of batches, each batch is limited
    // by cost_tracker on both account limit and block limits. Those limits are
    // set as `limit_ratio` of regular block limits to facilitate quicker iteration.
    forward_batches: Vec<ForwardBatch>,
}

impl ForwardPacketBatchesByAccounts {
    pub fn new_with_default_batch_limits() -> Self {
        Self::new(FORWARDED_BLOCK_COMPUTE_RATIO, DEFAULT_NUMBER_OF_BATCHES)
    }

    pub fn new(limit_ratio: u32, number_of_batches: u32) -> Self {
        let forward_batches = (0..number_of_batches)
            .map(|_| ForwardBatch::new(limit_ratio))
            .collect();
        Self { forward_batches }
    }

    /// packets are filled into first available 'batch' that have space to fit it.
    pub fn try_add_packet(
        &mut self,
        sanitized_transaction: &SanitizedTransaction,
        immutable_packet: Arc<ImmutableDeserializedPacket>,
        feature_set: &FeatureSet,
    ) -> bool {
        for forward_batch in self.forward_batches.iter_mut() {
            if forward_batch
                .try_add(sanitized_transaction, immutable_packet.clone(), feature_set)
                .is_ok()
            {
                return true;
            }
        }
        false
    }

    pub fn iter_batches(&self) -> impl Iterator<Item = &ForwardBatch> {
        self.forward_batches.iter()
    }
}
