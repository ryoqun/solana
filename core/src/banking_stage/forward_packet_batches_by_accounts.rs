use {
    super::immutable_deserialized_packet::ImmutableDeserializedPacket,
    solana_cost_model::{
        block_cost_limits,
        cost_model::CostModel,
        cost_tracker::{CostTracker, UpdatedCosts},
        transaction_cost::TransactionCost,
    },
    solana_perf::packet::Packet,
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
#[derive(Debug, Default)]
pub struct ForwardBatch {
    // `forwardable_packets` keeps forwardable packets in a vector in its
    // original fee prioritized order
    forwardable_packets: Vec<Arc<ImmutableDeserializedPacket>>,
}

impl ForwardBatch {
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

    pub fn reset(&mut self) {
        self.forwardable_packets.clear();
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

    // Single cost tracker that imposes the total cu limits for forwarding.
    cost_tracker: CostTracker,

    // Compute Unit limits for each batch
    batch_vote_limit: u64,
    batch_block_limit: u64,
    batch_account_limit: u64,
}

impl ForwardPacketBatchesByAccounts {
    pub fn new_with_default_batch_limits() -> Self {
        Self::new(FORWARDED_BLOCK_COMPUTE_RATIO, DEFAULT_NUMBER_OF_BATCHES)
    }

    pub fn new(limit_ratio: u32, number_of_batches: u32) -> Self {
        let forward_batches = (0..number_of_batches)
            .map(|_| ForwardBatch::default())
            .collect();

        let batch_vote_limit = block_cost_limits::MAX_VOTE_UNITS.saturating_div(limit_ratio as u64);
        let batch_block_limit =
            block_cost_limits::MAX_BLOCK_UNITS.saturating_div(limit_ratio as u64);
        let batch_account_limit =
            block_cost_limits::MAX_WRITABLE_ACCOUNT_UNITS.saturating_div(limit_ratio as u64);

        let mut cost_tracker = CostTracker::default();
        cost_tracker.set_limits(
            batch_account_limit.saturating_mul(number_of_batches as u64),
            batch_block_limit.saturating_mul(number_of_batches as u64),
            batch_vote_limit.saturating_mul(number_of_batches as u64),
        );
        Self {
            forward_batches,
            cost_tracker,
            batch_vote_limit,
            batch_block_limit,
            batch_account_limit,
        }
    }

    pub fn try_add_packet(
        &mut self,
        sanitized_transaction: &SanitizedTransaction,
        immutable_packet: Arc<ImmutableDeserializedPacket>,
        feature_set: &FeatureSet,
    ) -> bool {
        let tx_cost = CostModel::calculate_cost(sanitized_transaction, feature_set);

        if let Ok(updated_costs) = self.cost_tracker.try_add(&tx_cost) {
            let batch_index = self.get_batch_index_by_updated_costs(&tx_cost, &updated_costs);

            if let Some(forward_batch) = self.forward_batches.get_mut(batch_index) {
                forward_batch.forwardable_packets.push(immutable_packet);
            } else {
                // A successfully added tx_cost means it does not exceed block limit, nor vote
                // limit, nor account limit. batch_index calculated as quotient from division
                // will not be out of bounds.
                unreachable!("batch_index out of bounds");
            }
            true
        } else {
            false
        }
    }

    pub fn iter_batches(&self) -> impl Iterator<Item = &ForwardBatch> {
        self.forward_batches.iter()
    }

    pub fn reset(&mut self) {
        for forward_batch in self.forward_batches.iter_mut() {
            forward_batch.reset();
        }

        self.cost_tracker.reset();
    }

    // Successfully added packet should be placed into the batch where no block/vote/account limits
    // would be exceeded. Eg, if by block limit, it can be put into batch #1; by vote limit, it can
    // be put into batch #2; and by account limit, it can be put into batch #3; then it should be
    // put into batch #3 to satisfy all batch limits.
    fn get_batch_index_by_updated_costs(
        &self,
        tx_cost: &TransactionCost,
        updated_costs: &UpdatedCosts,
    ) -> usize {
        let Some(batch_index_by_block_limit) =
            updated_costs.updated_block_cost.checked_div(match tx_cost {
                TransactionCost::SimpleVote { .. } => self.batch_vote_limit,
                TransactionCost::Transaction(_) => self.batch_block_limit,
            })
        else {
            unreachable!("batch vote limit or block limit must not be zero")
        };

        let batch_index_by_account_limit =
            updated_costs.updated_costliest_account_cost / self.batch_account_limit;

        batch_index_by_block_limit.max(batch_index_by_account_limit) as usize
    }
}
