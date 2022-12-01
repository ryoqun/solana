use {
    crate::unprocessed_packet_batches::{self, ImmutableDeserializedPacket},
    solana_perf::packet::Packet,
    solana_runtime::{
        bank::Bank,
        block_cost_limits,
        cost_tracker::{CostTracker, CostTrackerError},
    },
    solana_sdk::pubkey::Pubkey,
    std::{rc::Rc, sync::Arc},
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
    forwardable_packets: Vec<Rc<ImmutableDeserializedPacket>>,
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
        write_lock_accounts: &[Pubkey],
        compute_units: u64,
        immutable_packet: Rc<ImmutableDeserializedPacket>,
    ) -> Result<u64, CostTrackerError> {
        let res = self.cost_tracker.try_add_requested_cus(
            write_lock_accounts,
            compute_units,
            immutable_packet.is_simple_vote(),
        );

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
    // Need a `bank` to load all accounts for VersionedTransaction. Currently
    // using current rooted bank for it.
    current_bank: Arc<Bank>,
    // Forwardable packets are staged in number of batches, each batch is limited
    // by cost_tracker on both account limit and block limits. Those limits are
    // set as `limit_ratio` of regular block limits to facilitate quicker iteration.
    forward_batches: Vec<ForwardBatch>,
}

impl ForwardPacketBatchesByAccounts {
    pub fn new_with_default_batch_limits(current_bank: Arc<Bank>) -> Self {
        Self::new(
            current_bank,
            FORWARDED_BLOCK_COMPUTE_RATIO,
            DEFAULT_NUMBER_OF_BATCHES,
        )
    }

    pub fn new(current_bank: Arc<Bank>, limit_ratio: u32, number_of_batches: u32) -> Self {
        let forward_batches = (0..number_of_batches)
            .map(|_| ForwardBatch::new(limit_ratio))
            .collect();
        Self {
            current_bank,
            forward_batches,
        }
    }

    pub fn add_packet(&mut self, packet: Rc<ImmutableDeserializedPacket>) -> bool {
        // do not forward packet that cannot be sanitized
        if let Some(sanitized_transaction) =
            unprocessed_packet_batches::transaction_from_deserialized_packet(
                &packet,
                &self.current_bank.feature_set,
                self.current_bank.vote_only_bank(),
                self.current_bank.as_ref(),
            )
        {
            // get write_lock_accounts
            let message = sanitized_transaction.message();
            let write_lock_accounts: Vec<_> = message
                .account_keys()
                .iter()
                .enumerate()
                .filter_map(|(i, account_key)| {
                    if message.is_writable(i) {
                        Some(*account_key)
                    } else {
                        None
                    }
                })
                .collect();

            // get requested CUs
            let requested_cu = packet.compute_unit_limit();

            // try to fill into forward batches
            self.add_packet_to_batches(&write_lock_accounts, requested_cu, packet)
        } else {
            false
        }
    }

    pub fn iter_batches(&self) -> impl Iterator<Item = &ForwardBatch> {
        self.forward_batches.iter()
    }

    /// transaction will try to be filled into 'batches', if can't fit into first batch
    /// due to cost_tracker (eg., exceeding account limit or block limit), it will try
    /// next batch until either being added to one of 'bucket' or not being forwarded.
    fn add_packet_to_batches(
        &mut self,
        write_lock_accounts: &[Pubkey],
        compute_units: u64,
        immutable_packet: Rc<ImmutableDeserializedPacket>,
    ) -> bool {
        for forward_batch in self.forward_batches.iter_mut() {
            if forward_batch
                .try_add(write_lock_accounts, compute_units, immutable_packet.clone())
                .is_ok()
            {
                return true;
            }
        }
        false
    }
}
