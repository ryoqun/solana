use {
    crate::{
        banking_stage::{BankingStageStats, FilterForwardingResults, ForwardOption},
        forward_packet_batches_by_accounts::ForwardPacketBatchesByAccounts,
        immutable_deserialized_packet::ImmutableDeserializedPacket,
        latest_unprocessed_votes::{
            LatestUnprocessedVotes, LatestValidatorVotePacket, VoteBatchInsertionMetrics,
            VoteSource,
        },
        leader_slot_banking_stage_metrics::LeaderSlotMetricsTracker,
        multi_iterator_scanner::{MultiIteratorScanner, ProcessingDecision},
        read_write_account_set::ReadWriteAccountSet,
        unprocessed_packet_batches::{
            DeserializedPacket, PacketBatchInsertionMetrics, UnprocessedPacketBatches,
        },
    },
    itertools::Itertools,
    min_max_heap::MinMaxHeap,
    solana_measure::measure,
    solana_runtime::bank::Bank,
    solana_sdk::{
        clock::FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET, feature_set::FeatureSet, hash::Hash,
        saturating_add_assign, transaction::SanitizedTransaction,
    },
    std::{
        collections::HashMap,
        sync::{atomic::Ordering, Arc},
    },
};

// Step-size set to be 64, equal to the maximum batch/entry size. With the
// multi-iterator change, there's no point in getting larger batches of
// non-conflicting transactions.
pub const UNPROCESSED_BUFFER_STEP_SIZE: usize = 64;
/// Maximum numer of votes a single receive call will accept
const MAX_NUM_VOTES_RECEIVE: usize = 10_000;

#[derive(Debug)]
pub enum UnprocessedTransactionStorage {
    VoteStorage(VoteStorage),
    LocalTransactionStorage(ThreadLocalUnprocessedPackets),
}

#[derive(Debug)]
pub struct ThreadLocalUnprocessedPackets {
    unprocessed_packet_batches: UnprocessedPacketBatches,
    thread_type: ThreadType,
}

#[derive(Debug)]
pub struct VoteStorage {
    latest_unprocessed_votes: Arc<LatestUnprocessedVotes>,
    vote_source: VoteSource,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ThreadType {
    Voting(VoteSource),
    Transactions,
}

#[derive(Debug)]
pub(crate) enum InsertPacketBatchSummary {
    VoteBatchInsertionMetrics(VoteBatchInsertionMetrics),
    PacketBatchInsertionMetrics(PacketBatchInsertionMetrics),
}

impl InsertPacketBatchSummary {
    pub fn total_dropped_packets(&self) -> usize {
        match self {
            Self::VoteBatchInsertionMetrics(metrics) => {
                metrics.num_dropped_gossip + metrics.num_dropped_tpu
            }
            Self::PacketBatchInsertionMetrics(metrics) => metrics.num_dropped_packets,
        }
    }

    pub fn dropped_gossip_packets(&self) -> usize {
        match self {
            Self::VoteBatchInsertionMetrics(metrics) => metrics.num_dropped_gossip,
            _ => 0,
        }
    }

    pub fn dropped_tpu_packets(&self) -> usize {
        match self {
            Self::VoteBatchInsertionMetrics(metrics) => metrics.num_dropped_tpu,
            _ => 0,
        }
    }

    pub fn dropped_tracer_packets(&self) -> usize {
        match self {
            Self::PacketBatchInsertionMetrics(metrics) => metrics.num_dropped_tracer_packets,
            _ => 0,
        }
    }
}

impl From<VoteBatchInsertionMetrics> for InsertPacketBatchSummary {
    fn from(metrics: VoteBatchInsertionMetrics) -> Self {
        Self::VoteBatchInsertionMetrics(metrics)
    }
}

impl From<PacketBatchInsertionMetrics> for InsertPacketBatchSummary {
    fn from(metrics: PacketBatchInsertionMetrics) -> Self {
        Self::PacketBatchInsertionMetrics(metrics)
    }
}

fn filter_processed_packets<'a, F>(
    retryable_transaction_indexes: impl Iterator<Item = &'a usize>,
    mut f: F,
) where
    F: FnMut(usize, usize),
{
    let mut prev_retryable_index = 0;
    for (i, retryable_index) in retryable_transaction_indexes.enumerate() {
        let start = if i == 0 { 0 } else { prev_retryable_index + 1 };

        let end = *retryable_index;
        prev_retryable_index = *retryable_index;

        if start < end {
            f(start, end)
        }
    }
}

/// Convenient wrapper for shared-state between banking stage processing and the
/// multi-iterator checking function.
pub struct ConsumeScannerPayload<'a> {
    pub reached_end_of_slot: bool,
    pub account_locks: ReadWriteAccountSet,
    pub sanitized_transactions: Vec<SanitizedTransaction>,
    pub slot_metrics_tracker: &'a mut LeaderSlotMetricsTracker,
    pub message_hash_to_transaction: &'a mut HashMap<Hash, DeserializedPacket>,
}

fn consume_scan_should_process_packet(
    bank: &Bank,
    banking_stage_stats: &BankingStageStats,
    packet: &ImmutableDeserializedPacket,
    payload: &mut ConsumeScannerPayload,
) -> ProcessingDecision {
    // If end of the slot, return should process (quick loop after reached end of slot)
    if payload.reached_end_of_slot {
        return ProcessingDecision::Now;
    }

    // Before sanitization, let's quickly check the static keys (performance optimization)
    let message = &packet.transaction().get_message().message;
    if !payload.account_locks.check_static_account_locks(message) {
        return ProcessingDecision::Later;
    }

    // Try to deserialize the packet
    let (maybe_sanitized_transaction, sanitization_time) = measure!(
        packet.build_sanitized_transaction(&bank.feature_set, bank.vote_only_bank(), bank)
    );

    let sanitization_time_us = sanitization_time.as_us();
    payload
        .slot_metrics_tracker
        .increment_transactions_from_packets_us(sanitization_time_us);
    banking_stage_stats
        .packet_conversion_elapsed
        .fetch_add(sanitization_time_us, Ordering::Relaxed);

    if let Some(sanitized_transaction) = maybe_sanitized_transaction {
        let message = sanitized_transaction.message();

        // Check the number of locks and whether there are duplicates
        if SanitizedTransaction::validate_account_locks(
            message,
            bank.get_transaction_account_lock_limit(),
        )
        .is_err()
        {
            payload
                .message_hash_to_transaction
                .remove(packet.message_hash());
            ProcessingDecision::Never
        } else if payload.account_locks.try_locking(message) {
            payload.sanitized_transactions.push(sanitized_transaction);
            ProcessingDecision::Now
        } else {
            ProcessingDecision::Later
        }
    } else {
        payload
            .message_hash_to_transaction
            .remove(packet.message_hash());
        ProcessingDecision::Never
    }
}

fn create_consume_multi_iterator<'a, 'b, F>(
    packets: &'a [Arc<ImmutableDeserializedPacket>],
    slot_metrics_tracker: &'b mut LeaderSlotMetricsTracker,
    message_hash_to_transaction: &'b mut HashMap<Hash, DeserializedPacket>,
    should_process_packet: F,
) -> MultiIteratorScanner<'a, Arc<ImmutableDeserializedPacket>, ConsumeScannerPayload<'b>, F>
where
    F: FnMut(
        &Arc<ImmutableDeserializedPacket>,
        &mut ConsumeScannerPayload<'b>,
    ) -> ProcessingDecision,
    'b: 'a,
{
    let payload = ConsumeScannerPayload {
        reached_end_of_slot: false,
        account_locks: ReadWriteAccountSet::default(),
        sanitized_transactions: Vec::with_capacity(UNPROCESSED_BUFFER_STEP_SIZE),
        slot_metrics_tracker,
        message_hash_to_transaction,
    };
    MultiIteratorScanner::new(
        packets,
        UNPROCESSED_BUFFER_STEP_SIZE,
        payload,
        should_process_packet,
    )
}

impl UnprocessedTransactionStorage {
    pub fn new_transaction_storage(
        unprocessed_packet_batches: UnprocessedPacketBatches,
        thread_type: ThreadType,
    ) -> Self {
        Self::LocalTransactionStorage(ThreadLocalUnprocessedPackets {
            unprocessed_packet_batches,
            thread_type,
        })
    }

    pub fn new_vote_storage(
        latest_unprocessed_votes: Arc<LatestUnprocessedVotes>,
        vote_source: VoteSource,
    ) -> Self {
        Self::VoteStorage(VoteStorage {
            latest_unprocessed_votes,
            vote_source,
        })
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::VoteStorage(vote_storage) => vote_storage.is_empty(),
            Self::LocalTransactionStorage(transaction_storage) => transaction_storage.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::VoteStorage(vote_storage) => vote_storage.len(),
            Self::LocalTransactionStorage(transaction_storage) => transaction_storage.len(),
        }
    }

    /// Returns the maximum number of packets a receive should accept
    pub fn max_receive_size(&self) -> usize {
        match self {
            Self::VoteStorage(vote_storage) => vote_storage.max_receive_size(),
            Self::LocalTransactionStorage(transaction_storage) => {
                transaction_storage.max_receive_size()
            }
        }
    }

    pub fn should_not_process(&self) -> bool {
        // The gossip vote thread does not need to process or forward any votes, that is
        // handled by the tpu vote thread
        if let Self::VoteStorage(vote_storage) = self {
            return matches!(vote_storage.vote_source, VoteSource::Gossip);
        }
        false
    }

    pub fn forward_option(&self) -> ForwardOption {
        match self {
            Self::VoteStorage(vote_storage) => vote_storage.forward_option(),
            Self::LocalTransactionStorage(transaction_storage) => {
                transaction_storage.forward_option()
            }
        }
    }

    pub fn clear_forwarded_packets(&mut self) {
        match self {
            Self::LocalTransactionStorage(transaction_storage) => transaction_storage.clear(), // Since we set everything as forwarded this is the same
            Self::VoteStorage(vote_storage) => vote_storage.clear_forwarded_packets(),
        }
    }

    pub(crate) fn insert_batch(
        &mut self,
        deserialized_packets: Vec<ImmutableDeserializedPacket>,
    ) -> InsertPacketBatchSummary {
        match self {
            Self::VoteStorage(vote_storage) => {
                InsertPacketBatchSummary::from(vote_storage.insert_batch(deserialized_packets))
            }
            Self::LocalTransactionStorage(transaction_storage) => InsertPacketBatchSummary::from(
                transaction_storage.insert_batch(deserialized_packets),
            ),
        }
    }

    pub fn filter_forwardable_packets_and_add_batches(
        &mut self,
        bank: Arc<Bank>,
        forward_packet_batches_by_accounts: &mut ForwardPacketBatchesByAccounts,
    ) -> FilterForwardingResults {
        match self {
            Self::LocalTransactionStorage(transaction_storage) => transaction_storage
                .filter_forwardable_packets_and_add_batches(
                    bank,
                    forward_packet_batches_by_accounts,
                ),
            Self::VoteStorage(vote_storage) => vote_storage
                .filter_forwardable_packets_and_add_batches(
                    bank,
                    forward_packet_batches_by_accounts,
                ),
        }
    }

    /// The processing function takes a stream of packets ready to process, and returns the indices
    /// of the unprocessed packets that are eligible for retry. A return value of None means that
    /// all packets are unprocessed and eligible for retry.
    #[must_use]
    pub fn process_packets<F>(
        &mut self,
        bank: Arc<Bank>,
        banking_stage_stats: &BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        processing_function: F,
    ) -> bool
    where
        F: FnMut(
            &Vec<Arc<ImmutableDeserializedPacket>>,
            &mut ConsumeScannerPayload,
        ) -> Option<Vec<usize>>,
    {
        match self {
            Self::LocalTransactionStorage(transaction_storage) => transaction_storage
                .process_packets(
                    &bank,
                    banking_stage_stats,
                    slot_metrics_tracker,
                    processing_function,
                ),
            Self::VoteStorage(vote_storage) => vote_storage.process_packets(
                bank,
                banking_stage_stats,
                slot_metrics_tracker,
                processing_function,
            ),
        }
    }
}

impl VoteStorage {
    fn is_empty(&self) -> bool {
        self.latest_unprocessed_votes.is_empty()
    }

    fn len(&self) -> usize {
        self.latest_unprocessed_votes.len()
    }

    fn max_receive_size(&self) -> usize {
        MAX_NUM_VOTES_RECEIVE
    }

    fn forward_option(&self) -> ForwardOption {
        match self.vote_source {
            VoteSource::Tpu => ForwardOption::ForwardTpuVote,
            VoteSource::Gossip => ForwardOption::NotForward,
        }
    }

    fn clear_forwarded_packets(&mut self) {
        self.latest_unprocessed_votes.clear_forwarded_packets();
    }

    fn insert_batch(
        &mut self,
        deserialized_packets: Vec<ImmutableDeserializedPacket>,
    ) -> VoteBatchInsertionMetrics {
        self.latest_unprocessed_votes
            .insert_batch(
                deserialized_packets
                    .into_iter()
                    .filter_map(|deserialized_packet| {
                        LatestValidatorVotePacket::new_from_immutable(
                            Arc::new(deserialized_packet),
                            self.vote_source,
                        )
                        .ok()
                    }),
            )
    }

    fn filter_forwardable_packets_and_add_batches(
        &mut self,
        bank: Arc<Bank>,
        forward_packet_batches_by_accounts: &mut ForwardPacketBatchesByAccounts,
    ) -> FilterForwardingResults {
        if matches!(self.vote_source, VoteSource::Tpu) {
            let total_forwardable_packets = self
                .latest_unprocessed_votes
                .get_and_insert_forwardable_packets(bank, forward_packet_batches_by_accounts);
            return FilterForwardingResults {
                total_forwardable_packets,
                ..FilterForwardingResults::default()
            };
        }
        FilterForwardingResults::default()
    }

    // returns `true` if the end of slot is reached
    fn process_packets<F>(
        &mut self,
        bank: Arc<Bank>,
        banking_stage_stats: &BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        mut processing_function: F,
    ) -> bool
    where
        F: FnMut(
            &Vec<Arc<ImmutableDeserializedPacket>>,
            &mut ConsumeScannerPayload,
        ) -> Option<Vec<usize>>,
    {
        if matches!(self.vote_source, VoteSource::Gossip) {
            panic!("Gossip vote thread should not be processing transactions");
        }

        let should_process_packet =
            |packet: &Arc<ImmutableDeserializedPacket>, payload: &mut ConsumeScannerPayload| {
                consume_scan_should_process_packet(&bank, banking_stage_stats, packet, payload)
            };

        // Based on the stake distribution present in the supplied bank, drain the unprocessed votes
        // from each validator using a weighted random ordering. Votes from validators with
        // 0 stake are ignored.
        let all_vote_packets = self
            .latest_unprocessed_votes
            .drain_unprocessed(bank.clone());

        // vote storage does not have a message hash map, so pass in an empty one
        let mut dummy_message_hash_to_transaction = HashMap::new();
        let mut scanner = create_consume_multi_iterator(
            &all_vote_packets,
            slot_metrics_tracker,
            &mut dummy_message_hash_to_transaction,
            should_process_packet,
        );

        while let Some((packets, payload)) = scanner.iterate() {
            let vote_packets = packets.iter().map(|p| (*p).clone()).collect_vec();

            if let Some(retryable_vote_indices) = processing_function(&vote_packets, payload) {
                self.latest_unprocessed_votes.insert_batch(
                    retryable_vote_indices.iter().filter_map(|i| {
                        LatestValidatorVotePacket::new_from_immutable(
                            vote_packets[*i].clone(),
                            self.vote_source,
                        )
                        .ok()
                    }),
                );
            } else {
                self.latest_unprocessed_votes
                    .insert_batch(vote_packets.into_iter().filter_map(|packet| {
                        LatestValidatorVotePacket::new_from_immutable(packet, self.vote_source).ok()
                    }));
            }
        }

        scanner.finalize().payload.reached_end_of_slot
    }
}

impl ThreadLocalUnprocessedPackets {
    fn is_empty(&self) -> bool {
        self.unprocessed_packet_batches.is_empty()
    }

    pub fn thread_type(&self) -> ThreadType {
        self.thread_type
    }

    fn len(&self) -> usize {
        self.unprocessed_packet_batches.len()
    }

    fn max_receive_size(&self) -> usize {
        self.unprocessed_packet_batches.capacity() - self.unprocessed_packet_batches.len()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DeserializedPacket> {
        self.unprocessed_packet_batches.iter_mut()
    }

    fn forward_option(&self) -> ForwardOption {
        match self.thread_type {
            ThreadType::Transactions => ForwardOption::ForwardTransaction,
            ThreadType::Voting(VoteSource::Tpu) => ForwardOption::ForwardTpuVote,
            ThreadType::Voting(VoteSource::Gossip) => ForwardOption::NotForward,
        }
    }

    fn clear(&mut self) {
        self.unprocessed_packet_batches.clear();
    }

    fn insert_batch(
        &mut self,
        deserialized_packets: Vec<ImmutableDeserializedPacket>,
    ) -> PacketBatchInsertionMetrics {
        self.unprocessed_packet_batches.insert_batch(
            deserialized_packets
                .into_iter()
                .map(DeserializedPacket::from_immutable_section),
        )
    }

    /// Filter out packets that fail to sanitize, or are no longer valid (could be
    /// too old, a duplicate of something already processed). Doing this in batches to avoid
    /// checking bank's blockhash and status cache per transaction which could be bad for performance.
    /// Added valid and sanitized packets to forwarding queue.
    fn filter_forwardable_packets_and_add_batches(
        &mut self,
        bank: Arc<Bank>,
        forward_buffer: &mut ForwardPacketBatchesByAccounts,
    ) -> FilterForwardingResults {
        let mut total_forwardable_tracer_packets: usize = 0;
        let mut total_tracer_packets_in_buffer: usize = 0;
        let mut total_forwardable_packets: usize = 0;
        let mut total_packet_conversion_us: u64 = 0;
        let mut total_filter_packets_us: u64 = 0;
        let mut total_dropped_packets: usize = 0;

        let mut original_priority_queue = self.take_priority_queue();
        let original_capacity = original_priority_queue.capacity();
        let mut new_priority_queue = MinMaxHeap::with_capacity(original_capacity);

        // indicates if `forward_buffer` still accept more packets, see details at
        // `ForwardPacketBatchesByAccounts.rs`.
        let mut accepting_packets = true;
        // batch iterate through self.unprocessed_packet_batches in desc priority order
        new_priority_queue.extend(
            original_priority_queue
                .drain_desc()
                .chunks(UNPROCESSED_BUFFER_STEP_SIZE)
                .into_iter()
                .flat_map(|packets_to_process| {
                    // Only process packets not yet forwarded
                    let (forwarded_packets, packets_to_forward, is_tracer_packet) = self
                        .prepare_packets_to_forward(
                            packets_to_process,
                            &mut total_tracer_packets_in_buffer,
                        );

                    [
                        forwarded_packets,
                        if accepting_packets {
                            let (
                                (sanitized_transactions, transaction_to_packet_indexes),
                                packet_conversion_time,
                            ): (
                                (Vec<SanitizedTransaction>, Vec<usize>),
                                _,
                            ) = measure!(
                                self.sanitize_unforwarded_packets(
                                    &packets_to_forward,
                                    &bank,
                                    &mut total_dropped_packets
                                ),
                                "sanitize_packet",
                            );
                            saturating_add_assign!(
                                total_packet_conversion_us,
                                packet_conversion_time.as_us()
                            );

                            let (forwardable_transaction_indexes, filter_packets_time) = measure!(
                                Self::filter_invalid_transactions(
                                    &sanitized_transactions,
                                    &bank,
                                    &mut total_dropped_packets
                                ),
                                "filter_packets",
                            );
                            saturating_add_assign!(
                                total_filter_packets_us,
                                filter_packets_time.as_us()
                            );

                            for forwardable_transaction_index in &forwardable_transaction_indexes {
                                saturating_add_assign!(total_forwardable_packets, 1);
                                let forwardable_packet_index =
                                    transaction_to_packet_indexes[*forwardable_transaction_index];
                                if is_tracer_packet[forwardable_packet_index] {
                                    saturating_add_assign!(total_forwardable_tracer_packets, 1);
                                }
                            }

                            let accepted_packet_indexes =
                                Self::add_filtered_packets_to_forward_buffer(
                                    forward_buffer,
                                    &packets_to_forward,
                                    &sanitized_transactions,
                                    &transaction_to_packet_indexes,
                                    &forwardable_transaction_indexes,
                                    &mut total_dropped_packets,
                                    &bank.feature_set,
                                );
                            accepting_packets = accepted_packet_indexes.len()
                                == forwardable_transaction_indexes.len();

                            self.unprocessed_packet_batches
                                .mark_accepted_packets_as_forwarded(
                                    &packets_to_forward,
                                    &accepted_packet_indexes,
                                );

                            Self::collect_retained_packets(
                                &mut self.unprocessed_packet_batches.message_hash_to_transaction,
                                &packets_to_forward,
                                &Self::prepare_filtered_packet_indexes(
                                    &transaction_to_packet_indexes,
                                    &forwardable_transaction_indexes,
                                ),
                            )
                        } else {
                            // skip sanitizing and filtering if not longer able to add more packets for forwarding
                            saturating_add_assign!(total_dropped_packets, packets_to_forward.len());
                            packets_to_forward
                        },
                    ]
                    .concat()
                }),
        );

        // replace packet priority queue
        self.unprocessed_packet_batches.packet_priority_queue = new_priority_queue;
        self.verify_priority_queue(original_capacity);

        // Assert unprocessed queue is still consistent
        assert_eq!(
            self.unprocessed_packet_batches.packet_priority_queue.len(),
            self.unprocessed_packet_batches
                .message_hash_to_transaction
                .len()
        );

        FilterForwardingResults {
            total_forwardable_packets,
            total_tracer_packets_in_buffer,
            total_forwardable_tracer_packets,
            total_dropped_packets,
            total_packet_conversion_us,
            total_filter_packets_us,
        }
    }

    /// Take self.unprocessed_packet_batches's priority_queue out, leave empty MinMaxHeap in its place.
    fn take_priority_queue(&mut self) -> MinMaxHeap<Arc<ImmutableDeserializedPacket>> {
        std::mem::replace(
            &mut self.unprocessed_packet_batches.packet_priority_queue,
            MinMaxHeap::new(), // <-- no need to reserve capacity as we will replace this
        )
    }

    /// Verify that the priority queue and map are consistent and that original capacity is maintained.
    fn verify_priority_queue(&self, original_capacity: usize) {
        // Assert unprocessed queue is still consistent and maintains original capacity
        assert_eq!(
            self.unprocessed_packet_batches
                .packet_priority_queue
                .capacity(),
            original_capacity
        );
        assert_eq!(
            self.unprocessed_packet_batches.packet_priority_queue.len(),
            self.unprocessed_packet_batches
                .message_hash_to_transaction
                .len()
        );
    }

    /// sanitize un-forwarded packet into SanitizedTransaction for validation and forwarding.
    fn sanitize_unforwarded_packets(
        &mut self,
        packets_to_process: &[Arc<ImmutableDeserializedPacket>],
        bank: &Arc<Bank>,
        total_dropped_packets: &mut usize,
    ) -> (Vec<SanitizedTransaction>, Vec<usize>) {
        // Get ref of ImmutableDeserializedPacket
        let deserialized_packets = packets_to_process.iter().map(|p| &**p);
        let (transactions, transaction_to_packet_indexes): (Vec<SanitizedTransaction>, Vec<usize>) =
            deserialized_packets
                .enumerate()
                .filter_map(|(packet_index, deserialized_packet)| {
                    deserialized_packet
                        .build_sanitized_transaction(
                            &bank.feature_set,
                            bank.vote_only_bank(),
                            bank.as_ref(),
                        )
                        .map(|transaction| (transaction, packet_index))
                })
                .unzip();

        inc_new_counter_info!("banking_stage-packet_conversion", 1);
        let filtered_count = packets_to_process.len().saturating_sub(transactions.len());
        saturating_add_assign!(*total_dropped_packets, filtered_count);

        (transactions, transaction_to_packet_indexes)
    }

    /// Checks sanitized transactions against bank, returns valid transaction indexes
    fn filter_invalid_transactions(
        transactions: &[SanitizedTransaction],
        bank: &Arc<Bank>,
        total_dropped_packets: &mut usize,
    ) -> Vec<usize> {
        let filter = vec![Ok(()); transactions.len()];
        let results = bank.check_transactions_with_forwarding_delay(
            transactions,
            &filter,
            FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET,
        );

        let filtered_count = transactions.len().saturating_sub(results.len());
        saturating_add_assign!(*total_dropped_packets, filtered_count);

        results
            .iter()
            .enumerate()
            .filter_map(
                |(tx_index, (result, _))| if result.is_ok() { Some(tx_index) } else { None },
            )
            .collect_vec()
    }

    fn prepare_filtered_packet_indexes(
        transaction_to_packet_indexes: &[usize],
        retained_transaction_indexes: &[usize],
    ) -> Vec<usize> {
        retained_transaction_indexes
            .iter()
            .map(|tx_index| transaction_to_packet_indexes[*tx_index])
            .collect_vec()
    }

    /// try to add filtered forwardable and valid packets to forward buffer;
    /// returns vector of packet indexes that were accepted for forwarding.
    fn add_filtered_packets_to_forward_buffer(
        forward_buffer: &mut ForwardPacketBatchesByAccounts,
        packets_to_process: &[Arc<ImmutableDeserializedPacket>],
        transactions: &[SanitizedTransaction],
        transaction_to_packet_indexes: &[usize],
        forwardable_transaction_indexes: &[usize],
        total_dropped_packets: &mut usize,
        feature_set: &FeatureSet,
    ) -> Vec<usize> {
        let mut added_packets_count: usize = 0;
        let mut accepted_packet_indexes = Vec::with_capacity(transaction_to_packet_indexes.len());
        for forwardable_transaction_index in forwardable_transaction_indexes {
            let sanitized_transaction = &transactions[*forwardable_transaction_index];
            let forwardable_packet_index =
                transaction_to_packet_indexes[*forwardable_transaction_index];
            let immutable_deserialized_packet =
                packets_to_process[forwardable_packet_index].clone();
            if !forward_buffer.try_add_packet(
                sanitized_transaction,
                immutable_deserialized_packet,
                feature_set,
            ) {
                break;
            }
            accepted_packet_indexes.push(forwardable_packet_index);
            saturating_add_assign!(added_packets_count, 1);
        }

        let filtered_count = forwardable_transaction_indexes
            .len()
            .saturating_sub(added_packets_count);
        saturating_add_assign!(*total_dropped_packets, filtered_count);

        accepted_packet_indexes
    }

    fn collect_retained_packets(
        message_hash_to_transaction: &mut HashMap<Hash, DeserializedPacket>,
        packets_to_process: &[Arc<ImmutableDeserializedPacket>],
        retained_packet_indexes: &[usize],
    ) -> Vec<Arc<ImmutableDeserializedPacket>> {
        Self::remove_non_retained_packets(
            message_hash_to_transaction,
            packets_to_process,
            retained_packet_indexes,
        );
        retained_packet_indexes
            .iter()
            .map(|i| packets_to_process[*i].clone())
            .collect_vec()
    }

    /// remove packets from UnprocessedPacketBatches.message_hash_to_transaction after they have
    /// been removed from UnprocessedPacketBatches.packet_priority_queue
    fn remove_non_retained_packets(
        message_hash_to_transaction: &mut HashMap<Hash, DeserializedPacket>,
        packets_to_process: &[Arc<ImmutableDeserializedPacket>],
        retained_packet_indexes: &[usize],
    ) {
        filter_processed_packets(
            retained_packet_indexes
                .iter()
                .chain(std::iter::once(&packets_to_process.len())),
            |start, end| {
                for processed_packet in &packets_to_process[start..end] {
                    message_hash_to_transaction.remove(processed_packet.message_hash());
                }
            },
        )
    }

    // returns `true` if reached end of slot
    fn process_packets<F>(
        &mut self,
        bank: &Bank,
        banking_stage_stats: &BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        mut processing_function: F,
    ) -> bool
    where
        F: FnMut(
            &Vec<Arc<ImmutableDeserializedPacket>>,
            &mut ConsumeScannerPayload,
        ) -> Option<Vec<usize>>,
    {
        let mut retryable_packets = self.take_priority_queue();
        let original_capacity = retryable_packets.capacity();
        let mut new_retryable_packets = MinMaxHeap::with_capacity(original_capacity);
        let all_packets_to_process = retryable_packets.drain_desc().collect_vec();

        let should_process_packet =
            |packet: &Arc<ImmutableDeserializedPacket>, payload: &mut ConsumeScannerPayload| {
                consume_scan_should_process_packet(bank, banking_stage_stats, packet, payload)
            };
        let mut scanner = create_consume_multi_iterator(
            &all_packets_to_process,
            slot_metrics_tracker,
            &mut self.unprocessed_packet_batches.message_hash_to_transaction,
            should_process_packet,
        );

        while let Some((packets_to_process, payload)) = scanner.iterate() {
            let packets_to_process = packets_to_process
                .iter()
                .map(|p| (*p).clone())
                .collect_vec();
            let retryable_packets = if let Some(retryable_transaction_indexes) =
                processing_function(&packets_to_process, payload)
            {
                Self::collect_retained_packets(
                    payload.message_hash_to_transaction,
                    &packets_to_process,
                    &retryable_transaction_indexes,
                )
            } else {
                packets_to_process
            };

            new_retryable_packets.extend(retryable_packets);
        }

        let reached_end_of_slot = scanner.finalize().payload.reached_end_of_slot;

        self.unprocessed_packet_batches.packet_priority_queue = new_retryable_packets;
        self.verify_priority_queue(original_capacity);

        reached_end_of_slot
    }

    /// Prepare a chunk of packets for forwarding, filter out already forwarded packets while
    /// counting tracers.
    /// Returns Vec of unforwarded packets, and Vec<bool> of same size each indicates corresponding
    /// packet is tracer packet.
    fn prepare_packets_to_forward(
        &self,
        packets_to_forward: impl Iterator<Item = Arc<ImmutableDeserializedPacket>>,
        total_tracer_packets_in_buffer: &mut usize,
    ) -> (
        Vec<Arc<ImmutableDeserializedPacket>>,
        Vec<Arc<ImmutableDeserializedPacket>>,
        Vec<bool>,
    ) {
        let mut forwarded_packets: Vec<Arc<ImmutableDeserializedPacket>> = vec![];
        let (forwardable_packets, is_tracer_packet) = packets_to_forward
            .into_iter()
            .filter_map(|immutable_deserialized_packet| {
                let is_tracer_packet = immutable_deserialized_packet
                    .original_packet()
                    .meta()
                    .is_tracer_packet();
                if is_tracer_packet {
                    saturating_add_assign!(*total_tracer_packets_in_buffer, 1);
                }
                if !self
                    .unprocessed_packet_batches
                    .is_forwarded(&immutable_deserialized_packet)
                {
                    Some((immutable_deserialized_packet, is_tracer_packet))
                } else {
                    forwarded_packets.push(immutable_deserialized_packet);
                    None
                }
            })
            .unzip();

        (forwarded_packets, forwardable_packets, is_tracer_packet)
    }
}
