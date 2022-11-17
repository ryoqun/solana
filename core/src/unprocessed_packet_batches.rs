use {
    min_max_heap::MinMaxHeap,
    solana_perf::packet::{Packet, PacketBatch},
    solana_program_runtime::compute_budget::ComputeBudget,
    solana_sdk::{
        feature_set,
        hash::Hash,
        message::{Message, SanitizedVersionedMessage},
        sanitize::SanitizeError,
        short_vec::decode_shortu16_len,
        signature::Signature,
        transaction::{
            AddressLoader, SanitizedTransaction, SanitizedVersionedTransaction, Transaction,
            VersionedTransaction,
        },
    },
    std::{
        cmp::Ordering,
        collections::{hash_map::Entry, HashMap},
        mem::size_of,
        rc::Rc,
        sync::Arc,
    },
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum DeserializedPacketError {
    #[error("ShortVec Failed to Deserialize")]
    // short_vec::decode_shortu16_len() currently returns () on error
    ShortVecError(()),
    #[error("Deserialization Error: {0}")]
    DeserializationError(#[from] bincode::Error),
    #[error("overflowed on signature size {0}")]
    SignatureOverflowed(usize),
    #[error("packet failed sanitization {0}")]
    SanitizeError(#[from] SanitizeError),
    #[error("transaction failed prioritization")]
    PrioritizationFailure,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TransactionPriorityDetails {
    pub priority: u64,
    pub compute_unit_limit: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ImmutableDeserializedPacket {
    original_packet: Packet,
    transaction: SanitizedVersionedTransaction,
    message_hash: Hash,
    is_simple_vote: bool,
    priority_details: TransactionPriorityDetails,
}

impl ImmutableDeserializedPacket {
    pub fn original_packet(&self) -> &Packet {
        &self.original_packet
    }

    pub fn transaction(&self) -> &SanitizedVersionedTransaction {
        &self.transaction
    }

    pub fn message_hash(&self) -> &Hash {
        &self.message_hash
    }

    pub fn is_simple_vote(&self) -> bool {
        self.is_simple_vote
    }

    pub fn priority(&self) -> u64 {
        self.priority_details.priority
    }

    pub fn compute_unit_limit(&self) -> u64 {
        self.priority_details.compute_unit_limit
    }
}

/// Holds deserialized messages, as well as computed message_hash and other things needed to create
/// SanitizedTransaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeserializedPacket {
    immutable_section: Rc<ImmutableDeserializedPacket>,
    pub forwarded: bool,
}

impl DeserializedPacket {
    pub fn new(packet: Packet) -> Result<Self, DeserializedPacketError> {
        Self::new_internal(packet, None)
    }

    pub fn new_internal(
        packet: Packet,
        priority_details: Option<TransactionPriorityDetails>,
    ) -> Result<Self, DeserializedPacketError> {
        let versioned_transaction: VersionedTransaction = packet.deserialize_slice(..)?;
        let sanitized_transaction = SanitizedVersionedTransaction::try_from(versioned_transaction)?;
        let message_bytes = packet_message(&packet)?;
        let message_hash = Message::hash_raw_message(message_bytes);
        let is_simple_vote = packet.meta.is_simple_vote_tx();

        // drop transaction if prioritization fails.
        let mut priority_details = priority_details
            .or_else(|| get_priority_details(sanitized_transaction.get_message()))
            .ok_or(DeserializedPacketError::PrioritizationFailure)?;

        // set priority to zero for vote transactions
        if is_simple_vote {
            priority_details.priority = 0;
        };

        Ok(Self {
            immutable_section: Rc::new(ImmutableDeserializedPacket {
                original_packet: packet,
                transaction: sanitized_transaction,
                message_hash,
                is_simple_vote,
                priority_details,
            }),
            forwarded: false,
        })
    }

    pub fn immutable_section(&self) -> &Rc<ImmutableDeserializedPacket> {
        &self.immutable_section
    }
}

impl PartialOrd for DeserializedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DeserializedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.immutable_section()
            .priority()
            .cmp(&other.immutable_section().priority())
    }
}

impl PartialOrd for ImmutableDeserializedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ImmutableDeserializedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority().cmp(&other.priority())
    }
}

/// Currently each banking_stage thread has a `UnprocessedPacketBatches` buffer to store
/// PacketBatch's received from sigverify. Banking thread continuously scans the buffer
/// to pick proper packets to add to the block.
#[derive(Default)]
pub struct UnprocessedPacketBatches {
    pub packet_priority_queue: MinMaxHeap<Rc<ImmutableDeserializedPacket>>,
    pub message_hash_to_transaction: HashMap<Hash, DeserializedPacket>,
    batch_limit: usize,
}

impl UnprocessedPacketBatches {
    pub fn from_iter<I: IntoIterator<Item = DeserializedPacket>>(iter: I, capacity: usize) -> Self {
        let mut unprocessed_packet_batches = Self::with_capacity(capacity);
        for deserialized_packet in iter.into_iter() {
            unprocessed_packet_batches.push(deserialized_packet);
        }

        unprocessed_packet_batches
    }

    pub fn with_capacity(capacity: usize) -> Self {
        UnprocessedPacketBatches {
            packet_priority_queue: MinMaxHeap::with_capacity(capacity),
            message_hash_to_transaction: HashMap::with_capacity(capacity),
            batch_limit: capacity,
        }
    }

    pub fn clear(&mut self) {
        self.packet_priority_queue.clear();
        self.message_hash_to_transaction.clear();
    }

    /// Insert new `deserialized_packet_batch` into inner `MinMaxHeap<DeserializedPacket>`,
    /// ordered by the tx priority.
    /// If buffer is at the max limit, the lowest priority packet is dropped
    ///
    /// Returns tuple of number of packets dropped
    pub fn insert_batch(
        &mut self,
        deserialized_packets: impl Iterator<Item = DeserializedPacket>,
    ) -> (usize, usize) {
        let mut num_dropped_packets = 0;
        let mut num_dropped_tracer_packets = 0;
        for deserialized_packet in deserialized_packets {
            if let Some(dropped_packet) = self.push(deserialized_packet) {
                num_dropped_packets += 1;
                if dropped_packet
                    .immutable_section()
                    .original_packet()
                    .meta
                    .is_tracer_packet()
                {
                    num_dropped_tracer_packets += 1;
                }
            }
        }
        (num_dropped_packets, num_dropped_tracer_packets)
    }

    pub fn push(&mut self, deserialized_packet: DeserializedPacket) -> Option<DeserializedPacket> {
        if self
            .message_hash_to_transaction
            .contains_key(deserialized_packet.immutable_section().message_hash())
        {
            return None;
        }

        if self.len() == self.batch_limit {
            // Optimized to not allocate by calling `MinMaxHeap::push_pop_min()`
            Some(self.push_pop_min(deserialized_packet))
        } else {
            self.push_internal(deserialized_packet);
            None
        }
    }

    pub fn iter(&mut self) -> impl Iterator<Item = &DeserializedPacket> {
        self.message_hash_to_transaction.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DeserializedPacket> {
        self.message_hash_to_transaction.iter_mut().map(|(_k, v)| v)
    }

    /// Iterates DeserializedPackets in descending priority (max-first) order,
    /// calls FnMut for each DeserializedPacket.
    pub fn iter_desc<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut DeserializedPacket) -> bool,
    {
        let mut packet_priority_queue_clone = self.packet_priority_queue.clone();

        for immutable_packet in packet_priority_queue_clone.drain_desc() {
            match self
                .message_hash_to_transaction
                .entry(*immutable_packet.message_hash())
            {
                Entry::Vacant(_vacant_entry) => {
                    panic!(
                        "entry {} must exist to be consistent with `packet_priority_queue`",
                        immutable_packet.message_hash()
                    );
                }
                Entry::Occupied(mut occupied_entry) => {
                    if !f(occupied_entry.get_mut()) {
                        return;
                    }
                }
            }
        }
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut DeserializedPacket) -> bool,
    {
        // TODO: optimize this only when number of packets
        // with outdated blockhash is high
        let new_packet_priority_queue: MinMaxHeap<Rc<ImmutableDeserializedPacket>> = self
            .packet_priority_queue
            .drain()
            .filter(|immutable_packet| {
                match self
                    .message_hash_to_transaction
                    .entry(*immutable_packet.message_hash())
                {
                    Entry::Vacant(_vacant_entry) => {
                        panic!(
                            "entry {} must exist to be consistent with `packet_priority_queue`",
                            immutable_packet.message_hash()
                        );
                    }
                    Entry::Occupied(mut occupied_entry) => {
                        let should_retain = f(occupied_entry.get_mut());
                        if !should_retain {
                            occupied_entry.remove_entry();
                        }
                        should_retain
                    }
                }
            })
            .collect();
        self.packet_priority_queue = new_packet_priority_queue;
    }

    pub fn len(&self) -> usize {
        self.packet_priority_queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packet_priority_queue.is_empty()
    }

    fn push_internal(&mut self, deserialized_packet: DeserializedPacket) {
        // Push into the priority queue
        self.packet_priority_queue
            .push(deserialized_packet.immutable_section().clone());

        // Keep track of the original packet in the tracking hashmap
        self.message_hash_to_transaction.insert(
            *deserialized_packet.immutable_section().message_hash(),
            deserialized_packet,
        );
    }

    /// Returns the popped minimum packet from the priority queue.
    fn push_pop_min(&mut self, deserialized_packet: DeserializedPacket) -> DeserializedPacket {
        let immutable_packet = deserialized_packet.immutable_section().clone();

        // Push into the priority queue
        let popped_immutable_packet = self.packet_priority_queue.push_pop_min(immutable_packet);

        if popped_immutable_packet.message_hash()
            != deserialized_packet.immutable_section().message_hash()
        {
            // Remove the popped entry from the tracking hashmap. Unwrap call is safe
            // because the priority queue and hashmap are kept consistent at all times.
            let removed_min = self
                .message_hash_to_transaction
                .remove(popped_immutable_packet.message_hash())
                .unwrap();

            // Keep track of the original packet in the tracking hashmap
            self.message_hash_to_transaction.insert(
                *deserialized_packet.immutable_section().message_hash(),
                deserialized_packet,
            );
            removed_min
        } else {
            deserialized_packet
        }
    }

    pub fn pop_max(&mut self) -> Option<DeserializedPacket> {
        self.packet_priority_queue
            .pop_max()
            .map(|immutable_packet| {
                self.message_hash_to_transaction
                    .remove(immutable_packet.message_hash())
                    .unwrap()
            })
    }

    /// Pop up to the next `n` highest priority transactions from the queue.
    /// Returns `None` if the queue is empty
    pub fn pop_max_n(&mut self, n: usize) -> Option<Vec<DeserializedPacket>> {
        let current_len = self.len();
        if self.is_empty() {
            None
        } else {
            let num_to_pop = std::cmp::min(current_len, n);
            Some(
                std::iter::from_fn(|| Some(self.pop_max().unwrap()))
                    .take(num_to_pop)
                    .collect::<Vec<DeserializedPacket>>(),
            )
        }
    }

    pub fn capacity(&self) -> usize {
        self.packet_priority_queue.capacity()
    }
}

pub fn deserialize_packets<'a>(
    packet_batch: &'a PacketBatch,
    packet_indexes: &'a [usize],
) -> impl Iterator<Item = DeserializedPacket> + 'a {
    packet_indexes.iter().filter_map(move |packet_index| {
        DeserializedPacket::new(packet_batch[*packet_index].clone()).ok()
    })
}

/// Read the transaction message from packet data
pub fn packet_message(packet: &Packet) -> Result<&[u8], DeserializedPacketError> {
    let (sig_len, sig_size) = packet
        .data(..)
        .and_then(|bytes| decode_shortu16_len(bytes).ok())
        .ok_or(DeserializedPacketError::ShortVecError(()))?;
    sig_len
        .checked_mul(size_of::<Signature>())
        .and_then(|v| v.checked_add(sig_size))
        .and_then(|msg_start| packet.data(msg_start..))
        .ok_or(DeserializedPacketError::SignatureOverflowed(sig_size))
}

fn get_priority_details(message: &SanitizedVersionedMessage) -> Option<TransactionPriorityDetails> {
    let mut compute_budget = ComputeBudget::default();
    let prioritization_fee_details = compute_budget
        .process_instructions(
            message.program_instructions_iter(),
            true, // don't reject txs that use request heap size ix
            true, // use default units per instruction
            true, // don't reject txs that use set compute unit price ix
        )
        .ok()?;
    Some(TransactionPriorityDetails {
        priority: prioritization_fee_details.get_priority(),
        compute_unit_limit: compute_budget.compute_unit_limit,
    })
}

pub fn transactions_to_deserialized_packets(
    transactions: &[Transaction],
) -> Result<Vec<DeserializedPacket>, DeserializedPacketError> {
    transactions
        .iter()
        .map(|transaction| {
            let packet = Packet::from_data(None, transaction)?;
            DeserializedPacket::new(packet)
        })
        .collect()
}

// This function deserializes packets into transactions, computes the blake3 hash of transaction
// messages, and verifies secp256k1 instructions. A list of sanitized transactions are returned
// with their packet indexes.
#[allow(clippy::needless_collect)]
pub fn transaction_from_deserialized_packet(
    deserialized_packet: &ImmutableDeserializedPacket,
    feature_set: &Arc<feature_set::FeatureSet>,
    votes_only: bool,
    address_loader: impl AddressLoader,
) -> Option<SanitizedTransaction> {
    if votes_only && !deserialized_packet.is_simple_vote() {
        return None;
    }

    let tx = SanitizedTransaction::try_new(
        deserialized_packet.transaction().clone(),
        *deserialized_packet.message_hash(),
        deserialized_packet.is_simple_vote(),
        address_loader,
    )
    .ok()?;
    tx.verify_precompiles(feature_set).ok()?;
    Some(tx)
}
