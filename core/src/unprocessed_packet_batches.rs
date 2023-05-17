use {
    crate::immutable_deserialized_packet::{DeserializedPacketError, ImmutableDeserializedPacket},
    min_max_heap::MinMaxHeap,
    solana_perf::packet::Packet,
    solana_sdk::hash::Hash,
    std::{
        cmp::Ordering,
        collections::{hash_map::Entry, HashMap},
        sync::Arc,
    },
};

/// Holds deserialized messages, as well as computed message_hash and other things needed to create
/// SanitizedTransaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeserializedPacket {
    immutable_section: Arc<ImmutableDeserializedPacket>,
    pub forwarded: bool,
}

impl DeserializedPacket {
    pub fn from_immutable_section(immutable_section: ImmutableDeserializedPacket) -> Self {
        Self {
            immutable_section: Arc::new(immutable_section),
            forwarded: false,
        }
    }

    pub fn new(packet: Packet) -> Result<Self, DeserializedPacketError> {
        let immutable_section = ImmutableDeserializedPacket::new(packet)?;

        Ok(Self {
            immutable_section: Arc::new(immutable_section),
            forwarded: false,
        })
    }

    pub fn immutable_section(&self) -> &Arc<ImmutableDeserializedPacket> {
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

#[derive(Debug)]
pub struct PacketBatchInsertionMetrics {
    pub(crate) num_dropped_packets: usize,
    pub(crate) num_dropped_tracer_packets: usize,
}

/// Currently each banking_stage thread has a `UnprocessedPacketBatches` buffer to store
/// PacketBatch's received from sigverify. Banking thread continuously scans the buffer
/// to pick proper packets to add to the block.
#[derive(Debug, Default)]
pub struct UnprocessedPacketBatches {
    pub packet_priority_queue: MinMaxHeap<Arc<ImmutableDeserializedPacket>>,
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
    ) -> PacketBatchInsertionMetrics {
        let mut num_dropped_packets = 0;
        let mut num_dropped_tracer_packets = 0;
        for deserialized_packet in deserialized_packets {
            if let Some(dropped_packet) = self.push(deserialized_packet) {
                num_dropped_packets += 1;
                if dropped_packet
                    .immutable_section()
                    .original_packet()
                    .meta()
                    .is_tracer_packet()
                {
                    num_dropped_tracer_packets += 1;
                }
            }
        }
        PacketBatchInsertionMetrics {
            num_dropped_packets,
            num_dropped_tracer_packets,
        }
    }

    /// Pushes a new `deserialized_packet` into the unprocessed packet batches if it does not already
    /// exist.
    ///
    /// Returns and drops the lowest priority packet if the buffer is at capacity.
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

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut DeserializedPacket) -> bool,
    {
        // TODO: optimize this only when number of packets
        // with outdated blockhash is high
        let new_packet_priority_queue: MinMaxHeap<Arc<ImmutableDeserializedPacket>> = self
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

    /// Pop up to the next `n` highest priority transactions from the queue.
    /// Returns `None` if the queue is empty

    pub fn capacity(&self) -> usize {
        self.packet_priority_queue.capacity()
    }

    pub fn is_forwarded(&self, immutable_packet: &ImmutableDeserializedPacket) -> bool {
        self.message_hash_to_transaction
            .get(immutable_packet.message_hash())
            .map_or(true, |p| p.forwarded)
    }

    pub fn mark_accepted_packets_as_forwarded(
        &mut self,
        packets_to_process: &[Arc<ImmutableDeserializedPacket>],
        accepted_packet_indexes: &[usize],
    ) {
        accepted_packet_indexes
            .iter()
            .for_each(|accepted_packet_index| {
                let accepted_packet = packets_to_process[*accepted_packet_index].clone();
                if let Some(deserialized_packet) = self
                    .message_hash_to_transaction
                    .get_mut(accepted_packet.message_hash())
                {
                    deserialized_packet.forwarded = true;
                }
            });
    }
}
