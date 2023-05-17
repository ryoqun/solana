use {
    crate::{
        duplicate_shred::{self, DuplicateShred, Error},
        duplicate_shred_listener::DuplicateShredHandlerTrait,
    },
    log::error,
    solana_ledger::{blockstore::Blockstore, leader_schedule_cache::LeaderScheduleCache},
    solana_runtime::bank_forks::BankForks,
    solana_sdk::{
        clock::{Epoch, Slot},
        pubkey::Pubkey,
    },
    std::{
        cmp::Reverse,
        collections::HashMap,
        sync::{Arc, RwLock},
    },
};

// Normally num_chunks is 3, because there are two shreds (each is one packet)
// and meta data. So we discard anything larger than 3 chunks.
const MAX_NUM_CHUNKS: usize = 3;
// Limit number of entries per node.
const MAX_NUM_ENTRIES_PER_PUBKEY: usize = 128;
const BUFFER_CAPACITY: usize = 512 * MAX_NUM_ENTRIES_PER_PUBKEY;

type BufferEntry = [Option<DuplicateShred>; MAX_NUM_CHUNKS];

pub struct DuplicateShredHandler {
    // Because we use UDP for packet transfer, we can normally only send ~1500 bytes
    // in each packet. We send both shreds and meta data in duplicate shred proof, and
    // each shred is normally 1 packet(1500 bytes), so the whole proof is larger than
    // 1 packet and it needs to be cut down as chunks for transfer. So we need to piece
    // together the chunks into the original proof before anything useful is done.
    buffer: HashMap<(Slot, Pubkey), BufferEntry>,
    // Slots for which a duplicate proof is already ingested.
    consumed: HashMap<Slot, bool>,
    // Cache last root to reduce read lock.
    last_root: Slot,
    blockstore: Arc<Blockstore>,
    leader_schedule_cache: Arc<LeaderScheduleCache>,
    bank_forks: Arc<RwLock<BankForks>>,
    // Cache information from root bank so we could function correctly without reading roots.
    cached_on_epoch: Epoch,
    cached_staked_nodes: Arc<HashMap<Pubkey, u64>>,
    cached_slots_in_epoch: u64,
}

impl DuplicateShredHandlerTrait for DuplicateShredHandler {
    // Here we are sending data one by one rather than in a batch because in the future
    // we may send different type of CrdsData to different senders.
    fn handle(&mut self, shred_data: DuplicateShred) {
        self.cache_root_info();
        self.maybe_prune_buffer();
        if let Err(error) = self.handle_shred_data(shred_data) {
            error!("handle packet: {error:?}")
        }
    }
}

impl DuplicateShredHandler {
    pub fn new(
        blockstore: Arc<Blockstore>,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> Self {
        Self {
            buffer: HashMap::<(Slot, Pubkey), BufferEntry>::default(),
            consumed: HashMap::<Slot, bool>::default(),
            last_root: 0,
            cached_on_epoch: 0,
            cached_staked_nodes: Arc::new(HashMap::new()),
            cached_slots_in_epoch: 0,
            blockstore,
            leader_schedule_cache,
            bank_forks,
        }
    }

    fn cache_root_info(&mut self) {
        let last_root = self.blockstore.last_root();
        if last_root == self.last_root && !self.cached_staked_nodes.is_empty() {
            return;
        }
        self.last_root = last_root;
        if let Ok(bank_fork) = self.bank_forks.try_read() {
            let root_bank = bank_fork.root_bank();
            let epoch_info = root_bank.get_epoch_info();
            if self.cached_staked_nodes.is_empty() || self.cached_on_epoch < epoch_info.epoch {
                self.cached_on_epoch = epoch_info.epoch;
                if let Some(cached_staked_nodes) = root_bank.epoch_staked_nodes(epoch_info.epoch) {
                    self.cached_staked_nodes = cached_staked_nodes;
                }
                self.cached_slots_in_epoch = epoch_info.slots_in_epoch;
            }
        }
    }

    fn handle_shred_data(&mut self, chunk: DuplicateShred) -> Result<(), Error> {
        if !self.should_consume_slot(chunk.slot) {
            return Ok(());
        }
        let slot = chunk.slot;
        let num_chunks = chunk.num_chunks();
        let chunk_index = chunk.chunk_index();
        if usize::from(num_chunks) > MAX_NUM_CHUNKS || chunk_index >= num_chunks {
            return Err(Error::InvalidChunkIndex {
                chunk_index,
                num_chunks,
            });
        }
        let entry = self.buffer.entry((chunk.slot, chunk.from)).or_default();
        *entry
            .get_mut(usize::from(chunk_index))
            .ok_or(Error::InvalidChunkIndex {
                chunk_index,
                num_chunks,
            })? = Some(chunk);
        // If all chunks are already received, reconstruct and store
        // the duplicate slot proof in blockstore
        if entry.iter().flatten().count() == usize::from(num_chunks) {
            let chunks = std::mem::take(entry).into_iter().flatten();
            let pubkey = self
                .leader_schedule_cache
                .slot_leader_at(slot, /*bank:*/ None)
                .ok_or(Error::UnknownSlotLeader(slot))?;
            let (shred1, shred2) = duplicate_shred::into_shreds(&pubkey, chunks)?;
            if !self.blockstore.has_duplicate_shreds_in_slot(slot) {
                self.blockstore.store_duplicate_slot(
                    slot,
                    shred1.into_payload(),
                    shred2.into_payload(),
                )?;
            }
            self.consumed.insert(slot, true);
        }
        Ok(())
    }

    fn should_consume_slot(&mut self, slot: Slot) -> bool {
        slot > self.last_root
            && slot < self.last_root.saturating_add(self.cached_slots_in_epoch)
            && should_consume_slot(slot, &self.blockstore, &mut self.consumed)
    }

    fn maybe_prune_buffer(&mut self) {
        // The buffer is allowed to grow to twice the intended capacity, at
        // which point the extraneous entries are removed in linear time,
        // resulting an amortized O(1) performance.
        if self.buffer.len() < BUFFER_CAPACITY.saturating_mul(2) {
            return;
        }
        self.consumed.retain(|&slot, _| slot > self.last_root);
        // Filter out obsolete slots and limit number of entries per pubkey.
        {
            let mut counts = HashMap::<Pubkey, usize>::new();
            self.buffer.retain(|(slot, pubkey), _| {
                *slot > self.last_root
                    && should_consume_slot(*slot, &self.blockstore, &mut self.consumed)
                    && {
                        let count = counts.entry(*pubkey).or_default();
                        *count = count.saturating_add(1);
                        *count <= MAX_NUM_ENTRIES_PER_PUBKEY
                    }
            });
        }
        if self.buffer.len() < BUFFER_CAPACITY {
            return;
        }
        // Lookup stake for each entry.
        let mut buffer: Vec<_> = self
            .buffer
            .drain()
            .map(|entry @ ((_, pubkey), _)| {
                let stake = self
                    .cached_staked_nodes
                    .get(&pubkey)
                    .copied()
                    .unwrap_or_default();
                (stake, entry)
            })
            .collect();
        // Drop entries with lowest stake and rebuffer remaining ones.
        buffer.select_nth_unstable_by_key(BUFFER_CAPACITY, |&(stake, _)| Reverse(stake));
        self.buffer.extend(
            buffer
                .into_iter()
                .take(BUFFER_CAPACITY)
                .map(|(_, entry)| entry),
        );
    }
}

// Returns false if a duplicate proof is already ingested for the slot,
// and updates local `consumed` cache with blockstore.
fn should_consume_slot(
    slot: Slot,
    blockstore: &Blockstore,
    consumed: &mut HashMap<Slot, bool>,
) -> bool {
    !*consumed
        .entry(slot)
        .or_insert_with(|| blockstore.has_duplicate_shreds_in_slot(slot))
}

