#![allow(clippy::rc_buffer)]

use {
    super::{
        broadcast_utils::{self, ReceiveResults},
        *,
    },
    crate::cluster_nodes::ClusterNodesCache,
    solana_entry::entry::Entry,
    solana_ledger::{
        blockstore,
        shred::{shred_code, ProcessShredsStats, ReedSolomonCache, Shred, ShredFlags, Shredder},
    },
    solana_sdk::{
        genesis_config::ClusterType,
        hash::Hash,
        signature::Keypair,
        timing::{duration_as_us, AtomicInterval},
    },
    std::{sync::RwLock, time::Duration},
    tokio::sync::mpsc::Sender as AsyncSender,
};

#[derive(Clone)]
pub struct StandardBroadcastRun {
    slot: Slot,
    parent: Slot,
    chained_merkle_root: Hash,
    next_shred_index: u32,
    next_code_index: u32,
    // If last_tick_height has reached bank.max_tick_height() for this slot
    // and so the slot is completed and all shreds are already broadcast.
    completed: bool,
    process_shreds_stats: ProcessShredsStats,
    transmit_shreds_stats: Arc<Mutex<SlotBroadcastStats<TransmitShredsStats>>>,
    insert_shreds_stats: Arc<Mutex<SlotBroadcastStats<InsertShredsStats>>>,
    slot_broadcast_start: Instant,
    shred_version: u16,
    last_datapoint_submit: Arc<AtomicInterval>,
    num_batches: usize,
    cluster_nodes_cache: Arc<ClusterNodesCache<BroadcastStage>>,
    reed_solomon_cache: Arc<ReedSolomonCache>,
}

#[derive(Debug)]
enum BroadcastError {
    TooManyShreds,
}

impl StandardBroadcastRun {
    pub(super) fn new(shred_version: u16) -> Self {
        let cluster_nodes_cache = Arc::new(ClusterNodesCache::<BroadcastStage>::new(
            CLUSTER_NODES_CACHE_NUM_EPOCH_CAP,
            CLUSTER_NODES_CACHE_TTL,
        ));
        Self {
            slot: Slot::MAX,
            parent: Slot::MAX,
            chained_merkle_root: Hash::default(),
            next_shred_index: 0,
            next_code_index: 0,
            completed: true,
            process_shreds_stats: ProcessShredsStats::default(),
            transmit_shreds_stats: Arc::default(),
            insert_shreds_stats: Arc::default(),
            slot_broadcast_start: Instant::now(),
            shred_version,
            last_datapoint_submit: Arc::default(),
            num_batches: 0,
            cluster_nodes_cache,
            reed_solomon_cache: Arc::<ReedSolomonCache>::default(),
        }
    }

    // If the current slot has changed, generates an empty shred indicating
    // last shred in the previous slot, along with coding shreds for the data
    // shreds buffered.
    fn finish_prev_slot(
        &mut self,
        keypair: &Keypair,
        max_ticks_in_slot: u8,
        cluster_type: ClusterType,
        stats: &mut ProcessShredsStats,
    ) -> Vec<Shred> {
        const SHRED_TICK_REFERENCE_MASK: u8 = ShredFlags::SHRED_TICK_REFERENCE_MASK.bits();
        if self.completed {
            return vec![];
        }
        let reference_tick = max_ticks_in_slot & SHRED_TICK_REFERENCE_MASK;
        let (mut shreds, coding_shreds) =
            Shredder::new(self.slot, self.parent, reference_tick, self.shred_version)
                .unwrap()
                .entries_to_shreds(
                    keypair,
                    &[],  // entries
                    true, // is_last_in_slot,
                    should_chain_merkle_shreds(self.slot, cluster_type)
                        .then_some(self.chained_merkle_root),
                    self.next_shred_index,
                    self.next_code_index,
                    true, // merkle_variant
                    &self.reed_solomon_cache,
                    stats,
                );
        if let Some(shred) = shreds.iter().max_by_key(|shred| shred.index()) {
            self.chained_merkle_root = shred.merkle_root().unwrap();
        }
        stats.num_merkle_data_shreds += shreds.len();
        stats.num_merkle_coding_shreds += coding_shreds.len();
        self.report_and_reset_stats(/*was_interrupted:*/ true);
        self.completed = true;
        shreds.extend(coding_shreds);
        shreds
    }

    #[allow(clippy::too_many_arguments)]
    fn entries_to_shreds(
        &mut self,
        keypair: &Keypair,
        entries: &[Entry],
        reference_tick: u8,
        is_slot_end: bool,
        cluster_type: ClusterType,
        process_stats: &mut ProcessShredsStats,
        max_data_shreds_per_slot: u32,
        max_code_shreds_per_slot: u32,
    ) -> std::result::Result<
        (
            Vec<Shred>, // data shreds
            Vec<Shred>, // coding shreds
        ),
        BroadcastError,
    > {
        let (data_shreds, coding_shreds) =
            Shredder::new(self.slot, self.parent, reference_tick, self.shred_version)
                .unwrap()
                .entries_to_shreds(
                    keypair,
                    entries,
                    is_slot_end,
                    should_chain_merkle_shreds(self.slot, cluster_type)
                        .then_some(self.chained_merkle_root),
                    self.next_shred_index,
                    self.next_code_index,
                    true, // merkle_variant
                    &self.reed_solomon_cache,
                    process_stats,
                );
        process_stats.num_merkle_data_shreds += data_shreds.len();
        process_stats.num_merkle_coding_shreds += coding_shreds.len();
        if let Some(shred) = data_shreds.iter().max_by_key(|shred| shred.index()) {
            self.chained_merkle_root = shred.merkle_root().unwrap();
            self.next_shred_index = shred.index() + 1;
        };
        if self.next_shred_index > max_data_shreds_per_slot {
            return Err(BroadcastError::TooManyShreds);
        }
        if let Some(index) = coding_shreds.iter().map(Shred::index).max() {
            self.next_code_index = index + 1;
        };
        if self.next_code_index > max_code_shreds_per_slot {
            return Err(BroadcastError::TooManyShreds);
        }
        Ok((data_shreds, coding_shreds))
    }

    fn process_receive_results(
        &mut self,
        keypair: &Keypair,
        blockstore: &Blockstore,
        socket_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        blockstore_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        receive_results: ReceiveResults,
    ) -> Result<()> {
        let mut receive_elapsed = receive_results.time_elapsed;
        let mut coalesce_elapsed = receive_results.time_coalesced;
        let num_entries = receive_results.entries.len();
        let bank = receive_results.bank.clone();
        let last_tick_height = receive_results.last_tick_height;
        inc_new_counter_info!("broadcast_service-entries_received", num_entries);

        let mut process_stats = ProcessShredsStats::default();

        let mut to_shreds_time = Measure::start("broadcast_to_shreds");
        let cluster_type = bank.cluster_type();

        if self.slot != bank.slot() {
            // Finish previous slot if it was interrupted.
            if !self.completed {
                let shreds = self.finish_prev_slot(
                    keypair,
                    bank.ticks_per_slot() as u8,
                    cluster_type,
                    &mut process_stats,
                );
                debug_assert!(shreds.iter().all(|shred| shred.slot() == self.slot));
                // Broadcast shreds for the interrupted slot.
                let batch_info = Some(BroadcastShredBatchInfo {
                    slot: self.slot,
                    num_expected_batches: Some(self.num_batches + 1),
                    slot_start_ts: self.slot_broadcast_start,
                    was_interrupted: true,
                });
                let shreds = Arc::new(shreds);
                socket_sender.send((shreds.clone(), batch_info.clone()))?;
                blockstore_sender.send((shreds, batch_info))?;
            }
            // If blockstore already has shreds for this slot,
            // it should not recreate the slot:
            // https://github.com/solana-labs/solana/blob/92a0b310c/ledger/src/leader_schedule_cache.rs##L139-L148
            if blockstore
                .meta(bank.slot())
                .unwrap()
                .filter(|slot_meta| slot_meta.received > 0 || slot_meta.consumed > 0)
                .is_some()
            {
                process_stats.num_extant_slots += 1;
                // This is a faulty situation that should not happen.
                // Refrain from generating shreds for the slot.
                return Err(Error::DuplicateSlotBroadcast(bank.slot()));
            }
            // Reinitialize state for this slot.
            let chained_merkle_root = if self.slot == bank.parent_slot() {
                self.chained_merkle_root
            } else {
                broadcast_utils::get_chained_merkle_root_from_parent(
                    bank.slot(),
                    bank.parent_slot(),
                    blockstore,
                )
                .unwrap_or_else(|err: Error| {
                    error!("Unknown chained Merkle root: {err:?}");
                    process_stats.err_unknown_chained_merkle_root += 1;
                    Hash::default()
                })
            };
            self.slot = bank.slot();
            self.parent = bank.parent_slot();
            self.chained_merkle_root = chained_merkle_root;
            self.next_shred_index = 0u32;
            self.next_code_index = 0u32;
            self.completed = false;
            self.slot_broadcast_start = Instant::now();
            self.num_batches = 0;
            receive_elapsed = Duration::ZERO;
            coalesce_elapsed = Duration::ZERO;
        }

        // 2) Convert entries to shreds and coding shreds
        let is_last_in_slot = last_tick_height == bank.max_tick_height();
        let reference_tick = bank.tick_height() % bank.ticks_per_slot();
        let (data_shreds, coding_shreds) = self
            .entries_to_shreds(
                keypair,
                &receive_results.entries,
                reference_tick as u8,
                is_last_in_slot,
                cluster_type,
                &mut process_stats,
                blockstore::MAX_DATA_SHREDS_PER_SLOT as u32,
                shred_code::MAX_CODE_SHREDS_PER_SLOT as u32,
            )
            .unwrap();
        // Insert the first data shred synchronously so that blockstore stores
        // that the leader started this block. This must be done before the
        // blocks are sent out over the wire, so that the slots we have already
        // sent a shred for are skipped (even if the node reboots):
        // https://github.com/solana-labs/solana/blob/92a0b310c/ledger/src/leader_schedule_cache.rs#L139-L148
        // preventing the node from broadcasting duplicate blocks:
        // https://github.com/solana-labs/solana/blob/92a0b310c/turbine/src/broadcast_stage/standard_broadcast_run.rs#L132-L142
        // By contrast Self::insert skips the 1st data shred with index zero:
        // https://github.com/solana-labs/solana/blob/92a0b310c/turbine/src/broadcast_stage/standard_broadcast_run.rs#L367-L373
        if let Some(shred) = data_shreds.first() {
            if shred.index() == 0 {
                blockstore
                    .insert_shreds(
                        vec![shred.clone()],
                        None, // leader_schedule
                        true, // is_trusted
                    )
                    .expect("Failed to insert shreds in blockstore");
            }
        }
        to_shreds_time.stop();

        let mut get_leader_schedule_time = Measure::start("broadcast_get_leader_schedule");
        // Increment by two batches, one for the data batch, one for the coding batch.
        self.num_batches += 2;
        let num_expected_batches = {
            if is_last_in_slot {
                Some(self.num_batches)
            } else {
                None
            }
        };
        let batch_info = Some(BroadcastShredBatchInfo {
            slot: bank.slot(),
            num_expected_batches,
            slot_start_ts: self.slot_broadcast_start,
            was_interrupted: false,
        });
        get_leader_schedule_time.stop();

        let mut coding_send_time = Measure::start("broadcast_coding_send");

        // Send data shreds
        let data_shreds = Arc::new(data_shreds);
        debug_assert!(data_shreds.iter().all(|shred| shred.slot() == bank.slot()));
        socket_sender.send((data_shreds.clone(), batch_info.clone()))?;
        blockstore_sender.send((data_shreds, batch_info.clone()))?;

        // Send coding shreds
        let coding_shreds = Arc::new(coding_shreds);
        debug_assert!(coding_shreds
            .iter()
            .all(|shred| shred.slot() == bank.slot()));
        socket_sender.send((coding_shreds.clone(), batch_info.clone()))?;
        blockstore_sender.send((coding_shreds, batch_info))?;

        coding_send_time.stop();

        process_stats.shredding_elapsed = to_shreds_time.as_us();
        process_stats.get_leader_schedule_elapsed = get_leader_schedule_time.as_us();
        process_stats.receive_elapsed = duration_as_us(&receive_elapsed);
        process_stats.coalesce_elapsed = duration_as_us(&coalesce_elapsed);
        process_stats.coding_send_elapsed = coding_send_time.as_us();

        self.process_shreds_stats += process_stats;

        if last_tick_height == bank.max_tick_height() {
            self.report_and_reset_stats(false);
            self.completed = true;
        }

        Ok(())
    }

    fn insert(
        &mut self,
        blockstore: &Blockstore,
        shreds: Arc<Vec<Shred>>,
        broadcast_shred_batch_info: Option<BroadcastShredBatchInfo>,
    ) {
        // Insert shreds into blockstore
        let insert_shreds_start = Instant::now();
        let mut shreds = Arc::unwrap_or_clone(shreds);
        // The first data shred is inserted synchronously.
        // https://github.com/solana-labs/solana/blob/92a0b310c/turbine/src/broadcast_stage/standard_broadcast_run.rs#L268-L283
        if let Some(shred) = shreds.first() {
            if shred.is_data() && shred.index() == 0 {
                shreds.swap_remove(0);
            }
        }
        let num_shreds = shreds.len();
        blockstore
            .insert_shreds(
                shreds, /*leader_schedule:*/ None, /*is_trusted:*/ true,
            )
            .expect("Failed to insert shreds in blockstore");
        let insert_shreds_elapsed = insert_shreds_start.elapsed();
        let new_insert_shreds_stats = InsertShredsStats {
            insert_shreds_elapsed: duration_as_us(&insert_shreds_elapsed),
            num_shreds,
        };
        self.update_insertion_metrics(&new_insert_shreds_stats, &broadcast_shred_batch_info);
    }

    fn update_insertion_metrics(
        &mut self,
        new_insertion_shreds_stats: &InsertShredsStats,
        broadcast_shred_batch_info: &Option<BroadcastShredBatchInfo>,
    ) {
        let mut insert_shreds_stats = self.insert_shreds_stats.lock().unwrap();
        insert_shreds_stats.update(new_insertion_shreds_stats, broadcast_shred_batch_info);
    }

    fn broadcast(
        &mut self,
        sock: &UdpSocket,
        cluster_info: &ClusterInfo,
        shreds: Arc<Vec<Shred>>,
        broadcast_shred_batch_info: Option<BroadcastShredBatchInfo>,
        bank_forks: &RwLock<BankForks>,
        quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
    ) -> Result<()> {
        trace!("Broadcasting {:?} shreds", shreds.len());
        let mut transmit_stats = TransmitShredsStats::default();
        // Broadcast the shreds
        let mut transmit_time = Measure::start("broadcast_shreds");

        broadcast_shreds(
            sock,
            &shreds,
            &self.cluster_nodes_cache,
            &self.last_datapoint_submit,
            &mut transmit_stats,
            cluster_info,
            bank_forks,
            cluster_info.socket_addr_space(),
            quic_endpoint_sender,
        )?;
        transmit_time.stop();

        transmit_stats.transmit_elapsed = transmit_time.as_us();
        transmit_stats.num_shreds = shreds.len();

        // Process metrics
        self.update_transmit_metrics(&transmit_stats, &broadcast_shred_batch_info);
        Ok(())
    }

    fn update_transmit_metrics(
        &mut self,
        new_transmit_shreds_stats: &TransmitShredsStats,
        broadcast_shred_batch_info: &Option<BroadcastShredBatchInfo>,
    ) {
        let mut transmit_shreds_stats = self.transmit_shreds_stats.lock().unwrap();
        transmit_shreds_stats.update(new_transmit_shreds_stats, broadcast_shred_batch_info);
    }

    fn report_and_reset_stats(&mut self, was_interrupted: bool) {
        let (name, slot_broadcast_time) = if was_interrupted {
            ("broadcast-process-shreds-interrupted-stats", None)
        } else {
            (
                "broadcast-process-shreds-stats",
                Some(self.slot_broadcast_start.elapsed()),
            )
        };

        self.process_shreds_stats.submit(
            name,
            self.slot,
            self.next_shred_index, // num_data_shreds
            self.next_code_index,  // num_coding_shreds
            slot_broadcast_time,
        );
    }
}

impl BroadcastRun for StandardBroadcastRun {
    fn run(
        &mut self,
        keypair: &Keypair,
        blockstore: &Blockstore,
        receiver: &Receiver<WorkingBankEntry>,
        socket_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        blockstore_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
    ) -> Result<()> {
        let receive_results = broadcast_utils::recv_slot_entries(receiver)?;
        // TODO: Confirm that last chunk of coding shreds
        // will not be lost or delayed for too long.
        self.process_receive_results(
            keypair,
            blockstore,
            socket_sender,
            blockstore_sender,
            receive_results,
        )
    }
    fn transmit(
        &mut self,
        receiver: &TransmitReceiver,
        cluster_info: &ClusterInfo,
        sock: &UdpSocket,
        bank_forks: &RwLock<BankForks>,
        quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
    ) -> Result<()> {
        let (shreds, batch_info) = receiver.recv()?;
        self.broadcast(
            sock,
            cluster_info,
            shreds,
            batch_info,
            bank_forks,
            quic_endpoint_sender,
        )
    }
    fn record(&mut self, receiver: &RecordReceiver, blockstore: &Blockstore) -> Result<()> {
        let (shreds, slot_start_ts) = receiver.recv()?;
        self.insert(blockstore, shreds, slot_start_ts);
        Ok(())
    }
}

fn should_chain_merkle_shreds(_slot: Slot, cluster_type: ClusterType) -> bool {
    cluster_type == ClusterType::Development
}
