#![cfg(feature = "dev-context-only-utils")]
use {
    crate::{
        banking_stage::BankingStage,
        banking_trace::{
            BankingPacketBatch, BankingTracer, ChannelLabel, TimedTracedEvent, TracedEvent,
            BANKING_TRACE_DIR_DEFAULT_BYTE_LIMIT, BASENAME,
        },
        validator::BlockProductionMethod,
    },
    bincode::deserialize_from,
    crossbeam_channel::unbounded,
    log::*,
    solana_client::connection_cache::ConnectionCache,
    solana_gossip::cluster_info::{ClusterInfo, Node},
    solana_ledger::{
        blockstore::{Blockstore, PurgeType},
        leader_schedule_cache::LeaderScheduleCache,
    },
    solana_poh::{
        poh_recorder::{PohRecorder, GRACE_TICKS_FACTOR, MAX_GRACE_SLOTS},
        poh_service::{PohService, DEFAULT_HASHES_PER_BATCH, DEFAULT_PINNED_CPU_CORE},
    },
    solana_runtime::{
        bank::{Bank, HashOverrides},
        bank_forks::BankForks,
        prioritization_fee_cache::PrioritizationFeeCache,
    },
    solana_sdk::{
        genesis_config::GenesisConfig, shred_version::compute_shred_version, slot_history::Slot,
    },
    solana_streamer::socket::SocketAddrSpace,
    solana_turbine::broadcast_stage::BroadcastStageType,
    std::{
        collections::BTreeMap,
        fs::File,
        io::{self, BufRead, BufReader},
        net::{Ipv4Addr, UdpSocket},
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, sleep},
        time::{Duration, SystemTime},
    },
    thiserror::Error,
};

// This creates a simulated environment around the banking stage to reproduce leader's blocks based
// on recorded banking trace events (`TimedTracedEvent`).
//
// The task of banking stage at the highest level is to pack transactions into their blocks as much
// as possible for scheduled fixed duration. So, there's 3 abstract inputs to simulate: blocks,
// time, and transactions.
//
// In the context of simulation, the first two are simple; both are well defined.
//
// For ancestor blocks, we firstly replay certain number of blocks immediately up to target
// simulation leader's slot with halt_at_slot mechanism, possibly priming various caches,
// ultimately freezing the ancestor block with expected and deterministic hashes.
//
// After replay, a minor tweak is applied during simulation: we forcibly override leader's hashes
// as simulated banking stage creates them, using recorded `BlockAndBankHash` events. This is to
// provide undistinguishable sysvars to TX execution and identical TX age resolution as the
// simulation goes on. Otherwise, vast majority of tx processing would differ because simulated
// block's hashes would definitely differ than the recorded ones as slight block composition
// difference is inevitable.
//
// For poh time, we just use PohRecorder as same as the real environment, which is just 400ms
// timer, external to banking stage and thus mostly irrelevant to banking stage performance. For
// wall time, we use the first BankStatus::BlockAndBankHash and `SystemTime::now()` to define T=0
// for simulation. Then, simulation progress is timed accordingly. As a context, this syncing is
// needed because all trace events are recorded in UTC, not relative to poh nor to leader schedule
// for simplicity at recording.
//
// Lastly, here's the last and most complicated input to simulate: transactions.
//
// A bit closer look of transaction load profile is like below, regardless of internal banking
// implementation and simulation:
//
// There's ever `BufferedPacketsDecision::Hold`-ed transactions to be processed as the first leader
// slot nears. This is due to solana's general tx broadcast strategy of node's forwarding and
// client's submission, which are unlikely to chabge soon. So, we take this as granted. Then, any
// initial leader block creation starts with rather large number of schedule-able transactions.
// Also, note that additional transactions arrive for the 4 leader slot window (roughly ~1.6
// seconds).
//
// Simulation have to mimic this load pattern while being agnostic to internal bnaking impl as much
// as possible. For that agnostic objective, `TracedSender`s are sneaked into the SigVerify stage
// and gossip subsystem by `BankingTracer` to trace **all** of `BankingPacketBatch`s' exact payload
// and _sender_'s timing with `SystemTime::now()` for all `ChannelLabel`s. This deliberate tracing
// placement is not to be affected by any banking-tage's capping (if any) and its channel
// consumption pattern.
//
// BankingSimulator consists of 2 phases chronologically: warm-up and on-the-fly. The 2 phases are
// segregated by the aforementioned T=0.
//
// Both phases just sends BankingPacketBatch in the same fashion, pretending to be sigveirfy
// stage/gossip while burning 1 thread to busy loop for precise T=N at ~1us granularity.
//
// Warm up is defined as T=-N secs using slot distance between immediate ancestor of first
// simulated block and root block. As soon as warm up is initiated, we invoke
// `BankingStage::new_num_threads()` as well to simulate the pre-leader slot's tx-buffering time.
pub struct BankingSimulator {
    banking_trace_events: BankingTraceEvents,
    first_simulated_slot: Slot,
}

#[derive(Error, Debug)]
pub enum SimulateError {
    #[error("IO Error: {0}")]
    IoError(#[from] io::Error),

    #[error("Deserialization Error: {0}")]
    SerializeError(#[from] bincode::Error),
}

pub struct BankingTraceEvents {
    /// BTreeMap is intentional because events could be unordered slightly due to tracing jitter.
    packet_batches_by_time: BTreeMap<SystemTime, (ChannelLabel, BankingPacketBatch)>,
    freeze_time_by_slot: BTreeMap<Slot, SystemTime>,
    hash_overrides: HashOverrides,
}

impl BankingTraceEvents {
    fn read_event_file(
        events: &mut Vec<TimedTracedEvent>,
        event_file_path: &PathBuf,
    ) -> Result<(), SimulateError> {
        let mut reader = BufReader::new(File::open(event_file_path)?);

        loop {
            events.push(deserialize_from(&mut reader)?);

            if reader.fill_buf()?.is_empty() {
                // EOF is reached at a correct deserialization boundary.
                // We're looking-ahead the buf, so NOT calling reader.consume(..) is correct.
                break;
            }
        }

        Ok(())
    }

    pub fn load(event_file_paths: &[PathBuf]) -> Result<Self, SimulateError> {
        let mut events = vec![];
        for event_file_path in event_file_paths {
            let old_len = events.len();
            let _ = Self::read_event_file(&mut events, event_file_path).inspect_err(|error| {
                error!(
                    "Reading {event_file_path:?} failed after {} events: {:?} due to file corruption or unclearn validator shutdown",
                    events.len() - old_len,
                    error
                );
            });
            info!(
                "Read {} events from {:?}",
                events.len() - old_len,
                event_file_path
            );
        }

        let mut packet_batches_by_time = BTreeMap::new();
        let mut freeze_time_by_slot = BTreeMap::new();
        let mut hash_overrides = HashOverrides::default();
        for TimedTracedEvent(event_time, event) in events {
            match event {
                TracedEvent::PacketBatch(label, batch) => {
                    // Deserialized PacketBatches will mostly be ordered by event_time, but this
                    // isn't guaranteed when traced, because time are measured by multiple _sender_
                    // threads withtout synchnotization among them to avoid overhead.
                    //
                    // Also, there's a possiblity of system clock change. In this case,
                    // the simulation is meaningless, though...
                    //
                    // Somewhat naively assume that event_times (nanosecond resolution) won't
                    // collide.
                    let is_new = packet_batches_by_time
                        .insert(event_time, (label, batch))
                        .is_none();
                    assert!(is_new);
                }
                TracedEvent::BlockAndBankHash(slot, blockhash, bank_hash) => {
                    let is_new = freeze_time_by_slot.insert(slot, event_time).is_none();
                    hash_overrides.add_override(slot, blockhash, bank_hash);
                    assert!(is_new);
                }
            }
        }

        Ok(Self {
            packet_batches_by_time,
            freeze_time_by_slot,
            hash_overrides,
        })
    }

    pub fn hash_overrides(&self) -> &HashOverrides {
        &self.hash_overrides
    }
}

impl BankingSimulator {
    pub fn new(banking_trace_events: BankingTraceEvents, first_simulated_slot: Slot) -> Self {
        Self {
            banking_trace_events,
            first_simulated_slot,
        }
    }

    pub fn parent_slot(&self) -> Option<Slot> {
        self.banking_trace_events
            .freeze_time_by_slot
            .range(..self.first_simulated_slot)
            .last()
            .map(|(slot, _time)| slot)
            .copied()
    }

    pub fn start(
        mut self,
        genesis_config: GenesisConfig,
        bank_forks: Arc<RwLock<BankForks>>,
        blockstore: Arc<Blockstore>,
        block_production_method: BlockProductionMethod,
    ) -> Result<(), SimulateError> {
        let mut bank = bank_forks
            .read()
            .unwrap()
            .working_bank_with_scheduler()
            .clone_with_scheduler();

        let leader_schedule_cache = Arc::new(LeaderScheduleCache::new_from_bank(&bank));
        let parent_slot = bank.slot();
        assert_eq!(Some(parent_slot), self.parent_slot());

        let simulated_leader = leader_schedule_cache
            .slot_leader_at(self.first_simulated_slot, None)
            .unwrap();
        info!(
            "Simulated leader and slot: {}, {}",
            simulated_leader, self.first_simulated_slot
        );

        let exit = Arc::new(AtomicBool::default());

        if let Some(end_slot) = blockstore
            .slot_meta_iterator(self.first_simulated_slot)
            .unwrap()
            .map(|(s, _)| s)
            .last()
        {
            info!("purging slots {}, {}", self.first_simulated_slot, end_slot);
            blockstore.purge_from_next_slots(self.first_simulated_slot, end_slot);
            blockstore.purge_slots(self.first_simulated_slot, end_slot, PurgeType::Exact);
            info!("done: purging");
        } else {
            info!("skipping purging...");
        }

        info!("Poh is starting!");

        let (poh_recorder, entry_receiver, record_receiver) = PohRecorder::new_with_clear_signal(
            bank.tick_height(),
            bank.last_blockhash(),
            bank.clone(),
            None,
            bank.ticks_per_slot(),
            false,
            blockstore.clone(),
            blockstore.get_new_shred_signal(0),
            &leader_schedule_cache,
            &genesis_config.poh_config,
            None,
            exit.clone(),
        );
        let poh_recorder = Arc::new(RwLock::new(poh_recorder));
        let poh_service = PohService::new(
            poh_recorder.clone(),
            &genesis_config.poh_config,
            exit.clone(),
            bank.ticks_per_slot(),
            DEFAULT_PINNED_CPU_CORE,
            DEFAULT_HASHES_PER_BATCH,
            record_receiver,
        );
        let warmup_duration = Duration::from_secs(12);

        let (banking_retracer, retracer_thread) = BankingTracer::new(Some((
            &blockstore.banking_retracer_path(),
            exit.clone(),
            BANKING_TRACE_DIR_DEFAULT_BYTE_LIMIT,
        )))
        .unwrap();
        if banking_retracer.is_enabled() {
            info!(
                "Enabled banking retracer (dir_byte_limit: {})",
                BANKING_TRACE_DIR_DEFAULT_BYTE_LIMIT,
            );
        } else {
            info!("Disabled banking retracer");
        }

        let (non_vote_sender, non_vote_receiver) = banking_retracer.create_channel_non_vote();
        let (tpu_vote_sender, tpu_vote_receiver) = banking_retracer.create_channel_tpu_vote();
        let (gossip_vote_sender, gossip_vote_receiver) =
            banking_retracer.create_channel_gossip_vote();

        let cluster_info = Arc::new(ClusterInfo::new_with_dummy_keypair(
            Node::new_localhost_with_pubkey(&simulated_leader).info,
            SocketAddrSpace::Unspecified,
        ));
        let connection_cache = Arc::new(ConnectionCache::new("connection_kache!"));
        let (replay_vote_sender, _replay_vote_receiver) = unbounded();
        let (retransmit_slots_sender, retransmit_slots_receiver) = unbounded();
        let shred_version = compute_shred_version(
            &genesis_config.hash(),
            Some(&bank_forks.read().unwrap().root_bank().hard_forks()),
        );
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let broadcast_stage = BroadcastStageType::Standard.new_broadcast_stage(
            vec![UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap()],
            cluster_info.clone(),
            entry_receiver,
            retransmit_slots_receiver,
            exit.clone(),
            blockstore.clone(),
            bank_forks.clone(),
            shred_version,
            sender,
        );

        info!("Start banking stage!...");
        let prioritization_fee_cache = &Arc::new(PrioritizationFeeCache::new(0u64));
        let banking_stage = BankingStage::new_num_threads(
            block_production_method.clone(),
            &cluster_info,
            &poh_recorder,
            non_vote_receiver,
            tpu_vote_receiver,
            gossip_vote_receiver,
            BankingStage::num_threads(),
            None,
            replay_vote_sender,
            None,
            connection_cache,
            bank_forks.clone(),
            prioritization_fee_cache,
            false,
        );

        let (&slot_before_next_leader_slot, &raw_base_event_time) = self
            .banking_trace_events
            .freeze_time_by_slot
            .range(parent_slot..)
            .next()
            .expect("timed hashes");

        let base_event_time = raw_base_event_time - warmup_duration;
        let base_simulation_time = SystemTime::now();

        let sender_thread = thread::Builder::new().name("solSimSender".into()).spawn({
            let exit = exit.clone();

            move || {
                let (mut non_vote_count, mut non_vote_tx_count) = (0, 0);
                let (mut tpu_vote_count, mut tpu_vote_tx_count) = (0, 0);
                let (mut gossip_vote_count, mut gossip_vote_tx_count) = (0, 0);

                info!("start sending!...");
                let timed_batches_to_send = self.banking_trace_events.packet_batches_by_time.split_off(&base_event_time);
                let event_count = timed_batches_to_send.len();
                let batch_and_tx_counts = timed_batches_to_send.values().map(|(_label, batches_with_stats)| {
                    let batches = &batches_with_stats.0;
                    (
                        batches.len(),
                        batches.iter().map(|batch| batch.len()).sum::<usize>(),
                    )
                }).collect::<Vec<_>>();
                // Convert to a large plain old Vec and drain on it, finally dropping it outside
                // the simulation loop to avoid jitter due to interleaved deallocs of BTreeMap.
                let mut timed_batches_to_send = timed_batches_to_send
                    .into_iter()
                    .zip(batch_and_tx_counts.into_iter())
                    .collect::<Vec<_>>();
                info!(
                    "simulating banking trace events: {} out of {}, starting at slot {} (based on {} from traced event slot: {}) (warmup: -{:?})",
                    event_count,
                    self.banking_trace_events.packet_batches_by_time.len(),
                    self.first_simulated_slot,
                    {
                        let raw_base_event_time: chrono::DateTime<chrono::Utc> = raw_base_event_time.into();
                        raw_base_event_time.format("%Y-%m-%d %H:%M:%S.%f")
                    },
                    slot_before_next_leader_slot,
                    warmup_duration,
                );
                let mut simulation_duration_since_base = Duration::default();
                let (
                    mut last_log_duration,
                    mut last_tx_count,
                    mut last_non_vote_count,
                    mut last_tpu_vote_tx_count,
                    mut last_gossip_vote_tx_count
                ) = (Duration::default(), 0, 0, 0, 0);
                for ((event_time, (label, batches_with_stats)), (batch_count, tx_count)) in
                    timed_batches_to_send.drain(..) {
                    let required_duration_since_base =
                        event_time.duration_since(base_event_time).unwrap();

                    // Busy loop for most accurate sending timings
                    while simulation_duration_since_base < required_duration_since_base {
                        let current_simulation_time = SystemTime::now();
                        simulation_duration_since_base = current_simulation_time
                            .duration_since(base_simulation_time)
                            .unwrap();
                    }

                    let sender = match label {
                        ChannelLabel::NonVote => &non_vote_sender,
                        ChannelLabel::TpuVote => &tpu_vote_sender,
                        ChannelLabel::GossipVote => &gossip_vote_sender,
                        ChannelLabel::Dummy => unreachable!(),
                    };
                    sender.send(batches_with_stats).unwrap();

                    debug!(
                        "sent {:?} {} batches ({} txes)",
                        label, batch_count, tx_count
                    );
                    let (total_batch_count, total_tx_count) = match label {
                        ChannelLabel::NonVote => (&mut non_vote_count, &mut non_vote_tx_count),
                        ChannelLabel::TpuVote => (&mut tpu_vote_count, &mut tpu_vote_tx_count),
                        ChannelLabel::GossipVote => (&mut gossip_vote_count, &mut gossip_vote_tx_count),
                        ChannelLabel::Dummy => unreachable!(),
                    };
                    *total_batch_count += batch_count;
                    *total_tx_count += tx_count;

                    let log_interval = simulation_duration_since_base - last_log_duration;
                    if log_interval > Duration::from_millis(100) {
                        let current_tx_count = non_vote_tx_count + tpu_vote_tx_count + gossip_vote_tx_count;
                        let duration =log_interval.as_secs_f64();
                        let tps = (current_tx_count - last_tx_count) as f64 / duration;
                        let non_vote_tps = (non_vote_tx_count - last_non_vote_count) as f64 / duration;
                        let tpu_vote_tps = (tpu_vote_tx_count - last_tpu_vote_tx_count) as f64 / duration;
                        let gossip_vote_tps = (gossip_vote_tx_count - last_gossip_vote_tx_count) as f64 / duration;
                        info!(
                            "senders(non-,tpu-,gossip-vote): tps: {} (={}+{}+{}) over {:?} not-recved: ({}+{}+{})",
                            tps as u64,
                            non_vote_tps as u64,
                            tpu_vote_tps as u64,
                            gossip_vote_tps as u64,
                            log_interval,
                            non_vote_sender.len(),
                            tpu_vote_sender.len(),
                            gossip_vote_sender.len(),
                        );
                        last_log_duration = simulation_duration_since_base;
                        last_tx_count = current_tx_count;
                        (last_non_vote_count, last_tpu_vote_tx_count, last_gossip_vote_tx_count) = (
                            non_vote_tx_count, tpu_vote_tx_count, gossip_vote_count
                        );
                    }

                    if exit.load(Ordering::Relaxed) {
                        break;
                    }
                }
                info!(
                    "terminating to send...: non_vote: {} ({}), tpu_vote: {} ({}), gossip_vote: {} ({})",
                    non_vote_count,
                    non_vote_tx_count,
                    tpu_vote_count,
                    tpu_vote_tx_count,
                    gossip_vote_count,
                    gossip_vote_tx_count
                );
                drop(timed_batches_to_send);
                // hold these senders in join_handle to control banking stage termination!
                (non_vote_sender, tpu_vote_sender, gossip_vote_sender)
            }
        })?;

        sleep(warmup_duration);
        info!("warmup done!");

        loop {
            if poh_recorder.read().unwrap().bank().is_none() {
                let next_leader_slot = leader_schedule_cache.next_leader_slot(
                    &simulated_leader,
                    bank.slot(),
                    &bank,
                    Some(&blockstore),
                    GRACE_TICKS_FACTOR * MAX_GRACE_SLOTS,
                );
                debug!("{next_leader_slot:?}");
                poh_recorder
                    .write()
                    .unwrap()
                    .reset(bank.clone_without_scheduler(), next_leader_slot);
                info!("Bank::new_from_parent()!");

                let old_slot = bank.slot();
                if let Some(event_time) =
                    self.banking_trace_events.freeze_time_by_slot.get(&old_slot)
                {
                    if log_enabled!(log::Level::Info) {
                        let current_simulation_time = SystemTime::now();
                        let elapsed_simulation_time = current_simulation_time
                            .duration_since(base_simulation_time)
                            .unwrap();
                        let elapsed_event_time =
                            event_time.duration_since(base_event_time).unwrap();
                        info!(
                            "jitter(parent_slot: {}): {}{:?} (sim: {:?} event: {:?})",
                            old_slot,
                            if elapsed_simulation_time > elapsed_event_time {
                                "+"
                            } else {
                                "-"
                            },
                            if elapsed_simulation_time > elapsed_event_time {
                                elapsed_simulation_time - elapsed_event_time
                            } else {
                                elapsed_event_time - elapsed_simulation_time
                            },
                            elapsed_simulation_time,
                            elapsed_event_time,
                        );
                    }
                }
                bank.freeze();
                let new_slot = if bank.slot() == parent_slot {
                    info!("initial leader block!");
                    self.first_simulated_slot
                } else {
                    info!("next leader block!");
                    bank.slot() + 1
                };
                info!("new leader bank slot: {new_slot}");
                let new_leader = leader_schedule_cache
                    .slot_leader_at(new_slot, None)
                    .unwrap();
                if simulated_leader != new_leader {
                    info!(
                        "bank cost: slot: {} {:?} (frozen)",
                        bank.slot(),
                        bank.read_cost_tracker()
                            .map(|t| (t.block_cost(), t.vote_cost()))
                            .unwrap()
                    );
                    info!(
                        "{} isn't leader anymore at slot {}; new leader: {}",
                        simulated_leader, new_slot, new_leader
                    );
                    break;
                } else if sender_thread.is_finished() {
                    warn!("sender thread existed maybe due to completion of sending traced events");
                    break;
                }
                let new_bank = Bank::new_from_parent(
                    bank.clone_without_scheduler(),
                    &simulated_leader,
                    new_slot,
                );
                // make sure parent is frozen for finalized hashes via the above
                // new()-ing of its child bank
                banking_retracer.hash_event(bank.slot(), &bank.last_blockhash(), &bank.hash());
                if *bank.collector_id() == simulated_leader {
                    info!(
                        "bank cost: slot: {} {:?} (frozen)",
                        bank.slot(),
                        bank.read_cost_tracker()
                            .map(|t| (t.block_cost(), t.vote_cost()))
                            .unwrap()
                    );
                }
                retransmit_slots_sender.send(bank.slot()).unwrap();
                bank_forks.write().unwrap().insert(new_bank);
                bank = bank_forks
                    .read()
                    .unwrap()
                    .working_bank_with_scheduler()
                    .clone_with_scheduler();
                poh_recorder
                    .write()
                    .unwrap()
                    .set_bank(bank.clone_with_scheduler(), false);
            } else {
                debug!(
                    "bank cost: slot: {} {:?} (ongoing)",
                    bank.slot(),
                    bank.read_cost_tracker()
                        .map(|t| (t.block_cost(), t.vote_cost()))
                        .unwrap()
                );
            }

            sleep(Duration::from_millis(10));
        }

        info!("Sleeping a bit before signaling exit");
        sleep(Duration::from_millis(100));
        exit.store(true, Ordering::Relaxed);

        // The order is important. consuming sender_thread by joining will terminate banking_stage,
        // in turn banking_retracer thread will termianl
        sender_thread.join().unwrap();
        banking_stage.join().unwrap();
        poh_service.join().unwrap();
        if let Some(retracer_thread) = retracer_thread {
            retracer_thread.join().unwrap().unwrap();
        }

        info!("Joining broadcast stage...");
        drop(poh_recorder);
        drop(retransmit_slots_sender);
        broadcast_stage.join().unwrap();

        Ok(())
    }

    pub fn event_file_name(index: usize) -> String {
        if index == 0 {
            BASENAME.to_string()
        } else {
            format!("{BASENAME}.{index}")
        }
    }
}
