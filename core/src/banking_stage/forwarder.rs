use {
    super::{BankingStageStats, ForwardOption},
    crate::{
        forward_packet_batches_by_accounts::ForwardPacketBatchesByAccounts,
        leader_slot_banking_stage_metrics::LeaderSlotMetricsTracker,
        next_leader::{next_leader_tpu_forwards, next_leader_tpu_vote},
        tracer_packet_stats::TracerPacketStats,
        unprocessed_transaction_storage::UnprocessedTransactionStorage,
    },
    solana_client::{connection_cache::ConnectionCache, tpu_connection::TpuConnection},
    solana_gossip::cluster_info::ClusterInfo,
    solana_measure::measure_us,
    solana_perf::{data_budget::DataBudget, packet::Packet},
    solana_poh::poh_recorder::PohRecorder,
    solana_runtime::bank_forks::BankForks,
    solana_sdk::{pubkey::Pubkey, transport::TransportError},
    solana_streamer::sendmmsg::batch_send,
    std::{
        iter::repeat,
        net::{SocketAddr, UdpSocket},
        sync::{atomic::Ordering, Arc, RwLock},
    },
};

pub(crate) struct Forwarder {
    poh_recorder: Arc<RwLock<PohRecorder>>,
    bank_forks: Arc<RwLock<BankForks>>,
    socket: UdpSocket,
    cluster_info: Arc<ClusterInfo>,
    connection_cache: Arc<ConnectionCache>,
    data_budget: Arc<DataBudget>,
}

impl Forwarder {
    pub(crate) fn new(
        poh_recorder: Arc<RwLock<PohRecorder>>,
        bank_forks: Arc<RwLock<BankForks>>,
        cluster_info: Arc<ClusterInfo>,
        connection_cache: Arc<ConnectionCache>,
        data_budget: Arc<DataBudget>,
    ) -> Self {
        Self {
            poh_recorder,
            bank_forks,
            socket: UdpSocket::bind("0.0.0.0:0").unwrap(),
            cluster_info,
            connection_cache,
            data_budget,
        }
    }

    pub(crate) fn handle_forwarding(
        &self,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        hold: bool,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        banking_stage_stats: &BankingStageStats,
        tracer_packet_stats: &mut TracerPacketStats,
    ) {
        let forward_option = unprocessed_transaction_storage.forward_option();

        // get current root bank from bank_forks, use it to sanitize transaction and
        // load all accounts from address loader;
        let current_bank = self.bank_forks.read().unwrap().root_bank();

        let mut forward_packet_batches_by_accounts =
            ForwardPacketBatchesByAccounts::new_with_default_batch_limits();

        // sanitize and filter packets that are no longer valid (could be too old, a duplicate of something
        // already processed), then add to forwarding buffer.
        let filter_forwarding_result = unprocessed_transaction_storage
            .filter_forwardable_packets_and_add_batches(
                current_bank,
                &mut forward_packet_batches_by_accounts,
            );
        slot_metrics_tracker.increment_transactions_from_packets_us(
            filter_forwarding_result.total_packet_conversion_us,
        );
        banking_stage_stats.packet_conversion_elapsed.fetch_add(
            filter_forwarding_result.total_packet_conversion_us,
            Ordering::Relaxed,
        );
        banking_stage_stats
            .filter_pending_packets_elapsed
            .fetch_add(
                filter_forwarding_result.total_filter_packets_us,
                Ordering::Relaxed,
            );

        forward_packet_batches_by_accounts
            .iter_batches()
            .filter(|&batch| !batch.is_empty())
            .for_each(|forward_batch| {
                slot_metrics_tracker.increment_forwardable_batches_count(1);

                let batched_forwardable_packets_count = forward_batch.len();
                let (_forward_result, sucessful_forwarded_packets_count, leader_pubkey) = self
                    .forward_buffered_packets(
                        &forward_option,
                        forward_batch.get_forwardable_packets(),
                        banking_stage_stats,
                    );

                if let Some(leader_pubkey) = leader_pubkey {
                    tracer_packet_stats.increment_total_forwardable_tracer_packets(
                        filter_forwarding_result.total_forwardable_tracer_packets,
                        leader_pubkey,
                    );
                }
                let failed_forwarded_packets_count = batched_forwardable_packets_count
                    .saturating_sub(sucessful_forwarded_packets_count);

                if failed_forwarded_packets_count > 0 {
                    slot_metrics_tracker.increment_failed_forwarded_packets_count(
                        failed_forwarded_packets_count as u64,
                    );
                    slot_metrics_tracker.increment_packet_batch_forward_failure_count(1);
                }

                if sucessful_forwarded_packets_count > 0 {
                    slot_metrics_tracker.increment_successful_forwarded_packets_count(
                        sucessful_forwarded_packets_count as u64,
                    );
                }
            });

        if !hold {
            slot_metrics_tracker.increment_cleared_from_buffer_after_forward_count(
                filter_forwarding_result.total_forwardable_packets as u64,
            );
            tracer_packet_stats.increment_total_cleared_from_buffer_after_forward(
                filter_forwarding_result.total_tracer_packets_in_buffer,
            );
            unprocessed_transaction_storage.clear_forwarded_packets();
        }
    }

    /// Forwards all valid, unprocessed packets in the iterator, up to a rate limit.
    /// Returns whether forwarding succeeded, the number of attempted forwarded packets
    /// if any, the time spent forwarding in us, and the leader pubkey if any.
    fn forward_packets<'a>(
        &self,
        forward_option: &ForwardOption,
        forwardable_packets: impl Iterator<Item = &'a Packet>,
    ) -> (
        std::result::Result<(), TransportError>,
        usize,
        u64,
        Option<Pubkey>,
    ) {
        let Some((leader_pubkey, addr)) = self.get_leader_and_addr(forward_option) else {
            return (Ok(()), 0, 0, None);
        };

        self.update_data_budget();
        let packet_vec: Vec<_> = forwardable_packets
            .filter(|p| !p.meta().forwarded())
            .filter(|p| self.data_budget.take(p.meta().size))
            .filter_map(|p| p.data(..).map(|data| data.to_vec()))
            .collect();

        let packet_vec_len = packet_vec.len();
        // TODO: see https://github.com/solana-labs/solana/issues/23819
        // fix this so returns the correct number of succeeded packets
        // when there's an error sending the batch. This was left as-is for now
        // in favor of shipping Quic support, which was considered higher-priority
        let (res, forward_us) = if !packet_vec.is_empty() {
            measure_us!(self.forward(forward_option, packet_vec, &addr))
        } else {
            (Ok(()), 0)
        };

        (res, packet_vec_len, forward_us, Some(leader_pubkey))
    }

    /// Forwards all valid, unprocessed packets in the buffer, up to a rate limit. Returns
    /// the number of successfully forwarded packets in second part of tuple
    fn forward_buffered_packets<'a>(
        &self,
        forward_option: &ForwardOption,
        forwardable_packets: impl Iterator<Item = &'a Packet>,
        banking_stage_stats: &BankingStageStats,
    ) -> (
        std::result::Result<(), TransportError>,
        usize,
        Option<Pubkey>,
    ) {
        let (res, num_packets, forward_us, leader_pubkey) =
            self.forward_packets(forward_option, forwardable_packets);

        if num_packets > 0 {
            inc_new_counter_info!("banking_stage-forwarded_packets", num_packets);
            if let ForwardOption::ForwardTpuVote = forward_option {
                banking_stage_stats
                    .forwarded_vote_count
                    .fetch_add(num_packets, Ordering::Relaxed);
            } else {
                banking_stage_stats
                    .forwarded_transaction_count
                    .fetch_add(num_packets, Ordering::Relaxed);
            }

            inc_new_counter_info!("banking_stage-forward-us", forward_us as usize, 1000, 1000);

            if res.is_err() {
                inc_new_counter_info!("banking_stage-forward_packets-failed-batches", 1);
            }
        }

        (res, num_packets, leader_pubkey)
    }

    /// Get the pubkey and socket address for the leader to forward to
    fn get_leader_and_addr(&self, forward_option: &ForwardOption) -> Option<(Pubkey, SocketAddr)> {
        match forward_option {
            ForwardOption::NotForward => None,
            ForwardOption::ForwardTransaction => {
                next_leader_tpu_forwards(&self.cluster_info, &self.poh_recorder)
            }

            ForwardOption::ForwardTpuVote => {
                next_leader_tpu_vote(&self.cluster_info, &self.poh_recorder)
            }
        }
    }

    /// Re-fill the data budget if enough time has passed
    fn update_data_budget(&self) {
        const INTERVAL_MS: u64 = 100;
        // 12 MB outbound limit per second
        const MAX_BYTES_PER_SECOND: usize = 12_000_000;
        const MAX_BYTES_PER_INTERVAL: usize = MAX_BYTES_PER_SECOND * INTERVAL_MS as usize / 1000;
        const MAX_BYTES_BUDGET: usize = MAX_BYTES_PER_INTERVAL * 5;
        self.data_budget.update(INTERVAL_MS, |bytes| {
            std::cmp::min(
                bytes.saturating_add(MAX_BYTES_PER_INTERVAL),
                MAX_BYTES_BUDGET,
            )
        });
    }

    fn forward(
        &self,
        forward_option: &ForwardOption,
        packet_vec: Vec<Vec<u8>>,
        addr: &SocketAddr,
    ) -> Result<(), TransportError> {
        match forward_option {
            ForwardOption::ForwardTpuVote => {
                // The vote must be forwarded using only UDP.
                let pkts: Vec<_> = packet_vec.into_iter().zip(repeat(*addr)).collect();
                batch_send(&self.socket, &pkts).map_err(|err| err.into())
            }
            ForwardOption::ForwardTransaction => {
                // All other transactions can be forwarded using QUIC, get_connection() will use
                // system wide setting to pick the correct connection object.
                let conn = self.connection_cache.get_connection(addr);
                conn.send_data_batch_async(packet_vec)
            }
            ForwardOption::NotForward => panic!("should not forward"),
        }
    }
}
