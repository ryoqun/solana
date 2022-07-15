use {
    crate::{
        quic::{configure_server, QuicServerError, StreamStats},
        streamer::StakedNodes,
        tls_certificates::get_pubkey_from_tls_certificate,
    },
    crossbeam_channel::Sender,
    futures_util::stream::StreamExt,
    indexmap::map::{Entry, IndexMap},
    percentage::Percentage,
    quinn::{
        Connecting, Connection, Endpoint, EndpointConfig, Incoming, IncomingUniStreams,
        NewConnection, VarInt,
    },
    rand::{thread_rng, Rng},
    solana_perf::packet::PacketBatch,
    solana_sdk::{
        packet::{Packet, PACKET_DATA_SIZE},
        pubkey::Pubkey,
        quic::{QUIC_CONNECTION_HANDSHAKE_TIMEOUT_MS, QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS},
        signature::Keypair,
        timing,
    },
    std::{
        net::{IpAddr, SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex, MutexGuard, RwLock,
        },
        time::{Duration, Instant},
    },
    tokio::{
        task::JoinHandle,
        time::{sleep, timeout},
    },
};

const QUIC_TOTAL_STAKED_CONCURRENT_STREAMS: f64 = 100_000f64;
const WAIT_FOR_STREAM_TIMEOUT_MS: u64 = 100;

pub const ALPN_TPU_PROTOCOL_ID: &[u8] = b"solana-tpu";

#[allow(clippy::too_many_arguments)]
pub fn spawn_server(
    sock: UdpSocket,
    keypair: &Keypair,
    gossip_host: IpAddr,
    packet_sender: Sender<PacketBatch>,
    exit: Arc<AtomicBool>,
    max_connections_per_peer: usize,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    max_staked_connections: usize,
    max_unstaked_connections: usize,
    stats: Arc<StreamStats>,
) -> Result<JoinHandle<()>, QuicServerError> {
    let (config, _cert) = configure_server(keypair, gossip_host)?;

    let (_, incoming) = {
        Endpoint::new(EndpointConfig::default(), Some(config), sock)
            .map_err(|_e| QuicServerError::EndpointFailed)?
    };

    let handle = tokio::spawn(run_server(
        incoming,
        packet_sender,
        exit,
        max_connections_per_peer,
        staked_nodes,
        max_staked_connections,
        max_unstaked_connections,
        stats,
    ));
    Ok(handle)
}

pub async fn run_server(
    mut incoming: Incoming,
    packet_sender: Sender<PacketBatch>,
    exit: Arc<AtomicBool>,
    max_connections_per_peer: usize,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    max_staked_connections: usize,
    max_unstaked_connections: usize,
    stats: Arc<StreamStats>,
) {
    debug!("spawn quic server");
    let mut last_datapoint = Instant::now();
    let unstaked_connection_table: Arc<Mutex<ConnectionTable>> = Arc::new(Mutex::new(
        ConnectionTable::new(ConnectionPeerType::Unstaked),
    ));
    let staked_connection_table: Arc<Mutex<ConnectionTable>> =
        Arc::new(Mutex::new(ConnectionTable::new(ConnectionPeerType::Staked)));
    while !exit.load(Ordering::Relaxed) {
        const WAIT_FOR_CONNECTION_TIMEOUT_MS: u64 = 1000;
        const WAIT_BETWEEN_NEW_CONNECTIONS_US: u64 = 1000;
        let timeout_connection = timeout(
            Duration::from_millis(WAIT_FOR_CONNECTION_TIMEOUT_MS),
            incoming.next(),
        )
        .await;

        if last_datapoint.elapsed().as_secs() >= 5 {
            stats.report();
            last_datapoint = Instant::now();
        }

        if let Ok(Some(connection)) = timeout_connection {
            tokio::spawn(setup_connection(
                connection,
                unstaked_connection_table.clone(),
                staked_connection_table.clone(),
                packet_sender.clone(),
                max_connections_per_peer,
                staked_nodes.clone(),
                max_staked_connections,
                max_unstaked_connections,
                stats.clone(),
            ));
            sleep(Duration::from_micros(WAIT_BETWEEN_NEW_CONNECTIONS_US)).await;
        }
    }
}

fn prune_unstaked_connection_table(
    unstaked_connection_table: &mut MutexGuard<ConnectionTable>,
    max_unstaked_connections: usize,
    stats: Arc<StreamStats>,
) {
    if unstaked_connection_table.total_size >= max_unstaked_connections {
        const PRUNE_TABLE_TO_PERCENTAGE: u8 = 90;
        let max_percentage_full = Percentage::from(PRUNE_TABLE_TO_PERCENTAGE);

        let max_connections = max_percentage_full.apply_to(max_unstaked_connections);
        let num_pruned = unstaked_connection_table.prune_oldest(max_connections);
        stats.num_evictions.fetch_add(num_pruned, Ordering::Relaxed);
    }
}

fn get_connection_stake(
    connection: &Connection,
    staked_nodes: Arc<RwLock<StakedNodes>>,
) -> Option<(Pubkey, u64)> {
    connection
        .peer_identity()
        .and_then(|der_cert_any| der_cert_any.downcast::<Vec<rustls::Certificate>>().ok())
        .and_then(|der_certs| {
            get_pubkey_from_tls_certificate(&der_certs).and_then(|pubkey| {
                debug!("Peer public key is {:?}", pubkey);

                let staked_nodes = staked_nodes.read().unwrap();
                staked_nodes
                    .pubkey_stake_map
                    .get(&pubkey)
                    .map(|stake| (pubkey, *stake))
            })
        })
}

async fn setup_connection(
    connecting: Connecting,
    unstaked_connection_table: Arc<Mutex<ConnectionTable>>,
    staked_connection_table: Arc<Mutex<ConnectionTable>>,
    packet_sender: Sender<PacketBatch>,
    max_connections_per_peer: usize,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    max_staked_connections: usize,
    max_unstaked_connections: usize,
    stats: Arc<StreamStats>,
) {
    if let Ok(connecting_result) = timeout(
        Duration::from_millis(QUIC_CONNECTION_HANDSHAKE_TIMEOUT_MS),
        connecting,
    )
    .await
    {
        if let Ok(new_connection) = connecting_result {
            stats.total_connections.fetch_add(1, Ordering::Relaxed);
            stats.total_new_connections.fetch_add(1, Ordering::Relaxed);
            let NewConnection {
                connection,
                uni_streams,
                ..
            } = new_connection;

            let remote_addr = connection.remote_address();
            let mut remote_pubkey = None;

            let table_and_stake = {
                let (some_pubkey, stake) = get_connection_stake(&connection, staked_nodes.clone())
                    .map_or((None, 0), |(pubkey, stake)| (Some(pubkey), stake));
                if stake > 0 {
                    remote_pubkey = some_pubkey;
                    let mut connection_table_l = staked_connection_table.lock().unwrap();
                    if connection_table_l.total_size >= max_staked_connections {
                        let num_pruned = connection_table_l.prune_random(stake);
                        if num_pruned == 0 {
                            if max_unstaked_connections > 0 {
                                // If we couldn't prune a connection in the staked connection table, let's
                                // put this connection in the unstaked connection table. If needed, prune a
                                // connection from the unstaked connection table.
                                connection_table_l = unstaked_connection_table.lock().unwrap();
                                prune_unstaked_connection_table(
                                    &mut connection_table_l,
                                    max_unstaked_connections,
                                    stats.clone(),
                                );
                                Some((connection_table_l, stake))
                            } else {
                                stats
                                    .connection_add_failed_on_pruning
                                    .fetch_add(1, Ordering::Relaxed);
                                None
                            }
                        } else {
                            stats.num_evictions.fetch_add(num_pruned, Ordering::Relaxed);
                            Some((connection_table_l, stake))
                        }
                    } else {
                        Some((connection_table_l, stake))
                    }
                } else if max_unstaked_connections > 0 {
                    let mut connection_table_l = unstaked_connection_table.lock().unwrap();
                    prune_unstaked_connection_table(
                        &mut connection_table_l,
                        max_unstaked_connections,
                        stats.clone(),
                    );
                    Some((connection_table_l, 0))
                } else {
                    None
                }
            };

            if let Some((mut connection_table_l, stake)) = table_and_stake {
                let table_type = connection_table_l.peer_type;
                let max_uni_streams = match table_type {
                    ConnectionPeerType::Unstaked => {
                        VarInt::from_u64(QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS as u64)
                    }
                    ConnectionPeerType::Staked => {
                        let staked_nodes = staked_nodes.read().unwrap();
                        VarInt::from_u64(
                            ((stake as f64 / staked_nodes.total_stake as f64)
                                * QUIC_TOTAL_STAKED_CONCURRENT_STREAMS)
                                as u64,
                        )
                    }
                };

                if let Ok(max_uni_streams) = max_uni_streams {
                    connection.set_max_concurrent_uni_streams(max_uni_streams);
                    if let Some((last_update, stream_exit)) = connection_table_l.try_add_connection(
                        ConnectionTableKey::new(remote_addr.ip(), remote_pubkey),
                        remote_addr.port(),
                        Some(connection),
                        stake,
                        timing::timestamp(),
                        max_connections_per_peer,
                    ) {
                        drop(connection_table_l);
                        let stats = stats.clone();
                        let connection_table = match table_type {
                            ConnectionPeerType::Unstaked => {
                                stats
                                    .connection_added_from_unstaked_peer
                                    .fetch_add(1, Ordering::Relaxed);
                                unstaked_connection_table.clone()
                            }
                            ConnectionPeerType::Staked => {
                                stats
                                    .connection_added_from_staked_peer
                                    .fetch_add(1, Ordering::Relaxed);
                                staked_connection_table.clone()
                            }
                        };
                        tokio::spawn(handle_connection(
                            uni_streams,
                            packet_sender,
                            remote_addr,
                            remote_pubkey,
                            last_update,
                            connection_table,
                            stream_exit,
                            stats,
                            stake,
                        ));
                    } else {
                        stats.connection_add_failed.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    stats
                        .connection_add_failed_invalid_stream_count
                        .fetch_add(1, Ordering::Relaxed);
                }
            } else {
                connection.close(0u32.into(), &[0u8]);
                stats
                    .connection_add_failed_unstaked_node
                    .fetch_add(1, Ordering::Relaxed);
            }
        } else {
            stats.connection_setup_error.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        stats
            .connection_setup_timeout
            .fetch_add(1, Ordering::Relaxed);
    }
}

async fn handle_connection(
    mut uni_streams: IncomingUniStreams,
    packet_sender: Sender<PacketBatch>,
    remote_addr: SocketAddr,
    remote_pubkey: Option<Pubkey>,
    last_update: Arc<AtomicU64>,
    connection_table: Arc<Mutex<ConnectionTable>>,
    stream_exit: Arc<AtomicBool>,
    stats: Arc<StreamStats>,
    stake: u64,
) {
    debug!(
        "quic new connection {} streams: {} connections: {}",
        remote_addr,
        stats.total_streams.load(Ordering::Relaxed),
        stats.total_connections.load(Ordering::Relaxed),
    );
    while !stream_exit.load(Ordering::Relaxed) {
        if let Ok(stream) = tokio::time::timeout(
            Duration::from_millis(WAIT_FOR_STREAM_TIMEOUT_MS),
            uni_streams.next(),
        )
        .await
        {
            match stream {
                Some(stream_result) => match stream_result {
                    Ok(mut stream) => {
                        stats.total_streams.fetch_add(1, Ordering::Relaxed);
                        stats.total_new_streams.fetch_add(1, Ordering::Relaxed);
                        let stream_exit = stream_exit.clone();
                        let stats = stats.clone();
                        let packet_sender = packet_sender.clone();
                        let last_update = last_update.clone();
                        tokio::spawn(async move {
                            let mut maybe_batch = None;
                            while !stream_exit.load(Ordering::Relaxed) {
                                if let Ok(chunk) = tokio::time::timeout(
                                    Duration::from_millis(WAIT_FOR_STREAM_TIMEOUT_MS),
                                    stream.read_chunk(PACKET_DATA_SIZE, false),
                                )
                                .await
                                {
                                    if handle_chunk(
                                        &chunk,
                                        &mut maybe_batch,
                                        &remote_addr,
                                        &packet_sender,
                                        stats.clone(),
                                        stake,
                                    ) {
                                        last_update.store(timing::timestamp(), Ordering::Relaxed);
                                        break;
                                    }
                                } else {
                                    debug!("Timeout in receiving on stream");
                                    stats
                                        .total_stream_read_timeouts
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            stats.total_streams.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        debug!("stream error: {:?}", e);
                        break;
                    }
                },
                None => {
                    break;
                }
            }
        }
    }

    if connection_table.lock().unwrap().remove_connection(
        ConnectionTableKey::new(remote_addr.ip(), remote_pubkey),
        remote_addr.port(),
    ) {
        stats.connection_removed.fetch_add(1, Ordering::Relaxed);
    } else {
        stats
            .connection_remove_failed
            .fetch_add(1, Ordering::Relaxed);
    }
    stats.total_connections.fetch_sub(1, Ordering::Relaxed);
}

// Return true if the server should drop the stream
fn handle_chunk(
    chunk: &Result<Option<quinn::Chunk>, quinn::ReadError>,
    maybe_batch: &mut Option<PacketBatch>,
    remote_addr: &SocketAddr,
    packet_sender: &Sender<PacketBatch>,
    stats: Arc<StreamStats>,
    stake: u64,
) -> bool {
    match chunk {
        Ok(maybe_chunk) => {
            if let Some(chunk) = maybe_chunk {
                trace!("got chunk: {:?}", chunk);
                let chunk_len = chunk.bytes.len() as u64;

                // shouldn't happen, but sanity check the size and offsets
                if chunk.offset > PACKET_DATA_SIZE as u64 || chunk_len > PACKET_DATA_SIZE as u64 {
                    stats.total_invalid_chunks.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                if chunk.offset + chunk_len > PACKET_DATA_SIZE as u64 {
                    stats
                        .total_invalid_chunk_size
                        .fetch_add(1, Ordering::Relaxed);
                    return true;
                }

                // chunk looks valid
                if maybe_batch.is_none() {
                    let mut batch = PacketBatch::with_capacity(1);
                    let mut packet = Packet::default();
                    packet.meta.set_socket_addr(remote_addr);
                    packet.meta.sender_stake = stake;
                    batch.push(packet);
                    *maybe_batch = Some(batch);
                    stats
                        .total_packets_allocated
                        .fetch_add(1, Ordering::Relaxed);
                }

                if let Some(batch) = maybe_batch.as_mut() {
                    let end = chunk.offset as usize + chunk.bytes.len();
                    batch[0].buffer_mut()[chunk.offset as usize..end].copy_from_slice(&chunk.bytes);
                    batch[0].meta.size = std::cmp::max(batch[0].meta.size, end);
                    stats.total_chunks_received.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                trace!("chunk is none");
                // done receiving chunks
                if let Some(batch) = maybe_batch.take() {
                    let len = batch[0].meta.size;
                    if let Err(e) = packet_sender.send(batch) {
                        stats
                            .total_packet_batch_send_err
                            .fetch_add(1, Ordering::Relaxed);
                        info!("send error: {}", e);
                    } else {
                        stats
                            .total_packet_batches_sent
                            .fetch_add(1, Ordering::Relaxed);
                        trace!("sent {} byte packet", len);
                    }
                } else {
                    stats
                        .total_packet_batches_none
                        .fetch_add(1, Ordering::Relaxed);
                }
                return true;
            }
        }
        Err(e) => {
            debug!("Received stream error: {:?}", e);
            stats
                .total_stream_read_errors
                .fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

#[derive(Debug)]
struct ConnectionEntry {
    exit: Arc<AtomicBool>,
    stake: u64,
    last_update: Arc<AtomicU64>,
    port: u16,
    connection: Option<Connection>,
}

impl ConnectionEntry {
    fn new(
        exit: Arc<AtomicBool>,
        stake: u64,
        last_update: Arc<AtomicU64>,
        port: u16,
        connection: Option<Connection>,
    ) -> Self {
        Self {
            exit,
            stake,
            last_update,
            port,
            connection,
        }
    }

    fn last_update(&self) -> u64 {
        self.last_update.load(Ordering::Relaxed)
    }
}

impl Drop for ConnectionEntry {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.close(0u32.into(), &[0u8]);
        }
        self.exit.store(true, Ordering::Relaxed);
    }
}

#[derive(Copy, Clone)]
enum ConnectionPeerType {
    Unstaked,
    Staked,
}

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
enum ConnectionTableKey {
    IP(IpAddr),
    Pubkey(Pubkey),
}

impl ConnectionTableKey {
    fn new(ip: IpAddr, maybe_pubkey: Option<Pubkey>) -> Self {
        maybe_pubkey.map_or(ConnectionTableKey::IP(ip), |pubkey| {
            ConnectionTableKey::Pubkey(pubkey)
        })
    }
}

// Map of IP to list of connection entries
struct ConnectionTable {
    table: IndexMap<ConnectionTableKey, Vec<ConnectionEntry>>,
    total_size: usize,
    peer_type: ConnectionPeerType,
}

// Prune the connection which has the oldest update
// Return number pruned
impl ConnectionTable {
    fn new(peer_type: ConnectionPeerType) -> Self {
        Self {
            table: IndexMap::default(),
            total_size: 0,
            peer_type,
        }
    }

    fn prune_oldest(&mut self, max_size: usize) -> usize {
        let mut num_pruned = 0;
        while self.total_size > max_size {
            let mut oldest = std::u64::MAX;
            let mut oldest_index = None;
            for (index, (_key, connections)) in self.table.iter().enumerate() {
                for entry in connections {
                    let last_update = entry.last_update();
                    if last_update < oldest {
                        oldest = last_update;
                        oldest_index = Some(index);
                    }
                }
            }
            if let Some(oldest_index) = oldest_index {
                if let Some((_, removed)) = self.table.swap_remove_index(oldest_index) {
                    self.total_size -= removed.len();
                    num_pruned += removed.len();
                }
            } else {
                // No valid entries in the table. Continuing the loop will cause
                // infinite looping.
                break;
            }
        }
        num_pruned
    }

    fn connection_stake(&self, index: usize) -> Option<u64> {
        self.table
            .get_index(index)
            .and_then(|(_, connection_vec)| connection_vec.first())
            .map(|connection| connection.stake)
    }

    // Randomly select two connections, and evict the one with lower stake. If the stakes of both
    // the connections are higher than the threshold_stake, reject the pruning attempt, and return 0.
    fn prune_random(&mut self, threshold_stake: u64) -> usize {
        let mut num_pruned = 0;
        let mut rng = thread_rng();
        // The candidate1 and candidate2 could potentially be the same. If so, the stake of the candidate
        // will be compared just against the threshold_stake.
        let candidate1 = rng.gen_range(0, self.table.len());
        let candidate2 = rng.gen_range(0, self.table.len());

        let candidate1_stake = self.connection_stake(candidate1).unwrap_or(0);
        let candidate2_stake = self.connection_stake(candidate2).unwrap_or(0);

        if candidate1_stake < threshold_stake || candidate2_stake < threshold_stake {
            let removed = if candidate1_stake < candidate2_stake {
                self.table.swap_remove_index(candidate1)
            } else {
                self.table.swap_remove_index(candidate2)
            };

            if let Some((_, removed_value)) = removed {
                self.total_size -= removed_value.len();
                num_pruned += removed_value.len();
            }
        }

        num_pruned
    }

    fn try_add_connection(
        &mut self,
        key: ConnectionTableKey,
        port: u16,
        connection: Option<Connection>,
        stake: u64,
        last_update: u64,
        max_connections_per_peer: usize,
    ) -> Option<(Arc<AtomicU64>, Arc<AtomicBool>)> {
        let connection_entry = self.table.entry(key).or_insert_with(Vec::new);
        let has_connection_capacity = connection_entry
            .len()
            .checked_add(1)
            .map(|c| c <= max_connections_per_peer)
            .unwrap_or(false);
        if has_connection_capacity {
            let exit = Arc::new(AtomicBool::new(false));
            let last_update = Arc::new(AtomicU64::new(last_update));
            connection_entry.push(ConnectionEntry::new(
                exit.clone(),
                stake,
                last_update.clone(),
                port,
                connection,
            ));
            self.total_size += 1;
            Some((last_update, exit))
        } else {
            None
        }
    }

    fn remove_connection(&mut self, key: ConnectionTableKey, port: u16) -> bool {
        if let Entry::Occupied(mut e) = self.table.entry(key) {
            let e_ref = e.get_mut();
            let old_size = e_ref.len();
            e_ref.retain(|connection| connection.port != port);
            let new_size = e_ref.len();
            if e_ref.is_empty() {
                e.remove_entry();
            }
            self.total_size = self
                .total_size
                .saturating_sub(old_size.saturating_sub(new_size));
            true
        } else {
            false
        }
    }
}
