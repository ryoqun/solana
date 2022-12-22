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
    quinn_proto::VarIntBoundsExceeded,
    rand::{thread_rng, Rng},
    solana_perf::packet::PacketBatch,
    solana_sdk::{
        packet::{Packet, PACKET_DATA_SIZE},
        pubkey::Pubkey,
        quic::{
            QUIC_CONNECTION_HANDSHAKE_TIMEOUT_MS, QUIC_MAX_STAKED_CONCURRENT_STREAMS,
            QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO, QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS,
            QUIC_MIN_STAKED_CONCURRENT_STREAMS, QUIC_MIN_STAKED_RECEIVE_WINDOW_RATIO,
            QUIC_TOTAL_STAKED_CONCURRENT_STREAMS, QUIC_UNSTAKED_RECEIVE_WINDOW_RATIO,
        },
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

const WAIT_FOR_STREAM_TIMEOUT_MS: u64 = 100;
pub const DEFAULT_WAIT_FOR_CHUNK_TIMEOUT_MS: u64 = 10000;

pub const ALPN_TPU_PROTOCOL_ID: &[u8] = b"solana-tpu";

const CONNECTION_CLOSE_CODE_DROPPED_ENTRY: u32 = 1;
const CONNECTION_CLOSE_REASON_DROPPED_ENTRY: &[u8] = b"dropped";

const CONNECTION_CLOSE_CODE_DISALLOWED: u32 = 2;
const CONNECTION_CLOSE_REASON_DISALLOWED: &[u8] = b"disallowed";

const CONNECTION_CLOSE_CODE_EXCEED_MAX_STREAM_COUNT: u32 = 3;
const CONNECTION_CLOSE_REASON_EXCEED_MAX_STREAM_COUNT: &[u8] = b"exceed_max_stream_count";

const CONNECTION_CLOSE_CODE_TOO_MANY: u32 = 4;
const CONNECTION_CLOSE_REASON_TOO_MANY: &[u8] = b"too_many";

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
    wait_for_chunk_timeout_ms: u64,
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
        wait_for_chunk_timeout_ms,
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
    wait_for_chunk_timeout_ms: u64,
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
                wait_for_chunk_timeout_ms,
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
) -> Option<(Pubkey, u64, u64, u64, u64)> {
    connection
        .peer_identity()
        .and_then(|der_cert_any| der_cert_any.downcast::<Vec<rustls::Certificate>>().ok())
        .and_then(|der_certs| {
            get_pubkey_from_tls_certificate(&der_certs).and_then(|pubkey| {
                debug!("Peer public key is {:?}", pubkey);

                let staked_nodes = staked_nodes.read().unwrap();
                let total_stake = staked_nodes.total_stake;
                let max_stake = staked_nodes.max_stake;
                let min_stake = staked_nodes.min_stake;
                staked_nodes
                    .pubkey_stake_map
                    .get(&pubkey)
                    .map(|stake| (pubkey, *stake, total_stake, max_stake, min_stake))
            })
        })
}

pub fn compute_max_allowed_uni_streams(
    peer_type: ConnectionPeerType,
    peer_stake: u64,
    total_stake: u64,
) -> usize {
    // Treat stake = 0 as unstaked
    if peer_stake == 0 {
        QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS
    } else {
        match peer_type {
            ConnectionPeerType::Staked => {
                // No checked math for f64 type. So let's explicitly check for 0 here
                if total_stake == 0 || peer_stake > total_stake {
                    warn!(
                        "Invalid stake values: peer_stake: {:?}, total_stake: {:?}",
                        peer_stake, total_stake,
                    );

                    QUIC_MIN_STAKED_CONCURRENT_STREAMS
                } else {
                    let delta = (QUIC_TOTAL_STAKED_CONCURRENT_STREAMS
                        - QUIC_MIN_STAKED_CONCURRENT_STREAMS)
                        as f64;

                    (((peer_stake as f64 / total_stake as f64) * delta) as usize
                        + QUIC_MIN_STAKED_CONCURRENT_STREAMS)
                        .clamp(
                            QUIC_MIN_STAKED_CONCURRENT_STREAMS,
                            QUIC_MAX_STAKED_CONCURRENT_STREAMS,
                        )
                }
            }
            _ => QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS,
        }
    }
}

enum ConnectionHandlerError {
    ConnectionAddError,
    MaxStreamError,
}

struct NewConnectionHandlerParams {
    packet_sender: Sender<PacketBatch>,
    remote_pubkey: Option<Pubkey>,
    stake: u64,
    total_stake: u64,
    max_connections_per_peer: usize,
    stats: Arc<StreamStats>,
    max_stake: u64,
    min_stake: u64,
}

impl NewConnectionHandlerParams {
    fn new_unstaked(
        packet_sender: Sender<PacketBatch>,
        max_connections_per_peer: usize,
        stats: Arc<StreamStats>,
    ) -> NewConnectionHandlerParams {
        NewConnectionHandlerParams {
            packet_sender,
            remote_pubkey: None,
            stake: 0,
            total_stake: 0,
            max_connections_per_peer,
            stats,
            max_stake: 0,
            min_stake: 0,
        }
    }
}

fn handle_and_cache_new_connection(
    new_connection: NewConnection,
    mut connection_table_l: MutexGuard<ConnectionTable>,
    connection_table: Arc<Mutex<ConnectionTable>>,
    params: &NewConnectionHandlerParams,
    wait_for_chunk_timeout_ms: u64,
) -> Result<(), ConnectionHandlerError> {
    let NewConnection {
        connection,
        uni_streams,
        ..
    } = new_connection;

    if let Ok(max_uni_streams) = VarInt::from_u64(compute_max_allowed_uni_streams(
        connection_table_l.peer_type,
        params.stake,
        params.total_stake,
    ) as u64)
    {
        connection.set_max_concurrent_uni_streams(max_uni_streams);
        let receive_window = compute_recieve_window(
            params.max_stake,
            params.min_stake,
            connection_table_l.peer_type,
            params.stake,
        );

        if let Ok(receive_window) = receive_window {
            connection.set_receive_window(receive_window);
        }

        let remote_addr = connection.remote_address();

        debug!(
            "Peer type: {:?}, stake {}, total stake {}, max streams {} receive_window {:?} from peer {}",
            connection_table_l.peer_type,
            params.stake,
            params.total_stake,
            max_uni_streams.into_inner(),
            receive_window,
            remote_addr,
        );

        if let Some((last_update, stream_exit)) = connection_table_l.try_add_connection(
            ConnectionTableKey::new(remote_addr.ip(), params.remote_pubkey),
            remote_addr.port(),
            Some(connection),
            params.stake,
            timing::timestamp(),
            params.max_connections_per_peer,
        ) {
            let peer_type = connection_table_l.peer_type;
            drop(connection_table_l);
            tokio::spawn(handle_connection(
                uni_streams,
                params.packet_sender.clone(),
                remote_addr,
                params.remote_pubkey,
                last_update,
                connection_table,
                stream_exit,
                params.stats.clone(),
                params.stake,
                peer_type,
                wait_for_chunk_timeout_ms,
            ));
            Ok(())
        } else {
            params
                .stats
                .connection_add_failed
                .fetch_add(1, Ordering::Relaxed);
            Err(ConnectionHandlerError::ConnectionAddError)
        }
    } else {
        connection.close(
            CONNECTION_CLOSE_CODE_EXCEED_MAX_STREAM_COUNT.into(),
            CONNECTION_CLOSE_REASON_EXCEED_MAX_STREAM_COUNT,
        );
        params
            .stats
            .connection_add_failed_invalid_stream_count
            .fetch_add(1, Ordering::Relaxed);
        Err(ConnectionHandlerError::MaxStreamError)
    }
}

fn prune_unstaked_connections_and_add_new_connection(
    new_connection: NewConnection,
    mut connection_table_l: MutexGuard<ConnectionTable>,
    connection_table: Arc<Mutex<ConnectionTable>>,
    max_connections: usize,
    params: &NewConnectionHandlerParams,
    wait_for_chunk_timeout_ms: u64,
) -> Result<(), ConnectionHandlerError> {
    let stats = params.stats.clone();
    if max_connections > 0 {
        prune_unstaked_connection_table(&mut connection_table_l, max_connections, stats);
        handle_and_cache_new_connection(
            new_connection,
            connection_table_l,
            connection_table,
            params,
            wait_for_chunk_timeout_ms,
        )
    } else {
        new_connection.connection.close(
            CONNECTION_CLOSE_CODE_DISALLOWED.into(),
            CONNECTION_CLOSE_REASON_DISALLOWED,
        );
        Err(ConnectionHandlerError::ConnectionAddError)
    }
}

/// Calculate the ratio for per connection receive window from a staked peer
fn compute_receive_window_ratio_for_staked_node(max_stake: u64, min_stake: u64, stake: u64) -> u64 {
    // Testing shows the maximum througput from a connection is achieved at receive_window =
    // PACKET_DATA_SIZE * 10. Beyond that, there is not much gain. We linearly map the
    // stake to the ratio range from QUIC_MIN_STAKED_RECEIVE_WINDOW_RATIO to
    // QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO. Where the linear algebra of finding the ratio 'r'
    // for stake 's' is,
    // r(s) = a * s + b. Given the max_stake, min_stake, max_ratio, min_ratio, we can find
    // a and b.

    if stake > max_stake {
        return QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO;
    }

    let max_ratio = QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO;
    let min_ratio = QUIC_MIN_STAKED_RECEIVE_WINDOW_RATIO;
    if max_stake > min_stake {
        let a = (max_ratio - min_ratio) as f64 / (max_stake - min_stake) as f64;
        let b = max_ratio as f64 - ((max_stake as f64) * a);
        let ratio = (a * stake as f64) + b;
        ratio.round() as u64
    } else {
        QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO
    }
}

fn compute_recieve_window(
    max_stake: u64,
    min_stake: u64,
    peer_type: ConnectionPeerType,
    peer_stake: u64,
) -> Result<VarInt, VarIntBoundsExceeded> {
    match peer_type {
        ConnectionPeerType::Unstaked => {
            VarInt::from_u64(PACKET_DATA_SIZE as u64 * QUIC_UNSTAKED_RECEIVE_WINDOW_RATIO)
        }
        ConnectionPeerType::Staked => {
            let ratio =
                compute_receive_window_ratio_for_staked_node(max_stake, min_stake, peer_stake);
            VarInt::from_u64(PACKET_DATA_SIZE as u64 * ratio)
        }
    }
}

#[allow(clippy::too_many_arguments)]
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
    wait_for_chunk_timeout_ms: u64,
) {
    if let Ok(connecting_result) = timeout(
        Duration::from_millis(QUIC_CONNECTION_HANDSHAKE_TIMEOUT_MS),
        connecting,
    )
    .await
    {
        if let Ok(new_connection) = connecting_result {
            stats.total_new_connections.fetch_add(1, Ordering::Relaxed);

            let params = get_connection_stake(&new_connection.connection, staked_nodes.clone())
                .map_or(
                    NewConnectionHandlerParams::new_unstaked(
                        packet_sender.clone(),
                        max_connections_per_peer,
                        stats.clone(),
                    ),
                    |(pubkey, stake, total_stake, max_stake, min_stake)| {
                        NewConnectionHandlerParams {
                            packet_sender,
                            remote_pubkey: Some(pubkey),
                            stake,
                            total_stake,
                            max_connections_per_peer,
                            stats: stats.clone(),
                            max_stake,
                            min_stake,
                        }
                    },
                );

            if params.stake > 0 {
                let mut connection_table_l = staked_connection_table.lock().unwrap();
                if connection_table_l.total_size >= max_staked_connections {
                    let num_pruned = connection_table_l.prune_random(params.stake);
                    stats.num_evictions.fetch_add(num_pruned, Ordering::Relaxed);
                }

                if connection_table_l.total_size < max_staked_connections {
                    if let Ok(()) = handle_and_cache_new_connection(
                        new_connection,
                        connection_table_l,
                        staked_connection_table.clone(),
                        &params,
                        wait_for_chunk_timeout_ms,
                    ) {
                        stats
                            .connection_added_from_staked_peer
                            .fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    // If we couldn't prune a connection in the staked connection table, let's
                    // put this connection in the unstaked connection table. If needed, prune a
                    // connection from the unstaked connection table.
                    if let Ok(()) = prune_unstaked_connections_and_add_new_connection(
                        new_connection,
                        unstaked_connection_table.lock().unwrap(),
                        unstaked_connection_table.clone(),
                        max_unstaked_connections,
                        &params,
                        wait_for_chunk_timeout_ms,
                    ) {
                        stats
                            .connection_added_from_staked_peer
                            .fetch_add(1, Ordering::Relaxed);
                    } else {
                        stats
                            .connection_add_failed_on_pruning
                            .fetch_add(1, Ordering::Relaxed);
                        stats
                            .connection_add_failed_staked_node
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            } else if let Ok(()) = prune_unstaked_connections_and_add_new_connection(
                new_connection,
                unstaked_connection_table.lock().unwrap(),
                unstaked_connection_table.clone(),
                max_unstaked_connections,
                &params,
                wait_for_chunk_timeout_ms,
            ) {
                stats
                    .connection_added_from_unstaked_peer
                    .fetch_add(1, Ordering::Relaxed);
            } else {
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

#[allow(clippy::too_many_arguments)]
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
    peer_type: ConnectionPeerType,
    wait_for_chunk_timeout_ms: u64,
) {
    debug!(
        "quic new connection {} streams: {} connections: {}",
        remote_addr,
        stats.total_streams.load(Ordering::Relaxed),
        stats.total_connections.load(Ordering::Relaxed),
    );
    stats.total_connections.fetch_add(1, Ordering::Relaxed);
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
                                    Duration::from_millis(wait_for_chunk_timeout_ms),
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
                                        peer_type,
                                    ) {
                                        last_update.store(timing::timestamp(), Ordering::Relaxed);
                                        break;
                                    }
                                } else {
                                    debug!("Timeout in receiving on stream");
                                    stats
                                        .total_stream_read_timeouts
                                        .fetch_add(1, Ordering::Relaxed);
                                    break;
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
    peer_type: ConnectionPeerType,
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
                let end_of_chunk = match chunk.offset.checked_add(chunk_len) {
                    Some(end) => end,
                    None => return true,
                };
                if end_of_chunk > PACKET_DATA_SIZE as u64 {
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
                    let end_of_chunk = match (chunk.offset as usize).checked_add(chunk.bytes.len())
                    {
                        Some(end) => end,
                        None => return true,
                    };
                    batch[0].buffer_mut()[chunk.offset as usize..end_of_chunk]
                        .copy_from_slice(&chunk.bytes);
                    batch[0].meta.size = std::cmp::max(batch[0].meta.size, end_of_chunk);
                    stats.total_chunks_received.fetch_add(1, Ordering::Relaxed);
                    match peer_type {
                        ConnectionPeerType::Staked => {
                            stats
                                .total_staked_chunks_received
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        ConnectionPeerType::Unstaked => {
                            stats
                                .total_unstaked_chunks_received
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
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
            conn.close(
                CONNECTION_CLOSE_CODE_DROPPED_ENTRY.into(),
                CONNECTION_CLOSE_REASON_DROPPED_ENTRY,
            );
        }
        self.exit.store(true, Ordering::Relaxed);
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ConnectionPeerType {
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
            if let Some(connection) = connection {
                connection.close(
                    CONNECTION_CLOSE_CODE_TOO_MANY.into(),
                    CONNECTION_CLOSE_REASON_TOO_MANY,
                );
            }
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
