use {
    solana_ledger::{
        blockstore::Blockstore,
        shred::{Nonce, SIZE_OF_NONCE},
    },
    solana_perf::packet::limited_deserialize,
    solana_sdk::{clock::Slot, packet::Packet},
    std::{io, net::SocketAddr},
};

pub fn repair_response_packet(
    blockstore: &Blockstore,
    slot: Slot,
    shred_index: u64,
    dest: &SocketAddr,
    nonce: Nonce,
) -> Option<Packet> {
    let shred = blockstore
        .get_data_shred(slot, shred_index)
        .expect("Blockstore could not get data shred");
    shred
        .map(|shred| repair_response_packet_from_bytes(shred, dest, nonce))
        .unwrap_or(None)
}

pub fn repair_response_packet_from_bytes(
    bytes: Vec<u8>,
    dest: &SocketAddr,
    nonce: Nonce,
) -> Option<Packet> {
    let mut packet = Packet::default();
    packet.meta.size = bytes.len() + SIZE_OF_NONCE;
    if packet.meta.size > packet.data.len() {
        return None;
    }
    packet.meta.set_addr(dest);
    packet.data[..bytes.len()].copy_from_slice(&bytes);
    let mut wr = io::Cursor::new(&mut packet.data[bytes.len()..]);
    bincode::serialize_into(&mut wr, &nonce).expect("Buffer not large enough to fit nonce");
    Some(packet)
}

pub fn nonce(buf: &[u8]) -> Option<Nonce> {
    if buf.len() < SIZE_OF_NONCE {
        None
    } else {
        limited_deserialize(&buf[buf.len() - SIZE_OF_NONCE..]).ok()
    }
}

