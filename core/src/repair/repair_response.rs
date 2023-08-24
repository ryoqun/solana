use {
    solana_ledger::{
        blockstore::Blockstore,
        shred::{Nonce, SIZE_OF_NONCE},
    },
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
    let size = bytes.len() + SIZE_OF_NONCE;
    if size > packet.buffer_mut().len() {
        return None;
    }
    packet.meta_mut().size = size;
    packet.meta_mut().set_socket_addr(dest);
    packet.buffer_mut()[..bytes.len()].copy_from_slice(&bytes);
    let mut wr = io::Cursor::new(&mut packet.buffer_mut()[bytes.len()..]);
    bincode::serialize_into(&mut wr, &nonce).expect("Buffer not large enough to fit nonce");
    Some(packet)
}

pub(crate) fn nonce(packet: &Packet) -> Option<Nonce> {
    // Nonces are attached to both repair and ancestor hashes responses.
    let data = packet.data(..)?;
    let offset = data.len().checked_sub(SIZE_OF_NONCE)?;
    <[u8; SIZE_OF_NONCE]>::try_from(&data[offset..])
        .map(Nonce::from_le_bytes)
        .ok()
}
