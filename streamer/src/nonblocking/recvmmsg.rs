//! The `recvmmsg` module provides a nonblocking recvmmsg() API implementation

use {
    crate::{
        packet::{Meta, Packet},
        recvmmsg::NUM_RCVMMSGS,
    },
    std::{cmp, io},
    tokio::net::UdpSocket,
};

pub async fn recv_mmsg(
    socket: &UdpSocket,
    packets: &mut [Packet],
) -> io::Result</*num packets:*/ usize> {
    debug_assert!(packets.iter().all(|pkt| pkt.meta == Meta::default()));
    let count = cmp::min(NUM_RCVMMSGS, packets.len());
    socket.readable().await?;
    let mut i = 0;
    for p in packets.iter_mut().take(count) {
        p.meta.size = 0;
        match socket.try_recv_from(p.buffer_mut()) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => {
                return Err(e);
            }
            Ok((nrecv, from)) => {
                p.meta.size = nrecv;
                p.meta.set_socket_addr(&from);
            }
        }
        i += 1;
    }
    Ok(i)
}
