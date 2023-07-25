pub use crate::legacy_contact_info::LegacyContactInfo;
use {
    crate::crds_value::MAX_WALLCLOCK,
    matches::{assert_matches, debug_assert_matches},
    serde::{Deserialize, Deserializer, Serialize},
    solana_sdk::{
        pubkey::Pubkey,
        quic::QUIC_PORT_OFFSET,
        rpc_port::{DEFAULT_RPC_PORT, DEFAULT_RPC_PUBSUB_PORT},
        sanitize::{Sanitize, SanitizeError},
        serde_varint, short_vec,
    },
    solana_streamer::socket::SocketAddrSpace,
    static_assertions::const_assert_eq,
    std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{SystemTime, UNIX_EPOCH},
    },
    thiserror::Error,
};

const SOCKET_TAG_GOSSIP: u8 = 0;
const SOCKET_TAG_REPAIR: u8 = 1;
const SOCKET_TAG_RPC: u8 = 2;
const SOCKET_TAG_RPC_PUBSUB: u8 = 3;
const SOCKET_TAG_SERVE_REPAIR: u8 = 4;
const SOCKET_TAG_TPU: u8 = 5;
const SOCKET_TAG_TPU_FORWARDS: u8 = 6;
const SOCKET_TAG_TPU_FORWARDS_QUIC: u8 = 7;
const SOCKET_TAG_TPU_QUIC: u8 = 8;
const SOCKET_TAG_TPU_VOTE: u8 = 9;
const SOCKET_TAG_TVU: u8 = 10;
const SOCKET_TAG_TVU_FORWARDS: u8 = 11;
const_assert_eq!(SOCKET_CACHE_SIZE, 12);
const SOCKET_CACHE_SIZE: usize = SOCKET_TAG_TVU_FORWARDS as usize + 1usize;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Duplicate IP address: {0}")]
    DuplicateIpAddr(IpAddr),
    #[error("Duplicate socket: {0}")]
    DuplicateSocket(/*key:*/ u8),
    #[error("Invalid IP address index: {index}, num addrs: {num_addrs}")]
    InvalidIpAddrIndex { index: u8, num_addrs: usize },
    #[error("Invalid port: {0}")]
    InvalidPort(/*port:*/ u16),
    #[error("Invalid {0:?} (udp) and {1:?} (quic) sockets")]
    InvalidQuicSocket(Option<SocketAddr>, Option<SocketAddr>),
    #[error("IP addresses saturated")]
    IpAddrsSaturated,
    #[error("Multicast IP address: {0}")]
    MulticastIpAddr(IpAddr),
    #[error("Port offsets overflow")]
    PortOffsetsOverflow,
    #[error("Socket not found: {0}")]
    SocketNotFound(/*key:*/ u8),
    #[error("Unspecified IP address: {0}")]
    UnspecifiedIpAddr(IpAddr),
    #[error("Unused IP address: {0}")]
    UnusedIpAddr(IpAddr),
}

#[derive(Clone, Debug, Eq, PartialEq, AbiExample, Serialize)]
pub struct ContactInfo {
    pubkey: Pubkey,
    #[serde(with = "serde_varint")]
    wallclock: u64,
    // When the node instance was first created.
    // Identifies duplicate running instances.
    outset: u64,
    shred_version: u16,
    version: solana_version::Version,
    // All IP addresses are unique and referenced at least once in sockets.
    #[serde(with = "short_vec")]
    addrs: Vec<IpAddr>,
    // All sockets have a unique key and a valid IP address index.
    #[serde(with = "short_vec")]
    sockets: Vec<SocketEntry>,
    #[serde(skip_serializing)]
    cache: [SocketAddr; SOCKET_CACHE_SIZE],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, AbiExample, Deserialize, Serialize)]
struct SocketEntry {
    key: u8,   // Protocol identifier, e.g. tvu, tpu, etc
    index: u8, // IpAddr index in the accompanying addrs vector.
    #[serde(with = "serde_varint")]
    offset: u16, // Port offset with respect to the previous entry.
}

// As part of deserialization, self.addrs and self.sockets should be cross
// verified and self.cache needs to be populated. This type serves as a
// workaround since serde does not have an initializer.
// https://github.com/serde-rs/serde/issues/642
#[derive(Deserialize)]
struct ContactInfoLite {
    pubkey: Pubkey,
    #[serde(with = "serde_varint")]
    wallclock: u64,
    outset: u64,
    shred_version: u16,
    version: solana_version::Version,
    #[serde(with = "short_vec")]
    addrs: Vec<IpAddr>,
    #[serde(with = "short_vec")]
    sockets: Vec<SocketEntry>,
}

macro_rules! get_socket {
    ($name:ident, $key:ident) => {
        pub fn $name(&self) -> Result<SocketAddr, Error> {
            let socket = self.cache[usize::from($key)];
            sanitize_socket(&socket)?;
            Ok(socket)
        }
    };
}

macro_rules! set_socket {
    ($name:ident, $key:ident) => {
        pub fn $name<T>(&mut self, socket: T) -> Result<(), Error>
        where
            SocketAddr: From<T>,
        {
            let socket = SocketAddr::from(socket);
            self.set_socket($key, socket)
        }
    };
    ($name:ident, $key:ident, $quic:ident) => {
        pub fn $name<T>(&mut self, socket: T) -> Result<(), Error>
        where
            SocketAddr: From<T>,
        {
            let socket = SocketAddr::from(socket);
            self.set_socket($key, socket)?;
            self.set_socket($quic, get_quic_socket(&socket)?)
        }
    };
}

macro_rules! remove_socket {
    ($name:ident, $key:ident) => {
        pub fn $name(&mut self) {
            self.remove_socket($key);
        }
    };
    ($name:ident, $key:ident, $quic:ident) => {
        pub fn $name(&mut self) {
            self.remove_socket($key);
            self.remove_socket($quic);
        }
    };
}

impl ContactInfo {
    pub fn new(pubkey: Pubkey, wallclock: u64, shred_version: u16) -> Self {
        Self {
            pubkey,
            wallclock,
            outset: {
                let now = SystemTime::now();
                let elapsed = now.duration_since(UNIX_EPOCH).unwrap();
                u64::try_from(elapsed.as_micros()).unwrap()
            },
            shred_version,
            version: solana_version::Version::default(),
            addrs: Vec::<IpAddr>::default(),
            sockets: Vec::<SocketEntry>::default(),
            cache: [socket_addr_unspecified(); SOCKET_CACHE_SIZE],
        }
    }

    #[inline]
    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }

    #[inline]
    pub fn wallclock(&self) -> u64 {
        self.wallclock
    }

    #[inline]
    pub fn shred_version(&self) -> u16 {
        self.shred_version
    }

    pub fn set_pubkey(&mut self, pubkey: Pubkey) {
        self.pubkey = pubkey
    }

    pub fn set_wallclock(&mut self, wallclock: u64) {
        self.wallclock = wallclock;
    }

    pub fn set_shred_version(&mut self, shred_version: u16) {
        self.shred_version = shred_version
    }

    get_socket!(gossip, SOCKET_TAG_GOSSIP);
    get_socket!(repair, SOCKET_TAG_REPAIR);
    get_socket!(rpc, SOCKET_TAG_RPC);
    get_socket!(rpc_pubsub, SOCKET_TAG_RPC_PUBSUB);
    get_socket!(serve_repair, SOCKET_TAG_SERVE_REPAIR);
    get_socket!(tpu, SOCKET_TAG_TPU);
    get_socket!(tpu_forwards, SOCKET_TAG_TPU_FORWARDS);
    get_socket!(tpu_forwards_quic, SOCKET_TAG_TPU_FORWARDS_QUIC);
    get_socket!(tpu_quic, SOCKET_TAG_TPU_QUIC);
    get_socket!(tpu_vote, SOCKET_TAG_TPU_VOTE);
    get_socket!(tvu, SOCKET_TAG_TVU);
    get_socket!(tvu_forwards, SOCKET_TAG_TVU_FORWARDS);

    set_socket!(set_gossip, SOCKET_TAG_GOSSIP);
    set_socket!(set_repair, SOCKET_TAG_REPAIR);
    set_socket!(set_rpc, SOCKET_TAG_RPC);
    set_socket!(set_rpc_pubsub, SOCKET_TAG_RPC_PUBSUB);
    set_socket!(set_serve_repair, SOCKET_TAG_SERVE_REPAIR);
    set_socket!(set_tpu, SOCKET_TAG_TPU, SOCKET_TAG_TPU_QUIC);
    set_socket!(
        set_tpu_forwards,
        SOCKET_TAG_TPU_FORWARDS,
        SOCKET_TAG_TPU_FORWARDS_QUIC
    );
    set_socket!(set_tpu_vote, SOCKET_TAG_TPU_VOTE);
    set_socket!(set_tvu, SOCKET_TAG_TVU);
    set_socket!(set_tvu_forwards, SOCKET_TAG_TVU_FORWARDS);

    remove_socket!(remove_serve_repair, SOCKET_TAG_SERVE_REPAIR);
    remove_socket!(remove_tpu, SOCKET_TAG_TPU, SOCKET_TAG_TPU_QUIC);
    remove_socket!(
        remove_tpu_forwards,
        SOCKET_TAG_TPU_FORWARDS,
        SOCKET_TAG_TPU_FORWARDS_QUIC
    );
    remove_socket!(remove_tvu, SOCKET_TAG_TVU);
    remove_socket!(remove_tvu_forwards, SOCKET_TAG_TVU_FORWARDS);


    // Adds given IP address to self.addrs returning respective index.
    fn push_addr(&mut self, addr: IpAddr) -> Result<u8, Error> {
        match self.addrs.iter().position(|k| k == &addr) {
            Some(index) => u8::try_from(index).map_err(|_| Error::IpAddrsSaturated),
            None => {
                let index = u8::try_from(self.addrs.len()).map_err(|_| Error::IpAddrsSaturated)?;
                self.addrs.push(addr);
                Ok(index)
            }
        }
    }

    pub fn set_socket(&mut self, key: u8, socket: SocketAddr) -> Result<(), Error> {
        sanitize_socket(&socket)?;
        // Remove the old entry associated with this key (if any).
        self.remove_socket(key);
        // Find the index at which the new socket entry would be inserted into
        // self.sockets, and the respective port offset.
        let mut offset = socket.port();
        let index = self.sockets.iter().position(|entry| {
            offset = match offset.checked_sub(entry.offset) {
                None => return true,
                Some(offset) => offset,
            };
            false
        });
        let entry = SocketEntry {
            key,
            index: self.push_addr(socket.ip())?,
            offset,
        };
        // Insert the new entry into self.sockets.
        // Adjust the port offset of the next entry (if any).
        match index {
            None => self.sockets.push(entry),
            Some(index) => {
                self.sockets[index].offset -= entry.offset;
                self.sockets.insert(index, entry);
            }
        }
        if let Some(entry) = self.cache.get_mut(usize::from(key)) {
            *entry = socket;
        }
        debug_assert_matches!(sanitize_entries(&self.addrs, &self.sockets), Ok(()));
        Ok(())
    }

    // Removes the socket associated with the specified key.
    fn remove_socket(&mut self, key: u8) {
        if let Some(index) = self.sockets.iter().position(|entry| entry.key == key) {
            let entry = self.sockets.remove(index);
            if let Some(next_entry) = self.sockets.get_mut(index) {
                next_entry.offset += entry.offset;
            }
            self.maybe_remove_addr(entry.index);
            if let Some(entry) = self.cache.get_mut(usize::from(key)) {
                *entry = socket_addr_unspecified();
            }
        }
    }

    // Removes the IP address at the given index if
    // no socket entry refrences that index.
    fn maybe_remove_addr(&mut self, index: u8) {
        if !self.sockets.iter().any(|entry| entry.index == index) {
            self.addrs.remove(usize::from(index));
            for entry in &mut self.sockets {
                if entry.index > index {
                    entry.index -= 1;
                }
            }
        }
    }

    pub fn is_valid_address(addr: &SocketAddr, socket_addr_space: &SocketAddrSpace) -> bool {
        LegacyContactInfo::is_valid_address(addr, socket_addr_space)
    }

    // Only for tests and simulations.
    pub fn new_localhost(pubkey: &Pubkey, wallclock: u64) -> Self {
        let mut node = Self::new(*pubkey, wallclock, /*shred_version:*/ 0u16);
        node.set_gossip((Ipv4Addr::LOCALHOST, 8000)).unwrap();
        node.set_tvu((Ipv4Addr::LOCALHOST, 8001)).unwrap();
        node.set_tvu_forwards((Ipv4Addr::LOCALHOST, 8002)).unwrap();
        node.set_repair((Ipv4Addr::LOCALHOST, 8007)).unwrap();
        node.set_tpu((Ipv4Addr::LOCALHOST, 8003)).unwrap(); // quic: 8009
        node.set_tpu_forwards((Ipv4Addr::LOCALHOST, 8004)).unwrap(); // quic: 8010
        node.set_tpu_vote((Ipv4Addr::LOCALHOST, 8005)).unwrap();
        node.set_rpc((Ipv4Addr::LOCALHOST, DEFAULT_RPC_PORT))
            .unwrap();
        node.set_rpc_pubsub((Ipv4Addr::LOCALHOST, DEFAULT_RPC_PUBSUB_PORT))
            .unwrap();
        node.set_serve_repair((Ipv4Addr::LOCALHOST, 8008)).unwrap();
        node
    }

    // Only for tests and simulations.
    pub fn new_with_socketaddr(pubkey: &Pubkey, socket: &SocketAddr) -> Self {
        assert_matches!(sanitize_socket(socket), Ok(()));
        let mut node = Self::new(
            *pubkey,
            solana_sdk::timing::timestamp(), // wallclock,
            0u16,                            // shred_version
        );
        let (addr, port) = (socket.ip(), socket.port());
        node.set_gossip((addr, port + 1)).unwrap();
        node.set_tvu((addr, port + 2)).unwrap();
        node.set_tvu_forwards((addr, port + 3)).unwrap();
        node.set_repair((addr, port + 4)).unwrap();
        node.set_tpu((addr, port)).unwrap(); // quic: port + 6
        node.set_tpu_forwards((addr, port + 5)).unwrap(); // quic: port + 11
        node.set_tpu_vote((addr, port + 7)).unwrap();
        node.set_rpc((addr, DEFAULT_RPC_PORT)).unwrap();
        node.set_rpc_pubsub((addr, DEFAULT_RPC_PUBSUB_PORT))
            .unwrap();
        node.set_serve_repair((addr, port + 8)).unwrap();
        node
    }
}

impl<'de> Deserialize<'de> for ContactInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let node = ContactInfoLite::deserialize(deserializer)?;
        ContactInfo::try_from(node).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<ContactInfoLite> for ContactInfo {
    type Error = Error;

    fn try_from(node: ContactInfoLite) -> Result<Self, Self::Error> {
        let ContactInfoLite {
            pubkey,
            wallclock,
            outset,
            shred_version,
            version,
            addrs,
            sockets,
        } = node;
        sanitize_entries(&addrs, &sockets)?;
        let mut node = ContactInfo {
            pubkey,
            wallclock,
            outset,
            shred_version,
            version,
            addrs,
            sockets,
            cache: [socket_addr_unspecified(); SOCKET_CACHE_SIZE],
        };
        // Populate node.cache.
        let mut port = 0u16;
        for &SocketEntry { key, index, offset } in &node.sockets {
            port += offset;
            let entry = match node.cache.get_mut(usize::from(key)) {
                None => continue,
                Some(entry) => entry,
            };
            let addr = match node.addrs.get(usize::from(index)) {
                None => continue,
                Some(&addr) => addr,
            };
            let socket = SocketAddr::new(addr, port);
            if sanitize_socket(&socket).is_ok() {
                *entry = socket;
            }
        }
        Ok(node)
    }
}

impl Sanitize for ContactInfo {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        if self.wallclock >= MAX_WALLCLOCK {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        Ok(())
    }
}

// Workaround until feature(const_socketaddr) is stable.
pub(crate) fn socket_addr_unspecified() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), /*port:*/ 0u16)
}

pub(crate) fn sanitize_socket(socket: &SocketAddr) -> Result<(), Error> {
    if socket.port() == 0u16 {
        return Err(Error::InvalidPort(socket.port()));
    }
    let addr = socket.ip();
    if addr.is_unspecified() {
        return Err(Error::UnspecifiedIpAddr(addr));
    }
    if addr.is_multicast() {
        return Err(Error::MulticastIpAddr(addr));
    }
    Ok(())
}

// Sanitizes deserialized IpAddr and socket entries.
fn sanitize_entries(addrs: &[IpAddr], sockets: &[SocketEntry]) -> Result<(), Error> {
    // Verify that all IP addresses are unique.
    {
        let mut seen = HashSet::with_capacity(addrs.len());
        for addr in addrs {
            if !seen.insert(addr) {
                return Err(Error::DuplicateIpAddr(*addr));
            }
        }
    }
    // Verify that all socket entries have unique key.
    {
        let mut mask = [0u64; 4]; // 256-bit bitmask.
        for &SocketEntry { key, .. } in sockets {
            let mask = &mut mask[usize::from(key / 64u8)];
            let bit = 1u64 << (key % 64u8);
            if (*mask & bit) != 0u64 {
                return Err(Error::DuplicateSocket(key));
            }
            *mask |= bit;
        }
    }
    // Verify that all socket entries reference a valid IP address, and
    // that all IP addresses are referenced in the sockets.
    {
        let num_addrs = addrs.len();
        let mut hits = vec![false; num_addrs];
        for &SocketEntry { index, .. } in sockets {
            *hits
                .get_mut(usize::from(index))
                .ok_or(Error::InvalidIpAddrIndex { index, num_addrs })? = true;
        }
        if let Some(index) = hits.into_iter().position(|hit| !hit) {
            return Err(Error::UnusedIpAddr(addrs[index]));
        }
    }
    // Verify that port offsets don't overflow.
    if sockets
        .iter()
        .fold(Some(0u16), |offset, entry| {
            offset?.checked_add(entry.offset)
        })
        .is_none()
    {
        return Err(Error::PortOffsetsOverflow);
    }
    Ok(())
}

// Verifies that the other socket is at QUIC_PORT_OFFSET from the first one.
pub(crate) fn sanitize_quic_offset(
    socket: &Option<SocketAddr>, // udp
    other: &Option<SocketAddr>,  // quic: udp + QUIC_PORT_OFFSET
) -> Result<(), Error> {
    (other == &socket.as_ref().map(get_quic_socket).transpose()?)
        .then_some(())
        .ok_or(Error::InvalidQuicSocket(*socket, *other))
}

// Returns the socket at QUIC_PORT_OFFSET from the given one.
pub(crate) fn get_quic_socket(socket: &SocketAddr) -> Result<SocketAddr, Error> {
    Ok(SocketAddr::new(
        socket.ip(),
        socket
            .port()
            .checked_add(QUIC_PORT_OFFSET)
            .ok_or_else(|| Error::InvalidPort(socket.port()))?,
    ))
}

