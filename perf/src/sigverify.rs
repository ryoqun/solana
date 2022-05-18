//! The `sigverify` module provides digital signature verification functions.
//! By default, signatures are verified in parallel using all available CPU
//! cores.  When perf-libs are available signature verification is offloaded
//! to the GPU.
//!

#[cfg(test)]
use solana_sdk::transaction::Transaction;
use {
    crate::{
        cuda_runtime::PinnedVec,
        packet::{Packet, PacketBatch, PacketFlags},
        perf_libs,
        recycler::Recycler,
    },
    ahash::AHasher,
    rand::{thread_rng, Rng},
    rayon::ThreadPool,
    solana_metrics::inc_new_counter_debug,
    solana_rayon_threadlimit::get_thread_count,
    solana_sdk::{
        hash::Hash,
        message::{MESSAGE_HEADER_LENGTH, MESSAGE_VERSION_PREFIX},
        pubkey::Pubkey,
        short_vec::decode_shortu16_len,
        signature::Signature,
    },
    std::hash::Hasher,
    std::sync::atomic::{AtomicBool, AtomicU64, Ordering},
    std::time::{Duration, Instant},
    std::{convert::TryFrom, mem::size_of},
};

// Representing key tKeYE4wtowRb8yRroZShTipE18YVnqwXjsSAoNsFU6g
const TRACER_KEY_BYTES: [u8; 32] = [
    13, 37, 180, 170, 252, 137, 36, 194, 183, 143, 161, 193, 201, 207, 211, 23, 189, 93, 33, 110,
    155, 90, 30, 39, 116, 115, 238, 38, 126, 21, 232, 133,
];
const TRACER_KEY: Pubkey = Pubkey::new_from_array(TRACER_KEY_BYTES);

lazy_static! {
    static ref PAR_THREAD_POOL: ThreadPool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_thread_count())
        .thread_name(|ix| format!("sigverify_{}", ix))
        .build()
        .unwrap();
}

pub type TxOffset = PinnedVec<u32>;

type TxOffsets = (TxOffset, TxOffset, TxOffset, TxOffset, Vec<Vec<u32>>);

#[derive(Debug, PartialEq, Eq)]
struct PacketOffsets {
    pub sig_len: u32,
    pub sig_start: u32,
    pub msg_start: u32,
    pub pubkey_start: u32,
    pub pubkey_len: u32,
}

impl PacketOffsets {
    pub fn new(
        sig_len: u32,
        sig_start: u32,
        msg_start: u32,
        pubkey_start: u32,
        pubkey_len: u32,
    ) -> Self {
        Self {
            sig_len,
            sig_start,
            msg_start,
            pubkey_start,
            pubkey_len,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum PacketError {
    InvalidLen,
    InvalidPubkeyLen,
    InvalidShortVec,
    InvalidSignatureLen,
    MismatchSignatureLen,
    PayerNotWritable,
    InvalidProgramIdIndex,
    InvalidProgramLen,
    UnsupportedVersion,
}

impl std::convert::From<std::boxed::Box<bincode::ErrorKind>> for PacketError {
    fn from(_e: std::boxed::Box<bincode::ErrorKind>) -> PacketError {
        PacketError::InvalidShortVec
    }
}

impl std::convert::From<std::num::TryFromIntError> for PacketError {
    fn from(_e: std::num::TryFromIntError) -> Self {
        Self::InvalidLen
    }
}

pub fn init() {
    if let Some(api) = perf_libs::api() {
        unsafe {
            (api.ed25519_set_verbose)(true);
            assert!((api.ed25519_init)(), "ed25519_init() failed");
            (api.ed25519_set_verbose)(false);
        }
    }
}

fn verify_packet(packet: &mut Packet, reject_non_vote: bool) {
    // If this packet was already marked as discard, drop it
    if packet.meta.discard() {
        return;
    }

    let packet_offsets = get_packet_offsets(packet, 0, reject_non_vote);
    let mut sig_start = packet_offsets.sig_start as usize;
    let mut pubkey_start = packet_offsets.pubkey_start as usize;
    let msg_start = packet_offsets.msg_start as usize;

    if packet_offsets.sig_len == 0 {
        packet.meta.set_discard(true);
        return;
    }

    if packet.meta.size <= msg_start {
        packet.meta.set_discard(true);
        return;
    }

    let msg_end = packet.meta.size;
    for _ in 0..packet_offsets.sig_len {
        let pubkey_end = pubkey_start.saturating_add(size_of::<Pubkey>());
        let sig_end = sig_start.saturating_add(size_of::<Signature>());

        // get_packet_offsets should ensure pubkey_end and sig_end do
        // not overflow packet.meta.size

        let signature = Signature::new(&packet.data[sig_start..sig_end]);

        if !signature.verify(
            &packet.data[pubkey_start..pubkey_end],
            &packet.data[msg_start..msg_end],
        ) {
            packet.meta.set_discard(true);
            return;
        }

        // Check for tracer pubkey
        if !packet.meta.is_tracer_tx()
            && &packet.data[pubkey_start..pubkey_end] == TRACER_KEY.as_ref()
        {
            packet.meta.flags |= PacketFlags::TRACER_TX;
        }

        pubkey_start = pubkey_end;
        sig_start = sig_end;
    }
}

pub fn count_packets_in_batches(batches: &[PacketBatch]) -> usize {
    batches.iter().map(|batch| batch.packets.len()).sum()
}

pub fn count_valid_packets(batches: &[PacketBatch]) -> usize {
    batches
        .iter()
        .map(|batch| batch.packets.iter().filter(|p| !p.meta.discard()).count())
        .sum()
}

// internal function to be unit-tested; should be used only by get_packet_offsets
fn do_get_packet_offsets(
    packet: &Packet,
    current_offset: usize,
) -> Result<PacketOffsets, PacketError> {
    // should have at least 1 signature and sig lengths
    let _ = 1usize
        .checked_add(size_of::<Signature>())
        .filter(|v| *v <= packet.meta.size)
        .ok_or(PacketError::InvalidLen)?;

    // read the length of Transaction.signatures (serialized with short_vec)
    let (sig_len_untrusted, sig_size) =
        decode_shortu16_len(&packet.data).map_err(|_| PacketError::InvalidShortVec)?;

    // Using msg_start_offset which is based on sig_len_untrusted introduces uncertainty.
    // Ultimately, the actual sigverify will determine the uncertainty.
    let msg_start_offset = sig_len_untrusted
        .checked_mul(size_of::<Signature>())
        .and_then(|v| v.checked_add(sig_size))
        .ok_or(PacketError::InvalidLen)?;

    // Determine the start of the message header by checking the message prefix bit.
    let msg_header_offset = {
        // Packet should have data for prefix bit
        if msg_start_offset >= packet.meta.size {
            return Err(PacketError::InvalidSignatureLen);
        }

        // next byte indicates if the transaction is versioned. If the top bit
        // is set, the remaining bits encode a version number. If the top bit is
        // not set, this byte is the first byte of the message header.
        let message_prefix = packet.data[msg_start_offset];
        if message_prefix & MESSAGE_VERSION_PREFIX != 0 {
            let version = message_prefix & !MESSAGE_VERSION_PREFIX;
            match version {
                0 => {
                    // header begins immediately after prefix byte
                    msg_start_offset
                        .checked_add(1)
                        .ok_or(PacketError::InvalidLen)?
                }

                // currently only v0 is supported
                _ => return Err(PacketError::UnsupportedVersion),
            }
        } else {
            msg_start_offset
        }
    };

    let msg_header_offset_plus_one = msg_header_offset
        .checked_add(1)
        .ok_or(PacketError::InvalidLen)?;

    // Packet should have data at least for MessageHeader and 1 byte for Message.account_keys.len
    let _ = msg_header_offset_plus_one
        .checked_add(MESSAGE_HEADER_LENGTH)
        .filter(|v| *v <= packet.meta.size)
        .ok_or(PacketError::InvalidSignatureLen)?;

    // read MessageHeader.num_required_signatures (serialized with u8)
    let sig_len_maybe_trusted = packet.data[msg_header_offset];

    let message_account_keys_len_offset = msg_header_offset
        .checked_add(MESSAGE_HEADER_LENGTH)
        .ok_or(PacketError::InvalidSignatureLen)?;

    // This reads and compares the MessageHeader num_required_signatures and
    // num_readonly_signed_accounts bytes. If num_required_signatures is not larger than
    // num_readonly_signed_accounts, the first account is not debitable, and cannot be charged
    // required transaction fees.
    let readonly_signer_offset = msg_header_offset_plus_one;
    if sig_len_maybe_trusted <= packet.data[readonly_signer_offset] {
        return Err(PacketError::PayerNotWritable);
    }

    if usize::from(sig_len_maybe_trusted) != sig_len_untrusted {
        return Err(PacketError::MismatchSignatureLen);
    }

    // read the length of Message.account_keys (serialized with short_vec)
    let (pubkey_len, pubkey_len_size) =
        decode_shortu16_len(&packet.data[message_account_keys_len_offset..])
            .map_err(|_| PacketError::InvalidShortVec)?;

    let pubkey_start = message_account_keys_len_offset
        .checked_add(pubkey_len_size)
        .ok_or(PacketError::InvalidPubkeyLen)?;

    let _ = pubkey_len
        .checked_mul(size_of::<Pubkey>())
        .and_then(|v| v.checked_add(pubkey_start))
        .filter(|v| *v <= packet.meta.size)
        .ok_or(PacketError::InvalidPubkeyLen)?;

    if pubkey_len < sig_len_untrusted {
        return Err(PacketError::InvalidPubkeyLen);
    }

    let sig_start = current_offset
        .checked_add(sig_size)
        .ok_or(PacketError::InvalidLen)?;
    let msg_start = current_offset
        .checked_add(msg_start_offset)
        .ok_or(PacketError::InvalidLen)?;
    let pubkey_start = current_offset
        .checked_add(pubkey_start)
        .ok_or(PacketError::InvalidLen)?;

    Ok(PacketOffsets::new(
        u32::try_from(sig_len_untrusted)?,
        u32::try_from(sig_start)?,
        u32::try_from(msg_start)?,
        u32::try_from(pubkey_start)?,
        u32::try_from(pubkey_len)?,
    ))
}

fn get_packet_offsets(
    packet: &mut Packet,
    current_offset: usize,
    reject_non_vote: bool,
) -> PacketOffsets {
    let unsanitized_packet_offsets = do_get_packet_offsets(packet, current_offset);
    if let Ok(offsets) = unsanitized_packet_offsets {
        check_for_simple_vote_transaction(packet, &offsets, current_offset).ok();
        if !reject_non_vote || packet.meta.is_simple_vote_tx() {
            return offsets;
        }
    }
    // force sigverify to fail by returning zeros
    PacketOffsets::new(0, 0, 0, 0, 0)
}

fn check_for_simple_vote_transaction(
    packet: &mut Packet,
    packet_offsets: &PacketOffsets,
    current_offset: usize,
) -> Result<(), PacketError> {
    // vote could have 1 or 2 sigs; zero sig has already been excluded at
    // do_get_packet_offsets.
    if packet_offsets.sig_len > 2 {
        return Err(PacketError::InvalidSignatureLen);
    }

    let pubkey_start = (packet_offsets.pubkey_start as usize)
        .checked_sub(current_offset)
        .ok_or(PacketError::InvalidLen)?;

    let instructions_len_offset = (packet_offsets.pubkey_len as usize)
        .checked_mul(size_of::<Pubkey>())
        .and_then(|v| v.checked_add(pubkey_start))
        .and_then(|v| v.checked_add(size_of::<Hash>()))
        .ok_or(PacketError::InvalidLen)?;

    // Packet should have at least 1 more byte for instructions.len
    let _ = instructions_len_offset
        .checked_add(1usize)
        .filter(|v| *v <= packet.meta.size)
        .ok_or(PacketError::InvalidLen)?;

    let (instruction_len, instruction_len_size) =
        decode_shortu16_len(&packet.data[instructions_len_offset..])
            .map_err(|_| PacketError::InvalidLen)?;

    // skip if has more than 1 instruction
    if instruction_len != 1 {
        return Err(PacketError::InvalidProgramLen);
    }

    let instruction_start = instructions_len_offset
        .checked_add(instruction_len_size)
        .ok_or(PacketError::InvalidLen)?;

    // Packet should have at least 1 more byte for one instructions_program_id
    let _ = instruction_start
        .checked_add(1usize)
        .filter(|v| *v <= packet.meta.size)
        .ok_or(PacketError::InvalidLen)?;

    let instruction_program_id_index: usize = usize::from(packet.data[instruction_start]);

    if instruction_program_id_index >= packet_offsets.pubkey_len as usize {
        return Err(PacketError::InvalidProgramIdIndex);
    }

    let instruction_program_id_start = instruction_program_id_index
        .checked_mul(size_of::<Pubkey>())
        .and_then(|v| v.checked_add(pubkey_start))
        .ok_or(PacketError::InvalidLen)?;
    let instruction_program_id_end = instruction_program_id_start
        .checked_add(size_of::<Pubkey>())
        .ok_or(PacketError::InvalidLen)?;

    if &packet.data[instruction_program_id_start..instruction_program_id_end]
        == solana_sdk::vote::program::id().as_ref()
    {
        packet.meta.flags |= PacketFlags::SIMPLE_VOTE_TX;
    }
    Ok(())
}

pub fn generate_offsets(
    batches: &mut [PacketBatch],
    recycler: &Recycler<TxOffset>,
    reject_non_vote: bool,
) -> TxOffsets {
    debug!("allocating..");
    let mut signature_offsets: PinnedVec<_> = recycler.allocate("sig_offsets");
    signature_offsets.set_pinnable();
    let mut pubkey_offsets: PinnedVec<_> = recycler.allocate("pubkey_offsets");
    pubkey_offsets.set_pinnable();
    let mut msg_start_offsets: PinnedVec<_> = recycler.allocate("msg_start_offsets");
    msg_start_offsets.set_pinnable();
    let mut msg_sizes: PinnedVec<_> = recycler.allocate("msg_size_offsets");
    msg_sizes.set_pinnable();
    let mut current_offset: usize = 0;
    let offsets = batches
        .iter_mut()
        .map(|batch| {
            batch
                .packets
                .iter_mut()
                .map(|packet| {
                    let packet_offsets =
                        get_packet_offsets(packet, current_offset, reject_non_vote);

                    trace!("pubkey_offset: {}", packet_offsets.pubkey_start);

                    let mut pubkey_offset = packet_offsets.pubkey_start;
                    let mut sig_offset = packet_offsets.sig_start;
                    let msg_size = current_offset.saturating_add(packet.meta.size) as u32;
                    for _ in 0..packet_offsets.sig_len {
                        signature_offsets.push(sig_offset);
                        sig_offset = sig_offset.saturating_add(size_of::<Signature>() as u32);

                        pubkey_offsets.push(pubkey_offset);
                        pubkey_offset = pubkey_offset.saturating_add(size_of::<Pubkey>() as u32);

                        msg_start_offsets.push(packet_offsets.msg_start);

                        let msg_size = msg_size.saturating_sub(packet_offsets.msg_start);
                        msg_sizes.push(msg_size);
                    }
                    current_offset = current_offset.saturating_add(size_of::<Packet>());
                    packet_offsets.sig_len
                })
                .collect()
        })
        .collect();
    (
        signature_offsets,
        pubkey_offsets,
        msg_start_offsets,
        msg_sizes,
        offsets,
    )
}

pub struct Deduper {
    filter: Vec<AtomicU64>,
    seed: (u128, u128),
    age: Instant,
    max_age: Duration,
    pub saturated: AtomicBool,
}

impl Deduper {
    pub fn new(size: u32, max_age: Duration) -> Self {
        let mut filter: Vec<AtomicU64> = Vec::with_capacity(size as usize);
        filter.resize_with(size as usize, Default::default);
        let seed = thread_rng().gen();
        Self {
            filter,
            seed,
            age: Instant::now(),
            max_age,
            saturated: AtomicBool::new(false),
        }
    }

    pub fn reset(&mut self) {
        let now = Instant::now();
        //this should reset every 500k unique packets per 1m sized deduper
        //false positive rate is 1/1000 at that point
        let saturated = self.saturated.load(Ordering::Relaxed);
        if saturated || now.duration_since(self.age) > self.max_age {
            for i in &self.filter {
                i.store(0, Ordering::Relaxed);
            }
            self.seed = thread_rng().gen();
            self.age = now;
            self.saturated.store(false, Ordering::Relaxed);
        }
    }

    fn dedup_packet(&self, packet: &mut Packet) -> u64 {
        // If this packet was already marked as discard, drop it
        if packet.meta.discard() {
            return 0;
        }
        let mut hasher = AHasher::new_with_keys(self.seed.0, self.seed.1);
        hasher.write(&packet.data[0..packet.meta.size]);
        let hash = hasher.finish();
        let len = self.filter.len();
        let pos = (usize::try_from(hash).unwrap()).wrapping_rem(len);
        // saturate each position with or
        let prev = self.filter[pos].fetch_or(hash, Ordering::Relaxed);
        if prev == u64::MAX {
            self.saturated.store(true, Ordering::Relaxed);
            //reset this value
            self.filter[pos].store(hash, Ordering::Relaxed);
        }
        if hash == prev & hash {
            packet.meta.set_discard(true);
            return 1;
        }
        0
    }

    pub fn dedup_packets(&self, batches: &mut [PacketBatch]) -> u64 {
        batches
            .iter_mut()
            .flat_map(|batch| batch.packets.iter_mut().map(|p| self.dedup_packet(p)))
            .sum()
    }
}

//inplace shrink a batch of packets
pub fn shrink_batches(batches: &mut Vec<PacketBatch>) -> usize {
    let mut valid_batch_ix = 0;
    let mut valid_packet_ix = 0;
    let mut last_valid_batch = 0;
    for batch_ix in 0..batches.len() {
        for packet_ix in 0..batches[batch_ix].packets.len() {
            if batches[batch_ix].packets[packet_ix].meta.discard() {
                continue;
            }
            last_valid_batch = batch_ix.saturating_add(1);
            let mut found_spot = false;
            while valid_batch_ix < batch_ix && !found_spot {
                while valid_packet_ix < batches[valid_batch_ix].packets.len() {
                    if batches[valid_batch_ix].packets[valid_packet_ix]
                        .meta
                        .discard()
                    {
                        batches[valid_batch_ix].packets[valid_packet_ix] =
                            batches[batch_ix].packets[packet_ix].clone();
                        batches[batch_ix].packets[packet_ix].meta.set_discard(true);
                        last_valid_batch = valid_batch_ix.saturating_add(1);
                        found_spot = true;
                        break;
                    }
                    valid_packet_ix = valid_packet_ix.saturating_add(1);
                }
                if valid_packet_ix >= batches[valid_batch_ix].packets.len() {
                    valid_packet_ix = 0;
                    valid_batch_ix = valid_batch_ix.saturating_add(1);
                }
            }
        }
    }
    last_valid_batch
}

pub fn ed25519_verify_cpu(batches: &mut [PacketBatch], reject_non_vote: bool, packet_count: usize) {
    use rayon::prelude::*;
    debug!("CPU ECDSA for {}", packet_count);
    PAR_THREAD_POOL.install(|| {
        batches.into_par_iter().for_each(|batch| {
            batch
                .packets
                .par_iter_mut()
                .for_each(|p| verify_packet(p, reject_non_vote))
        });
    });
    inc_new_counter_debug!("ed25519_verify_cpu", packet_count);
}

pub fn ed25519_verify_disabled(batches: &mut [PacketBatch]) {
    use rayon::prelude::*;
    let packet_count = count_packets_in_batches(batches);
    debug!("disabled ECDSA for {}", packet_count);
    batches.into_par_iter().for_each(|batch| {
        batch
            .packets
            .par_iter_mut()
            .for_each(|p| p.meta.set_discard(false))
    });
    inc_new_counter_debug!("ed25519_verify_disabled", packet_count);
}

pub fn copy_return_values(sig_lens: &[Vec<u32>], out: &PinnedVec<u8>, rvs: &mut Vec<Vec<u8>>) {
    let mut num = 0;
    for (vs, sig_vs) in rvs.iter_mut().zip(sig_lens.iter()) {
        for (v, sig_v) in vs.iter_mut().zip(sig_vs.iter()) {
            if *sig_v == 0 {
                *v = 0;
            } else {
                let mut vout = 1;
                for _ in 0..*sig_v {
                    if 0 == out[num] {
                        vout = 0;
                    }
                    num = num.saturating_add(1);
                }
                *v = vout;
            }
            if *v != 0 {
                trace!("VERIFIED PACKET!!!!!");
            }
        }
    }
}

// return true for success, i.e ge unpacks and !ge.is_small_order()
pub fn check_packed_ge_small_order(ge: &[u8; 32]) -> bool {
    if let Some(api) = perf_libs::api() {
        unsafe {
            // Returns 1 == fail, 0 == success
            let res = (api.ed25519_check_packed_ge_small_order)(ge.as_ptr());

            return res == 0;
        }
    }
    false
}

pub fn get_checked_scalar(scalar: &[u8; 32]) -> Result<[u8; 32], PacketError> {
    let mut out = [0u8; 32];
    if let Some(api) = perf_libs::api() {
        unsafe {
            let res = (api.ed25519_get_checked_scalar)(out.as_mut_ptr(), scalar.as_ptr());
            if res == 0 {
                return Ok(out);
            } else {
                return Err(PacketError::InvalidLen);
            }
        }
    }
    Ok(out)
}

pub fn mark_disabled(batches: &mut [PacketBatch], r: &[Vec<u8>]) {
    for (batch, v) in batches.iter_mut().zip(r) {
        for (pkt, f) in batch.packets.iter_mut().zip(v) {
            if !pkt.meta.discard() {
                pkt.meta.set_discard(*f == 0);
            }
        }
    }
}

pub fn ed25519_verify(
    batches: &mut [PacketBatch],
    recycler: &Recycler<TxOffset>,
    recycler_out: &Recycler<PinnedVec<u8>>,
    reject_non_vote: bool,
    valid_packet_count: usize,
) {
    let api = perf_libs::api();
    if api.is_none() {
        return ed25519_verify_cpu(batches, reject_non_vote, valid_packet_count);
    }
    let api = api.unwrap();

    use crate::packet::PACKET_DATA_SIZE;

    let total_packet_count = count_packets_in_batches(batches);
    // micro-benchmarks show GPU time for smallest batch around 15-20ms
    // and CPU speed for 64-128 sigverifies around 10-20ms. 64 is a nice
    // power-of-two number around that accounting for the fact that the CPU
    // may be busy doing other things while being a real validator
    // TODO: dynamically adjust this crossover
    if valid_packet_count < 64
        || 100usize
            .wrapping_mul(valid_packet_count)
            .wrapping_div(total_packet_count)
            < 90
    {
        return ed25519_verify_cpu(batches, reject_non_vote, valid_packet_count);
    }

    let (signature_offsets, pubkey_offsets, msg_start_offsets, msg_sizes, sig_lens) =
        generate_offsets(batches, recycler, reject_non_vote);

    debug!("CUDA ECDSA for {}", valid_packet_count);
    debug!("allocating out..");
    let mut out = recycler_out.allocate("out_buffer");
    out.set_pinnable();
    let mut elems = Vec::new();
    let mut rvs = Vec::new();

    let mut num_packets: usize = 0;
    for batch in batches.iter() {
        elems.push(perf_libs::Elems {
            elems: batch.packets.as_ptr(),
            num: batch.packets.len() as u32,
        });
        let v = vec![0u8; batch.packets.len()];
        rvs.push(v);
        num_packets = num_packets.saturating_add(batch.packets.len());
    }
    out.resize(signature_offsets.len(), 0);
    trace!("Starting verify num packets: {}", num_packets);
    trace!("elem len: {}", elems.len() as u32);
    trace!("packet sizeof: {}", size_of::<Packet>() as u32);
    trace!("len offset: {}", PACKET_DATA_SIZE as u32);
    const USE_NON_DEFAULT_STREAM: u8 = 1;
    unsafe {
        let res = (api.ed25519_verify_many)(
            elems.as_ptr(),
            elems.len() as u32,
            size_of::<Packet>() as u32,
            num_packets as u32,
            signature_offsets.len() as u32,
            msg_sizes.as_ptr(),
            pubkey_offsets.as_ptr(),
            signature_offsets.as_ptr(),
            msg_start_offsets.as_ptr(),
            out.as_mut_ptr(),
            USE_NON_DEFAULT_STREAM,
        );
        if res != 0 {
            trace!("RETURN!!!: {}", res);
        }
    }
    trace!("done verify");
    copy_return_values(&sig_lens, &out, &mut rvs);
    mark_disabled(batches, &rvs);
    inc_new_counter_debug!("ed25519_verify_gpu", valid_packet_count);
}

#[cfg(test)]
pub fn make_packet_from_transaction(tx: Transaction) -> Packet {
    use bincode::serialize;

    let tx_bytes = serialize(&tx).unwrap();
    let mut packet = Packet::default();
    packet.meta.size = tx_bytes.len();
    packet.data[..packet.meta.size].copy_from_slice(&tx_bytes);
    packet
}
