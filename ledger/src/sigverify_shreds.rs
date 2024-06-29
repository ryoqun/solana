#![allow(clippy::implicit_hasher)]
use {
    crate::shred::{self, SignedData, SIZE_OF_MERKLE_ROOT},
    itertools::{izip, Itertools},
    rayon::{prelude::*, ThreadPool},
    sha2::{Digest, Sha512},
    solana_metrics::inc_new_counter_debug,
    solana_perf::{
        cuda_runtime::PinnedVec,
        packet::{Packet, PacketBatch},
        perf_libs,
        recycler_cache::RecyclerCache,
        sigverify::{self, count_packets_in_batches, TxOffset},
    },
    solana_sdk::{
        clock::Slot,
        hash::Hash,
        pubkey::Pubkey,
        signature::{Keypair, Signature, Signer},
    },
    std::{
        collections::HashMap,
        iter::repeat,
        mem::size_of,
        ops::Range,
        sync::{Arc, RwLock},
    },
};

const SIGN_SHRED_GPU_MIN: usize = 256;

pub type LruCache = lazy_lru::LruCache<(Signature, Pubkey, /*merkle root:*/ Hash), ()>;

#[must_use]
pub fn verify_shred_cpu(
    packet: &Packet,
    slot_leaders: &HashMap<Slot, Pubkey>,
    cache: &RwLock<LruCache>,
) -> bool {
    if packet.meta().discard() {
        return false;
    }
    let Some(shred) = shred::layout::get_shred(packet) else {
        return false;
    };
    let Some(slot) = shred::layout::get_slot(shred) else {
        return false;
    };
    trace!("slot {}", slot);
    let Some(pubkey) = slot_leaders.get(&slot) else {
        return false;
    };
    let Some(signature) = shred::layout::get_signature(shred) else {
        return false;
    };
    trace!("signature {}", signature);
    let Some(data) = shred::layout::get_signed_data(shred) else {
        return false;
    };
    match data {
        SignedData::Chunk(chunk) => signature.verify(pubkey.as_ref(), chunk),
        SignedData::MerkleRoot(root) => {
            let key = (signature, *pubkey, root);
            if cache.read().unwrap().get(&key).is_some() {
                true
            } else if key.0.verify(key.1.as_ref(), key.2.as_ref()) {
                cache.write().unwrap().put(key, ());
                true
            } else {
                false
            }
        }
    }
}

fn verify_shreds_cpu(
    thread_pool: &ThreadPool,
    batches: &[PacketBatch],
    slot_leaders: &HashMap<Slot, Pubkey>,
    cache: &RwLock<LruCache>,
) -> Vec<Vec<u8>> {
    let packet_count = count_packets_in_batches(batches);
    debug!("CPU SHRED ECDSA for {}", packet_count);
    let rv = thread_pool.install(|| {
        batches
            .into_par_iter()
            .map(|batch| {
                batch
                    .par_iter()
                    .map(|packet| u8::from(verify_shred_cpu(packet, slot_leaders, cache)))
                    .collect()
            })
            .collect()
    });
    inc_new_counter_debug!("ed25519_shred_verify_cpu", packet_count);
    rv
}

fn slot_key_data_for_gpu(
    thread_pool: &ThreadPool,
    batches: &[PacketBatch],
    slot_keys: &HashMap<Slot, Pubkey>,
    recycler_cache: &RecyclerCache,
) -> (/*pubkeys:*/ PinnedVec<u8>, TxOffset) {
    //TODO: mark Pubkey::default shreds as failed after the GPU returns
    assert_eq!(slot_keys.get(&Slot::MAX), Some(&Pubkey::default()));
    let slots: Vec<Slot> = thread_pool.install(|| {
        batches
            .into_par_iter()
            .flat_map_iter(|batch| {
                batch.iter().map(|packet| {
                    if packet.meta().discard() {
                        return Slot::MAX;
                    }
                    let shred = shred::layout::get_shred(packet);
                    match shred.and_then(shred::layout::get_slot) {
                        Some(slot) if slot_keys.contains_key(&slot) => slot,
                        _ => Slot::MAX,
                    }
                })
            })
            .collect()
    });
    let keys_to_slots: HashMap<Pubkey, Vec<Slot>> = slots
        .iter()
        .map(|slot| (slot_keys[slot], *slot))
        .into_group_map();
    let mut keyvec = recycler_cache.buffer().allocate("shred_gpu_pubkeys");
    keyvec.set_pinnable();

    let keyvec_size = keys_to_slots.len() * size_of::<Pubkey>();
    resize_buffer(&mut keyvec, keyvec_size);

    let key_offsets: HashMap<Slot, /*key offset:*/ usize> = {
        let mut next_offset = 0;
        keys_to_slots
            .into_iter()
            .flat_map(|(key, slots)| {
                let offset = next_offset;
                next_offset += std::mem::size_of::<Pubkey>();
                keyvec[offset..next_offset].copy_from_slice(key.as_ref());
                slots.into_iter().zip(repeat(offset))
            })
            .collect()
    };
    let mut offsets = recycler_cache.offsets().allocate("shred_offsets");
    offsets.set_pinnable();
    for slot in slots {
        offsets.push(key_offsets[&slot] as u32);
    }
    trace!("keyvec.len: {}", keyvec.len());
    trace!("keyvec: {:?}", keyvec);
    trace!("offsets: {:?}", offsets);
    (keyvec, offsets)
}

// Recovers merkle roots from shreds binary.
fn get_merkle_roots(
    thread_pool: &ThreadPool,
    packets: &[PacketBatch],
    recycler_cache: &RecyclerCache,
) -> (
    PinnedVec<u8>,      // Merkle roots
    Vec<Option<usize>>, // Offsets
) {
    let merkle_roots: Vec<Option<Hash>> = thread_pool.install(|| {
        packets
            .par_iter()
            .flat_map(|packets| {
                packets.par_iter().map(|packet| {
                    if packet.meta().discard() {
                        return None;
                    }
                    let shred = shred::layout::get_shred(packet)?;
                    shred::layout::get_merkle_root(shred)
                })
            })
            .collect()
    });
    let num_merkle_roots = merkle_roots.iter().flatten().count();
    let mut buffer = recycler_cache.buffer().allocate("shred_gpu_merkle_roots");
    buffer.set_pinnable();
    resize_buffer(&mut buffer, num_merkle_roots * SIZE_OF_MERKLE_ROOT);
    let offsets = {
        let mut next_offset = 0;
        merkle_roots
            .into_iter()
            .map(|root| {
                let root = root?;
                let offset = next_offset;
                next_offset += SIZE_OF_MERKLE_ROOT;
                buffer[offset..next_offset].copy_from_slice(root.as_ref());
                Some(offset)
            })
            .collect()
    };
    (buffer, offsets)
}

// Resizes the buffer to >= size and a multiple of
// std::mem::size_of::<Packet>().
fn resize_buffer(buffer: &mut PinnedVec<u8>, size: usize) {
    //HACK: Pubkeys vector is passed along as a `PacketBatch` buffer to the GPU
    //TODO: GPU needs a more opaque interface, which can handle variable sized structures for data
    //Pad the Pubkeys buffer such that it is bigger than a buffer of Packet sized elems
    let num_packets = (size + std::mem::size_of::<Packet>() - 1) / std::mem::size_of::<Packet>();
    let size = num_packets * std::mem::size_of::<Packet>();
    buffer.resize(size, 0u8);
}

fn elems_from_buffer(buffer: &PinnedVec<u8>) -> perf_libs::Elems {
    // resize_buffer ensures that buffer size is a multiple of Packet size.
    debug_assert_eq!(buffer.len() % std::mem::size_of::<Packet>(), 0);
    let num_packets = buffer.len() / std::mem::size_of::<Packet>();
    perf_libs::Elems {
        elems: buffer.as_ptr().cast::<u8>(),
        num: num_packets as u32,
    }
}

fn shred_gpu_offsets(
    offset: usize,
    batches: &[PacketBatch],
    merkle_roots_offsets: impl IntoIterator<Item = Option<usize>>,
    recycler_cache: &RecyclerCache,
) -> (TxOffset, TxOffset, TxOffset) {
    fn add_offset(range: Range<usize>, offset: usize) -> Range<usize> {
        range.start + offset..range.end + offset
    }
    let mut signature_offsets = recycler_cache.offsets().allocate("shred_signatures");
    signature_offsets.set_pinnable();
    let mut msg_start_offsets = recycler_cache.offsets().allocate("shred_msg_starts");
    msg_start_offsets.set_pinnable();
    let mut msg_sizes = recycler_cache.offsets().allocate("shred_msg_sizes");
    msg_sizes.set_pinnable();
    let offsets = std::iter::successors(Some(offset), |offset| {
        offset.checked_add(std::mem::size_of::<Packet>())
    });
    let packets = batches.iter().flatten();
    for (offset, packet, merkle_root_offset) in izip!(offsets, packets, merkle_roots_offsets) {
        let sig = shred::layout::get_signature_range();
        let sig = add_offset(sig, offset);
        debug_assert_eq!(sig.end - sig.start, std::mem::size_of::<Signature>());
        // Signature may verify for an empty message but the packet will be
        // discarded during deserialization.
        let msg: Range<usize> = match merkle_root_offset {
            None => {
                let shred = shred::layout::get_shred(packet);
                let msg = shred.and_then(shred::layout::get_signed_data_offsets);
                add_offset(msg.unwrap_or_default(), offset)
            }
            Some(merkle_root_offset) => {
                merkle_root_offset..merkle_root_offset + SIZE_OF_MERKLE_ROOT
            }
        };
        signature_offsets.push(sig.start as u32);
        msg_start_offsets.push(msg.start as u32);
        let msg_size = msg.end.saturating_sub(msg.start);
        msg_sizes.push(msg_size as u32);
    }
    (signature_offsets, msg_start_offsets, msg_sizes)
}

pub fn verify_shreds_gpu(
    thread_pool: &ThreadPool,
    batches: &[PacketBatch],
    slot_leaders: &HashMap<Slot, Pubkey>,
    recycler_cache: &RecyclerCache,
    cache: &RwLock<LruCache>,
) -> Vec<Vec<u8>> {
    let Some(api) = perf_libs::api() else {
        return verify_shreds_cpu(thread_pool, batches, slot_leaders, cache);
    };
    let (pubkeys, pubkey_offsets) =
        slot_key_data_for_gpu(thread_pool, batches, slot_leaders, recycler_cache);
    //HACK: Pubkeys vector is passed along as a `PacketBatch` buffer to the GPU
    //TODO: GPU needs a more opaque interface, which can handle variable sized structures for data
    let (merkle_roots, merkle_roots_offsets) =
        get_merkle_roots(thread_pool, batches, recycler_cache);
    // Merkle roots are placed after pubkeys; adjust offsets accordingly.
    let merkle_roots_offsets = {
        let shift = pubkeys.len();
        merkle_roots_offsets
            .into_iter()
            .map(move |offset| Some(offset? + shift))
    };
    let offset = pubkeys.len() + merkle_roots.len();
    let (signature_offsets, msg_start_offsets, msg_sizes) =
        shred_gpu_offsets(offset, batches, merkle_roots_offsets, recycler_cache);
    let mut out = recycler_cache.buffer().allocate("out_buffer");
    out.set_pinnable();
    out.resize(signature_offsets.len(), 0u8);
    let mut elems = vec![
        elems_from_buffer(&pubkeys),
        elems_from_buffer(&merkle_roots),
    ];
    elems.extend(batches.iter().map(|batch| perf_libs::Elems {
        elems: batch.as_ptr().cast::<u8>(),
        num: batch.len() as u32,
    }));
    let num_packets = elems.iter().map(|elem| elem.num).sum();
    trace!("Starting verify num packets: {}", num_packets);
    trace!("elem len: {}", elems.len() as u32);
    trace!("packet sizeof: {}", size_of::<Packet>() as u32);
    const USE_NON_DEFAULT_STREAM: u8 = 1;
    unsafe {
        let res = (api.ed25519_verify_many)(
            elems.as_ptr(),
            elems.len() as u32,
            size_of::<Packet>() as u32,
            num_packets,
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
    trace!("out buf {:?}", out);

    // Each shred has exactly one signature.
    let v_sig_lens = batches.iter().map(|batch| repeat(1u32).take(batch.len()));
    let mut rvs: Vec<_> = batches.iter().map(|batch| vec![0u8; batch.len()]).collect();
    sigverify::copy_return_values(v_sig_lens, &out, &mut rvs);

    inc_new_counter_debug!("ed25519_shred_verify_gpu", out.len());
    rvs
}

fn sign_shred_cpu(keypair: &Keypair, packet: &mut Packet) {
    let sig = shred::layout::get_signature_range();
    let msg = shred::layout::get_shred(packet)
        .and_then(shred::layout::get_signed_data)
        .unwrap();
    assert!(
        packet.meta().size >= sig.end,
        "packet is not large enough for a signature"
    );
    let signature = keypair.sign_message(msg.as_ref());
    trace!("signature {:?}", signature);
    packet.buffer_mut()[sig].copy_from_slice(signature.as_ref());
}

pub fn sign_shreds_cpu(thread_pool: &ThreadPool, keypair: &Keypair, batches: &mut [PacketBatch]) {
    let packet_count = count_packets_in_batches(batches);
    debug!("CPU SHRED ECDSA for {}", packet_count);
    thread_pool.install(|| {
        batches.par_iter_mut().for_each(|batch| {
            batch[..]
                .par_iter_mut()
                .for_each(|p| sign_shred_cpu(keypair, p));
        });
    });
    inc_new_counter_debug!("ed25519_shred_sign_cpu", packet_count);
}

pub fn sign_shreds_gpu_pinned_keypair(keypair: &Keypair, cache: &RecyclerCache) -> PinnedVec<u8> {
    let mut vec = cache.buffer().allocate("pinned_keypair");
    let pubkey = keypair.pubkey().to_bytes();
    let secret = keypair.secret().to_bytes();
    let mut hasher = Sha512::default();
    hasher.update(secret);
    let mut result = hasher.finalize();
    result[0] &= 248;
    result[31] &= 63;
    result[31] |= 64;
    let size = pubkey.len() + result.len();
    resize_buffer(&mut vec, size);
    vec[0..pubkey.len()].copy_from_slice(&pubkey);
    vec[pubkey.len()..size].copy_from_slice(&result);
    vec
}

pub fn sign_shreds_gpu(
    thread_pool: &ThreadPool,
    keypair: &Keypair,
    pinned_keypair: &Option<Arc<PinnedVec<u8>>>,
    batches: &mut [PacketBatch],
    recycler_cache: &RecyclerCache,
) {
    let sig_size = size_of::<Signature>();
    let pubkey_size = size_of::<Pubkey>();
    let packet_count = count_packets_in_batches(batches);
    if packet_count < SIGN_SHRED_GPU_MIN || pinned_keypair.is_none() {
        return sign_shreds_cpu(thread_pool, keypair, batches);
    }
    let Some(api) = perf_libs::api() else {
        return sign_shreds_cpu(thread_pool, keypair, batches);
    };
    let pinned_keypair = pinned_keypair.as_ref().unwrap();

    //should be zero
    let mut pubkey_offsets = recycler_cache.offsets().allocate("pubkey offsets");
    pubkey_offsets.resize(packet_count, 0);

    let mut secret_offsets = recycler_cache.offsets().allocate("secret_offsets");
    secret_offsets.resize(packet_count, pubkey_size as u32);

    let (merkle_roots, merkle_roots_offsets) =
        get_merkle_roots(thread_pool, batches, recycler_cache);
    // Merkle roots are placed after the keypair; adjust offsets accordingly.
    let merkle_roots_offsets = {
        let shift = pinned_keypair.len();
        merkle_roots_offsets
            .into_iter()
            .map(move |offset| Some(offset? + shift))
    };
    let offset = pinned_keypair.len() + merkle_roots.len();
    trace!("offset: {}", offset);
    let (signature_offsets, msg_start_offsets, msg_sizes) =
        shred_gpu_offsets(offset, batches, merkle_roots_offsets, recycler_cache);
    let total_sigs = signature_offsets.len();
    let mut signatures_out = recycler_cache.buffer().allocate("ed25519 signatures");
    signatures_out.set_pinnable();
    signatures_out.resize(total_sigs * sig_size, 0);

    let mut elems = vec![
        elems_from_buffer(pinned_keypair),
        elems_from_buffer(&merkle_roots),
    ];
    elems.extend(batches.iter().map(|batch| perf_libs::Elems {
        elems: batch.as_ptr().cast::<u8>(),
        num: batch.len() as u32,
    }));
    let num_packets = elems.iter().map(|elem| elem.num).sum();
    trace!("Starting verify num packets: {}", num_packets);
    trace!("elem len: {}", elems.len() as u32);
    trace!("packet sizeof: {}", size_of::<Packet>() as u32);
    const USE_NON_DEFAULT_STREAM: u8 = 1;
    unsafe {
        let res = (api.ed25519_sign_many)(
            elems.as_mut_ptr(),
            elems.len() as u32,
            size_of::<Packet>() as u32,
            num_packets,
            total_sigs as u32,
            msg_sizes.as_ptr(),
            pubkey_offsets.as_ptr(),
            secret_offsets.as_ptr(),
            msg_start_offsets.as_ptr(),
            signatures_out.as_mut_ptr(),
            USE_NON_DEFAULT_STREAM,
        );
        if res != 0 {
            trace!("RETURN!!!: {}", res);
        }
    }
    trace!("done sign");
    // Cumulative number of packets within batches.
    let num_packets: Vec<_> = batches
        .iter()
        .scan(0, |num_packets, batch| {
            let out = *num_packets;
            *num_packets += batch.len();
            Some(out)
        })
        .collect();
    thread_pool.install(|| {
        batches
            .par_iter_mut()
            .zip(num_packets)
            .for_each(|(batch, num_packets)| {
                batch[..]
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(packet_ix, packet)| {
                        let sig_ix = packet_ix + num_packets;
                        let sig_start = sig_ix * sig_size;
                        let sig_end = sig_start + sig_size;
                        packet.buffer_mut()[..sig_size]
                            .copy_from_slice(&signatures_out[sig_start..sig_end]);
                    });
            });
    });
    inc_new_counter_debug!("ed25519_shred_sign_gpu", packet_count);
}
