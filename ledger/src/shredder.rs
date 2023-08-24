use {
    crate::shred::{
        self, Error, ProcessShredsStats, Shred, ShredData, ShredFlags, DATA_SHREDS_PER_FEC_BLOCK,
    },
    itertools::Itertools,
    lazy_static::lazy_static,
    lru::LruCache,
    rayon::{prelude::*, ThreadPool},
    reed_solomon_erasure::{
        galois_8::ReedSolomon,
        Error::{InvalidIndex, TooFewDataShards, TooFewShardsPresent},
    },
    solana_entry::entry::Entry,
    solana_measure::measure::Measure,
    solana_rayon_threadlimit::get_thread_count,
    solana_sdk::{clock::Slot, signature::Keypair},
    std::{
        borrow::Borrow,
        fmt::Debug,
        sync::{Arc, Mutex},
    },
};

lazy_static! {
    static ref PAR_THREAD_POOL: ThreadPool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_thread_count())
        .thread_name(|i| format!("solShredder{i:02}"))
        .build()
        .unwrap();
}

// Maps number of data shreds to the optimal erasure batch size which has the
// same recovery probabilities as a 32:32 erasure batch.
pub(crate) const ERASURE_BATCH_SIZE: [usize; 33] = [
    0, 18, 20, 22, 23, 25, 27, 28, 30, // 8
    32, 33, 35, 36, 38, 39, 41, 42, // 16
    43, 45, 46, 48, 49, 51, 52, 53, // 24
    55, 56, 58, 59, 60, 62, 63, 64, // 32
];

pub struct ReedSolomonCache(
    Mutex<LruCache<(/*data_shards:*/ usize, /*parity_shards:*/ usize), Arc<ReedSolomon>>>,
);

#[derive(Debug)]
pub struct Shredder {
    slot: Slot,
    parent_slot: Slot,
    version: u16,
    reference_tick: u8,
}

impl Shredder {
    pub fn new(
        slot: Slot,
        parent_slot: Slot,
        reference_tick: u8,
        version: u16,
    ) -> Result<Self, Error> {
        if slot < parent_slot || slot - parent_slot > u64::from(std::u16::MAX) {
            Err(Error::InvalidParentSlot { slot, parent_slot })
        } else {
            Ok(Self {
                slot,
                parent_slot,
                reference_tick,
                version,
            })
        }
    }

    pub fn entries_to_shreds(
        &self,
        keypair: &Keypair,
        entries: &[Entry],
        is_last_in_slot: bool,
        next_shred_index: u32,
        next_code_index: u32,
        merkle_variant: bool,
        reed_solomon_cache: &ReedSolomonCache,
        stats: &mut ProcessShredsStats,
    ) -> (
        Vec<Shred>, // data shreds
        Vec<Shred>, // coding shreds
    ) {
        if merkle_variant {
            return shred::make_merkle_shreds_from_entries(
                &PAR_THREAD_POOL,
                keypair,
                entries,
                self.slot,
                self.parent_slot,
                self.version,
                self.reference_tick,
                is_last_in_slot,
                next_shred_index,
                next_code_index,
                reed_solomon_cache,
                stats,
            )
            .unwrap()
            .into_iter()
            .partition(Shred::is_data);
        }
        let data_shreds =
            self.entries_to_data_shreds(keypair, entries, is_last_in_slot, next_shred_index, stats);
        let coding_shreds = Self::data_shreds_to_coding_shreds(
            keypair,
            &data_shreds,
            next_code_index,
            reed_solomon_cache,
            stats,
        )
        .unwrap();
        (data_shreds, coding_shreds)
    }

    fn entries_to_data_shreds(
        &self,
        keypair: &Keypair,
        entries: &[Entry],
        is_last_in_slot: bool,
        next_shred_index: u32,
        process_stats: &mut ProcessShredsStats,
    ) -> Vec<Shred> {
        let mut serialize_time = Measure::start("shred_serialize");
        let serialized_shreds =
            bincode::serialize(entries).expect("Expect to serialize all entries");
        serialize_time.stop();

        let mut gen_data_time = Measure::start("shred_gen_data_time");
        let data_buffer_size = ShredData::capacity(/*merkle_proof_size:*/ None).unwrap();
        process_stats.data_buffer_residual +=
            (data_buffer_size - serialized_shreds.len() % data_buffer_size) % data_buffer_size;
        // Integer division to ensure we have enough shreds to fit all the data
        let num_shreds = (serialized_shreds.len() + data_buffer_size - 1) / data_buffer_size;
        let last_shred_index = next_shred_index + num_shreds as u32 - 1;
        // 1) Generate data shreds
        let make_data_shred = |data, shred_index: u32, fec_set_index: u32| {
            let flags = if shred_index != last_shred_index {
                ShredFlags::empty()
            } else if is_last_in_slot {
                // LAST_SHRED_IN_SLOT also implies DATA_COMPLETE_SHRED.
                ShredFlags::LAST_SHRED_IN_SLOT
            } else {
                ShredFlags::DATA_COMPLETE_SHRED
            };
            let parent_offset = self.slot - self.parent_slot;
            let mut shred = Shred::new_from_data(
                self.slot,
                shred_index,
                parent_offset as u16,
                data,
                flags,
                self.reference_tick,
                self.version,
                fec_set_index,
            );
            shred.sign(keypair);
            shred
        };
        let shreds: Vec<&[u8]> = serialized_shreds.chunks(data_buffer_size).collect();
        let fec_set_offsets: Vec<usize> =
            get_fec_set_offsets(shreds.len(), DATA_SHREDS_PER_FEC_BLOCK).collect();
        assert_eq!(shreds.len(), fec_set_offsets.len());
        let shreds: Vec<Shred> = PAR_THREAD_POOL.install(|| {
            shreds
                .into_par_iter()
                .zip(fec_set_offsets)
                .enumerate()
                .map(|(i, (shred, offset))| {
                    let shred_index = next_shred_index + i as u32;
                    let fec_set_index = next_shred_index + offset as u32;
                    make_data_shred(shred, shred_index, fec_set_index)
                })
                .collect()
        });
        gen_data_time.stop();

        process_stats.serialize_elapsed += serialize_time.as_us();
        process_stats.gen_data_elapsed += gen_data_time.as_us();
        process_stats.record_num_data_shreds(shreds.len());

        shreds
    }

    fn data_shreds_to_coding_shreds(
        keypair: &Keypair,
        data_shreds: &[Shred],
        next_code_index: u32,
        reed_solomon_cache: &ReedSolomonCache,
        process_stats: &mut ProcessShredsStats,
    ) -> Result<Vec<Shred>, Error> {
        if data_shreds.is_empty() {
            return Ok(Vec::default());
        }
        let mut gen_coding_time = Measure::start("gen_coding_shreds");
        let chunks: Vec<Vec<&Shred>> = data_shreds
            .iter()
            .group_by(|shred| shred.fec_set_index())
            .into_iter()
            .map(|(_, shreds)| shreds.collect())
            .collect();
        let next_code_index: Vec<_> = std::iter::once(next_code_index)
            .chain(
                chunks
                    .iter()
                    .scan(next_code_index, |next_code_index, chunk| {
                        let num_data_shreds = chunk.len();
                        let erasure_batch_size = get_erasure_batch_size(num_data_shreds);
                        *next_code_index += (erasure_batch_size - num_data_shreds) as u32;
                        Some(*next_code_index)
                    }),
            )
            .collect();
        // 1) Generate coding shreds
        let mut coding_shreds: Vec<_> = if chunks.len() <= 1 {
            chunks
                .into_iter()
                .zip(next_code_index)
                .flat_map(|(shreds, next_code_index)| {
                    Shredder::generate_coding_shreds(&shreds, next_code_index, reed_solomon_cache)
                })
                .collect()
        } else {
            PAR_THREAD_POOL.install(|| {
                chunks
                    .into_par_iter()
                    .zip(next_code_index)
                    .flat_map(|(shreds, next_code_index)| {
                        Shredder::generate_coding_shreds(
                            &shreds,
                            next_code_index,
                            reed_solomon_cache,
                        )
                    })
                    .collect()
            })
        };
        gen_coding_time.stop();

        let mut sign_coding_time = Measure::start("sign_coding_shreds");
        // 2) Sign coding shreds
        PAR_THREAD_POOL.install(|| {
            coding_shreds.par_iter_mut().for_each(|coding_shred| {
                coding_shred.sign(keypair);
            })
        });
        sign_coding_time.stop();

        process_stats.gen_coding_elapsed += gen_coding_time.as_us();
        process_stats.sign_coding_elapsed += sign_coding_time.as_us();
        Ok(coding_shreds)
    }

    /// Generates coding shreds for the data shreds in the current FEC set
    pub fn generate_coding_shreds<T: Borrow<Shred>>(
        data: &[T],
        next_code_index: u32,
        reed_solomon_cache: &ReedSolomonCache,
    ) -> Vec<Shred> {
        let (slot, index, version, fec_set_index) = {
            let shred = data.first().unwrap().borrow();
            (
                shred.slot(),
                shred.index(),
                shred.version(),
                shred.fec_set_index(),
            )
        };
        assert_eq!(fec_set_index, index);
        assert!(data
            .iter()
            .map(Borrow::borrow)
            .all(|shred| shred.slot() == slot
                && shred.version() == version
                && shred.fec_set_index() == fec_set_index));
        let num_data = data.len();
        let num_coding = get_erasure_batch_size(num_data)
            .checked_sub(num_data)
            .unwrap();
        assert!(num_coding > 0);
        let data: Vec<_> = data
            .iter()
            .map(Borrow::borrow)
            .map(Shred::erasure_shard_as_slice)
            .collect::<Result<_, _>>()
            .unwrap();
        let mut parity = vec![vec![0u8; data[0].len()]; num_coding];
        reed_solomon_cache
            .get(num_data, num_coding)
            .unwrap()
            .encode_sep(&data, &mut parity[..])
            .unwrap();
        let num_data = u16::try_from(num_data).unwrap();
        let num_coding = u16::try_from(num_coding).unwrap();
        parity
            .iter()
            .enumerate()
            .map(|(i, parity)| {
                let index = next_code_index + u32::try_from(i).unwrap();
                Shred::new_from_parity_shard(
                    slot,
                    index,
                    parity,
                    fec_set_index,
                    num_data,
                    num_coding,
                    u16::try_from(i).unwrap(), // position
                    version,
                )
            })
            .collect()
    }

    pub fn try_recovery(
        shreds: Vec<Shred>,
        reed_solomon_cache: &ReedSolomonCache,
    ) -> Result<Vec<Shred>, Error> {
        let (slot, fec_set_index) = match shreds.first() {
            None => return Err(Error::from(TooFewShardsPresent)),
            Some(shred) => (shred.slot(), shred.fec_set_index()),
        };
        let (num_data_shreds, num_coding_shreds) = match shreds.iter().find(|shred| shred.is_code())
        {
            None => return Ok(Vec::default()),
            Some(shred) => (
                shred.num_data_shreds().unwrap(),
                shred.num_coding_shreds().unwrap(),
            ),
        };
        debug_assert!(shreds
            .iter()
            .all(|shred| shred.slot() == slot && shred.fec_set_index() == fec_set_index));
        debug_assert!(shreds
            .iter()
            .filter(|shred| shred.is_code())
            .all(|shred| shred.num_data_shreds().unwrap() == num_data_shreds
                && shred.num_coding_shreds().unwrap() == num_coding_shreds));
        let num_data_shreds = num_data_shreds as usize;
        let num_coding_shreds = num_coding_shreds as usize;
        let fec_set_size = num_data_shreds + num_coding_shreds;
        if num_coding_shreds == 0 || shreds.len() >= fec_set_size {
            return Ok(Vec::default());
        }
        // Mask to exclude data shreds already received from the return value.
        let mut mask = vec![false; num_data_shreds];
        let mut shards = vec![None; fec_set_size];
        for shred in shreds {
            let index = match shred.erasure_shard_index() {
                Ok(index) if index < fec_set_size => index,
                _ => return Err(Error::from(InvalidIndex)),
            };
            shards[index] = Some(shred.erasure_shard()?);
            if index < num_data_shreds {
                mask[index] = true;
            }
        }
        reed_solomon_cache
            .get(num_data_shreds, num_coding_shreds)?
            .reconstruct_data(&mut shards)?;
        let recovered_data = mask
            .into_iter()
            .zip(shards)
            .filter(|(mask, _)| !mask)
            .filter_map(|(_, shard)| Shred::new_from_serialized_shred(shard?).ok())
            .filter(|shred| {
                shred.slot() == slot
                    && shred.is_data()
                    && match shred.erasure_shard_index() {
                        Ok(index) => index < num_data_shreds,
                        Err(_) => false,
                    }
            })
            .collect();
        Ok(recovered_data)
    }

    /// Combines all shreds to recreate the original buffer
    pub fn deshred(shreds: &[Shred]) -> Result<Vec<u8>, Error> {
        let index = shreds.first().ok_or(TooFewDataShards)?.index();
        let aligned = shreds.iter().zip(index..).all(|(s, i)| s.index() == i);
        let data_complete = {
            let shred = shreds.last().unwrap();
            shred.data_complete() || shred.last_in_slot()
        };
        if !data_complete || !aligned {
            return Err(Error::from(TooFewDataShards));
        }
        let data: Vec<_> = shreds.iter().map(Shred::data).collect::<Result<_, _>>()?;
        let data: Vec<_> = data.into_iter().flatten().copied().collect();
        if data.is_empty() {
            // For backward compatibility. This is needed when the data shred
            // payload is None, so that deserializing to Vec<Entry> results in
            // an empty vector.
            let data_buffer_size = ShredData::capacity(/*merkle_proof_size:*/ None).unwrap();
            Ok(vec![0u8; data_buffer_size])
        } else {
            Ok(data)
        }
    }
}

impl ReedSolomonCache {
    const CAPACITY: usize = 4 * DATA_SHREDS_PER_FEC_BLOCK;

    pub(crate) fn get(
        &self,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Arc<ReedSolomon>, reed_solomon_erasure::Error> {
        let key = (data_shards, parity_shards);
        {
            let mut cache = self.0.lock().unwrap();
            if let Some(entry) = cache.get(&key) {
                return Ok(entry.clone());
            }
        }
        let entry = ReedSolomon::new(data_shards, parity_shards)?;
        let entry = Arc::new(entry);
        {
            let entry = entry.clone();
            let mut cache = self.0.lock().unwrap();
            cache.put(key, entry);
        }
        Ok(entry)
    }
}

impl Default for ReedSolomonCache {
    fn default() -> Self {
        Self(Mutex::new(LruCache::new(Self::CAPACITY)))
    }
}

/// Maps number of data shreds in each batch to the erasure batch size.
pub(crate) fn get_erasure_batch_size(num_data_shreds: usize) -> usize {
    ERASURE_BATCH_SIZE
        .get(num_data_shreds)
        .copied()
        .unwrap_or(2 * num_data_shreds)
}

// Returns offsets to fec_set_index when spliting shreds into erasure batches.
fn get_fec_set_offsets(
    mut num_shreds: usize,
    min_chunk_size: usize,
) -> impl Iterator<Item = usize> {
    let mut offset = 0;
    std::iter::from_fn(move || {
        if num_shreds == 0 {
            return None;
        }
        let num_chunks = (num_shreds / min_chunk_size).max(1);
        let chunk_size = (num_shreds + num_chunks - 1) / num_chunks;
        let offsets = std::iter::repeat(offset).take(chunk_size);
        num_shreds -= chunk_size;
        offset += chunk_size;
        Some(offsets)
    })
    .flatten()
}
