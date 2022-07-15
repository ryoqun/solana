use {
    crate::shred::{
        Error, ProcessShredsStats, Shred, ShredData, ShredFlags, MAX_DATA_SHREDS_PER_FEC_BLOCK,
    },
    lazy_static::lazy_static,
    rayon::{prelude::*, ThreadPool},
    reed_solomon_erasure::{
        galois_8::Field,
        Error::{InvalidIndex, TooFewDataShards, TooFewShardsPresent},
    },
    solana_entry::entry::Entry,
    solana_measure::measure::Measure,
    solana_rayon_threadlimit::get_thread_count,
    solana_sdk::{clock::Slot, signature::Keypair},
    std::fmt::Debug,
};

lazy_static! {
    static ref PAR_THREAD_POOL: ThreadPool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_thread_count())
        .thread_name(|ix| format!("shredder_{}", ix))
        .build()
        .unwrap();
}

type ReedSolomon = reed_solomon_erasure::ReedSolomon<Field>;

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
        stats: &mut ProcessShredsStats,
    ) -> (
        Vec<Shred>, // data shreds
        Vec<Shred>, // coding shreds
    ) {
        let data_shreds = self.entries_to_data_shreds(
            keypair,
            entries,
            is_last_in_slot,
            next_shred_index,
            next_shred_index, // fec_set_offset
            stats,
        );
        let coding_shreds = Self::data_shreds_to_coding_shreds(
            keypair,
            &data_shreds,
            is_last_in_slot,
            next_code_index,
            stats,
        )
        .unwrap();
        (data_shreds, coding_shreds)
    }

    /// Each FEC block has maximum MAX_DATA_SHREDS_PER_FEC_BLOCK shreds.
    /// "FEC set index" is the index of first data shred in that FEC block.
    /// **Data** shreds with the same value of:
    ///     (data_shred.index() - fec_set_offset) / MAX_DATA_SHREDS_PER_FEC_BLOCK
    /// belong to the same FEC set.
    /// Coding shreds inherit their fec_set_index from the data shreds that
    /// they are generated from.
    pub fn fec_set_index(data_shred_index: u32, fec_set_offset: u32) -> Option<u32> {
        let diff = data_shred_index.checked_sub(fec_set_offset)?;
        Some(data_shred_index - diff % MAX_DATA_SHREDS_PER_FEC_BLOCK)
    }

    pub fn entries_to_data_shreds(
        &self,
        keypair: &Keypair,
        entries: &[Entry],
        is_last_in_slot: bool,
        next_shred_index: u32,
        // Shred index offset at which FEC sets are generated.
        fec_set_offset: u32,
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
        let make_data_shred = |shred_index: u32, data| {
            let flags = if shred_index != last_shred_index {
                ShredFlags::empty()
            } else if is_last_in_slot {
                // LAST_SHRED_IN_SLOT also implies DATA_COMPLETE_SHRED.
                ShredFlags::LAST_SHRED_IN_SLOT
            } else {
                ShredFlags::DATA_COMPLETE_SHRED
            };
            let parent_offset = self.slot - self.parent_slot;
            let fec_set_index = Self::fec_set_index(shred_index, fec_set_offset);
            let mut shred = Shred::new_from_data(
                self.slot,
                shred_index,
                parent_offset as u16,
                data,
                flags,
                self.reference_tick,
                self.version,
                fec_set_index.unwrap(),
            );
            shred.sign(keypair);
            shred
        };
        let data_shreds: Vec<Shred> = PAR_THREAD_POOL.install(|| {
            serialized_shreds
                .par_chunks(data_buffer_size)
                .enumerate()
                .map(|(i, shred_data)| {
                    let shred_index = next_shred_index + i as u32;
                    make_data_shred(shred_index, shred_data)
                })
                .collect()
        });
        gen_data_time.stop();

        process_stats.serialize_elapsed += serialize_time.as_us();
        process_stats.gen_data_elapsed += gen_data_time.as_us();
        process_stats.record_num_residual_data_shreds(data_shreds.len());

        data_shreds
    }

    pub fn data_shreds_to_coding_shreds(
        keypair: &Keypair,
        data_shreds: &[Shred],
        is_last_in_slot: bool,
        next_code_index: u32,
        process_stats: &mut ProcessShredsStats,
    ) -> Result<Vec<Shred>, Error> {
        if data_shreds.is_empty() {
            return Ok(Vec::default());
        }
        let mut gen_coding_time = Measure::start("gen_coding_shreds");
        // Step size when advancing next_code_index from one batch to the next.
        let step = get_erasure_batch_size(
            MAX_DATA_SHREDS_PER_FEC_BLOCK as usize,
            false, // is_last_in_slot
        ) - MAX_DATA_SHREDS_PER_FEC_BLOCK as usize;
        // 1) Generate coding shreds
        let mut coding_shreds: Vec<_> = PAR_THREAD_POOL.install(|| {
            data_shreds
                .par_chunks(MAX_DATA_SHREDS_PER_FEC_BLOCK as usize)
                .enumerate()
                .flat_map(|(k, shred_data_batch)| {
                    let offset = u32::try_from(step.checked_mul(k).unwrap());
                    let next_code_index = next_code_index.checked_add(offset.unwrap());
                    Shredder::generate_coding_shreds(
                        shred_data_batch,
                        is_last_in_slot,
                        next_code_index.unwrap(),
                    )
                })
                .collect()
        });
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
    pub fn generate_coding_shreds(
        data: &[Shred],
        is_last_in_slot: bool,
        next_code_index: u32,
    ) -> Vec<Shred> {
        let (slot, index, version, fec_set_index) = {
            let shred = data.first().unwrap();
            (
                shred.slot(),
                shred.index(),
                shred.version(),
                shred.fec_set_index(),
            )
        };
        assert_eq!(fec_set_index, index);
        assert!(data.iter().all(|shred| shred.slot() == slot
            && shred.version() == version
            && shred.fec_set_index() == fec_set_index));
        let num_data = data.len();
        let num_coding = get_erasure_batch_size(num_data, is_last_in_slot)
            .checked_sub(num_data)
            .unwrap();
        let data = data.iter().map(Shred::erasure_shard_as_slice);
        let data: Vec<_> = data.collect::<Result<_, _>>().unwrap();
        let mut parity = vec![vec![0u8; data[0].len()]; num_coding];
        ReedSolomon::new(num_data, num_coding)
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

    pub fn try_recovery(shreds: Vec<Shred>) -> Result<Vec<Shred>, Error> {
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
        ReedSolomon::new(num_data_shreds, num_coding_shreds)?.reconstruct_data(&mut shards)?;
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

/// Maps number of data shreds in each batch to the erasure batch size.
fn get_erasure_batch_size(num_data_shreds: usize, is_last_in_slot: bool) -> usize {
    if is_last_in_slot {
        2 * num_data_shreds.max(MAX_DATA_SHREDS_PER_FEC_BLOCK as usize)
    } else {
        2 * num_data_shreds
    }
}
