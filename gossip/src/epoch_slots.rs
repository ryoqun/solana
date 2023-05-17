use {
    crate::{
        cluster_info::MAX_CRDS_OBJECT_SIZE,
        crds_value::{self, MAX_SLOT, MAX_WALLCLOCK},
    },
    bincode::serialized_size,
    bv::BitVec,
    flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress},
    solana_sdk::{
        clock::Slot,
        pubkey::Pubkey,
        sanitize::{Sanitize, SanitizeError},
    },
};

const MAX_SLOTS_PER_ENTRY: usize = 2048 * 8;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, AbiExample)]
pub struct Uncompressed {
    pub first_slot: Slot,
    pub num: usize,
    pub slots: BitVec<u8>,
}

impl Sanitize for Uncompressed {
    fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        if self.first_slot >= MAX_SLOT {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        if self.num >= MAX_SLOTS_PER_ENTRY {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        if self.slots.len() % 8 != 0 {
            // Uncompressed::new() ensures the length is always a multiple of 8
            return Err(SanitizeError::ValueOutOfBounds);
        }
        if self.slots.len() != self.slots.capacity() {
            // A BitVec<u8> with a length that's a multiple of 8 will always have len() equal to
            // capacity(), assuming no bit manipulation
            return Err(SanitizeError::ValueOutOfBounds);
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq, AbiExample)]
pub struct Flate2 {
    pub first_slot: Slot,
    pub num: usize,
    pub compressed: Vec<u8>,
}

impl Sanitize for Flate2 {
    fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        if self.first_slot >= MAX_SLOT {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        if self.num >= MAX_SLOTS_PER_ENTRY {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    CompressError,
    DecompressError,
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::convert::From<flate2::CompressError> for Error {
    fn from(_e: flate2::CompressError) -> Error {
        Error::CompressError
    }
}
impl std::convert::From<flate2::DecompressError> for Error {
    fn from(_e: flate2::DecompressError) -> Error {
        Error::DecompressError
    }
}

impl Flate2 {
    fn deflate(mut unc: Uncompressed) -> Result<Self> {
        let mut compressed = Vec::with_capacity(unc.slots.block_capacity());
        let mut compressor = Compress::new(Compression::best(), false);
        let first_slot = unc.first_slot;
        let num = unc.num;
        unc.slots.shrink_to_fit();
        let bits = unc.slots.into_boxed_slice();
        compressor.compress_vec(&bits, &mut compressed, FlushCompress::Finish)?;
        let rv = Self {
            first_slot,
            num,
            compressed,
        };
        let _ = rv.inflate()?;
        Ok(rv)
    }
    pub fn inflate(&self) -> Result<Uncompressed> {
        //add some head room for the decompressor which might spill more bits
        let mut uncompressed = Vec::with_capacity(32 + (self.num + 4) / 8);
        let mut decompress = Decompress::new(false);
        decompress.decompress_vec(&self.compressed, &mut uncompressed, FlushDecompress::Finish)?;
        Ok(Uncompressed {
            first_slot: self.first_slot,
            num: self.num,
            slots: BitVec::from_bits(&uncompressed),
        })
    }
}

impl Uncompressed {
    pub fn new(max_size: usize) -> Self {
        Self {
            num: 0,
            first_slot: 0,
            slots: BitVec::new_fill(false, 8 * max_size as u64),
        }
    }
    pub fn to_slots(&self, min_slot: Slot) -> Vec<Slot> {
        let mut rv = vec![];
        let start = if min_slot < self.first_slot {
            0
        } else {
            (min_slot - self.first_slot) as usize
        };
        for i in start..self.num {
            if i >= self.slots.len() as usize {
                break;
            }
            if self.slots.get(i as u64) {
                rv.push(self.first_slot + i as Slot);
            }
        }
        rv
    }
    pub fn add(&mut self, slots: &[Slot]) -> usize {
        for (i, s) in slots.iter().enumerate() {
            if self.num == 0 {
                self.first_slot = *s;
            }
            if self.num >= MAX_SLOTS_PER_ENTRY {
                return i;
            }
            if *s < self.first_slot {
                return i;
            }
            if *s - self.first_slot >= self.slots.len() {
                return i;
            }
            self.slots.set(*s - self.first_slot, true);
            self.num = std::cmp::max(self.num, 1 + (*s - self.first_slot) as usize);
        }
        slots.len()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, AbiExample, AbiEnumVisitor)]
pub enum CompressedSlots {
    Flate2(Flate2),
    Uncompressed(Uncompressed),
}

impl Sanitize for CompressedSlots {
    fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        match self {
            CompressedSlots::Uncompressed(a) => a.sanitize(),
            CompressedSlots::Flate2(b) => b.sanitize(),
        }
    }
}

impl Default for CompressedSlots {
    fn default() -> Self {
        CompressedSlots::new(0)
    }
}

impl CompressedSlots {
    fn new(max_size: usize) -> Self {
        CompressedSlots::Uncompressed(Uncompressed::new(max_size))
    }

    pub fn first_slot(&self) -> Slot {
        match self {
            CompressedSlots::Uncompressed(a) => a.first_slot,
            CompressedSlots::Flate2(b) => b.first_slot,
        }
    }

    pub fn num_slots(&self) -> usize {
        match self {
            CompressedSlots::Uncompressed(a) => a.num,
            CompressedSlots::Flate2(b) => b.num,
        }
    }

    pub fn add(&mut self, slots: &[Slot]) -> usize {
        match self {
            CompressedSlots::Uncompressed(vals) => vals.add(slots),
            CompressedSlots::Flate2(_) => 0,
        }
    }
    pub fn to_slots(&self, min_slot: Slot) -> Result<Vec<Slot>> {
        match self {
            CompressedSlots::Uncompressed(vals) => Ok(vals.to_slots(min_slot)),
            CompressedSlots::Flate2(vals) => {
                let unc = vals.inflate()?;
                Ok(unc.to_slots(min_slot))
            }
        }
    }
    pub fn deflate(&mut self) -> Result<()> {
        match self {
            CompressedSlots::Uncompressed(vals) => {
                let unc = vals.clone();
                let compressed = Flate2::deflate(unc)?;
                *self = CompressedSlots::Flate2(compressed);
                Ok(())
            }
            CompressedSlots::Flate2(_) => Ok(()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, AbiExample)]
pub struct EpochSlots {
    pub from: Pubkey,
    pub slots: Vec<CompressedSlots>,
    pub wallclock: u64,
}

impl Sanitize for EpochSlots {
    fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        if self.wallclock >= MAX_WALLCLOCK {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        self.from.sanitize()?;
        self.slots.sanitize()
    }
}

use std::fmt;
impl fmt::Debug for EpochSlots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let num_slots: usize = self.slots.iter().map(|s| s.num_slots()).sum();
        let lowest_slot = self
            .slots
            .iter()
            .map(|s| s.first_slot())
            .fold(0, std::cmp::min);
        write!(
            f,
            "EpochSlots {{ from: {} num_slots: {} lowest_slot: {} wallclock: {} }}",
            self.from, num_slots, lowest_slot, self.wallclock
        )
    }
}

impl EpochSlots {
    pub fn new(from: Pubkey, now: u64) -> Self {
        Self {
            from,
            wallclock: now,
            slots: vec![],
        }
    }
    pub fn fill(&mut self, slots: &[Slot], now: u64) -> usize {
        let mut num = 0;
        self.wallclock = std::cmp::max(now, self.wallclock + 1);
        while num < slots.len() {
            num += self.add(&slots[num..]);
            if num < slots.len() {
                if self.deflate().is_err() {
                    return num;
                }
                let space = self.max_compressed_slot_size();
                if space > 0 {
                    let cslot = CompressedSlots::new(space as usize);
                    self.slots.push(cslot);
                } else {
                    return num;
                }
            }
        }
        num
    }
    pub fn add(&mut self, slots: &[Slot]) -> usize {
        let mut num = 0;
        for s in &mut self.slots {
            num += s.add(&slots[num..]);
            if num >= slots.len() {
                break;
            }
        }
        num
    }
    pub fn deflate(&mut self) -> Result<()> {
        for s in self.slots.iter_mut() {
            s.deflate()?;
        }
        Ok(())
    }
    pub fn max_compressed_slot_size(&self) -> isize {
        let len_header = serialized_size(self).unwrap();
        let len_slot = serialized_size(&CompressedSlots::default()).unwrap();
        MAX_CRDS_OBJECT_SIZE as isize - (len_header + len_slot) as isize
    }

    pub fn first_slot(&self) -> Option<Slot> {
        self.slots.iter().map(|s| s.first_slot()).min()
    }

    pub fn to_slots(&self, min_slot: Slot) -> Vec<Slot> {
        self.slots
            .iter()
            .filter(|s| min_slot < s.first_slot() + s.num_slots() as u64)
            .filter_map(|s| s.to_slots(min_slot).ok())
            .flatten()
            .collect()
    }

    /// New random EpochSlots for tests and simulations.
    pub(crate) fn new_rand<R: rand::Rng>(rng: &mut R, pubkey: Option<Pubkey>) -> Self {
        let now = crds_value::new_rand_timestamp(rng);
        let pubkey = pubkey.unwrap_or_else(solana_sdk::pubkey::new_rand);
        let mut epoch_slots = Self::new(pubkey, now);
        let num_slots = rng.gen_range(0, 20);
        let slots: Vec<_> = std::iter::repeat_with(|| 47825632 + rng.gen_range(0, 512))
            .take(num_slots)
            .collect();
        epoch_slots.add(&slots);
        epoch_slots
    }
}

