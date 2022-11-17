//! # Erasure Coding and Recovery
//!
//! Shreds are logically grouped into erasure sets or blocks. Each set contains 16 sequential data
//! shreds and 4 sequential coding shreds.
//!
//! Coding shreds in each set starting from `start_idx`:
//!   For each erasure set:
//!     generate `NUM_CODING` coding_shreds.
//!     index the coding shreds from `start_idx` to `start_idx + NUM_CODING - 1`.
//!
//!  model of an erasure set, with top row being data shreds and second being coding
//!  |<======================= NUM_DATA ==============================>|
//!  |<==== NUM_CODING ===>|
//!  +---+ +---+ +---+ +---+ +---+         +---+ +---+ +---+ +---+ +---+
//!  | D | | D | | D | | D | | D |         | D | | D | | D | | D | | D |
//!  +---+ +---+ +---+ +---+ +---+  . . .  +---+ +---+ +---+ +---+ +---+
//!  | C | | C | | C | | C | |   |         |   | |   | |   | |   | |   |
//!  +---+ +---+ +---+ +---+ +---+         +---+ +---+ +---+ +---+ +---+
//!
//!  shred structure for coding shreds
//!
//!   + ------- meta is set and used by transport, meta.size is actual length
//!   |           of data in the byte array shred.data
//!   |
//!   |          + -- data is stuff shipped over the wire, and has an included
//!   |          |        header
//!   V          V
//!  +----------+------------------------------------------------------------+
//!  | meta     |  data                                                      |
//!  |+---+--   |+---+---+---+---+------------------------------------------+|
//!  || s | .   || i |   | f | s |                                          ||
//!  || i | .   || n | i | l | i |                                          ||
//!  || z | .   || d | d | a | z |     shred.data(), or shred.data_mut()      ||
//!  || e |     || e |   | g | e |                                          ||
//!  |+---+--   || x |   | s |   |                                          ||
//!  |          |+---+---+---+---+------------------------------------------+|
//!  +----------+------------------------------------------------------------+
//!             |                |<=== coding shred part for "coding" =======>|
//!             |                                                            |
//!             |<============== data shred part for "coding"  ==============>|
//!
//!

use {
    reed_solomon_erasure::{galois_8::Field, ReconstructShard, ReedSolomon},
    serde::{Deserialize, Serialize},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ErasureConfig {
    num_data: usize,
    num_coding: usize,
}

impl ErasureConfig {
    pub(crate) fn new(num_data: usize, num_coding: usize) -> ErasureConfig {
        ErasureConfig {
            num_data,
            num_coding,
        }
    }

    pub(crate) fn num_data(self) -> usize {
        self.num_data
    }

    pub(crate) fn num_coding(self) -> usize {
        self.num_coding
    }
}

type Result<T> = std::result::Result<T, reed_solomon_erasure::Error>;

/// Represents an erasure "session" with a particular configuration and number of data and coding
/// shreds
#[derive(Debug, Clone)]
pub struct Session(ReedSolomon<Field>);

impl Session {
    pub fn new(data_count: usize, coding_count: usize) -> Result<Session> {
        let rs = ReedSolomon::new(data_count, coding_count)?;

        Ok(Session(rs))
    }

    pub fn new_from_config(config: &ErasureConfig) -> Result<Session> {
        let rs = ReedSolomon::new(config.num_data, config.num_coding)?;

        Ok(Session(rs))
    }

    /// Create coding blocks by overwriting `parity`
    pub fn encode<T, U>(&self, data: &[T], parity: &mut [U]) -> Result<()>
    where
        T: AsRef<[u8]>,
        U: AsRef<[u8]> + AsMut<[u8]>,
    {
        self.0.encode_sep(data, parity)
    }

    /// Recover data + coding blocks into data blocks
    pub fn decode_blocks<T>(&self, blocks: &mut [T]) -> Result<()>
    where
        T: ReconstructShard<Field>,
    {
        self.0.reconstruct_data(blocks)
    }
}
