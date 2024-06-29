use {
    crate::{
        shred::{
            self,
            common::impl_shred_common,
            dispatch, shred_code, shred_data,
            traits::{
                Shred as ShredTrait, ShredCode as ShredCodeTrait, ShredData as ShredDataTrait,
            },
            CodingShredHeader, DataShredHeader, Error, ProcessShredsStats, ShredCommonHeader,
            ShredFlags, ShredVariant, DATA_SHREDS_PER_FEC_BLOCK, SIZE_OF_CODING_SHRED_HEADERS,
            SIZE_OF_DATA_SHRED_HEADERS, SIZE_OF_SIGNATURE,
        },
        shredder::{self, ReedSolomonCache},
    },
    assert_matches::debug_assert_matches,
    itertools::{Either, Itertools},
    rayon::{prelude::*, ThreadPool},
    reed_solomon_erasure::Error::{InvalidIndex, TooFewParityShards, TooFewShards},
    solana_perf::packet::deserialize_from_with_limit,
    solana_sdk::{
        clock::Slot,
        hash::{hashv, Hash},
        pubkey::Pubkey,
        signature::{Signature, Signer},
        signer::keypair::Keypair,
    },
    static_assertions::const_assert_eq,
    std::{
        io::{Cursor, Write},
        ops::Range,
        time::Instant,
    },
};

const_assert_eq!(SIZE_OF_MERKLE_ROOT, 32);
pub(crate) const SIZE_OF_MERKLE_ROOT: usize = std::mem::size_of::<Hash>();
const_assert_eq!(SIZE_OF_MERKLE_PROOF_ENTRY, 20);
const SIZE_OF_MERKLE_PROOF_ENTRY: usize = std::mem::size_of::<MerkleProofEntry>();
const_assert_eq!(ShredData::SIZE_OF_PAYLOAD, 1203);

// Defense against second preimage attack:
// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
// Following Certificate Transparency, 0x00 and 0x01 bytes are prepended to
// hash data when computing leaf and internal node hashes respectively.
const MERKLE_HASH_PREFIX_LEAF: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
const MERKLE_HASH_PREFIX_NODE: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

type MerkleProofEntry = [u8; 20];

// Layout: {common, data} headers | data buffer
//     | [Merkle root of the previous erasure batch if chained]
//     | Merkle proof
//     | [Retransmitter's signature if resigned]
// The slice past signature till the end of the data buffer is erasure coded.
// The slice past signature and before the merkle proof is hashed to generate
// the Merkle tree. The root of the Merkle tree is signed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShredData {
    common_header: ShredCommonHeader,
    data_header: DataShredHeader,
    payload: Vec<u8>,
}

// Layout: {common, coding} headers | erasure coded shard
//     | [Merkle root of the previous erasure batch if chained]
//     | Merkle proof
//     | [Retransmitter's signature if resigned]
// The slice past signature and before the merkle proof is hashed to generate
// the Merkle tree. The root of the Merkle tree is signed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShredCode {
    common_header: ShredCommonHeader,
    coding_header: CodingShredHeader,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Shred {
    ShredCode(ShredCode),
    ShredData(ShredData),
}

impl Shred {
    dispatch!(fn common_header(&self) -> &ShredCommonHeader);
    dispatch!(fn erasure_shard_as_slice(&self) -> Result<&[u8], Error>);
    dispatch!(fn erasure_shard_index(&self) -> Result<usize, Error>);
    dispatch!(fn merkle_node(&self) -> Result<Hash, Error>);
    dispatch!(fn payload(&self) -> &Vec<u8>);
    dispatch!(fn sanitize(&self) -> Result<(), Error>);
    dispatch!(fn set_merkle_proof(&mut self, proof: &[&MerkleProofEntry]) -> Result<(), Error>);
    dispatch!(fn set_signature(&mut self, signature: Signature));
    dispatch!(fn signed_data(&self) -> Result<Hash, Error>);

    fn merkle_proof(&self) -> Result<impl Iterator<Item = &MerkleProofEntry>, Error> {
        match self {
            Self::ShredCode(shred) => shred.merkle_proof().map(Either::Left),
            Self::ShredData(shred) => shred.merkle_proof().map(Either::Right),
        }
    }

    #[must_use]
    fn verify(&self, pubkey: &Pubkey) -> bool {
        match self.signed_data() {
            Ok(data) => self.signature().verify(pubkey.as_ref(), data.as_ref()),
            Err(_) => false,
        }
    }

    fn signature(&self) -> &Signature {
        &self.common_header().signature
    }

    fn from_payload(shred: Vec<u8>) -> Result<Self, Error> {
        match shred::layout::get_shred_variant(&shred)? {
            ShredVariant::LegacyCode | ShredVariant::LegacyData => Err(Error::InvalidShredVariant),
            ShredVariant::MerkleCode { .. } => Ok(Self::ShredCode(ShredCode::from_payload(shred)?)),
            ShredVariant::MerkleData { .. } => Ok(Self::ShredData(ShredData::from_payload(shred)?)),
        }
    }
}

impl ShredData {
    impl_merkle_shred!(MerkleData);

    fn from_recovered_shard(
        signature: &Signature,
        chained_merkle_root: &Option<Hash>,
        retransmitter_signature: &Option<Signature>,
        mut shard: Vec<u8>,
    ) -> Result<Self, Error> {
        let shard_size = shard.len();
        if shard_size + SIZE_OF_SIGNATURE > Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidShardSize(shard_size));
        }
        shard.resize(Self::SIZE_OF_PAYLOAD, 0u8);
        shard.copy_within(0..shard_size, SIZE_OF_SIGNATURE);
        shard[0..SIZE_OF_SIGNATURE].copy_from_slice(signature.as_ref());
        // Deserialize headers.
        let mut cursor = Cursor::new(&shard[..]);
        let common_header: ShredCommonHeader = deserialize_from_with_limit(&mut cursor)?;
        let ShredVariant::MerkleData {
            proof_size,
            chained,
            resigned,
        } = common_header.shred_variant
        else {
            return Err(Error::InvalidShredVariant);
        };
        if ShredCode::capacity(proof_size, chained, resigned)? != shard_size {
            return Err(Error::InvalidShardSize(shard_size));
        }
        let data_header = deserialize_from_with_limit(&mut cursor)?;
        let mut shred = Self {
            common_header,
            data_header,
            payload: shard,
        };
        if let Some(chained_merkle_root) = chained_merkle_root {
            shred.set_chained_merkle_root(chained_merkle_root)?;
        }
        if let Some(signature) = retransmitter_signature {
            shred.set_retransmitter_signature(signature)?;
        }
        shred.sanitize()?;
        Ok(shred)
    }

    pub(super) fn get_merkle_root(
        shred: &[u8],
        proof_size: u8,
        chained: bool,
        resigned: bool,
    ) -> Option<Hash> {
        debug_assert_eq!(
            shred::layout::get_shred_variant(shred).unwrap(),
            ShredVariant::MerkleData {
                proof_size,
                chained,
                resigned,
            },
        );
        // Shred index in the erasure batch.
        let index = {
            let fec_set_index = <[u8; 4]>::try_from(shred.get(79..83)?)
                .map(u32::from_le_bytes)
                .ok()?;
            shred::layout::get_index(shred)?
                .checked_sub(fec_set_index)
                .map(usize::try_from)?
                .ok()?
        };
        let proof_offset = Self::get_proof_offset(proof_size, chained, resigned).ok()?;
        let proof = get_merkle_proof(shred, proof_offset, proof_size).ok()?;
        let node = get_merkle_node(shred, SIZE_OF_SIGNATURE..proof_offset).ok()?;
        get_merkle_root(index, node, proof).ok()
    }
}

impl ShredCode {
    impl_merkle_shred!(MerkleCode);

    fn from_recovered_shard(
        common_header: ShredCommonHeader,
        coding_header: CodingShredHeader,
        chained_merkle_root: &Option<Hash>,
        retransmitter_signature: &Option<Signature>,
        mut shard: Vec<u8>,
    ) -> Result<Self, Error> {
        let ShredVariant::MerkleCode {
            proof_size,
            chained,
            resigned,
        } = common_header.shred_variant
        else {
            return Err(Error::InvalidShredVariant);
        };
        let shard_size = shard.len();
        if Self::capacity(proof_size, chained, resigned)? != shard_size {
            return Err(Error::InvalidShardSize(shard_size));
        }
        if shard_size + Self::SIZE_OF_HEADERS > Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidShardSize(shard_size));
        }
        shard.resize(Self::SIZE_OF_PAYLOAD, 0u8);
        shard.copy_within(0..shard_size, Self::SIZE_OF_HEADERS);
        let mut cursor = Cursor::new(&mut shard[..]);
        bincode::serialize_into(&mut cursor, &common_header)?;
        bincode::serialize_into(&mut cursor, &coding_header)?;
        let mut shred = Self {
            common_header,
            coding_header,
            payload: shard,
        };
        if let Some(chained_merkle_root) = chained_merkle_root {
            shred.set_chained_merkle_root(chained_merkle_root)?;
        }
        if let Some(signature) = retransmitter_signature {
            shred.set_retransmitter_signature(signature)?;
        }
        shred.sanitize()?;
        Ok(shred)
    }

    pub(super) fn get_merkle_root(
        shred: &[u8],
        proof_size: u8,
        chained: bool,
        resigned: bool,
    ) -> Option<Hash> {
        debug_assert_eq!(
            shred::layout::get_shred_variant(shred).unwrap(),
            ShredVariant::MerkleCode {
                proof_size,
                chained,
                resigned,
            },
        );
        // Shred index in the erasure batch.
        let index = {
            let num_data_shreds = <[u8; 2]>::try_from(shred.get(83..85)?)
                .map(u16::from_le_bytes)
                .map(usize::from)
                .ok()?;
            let position = <[u8; 2]>::try_from(shred.get(87..89)?)
                .map(u16::from_le_bytes)
                .map(usize::from)
                .ok()?;
            num_data_shreds.checked_add(position)?
        };
        let proof_offset = Self::get_proof_offset(proof_size, chained, resigned).ok()?;
        let proof = get_merkle_proof(shred, proof_offset, proof_size).ok()?;
        let node = get_merkle_node(shred, SIZE_OF_SIGNATURE..proof_offset).ok()?;
        get_merkle_root(index, node, proof).ok()
    }
}

macro_rules! impl_merkle_shred {
    ($variant:ident) => {
        // proof_size is the number of merkle proof entries.
        fn proof_size(&self) -> Result<u8, Error> {
            match self.common_header.shred_variant {
                ShredVariant::$variant { proof_size, .. } => Ok(proof_size),
                _ => Err(Error::InvalidShredVariant),
            }
        }

        // For ShredCode, size of buffer embedding erasure codes.
        // For ShredData, maximum size of ledger data that can be embedded in a
        // data-shred, which is also equal to:
        //   ShredCode::capacity(proof_size, chained, resigned).unwrap()
        //       - ShredData::SIZE_OF_HEADERS
        //       + SIZE_OF_SIGNATURE
        pub(super) fn capacity(
            proof_size: u8,
            chained: bool,
            resigned: bool,
        ) -> Result<usize, Error> {
            debug_assert!(chained || !resigned);
            // Merkle proof is generated and signed after coding shreds are
            // generated. Coding shred headers cannot be erasure coded either.
            Self::SIZE_OF_PAYLOAD
                .checked_sub(
                    Self::SIZE_OF_HEADERS
                        + if chained { SIZE_OF_MERKLE_ROOT } else { 0 }
                        + usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY
                        + if resigned { SIZE_OF_SIGNATURE } else { 0 },
                )
                .ok_or(Error::InvalidProofSize(proof_size))
        }

        // Where the merkle proof starts in the shred binary.
        fn proof_offset(&self) -> Result<usize, Error> {
            let ShredVariant::$variant {
                proof_size,
                chained,
                resigned,
            } = self.common_header.shred_variant
            else {
                return Err(Error::InvalidShredVariant);
            };
            Self::get_proof_offset(proof_size, chained, resigned)
        }

        fn get_proof_offset(proof_size: u8, chained: bool, resigned: bool) -> Result<usize, Error> {
            Ok(Self::SIZE_OF_HEADERS
                + Self::capacity(proof_size, chained, resigned)?
                + if chained { SIZE_OF_MERKLE_ROOT } else { 0 })
        }

        fn chained_merkle_root_offset(&self) -> Result<usize, Error> {
            let ShredVariant::$variant {
                proof_size,
                chained,
                resigned,
            } = self.common_header.shred_variant
            else {
                return Err(Error::InvalidShredVariant);
            };
            Self::get_chained_merkle_root_offset(proof_size, chained, resigned)
        }

        pub(super) fn get_chained_merkle_root_offset(
            proof_size: u8,
            chained: bool,
            resigned: bool,
        ) -> Result<usize, Error> {
            if !chained {
                return Err(Error::InvalidShredVariant);
            }
            debug_assert!(chained);
            Ok(Self::SIZE_OF_HEADERS + Self::capacity(proof_size, chained, resigned)?)
        }

        pub(super) fn chained_merkle_root(&self) -> Result<Hash, Error> {
            let offset = self.chained_merkle_root_offset()?;
            self.payload
                .get(offset..offset + SIZE_OF_MERKLE_ROOT)
                .map(Hash::new)
                .ok_or(Error::InvalidPayloadSize(self.payload.len()))
        }

        fn set_chained_merkle_root(&mut self, chained_merkle_root: &Hash) -> Result<(), Error> {
            let offset = self.chained_merkle_root_offset()?;
            let Some(buffer) = self.payload.get_mut(offset..offset + SIZE_OF_MERKLE_ROOT) else {
                return Err(Error::InvalidPayloadSize(self.payload.len()));
            };
            buffer.copy_from_slice(chained_merkle_root.as_ref());
            Ok(())
        }

        pub(super) fn merkle_root(&self) -> Result<Hash, Error> {
            let proof_size = self.proof_size()?;
            let index = self.erasure_shard_index()?;
            let proof_offset = self.proof_offset()?;
            let proof = get_merkle_proof(&self.payload, proof_offset, proof_size)?;
            let node = get_merkle_node(&self.payload, SIZE_OF_SIGNATURE..proof_offset)?;
            get_merkle_root(index, node, proof)
        }

        fn merkle_proof(&self) -> Result<impl Iterator<Item = &MerkleProofEntry>, Error> {
            let proof_size = self.proof_size()?;
            let proof_offset = self.proof_offset()?;
            get_merkle_proof(&self.payload, proof_offset, proof_size)
        }

        fn merkle_node(&self) -> Result<Hash, Error> {
            let proof_offset = self.proof_offset()?;
            get_merkle_node(&self.payload, SIZE_OF_SIGNATURE..proof_offset)
        }

        fn set_merkle_proof(&mut self, proof: &[&MerkleProofEntry]) -> Result<(), Error> {
            let proof_size = self.proof_size()?;
            if proof.len() != usize::from(proof_size) {
                return Err(Error::InvalidMerkleProof);
            }
            let proof_offset = self.proof_offset()?;
            let mut cursor = Cursor::new(
                self.payload
                    .get_mut(proof_offset..)
                    .ok_or(Error::InvalidProofSize(proof_size))?,
            );
            for entry in proof {
                bincode::serialize_into(&mut cursor, entry)?;
            }
            Ok(())
        }

        pub(super) fn retransmitter_signature(&self) -> Result<Signature, Error> {
            let offset = self.retransmitter_signature_offset()?;
            self.payload
                .get(offset..offset + SIZE_OF_SIGNATURE)
                .map(|bytes| <[u8; SIZE_OF_SIGNATURE]>::try_from(bytes).unwrap())
                .map(Signature::from)
                .ok_or(Error::InvalidPayloadSize(self.payload.len()))
        }

        fn set_retransmitter_signature(&mut self, signature: &Signature) -> Result<(), Error> {
            let offset = self.retransmitter_signature_offset()?;
            let Some(buffer) = self.payload.get_mut(offset..offset + SIZE_OF_SIGNATURE) else {
                return Err(Error::InvalidPayloadSize(self.payload.len()));
            };
            buffer.copy_from_slice(signature.as_ref());
            Ok(())
        }

        fn retransmitter_signature_offset(&self) -> Result<usize, Error> {
            let ShredVariant::$variant {
                proof_size,
                chained,
                resigned,
            } = self.common_header.shred_variant
            else {
                return Err(Error::InvalidShredVariant);
            };
            Self::get_retransmitter_signature_offset(proof_size, chained, resigned)
        }

        pub(super) fn get_retransmitter_signature_offset(
            proof_size: u8,
            chained: bool,
            resigned: bool,
        ) -> Result<usize, Error> {
            if !resigned {
                return Err(Error::InvalidShredVariant);
            }
            let proof_offset = Self::get_proof_offset(proof_size, chained, resigned)?;
            Ok(proof_offset + usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY)
        }
    };
}

use impl_merkle_shred;

impl<'a> ShredTrait<'a> for ShredData {
    type SignedData = Hash;

    impl_shred_common!();

    // Also equal to:
    // ShredData::SIZE_OF_HEADERS
    //       + ShredData::capacity(proof_size, chained, resigned).unwrap()
    //       + if chained { SIZE_OF_MERKLE_ROOT } else { 0 }
    //       + usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY
    //       + if resigned { SIZE_OF_SIGNATURE } else { 0 }
    const SIZE_OF_PAYLOAD: usize =
        ShredCode::SIZE_OF_PAYLOAD - ShredCode::SIZE_OF_HEADERS + SIZE_OF_SIGNATURE;
    const SIZE_OF_HEADERS: usize = SIZE_OF_DATA_SHRED_HEADERS;

    fn from_payload(mut payload: Vec<u8>) -> Result<Self, Error> {
        // see: https://github.com/solana-labs/solana/pull/10109
        if payload.len() < Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(payload.len()));
        }
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        let mut cursor = Cursor::new(&payload[..]);
        let common_header: ShredCommonHeader = deserialize_from_with_limit(&mut cursor)?;
        if !matches!(common_header.shred_variant, ShredVariant::MerkleData { .. }) {
            return Err(Error::InvalidShredVariant);
        }
        let data_header = deserialize_from_with_limit(&mut cursor)?;
        let shred = Self {
            common_header,
            data_header,
            payload,
        };
        shred.sanitize()?;
        Ok(shred)
    }

    fn erasure_shard_index(&self) -> Result<usize, Error> {
        shred_data::erasure_shard_index(self).ok_or_else(|| {
            let headers = Box::new((self.common_header, self.data_header));
            Error::InvalidErasureShardIndex(headers)
        })
    }

    fn erasure_shard(self) -> Result<Vec<u8>, Error> {
        if self.payload.len() != Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(self.payload.len()));
        }
        let ShredVariant::MerkleData {
            proof_size,
            chained,
            resigned,
        } = self.common_header.shred_variant
        else {
            return Err(Error::InvalidShredVariant);
        };
        let offset = Self::SIZE_OF_HEADERS + Self::capacity(proof_size, chained, resigned)?;
        let mut shard = self.payload;
        shard.truncate(offset);
        shard.drain(..SIZE_OF_SIGNATURE);
        Ok(shard)
    }

    fn erasure_shard_as_slice(&self) -> Result<&[u8], Error> {
        if self.payload.len() != Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(self.payload.len()));
        }
        let ShredVariant::MerkleData {
            proof_size,
            chained,
            resigned,
        } = self.common_header.shred_variant
        else {
            return Err(Error::InvalidShredVariant);
        };
        let offset = Self::SIZE_OF_HEADERS + Self::capacity(proof_size, chained, resigned)?;
        self.payload
            .get(SIZE_OF_SIGNATURE..offset)
            .ok_or(Error::InvalidPayloadSize(self.payload.len()))
    }

    fn sanitize(&self) -> Result<(), Error> {
        let shred_variant = self.common_header.shred_variant;
        if !matches!(shred_variant, ShredVariant::MerkleData { .. }) {
            return Err(Error::InvalidShredVariant);
        }
        let _ = self.merkle_proof()?;
        shred_data::sanitize(self)
    }

    fn signed_data(&'a self) -> Result<Self::SignedData, Error> {
        self.merkle_root()
    }
}

impl<'a> ShredTrait<'a> for ShredCode {
    type SignedData = Hash;

    impl_shred_common!();
    const SIZE_OF_PAYLOAD: usize = shred_code::ShredCode::SIZE_OF_PAYLOAD;
    const SIZE_OF_HEADERS: usize = SIZE_OF_CODING_SHRED_HEADERS;

    fn from_payload(mut payload: Vec<u8>) -> Result<Self, Error> {
        let mut cursor = Cursor::new(&payload[..]);
        let common_header: ShredCommonHeader = deserialize_from_with_limit(&mut cursor)?;
        if !matches!(common_header.shred_variant, ShredVariant::MerkleCode { .. }) {
            return Err(Error::InvalidShredVariant);
        }
        let coding_header = deserialize_from_with_limit(&mut cursor)?;
        // see: https://github.com/solana-labs/solana/pull/10109
        if payload.len() < Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(payload.len()));
        }
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        let shred = Self {
            common_header,
            coding_header,
            payload,
        };
        shred.sanitize()?;
        Ok(shred)
    }

    fn erasure_shard_index(&self) -> Result<usize, Error> {
        shred_code::erasure_shard_index(self).ok_or_else(|| {
            let headers = Box::new((self.common_header, self.coding_header));
            Error::InvalidErasureShardIndex(headers)
        })
    }

    fn erasure_shard(self) -> Result<Vec<u8>, Error> {
        if self.payload.len() != Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(self.payload.len()));
        }
        let ShredVariant::MerkleCode {
            proof_size,
            chained,
            resigned,
        } = self.common_header.shred_variant
        else {
            return Err(Error::InvalidShredVariant);
        };
        let offset = Self::SIZE_OF_HEADERS + Self::capacity(proof_size, chained, resigned)?;
        let mut shard = self.payload;
        shard.truncate(offset);
        shard.drain(..Self::SIZE_OF_HEADERS);
        Ok(shard)
    }

    fn erasure_shard_as_slice(&self) -> Result<&[u8], Error> {
        if self.payload.len() != Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(self.payload.len()));
        }
        let ShredVariant::MerkleCode {
            proof_size,
            chained,
            resigned,
        } = self.common_header.shred_variant
        else {
            return Err(Error::InvalidShredVariant);
        };
        let offset = Self::SIZE_OF_HEADERS + Self::capacity(proof_size, chained, resigned)?;
        self.payload
            .get(Self::SIZE_OF_HEADERS..offset)
            .ok_or(Error::InvalidPayloadSize(self.payload.len()))
    }

    fn sanitize(&self) -> Result<(), Error> {
        let shred_variant = self.common_header.shred_variant;
        if !matches!(shred_variant, ShredVariant::MerkleCode { .. }) {
            return Err(Error::InvalidShredVariant);
        }
        let _ = self.merkle_proof()?;
        shred_code::sanitize(self)
    }

    fn signed_data(&'a self) -> Result<Self::SignedData, Error> {
        self.merkle_root()
    }
}

impl ShredDataTrait for ShredData {
    #[inline]
    fn data_header(&self) -> &DataShredHeader {
        &self.data_header
    }

    fn data(&self) -> Result<&[u8], Error> {
        let ShredVariant::MerkleData {
            proof_size,
            chained,
            resigned,
        } = self.common_header.shred_variant
        else {
            return Err(Error::InvalidShredVariant);
        };
        let data_buffer_size = Self::capacity(proof_size, chained, resigned)?;
        let size = usize::from(self.data_header.size);
        if size > self.payload.len()
            || size < Self::SIZE_OF_HEADERS
            || size > Self::SIZE_OF_HEADERS + data_buffer_size
        {
            return Err(Error::InvalidDataSize {
                size: self.data_header.size,
                payload: self.payload.len(),
            });
        }
        Ok(&self.payload[Self::SIZE_OF_HEADERS..size])
    }
}

impl ShredCodeTrait for ShredCode {
    #[inline]
    fn coding_header(&self) -> &CodingShredHeader {
        &self.coding_header
    }
}

// Obtains parent's hash by joining two sibiling nodes in merkle tree.
fn join_nodes<S: AsRef<[u8]>, T: AsRef<[u8]>>(node: S, other: T) -> Hash {
    let node = &node.as_ref()[..SIZE_OF_MERKLE_PROOF_ENTRY];
    let other = &other.as_ref()[..SIZE_OF_MERKLE_PROOF_ENTRY];
    hashv(&[MERKLE_HASH_PREFIX_NODE, node, other])
}

// Recovers root of the merkle tree from a leaf node
// at the given index and the respective proof.
fn get_merkle_root<'a, I>(index: usize, node: Hash, proof: I) -> Result<Hash, Error>
where
    I: IntoIterator<Item = &'a MerkleProofEntry>,
{
    let (index, root) = proof
        .into_iter()
        .fold((index, node), |(index, node), other| {
            let parent = if index % 2 == 0 {
                join_nodes(node, other)
            } else {
                join_nodes(other, node)
            };
            (index >> 1, parent)
        });
    (index == 0)
        .then_some(root)
        .ok_or(Error::InvalidMerkleProof)
}

fn get_merkle_proof(
    shred: &[u8],
    proof_offset: usize, // Where the merkle proof starts.
    proof_size: u8,      // Number of proof entries.
) -> Result<impl Iterator<Item = &MerkleProofEntry>, Error> {
    let proof_size = usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY;
    Ok(shred
        .get(proof_offset..proof_offset + proof_size)
        .ok_or(Error::InvalidPayloadSize(shred.len()))?
        .chunks(SIZE_OF_MERKLE_PROOF_ENTRY)
        .map(<&MerkleProofEntry>::try_from)
        .map(Result::unwrap))
}

fn get_merkle_node(shred: &[u8], offsets: Range<usize>) -> Result<Hash, Error> {
    let node = shred
        .get(offsets)
        .ok_or(Error::InvalidPayloadSize(shred.len()))?;
    Ok(hashv(&[MERKLE_HASH_PREFIX_LEAF, node]))
}

fn make_merkle_tree(mut nodes: Vec<Hash>) -> Vec<Hash> {
    let mut size = nodes.len();
    while size > 1 {
        let offset = nodes.len() - size;
        for index in (offset..offset + size).step_by(2) {
            let node = &nodes[index];
            let other = &nodes[(index + 1).min(offset + size - 1)];
            let parent = join_nodes(node, other);
            nodes.push(parent);
        }
        size = nodes.len() - offset - size;
    }
    nodes
}

fn make_merkle_proof(
    mut index: usize, // leaf index ~ shred's erasure shard index.
    mut size: usize,  // number of leaves ~ erasure batch size.
    tree: &[Hash],
) -> Option<Vec<&MerkleProofEntry>> {
    if index >= size {
        return None;
    }
    let mut offset = 0;
    let mut proof = Vec::<&MerkleProofEntry>::new();
    while size > 1 {
        let node = tree.get(offset + (index ^ 1).min(size - 1))?;
        let entry = &node.as_ref()[..SIZE_OF_MERKLE_PROOF_ENTRY];
        proof.push(<&MerkleProofEntry>::try_from(entry).unwrap());
        offset += size;
        size = (size + 1) >> 1;
        index >>= 1;
    }
    (offset + 1 == tree.len()).then_some(proof)
}

pub(super) fn recover(
    mut shreds: Vec<Shred>,
    reed_solomon_cache: &ReedSolomonCache,
) -> Result<Vec<Shred>, Error> {
    // Grab {common, coding} headers from first coding shred.
    // Incoming shreds are resigned immediately after signature verification,
    // so we can just grab the retransmitter signature from one of the
    // available shreds and attach it to the recovered shreds.
    let (common_header, coding_header, chained_merkle_root, retransmitter_signature) = shreds
        .iter()
        .find_map(|shred| {
            let Shred::ShredCode(shred) = shred else {
                return None;
            };
            let chained_merkle_root = shred.chained_merkle_root().ok();
            let retransmitter_signature = shred.retransmitter_signature().ok();
            let position = u32::from(shred.coding_header.position);
            let common_header = ShredCommonHeader {
                index: shred.common_header.index.checked_sub(position)?,
                ..shred.common_header
            };
            let coding_header = CodingShredHeader {
                position: 0u16,
                ..shred.coding_header
            };
            Some((
                common_header,
                coding_header,
                chained_merkle_root,
                retransmitter_signature,
            ))
        })
        .ok_or(TooFewParityShards)?;
    debug_assert_matches!(common_header.shred_variant, ShredVariant::MerkleCode { .. });
    let (proof_size, chained, resigned) = match common_header.shred_variant {
        ShredVariant::MerkleCode {
            proof_size,
            chained,
            resigned,
        } => (proof_size, chained, resigned),
        ShredVariant::MerkleData { .. } | ShredVariant::LegacyCode | ShredVariant::LegacyData => {
            return Err(Error::InvalidShredVariant);
        }
    };
    debug_assert!(!resigned || retransmitter_signature.is_some());
    // Verify that shreds belong to the same erasure batch
    // and have consistent headers.
    debug_assert!(shreds.iter().all(|shred| {
        let ShredCommonHeader {
            signature,
            shred_variant,
            slot,
            index: _,
            version,
            fec_set_index,
        } = shred.common_header();
        signature == &common_header.signature
            && slot == &common_header.slot
            && version == &common_header.version
            && fec_set_index == &common_header.fec_set_index
            && match shred {
                Shred::ShredData(_) => {
                    shred_variant
                        == &ShredVariant::MerkleData {
                            proof_size,
                            chained,
                            resigned,
                        }
                }
                Shred::ShredCode(shred) => {
                    let CodingShredHeader {
                        num_data_shreds,
                        num_coding_shreds,
                        position: _,
                    } = shred.coding_header;
                    shred_variant
                        == &ShredVariant::MerkleCode {
                            proof_size,
                            chained,
                            resigned,
                        }
                        && num_data_shreds == coding_header.num_data_shreds
                        && num_coding_shreds == coding_header.num_coding_shreds
                }
            }
    }));
    let num_data_shreds = usize::from(coding_header.num_data_shreds);
    let num_coding_shreds = usize::from(coding_header.num_coding_shreds);
    let num_shards = num_data_shreds + num_coding_shreds;
    // Obtain erasure encoded shards from shreds.
    let shreds = {
        let mut batch = vec![None; num_shards];
        while let Some(shred) = shreds.pop() {
            let index = match shred.erasure_shard_index() {
                Ok(index) if index < batch.len() => index,
                _ => return Err(Error::from(InvalidIndex)),
            };
            batch[index] = Some(shred);
        }
        batch
    };
    let mut shards: Vec<Option<Vec<u8>>> = shreds
        .iter()
        .map(|shred| Some(shred.as_ref()?.erasure_shard_as_slice().ok()?.to_vec()))
        .collect();
    reed_solomon_cache
        .get(num_data_shreds, num_coding_shreds)?
        .reconstruct(&mut shards)?;
    let mask: Vec<_> = shreds.iter().map(Option::is_some).collect();
    // Reconstruct code and data shreds from erasure encoded shards.
    let mut shreds: Vec<_> = shreds
        .into_iter()
        .zip(shards)
        .enumerate()
        .map(|(index, (shred, shard))| {
            if let Some(shred) = shred {
                return Ok(shred);
            }
            let shard = shard.ok_or(TooFewShards)?;
            if index < num_data_shreds {
                let shred = ShredData::from_recovered_shard(
                    &common_header.signature,
                    &chained_merkle_root,
                    &retransmitter_signature,
                    shard,
                )?;
                let ShredCommonHeader {
                    signature: _,
                    shred_variant,
                    slot,
                    index: _,
                    version,
                    fec_set_index,
                } = shred.common_header;
                let expected_shred_variant = ShredVariant::MerkleData {
                    proof_size,
                    chained,
                    resigned,
                };
                if shred_variant != expected_shred_variant
                    || common_header.slot != slot
                    || common_header.version != version
                    || common_header.fec_set_index != fec_set_index
                {
                    return Err(Error::InvalidRecoveredShred);
                }
                Ok(Shred::ShredData(shred))
            } else {
                let offset = index - num_data_shreds;
                let coding_header = CodingShredHeader {
                    position: offset as u16,
                    ..coding_header
                };
                let common_header = ShredCommonHeader {
                    index: common_header.index + offset as u32,
                    ..common_header
                };
                let shred = ShredCode::from_recovered_shard(
                    common_header,
                    coding_header,
                    &chained_merkle_root,
                    &retransmitter_signature,
                    shard,
                )?;
                Ok(Shred::ShredCode(shred))
            }
        })
        .collect::<Result<_, Error>>()?;
    // Compute merkle tree and set the merkle proof on the recovered shreds.
    let nodes: Vec<_> = shreds
        .iter()
        .map(Shred::merkle_node)
        .collect::<Result<_, _>>()?;
    let tree = make_merkle_tree(nodes);
    for (index, (shred, mask)) in shreds.iter_mut().zip(&mask).enumerate() {
        let proof = make_merkle_proof(index, num_shards, &tree).ok_or(Error::InvalidMerkleProof)?;
        if proof.len() != usize::from(proof_size) {
            return Err(Error::InvalidMerkleProof);
        }
        if *mask {
            if shred.merkle_proof()?.ne(proof) {
                return Err(Error::InvalidMerkleProof);
            }
        } else {
            shred.set_merkle_proof(&proof)?;
            // Already sanitized in Shred{Code,Data}::from_recovered_shard.
            debug_assert_matches!(shred.sanitize(), Ok(()));
            // Assert that shred payload is fully populated.
            debug_assert_eq!(shred, {
                let shred = shred.payload().clone();
                &Shred::from_payload(shred).unwrap()
            });
        }
    }
    Ok(shreds
        .into_iter()
        .zip(mask)
        .filter(|(_, mask)| !mask)
        .map(|(shred, _)| shred)
        .collect())
}

// Maps number of (code + data) shreds to merkle_proof.len().
fn get_proof_size(num_shreds: usize) -> u8 {
    let bits = usize::BITS - num_shreds.leading_zeros();
    let proof_size = if num_shreds.is_power_of_two() {
        bits.checked_sub(1).unwrap()
    } else {
        bits
    };
    u8::try_from(proof_size).unwrap()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn make_shreds_from_data(
    thread_pool: &ThreadPool,
    keypair: &Keypair,
    // The Merkle root of the previous erasure batch if chained.
    chained_merkle_root: Option<Hash>,
    mut data: &[u8], // Serialized &[Entry]
    slot: Slot,
    parent_slot: Slot,
    shred_version: u16,
    reference_tick: u8,
    is_last_in_slot: bool,
    next_shred_index: u32,
    next_code_index: u32,
    reed_solomon_cache: &ReedSolomonCache,
    stats: &mut ProcessShredsStats,
) -> Result<Vec</*erasure batch:*/ Vec<Shred>>, Error> {
    fn new_shred_data(
        common_header: ShredCommonHeader,
        mut data_header: DataShredHeader,
        data: &[u8],
    ) -> ShredData {
        let size = ShredData::SIZE_OF_HEADERS + data.len();
        let mut payload = vec![0u8; ShredData::SIZE_OF_PAYLOAD];
        payload[ShredData::SIZE_OF_HEADERS..size].copy_from_slice(data);
        data_header.size = size as u16;
        ShredData {
            common_header,
            data_header,
            payload,
        }
    }
    let now = Instant::now();
    let chained = chained_merkle_root.is_some();
    let resigned = chained && is_last_in_slot;
    let erasure_batch_size =
        shredder::get_erasure_batch_size(DATA_SHREDS_PER_FEC_BLOCK, is_last_in_slot);
    let proof_size = get_proof_size(erasure_batch_size);
    let data_buffer_size = ShredData::capacity(proof_size, chained, resigned)?;
    let chunk_size = DATA_SHREDS_PER_FEC_BLOCK * data_buffer_size;
    let mut common_header = ShredCommonHeader {
        signature: Signature::default(),
        shred_variant: ShredVariant::MerkleData {
            proof_size,
            chained,
            resigned,
        },
        slot,
        index: next_shred_index,
        version: shred_version,
        fec_set_index: next_shred_index,
    };
    let data_header = {
        let parent_offset = slot
            .checked_sub(parent_slot)
            .and_then(|offset| u16::try_from(offset).ok())
            .ok_or(Error::InvalidParentSlot { slot, parent_slot })?;
        let flags = ShredFlags::from_bits_retain(
            ShredFlags::SHRED_TICK_REFERENCE_MASK
                .bits()
                .min(reference_tick),
        );
        DataShredHeader {
            parent_offset,
            flags,
            size: 0u16,
        }
    };
    // Split the data into erasure batches and initialize
    // data shreds from chunks of each batch.
    let mut shreds = Vec::<ShredData>::new();
    while data.len() >= 2 * chunk_size || data.len() == chunk_size {
        let (chunk, rest) = data.split_at(chunk_size);
        common_header.fec_set_index = common_header.index;
        for shred in chunk.chunks(data_buffer_size) {
            let shred = new_shred_data(common_header, data_header, shred);
            shreds.push(shred);
            common_header.index += 1;
        }
        data = rest;
    }
    // If shreds.is_empty() then the data argument was empty. In that case we
    // want to generate one data shred with empty data.
    if !data.is_empty() || shreds.is_empty() {
        // Should generate at least one data shred (which may have no data).
        // Last erasure batch should also be padded with empty data shreds to
        // make >= 32 data shreds. This gaurantees that the batch cannot be
        // recovered unless 32+ shreds are received from turbine or repair.
        let min_num_data_shreds = if is_last_in_slot {
            DATA_SHREDS_PER_FEC_BLOCK
        } else {
            1
        };
        // Find the Merkle proof_size and data_buffer_size
        // which can embed the remaining data.
        let (proof_size, data_buffer_size, num_data_shreds) = (1u8..32)
            .find_map(|proof_size| {
                let data_buffer_size = ShredData::capacity(proof_size, chained, resigned).ok()?;
                let num_data_shreds = (data.len() + data_buffer_size - 1) / data_buffer_size;
                let num_data_shreds = num_data_shreds.max(min_num_data_shreds);
                let erasure_batch_size =
                    shredder::get_erasure_batch_size(num_data_shreds, is_last_in_slot);
                (proof_size == get_proof_size(erasure_batch_size)).then_some((
                    proof_size,
                    data_buffer_size,
                    num_data_shreds,
                ))
            })
            .ok_or(Error::UnknownProofSize)?;
        common_header.shred_variant = ShredVariant::MerkleData {
            proof_size,
            chained,
            resigned,
        };
        common_header.fec_set_index = common_header.index;
        for shred in data
            .chunks(data_buffer_size)
            .chain(std::iter::repeat(&[][..]))
            .take(num_data_shreds)
        {
            let shred = new_shred_data(common_header, data_header, shred);
            shreds.push(shred);
            common_header.index += 1;
        }
        if let Some(shred) = shreds.last() {
            stats.data_buffer_residual += data_buffer_size - shred.data()?.len();
        }
    }
    // Only the trailing data shreds may have residual data buffer.
    debug_assert!(shreds
        .iter()
        .rev()
        .skip_while(|shred| is_last_in_slot && shred.data().unwrap().is_empty())
        .skip(1)
        .all(|shred| {
            let proof_size = shred.proof_size().unwrap();
            let capacity = ShredData::capacity(proof_size, chained, resigned).unwrap();
            shred.data().unwrap().len() == capacity
        }));
    // Adjust flags for the very last shred.
    if let Some(shred) = shreds.last_mut() {
        shred.data_header.flags |= if is_last_in_slot {
            ShredFlags::LAST_SHRED_IN_SLOT // also implies DATA_COMPLETE_SHRED
        } else {
            ShredFlags::DATA_COMPLETE_SHRED
        };
    }
    // Write common and data headers into data shreds' payload buffer.
    thread_pool.install(|| {
        shreds.par_iter_mut().try_for_each(|shred| {
            let mut cursor = Cursor::new(&mut shred.payload[..]);
            bincode::serialize_into(&mut cursor, &shred.common_header)?;
            bincode::serialize_into(&mut cursor, &shred.data_header)
        })
    })?;
    stats.gen_data_elapsed += now.elapsed().as_micros() as u64;
    stats.record_num_data_shreds(shreds.len());
    let now = Instant::now();
    // Group shreds by their respective erasure-batch.
    let shreds: Vec<Vec<ShredData>> = shreds
        .into_iter()
        .group_by(|shred| shred.common_header.fec_set_index)
        .into_iter()
        .map(|(_, shreds)| shreds.collect())
        .collect();
    // Obtain the shred index for the first coding shred of each batch.
    let next_code_index: Vec<_> = shreds
        .iter()
        .scan(next_code_index, |next_code_index, chunk| {
            let out = Some(*next_code_index);
            let num_data_shreds = chunk.len();
            let erasure_batch_size =
                shredder::get_erasure_batch_size(num_data_shreds, is_last_in_slot);
            let num_coding_shreds = erasure_batch_size - num_data_shreds;
            *next_code_index += num_coding_shreds as u32;
            out
        })
        .collect();
    // Generate coding shreds, populate merkle proof
    // for all shreds and attach signature.
    let shreds: Result<Vec<_>, Error> = if let Some(chained_merkle_root) = chained_merkle_root {
        shreds
            .into_iter()
            .zip(next_code_index)
            .scan(
                chained_merkle_root,
                |chained_merkle_root, (shreds, next_code_index)| {
                    Some(
                        make_erasure_batch(
                            keypair,
                            shreds,
                            Some(*chained_merkle_root),
                            next_code_index,
                            is_last_in_slot,
                            reed_solomon_cache,
                        )
                        .map(|(merkle_root, shreds)| {
                            *chained_merkle_root = merkle_root;
                            shreds
                        }),
                    )
                },
            )
            .collect()
    } else if shreds.len() <= 1 {
        shreds
            .into_iter()
            .zip(next_code_index)
            .map(|(shreds, next_code_index)| {
                make_erasure_batch(
                    keypair,
                    shreds,
                    None, // chained_merkle_root
                    next_code_index,
                    is_last_in_slot,
                    reed_solomon_cache,
                )
                .map(|(_merkle_root, shreds)| shreds)
            })
            .collect()
    } else {
        thread_pool.install(|| {
            shreds
                .into_par_iter()
                .zip(next_code_index)
                .map(|(shreds, next_code_index)| {
                    make_erasure_batch(
                        keypair,
                        shreds,
                        None, // chained_merkle_root
                        next_code_index,
                        is_last_in_slot,
                        reed_solomon_cache,
                    )
                    .map(|(_merkle_root, shreds)| shreds)
                })
                .collect()
        })
    };
    stats.gen_coding_elapsed += now.elapsed().as_micros() as u64;
    shreds
}

// Generates coding shreds from data shreds, populates merke proof for all
// shreds and attaches signature.
fn make_erasure_batch(
    keypair: &Keypair,
    mut shreds: Vec<ShredData>,
    // The Merkle root of the previous erasure batch if chained.
    chained_merkle_root: Option<Hash>,
    next_code_index: u32,
    is_last_in_slot: bool,
    reed_solomon_cache: &ReedSolomonCache,
) -> Result<(/*merkle root:*/ Hash, Vec<Shred>), Error> {
    let num_data_shreds = shreds.len();
    let chained = chained_merkle_root.is_some();
    let resigned = chained && is_last_in_slot;
    let erasure_batch_size = shredder::get_erasure_batch_size(num_data_shreds, is_last_in_slot);
    let num_coding_shreds = erasure_batch_size - num_data_shreds;
    let proof_size = get_proof_size(erasure_batch_size);
    debug_assert!(shreds.iter().all(|shred| shred.common_header.shred_variant
        == ShredVariant::MerkleData {
            proof_size,
            chained,
            resigned
        }));
    let mut common_header = match shreds.first() {
        None => return Err(Error::from(TooFewShards)),
        Some(shred) => shred.common_header,
    };
    if let Some(hash) = chained_merkle_root {
        for shred in &mut shreds {
            shred.set_chained_merkle_root(&hash)?;
        }
    }
    // Generate erasure codings for encoded shard of data shreds.
    let data: Vec<_> = shreds
        .iter()
        .map(ShredData::erasure_shard_as_slice)
        .collect::<Result<_, _>>()?;
    // Shreds should have erasure encoded shard of the same length.
    debug_assert_eq!(data.iter().map(|shard| shard.len()).dedup().count(), 1);
    let mut parity = vec![vec![0u8; data[0].len()]; num_coding_shreds];
    reed_solomon_cache
        .get(num_data_shreds, num_coding_shreds)?
        .encode_sep(&data, &mut parity[..])?;
    let mut shreds: Vec<_> = shreds.into_iter().map(Shred::ShredData).collect();
    // Initialize coding shreds from erasure coding shards.
    common_header.index = next_code_index;
    common_header.shred_variant = ShredVariant::MerkleCode {
        proof_size,
        chained,
        resigned,
    };
    let mut coding_header = CodingShredHeader {
        num_data_shreds: num_data_shreds as u16,
        num_coding_shreds: num_coding_shreds as u16,
        position: 0,
    };
    for code in parity {
        let mut payload = vec![0u8; ShredCode::SIZE_OF_PAYLOAD];
        let mut cursor = Cursor::new(&mut payload[..]);
        bincode::serialize_into(&mut cursor, &common_header)?;
        bincode::serialize_into(&mut cursor, &coding_header)?;
        cursor.write_all(&code)?;
        if let Some(chained_merkle_root) = chained_merkle_root {
            cursor.write_all(chained_merkle_root.as_ref())?;
        }
        let shred = ShredCode {
            common_header,
            coding_header,
            payload,
        };
        shreds.push(Shred::ShredCode(shred));
        common_header.index += 1;
        coding_header.position += 1;
    }
    // Compute Merkle tree for the erasure batch.
    let tree = make_merkle_tree(
        shreds
            .iter()
            .map(Shred::merkle_node)
            .collect::<Result<_, _>>()?,
    );
    // Sign root of Merkle tree.
    let root = tree.last().ok_or(Error::InvalidMerkleProof)?;
    let signature = keypair.sign_message(root.as_ref());
    // Populate merkle proof for all shreds and attach signature.
    for (index, shred) in shreds.iter_mut().enumerate() {
        let proof =
            make_merkle_proof(index, erasure_batch_size, &tree).ok_or(Error::InvalidMerkleProof)?;
        debug_assert_eq!(proof.len(), usize::from(proof_size));
        shred.set_merkle_proof(&proof)?;
        shred.set_signature(signature);
        debug_assert!(shred.verify(&keypair.pubkey()));
        debug_assert_matches!(shred.sanitize(), Ok(()));
        // Assert that shred payload is fully populated.
        debug_assert_eq!(shred, {
            let shred = shred.payload().clone();
            &Shred::from_payload(shred).unwrap()
        });
    }
    Ok((*root, shreds))
}
