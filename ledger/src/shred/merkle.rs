use {
    crate::shred::{
        common::impl_shred_common,
        shred_code, shred_data,
        traits::{Shred, ShredCode as ShredCodeTrait, ShredData as ShredDataTrait},
        CodingShredHeader, DataShredHeader, Error, ShredCommonHeader, ShredFlags, ShredVariant,
        SIZE_OF_CODING_SHRED_HEADERS, SIZE_OF_COMMON_SHRED_HEADER, SIZE_OF_DATA_SHRED_HEADERS,
        SIZE_OF_SIGNATURE,
    },
    solana_perf::packet::deserialize_from_with_limit,
    solana_sdk::{
        clock::Slot,
        hash::{hashv, Hash},
        signature::Signature,
    },
    static_assertions::const_assert_eq,
    std::{
        io::{Cursor, Seek, SeekFrom},
        iter::repeat_with,
        ops::Range,
    },
};

const_assert_eq!(SIZE_OF_MERKLE_ROOT, 20);
const SIZE_OF_MERKLE_ROOT: usize = std::mem::size_of::<MerkleRoot>();
const_assert_eq!(SIZE_OF_MERKLE_PROOF_ENTRY, 20);
const SIZE_OF_MERKLE_PROOF_ENTRY: usize = std::mem::size_of::<MerkleProofEntry>();
const_assert_eq!(ShredData::SIZE_OF_PAYLOAD, 1203);

// Defense against second preimage attack:
// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const MERKLE_HASH_PREFIX_LEAF: &[u8] = &[0x00];
const MERKLE_HASH_PREFIX_NODE: &[u8] = &[0x01];

type MerkleRoot = MerkleProofEntry;
type MerkleProofEntry = [u8; 20];

// Layout: {common, data} headers | data buffer | merkle branch
// The slice past signature and before merkle branch is erasure coded.
// Same slice is hashed to generate merkle tree.
// The root of merkle tree is signed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShredData {
    common_header: ShredCommonHeader,
    data_header: DataShredHeader,
    merkle_branch: MerkleBranch,
    payload: Vec<u8>,
}

// Layout: {common, coding} headers | erasure coded shard | merkle branch
// The slice past signature and before merkle branch is hashed to generate
// merkle tree. The root of merkle tree is signed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShredCode {
    common_header: ShredCommonHeader,
    coding_header: CodingShredHeader,
    merkle_branch: MerkleBranch,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MerkleBranch {
    root: MerkleRoot,
    proof: Vec<MerkleProofEntry>,
}

impl ShredData {
    // proof_size is the number of proof entries in the merkle tree branch.
    fn proof_size(&self) -> Result<u8, Error> {
        match self.common_header.shred_variant {
            ShredVariant::MerkleData(proof_size) => Ok(proof_size),
            _ => Err(Error::InvalidShredVariant),
        }
    }

    // Maximum size of ledger data that can be embedded in a data-shred.
    // Also equal to:
    //   ShredCode::size_of_erasure_encoded_slice(proof_size).unwrap()
    //       - SIZE_OF_DATA_SHRED_HEADERS
    //       + SIZE_OF_SIGNATURE
    pub(super) fn capacity(proof_size: u8) -> Result<usize, Error> {
        Self::SIZE_OF_PAYLOAD
            .checked_sub(
                SIZE_OF_DATA_SHRED_HEADERS
                    + SIZE_OF_MERKLE_ROOT
                    + usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY,
            )
            .ok_or(Error::InvalidProofSize(proof_size))
    }

    pub(super) fn get_signed_message_range(proof_size: u8) -> Option<Range<usize>> {
        let data_buffer_size = Self::capacity(proof_size).ok()?;
        let offset = SIZE_OF_DATA_SHRED_HEADERS + data_buffer_size;
        Some(offset..offset + SIZE_OF_MERKLE_ROOT)
    }

    fn merkle_tree_node(&self) -> Result<Hash, Error> {
        let chunk = self.erasure_shard_as_slice()?;
        Ok(hashv(&[MERKLE_HASH_PREFIX_LEAF, chunk]))
    }

    fn verify_merkle_proof(&self) -> Result<bool, Error> {
        let node = self.merkle_tree_node()?;
        let index = self.erasure_shard_index()?;
        Ok(verify_merkle_proof(index, node, &self.merkle_branch))
    }
}

impl ShredCode {
    // proof_size is the number of proof entries in the merkle tree branch.
    fn proof_size(&self) -> Result<u8, Error> {
        match self.common_header.shred_variant {
            ShredVariant::MerkleCode(proof_size) => Ok(proof_size),
            _ => Err(Error::InvalidShredVariant),
        }
    }

    // Size of the chunk of payload which will be erasure coded.
    fn size_of_erasure_encoded_slice(proof_size: u8) -> Result<usize, Error> {
        // Merkle branch is generated and signed after coding shreds are
        // generated. Coding shred headers cannot be erasure coded either.
        Self::SIZE_OF_PAYLOAD
            .checked_sub(
                SIZE_OF_CODING_SHRED_HEADERS
                    + SIZE_OF_MERKLE_ROOT
                    + SIZE_OF_MERKLE_PROOF_ENTRY * usize::from(proof_size),
            )
            .ok_or(Error::InvalidProofSize(proof_size))
    }

    fn merkle_tree_node(&self) -> Result<Hash, Error> {
        let proof_size = self.proof_size()?;
        let shard_size = Self::size_of_erasure_encoded_slice(proof_size)?;
        let chunk = self
            .payload
            .get(SIZE_OF_SIGNATURE..SIZE_OF_CODING_SHRED_HEADERS + shard_size)
            .ok_or(Error::InvalidPayloadSize(self.payload.len()))?;
        Ok(hashv(&[MERKLE_HASH_PREFIX_LEAF, chunk]))
    }

    fn verify_merkle_proof(&self) -> Result<bool, Error> {
        let node = self.merkle_tree_node()?;
        let index = self.erasure_shard_index()?;
        Ok(verify_merkle_proof(index, node, &self.merkle_branch))
    }

    pub(super) fn get_signed_message_range(proof_size: u8) -> Option<Range<usize>> {
        let offset =
            SIZE_OF_CODING_SHRED_HEADERS + Self::size_of_erasure_encoded_slice(proof_size).ok()?;
        Some(offset..offset + SIZE_OF_MERKLE_ROOT)
    }

    pub(super) fn erasure_mismatch(&self, other: &ShredCode) -> bool {
        shred_code::erasure_mismatch(self, other)
            || self.merkle_branch.root != other.merkle_branch.root
            || self.common_header.signature != other.common_header.signature
    }
}

impl Shred for ShredData {
    impl_shred_common!();

    // Also equal to:
    // SIZE_OF_DATA_SHRED_HEADERS
    //       + ShredData::capacity(proof_size).unwrap()
    //       + SIZE_OF_MERKLE_ROOT
    //       + usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY
    const SIZE_OF_PAYLOAD: usize =
        ShredCode::SIZE_OF_PAYLOAD - SIZE_OF_CODING_SHRED_HEADERS + SIZE_OF_SIGNATURE;

    fn from_payload(mut payload: Vec<u8>) -> Result<Self, Error> {
        if payload.len() < Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(payload.len()));
        }
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        let mut cursor = Cursor::new(&payload[..]);
        let common_header: ShredCommonHeader = deserialize_from_with_limit(&mut cursor)?;
        let proof_size = match common_header.shred_variant {
            ShredVariant::MerkleData(proof_size) => proof_size,
            _ => return Err(Error::InvalidShredVariant),
        };
        let data_header = deserialize_from_with_limit(&mut cursor)?;
        // Skip data buffer.
        let data_buffer_size = Self::capacity(proof_size)?;
        let data_buffer_size = i64::try_from(data_buffer_size).unwrap();
        cursor.seek(SeekFrom::Current(data_buffer_size))?;
        // Deserialize merkle branch.
        let root = deserialize_from_with_limit(&mut cursor)?;
        let proof = repeat_with(|| deserialize_from_with_limit(&mut cursor))
            .take(usize::from(proof_size))
            .collect::<Result<_, _>>()?;
        let merkle_branch = MerkleBranch { root, proof };
        let shred = Self {
            common_header,
            data_header,
            merkle_branch,
            payload,
        };
        shred.sanitize().map(|_| shred)
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
        let proof_size = self.proof_size()?;
        let data_buffer_size = Self::capacity(proof_size)?;
        let mut shard = self.payload;
        shard.truncate(SIZE_OF_DATA_SHRED_HEADERS + data_buffer_size);
        shard.drain(0..SIZE_OF_SIGNATURE);
        Ok(shard)
    }

    fn erasure_shard_as_slice(&self) -> Result<&[u8], Error> {
        if self.payload.len() != Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(self.payload.len()));
        }
        let proof_size = self.proof_size()?;
        let data_buffer_size = Self::capacity(proof_size)?;
        self.payload
            .get(SIZE_OF_SIGNATURE..SIZE_OF_DATA_SHRED_HEADERS + data_buffer_size)
            .ok_or(Error::InvalidPayloadSize(self.payload.len()))
    }

    fn sanitize(&self) -> Result<(), Error> {
        match self.common_header.shred_variant {
            ShredVariant::MerkleData(proof_size) => {
                if self.merkle_branch.proof.len() != usize::from(proof_size) {
                    return Err(Error::InvalidProofSize(proof_size));
                }
            }
            _ => return Err(Error::InvalidShredVariant),
        }
        if !self.verify_merkle_proof()? {
            return Err(Error::InvalidMerkleProof);
        }
        shred_data::sanitize(self)
    }

    fn signed_message(&self) -> &[u8] {
        self.merkle_branch.root.as_ref()
    }
}

impl Shred for ShredCode {
    impl_shred_common!();
    const SIZE_OF_PAYLOAD: usize = shred_code::ShredCode::SIZE_OF_PAYLOAD;

    fn from_payload(mut payload: Vec<u8>) -> Result<Self, Error> {
        let mut cursor = Cursor::new(&payload[..]);
        let common_header: ShredCommonHeader = deserialize_from_with_limit(&mut cursor)?;
        let proof_size = match common_header.shred_variant {
            ShredVariant::MerkleCode(proof_size) => proof_size,
            _ => return Err(Error::InvalidShredVariant),
        };
        let coding_header = deserialize_from_with_limit(&mut cursor)?;
        // Skip erasure code shard.
        let shard_size = Self::size_of_erasure_encoded_slice(proof_size)?;
        let shard_size = i64::try_from(shard_size).unwrap();
        cursor.seek(SeekFrom::Current(shard_size))?;
        // Deserialize merkle branch.
        let root = deserialize_from_with_limit(&mut cursor)?;
        let proof = repeat_with(|| deserialize_from_with_limit(&mut cursor))
            .take(usize::from(proof_size))
            .collect::<Result<_, _>>()?;
        let merkle_branch = MerkleBranch { root, proof };
        // see: https://github.com/solana-labs/solana/pull/10109
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        let shred = Self {
            common_header,
            coding_header,
            merkle_branch,
            payload,
        };
        shred.sanitize().map(|_| shred)
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
        let proof_size = self.proof_size()?;
        let shard_size = Self::size_of_erasure_encoded_slice(proof_size)?;
        let mut shard = self.payload;
        shard.drain(..SIZE_OF_CODING_SHRED_HEADERS);
        shard.truncate(shard_size);
        Ok(shard)
    }

    fn erasure_shard_as_slice(&self) -> Result<&[u8], Error> {
        if self.payload.len() != Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(self.payload.len()));
        }
        let proof_size = self.proof_size()?;
        let shard_size = Self::size_of_erasure_encoded_slice(proof_size)?;
        self.payload
            .get(SIZE_OF_CODING_SHRED_HEADERS..SIZE_OF_CODING_SHRED_HEADERS + shard_size)
            .ok_or(Error::InvalidPayloadSize(self.payload.len()))
    }

    fn sanitize(&self) -> Result<(), Error> {
        match self.common_header.shred_variant {
            ShredVariant::MerkleCode(proof_size) => {
                if self.merkle_branch.proof.len() != usize::from(proof_size) {
                    return Err(Error::InvalidProofSize(proof_size));
                }
            }
            _ => return Err(Error::InvalidShredVariant),
        }
        if !self.verify_merkle_proof()? {
            return Err(Error::InvalidMerkleProof);
        }
        shred_code::sanitize(self)
    }

    fn signed_message(&self) -> &[u8] {
        self.merkle_branch.root.as_ref()
    }
}

impl ShredDataTrait for ShredData {
    #[inline]
    fn data_header(&self) -> &DataShredHeader {
        &self.data_header
    }

    fn data(&self) -> Result<&[u8], Error> {
        let proof_size = self.proof_size()?;
        let data_buffer_size = Self::capacity(proof_size)?;
        let size = usize::from(self.data_header.size);
        if size > self.payload.len()
            || size < SIZE_OF_DATA_SHRED_HEADERS
            || size > SIZE_OF_DATA_SHRED_HEADERS + data_buffer_size
        {
            return Err(Error::InvalidDataSize {
                size: self.data_header.size,
                payload: self.payload.len(),
            });
        }
        Ok(&self.payload[SIZE_OF_DATA_SHRED_HEADERS..size])
    }

    // Only for tests.
    fn set_last_in_slot(&mut self) {
        self.data_header.flags |= ShredFlags::LAST_SHRED_IN_SLOT;
        let buffer = &mut self.payload[SIZE_OF_COMMON_SHRED_HEADER..];
        bincode::serialize_into(buffer, &self.data_header).unwrap();
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

fn verify_merkle_proof(index: usize, node: Hash, merkle_branch: &MerkleBranch) -> bool {
    let proof = merkle_branch.proof.iter();
    let (index, root) = proof.fold((index, node), |(index, node), other| {
        let parent = if index % 2 == 0 {
            join_nodes(node, other)
        } else {
            join_nodes(other, node)
        };
        (index >> 1, parent)
    });
    let root = &root.as_ref()[..SIZE_OF_MERKLE_ROOT];
    (index, root) == (0usize, &merkle_branch.root[..])
}
