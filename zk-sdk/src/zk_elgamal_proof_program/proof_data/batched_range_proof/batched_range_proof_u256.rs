//! The 256-bit batched range proof instruction.

#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        range_proof::RangeProof,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            proof_data::batched_range_proof::{MAX_COMMITMENTS, MAX_SINGLE_BIT_LENGTH},
        },
    },
    std::convert::TryInto,
};
use {
    crate::{
        range_proof::pod::PodRangeProofU256,
        zk_elgamal_proof_program::proof_data::{
            batched_range_proof::BatchedRangeProofContext, ProofType, ZkProofData,
        },
    },
    bytemuck_derive::{Pod, Zeroable},
};

#[cfg(not(target_os = "solana"))]
const BATCHED_RANGE_PROOF_U256_BIT_LENGTH: usize = 256;

/// The instruction data that is needed for the
/// `ProofInstruction::BatchedRangeProofU256Data` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedRangeProofU256Data {
    /// The context data for a batched range proof
    pub context: BatchedRangeProofContext,

    /// The batched range proof
    pub proof: PodRangeProofU256,
}

#[cfg(not(target_os = "solana"))]
impl BatchedRangeProofU256Data {
    pub fn new(
        commitments: Vec<&PedersenCommitment>,
        amounts: Vec<u64>,
        bit_lengths: Vec<usize>,
        openings: Vec<&PedersenOpening>,
    ) -> Result<Self, ProofGenerationError> {
        // Range proof on 256 bit length could potentially result in an unexpected behavior and
        // therefore, restrict the bit length to be at most 128. This check is not needed for the
        // `BatchedRangeProofU64` or `BatchedRangeProofU128`.
        if bit_lengths
            .iter()
            .any(|length| *length > MAX_SINGLE_BIT_LENGTH)
        {
            return Err(ProofGenerationError::IllegalCommitmentLength);
        }

        // the sum of the bit lengths must be 256
        let batched_bit_length = bit_lengths
            .iter()
            .try_fold(0_usize, |acc, &x| acc.checked_add(x))
            .ok_or(ProofGenerationError::IllegalAmountBitLength)?;
        if batched_bit_length != BATCHED_RANGE_PROOF_U256_BIT_LENGTH {
            return Err(ProofGenerationError::IllegalAmountBitLength);
        }

        let context =
            BatchedRangeProofContext::new(&commitments, &amounts, &bit_lengths, &openings)?;

        let mut transcript = context.new_transcript();
        let proof = RangeProof::new(amounts, bit_lengths, openings, &mut transcript)?
            .try_into()
            .map_err(|_| ProofGenerationError::ProofLength)?;

        Ok(Self { context, proof })
    }
}

impl ZkProofData<BatchedRangeProofContext> for BatchedRangeProofU256Data {
    const PROOF_TYPE: ProofType = ProofType::BatchedRangeProofU256;

    fn context_data(&self) -> &BatchedRangeProofContext {
        &self.context
    }

    #[cfg(not(target_os = "solana"))]
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let (commitments, bit_lengths) = self.context.try_into()?;
        let num_commitments = commitments.len();

        if bit_lengths
            .iter()
            .any(|length| *length > MAX_SINGLE_BIT_LENGTH)
        {
            return Err(ProofVerificationError::IllegalCommitmentLength);
        }

        if num_commitments > MAX_COMMITMENTS || num_commitments != bit_lengths.len() {
            return Err(ProofVerificationError::IllegalCommitmentLength);
        }

        let mut transcript = self.context_data().new_transcript();
        let proof: RangeProof = self.proof.try_into()?;

        proof
            .verify(commitments.iter().collect(), bit_lengths, &mut transcript)
            .map_err(|e| e.into())
    }
}
