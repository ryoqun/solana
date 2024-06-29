//! The batched ciphertext with 3 handles validity sigma proof system.
//!
//! A batched grouped ciphertext validity proof certifies the validity of two instances of a
//! standard grouped ciphertext validity proof. An instance of a standard grouped ciphertext
//! with 3 handles validity proof consists of one ciphertext and three decryption handles:
//! `(commitment, source_handle, destination_handle, auditor_handle)`. An instance of a batched
//! grouped ciphertext with 3 handles validity proof consist of a pair of `(commitment_0,
//! source_handle_0, destination_handle_0, auditor_handle_0)` and `(commitment_1, source_handle_1,
//! destination_handle_1, auditor_handle_1)`. The proof certifies the anagolous decryptable
//! properties for each one of these pairs of commitment and decryption handles.
//!
//! The protocol guarantees computational soundness (by the hardness of discrete log) and perfect
//! zero-knowledge in the random oracle model.

#[cfg(not(target_os = "solana"))]
use crate::encryption::{
    elgamal::{DecryptHandle, ElGamalPubkey},
    pedersen::{PedersenCommitment, PedersenOpening},
};
use {
    crate::{
        sigma_proofs::{
            errors::ValidityProofVerificationError,
            grouped_ciphertext_validity_proof::GroupedCiphertext3HandlesValidityProof,
        },
        transcript::TranscriptProtocol,
        UNIT_LEN,
    },
    curve25519_dalek::scalar::Scalar,
    merlin::Transcript,
};

/// Byte length of a batched grouped ciphertext validity proof for 3 handles
#[allow(dead_code)]
const BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN: usize = UNIT_LEN * 6;

/// Batched grouped ciphertext validity proof with two handles.
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct BatchedGroupedCiphertext3HandlesValidityProof(GroupedCiphertext3HandlesValidityProof);

#[allow(non_snake_case)]
#[allow(dead_code)]
#[cfg(not(target_os = "solana"))]
impl BatchedGroupedCiphertext3HandlesValidityProof {
    /// Creates a batched grouped ciphertext validity proof.
    ///
    /// The function simply batches the input openings and invokes the standard grouped ciphertext
    /// validity proof constructor.
    pub fn new<T: Into<Scalar>>(
        source_pubkey: &ElGamalPubkey,
        destination_pubkey: &ElGamalPubkey,
        auditor_pubkey: &ElGamalPubkey,
        amount_lo: T,
        amount_hi: T,
        opening_lo: &PedersenOpening,
        opening_hi: &PedersenOpening,
        transcript: &mut Transcript,
    ) -> Self {
        transcript.batched_grouped_ciphertext_validity_proof_domain_separator();

        let t = transcript.challenge_scalar(b"t");

        let batched_message = amount_lo.into() + amount_hi.into() * t;
        let batched_opening = opening_lo + &(opening_hi * &t);

        BatchedGroupedCiphertext3HandlesValidityProof(GroupedCiphertext3HandlesValidityProof::new(
            source_pubkey,
            destination_pubkey,
            auditor_pubkey,
            batched_message,
            &batched_opening,
            transcript,
        ))
    }

    /// Verifies a batched grouped ciphertext validity proof.
    ///
    /// The function does *not* hash the public keys, commitment, or decryption handles into the
    /// transcript. For security, the caller (the main protocol) should hash these public
    /// components prior to invoking this constructor.
    ///
    /// This function is randomized. It uses `OsRng` internally to generate random scalars.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        self,
        source_pubkey: &ElGamalPubkey,
        destination_pubkey: &ElGamalPubkey,
        auditor_pubkey: &ElGamalPubkey,
        commitment_lo: &PedersenCommitment,
        commitment_hi: &PedersenCommitment,
        source_handle_lo: &DecryptHandle,
        source_handle_hi: &DecryptHandle,
        destination_handle_lo: &DecryptHandle,
        destination_handle_hi: &DecryptHandle,
        auditor_handle_lo: &DecryptHandle,
        auditor_handle_hi: &DecryptHandle,
        transcript: &mut Transcript,
    ) -> Result<(), ValidityProofVerificationError> {
        transcript.batched_grouped_ciphertext_validity_proof_domain_separator();

        let t = transcript.challenge_scalar(b"t");

        let batched_commitment = commitment_lo + commitment_hi * t;
        let source_batched_handle = source_handle_lo + source_handle_hi * t;
        let destination_batched_handle = destination_handle_lo + destination_handle_hi * t;
        let auditor_batched_handle = auditor_handle_lo + auditor_handle_hi * t;

        let BatchedGroupedCiphertext3HandlesValidityProof(validity_proof) = self;

        validity_proof.verify(
            &batched_commitment,
            source_pubkey,
            destination_pubkey,
            auditor_pubkey,
            &source_batched_handle,
            &destination_batched_handle,
            &auditor_batched_handle,
            transcript,
        )
    }

    pub fn to_bytes(&self) -> [u8; BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidityProofVerificationError> {
        GroupedCiphertext3HandlesValidityProof::from_bytes(bytes).map(Self)
    }
}
