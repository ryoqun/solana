pub use target_arch::*;

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        crate::{encryption::elgamal::ElGamalCiphertext, zk_token_elgamal::pod},
        curve25519_dalek::{constants::RISTRETTO_BASEPOINT_COMPRESSED, scalar::Scalar},
        std::convert::TryInto,
    };
    pub const TWO_32: u64 = 4294967296;

    // On input two scalars x0, x1 and two ciphertexts ct0, ct1,
    // returns `Some(x0*ct0 + x1*ct1)` or `None` if the input was invalid
    fn add_ciphertexts(
        scalar_0: Scalar,
        ct_0: &pod::ElGamalCiphertext,
        scalar_1: Scalar,
        ct_1: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        let ct_0: ElGamalCiphertext = (*ct_0).try_into().ok()?;
        let ct_1: ElGamalCiphertext = (*ct_1).try_into().ok()?;

        let ct_sum = ct_0 * scalar_0 + ct_1 * scalar_1;
        Some(pod::ElGamalCiphertext::from(ct_sum))
    }

    pub(crate) fn combine_lo_hi(
        ct_lo: &pod::ElGamalCiphertext,
        ct_hi: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        add_ciphertexts(Scalar::one(), ct_lo, Scalar::from(TWO_32), ct_hi)
    }

    pub fn add(
        ct_0: &pod::ElGamalCiphertext,
        ct_1: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        add_ciphertexts(Scalar::one(), ct_0, Scalar::one(), ct_1)
    }

    pub fn add_with_lo_hi(
        ct_0: &pod::ElGamalCiphertext,
        ct_1_lo: &pod::ElGamalCiphertext,
        ct_1_hi: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        let ct_1 = combine_lo_hi(ct_1_lo, ct_1_hi)?;
        add_ciphertexts(Scalar::one(), ct_0, Scalar::one(), &ct_1)
    }

    pub fn subtract(
        ct_0: &pod::ElGamalCiphertext,
        ct_1: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        add_ciphertexts(Scalar::one(), ct_0, -Scalar::one(), ct_1)
    }

    pub fn subtract_with_lo_hi(
        ct_0: &pod::ElGamalCiphertext,
        ct_1_lo: &pod::ElGamalCiphertext,
        ct_1_hi: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        let ct_1 = combine_lo_hi(ct_1_lo, ct_1_hi)?;
        add_ciphertexts(Scalar::one(), ct_0, -Scalar::one(), &ct_1)
    }

    pub fn add_to(ct: &pod::ElGamalCiphertext, amount: u64) -> Option<pod::ElGamalCiphertext> {
        let mut amount_as_ct = [0_u8; 64];
        amount_as_ct[..32].copy_from_slice(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
        add_ciphertexts(
            Scalar::one(),
            ct,
            Scalar::from(amount),
            &pod::ElGamalCiphertext(amount_as_ct),
        )
    }

    pub fn subtract_from(
        ct: &pod::ElGamalCiphertext,
        amount: u64,
    ) -> Option<pod::ElGamalCiphertext> {
        let mut amount_as_ct = [0_u8; 64];
        amount_as_ct[..32].copy_from_slice(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
        add_ciphertexts(
            Scalar::one(),
            ct,
            -Scalar::from(amount),
            &pod::ElGamalCiphertext(amount_as_ct),
        )
    }
}

#[cfg(target_os = "solana")]
#[allow(unused_variables)]
mod target_arch {
    use crate::{
        curve25519::{
            ristretto::{add_ristretto, multiply_ristretto, subtract_ristretto, PodRistrettoPoint},
            scalar::PodScalar,
        },
        zk_token_elgamal::pod,
    };

    const SHIFT_BITS: usize = 16;

    const G: PodRistrettoPoint = PodRistrettoPoint([
        226, 242, 174, 10, 106, 188, 78, 113, 168, 132, 169, 97, 197, 0, 81, 95, 88, 227, 11, 106,
        165, 130, 221, 141, 182, 166, 89, 69, 224, 141, 45, 118,
    ]);

    pub fn add(
        left_ciphertext: &pod::ElGamalCiphertext,
        right_ciphertext: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        let (left_commitment, left_handle): (pod::PedersenCommitment, pod::DecryptHandle) =
            (*left_ciphertext).into();
        let (right_commitment, right_handle): (pod::PedersenCommitment, pod::DecryptHandle) =
            (*right_ciphertext).into();

        let result_commitment: pod::PedersenCommitment =
            add_ristretto(&left_commitment.into(), &right_commitment.into())?.into();
        let result_handle: pod::DecryptHandle =
            add_ristretto(&left_handle.into(), &right_handle.into())?.into();

        Some((result_commitment, result_handle).into())
    }

    pub fn add_with_lo_hi(
        left_ciphertext: &pod::ElGamalCiphertext,
        right_ciphertext_lo: &pod::ElGamalCiphertext,
        right_ciphertext_hi: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        let shift_scalar = to_scalar(1_u64 << SHIFT_BITS);
        let shifted_right_ciphertext_hi = scalar_ciphertext(&shift_scalar, &right_ciphertext_hi)?;
        let combined_right_ciphertext = add(right_ciphertext_lo, &shifted_right_ciphertext_hi)?;
        add(left_ciphertext, &combined_right_ciphertext)
    }

    pub fn subtract(
        left_ciphertext: &pod::ElGamalCiphertext,
        right_ciphertext: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        let (left_commitment, left_handle): (pod::PedersenCommitment, pod::DecryptHandle) =
            (*left_ciphertext).into();
        let (right_commitment, right_handle): (pod::PedersenCommitment, pod::DecryptHandle) =
            (*right_ciphertext).into();

        let result_commitment: pod::PedersenCommitment =
            subtract_ristretto(&left_commitment.into(), &right_commitment.into())?.into();
        let result_handle: pod::DecryptHandle =
            subtract_ristretto(&left_handle.into(), &right_handle.into())?.into();

        Some((result_commitment, result_handle).into())
    }

    pub fn subtract_with_lo_hi(
        left_ciphertext: &pod::ElGamalCiphertext,
        right_ciphertext_lo: &pod::ElGamalCiphertext,
        right_ciphertext_hi: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        let shift_scalar = to_scalar(1_u64 << SHIFT_BITS);
        let shifted_right_ciphertext_hi = scalar_ciphertext(&shift_scalar, &right_ciphertext_hi)?;
        let combined_right_ciphertext = add(right_ciphertext_lo, &shifted_right_ciphertext_hi)?;
        subtract(left_ciphertext, &combined_right_ciphertext)
    }

    pub fn add_to(
        ciphertext: &pod::ElGamalCiphertext,
        amount: u64,
    ) -> Option<pod::ElGamalCiphertext> {
        let amount_scalar = to_scalar(amount);
        let amount_point = multiply_ristretto(&amount_scalar, &G)?;

        let (commitment, handle): (pod::PedersenCommitment, pod::DecryptHandle) =
            (*ciphertext).into();
        let commitment_point: PodRistrettoPoint = commitment.into();

        let result_commitment: pod::PedersenCommitment =
            add_ristretto(&commitment_point, &amount_point)?.into();
        Some((result_commitment, handle).into())
    }

    pub fn subtract_from(
        ciphertext: &pod::ElGamalCiphertext,
        amount: u64,
    ) -> Option<pod::ElGamalCiphertext> {
        let amount_scalar = to_scalar(amount);
        let amount_point = multiply_ristretto(&amount_scalar, &G)?;

        let (commitment, handle): (pod::PedersenCommitment, pod::DecryptHandle) =
            (*ciphertext).into();
        let commitment_point: PodRistrettoPoint = commitment.into();

        let result_commitment: pod::PedersenCommitment =
            subtract_ristretto(&commitment_point, &amount_point)?.into();
        Some((result_commitment, handle).into())
    }

    fn to_scalar(amount: u64) -> PodScalar {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&amount.to_le_bytes());
        PodScalar(bytes)
    }

    fn scalar_ciphertext(
        scalar: &PodScalar,
        ciphertext: &pod::ElGamalCiphertext,
    ) -> Option<pod::ElGamalCiphertext> {
        let (commitment, handle): (pod::PedersenCommitment, pod::DecryptHandle) =
            (*ciphertext).into();

        let commitment_point: PodRistrettoPoint = commitment.into();
        let handle_point: PodRistrettoPoint = handle.into();

        let result_commitment: pod::PedersenCommitment =
            multiply_ristretto(scalar, &commitment_point)?.into();
        let result_handle: pod::DecryptHandle = multiply_ristretto(scalar, &handle_point)?.into();

        Some((result_commitment, result_handle).into())
    }
}

pub const OP_ADD: u64 = 0;
pub const OP_SUB: u64 = 1;
