//! Plain Old Data types for the Grouped ElGamal encryption scheme.

#[cfg(not(target_os = "solana"))]
use crate::encryption::grouped_elgamal::GroupedElGamalCiphertext;
use {
    crate::{
        encryption::{
            pod::{elgamal::PodElGamalCiphertext, pedersen::PodPedersenCommitment},
            DECRYPT_HANDLE_LEN, ELGAMAL_CIPHERTEXT_LEN, PEDERSEN_COMMITMENT_LEN,
        },
        errors::ElGamalError,
    },
    bytemuck::Zeroable,
    std::fmt,
};

macro_rules! impl_extract {
    (TYPE = $type:ident) => {
        impl $type {
            /// Extract the commitment component from a grouped ciphertext
            pub fn extract_commitment(&self) -> PodPedersenCommitment {
                // `GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES` guaranteed to be at least `PEDERSEN_COMMITMENT_LEN`
                let commitment = self.0[..PEDERSEN_COMMITMENT_LEN].try_into().unwrap();
                PodPedersenCommitment(commitment)
            }

            /// Extract a regular ElGamal ciphertext using the decrypt handle at a specified index.
            pub fn try_extract_ciphertext(
                &self,
                index: usize,
            ) -> Result<PodElGamalCiphertext, ElGamalError> {
                let mut ciphertext_bytes = [0u8; ELGAMAL_CIPHERTEXT_LEN];
                ciphertext_bytes[..PEDERSEN_COMMITMENT_LEN]
                    .copy_from_slice(&self.0[..PEDERSEN_COMMITMENT_LEN]);

                let handle_start = DECRYPT_HANDLE_LEN
                    .checked_mul(index)
                    .and_then(|n| n.checked_add(PEDERSEN_COMMITMENT_LEN))
                    .ok_or(ElGamalError::CiphertextDeserialization)?;
                let handle_end = handle_start
                    .checked_add(DECRYPT_HANDLE_LEN)
                    .ok_or(ElGamalError::CiphertextDeserialization)?;
                ciphertext_bytes[PEDERSEN_COMMITMENT_LEN..].copy_from_slice(
                    self.0
                        .get(handle_start..handle_end)
                        .ok_or(ElGamalError::CiphertextDeserialization)?,
                );

                Ok(PodElGamalCiphertext(ciphertext_bytes))
            }
        }
    };
}

/// Byte length of a grouped ElGamal ciphertext with 2 handles
const GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES: usize =
    PEDERSEN_COMMITMENT_LEN + DECRYPT_HANDLE_LEN + DECRYPT_HANDLE_LEN;

/// Byte length of a grouped ElGamal ciphertext with 3 handles
const GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES: usize =
    PEDERSEN_COMMITMENT_LEN + DECRYPT_HANDLE_LEN + DECRYPT_HANDLE_LEN + DECRYPT_HANDLE_LEN;

/// The `GroupedElGamalCiphertext` type with two decryption handles as a `Pod`
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodGroupedElGamalCiphertext2Handles(
    pub(crate) [u8; GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES],
);

impl fmt::Debug for PodGroupedElGamalCiphertext2Handles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Default for PodGroupedElGamalCiphertext2Handles {
    fn default() -> Self {
        Self::zeroed()
    }
}
#[cfg(not(target_os = "solana"))]
impl From<GroupedElGamalCiphertext<2>> for PodGroupedElGamalCiphertext2Handles {
    fn from(decoded_ciphertext: GroupedElGamalCiphertext<2>) -> Self {
        Self(decoded_ciphertext.to_bytes().try_into().unwrap())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodGroupedElGamalCiphertext2Handles> for GroupedElGamalCiphertext<2> {
    type Error = ElGamalError;

    fn try_from(pod_ciphertext: PodGroupedElGamalCiphertext2Handles) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_ciphertext.0).ok_or(ElGamalError::CiphertextDeserialization)
    }
}

impl_extract!(TYPE = PodGroupedElGamalCiphertext2Handles);

/// The `GroupedElGamalCiphertext` type with three decryption handles as a `Pod`
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodGroupedElGamalCiphertext3Handles(
    pub(crate) [u8; GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES],
);

impl fmt::Debug for PodGroupedElGamalCiphertext3Handles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Default for PodGroupedElGamalCiphertext3Handles {
    fn default() -> Self {
        Self::zeroed()
    }
}

#[cfg(not(target_os = "solana"))]
impl From<GroupedElGamalCiphertext<3>> for PodGroupedElGamalCiphertext3Handles {
    fn from(decoded_ciphertext: GroupedElGamalCiphertext<3>) -> Self {
        Self(decoded_ciphertext.to_bytes().try_into().unwrap())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodGroupedElGamalCiphertext3Handles> for GroupedElGamalCiphertext<3> {
    type Error = ElGamalError;

    fn try_from(pod_ciphertext: PodGroupedElGamalCiphertext3Handles) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_ciphertext.0).ok_or(ElGamalError::CiphertextDeserialization)
    }
}

impl_extract!(TYPE = PodGroupedElGamalCiphertext3Handles);
