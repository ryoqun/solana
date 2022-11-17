//! The `signature` module provides functionality for public, and private keys.
#![cfg(feature = "full")]

// legacy module paths
pub use crate::signer::{keypair::*, null_signer::*, presigner::*, *};
use {
    crate::pubkey::Pubkey,
    generic_array::{typenum::U64, GenericArray},
    std::{
        borrow::{Borrow, Cow},
        convert::TryInto,
        fmt, mem,
        str::FromStr,
    },
    thiserror::Error,
};

/// Number of bytes in a signature
pub const SIGNATURE_BYTES: usize = 64;
/// Maximum string length of a base58 encoded signature
const MAX_BASE58_SIGNATURE_LEN: usize = 88;

#[repr(transparent)]
#[derive(
    Serialize, Deserialize, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash, AbiExample,
)]
pub struct Signature(GenericArray<u8, U64>);

impl crate::sanitize::Sanitize for Signature {}

impl Signature {
    pub fn new(signature_slice: &[u8]) -> Self {
        Self(GenericArray::clone_from_slice(signature_slice))
    }

    pub fn new_unique() -> Self {
        let random_bytes: Vec<u8> = (0..64).map(|_| rand::random::<u8>()).collect();
        Self::new(&random_bytes)
    }

    pub(self) fn verify_verbose(
        &self,
        pubkey_bytes: &[u8],
        message_bytes: &[u8],
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let publickey = ed25519_dalek::PublicKey::from_bytes(pubkey_bytes)?;
        let signature = self.0.as_slice().try_into()?;
        publickey.verify_strict(message_bytes, &signature)
    }

    pub fn verify(&self, pubkey_bytes: &[u8], message_bytes: &[u8]) -> bool {
        self.verify_verbose(pubkey_bytes, message_bytes).is_ok()
    }
}

pub trait Signable {
    fn sign(&mut self, keypair: &Keypair) {
        let signature = keypair.sign_message(self.signable_data().borrow());
        self.set_signature(signature);
    }
    fn verify(&self) -> bool {
        self.get_signature()
            .verify(self.pubkey().as_ref(), self.signable_data().borrow())
    }

    fn pubkey(&self) -> Pubkey;
    fn signable_data(&self) -> Cow<[u8]>;
    fn get_signature(&self) -> Signature;
    fn set_signature(&mut self, signature: Signature);
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl From<Signature> for [u8; 64] {
    fn from(signature: Signature) -> Self {
        signature.0.into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseSignatureError {
    #[error("string decoded to wrong size for signature")]
    WrongSize,
    #[error("failed to decode string to signature")]
    Invalid,
}

impl FromStr for Signature {
    type Err = ParseSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_BASE58_SIGNATURE_LEN {
            return Err(ParseSignatureError::WrongSize);
        }
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| ParseSignatureError::Invalid)?;
        if bytes.len() != mem::size_of::<Signature>() {
            Err(ParseSignatureError::WrongSize)
        } else {
            Ok(Signature::new(&bytes))
        }
    }
}
