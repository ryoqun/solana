//! The twisted ElGamal encryption implementation.
//!
//! The message space consists of any number that is representable as a scalar (a.k.a. "exponent")
//! for Curve25519.
//!
//! A twisted ElGamal ciphertext consists of two components:
//! - A Pedersen commitment that encodes a message to be encrypted
//! - A "decryption handle" that binds the Pedersen opening to a specific public key
//! In contrast to the traditional ElGamal encryption scheme, the twisted ElGamal encodes messages
//! directly as a Pedersen commitment. Therefore, proof systems that are designed specifically for
//! Pedersen commitments can be used on the twisted ElGamal ciphertexts.
//!
//! As the messages are encrypted as scalar elements (a.k.a. in the "exponent"), the encryption
//! scheme requires solving discrete log to recover the original plaintext.

use {
    crate::encryption::{
        discrete_log::DiscreteLog,
        pedersen::{Pedersen, PedersenCommitment, PedersenOpening, G, H},
    },
    arrayref::{array_ref, array_refs},
    core::ops::{Add, Mul, Sub},
    curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::Identity,
    },
    serde::{Deserialize, Serialize},
    solana_sdk::{
        instruction::Instruction,
        message::Message,
        pubkey::Pubkey,
        signature::Signature,
        signer::{Signer, SignerError},
    },
    std::convert::TryInto,
    subtle::{Choice, ConstantTimeEq},
    zeroize::Zeroize,
};
#[cfg(not(target_arch = "bpf"))]
use {
    rand::rngs::OsRng,
    sha3::Sha3_512,
    std::{
        fmt,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        path::Path,
    },
};

/// Algorithm handle for the twisted ElGamal encryption scheme
pub struct ElGamal;
impl ElGamal {
    /// Generates an ElGamal keypair.
    ///
    /// This function is randomized. It internally samples a scalar element using `OsRng`.
    #[cfg(not(target_arch = "bpf"))]
    #[allow(non_snake_case)]
    fn keygen() -> ElGamalKeypair {
        // secret scalar should be zero with negligible probability
        let mut s = Scalar::random(&mut OsRng);
        let keypair = Self::keygen_with_scalar(&s);

        s.zeroize();
        keypair
    }

    /// Generates an ElGamal keypair from a scalar input that determines the ElGamal private key.
    #[cfg(not(target_arch = "bpf"))]
    #[allow(non_snake_case)]
    fn keygen_with_scalar(s: &Scalar) -> ElGamalKeypair {
        assert!(s != &Scalar::zero());

        let P = s.invert() * &(*H);

        ElGamalKeypair {
            public: ElGamalPubkey(P),
            secret: ElGamalSecretKey(*s),
        }
    }

    /// On input an ElGamal public key and a mesage to be encrypted, the function returns a
    /// corresponding ElGamal ciphertext.
    ///
    /// This function is randomized. It internally samples a scalar element using `OsRng`.
    #[cfg(not(target_arch = "bpf"))]
    fn encrypt<T: Into<Scalar>>(public: &ElGamalPubkey, amount: T) -> ElGamalCiphertext {
        let (commitment, opening) = Pedersen::new(amount);
        let handle = public.decrypt_handle(&opening);

        ElGamalCiphertext { commitment, handle }
    }

    /// On input a public key, message, and Pedersen opening, the function
    /// returns the corresponding ElGamal ciphertext.
    #[cfg(not(target_arch = "bpf"))]
    fn encrypt_with<T: Into<Scalar>>(
        amount: T,
        public: &ElGamalPubkey,
        opening: &PedersenOpening,
    ) -> ElGamalCiphertext {
        let commitment = Pedersen::with(amount, opening);
        let handle = public.decrypt_handle(opening);

        ElGamalCiphertext { commitment, handle }
    }

    /// On input a message, the function returns a twisted ElGamal ciphertext where the associated
    /// Pedersen opening is always zero. Since the opening is zero, any twisted ElGamal ciphertext
    /// of this form is a valid ciphertext under any ElGamal public key.
    #[cfg(not(target_arch = "bpf"))]
    pub fn encode<T: Into<Scalar>>(amount: T) -> ElGamalCiphertext {
        let commitment = Pedersen::encode(amount);
        let handle = DecryptHandle(RistrettoPoint::identity());

        ElGamalCiphertext { commitment, handle }
    }

    /// On input a secret key and a ciphertext, the function returns the decrypted message.
    ///
    /// The output of this function is of type `DiscreteLog`. To recover, the originally encrypted
    /// message, use `DiscreteLog::decode`.
    #[cfg(not(target_arch = "bpf"))]
    fn decrypt(secret: &ElGamalSecretKey, ciphertext: &ElGamalCiphertext) -> DiscreteLog {
        DiscreteLog {
            generator: *G,
            target: &ciphertext.commitment.0 - &(&secret.0 * &ciphertext.handle.0),
        }
    }

    /// On input a secret key and a ciphertext, the function returns the decrypted message
    /// interpretted as type `u32`.
    #[cfg(not(target_arch = "bpf"))]
    fn decrypt_u32(secret: &ElGamalSecretKey, ciphertext: &ElGamalCiphertext) -> Option<u64> {
        let discrete_log_instance = Self::decrypt(secret, ciphertext);
        discrete_log_instance.decode_u32()
    }
}

/// A (twisted) ElGamal encryption keypair.
///
/// The instances of the secret key are zeroized on drop.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Zeroize)]
pub struct ElGamalKeypair {
    /// The public half of this keypair.
    pub public: ElGamalPubkey,
    /// The secret half of this keypair.
    pub secret: ElGamalSecretKey,
}

impl ElGamalKeypair {
    /// Deterministically derives an ElGamal keypair from an Ed25519 signing key and a Solana address.
    #[cfg(not(target_arch = "bpf"))]
    #[allow(non_snake_case)]
    pub fn new(signer: &dyn Signer, address: &Pubkey) -> Result<Self, SignerError> {
        let message = Message::new(
            &[Instruction::new_with_bytes(
                *address,
                b"ElGamalSecretKey",
                vec![],
            )],
            Some(&signer.try_pubkey()?),
        );
        let signature = signer.try_sign_message(&message.serialize())?;

        // Some `Signer` implementations return the default signature, which is not suitable for
        // use as key material
        if signature == Signature::default() {
            return Err(SignerError::Custom("Rejecting default signature".into()));
        }

        let mut scalar = Scalar::hash_from_bytes::<Sha3_512>(signature.as_ref());
        let keypair = ElGamal::keygen_with_scalar(&scalar);

        // TODO: zeroize signature?
        scalar.zeroize();
        Ok(keypair)
    }

    /// Generates the public and secret keys for ElGamal encryption.
    ///
    /// This function is randomized. It internally samples a scalar element using `OsRng`.
    #[cfg(not(target_arch = "bpf"))]
    #[allow(clippy::new_ret_no_self)]
    pub fn new_rand() -> Self {
        ElGamal::keygen()
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.public.to_bytes());
        bytes[32..].copy_from_slice(self.secret.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            public: ElGamalPubkey::from_bytes(bytes[..32].try_into().ok()?)?,
            secret: ElGamalSecretKey::from_bytes(bytes[32..].try_into().ok()?)?,
        })
    }

    /// Reads a JSON-encoded keypair from a `Reader` implementor
    pub fn read_json<R: Read>(reader: &mut R) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes: Vec<u8> = serde_json::from_reader(reader)?;
        Self::from_bytes(&bytes).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "Invalid ElGamalKeypair").into()
        })
    }

    /// Reads keypair from a file
    pub fn read_json_file<F: AsRef<Path>>(path: F) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path.as_ref())?;
        Self::read_json(&mut file)
    }

    /// Writes to a `Write` implementer with JSON-encoding
    pub fn write_json<W: Write>(
        &self,
        writer: &mut W,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let bytes = self.to_bytes();
        let json = serde_json::to_string(&bytes.to_vec())?;
        writer.write_all(&json.clone().into_bytes())?;
        Ok(json)
    }

    /// Write keypair to a file with JSON-encoding
    pub fn write_json_file<F: AsRef<Path>>(
        &self,
        outfile: F,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let outfile = outfile.as_ref();

        if let Some(outdir) = outfile.parent() {
            fs::create_dir_all(outdir)?;
        }

        let mut f = {
            #[cfg(not(unix))]
            {
                OpenOptions::new()
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                OpenOptions::new().mode(0o600)
            }
        }
        .write(true)
        .truncate(true)
        .create(true)
        .open(outfile)?;

        self.write_json(&mut f)
    }
}

/// Public key for the ElGamal encryption scheme.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Zeroize)]
pub struct ElGamalPubkey(RistrettoPoint);
impl ElGamalPubkey {
    /// Derives the `ElGamalPubkey` that uniquely corresponds to an `ElGamalSecretKey`.
    #[allow(non_snake_case)]
    pub fn new(secret: &ElGamalSecretKey) -> Self {
        ElGamalPubkey(&secret.0 * &(*H))
    }

    pub fn get_point(&self) -> &RistrettoPoint {
        &self.0
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<ElGamalPubkey> {
        Some(ElGamalPubkey(
            CompressedRistretto::from_slice(bytes).decompress()?,
        ))
    }

    /// Encrypts an amount under the public key.
    ///
    /// This function is randomized. It internally samples a scalar element using `OsRng`.
    #[cfg(not(target_arch = "bpf"))]
    pub fn encrypt<T: Into<Scalar>>(&self, amount: T) -> ElGamalCiphertext {
        ElGamal::encrypt(self, amount)
    }

    /// Encrypts an amount under the public key and an input Pedersen opening.
    pub fn encrypt_with<T: Into<Scalar>>(
        &self,
        amount: T,
        opening: &PedersenOpening,
    ) -> ElGamalCiphertext {
        ElGamal::encrypt_with(amount, self, opening)
    }

    /// Generates a decryption handle for an ElGamal public key under a Pedersen
    /// opening.
    pub fn decrypt_handle(self, opening: &PedersenOpening) -> DecryptHandle {
        DecryptHandle::new(&self, opening)
    }
}

impl fmt::Display for ElGamalPubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", base64::encode(self.to_bytes()))
    }
}

/// Secret key for the ElGamal encryption scheme.
///
/// Instances of ElGamal secret key are zeroized on drop.
#[derive(Clone, Debug, Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct ElGamalSecretKey(Scalar);
impl ElGamalSecretKey {
    /// Deterministically derives an ElGamal keypair from an Ed25519 signing key and a Solana
    /// address.
    pub fn new(signer: &dyn Signer, address: &Pubkey) -> Result<Self, SignerError> {
        let message = Message::new(
            &[Instruction::new_with_bytes(
                *address,
                b"ElGamalSecretKey",
                vec![],
            )],
            Some(&signer.try_pubkey()?),
        );
        let signature = signer.try_sign_message(&message.serialize())?;

        // Some `Signer` implementations return the default signature, which is not suitable for
        // use as key material
        if signature == Signature::default() {
            Err(SignerError::Custom("Rejecting default signature".into()))
        } else {
            Ok(ElGamalSecretKey(Scalar::hash_from_bytes::<Sha3_512>(
                signature.as_ref(),
            )))
        }
    }

    /// Randomly samples an ElGamal secret key.
    ///
    /// This function is randomized. It internally samples a scalar element using `OsRng`.
    pub fn new_rand() -> Self {
        ElGamalSecretKey(Scalar::random(&mut OsRng))
    }

    pub fn get_scalar(&self) -> &Scalar {
        &self.0
    }

    /// Decrypts a ciphertext using the ElGamal secret key.
    ///
    /// The output of this function is of type `DiscreteLog`. To recover, the originally encrypted
    /// message, use `DiscreteLog::decode`.
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> DiscreteLog {
        ElGamal::decrypt(self, ciphertext)
    }

    /// Decrypts a ciphertext using the ElGamal secret key interpretting the message as type `u32`.
    pub fn decrypt_u32(&self, ciphertext: &ElGamalCiphertext) -> Option<u64> {
        ElGamal::decrypt_u32(self, ciphertext)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Option<ElGamalSecretKey> {
        Scalar::from_canonical_bytes(bytes).map(ElGamalSecretKey)
    }
}

impl From<Scalar> for ElGamalSecretKey {
    fn from(scalar: Scalar) -> ElGamalSecretKey {
        ElGamalSecretKey(scalar)
    }
}

impl Eq for ElGamalSecretKey {}
impl PartialEq for ElGamalSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}
impl ConstantTimeEq for ElGamalSecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Ciphertext for the ElGamal encryption scheme.
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ElGamalCiphertext {
    pub commitment: PedersenCommitment,
    pub handle: DecryptHandle,
}
impl ElGamalCiphertext {
    pub fn add_amount<T: Into<Scalar>>(&self, amount: T) -> Self {
        let commitment_to_add = PedersenCommitment(amount.into() * &(*G));
        ElGamalCiphertext {
            commitment: &self.commitment + &commitment_to_add,
            handle: self.handle,
        }
    }

    pub fn subtract_amount<T: Into<Scalar>>(&self, amount: T) -> Self {
        let commitment_to_subtract = PedersenCommitment(amount.into() * &(*G));
        ElGamalCiphertext {
            commitment: &self.commitment - &commitment_to_subtract,
            handle: self.handle,
        }
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.commitment.to_bytes());
        bytes[32..].copy_from_slice(&self.handle.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<ElGamalCiphertext> {
        let bytes = array_ref![bytes, 0, 64];
        let (commitment, handle) = array_refs![bytes, 32, 32];

        let commitment = CompressedRistretto::from_slice(commitment).decompress()?;
        let handle = CompressedRistretto::from_slice(handle).decompress()?;

        Some(ElGamalCiphertext {
            commitment: PedersenCommitment(commitment),
            handle: DecryptHandle(handle),
        })
    }

    /// Decrypts the ciphertext using an ElGamal secret key.
    ///
    /// The output of this function is of type `DiscreteLog`. To recover, the originally encrypted
    /// message, use `DiscreteLog::decode`.
    pub fn decrypt(&self, secret: &ElGamalSecretKey) -> DiscreteLog {
        ElGamal::decrypt(secret, self)
    }

    /// Decrypts the ciphertext using an ElGamal secret key interpretting the message as type `u32`.
    pub fn decrypt_u32(&self, secret: &ElGamalSecretKey) -> Option<u64> {
        ElGamal::decrypt_u32(secret, self)
    }
}

impl<'a, 'b> Add<&'b ElGamalCiphertext> for &'a ElGamalCiphertext {
    type Output = ElGamalCiphertext;

    fn add(self, other: &'b ElGamalCiphertext) -> ElGamalCiphertext {
        ElGamalCiphertext {
            commitment: &self.commitment + &other.commitment,
            handle: &self.handle + &other.handle,
        }
    }
}

define_add_variants!(
    LHS = ElGamalCiphertext,
    RHS = ElGamalCiphertext,
    Output = ElGamalCiphertext
);

impl<'a, 'b> Sub<&'b ElGamalCiphertext> for &'a ElGamalCiphertext {
    type Output = ElGamalCiphertext;

    fn sub(self, other: &'b ElGamalCiphertext) -> ElGamalCiphertext {
        ElGamalCiphertext {
            commitment: &self.commitment - &other.commitment,
            handle: &self.handle - &other.handle,
        }
    }
}

define_sub_variants!(
    LHS = ElGamalCiphertext,
    RHS = ElGamalCiphertext,
    Output = ElGamalCiphertext
);

impl<'a, 'b> Mul<&'b Scalar> for &'a ElGamalCiphertext {
    type Output = ElGamalCiphertext;

    fn mul(self, other: &'b Scalar) -> ElGamalCiphertext {
        ElGamalCiphertext {
            commitment: &self.commitment * other,
            handle: &self.handle * other,
        }
    }
}

define_mul_variants!(
    LHS = ElGamalCiphertext,
    RHS = Scalar,
    Output = ElGamalCiphertext
);

/// Decryption handle for Pedersen commitment.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecryptHandle(RistrettoPoint);
impl DecryptHandle {
    pub fn new(public: &ElGamalPubkey, opening: &PedersenOpening) -> Self {
        Self(&public.0 * &opening.0)
    }

    pub fn get_point(&self) -> &RistrettoPoint {
        &self.0
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<DecryptHandle> {
        Some(DecryptHandle(
            CompressedRistretto::from_slice(bytes).decompress()?,
        ))
    }
}

impl<'a, 'b> Add<&'b DecryptHandle> for &'a DecryptHandle {
    type Output = DecryptHandle;

    fn add(self, other: &'b DecryptHandle) -> DecryptHandle {
        DecryptHandle(&self.0 + &other.0)
    }
}

define_add_variants!(
    LHS = DecryptHandle,
    RHS = DecryptHandle,
    Output = DecryptHandle
);

impl<'a, 'b> Sub<&'b DecryptHandle> for &'a DecryptHandle {
    type Output = DecryptHandle;

    fn sub(self, other: &'b DecryptHandle) -> DecryptHandle {
        DecryptHandle(&self.0 - &other.0)
    }
}

define_sub_variants!(
    LHS = DecryptHandle,
    RHS = DecryptHandle,
    Output = DecryptHandle
);

impl<'a, 'b> Mul<&'b Scalar> for &'a DecryptHandle {
    type Output = DecryptHandle;

    fn mul(self, other: &'b Scalar) -> DecryptHandle {
        DecryptHandle(&self.0 * other)
    }
}

define_mul_variants!(LHS = DecryptHandle, RHS = Scalar, Output = DecryptHandle);

