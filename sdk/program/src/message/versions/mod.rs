use {
    crate::{
        hash::Hash,
        instruction::CompiledInstruction,
        message::{legacy::Message as LegacyMessage, MessageHeader},
        pubkey::Pubkey,
        sanitize::{Sanitize, SanitizeError},
        short_vec,
    },
    serde::{
        de::{self, Deserializer, SeqAccess, Visitor},
        ser::{SerializeTuple, Serializer},
        Deserialize, Serialize,
    },
    std::fmt,
};

pub mod v0;

/// Bit mask that indicates whether a serialized message is versioned.
pub const MESSAGE_VERSION_PREFIX: u8 = 0x80;

/// Either a legacy message or a v0 message.
///
/// # Serialization
///
/// If the first bit is set, the remaining 7 bits will be used to determine
/// which message version is serialized starting from version `0`. If the first
/// is bit is not set, all bytes are used to encode the legacy `Message`
/// format.
#[frozen_abi(digest = "G4EAiqmGgBprgf5ePYemLJcoFfx4R7rhC1Weo2FVJ7fn")]
#[derive(Debug, PartialEq, Eq, Clone, AbiEnumVisitor, AbiExample)]
pub enum VersionedMessage {
    Legacy(LegacyMessage),
    V0(v0::Message),
}

impl VersionedMessage {
    pub fn header(&self) -> &MessageHeader {
        match self {
            Self::Legacy(message) => &message.header,
            Self::V0(message) => &message.header,
        }
    }

    pub fn static_account_keys(&self) -> &[Pubkey] {
        match self {
            Self::Legacy(message) => &message.account_keys,
            Self::V0(message) => &message.account_keys,
        }
    }

    pub fn into_static_account_keys(self) -> Vec<Pubkey> {
        match self {
            Self::Legacy(message) => message.account_keys,
            Self::V0(message) => message.account_keys,
        }
    }

    pub fn static_account_keys_iter(&self) -> impl Iterator<Item = &Pubkey> {
        match self {
            Self::Legacy(message) => message.account_keys.iter(),
            Self::V0(message) => message.account_keys.iter(),
        }
    }

    pub fn static_account_keys_len(&self) -> usize {
        match self {
            Self::Legacy(message) => message.account_keys.len(),
            Self::V0(message) => message.account_keys.len(),
        }
    }

    pub fn recent_blockhash(&self) -> &Hash {
        match self {
            Self::Legacy(message) => &message.recent_blockhash,
            Self::V0(message) => &message.recent_blockhash,
        }
    }

    pub fn set_recent_blockhash(&mut self, recent_blockhash: Hash) {
        match self {
            Self::Legacy(message) => message.recent_blockhash = recent_blockhash,
            Self::V0(message) => message.recent_blockhash = recent_blockhash,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    /// Compute the blake3 hash of this transaction's message
    pub fn hash(&self) -> Hash {
        let message_bytes = self.serialize();
        Self::hash_raw_message(&message_bytes)
    }

    /// Compute the blake3 hash of a raw transaction message
    pub fn hash_raw_message(message_bytes: &[u8]) -> Hash {
        use blake3::traits::digest::Digest;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"solana-tx-message-v1");
        hasher.update(message_bytes);
        Hash(<[u8; crate::hash::HASH_BYTES]>::try_from(hasher.finalize().as_slice()).unwrap())
    }
}

impl Default for VersionedMessage {
    fn default() -> Self {
        Self::Legacy(LegacyMessage::default())
    }
}

impl Sanitize for VersionedMessage {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        match self {
            Self::Legacy(message) => message.sanitize(),
            Self::V0(message) => message.sanitize(),
        }
    }
}

impl Serialize for VersionedMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Legacy(message) => {
                let mut seq = serializer.serialize_tuple(1)?;
                seq.serialize_element(message)?;
                seq.end()
            }
            Self::V0(message) => {
                let mut seq = serializer.serialize_tuple(2)?;
                seq.serialize_element(&MESSAGE_VERSION_PREFIX)?;
                seq.serialize_element(message)?;
                seq.end()
            }
        }
    }
}

enum MessagePrefix {
    Legacy(u8),
    Versioned(u8),
}

impl<'de> Deserialize<'de> for MessagePrefix {
    fn deserialize<D>(deserializer: D) -> Result<MessagePrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrefixVisitor;

        impl<'de> Visitor<'de> for PrefixVisitor {
            type Value = MessagePrefix;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("message prefix byte")
            }

            fn visit_u8<E>(self, byte: u8) -> Result<MessagePrefix, E> {
                if byte & MESSAGE_VERSION_PREFIX != 0 {
                    Ok(MessagePrefix::Versioned(byte & !MESSAGE_VERSION_PREFIX))
                } else {
                    Ok(MessagePrefix::Legacy(byte))
                }
            }
        }

        deserializer.deserialize_u8(PrefixVisitor)
    }
}

impl<'de> Deserialize<'de> for VersionedMessage {
    fn deserialize<D>(deserializer: D) -> Result<VersionedMessage, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MessageVisitor;

        impl<'de> Visitor<'de> for MessageVisitor {
            type Value = VersionedMessage;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("message bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<VersionedMessage, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let prefix: MessagePrefix = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match prefix {
                    MessagePrefix::Legacy(num_required_signatures) => {
                        // The remaining fields of the legacy Message struct after the first byte.
                        #[derive(Serialize, Deserialize)]
                        struct RemainingLegacyMessage {
                            pub num_readonly_signed_accounts: u8,
                            pub num_readonly_unsigned_accounts: u8,
                            #[serde(with = "short_vec")]
                            pub account_keys: Vec<Pubkey>,
                            pub recent_blockhash: Hash,
                            #[serde(with = "short_vec")]
                            pub instructions: Vec<CompiledInstruction>,
                        }

                        let message: RemainingLegacyMessage =
                            seq.next_element()?.ok_or_else(|| {
                                // will never happen since tuple length is always 2
                                de::Error::invalid_length(1, &self)
                            })?;

                        Ok(VersionedMessage::Legacy(LegacyMessage {
                            header: MessageHeader {
                                num_required_signatures,
                                num_readonly_signed_accounts: message.num_readonly_signed_accounts,
                                num_readonly_unsigned_accounts: message
                                    .num_readonly_unsigned_accounts,
                            },
                            account_keys: message.account_keys,
                            recent_blockhash: message.recent_blockhash,
                            instructions: message.instructions,
                        }))
                    }
                    MessagePrefix::Versioned(version) => {
                        if version == 0 {
                            Ok(VersionedMessage::V0(seq.next_element()?.ok_or_else(
                                || {
                                    // will never happen since tuple length is always 2
                                    de::Error::invalid_length(1, &self)
                                },
                            )?))
                        } else {
                            Err(de::Error::invalid_value(
                                de::Unexpected::Unsigned(version as u64),
                                &"supported versions: [0]",
                            ))
                        }
                    }
                }
            }
        }

        deserializer.deserialize_tuple(2, MessageVisitor)
    }
}

