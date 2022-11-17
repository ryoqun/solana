//! A future Solana message format.
//!
//! This crate defines two versions of `Message` in their own modules:
//! [`legacy`] and [`v0`]. `legacy` is the current version as of Solana 1.10.0.
//! `v0` is a [future message format] that encodes more account keys into a
//! transaction than the legacy format.
//!
//! [`legacy`]: crate::message::legacy
//! [`v0`]: crate::message::v0
//! [future message format]: https://docs.solana.com/proposals/transactions-v2

use crate::{
    bpf_loader_upgradeable,
    hash::Hash,
    instruction::CompiledInstruction,
    message::{legacy::BUILTIN_PROGRAMS_KEYS, MessageHeader, MESSAGE_VERSION_PREFIX},
    pubkey::Pubkey,
    sanitize::SanitizeError,
    short_vec, sysvar,
};

mod loaded;

pub use loaded::*;

/// Address table lookups describe an on-chain address lookup table to use
/// for loading more readonly and writable accounts in a single tx.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone, AbiExample)]
#[serde(rename_all = "camelCase")]
pub struct MessageAddressTableLookup {
    /// Address lookup table account key
    pub account_key: Pubkey,
    /// List of indexes used to load writable account addresses
    #[serde(with = "short_vec")]
    pub writable_indexes: Vec<u8>,
    /// List of indexes used to load readonly account addresses
    #[serde(with = "short_vec")]
    pub readonly_indexes: Vec<u8>,
}

/// A Solana transaction message (v0).
///
/// This message format supports succinct account loading with
/// on-chain address lookup tables.
///
/// See the [`message`] module documentation for further description.
///
/// [`message`]: crate::message
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone, AbiExample)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// The message header, identifying signed and read-only `account_keys`.
    /// Header values only describe static `account_keys`, they do not describe
    /// any additional account keys loaded via address table lookups.
    pub header: MessageHeader,

    /// List of accounts loaded by this transaction.
    #[serde(with = "short_vec")]
    pub account_keys: Vec<Pubkey>,

    /// The blockhash of a recent block.
    pub recent_blockhash: Hash,

    /// Instructions that invoke a designated program, are executed in sequence,
    /// and committed in one atomic transaction if all succeed.
    ///
    /// # Notes
    ///
    /// Program indexes must index into the list of message `account_keys` because
    /// program id's cannot be dynamically loaded from a lookup table.
    ///
    /// Account indexes must index into the list of addresses
    /// constructed from the concatenation of three key lists:
    ///   1) message `account_keys`
    ///   2) ordered list of keys loaded from `writable` lookup table indexes
    ///   3) ordered list of keys loaded from `readable` lookup table indexes
    #[serde(with = "short_vec")]
    pub instructions: Vec<CompiledInstruction>,

    /// List of address table lookups used to load additional accounts
    /// for this transaction.
    #[serde(with = "short_vec")]
    pub address_table_lookups: Vec<MessageAddressTableLookup>,
}

impl Message {
    /// Sanitize message fields and compiled instruction indexes
    pub fn sanitize(&self, reject_dynamic_program_ids: bool) -> Result<(), SanitizeError> {
        let num_static_account_keys = self.account_keys.len();
        if usize::from(self.header.num_required_signatures)
            .saturating_add(usize::from(self.header.num_readonly_unsigned_accounts))
            > num_static_account_keys
        {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        // there should be at least 1 RW fee-payer account.
        if self.header.num_readonly_signed_accounts >= self.header.num_required_signatures {
            return Err(SanitizeError::InvalidValue);
        }

        let num_dynamic_account_keys = {
            let mut total_lookup_keys: usize = 0;
            for lookup in &self.address_table_lookups {
                let num_lookup_indexes = lookup
                    .writable_indexes
                    .len()
                    .saturating_add(lookup.readonly_indexes.len());

                // each lookup table must be used to load at least one account
                if num_lookup_indexes == 0 {
                    return Err(SanitizeError::InvalidValue);
                }

                total_lookup_keys = total_lookup_keys.saturating_add(num_lookup_indexes);
            }
            total_lookup_keys
        };

        // this is redundant with the above sanitization checks which require that:
        // 1) the header describes at least 1 RW account
        // 2) the header doesn't describe more account keys than the number of account keys
        if num_static_account_keys == 0 {
            return Err(SanitizeError::InvalidValue);
        }

        // the combined number of static and dynamic account keys must be <= 256
        // since account indices are encoded as `u8`
        let total_account_keys = num_static_account_keys.saturating_add(num_dynamic_account_keys);
        if total_account_keys > 256 {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        // `expect` is safe because of earlier check that
        // `num_static_account_keys` is non-zero
        let max_account_ix = total_account_keys
            .checked_sub(1)
            .expect("message doesn't contain any account keys");

        // switch to rejecting program ids loaded from lookup tables so that
        // static analysis on program instructions can be performed without
        // loading on-chain data from a bank
        let max_program_id_ix = if reject_dynamic_program_ids {
            // `expect` is safe because of earlier check that
            // `num_static_account_keys` is non-zero
            num_static_account_keys
                .checked_sub(1)
                .expect("message doesn't contain any static account keys")
        } else {
            max_account_ix
        };

        for ci in &self.instructions {
            if usize::from(ci.program_id_index) > max_program_id_ix {
                return Err(SanitizeError::IndexOutOfBounds);
            }
            // A program cannot be a payer.
            if ci.program_id_index == 0 {
                return Err(SanitizeError::IndexOutOfBounds);
            }
            for ai in &ci.accounts {
                if usize::from(*ai) > max_account_ix {
                    return Err(SanitizeError::IndexOutOfBounds);
                }
            }
        }

        Ok(())
    }
}

impl Message {
    /// Serialize this message with a version #0 prefix using bincode encoding.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&(MESSAGE_VERSION_PREFIX, self)).unwrap()
    }

    /// Returns true if the account at the specified index is called as a program by an instruction
    pub fn is_key_called_as_program(&self, key_index: usize) -> bool {
        if let Ok(key_index) = u8::try_from(key_index) {
            self.instructions
                .iter()
                .any(|ix| ix.program_id_index == key_index)
        } else {
            false
        }
    }

    /// Returns true if the account at the specified index was requested to be
    /// writable.  This method should not be used directly.
    fn is_writable_index(&self, key_index: usize) -> bool {
        let header = &self.header;
        let num_account_keys = self.account_keys.len();
        let num_signed_accounts = usize::from(header.num_required_signatures);
        if key_index >= num_account_keys {
            let loaded_addresses_index = key_index.saturating_sub(num_account_keys);
            let num_writable_dynamic_addresses = self
                .address_table_lookups
                .iter()
                .map(|lookup| lookup.writable_indexes.len())
                .sum();
            loaded_addresses_index < num_writable_dynamic_addresses
        } else if key_index >= num_signed_accounts {
            let num_unsigned_accounts = num_account_keys.saturating_sub(num_signed_accounts);
            let num_writable_unsigned_accounts = num_unsigned_accounts
                .saturating_sub(usize::from(header.num_readonly_unsigned_accounts));
            let unsigned_account_index = key_index.saturating_sub(num_signed_accounts);
            unsigned_account_index < num_writable_unsigned_accounts
        } else {
            let num_writable_signed_accounts = num_signed_accounts
                .saturating_sub(usize::from(header.num_readonly_signed_accounts));
            key_index < num_writable_signed_accounts
        }
    }

    /// Returns true if any static account key is the bpf upgradeable loader
    fn is_upgradeable_loader_in_static_keys(&self) -> bool {
        self.account_keys
            .iter()
            .any(|&key| key == bpf_loader_upgradeable::id())
    }

    /// Returns true if the account at the specified index was requested as writable.
    /// Before loading addresses, we can't demote write locks for dynamically loaded
    /// addresses so this should not be used by the runtime.
    pub fn is_maybe_writable(&self, key_index: usize) -> bool {
        self.is_writable_index(key_index)
            && !{
                // demote reserved ids
                self.account_keys
                    .get(key_index)
                    .map(|key| sysvar::is_sysvar_id(key) || BUILTIN_PROGRAMS_KEYS.contains(key))
                    .unwrap_or_default()
            }
            && !{
                // demote program ids
                self.is_key_called_as_program(key_index)
                    && !self.is_upgradeable_loader_in_static_keys()
            }
    }
}
