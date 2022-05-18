use {
    crate::{instruction::Instruction, message::MessageHeader, pubkey::Pubkey},
    std::collections::BTreeMap,
};

/// A helper struct to collect pubkeys compiled for a set of instructions
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct CompiledKeys {
    writable_signer_keys: Vec<Pubkey>,
    readonly_signer_keys: Vec<Pubkey>,
    writable_non_signer_keys: Vec<Pubkey>,
    readonly_non_signer_keys: Vec<Pubkey>,
}

#[derive(Default, Debug)]
struct CompiledKeyMeta {
    is_signer: bool,
    is_writable: bool,
}

impl CompiledKeys {
    /// Compiles the pubkeys referenced by a list of instructions and organizes by
    /// signer/non-signer and writable/readonly.
    pub(crate) fn compile(instructions: &[Instruction], payer: Option<Pubkey>) -> Self {
        let mut key_meta_map = BTreeMap::<&Pubkey, CompiledKeyMeta>::new();
        for ix in instructions {
            key_meta_map.entry(&ix.program_id).or_default();
            for account_meta in &ix.accounts {
                let meta = key_meta_map.entry(&account_meta.pubkey).or_default();
                meta.is_signer |= account_meta.is_signer;
                meta.is_writable |= account_meta.is_writable;
            }
        }

        if let Some(payer) = &payer {
            key_meta_map.remove(payer);
        }

        let writable_signer_keys: Vec<Pubkey> = payer
            .into_iter()
            .chain(
                key_meta_map
                    .iter()
                    .filter_map(|(key, meta)| (meta.is_signer && meta.is_writable).then(|| **key)),
            )
            .collect();
        let readonly_signer_keys = key_meta_map
            .iter()
            .filter_map(|(key, meta)| (meta.is_signer && !meta.is_writable).then(|| **key))
            .collect();
        let writable_non_signer_keys = key_meta_map
            .iter()
            .filter_map(|(key, meta)| (!meta.is_signer && meta.is_writable).then(|| **key))
            .collect();
        let readonly_non_signer_keys = key_meta_map
            .iter()
            .filter_map(|(key, meta)| (!meta.is_signer && !meta.is_writable).then(|| **key))
            .collect();

        CompiledKeys {
            writable_signer_keys,
            readonly_signer_keys,
            writable_non_signer_keys,
            readonly_non_signer_keys,
        }
    }

    pub(crate) fn try_into_message_components(self) -> Option<(MessageHeader, Vec<Pubkey>)> {
        let header = MessageHeader {
            num_required_signatures: u8::try_from(
                self.writable_signer_keys
                    .len()
                    .checked_add(self.readonly_signer_keys.len())?,
            )
            .ok()?,
            num_readonly_signed_accounts: u8::try_from(self.readonly_signer_keys.len()).ok()?,
            num_readonly_unsigned_accounts: u8::try_from(self.readonly_non_signer_keys.len())
                .ok()?,
        };

        let static_account_keys = std::iter::empty()
            .chain(self.writable_signer_keys)
            .chain(self.readonly_signer_keys)
            .chain(self.writable_non_signer_keys)
            .chain(self.readonly_non_signer_keys)
            .collect();

        Some((header, static_account_keys))
    }
}

