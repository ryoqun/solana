use {
    crate::{
        instruction::{CompiledInstruction, Instruction},
        message::v0::LoadedAddresses,
        pubkey::Pubkey,
    },
    std::{collections::BTreeMap, ops::Index},
};

/// Collection of static and dynamically loaded keys used to load accounts
/// during transaction processing.
pub struct AccountKeys<'a> {
    static_keys: &'a [Pubkey],
    dynamic_keys: Option<&'a LoadedAddresses>,
}

impl Index<usize> for AccountKeys<'_> {
    type Output = Pubkey;
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index is invalid")
    }
}

impl<'a> AccountKeys<'a> {
    pub fn new(static_keys: &'a [Pubkey], dynamic_keys: Option<&'a LoadedAddresses>) -> Self {
        Self {
            static_keys,
            dynamic_keys,
        }
    }

    /// Returns an iterator of account key segments. The ordering of segments
    /// affects how account indexes from compiled instructions are resolved and
    /// so should not be changed.
    fn key_segment_iter(&self) -> impl Iterator<Item = &'a [Pubkey]> {
        if let Some(dynamic_keys) = self.dynamic_keys {
            [
                self.static_keys,
                &dynamic_keys.writable,
                &dynamic_keys.readonly,
            ]
            .into_iter()
        } else {
            // empty segments added for branch type compatibility
            [self.static_keys, &[], &[]].into_iter()
        }
    }

    /// Returns the address of the account at the specified index of the list of
    /// message account keys constructed from static keys, followed by dynamically
    /// loaded writable addresses, and lastly the list of dynamically loaded
    /// readonly addresses.
    pub fn get(&self, mut index: usize) -> Option<&'a Pubkey> {
        for key_segment in self.key_segment_iter() {
            if index < key_segment.len() {
                return Some(&key_segment[index]);
            }
            index = index.saturating_sub(key_segment.len());
        }

        None
    }

    /// Returns the total length of loaded accounts for a message
    pub fn len(&self) -> usize {
        let mut len = 0usize;
        for key_segment in self.key_segment_iter() {
            len = len.saturating_add(key_segment.len());
        }
        len
    }

    /// Returns true if this collection of account keys is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterator for the addresses of the loaded accounts for a message
    pub fn iter(&self) -> impl Iterator<Item = &'a Pubkey> {
        self.key_segment_iter().flatten()
    }

    /// Compile instructions using the order of account keys to determine
    /// compiled instruction account indexes.
    pub fn compile_instructions(&self, instructions: &[Instruction]) -> Vec<CompiledInstruction> {
        let account_index_map: BTreeMap<&Pubkey, u8> = BTreeMap::from_iter(
            self.iter()
                .enumerate()
                .map(|(index, key)| (key, index as u8)),
        );

        instructions
            .iter()
            .map(|ix| {
                let accounts: Vec<u8> = ix
                    .accounts
                    .iter()
                    .map(|account_meta| *account_index_map.get(&account_meta.pubkey).unwrap())
                    .collect();

                CompiledInstruction {
                    program_id_index: *account_index_map.get(&ix.program_id).unwrap(),
                    data: ix.data.clone(),
                    accounts,
                }
            })
            .collect()
    }
}
