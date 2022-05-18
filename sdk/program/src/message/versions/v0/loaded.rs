use {
    crate::{
        bpf_loader_upgradeable,
        message::{legacy::BUILTIN_PROGRAMS_KEYS, v0},
        pubkey::Pubkey,
        sysvar,
    },
    std::{collections::HashSet, ops::Deref},
};

/// Combination of a version #0 message and its loaded addresses
#[derive(Debug, Clone)]
pub struct LoadedMessage {
    /// Message which loaded a collection of lookup table addresses
    pub message: v0::Message,
    /// Addresses loaded with on-chain address lookup tables
    pub loaded_addresses: LoadedAddresses,
}

impl Deref for LoadedMessage {
    type Target = v0::Message;
    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

/// Collection of addresses loaded from on-chain lookup tables, split
/// by readonly and writable.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoadedAddresses {
    /// List of addresses for writable loaded accounts
    pub writable: Vec<Pubkey>,
    /// List of addresses for read-only loaded accounts
    pub readonly: Vec<Pubkey>,
}

impl FromIterator<LoadedAddresses> for LoadedAddresses {
    fn from_iter<T: IntoIterator<Item = LoadedAddresses>>(iter: T) -> Self {
        let (writable, readonly): (Vec<Vec<Pubkey>>, Vec<Vec<Pubkey>>) = iter
            .into_iter()
            .map(|addresses| (addresses.writable, addresses.readonly))
            .unzip();
        LoadedAddresses {
            writable: writable.into_iter().flatten().collect(),
            readonly: readonly.into_iter().flatten().collect(),
        }
    }
}

impl LoadedMessage {
    /// Returns an iterator of account key segments. The ordering of segments
    /// affects how account indexes from compiled instructions are resolved and
    /// so should not be changed.
    fn account_keys_segment_iter(&self) -> impl Iterator<Item = &Vec<Pubkey>> {
        vec![
            &self.message.account_keys,
            &self.loaded_addresses.writable,
            &self.loaded_addresses.readonly,
        ]
        .into_iter()
    }

    /// Returns the total length of loaded accounts for this message
    pub fn account_keys_len(&self) -> usize {
        let mut len = 0usize;
        for key_segment in self.account_keys_segment_iter() {
            len = len.saturating_add(key_segment.len());
        }
        len
    }

    /// Iterator for the addresses of the loaded accounts for this message
    pub fn account_keys_iter(&self) -> impl Iterator<Item = &Pubkey> {
        self.account_keys_segment_iter().flatten()
    }

    /// Returns true if any account keys are duplicates
    pub fn has_duplicates(&self) -> bool {
        let mut uniq = HashSet::new();
        self.account_keys_iter().any(|x| !uniq.insert(x))
    }

    /// Returns the address of the account at the specified index of the list of
    /// message account keys constructed from static keys, followed by dynamically
    /// loaded writable addresses, and lastly the list of dynamically loaded
    /// readonly addresses.
    pub fn get_account_key(&self, mut index: usize) -> Option<&Pubkey> {
        for key_segment in self.account_keys_segment_iter() {
            if index < key_segment.len() {
                return Some(&key_segment[index]);
            }
            index = index.saturating_sub(key_segment.len());
        }

        None
    }

    /// Returns true if the account at the specified index was requested to be
    /// writable.  This method should not be used directly.
    fn is_writable_index(&self, key_index: usize) -> bool {
        let header = &self.message.header;
        let num_account_keys = self.message.account_keys.len();
        let num_signed_accounts = usize::from(header.num_required_signatures);
        if key_index >= num_account_keys {
            let loaded_addresses_index = key_index.saturating_sub(num_account_keys);
            loaded_addresses_index < self.loaded_addresses.writable.len()
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

    /// Returns true if the account at the specified index was loaded as writable
    pub fn is_writable(&self, key_index: usize) -> bool {
        if self.is_writable_index(key_index) {
            if let Some(key) = self.get_account_key(key_index) {
                let demote_program_id = self.is_key_called_as_program(key_index)
                    && !self.is_upgradeable_loader_present();
                return !(sysvar::is_sysvar_id(key)
                    || BUILTIN_PROGRAMS_KEYS.contains(key)
                    || demote_program_id);
            }
        }
        false
    }

    /// Returns true if the account at the specified index is called as a program by an instruction
    pub fn is_key_called_as_program(&self, key_index: usize) -> bool {
        if let Ok(key_index) = u8::try_from(key_index) {
            self.message
                .instructions
                .iter()
                .any(|ix| ix.program_id_index == key_index)
        } else {
            false
        }
    }

    /// Returns true if any account is the bpf upgradeable loader
    pub fn is_upgradeable_loader_present(&self) -> bool {
        self.account_keys_iter()
            .any(|&key| key == bpf_loader_upgradeable::id())
    }
}

