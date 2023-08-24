use {
    solana_sdk::{
        message::{SanitizedMessage, VersionedMessage},
        pubkey::Pubkey,
    },
    std::collections::HashSet,
};

/// Wrapper struct to check account locks for a batch of transactions.
#[derive(Debug, Default)]
pub struct ReadWriteAccountSet {
    /// Set of accounts that are locked for read
    read_set: HashSet<Pubkey>,
    /// Set of accounts that are locked for write
    write_set: HashSet<Pubkey>,
}

impl ReadWriteAccountSet {
    /// Check static account locks for a transaction message.
    pub fn check_static_account_locks(&self, message: &VersionedMessage) -> bool {
        !message
            .static_account_keys()
            .iter()
            .enumerate()
            .any(|(index, pubkey)| {
                if message.is_maybe_writable(index) {
                    !self.can_write(pubkey)
                } else {
                    !self.can_read(pubkey)
                }
            })
    }

    /// Check all account locks and if they are available, lock them.
    /// Returns true if all account locks are available and false otherwise.
    pub fn try_locking(&mut self, message: &SanitizedMessage) -> bool {
        if self.check_sanitized_message_account_locks(message) {
            self.add_sanitized_message_account_locks(message);
            true
        } else {
            false
        }
    }

    /// Clears the read and write sets
    pub fn clear(&mut self) {
        self.read_set.clear();
        self.write_set.clear();
    }

    /// Check if a sanitized message's account locks are available.
    fn check_sanitized_message_account_locks(&self, message: &SanitizedMessage) -> bool {
        !message
            .account_keys()
            .iter()
            .enumerate()
            .any(|(index, pubkey)| {
                if message.is_writable(index) {
                    !self.can_write(pubkey)
                } else {
                    !self.can_read(pubkey)
                }
            })
    }

    /// Insert the read and write locks for a sanitized message.
    fn add_sanitized_message_account_locks(&mut self, message: &SanitizedMessage) {
        message
            .account_keys()
            .iter()
            .enumerate()
            .for_each(|(index, pubkey)| {
                if message.is_writable(index) {
                    self.add_write(pubkey);
                } else {
                    self.add_read(pubkey);
                }
            });
    }

    /// Check if an account can be read-locked
    fn can_read(&self, pubkey: &Pubkey) -> bool {
        !self.write_set.contains(pubkey)
    }

    /// Check if an account can be write-locked
    fn can_write(&self, pubkey: &Pubkey) -> bool {
        !self.write_set.contains(pubkey) && !self.read_set.contains(pubkey)
    }

    /// Add an account to the read-set.
    /// Should only be called after `can_read()` returns true
    fn add_read(&mut self, pubkey: &Pubkey) {
        self.read_set.insert(*pubkey);
    }

    /// Add an account to the write-set.
    /// Should only be called after `can_write()` returns true
    fn add_write(&mut self, pubkey: &Pubkey) {
        self.write_set.insert(*pubkey);
    }
}
