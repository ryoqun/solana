use {
    crate::timings::ExecuteDetailsTimings,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        instruction::InstructionError,
        pubkey::Pubkey,
        rent::Rent,
        system_instruction::MAX_PERMITTED_DATA_LENGTH,
    },
    std::fmt::Debug,
};

// The relevant state of an account before an Instruction executes, used
// to verify account integrity after the Instruction completes
#[derive(Clone, Debug, Default)]
pub struct PreAccount {
    key: Pubkey,
    account: AccountSharedData,
    changed: bool,
}
impl PreAccount {
    pub fn new(key: &Pubkey, account: AccountSharedData) -> Self {
        Self {
            key: *key,
            account,
            changed: false,
        }
    }

    pub fn verify(
        &self,
        program_id: &Pubkey,
        is_writable: bool,
        rent: &Rent,
        post: &AccountSharedData,
        timings: &mut ExecuteDetailsTimings,
        outermost_call: bool,
    ) -> Result<(), InstructionError> {
        let pre = &self.account;

        // Only the owner of the account may change owner and
        //   only if the account is writable and
        //   only if the account is not executable and
        //   only if the data is zero-initialized or empty
        let owner_changed = pre.owner() != post.owner();
        if owner_changed
            && (!is_writable // line coverage used to get branch coverage
                || pre.executable()
                || program_id != pre.owner()
            || !Self::is_zeroed(post.data()))
        {
            return Err(InstructionError::ModifiedProgramId);
        }

        // An account not assigned to the program cannot have its balance decrease.
        if program_id != pre.owner() // line coverage used to get branch coverage
         && pre.lamports() > post.lamports()
        {
            return Err(InstructionError::ExternalAccountLamportSpend);
        }

        // The balance of read-only and executable accounts may not change
        let lamports_changed = pre.lamports() != post.lamports();
        if lamports_changed {
            if !is_writable {
                return Err(InstructionError::ReadonlyLamportChange);
            }
            if pre.executable() {
                return Err(InstructionError::ExecutableLamportChange);
            }
        }

        // Account data size cannot exceed a maxumum length
        if post.data().len() > MAX_PERMITTED_DATA_LENGTH as usize {
            return Err(InstructionError::InvalidRealloc);
        }

        // The owner of the account can change the size of the data
        let data_len_changed = pre.data().len() != post.data().len();
        if data_len_changed && program_id != pre.owner() {
            return Err(InstructionError::AccountDataSizeChanged);
        }

        // Only the owner may change account data
        //   and if the account is writable
        //   and if the account is not executable
        if !(program_id == pre.owner()
            && is_writable  // line coverage used to get branch coverage
            && !pre.executable())
            && pre.data() != post.data()
        {
            if pre.executable() {
                return Err(InstructionError::ExecutableDataModified);
            } else if is_writable {
                return Err(InstructionError::ExternalAccountDataModified);
            } else {
                return Err(InstructionError::ReadonlyDataModified);
            }
        }

        // executable is one-way (false->true) and only the account owner may set it.
        let executable_changed = pre.executable() != post.executable();
        if executable_changed {
            if !rent.is_exempt(post.lamports(), post.data().len()) {
                return Err(InstructionError::ExecutableAccountNotRentExempt);
            }
            if !is_writable // line coverage used to get branch coverage
                || pre.executable()
                || program_id != post.owner()
            {
                return Err(InstructionError::ExecutableModified);
            }
        }

        // No one modifies rent_epoch (yet).
        let rent_epoch_changed = pre.rent_epoch() != post.rent_epoch();
        if rent_epoch_changed {
            return Err(InstructionError::RentEpochModified);
        }

        if outermost_call {
            timings.total_account_count = timings.total_account_count.saturating_add(1);
            if owner_changed
                || lamports_changed
                || data_len_changed
                || executable_changed
                || rent_epoch_changed
                || self.changed
            {
                timings.changed_account_count = timings.changed_account_count.saturating_add(1);
            }
        }

        Ok(())
    }

    pub fn update(&mut self, account: AccountSharedData) {
        let rent_epoch = self.account.rent_epoch();
        self.account = account;
        self.account.set_rent_epoch(rent_epoch);

        self.changed = true;
    }

    pub fn key(&self) -> &Pubkey {
        &self.key
    }

    pub fn data(&self) -> &[u8] {
        self.account.data()
    }

    pub fn lamports(&self) -> u64 {
        self.account.lamports()
    }

    pub fn executable(&self) -> bool {
        self.account.executable()
    }

    pub fn is_zeroed(buf: &[u8]) -> bool {
        const ZEROS_LEN: usize = 1024;
        static ZEROS: [u8; ZEROS_LEN] = [0; ZEROS_LEN];
        let mut chunks = buf.chunks_exact(ZEROS_LEN);

        #[allow(clippy::indexing_slicing)]
        {
            chunks.all(|chunk| chunk == &ZEROS[..])
                && chunks.remainder() == &ZEROS[..chunks.remainder().len()]
        }
    }
}
