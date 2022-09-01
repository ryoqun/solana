use {
    solana_program_runtime::{ic_msg, invoke_context::InvokeContext},
    solana_sdk::{
        account::{ReadableAccount, WritableAccount},
        account_utils::State as AccountUtilsState,
        feature_set::{self, nonce_must_be_writable},
        instruction::{checked_add, InstructionError},
        keyed_account::KeyedAccount,
        nonce::{
            self,
            state::{DurableNonce, Versions},
            State,
        },
        pubkey::Pubkey,
        system_instruction::{nonce_to_instruction_error, NonceError},
        sysvar::rent::Rent,
    },
    std::collections::HashSet,
};

pub trait NonceKeyedAccount {
    fn advance_nonce_account(
        &self,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError>;
    fn withdraw_nonce_account(
        &self,
        lamports: u64,
        to: &KeyedAccount,
        rent: &Rent,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError>;
    fn initialize_nonce_account(
        &self,
        nonce_authority: &Pubkey,
        rent: &Rent,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError>;
    fn authorize_nonce_account(
        &self,
        nonce_authority: &Pubkey,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError>;
}

fn get_durable_nonce(invoke_context: &InvokeContext) -> (DurableNonce, /*separate_domains:*/ bool) {
    let separate_nonce_from_blockhash = invoke_context
        .feature_set
        .is_active(&feature_set::separate_nonce_from_blockhash::id());
    let durable_nonce =
        DurableNonce::from_blockhash(&invoke_context.blockhash, separate_nonce_from_blockhash);
    (durable_nonce, separate_nonce_from_blockhash)
}

impl<'a> NonceKeyedAccount for KeyedAccount<'a> {
    fn advance_nonce_account(
        &self,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError> {
        let merge_nonce_error_into_system_error = invoke_context
            .feature_set
            .is_active(&feature_set::merge_nonce_error_into_system_error::id());

        if invoke_context
            .feature_set
            .is_active(&nonce_must_be_writable::id())
            && !self.is_writable()
        {
            ic_msg!(
                invoke_context,
                "Advance nonce account: Account {} must be writeable",
                self.unsigned_key()
            );
            return Err(InstructionError::InvalidArgument);
        }

        let versions = AccountUtilsState::<Versions>::state(self)?;
        match versions.state() {
            State::Initialized(data) => {
                if !signers.contains(&data.authority) {
                    ic_msg!(
                        invoke_context,
                        "Advance nonce account: Account {} must be a signer",
                        data.authority
                    );
                    return Err(InstructionError::MissingRequiredSignature);
                }
                let (next_durable_nonce, separate_domains) = get_durable_nonce(invoke_context);
                if data.durable_nonce == next_durable_nonce {
                    ic_msg!(
                        invoke_context,
                        "Advance nonce account: nonce can only advance once per slot"
                    );
                    return Err(nonce_to_instruction_error(
                        NonceError::NotExpired,
                        merge_nonce_error_into_system_error,
                    ));
                }

                let new_data = nonce::state::Data::new(
                    data.authority,
                    next_durable_nonce,
                    invoke_context.lamports_per_signature,
                );
                self.set_state(&Versions::new(
                    State::Initialized(new_data),
                    separate_domains,
                ))
            }
            State::Uninitialized => {
                ic_msg!(
                    invoke_context,
                    "Advance nonce account: Account {} state is invalid",
                    self.unsigned_key()
                );
                Err(nonce_to_instruction_error(
                    NonceError::BadAccountState,
                    merge_nonce_error_into_system_error,
                ))
            }
        }
    }

    fn withdraw_nonce_account(
        &self,
        lamports: u64,
        to: &KeyedAccount,
        rent: &Rent,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError> {
        let merge_nonce_error_into_system_error = invoke_context
            .feature_set
            .is_active(&feature_set::merge_nonce_error_into_system_error::id());

        if invoke_context
            .feature_set
            .is_active(&nonce_must_be_writable::id())
            && !self.is_writable()
        {
            ic_msg!(
                invoke_context,
                "Withdraw nonce account: Account {} must be writeable",
                self.unsigned_key()
            );
            return Err(InstructionError::InvalidArgument);
        }

        let signer = match AccountUtilsState::<Versions>::state(self)?.state() {
            State::Uninitialized => {
                if lamports > self.lamports()? {
                    ic_msg!(
                        invoke_context,
                        "Withdraw nonce account: insufficient lamports {}, need {}",
                        self.lamports()?,
                        lamports,
                    );
                    return Err(InstructionError::InsufficientFunds);
                }
                *self.unsigned_key()
            }
            State::Initialized(ref data) => {
                if lamports == self.lamports()? {
                    let (durable_nonce, separate_domains) = get_durable_nonce(invoke_context);
                    if data.durable_nonce == durable_nonce {
                        ic_msg!(
                            invoke_context,
                            "Withdraw nonce account: nonce can only advance once per slot"
                        );
                        return Err(nonce_to_instruction_error(
                            NonceError::NotExpired,
                            merge_nonce_error_into_system_error,
                        ));
                    }
                    self.set_state(&Versions::new(State::Uninitialized, separate_domains))?;
                } else {
                    let min_balance = rent.minimum_balance(self.data_len()?);
                    let amount = checked_add(lamports, min_balance)?;
                    if amount > self.lamports()? {
                        ic_msg!(
                            invoke_context,
                            "Withdraw nonce account: insufficient lamports {}, need {}",
                            self.lamports()?,
                            amount,
                        );
                        return Err(InstructionError::InsufficientFunds);
                    }
                }
                data.authority
            }
        };

        if !signers.contains(&signer) {
            ic_msg!(
                invoke_context,
                "Withdraw nonce account: Account {} must sign",
                signer
            );
            return Err(InstructionError::MissingRequiredSignature);
        }

        let nonce_balance = self.try_account_ref_mut()?.lamports();
        self.try_account_ref_mut()?.set_lamports(
            nonce_balance
                .checked_sub(lamports)
                .ok_or(InstructionError::ArithmeticOverflow)?,
        );
        let to_balance = to.try_account_ref_mut()?.lamports();
        to.try_account_ref_mut()?.set_lamports(
            to_balance
                .checked_add(lamports)
                .ok_or(InstructionError::ArithmeticOverflow)?,
        );

        Ok(())
    }

    fn initialize_nonce_account(
        &self,
        nonce_authority: &Pubkey,
        rent: &Rent,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError> {
        let merge_nonce_error_into_system_error = invoke_context
            .feature_set
            .is_active(&feature_set::merge_nonce_error_into_system_error::id());

        if invoke_context
            .feature_set
            .is_active(&nonce_must_be_writable::id())
            && !self.is_writable()
        {
            ic_msg!(
                invoke_context,
                "Initialize nonce account: Account {} must be writeable",
                self.unsigned_key()
            );
            return Err(InstructionError::InvalidArgument);
        }

        match AccountUtilsState::<Versions>::state(self)?.state() {
            State::Uninitialized => {
                let min_balance = rent.minimum_balance(self.data_len()?);
                if self.lamports()? < min_balance {
                    ic_msg!(
                        invoke_context,
                        "Initialize nonce account: insufficient lamports {}, need {}",
                        self.lamports()?,
                        min_balance
                    );
                    return Err(InstructionError::InsufficientFunds);
                }
                let (durable_nonce, separate_domains) = get_durable_nonce(invoke_context);
                let data = nonce::state::Data::new(
                    *nonce_authority,
                    durable_nonce,
                    invoke_context.lamports_per_signature,
                );
                self.set_state(&Versions::new(State::Initialized(data), separate_domains))
            }
            State::Initialized(_) => {
                ic_msg!(
                    invoke_context,
                    "Initialize nonce account: Account {} state is invalid",
                    self.unsigned_key()
                );
                Err(nonce_to_instruction_error(
                    NonceError::BadAccountState,
                    merge_nonce_error_into_system_error,
                ))
            }
        }
    }

    fn authorize_nonce_account(
        &self,
        nonce_authority: &Pubkey,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError> {
        let merge_nonce_error_into_system_error = invoke_context
            .feature_set
            .is_active(&feature_set::merge_nonce_error_into_system_error::id());

        if invoke_context
            .feature_set
            .is_active(&nonce_must_be_writable::id())
            && !self.is_writable()
        {
            ic_msg!(
                invoke_context,
                "Authorize nonce account: Account {} must be writeable",
                self.unsigned_key()
            );
            return Err(InstructionError::InvalidArgument);
        }

        let versions = AccountUtilsState::<Versions>::state(self)?;
        let separate_domains = versions.separate_domains();
        match versions.state() {
            State::Initialized(data) => {
                if !signers.contains(&data.authority) {
                    ic_msg!(
                        invoke_context,
                        "Authorize nonce account: Account {} must sign",
                        data.authority
                    );
                    return Err(InstructionError::MissingRequiredSignature);
                }
                let new_data = nonce::state::Data::new(
                    *nonce_authority,
                    data.durable_nonce,
                    data.get_lamports_per_signature(),
                );
                self.set_state(&Versions::new(
                    State::Initialized(new_data),
                    separate_domains,
                ))
            }
            State::Uninitialized => {
                ic_msg!(
                    invoke_context,
                    "Authorize nonce account: Account {} state is invalid",
                    self.unsigned_key()
                );
                Err(nonce_to_instruction_error(
                    NonceError::BadAccountState,
                    merge_nonce_error_into_system_error,
                ))
            }
        }
    }
}
