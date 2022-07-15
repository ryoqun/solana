use {
    log::*,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        pubkey::Pubkey,
        rent::Rent,
        transaction::{Result, TransactionError},
        transaction_context::TransactionContext,
    },
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RentState {
    /// account.lamports == 0
    Uninitialized,
    /// 0 < account.lamports < rent-exempt-minimum
    /// Parameter is the size of the account data
    RentPaying(usize),
    /// account.lamports >= rent-exempt-minimum
    RentExempt,
}

impl RentState {
    pub(crate) fn from_account(account: &AccountSharedData, rent: &Rent) -> Self {
        if account.lamports() == 0 {
            Self::Uninitialized
        } else if !rent.is_exempt(account.lamports(), account.data().len()) {
            Self::RentPaying(account.data().len())
        } else {
            Self::RentExempt
        }
    }

    pub(crate) fn transition_allowed_from(&self, pre_rent_state: &RentState) -> bool {
        if let Self::RentPaying(post_data_size) = self {
            if let Self::RentPaying(pre_data_size) = pre_rent_state {
                post_data_size == pre_data_size // Cannot be RentPaying if resized
            } else {
                false // Only RentPaying can continue to be RentPaying
            }
        } else {
            true // Post not-RentPaying always ok
        }
    }
}

pub(crate) fn submit_rent_state_metrics(pre_rent_state: &RentState, post_rent_state: &RentState) {
    match (pre_rent_state, post_rent_state) {
        (&RentState::Uninitialized, &RentState::RentPaying(_)) => {
            inc_new_counter_info!("rent_paying_err-new_account", 1);
        }
        (&RentState::RentPaying(_), &RentState::RentPaying(_)) => {
            inc_new_counter_info!("rent_paying_ok-legacy", 1);
        }
        (_, &RentState::RentPaying(_)) => {
            inc_new_counter_info!("rent_paying_err-other", 1);
        }
        _ => {}
    }
}

pub(crate) fn check_rent_state(
    pre_rent_state: Option<&RentState>,
    post_rent_state: Option<&RentState>,
    transaction_context: &TransactionContext,
    index: usize,
    include_account_index_in_err: bool,
) -> Result<()> {
    if let Some((pre_rent_state, post_rent_state)) = pre_rent_state.zip(post_rent_state) {
        let expect_msg = "account must exist at TransactionContext index if rent-states are Some";
        check_rent_state_with_account(
            pre_rent_state,
            post_rent_state,
            transaction_context
                .get_key_of_account_at_index(index)
                .expect(expect_msg),
            &transaction_context
                .get_account_at_index(index)
                .expect(expect_msg)
                .borrow(),
            include_account_index_in_err.then(|| index),
        )?;
    }
    Ok(())
}

pub(crate) fn check_rent_state_with_account(
    pre_rent_state: &RentState,
    post_rent_state: &RentState,
    address: &Pubkey,
    account_state: &AccountSharedData,
    account_index: Option<usize>,
) -> Result<()> {
    submit_rent_state_metrics(pre_rent_state, post_rent_state);
    if !solana_sdk::incinerator::check_id(address)
        && !post_rent_state.transition_allowed_from(pre_rent_state)
    {
        debug!(
            "Account {} not rent exempt, state {:?}",
            address, account_state,
        );
        if let Some(account_index) = account_index {
            let account_index = account_index as u8;
            Err(TransactionError::InsufficientFundsForRent { account_index })
        } else {
            Err(TransactionError::InvalidRentPayingAccount)
        }
    } else {
        Ok(())
    }
}
