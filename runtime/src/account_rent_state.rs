use {
    log::*,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        pubkey::Pubkey,
        rent::Rent,
        transaction::{Result, TransactionError},
    },
};

#[derive(Debug, PartialEq)]
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

    pub(crate) fn transition_allowed_from(
        &self,
        pre_rent_state: &RentState,
        do_support_realloc: bool,
    ) -> bool {
        if let Self::RentPaying(post_data_size) = self {
            if let Self::RentPaying(pre_data_size) = pre_rent_state {
                if do_support_realloc {
                    post_data_size == pre_data_size // Cannot be RentPaying if resized
                } else {
                    true // RentPaying can continue to be RentPaying
                }
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
    address: &Pubkey,
    account: &AccountSharedData,
    do_support_realloc: bool,
) -> Result<()> {
    if let Some((pre_rent_state, post_rent_state)) = pre_rent_state.zip(post_rent_state) {
        submit_rent_state_metrics(pre_rent_state, post_rent_state);
        if !solana_sdk::incinerator::check_id(address)
            && !post_rent_state.transition_allowed_from(pre_rent_state, do_support_realloc)
        {
            debug!("Account {:?} not rent exempt, state {:?}", address, account);
            return Err(TransactionError::InvalidRentPayingAccount);
        }
    }
    Ok(())
}

