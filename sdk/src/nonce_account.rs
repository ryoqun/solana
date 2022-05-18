use {
    crate::{
        account::{AccountSharedData, ReadableAccount},
        account_utils::StateMut,
        hash::Hash,
        nonce::{state::Versions, State},
    },
    std::cell::RefCell,
};

pub fn create_account(lamports: u64) -> RefCell<AccountSharedData> {
    RefCell::new(
        AccountSharedData::new_data_with_space(
            lamports,
            &Versions::new_current(State::Uninitialized),
            State::size(),
            &crate::system_program::id(),
        )
        .expect("nonce_account"),
    )
}

pub fn verify_nonce_account(acc: &AccountSharedData, hash: &Hash) -> bool {
    if acc.owner() != &crate::system_program::id() {
        return false;
    }
    match StateMut::<Versions>::state(acc).map(|v| v.convert_to_current()) {
        Ok(State::Initialized(ref data)) => *hash == data.blockhash,
        _ => false,
    }
}

pub fn lamports_per_signature_of(account: &AccountSharedData) -> Option<u64> {
    let state = StateMut::<Versions>::state(account)
        .ok()?
        .convert_to_current();
    match state {
        State::Initialized(data) => Some(data.fee_calculator.lamports_per_signature),
        _ => None,
    }
}

