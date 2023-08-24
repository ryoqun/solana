use solana_sdk::{
    clock::SECONDS_PER_DAY,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    stake::{
        self,
        instruction::{self as stake_instruction, LockupArgs},
        state::{Authorized, Lockup, StakeAuthorize},
    },
};

const DAYS_PER_YEAR: f64 = 365.25;
const SECONDS_PER_YEAR: i64 = (SECONDS_PER_DAY as f64 * DAYS_PER_YEAR) as i64;

pub(crate) fn derive_stake_account_address(base_pubkey: &Pubkey, i: usize) -> Pubkey {
    Pubkey::create_with_seed(base_pubkey, &i.to_string(), &stake::program::id()).unwrap()
}

// Return derived addresses
pub(crate) fn derive_stake_account_addresses(
    base_pubkey: &Pubkey,
    num_accounts: usize,
) -> Vec<Pubkey> {
    (0..num_accounts)
        .map(|i| derive_stake_account_address(base_pubkey, i))
        .collect()
}

pub(crate) fn new_stake_account(
    fee_payer_pubkey: &Pubkey,
    funding_pubkey: &Pubkey,
    base_pubkey: &Pubkey,
    lamports: u64,
    stake_authority_pubkey: &Pubkey,
    withdraw_authority_pubkey: &Pubkey,
    custodian_pubkey: &Pubkey,
    index: usize,
) -> Message {
    let stake_account_address = derive_stake_account_address(base_pubkey, index);
    let authorized = Authorized {
        staker: *stake_authority_pubkey,
        withdrawer: *withdraw_authority_pubkey,
    };
    let lockup = Lockup {
        custodian: *custodian_pubkey,
        ..Lockup::default()
    };
    let instructions = stake_instruction::create_account_with_seed(
        funding_pubkey,
        &stake_account_address,
        base_pubkey,
        &index.to_string(),
        &authorized,
        &lockup,
        lamports,
    );
    Message::new(&instructions, Some(fee_payer_pubkey))
}

fn authorize_stake_accounts_instructions(
    stake_account_address: &Pubkey,
    stake_authority_pubkey: &Pubkey,
    withdraw_authority_pubkey: &Pubkey,
    new_stake_authority_pubkey: &Pubkey,
    new_withdraw_authority_pubkey: &Pubkey,
) -> Vec<Instruction> {
    let instruction0 = stake_instruction::authorize(
        stake_account_address,
        stake_authority_pubkey,
        new_stake_authority_pubkey,
        StakeAuthorize::Staker,
        None,
    );
    let instruction1 = stake_instruction::authorize(
        stake_account_address,
        withdraw_authority_pubkey,
        new_withdraw_authority_pubkey,
        StakeAuthorize::Withdrawer,
        None,
    );
    vec![instruction0, instruction1]
}

fn rebase_stake_account(
    stake_account_address: &Pubkey,
    new_base_pubkey: &Pubkey,
    i: usize,
    fee_payer_pubkey: &Pubkey,
    stake_authority_pubkey: &Pubkey,
    lamports: u64,
) -> Option<Message> {
    if lamports == 0 {
        return None;
    }
    let new_stake_account_address = derive_stake_account_address(new_base_pubkey, i);
    let instructions = stake_instruction::split_with_seed(
        stake_account_address,
        stake_authority_pubkey,
        lamports,
        &new_stake_account_address,
        new_base_pubkey,
        &i.to_string(),
    );
    let message = Message::new(&instructions, Some(fee_payer_pubkey));
    Some(message)
}

fn move_stake_account(
    stake_account_address: &Pubkey,
    new_base_pubkey: &Pubkey,
    i: usize,
    fee_payer_pubkey: &Pubkey,
    stake_authority_pubkey: &Pubkey,
    withdraw_authority_pubkey: &Pubkey,
    new_stake_authority_pubkey: &Pubkey,
    new_withdraw_authority_pubkey: &Pubkey,
    lamports: u64,
) -> Option<Message> {
    if lamports == 0 {
        return None;
    }
    let new_stake_account_address = derive_stake_account_address(new_base_pubkey, i);
    let mut instructions = stake_instruction::split_with_seed(
        stake_account_address,
        stake_authority_pubkey,
        lamports,
        &new_stake_account_address,
        new_base_pubkey,
        &i.to_string(),
    );

    let authorize_instructions = authorize_stake_accounts_instructions(
        &new_stake_account_address,
        stake_authority_pubkey,
        withdraw_authority_pubkey,
        new_stake_authority_pubkey,
        new_withdraw_authority_pubkey,
    );

    instructions.extend(authorize_instructions.into_iter());
    let message = Message::new(&instructions, Some(fee_payer_pubkey));
    Some(message)
}

pub(crate) fn authorize_stake_accounts(
    fee_payer_pubkey: &Pubkey,
    base_pubkey: &Pubkey,
    stake_authority_pubkey: &Pubkey,
    withdraw_authority_pubkey: &Pubkey,
    new_stake_authority_pubkey: &Pubkey,
    new_withdraw_authority_pubkey: &Pubkey,
    num_accounts: usize,
) -> Vec<Message> {
    let stake_account_addresses = derive_stake_account_addresses(base_pubkey, num_accounts);
    stake_account_addresses
        .iter()
        .map(|stake_account_address| {
            let instructions = authorize_stake_accounts_instructions(
                stake_account_address,
                stake_authority_pubkey,
                withdraw_authority_pubkey,
                new_stake_authority_pubkey,
                new_withdraw_authority_pubkey,
            );
            Message::new(&instructions, Some(fee_payer_pubkey))
        })
        .collect::<Vec<_>>()
}

fn extend_lockup(lockup: &LockupArgs, years: f64) -> LockupArgs {
    let offset = (SECONDS_PER_YEAR as f64 * years) as i64;
    let unix_timestamp = lockup.unix_timestamp.map(|x| x + offset);
    let epoch = lockup.epoch.map(|_| todo!());
    LockupArgs {
        unix_timestamp,
        epoch,
        custodian: lockup.custodian,
    }
}

fn apply_lockup_changes(lockup: &LockupArgs, existing_lockup: &Lockup) -> LockupArgs {
    let custodian = match lockup.custodian {
        Some(x) if x == existing_lockup.custodian => None,
        x => x,
    };
    let epoch = match lockup.epoch {
        Some(x) if x == existing_lockup.epoch => None,
        x => x,
    };
    let unix_timestamp = match lockup.unix_timestamp {
        Some(x) if x == existing_lockup.unix_timestamp => None,
        x => x,
    };
    LockupArgs {
        unix_timestamp,
        epoch,
        custodian,
    }
}

pub(crate) fn lockup_stake_accounts(
    fee_payer_pubkey: &Pubkey,
    custodian_pubkey: &Pubkey,
    lockup: &LockupArgs,
    existing_lockups: &[(Pubkey, Lockup)],
    unlock_years: Option<f64>,
) -> Vec<Message> {
    let default_lockup = LockupArgs::default();
    existing_lockups
        .iter()
        .enumerate()
        .filter_map(|(index, (address, existing_lockup))| {
            let lockup = if let Some(unlock_years) = unlock_years {
                let unlocks = existing_lockups.len() - 1;
                let years = (unlock_years / unlocks as f64) * index as f64;
                extend_lockup(lockup, years)
            } else {
                *lockup
            };
            let lockup = apply_lockup_changes(&lockup, existing_lockup);
            if lockup == default_lockup {
                return None;
            }
            let instruction = stake_instruction::set_lockup(address, &lockup, custodian_pubkey);
            let message = Message::new(&[instruction], Some(fee_payer_pubkey));
            Some(message)
        })
        .collect()
}

pub(crate) fn rebase_stake_accounts(
    fee_payer_pubkey: &Pubkey,
    new_base_pubkey: &Pubkey,
    stake_authority_pubkey: &Pubkey,
    balances: &[(Pubkey, u64)],
) -> Vec<Message> {
    balances
        .iter()
        .enumerate()
        .filter_map(|(i, (stake_account_address, lamports))| {
            rebase_stake_account(
                stake_account_address,
                new_base_pubkey,
                i,
                fee_payer_pubkey,
                stake_authority_pubkey,
                *lamports,
            )
        })
        .collect()
}

pub(crate) fn move_stake_accounts(
    fee_payer_pubkey: &Pubkey,
    new_base_pubkey: &Pubkey,
    stake_authority_pubkey: &Pubkey,
    withdraw_authority_pubkey: &Pubkey,
    new_stake_authority_pubkey: &Pubkey,
    new_withdraw_authority_pubkey: &Pubkey,
    balances: &[(Pubkey, u64)],
) -> Vec<Message> {
    balances
        .iter()
        .enumerate()
        .filter_map(|(i, (stake_account_address, lamports))| {
            move_stake_account(
                stake_account_address,
                new_base_pubkey,
                i,
                fee_payer_pubkey,
                stake_authority_pubkey,
                withdraw_authority_pubkey,
                new_stake_authority_pubkey,
                new_withdraw_authority_pubkey,
                *lamports,
            )
        })
        .collect()
}
