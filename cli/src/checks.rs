use {
    crate::cli::CliError,
    solana_rpc_client::rpc_client::RpcClient,
    solana_rpc_client_api::client_error::{Error as ClientError, Result as ClientResult},
    solana_sdk::{
        commitment_config::CommitmentConfig, message::Message, native_token::lamports_to_sol,
        pubkey::Pubkey,
    },
};

pub fn check_account_for_fee(
    rpc_client: &RpcClient,
    account_pubkey: &Pubkey,
    message: &Message,
) -> Result<(), CliError> {
    check_account_for_multiple_fees(rpc_client, account_pubkey, &[message])
}

pub fn check_account_for_fee_with_commitment(
    rpc_client: &RpcClient,
    account_pubkey: &Pubkey,
    message: &Message,
    commitment: CommitmentConfig,
) -> Result<(), CliError> {
    check_account_for_multiple_fees_with_commitment(
        rpc_client,
        account_pubkey,
        &[message],
        commitment,
    )
}

pub fn check_account_for_multiple_fees(
    rpc_client: &RpcClient,
    account_pubkey: &Pubkey,
    messages: &[&Message],
) -> Result<(), CliError> {
    check_account_for_multiple_fees_with_commitment(
        rpc_client,
        account_pubkey,
        messages,
        CommitmentConfig::default(),
    )
}

pub fn check_account_for_multiple_fees_with_commitment(
    rpc_client: &RpcClient,
    account_pubkey: &Pubkey,
    messages: &[&Message],
    commitment: CommitmentConfig,
) -> Result<(), CliError> {
    check_account_for_spend_multiple_fees_with_commitment(
        rpc_client,
        account_pubkey,
        0,
        messages,
        commitment,
    )
}

pub fn check_account_for_spend_multiple_fees_with_commitment(
    rpc_client: &RpcClient,
    account_pubkey: &Pubkey,
    balance: u64,
    messages: &[&Message],
    commitment: CommitmentConfig,
) -> Result<(), CliError> {
    let fee = get_fee_for_messages(rpc_client, messages)?;
    check_account_for_spend_and_fee_with_commitment(
        rpc_client,
        account_pubkey,
        balance,
        fee,
        commitment,
    )
}

pub fn check_account_for_spend_and_fee_with_commitment(
    rpc_client: &RpcClient,
    account_pubkey: &Pubkey,
    balance: u64,
    fee: u64,
    commitment: CommitmentConfig,
) -> Result<(), CliError> {
    if !check_account_for_balance_with_commitment(
        rpc_client,
        account_pubkey,
        balance + fee,
        commitment,
    )
    .map_err(Into::<ClientError>::into)?
    {
        if balance > 0 {
            return Err(CliError::InsufficientFundsForSpendAndFee(
                lamports_to_sol(balance),
                lamports_to_sol(fee),
                *account_pubkey,
            ));
        } else {
            return Err(CliError::InsufficientFundsForFee(
                lamports_to_sol(fee),
                *account_pubkey,
            ));
        }
    }
    Ok(())
}

pub fn get_fee_for_messages(
    rpc_client: &RpcClient,
    messages: &[&Message],
) -> Result<u64, CliError> {
    Ok(messages
        .iter()
        .map(|message| rpc_client.get_fee_for_message(*message))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .sum())
}

pub fn check_account_for_balance(
    rpc_client: &RpcClient,
    account_pubkey: &Pubkey,
    balance: u64,
) -> ClientResult<bool> {
    check_account_for_balance_with_commitment(
        rpc_client,
        account_pubkey,
        balance,
        CommitmentConfig::default(),
    )
}

pub fn check_account_for_balance_with_commitment(
    rpc_client: &RpcClient,
    account_pubkey: &Pubkey,
    balance: u64,
    commitment: CommitmentConfig,
) -> ClientResult<bool> {
    let lamports = rpc_client
        .get_balance_with_commitment(account_pubkey, commitment)?
        .value;
    if lamports != 0 && lamports >= balance {
        return Ok(true);
    }
    Ok(false)
}

pub fn check_unique_pubkeys(
    pubkey0: (&Pubkey, String),
    pubkey1: (&Pubkey, String),
) -> Result<(), CliError> {
    if pubkey0.0 == pubkey1.0 {
        Err(CliError::BadParameter(format!(
            "Identical pubkeys found: `{}` and `{}` must be unique",
            pubkey0.1, pubkey1.1
        )))
    } else {
        Ok(())
    }
}
