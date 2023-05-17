use {
    crate::{
        args::{
            BalancesArgs, DistributeTokensArgs, SenderStakeArgs, StakeArgs, TransactionLogArgs,
        },
        db::{self, TransactionInfo},
        spl_token::*,
        token_display::Token,
    },
    chrono::prelude::*,
    console::style,
    csv::{ReaderBuilder, Trim},
    indexmap::IndexMap,
    indicatif::{ProgressBar, ProgressStyle},
    pickledb::PickleDb,
    serde::{Deserialize, Serialize},
    solana_account_decoder::parse_token::{
        pubkey_from_spl_token, real_number_string, spl_token_pubkey,
    },
    solana_rpc_client::rpc_client::RpcClient,
    solana_rpc_client_api::{
        client_error::{Error as ClientError, Result as ClientResult},
        config::RpcSendTransactionConfig,
        request::{MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS, MAX_MULTIPLE_ACCOUNTS},
    },
    solana_sdk::{
        clock::Slot,
        commitment_config::CommitmentConfig,
        hash::Hash,
        instruction::Instruction,
        message::Message,
        native_token::{lamports_to_sol, sol_to_lamports},
        signature::{unique_signers, Signature, Signer},
        stake::{
            instruction::{self as stake_instruction, LockupArgs},
            state::{Authorized, Lockup, StakeAuthorize},
        },
        system_instruction,
        transaction::Transaction,
    },
    solana_transaction_status::TransactionStatus,
    spl_associated_token_account::get_associated_token_address,
    spl_token::solana_program::program_error::ProgramError,
    std::{
        cmp::{self},
        io,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::sleep,
        time::Duration,
    },
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub recipient: String,
    pub amount: u64,
    pub lockup_date: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FundingSource {
    FeePayer,
    SplTokenAccount,
    StakeAccount,
    SystemAccount,
}

pub struct FundingSources(Vec<FundingSource>);

impl std::fmt::Debug for FundingSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, source) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, "/")?;
            }
            write!(f, "{source:?}")?;
        }
        Ok(())
    }
}

impl PartialEq for FundingSources {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<Vec<FundingSource>> for FundingSources {
    fn from(sources_vec: Vec<FundingSource>) -> Self {
        Self(sources_vec)
    }
}

type StakeExtras = Vec<(Keypair, Option<DateTime<Utc>>)>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    IoError(#[from] io::Error),
    #[error("CSV error")]
    CsvError(#[from] csv::Error),
    #[error("PickleDb error")]
    PickleDbError(#[from] pickledb::error::Error),
    #[error("Transport error")]
    ClientError(#[from] ClientError),
    #[error("Missing lockup authority")]
    MissingLockupAuthority,
    #[error("Missing messages")]
    MissingMessages,
    #[error("Error estimating message fees")]
    FeeEstimationError,
    #[error("insufficient funds in {0:?}, requires {1}")]
    InsufficientFunds(FundingSources, String),
    #[error("Program error")]
    ProgramError(#[from] ProgramError),
    #[error("Exit signal received")]
    ExitSignal,
}

fn merge_allocations(allocations: &[Allocation]) -> Vec<Allocation> {
    let mut allocation_map = IndexMap::new();
    for allocation in allocations {
        allocation_map
            .entry(&allocation.recipient)
            .or_insert(Allocation {
                recipient: allocation.recipient.clone(),
                amount: 0,
                lockup_date: "".to_string(),
            })
            .amount += allocation.amount;
    }
    allocation_map.values().cloned().collect()
}

/// Return true if the recipient and lockups are the same
fn has_same_recipient(allocation: &Allocation, transaction_info: &TransactionInfo) -> bool {
    allocation.recipient == transaction_info.recipient.to_string()
        && allocation.lockup_date.parse().ok() == transaction_info.lockup_date
}

fn apply_previous_transactions(
    allocations: &mut Vec<Allocation>,
    transaction_infos: &[TransactionInfo],
) {
    for transaction_info in transaction_infos {
        let mut amount = transaction_info.amount;
        for allocation in allocations.iter_mut() {
            if !has_same_recipient(allocation, transaction_info) {
                continue;
            }
            if allocation.amount >= amount {
                allocation.amount -= amount;
                break;
            } else {
                amount -= allocation.amount;
                allocation.amount = 0;
            }
        }
    }
    allocations.retain(|x| x.amount > 0);
}

fn transfer<S: Signer>(
    client: &RpcClient,
    lamports: u64,
    sender_keypair: &S,
    to_pubkey: &Pubkey,
) -> ClientResult<Transaction> {
    let create_instruction =
        system_instruction::transfer(&sender_keypair.pubkey(), to_pubkey, lamports);
    let message = Message::new(&[create_instruction], Some(&sender_keypair.pubkey()));
    let recent_blockhash = client.get_latest_blockhash()?;
    Ok(Transaction::new(
        &[sender_keypair],
        message,
        recent_blockhash,
    ))
}

fn distribution_instructions(
    allocation: &Allocation,
    new_stake_account_address: &Pubkey,
    args: &DistributeTokensArgs,
    lockup_date: Option<DateTime<Utc>>,
    do_create_associated_token_account: bool,
) -> Vec<Instruction> {
    if args.spl_token_args.is_some() {
        return build_spl_token_instructions(allocation, args, do_create_associated_token_account);
    }

    match &args.stake_args {
        // No stake args; a simple token transfer.
        None => {
            let from = args.sender_keypair.pubkey();
            let to = allocation.recipient.parse().unwrap();
            let lamports = allocation.amount;
            let instruction = system_instruction::transfer(&from, &to, lamports);
            vec![instruction]
        }

        // Stake args provided, so create a recipient stake account.
        Some(stake_args) => {
            let unlocked_sol = stake_args.unlocked_sol;
            let sender_pubkey = args.sender_keypair.pubkey();
            let recipient = allocation.recipient.parse().unwrap();

            let mut instructions = match &stake_args.sender_stake_args {
                // No source stake account, so create a recipient stake account directly.
                None => {
                    // Make the recipient both the new stake and withdraw authority
                    let authorized = Authorized {
                        staker: recipient,
                        withdrawer: recipient,
                    };
                    let mut lockup = Lockup::default();
                    if let Some(lockup_date) = lockup_date {
                        lockup.unix_timestamp = lockup_date.timestamp();
                    }
                    if let Some(lockup_authority) = stake_args.lockup_authority {
                        lockup.custodian = lockup_authority;
                    }
                    stake_instruction::create_account(
                        &sender_pubkey,
                        new_stake_account_address,
                        &authorized,
                        &lockup,
                        allocation.amount - unlocked_sol,
                    )
                }

                // A sender stake account was provided, so create a recipient stake account by
                // splitting the sender account.
                Some(sender_stake_args) => {
                    let stake_authority = sender_stake_args.stake_authority.pubkey();
                    let withdraw_authority = sender_stake_args.withdraw_authority.pubkey();
                    let mut instructions = stake_instruction::split(
                        &sender_stake_args.stake_account_address,
                        &stake_authority,
                        allocation.amount - unlocked_sol,
                        new_stake_account_address,
                    );

                    // Make the recipient the new stake authority
                    instructions.push(stake_instruction::authorize(
                        new_stake_account_address,
                        &stake_authority,
                        &recipient,
                        StakeAuthorize::Staker,
                        None,
                    ));

                    // Make the recipient the new withdraw authority
                    instructions.push(stake_instruction::authorize(
                        new_stake_account_address,
                        &withdraw_authority,
                        &recipient,
                        StakeAuthorize::Withdrawer,
                        None,
                    ));

                    // Add lockup
                    if let Some(lockup_date) = lockup_date {
                        let lockup = LockupArgs {
                            unix_timestamp: Some(lockup_date.timestamp()),
                            epoch: None,
                            custodian: None,
                        };
                        instructions.push(stake_instruction::set_lockup(
                            new_stake_account_address,
                            &lockup,
                            &stake_args.lockup_authority.unwrap(),
                        ));
                    }

                    instructions
                }
            };

            // Transfer some unlocked tokens to recipient, which they can use for transaction fees.
            instructions.push(system_instruction::transfer(
                &sender_pubkey,
                &recipient,
                unlocked_sol,
            ));

            instructions
        }
    }
}

fn build_messages(
    client: &RpcClient,
    db: &mut PickleDb,
    allocations: &[Allocation],
    args: &DistributeTokensArgs,
    exit: Arc<AtomicBool>,
    messages: &mut Vec<Message>,
    stake_extras: &mut StakeExtras,
    created_accounts: &mut u64,
) -> Result<(), Error> {
    let mut existing_associated_token_accounts = vec![];
    if let Some(spl_token_args) = &args.spl_token_args {
        let allocation_chunks = allocations.chunks(MAX_MULTIPLE_ACCOUNTS);
        for allocation_chunk in allocation_chunks {
            let associated_token_addresses = allocation_chunk
                .iter()
                .map(|x| {
                    let wallet_address = x.recipient.parse().unwrap();
                    let associated_token_address = get_associated_token_address(
                        &wallet_address,
                        &spl_token_pubkey(&spl_token_args.mint),
                    );
                    pubkey_from_spl_token(&associated_token_address)
                })
                .collect::<Vec<_>>();
            let mut maybe_accounts = client.get_multiple_accounts(&associated_token_addresses)?;
            existing_associated_token_accounts.append(&mut maybe_accounts);
        }
    }

    for (i, allocation) in allocations.iter().enumerate() {
        if exit.load(Ordering::SeqCst) {
            db.dump()?;
            return Err(Error::ExitSignal);
        }
        let new_stake_account_keypair = Keypair::new();
        let lockup_date = if allocation.lockup_date.is_empty() {
            None
        } else {
            Some(allocation.lockup_date.parse::<DateTime<Utc>>().unwrap())
        };

        let do_create_associated_token_account = if let Some(spl_token_args) = &args.spl_token_args
        {
            let do_create_associated_token_account =
                existing_associated_token_accounts[i].is_none();
            if do_create_associated_token_account {
                *created_accounts += 1;
            }
            println!(
                "{:<44}  {:>24}",
                allocation.recipient,
                real_number_string(allocation.amount, spl_token_args.decimals)
            );
            do_create_associated_token_account
        } else {
            println!(
                "{:<44}  {:>24.9}",
                allocation.recipient,
                lamports_to_sol(allocation.amount)
            );
            false
        };
        let instructions = distribution_instructions(
            allocation,
            &new_stake_account_keypair.pubkey(),
            args,
            lockup_date,
            do_create_associated_token_account,
        );
        let fee_payer_pubkey = args.fee_payer.pubkey();
        let message = Message::new_with_blockhash(
            &instructions,
            Some(&fee_payer_pubkey),
            &Hash::default(), // populated by a real blockhash for balance check and submission
        );
        messages.push(message);
        stake_extras.push((new_stake_account_keypair, lockup_date));
    }
    Ok(())
}

fn send_messages(
    client: &RpcClient,
    db: &mut PickleDb,
    allocations: &[Allocation],
    args: &DistributeTokensArgs,
    exit: Arc<AtomicBool>,
    messages: Vec<Message>,
    stake_extras: StakeExtras,
) -> Result<(), Error> {
    for ((allocation, message), (new_stake_account_keypair, lockup_date)) in
        allocations.iter().zip(messages).zip(stake_extras)
    {
        if exit.load(Ordering::SeqCst) {
            db.dump()?;
            return Err(Error::ExitSignal);
        }
        let new_stake_account_address = new_stake_account_keypair.pubkey();

        let mut signers = vec![&*args.fee_payer, &*args.sender_keypair];
        if let Some(stake_args) = &args.stake_args {
            signers.push(&new_stake_account_keypair);
            if let Some(sender_stake_args) = &stake_args.sender_stake_args {
                signers.push(&*sender_stake_args.stake_authority);
                signers.push(&*sender_stake_args.withdraw_authority);
                signers.push(&new_stake_account_keypair);
                if !allocation.lockup_date.is_empty() {
                    if let Some(lockup_authority) = &sender_stake_args.lockup_authority {
                        signers.push(&**lockup_authority);
                    } else {
                        return Err(Error::MissingLockupAuthority);
                    }
                }
            }
        }
        let signers = unique_signers(signers);
        let result: ClientResult<(Transaction, u64)> = {
            if args.dry_run {
                Ok((Transaction::new_unsigned(message), std::u64::MAX))
            } else {
                let (blockhash, last_valid_block_height) =
                    client.get_latest_blockhash_with_commitment(CommitmentConfig::default())?;
                let transaction = Transaction::new(&signers, message, blockhash);
                let config = RpcSendTransactionConfig {
                    skip_preflight: true,
                    ..RpcSendTransactionConfig::default()
                };
                client.send_transaction_with_config(&transaction, config)?;
                Ok((transaction, last_valid_block_height))
            }
        };
        match result {
            Ok((transaction, last_valid_block_height)) => {
                let new_stake_account_address_option =
                    args.stake_args.as_ref().map(|_| &new_stake_account_address);
                db::set_transaction_info(
                    db,
                    &allocation.recipient.parse().unwrap(),
                    allocation.amount,
                    &transaction,
                    new_stake_account_address_option,
                    false,
                    last_valid_block_height,
                    lockup_date,
                )?;
            }
            Err(e) => {
                eprintln!("Error sending tokens to {}: {}", allocation.recipient, e);
            }
        };
    }
    Ok(())
}

fn distribute_allocations(
    client: &RpcClient,
    db: &mut PickleDb,
    allocations: &[Allocation],
    args: &DistributeTokensArgs,
    exit: Arc<AtomicBool>,
) -> Result<(), Error> {
    let mut messages: Vec<Message> = vec![];
    let mut stake_extras: StakeExtras = vec![];
    let mut created_accounts = 0;

    build_messages(
        client,
        db,
        allocations,
        args,
        exit.clone(),
        &mut messages,
        &mut stake_extras,
        &mut created_accounts,
    )?;

    if args.spl_token_args.is_some() {
        check_spl_token_balances(&messages, allocations, client, args, created_accounts)?;
    } else {
        check_payer_balances(&messages, allocations, client, args)?;
    }

    send_messages(client, db, allocations, args, exit, messages, stake_extras)?;

    db.dump()?;
    Ok(())
}

#[allow(clippy::needless_collect)]
fn read_allocations(
    input_csv: &str,
    transfer_amount: Option<u64>,
    require_lockup_heading: bool,
    raw_amount: bool,
) -> io::Result<Vec<Allocation>> {
    let mut rdr = ReaderBuilder::new().trim(Trim::All).from_path(input_csv)?;
    let allocations = if let Some(amount) = transfer_amount {
        let recipients: Vec<String> = rdr
            .deserialize()
            .map(|recipient| recipient.unwrap())
            .collect();
        recipients
            .into_iter()
            .map(|recipient| Allocation {
                recipient,
                amount,
                lockup_date: "".to_string(),
            })
            .collect()
    } else if require_lockup_heading {
        let recipients: Vec<(String, f64, String)> = rdr
            .deserialize()
            .map(|recipient| recipient.unwrap())
            .collect();
        recipients
            .into_iter()
            .map(|(recipient, amount, lockup_date)| Allocation {
                recipient,
                amount: sol_to_lamports(amount),
                lockup_date,
            })
            .collect()
    } else if raw_amount {
        let recipients: Vec<(String, u64)> = rdr
            .deserialize()
            .map(|recipient| recipient.unwrap())
            .collect();
        recipients
            .into_iter()
            .map(|(recipient, amount)| Allocation {
                recipient,
                amount,
                lockup_date: "".to_string(),
            })
            .collect()
    } else {
        let recipients: Vec<(String, f64)> = rdr
            .deserialize()
            .map(|recipient| recipient.unwrap())
            .collect();
        recipients
            .into_iter()
            .map(|(recipient, amount)| Allocation {
                recipient,
                amount: sol_to_lamports(amount),
                lockup_date: "".to_string(),
            })
            .collect()
    };
    Ok(allocations)
}

fn new_spinner_progress_bar() -> ProgressBar {
    let progress_bar = ProgressBar::new(42);
    progress_bar.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {wide_msg}")
            .expect("ProgresStyle::template direct input to be correct"),
    );
    progress_bar.enable_steady_tick(Duration::from_millis(100));
    progress_bar
}

pub fn process_allocations(
    client: &RpcClient,
    args: &DistributeTokensArgs,
    exit: Arc<AtomicBool>,
) -> Result<Option<usize>, Error> {
    let require_lockup_heading = args.stake_args.is_some();
    let mut allocations: Vec<Allocation> = read_allocations(
        &args.input_csv,
        args.transfer_amount,
        require_lockup_heading,
        args.spl_token_args.is_some(),
    )?;

    let starting_total_tokens = allocations.iter().map(|x| x.amount).sum();
    let starting_total_tokens = if let Some(spl_token_args) = &args.spl_token_args {
        Token::spl_token(starting_total_tokens, spl_token_args.decimals)
    } else {
        Token::sol(starting_total_tokens)
    };
    println!(
        "{} {}",
        style("Total in input_csv:").bold(),
        starting_total_tokens,
    );

    let mut db = db::open_db(&args.transaction_db, args.dry_run)?;

    // Start by finalizing any transactions from the previous run.
    let confirmations = finalize_transactions(client, &mut db, args.dry_run, exit.clone())?;

    let transaction_infos = db::read_transaction_infos(&db);
    apply_previous_transactions(&mut allocations, &transaction_infos);

    if allocations.is_empty() {
        eprintln!("No work to do");
        return Ok(confirmations);
    }

    let distributed_tokens = transaction_infos.iter().map(|x| x.amount).sum();
    let undistributed_tokens = allocations.iter().map(|x| x.amount).sum();
    let (distributed_tokens, undistributed_tokens) =
        if let Some(spl_token_args) = &args.spl_token_args {
            (
                Token::spl_token(distributed_tokens, spl_token_args.decimals),
                Token::spl_token(undistributed_tokens, spl_token_args.decimals),
            )
        } else {
            (
                Token::sol(distributed_tokens),
                Token::sol(undistributed_tokens),
            )
        };
    println!("{} {}", style("Distributed:").bold(), distributed_tokens,);
    println!(
        "{} {}",
        style("Undistributed:").bold(),
        undistributed_tokens,
    );
    println!(
        "{} {}",
        style("Total:").bold(),
        distributed_tokens + undistributed_tokens,
    );

    println!(
        "{}",
        style(format!("{:<44}  {:>24}", "Recipient", "Expected Balance",)).bold()
    );

    distribute_allocations(client, &mut db, &allocations, args, exit.clone())?;

    let opt_confirmations = finalize_transactions(client, &mut db, args.dry_run, exit)?;

    if !args.dry_run {
        if let Some(output_path) = &args.output_path {
            db::write_transaction_log(&db, &output_path)?;
        }
    }

    Ok(opt_confirmations)
}

fn finalize_transactions(
    client: &RpcClient,
    db: &mut PickleDb,
    dry_run: bool,
    exit: Arc<AtomicBool>,
) -> Result<Option<usize>, Error> {
    if dry_run {
        return Ok(None);
    }

    let mut opt_confirmations = update_finalized_transactions(client, db, exit.clone())?;

    let progress_bar = new_spinner_progress_bar();

    while opt_confirmations.is_some() {
        if let Some(confirmations) = opt_confirmations {
            progress_bar.set_message(format!(
                "[{}/{}] Finalizing transactions",
                confirmations, 32,
            ));
        }

        // Sleep for about 1 slot
        sleep(Duration::from_millis(500));
        let opt_conf = update_finalized_transactions(client, db, exit.clone())?;
        opt_confirmations = opt_conf;
    }

    Ok(opt_confirmations)
}

// Update the finalized bit on any transactions that are now rooted
// Return the lowest number of confirmations on the unfinalized transactions or None if all are finalized.
fn update_finalized_transactions(
    client: &RpcClient,
    db: &mut PickleDb,
    exit: Arc<AtomicBool>,
) -> Result<Option<usize>, Error> {
    let transaction_infos = db::read_transaction_infos(db);
    let unconfirmed_transactions: Vec<_> = transaction_infos
        .iter()
        .filter_map(|info| {
            if info.finalized_date.is_some() {
                None
            } else {
                Some((&info.transaction, info.last_valid_block_height))
            }
        })
        .collect();
    let unconfirmed_signatures: Vec<_> = unconfirmed_transactions
        .iter()
        .map(|(tx, _slot)| tx.signatures[0])
        .filter(|sig| *sig != Signature::default()) // Filter out dry-run signatures
        .collect();
    let mut statuses = vec![];
    for unconfirmed_signatures_chunk in
        unconfirmed_signatures.chunks(MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS - 1)
    {
        statuses.extend(
            client
                .get_signature_statuses(unconfirmed_signatures_chunk)?
                .value
                .into_iter(),
        );
    }

    let mut confirmations = None;
    log_transaction_confirmations(
        client,
        db,
        exit,
        unconfirmed_transactions,
        statuses,
        &mut confirmations,
    )?;
    db.dump()?;
    Ok(confirmations)
}

fn log_transaction_confirmations(
    client: &RpcClient,
    db: &mut PickleDb,
    exit: Arc<AtomicBool>,
    unconfirmed_transactions: Vec<(&Transaction, Slot)>,
    statuses: Vec<Option<TransactionStatus>>,
    confirmations: &mut Option<usize>,
) -> Result<(), Error> {
    let finalized_block_height = client.get_block_height()?;
    for ((transaction, last_valid_block_height), opt_transaction_status) in unconfirmed_transactions
        .into_iter()
        .zip(statuses.into_iter())
    {
        match db::update_finalized_transaction(
            db,
            &transaction.signatures[0],
            opt_transaction_status,
            last_valid_block_height,
            finalized_block_height,
        ) {
            Ok(Some(confs)) => {
                *confirmations = Some(cmp::min(confs, confirmations.unwrap_or(usize::MAX)));
            }
            result => {
                result?;
            }
        }
        if exit.load(Ordering::SeqCst) {
            db.dump()?;
            return Err(Error::ExitSignal);
        }
    }
    Ok(())
}

pub fn get_fee_estimate_for_messages(
    messages: &[Message],
    client: &RpcClient,
) -> Result<u64, Error> {
    let mut message = messages.first().ok_or(Error::MissingMessages)?.clone();
    let latest_blockhash = client.get_latest_blockhash()?;
    message.recent_blockhash = latest_blockhash;
    let fee = client.get_fee_for_message(&message)?;
    let fee_estimate = fee
        .checked_mul(messages.len() as u64)
        .ok_or(Error::FeeEstimationError)?;
    Ok(fee_estimate)
}

fn check_payer_balances(
    messages: &[Message],
    allocations: &[Allocation],
    client: &RpcClient,
    args: &DistributeTokensArgs,
) -> Result<(), Error> {
    let mut undistributed_tokens: u64 = allocations.iter().map(|x| x.amount).sum();
    let fees = get_fee_estimate_for_messages(messages, client)?;

    let (distribution_source, unlocked_sol_source) = if let Some(stake_args) = &args.stake_args {
        let total_unlocked_sol = allocations.len() as u64 * stake_args.unlocked_sol;
        undistributed_tokens -= total_unlocked_sol;
        let from_pubkey = if let Some(sender_stake_args) = &stake_args.sender_stake_args {
            sender_stake_args.stake_account_address
        } else {
            args.sender_keypair.pubkey()
        };
        (
            from_pubkey,
            Some((args.sender_keypair.pubkey(), total_unlocked_sol)),
        )
    } else {
        (args.sender_keypair.pubkey(), None)
    };

    let fee_payer_balance = client.get_balance(&args.fee_payer.pubkey())?;
    if let Some((unlocked_sol_source, total_unlocked_sol)) = unlocked_sol_source {
        let staker_balance = client.get_balance(&distribution_source)?;
        if staker_balance < undistributed_tokens {
            return Err(Error::InsufficientFunds(
                vec![FundingSource::StakeAccount].into(),
                lamports_to_sol(undistributed_tokens).to_string(),
            ));
        }
        if args.fee_payer.pubkey() == unlocked_sol_source {
            if fee_payer_balance < fees + total_unlocked_sol {
                return Err(Error::InsufficientFunds(
                    vec![FundingSource::SystemAccount, FundingSource::FeePayer].into(),
                    lamports_to_sol(fees + total_unlocked_sol).to_string(),
                ));
            }
        } else {
            if fee_payer_balance < fees {
                return Err(Error::InsufficientFunds(
                    vec![FundingSource::FeePayer].into(),
                    lamports_to_sol(fees).to_string(),
                ));
            }
            let unlocked_sol_balance = client.get_balance(&unlocked_sol_source)?;
            if unlocked_sol_balance < total_unlocked_sol {
                return Err(Error::InsufficientFunds(
                    vec![FundingSource::SystemAccount].into(),
                    lamports_to_sol(total_unlocked_sol).to_string(),
                ));
            }
        }
    } else if args.fee_payer.pubkey() == distribution_source {
        if fee_payer_balance < fees + undistributed_tokens {
            return Err(Error::InsufficientFunds(
                vec![FundingSource::SystemAccount, FundingSource::FeePayer].into(),
                lamports_to_sol(fees + undistributed_tokens).to_string(),
            ));
        }
    } else {
        if fee_payer_balance < fees {
            return Err(Error::InsufficientFunds(
                vec![FundingSource::FeePayer].into(),
                lamports_to_sol(fees).to_string(),
            ));
        }
        let sender_balance = client.get_balance(&distribution_source)?;
        if sender_balance < undistributed_tokens {
            return Err(Error::InsufficientFunds(
                vec![FundingSource::SystemAccount].into(),
                lamports_to_sol(undistributed_tokens).to_string(),
            ));
        }
    }
    Ok(())
}

pub fn process_balances(
    client: &RpcClient,
    args: &BalancesArgs,
    exit: Arc<AtomicBool>,
) -> Result<(), Error> {
    let allocations: Vec<Allocation> =
        read_allocations(&args.input_csv, None, false, args.spl_token_args.is_some())?;
    let allocations = merge_allocations(&allocations);

    let token = if let Some(spl_token_args) = &args.spl_token_args {
        spl_token_args.mint.to_string()
    } else {
        "◎".to_string()
    };
    println!("{} {}", style("Token:").bold(), token);

    println!(
        "{}",
        style(format!(
            "{:<44}  {:>24}  {:>24}  {:>24}",
            "Recipient", "Expected Balance", "Actual Balance", "Difference"
        ))
        .bold()
    );

    for allocation in &allocations {
        if exit.load(Ordering::SeqCst) {
            return Err(Error::ExitSignal);
        }

        if let Some(spl_token_args) = &args.spl_token_args {
            print_token_balances(client, allocation, spl_token_args)?;
        } else {
            let address: Pubkey = allocation.recipient.parse().unwrap();
            let expected = lamports_to_sol(allocation.amount);
            let actual = lamports_to_sol(client.get_balance(&address).unwrap());
            println!(
                "{:<44}  {:>24.9}  {:>24.9}  {:>24.9}",
                allocation.recipient,
                expected,
                actual,
                actual - expected,
            );
        }
    }

    Ok(())
}

pub fn process_transaction_log(args: &TransactionLogArgs) -> Result<(), Error> {
    let db = db::open_db(&args.transaction_db, true)?;
    db::write_transaction_log(&db, &args.output_path)?;
    Ok(())
}

use {
    crate::db::check_output_file,
    solana_sdk::{pubkey::Pubkey, signature::Keypair},
    tempfile::{tempdir, NamedTempFile},
};
pub fn test_process_distribute_tokens_with_client(
    client: &RpcClient,
    sender_keypair: Keypair,
    transfer_amount: Option<u64>,
) {
    let exit = Arc::new(AtomicBool::default());
    let fee_payer = Keypair::new();
    let transaction = transfer(
        client,
        sol_to_lamports(1.0),
        &sender_keypair,
        &fee_payer.pubkey(),
    )
    .unwrap();
    client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .unwrap();
    assert_eq!(
        client.get_balance(&fee_payer.pubkey()).unwrap(),
        sol_to_lamports(1.0),
    );

    let expected_amount = if let Some(amount) = transfer_amount {
        amount
    } else {
        sol_to_lamports(1000.0)
    };
    let alice_pubkey = solana_sdk::pubkey::new_rand();
    let allocations_file = NamedTempFile::new().unwrap();
    let input_csv = allocations_file.path().to_str().unwrap().to_string();
    let mut wtr = csv::WriterBuilder::new().from_writer(allocations_file);
    wtr.write_record(["recipient", "amount"]).unwrap();
    wtr.write_record([
        alice_pubkey.to_string(),
        lamports_to_sol(expected_amount).to_string(),
    ])
    .unwrap();
    wtr.flush().unwrap();

    let dir = tempdir().unwrap();
    let transaction_db = dir
        .path()
        .join("transactions.db")
        .to_str()
        .unwrap()
        .to_string();

    let output_file = NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap().to_string();

    let args = DistributeTokensArgs {
        sender_keypair: Box::new(sender_keypair),
        fee_payer: Box::new(fee_payer),
        dry_run: false,
        input_csv,
        transaction_db: transaction_db.clone(),
        output_path: Some(output_path.clone()),
        stake_args: None,
        spl_token_args: None,
        transfer_amount,
    };
    let confirmations = process_allocations(client, &args, exit.clone()).unwrap();
    assert_eq!(confirmations, None);

    let transaction_infos =
        db::read_transaction_infos(&db::open_db(&transaction_db, true).unwrap());
    assert_eq!(transaction_infos.len(), 1);
    assert_eq!(transaction_infos[0].recipient, alice_pubkey);
    assert_eq!(transaction_infos[0].amount, expected_amount);

    assert_eq!(client.get_balance(&alice_pubkey).unwrap(), expected_amount);

    check_output_file(&output_path, &db::open_db(&transaction_db, true).unwrap());

    // Now, run it again, and check there's no double-spend.
    process_allocations(client, &args, exit).unwrap();
    let transaction_infos =
        db::read_transaction_infos(&db::open_db(&transaction_db, true).unwrap());
    assert_eq!(transaction_infos.len(), 1);
    assert_eq!(transaction_infos[0].recipient, alice_pubkey);
    assert_eq!(transaction_infos[0].amount, expected_amount);

    assert_eq!(client.get_balance(&alice_pubkey).unwrap(), expected_amount);

    check_output_file(&output_path, &db::open_db(&transaction_db, true).unwrap());
}

pub fn test_process_create_stake_with_client(client: &RpcClient, sender_keypair: Keypair) {
    let exit = Arc::new(AtomicBool::default());
    let fee_payer = Keypair::new();
    let transaction = transfer(
        client,
        sol_to_lamports(1.0),
        &sender_keypair,
        &fee_payer.pubkey(),
    )
    .unwrap();
    client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .unwrap();

    let stake_account_keypair = Keypair::new();
    let stake_account_address = stake_account_keypair.pubkey();
    let stake_authority = Keypair::new();
    let withdraw_authority = Keypair::new();

    let authorized = Authorized {
        staker: stake_authority.pubkey(),
        withdrawer: withdraw_authority.pubkey(),
    };
    let lockup = Lockup::default();
    let instructions = stake_instruction::create_account(
        &sender_keypair.pubkey(),
        &stake_account_address,
        &authorized,
        &lockup,
        sol_to_lamports(3000.0),
    );
    let message = Message::new(&instructions, Some(&sender_keypair.pubkey()));
    let signers = [&sender_keypair, &stake_account_keypair];
    let blockhash = client.get_latest_blockhash().unwrap();
    let transaction = Transaction::new(&signers, message, blockhash);
    client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .unwrap();

    let expected_amount = sol_to_lamports(1000.0);
    let alice_pubkey = solana_sdk::pubkey::new_rand();
    let file = NamedTempFile::new().unwrap();
    let input_csv = file.path().to_str().unwrap().to_string();
    let mut wtr = csv::WriterBuilder::new().from_writer(file);
    wtr.write_record(["recipient", "amount", "lockup_date"])
        .unwrap();
    wtr.write_record([
        alice_pubkey.to_string(),
        lamports_to_sol(expected_amount).to_string(),
        "".to_string(),
    ])
    .unwrap();
    wtr.flush().unwrap();

    let dir = tempdir().unwrap();
    let transaction_db = dir
        .path()
        .join("transactions.db")
        .to_str()
        .unwrap()
        .to_string();

    let output_file = NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap().to_string();

    let stake_args = StakeArgs {
        lockup_authority: None,
        unlocked_sol: sol_to_lamports(1.0),
        sender_stake_args: None,
    };
    let args = DistributeTokensArgs {
        fee_payer: Box::new(fee_payer),
        dry_run: false,
        input_csv,
        transaction_db: transaction_db.clone(),
        output_path: Some(output_path.clone()),
        stake_args: Some(stake_args),
        spl_token_args: None,
        sender_keypair: Box::new(sender_keypair),
        transfer_amount: None,
    };
    let confirmations = process_allocations(client, &args, exit.clone()).unwrap();
    assert_eq!(confirmations, None);

    let transaction_infos =
        db::read_transaction_infos(&db::open_db(&transaction_db, true).unwrap());
    assert_eq!(transaction_infos.len(), 1);
    assert_eq!(transaction_infos[0].recipient, alice_pubkey);
    assert_eq!(transaction_infos[0].amount, expected_amount);

    assert_eq!(
        client.get_balance(&alice_pubkey).unwrap(),
        sol_to_lamports(1.0),
    );
    let new_stake_account_address = transaction_infos[0].new_stake_account_address.unwrap();
    assert_eq!(
        client.get_balance(&new_stake_account_address).unwrap(),
        expected_amount - sol_to_lamports(1.0),
    );

    check_output_file(&output_path, &db::open_db(&transaction_db, true).unwrap());

    // Now, run it again, and check there's no double-spend.
    process_allocations(client, &args, exit).unwrap();
    let transaction_infos =
        db::read_transaction_infos(&db::open_db(&transaction_db, true).unwrap());
    assert_eq!(transaction_infos.len(), 1);
    assert_eq!(transaction_infos[0].recipient, alice_pubkey);
    assert_eq!(transaction_infos[0].amount, expected_amount);

    assert_eq!(
        client.get_balance(&alice_pubkey).unwrap(),
        sol_to_lamports(1.0),
    );
    assert_eq!(
        client.get_balance(&new_stake_account_address).unwrap(),
        expected_amount - sol_to_lamports(1.0),
    );

    check_output_file(&output_path, &db::open_db(&transaction_db, true).unwrap());
}

pub fn test_process_distribute_stake_with_client(client: &RpcClient, sender_keypair: Keypair) {
    let exit = Arc::new(AtomicBool::default());
    let fee_payer = Keypair::new();
    let transaction = transfer(
        client,
        sol_to_lamports(1.0),
        &sender_keypair,
        &fee_payer.pubkey(),
    )
    .unwrap();
    client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .unwrap();

    let stake_account_keypair = Keypair::new();
    let stake_account_address = stake_account_keypair.pubkey();
    let stake_authority = Keypair::new();
    let withdraw_authority = Keypair::new();

    let authorized = Authorized {
        staker: stake_authority.pubkey(),
        withdrawer: withdraw_authority.pubkey(),
    };
    let lockup = Lockup::default();
    let instructions = stake_instruction::create_account(
        &sender_keypair.pubkey(),
        &stake_account_address,
        &authorized,
        &lockup,
        sol_to_lamports(3000.0),
    );
    let message = Message::new(&instructions, Some(&sender_keypair.pubkey()));
    let signers = [&sender_keypair, &stake_account_keypair];
    let blockhash = client.get_latest_blockhash().unwrap();
    let transaction = Transaction::new(&signers, message, blockhash);
    client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .unwrap();

    let expected_amount = sol_to_lamports(1000.0);
    let alice_pubkey = solana_sdk::pubkey::new_rand();
    let file = NamedTempFile::new().unwrap();
    let input_csv = file.path().to_str().unwrap().to_string();
    let mut wtr = csv::WriterBuilder::new().from_writer(file);
    wtr.write_record(["recipient", "amount", "lockup_date"])
        .unwrap();
    wtr.write_record([
        alice_pubkey.to_string(),
        lamports_to_sol(expected_amount).to_string(),
        "".to_string(),
    ])
    .unwrap();
    wtr.flush().unwrap();

    let dir = tempdir().unwrap();
    let transaction_db = dir
        .path()
        .join("transactions.db")
        .to_str()
        .unwrap()
        .to_string();

    let output_file = NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap().to_string();

    let sender_stake_args = SenderStakeArgs {
        stake_account_address,
        stake_authority: Box::new(stake_authority),
        withdraw_authority: Box::new(withdraw_authority),
        lockup_authority: None,
    };
    let stake_args = StakeArgs {
        unlocked_sol: sol_to_lamports(1.0),
        lockup_authority: None,
        sender_stake_args: Some(sender_stake_args),
    };
    let args = DistributeTokensArgs {
        fee_payer: Box::new(fee_payer),
        dry_run: false,
        input_csv,
        transaction_db: transaction_db.clone(),
        output_path: Some(output_path.clone()),
        stake_args: Some(stake_args),
        spl_token_args: None,
        sender_keypair: Box::new(sender_keypair),
        transfer_amount: None,
    };
    let confirmations = process_allocations(client, &args, exit.clone()).unwrap();
    assert_eq!(confirmations, None);

    let transaction_infos =
        db::read_transaction_infos(&db::open_db(&transaction_db, true).unwrap());
    assert_eq!(transaction_infos.len(), 1);
    assert_eq!(transaction_infos[0].recipient, alice_pubkey);
    assert_eq!(transaction_infos[0].amount, expected_amount);

    assert_eq!(
        client.get_balance(&alice_pubkey).unwrap(),
        sol_to_lamports(1.0),
    );
    let new_stake_account_address = transaction_infos[0].new_stake_account_address.unwrap();
    assert_eq!(
        client.get_balance(&new_stake_account_address).unwrap(),
        expected_amount - sol_to_lamports(1.0),
    );

    check_output_file(&output_path, &db::open_db(&transaction_db, true).unwrap());

    // Now, run it again, and check there's no double-spend.
    process_allocations(client, &args, exit).unwrap();
    let transaction_infos =
        db::read_transaction_infos(&db::open_db(&transaction_db, true).unwrap());
    assert_eq!(transaction_infos.len(), 1);
    assert_eq!(transaction_infos[0].recipient, alice_pubkey);
    assert_eq!(transaction_infos[0].amount, expected_amount);

    assert_eq!(
        client.get_balance(&alice_pubkey).unwrap(),
        sol_to_lamports(1.0),
    );
    assert_eq!(
        client.get_balance(&new_stake_account_address).unwrap(),
        expected_amount - sol_to_lamports(1.0),
    );

    check_output_file(&output_path, &db::open_db(&transaction_db, true).unwrap());
}
