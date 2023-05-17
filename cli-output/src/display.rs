use {
    crate::cli_output::CliSignatureVerificationStatus,
    base64::{prelude::BASE64_STANDARD, Engine},
    chrono::{DateTime, Local, NaiveDateTime, SecondsFormat, TimeZone, Utc},
    console::style,
    indicatif::{ProgressBar, ProgressStyle},
    solana_cli_config::SettingType,
    solana_sdk::{
        clock::UnixTimestamp,
        hash::Hash,
        instruction::CompiledInstruction,
        message::v0::MessageAddressTableLookup,
        native_token::lamports_to_sol,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        signature::Signature,
        stake,
        transaction::{TransactionError, TransactionVersion, VersionedTransaction},
    },
    solana_transaction_status::{
        Rewards, UiReturnDataEncoding, UiTransactionReturnData, UiTransactionStatusMeta,
    },
    spl_memo::{id as spl_memo_id, v1::id as spl_memo_v1_id},
    std::{collections::HashMap, fmt, io, time::Duration},
};

#[derive(Clone, Debug)]
pub struct BuildBalanceMessageConfig {
    pub use_lamports_unit: bool,
    pub show_unit: bool,
    pub trim_trailing_zeros: bool,
}

impl Default for BuildBalanceMessageConfig {
    fn default() -> Self {
        Self {
            use_lamports_unit: false,
            show_unit: true,
            trim_trailing_zeros: true,
        }
    }
}

fn is_memo_program(k: &Pubkey) -> bool {
    let k_str = k.to_string();
    (k_str == spl_memo_v1_id().to_string()) || (k_str == spl_memo_id().to_string())
}

pub fn build_balance_message_with_config(
    lamports: u64,
    config: &BuildBalanceMessageConfig,
) -> String {
    let value = if config.use_lamports_unit {
        lamports.to_string()
    } else {
        let sol = lamports_to_sol(lamports);
        let sol_str = format!("{sol:.9}");
        if config.trim_trailing_zeros {
            sol_str
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string()
        } else {
            sol_str
        }
    };
    let unit = if config.show_unit {
        if config.use_lamports_unit {
            let ess = if lamports == 1 { "" } else { "s" };
            format!(" lamport{ess}")
        } else {
            " SOL".to_string()
        }
    } else {
        "".to_string()
    };
    format!("{value}{unit}")
}

pub fn build_balance_message(lamports: u64, use_lamports_unit: bool, show_unit: bool) -> String {
    build_balance_message_with_config(
        lamports,
        &BuildBalanceMessageConfig {
            use_lamports_unit,
            show_unit,
            ..BuildBalanceMessageConfig::default()
        },
    )
}

// Pretty print a "name value"
pub fn println_name_value(name: &str, value: &str) {
    let styled_value = if value.is_empty() {
        style("(not set)").italic()
    } else {
        style(value)
    };
    println!("{} {}", style(name).bold(), styled_value);
}

pub fn writeln_name_value(f: &mut dyn fmt::Write, name: &str, value: &str) -> fmt::Result {
    let styled_value = if value.is_empty() {
        style("(not set)").italic()
    } else {
        style(value)
    };
    writeln!(f, "{} {}", style(name).bold(), styled_value)
}

pub fn println_name_value_or(name: &str, value: &str, setting_type: SettingType) {
    let description = match setting_type {
        SettingType::Explicit => "",
        SettingType::Computed => "(computed)",
        SettingType::SystemDefault => "(default)",
    };

    println!(
        "{} {} {}",
        style(name).bold(),
        style(value),
        style(description).italic(),
    );
}

pub fn format_labeled_address(pubkey: &str, address_labels: &HashMap<String, String>) -> String {
    let label = address_labels.get(pubkey);
    match label {
        Some(label) => format!(
            "{:.31} ({:.4}..{})",
            label,
            pubkey,
            pubkey.split_at(pubkey.len() - 4).1
        ),
        None => pubkey.to_string(),
    }
}

pub fn println_signers(
    blockhash: &Hash,
    signers: &[String],
    absent: &[String],
    bad_sig: &[String],
) {
    println!();
    println!("Blockhash: {blockhash}");
    if !signers.is_empty() {
        println!("Signers (Pubkey=Signature):");
        signers.iter().for_each(|signer| println!("  {signer}"))
    }
    if !absent.is_empty() {
        println!("Absent Signers (Pubkey):");
        absent.iter().for_each(|pubkey| println!("  {pubkey}"))
    }
    if !bad_sig.is_empty() {
        println!("Bad Signatures (Pubkey):");
        bad_sig.iter().for_each(|pubkey| println!("  {pubkey}"))
    }
    println!();
}

struct CliAccountMeta {
    is_signer: bool,
    is_writable: bool,
    is_invoked: bool,
}

fn format_account_mode(meta: CliAccountMeta) -> String {
    format!(
        "{}r{}{}", // accounts are always readable...
        if meta.is_signer {
            "s" // stands for signer
        } else {
            "-"
        },
        if meta.is_writable {
            "w" // comment for consistent rust fmt (no joking; lol)
        } else {
            "-"
        },
        // account may be executable on-chain while not being
        // designated as a program-id in the message
        if meta.is_invoked {
            "x"
        } else {
            // programs to be executed via CPI cannot be identified as
            // executable from the message
            "-"
        },
    )
}

fn write_transaction<W: io::Write>(
    w: &mut W,
    transaction: &VersionedTransaction,
    transaction_status: Option<&UiTransactionStatusMeta>,
    prefix: &str,
    sigverify_status: Option<&[CliSignatureVerificationStatus]>,
    block_time: Option<UnixTimestamp>,
    timezone: CliTimezone,
) -> io::Result<()> {
    write_block_time(w, block_time, timezone, prefix)?;

    let message = &transaction.message;
    let account_keys: Vec<AccountKeyType> = {
        let static_keys_iter = message
            .static_account_keys()
            .iter()
            .map(AccountKeyType::Known);
        let dynamic_keys: Vec<AccountKeyType> = message
            .address_table_lookups()
            .map(transform_lookups_to_unknown_keys)
            .unwrap_or_default();
        static_keys_iter.chain(dynamic_keys).collect()
    };

    write_version(w, transaction.version(), prefix)?;
    write_recent_blockhash(w, message.recent_blockhash(), prefix)?;
    write_signatures(w, &transaction.signatures, sigverify_status, prefix)?;

    let mut fee_payer_index = None;
    for (account_index, account) in account_keys.iter().enumerate() {
        if fee_payer_index.is_none() && message.is_non_loader_key(account_index) {
            fee_payer_index = Some(account_index)
        }

        let account_meta = CliAccountMeta {
            is_signer: message.is_signer(account_index),
            is_writable: message.is_maybe_writable(account_index),
            is_invoked: message.is_invoked(account_index),
        };

        write_account(
            w,
            account_index,
            *account,
            format_account_mode(account_meta),
            Some(account_index) == fee_payer_index,
            prefix,
        )?;
    }

    for (instruction_index, instruction) in message.instructions().iter().enumerate() {
        let program_pubkey = account_keys[instruction.program_id_index as usize];
        let instruction_accounts = instruction
            .accounts
            .iter()
            .map(|account_index| (account_keys[*account_index as usize], *account_index));

        write_instruction(
            w,
            instruction_index,
            program_pubkey,
            instruction,
            instruction_accounts,
            prefix,
        )?;
    }

    if let Some(address_table_lookups) = message.address_table_lookups() {
        write_address_table_lookups(w, address_table_lookups, prefix)?;
    }

    if let Some(transaction_status) = transaction_status {
        write_status(w, &transaction_status.status, prefix)?;
        write_fees(w, transaction_status.fee, prefix)?;
        write_balances(w, transaction_status, prefix)?;
        write_compute_units_consumed(
            w,
            transaction_status.compute_units_consumed.clone().into(),
            prefix,
        )?;
        write_log_messages(w, transaction_status.log_messages.as_ref().into(), prefix)?;
        write_return_data(w, transaction_status.return_data.as_ref().into(), prefix)?;
        write_rewards(w, transaction_status.rewards.as_ref().into(), prefix)?;
    } else {
        writeln!(w, "{prefix}Status: Unavailable")?;
    }

    Ok(())
}

fn transform_lookups_to_unknown_keys(lookups: &[MessageAddressTableLookup]) -> Vec<AccountKeyType> {
    let unknown_writable_keys = lookups
        .iter()
        .enumerate()
        .flat_map(|(lookup_index, lookup)| {
            lookup
                .writable_indexes
                .iter()
                .map(move |table_index| AccountKeyType::Unknown {
                    lookup_index,
                    table_index: *table_index,
                })
        });

    let unknown_readonly_keys = lookups
        .iter()
        .enumerate()
        .flat_map(|(lookup_index, lookup)| {
            lookup
                .readonly_indexes
                .iter()
                .map(move |table_index| AccountKeyType::Unknown {
                    lookup_index,
                    table_index: *table_index,
                })
        });

    unknown_writable_keys.chain(unknown_readonly_keys).collect()
}

enum CliTimezone {
    Local,
    #[allow(dead_code)]
    Utc,
}

fn write_block_time<W: io::Write>(
    w: &mut W,
    block_time: Option<UnixTimestamp>,
    timezone: CliTimezone,
    prefix: &str,
) -> io::Result<()> {
    if let Some(block_time) = block_time {
        let block_time_output = match timezone {
            CliTimezone::Local => format!("{:?}", Local.timestamp_opt(block_time, 0).unwrap()),
            CliTimezone::Utc => format!("{:?}", Utc.timestamp_opt(block_time, 0).unwrap()),
        };
        writeln!(w, "{prefix}Block Time: {block_time_output}",)?;
    }
    Ok(())
}

fn write_version<W: io::Write>(
    w: &mut W,
    version: TransactionVersion,
    prefix: &str,
) -> io::Result<()> {
    let version = match version {
        TransactionVersion::Legacy(_) => "legacy".to_string(),
        TransactionVersion::Number(number) => number.to_string(),
    };
    writeln!(w, "{prefix}Version: {version}")
}

fn write_recent_blockhash<W: io::Write>(
    w: &mut W,
    recent_blockhash: &Hash,
    prefix: &str,
) -> io::Result<()> {
    writeln!(w, "{prefix}Recent Blockhash: {recent_blockhash:?}")
}

fn write_signatures<W: io::Write>(
    w: &mut W,
    signatures: &[Signature],
    sigverify_status: Option<&[CliSignatureVerificationStatus]>,
    prefix: &str,
) -> io::Result<()> {
    let sigverify_statuses = if let Some(sigverify_status) = sigverify_status {
        sigverify_status.iter().map(|s| format!(" ({s})")).collect()
    } else {
        vec!["".to_string(); signatures.len()]
    };
    for (signature_index, (signature, sigverify_status)) in
        signatures.iter().zip(&sigverify_statuses).enumerate()
    {
        writeln!(
            w,
            "{prefix}Signature {signature_index}: {signature:?}{sigverify_status}",
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountKeyType<'a> {
    Known(&'a Pubkey),
    Unknown {
        lookup_index: usize,
        table_index: u8,
    },
}

impl fmt::Display for AccountKeyType<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Known(address) => write!(f, "{address}"),
            Self::Unknown {
                lookup_index,
                table_index,
            } => {
                write!(
                    f,
                    "Unknown Address (uses lookup {lookup_index} and index {table_index})"
                )
            }
        }
    }
}

fn write_account<W: io::Write>(
    w: &mut W,
    account_index: usize,
    account_address: AccountKeyType,
    account_mode: String,
    is_fee_payer: bool,
    prefix: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "{}Account {}: {} {}{}",
        prefix,
        account_index,
        account_mode,
        account_address,
        if is_fee_payer { " (fee payer)" } else { "" },
    )
}

fn write_instruction<'a, W: io::Write>(
    w: &mut W,
    instruction_index: usize,
    program_pubkey: AccountKeyType,
    instruction: &CompiledInstruction,
    instruction_accounts: impl Iterator<Item = (AccountKeyType<'a>, u8)>,
    prefix: &str,
) -> io::Result<()> {
    writeln!(w, "{prefix}Instruction {instruction_index}")?;
    writeln!(
        w,
        "{}  Program:   {} ({})",
        prefix, program_pubkey, instruction.program_id_index
    )?;
    for (index, (account_address, account_index)) in instruction_accounts.enumerate() {
        writeln!(
            w,
            "{prefix}  Account {index}: {account_address} ({account_index})"
        )?;
    }

    let mut raw = true;
    if let AccountKeyType::Known(program_pubkey) = program_pubkey {
        if program_pubkey == &solana_vote_program::id() {
            if let Ok(vote_instruction) = limited_deserialize::<
                solana_vote_program::vote_instruction::VoteInstruction,
            >(&instruction.data)
            {
                writeln!(w, "{prefix}  {vote_instruction:?}")?;
                raw = false;
            }
        } else if program_pubkey == &stake::program::id() {
            if let Ok(stake_instruction) =
                limited_deserialize::<stake::instruction::StakeInstruction>(&instruction.data)
            {
                writeln!(w, "{prefix}  {stake_instruction:?}")?;
                raw = false;
            }
        } else if program_pubkey == &solana_sdk::system_program::id() {
            if let Ok(system_instruction) = limited_deserialize::<
                solana_sdk::system_instruction::SystemInstruction,
            >(&instruction.data)
            {
                writeln!(w, "{prefix}  {system_instruction:?}")?;
                raw = false;
            }
        } else if is_memo_program(program_pubkey) {
            if let Ok(s) = std::str::from_utf8(&instruction.data) {
                writeln!(w, "{prefix}  Data: \"{s}\"")?;
                raw = false;
            }
        }
    }

    if raw {
        writeln!(w, "{}  Data: {:?}", prefix, instruction.data)?;
    }

    Ok(())
}

fn write_address_table_lookups<W: io::Write>(
    w: &mut W,
    address_table_lookups: &[MessageAddressTableLookup],
    prefix: &str,
) -> io::Result<()> {
    for (lookup_index, lookup) in address_table_lookups.iter().enumerate() {
        writeln!(w, "{prefix}Address Table Lookup {lookup_index}",)?;
        writeln!(w, "{}  Table Account: {}", prefix, lookup.account_key,)?;
        writeln!(
            w,
            "{}  Writable Indexes: {:?}",
            prefix,
            &lookup.writable_indexes[..],
        )?;
        writeln!(
            w,
            "{}  Readonly Indexes: {:?}",
            prefix,
            &lookup.readonly_indexes[..],
        )?;
    }
    Ok(())
}

fn write_rewards<W: io::Write>(
    w: &mut W,
    rewards: Option<&Rewards>,
    prefix: &str,
) -> io::Result<()> {
    if let Some(rewards) = rewards {
        if !rewards.is_empty() {
            writeln!(w, "{prefix}Rewards:",)?;
            writeln!(
                w,
                "{}  {:<44}  {:^15}  {:<16}  {:<20}",
                prefix, "Address", "Type", "Amount", "New Balance"
            )?;
            for reward in rewards {
                let sign = if reward.lamports < 0 { "-" } else { "" };
                writeln!(
                    w,
                    "{}  {:<44}  {:^15}  {}◎{:<14.9}  ◎{:<18.9}",
                    prefix,
                    reward.pubkey,
                    if let Some(reward_type) = reward.reward_type {
                        format!("{reward_type}")
                    } else {
                        "-".to_string()
                    },
                    sign,
                    lamports_to_sol(reward.lamports.unsigned_abs()),
                    lamports_to_sol(reward.post_balance)
                )?;
            }
        }
    }
    Ok(())
}

fn write_status<W: io::Write>(
    w: &mut W,
    transaction_status: &Result<(), TransactionError>,
    prefix: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "{}Status: {}",
        prefix,
        match transaction_status {
            Ok(_) => "Ok".into(),
            Err(err) => err.to_string(),
        }
    )
}

fn write_fees<W: io::Write>(w: &mut W, transaction_fee: u64, prefix: &str) -> io::Result<()> {
    writeln!(w, "{}  Fee: ◎{}", prefix, lamports_to_sol(transaction_fee))
}

fn write_balances<W: io::Write>(
    w: &mut W,
    transaction_status: &UiTransactionStatusMeta,
    prefix: &str,
) -> io::Result<()> {
    assert_eq!(
        transaction_status.pre_balances.len(),
        transaction_status.post_balances.len()
    );
    for (i, (pre, post)) in transaction_status
        .pre_balances
        .iter()
        .zip(transaction_status.post_balances.iter())
        .enumerate()
    {
        if pre == post {
            writeln!(
                w,
                "{}  Account {} balance: ◎{}",
                prefix,
                i,
                lamports_to_sol(*pre)
            )?;
        } else {
            writeln!(
                w,
                "{}  Account {} balance: ◎{} -> ◎{}",
                prefix,
                i,
                lamports_to_sol(*pre),
                lamports_to_sol(*post)
            )?;
        }
    }
    Ok(())
}

fn write_return_data<W: io::Write>(
    w: &mut W,
    return_data: Option<&UiTransactionReturnData>,
    prefix: &str,
) -> io::Result<()> {
    if let Some(return_data) = return_data {
        let (data, encoding) = &return_data.data;
        let raw_return_data = match encoding {
            UiReturnDataEncoding::Base64 => BASE64_STANDARD.decode(data).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("could not parse data as {encoding:?}: {err:?}"),
                )
            })?,
        };
        if !raw_return_data.is_empty() {
            use pretty_hex::*;
            writeln!(
                w,
                "{}Return Data from Program {}:",
                prefix, return_data.program_id
            )?;
            writeln!(w, "{}  {:?}", prefix, raw_return_data.hex_dump())?;
        }
    }
    Ok(())
}

fn write_compute_units_consumed<W: io::Write>(
    w: &mut W,
    compute_units_consumed: Option<u64>,
    prefix: &str,
) -> io::Result<()> {
    if let Some(cus) = compute_units_consumed {
        writeln!(w, "{prefix}Compute Units Consumed: {cus}")?;
    }
    Ok(())
}

fn write_log_messages<W: io::Write>(
    w: &mut W,
    log_messages: Option<&Vec<String>>,
    prefix: &str,
) -> io::Result<()> {
    if let Some(log_messages) = log_messages {
        if !log_messages.is_empty() {
            writeln!(w, "{prefix}Log Messages:",)?;
            for log_message in log_messages {
                writeln!(w, "{prefix}  {log_message}")?;
            }
        }
    }
    Ok(())
}

pub fn println_transaction(
    transaction: &VersionedTransaction,
    transaction_status: Option<&UiTransactionStatusMeta>,
    prefix: &str,
    sigverify_status: Option<&[CliSignatureVerificationStatus]>,
    block_time: Option<UnixTimestamp>,
) {
    let mut w = Vec::new();
    if write_transaction(
        &mut w,
        transaction,
        transaction_status,
        prefix,
        sigverify_status,
        block_time,
        CliTimezone::Local,
    )
    .is_ok()
    {
        if let Ok(s) = String::from_utf8(w) {
            print!("{s}");
        }
    }
}

pub fn writeln_transaction(
    f: &mut dyn fmt::Write,
    transaction: &VersionedTransaction,
    transaction_status: Option<&UiTransactionStatusMeta>,
    prefix: &str,
    sigverify_status: Option<&[CliSignatureVerificationStatus]>,
    block_time: Option<UnixTimestamp>,
) -> fmt::Result {
    let mut w = Vec::new();
    let write_result = write_transaction(
        &mut w,
        transaction,
        transaction_status,
        prefix,
        sigverify_status,
        block_time,
        CliTimezone::Local,
    );

    if write_result.is_ok() {
        if let Ok(s) = String::from_utf8(w) {
            write!(f, "{s}")?;
        }
    }
    Ok(())
}

/// Creates a new process bar for processing that will take an unknown amount of time
pub fn new_spinner_progress_bar() -> ProgressBar {
    let progress_bar = ProgressBar::new(42);
    progress_bar.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {wide_msg}")
            .expect("ProgresStyle::template direct input to be correct"),
    );
    progress_bar.enable_steady_tick(Duration::from_millis(100));
    progress_bar
}

pub fn unix_timestamp_to_string(unix_timestamp: UnixTimestamp) -> String {
    match NaiveDateTime::from_timestamp_opt(unix_timestamp, 0) {
        Some(ndt) => DateTime::<Utc>::from_utc(ndt, Utc).to_rfc3339_opts(SecondsFormat::Secs, true),
        None => format!("UnixTimestamp {unix_timestamp}"),
    }
}
