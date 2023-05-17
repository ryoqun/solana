use {
    chrono::prelude::*,
    pickledb::{error::Error, PickleDb, PickleDbDumpPolicy},
    serde::{Deserialize, Serialize},
    solana_sdk::{clock::Slot, pubkey::Pubkey, signature::Signature, transaction::Transaction},
    solana_transaction_status::TransactionStatus,
    std::{cmp::Ordering, fs, io, path::Path},
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionInfo {
    pub recipient: Pubkey,
    pub amount: u64,
    pub new_stake_account_address: Option<Pubkey>,
    pub finalized_date: Option<DateTime<Utc>>,
    pub transaction: Transaction,
    pub last_valid_block_height: Slot,
    pub lockup_date: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
struct SignedTransactionInfo {
    recipient: String,
    amount: u64,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    new_stake_account_address: String,
    finalized_date: Option<DateTime<Utc>>,
    signature: String,
}

impl Default for TransactionInfo {
    fn default() -> Self {
        let transaction = Transaction {
            signatures: vec![Signature::default()],
            ..Transaction::default()
        };
        Self {
            recipient: Pubkey::default(),
            amount: 0,
            new_stake_account_address: None,
            finalized_date: None,
            transaction,
            last_valid_block_height: 0,
            lockup_date: None,
        }
    }
}

pub fn open_db(path: &str, dry_run: bool) -> Result<PickleDb, Error> {
    let policy = if dry_run {
        PickleDbDumpPolicy::NeverDump
    } else {
        PickleDbDumpPolicy::DumpUponRequest
    };
    let path = Path::new(path);
    let db = if path.exists() {
        PickleDb::load_yaml(path, policy)?
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        PickleDb::new_yaml(path, policy)
    };
    Ok(db)
}

pub fn compare_transaction_infos(a: &TransactionInfo, b: &TransactionInfo) -> Ordering {
    let ordering = match (a.finalized_date, b.finalized_date) {
        (Some(a), Some(b)) => a.cmp(&b),
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less, // Future finalized date will be greater
        _ => Ordering::Equal,
    };
    if ordering == Ordering::Equal {
        return a.recipient.to_string().cmp(&b.recipient.to_string());
    }
    ordering
}

pub fn write_transaction_log<P: AsRef<Path>>(db: &PickleDb, path: &P) -> Result<(), io::Error> {
    let mut wtr = csv::WriterBuilder::new().from_path(path).unwrap();
    let mut transaction_infos = read_transaction_infos(db);
    transaction_infos.sort_by(compare_transaction_infos);
    for info in transaction_infos {
        let signed_info = SignedTransactionInfo {
            recipient: info.recipient.to_string(),
            amount: info.amount,
            new_stake_account_address: info
                .new_stake_account_address
                .map(|x| x.to_string())
                .unwrap_or_else(|| "".to_string()),
            finalized_date: info.finalized_date,
            signature: info.transaction.signatures[0].to_string(),
        };
        wtr.serialize(&signed_info)?;
    }
    wtr.flush()
}

pub fn read_transaction_infos(db: &PickleDb) -> Vec<TransactionInfo> {
    db.iter()
        .map(|kv| kv.get_value::<TransactionInfo>().unwrap())
        .collect()
}

pub fn set_transaction_info(
    db: &mut PickleDb,
    recipient: &Pubkey,
    amount: u64,
    transaction: &Transaction,
    new_stake_account_address: Option<&Pubkey>,
    finalized: bool,
    last_valid_block_height: u64,
    lockup_date: Option<DateTime<Utc>>,
) -> Result<(), Error> {
    let finalized_date = if finalized { Some(Utc::now()) } else { None };
    let transaction_info = TransactionInfo {
        recipient: *recipient,
        amount,
        new_stake_account_address: new_stake_account_address.cloned(),
        finalized_date,
        transaction: transaction.clone(),
        last_valid_block_height,
        lockup_date,
    };
    let signature = transaction.signatures[0];
    db.set(&signature.to_string(), &transaction_info)?;
    Ok(())
}

// Set the finalized bit in the database if the transaction is rooted.
// Remove the TransactionInfo from the database if the transaction failed.
// Return the number of confirmations on the transaction or None if either
// finalized or discarded.
pub fn update_finalized_transaction(
    db: &mut PickleDb,
    signature: &Signature,
    opt_transaction_status: Option<TransactionStatus>,
    last_valid_block_height: u64,
    finalized_block_height: u64,
) -> Result<Option<usize>, Error> {
    if opt_transaction_status.is_none() {
        if finalized_block_height > last_valid_block_height {
            eprintln!(
                "Signature not found {signature} and blockhash expired. Transaction either dropped or the validator purged the transaction status."
            );
            eprintln!();

            // Don't discard the transaction, because we are not certain the
            // blockhash is expired. Instead, return None to signal that
            // we don't need to wait for confirmations.
            return Ok(None);
        }

        // Return zero to signal the transaction may still be in flight.
        return Ok(Some(0));
    }
    let transaction_status = opt_transaction_status.unwrap();

    if let Some(confirmations) = transaction_status.confirmations {
        // The transaction was found but is not yet finalized.
        return Ok(Some(confirmations));
    }

    if let Some(e) = &transaction_status.err {
        // The transaction was finalized, but execution failed. Drop it.
        eprintln!("Error in transaction with signature {signature}: {e}");
        eprintln!("Discarding transaction record");
        eprintln!();
        db.rem(&signature.to_string())?;
        return Ok(None);
    }

    // Transaction is rooted. Set the finalized date in the database.
    let mut transaction_info = db.get::<TransactionInfo>(&signature.to_string()).unwrap();
    transaction_info.finalized_date = Some(Utc::now());
    db.set(&signature.to_string(), &transaction_info)?;
    Ok(None)
}

use csv::{ReaderBuilder, Trim};
pub(crate) fn check_output_file(path: &str, db: &PickleDb) {
    let mut rdr = ReaderBuilder::new()
        .trim(Trim::All)
        .from_path(path)
        .unwrap();
    let logged_infos: Vec<SignedTransactionInfo> =
        rdr.deserialize().map(|entry| entry.unwrap()).collect();

    let mut transaction_infos = read_transaction_infos(db);
    transaction_infos.sort_by(compare_transaction_infos);
    let transaction_infos: Vec<SignedTransactionInfo> = transaction_infos
        .iter()
        .map(|info| SignedTransactionInfo {
            recipient: info.recipient.to_string(),
            amount: info.amount,
            new_stake_account_address: info
                .new_stake_account_address
                .map(|x| x.to_string())
                .unwrap_or_else(|| "".to_string()),
            finalized_date: info.finalized_date,
            signature: info.transaction.signatures[0].to_string(),
        })
        .collect();
    assert_eq!(logged_infos, transaction_infos);
}
