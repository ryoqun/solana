use {
    clap::{crate_description, crate_name, crate_version, ArgEnum, Args, Parser},
    serde::{Deserialize, Serialize},
    solana_sdk::pubkey::Pubkey,
    std::{net::SocketAddr, process::exit, str::FromStr},
};

#[derive(Parser, Debug, PartialEq, Eq)]
#[clap(name = crate_name!(),
    version = crate_version!(),
    about = crate_description!(),
    rename_all = "kebab-case"
)]
pub struct DosClientParameters {
    #[clap(long, arg_enum, help = "Interface to DoS")]
    pub mode: Mode,

    #[clap(long, arg_enum, help = "Type of data to send")]
    pub data_type: DataType,

    #[clap(
        long = "entrypoint",
        parse(try_from_str = addr_parser),
        default_value = "127.0.0.1:8001",
        help = "Gossip entrypoint address. Usually <ip>:8001"
    )]
    pub entrypoint_addr: SocketAddr,

    #[clap(
        long,
        default_value = "128",
        required_if_eq("data-type", "random"),
        help = "Size of packet to DoS with, relevant only for data-type=random"
    )]
    pub data_size: usize,

    #[clap(
        long,
        parse(try_from_str = pubkey_parser),
        required_if_eq("mode", "rpc"),
        help = "Pubkey for rpc-mode calls"
    )]
    pub data_input: Option<Pubkey>,

    #[clap(long, help = "Just use entrypoint address directly")]
    pub skip_gossip: bool,

    #[clap(long, help = "Allow contacting private ip addresses")]
    pub allow_private_addr: bool,

    #[clap(
        long,
        default_value = "1",
        help = "Number of threads generating transactions"
    )]
    pub num_gen_threads: usize,

    #[clap(flatten)]
    pub transaction_params: TransactionParams,

    #[clap(
        long,
        conflicts_with("skip-gossip"),
        help = "Submit transactions via QUIC"
    )]
    pub tpu_use_quic: bool,

    #[clap(long, default_value = "16384", help = "Size of the transactions batch")]
    pub send_batch_size: usize,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub struct TransactionParams {
    #[clap(
        long,
        conflicts_with("valid-blockhash"),
        help = "Number of signatures in transaction"
    )]
    pub num_signatures: Option<usize>,

    #[clap(
        long,
        requires("transaction-type"),
        conflicts_with("skip-gossip"),
        help = "Generate a valid blockhash for transaction"
    )]
    pub valid_blockhash: bool,

    #[clap(
        long,
        requires("num-signatures"),
        help = "Generate valid signature(s) for transaction"
    )]
    pub valid_signatures: bool,

    #[clap(long, help = "Generate unique transactions")]
    pub unique_transactions: bool,

    #[clap(
        long,
        arg_enum,
        requires("valid-blockhash"),
        help = "Type of transaction to be sent"
    )]
    pub transaction_type: Option<TransactionType>,

    #[clap(
        long,
        required_if_eq("transaction-type", "transfer"),
        help = "Number of instructions in transfer transaction"
    )]
    pub num_instructions: Option<usize>,
}

#[derive(ArgEnum, Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Gossip,
    Tvu,
    TvuForwards,
    Tpu,
    TpuForwards,
    Repair,
    ServeRepair,
    Rpc,
}

#[derive(ArgEnum, Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataType {
    RepairHighest,
    RepairShred,
    RepairOrphan,
    Random,
    GetAccountInfo,
    GetProgramAccounts,
    Transaction,
}

#[derive(ArgEnum, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TransactionType {
    Transfer,
    AccountCreation,
}

fn addr_parser(addr: &str) -> Result<SocketAddr, &'static str> {
    match solana_net_utils::parse_host_port(addr) {
        Ok(v) => Ok(v),
        Err(_) => Err("failed to parse address"),
    }
}

fn pubkey_parser(pubkey: &str) -> Result<Pubkey, &'static str> {
    match Pubkey::from_str(pubkey) {
        Ok(v) => Ok(v),
        Err(_) => Err("failed to parse pubkey"),
    }
}

/// input checks which are not covered by Clap
fn validate_input(params: &DosClientParameters) {
    if params.mode == Mode::Rpc
        && (params.data_type != DataType::GetAccountInfo
            && params.data_type != DataType::GetProgramAccounts)
    {
        eprintln!("unsupported data type");
        exit(1);
    }

    if params.data_type != DataType::Transaction {
        let tp = &params.transaction_params;
        if tp.valid_blockhash || tp.valid_signatures || tp.unique_transactions {
            eprintln!("Arguments valid-blockhash, valid-sign, unique-transactions are ignored if data-type != transaction");
            exit(1);
        }
    }
}

pub fn build_cli_parameters() -> DosClientParameters {
    let cmd_params = DosClientParameters::parse();
    validate_input(&cmd_params);
    cmd_params
}
