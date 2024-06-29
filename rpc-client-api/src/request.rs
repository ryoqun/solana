use {
    crate::response::RpcSimulateTransactionResult,
    serde_json::{json, Value},
    solana_sdk::{clock::Slot, pubkey::Pubkey},
    std::fmt,
    thiserror::Error,
};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum RpcRequest {
    Custom { method: &'static str },
    DeregisterNode,
    GetAccountInfo,
    GetBalance,
    GetBlock,
    GetBlockHeight,
    GetBlockProduction,
    GetBlocks,
    GetBlocksWithLimit,
    GetBlockTime,
    GetClusterNodes,
    GetEpochInfo,
    GetEpochSchedule,
    GetFeeForMessage,
    GetFirstAvailableBlock,
    GetGenesisHash,
    GetHealth,
    GetIdentity,
    GetInflationGovernor,
    GetInflationRate,
    GetInflationReward,
    GetLargestAccounts,
    GetLatestBlockhash,
    GetLeaderSchedule,
    GetMaxRetransmitSlot,
    GetMaxShredInsertSlot,
    GetMinimumBalanceForRentExemption,
    GetMultipleAccounts,
    GetProgramAccounts,
    GetRecentPerformanceSamples,
    GetRecentPrioritizationFees,
    GetHighestSnapshotSlot,
    GetSignaturesForAddress,
    GetSignatureStatuses,
    GetSlot,
    GetSlotLeader,
    GetSlotLeaders,
    GetStorageTurn,
    GetStorageTurnRate,
    GetSlotsPerSegment,
    GetStakeActivation,
    GetStakeMinimumDelegation,
    GetStoragePubkeysForSlot,
    GetSupply,
    GetTokenAccountBalance,
    GetTokenAccountsByDelegate,
    GetTokenAccountsByOwner,
    GetTokenLargestAccounts,
    GetTokenSupply,
    GetTransaction,
    GetTransactionCount,
    GetVersion,
    GetVoteAccounts,
    IsBlockhashValid,
    MinimumLedgerSlot,
    RegisterNode,
    RequestAirdrop,
    SendTransaction,
    SimulateTransaction,
    SignVote,
}

#[allow(deprecated)]
impl fmt::Display for RpcRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let method = match self {
            RpcRequest::Custom { method } => method,
            RpcRequest::DeregisterNode => "deregisterNode",
            RpcRequest::GetAccountInfo => "getAccountInfo",
            RpcRequest::GetBalance => "getBalance",
            RpcRequest::GetBlock => "getBlock",
            RpcRequest::GetBlockHeight => "getBlockHeight",
            RpcRequest::GetBlockProduction => "getBlockProduction",
            RpcRequest::GetBlocks => "getBlocks",
            RpcRequest::GetBlocksWithLimit => "getBlocksWithLimit",
            RpcRequest::GetBlockTime => "getBlockTime",
            RpcRequest::GetClusterNodes => "getClusterNodes",
            RpcRequest::GetEpochInfo => "getEpochInfo",
            RpcRequest::GetEpochSchedule => "getEpochSchedule",
            RpcRequest::GetFeeForMessage => "getFeeForMessage",
            RpcRequest::GetFirstAvailableBlock => "getFirstAvailableBlock",
            RpcRequest::GetGenesisHash => "getGenesisHash",
            RpcRequest::GetHealth => "getHealth",
            RpcRequest::GetIdentity => "getIdentity",
            RpcRequest::GetInflationGovernor => "getInflationGovernor",
            RpcRequest::GetInflationRate => "getInflationRate",
            RpcRequest::GetInflationReward => "getInflationReward",
            RpcRequest::GetLargestAccounts => "getLargestAccounts",
            RpcRequest::GetLatestBlockhash => "getLatestBlockhash",
            RpcRequest::GetLeaderSchedule => "getLeaderSchedule",
            RpcRequest::GetMaxRetransmitSlot => "getMaxRetransmitSlot",
            RpcRequest::GetMaxShredInsertSlot => "getMaxShredInsertSlot",
            RpcRequest::GetMinimumBalanceForRentExemption => "getMinimumBalanceForRentExemption",
            RpcRequest::GetMultipleAccounts => "getMultipleAccounts",
            RpcRequest::GetProgramAccounts => "getProgramAccounts",
            RpcRequest::GetRecentPerformanceSamples => "getRecentPerformanceSamples",
            RpcRequest::GetRecentPrioritizationFees => "getRecentPrioritizationFees",
            RpcRequest::GetHighestSnapshotSlot => "getHighestSnapshotSlot",
            RpcRequest::GetSignaturesForAddress => "getSignaturesForAddress",
            RpcRequest::GetSignatureStatuses => "getSignatureStatuses",
            RpcRequest::GetSlot => "getSlot",
            RpcRequest::GetSlotLeader => "getSlotLeader",
            RpcRequest::GetSlotLeaders => "getSlotLeaders",
            RpcRequest::GetStakeActivation => "getStakeActivation",
            RpcRequest::GetStakeMinimumDelegation => "getStakeMinimumDelegation",
            RpcRequest::GetStorageTurn => "getStorageTurn",
            RpcRequest::GetStorageTurnRate => "getStorageTurnRate",
            RpcRequest::GetSlotsPerSegment => "getSlotsPerSegment",
            RpcRequest::GetStoragePubkeysForSlot => "getStoragePubkeysForSlot",
            RpcRequest::GetSupply => "getSupply",
            RpcRequest::GetTokenAccountBalance => "getTokenAccountBalance",
            RpcRequest::GetTokenAccountsByDelegate => "getTokenAccountsByDelegate",
            RpcRequest::GetTokenAccountsByOwner => "getTokenAccountsByOwner",
            RpcRequest::GetTokenSupply => "getTokenSupply",
            RpcRequest::GetTokenLargestAccounts => "getTokenLargestAccounts",
            RpcRequest::GetTransaction => "getTransaction",
            RpcRequest::GetTransactionCount => "getTransactionCount",
            RpcRequest::GetVersion => "getVersion",
            RpcRequest::GetVoteAccounts => "getVoteAccounts",
            RpcRequest::IsBlockhashValid => "isBlockhashValid",
            RpcRequest::MinimumLedgerSlot => "minimumLedgerSlot",
            RpcRequest::RegisterNode => "registerNode",
            RpcRequest::RequestAirdrop => "requestAirdrop",
            RpcRequest::SendTransaction => "sendTransaction",
            RpcRequest::SimulateTransaction => "simulateTransaction",
            RpcRequest::SignVote => "signVote",
        };

        write!(f, "{method}")
    }
}

// Changing any of these? Update the JSON RPC docs!
pub const MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS: usize = 256;
pub const MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS_SLOT_RANGE: u64 = 10_000;
pub const MAX_GET_CONFIRMED_BLOCKS_RANGE: u64 = 500_000;
pub const MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS2_LIMIT: usize = 1_000;
pub const MAX_MULTIPLE_ACCOUNTS: usize = 100;
pub const NUM_LARGEST_ACCOUNTS: usize = 20;
pub const MAX_GET_PROGRAM_ACCOUNT_FILTERS: usize = 4;
pub const MAX_GET_SLOT_LEADERS: usize = 5000;

// Limit the length of the `epoch_credits` array for each validator in a `get_vote_accounts`
// response
pub const MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY: usize = 5;

// Validators that are this number of slots behind are considered delinquent
pub const DELINQUENT_VALIDATOR_SLOT_DISTANCE: u64 = 128;

impl RpcRequest {
    pub fn build_request_json(self, id: u64, params: Value) -> Value {
        let jsonrpc = "2.0";
        json!({
           "jsonrpc": jsonrpc,
           "id": id,
           "method": format!("{self}"),
           "params": params,
        })
    }
}

#[derive(Debug)]
pub enum RpcResponseErrorData {
    Empty,
    SendTransactionPreflightFailure(RpcSimulateTransactionResult),
    NodeUnhealthy { num_slots_behind: Option<Slot> },
}

impl fmt::Display for RpcResponseErrorData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RpcResponseErrorData::SendTransactionPreflightFailure(
                RpcSimulateTransactionResult {
                    logs: Some(logs), ..
                },
            ) => {
                if logs.is_empty() {
                    Ok(())
                } else {
                    writeln!(f, "{} log messages:", logs.len())?;
                    for log in logs {
                        writeln!(f, "  {log}")?;
                    }
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("RPC request error: {0}")]
    RpcRequestError(String),
    #[error("RPC response error {code}: {message}; {data}")]
    RpcResponseError {
        code: i64,
        message: String,
        data: RpcResponseErrorData,
    },
    #[error("parse error: expected {0}")]
    ParseError(String), /* "expected" */
    // Anything in a `ForUser` needs to die.  The caller should be
    // deciding what to tell their user
    #[error("{0}")]
    ForUser(String), /* "direct-to-user message" */
}

#[derive(Serialize, Deserialize)]
pub enum TokenAccountsFilter {
    Mint(Pubkey),
    ProgramId(Pubkey),
}
