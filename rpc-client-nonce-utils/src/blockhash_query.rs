use {
    clap::ArgMatches,
    solana_clap_utils::{
        input_parsers::{pubkey_of, value_of},
        nonce::*,
        offline::*,
    },
    solana_rpc_client::rpc_client::RpcClient,
    solana_sdk::{commitment_config::CommitmentConfig, hash::Hash, pubkey::Pubkey},
};

#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    Cluster,
    NonceAccount(Pubkey),
}

impl Source {
    pub fn get_blockhash(
        &self,
        rpc_client: &RpcClient,
        commitment: CommitmentConfig,
    ) -> Result<Hash, Box<dyn std::error::Error>> {
        match self {
            Self::Cluster => {
                let (blockhash, _) = rpc_client.get_latest_blockhash_with_commitment(commitment)?;
                Ok(blockhash)
            }
            Self::NonceAccount(ref pubkey) => {
                let data = crate::get_account_with_commitment(rpc_client, pubkey, commitment)
                    .and_then(|ref a| crate::data_from_account(a))?;
                Ok(data.blockhash())
            }
        }
    }

    pub fn is_blockhash_valid(
        &self,
        rpc_client: &RpcClient,
        blockhash: &Hash,
        commitment: CommitmentConfig,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(match self {
            Self::Cluster => rpc_client.is_blockhash_valid(blockhash, commitment)?,
            Self::NonceAccount(ref pubkey) => {
                let _ = crate::get_account_with_commitment(rpc_client, pubkey, commitment)
                    .and_then(|ref a| crate::data_from_account(a))?;
                true
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlockhashQuery {
    None(Hash),
    FeeCalculator(Source, Hash),
    All(Source),
}

impl BlockhashQuery {
    pub fn new(blockhash: Option<Hash>, sign_only: bool, nonce_account: Option<Pubkey>) -> Self {
        let source = nonce_account
            .map(Source::NonceAccount)
            .unwrap_or(Source::Cluster);
        match blockhash {
            Some(hash) if sign_only => Self::None(hash),
            Some(hash) if !sign_only => Self::FeeCalculator(source, hash),
            None if !sign_only => Self::All(source),
            _ => panic!("Cannot resolve blockhash"),
        }
    }

    pub fn new_from_matches(matches: &ArgMatches<'_>) -> Self {
        let blockhash = value_of(matches, BLOCKHASH_ARG.name);
        let sign_only = matches.is_present(SIGN_ONLY_ARG.name);
        let nonce_account = pubkey_of(matches, NONCE_ARG.name);
        BlockhashQuery::new(blockhash, sign_only, nonce_account)
    }

    pub fn get_blockhash(
        &self,
        rpc_client: &RpcClient,
        commitment: CommitmentConfig,
    ) -> Result<Hash, Box<dyn std::error::Error>> {
        match self {
            BlockhashQuery::None(hash) => Ok(*hash),
            BlockhashQuery::FeeCalculator(source, hash) => {
                if !source.is_blockhash_valid(rpc_client, hash, commitment)? {
                    return Err(format!("Hash has expired {hash:?}").into());
                }
                Ok(*hash)
            }
            BlockhashQuery::All(source) => source.get_blockhash(rpc_client, commitment),
        }
    }
}

impl Default for BlockhashQuery {
    fn default() -> Self {
        BlockhashQuery::All(Source::Cluster)
    }
}
