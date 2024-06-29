use solana_sdk::{
    message::{v0::LoadedMessage, Message},
    reserved_account_keys::ReservedAccountKeys,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ParsedAccount {
    pub pubkey: String,
    pub writable: bool,
    pub signer: bool,
    pub source: Option<ParsedAccountSource>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ParsedAccountSource {
    Transaction,
    LookupTable,
}

pub fn parse_legacy_message_accounts(message: &Message) -> Vec<ParsedAccount> {
    let reserved_account_keys = ReservedAccountKeys::new_all_activated().active;
    let mut accounts: Vec<ParsedAccount> = vec![];
    for (i, account_key) in message.account_keys.iter().enumerate() {
        accounts.push(ParsedAccount {
            pubkey: account_key.to_string(),
            writable: message.is_maybe_writable(i, Some(&reserved_account_keys)),
            signer: message.is_signer(i),
            source: Some(ParsedAccountSource::Transaction),
        });
    }
    accounts
}

pub fn parse_v0_message_accounts(message: &LoadedMessage) -> Vec<ParsedAccount> {
    let mut accounts: Vec<ParsedAccount> = vec![];
    for (i, account_key) in message.account_keys().iter().enumerate() {
        let source = if i < message.static_account_keys().len() {
            ParsedAccountSource::Transaction
        } else {
            ParsedAccountSource::LookupTable
        };
        accounts.push(ParsedAccount {
            pubkey: account_key.to_string(),
            writable: message.is_writable(i),
            signer: message.is_signer(i),
            source: Some(source),
        });
    }
    accounts
}
