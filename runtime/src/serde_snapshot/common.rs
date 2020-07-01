use super::*;
use std::collections::HashSet;

#[derive(Default, Clone, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct UnusedAccounts {
    unused1: HashSet<Pubkey>,
    unused2: HashSet<Pubkey>,
    unused3: HashMap<Pubkey, u64>,
}
