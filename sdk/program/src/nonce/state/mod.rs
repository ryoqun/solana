mod current;
pub use current::{Data, DurableNonce, State};
use {
    crate::hash::Hash,
    serde_derive::{Deserialize, Serialize},
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum Versions {
    Legacy(Box<State>),
    /// Current variants have durable nonce and blockhash domains separated.
    Current(Box<State>),
}

impl Versions {
    pub fn new(state: State, separate_domains: bool) -> Self {
        if separate_domains {
            Self::Current(Box::new(state))
        } else {
            Self::Legacy(Box::new(state))
        }
    }

    pub fn state(&self) -> &State {
        match self {
            Self::Legacy(state) => state,
            Self::Current(state) => state,
        }
    }

    /// Returns true if the durable nonce is not in the blockhash domain.
    pub fn separate_domains(&self) -> bool {
        match self {
            Self::Legacy(_) => false,
            Self::Current(_) => true,
        }
    }

    /// Checks if the recent_blockhash field in Transaction verifies, and
    /// returns nonce account data if so.
    pub fn verify_recent_blockhash(
        &self,
        recent_blockhash: &Hash, // Transaction.message.recent_blockhash
        separate_domains: bool,
    ) -> Option<&Data> {
        let state = match self {
            Self::Legacy(state) => {
                if separate_domains {
                    // Legacy durable nonces are invalid and should not
                    // allow durable transactions.
                    return None;
                } else {
                    state
                }
            }
            Self::Current(state) => state,
        };
        match **state {
            State::Uninitialized => None,
            State::Initialized(ref data) => (recent_blockhash == &data.blockhash()).then(|| data),
        }
    }

    // Upgrades legacy nonces out of chain blockhash domains.
    pub fn upgrade(self) -> Option<Self> {
        match self {
            Self::Legacy(mut state) => {
                match *state {
                    // An Uninitialized legacy nonce cannot verify a durable
                    // transaction. The nonce will be upgraded to Current
                    // version when initialized. Therefore there is no need to
                    // upgrade Uninitialized legacy nonces.
                    State::Uninitialized => None,
                    State::Initialized(ref mut data) => {
                        data.durable_nonce = DurableNonce::from_blockhash(
                            &data.blockhash(),
                            true, // separate_domains
                        );
                        Some(Self::Current(state))
                    }
                }
            }
            Self::Current(_) => None,
        }
    }
}

impl From<Versions> for State {
    fn from(versions: Versions) -> Self {
        match versions {
            Versions::Legacy(state) => *state,
            Versions::Current(state) => *state,
        }
    }
}
