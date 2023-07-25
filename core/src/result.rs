//! The `result` module exposes a Result type that propagates one of many different Error types.

use {
    crate::serve_repair::RepairVerifyError,
    solana_gossip::{cluster_info, contact_info, gossip_error::GossipError},
    solana_ledger::blockstore,
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Blockstore(#[from] blockstore::BlockstoreError),
    #[error(transparent)]
    ClusterInfo(#[from] cluster_info::ClusterInfoError),
    #[error(transparent)]
    Gossip(#[from] GossipError),
    #[error(transparent)]
    InvalidContactInfo(#[from] contact_info::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("ReadyTimeout")]
    ReadyTimeout,
    #[error(transparent)]
    Recv(#[from] crossbeam_channel::RecvError),
    #[error(transparent)]
    RecvTimeout(#[from] crossbeam_channel::RecvTimeoutError),
    #[error("Send")]
    Send,
    #[error("TrySend")]
    TrySend,
    #[error(transparent)]
    Serialize(#[from] std::boxed::Box<bincode::ErrorKind>),
    #[error(transparent)]
    WeightedIndex(#[from] rand::distributions::weighted::WeightedError),
    #[error(transparent)]
    RepairVerify(#[from] RepairVerifyError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::convert::From<crossbeam_channel::ReadyTimeoutError> for Error {
    fn from(_e: crossbeam_channel::ReadyTimeoutError) -> Error {
        Error::ReadyTimeout
    }
}
impl<T> std::convert::From<crossbeam_channel::TrySendError<T>> for Error {
    fn from(_e: crossbeam_channel::TrySendError<T>) -> Error {
        Error::TrySend
    }
}
impl<T> std::convert::From<crossbeam_channel::SendError<T>> for Error {
    fn from(_e: crossbeam_channel::SendError<T>) -> Error {
        Error::Send
    }
}
