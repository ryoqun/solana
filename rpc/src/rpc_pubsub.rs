//! The `pubsub` module implements a threaded subscription service on client RPC request
use {
    crate::{
        rpc::check_is_at_least_confirmed,
        rpc_pubsub_service::PubSubConfig,
        rpc_subscription_tracker::{
            AccountSubscriptionParams, BlockSubscriptionKind, BlockSubscriptionParams,
            LogsSubscriptionKind, LogsSubscriptionParams, ProgramSubscriptionParams,
            SignatureSubscriptionParams, SubscriptionControl, SubscriptionId, SubscriptionParams,
            SubscriptionToken,
        },
    },
    dashmap::DashMap,
    jsonrpc_core::{Error, ErrorCode, Result},
    jsonrpc_derive::rpc,
    jsonrpc_pubsub::{typed::Subscriber, SubscriptionId as PubSubSubscriptionId},
    solana_account_decoder::{UiAccount, UiAccountEncoding},
    solana_rpc_client_api::{
        config::{
            RpcAccountInfoConfig, RpcBlockSubscribeConfig, RpcBlockSubscribeFilter,
            RpcProgramAccountsConfig, RpcSignatureSubscribeConfig, RpcTransactionLogsConfig,
            RpcTransactionLogsFilter,
        },
        response::{
            Response as RpcResponse, RpcBlockUpdate, RpcKeyedAccount, RpcLogsResponse,
            RpcSignatureResult, RpcVersionInfo, RpcVote, SlotInfo, SlotUpdate,
        },
    },
    solana_sdk::{clock::Slot, pubkey::Pubkey, signature::Signature},
    solana_transaction_status::UiTransactionEncoding,
    std::{str::FromStr, sync::Arc},
};

// We have to keep both of the following traits to not break backwards compatibility.
// `RpcSolPubSubInternal` is actually used by the current PubSub API implementation.
// `RpcSolPubSub` and the corresponding `gen_client` module are preserved
// so the clients reliant on `gen_client::Client` do not break after this implementation is released.
//
// There are no compile-time checks that ensure coherence between traits
// so extra attention is required when adding a new method to the API.

// Suppress needless_return due to
//   https://github.com/paritytech/jsonrpc/blob/2d38e6424d8461cdf72e78425ce67d51af9c6586/derive/src/lib.rs#L204
// Once https://github.com/paritytech/jsonrpc/issues/418 is resolved, try to remove this clippy allow
#[allow(clippy::needless_return)]
#[rpc]
pub trait RpcSolPubSub {
    type Metadata;

    // Get notification every time account data is changed
    // Accepts pubkey parameter as base-58 encoded string
    #[pubsub(
        subscription = "accountNotification",
        subscribe,
        name = "accountSubscribe"
    )]
    fn account_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: Subscriber<RpcResponse<UiAccount>>,
        pubkey_str: String,
        config: Option<RpcAccountInfoConfig>,
    );

    // Unsubscribe from account notification subscription.
    #[pubsub(
        subscription = "accountNotification",
        unsubscribe,
        name = "accountUnsubscribe"
    )]
    fn account_unsubscribe(
        &self,
        meta: Option<Self::Metadata>,
        id: PubSubSubscriptionId,
    ) -> Result<bool>;

    // Get notification every time account data owned by a particular program is changed
    // Accepts pubkey parameter as base-58 encoded string
    #[pubsub(
        subscription = "programNotification",
        subscribe,
        name = "programSubscribe"
    )]
    fn program_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: Subscriber<RpcResponse<RpcKeyedAccount>>,
        pubkey_str: String,
        config: Option<RpcProgramAccountsConfig>,
    );

    // Unsubscribe from account notification subscription.
    #[pubsub(
        subscription = "programNotification",
        unsubscribe,
        name = "programUnsubscribe"
    )]
    fn program_unsubscribe(
        &self,
        meta: Option<Self::Metadata>,
        id: PubSubSubscriptionId,
    ) -> Result<bool>;

    // Get logs for all transactions that reference the specified address
    #[pubsub(subscription = "logsNotification", subscribe, name = "logsSubscribe")]
    fn logs_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: Subscriber<RpcResponse<RpcLogsResponse>>,
        filter: RpcTransactionLogsFilter,
        config: Option<RpcTransactionLogsConfig>,
    );

    // Unsubscribe from logs notification subscription.
    #[pubsub(
        subscription = "logsNotification",
        unsubscribe,
        name = "logsUnsubscribe"
    )]
    fn logs_unsubscribe(
        &self,
        meta: Option<Self::Metadata>,
        id: PubSubSubscriptionId,
    ) -> Result<bool>;

    // Get notification when signature is verified
    // Accepts signature parameter as base-58 encoded string
    #[pubsub(
        subscription = "signatureNotification",
        subscribe,
        name = "signatureSubscribe"
    )]
    fn signature_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: Subscriber<RpcResponse<RpcSignatureResult>>,
        signature_str: String,
        config: Option<RpcSignatureSubscribeConfig>,
    );

    // Unsubscribe from signature notification subscription.
    #[pubsub(
        subscription = "signatureNotification",
        unsubscribe,
        name = "signatureUnsubscribe"
    )]
    fn signature_unsubscribe(
        &self,
        meta: Option<Self::Metadata>,
        id: PubSubSubscriptionId,
    ) -> Result<bool>;

    // Get notification when slot is encountered
    #[pubsub(subscription = "slotNotification", subscribe, name = "slotSubscribe")]
    fn slot_subscribe(&self, meta: Self::Metadata, subscriber: Subscriber<SlotInfo>);

    // Unsubscribe from slot notification subscription.
    #[pubsub(
        subscription = "slotNotification",
        unsubscribe,
        name = "slotUnsubscribe"
    )]
    fn slot_unsubscribe(
        &self,
        meta: Option<Self::Metadata>,
        id: PubSubSubscriptionId,
    ) -> Result<bool>;

    // Get series of updates for all slots
    #[pubsub(
        subscription = "slotsUpdatesNotification",
        subscribe,
        name = "slotsUpdatesSubscribe"
    )]
    fn slots_updates_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: Subscriber<Arc<SlotUpdate>>,
    );

    // Unsubscribe from slots updates notification subscription.
    #[pubsub(
        subscription = "slotsUpdatesNotification",
        unsubscribe,
        name = "slotsUpdatesUnsubscribe"
    )]
    fn slots_updates_unsubscribe(
        &self,
        meta: Option<Self::Metadata>,
        id: PubSubSubscriptionId,
    ) -> Result<bool>;

    // Subscribe to block data and content
    #[pubsub(subscription = "blockNotification", subscribe, name = "blockSubscribe")]
    fn block_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: Subscriber<Arc<RpcBlockUpdate>>,
        filter: RpcBlockSubscribeFilter,
        config: Option<RpcBlockSubscribeConfig>,
    );

    // Unsubscribe from block notification subscription.
    #[pubsub(
        subscription = "blockNotification",
        unsubscribe,
        name = "blockUnsubscribe"
    )]
    fn block_unsubscribe(
        &self,
        meta: Option<Self::Metadata>,
        id: PubSubSubscriptionId,
    ) -> Result<bool>;

    // Get notification when vote is encountered
    #[pubsub(subscription = "voteNotification", subscribe, name = "voteSubscribe")]
    fn vote_subscribe(&self, meta: Self::Metadata, subscriber: Subscriber<RpcVote>);

    // Unsubscribe from vote notification subscription.
    #[pubsub(
        subscription = "voteNotification",
        unsubscribe,
        name = "voteUnsubscribe"
    )]
    fn vote_unsubscribe(
        &self,
        meta: Option<Self::Metadata>,
        id: PubSubSubscriptionId,
    ) -> Result<bool>;

    // Get notification when a new root is set
    #[pubsub(subscription = "rootNotification", subscribe, name = "rootSubscribe")]
    fn root_subscribe(&self, meta: Self::Metadata, subscriber: Subscriber<Slot>);

    // Unsubscribe from slot notification subscription.
    #[pubsub(
        subscription = "rootNotification",
        unsubscribe,
        name = "rootUnsubscribe"
    )]
    fn root_unsubscribe(
        &self,
        meta: Option<Self::Metadata>,
        id: PubSubSubscriptionId,
    ) -> Result<bool>;
}

pub use internal::RpcSolPubSubInternal;

// We have to use a separate module so the code generated by different `rpc` macro invocations do not interfere with each other.
mod internal {
    use super::*;

    #[rpc]
    pub trait RpcSolPubSubInternal {
        // Get notification every time account data is changed
        // Accepts pubkey parameter as base-58 encoded string
        #[rpc(name = "accountSubscribe")]
        fn account_subscribe(
            &self,
            pubkey_str: String,
            config: Option<RpcAccountInfoConfig>,
        ) -> Result<SubscriptionId>;

        // Unsubscribe from account notification subscription.
        #[rpc(name = "accountUnsubscribe")]
        fn account_unsubscribe(&self, id: SubscriptionId) -> Result<bool>;

        // Get notification every time account data owned by a particular program is changed
        // Accepts pubkey parameter as base-58 encoded string
        #[rpc(name = "programSubscribe")]
        fn program_subscribe(
            &self,
            pubkey_str: String,
            config: Option<RpcProgramAccountsConfig>,
        ) -> Result<SubscriptionId>;

        // Unsubscribe from account notification subscription.
        #[rpc(name = "programUnsubscribe")]
        fn program_unsubscribe(&self, id: SubscriptionId) -> Result<bool>;

        // Get logs for all transactions that reference the specified address
        #[rpc(name = "logsSubscribe")]
        fn logs_subscribe(
            &self,
            filter: RpcTransactionLogsFilter,
            config: Option<RpcTransactionLogsConfig>,
        ) -> Result<SubscriptionId>;

        // Unsubscribe from logs notification subscription.
        #[rpc(name = "logsUnsubscribe")]
        fn logs_unsubscribe(&self, id: SubscriptionId) -> Result<bool>;

        // Get notification when signature is verified
        // Accepts signature parameter as base-58 encoded string
        #[rpc(name = "signatureSubscribe")]
        fn signature_subscribe(
            &self,
            signature_str: String,
            config: Option<RpcSignatureSubscribeConfig>,
        ) -> Result<SubscriptionId>;

        // Unsubscribe from signature notification subscription.
        #[rpc(name = "signatureUnsubscribe")]
        fn signature_unsubscribe(&self, id: SubscriptionId) -> Result<bool>;

        // Get notification when slot is encountered
        #[rpc(name = "slotSubscribe")]
        fn slot_subscribe(&self) -> Result<SubscriptionId>;

        // Unsubscribe from slot notification subscription.
        #[rpc(name = "slotUnsubscribe")]
        fn slot_unsubscribe(&self, id: SubscriptionId) -> Result<bool>;

        // Get series of updates for all slots
        #[rpc(name = "slotsUpdatesSubscribe")]
        fn slots_updates_subscribe(&self) -> Result<SubscriptionId>;

        // Unsubscribe from slots updates notification subscription.
        #[rpc(name = "slotsUpdatesUnsubscribe")]
        fn slots_updates_unsubscribe(&self, id: SubscriptionId) -> Result<bool>;

        // Subscribe to block data and content
        #[rpc(name = "blockSubscribe")]
        fn block_subscribe(
            &self,
            filter: RpcBlockSubscribeFilter,
            config: Option<RpcBlockSubscribeConfig>,
        ) -> Result<SubscriptionId>;

        // Unsubscribe from block notification subscription.
        #[rpc(name = "blockUnsubscribe")]
        fn block_unsubscribe(&self, id: SubscriptionId) -> Result<bool>;

        // Get notification when vote is encountered
        #[rpc(name = "voteSubscribe")]
        fn vote_subscribe(&self) -> Result<SubscriptionId>;

        // Unsubscribe from vote notification subscription.
        #[rpc(name = "voteUnsubscribe")]
        fn vote_unsubscribe(&self, id: SubscriptionId) -> Result<bool>;

        // Get notification when a new root is set
        #[rpc(name = "rootSubscribe")]
        fn root_subscribe(&self) -> Result<SubscriptionId>;

        // Unsubscribe from slot notification subscription.
        #[rpc(name = "rootUnsubscribe")]
        fn root_unsubscribe(&self, id: SubscriptionId) -> Result<bool>;

        // Get the current solana version running on the node
        #[rpc(name = "getVersion")]
        fn get_version(&self) -> Result<RpcVersionInfo>;
    }
}

pub struct RpcSolPubSubImpl {
    config: PubSubConfig,
    subscription_control: SubscriptionControl,
    current_subscriptions: Arc<DashMap<SubscriptionId, SubscriptionToken>>,
}

impl RpcSolPubSubImpl {
    pub fn new(
        config: PubSubConfig,
        subscription_control: SubscriptionControl,
        current_subscriptions: Arc<DashMap<SubscriptionId, SubscriptionToken>>,
    ) -> Self {
        Self {
            config,
            subscription_control,
            current_subscriptions,
        }
    }

    fn subscribe(&self, params: SubscriptionParams) -> Result<SubscriptionId> {
        let token = self
            .subscription_control
            .subscribe(params)
            .map_err(|_| Error {
                code: ErrorCode::InternalError,
                message: "Internal Error: Subscription refused. Node subscription limit reached"
                    .into(),
                data: None,
            })?;
        let id = token.id();
        self.current_subscriptions.insert(id, token);
        Ok(id)
    }

    fn unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        if self.current_subscriptions.remove(&id).is_some() {
            Ok(true)
        } else {
            Err(Error {
                code: ErrorCode::InvalidParams,
                message: "Invalid subscription id.".into(),
                data: None,
            })
        }
    }
}

fn param<T: FromStr>(param_str: &str, thing: &str) -> Result<T> {
    param_str.parse::<T>().map_err(|_e| Error {
        code: ErrorCode::InvalidParams,
        message: format!("Invalid Request: Invalid {thing} provided"),
        data: None,
    })
}

impl RpcSolPubSubInternal for RpcSolPubSubImpl {
    fn account_subscribe(
        &self,
        pubkey_str: String,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<SubscriptionId> {
        let RpcAccountInfoConfig {
            encoding,
            data_slice,
            commitment,
            min_context_slot: _, // ignored
        } = config.unwrap_or_default();
        let params = AccountSubscriptionParams {
            pubkey: param::<Pubkey>(&pubkey_str, "pubkey")?,
            commitment: commitment.unwrap_or_default(),
            data_slice,
            encoding: encoding.unwrap_or(UiAccountEncoding::Binary),
        };
        self.subscribe(SubscriptionParams::Account(params))
    }

    fn account_unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        self.unsubscribe(id)
    }

    fn program_subscribe(
        &self,
        pubkey_str: String,
        config: Option<RpcProgramAccountsConfig>,
    ) -> Result<SubscriptionId> {
        let config = config.unwrap_or_default();
        let params = ProgramSubscriptionParams {
            pubkey: param::<Pubkey>(&pubkey_str, "pubkey")?,
            filters: config.filters.unwrap_or_default(),
            encoding: config
                .account_config
                .encoding
                .unwrap_or(UiAccountEncoding::Binary),
            data_slice: config.account_config.data_slice,
            commitment: config.account_config.commitment.unwrap_or_default(),
            with_context: config.with_context.unwrap_or_default(),
        };
        self.subscribe(SubscriptionParams::Program(params))
    }

    fn program_unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        self.unsubscribe(id)
    }

    fn logs_subscribe(
        &self,
        filter: RpcTransactionLogsFilter,
        config: Option<RpcTransactionLogsConfig>,
    ) -> Result<SubscriptionId> {
        let params = LogsSubscriptionParams {
            kind: match filter {
                RpcTransactionLogsFilter::All => LogsSubscriptionKind::All,
                RpcTransactionLogsFilter::AllWithVotes => LogsSubscriptionKind::AllWithVotes,
                RpcTransactionLogsFilter::Mentions(keys) => {
                    if keys.len() != 1 {
                        return Err(Error {
                            code: ErrorCode::InvalidParams,
                            message: "Invalid Request: Only 1 address supported".into(),
                            data: None,
                        });
                    }
                    LogsSubscriptionKind::Single(param::<Pubkey>(&keys[0], "mentions")?)
                }
            },
            commitment: config.and_then(|c| c.commitment).unwrap_or_default(),
        };
        self.subscribe(SubscriptionParams::Logs(params))
    }

    fn logs_unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        self.unsubscribe(id)
    }

    fn signature_subscribe(
        &self,
        signature_str: String,
        config: Option<RpcSignatureSubscribeConfig>,
    ) -> Result<SubscriptionId> {
        let config = config.unwrap_or_default();
        let params = SignatureSubscriptionParams {
            signature: param::<Signature>(&signature_str, "signature")?,
            commitment: config.commitment.unwrap_or_default(),
            enable_received_notification: config.enable_received_notification.unwrap_or_default(),
        };
        self.subscribe(SubscriptionParams::Signature(params))
    }

    fn signature_unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        self.unsubscribe(id)
    }

    fn slot_subscribe(&self) -> Result<SubscriptionId> {
        self.subscribe(SubscriptionParams::Slot)
    }

    fn slot_unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        self.unsubscribe(id)
    }

    fn slots_updates_subscribe(&self) -> Result<SubscriptionId> {
        self.subscribe(SubscriptionParams::SlotsUpdates)
    }

    fn slots_updates_unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        self.unsubscribe(id)
    }

    fn block_subscribe(
        &self,
        filter: RpcBlockSubscribeFilter,
        config: Option<RpcBlockSubscribeConfig>,
    ) -> Result<SubscriptionId> {
        if !self.config.enable_block_subscription {
            return Err(Error::new(jsonrpc_core::ErrorCode::MethodNotFound));
        }
        let config = config.unwrap_or_default();
        let commitment = config.commitment.unwrap_or_default();
        check_is_at_least_confirmed(commitment)?;
        let params = BlockSubscriptionParams {
            commitment: config.commitment.unwrap_or_default(),
            encoding: config.encoding.unwrap_or(UiTransactionEncoding::Base64),
            kind: match filter {
                RpcBlockSubscribeFilter::All => BlockSubscriptionKind::All,
                RpcBlockSubscribeFilter::MentionsAccountOrProgram(key) => {
                    BlockSubscriptionKind::MentionsAccountOrProgram(param::<Pubkey>(
                        &key,
                        "mentions_account_or_program",
                    )?)
                }
            },
            transaction_details: config.transaction_details.unwrap_or_default(),
            show_rewards: config.show_rewards.unwrap_or_default(),
            max_supported_transaction_version: config.max_supported_transaction_version,
        };
        self.subscribe(SubscriptionParams::Block(params))
    }

    fn block_unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        if !self.config.enable_block_subscription {
            return Err(Error::new(jsonrpc_core::ErrorCode::MethodNotFound));
        }
        self.unsubscribe(id)
    }

    fn vote_subscribe(&self) -> Result<SubscriptionId> {
        if !self.config.enable_vote_subscription {
            return Err(Error::new(jsonrpc_core::ErrorCode::MethodNotFound));
        }
        self.subscribe(SubscriptionParams::Vote)
    }

    fn vote_unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        if !self.config.enable_vote_subscription {
            return Err(Error::new(jsonrpc_core::ErrorCode::MethodNotFound));
        }
        self.unsubscribe(id)
    }

    fn root_subscribe(&self) -> Result<SubscriptionId> {
        self.subscribe(SubscriptionParams::Root)
    }

    fn root_unsubscribe(&self, id: SubscriptionId) -> Result<bool> {
        self.unsubscribe(id)
    }

    fn get_version(&self) -> Result<RpcVersionInfo> {
        let version = solana_version::Version::default();
        Ok(RpcVersionInfo {
            solana_core: version.to_string(),
            feature_set: Some(version.feature_set),
        })
    }
}
