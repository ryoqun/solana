//! RuntimeTransaction is `runtime` facing representation of transaction, while
//! solana_sdk::SanitizedTransaction is client facing representation.
//!
//! It has two states:
//! 1. Statically Loaded: after receiving `packet` from sigverify and deserializing
//!    it into `solana_sdk::VersionedTransaction`, then sanitizing into
//!    `solana_sdk::SanitizedVersionedTransaction`, which can be wrapped into
//!    `RuntimeTransaction` with static transaction metadata extracted.
//! 2. Dynamically Loaded: after successfully loaded account addresses from onchain
//!    ALT, RuntimeTransaction<SanitizedMessage> transits into Dynamically Loaded state,
//!    with its dynamic metadata loaded.
use {
    crate::transaction_meta::{DynamicMeta, StaticMeta, TransactionMeta},
    solana_compute_budget::compute_budget_processor::{
        process_compute_budget_instructions, ComputeBudgetLimits,
    },
    solana_sdk::{
        hash::Hash,
        message::{AddressLoader, SanitizedMessage, SanitizedVersionedMessage},
        pubkey::Pubkey,
        signature::Signature,
        simple_vote_transaction_checker::is_simple_vote_transaction,
        transaction::{Result, SanitizedVersionedTransaction},
    },
    std::collections::HashSet,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeTransaction<M> {
    signatures: Vec<Signature>,
    message: M,
    // transaction meta is a collection of fields, it is updated
    // during message state transition
    meta: TransactionMeta,
}

// These traits gate access to static and dynamic metadata
// so that only transactions with supporting message types
// can access them.
trait StaticMetaAccess {}
trait DynamicMetaAccess: StaticMetaAccess {}

// Implement the gate traits for the message types that should
// have access to the static and dynamic metadata.
impl StaticMetaAccess for SanitizedVersionedMessage {}
impl StaticMetaAccess for SanitizedMessage {}
impl DynamicMetaAccess for SanitizedMessage {}

impl<M: StaticMetaAccess> StaticMeta for RuntimeTransaction<M> {
    fn message_hash(&self) -> &Hash {
        &self.meta.message_hash
    }
    fn is_simple_vote_tx(&self) -> bool {
        self.meta.is_simple_vote_tx
    }
    fn compute_unit_limit(&self) -> u32 {
        self.meta.compute_unit_limit
    }
    fn compute_unit_price(&self) -> u64 {
        self.meta.compute_unit_price
    }
    fn loaded_accounts_bytes(&self) -> u32 {
        self.meta.loaded_accounts_bytes
    }
}

impl<M: DynamicMetaAccess> DynamicMeta for RuntimeTransaction<M> {}

impl RuntimeTransaction<SanitizedVersionedMessage> {
    pub fn try_from(
        sanitized_versioned_tx: SanitizedVersionedTransaction,
        message_hash: Option<Hash>,
        is_simple_vote_tx: Option<bool>,
    ) -> Result<Self> {
        let mut meta = TransactionMeta::default();
        meta.set_is_simple_vote_tx(
            is_simple_vote_tx
                .unwrap_or_else(|| is_simple_vote_transaction(&sanitized_versioned_tx)),
        );

        let (signatures, message) = sanitized_versioned_tx.destruct();
        meta.set_message_hash(message_hash.unwrap_or_else(|| message.message.hash()));

        let ComputeBudgetLimits {
            compute_unit_limit,
            compute_unit_price,
            loaded_accounts_bytes,
            ..
        } = process_compute_budget_instructions(message.program_instructions_iter())?;
        meta.set_compute_unit_limit(compute_unit_limit);
        meta.set_compute_unit_price(compute_unit_price);
        meta.set_loaded_accounts_bytes(loaded_accounts_bytes);

        Ok(Self {
            signatures,
            message,
            meta,
        })
    }
}

impl RuntimeTransaction<SanitizedMessage> {
    pub fn try_from(
        statically_loaded_runtime_tx: RuntimeTransaction<SanitizedVersionedMessage>,
        address_loader: impl AddressLoader,
        reserved_account_keys: &HashSet<Pubkey>,
    ) -> Result<Self> {
        let mut tx = Self {
            signatures: statically_loaded_runtime_tx.signatures,
            message: SanitizedMessage::try_new(
                statically_loaded_runtime_tx.message,
                address_loader,
                reserved_account_keys,
            )?,
            meta: statically_loaded_runtime_tx.meta,
        };
        tx.load_dynamic_metadata()?;

        Ok(tx)
    }

    fn load_dynamic_metadata(&mut self) -> Result<()> {
        Ok(())
    }
}
