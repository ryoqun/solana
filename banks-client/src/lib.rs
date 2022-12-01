//! A client for the ledger state, from the perspective of an arbitrary validator.
//!
//! Use start_tcp_client() to create a client and then import BanksClientExt to
//! access its methods. Additional "*_with_context" methods are also available,
//! but they are undocumented, may change over time, and are generally more
//! cumbersome to use.

pub use {
    crate::error::BanksClientError,
    solana_banks_interface::{BanksClient as TarpcClient, TransactionStatus},
};
use {
    borsh::BorshDeserialize,
    futures::{future::join_all, Future, FutureExt, TryFutureExt},
    solana_banks_interface::{
        BanksRequest, BanksResponse, BanksTransactionResultWithMetadata,
        BanksTransactionResultWithSimulation,
    },
    solana_program::{
        clock::Slot, fee_calculator::FeeCalculator, hash::Hash, program_pack::Pack, pubkey::Pubkey,
        rent::Rent, sysvar::Sysvar,
    },
    solana_sdk::{
        account::{from_account, Account},
        commitment_config::CommitmentLevel,
        message::Message,
        signature::Signature,
        transaction::{self, Transaction, VersionedTransaction},
    },
    tarpc::{
        client::{self, NewClient, RequestDispatch},
        context::{self, Context},
        serde_transport::tcp,
        ClientMessage, Response, Transport,
    },
    tokio::{net::ToSocketAddrs, time::Duration},
    tokio_serde::formats::Bincode,
};

mod error;

// This exists only for backward compatibility
pub trait BanksClientExt {}

#[derive(Clone)]
pub struct BanksClient {
    inner: TarpcClient,
}

impl BanksClient {
    #[allow(clippy::new_ret_no_self)]
    pub fn new<C>(
        config: client::Config,
        transport: C,
    ) -> NewClient<TarpcClient, RequestDispatch<BanksRequest, BanksResponse, C>>
    where
        C: Transport<ClientMessage<BanksRequest>, Response<BanksResponse>>,
    {
        TarpcClient::new(config, transport)
    }

    pub fn send_transaction_with_context(
        &mut self,
        ctx: Context,
        transaction: impl Into<VersionedTransaction>,
    ) -> impl Future<Output = Result<(), BanksClientError>> + '_ {
        self.inner
            .send_transaction_with_context(ctx, transaction.into())
            .map_err(Into::into)
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please use `get_fee_for_message` or `is_blockhash_valid` instead"
    )]
    pub fn get_fees_with_commitment_and_context(
        &mut self,
        ctx: Context,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<(FeeCalculator, Hash, u64), BanksClientError>> + '_ {
        #[allow(deprecated)]
        self.inner
            .get_fees_with_commitment_and_context(ctx, commitment)
            .map_err(Into::into)
    }

    pub fn get_transaction_status_with_context(
        &mut self,
        ctx: Context,
        signature: Signature,
    ) -> impl Future<Output = Result<Option<TransactionStatus>, BanksClientError>> + '_ {
        self.inner
            .get_transaction_status_with_context(ctx, signature)
            .map_err(Into::into)
    }

    pub fn get_slot_with_context(
        &mut self,
        ctx: Context,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<Slot, BanksClientError>> + '_ {
        self.inner
            .get_slot_with_context(ctx, commitment)
            .map_err(Into::into)
    }

    pub fn get_block_height_with_context(
        &mut self,
        ctx: Context,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<Slot, BanksClientError>> + '_ {
        self.inner
            .get_block_height_with_context(ctx, commitment)
            .map_err(Into::into)
    }

    pub fn process_transaction_with_commitment_and_context(
        &mut self,
        ctx: Context,
        transaction: impl Into<VersionedTransaction>,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<Option<transaction::Result<()>>, BanksClientError>> + '_ {
        self.inner
            .process_transaction_with_commitment_and_context(ctx, transaction.into(), commitment)
            .map_err(Into::into)
    }

    pub fn process_transaction_with_preflight_and_commitment_and_context(
        &mut self,
        ctx: Context,
        transaction: impl Into<VersionedTransaction>,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<BanksTransactionResultWithSimulation, BanksClientError>> + '_
    {
        self.inner
            .process_transaction_with_preflight_and_commitment_and_context(
                ctx,
                transaction.into(),
                commitment,
            )
            .map_err(Into::into)
    }

    pub fn process_transaction_with_metadata_and_context(
        &mut self,
        ctx: Context,
        transaction: impl Into<VersionedTransaction>,
    ) -> impl Future<Output = Result<BanksTransactionResultWithMetadata, BanksClientError>> + '_
    {
        self.inner
            .process_transaction_with_metadata_and_context(ctx, transaction.into())
            .map_err(Into::into)
    }

    pub fn simulate_transaction_with_commitment_and_context(
        &mut self,
        ctx: Context,
        transaction: impl Into<VersionedTransaction>,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<BanksTransactionResultWithSimulation, BanksClientError>> + '_
    {
        self.inner
            .simulate_transaction_with_commitment_and_context(ctx, transaction.into(), commitment)
            .map_err(Into::into)
    }

    pub fn get_account_with_commitment_and_context(
        &mut self,
        ctx: Context,
        address: Pubkey,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<Option<Account>, BanksClientError>> + '_ {
        self.inner
            .get_account_with_commitment_and_context(ctx, address, commitment)
            .map_err(Into::into)
    }

    /// Send a transaction and return immediately. The server will resend the
    /// transaction until either it is accepted by the cluster or the transaction's
    /// blockhash expires.
    pub fn send_transaction(
        &mut self,
        transaction: impl Into<VersionedTransaction>,
    ) -> impl Future<Output = Result<(), BanksClientError>> + '_ {
        self.send_transaction_with_context(context::current(), transaction.into())
    }

    /// Return the fee parameters associated with a recent, rooted blockhash. The cluster
    /// will use the transaction's blockhash to look up these same fee parameters and
    /// use them to calculate the transaction fee.
    #[deprecated(
        since = "1.9.0",
        note = "Please use `get_fee_for_message` or `is_blockhash_valid` instead"
    )]
    pub fn get_fees(
        &mut self,
    ) -> impl Future<Output = Result<(FeeCalculator, Hash, u64), BanksClientError>> + '_ {
        #[allow(deprecated)]
        self.get_fees_with_commitment_and_context(context::current(), CommitmentLevel::default())
    }

    /// Return the cluster Sysvar
    pub fn get_sysvar<T: Sysvar>(
        &mut self,
    ) -> impl Future<Output = Result<T, BanksClientError>> + '_ {
        self.get_account(T::id()).map(|result| {
            let sysvar = result?.ok_or(BanksClientError::ClientError("Sysvar not present"))?;
            from_account::<T, _>(&sysvar).ok_or(BanksClientError::ClientError(
                "Failed to deserialize sysvar",
            ))
        })
    }

    /// Return the cluster rent
    pub fn get_rent(&mut self) -> impl Future<Output = Result<Rent, BanksClientError>> + '_ {
        self.get_sysvar::<Rent>()
    }

    /// Return a recent, rooted blockhash from the server. The cluster will only accept
    /// transactions with a blockhash that has not yet expired. Use the `get_fees`
    /// method to get both a blockhash and the blockhash's last valid slot.
    #[deprecated(since = "1.9.0", note = "Please use `get_latest_blockhash` instead")]
    pub fn get_recent_blockhash(
        &mut self,
    ) -> impl Future<Output = Result<Hash, BanksClientError>> + '_ {
        #[allow(deprecated)]
        self.get_fees().map(|result| Ok(result?.1))
    }

    /// Send a transaction and return after the transaction has been rejected or
    /// reached the given level of commitment.
    pub fn process_transaction_with_commitment(
        &mut self,
        transaction: Transaction,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<(), BanksClientError>> + '_ {
        let mut ctx = context::current();
        ctx.deadline += Duration::from_secs(50);
        self.process_transaction_with_commitment_and_context(ctx, transaction, commitment)
            .map(|result| match result? {
                None => Err(BanksClientError::ClientError(
                    "invalid blockhash or fee-payer",
                )),
                Some(transaction_result) => Ok(transaction_result?),
            })
    }

    /// Process a transaction and return the result with metadata.
    pub fn process_transaction_with_metadata(
        &mut self,
        transaction: impl Into<VersionedTransaction>,
    ) -> impl Future<Output = Result<BanksTransactionResultWithMetadata, BanksClientError>> + '_
    {
        let mut ctx = context::current();
        ctx.deadline += Duration::from_secs(50);
        self.process_transaction_with_metadata_and_context(ctx, transaction.into())
    }

    /// Send a transaction and return any preflight (sanitization or simulation) errors, or return
    /// after the transaction has been rejected or reached the given level of commitment.
    pub fn process_transaction_with_preflight_and_commitment(
        &mut self,
        transaction: Transaction,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<(), BanksClientError>> + '_ {
        let mut ctx = context::current();
        ctx.deadline += Duration::from_secs(50);
        self.process_transaction_with_preflight_and_commitment_and_context(
            ctx,
            transaction,
            commitment,
        )
        .map(|result| match result? {
            BanksTransactionResultWithSimulation {
                result: None,
                simulation_details: _,
            } => Err(BanksClientError::ClientError(
                "invalid blockhash or fee-payer",
            )),
            BanksTransactionResultWithSimulation {
                result: Some(Err(err)),
                simulation_details: Some(simulation_details),
            } => Err(BanksClientError::SimulationError {
                err,
                logs: simulation_details.logs,
                units_consumed: simulation_details.units_consumed,
                return_data: simulation_details.return_data,
            }),
            BanksTransactionResultWithSimulation {
                result: Some(result),
                simulation_details: _,
            } => result.map_err(Into::into),
        })
    }

    /// Send a transaction and return any preflight (sanitization or simulation) errors, or return
    /// after the transaction has been finalized or rejected.
    pub fn process_transaction_with_preflight(
        &mut self,
        transaction: Transaction,
    ) -> impl Future<Output = Result<(), BanksClientError>> + '_ {
        self.process_transaction_with_preflight_and_commitment(
            transaction,
            CommitmentLevel::default(),
        )
    }

    /// Send a transaction and return until the transaction has been finalized or rejected.
    pub fn process_transaction(
        &mut self,
        transaction: Transaction,
    ) -> impl Future<Output = Result<(), BanksClientError>> + '_ {
        self.process_transaction_with_commitment(transaction, CommitmentLevel::default())
    }

    pub async fn process_transactions_with_commitment(
        &mut self,
        transactions: Vec<Transaction>,
        commitment: CommitmentLevel,
    ) -> Result<(), BanksClientError> {
        let mut clients: Vec<_> = transactions.iter().map(|_| self.clone()).collect();
        let futures = clients
            .iter_mut()
            .zip(transactions)
            .map(|(client, transaction)| {
                client.process_transaction_with_commitment(transaction, commitment)
            });
        let statuses = join_all(futures).await;
        statuses.into_iter().collect() // Convert Vec<Result<_, _>> to Result<Vec<_>>
    }

    /// Send transactions and return until the transaction has been finalized or rejected.
    pub fn process_transactions(
        &mut self,
        transactions: Vec<Transaction>,
    ) -> impl Future<Output = Result<(), BanksClientError>> + '_ {
        self.process_transactions_with_commitment(transactions, CommitmentLevel::default())
    }

    /// Simulate a transaction at the given commitment level
    pub fn simulate_transaction_with_commitment(
        &mut self,
        transaction: Transaction,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<BanksTransactionResultWithSimulation, BanksClientError>> + '_
    {
        self.simulate_transaction_with_commitment_and_context(
            context::current(),
            transaction,
            commitment,
        )
    }

    /// Simulate a transaction at the default commitment level
    pub fn simulate_transaction(
        &mut self,
        transaction: Transaction,
    ) -> impl Future<Output = Result<BanksTransactionResultWithSimulation, BanksClientError>> + '_
    {
        self.simulate_transaction_with_commitment(transaction, CommitmentLevel::default())
    }

    /// Return the most recent rooted slot. All transactions at or below this slot
    /// are said to be finalized. The cluster will not fork to a higher slot.
    pub fn get_root_slot(&mut self) -> impl Future<Output = Result<Slot, BanksClientError>> + '_ {
        self.get_slot_with_context(context::current(), CommitmentLevel::default())
    }

    /// Return the most recent rooted block height. All transactions at or below this height
    /// are said to be finalized. The cluster will not fork to a higher block height.
    pub fn get_root_block_height(
        &mut self,
    ) -> impl Future<Output = Result<Slot, BanksClientError>> + '_ {
        self.get_block_height_with_context(context::current(), CommitmentLevel::default())
    }

    /// Return the account at the given address at the slot corresponding to the given
    /// commitment level. If the account is not found, None is returned.
    pub fn get_account_with_commitment(
        &mut self,
        address: Pubkey,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<Option<Account>, BanksClientError>> + '_ {
        self.get_account_with_commitment_and_context(context::current(), address, commitment)
    }

    /// Return the account at the given address at the time of the most recent root slot.
    /// If the account is not found, None is returned.
    pub fn get_account(
        &mut self,
        address: Pubkey,
    ) -> impl Future<Output = Result<Option<Account>, BanksClientError>> + '_ {
        self.get_account_with_commitment(address, CommitmentLevel::default())
    }

    /// Return the unpacked account data at the given address
    /// If the account is not found, an error is returned
    pub fn get_packed_account_data<T: Pack>(
        &mut self,
        address: Pubkey,
    ) -> impl Future<Output = Result<T, BanksClientError>> + '_ {
        self.get_account(address).map(|result| {
            let account = result?.ok_or(BanksClientError::ClientError("Account not found"))?;
            T::unpack_from_slice(&account.data)
                .map_err(|_| BanksClientError::ClientError("Failed to deserialize account"))
        })
    }

    /// Return the unpacked account data at the given address
    /// If the account is not found, an error is returned
    pub fn get_account_data_with_borsh<T: BorshDeserialize>(
        &mut self,
        address: Pubkey,
    ) -> impl Future<Output = Result<T, BanksClientError>> + '_ {
        self.get_account(address).map(|result| {
            let account = result?.ok_or(BanksClientError::ClientError("Account not found"))?;
            T::try_from_slice(&account.data).map_err(Into::into)
        })
    }

    /// Return the balance in lamports of an account at the given address at the slot
    /// corresponding to the given commitment level.
    pub fn get_balance_with_commitment(
        &mut self,
        address: Pubkey,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<u64, BanksClientError>> + '_ {
        self.get_account_with_commitment_and_context(context::current(), address, commitment)
            .map(|result| Ok(result?.map(|x| x.lamports).unwrap_or(0)))
    }

    /// Return the balance in lamports of an account at the given address at the time
    /// of the most recent root slot.
    pub fn get_balance(
        &mut self,
        address: Pubkey,
    ) -> impl Future<Output = Result<u64, BanksClientError>> + '_ {
        self.get_balance_with_commitment(address, CommitmentLevel::default())
    }

    /// Return the status of a transaction with a signature matching the transaction's first
    /// signature. Return None if the transaction is not found, which may be because the
    /// blockhash was expired or the fee-paying account had insufficient funds to pay the
    /// transaction fee. Note that servers rarely store the full transaction history. This
    /// method may return None if the transaction status has been discarded.
    pub fn get_transaction_status(
        &mut self,
        signature: Signature,
    ) -> impl Future<Output = Result<Option<TransactionStatus>, BanksClientError>> + '_ {
        self.get_transaction_status_with_context(context::current(), signature)
    }

    /// Same as get_transaction_status, but for multiple transactions.
    pub async fn get_transaction_statuses(
        &mut self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, BanksClientError> {
        // tarpc futures oddly hold a mutable reference back to the client so clone the client upfront
        let mut clients_and_signatures: Vec<_> = signatures
            .into_iter()
            .map(|signature| (self.clone(), signature))
            .collect();

        let futs = clients_and_signatures
            .iter_mut()
            .map(|(client, signature)| client.get_transaction_status(*signature));

        let statuses = join_all(futs).await;

        // Convert Vec<Result<_, _>> to Result<Vec<_>>
        statuses.into_iter().collect()
    }

    pub fn get_latest_blockhash(
        &mut self,
    ) -> impl Future<Output = Result<Hash, BanksClientError>> + '_ {
        self.get_latest_blockhash_with_commitment(CommitmentLevel::default())
            .map(|result| {
                result?
                    .map(|x| x.0)
                    .ok_or(BanksClientError::ClientError("valid blockhash not found"))
                    .map_err(Into::into)
            })
    }

    pub fn get_latest_blockhash_with_commitment(
        &mut self,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<Option<(Hash, u64)>, BanksClientError>> + '_ {
        self.get_latest_blockhash_with_commitment_and_context(context::current(), commitment)
    }

    pub fn get_latest_blockhash_with_commitment_and_context(
        &mut self,
        ctx: Context,
        commitment: CommitmentLevel,
    ) -> impl Future<Output = Result<Option<(Hash, u64)>, BanksClientError>> + '_ {
        self.inner
            .get_latest_blockhash_with_commitment_and_context(ctx, commitment)
            .map_err(Into::into)
    }

    pub fn get_fee_for_message_with_commitment_and_context(
        &mut self,
        ctx: Context,
        commitment: CommitmentLevel,
        message: Message,
    ) -> impl Future<Output = Result<Option<u64>, BanksClientError>> + '_ {
        self.inner
            .get_fee_for_message_with_commitment_and_context(ctx, commitment, message)
            .map_err(Into::into)
    }
}

pub async fn start_client<C>(transport: C) -> Result<BanksClient, BanksClientError>
where
    C: Transport<ClientMessage<BanksRequest>, Response<BanksResponse>> + Send + 'static,
{
    Ok(BanksClient {
        inner: TarpcClient::new(client::Config::default(), transport).spawn(),
    })
}

pub async fn start_tcp_client<T: ToSocketAddrs>(addr: T) -> Result<BanksClient, BanksClientError> {
    let transport = tcp::connect(addr, Bincode::default).await?;
    Ok(BanksClient {
        inner: TarpcClient::new(client::Config::default(), transport).spawn(),
    })
}

