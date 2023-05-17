//! The `rpc` module implements the Solana RPC interface.

use {
    crate::{
        max_slots::MaxSlots, optimistically_confirmed_bank_tracker::OptimisticallyConfirmedBank,
        parsed_token_accounts::*, rpc_cache::LargestAccountsCache, rpc_health::*,
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    bincode::{config::Options, serialize},
    crossbeam_channel::{unbounded, Receiver, Sender},
    jsonrpc_core::{futures::future, types::error, BoxFuture, Error, Metadata, Result},
    jsonrpc_derive::rpc,
    solana_account_decoder::{
        parse_token::{is_known_spl_token_id, token_amount_to_ui_amount, UiTokenAmount},
        UiAccount, UiAccountEncoding, UiDataSliceConfig, MAX_BASE58_BYTES,
    },
    solana_client::connection_cache::{ConnectionCache, Protocol},
    solana_entry::entry::Entry,
    solana_faucet::faucet::request_airdrop_transaction,
    solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
    solana_ledger::{
        blockstore::{Blockstore, SignatureInfosForAddress},
        blockstore_db::BlockstoreError,
        blockstore_meta::{PerfSample, PerfSampleV1, PerfSampleV2},
        get_tmp_ledger_path,
        leader_schedule_cache::LeaderScheduleCache,
    },
    solana_metrics::inc_new_counter_info,
    solana_perf::packet::PACKET_DATA_SIZE,
    solana_rpc_client_api::{
        config::*,
        custom_error::RpcCustomError,
        deprecated_config::*,
        filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType},
        request::{
            TokenAccountsFilter, DELINQUENT_VALIDATOR_SLOT_DISTANCE,
            MAX_GET_CONFIRMED_BLOCKS_RANGE, MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS2_LIMIT,
            MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS_SLOT_RANGE, MAX_GET_PROGRAM_ACCOUNT_FILTERS,
            MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS, MAX_GET_SLOT_LEADERS, MAX_MULTIPLE_ACCOUNTS,
            MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY, NUM_LARGEST_ACCOUNTS,
        },
        response::{Response as RpcResponse, *},
    },
    solana_runtime::{
        accounts::AccountAddressFilter,
        accounts_index::{AccountIndex, AccountSecondaryIndexes, IndexKey, ScanConfig},
        bank::{Bank, TransactionSimulationResult},
        bank_forks::BankForks,
        commitment::{BlockCommitmentArray, BlockCommitmentCache, CommitmentSlots},
        inline_spl_token::{SPL_TOKEN_ACCOUNT_MINT_OFFSET, SPL_TOKEN_ACCOUNT_OWNER_OFFSET},
        inline_spl_token_2022::{self, ACCOUNTTYPE_ACCOUNT},
        non_circulating_supply::calculate_non_circulating_supply,
        prioritization_fee_cache::PrioritizationFeeCache,
        snapshot_config::SnapshotConfig,
        snapshot_utils,
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        account_utils::StateMut,
        clock::{Slot, UnixTimestamp, MAX_RECENT_BLOCKHASHES},
        commitment_config::{CommitmentConfig, CommitmentLevel},
        epoch_info::EpochInfo,
        epoch_schedule::EpochSchedule,
        exit::Exit,
        feature_set,
        fee_calculator::FeeCalculator,
        hash::Hash,
        message::SanitizedMessage,
        pubkey::{Pubkey, PUBKEY_BYTES},
        signature::{Keypair, Signature, Signer},
        stake::state::{StakeActivationStatus, StakeState},
        stake_history::StakeHistory,
        system_instruction,
        sysvar::stake_history,
        transaction::{
            self, AddressLoader, MessageHash, SanitizedTransaction, TransactionError,
            VersionedTransaction, MAX_TX_ACCOUNT_LOCKS,
        },
    },
    solana_send_transaction_service::{
        send_transaction_service::{SendTransactionService, TransactionInfo},
        tpu_info::NullTpuInfo,
    },
    solana_stake_program,
    solana_storage_bigtable::Error as StorageError,
    solana_streamer::socket::SocketAddrSpace,
    solana_transaction_status::{
        BlockEncodingOptions, ConfirmedBlock, ConfirmedTransactionStatusWithSignature,
        ConfirmedTransactionWithStatusMeta, EncodedConfirmedTransactionWithStatusMeta, Reward,
        RewardType, TransactionBinaryEncoding, TransactionConfirmationStatus, TransactionStatus,
        UiConfirmedBlock, UiTransactionEncoding,
    },
    solana_vote_program::vote_state::{VoteState, MAX_LOCKOUT_HISTORY},
    spl_token_2022::{
        extension::StateWithExtensions,
        solana_program::program_pack::Pack,
        state::{Account as TokenAccount, Mint},
    },
    std::{
        any::type_name,
        cmp::{max, min},
        collections::{HashMap, HashSet},
        convert::TryFrom,
        net::SocketAddr,
        str::FromStr,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex, RwLock,
        },
        time::Duration,
    },
};

type RpcCustomResult<T> = std::result::Result<T, RpcCustomError>;

pub const MAX_REQUEST_BODY_SIZE: usize = 50 * (1 << 10); // 50kB
pub const PERFORMANCE_SAMPLES_LIMIT: usize = 720;

fn new_response<T>(bank: &Bank, value: T) -> RpcResponse<T> {
    RpcResponse {
        context: RpcResponseContext::new(bank.slot()),
        value,
    }
}

fn is_finalized(
    block_commitment_cache: &BlockCommitmentCache,
    bank: &Bank,
    blockstore: &Blockstore,
    slot: Slot,
) -> bool {
    slot <= block_commitment_cache.highest_confirmed_root()
        && (blockstore.is_root(slot) || bank.status_cache_ancestors().contains(&slot))
}

#[derive(Debug, Default, Clone)]
pub struct JsonRpcConfig {
    pub enable_rpc_transaction_history: bool,
    pub enable_extended_tx_metadata_storage: bool,
    pub faucet_addr: Option<SocketAddr>,
    pub health_check_slot_distance: u64,
    pub rpc_bigtable_config: Option<RpcBigtableConfig>,
    pub max_multiple_accounts: Option<usize>,
    pub account_indexes: AccountSecondaryIndexes,
    pub rpc_threads: usize,
    pub rpc_niceness_adj: i8,
    pub full_api: bool,
    pub obsolete_v1_7_api: bool,
    pub rpc_scan_and_fix_roots: bool,
    pub max_request_body_size: Option<usize>,
}

impl JsonRpcConfig {
    pub fn default_for_test() -> Self {
        Self {
            full_api: true,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcBigtableConfig {
    pub enable_bigtable_ledger_upload: bool,
    pub bigtable_instance_name: String,
    pub bigtable_app_profile_id: String,
    pub timeout: Option<Duration>,
}

impl Default for RpcBigtableConfig {
    fn default() -> Self {
        let bigtable_instance_name = solana_storage_bigtable::DEFAULT_INSTANCE_NAME.to_string();
        let bigtable_app_profile_id = solana_storage_bigtable::DEFAULT_APP_PROFILE_ID.to_string();
        Self {
            enable_bigtable_ledger_upload: false,
            bigtable_instance_name,
            bigtable_app_profile_id,
            timeout: None,
        }
    }
}

#[derive(Clone)]
pub struct JsonRpcRequestProcessor {
    bank_forks: Arc<RwLock<BankForks>>,
    block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
    blockstore: Arc<Blockstore>,
    config: JsonRpcConfig,
    snapshot_config: Option<SnapshotConfig>,
    #[allow(dead_code)]
    validator_exit: Arc<RwLock<Exit>>,
    health: Arc<RpcHealth>,
    cluster_info: Arc<ClusterInfo>,
    genesis_hash: Hash,
    transaction_sender: Arc<Mutex<Sender<TransactionInfo>>>,
    bigtable_ledger_storage: Option<solana_storage_bigtable::LedgerStorage>,
    optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
    largest_accounts_cache: Arc<RwLock<LargestAccountsCache>>,
    max_slots: Arc<MaxSlots>,
    leader_schedule_cache: Arc<LeaderScheduleCache>,
    max_complete_transaction_status_slot: Arc<AtomicU64>,
    max_complete_rewards_slot: Arc<AtomicU64>,
    prioritization_fee_cache: Arc<PrioritizationFeeCache>,
}
impl Metadata for JsonRpcRequestProcessor {}

impl JsonRpcRequestProcessor {
    fn get_bank_with_config(&self, config: RpcContextConfig) -> Result<Arc<Bank>> {
        let RpcContextConfig {
            commitment,
            min_context_slot,
        } = config;
        let bank = self.bank(commitment);
        if let Some(min_context_slot) = min_context_slot {
            if bank.slot() < min_context_slot {
                return Err(RpcCustomError::MinContextSlotNotReached {
                    context_slot: bank.slot(),
                }
                .into());
            }
        }
        Ok(bank)
    }

    #[allow(deprecated)]
    fn bank(&self, commitment: Option<CommitmentConfig>) -> Arc<Bank> {
        debug!("RPC commitment_config: {:?}", commitment);

        let commitment = commitment.unwrap_or_default();
        if commitment.is_confirmed() {
            let bank = self
                .optimistically_confirmed_bank
                .read()
                .unwrap()
                .bank
                .clone();
            debug!("RPC using optimistically confirmed slot: {:?}", bank.slot());
            return bank;
        }

        let slot = self
            .block_commitment_cache
            .read()
            .unwrap()
            .slot_with_commitment(commitment.commitment);

        match commitment.commitment {
            // Recent variant is deprecated
            CommitmentLevel::Recent | CommitmentLevel::Processed => {
                debug!("RPC using the heaviest slot: {:?}", slot);
            }
            // Root variant is deprecated
            CommitmentLevel::Root => {
                debug!("RPC using node root: {:?}", slot);
            }
            // Single variant is deprecated
            CommitmentLevel::Single => {
                debug!("RPC using confirmed slot: {:?}", slot);
            }
            // Max variant is deprecated
            CommitmentLevel::Max | CommitmentLevel::Finalized => {
                debug!("RPC using block: {:?}", slot);
            }
            CommitmentLevel::SingleGossip | CommitmentLevel::Confirmed => unreachable!(), // SingleGossip variant is deprecated
        };

        let r_bank_forks = self.bank_forks.read().unwrap();
        r_bank_forks.get(slot).unwrap_or_else(|| {
            // We log a warning instead of returning an error, because all known error cases
            // are due to known bugs that should be fixed instead.
            //
            // The slot may not be found as a result of a known bug in snapshot creation, where
            // the bank at the given slot was not included in the snapshot.
            // Also, it may occur after an old bank has been purged from BankForks and a new
            // BlockCommitmentCache has not yet arrived. To make this case impossible,
            // BlockCommitmentCache should hold an `Arc<Bank>` everywhere it currently holds
            // a slot.
            //
            // For more information, see https://github.com/solana-labs/solana/issues/11078
            warn!(
                "Bank with {:?} not found at slot: {:?}",
                commitment.commitment, slot
            );
            r_bank_forks.root_bank()
        })
    }

    fn genesis_creation_time(&self) -> UnixTimestamp {
        self.bank(None).genesis_creation_time()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: JsonRpcConfig,
        snapshot_config: Option<SnapshotConfig>,
        bank_forks: Arc<RwLock<BankForks>>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        blockstore: Arc<Blockstore>,
        validator_exit: Arc<RwLock<Exit>>,
        health: Arc<RpcHealth>,
        cluster_info: Arc<ClusterInfo>,
        genesis_hash: Hash,
        bigtable_ledger_storage: Option<solana_storage_bigtable::LedgerStorage>,
        optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
        largest_accounts_cache: Arc<RwLock<LargestAccountsCache>>,
        max_slots: Arc<MaxSlots>,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        max_complete_rewards_slot: Arc<AtomicU64>,
        prioritization_fee_cache: Arc<PrioritizationFeeCache>,
    ) -> (Self, Receiver<TransactionInfo>) {
        let (sender, receiver) = unbounded();
        (
            Self {
                config,
                snapshot_config,
                bank_forks,
                block_commitment_cache,
                blockstore,
                validator_exit,
                health,
                cluster_info,
                genesis_hash,
                transaction_sender: Arc::new(Mutex::new(sender)),
                bigtable_ledger_storage,
                optimistically_confirmed_bank,
                largest_accounts_cache,
                max_slots,
                leader_schedule_cache,
                max_complete_transaction_status_slot,
                max_complete_rewards_slot,
                prioritization_fee_cache,
            },
            receiver,
        )
    }

    // Useful for unit testing
    pub fn new_from_bank(
        bank: &Arc<Bank>,
        socket_addr_space: SocketAddrSpace,
        connection_cache: Arc<ConnectionCache>,
    ) -> Self {
        let genesis_hash = bank.hash();
        let bank_forks = Arc::new(RwLock::new(BankForks::new_from_banks(
            &[bank.clone()],
            bank.slot(),
        )));
        let blockstore = Arc::new(Blockstore::open(&get_tmp_ledger_path!()).unwrap());
        let exit = Arc::new(AtomicBool::new(false));
        let cluster_info = Arc::new({
            let keypair = Arc::new(Keypair::new());
            let contact_info = ContactInfo::new_localhost(
                &keypair.pubkey(),
                solana_sdk::timing::timestamp(), // wallclock
            );
            ClusterInfo::new(contact_info, keypair, socket_addr_space)
        });
        let tpu_address = cluster_info
            .my_contact_info()
            .tpu(connection_cache.protocol())
            .unwrap();
        let (sender, receiver) = unbounded();
        SendTransactionService::new::<NullTpuInfo>(
            tpu_address,
            &bank_forks,
            None,
            receiver,
            &connection_cache,
            1000,
            1,
            exit.clone(),
        );

        Self {
            config: JsonRpcConfig::default(),
            snapshot_config: None,
            bank_forks,
            block_commitment_cache: Arc::new(RwLock::new(BlockCommitmentCache::new(
                HashMap::new(),
                0,
                CommitmentSlots::new_from_slot(bank.slot()),
            ))),
            blockstore,
            validator_exit: create_validator_exit(&exit),
            health: Arc::new(RpcHealth::new(
                cluster_info.clone(),
                None,
                0,
                exit.clone(),
                Arc::clone(bank.get_startup_verification_complete()),
            )),
            cluster_info,
            genesis_hash,
            transaction_sender: Arc::new(Mutex::new(sender)),
            bigtable_ledger_storage: None,
            optimistically_confirmed_bank: Arc::new(RwLock::new(OptimisticallyConfirmedBank {
                bank: bank.clone(),
            })),
            largest_accounts_cache: Arc::new(RwLock::new(LargestAccountsCache::new(30))),
            max_slots: Arc::new(MaxSlots::default()),
            leader_schedule_cache: Arc::new(LeaderScheduleCache::new_from_bank(bank)),
            max_complete_transaction_status_slot: Arc::new(AtomicU64::default()),
            max_complete_rewards_slot: Arc::new(AtomicU64::default()),
            prioritization_fee_cache: Arc::new(PrioritizationFeeCache::default()),
        }
    }

    pub fn get_account_info(
        &self,
        pubkey: &Pubkey,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Option<UiAccount>>> {
        let RpcAccountInfoConfig {
            encoding,
            data_slice,
            commitment,
            min_context_slot,
        } = config.unwrap_or_default();
        let bank = self.get_bank_with_config(RpcContextConfig {
            commitment,
            min_context_slot,
        })?;
        let encoding = encoding.unwrap_or(UiAccountEncoding::Binary);

        let response = get_encoded_account(&bank, pubkey, encoding, data_slice)?;
        Ok(new_response(&bank, response))
    }

    pub fn get_multiple_accounts(
        &self,
        pubkeys: Vec<Pubkey>,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Vec<Option<UiAccount>>>> {
        let RpcAccountInfoConfig {
            encoding,
            data_slice,
            commitment,
            min_context_slot,
        } = config.unwrap_or_default();
        let bank = self.get_bank_with_config(RpcContextConfig {
            commitment,
            min_context_slot,
        })?;
        let encoding = encoding.unwrap_or(UiAccountEncoding::Base64);

        let accounts = pubkeys
            .into_iter()
            .map(|pubkey| get_encoded_account(&bank, &pubkey, encoding, data_slice))
            .collect::<Result<Vec<_>>>()?;
        Ok(new_response(&bank, accounts))
    }

    pub fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
        commitment: Option<CommitmentConfig>,
    ) -> u64 {
        self.bank(commitment)
            .get_minimum_balance_for_rent_exemption(data_len)
    }

    pub fn get_program_accounts(
        &self,
        program_id: &Pubkey,
        config: Option<RpcAccountInfoConfig>,
        mut filters: Vec<RpcFilterType>,
        with_context: bool,
    ) -> Result<OptionalContext<Vec<RpcKeyedAccount>>> {
        let RpcAccountInfoConfig {
            encoding,
            data_slice: data_slice_config,
            commitment,
            min_context_slot,
        } = config.unwrap_or_default();
        let bank = self.get_bank_with_config(RpcContextConfig {
            commitment,
            min_context_slot,
        })?;
        let encoding = encoding.unwrap_or(UiAccountEncoding::Binary);
        optimize_filters(&mut filters);
        let keyed_accounts = {
            if let Some(owner) = get_spl_token_owner_filter(program_id, &filters) {
                self.get_filtered_spl_token_accounts_by_owner(&bank, program_id, &owner, filters)?
            } else if let Some(mint) = get_spl_token_mint_filter(program_id, &filters) {
                self.get_filtered_spl_token_accounts_by_mint(&bank, program_id, &mint, filters)?
            } else {
                self.get_filtered_program_accounts(&bank, program_id, filters)?
            }
        };
        let accounts = if is_known_spl_token_id(program_id)
            && encoding == UiAccountEncoding::JsonParsed
        {
            get_parsed_token_accounts(bank.clone(), keyed_accounts.into_iter()).collect()
        } else {
            keyed_accounts
                .into_iter()
                .map(|(pubkey, account)| {
                    Ok(RpcKeyedAccount {
                        pubkey: pubkey.to_string(),
                        account: encode_account(&account, &pubkey, encoding, data_slice_config)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };
        Ok(match with_context {
            true => OptionalContext::Context(new_response(&bank, accounts)),
            false => OptionalContext::NoContext(accounts),
        })
    }

    pub async fn get_inflation_reward(
        &self,
        addresses: Vec<Pubkey>,
        config: Option<RpcEpochConfig>,
    ) -> Result<Vec<Option<RpcInflationReward>>> {
        let config = config.unwrap_or_default();
        let epoch_schedule = self.get_epoch_schedule();
        let first_available_block = self.get_first_available_block().await;
        let epoch = match config.epoch {
            Some(epoch) => epoch,
            None => epoch_schedule
                .get_epoch(self.get_slot(RpcContextConfig {
                    commitment: config.commitment,
                    min_context_slot: config.min_context_slot,
                })?)
                .saturating_sub(1),
        };

        // Rewards for this epoch are found in the first confirmed block of the next epoch
        let first_slot_in_epoch = epoch_schedule.get_first_slot_in_epoch(epoch.saturating_add(1));
        if first_slot_in_epoch < first_available_block {
            if self.bigtable_ledger_storage.is_some() {
                return Err(RpcCustomError::LongTermStorageSlotSkipped {
                    slot: first_slot_in_epoch,
                }
                .into());
            } else {
                return Err(RpcCustomError::BlockCleanedUp {
                    slot: first_slot_in_epoch,
                    first_available_block,
                }
                .into());
            }
        }

        let first_confirmed_block_in_epoch = *self
            .get_blocks_with_limit(first_slot_in_epoch, 1, config.commitment)
            .await?
            .first()
            .ok_or(RpcCustomError::BlockNotAvailable {
                slot: first_slot_in_epoch,
            })?;

        let first_confirmed_block = if let Ok(Some(first_confirmed_block)) = self
            .get_block(
                first_confirmed_block_in_epoch,
                Some(RpcBlockConfig::rewards_with_commitment(config.commitment).into()),
            )
            .await
        {
            first_confirmed_block
        } else {
            return Err(RpcCustomError::BlockNotAvailable {
                slot: first_confirmed_block_in_epoch,
            }
            .into());
        };

        let addresses: Vec<String> = addresses
            .into_iter()
            .map(|pubkey| pubkey.to_string())
            .collect();

        let reward_hash: HashMap<String, Reward> = first_confirmed_block
            .rewards
            .unwrap_or_default()
            .into_iter()
            .filter_map(|reward| match reward.reward_type? {
                RewardType::Staking | RewardType::Voting => addresses
                    .contains(&reward.pubkey)
                    .then(|| (reward.clone().pubkey, reward)),
                _ => None,
            })
            .collect();

        let rewards = addresses
            .iter()
            .map(|address| {
                if let Some(reward) = reward_hash.get(address) {
                    return Some(RpcInflationReward {
                        epoch,
                        effective_slot: first_confirmed_block_in_epoch,
                        amount: reward.lamports.unsigned_abs(),
                        post_balance: reward.post_balance,
                        commission: reward.commission,
                    });
                }
                None
            })
            .collect();

        Ok(rewards)
    }

    pub fn get_inflation_governor(
        &self,
        commitment: Option<CommitmentConfig>,
    ) -> RpcInflationGovernor {
        self.bank(commitment).inflation().into()
    }

    pub fn get_inflation_rate(&self) -> RpcInflationRate {
        let bank = self.bank(None);
        let epoch = bank.epoch();
        let inflation = bank.inflation();
        let slot_in_year = bank.slot_in_year_for_inflation();

        RpcInflationRate {
            total: inflation.total(slot_in_year),
            validator: inflation.validator(slot_in_year),
            foundation: inflation.foundation(slot_in_year),
            epoch,
        }
    }

    pub fn get_epoch_schedule(&self) -> EpochSchedule {
        // Since epoch schedule data comes from the genesis config, any commitment level should be
        // fine
        let bank = self.bank(Some(CommitmentConfig::finalized()));
        *bank.epoch_schedule()
    }

    pub fn get_balance(
        &self,
        pubkey: &Pubkey,
        config: RpcContextConfig,
    ) -> Result<RpcResponse<u64>> {
        let bank = self.get_bank_with_config(config)?;
        Ok(new_response(&bank, bank.get_balance(pubkey)))
    }

    fn get_recent_blockhash(
        &self,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<RpcBlockhashFeeCalculator>> {
        let bank = self.bank(commitment);
        let blockhash = bank.confirmed_last_blockhash();
        let lamports_per_signature = bank
            .get_lamports_per_signature_for_blockhash(&blockhash)
            .unwrap();
        Ok(new_response(
            &bank,
            RpcBlockhashFeeCalculator {
                blockhash: blockhash.to_string(),
                fee_calculator: FeeCalculator::new(lamports_per_signature),
            },
        ))
    }

    fn get_fees(&self, commitment: Option<CommitmentConfig>) -> Result<RpcResponse<RpcFees>> {
        let bank = self.bank(commitment);
        let blockhash = bank.confirmed_last_blockhash();
        let lamports_per_signature = bank
            .get_lamports_per_signature_for_blockhash(&blockhash)
            .unwrap();
        #[allow(deprecated)]
        let last_valid_slot = bank
            .get_blockhash_last_valid_slot(&blockhash)
            .expect("bank blockhash queue should contain blockhash");
        let last_valid_block_height = bank
            .get_blockhash_last_valid_block_height(&blockhash)
            .expect("bank blockhash queue should contain blockhash");
        Ok(new_response(
            &bank,
            RpcFees {
                blockhash: blockhash.to_string(),
                fee_calculator: FeeCalculator::new(lamports_per_signature),
                last_valid_slot,
                last_valid_block_height,
            },
        ))
    }

    fn get_fee_calculator_for_blockhash(
        &self,
        blockhash: &Hash,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<Option<RpcFeeCalculator>>> {
        let bank = self.bank(commitment);
        let lamports_per_signature = bank.get_lamports_per_signature_for_blockhash(blockhash);
        Ok(new_response(
            &bank,
            lamports_per_signature.map(|lamports_per_signature| RpcFeeCalculator {
                fee_calculator: FeeCalculator::new(lamports_per_signature),
            }),
        ))
    }

    fn get_fee_rate_governor(&self) -> RpcResponse<RpcFeeRateGovernor> {
        let bank = self.bank(None);
        #[allow(deprecated)]
        let fee_rate_governor = bank.get_fee_rate_governor();
        new_response(
            &bank,
            RpcFeeRateGovernor {
                fee_rate_governor: fee_rate_governor.clone(),
            },
        )
    }

    pub fn confirm_transaction(
        &self,
        signature: &Signature,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<bool>> {
        let bank = self.bank(commitment);
        let status = bank.get_signature_status(signature);
        match status {
            Some(status) => Ok(new_response(&bank, status.is_ok())),
            None => Ok(new_response(&bank, false)),
        }
    }

    fn get_block_commitment(&self, block: Slot) -> RpcBlockCommitment<BlockCommitmentArray> {
        let r_block_commitment = self.block_commitment_cache.read().unwrap();
        RpcBlockCommitment {
            commitment: r_block_commitment
                .get_block_commitment(block)
                .map(|block_commitment| block_commitment.commitment),
            total_stake: r_block_commitment.total_stake(),
        }
    }

    fn get_slot(&self, config: RpcContextConfig) -> Result<Slot> {
        let bank = self.get_bank_with_config(config)?;
        Ok(bank.slot())
    }

    fn get_block_height(&self, config: RpcContextConfig) -> Result<u64> {
        let bank = self.get_bank_with_config(config)?;
        Ok(bank.block_height())
    }

    fn get_max_retransmit_slot(&self) -> Slot {
        self.max_slots.retransmit.load(Ordering::Relaxed)
    }

    fn get_max_shred_insert_slot(&self) -> Slot {
        self.max_slots.shred_insert.load(Ordering::Relaxed)
    }

    fn get_slot_leader(&self, config: RpcContextConfig) -> Result<String> {
        let bank = self.get_bank_with_config(config)?;
        Ok(bank.collector_id().to_string())
    }

    fn get_slot_leaders(
        &self,
        commitment: Option<CommitmentConfig>,
        start_slot: Slot,
        limit: usize,
    ) -> Result<Vec<Pubkey>> {
        let bank = self.bank(commitment);

        let (mut epoch, mut slot_index) =
            bank.epoch_schedule().get_epoch_and_slot_index(start_slot);

        let mut slot_leaders = Vec::with_capacity(limit);
        while slot_leaders.len() < limit {
            if let Some(leader_schedule) =
                self.leader_schedule_cache.get_epoch_leader_schedule(epoch)
            {
                slot_leaders.extend(
                    leader_schedule
                        .get_slot_leaders()
                        .iter()
                        .skip(slot_index as usize)
                        .take(limit.saturating_sub(slot_leaders.len())),
                );
            } else {
                return Err(Error::invalid_params(format!(
                    "Invalid slot range: leader schedule for epoch {epoch} is unavailable"
                )));
            }

            epoch += 1;
            slot_index = 0;
        }

        Ok(slot_leaders)
    }

    fn minimum_ledger_slot(&self) -> Result<Slot> {
        match self.blockstore.slot_meta_iterator(0) {
            Ok(mut metas) => match metas.next() {
                Some((slot, _meta)) => Ok(slot),
                None => Err(Error::invalid_request()),
            },
            Err(err) => {
                warn!("slot_meta_iterator failed: {:?}", err);
                Err(Error::invalid_request())
            }
        }
    }

    fn get_transaction_count(&self, config: RpcContextConfig) -> Result<u64> {
        let bank = self.get_bank_with_config(config)?;
        Ok(bank.transaction_count())
    }

    fn get_total_supply(&self, commitment: Option<CommitmentConfig>) -> Result<u64> {
        let bank = self.bank(commitment);
        Ok(bank.capitalization())
    }

    fn get_cached_largest_accounts(
        &self,
        filter: &Option<RpcLargestAccountsFilter>,
    ) -> Option<(u64, Vec<RpcAccountBalance>)> {
        let largest_accounts_cache = self.largest_accounts_cache.read().unwrap();
        largest_accounts_cache.get_largest_accounts(filter)
    }

    fn set_cached_largest_accounts(
        &self,
        filter: &Option<RpcLargestAccountsFilter>,
        slot: u64,
        accounts: &[RpcAccountBalance],
    ) {
        let mut largest_accounts_cache = self.largest_accounts_cache.write().unwrap();
        largest_accounts_cache.set_largest_accounts(filter, slot, accounts)
    }

    fn get_largest_accounts(
        &self,
        config: Option<RpcLargestAccountsConfig>,
    ) -> RpcCustomResult<RpcResponse<Vec<RpcAccountBalance>>> {
        let config = config.unwrap_or_default();
        let bank = self.bank(config.commitment);

        if let Some((slot, accounts)) = self.get_cached_largest_accounts(&config.filter) {
            Ok(RpcResponse {
                context: RpcResponseContext::new(slot),
                value: accounts,
            })
        } else {
            let (addresses, address_filter) = if let Some(filter) = config.clone().filter {
                let non_circulating_supply =
                    calculate_non_circulating_supply(&bank).map_err(|e| {
                        RpcCustomError::ScanError {
                            message: e.to_string(),
                        }
                    })?;
                let addresses = non_circulating_supply.accounts.into_iter().collect();
                let address_filter = match filter {
                    RpcLargestAccountsFilter::Circulating => AccountAddressFilter::Exclude,
                    RpcLargestAccountsFilter::NonCirculating => AccountAddressFilter::Include,
                };
                (addresses, address_filter)
            } else {
                (HashSet::new(), AccountAddressFilter::Exclude)
            };
            let accounts = bank
                .get_largest_accounts(NUM_LARGEST_ACCOUNTS, &addresses, address_filter)
                .map_err(|e| RpcCustomError::ScanError {
                    message: e.to_string(),
                })?
                .into_iter()
                .map(|(address, lamports)| RpcAccountBalance {
                    address: address.to_string(),
                    lamports,
                })
                .collect::<Vec<RpcAccountBalance>>();

            self.set_cached_largest_accounts(&config.filter, bank.slot(), &accounts);
            Ok(new_response(&bank, accounts))
        }
    }

    fn get_supply(
        &self,
        config: Option<RpcSupplyConfig>,
    ) -> RpcCustomResult<RpcResponse<RpcSupply>> {
        let config = config.unwrap_or_default();
        let bank = self.bank(config.commitment);
        let non_circulating_supply =
            calculate_non_circulating_supply(&bank).map_err(|e| RpcCustomError::ScanError {
                message: e.to_string(),
            })?;
        let total_supply = bank.capitalization();
        let non_circulating_accounts = if config.exclude_non_circulating_accounts_list {
            vec![]
        } else {
            non_circulating_supply
                .accounts
                .iter()
                .map(|pubkey| pubkey.to_string())
                .collect()
        };

        Ok(new_response(
            &bank,
            RpcSupply {
                total: total_supply,
                circulating: total_supply - non_circulating_supply.lamports,
                non_circulating: non_circulating_supply.lamports,
                non_circulating_accounts,
            },
        ))
    }

    fn get_vote_accounts(
        &self,
        config: Option<RpcGetVoteAccountsConfig>,
    ) -> Result<RpcVoteAccountStatus> {
        let config = config.unwrap_or_default();

        let filter_by_vote_pubkey = if let Some(ref vote_pubkey) = config.vote_pubkey {
            Some(verify_pubkey(vote_pubkey)?)
        } else {
            None
        };

        let bank = self.bank(config.commitment);
        let vote_accounts = bank.vote_accounts();
        let epoch_vote_accounts = bank
            .epoch_vote_accounts(bank.get_epoch_and_slot_index(bank.slot()).0)
            .ok_or_else(Error::invalid_request)?;
        let default_vote_state = VoteState::default();
        let delinquent_validator_slot_distance = config
            .delinquent_slot_distance
            .unwrap_or(DELINQUENT_VALIDATOR_SLOT_DISTANCE);
        let (current_vote_accounts, delinquent_vote_accounts): (
            Vec<RpcVoteAccountInfo>,
            Vec<RpcVoteAccountInfo>,
        ) = vote_accounts
            .iter()
            .filter_map(|(vote_pubkey, (activated_stake, account))| {
                if let Some(filter_by_vote_pubkey) = filter_by_vote_pubkey {
                    if *vote_pubkey != filter_by_vote_pubkey {
                        return None;
                    }
                }

                let vote_state = account.vote_state();
                let vote_state = vote_state.unwrap_or(&default_vote_state);
                let last_vote = if let Some(vote) = vote_state.votes.iter().last() {
                    vote.slot()
                } else {
                    0
                };

                let epoch_credits = vote_state.epoch_credits();
                let epoch_credits = if epoch_credits.len()
                    > MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY
                {
                    epoch_credits
                        .iter()
                        .skip(epoch_credits.len() - MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY)
                        .cloned()
                        .collect()
                } else {
                    epoch_credits.clone()
                };

                Some(RpcVoteAccountInfo {
                    vote_pubkey: vote_pubkey.to_string(),
                    node_pubkey: vote_state.node_pubkey.to_string(),
                    activated_stake: *activated_stake,
                    commission: vote_state.commission,
                    root_slot: vote_state.root_slot.unwrap_or(0),
                    epoch_credits,
                    epoch_vote_account: epoch_vote_accounts.contains_key(vote_pubkey),
                    last_vote,
                })
            })
            .partition(|vote_account_info| {
                if bank.slot() >= delinquent_validator_slot_distance {
                    vote_account_info.last_vote > bank.slot() - delinquent_validator_slot_distance
                } else {
                    vote_account_info.last_vote > 0
                }
            });

        let keep_unstaked_delinquents = config.keep_unstaked_delinquents.unwrap_or_default();
        let delinquent_vote_accounts = if !keep_unstaked_delinquents {
            delinquent_vote_accounts
                .into_iter()
                .filter(|vote_account_info| vote_account_info.activated_stake > 0)
                .collect::<Vec<_>>()
        } else {
            delinquent_vote_accounts
        };

        Ok(RpcVoteAccountStatus {
            current: current_vote_accounts,
            delinquent: delinquent_vote_accounts,
        })
    }

    fn check_blockstore_root<T>(
        &self,
        result: &std::result::Result<T, BlockstoreError>,
        slot: Slot,
    ) -> Result<()> {
        if let Err(err) = result {
            debug!(
                "check_blockstore_root, slot: {:?}, max root: {:?}, err: {:?}",
                slot,
                self.blockstore.max_root(),
                err
            );
            if slot >= self.blockstore.max_root() {
                return Err(RpcCustomError::BlockNotAvailable { slot }.into());
            }
            if self.blockstore.is_skipped(slot) {
                return Err(RpcCustomError::SlotSkipped { slot }.into());
            }
        }
        Ok(())
    }

    fn check_slot_cleaned_up<T>(
        &self,
        result: &std::result::Result<T, BlockstoreError>,
        slot: Slot,
    ) -> Result<()> {
        let first_available_block = self
            .blockstore
            .get_first_available_block()
            .unwrap_or_default();
        let err: Error = RpcCustomError::BlockCleanedUp {
            slot,
            first_available_block,
        }
        .into();
        if let Err(BlockstoreError::SlotCleanedUp) = result {
            return Err(err);
        }
        if slot < first_available_block {
            return Err(err);
        }
        Ok(())
    }

    fn check_bigtable_result<T>(
        &self,
        result: &std::result::Result<T, solana_storage_bigtable::Error>,
    ) -> Result<()> {
        if let Err(solana_storage_bigtable::Error::BlockNotFound(slot)) = result {
            return Err(RpcCustomError::LongTermStorageSlotSkipped { slot: *slot }.into());
        }
        Ok(())
    }

    fn check_blockstore_writes_complete(&self, slot: Slot) -> Result<()> {
        if slot
            > self
                .max_complete_transaction_status_slot
                .load(Ordering::SeqCst)
            || slot > self.max_complete_rewards_slot.load(Ordering::SeqCst)
        {
            Err(RpcCustomError::BlockStatusNotAvailableYet { slot }.into())
        } else {
            Ok(())
        }
    }

    pub async fn get_block(
        &self,
        slot: Slot,
        config: Option<RpcEncodingConfigWrapper<RpcBlockConfig>>,
    ) -> Result<Option<UiConfirmedBlock>> {
        if self.config.enable_rpc_transaction_history {
            let config = config
                .map(|config| config.convert_to_current())
                .unwrap_or_default();
            let encoding = config.encoding.unwrap_or(UiTransactionEncoding::Json);
            let encoding_options = BlockEncodingOptions {
                transaction_details: config.transaction_details.unwrap_or_default(),
                show_rewards: config.rewards.unwrap_or(true),
                max_supported_transaction_version: config.max_supported_transaction_version,
            };
            let commitment = config.commitment.unwrap_or_default();
            check_is_at_least_confirmed(commitment)?;

            // Block is old enough to be finalized
            if slot
                <= self
                    .block_commitment_cache
                    .read()
                    .unwrap()
                    .highest_confirmed_root()
            {
                self.check_blockstore_writes_complete(slot)?;
                let result = self.blockstore.get_rooted_block(slot, true);
                self.check_blockstore_root(&result, slot)?;
                let encode_block = |confirmed_block: ConfirmedBlock| -> Result<UiConfirmedBlock> {
                    let mut encoded_block = confirmed_block
                        .encode_with_options(encoding, encoding_options)
                        .map_err(RpcCustomError::from)?;
                    if slot == 0 {
                        encoded_block.block_time = Some(self.genesis_creation_time());
                        encoded_block.block_height = Some(0);
                    }
                    Ok(encoded_block)
                };
                if result.is_err() {
                    if let Some(bigtable_ledger_storage) = &self.bigtable_ledger_storage {
                        let bigtable_result =
                            bigtable_ledger_storage.get_confirmed_block(slot).await;
                        self.check_bigtable_result(&bigtable_result)?;
                        return bigtable_result.ok().map(encode_block).transpose();
                    }
                }
                self.check_slot_cleaned_up(&result, slot)?;
                return result
                    .ok()
                    .map(ConfirmedBlock::from)
                    .map(encode_block)
                    .transpose();
            } else if commitment.is_confirmed() {
                // Check if block is confirmed
                let confirmed_bank = self.bank(Some(CommitmentConfig::confirmed()));
                if confirmed_bank.status_cache_ancestors().contains(&slot) {
                    self.check_blockstore_writes_complete(slot)?;
                    let result = self.blockstore.get_complete_block(slot, true);
                    return result
                        .ok()
                        .map(ConfirmedBlock::from)
                        .map(|mut confirmed_block| -> Result<UiConfirmedBlock> {
                            if confirmed_block.block_time.is_none()
                                || confirmed_block.block_height.is_none()
                            {
                                let r_bank_forks = self.bank_forks.read().unwrap();
                                if let Some(bank) = r_bank_forks.get(slot) {
                                    if confirmed_block.block_time.is_none() {
                                        confirmed_block.block_time =
                                            Some(bank.clock().unix_timestamp);
                                    }
                                    if confirmed_block.block_height.is_none() {
                                        confirmed_block.block_height = Some(bank.block_height());
                                    }
                                }
                            }

                            Ok(confirmed_block
                                .encode_with_options(encoding, encoding_options)
                                .map_err(RpcCustomError::from)?)
                        })
                        .transpose();
                }
            }
        } else {
            return Err(RpcCustomError::TransactionHistoryNotAvailable.into());
        }
        Err(RpcCustomError::BlockNotAvailable { slot }.into())
    }

    pub async fn get_blocks(
        &self,
        start_slot: Slot,
        end_slot: Option<Slot>,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Vec<Slot>> {
        let commitment = commitment.unwrap_or_default();
        check_is_at_least_confirmed(commitment)?;

        let highest_confirmed_root = self
            .block_commitment_cache
            .read()
            .unwrap()
            .highest_confirmed_root();

        let end_slot = min(
            end_slot.unwrap_or_else(|| start_slot.saturating_add(MAX_GET_CONFIRMED_BLOCKS_RANGE)),
            if commitment.is_finalized() {
                highest_confirmed_root
            } else {
                self.bank(Some(CommitmentConfig::confirmed())).slot()
            },
        );
        if end_slot < start_slot {
            return Ok(vec![]);
        }
        if end_slot - start_slot > MAX_GET_CONFIRMED_BLOCKS_RANGE {
            return Err(Error::invalid_params(format!(
                "Slot range too large; max {MAX_GET_CONFIRMED_BLOCKS_RANGE}"
            )));
        }

        let lowest_blockstore_slot = self
            .blockstore
            .get_first_available_block()
            .unwrap_or_default();
        if start_slot < lowest_blockstore_slot {
            // If the starting slot is lower than what's available in blockstore assume the entire
            // [start_slot..end_slot] can be fetched from BigTable. This range should not ever run
            // into unfinalized confirmed blocks due to MAX_GET_CONFIRMED_BLOCKS_RANGE
            if let Some(bigtable_ledger_storage) = &self.bigtable_ledger_storage {
                return bigtable_ledger_storage
                    .get_confirmed_blocks(start_slot, (end_slot - start_slot) as usize + 1) // increment limit by 1 to ensure returned range is inclusive of both start_slot and end_slot
                    .await
                    .map(|mut bigtable_blocks| {
                        bigtable_blocks.retain(|&slot| slot <= end_slot);
                        bigtable_blocks
                    })
                    .map_err(|_| {
                        Error::invalid_params(
                            "BigTable query failed (maybe timeout due to too large range?)"
                                .to_string(),
                        )
                    });
            }
        }

        // Finalized blocks
        let mut blocks: Vec<_> = self
            .blockstore
            .rooted_slot_iterator(max(start_slot, lowest_blockstore_slot))
            .map_err(|_| Error::internal_error())?
            .filter(|&slot| slot <= end_slot && slot <= highest_confirmed_root)
            .collect();
        let last_element = blocks
            .last()
            .cloned()
            .unwrap_or_else(|| start_slot.saturating_sub(1));

        // Maybe add confirmed blocks
        if commitment.is_confirmed() && last_element < end_slot {
            let confirmed_bank = self.bank(Some(CommitmentConfig::confirmed()));
            let mut confirmed_blocks = confirmed_bank
                .status_cache_ancestors()
                .into_iter()
                .filter(|&slot| slot <= end_slot && slot > last_element)
                .collect();
            blocks.append(&mut confirmed_blocks);
        }

        Ok(blocks)
    }

    pub async fn get_blocks_with_limit(
        &self,
        start_slot: Slot,
        limit: usize,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Vec<Slot>> {
        let commitment = commitment.unwrap_or_default();
        check_is_at_least_confirmed(commitment)?;

        if limit > MAX_GET_CONFIRMED_BLOCKS_RANGE as usize {
            return Err(Error::invalid_params(format!(
                "Limit too large; max {MAX_GET_CONFIRMED_BLOCKS_RANGE}"
            )));
        }

        let lowest_blockstore_slot = self
            .blockstore
            .get_first_available_block()
            .unwrap_or_default();

        if start_slot < lowest_blockstore_slot {
            // If the starting slot is lower than what's available in blockstore assume the entire
            // range can be fetched from BigTable. This range should not ever run into unfinalized
            // confirmed blocks due to MAX_GET_CONFIRMED_BLOCKS_RANGE
            if let Some(bigtable_ledger_storage) = &self.bigtable_ledger_storage {
                return Ok(bigtable_ledger_storage
                    .get_confirmed_blocks(start_slot, limit)
                    .await
                    .unwrap_or_default());
            }
        }

        let highest_confirmed_root = self
            .block_commitment_cache
            .read()
            .unwrap()
            .highest_confirmed_root();

        // Finalized blocks
        let mut blocks: Vec<_> = self
            .blockstore
            .rooted_slot_iterator(max(start_slot, lowest_blockstore_slot))
            .map_err(|_| Error::internal_error())?
            .take(limit)
            .filter(|&slot| slot <= highest_confirmed_root)
            .collect();

        // Maybe add confirmed blocks
        if commitment.is_confirmed() && blocks.len() < limit {
            let last_element = blocks
                .last()
                .cloned()
                .unwrap_or_else(|| start_slot.saturating_sub(1));
            let confirmed_bank = self.bank(Some(CommitmentConfig::confirmed()));
            let mut confirmed_blocks = confirmed_bank
                .status_cache_ancestors()
                .into_iter()
                .filter(|&slot| slot > last_element)
                .collect();
            blocks.append(&mut confirmed_blocks);
            blocks.truncate(limit);
        }

        Ok(blocks)
    }

    pub async fn get_block_time(&self, slot: Slot) -> Result<Option<UnixTimestamp>> {
        if slot == 0 {
            return Ok(Some(self.genesis_creation_time()));
        }
        if slot
            <= self
                .block_commitment_cache
                .read()
                .unwrap()
                .highest_confirmed_root()
        {
            let result = self.blockstore.get_block_time(slot);
            self.check_blockstore_root(&result, slot)?;
            if result.is_err() || matches!(result, Ok(None)) {
                if let Some(bigtable_ledger_storage) = &self.bigtable_ledger_storage {
                    let bigtable_result = bigtable_ledger_storage.get_confirmed_block(slot).await;
                    self.check_bigtable_result(&bigtable_result)?;
                    return Ok(bigtable_result
                        .ok()
                        .and_then(|confirmed_block| confirmed_block.block_time));
                }
            }
            self.check_slot_cleaned_up(&result, slot)?;
            Ok(result.ok().unwrap_or(None))
        } else {
            let r_bank_forks = self.bank_forks.read().unwrap();
            if let Some(bank) = r_bank_forks.get(slot) {
                Ok(Some(bank.clock().unix_timestamp))
            } else {
                Err(RpcCustomError::BlockNotAvailable { slot }.into())
            }
        }
    }

    pub fn get_signature_confirmation_status(
        &self,
        signature: Signature,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Option<RpcSignatureConfirmation>> {
        let bank = self.bank(commitment);
        Ok(self
            .get_transaction_status(signature, &bank)
            .map(|transaction_status| {
                let confirmations = transaction_status
                    .confirmations
                    .unwrap_or(MAX_LOCKOUT_HISTORY + 1);
                RpcSignatureConfirmation {
                    confirmations,
                    status: transaction_status.status,
                }
            }))
    }

    pub fn get_signature_status(
        &self,
        signature: Signature,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Option<transaction::Result<()>>> {
        let bank = self.bank(commitment);
        Ok(bank
            .get_signature_status_slot(&signature)
            .map(|(_, status)| status))
    }

    pub async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
        config: Option<RpcSignatureStatusConfig>,
    ) -> Result<RpcResponse<Vec<Option<TransactionStatus>>>> {
        let mut statuses: Vec<Option<TransactionStatus>> = vec![];

        let search_transaction_history = config
            .map(|x| x.search_transaction_history)
            .unwrap_or(false);
        let bank = self.bank(Some(CommitmentConfig::processed()));

        if search_transaction_history && !self.config.enable_rpc_transaction_history {
            return Err(RpcCustomError::TransactionHistoryNotAvailable.into());
        }

        for signature in signatures {
            let status = if let Some(status) = self.get_transaction_status(signature, &bank) {
                Some(status)
            } else if self.config.enable_rpc_transaction_history && search_transaction_history {
                if let Some(status) = self
                    .blockstore
                    .get_rooted_transaction_status(signature)
                    .map_err(|_| Error::internal_error())?
                    .filter(|(slot, _status_meta)| {
                        slot <= &self
                            .block_commitment_cache
                            .read()
                            .unwrap()
                            .highest_confirmed_root()
                    })
                    .map(|(slot, status_meta)| {
                        let err = status_meta.status.clone().err();
                        TransactionStatus {
                            slot,
                            status: status_meta.status,
                            confirmations: None,
                            err,
                            confirmation_status: Some(TransactionConfirmationStatus::Finalized),
                        }
                    })
                {
                    Some(status)
                } else if let Some(bigtable_ledger_storage) = &self.bigtable_ledger_storage {
                    bigtable_ledger_storage
                        .get_signature_status(&signature)
                        .await
                        .map(Some)
                        .unwrap_or(None)
                } else {
                    None
                }
            } else {
                None
            };
            statuses.push(status);
        }
        Ok(new_response(&bank, statuses))
    }

    fn get_transaction_status(
        &self,
        signature: Signature,
        bank: &Arc<Bank>,
    ) -> Option<TransactionStatus> {
        let (slot, status) = bank.get_signature_status_slot(&signature)?;

        let optimistically_confirmed_bank = self.bank(Some(CommitmentConfig::confirmed()));
        let optimistically_confirmed =
            optimistically_confirmed_bank.get_signature_status_slot(&signature);

        let r_block_commitment_cache = self.block_commitment_cache.read().unwrap();
        let confirmations = if r_block_commitment_cache.root() >= slot
            && is_finalized(&r_block_commitment_cache, bank, &self.blockstore, slot)
        {
            None
        } else {
            r_block_commitment_cache
                .get_confirmation_count(slot)
                .or(Some(0))
        };
        let err = status.clone().err();
        Some(TransactionStatus {
            slot,
            status,
            confirmations,
            err,
            confirmation_status: if confirmations.is_none() {
                Some(TransactionConfirmationStatus::Finalized)
            } else if optimistically_confirmed.is_some() {
                Some(TransactionConfirmationStatus::Confirmed)
            } else {
                Some(TransactionConfirmationStatus::Processed)
            },
        })
    }

    pub async fn get_transaction(
        &self,
        signature: Signature,
        config: Option<RpcEncodingConfigWrapper<RpcTransactionConfig>>,
    ) -> Result<Option<EncodedConfirmedTransactionWithStatusMeta>> {
        let config = config
            .map(|config| config.convert_to_current())
            .unwrap_or_default();
        let encoding = config.encoding.unwrap_or(UiTransactionEncoding::Json);
        let max_supported_transaction_version = config.max_supported_transaction_version;
        let commitment = config.commitment.unwrap_or_default();
        check_is_at_least_confirmed(commitment)?;

        if self.config.enable_rpc_transaction_history {
            let confirmed_bank = self.bank(Some(CommitmentConfig::confirmed()));
            let confirmed_transaction = if commitment.is_confirmed() {
                let highest_confirmed_slot = confirmed_bank.slot();
                self.blockstore
                    .get_complete_transaction(signature, highest_confirmed_slot)
            } else {
                self.blockstore.get_rooted_transaction(signature)
            };

            let encode_transaction =
                |confirmed_tx_with_meta: ConfirmedTransactionWithStatusMeta| -> Result<EncodedConfirmedTransactionWithStatusMeta> {
                    Ok(confirmed_tx_with_meta.encode(encoding, max_supported_transaction_version).map_err(RpcCustomError::from)?)
                };

            match confirmed_transaction.unwrap_or(None) {
                Some(mut confirmed_transaction) => {
                    if commitment.is_confirmed()
                        && confirmed_bank // should be redundant
                            .status_cache_ancestors()
                            .contains(&confirmed_transaction.slot)
                    {
                        if confirmed_transaction.block_time.is_none() {
                            let r_bank_forks = self.bank_forks.read().unwrap();
                            confirmed_transaction.block_time = r_bank_forks
                                .get(confirmed_transaction.slot)
                                .map(|bank| bank.clock().unix_timestamp);
                        }
                        return Ok(Some(encode_transaction(confirmed_transaction)?));
                    }

                    if confirmed_transaction.slot
                        <= self
                            .block_commitment_cache
                            .read()
                            .unwrap()
                            .highest_confirmed_root()
                    {
                        return Ok(Some(encode_transaction(confirmed_transaction)?));
                    }
                }
                None => {
                    if let Some(bigtable_ledger_storage) = &self.bigtable_ledger_storage {
                        return bigtable_ledger_storage
                            .get_confirmed_transaction(&signature)
                            .await
                            .unwrap_or(None)
                            .map(encode_transaction)
                            .transpose();
                    }
                }
            }
        } else {
            return Err(RpcCustomError::TransactionHistoryNotAvailable.into());
        }
        Ok(None)
    }

    pub fn get_confirmed_signatures_for_address(
        &self,
        pubkey: Pubkey,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Vec<Signature> {
        if self.config.enable_rpc_transaction_history {
            // TODO: Add bigtable_ledger_storage support as a part of
            // https://github.com/solana-labs/solana/pull/10928
            let end_slot = min(
                end_slot,
                self.block_commitment_cache
                    .read()
                    .unwrap()
                    .highest_confirmed_root(),
            );
            self.blockstore
                .get_confirmed_signatures_for_address(pubkey, start_slot, end_slot)
                .unwrap_or_default()
        } else {
            vec![]
        }
    }

    pub async fn get_signatures_for_address(
        &self,
        address: Pubkey,
        before: Option<Signature>,
        until: Option<Signature>,
        mut limit: usize,
        config: RpcContextConfig,
    ) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        let commitment = config.commitment.unwrap_or_default();
        check_is_at_least_confirmed(commitment)?;

        if self.config.enable_rpc_transaction_history {
            let highest_confirmed_root = self
                .block_commitment_cache
                .read()
                .unwrap()
                .highest_confirmed_root();
            let highest_slot = if commitment.is_confirmed() {
                let confirmed_bank = self.get_bank_with_config(config)?;
                confirmed_bank.slot()
            } else {
                let min_context_slot = config.min_context_slot.unwrap_or_default();
                if highest_confirmed_root < min_context_slot {
                    return Err(RpcCustomError::MinContextSlotNotReached {
                        context_slot: highest_confirmed_root,
                    }
                    .into());
                }
                highest_confirmed_root
            };

            let SignatureInfosForAddress {
                infos: mut results,
                found_before,
            } = self
                .blockstore
                .get_confirmed_signatures_for_address2(address, highest_slot, before, until, limit)
                .map_err(|err| Error::invalid_params(format!("{err}")))?;

            let map_results = |results: Vec<ConfirmedTransactionStatusWithSignature>| {
                results
                    .into_iter()
                    .map(|x| {
                        let mut item: RpcConfirmedTransactionStatusWithSignature = x.into();
                        if item.slot <= highest_confirmed_root {
                            item.confirmation_status =
                                Some(TransactionConfirmationStatus::Finalized);
                        } else {
                            item.confirmation_status =
                                Some(TransactionConfirmationStatus::Confirmed);
                            if item.block_time.is_none() {
                                let r_bank_forks = self.bank_forks.read().unwrap();
                                item.block_time = r_bank_forks
                                    .get(item.slot)
                                    .map(|bank| bank.clock().unix_timestamp);
                            }
                        }
                        item
                    })
                    .collect()
            };

            if results.len() < limit {
                if let Some(bigtable_ledger_storage) = &self.bigtable_ledger_storage {
                    let mut bigtable_before = before;
                    if !results.is_empty() {
                        limit -= results.len();
                        bigtable_before = results.last().map(|x| x.signature);
                    }

                    // If the oldest address-signature found in Blockstore has not yet been
                    // uploaded to long-term storage, modify the storage query to return all latest
                    // signatures to prevent erroring on RowNotFound. This can race with upload.
                    if found_before && bigtable_before.is_some() {
                        match bigtable_ledger_storage
                            .get_signature_status(&bigtable_before.unwrap())
                            .await
                        {
                            Err(StorageError::SignatureNotFound) => {
                                bigtable_before = None;
                            }
                            Err(err) => {
                                warn!("{:?}", err);
                                return Ok(map_results(results));
                            }
                            Ok(_) => {}
                        }
                    }

                    let bigtable_results = bigtable_ledger_storage
                        .get_confirmed_signatures_for_address(
                            &address,
                            bigtable_before.as_ref(),
                            until.as_ref(),
                            limit,
                        )
                        .await;
                    match bigtable_results {
                        Ok(bigtable_results) => {
                            let results_set: HashSet<_> =
                                results.iter().map(|result| result.signature).collect();
                            for (bigtable_result, _) in bigtable_results {
                                // In the upload race condition, latest address-signatures in
                                // long-term storage may include original `before` signature...
                                if before != Some(bigtable_result.signature)
                                    // ...or earlier Blockstore signatures
                                    && !results_set.contains(&bigtable_result.signature)
                                {
                                    results.push(bigtable_result);
                                }
                            }
                        }
                        Err(err) => {
                            warn!("{:?}", err);
                        }
                    }
                }
            }

            Ok(map_results(results))
        } else {
            Err(RpcCustomError::TransactionHistoryNotAvailable.into())
        }
    }

    pub async fn get_first_available_block(&self) -> Slot {
        let slot = self
            .blockstore
            .get_first_available_block()
            .unwrap_or_default();

        if let Some(bigtable_ledger_storage) = &self.bigtable_ledger_storage {
            let bigtable_slot = bigtable_ledger_storage
                .get_first_available_block()
                .await
                .unwrap_or(None)
                .unwrap_or(slot);

            if bigtable_slot < slot {
                return bigtable_slot;
            }
        }
        slot
    }

    pub fn get_stake_activation(
        &self,
        pubkey: &Pubkey,
        config: Option<RpcEpochConfig>,
    ) -> Result<RpcStakeActivation> {
        let config = config.unwrap_or_default();
        let bank = self.get_bank_with_config(RpcContextConfig {
            commitment: config.commitment,
            min_context_slot: config.min_context_slot,
        })?;
        let epoch = config.epoch.unwrap_or_else(|| bank.epoch());
        if bank.epoch().saturating_sub(epoch) > solana_sdk::stake_history::MAX_ENTRIES as u64 {
            return Err(Error::invalid_params(format!(
                "Invalid param: epoch {epoch:?} is too far in the past"
            )));
        }
        if epoch > bank.epoch() {
            return Err(Error::invalid_params(format!(
                "Invalid param: epoch {epoch:?} has not yet started"
            )));
        }

        let stake_account = bank
            .get_account(pubkey)
            .ok_or_else(|| Error::invalid_params("Invalid param: account not found".to_string()))?;
        let stake_state: StakeState = stake_account
            .state()
            .map_err(|_| Error::invalid_params("Invalid param: not a stake account".to_string()))?;
        let delegation = stake_state.delegation();

        let rent_exempt_reserve = stake_state
            .meta()
            .ok_or_else(|| {
                Error::invalid_params("Invalid param: stake account not initialized".to_string())
            })?
            .rent_exempt_reserve;

        let delegation = match delegation {
            None => {
                return Ok(RpcStakeActivation {
                    state: StakeActivationState::Inactive,
                    active: 0,
                    inactive: stake_account.lamports().saturating_sub(rent_exempt_reserve),
                })
            }
            Some(delegation) => delegation,
        };

        let stake_history_account = bank
            .get_account(&stake_history::id())
            .ok_or_else(Error::internal_error)?;
        let stake_history =
            solana_sdk::account::from_account::<StakeHistory, _>(&stake_history_account)
                .ok_or_else(Error::internal_error)?;

        let StakeActivationStatus {
            effective,
            activating,
            deactivating,
        } = delegation.stake_activating_and_deactivating(epoch, Some(&stake_history));
        let stake_activation_state = if deactivating > 0 {
            StakeActivationState::Deactivating
        } else if activating > 0 {
            StakeActivationState::Activating
        } else if effective > 0 {
            StakeActivationState::Active
        } else {
            StakeActivationState::Inactive
        };
        let inactive_stake = match stake_activation_state {
            StakeActivationState::Activating => activating,
            StakeActivationState::Active => 0,
            StakeActivationState::Deactivating => stake_account
                .lamports()
                .saturating_sub(effective + rent_exempt_reserve),
            StakeActivationState::Inactive => {
                stake_account.lamports().saturating_sub(rent_exempt_reserve)
            }
        };
        Ok(RpcStakeActivation {
            state: stake_activation_state,
            active: effective,
            inactive: inactive_stake,
        })
    }

    pub fn get_token_account_balance(
        &self,
        pubkey: &Pubkey,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<UiTokenAmount>> {
        let bank = self.bank(commitment);
        let account = bank.get_account(pubkey).ok_or_else(|| {
            Error::invalid_params("Invalid param: could not find account".to_string())
        })?;

        if !is_known_spl_token_id(account.owner()) {
            return Err(Error::invalid_params(
                "Invalid param: not a Token account".to_string(),
            ));
        }
        let token_account = StateWithExtensions::<TokenAccount>::unpack(account.data())
            .map_err(|_| Error::invalid_params("Invalid param: not a Token account".to_string()))?;
        let mint = &Pubkey::from_str(&token_account.base.mint.to_string())
            .expect("Token account mint should be convertible to Pubkey");
        let (_, decimals) = get_mint_owner_and_decimals(&bank, mint)?;
        let balance = token_amount_to_ui_amount(token_account.base.amount, decimals);
        Ok(new_response(&bank, balance))
    }

    pub fn get_token_supply(
        &self,
        mint: &Pubkey,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<UiTokenAmount>> {
        let bank = self.bank(commitment);
        let mint_account = bank.get_account(mint).ok_or_else(|| {
            Error::invalid_params("Invalid param: could not find account".to_string())
        })?;
        if !is_known_spl_token_id(mint_account.owner()) {
            return Err(Error::invalid_params(
                "Invalid param: not a Token mint".to_string(),
            ));
        }
        let mint = StateWithExtensions::<Mint>::unpack(mint_account.data()).map_err(|_| {
            Error::invalid_params("Invalid param: mint could not be unpacked".to_string())
        })?;

        let supply = token_amount_to_ui_amount(mint.base.supply, mint.base.decimals);
        Ok(new_response(&bank, supply))
    }

    pub fn get_token_largest_accounts(
        &self,
        mint: &Pubkey,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<Vec<RpcTokenAccountBalance>>> {
        let bank = self.bank(commitment);
        let (mint_owner, decimals) = get_mint_owner_and_decimals(&bank, mint)?;
        if !is_known_spl_token_id(&mint_owner) {
            return Err(Error::invalid_params(
                "Invalid param: not a Token mint".to_string(),
            ));
        }
        let mut token_balances: Vec<RpcTokenAccountBalance> = self
            .get_filtered_spl_token_accounts_by_mint(&bank, &mint_owner, mint, vec![])?
            .into_iter()
            .map(|(address, account)| {
                let amount = StateWithExtensions::<TokenAccount>::unpack(account.data())
                    .map(|account| account.base.amount)
                    .unwrap_or(0);
                let amount = token_amount_to_ui_amount(amount, decimals);
                RpcTokenAccountBalance {
                    address: address.to_string(),
                    amount,
                }
            })
            .collect();
        token_balances.sort_by(|a, b| {
            a.amount
                .amount
                .parse::<u64>()
                .unwrap()
                .cmp(&b.amount.amount.parse::<u64>().unwrap())
                .reverse()
        });
        token_balances.truncate(NUM_LARGEST_ACCOUNTS);
        Ok(new_response(&bank, token_balances))
    }

    pub fn get_token_accounts_by_owner(
        &self,
        owner: &Pubkey,
        token_account_filter: TokenAccountsFilter,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>> {
        let RpcAccountInfoConfig {
            encoding,
            data_slice: data_slice_config,
            commitment,
            min_context_slot,
        } = config.unwrap_or_default();
        let bank = self.get_bank_with_config(RpcContextConfig {
            commitment,
            min_context_slot,
        })?;
        let encoding = encoding.unwrap_or(UiAccountEncoding::Binary);
        let (token_program_id, mint) = get_token_program_id_and_mint(&bank, token_account_filter)?;

        let mut filters = vec![];
        if let Some(mint) = mint {
            // Optional filter on Mint address
            filters.push(RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                0,
                mint.to_bytes().into(),
            )));
        }

        let keyed_accounts = self.get_filtered_spl_token_accounts_by_owner(
            &bank,
            &token_program_id,
            owner,
            filters,
        )?;
        let accounts = if encoding == UiAccountEncoding::JsonParsed {
            get_parsed_token_accounts(bank.clone(), keyed_accounts.into_iter()).collect()
        } else {
            keyed_accounts
                .into_iter()
                .map(|(pubkey, account)| {
                    Ok(RpcKeyedAccount {
                        pubkey: pubkey.to_string(),
                        account: encode_account(&account, &pubkey, encoding, data_slice_config)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };
        Ok(new_response(&bank, accounts))
    }

    pub fn get_token_accounts_by_delegate(
        &self,
        delegate: &Pubkey,
        token_account_filter: TokenAccountsFilter,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>> {
        let RpcAccountInfoConfig {
            encoding,
            data_slice: data_slice_config,
            commitment,
            min_context_slot,
        } = config.unwrap_or_default();
        let bank = self.get_bank_with_config(RpcContextConfig {
            commitment,
            min_context_slot,
        })?;
        let encoding = encoding.unwrap_or(UiAccountEncoding::Binary);
        let (token_program_id, mint) = get_token_program_id_and_mint(&bank, token_account_filter)?;

        let mut filters = vec![
            // Filter on Delegate is_some()
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                72,
                bincode::serialize(&1u32).unwrap(),
            )),
            // Filter on Delegate address
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(76, delegate.to_bytes().into())),
        ];
        // Optional filter on Mint address, uses mint account index for scan
        let keyed_accounts = if let Some(mint) = mint {
            self.get_filtered_spl_token_accounts_by_mint(&bank, &token_program_id, &mint, filters)?
        } else {
            // Filter on Token Account state
            filters.push(RpcFilterType::TokenAccountState);
            self.get_filtered_program_accounts(&bank, &token_program_id, filters)?
        };
        let accounts = if encoding == UiAccountEncoding::JsonParsed {
            get_parsed_token_accounts(bank.clone(), keyed_accounts.into_iter()).collect()
        } else {
            keyed_accounts
                .into_iter()
                .map(|(pubkey, account)| {
                    Ok(RpcKeyedAccount {
                        pubkey: pubkey.to_string(),
                        account: encode_account(&account, &pubkey, encoding, data_slice_config)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };
        Ok(new_response(&bank, accounts))
    }

    /// Use a set of filters to get an iterator of keyed program accounts from a bank
    fn get_filtered_program_accounts(
        &self,
        bank: &Arc<Bank>,
        program_id: &Pubkey,
        mut filters: Vec<RpcFilterType>,
    ) -> RpcCustomResult<Vec<(Pubkey, AccountSharedData)>> {
        optimize_filters(&mut filters);
        let filter_closure = |account: &AccountSharedData| {
            filters
                .iter()
                .all(|filter_type| filter_type.allows(account))
        };
        if self
            .config
            .account_indexes
            .contains(&AccountIndex::ProgramId)
        {
            if !self.config.account_indexes.include_key(program_id) {
                return Err(RpcCustomError::KeyExcludedFromSecondaryIndex {
                    index_key: program_id.to_string(),
                });
            }
            Ok(bank
                .get_filtered_indexed_accounts(
                    &IndexKey::ProgramId(*program_id),
                    |account| {
                        // The program-id account index checks for Account owner on inclusion. However, due
                        // to the current AccountsDb implementation, an account may remain in storage as a
                        // zero-lamport AccountSharedData::Default() after being wiped and reinitialized in later
                        // updates. We include the redundant filters here to avoid returning these
                        // accounts.
                        account.owner() == program_id && filter_closure(account)
                    },
                    &ScanConfig::default(),
                    bank.byte_limit_for_scans(),
                )
                .map_err(|e| RpcCustomError::ScanError {
                    message: e.to_string(),
                })?)
        } else {
            // this path does not need to provide a mb limit because we only want to support secondary indexes
            Ok(bank
                .get_filtered_program_accounts(program_id, filter_closure, &ScanConfig::default())
                .map_err(|e| RpcCustomError::ScanError {
                    message: e.to_string(),
                })?)
        }
    }

    /// Get an iterator of spl-token accounts by owner address
    fn get_filtered_spl_token_accounts_by_owner(
        &self,
        bank: &Arc<Bank>,
        program_id: &Pubkey,
        owner_key: &Pubkey,
        mut filters: Vec<RpcFilterType>,
    ) -> RpcCustomResult<Vec<(Pubkey, AccountSharedData)>> {
        // The by-owner accounts index checks for Token Account state and Owner address on
        // inclusion. However, due to the current AccountsDb implementation, an account may remain
        // in storage as a zero-lamport AccountSharedData::Default() after being wiped and reinitialized in
        // later updates. We include the redundant filters here to avoid returning these accounts.
        //
        // Filter on Token Account state
        filters.push(RpcFilterType::TokenAccountState);
        // Filter on Owner address
        filters.push(RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
            SPL_TOKEN_ACCOUNT_OWNER_OFFSET,
            owner_key.to_bytes().into(),
        )));

        if self
            .config
            .account_indexes
            .contains(&AccountIndex::SplTokenOwner)
        {
            if !self.config.account_indexes.include_key(owner_key) {
                return Err(RpcCustomError::KeyExcludedFromSecondaryIndex {
                    index_key: owner_key.to_string(),
                });
            }
            Ok(bank
                .get_filtered_indexed_accounts(
                    &IndexKey::SplTokenOwner(*owner_key),
                    |account| {
                        account.owner() == program_id
                            && filters
                                .iter()
                                .all(|filter_type| filter_type.allows(account))
                    },
                    &ScanConfig::default(),
                    bank.byte_limit_for_scans(),
                )
                .map_err(|e| RpcCustomError::ScanError {
                    message: e.to_string(),
                })?)
        } else {
            self.get_filtered_program_accounts(bank, program_id, filters)
        }
    }

    /// Get an iterator of spl-token accounts by mint address
    fn get_filtered_spl_token_accounts_by_mint(
        &self,
        bank: &Arc<Bank>,
        program_id: &Pubkey,
        mint_key: &Pubkey,
        mut filters: Vec<RpcFilterType>,
    ) -> RpcCustomResult<Vec<(Pubkey, AccountSharedData)>> {
        // The by-mint accounts index checks for Token Account state and Mint address on inclusion.
        // However, due to the current AccountsDb implementation, an account may remain in storage
        // as be zero-lamport AccountSharedData::Default() after being wiped and reinitialized in later
        // updates. We include the redundant filters here to avoid returning these accounts.
        //
        // Filter on Token Account state
        filters.push(RpcFilterType::TokenAccountState);
        // Filter on Mint address
        filters.push(RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
            SPL_TOKEN_ACCOUNT_MINT_OFFSET,
            mint_key.to_bytes().into(),
        )));
        if self
            .config
            .account_indexes
            .contains(&AccountIndex::SplTokenMint)
        {
            if !self.config.account_indexes.include_key(mint_key) {
                return Err(RpcCustomError::KeyExcludedFromSecondaryIndex {
                    index_key: mint_key.to_string(),
                });
            }
            Ok(bank
                .get_filtered_indexed_accounts(
                    &IndexKey::SplTokenMint(*mint_key),
                    |account| {
                        account.owner() == program_id
                            && filters
                                .iter()
                                .all(|filter_type| filter_type.allows(account))
                    },
                    &ScanConfig::default(),
                    bank.byte_limit_for_scans(),
                )
                .map_err(|e| RpcCustomError::ScanError {
                    message: e.to_string(),
                })?)
        } else {
            self.get_filtered_program_accounts(bank, program_id, filters)
        }
    }

    fn get_latest_blockhash(&self, config: RpcContextConfig) -> Result<RpcResponse<RpcBlockhash>> {
        let bank = self.get_bank_with_config(config)?;
        let blockhash = bank.last_blockhash();
        let last_valid_block_height = bank
            .get_blockhash_last_valid_block_height(&blockhash)
            .expect("bank blockhash queue should contain blockhash");
        Ok(new_response(
            &bank,
            RpcBlockhash {
                blockhash: blockhash.to_string(),
                last_valid_block_height,
            },
        ))
    }

    fn is_blockhash_valid(
        &self,
        blockhash: &Hash,
        config: RpcContextConfig,
    ) -> Result<RpcResponse<bool>> {
        let bank = self.get_bank_with_config(config)?;
        let is_valid = bank.is_blockhash_valid(blockhash);
        Ok(new_response(&bank, is_valid))
    }

    fn get_stake_minimum_delegation(&self, config: RpcContextConfig) -> Result<RpcResponse<u64>> {
        let bank = self.get_bank_with_config(config)?;
        let stake_minimum_delegation =
            solana_stake_program::get_minimum_delegation(&bank.feature_set);
        Ok(new_response(&bank, stake_minimum_delegation))
    }

    fn get_recent_prioritization_fees(
        &self,
        pubkeys: Vec<Pubkey>,
    ) -> Result<Vec<RpcPrioritizationFee>> {
        Ok(self
            .prioritization_fee_cache
            .get_prioritization_fees(&pubkeys)
            .into_iter()
            .map(|(slot, prioritization_fee)| RpcPrioritizationFee {
                slot,
                prioritization_fee,
            })
            .collect())
    }
}

fn optimize_filters(filters: &mut [RpcFilterType]) {
    filters.iter_mut().for_each(|filter_type| {
        if let RpcFilterType::Memcmp(compare) = filter_type {
            if let Err(err) = compare.convert_to_raw_bytes() {
                // All filters should have been previously verified
                warn!("Invalid filter: bytes could not be decoded, {err}");
            }
        }
    })
}

fn verify_transaction(
    transaction: &SanitizedTransaction,
    feature_set: &Arc<feature_set::FeatureSet>,
) -> Result<()> {
    #[allow(clippy::question_mark)]
    if transaction.verify().is_err() {
        return Err(RpcCustomError::TransactionSignatureVerificationFailure.into());
    }

    if let Err(e) = transaction.verify_precompiles(feature_set) {
        return Err(RpcCustomError::TransactionPrecompileVerificationFailure(e).into());
    }

    Ok(())
}

fn verify_filter(input: &RpcFilterType) -> Result<()> {
    input
        .verify()
        .map_err(|e| Error::invalid_params(format!("Invalid param: {e:?}")))
}

pub fn verify_pubkey(input: &str) -> Result<Pubkey> {
    input
        .parse()
        .map_err(|e| Error::invalid_params(format!("Invalid param: {e:?}")))
}

fn verify_hash(input: &str) -> Result<Hash> {
    input
        .parse()
        .map_err(|e| Error::invalid_params(format!("Invalid param: {e:?}")))
}

fn verify_signature(input: &str) -> Result<Signature> {
    input
        .parse()
        .map_err(|e| Error::invalid_params(format!("Invalid param: {e:?}")))
}

fn verify_token_account_filter(
    token_account_filter: RpcTokenAccountsFilter,
) -> Result<TokenAccountsFilter> {
    match token_account_filter {
        RpcTokenAccountsFilter::Mint(mint_str) => {
            let mint = verify_pubkey(&mint_str)?;
            Ok(TokenAccountsFilter::Mint(mint))
        }
        RpcTokenAccountsFilter::ProgramId(program_id_str) => {
            let program_id = verify_pubkey(&program_id_str)?;
            Ok(TokenAccountsFilter::ProgramId(program_id))
        }
    }
}

fn verify_and_parse_signatures_for_address_params(
    address: String,
    before: Option<String>,
    until: Option<String>,
    limit: Option<usize>,
) -> Result<(Pubkey, Option<Signature>, Option<Signature>, usize)> {
    let address = verify_pubkey(&address)?;
    let before = before
        .map(|ref before| verify_signature(before))
        .transpose()?;
    let until = until.map(|ref until| verify_signature(until)).transpose()?;
    let limit = limit.unwrap_or(MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS2_LIMIT);

    if limit == 0 || limit > MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS2_LIMIT {
        return Err(Error::invalid_params(format!(
            "Invalid limit; max {MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS2_LIMIT}"
        )));
    }
    Ok((address, before, until, limit))
}

pub(crate) fn check_is_at_least_confirmed(commitment: CommitmentConfig) -> Result<()> {
    if !commitment.is_at_least_confirmed() {
        return Err(Error::invalid_params(
            "Method does not support commitment below `confirmed`",
        ));
    }
    Ok(())
}

fn get_encoded_account(
    bank: &Arc<Bank>,
    pubkey: &Pubkey,
    encoding: UiAccountEncoding,
    data_slice: Option<UiDataSliceConfig>,
) -> Result<Option<UiAccount>> {
    match bank.get_account(pubkey) {
        Some(account) => {
            let response = if is_known_spl_token_id(account.owner())
                && encoding == UiAccountEncoding::JsonParsed
            {
                get_parsed_token_account(bank.clone(), pubkey, account)
            } else {
                encode_account(&account, pubkey, encoding, data_slice)?
            };
            Ok(Some(response))
        }
        None => Ok(None),
    }
}

fn encode_account<T: ReadableAccount>(
    account: &T,
    pubkey: &Pubkey,
    encoding: UiAccountEncoding,
    data_slice: Option<UiDataSliceConfig>,
) -> Result<UiAccount> {
    if (encoding == UiAccountEncoding::Binary || encoding == UiAccountEncoding::Base58)
        && account.data().len() > MAX_BASE58_BYTES
    {
        let message = format!("Encoded binary (base 58) data should be less than {MAX_BASE58_BYTES} bytes, please use Base64 encoding.");
        Err(error::Error {
            code: error::ErrorCode::InvalidRequest,
            message,
            data: None,
        })
    } else {
        Ok(UiAccount::encode(
            pubkey, account, encoding, None, data_slice,
        ))
    }
}

/// Analyze custom filters to determine if the result will be a subset of spl-token accounts by
/// owner.
/// NOTE: `optimize_filters()` should almost always be called before using this method because of
/// the strict match on `MemcmpEncodedBytes::Bytes`.
fn get_spl_token_owner_filter(program_id: &Pubkey, filters: &[RpcFilterType]) -> Option<Pubkey> {
    if !is_known_spl_token_id(program_id) {
        return None;
    }
    let mut data_size_filter: Option<u64> = None;
    let mut memcmp_filter: Option<&[u8]> = None;
    let mut owner_key: Option<Pubkey> = None;
    let mut incorrect_owner_len: Option<usize> = None;
    let mut token_account_state_filter = false;
    let account_packed_len = TokenAccount::get_packed_len();
    for filter in filters {
        match filter {
            RpcFilterType::DataSize(size) => data_size_filter = Some(*size),
            #[allow(deprecated)]
            RpcFilterType::Memcmp(Memcmp {
                offset,
                bytes: MemcmpEncodedBytes::Bytes(bytes),
                ..
            }) if *offset == account_packed_len && *program_id == inline_spl_token_2022::id() => {
                memcmp_filter = Some(bytes)
            }
            #[allow(deprecated)]
            RpcFilterType::Memcmp(Memcmp {
                offset,
                bytes: MemcmpEncodedBytes::Bytes(bytes),
                ..
            }) if *offset == SPL_TOKEN_ACCOUNT_OWNER_OFFSET => {
                if bytes.len() == PUBKEY_BYTES {
                    owner_key = Pubkey::try_from(&bytes[..]).ok();
                } else {
                    incorrect_owner_len = Some(bytes.len());
                }
            }
            RpcFilterType::TokenAccountState => token_account_state_filter = true,
            _ => {}
        }
    }
    if data_size_filter == Some(account_packed_len as u64)
        || memcmp_filter == Some(&[ACCOUNTTYPE_ACCOUNT])
        || token_account_state_filter
    {
        if let Some(incorrect_owner_len) = incorrect_owner_len {
            info!(
                "Incorrect num bytes ({:?}) provided for spl_token_owner_filter",
                incorrect_owner_len
            );
        }
        owner_key
    } else {
        debug!("spl_token program filters do not match by-owner index requisites");
        None
    }
}

/// Analyze custom filters to determine if the result will be a subset of spl-token accounts by
/// mint.
/// NOTE: `optimize_filters()` should almost always be called before using this method because of
/// the strict match on `MemcmpEncodedBytes::Bytes`.
fn get_spl_token_mint_filter(program_id: &Pubkey, filters: &[RpcFilterType]) -> Option<Pubkey> {
    if !is_known_spl_token_id(program_id) {
        return None;
    }
    let mut data_size_filter: Option<u64> = None;
    let mut memcmp_filter: Option<&[u8]> = None;
    let mut mint: Option<Pubkey> = None;
    let mut incorrect_mint_len: Option<usize> = None;
    let mut token_account_state_filter = false;
    let account_packed_len = TokenAccount::get_packed_len();
    for filter in filters {
        match filter {
            RpcFilterType::DataSize(size) => data_size_filter = Some(*size),
            #[allow(deprecated)]
            RpcFilterType::Memcmp(Memcmp {
                offset,
                bytes: MemcmpEncodedBytes::Bytes(bytes),
                ..
            }) if *offset == account_packed_len && *program_id == inline_spl_token_2022::id() => {
                memcmp_filter = Some(bytes)
            }
            #[allow(deprecated)]
            RpcFilterType::Memcmp(Memcmp {
                offset,
                bytes: MemcmpEncodedBytes::Bytes(bytes),
                ..
            }) if *offset == SPL_TOKEN_ACCOUNT_MINT_OFFSET => {
                if bytes.len() == PUBKEY_BYTES {
                    mint = Pubkey::try_from(&bytes[..]).ok();
                } else {
                    incorrect_mint_len = Some(bytes.len());
                }
            }
            RpcFilterType::TokenAccountState => token_account_state_filter = true,
            _ => {}
        }
    }
    if data_size_filter == Some(account_packed_len as u64)
        || memcmp_filter == Some(&[ACCOUNTTYPE_ACCOUNT])
        || token_account_state_filter
    {
        if let Some(incorrect_mint_len) = incorrect_mint_len {
            info!(
                "Incorrect num bytes ({:?}) provided for spl_token_mint_filter",
                incorrect_mint_len
            );
        }
        mint
    } else {
        debug!("spl_token program filters do not match by-mint index requisites");
        None
    }
}

/// Analyze a passed Pubkey that may be a Token program id or Mint address to determine the program
/// id and optional Mint
fn get_token_program_id_and_mint(
    bank: &Arc<Bank>,
    token_account_filter: TokenAccountsFilter,
) -> Result<(Pubkey, Option<Pubkey>)> {
    match token_account_filter {
        TokenAccountsFilter::Mint(mint) => {
            let (mint_owner, _) = get_mint_owner_and_decimals(bank, &mint)?;
            if !is_known_spl_token_id(&mint_owner) {
                return Err(Error::invalid_params(
                    "Invalid param: not a Token mint".to_string(),
                ));
            }
            Ok((mint_owner, Some(mint)))
        }
        TokenAccountsFilter::ProgramId(program_id) => {
            if is_known_spl_token_id(&program_id) {
                Ok((program_id, None))
            } else {
                Err(Error::invalid_params(
                    "Invalid param: unrecognized Token program id".to_string(),
                ))
            }
        }
    }
}

fn _send_transaction(
    meta: JsonRpcRequestProcessor,
    signature: Signature,
    wire_transaction: Vec<u8>,
    last_valid_block_height: u64,
    durable_nonce_info: Option<(Pubkey, Hash)>,
    max_retries: Option<usize>,
) -> Result<String> {
    let transaction_info = TransactionInfo::new(
        signature,
        wire_transaction,
        last_valid_block_height,
        durable_nonce_info,
        max_retries,
        None,
    );
    meta.transaction_sender
        .lock()
        .unwrap()
        .send(transaction_info)
        .unwrap_or_else(|err| warn!("Failed to enqueue transaction: {}", err));

    Ok(signature.to_string())
}

// Minimal RPC interface that known validators are expected to provide
pub mod rpc_minimal {
    use super::*;
    #[rpc]
    pub trait Minimal {
        type Metadata;

        #[rpc(meta, name = "getBalance")]
        fn get_balance(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<u64>>;

        #[rpc(meta, name = "getEpochInfo")]
        fn get_epoch_info(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<EpochInfo>;

        #[rpc(meta, name = "getGenesisHash")]
        fn get_genesis_hash(&self, meta: Self::Metadata) -> Result<String>;

        #[rpc(meta, name = "getHealth")]
        fn get_health(&self, meta: Self::Metadata) -> Result<String>;

        #[rpc(meta, name = "getIdentity")]
        fn get_identity(&self, meta: Self::Metadata) -> Result<RpcIdentity>;

        #[rpc(meta, name = "getSlot")]
        fn get_slot(&self, meta: Self::Metadata, config: Option<RpcContextConfig>) -> Result<Slot>;

        #[rpc(meta, name = "getBlockHeight")]
        fn get_block_height(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<u64>;

        #[rpc(meta, name = "getHighestSnapshotSlot")]
        fn get_highest_snapshot_slot(&self, meta: Self::Metadata) -> Result<RpcSnapshotSlotInfo>;

        #[rpc(meta, name = "getTransactionCount")]
        fn get_transaction_count(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<u64>;

        #[rpc(meta, name = "getVersion")]
        fn get_version(&self, meta: Self::Metadata) -> Result<RpcVersionInfo>;

        // TODO: Refactor `solana-validator wait-for-restart-window` to not require this method, so
        //       it can be removed from rpc_minimal
        #[rpc(meta, name = "getVoteAccounts")]
        fn get_vote_accounts(
            &self,
            meta: Self::Metadata,
            config: Option<RpcGetVoteAccountsConfig>,
        ) -> Result<RpcVoteAccountStatus>;

        // TODO: Refactor `solana-validator wait-for-restart-window` to not require this method, so
        //       it can be removed from rpc_minimal
        #[rpc(meta, name = "getLeaderSchedule")]
        fn get_leader_schedule(
            &self,
            meta: Self::Metadata,
            options: Option<RpcLeaderScheduleConfigWrapper>,
            config: Option<RpcLeaderScheduleConfig>,
        ) -> Result<Option<RpcLeaderSchedule>>;
    }

    pub struct MinimalImpl;
    impl Minimal for MinimalImpl {
        type Metadata = JsonRpcRequestProcessor;

        fn get_balance(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<u64>> {
            debug!("get_balance rpc request received: {:?}", pubkey_str);
            let pubkey = verify_pubkey(&pubkey_str)?;
            meta.get_balance(&pubkey, config.unwrap_or_default())
        }

        fn get_epoch_info(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<EpochInfo> {
            debug!("get_epoch_info rpc request received");
            let bank = meta.get_bank_with_config(config.unwrap_or_default())?;
            Ok(bank.get_epoch_info())
        }

        fn get_genesis_hash(&self, meta: Self::Metadata) -> Result<String> {
            debug!("get_genesis_hash rpc request received");
            Ok(meta.genesis_hash.to_string())
        }

        fn get_health(&self, meta: Self::Metadata) -> Result<String> {
            match meta.health.check() {
                RpcHealthStatus::Ok => Ok("ok".to_string()),
                RpcHealthStatus::Unknown => Err(RpcCustomError::NodeUnhealthy {
                    num_slots_behind: None,
                }
                .into()),
                RpcHealthStatus::Behind { num_slots } => Err(RpcCustomError::NodeUnhealthy {
                    num_slots_behind: Some(num_slots),
                }
                .into()),
            }
        }

        fn get_identity(&self, meta: Self::Metadata) -> Result<RpcIdentity> {
            debug!("get_identity rpc request received");
            Ok(RpcIdentity {
                identity: meta.cluster_info.id().to_string(),
            })
        }

        fn get_slot(&self, meta: Self::Metadata, config: Option<RpcContextConfig>) -> Result<Slot> {
            debug!("get_slot rpc request received");
            meta.get_slot(config.unwrap_or_default())
        }

        fn get_block_height(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<u64> {
            debug!("get_block_height rpc request received");
            meta.get_block_height(config.unwrap_or_default())
        }

        fn get_highest_snapshot_slot(&self, meta: Self::Metadata) -> Result<RpcSnapshotSlotInfo> {
            debug!("get_highest_snapshot_slot rpc request received");

            if meta.snapshot_config.is_none() {
                return Err(RpcCustomError::NoSnapshot.into());
            }

            let (full_snapshot_archives_dir, incremental_snapshot_archives_dir) = meta
                .snapshot_config
                .map(|snapshot_config| {
                    (
                        snapshot_config.full_snapshot_archives_dir,
                        snapshot_config.incremental_snapshot_archives_dir,
                    )
                })
                .unwrap();

            let full_snapshot_slot =
                snapshot_utils::get_highest_full_snapshot_archive_slot(full_snapshot_archives_dir)
                    .ok_or(RpcCustomError::NoSnapshot)?;
            let incremental_snapshot_slot =
                snapshot_utils::get_highest_incremental_snapshot_archive_slot(
                    incremental_snapshot_archives_dir,
                    full_snapshot_slot,
                );

            Ok(RpcSnapshotSlotInfo {
                full: full_snapshot_slot,
                incremental: incremental_snapshot_slot,
            })
        }

        fn get_transaction_count(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<u64> {
            debug!("get_transaction_count rpc request received");
            meta.get_transaction_count(config.unwrap_or_default())
        }

        fn get_version(&self, _: Self::Metadata) -> Result<RpcVersionInfo> {
            debug!("get_version rpc request received");
            let version = solana_version::Version::default();
            Ok(RpcVersionInfo {
                solana_core: version.to_string(),
                feature_set: Some(version.feature_set),
            })
        }

        // TODO: Refactor `solana-validator wait-for-restart-window` to not require this method, so
        //       it can be removed from rpc_minimal
        fn get_vote_accounts(
            &self,
            meta: Self::Metadata,
            config: Option<RpcGetVoteAccountsConfig>,
        ) -> Result<RpcVoteAccountStatus> {
            debug!("get_vote_accounts rpc request received");
            meta.get_vote_accounts(config)
        }

        // TODO: Refactor `solana-validator wait-for-restart-window` to not require this method, so
        //       it can be removed from rpc_minimal
        fn get_leader_schedule(
            &self,
            meta: Self::Metadata,
            options: Option<RpcLeaderScheduleConfigWrapper>,
            config: Option<RpcLeaderScheduleConfig>,
        ) -> Result<Option<RpcLeaderSchedule>> {
            let (slot, maybe_config) = options.map(|options| options.unzip()).unwrap_or_default();
            let config = maybe_config.or(config).unwrap_or_default();

            if let Some(ref identity) = config.identity {
                let _ = verify_pubkey(identity)?;
            }

            let bank = meta.bank(config.commitment);
            let slot = slot.unwrap_or_else(|| bank.slot());
            let epoch = bank.epoch_schedule().get_epoch(slot);

            debug!("get_leader_schedule rpc request received: {:?}", slot);

            Ok(meta
                .leader_schedule_cache
                .get_epoch_leader_schedule(epoch)
                .map(|leader_schedule| {
                    let mut schedule_by_identity =
                        solana_ledger::leader_schedule_utils::leader_schedule_by_identity(
                            leader_schedule.get_slot_leaders().iter().enumerate(),
                        );
                    if let Some(identity) = config.identity {
                        schedule_by_identity.retain(|k, _| *k == identity);
                    }
                    schedule_by_identity
                }))
        }
    }
}

// RPC interface that only depends on immediate Bank data
// Expected to be provided by API nodes
pub mod rpc_bank {
    use super::*;
    #[rpc]
    pub trait BankData {
        type Metadata;

        #[rpc(meta, name = "getMinimumBalanceForRentExemption")]
        fn get_minimum_balance_for_rent_exemption(
            &self,
            meta: Self::Metadata,
            data_len: usize,
            commitment: Option<CommitmentConfig>,
        ) -> Result<u64>;

        #[rpc(meta, name = "getInflationGovernor")]
        fn get_inflation_governor(
            &self,
            meta: Self::Metadata,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcInflationGovernor>;

        #[rpc(meta, name = "getInflationRate")]
        fn get_inflation_rate(&self, meta: Self::Metadata) -> Result<RpcInflationRate>;

        #[rpc(meta, name = "getEpochSchedule")]
        fn get_epoch_schedule(&self, meta: Self::Metadata) -> Result<EpochSchedule>;

        #[rpc(meta, name = "getSlotLeader")]
        fn get_slot_leader(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<String>;

        #[rpc(meta, name = "getSlotLeaders")]
        fn get_slot_leaders(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            limit: u64,
        ) -> Result<Vec<String>>;

        #[rpc(meta, name = "getBlockProduction")]
        fn get_block_production(
            &self,
            meta: Self::Metadata,
            config: Option<RpcBlockProductionConfig>,
        ) -> Result<RpcResponse<RpcBlockProduction>>;
    }

    pub struct BankDataImpl;
    impl BankData for BankDataImpl {
        type Metadata = JsonRpcRequestProcessor;

        fn get_minimum_balance_for_rent_exemption(
            &self,
            meta: Self::Metadata,
            data_len: usize,
            commitment: Option<CommitmentConfig>,
        ) -> Result<u64> {
            debug!(
                "get_minimum_balance_for_rent_exemption rpc request received: {:?}",
                data_len
            );
            if data_len as u64 > system_instruction::MAX_PERMITTED_DATA_LENGTH {
                return Err(Error::invalid_request());
            }
            Ok(meta.get_minimum_balance_for_rent_exemption(data_len, commitment))
        }

        fn get_inflation_governor(
            &self,
            meta: Self::Metadata,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcInflationGovernor> {
            debug!("get_inflation_governor rpc request received");
            Ok(meta.get_inflation_governor(commitment))
        }

        fn get_inflation_rate(&self, meta: Self::Metadata) -> Result<RpcInflationRate> {
            debug!("get_inflation_rate rpc request received");
            Ok(meta.get_inflation_rate())
        }

        fn get_epoch_schedule(&self, meta: Self::Metadata) -> Result<EpochSchedule> {
            debug!("get_epoch_schedule rpc request received");
            Ok(meta.get_epoch_schedule())
        }

        fn get_slot_leader(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<String> {
            debug!("get_slot_leader rpc request received");
            meta.get_slot_leader(config.unwrap_or_default())
        }

        fn get_slot_leaders(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            limit: u64,
        ) -> Result<Vec<String>> {
            debug!(
                "get_slot_leaders rpc request received (start: {} limit: {})",
                start_slot, limit
            );

            let limit = limit as usize;
            if limit > MAX_GET_SLOT_LEADERS {
                return Err(Error::invalid_params(format!(
                    "Invalid limit; max {MAX_GET_SLOT_LEADERS}"
                )));
            }

            Ok(meta
                .get_slot_leaders(None, start_slot, limit)?
                .into_iter()
                .map(|identity| identity.to_string())
                .collect())
        }

        fn get_block_production(
            &self,
            meta: Self::Metadata,
            config: Option<RpcBlockProductionConfig>,
        ) -> Result<RpcResponse<RpcBlockProduction>> {
            debug!("get_block_production rpc request received");

            let config = config.unwrap_or_default();
            let filter_by_identity = if let Some(ref identity) = config.identity {
                Some(verify_pubkey(identity)?)
            } else {
                None
            };

            let bank = meta.bank(config.commitment);
            let (first_slot, last_slot) = match config.range {
                None => (
                    bank.epoch_schedule().get_first_slot_in_epoch(bank.epoch()),
                    bank.slot(),
                ),
                Some(range) => {
                    let first_slot = range.first_slot;
                    let last_slot = range.last_slot.unwrap_or_else(|| bank.slot());
                    if last_slot < first_slot {
                        return Err(Error::invalid_params(format!(
                            "lastSlot, {last_slot}, cannot be less than firstSlot, {first_slot}"
                        )));
                    }
                    (first_slot, last_slot)
                }
            };

            let slot_history = bank.get_slot_history();
            if first_slot < slot_history.oldest() {
                return Err(Error::invalid_params(format!(
                    "firstSlot, {}, is too small; min {}",
                    first_slot,
                    slot_history.oldest()
                )));
            }
            if last_slot > slot_history.newest() {
                return Err(Error::invalid_params(format!(
                    "lastSlot, {}, is too large; max {}",
                    last_slot,
                    slot_history.newest()
                )));
            }

            let slot_leaders = meta.get_slot_leaders(
                config.commitment,
                first_slot,
                last_slot.saturating_sub(first_slot) as usize + 1, // +1 because last_slot is inclusive
            )?;

            let mut block_production: HashMap<_, (usize, usize)> = HashMap::new();

            let mut slot = first_slot;
            for identity in slot_leaders {
                if let Some(ref filter_by_identity) = filter_by_identity {
                    if identity != *filter_by_identity {
                        slot += 1;
                        continue;
                    }
                }

                let mut entry = block_production.entry(identity).or_default();
                if slot_history.check(slot) == solana_sdk::slot_history::Check::Found {
                    entry.1 += 1; // Increment blocks_produced
                }
                entry.0 += 1; // Increment leader_slots
                slot += 1;
            }

            Ok(new_response(
                &bank,
                RpcBlockProduction {
                    by_identity: block_production
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                    range: RpcBlockProductionRange {
                        first_slot,
                        last_slot,
                    },
                },
            ))
        }
    }
}

// RPC interface that depends on AccountsDB
// Expected to be provided by API nodes
pub mod rpc_accounts {
    use super::*;
    #[rpc]
    pub trait AccountsData {
        type Metadata;

        #[rpc(meta, name = "getAccountInfo")]
        fn get_account_info(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            config: Option<RpcAccountInfoConfig>,
        ) -> Result<RpcResponse<Option<UiAccount>>>;

        #[rpc(meta, name = "getMultipleAccounts")]
        fn get_multiple_accounts(
            &self,
            meta: Self::Metadata,
            pubkey_strs: Vec<String>,
            config: Option<RpcAccountInfoConfig>,
        ) -> Result<RpcResponse<Vec<Option<UiAccount>>>>;

        #[rpc(meta, name = "getBlockCommitment")]
        fn get_block_commitment(
            &self,
            meta: Self::Metadata,
            block: Slot,
        ) -> Result<RpcBlockCommitment<BlockCommitmentArray>>;

        #[rpc(meta, name = "getStakeActivation")]
        fn get_stake_activation(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            config: Option<RpcEpochConfig>,
        ) -> Result<RpcStakeActivation>;

        // SPL Token-specific RPC endpoints
        // See https://github.com/solana-labs/solana-program-library/releases/tag/token-v2.0.0 for
        // program details

        #[rpc(meta, name = "getTokenAccountBalance")]
        fn get_token_account_balance(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<UiTokenAmount>>;

        #[rpc(meta, name = "getTokenSupply")]
        fn get_token_supply(
            &self,
            meta: Self::Metadata,
            mint_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<UiTokenAmount>>;
    }

    pub struct AccountsDataImpl;
    impl AccountsData for AccountsDataImpl {
        type Metadata = JsonRpcRequestProcessor;

        fn get_account_info(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            config: Option<RpcAccountInfoConfig>,
        ) -> Result<RpcResponse<Option<UiAccount>>> {
            debug!("get_account_info rpc request received: {:?}", pubkey_str);
            let pubkey = verify_pubkey(&pubkey_str)?;
            meta.get_account_info(&pubkey, config)
        }

        fn get_multiple_accounts(
            &self,
            meta: Self::Metadata,
            pubkey_strs: Vec<String>,
            config: Option<RpcAccountInfoConfig>,
        ) -> Result<RpcResponse<Vec<Option<UiAccount>>>> {
            debug!(
                "get_multiple_accounts rpc request received: {:?}",
                pubkey_strs.len()
            );

            let max_multiple_accounts = meta
                .config
                .max_multiple_accounts
                .unwrap_or(MAX_MULTIPLE_ACCOUNTS);
            if pubkey_strs.len() > max_multiple_accounts {
                return Err(Error::invalid_params(format!(
                    "Too many inputs provided; max {max_multiple_accounts}"
                )));
            }
            let pubkeys = pubkey_strs
                .into_iter()
                .map(|pubkey_str| verify_pubkey(&pubkey_str))
                .collect::<Result<Vec<_>>>()?;
            meta.get_multiple_accounts(pubkeys, config)
        }

        fn get_block_commitment(
            &self,
            meta: Self::Metadata,
            block: Slot,
        ) -> Result<RpcBlockCommitment<BlockCommitmentArray>> {
            debug!("get_block_commitment rpc request received");
            Ok(meta.get_block_commitment(block))
        }

        fn get_stake_activation(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            config: Option<RpcEpochConfig>,
        ) -> Result<RpcStakeActivation> {
            debug!(
                "get_stake_activation rpc request received: {:?}",
                pubkey_str
            );
            let pubkey = verify_pubkey(&pubkey_str)?;
            meta.get_stake_activation(&pubkey, config)
        }

        fn get_token_account_balance(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<UiTokenAmount>> {
            debug!(
                "get_token_account_balance rpc request received: {:?}",
                pubkey_str
            );
            let pubkey = verify_pubkey(&pubkey_str)?;
            meta.get_token_account_balance(&pubkey, commitment)
        }

        fn get_token_supply(
            &self,
            meta: Self::Metadata,
            mint_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<UiTokenAmount>> {
            debug!("get_token_supply rpc request received: {:?}", mint_str);
            let mint = verify_pubkey(&mint_str)?;
            meta.get_token_supply(&mint, commitment)
        }
    }
}

// RPC interface that depends on AccountsDB and requires accounts scan
// Expected to be provided by API nodes for now, but collected for easy separation and removal in
// the future.
pub mod rpc_accounts_scan {
    use super::*;
    #[rpc]
    pub trait AccountsScan {
        type Metadata;

        #[rpc(meta, name = "getProgramAccounts")]
        fn get_program_accounts(
            &self,
            meta: Self::Metadata,
            program_id_str: String,
            config: Option<RpcProgramAccountsConfig>,
        ) -> Result<OptionalContext<Vec<RpcKeyedAccount>>>;

        #[rpc(meta, name = "getLargestAccounts")]
        fn get_largest_accounts(
            &self,
            meta: Self::Metadata,
            config: Option<RpcLargestAccountsConfig>,
        ) -> Result<RpcResponse<Vec<RpcAccountBalance>>>;

        #[rpc(meta, name = "getSupply")]
        fn get_supply(
            &self,
            meta: Self::Metadata,
            config: Option<RpcSupplyConfig>,
        ) -> Result<RpcResponse<RpcSupply>>;

        // SPL Token-specific RPC endpoints
        // See https://github.com/solana-labs/solana-program-library/releases/tag/token-v2.0.0 for
        // program details

        #[rpc(meta, name = "getTokenLargestAccounts")]
        fn get_token_largest_accounts(
            &self,
            meta: Self::Metadata,
            mint_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<Vec<RpcTokenAccountBalance>>>;

        #[rpc(meta, name = "getTokenAccountsByOwner")]
        fn get_token_accounts_by_owner(
            &self,
            meta: Self::Metadata,
            owner_str: String,
            token_account_filter: RpcTokenAccountsFilter,
            config: Option<RpcAccountInfoConfig>,
        ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>>;

        #[rpc(meta, name = "getTokenAccountsByDelegate")]
        fn get_token_accounts_by_delegate(
            &self,
            meta: Self::Metadata,
            delegate_str: String,
            token_account_filter: RpcTokenAccountsFilter,
            config: Option<RpcAccountInfoConfig>,
        ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>>;
    }

    pub struct AccountsScanImpl;
    impl AccountsScan for AccountsScanImpl {
        type Metadata = JsonRpcRequestProcessor;

        fn get_program_accounts(
            &self,
            meta: Self::Metadata,
            program_id_str: String,
            config: Option<RpcProgramAccountsConfig>,
        ) -> Result<OptionalContext<Vec<RpcKeyedAccount>>> {
            debug!(
                "get_program_accounts rpc request received: {:?}",
                program_id_str
            );
            let program_id = verify_pubkey(&program_id_str)?;
            let (config, filters, with_context) = if let Some(config) = config {
                (
                    Some(config.account_config),
                    config.filters.unwrap_or_default(),
                    config.with_context.unwrap_or_default(),
                )
            } else {
                (None, vec![], false)
            };
            if filters.len() > MAX_GET_PROGRAM_ACCOUNT_FILTERS {
                return Err(Error::invalid_params(format!(
                    "Too many filters provided; max {MAX_GET_PROGRAM_ACCOUNT_FILTERS}"
                )));
            }
            for filter in &filters {
                verify_filter(filter)?;
            }
            meta.get_program_accounts(&program_id, config, filters, with_context)
        }

        fn get_largest_accounts(
            &self,
            meta: Self::Metadata,
            config: Option<RpcLargestAccountsConfig>,
        ) -> Result<RpcResponse<Vec<RpcAccountBalance>>> {
            debug!("get_largest_accounts rpc request received");
            Ok(meta.get_largest_accounts(config)?)
        }

        fn get_supply(
            &self,
            meta: Self::Metadata,
            config: Option<RpcSupplyConfig>,
        ) -> Result<RpcResponse<RpcSupply>> {
            debug!("get_supply rpc request received");
            Ok(meta.get_supply(config)?)
        }

        fn get_token_largest_accounts(
            &self,
            meta: Self::Metadata,
            mint_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<Vec<RpcTokenAccountBalance>>> {
            debug!(
                "get_token_largest_accounts rpc request received: {:?}",
                mint_str
            );
            let mint = verify_pubkey(&mint_str)?;
            meta.get_token_largest_accounts(&mint, commitment)
        }

        fn get_token_accounts_by_owner(
            &self,
            meta: Self::Metadata,
            owner_str: String,
            token_account_filter: RpcTokenAccountsFilter,
            config: Option<RpcAccountInfoConfig>,
        ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>> {
            debug!(
                "get_token_accounts_by_owner rpc request received: {:?}",
                owner_str
            );
            let owner = verify_pubkey(&owner_str)?;
            let token_account_filter = verify_token_account_filter(token_account_filter)?;
            meta.get_token_accounts_by_owner(&owner, token_account_filter, config)
        }

        fn get_token_accounts_by_delegate(
            &self,
            meta: Self::Metadata,
            delegate_str: String,
            token_account_filter: RpcTokenAccountsFilter,
            config: Option<RpcAccountInfoConfig>,
        ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>> {
            debug!(
                "get_token_accounts_by_delegate rpc request received: {:?}",
                delegate_str
            );
            let delegate = verify_pubkey(&delegate_str)?;
            let token_account_filter = verify_token_account_filter(token_account_filter)?;
            meta.get_token_accounts_by_delegate(&delegate, token_account_filter, config)
        }
    }
}

// Full RPC interface that an API node is expected to provide
// (rpc_minimal should also be provided by an API node)
pub mod rpc_full {
    use {
        super::*,
        solana_sdk::message::{SanitizedVersionedMessage, VersionedMessage},
    };
    #[rpc]
    pub trait Full {
        type Metadata;

        #[rpc(meta, name = "getInflationReward")]
        fn get_inflation_reward(
            &self,
            meta: Self::Metadata,
            address_strs: Vec<String>,
            config: Option<RpcEpochConfig>,
        ) -> BoxFuture<Result<Vec<Option<RpcInflationReward>>>>;

        #[rpc(meta, name = "getClusterNodes")]
        fn get_cluster_nodes(&self, meta: Self::Metadata) -> Result<Vec<RpcContactInfo>>;

        #[rpc(meta, name = "getRecentPerformanceSamples")]
        fn get_recent_performance_samples(
            &self,
            meta: Self::Metadata,
            limit: Option<usize>,
        ) -> Result<Vec<RpcPerfSample>>;

        #[rpc(meta, name = "getSignatureStatuses")]
        fn get_signature_statuses(
            &self,
            meta: Self::Metadata,
            signature_strs: Vec<String>,
            config: Option<RpcSignatureStatusConfig>,
        ) -> BoxFuture<Result<RpcResponse<Vec<Option<TransactionStatus>>>>>;

        #[rpc(meta, name = "getMaxRetransmitSlot")]
        fn get_max_retransmit_slot(&self, meta: Self::Metadata) -> Result<Slot>;

        #[rpc(meta, name = "getMaxShredInsertSlot")]
        fn get_max_shred_insert_slot(&self, meta: Self::Metadata) -> Result<Slot>;

        #[rpc(meta, name = "requestAirdrop")]
        fn request_airdrop(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            lamports: u64,
            config: Option<RpcRequestAirdropConfig>,
        ) -> Result<String>;

        #[rpc(meta, name = "sendTransaction")]
        fn send_transaction(
            &self,
            meta: Self::Metadata,
            data: String,
            config: Option<RpcSendTransactionConfig>,
        ) -> Result<String>;

        #[rpc(meta, name = "simulateTransaction")]
        fn simulate_transaction(
            &self,
            meta: Self::Metadata,
            data: String,
            config: Option<RpcSimulateTransactionConfig>,
        ) -> Result<RpcResponse<RpcSimulateTransactionResult>>;

        #[rpc(meta, name = "minimumLedgerSlot")]
        fn minimum_ledger_slot(&self, meta: Self::Metadata) -> Result<Slot>;

        #[rpc(meta, name = "getBlock")]
        fn get_block(
            &self,
            meta: Self::Metadata,
            slot: Slot,
            config: Option<RpcEncodingConfigWrapper<RpcBlockConfig>>,
        ) -> BoxFuture<Result<Option<UiConfirmedBlock>>>;

        #[rpc(meta, name = "getBlockTime")]
        fn get_block_time(
            &self,
            meta: Self::Metadata,
            slot: Slot,
        ) -> BoxFuture<Result<Option<UnixTimestamp>>>;

        #[rpc(meta, name = "getBlocks")]
        fn get_blocks(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            config: Option<RpcBlocksConfigWrapper>,
            commitment: Option<CommitmentConfig>,
        ) -> BoxFuture<Result<Vec<Slot>>>;

        #[rpc(meta, name = "getBlocksWithLimit")]
        fn get_blocks_with_limit(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            limit: usize,
            commitment: Option<CommitmentConfig>,
        ) -> BoxFuture<Result<Vec<Slot>>>;

        #[rpc(meta, name = "getTransaction")]
        fn get_transaction(
            &self,
            meta: Self::Metadata,
            signature_str: String,
            config: Option<RpcEncodingConfigWrapper<RpcTransactionConfig>>,
        ) -> BoxFuture<Result<Option<EncodedConfirmedTransactionWithStatusMeta>>>;

        #[rpc(meta, name = "getSignaturesForAddress")]
        fn get_signatures_for_address(
            &self,
            meta: Self::Metadata,
            address: String,
            config: Option<RpcSignaturesForAddressConfig>,
        ) -> BoxFuture<Result<Vec<RpcConfirmedTransactionStatusWithSignature>>>;

        #[rpc(meta, name = "getFirstAvailableBlock")]
        fn get_first_available_block(&self, meta: Self::Metadata) -> BoxFuture<Result<Slot>>;

        #[rpc(meta, name = "getLatestBlockhash")]
        fn get_latest_blockhash(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<RpcBlockhash>>;

        #[rpc(meta, name = "isBlockhashValid")]
        fn is_blockhash_valid(
            &self,
            meta: Self::Metadata,
            blockhash: String,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<bool>>;

        #[rpc(meta, name = "getFeeForMessage")]
        fn get_fee_for_message(
            &self,
            meta: Self::Metadata,
            data: String,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<Option<u64>>>;

        #[rpc(meta, name = "getStakeMinimumDelegation")]
        fn get_stake_minimum_delegation(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<u64>>;

        #[rpc(meta, name = "getRecentPrioritizationFees")]
        fn get_recent_prioritization_fees(
            &self,
            meta: Self::Metadata,
            pubkey_strs: Option<Vec<String>>,
        ) -> Result<Vec<RpcPrioritizationFee>>;
    }

    pub struct FullImpl;
    impl Full for FullImpl {
        type Metadata = JsonRpcRequestProcessor;

        fn get_recent_performance_samples(
            &self,
            meta: Self::Metadata,
            limit: Option<usize>,
        ) -> Result<Vec<RpcPerfSample>> {
            debug!("get_recent_performance_samples request received");

            let limit = limit.unwrap_or(PERFORMANCE_SAMPLES_LIMIT);

            if limit > PERFORMANCE_SAMPLES_LIMIT {
                return Err(Error::invalid_params(format!(
                    "Invalid limit; max {PERFORMANCE_SAMPLES_LIMIT}"
                )));
            }

            Ok(meta
                .blockstore
                .get_recent_perf_samples(limit)
                .map_err(|err| {
                    warn!("get_recent_performance_samples failed: {:?}", err);
                    Error::invalid_request()
                })?
                .into_iter()
                .map(|(slot, sample)| rpc_perf_sample_from_perf_sample(slot, sample))
                .collect())
        }

        fn get_cluster_nodes(&self, meta: Self::Metadata) -> Result<Vec<RpcContactInfo>> {
            debug!("get_cluster_nodes rpc request received");
            let cluster_info = &meta.cluster_info;
            let socket_addr_space = cluster_info.socket_addr_space();
            let my_shred_version = cluster_info.my_shred_version();
            Ok(cluster_info
                .all_peers()
                .iter()
                .filter_map(|(contact_info, _)| {
                    if my_shred_version == contact_info.shred_version()
                        && contact_info
                            .gossip()
                            .map(|addr| socket_addr_space.check(&addr))
                            .unwrap_or_default()
                    {
                        let (version, feature_set) = if let Some(version) =
                            cluster_info.get_node_version(contact_info.pubkey())
                        {
                            (Some(version.to_string()), Some(version.feature_set))
                        } else {
                            (None, None)
                        };
                        Some(RpcContactInfo {
                            pubkey: contact_info.pubkey().to_string(),
                            gossip: contact_info.gossip().ok(),
                            tpu: contact_info
                                .tpu(Protocol::UDP)
                                .ok()
                                .filter(|addr| socket_addr_space.check(addr)),
                            tpu_quic: contact_info
                                .tpu(Protocol::QUIC)
                                .ok()
                                .filter(|addr| socket_addr_space.check(addr)),
                            rpc: contact_info
                                .rpc()
                                .ok()
                                .filter(|addr| socket_addr_space.check(addr)),
                            pubsub: contact_info
                                .rpc_pubsub()
                                .ok()
                                .filter(|addr| socket_addr_space.check(addr)),
                            version,
                            feature_set,
                            shred_version: Some(my_shred_version),
                        })
                    } else {
                        None // Exclude spy nodes
                    }
                })
                .collect())
        }

        fn get_signature_statuses(
            &self,
            meta: Self::Metadata,
            signature_strs: Vec<String>,
            config: Option<RpcSignatureStatusConfig>,
        ) -> BoxFuture<Result<RpcResponse<Vec<Option<TransactionStatus>>>>> {
            debug!(
                "get_signature_statuses rpc request received: {:?}",
                signature_strs.len()
            );
            if signature_strs.len() > MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS {
                return Box::pin(future::err(Error::invalid_params(format!(
                    "Too many inputs provided; max {MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS}"
                ))));
            }
            let mut signatures: Vec<Signature> = vec![];
            for signature_str in signature_strs {
                match verify_signature(&signature_str) {
                    Ok(signature) => {
                        signatures.push(signature);
                    }
                    Err(err) => return Box::pin(future::err(err)),
                }
            }
            Box::pin(async move { meta.get_signature_statuses(signatures, config).await })
        }

        fn get_max_retransmit_slot(&self, meta: Self::Metadata) -> Result<Slot> {
            debug!("get_max_retransmit_slot rpc request received");
            Ok(meta.get_max_retransmit_slot())
        }

        fn get_max_shred_insert_slot(&self, meta: Self::Metadata) -> Result<Slot> {
            debug!("get_max_shred_insert_slot rpc request received");
            Ok(meta.get_max_shred_insert_slot())
        }

        fn request_airdrop(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            lamports: u64,
            config: Option<RpcRequestAirdropConfig>,
        ) -> Result<String> {
            debug!("request_airdrop rpc request received");
            trace!(
                "request_airdrop id={} lamports={} config: {:?}",
                pubkey_str,
                lamports,
                &config
            );

            let faucet_addr = meta.config.faucet_addr.ok_or_else(Error::invalid_request)?;
            let pubkey = verify_pubkey(&pubkey_str)?;

            let config = config.unwrap_or_default();
            let bank = meta.bank(config.commitment);

            let blockhash = if let Some(blockhash) = config.recent_blockhash {
                verify_hash(&blockhash)?
            } else {
                bank.confirmed_last_blockhash()
            };
            let last_valid_block_height = bank
                .get_blockhash_last_valid_block_height(&blockhash)
                .unwrap_or(0);

            let transaction =
                request_airdrop_transaction(&faucet_addr, &pubkey, lamports, blockhash).map_err(
                    |err| {
                        info!("request_airdrop_transaction failed: {:?}", err);
                        Error::internal_error()
                    },
                )?;

            let wire_transaction = serialize(&transaction).map_err(|err| {
                info!("request_airdrop: serialize error: {:?}", err);
                Error::internal_error()
            })?;

            let signature = if !transaction.signatures.is_empty() {
                transaction.signatures[0]
            } else {
                return Err(RpcCustomError::TransactionSignatureVerificationFailure.into());
            };

            _send_transaction(
                meta,
                signature,
                wire_transaction,
                last_valid_block_height,
                None,
                None,
            )
        }

        fn send_transaction(
            &self,
            meta: Self::Metadata,
            data: String,
            config: Option<RpcSendTransactionConfig>,
        ) -> Result<String> {
            debug!("send_transaction rpc request received");
            let RpcSendTransactionConfig {
                skip_preflight,
                preflight_commitment,
                encoding,
                max_retries,
                min_context_slot,
            } = config.unwrap_or_default();
            let tx_encoding = encoding.unwrap_or(UiTransactionEncoding::Base58);
            let binary_encoding = tx_encoding.into_binary_encoding().ok_or_else(|| {
                Error::invalid_params(format!(
                    "unsupported encoding: {tx_encoding}. Supported encodings: base58, base64"
                ))
            })?;
            let (wire_transaction, unsanitized_tx) =
                decode_and_deserialize::<VersionedTransaction>(data, binary_encoding)?;

            let preflight_commitment =
                preflight_commitment.map(|commitment| CommitmentConfig { commitment });
            let preflight_bank = &*meta.get_bank_with_config(RpcContextConfig {
                commitment: preflight_commitment,
                min_context_slot,
            })?;

            let transaction = sanitize_transaction(unsanitized_tx, preflight_bank)?;
            let signature = *transaction.signature();

            let mut last_valid_block_height = preflight_bank
                .get_blockhash_last_valid_block_height(transaction.message().recent_blockhash())
                .unwrap_or(0);

            let durable_nonce_info = transaction
                .get_durable_nonce()
                .map(|&pubkey| (pubkey, *transaction.message().recent_blockhash()));
            if durable_nonce_info.is_some() {
                // While it uses a defined constant, this last_valid_block_height value is chosen arbitrarily.
                // It provides a fallback timeout for durable-nonce transaction retries in case of
                // malicious packing of the retry queue. Durable-nonce transactions are otherwise
                // retried until the nonce is advanced.
                last_valid_block_height =
                    preflight_bank.block_height() + MAX_RECENT_BLOCKHASHES as u64;
            }

            if !skip_preflight {
                verify_transaction(&transaction, &preflight_bank.feature_set)?;

                match meta.health.check() {
                    RpcHealthStatus::Ok => (),
                    RpcHealthStatus::Unknown => {
                        inc_new_counter_info!("rpc-send-tx_health-unknown", 1);
                        return Err(RpcCustomError::NodeUnhealthy {
                            num_slots_behind: None,
                        }
                        .into());
                    }
                    RpcHealthStatus::Behind { num_slots } => {
                        inc_new_counter_info!("rpc-send-tx_health-behind", 1);
                        return Err(RpcCustomError::NodeUnhealthy {
                            num_slots_behind: Some(num_slots),
                        }
                        .into());
                    }
                }

                if let TransactionSimulationResult {
                    result: Err(err),
                    logs,
                    post_simulation_accounts: _,
                    units_consumed,
                    return_data,
                } = preflight_bank.simulate_transaction(transaction)
                {
                    match err {
                        TransactionError::BlockhashNotFound => {
                            inc_new_counter_info!("rpc-send-tx_err-blockhash-not-found", 1);
                        }
                        _ => {
                            inc_new_counter_info!("rpc-send-tx_err-other", 1);
                        }
                    }
                    return Err(RpcCustomError::SendTransactionPreflightFailure {
                        message: format!("Transaction simulation failed: {err}"),
                        result: RpcSimulateTransactionResult {
                            err: Some(err),
                            logs: Some(logs),
                            accounts: None,
                            units_consumed: Some(units_consumed),
                            return_data: return_data.map(|return_data| return_data.into()),
                        },
                    }
                    .into());
                }
            }

            _send_transaction(
                meta,
                signature,
                wire_transaction,
                last_valid_block_height,
                durable_nonce_info,
                max_retries,
            )
        }

        fn simulate_transaction(
            &self,
            meta: Self::Metadata,
            data: String,
            config: Option<RpcSimulateTransactionConfig>,
        ) -> Result<RpcResponse<RpcSimulateTransactionResult>> {
            debug!("simulate_transaction rpc request received");
            let RpcSimulateTransactionConfig {
                sig_verify,
                replace_recent_blockhash,
                commitment,
                encoding,
                accounts: config_accounts,
                min_context_slot,
            } = config.unwrap_or_default();
            let tx_encoding = encoding.unwrap_or(UiTransactionEncoding::Base58);
            let binary_encoding = tx_encoding.into_binary_encoding().ok_or_else(|| {
                Error::invalid_params(format!(
                    "unsupported encoding: {tx_encoding}. Supported encodings: base58, base64"
                ))
            })?;
            let (_, mut unsanitized_tx) =
                decode_and_deserialize::<VersionedTransaction>(data, binary_encoding)?;

            let bank = &*meta.get_bank_with_config(RpcContextConfig {
                commitment,
                min_context_slot,
            })?;
            if replace_recent_blockhash {
                if sig_verify {
                    return Err(Error::invalid_params(
                        "sigVerify may not be used with replaceRecentBlockhash",
                    ));
                }
                unsanitized_tx
                    .message
                    .set_recent_blockhash(bank.last_blockhash());
            }

            let transaction = sanitize_transaction(unsanitized_tx, bank)?;
            if sig_verify {
                verify_transaction(&transaction, &bank.feature_set)?;
            }
            let number_of_accounts = transaction.message().account_keys().len();

            let TransactionSimulationResult {
                result,
                logs,
                post_simulation_accounts,
                units_consumed,
                return_data,
            } = bank.simulate_transaction(transaction);

            let accounts = if let Some(config_accounts) = config_accounts {
                let accounts_encoding = config_accounts
                    .encoding
                    .unwrap_or(UiAccountEncoding::Base64);

                if accounts_encoding == UiAccountEncoding::Binary
                    || accounts_encoding == UiAccountEncoding::Base58
                {
                    return Err(Error::invalid_params("base58 encoding not supported"));
                }

                if config_accounts.addresses.len() > number_of_accounts {
                    return Err(Error::invalid_params(format!(
                        "Too many accounts provided; max {number_of_accounts}"
                    )));
                }

                if result.is_err() {
                    Some(vec![None; config_accounts.addresses.len()])
                } else {
                    Some(
                        config_accounts
                            .addresses
                            .iter()
                            .map(|address_str| {
                                let address = verify_pubkey(address_str)?;
                                post_simulation_accounts
                                    .iter()
                                    .find(|(key, _account)| key == &address)
                                    .map(|(pubkey, account)| {
                                        encode_account(account, pubkey, accounts_encoding, None)
                                    })
                                    .transpose()
                            })
                            .collect::<Result<Vec<_>>>()?,
                    )
                }
            } else {
                None
            };

            Ok(new_response(
                bank,
                RpcSimulateTransactionResult {
                    err: result.err(),
                    logs: Some(logs),
                    accounts,
                    units_consumed: Some(units_consumed),
                    return_data: return_data.map(|return_data| return_data.into()),
                },
            ))
        }

        fn minimum_ledger_slot(&self, meta: Self::Metadata) -> Result<Slot> {
            debug!("minimum_ledger_slot rpc request received");
            meta.minimum_ledger_slot()
        }

        fn get_block(
            &self,
            meta: Self::Metadata,
            slot: Slot,
            config: Option<RpcEncodingConfigWrapper<RpcBlockConfig>>,
        ) -> BoxFuture<Result<Option<UiConfirmedBlock>>> {
            debug!("get_block rpc request received: {:?}", slot);
            Box::pin(async move { meta.get_block(slot, config).await })
        }

        fn get_blocks(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            config: Option<RpcBlocksConfigWrapper>,
            commitment: Option<CommitmentConfig>,
        ) -> BoxFuture<Result<Vec<Slot>>> {
            let (end_slot, maybe_commitment) =
                config.map(|config| config.unzip()).unwrap_or_default();
            debug!(
                "get_blocks rpc request received: {}-{:?}",
                start_slot, end_slot
            );
            Box::pin(async move {
                meta.get_blocks(start_slot, end_slot, commitment.or(maybe_commitment))
                    .await
            })
        }

        fn get_blocks_with_limit(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            limit: usize,
            commitment: Option<CommitmentConfig>,
        ) -> BoxFuture<Result<Vec<Slot>>> {
            debug!(
                "get_blocks_with_limit rpc request received: {}-{}",
                start_slot, limit,
            );
            Box::pin(async move {
                meta.get_blocks_with_limit(start_slot, limit, commitment)
                    .await
            })
        }

        fn get_block_time(
            &self,
            meta: Self::Metadata,
            slot: Slot,
        ) -> BoxFuture<Result<Option<UnixTimestamp>>> {
            Box::pin(async move { meta.get_block_time(slot).await })
        }

        fn get_transaction(
            &self,
            meta: Self::Metadata,
            signature_str: String,
            config: Option<RpcEncodingConfigWrapper<RpcTransactionConfig>>,
        ) -> BoxFuture<Result<Option<EncodedConfirmedTransactionWithStatusMeta>>> {
            debug!("get_transaction rpc request received: {:?}", signature_str);
            let signature = verify_signature(&signature_str);
            if let Err(err) = signature {
                return Box::pin(future::err(err));
            }
            Box::pin(async move { meta.get_transaction(signature.unwrap(), config).await })
        }

        fn get_signatures_for_address(
            &self,
            meta: Self::Metadata,
            address: String,
            config: Option<RpcSignaturesForAddressConfig>,
        ) -> BoxFuture<Result<Vec<RpcConfirmedTransactionStatusWithSignature>>> {
            let RpcSignaturesForAddressConfig {
                before,
                until,
                limit,
                commitment,
                min_context_slot,
            } = config.unwrap_or_default();
            let verification =
                verify_and_parse_signatures_for_address_params(address, before, until, limit);

            match verification {
                Err(err) => Box::pin(future::err(err)),
                Ok((address, before, until, limit)) => Box::pin(async move {
                    meta.get_signatures_for_address(
                        address,
                        before,
                        until,
                        limit,
                        RpcContextConfig {
                            commitment,
                            min_context_slot,
                        },
                    )
                    .await
                }),
            }
        }

        fn get_first_available_block(&self, meta: Self::Metadata) -> BoxFuture<Result<Slot>> {
            debug!("get_first_available_block rpc request received");
            Box::pin(async move { Ok(meta.get_first_available_block().await) })
        }

        fn get_inflation_reward(
            &self,
            meta: Self::Metadata,
            address_strs: Vec<String>,
            config: Option<RpcEpochConfig>,
        ) -> BoxFuture<Result<Vec<Option<RpcInflationReward>>>> {
            debug!(
                "get_inflation_reward rpc request received: {:?}",
                address_strs.len()
            );

            let mut addresses: Vec<Pubkey> = vec![];
            for address_str in address_strs {
                match verify_pubkey(&address_str) {
                    Ok(pubkey) => {
                        addresses.push(pubkey);
                    }
                    Err(err) => return Box::pin(future::err(err)),
                }
            }

            Box::pin(async move { meta.get_inflation_reward(addresses, config).await })
        }

        fn get_latest_blockhash(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<RpcBlockhash>> {
            debug!("get_latest_blockhash rpc request received");
            meta.get_latest_blockhash(config.unwrap_or_default())
        }

        fn is_blockhash_valid(
            &self,
            meta: Self::Metadata,
            blockhash: String,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<bool>> {
            let blockhash =
                Hash::from_str(&blockhash).map_err(|e| Error::invalid_params(format!("{e:?}")))?;
            meta.is_blockhash_valid(&blockhash, config.unwrap_or_default())
        }

        fn get_fee_for_message(
            &self,
            meta: Self::Metadata,
            data: String,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<Option<u64>>> {
            debug!("get_fee_for_message rpc request received");
            let (_, message) = decode_and_deserialize::<VersionedMessage>(
                data,
                TransactionBinaryEncoding::Base64,
            )?;
            let bank = &*meta.get_bank_with_config(config.unwrap_or_default())?;
            let sanitized_versioned_message = SanitizedVersionedMessage::try_from(message)
                .map_err(|err| {
                    Error::invalid_params(format!("invalid transaction message: {err}"))
                })?;
            let sanitized_message = SanitizedMessage::try_new(sanitized_versioned_message, bank)
                .map_err(|err| {
                    Error::invalid_params(format!("invalid transaction message: {err}"))
                })?;
            let fee = bank.get_fee_for_message(&sanitized_message);
            Ok(new_response(bank, fee))
        }

        fn get_stake_minimum_delegation(
            &self,
            meta: Self::Metadata,
            config: Option<RpcContextConfig>,
        ) -> Result<RpcResponse<u64>> {
            debug!("get_stake_minimum_delegation rpc request received");
            meta.get_stake_minimum_delegation(config.unwrap_or_default())
        }

        fn get_recent_prioritization_fees(
            &self,
            meta: Self::Metadata,
            pubkey_strs: Option<Vec<String>>,
        ) -> Result<Vec<RpcPrioritizationFee>> {
            let pubkey_strs = pubkey_strs.unwrap_or_default();
            debug!(
                "get_recent_prioritization_fees rpc request received: {:?} pubkeys",
                pubkey_strs.len()
            );
            if pubkey_strs.len() > MAX_TX_ACCOUNT_LOCKS {
                return Err(Error::invalid_params(format!(
                    "Too many inputs provided; max {MAX_TX_ACCOUNT_LOCKS}"
                )));
            }
            let pubkeys = pubkey_strs
                .into_iter()
                .map(|pubkey_str| verify_pubkey(&pubkey_str))
                .collect::<Result<Vec<_>>>()?;
            meta.get_recent_prioritization_fees(pubkeys)
        }
    }
}

fn rpc_perf_sample_from_perf_sample(slot: u64, sample: PerfSample) -> RpcPerfSample {
    match sample {
        PerfSample::V1(PerfSampleV1 {
            num_transactions,
            num_slots,
            sample_period_secs,
        }) => RpcPerfSample {
            slot,
            num_transactions,
            num_non_vote_transactions: None,
            num_slots,
            sample_period_secs,
        },
        PerfSample::V2(PerfSampleV2 {
            num_transactions,
            num_non_vote_transactions,
            num_slots,
            sample_period_secs,
        }) => RpcPerfSample {
            slot,
            num_transactions,
            num_non_vote_transactions: Some(num_non_vote_transactions),
            num_slots,
            sample_period_secs,
        },
    }
}

// RPC methods deprecated in v1.8
pub mod rpc_deprecated_v1_9 {
    #![allow(deprecated)]
    use super::*;
    #[rpc]
    pub trait DeprecatedV1_9 {
        type Metadata;

        #[rpc(meta, name = "getRecentBlockhash")]
        fn get_recent_blockhash(
            &self,
            meta: Self::Metadata,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<RpcBlockhashFeeCalculator>>;

        #[rpc(meta, name = "getFees")]
        fn get_fees(
            &self,
            meta: Self::Metadata,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<RpcFees>>;

        #[rpc(meta, name = "getFeeCalculatorForBlockhash")]
        fn get_fee_calculator_for_blockhash(
            &self,
            meta: Self::Metadata,
            blockhash: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<Option<RpcFeeCalculator>>>;

        #[rpc(meta, name = "getFeeRateGovernor")]
        fn get_fee_rate_governor(
            &self,
            meta: Self::Metadata,
        ) -> Result<RpcResponse<RpcFeeRateGovernor>>;

        #[rpc(meta, name = "getSnapshotSlot")]
        fn get_snapshot_slot(&self, meta: Self::Metadata) -> Result<Slot>;
    }

    pub struct DeprecatedV1_9Impl;
    impl DeprecatedV1_9 for DeprecatedV1_9Impl {
        type Metadata = JsonRpcRequestProcessor;

        fn get_recent_blockhash(
            &self,
            meta: Self::Metadata,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<RpcBlockhashFeeCalculator>> {
            debug!("get_recent_blockhash rpc request received");
            meta.get_recent_blockhash(commitment)
        }

        fn get_fees(
            &self,
            meta: Self::Metadata,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<RpcFees>> {
            debug!("get_fees rpc request received");
            meta.get_fees(commitment)
        }

        fn get_fee_calculator_for_blockhash(
            &self,
            meta: Self::Metadata,
            blockhash: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<Option<RpcFeeCalculator>>> {
            debug!("get_fee_calculator_for_blockhash rpc request received");
            let blockhash =
                Hash::from_str(&blockhash).map_err(|e| Error::invalid_params(format!("{e:?}")))?;
            meta.get_fee_calculator_for_blockhash(&blockhash, commitment)
        }

        fn get_fee_rate_governor(
            &self,
            meta: Self::Metadata,
        ) -> Result<RpcResponse<RpcFeeRateGovernor>> {
            debug!("get_fee_rate_governor rpc request received");
            Ok(meta.get_fee_rate_governor())
        }

        fn get_snapshot_slot(&self, meta: Self::Metadata) -> Result<Slot> {
            debug!("get_snapshot_slot rpc request received");

            meta.snapshot_config
                .and_then(|snapshot_config| {
                    snapshot_utils::get_highest_full_snapshot_archive_slot(
                        snapshot_config.full_snapshot_archives_dir,
                    )
                })
                .ok_or_else(|| RpcCustomError::NoSnapshot.into())
        }
    }
}

// RPC methods deprecated in v1.7
pub mod rpc_deprecated_v1_7 {
    #![allow(deprecated)]
    use super::*;
    #[rpc]
    pub trait DeprecatedV1_7 {
        type Metadata;

        // DEPRECATED
        #[rpc(meta, name = "getConfirmedBlock")]
        fn get_confirmed_block(
            &self,
            meta: Self::Metadata,
            slot: Slot,
            config: Option<RpcEncodingConfigWrapper<RpcConfirmedBlockConfig>>,
        ) -> BoxFuture<Result<Option<UiConfirmedBlock>>>;

        // DEPRECATED
        #[rpc(meta, name = "getConfirmedBlocks")]
        fn get_confirmed_blocks(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            config: Option<RpcConfirmedBlocksConfigWrapper>,
            commitment: Option<CommitmentConfig>,
        ) -> BoxFuture<Result<Vec<Slot>>>;

        // DEPRECATED
        #[rpc(meta, name = "getConfirmedBlocksWithLimit")]
        fn get_confirmed_blocks_with_limit(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            limit: usize,
            commitment: Option<CommitmentConfig>,
        ) -> BoxFuture<Result<Vec<Slot>>>;

        // DEPRECATED
        #[rpc(meta, name = "getConfirmedTransaction")]
        fn get_confirmed_transaction(
            &self,
            meta: Self::Metadata,
            signature_str: String,
            config: Option<RpcEncodingConfigWrapper<RpcConfirmedTransactionConfig>>,
        ) -> BoxFuture<Result<Option<EncodedConfirmedTransactionWithStatusMeta>>>;

        // DEPRECATED
        #[rpc(meta, name = "getConfirmedSignaturesForAddress2")]
        fn get_confirmed_signatures_for_address2(
            &self,
            meta: Self::Metadata,
            address: String,
            config: Option<RpcGetConfirmedSignaturesForAddress2Config>,
        ) -> BoxFuture<Result<Vec<RpcConfirmedTransactionStatusWithSignature>>>;
    }

    pub struct DeprecatedV1_7Impl;
    impl DeprecatedV1_7 for DeprecatedV1_7Impl {
        type Metadata = JsonRpcRequestProcessor;

        fn get_confirmed_block(
            &self,
            meta: Self::Metadata,
            slot: Slot,
            config: Option<RpcEncodingConfigWrapper<RpcConfirmedBlockConfig>>,
        ) -> BoxFuture<Result<Option<UiConfirmedBlock>>> {
            debug!("get_confirmed_block rpc request received: {:?}", slot);
            Box::pin(async move {
                meta.get_block(slot, config.map(|config| config.convert()))
                    .await
            })
        }

        fn get_confirmed_blocks(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            config: Option<RpcConfirmedBlocksConfigWrapper>,
            commitment: Option<CommitmentConfig>,
        ) -> BoxFuture<Result<Vec<Slot>>> {
            let (end_slot, maybe_commitment) =
                config.map(|config| config.unzip()).unwrap_or_default();
            debug!(
                "get_confirmed_blocks rpc request received: {}-{:?}",
                start_slot, end_slot
            );
            Box::pin(async move {
                meta.get_blocks(start_slot, end_slot, commitment.or(maybe_commitment))
                    .await
            })
        }

        fn get_confirmed_blocks_with_limit(
            &self,
            meta: Self::Metadata,
            start_slot: Slot,
            limit: usize,
            commitment: Option<CommitmentConfig>,
        ) -> BoxFuture<Result<Vec<Slot>>> {
            debug!(
                "get_confirmed_blocks_with_limit rpc request received: {}-{}",
                start_slot, limit,
            );
            Box::pin(async move {
                meta.get_blocks_with_limit(start_slot, limit, commitment)
                    .await
            })
        }

        fn get_confirmed_transaction(
            &self,
            meta: Self::Metadata,
            signature_str: String,
            config: Option<RpcEncodingConfigWrapper<RpcConfirmedTransactionConfig>>,
        ) -> BoxFuture<Result<Option<EncodedConfirmedTransactionWithStatusMeta>>> {
            debug!(
                "get_confirmed_transaction rpc request received: {:?}",
                signature_str
            );
            let signature = verify_signature(&signature_str);
            if let Err(err) = signature {
                return Box::pin(future::err(err));
            }
            Box::pin(async move {
                meta.get_transaction(signature.unwrap(), config.map(|config| config.convert()))
                    .await
            })
        }

        fn get_confirmed_signatures_for_address2(
            &self,
            meta: Self::Metadata,
            address: String,
            config: Option<RpcGetConfirmedSignaturesForAddress2Config>,
        ) -> BoxFuture<Result<Vec<RpcConfirmedTransactionStatusWithSignature>>> {
            let config = config.unwrap_or_default();
            let commitment = config.commitment;
            let verification = verify_and_parse_signatures_for_address_params(
                address,
                config.before,
                config.until,
                config.limit,
            );

            match verification {
                Err(err) => Box::pin(future::err(err)),
                Ok((address, before, until, limit)) => Box::pin(async move {
                    meta.get_signatures_for_address(
                        address,
                        before,
                        until,
                        limit,
                        RpcContextConfig {
                            commitment,
                            min_context_slot: None,
                        },
                    )
                    .await
                }),
            }
        }
    }
}

// Obsolete RPC methods, collected for easy deactivation and removal
pub mod rpc_obsolete_v1_7 {
    use super::*;
    #[rpc]
    pub trait ObsoleteV1_7 {
        type Metadata;

        // DEPRECATED
        #[rpc(meta, name = "confirmTransaction")]
        fn confirm_transaction(
            &self,
            meta: Self::Metadata,
            signature_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<bool>>;

        // DEPRECATED
        #[rpc(meta, name = "getSignatureStatus")]
        fn get_signature_status(
            &self,
            meta: Self::Metadata,
            signature_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<Option<transaction::Result<()>>>;

        // DEPRECATED (used by Trust Wallet)
        #[rpc(meta, name = "getSignatureConfirmation")]
        fn get_signature_confirmation(
            &self,
            meta: Self::Metadata,
            signature_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<Option<RpcSignatureConfirmation>>;

        // DEPRECATED
        #[rpc(meta, name = "getTotalSupply")]
        fn get_total_supply(
            &self,
            meta: Self::Metadata,
            commitment: Option<CommitmentConfig>,
        ) -> Result<u64>;

        // DEPRECATED
        #[rpc(meta, name = "getConfirmedSignaturesForAddress")]
        fn get_confirmed_signatures_for_address(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            start_slot: Slot,
            end_slot: Slot,
        ) -> Result<Vec<String>>;
    }

    pub struct ObsoleteV1_7Impl;
    impl ObsoleteV1_7 for ObsoleteV1_7Impl {
        type Metadata = JsonRpcRequestProcessor;

        fn confirm_transaction(
            &self,
            meta: Self::Metadata,
            id: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<RpcResponse<bool>> {
            debug!("confirm_transaction rpc request received: {:?}", id);
            let signature = verify_signature(&id)?;
            meta.confirm_transaction(&signature, commitment)
        }

        fn get_signature_status(
            &self,
            meta: Self::Metadata,
            signature_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<Option<transaction::Result<()>>> {
            debug!(
                "get_signature_status rpc request received: {:?}",
                signature_str
            );
            let signature = verify_signature(&signature_str)?;
            meta.get_signature_status(signature, commitment)
        }

        fn get_signature_confirmation(
            &self,
            meta: Self::Metadata,
            signature_str: String,
            commitment: Option<CommitmentConfig>,
        ) -> Result<Option<RpcSignatureConfirmation>> {
            debug!(
                "get_signature_confirmation rpc request received: {:?}",
                signature_str
            );
            let signature = verify_signature(&signature_str)?;
            meta.get_signature_confirmation_status(signature, commitment)
        }

        fn get_total_supply(
            &self,
            meta: Self::Metadata,
            commitment: Option<CommitmentConfig>,
        ) -> Result<u64> {
            debug!("get_total_supply rpc request received");
            meta.get_total_supply(commitment)
        }

        fn get_confirmed_signatures_for_address(
            &self,
            meta: Self::Metadata,
            pubkey_str: String,
            start_slot: Slot,
            end_slot: Slot,
        ) -> Result<Vec<String>> {
            debug!(
                "get_confirmed_signatures_for_address rpc request received: {:?} {:?}-{:?}",
                pubkey_str, start_slot, end_slot
            );
            let pubkey = verify_pubkey(&pubkey_str)?;
            if end_slot < start_slot {
                return Err(Error::invalid_params(format!(
                    "start_slot {start_slot} must be less than or equal to end_slot {end_slot}"
                )));
            }
            if end_slot - start_slot > MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS_SLOT_RANGE {
                return Err(Error::invalid_params(format!(
                    "Slot range too large; max {MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS_SLOT_RANGE}"
                )));
            }
            Ok(meta
                .get_confirmed_signatures_for_address(pubkey, start_slot, end_slot)
                .iter()
                .map(|signature| signature.to_string())
                .collect())
        }
    }
}

const MAX_BASE58_SIZE: usize = 1683; // Golden, bump if PACKET_DATA_SIZE changes
const MAX_BASE64_SIZE: usize = 1644; // Golden, bump if PACKET_DATA_SIZE changes
fn decode_and_deserialize<T>(
    encoded: String,
    encoding: TransactionBinaryEncoding,
) -> Result<(Vec<u8>, T)>
where
    T: serde::de::DeserializeOwned,
{
    let wire_output = match encoding {
        TransactionBinaryEncoding::Base58 => {
            inc_new_counter_info!("rpc-base58_encoded_tx", 1);
            if encoded.len() > MAX_BASE58_SIZE {
                return Err(Error::invalid_params(format!(
                    "base58 encoded {} too large: {} bytes (max: encoded/raw {}/{})",
                    type_name::<T>(),
                    encoded.len(),
                    MAX_BASE58_SIZE,
                    PACKET_DATA_SIZE,
                )));
            }
            bs58::decode(encoded)
                .into_vec()
                .map_err(|e| Error::invalid_params(format!("invalid base58 encoding: {e:?}")))?
        }
        TransactionBinaryEncoding::Base64 => {
            inc_new_counter_info!("rpc-base64_encoded_tx", 1);
            if encoded.len() > MAX_BASE64_SIZE {
                return Err(Error::invalid_params(format!(
                    "base64 encoded {} too large: {} bytes (max: encoded/raw {}/{})",
                    type_name::<T>(),
                    encoded.len(),
                    MAX_BASE64_SIZE,
                    PACKET_DATA_SIZE,
                )));
            }
            BASE64_STANDARD
                .decode(encoded)
                .map_err(|e| Error::invalid_params(format!("invalid base64 encoding: {e:?}")))?
        }
    };
    if wire_output.len() > PACKET_DATA_SIZE {
        return Err(Error::invalid_params(format!(
            "decoded {} too large: {} bytes (max: {} bytes)",
            type_name::<T>(),
            wire_output.len(),
            PACKET_DATA_SIZE
        )));
    }
    bincode::options()
        .with_limit(PACKET_DATA_SIZE as u64)
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize_from(&wire_output[..])
        .map_err(|err| {
            Error::invalid_params(format!(
                "failed to deserialize {}: {}",
                type_name::<T>(),
                &err.to_string()
            ))
        })
        .map(|output| (wire_output, output))
}

fn sanitize_transaction(
    transaction: VersionedTransaction,
    address_loader: impl AddressLoader,
) -> Result<SanitizedTransaction> {
    SanitizedTransaction::try_create(
        transaction,
        MessageHash::Compute,
        None,
        address_loader,
        true, // require_static_program_ids
    )
    .map_err(|err| Error::invalid_params(format!("invalid transaction: {err}")))
}

pub fn create_validator_exit(exit: &Arc<AtomicBool>) -> Arc<RwLock<Exit>> {
    let mut validator_exit = Exit::default();
    let exit_ = exit.clone();
    validator_exit.register_exit(Box::new(move || exit_.store(true, Ordering::Relaxed)));
    Arc::new(RwLock::new(validator_exit))
}

pub fn create_test_transaction_entries(
    keypairs: Vec<&Keypair>,
    bank: Arc<Bank>,
) -> (Vec<Entry>, Vec<Signature>) {
    let mint_keypair = keypairs[0];
    let keypair1 = keypairs[1];
    let keypair2 = keypairs[2];
    let keypair3 = keypairs[3];
    let blockhash = bank.confirmed_last_blockhash();
    let rent_exempt_amount = bank.get_minimum_balance_for_rent_exemption(0);

    let mut signatures = Vec::new();
    // Generate transactions for processing
    // Successful transaction
    let success_tx = solana_sdk::system_transaction::transfer(
        mint_keypair,
        &keypair1.pubkey(),
        rent_exempt_amount,
        blockhash,
    );
    signatures.push(success_tx.signatures[0]);
    let entry_1 = solana_entry::entry::next_entry(&blockhash, 1, vec![success_tx]);
    // Failed transaction, InstructionError
    let ix_error_tx = solana_sdk::system_transaction::transfer(
        keypair2,
        &keypair3.pubkey(),
        2 * rent_exempt_amount,
        blockhash,
    );
    signatures.push(ix_error_tx.signatures[0]);
    let entry_2 = solana_entry::entry::next_entry(&entry_1.hash, 1, vec![ix_error_tx]);
    (vec![entry_1, entry_2], signatures)
}

pub fn populate_blockstore_for_tests(
    entries: Vec<Entry>,
    bank: Arc<Bank>,
    blockstore: Arc<Blockstore>,
    max_complete_transaction_status_slot: Arc<AtomicU64>,
) {
    let slot = bank.slot();
    let parent_slot = bank.parent_slot();
    let shreds = solana_ledger::blockstore::entries_to_test_shreds(
        &entries,
        slot,
        parent_slot,
        true,
        0,
        true, // merkle_variant
    );
    blockstore.insert_shreds(shreds, None, false).unwrap();
    blockstore.set_roots(std::iter::once(&slot)).unwrap();

    let (transaction_status_sender, transaction_status_receiver) = unbounded();
    let (replay_vote_sender, _replay_vote_receiver) = unbounded();
    let transaction_status_service =
        crate::transaction_status_service::TransactionStatusService::new(
            transaction_status_receiver,
            max_complete_transaction_status_slot,
            true,
            None,
            blockstore,
            false,
            &Arc::new(AtomicBool::new(false)),
        );

    // Check that process_entries successfully writes can_commit transactions statuses, and
    // that they are matched properly by get_rooted_block
    assert_eq!(
        solana_ledger::blockstore_processor::process_entries_for_tests(
            &bank,
            entries,
            true,
            Some(
                &solana_ledger::blockstore_processor::TransactionStatusSender {
                    sender: transaction_status_sender,
                },
            ),
            Some(&replay_vote_sender),
        ),
        Ok(())
    );

    transaction_status_service.join().unwrap();
}
