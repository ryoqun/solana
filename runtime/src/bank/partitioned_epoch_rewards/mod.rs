mod calculation;
mod compare;
mod distribution;
mod epoch_rewards_hasher;
mod sysvar;

use {
    super::Bank,
    crate::{stake_account::StakeAccount, stake_history::StakeHistory},
    solana_accounts_db::{
        partitioned_rewards::PartitionedEpochRewardsConfig, stake_rewards::StakeReward,
    },
    solana_sdk::{
        account::AccountSharedData,
        account_utils::StateMut,
        feature_set,
        pubkey::Pubkey,
        reward_info::RewardInfo,
        stake::state::{Delegation, Stake, StakeStateV2},
    },
    solana_vote::vote_account::VoteAccounts,
    std::sync::Arc,
};

/// Number of blocks for reward calculation and storing vote accounts.
/// Distributing rewards to stake accounts begins AFTER this many blocks.
const REWARD_CALCULATION_NUM_BLOCKS: u64 = 1;

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct PartitionedStakeReward {
    /// Stake account address
    pub stake_pubkey: Pubkey,
    /// `Stake` state to be stored in account
    pub stake: Stake,
    /// RewardInfo for recording in the Bank on distribution. Most of these
    /// fields are available on calculation, but RewardInfo::post_balance must
    /// be updated based on current account state before recording.
    pub stake_reward_info: RewardInfo,
}

impl PartitionedStakeReward {
    fn maybe_from(stake_reward: &StakeReward) -> Option<Self> {
        if let Ok(StakeStateV2::Stake(_meta, stake, _flags)) = stake_reward.stake_account.state() {
            Some(Self {
                stake_pubkey: stake_reward.stake_pubkey,
                stake,
                stake_reward_info: stake_reward.stake_reward_info,
            })
        } else {
            None
        }
    }
}

type PartitionedStakeRewards = Vec<PartitionedStakeReward>;

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct StartBlockHeightAndRewards {
    /// the block height of the slot at which rewards distribution began
    pub(crate) distribution_starting_block_height: u64,
    /// calculated epoch rewards pending distribution, outer Vec is by partition (one partition per block)
    pub(crate) stake_rewards_by_partition: Arc<Vec<PartitionedStakeRewards>>,
}

/// Represent whether bank is in the reward phase or not.
#[cfg_attr(feature = "frozen-abi", derive(AbiExample, AbiEnumVisitor))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub(crate) enum EpochRewardStatus {
    /// this bank is in the reward phase.
    /// Contents are the start point for epoch reward calculation,
    /// i.e. parent_slot and parent_block height for the starting
    /// block of the current epoch.
    Active(StartBlockHeightAndRewards),
    /// this bank is outside of the rewarding phase.
    #[default]
    Inactive,
}

#[derive(Debug, Default)]
pub(super) struct VoteRewardsAccounts {
    /// reward info for each vote account pubkey.
    /// This type is used by `update_reward_history()`
    pub(super) rewards: Vec<(Pubkey, RewardInfo)>,
    /// corresponds to pubkey in `rewards`
    /// Some if account is to be stored.
    /// None if to be skipped.
    pub(super) accounts_to_store: Vec<Option<AccountSharedData>>,
}

#[derive(Debug, Default)]
/// result of calculating the stake rewards at end of epoch
struct StakeRewardCalculation {
    /// each individual stake account to reward
    stake_rewards: PartitionedStakeRewards,
    /// total lamports across all `stake_rewards`
    total_stake_rewards_lamports: u64,
}

#[derive(Debug, Default)]
struct CalculateValidatorRewardsResult {
    vote_rewards_accounts: VoteRewardsAccounts,
    stake_reward_calculation: StakeRewardCalculation,
    total_points: u128,
}

/// hold reward calc info to avoid recalculation across functions
pub(super) struct EpochRewardCalculateParamInfo<'a> {
    pub(super) stake_history: StakeHistory,
    pub(super) stake_delegations: Vec<(&'a Pubkey, &'a StakeAccount<Delegation>)>,
    pub(super) cached_vote_accounts: &'a VoteAccounts,
}

/// Hold all results from calculating the rewards for partitioned distribution.
/// This struct exists so we can have a function which does all the calculation with no
/// side effects.
pub(super) struct PartitionedRewardsCalculation {
    pub(super) vote_account_rewards: VoteRewardsAccounts,
    pub(super) stake_rewards_by_partition: StakeRewardCalculationPartitioned,
    pub(super) old_vote_balance_and_staked: u64,
    pub(super) validator_rewards: u64,
    pub(super) validator_rate: f64,
    pub(super) foundation_rate: f64,
    pub(super) prev_epoch_duration_in_years: f64,
    pub(super) capitalization: u64,
    total_points: u128,
}

/// result of calculating the stake rewards at beginning of new epoch
pub(super) struct StakeRewardCalculationPartitioned {
    /// each individual stake account to reward, grouped by partition
    pub(super) stake_rewards_by_partition: Vec<PartitionedStakeRewards>,
    /// total lamports across all `stake_rewards`
    pub(super) total_stake_rewards_lamports: u64,
}

pub(super) struct CalculateRewardsAndDistributeVoteRewardsResult {
    /// total rewards for the epoch (including both vote rewards and stake rewards)
    pub(super) total_rewards: u64,
    /// distributed vote rewards
    pub(super) distributed_rewards: u64,
    /// total rewards points calculated for the current epoch, where points
    /// equals the sum of (delegated stake * credits observed) for all
    /// delegations
    pub(super) total_points: u128,
    /// stake rewards that still need to be distributed, grouped by partition
    pub(super) stake_rewards_by_partition: Vec<PartitionedStakeRewards>,
}

pub(crate) type StakeRewards = Vec<StakeReward>;

#[derive(Debug, PartialEq)]
pub struct KeyedRewardsAndNumPartitions {
    pub keyed_rewards: Vec<(Pubkey, RewardInfo)>,
    pub num_partitions: Option<u64>,
}

impl KeyedRewardsAndNumPartitions {
    pub fn should_record(&self) -> bool {
        !self.keyed_rewards.is_empty() || self.num_partitions.is_some()
    }
}

impl Bank {
    pub fn get_rewards_and_num_partitions(&self) -> KeyedRewardsAndNumPartitions {
        let keyed_rewards = self.rewards.read().unwrap().clone();
        let epoch_rewards_sysvar = self.get_epoch_rewards_sysvar();
        // If partitioned epoch rewards are active and this Bank is the
        // epoch-boundary block, populate num_partitions
        let epoch_schedule = self.epoch_schedule();
        let parent_epoch = epoch_schedule.get_epoch(self.parent_slot());
        let is_first_block_in_epoch = self.epoch() > parent_epoch;

        let num_partitions = (epoch_rewards_sysvar.active && is_first_block_in_epoch)
            .then_some(epoch_rewards_sysvar.num_partitions);
        KeyedRewardsAndNumPartitions {
            keyed_rewards,
            num_partitions,
        }
    }

    pub(super) fn is_partitioned_rewards_feature_enabled(&self) -> bool {
        self.feature_set
            .is_active(&feature_set::enable_partitioned_epoch_reward::id())
    }

    pub(crate) fn set_epoch_reward_status_active(
        &mut self,
        distribution_starting_block_height: u64,
        stake_rewards_by_partition: Vec<PartitionedStakeRewards>,
    ) {
        self.epoch_reward_status = EpochRewardStatus::Active(StartBlockHeightAndRewards {
            distribution_starting_block_height,
            stake_rewards_by_partition: Arc::new(stake_rewards_by_partition),
        });
    }

    pub(super) fn partitioned_epoch_rewards_config(&self) -> &PartitionedEpochRewardsConfig {
        &self
            .rc
            .accounts
            .accounts_db
            .partitioned_epoch_rewards_config
    }

    /// # stake accounts to store in one block during partitioned reward interval
    pub(super) fn partitioned_rewards_stake_account_stores_per_block(&self) -> u64 {
        self.partitioned_epoch_rewards_config()
            .stake_account_stores_per_block
    }

    /// Calculate the number of blocks required to distribute rewards to all stake accounts.
    pub(super) fn get_reward_distribution_num_blocks(
        &self,
        rewards: &PartitionedStakeRewards,
    ) -> u64 {
        let total_stake_accounts = rewards.len();
        if self.epoch_schedule.warmup && self.epoch < self.first_normal_epoch() {
            1
        } else {
            const MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH: u64 = 10;
            let num_chunks = solana_accounts_db::accounts_hash::AccountsHasher::div_ceil(
                total_stake_accounts,
                self.partitioned_rewards_stake_account_stores_per_block() as usize,
            ) as u64;

            // Limit the reward credit interval to 10% of the total number of slots in a epoch
            num_chunks.clamp(
                1,
                (self.epoch_schedule.slots_per_epoch / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH).max(1),
            )
        }
    }

    /// true if it is ok to run partitioned rewards code.
    /// This means the feature is activated or certain testing situations.
    pub(super) fn is_partitioned_rewards_code_enabled(&self) -> bool {
        self.is_partitioned_rewards_feature_enabled()
            || self
                .partitioned_epoch_rewards_config()
                .test_enable_partitioned_rewards
    }

    /// For testing only
    pub fn force_reward_interval_end_for_tests(&mut self) {
        self.epoch_reward_status = EpochRewardStatus::Inactive;
    }

    pub(super) fn force_partition_rewards_in_first_block_of_epoch(&self) -> bool {
        self.partitioned_epoch_rewards_config()
            .test_enable_partitioned_rewards
            && self.partitioned_rewards_stake_account_stores_per_block() == u64::MAX
    }
}
