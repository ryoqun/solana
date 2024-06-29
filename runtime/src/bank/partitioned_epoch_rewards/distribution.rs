use {
    super::{
        Bank, EpochRewardStatus, PartitionedStakeReward, PartitionedStakeRewards, StakeRewards,
    },
    crate::{
        bank::metrics::{report_partitioned_reward_metrics, RewardsStoreMetrics},
        stake_account::StakeAccount,
    },
    log::error,
    solana_accounts_db::stake_rewards::StakeReward,
    solana_measure::measure_us,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        account_utils::StateMut,
        pubkey::Pubkey,
        stake::state::{Delegation, StakeStateV2},
    },
    std::sync::atomic::Ordering::Relaxed,
    thiserror::Error,
};

#[derive(Serialize, Deserialize, Debug, Error, PartialEq, Eq, Clone)]
enum DistributionError {
    #[error("stake account not found")]
    AccountNotFound,

    #[error("rewards arithmetic overflowed")]
    ArithmeticOverflow,

    #[error("stake account set_state failed")]
    UnableToSetState,
}

struct DistributionResults {
    lamports_distributed: u64,
    lamports_burned: u64,
    updated_stake_rewards: StakeRewards,
}

impl Bank {
    /// Process reward distribution for the block if it is inside reward interval.
    pub(in crate::bank) fn distribute_partitioned_epoch_rewards(&mut self) {
        let EpochRewardStatus::Active(status) = &self.epoch_reward_status else {
            return;
        };

        let height = self.block_height();
        let distribution_starting_block_height = status.distribution_starting_block_height;
        let distribution_end_exclusive =
            distribution_starting_block_height + status.stake_rewards_by_partition.len() as u64;
        assert!(
            self.epoch_schedule.get_slots_in_epoch(self.epoch)
                > status.stake_rewards_by_partition.len() as u64
        );

        if height >= distribution_starting_block_height && height < distribution_end_exclusive {
            let partition_index = height - distribution_starting_block_height;
            self.distribute_epoch_rewards_in_partition(
                &status.stake_rewards_by_partition,
                partition_index,
            );
        }

        if height.saturating_add(1) >= distribution_end_exclusive {
            datapoint_info!(
                "epoch-rewards-status-update",
                ("slot", self.slot(), i64),
                ("block_height", height, i64),
                ("active", 0, i64),
                (
                    "distribution_starting_block_height",
                    distribution_starting_block_height,
                    i64
                ),
            );

            assert!(matches!(
                self.epoch_reward_status,
                EpochRewardStatus::Active(_)
            ));
            self.epoch_reward_status = EpochRewardStatus::Inactive;
            self.set_epoch_rewards_sysvar_to_inactive();
        }
    }

    /// Process reward credits for a partition of rewards
    /// Store the rewards to AccountsDB, update reward history record and total capitalization.
    fn distribute_epoch_rewards_in_partition(
        &self,
        all_stake_rewards: &[PartitionedStakeRewards],
        partition_index: u64,
    ) {
        let pre_capitalization = self.capitalization();
        let this_partition_stake_rewards = &all_stake_rewards[partition_index as usize];

        let (
            DistributionResults {
                lamports_distributed,
                lamports_burned,
                updated_stake_rewards,
            },
            store_stake_accounts_us,
        ) = measure_us!(self.store_stake_accounts_in_partition(this_partition_stake_rewards));

        // increase total capitalization by the distributed rewards
        self.capitalization.fetch_add(lamports_distributed, Relaxed);

        // decrease distributed capital from epoch rewards sysvar
        self.update_epoch_rewards_sysvar(lamports_distributed + lamports_burned);

        // update reward history for this partitioned distribution
        self.update_reward_history_in_partition(&updated_stake_rewards);

        let metrics = RewardsStoreMetrics {
            pre_capitalization,
            post_capitalization: self.capitalization(),
            total_stake_accounts_count: all_stake_rewards.len(),
            partition_index,
            store_stake_accounts_us,
            store_stake_accounts_count: updated_stake_rewards.len(),
            distributed_rewards: lamports_distributed,
            burned_rewards: lamports_burned,
        };

        report_partitioned_reward_metrics(self, metrics);
    }

    /// insert non-zero stake rewards to self.rewards
    /// Return the number of rewards inserted
    fn update_reward_history_in_partition(&self, stake_rewards: &[StakeReward]) -> usize {
        let mut rewards = self.rewards.write().unwrap();
        rewards.reserve(stake_rewards.len());
        let initial_len = rewards.len();
        stake_rewards
            .iter()
            .filter(|x| x.get_stake_reward() > 0)
            .for_each(|x| rewards.push((x.stake_pubkey, x.stake_reward_info)));
        rewards.len().saturating_sub(initial_len)
    }

    fn build_updated_stake_reward(
        stakes_cache_accounts: &im::HashMap<Pubkey, StakeAccount<Delegation>>,
        partitioned_stake_reward: &PartitionedStakeReward,
    ) -> Result<StakeReward, DistributionError> {
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();

        let (mut account, stake_state): (AccountSharedData, StakeStateV2) = stake_account.into();
        let StakeStateV2::Stake(meta, stake, flags) = stake_state else {
            // StakesCache only stores accounts where StakeStateV2::delegation().is_some()
            unreachable!(
                "StakesCache entry {:?} failed StakeStateV2 deserialization",
                partitioned_stake_reward.stake_pubkey
            )
        };
        account
            .checked_add_lamports(partitioned_stake_reward.stake_reward_info.lamports as u64)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
        assert_eq!(
            stake
                .delegation
                .stake
                .saturating_add(partitioned_stake_reward.stake_reward_info.lamports as u64),
            partitioned_stake_reward.stake.delegation.stake,
        );
        account
            .set_state(&StakeStateV2::Stake(
                meta,
                partitioned_stake_reward.stake,
                flags,
            ))
            .map_err(|_| DistributionError::UnableToSetState)?;
        let mut stake_reward_info = partitioned_stake_reward.stake_reward_info;
        stake_reward_info.post_balance = account.lamports();
        Ok(StakeReward {
            stake_pubkey: partitioned_stake_reward.stake_pubkey,
            stake_reward_info,
            stake_account: account,
        })
    }

    /// Store stake rewards in partition
    /// Returns DistributionResults containing the sum of all the rewards
    /// stored, the sum of all rewards burned, and the updated StakeRewards.
    /// Because stake accounts are checked in calculation, and further state
    /// mutation prevents by stake-program restrictions, there should never be
    /// rewards burned.
    ///
    /// Note: even if staker's reward is 0, the stake account still needs to be
    /// stored because credits observed has changed
    fn store_stake_accounts_in_partition(
        &self,
        stake_rewards: &[PartitionedStakeReward],
    ) -> DistributionResults {
        let mut lamports_distributed = 0;
        let mut lamports_burned = 0;
        let mut updated_stake_rewards = Vec::with_capacity(stake_rewards.len());
        let stakes_cache = self.stakes_cache.stakes();
        let stakes_cache_accounts = stakes_cache.stake_delegations();
        for partitioned_stake_reward in stake_rewards {
            let stake_pubkey = partitioned_stake_reward.stake_pubkey;
            let reward_amount = partitioned_stake_reward.stake_reward_info.lamports as u64;
            match Self::build_updated_stake_reward(stakes_cache_accounts, partitioned_stake_reward)
            {
                Ok(stake_reward) => {
                    lamports_distributed += reward_amount;
                    updated_stake_rewards.push(stake_reward);
                }
                Err(err) => {
                    error!(
                        "bank::distribution::store_stake_accounts_in_partition() failed for \
                         {stake_pubkey}, {reward_amount} lamports burned: {err:?}"
                    );
                    lamports_burned += reward_amount;
                }
            }
        }
        drop(stakes_cache);
        self.store_accounts((self.slot(), &updated_stake_rewards[..]));
        DistributionResults {
            lamports_distributed,
            lamports_burned,
            updated_stake_rewards,
        }
    }
}
