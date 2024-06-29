use {
    super::Bank,
    log::info,
    solana_sdk::{
        account::{create_account_shared_data_with_fields as create_account, from_account},
        sysvar,
    },
};

impl Bank {
    /// Helper fn to log epoch_rewards sysvar
    fn log_epoch_rewards_sysvar(&self, prefix: &str) {
        if let Some(account) = self.get_account(&sysvar::epoch_rewards::id()) {
            let epoch_rewards: sysvar::epoch_rewards::EpochRewards =
                from_account(&account).unwrap();
            info!("{prefix} epoch_rewards sysvar: {:?}", epoch_rewards);
        } else {
            info!("{prefix} epoch_rewards sysvar: none");
        }
    }

    /// Create EpochRewards sysvar with calculated rewards
    /// This method must be called before a new Bank advances its
    /// last_blockhash.
    pub(in crate::bank) fn create_epoch_rewards_sysvar(
        &self,
        total_rewards: u64,
        distributed_rewards: u64,
        distribution_starting_block_height: u64,
        num_partitions: u64,
        total_points: u128,
    ) {
        assert!(self.is_partitioned_rewards_code_enabled());

        assert!(total_rewards >= distributed_rewards);

        let parent_blockhash = self.last_blockhash();

        let epoch_rewards = sysvar::epoch_rewards::EpochRewards {
            distribution_starting_block_height,
            num_partitions,
            parent_blockhash,
            total_points,
            total_rewards,
            distributed_rewards,
            active: true,
        };

        self.update_sysvar_account(&sysvar::epoch_rewards::id(), |account| {
            create_account(
                &epoch_rewards,
                self.inherit_specially_retained_account_fields(account),
            )
        });

        self.log_epoch_rewards_sysvar("create");
    }

    /// Update EpochRewards sysvar with distributed rewards
    pub(in crate::bank::partitioned_epoch_rewards) fn update_epoch_rewards_sysvar(
        &self,
        distributed: u64,
    ) {
        assert!(self.is_partitioned_rewards_code_enabled());

        let mut epoch_rewards = self.get_epoch_rewards_sysvar();
        assert!(epoch_rewards.active);

        epoch_rewards.distribute(distributed);

        self.update_sysvar_account(&sysvar::epoch_rewards::id(), |account| {
            create_account(
                &epoch_rewards,
                self.inherit_specially_retained_account_fields(account),
            )
        });

        self.log_epoch_rewards_sysvar("update");
    }

    /// Update EpochRewards sysvar with distributed rewards
    pub(in crate::bank::partitioned_epoch_rewards) fn set_epoch_rewards_sysvar_to_inactive(&self) {
        let mut epoch_rewards = self.get_epoch_rewards_sysvar();
        assert_eq!(
            epoch_rewards.distributed_rewards,
            epoch_rewards.total_rewards
        );
        epoch_rewards.active = false;

        self.update_sysvar_account(&sysvar::epoch_rewards::id(), |account| {
            create_account(
                &epoch_rewards,
                self.inherit_specially_retained_account_fields(account),
            )
        });

        self.log_epoch_rewards_sysvar("set_inactive");
    }

    /// Get EpochRewards sysvar. Returns EpochRewards::default() if sysvar
    /// account cannot be found or cannot be deserialized.
    pub(in crate::bank::partitioned_epoch_rewards) fn get_epoch_rewards_sysvar(
        &self,
    ) -> sysvar::epoch_rewards::EpochRewards {
        from_account(
            &self
                .get_account(&sysvar::epoch_rewards::id())
                .unwrap_or_default(),
        )
        .unwrap_or_default()
    }
}
