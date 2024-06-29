use {
    crate::bank::partitioned_epoch_rewards::PartitionedStakeRewards,
    solana_sdk::{epoch_rewards_hasher::EpochRewardsHasher, hash::Hash},
};

pub(in crate::bank::partitioned_epoch_rewards) fn hash_rewards_into_partitions(
    stake_rewards: PartitionedStakeRewards,
    parent_blockhash: &Hash,
    num_partitions: usize,
) -> Vec<PartitionedStakeRewards> {
    let hasher = EpochRewardsHasher::new(num_partitions, parent_blockhash);
    let mut result = vec![vec![]; num_partitions];

    for reward in stake_rewards {
        // clone here so the hasher's state is re-used on each call to `hash_address_to_partition`.
        // This prevents us from re-hashing the seed each time.
        // The clone is explicit (as opposed to an implicit copy) so it is clear this is intended.
        let partition_index = hasher
            .clone()
            .hash_address_to_partition(&reward.stake_pubkey);
        result[partition_index].push(reward);
    }
    result
}
