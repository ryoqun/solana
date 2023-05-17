//! Partitioning of the accounts into chunks for rent collection
use {
    itertools::Itertools,
    log::trace,
    solana_sdk::{
        clock::{Slot, SlotCount, SlotIndex},
        pubkey::Pubkey,
        stake_history::Epoch,
        sysvar::epoch_schedule::EpochSchedule,
    },
    std::{collections::HashSet, mem, ops::RangeInclusive},
};

// Eager rent collection repeats in cyclic manner.
// Each cycle is composed of <partition_count> number of tiny pubkey subranges
// to scan, which is always multiple of the number of slots in epoch.
pub(crate) type PartitionIndex = u64;
type PartitionsPerCycle = u64;
pub(crate) type Partition = (PartitionIndex, PartitionIndex, PartitionsPerCycle);
type RentCollectionCycleParams = (
    Epoch,
    SlotCount,
    bool,
    Epoch,
    EpochCount,
    PartitionsPerCycle,
);
type EpochCount = u64;

fn partition_index_from_slot_index(
    slot_index_in_epoch: SlotIndex,
    (
        epoch,
        slot_count_per_epoch,
        _,
        base_epoch,
        epoch_count_per_cycle,
        _,
    ): RentCollectionCycleParams,
) -> PartitionIndex {
    let epoch_offset = epoch - base_epoch;
    let epoch_index_in_cycle = epoch_offset % epoch_count_per_cycle;
    slot_index_in_epoch + epoch_index_in_cycle * slot_count_per_epoch
}

pub(crate) fn get_partition_from_slot_indexes(
    cycle_params: RentCollectionCycleParams,
    start_slot_index: SlotIndex,
    end_slot_index: SlotIndex,
    generated_for_gapped_epochs: bool,
) -> Partition {
    let (_, _, in_multi_epoch_cycle, _, _, partition_count) = cycle_params;

    // use common codepath for both very likely and very unlikely for the sake of minimized
    // risk of any miscalculation instead of negligibly faster computation per slot for the
    // likely case.
    let mut start_partition_index = partition_index_from_slot_index(start_slot_index, cycle_params);
    let mut end_partition_index = partition_index_from_slot_index(end_slot_index, cycle_params);

    // Adjust partition index for some edge cases
    let is_special_new_epoch = start_slot_index == 0 && end_slot_index != 1;
    let in_middle_of_cycle = start_partition_index > 0;
    if in_multi_epoch_cycle && is_special_new_epoch && in_middle_of_cycle {
        // Adjust slot indexes so that the final partition ranges are continuous!
        // This is need because the caller gives us off-by-one indexes when
        // an epoch boundary is crossed.
        // Usually there is no need for this adjustment because cycles are aligned
        // with epochs. But for multi-epoch cycles, adjust the indexes if it
        // happens in the middle of a cycle for both gapped and not-gapped cases:
        //
        // epoch (slot range)|slot idx.*1|raw part. idx.|adj. part. idx.|epoch boundary
        // ------------------+-----------+--------------+---------------+--------------
        // 3 (20..30)        | [7..8]    |   7.. 8      |   7.. 8
        //                   | [8..9]    |   8.. 9      |   8.. 9
        // 4 (30..40)        | [0..0]    |<10>..10      | <9>..10      <--- not gapped
        //                   | [0..1]    |  10..11      |  10..12
        //                   | [1..2]    |  11..12      |  11..12
        //                   | [2..9   *2|  12..19      |  12..19      <-+
        // 5 (40..50)        |  0..0   *2|<20>..<20>    |<19>..<19> *3 <-+- gapped
        //                   |  0..4]    |<20>..24      |<19>..24      <-+
        //                   | [4..5]    |  24..25      |  24..25
        //                   | [5..6]    |  25..26      |  25..26
        //
        // NOTE: <..> means the adjusted slots
        //
        // *1: The range of parent_bank.slot() and current_bank.slot() is firstly
        //     split by the epoch boundaries and then the split ones are given to us.
        //     The original ranges are denoted as [...]
        // *2: These are marked with generated_for_gapped_epochs = true.
        // *3: This becomes no-op partition
        start_partition_index -= 1;
        if generated_for_gapped_epochs {
            assert_eq!(start_slot_index, end_slot_index);
            end_partition_index -= 1;
        }
    }

    (start_partition_index, end_partition_index, partition_count)
}

/// return all end partition indexes for the given partition
/// partition could be (0, 1, N). In this case we only return [1]
///  the single 'end_index' that covers this partition.
/// partition could be (0, 2, N). In this case, we return [1, 2], which are all
/// the 'end_index' values contained in that range.
/// (0, 0, N) returns [0] as a special case.
/// There is a relationship between
/// 1. 'pubkey_range_from_partition'
/// 2. 'partition_from_pubkey'
/// 3. this function
pub(crate) fn get_partition_end_indexes(partition: &Partition) -> Vec<PartitionIndex> {
    if partition.0 == partition.1 && partition.0 == 0 {
        // special case for start=end=0. ie. (0, 0, N). This returns [0]
        vec![0]
    } else {
        // normal case of (start, end, N)
        // so, we want [start+1, start+2, ..=end]
        // if start == end, then return []
        (partition.0..partition.1).map(|index| index + 1).collect()
    }
}

pub(crate) fn rent_single_epoch_collection_cycle_params(
    epoch: Epoch,
    slot_count_per_epoch: SlotCount,
) -> RentCollectionCycleParams {
    (
        epoch,
        slot_count_per_epoch,
        false,
        0,
        1,
        slot_count_per_epoch,
    )
}

pub(crate) fn rent_multi_epoch_collection_cycle_params(
    epoch: Epoch,
    slot_count_per_epoch: SlotCount,
    first_normal_epoch: Epoch,
    epoch_count_in_cycle: Epoch,
) -> RentCollectionCycleParams {
    let partition_count = slot_count_per_epoch * epoch_count_in_cycle;
    (
        epoch,
        slot_count_per_epoch,
        true,
        first_normal_epoch,
        epoch_count_in_cycle,
        partition_count,
    )
}

pub(crate) fn get_partitions(
    slot: Slot,
    parent_slot: Slot,
    slot_count_in_two_day: SlotCount,
) -> Vec<Partition> {
    let parent_cycle = parent_slot / slot_count_in_two_day;
    let current_cycle = slot / slot_count_in_two_day;
    let mut parent_cycle_index = parent_slot % slot_count_in_two_day;
    let current_cycle_index = slot % slot_count_in_two_day;
    let mut partitions = vec![];
    if parent_cycle < current_cycle {
        if current_cycle_index > 0 {
            // generate and push gapped partitions because some slots are skipped
            let parent_last_cycle_index = slot_count_in_two_day - 1;

            // ... for parent cycle
            partitions.push((
                parent_cycle_index,
                parent_last_cycle_index,
                slot_count_in_two_day,
            ));

            // ... for current cycle
            partitions.push((0, 0, slot_count_in_two_day));
        }
        parent_cycle_index = 0;
    }

    partitions.push((
        parent_cycle_index,
        current_cycle_index,
        slot_count_in_two_day,
    ));

    partitions
}

// Mostly, the pair (start_index & end_index) is equivalent to this range:
// start_index..=end_index. But it has some exceptional cases, including
// this important and valid one:
//   0..=0: the first partition in the new epoch when crossing epochs
pub(crate) fn pubkey_range_from_partition(
    (start_index, end_index, partition_count): Partition,
) -> RangeInclusive<Pubkey> {
    assert!(start_index <= end_index);
    assert!(start_index < partition_count);
    assert!(end_index < partition_count);
    assert!(0 < partition_count);

    type Prefix = u64;
    const PREFIX_SIZE: usize = mem::size_of::<Prefix>();
    const PREFIX_MAX: Prefix = Prefix::max_value();

    let mut start_pubkey = [0x00u8; 32];
    let mut end_pubkey = [0xffu8; 32];

    if partition_count == 1 {
        assert_eq!(start_index, 0);
        assert_eq!(end_index, 0);
        return Pubkey::new_from_array(start_pubkey)..=Pubkey::new_from_array(end_pubkey);
    }

    // not-overflowing way of `(Prefix::max_value() + 1) / partition_count`
    let partition_width = (PREFIX_MAX - partition_count + 1) / partition_count + 1;
    let mut start_key_prefix = if start_index == 0 && end_index == 0 {
        0
    } else if start_index + 1 == partition_count {
        PREFIX_MAX
    } else {
        (start_index + 1) * partition_width
    };

    let mut end_key_prefix = if end_index + 1 == partition_count {
        PREFIX_MAX
    } else {
        (end_index + 1) * partition_width - 1
    };

    if start_index != 0 && start_index == end_index {
        // n..=n (n != 0): a noop pair across epochs without a gap under
        // multi_epoch_cycle, just nullify it.
        if end_key_prefix == PREFIX_MAX {
            start_key_prefix = end_key_prefix;
            start_pubkey = end_pubkey;
        } else {
            end_key_prefix = start_key_prefix;
            end_pubkey = start_pubkey;
        }
    }

    start_pubkey[0..PREFIX_SIZE].copy_from_slice(&start_key_prefix.to_be_bytes());
    end_pubkey[0..PREFIX_SIZE].copy_from_slice(&end_key_prefix.to_be_bytes());
    let start_pubkey_final = Pubkey::new_from_array(start_pubkey);
    let end_pubkey_final = Pubkey::new_from_array(end_pubkey);
    trace!(
        "pubkey_range_from_partition: ({}-{})/{} [{}]: {}-{}",
        start_index,
        end_index,
        partition_count,
        (end_key_prefix - start_key_prefix),
        start_pubkey.iter().map(|x| format!("{x:02x}")).join(""),
        end_pubkey.iter().map(|x| format!("{x:02x}")).join(""),
    );
    // should be an inclusive range (a closed interval) like this:
    // [0xgg00-0xhhff], [0xii00-0xjjff], ... (where 0xii00 == 0xhhff + 1)
    start_pubkey_final..=end_pubkey_final
}

pub(crate) fn prefix_from_pubkey(pubkey: &Pubkey) -> u64 {
    const PREFIX_SIZE: usize = mem::size_of::<u64>();
    u64::from_be_bytes(pubkey.as_ref()[0..PREFIX_SIZE].try_into().unwrap())
}

/// This is the inverse of pubkey_range_from_partition.
/// return the lowest end_index which would contain this pubkey
pub(crate) fn partition_from_pubkey(
    pubkey: &Pubkey,
    partition_count: PartitionsPerCycle,
) -> PartitionIndex {
    type Prefix = u64;
    const PREFIX_MAX: Prefix = Prefix::max_value();

    if partition_count == 1 {
        return 0;
    }

    // not-overflowing way of `(Prefix::max_value() + 1) / partition_count`
    let partition_width = (PREFIX_MAX - partition_count + 1) / partition_count + 1;

    let prefix = prefix_from_pubkey(pubkey);
    if prefix == 0 {
        return 0;
    }

    if prefix == PREFIX_MAX {
        return partition_count - 1;
    }

    let mut result = (prefix + 1) / partition_width;
    if (prefix + 1) % partition_width == 0 {
        // adjust for integer divide
        result = result.saturating_sub(1);
    }
    result
}

lazy_static! {
    static ref EMPTY_HASHSET: HashSet<Pubkey> = HashSet::default();
}

/// populated at startup with the accounts that were found that are rent paying.
/// These are the 'possible' rent paying accounts.
/// This set can never grow during runtime since it is not possible to create rent paying accounts now.
/// It can shrink during execution if a rent paying account is dropped to lamports=0 or is topped off.
/// The next time the validator restarts, it will remove the account from this list.
#[derive(Debug, Default)]
pub struct RentPayingAccountsByPartition {
    /// 1st index is partition end index, 0..=432_000
    /// 2nd dimension is list of pubkeys which were identified at startup to be rent paying
    /// At the moment, we use this data structure to verify all rent paying accounts are expected.
    /// When we stop iterating the accounts index to FIND rent paying accounts, we will no longer need this to be a hashset.
    /// It can just be a vec.
    pub accounts: Vec<HashSet<Pubkey>>,
    partition_count: PartitionsPerCycle,
}

impl RentPayingAccountsByPartition {
    /// create new struct. Need slots per epoch from 'epoch_schedule'
    pub fn new(epoch_schedule: &EpochSchedule) -> Self {
        let partition_count = epoch_schedule.slots_per_epoch;
        Self {
            partition_count,
            accounts: (0..=partition_count)
                .map(|_| HashSet::<Pubkey>::default())
                .collect(),
        }
    }
    /// Remember that 'pubkey' can possibly be rent paying.
    pub fn add_account(&mut self, pubkey: &Pubkey) {
        let partition_end_index = partition_from_pubkey(pubkey, self.partition_count);
        let list = &mut self.accounts[partition_end_index as usize];

        list.insert(*pubkey);
    }
    /// return all pubkeys that can possibly be rent paying with this partition end_index
    pub fn get_pubkeys_in_partition_index(
        &self,
        partition_end_index: PartitionIndex,
    ) -> &HashSet<Pubkey> {
        self.accounts
            .get(partition_end_index as usize)
            .unwrap_or(&EMPTY_HASHSET)
    }
    pub fn is_initialized(&self) -> bool {
        self.partition_count != 0
    }
}
