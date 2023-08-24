use {
    crate::leader_schedule::LeaderSchedule,
    solana_runtime::bank::Bank,
    solana_sdk::{
        clock::{Epoch, Slot, NUM_CONSECUTIVE_LEADER_SLOTS},
        pubkey::Pubkey,
    },
    std::collections::HashMap,
};

/// Return the leader schedule for the given epoch.
pub fn leader_schedule(epoch: Epoch, bank: &Bank) -> Option<LeaderSchedule> {
    bank.epoch_staked_nodes(epoch).map(|stakes| {
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&epoch.to_le_bytes());
        let mut stakes: Vec<_> = stakes
            .iter()
            .map(|(pubkey, stake)| (*pubkey, *stake))
            .collect();
        sort_stakes(&mut stakes);
        LeaderSchedule::new(
            &stakes,
            seed,
            bank.get_slots_in_epoch(epoch),
            NUM_CONSECUTIVE_LEADER_SLOTS,
        )
    })
}

/// Map of leader base58 identity pubkeys to the slot indices relative to the first epoch slot
pub type LeaderScheduleByIdentity = HashMap<String, Vec<usize>>;

pub fn leader_schedule_by_identity<'a>(
    upcoming_leaders: impl Iterator<Item = (usize, &'a Pubkey)>,
) -> LeaderScheduleByIdentity {
    let mut leader_schedule_by_identity = HashMap::new();

    for (slot_index, identity_pubkey) in upcoming_leaders {
        leader_schedule_by_identity
            .entry(identity_pubkey)
            .or_insert_with(Vec::new)
            .push(slot_index);
    }

    leader_schedule_by_identity
        .into_iter()
        .map(|(identity_pubkey, slot_indices)| (identity_pubkey.to_string(), slot_indices))
        .collect()
}

/// Return the leader for the given slot.
pub fn slot_leader_at(slot: Slot, bank: &Bank) -> Option<Pubkey> {
    let (epoch, slot_index) = bank.get_epoch_and_slot_index(slot);

    leader_schedule(epoch, bank).map(|leader_schedule| leader_schedule[slot_index])
}

// Returns the number of ticks remaining from the specified tick_height to the end of the
// slot implied by the tick_height
pub fn num_ticks_left_in_slot(bank: &Bank, tick_height: u64) -> u64 {
    bank.ticks_per_slot() - tick_height % bank.ticks_per_slot()
}

pub fn first_of_consecutive_leader_slots(slot: Slot) -> Slot {
    (slot / NUM_CONSECUTIVE_LEADER_SLOTS) * NUM_CONSECUTIVE_LEADER_SLOTS
}

fn sort_stakes(stakes: &mut Vec<(Pubkey, u64)>) {
    // Sort first by stake. If stakes are the same, sort by pubkey to ensure a
    // deterministic result.
    // Note: Use unstable sort, because we dedup right after to remove the equal elements.
    stakes.sort_unstable_by(|(l_pubkey, l_stake), (r_pubkey, r_stake)| {
        if r_stake == l_stake {
            r_pubkey.cmp(l_pubkey)
        } else {
            r_stake.cmp(l_stake)
        }
    });

    // Now that it's sorted, we can do an O(n) dedup.
    stakes.dedup();
}
