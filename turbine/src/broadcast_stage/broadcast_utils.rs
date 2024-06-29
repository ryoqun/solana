use {
    super::{Error, Result},
    bincode::serialized_size,
    crossbeam_channel::Receiver,
    solana_entry::entry::Entry,
    solana_ledger::{
        blockstore::Blockstore,
        shred::{self, ShredData},
    },
    solana_poh::poh_recorder::WorkingBankEntry,
    solana_runtime::bank::Bank,
    solana_sdk::{clock::Slot, hash::Hash},
    std::{
        sync::Arc,
        time::{Duration, Instant},
    },
};

const ENTRY_COALESCE_DURATION: Duration = Duration::from_millis(50);

pub(super) struct ReceiveResults {
    pub entries: Vec<Entry>,
    pub time_elapsed: Duration,
    pub time_coalesced: Duration,
    pub bank: Arc<Bank>,
    pub last_tick_height: u64,
}

pub(super) fn recv_slot_entries(receiver: &Receiver<WorkingBankEntry>) -> Result<ReceiveResults> {
    let target_serialized_batch_byte_count: u64 =
        32 * ShredData::capacity(/*merkle_proof_size*/ None).unwrap() as u64;
    let timer = Duration::new(1, 0);
    let recv_start = Instant::now();
    let (mut bank, (entry, mut last_tick_height)) = receiver.recv_timeout(timer)?;
    let mut entries = vec![entry];
    assert!(last_tick_height <= bank.max_tick_height());

    // Drain channel
    while last_tick_height != bank.max_tick_height() {
        let Ok((try_bank, (entry, tick_height))) = receiver.try_recv() else {
            break;
        };
        // If the bank changed, that implies the previous slot was interrupted and we do not have to
        // broadcast its entries.
        if try_bank.slot() != bank.slot() {
            warn!("Broadcast for slot: {} interrupted", bank.slot());
            entries.clear();
            bank = try_bank;
        }
        last_tick_height = tick_height;
        entries.push(entry);
        assert!(last_tick_height <= bank.max_tick_height());
    }

    let mut serialized_batch_byte_count = serialized_size(&entries)?;

    // Wait up to `ENTRY_COALESCE_DURATION` to try to coalesce entries into a 32 shred batch
    let mut coalesce_start = Instant::now();
    while last_tick_height != bank.max_tick_height()
        && serialized_batch_byte_count < target_serialized_batch_byte_count
    {
        let Ok((try_bank, (entry, tick_height))) =
            receiver.recv_deadline(coalesce_start + ENTRY_COALESCE_DURATION)
        else {
            break;
        };
        // If the bank changed, that implies the previous slot was interrupted and we do not have to
        // broadcast its entries.
        if try_bank.slot() != bank.slot() {
            warn!("Broadcast for slot: {} interrupted", bank.slot());
            entries.clear();
            serialized_batch_byte_count = 8; // Vec len
            bank = try_bank;
            coalesce_start = Instant::now();
        }
        last_tick_height = tick_height;
        let entry_bytes = serialized_size(&entry)?;
        serialized_batch_byte_count += entry_bytes;
        entries.push(entry);
        assert!(last_tick_height <= bank.max_tick_height());
    }
    let time_coalesced = coalesce_start.elapsed();

    let time_elapsed = recv_start.elapsed();
    Ok(ReceiveResults {
        entries,
        time_elapsed,
        time_coalesced,
        bank,
        last_tick_height,
    })
}

// Returns the Merkle root of the last erasure batch of the parent slot.
pub(super) fn get_chained_merkle_root_from_parent(
    slot: Slot,
    parent: Slot,
    blockstore: &Blockstore,
) -> Result<Hash> {
    if slot == parent {
        debug_assert_eq!(slot, 0u64);
        return Ok(Hash::default());
    }
    debug_assert!(parent < slot, "parent: {parent} >= slot: {slot}");
    let index = blockstore
        .meta(parent)?
        .ok_or_else(|| Error::UnknownSlotMeta(parent))?
        .last_index
        .ok_or_else(|| Error::UnknownLastIndex(parent))?;
    let shred = blockstore
        .get_data_shred(parent, index)?
        .ok_or(Error::ShredNotFound {
            slot: parent,
            index,
        })?;
    shred::layout::get_merkle_root(&shred).ok_or(Error::InvalidMerkleRoot {
        slot: parent,
        index,
    })
}
