use {
    crate::result::Result,
    crossbeam_channel::Receiver,
    solana_entry::entry::Entry,
    solana_ledger::shred::Shred,
    solana_poh::poh_recorder::WorkingBankEntry,
    solana_runtime::bank::Bank,
    solana_sdk::clock::Slot,
    std::{
        sync::Arc,
        time::{Duration, Instant},
    },
};

pub(super) struct ReceiveResults {
    pub entries: Vec<Entry>,
    pub time_elapsed: Duration,
    pub bank: Arc<Bank>,
    pub last_tick_height: u64,
}

#[derive(Clone)]
pub struct UnfinishedSlotInfo {
    pub next_shred_index: u32,
    pub(crate) next_code_index: u32,
    pub slot: Slot,
    pub parent: Slot,
    // Data shreds buffered to make a batch of size
    // MAX_DATA_SHREDS_PER_FEC_BLOCK.
    pub(crate) data_shreds_buffer: Vec<Shred>,
    pub(crate) fec_set_offset: u32, // See Shredder::fec_set_index.
}

/// This parameter tunes how many entries are received in one iteration of recv loop
/// This will prevent broadcast stage from consuming more entries, that could have led
/// to delays in shredding, and broadcasting shreds to peer validators
const RECEIVE_ENTRY_COUNT_THRESHOLD: usize = 8;

pub(super) fn recv_slot_entries(receiver: &Receiver<WorkingBankEntry>) -> Result<ReceiveResults> {
    let timer = Duration::new(1, 0);
    let recv_start = Instant::now();
    let (mut bank, (entry, mut last_tick_height)) = receiver.recv_timeout(timer)?;

    let mut entries = vec![entry];
    let mut slot = bank.slot();
    let mut max_tick_height = bank.max_tick_height();

    assert!(last_tick_height <= max_tick_height);

    if last_tick_height != max_tick_height {
        while let Ok((try_bank, (entry, tick_height))) = receiver.try_recv() {
            // If the bank changed, that implies the previous slot was interrupted and we do not have to
            // broadcast its entries.
            if try_bank.slot() != slot {
                warn!("Broadcast for slot: {} interrupted", bank.slot());
                entries.clear();
                bank = try_bank;
                slot = bank.slot();
                max_tick_height = bank.max_tick_height();
            }
            last_tick_height = tick_height;
            entries.push(entry);

            if entries.len() >= RECEIVE_ENTRY_COUNT_THRESHOLD {
                break;
            }

            assert!(last_tick_height <= max_tick_height);
            if last_tick_height == max_tick_height {
                break;
            }
        }
    }

    let time_elapsed = recv_start.elapsed();
    Ok(ReceiveResults {
        entries,
        time_elapsed,
        bank,
        last_tick_height,
    })
}
