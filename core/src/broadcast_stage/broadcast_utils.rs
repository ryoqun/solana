use {
    crate::result::Result,
    bincode::serialized_size,
    crossbeam_channel::Receiver,
    solana_entry::entry::Entry,
    solana_ledger::shred::ShredData,
    solana_poh::poh_recorder::WorkingBankEntry,
    solana_runtime::bank::Bank,
    solana_sdk::clock::Slot,
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

#[derive(Clone)]
pub struct UnfinishedSlotInfo {
    pub next_shred_index: u32,
    pub(crate) next_code_index: u32,
    pub slot: Slot,
    pub parent: Slot,
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
        let (try_bank, (entry, tick_height)) = match receiver.try_recv() {
            Ok(working_bank_entry) => working_bank_entry,
            Err(_) => break,
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
        let (try_bank, (entry, tick_height)) =
            match receiver.recv_deadline(coalesce_start + ENTRY_COALESCE_DURATION) {
                Ok(working_bank_entry) => working_bank_entry,
                Err(_) => break,
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
