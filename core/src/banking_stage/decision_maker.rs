use {
    solana_poh::poh_recorder::{BankStart, PohRecorder},
    solana_sdk::{
        clock::{
            DEFAULT_TICKS_PER_SLOT, FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET,
            HOLD_TRANSACTIONS_SLOT_OFFSET,
        },
        pubkey::Pubkey,
    },
    std::sync::{Arc, RwLock},
};

#[derive(Debug, Clone)]
pub enum BufferedPacketsDecision {
    Consume(BankStart),
    Forward,
    ForwardAndHold,
    Hold,
}

impl BufferedPacketsDecision {
    /// Returns the `BankStart` if the decision is `Consume`. Otherwise, returns `None`.
    pub fn bank_start(&self) -> Option<&BankStart> {
        match self {
            Self::Consume(bank_start) => Some(bank_start),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct DecisionMaker {
    my_pubkey: Pubkey,
    poh_recorder: Arc<RwLock<PohRecorder>>,
}

impl DecisionMaker {
    pub fn new(my_pubkey: Pubkey, poh_recorder: Arc<RwLock<PohRecorder>>) -> Self {
        Self {
            my_pubkey,
            poh_recorder,
        }
    }

    pub(crate) fn make_consume_or_forward_decision(&self) -> BufferedPacketsDecision {
        let decision;
        {
            let poh_recorder = self.poh_recorder.read().unwrap();
            decision = Self::consume_or_forward_packets(
                &self.my_pubkey,
                || Self::bank_start(&poh_recorder),
                || Self::would_be_leader_shortly(&poh_recorder),
                || Self::would_be_leader(&poh_recorder),
                || Self::leader_pubkey(&poh_recorder),
            );
        }

        decision
    }

    fn consume_or_forward_packets(
        my_pubkey: &Pubkey,
        bank_start_fn: impl FnOnce() -> Option<BankStart>,
        would_be_leader_shortly_fn: impl FnOnce() -> bool,
        would_be_leader_fn: impl FnOnce() -> bool,
        leader_pubkey_fn: impl FnOnce() -> Option<Pubkey>,
    ) -> BufferedPacketsDecision {
        // If has active bank, then immediately process buffered packets
        // otherwise, based on leader schedule to either forward or hold packets
        if let Some(bank_start) = bank_start_fn() {
            // If the bank is available, this node is the leader
            BufferedPacketsDecision::Consume(bank_start)
        } else if would_be_leader_shortly_fn() {
            // If the node will be the leader soon, hold the packets for now
            BufferedPacketsDecision::Hold
        } else if would_be_leader_fn() {
            // Node will be leader within ~20 slots, hold the transactions in
            // case it is the only node which produces an accepted slot.
            BufferedPacketsDecision::ForwardAndHold
        } else if let Some(x) = leader_pubkey_fn() {
            if x != *my_pubkey {
                // If the current node is not the leader, forward the buffered packets
                BufferedPacketsDecision::Forward
            } else {
                // If the current node is the leader, return the buffered packets as is
                BufferedPacketsDecision::Hold
            }
        } else {
            // We don't know the leader. Hold the packets for now
            BufferedPacketsDecision::Hold
        }
    }

    fn bank_start(poh_recorder: &PohRecorder) -> Option<BankStart> {
        poh_recorder
            .bank_start()
            .filter(|bank_start| bank_start.should_working_bank_still_be_processing_txs())
    }

    fn would_be_leader_shortly(poh_recorder: &PohRecorder) -> bool {
        poh_recorder.would_be_leader(
            (FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET - 1) * DEFAULT_TICKS_PER_SLOT,
        )
    }

    fn would_be_leader(poh_recorder: &PohRecorder) -> bool {
        poh_recorder.would_be_leader(HOLD_TRANSACTIONS_SLOT_OFFSET * DEFAULT_TICKS_PER_SLOT)
    }

    fn leader_pubkey(poh_recorder: &PohRecorder) -> Option<Pubkey> {
        poh_recorder.leader_after_n_slots(FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET)
    }
}
