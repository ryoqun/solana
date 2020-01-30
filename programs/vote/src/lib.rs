#![cfg_attr(RUSTC_IS_NIGHTLY, feature(specialization))]
pub mod vote_instruction;
pub mod vote_state;

use crate::vote_instruction::process_instruction;

solana_sdk::declare_program!(
    "Vote111111111111111111111111111111111111111",
    solana_vote_program,
    process_instruction
);

#[macro_use]
extern crate solana_sdk_macro;
