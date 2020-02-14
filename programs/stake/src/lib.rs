#![cfg_attr(RUSTC_WITH_SPECIALIZATION, feature(specialization))]
use solana_sdk::genesis_config::GenesisConfig;

pub mod config;
pub mod stake_instruction;
pub mod stake_state;

solana_sdk::declare_program!(
    "Stake11111111111111111111111111111111111111",
    solana_stake_program,
    stake_instruction::process_instruction
);

pub fn add_genesis_accounts(genesis_config: &mut GenesisConfig) -> u64 {
    config::add_genesis_account(genesis_config)
}

#[macro_use]
extern crate solana_sdk_macro_frozen_abi;
