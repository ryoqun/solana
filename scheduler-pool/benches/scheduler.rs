#![feature(test)]

extern crate test;

use test::Bencher;

use {
    rand::{thread_rng, Rng},
    solana_ledger::blockstore_processor::{
        execute_batch, TransactionBatchWithIndexes, TransactionStatusSender,
    },
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        installed_scheduler_pool::{
            InstalledScheduler, InstalledSchedulerBox, InstalledSchedulerPool,
            InstalledSchedulerPoolArc, ResultWithTimings, SchedulerId, SchedulingContext,
            WaitReason,
        },
        prioritization_fee_cache::PrioritizationFeeCache,
        vote_sender_types::ReplayVoteSender,
    },
    solana_scheduler::{SchedulingMode, WithSchedulingMode},
    solana_sdk::transaction::SanitizedTransaction,
    std::sync::{Arc, Mutex, Weak},
};
use solana_scheduler_pool::{SchedulerPool, PooledScheduler};

use {
    assert_matches::assert_matches,
    solana_runtime::{
        bank::Bank,
        bank_forks::BankForks,
        genesis_utils::{create_genesis_config, GenesisConfigInfo},
    },
    solana_sdk::{pubkey::Pubkey, signer::keypair::Keypair, system_transaction},
};

struct D;

impl solana_scheduler_pool::TransactionHandler for D {
    fn handle_transaction(_result: &mut solana_sdk::transaction::Result<()>, _timings: &mut ExecuteTimings, bank: &Arc<Bank>, transaction: &SanitizedTransaction, _index: usize, _pool: &SchedulerPool) {
        //std::hint::black_box(bank.clone());
        std::hint::black_box(bank.get_fee_for_message_with_lamports_per_signature(transaction.message(), 23));
    }

}

#[bench]
fn bench_scheduler(bencher: &mut Bencher) {
        solana_logger::setup();

        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config(1_000_000_000);
        let bank = &Arc::new(Bank::new_for_tests(&genesis_config));
        let _ignored_prioritization_fee_cache = Arc::new(PrioritizationFeeCache::new(0u64));
        let pool = SchedulerPool::new(None, None, None, _ignored_prioritization_fee_cache);
        let create_context = || SchedulingContext::new(SchedulingMode::BlockVerification, bank.clone());

        let mut scheduler = PooledScheduler::<D>::spawn(pool, create_context());
        let tx0 = &SanitizedTransaction::from_transaction_for_tests(system_transaction::transfer(
            &mint_keypair,
            &solana_sdk::pubkey::new_rand(),
            2,
            genesis_config.hash(),
        ));
        bencher.iter(|| {
            for _ in 0..10_000 {
                scheduler.schedule_execution(tx0.clone(), 0);
            }
            assert_matches!(scheduler.wait_for_termination(&WaitReason::TerminatedToFreeze), Some((Ok(()), _)));
            scheduler.replace_context(create_context());
        });
}
