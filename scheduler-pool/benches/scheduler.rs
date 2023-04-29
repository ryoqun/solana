#![feature(test)]

extern crate test;

use {
    assert_matches::assert_matches,
    rand::{thread_rng, Rng},
    solana_ledger::blockstore_processor::{
        execute_batch, TransactionBatchWithIndexes, TransactionStatusSender,
    },
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        bank::Bank,
        bank_forks::BankForks,
        genesis_utils::{create_genesis_config, GenesisConfigInfo},
        installed_scheduler_pool::{
            InstalledScheduler, InstalledSchedulerBox, InstalledSchedulerPool,
            InstalledSchedulerPoolArc, ResultWithTimings, SchedulerId, SchedulingContext,
            WaitReason,
        },
        prioritization_fee_cache::PrioritizationFeeCache,
        vote_sender_types::ReplayVoteSender,
    },
    solana_scheduler::{SchedulingMode, WithSchedulingMode},
    solana_scheduler_pool::{PooledScheduler, PooledScheduler2, SchedulerPool},
    solana_sdk::{
        pubkey::Pubkey, signer::keypair::Keypair, system_transaction,
        transaction::SanitizedTransaction,
    },
    std::sync::{Arc, Mutex, Weak},
    test::Bencher,
};

struct D;

impl solana_scheduler_pool::TransactionHandler for D {
    fn handle_transaction(
        _result: &mut solana_sdk::transaction::Result<()>,
        _timings: &mut ExecuteTimings,
        bank: &Arc<Bank>,
        transaction: &SanitizedTransaction,
        _index: usize,
        _pool: &SchedulerPool,
    ) {
        //std::hint::black_box(bank.clone());
        let mut i = 0;
        for _ in 1..10 {
            i += bank.get_fee_for_message_with_lamports_per_signature(transaction.message(), 23)
        }
        std::hint::black_box(i);
    }
}

#[bench]
fn bench_pooled_scheduler1(bencher: &mut Bencher) {
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
        assert_matches!(
            scheduler.wait_for_termination(&WaitReason::TerminatedToFreeze),
            Some((Ok(()), _))
        );
        scheduler.replace_context(create_context());
    });
}

#[bench]
fn bench_pooled_scheduler2(bencher: &mut Bencher) {
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

    let mut scheduler = PooledScheduler2::<D>::spawn(pool, create_context());
    let tx0 = &SanitizedTransaction::from_transaction_for_tests(system_transaction::transfer(
        &mint_keypair,
        &solana_sdk::pubkey::new_rand(),
        2,
        genesis_config.hash(),
    ));
    bencher.iter(|| {
        let tx_count = 10_000;
        for _ in 0..tx_count {
            scheduler.schedule_execution(tx0.clone(), 0);
        }
        assert_matches!(
            scheduler.wait_for_termination(&WaitReason::TerminatedToFreeze),
            Some((Ok(()), _))
        );
        scheduler.recv(tx_count);
        scheduler.replace_context(create_context());
    });
}
