#![feature(test)]

extern crate test;

#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use {
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        bank::Bank,
        bank_forks::BankForks,
        genesis_utils::{create_genesis_config, GenesisConfigInfo},
        installed_scheduler_pool::{InstalledScheduler, SchedulingContext},
        prioritization_fee_cache::PrioritizationFeeCache,
    },
    solana_sdk::{
        system_transaction,
        transaction::{Result, SanitizedTransaction},
    },
    solana_unified_scheduler_pool::{HandlerContext, PooledScheduler, SchedulerPool, TaskHandler},
    std::sync::Arc,
    test::Bencher,
};

#[derive(Debug)]
struct DummyTaskHandler;

impl TaskHandler for DummyTaskHandler {
    fn handle(
        _result: &mut Result<()>,
        _timings: &mut ExecuteTimings,
        _bank: &Arc<Bank>,
        _transaction: &SanitizedTransaction,
        _index: usize,
        _handler_context: &HandlerContext,
    ) {
    }
}

fn setup_dummy_fork_graph(bank: Bank) -> Arc<Bank> {
    let slot = bank.slot();
    let bank_fork = BankForks::new_rw_arc(bank);
    let bank = bank_fork.read().unwrap().get(slot).unwrap();
    bank.loaded_programs_cache
        .write()
        .unwrap()
        .set_fork_graph(bank_fork);
    bank
}

fn do_bench_tx_throughput(bencher: &mut Bencher) {
    solana_logger::setup();

    let GenesisConfigInfo {
        genesis_config,
        mint_keypair,
        ..
    } = create_genesis_config(10_000);
    let tx0 = &SanitizedTransaction::from_transaction_for_tests(system_transaction::transfer(
        &mint_keypair,
        &solana_sdk::pubkey::new_rand(),
        2,
        genesis_config.hash(),
    ));
    let bank = Bank::new_for_tests(&genesis_config);
    let bank = setup_dummy_fork_graph(bank);
    let ignored_prioritization_fee_cache = Arc::new(PrioritizationFeeCache::new(0u64));
    let pool = SchedulerPool::<PooledScheduler<DummyTaskHandler>, _>::new(
        None,
        None,
        None,
        ignored_prioritization_fee_cache,
    );
    let context = SchedulingContext::new(bank.clone());

    assert_eq!(bank.transaction_count(), 0);
    let mut scheduler = pool.do_take_scheduler(context);
    bencher.iter(|| {
        for _ in 0..10_000 {
            scheduler.schedule_execution(&(tx0, 0));
        }
        scheduler.pause_for_recent_blockhash();
        scheduler.clear_session_result_with_timings();
        scheduler.restart_session();
    });
}

#[cfg(all(
    feature = "bench-drop-in-accumulator",
    not(feature = "bench-conflicting-execution")
))]
#[bench]
fn bench_tx_throughput_drop_in_accumulator(bencher: &mut Bencher) {
    do_bench_tx_throughput(bencher)
}

#[cfg(all(
    feature = "bench-drop-in-scheduler",
    not(feature = "bench-conflicting-execution")
))]
#[bench]
fn bench_tx_throughput_drop_in_scheduler(bencher: &mut Bencher) {
    do_bench_tx_throughput(bencher)
}

#[cfg(all(
    feature = "bench-drop-in-accumulator",
    feature = "bench-conflicting-execution"
))]
#[bench]
fn bench_tx_throughput_drop_in_accumulator_conflicting(bencher: &mut Bencher) {
    do_bench_tx_throughput(bencher)
}

#[cfg(all(
    feature = "bench-drop-in-scheduler",
    feature = "bench-conflicting-execution"
))]
#[bench]
fn bench_tx_throughput_drop_in_scheduler_conflicting(bencher: &mut Bencher) {
    do_bench_tx_throughput(bencher)
}
