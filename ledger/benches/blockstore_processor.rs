#![allow(clippy::arithmetic_side_effects)]
#![feature(test)]

use {
    rayon::{
        iter::IndexedParallelIterator,
        prelude::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator},
    },
    solana_ledger::{
        blockstore_processor::{execute_batch, TransactionBatchWithIndexes},
        genesis_utils::{create_genesis_config, GenesisConfigInfo},
    },
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        bank::Bank, prioritization_fee_cache::PrioritizationFeeCache,
        transaction_batch::TransactionBatch,
    },
    solana_sdk::{
        account::Account, feature_set::apply_cost_tracker_during_replay, signature::Keypair,
        signer::Signer, stake_history::Epoch, system_program, system_transaction,
        transaction::SanitizedTransaction,
    },
    std::{borrow::Cow, sync::Arc},
    test::Bencher,
};
use solana_ledger::blockstore_processor::execute_batch2;

extern crate test;

fn create_accounts(num: usize) -> Vec<Keypair> {
    (0..num).into_par_iter().map(|_| Keypair::new()).collect()
}

fn create_funded_accounts(bank: &Bank, num: usize) -> Vec<Keypair> {
    assert!(
        num.is_power_of_two(),
        "must be power of 2 for parallel funding tree"
    );
    let accounts = create_accounts(num);

    accounts.par_iter().for_each(|account| {
        bank.store_account(
            &account.pubkey(),
            &Account {
                lamports: 5100,
                data: vec![],
                owner: system_program::id(),
                executable: false,
                rent_epoch: Epoch::MAX,
            },
        );
    });

    accounts
}

fn create_transactions(bank: &Bank, num: usize) -> Vec<SanitizedTransaction> {
    let funded_accounts = create_funded_accounts(bank, 2 * num);
    funded_accounts
        .into_par_iter()
        .chunks(2)
        .map(|chunk| {
            let from = &chunk[0];
            let to = &chunk[1];
            system_transaction::transfer(from, &to.pubkey(), 1, bank.last_blockhash())
        })
        .map(SanitizedTransaction::from_transaction_for_tests)
        .collect()
}

struct BenchFrame {
    bank: Arc<Bank>,
    prioritization_fee_cache: PrioritizationFeeCache,
}

fn setup(apply_cost_tracker_during_replay: bool) -> BenchFrame {
    let mint_total = u64::MAX;
    let GenesisConfigInfo {
        mut genesis_config, ..
    } = create_genesis_config(mint_total);

    // Set a high ticks_per_slot so we don't run out of ticks
    // during the benchmark
    genesis_config.ticks_per_slot = 10_000;

    let mut bank = Bank::new_for_benches(&genesis_config);

    if !apply_cost_tracker_during_replay {
        bank.deactivate_feature(&apply_cost_tracker_during_replay::id());
    }

    // Allow arbitrary transaction processing time for the purposes of this bench
    bank.ns_per_slot = u128::MAX;

    // set cost tracker limits to MAX so it will not filter out TXs
    bank.write_cost_tracker()
        .unwrap()
        .set_limits(std::u64::MAX, std::u64::MAX, std::u64::MAX);
    let bank = bank.wrap_with_bank_forks_for_tests().0;
    let prioritization_fee_cache = PrioritizationFeeCache::default();
    BenchFrame {
        bank,
        prioritization_fee_cache,
    }
}

fn bench_execute_batch(
    bencher: &mut Bencher,
    batch_size: usize,
    apply_cost_tracker_during_replay: bool,
) {
    let BenchFrame {
        bank,
        prioritization_fee_cache,
    } = setup(apply_cost_tracker_during_replay);
    let transactions = create_transactions(&bank, 2_usize.pow(21));
    let bank2 = bank.clone();
    let batches: Vec<_> = transactions
        .chunks(batch_size)
        .map(|txs| {
            let mut batch =
                TransactionBatch::new(vec![Ok(()); txs.len()], &bank2, Cow::Borrowed(txs));
            batch.set_needs_unlock(false);
            TransactionBatchWithIndexes {
                batch,
                transaction_indexes: (0..batch_size).collect(),
            }
        })
        .collect();
    let mut batches_iter = batches.iter();

    let mut timing = ExecuteTimings::default();

    std::thread::scope(move |scope| {
        scope.spawn(move || {
            eprintln!("profile me!: {}", rustix::thread::gettid().as_raw_nonzero().get());
            std::thread::sleep(std::time::Duration::from_secs(10));
            for _ in 0..100 {
                for _ in 0..(64/batch_size) {
                    let batch = batches_iter.next().unwrap();
                    execute_batch(
                        &batch,
                        &bank,
                        None,
                        None,
                        &mut timing,
                        None,
                        &prioritization_fee_cache,
                    ).unwrap();
                }
            }
        });
    });
    drop(batches);
    //eprintln!("{:?}", timing);
}

fn bench_execute_batch2(
    bencher: &mut Bencher,
    batch_size: usize,
    apply_cost_tracker_during_replay: bool,
) {
    let BenchFrame {
        bank,
        prioritization_fee_cache,
    } = setup(apply_cost_tracker_during_replay);
    let transactions = create_transactions(&bank, 2_usize.pow(21));
    let bank2 = bank.clone();
    let batches: Vec<_> = transactions
        .chunks(batch_size)
        .map(|txs| {
            let mut batch =
                TransactionBatch::new(vec![Ok(()); txs.len()], &bank2, Cow::Borrowed(txs));
            batch.set_needs_unlock(false);
            TransactionBatchWithIndexes {
                batch,
                transaction_indexes: (0..batch_size).collect(),
            }
        })
        .collect();
    let mut batches_iter = batches.iter();

    let mut timing = ExecuteTimings::default();

    std::thread::scope(move |scope| {
        scope.spawn(move || {
            eprintln!("profile me!: {}", rustix::thread::gettid().as_raw_nonzero().get());
            std::thread::sleep(std::time::Duration::from_secs(10));
            bencher.iter(|| {
            //for _ in 0..100 {
                for _ in 0..(64/batch_size) {
                    let batch = batches_iter.next().unwrap();
                    execute_batch2(
                        &batch,
                        &bank,
                        None,
                        None,
                        &mut timing,
                        None,
                        &prioritization_fee_cache,
                    ).unwrap();
                }
            //}
            });
        });
    });
    drop(batches);
    //eprintln!("{:?}", timing);
}

#[bench]
fn bench_execute_batch_01_unbatched_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch(bencher, 1, false);
}

#[bench]
fn bench_execute_batch_00001_unbatched_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch2(bencher, 1, false);
}

#[bench]
fn bench_execute_batch_00004_unbatched_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch2(bencher, 4, false);
}

#[bench]
fn bench_execute_batch_00016_unbatched_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch2(bencher, 16, false);
}

#[bench]
fn bench_execute_batch_00064_unbatched_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch2(bencher, 64, false);
}

#[bench]
fn bench_execute_batch_02_tx2_batch_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch(bencher, 2, false);
}

#[bench]
fn bench_execute_batch_04_tx4_batch_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch(bencher, 4, false);
}

#[bench]
fn bench_execute_batch_08_tx8_batch_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch(bencher, 8, false);
}

#[bench]
fn bench_execute_batch_16_tx8_batch_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch(bencher, 16, false);
}

#[bench]
fn bench_execute_batch_32_half_batch_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch(bencher, 32, false);
}

#[bench]
fn bench_execute_batch_64_full_batch_disable_tx_cost_update(bencher: &mut Bencher) {
    bench_execute_batch(bencher, 64, false);
}
