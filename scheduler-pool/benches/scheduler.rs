#![feature(test)]
#![allow(clippy::integer_arithmetic)]

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

extern crate test;

use {
    assert_matches::assert_matches,
    log::*,
    rand::{thread_rng, Rng},
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        bank::Bank,
        genesis_utils::{create_genesis_config, GenesisConfigInfo},
        installed_scheduler_pool::{
            InstalledScheduler, InstalledSchedulerPoolArc, ResultWithTimings, ScheduleExecutionArg,
            SchedulerId, SchedulingContext, WaitReason, WithTransactionAndIndex,
        },
        prioritization_fee_cache::PrioritizationFeeCache,
    },
    solana_scheduler::SchedulingMode,
    solana_scheduler_pool::{PooledScheduler, ScheduledTransactionHandler, SchedulerPool},
    solana_sdk::{
        system_transaction,
        transaction::{Result, SanitizedTransaction},
    },
    std::{
        fmt::Debug,
        marker::{PhantomData, Send, Sync},
        mem,
        sync::Arc,
    },
    test::Bencher,
};

const TX_COUNT: usize = 10_000;

#[derive(Debug, Default, Clone)]
struct ScheduleExecutionArgForBench;

// use Arc-ed transaction for very cheap .clone() so that the consumer is never starved for
// incoming transactions.
type TransactionWithIndexForBench = Arc<(SanitizedTransaction, usize)>;

impl ScheduleExecutionArg for ScheduleExecutionArgForBench {
    type TransactionWithIndex<'_tx> = TransactionWithIndexForBench;
}

#[derive(Debug, Default, Clone)]
struct BenchFriendlyHandler<SEA: ScheduleExecutionArg + Clone, const MUTATE_ARC: bool>(
    std::marker::PhantomData<SEA>,
);

impl<SEA: ScheduleExecutionArg + Clone, const MUTATE_ARC: bool> ScheduledTransactionHandler<SEA>
    for BenchFriendlyHandler<SEA, MUTATE_ARC>
{
    fn handle(
        &self,
        _result: &mut Result<()>,
        _timings: &mut ExecuteTimings,
        bank: &Arc<Bank>,
        transaction_with_index: &SEA::TransactionWithIndex<'_>,
        _pool: &SchedulerPool,
    ) {
        //std::hint::black_box(bank.clone());
        let mut i = 0;
        for _ in 0..10 {
            if MUTATE_ARC {
                //for _ in 0..2 {
                std::hint::black_box((Arc::downgrade(bank)).upgrade().unwrap());
                //}
            }
            // call random one of Bank's lightweight-and-very-multi-threaded-friendly methods which take a
            // transaction inside this artifical tight loop.
            transaction_with_index.with_transaction_and_index(|transaction, _index| {
                i += bank.get_fee_for_message_with_lamports_per_signature(transaction.message(), i)
            });
        }
        std::hint::black_box(i);
    }
}

type BenchFriendlyHandlerWithArcMutation = BenchFriendlyHandler<ScheduleExecutionArgForBench, true>;
type BenchFriendlyHandlerWithoutArcMutation =
    BenchFriendlyHandler<ScheduleExecutionArgForBench, false>;

fn run_bench<
    F: FnOnce(Arc<SchedulerPool>, SchedulingContext) -> I,
    I: InstalledScheduler<ScheduleExecutionArgForBench>,
>(
    bencher: &mut Bencher,
    create_scheduler: F,
) {
    solana_logger::setup();

    let GenesisConfigInfo {
        genesis_config,
        mint_keypair,
        ..
    } = create_genesis_config(1_000_000_000);
    let bank = &Arc::new(Bank::new_for_tests(&genesis_config));
    let _ignored_prioritization_fee_cache = Arc::new(PrioritizationFeeCache::new(0u64));
    let pool = SchedulerPool::new(None, None, None, _ignored_prioritization_fee_cache);
    let context = SchedulingContext::new(SchedulingMode::BlockVerification, bank.clone());

    let mut scheduler = create_scheduler(pool, context.clone());
    let tx0 = &SanitizedTransaction::from_transaction_for_tests(system_transaction::transfer(
        &mint_keypair,
        &solana_sdk::pubkey::new_rand(),
        2,
        genesis_config.hash(),
    ));
    let tx_with_index = TransactionWithIndexForBench::new((tx0.clone(), 0));
    bencher.iter(|| {
        for _ in 0..TX_COUNT {
            scheduler.schedule_execution(&[tx_with_index.clone()]);
        }
        assert_matches!(
            scheduler.wait_for_termination(&WaitReason::TerminatedToFreeze),
            Some((Ok(()), _))
        );
        scheduler.replace_context(context.clone());
    });
}

mod blocking_ref {
    use {super::*, solana_runtime::installed_scheduler_pool::DefaultScheduleExecutionArg};

    #[bench]
    fn bench_without_arc_mutation(bencher: &mut Bencher) {
        solana_logger::setup();

        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config(1_000_000_000);
        let bank = &Arc::new(Bank::new_for_tests(&genesis_config));
        let _ignored_prioritization_fee_cache = Arc::new(PrioritizationFeeCache::new(0u64));
        let pool = SchedulerPool::new(None, None, None, _ignored_prioritization_fee_cache);
        let context = SchedulingContext::new(SchedulingMode::BlockVerification, bank.clone());

        let mut scheduler = PooledScheduler::<
            _,
            DefaultScheduleExecutionArg,
        >::spawn(pool, context.clone(), BenchFriendlyHandler::<DefaultScheduleExecutionArg, false>::default());
        let tx0 = &SanitizedTransaction::from_transaction_for_tests(system_transaction::transfer(
            &mint_keypair,
            &solana_sdk::pubkey::new_rand(),
            2,
            genesis_config.hash(),
        ));
        let tx_with_index = &(tx0, 0);
        bencher.iter(|| {
            for _ in 0..TX_COUNT {
                scheduler.schedule_execution(&[tx_with_index]);
            }
            assert_matches!(
                scheduler.wait_for_termination(&WaitReason::TerminatedToFreeze),
                Some((Ok(()), _))
            );
            scheduler.replace_context(context.clone());
        });
    }
}

mod blocking {
    use super::*;

    type BlockingScheduler<H> = PooledScheduler<H, ScheduleExecutionArgForBench>;

    #[bench]
    fn bench_with_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            BlockingScheduler::spawn(pool, context, BenchFriendlyHandlerWithArcMutation::default())
        });
    }

    #[bench]
    fn bench_without_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            BlockingScheduler::spawn(pool, context, BenchFriendlyHandlerWithoutArcMutation::default())
        });
    }
}

mod nonblocking {
    use super::*;

    #[derive(Debug)]
    struct NonblockingScheduler<H: ScheduledTransactionHandler<ScheduleExecutionArgForBench>> {
        id: SchedulerId,
        pool: Arc<SchedulerPool>,
        transaction_sender: crossbeam_channel::Sender<ChainedChannel>,
        result_receiver: crossbeam_channel::Receiver<(Result<()>, ExecuteTimings, usize)>,
        lane_count: usize,
        _phantom: PhantomData<H>,
    }

    enum ChainedChannel {
        Payload(TransactionWithIndexForBench),
        NextContext(SchedulingContext),
        NextChannel(Box<dyn WithChannelPair + Send + Sync>),
    }

    type ChannelPair = (
        crossbeam_channel::Receiver<ChainedChannel>,
        crossbeam_channel::Sender<(Result<()>, ExecuteTimings, usize)>,
    );

    trait WithChannelPair {
        fn unwrap_channel_pair(&mut self) -> ChannelPair;
    }

    struct ChannelPairOption(Option<ChannelPair>);

    impl WithChannelPair for ChannelPairOption {
        fn unwrap_channel_pair(&mut self) -> ChannelPair {
            self.0.take().unwrap()
        }
    }

    impl<H: ScheduledTransactionHandler<ScheduleExecutionArgForBench> + Clone + 'static> NonblockingScheduler<H> {
        fn spawn(
            pool: Arc<SchedulerPool>,
            initial_context: SchedulingContext,
            lane_count: usize,
            handler: H,
        ) -> Self {
            let (transaction_sender, transaction_receiver) =
                crossbeam_channel::unbounded::<ChainedChannel>();
            let (result_sender, result_receiver) = crossbeam_channel::unbounded();

            for _ in 0..lane_count {
                let mut bank = Arc::clone(initial_context.bank());
                let mut transaction_receiver = transaction_receiver.clone();
                let mut result_sender = result_sender.clone();
                std::thread::spawn({
                    let pool = pool.clone();
                    let handler = handler.clone();
                    move || {
                        let mut result = Ok(());
                        let mut timings = ExecuteTimings::default();
                        let mut count = 0;
                        while let Ok(message) = transaction_receiver.recv() {
                            match message {
                                ChainedChannel::Payload(with_transaction_and_index) => {
                                    count += 1;
                                    H::handle(
                                        &handler,
                                        &mut result,
                                        &mut timings,
                                        &bank,
                                        &with_transaction_and_index,
                                        &pool,
                                    );
                                }
                                ChainedChannel::NextContext(next_context) => {
                                    bank = next_context.bank().clone();
                                }
                                ChainedChannel::NextChannel(mut next_receiver_box) => {
                                    result_sender
                                        .send((
                                            mem::replace(&mut result, Ok(())),
                                            mem::take(&mut timings),
                                            mem::take(&mut count),
                                        ))
                                        .unwrap();
                                    (transaction_receiver, result_sender) =
                                        next_receiver_box.unwrap_channel_pair();
                                }
                            }
                        }
                    }
                });
            }

            Self {
                id: thread_rng().gen::<SchedulerId>(),
                pool,
                transaction_sender,
                result_receiver,
                lane_count,
                _phantom: PhantomData::default(),
            }
        }
    }
    impl<H: ScheduledTransactionHandler<ScheduleExecutionArgForBench>>
        InstalledScheduler<ScheduleExecutionArgForBench> for NonblockingScheduler<H>
    {
        fn id(&self) -> SchedulerId {
            self.id
        }

        fn pool(&self) -> InstalledSchedulerPoolArc {
            self.pool.clone()
        }

        fn schedule_execution(&self, transaction_with_index: &[TransactionWithIndexForBench]) {
            for tt in transaction_with_index {
                self.transaction_sender
                    .send(ChainedChannel::Payload(tt.clone()))
                    .unwrap();
            }
        }

        fn wait_for_termination(&mut self, _wait_reason: &WaitReason) -> Option<ResultWithTimings> {
            let (next_transaction_sender, next_transaction_receiver) =
                crossbeam_channel::unbounded::<ChainedChannel>();
            let (next_result_sender, next_result_receiver) = crossbeam_channel::unbounded();
            for _ in 0..self.lane_count {
                let (next_transaction_receiver, next_result_sender) = (
                    next_transaction_receiver.clone(),
                    next_result_sender.clone(),
                );
                self.transaction_sender
                    .send(ChainedChannel::NextChannel(Box::new(ChannelPairOption(
                        Some((next_transaction_receiver, next_result_sender)),
                    ))))
                    .unwrap();
            }
            self.transaction_sender = next_transaction_sender;

            let mut overall_result = Ok(());
            let mut overall_timings = ExecuteTimings::default();

            while let Ok((result, timings, count)) = self.result_receiver.recv() {
                match result {
                    Ok(()) => {}
                    Err(e) => overall_result = Err(e),
                }
                overall_timings.accumulate(&timings);
                trace!("received: {count:?}");
            }
            self.result_receiver = next_result_receiver;

            Some((overall_result, overall_timings))
        }

        fn context(&self) -> Option<&SchedulingContext> {
            unimplemented!("not needed for this bench");
        }

        fn replace_context(&mut self, context: SchedulingContext) {
            for _ in 0..self.lane_count {
                self.transaction_sender
                    .send(ChainedChannel::NextContext(context.clone()))
                    .unwrap();
            }
        }
    }

    #[bench]
    fn bench_with_01_thread_with_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            NonblockingScheduler::spawn(pool, context, 1, BenchFriendlyHandlerWithArcMutation::default())
        });
    }

    #[bench]
    fn bench_with_01_thread_without_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            NonblockingScheduler::spawn(pool, context, 1, BenchFriendlyHandlerWithoutArcMutation::default())
        });
    }

    #[bench]
    fn bench_with_04_threads_with_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            NonblockingScheduler::spawn(pool, context, 4, BenchFriendlyHandlerWithArcMutation::default())
        });
    }

    #[bench]
    fn bench_with_04_threads_without_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            NonblockingScheduler::spawn(pool, context, 4, BenchFriendlyHandlerWithoutArcMutation::default())
        });
    }

    #[bench]
    fn bench_with_08_threads_with_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            NonblockingScheduler::spawn(pool, context, 8, BenchFriendlyHandlerWithArcMutation::default())
        });
    }

    #[bench]
    fn bench_with_08_threads_without_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            NonblockingScheduler::spawn(pool, context, 8, BenchFriendlyHandlerWithoutArcMutation::default())
        });
    }

    #[bench]
    fn bench_with_16_threads_with_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            NonblockingScheduler::spawn(pool, context, 16, BenchFriendlyHandlerWithArcMutation::default())
        });
    }

    #[bench]
    fn bench_with_16_threads_without_arc_mutation(bencher: &mut Bencher) {
        run_bench(bencher, |pool, context| {
            NonblockingScheduler::spawn(pool, context, 16, BenchFriendlyHandlerWithoutArcMutation::default())
        });
    }

    mod thread_utilization {
        // tiling?
        use {
            super::*,
            solana_sdk::system_instruction::{SystemInstruction, SystemInstruction::Transfer},
        };

        #[derive(Debug, Clone)]
        struct SleepyHandler;

        impl<SEA: ScheduleExecutionArg> ScheduledTransactionHandler<SEA> for SleepyHandler {
            fn handle(
                &self,
                _result: &mut Result<()>,
                _timings: &mut ExecuteTimings,
                _bank: &Arc<Bank>,
                transaction_with_index: &SEA::TransactionWithIndex<'_>,
                _pool: &SchedulerPool,
            ) {
                transaction_with_index.with_transaction_and_index(|transaction, _index| {
                    let dummy_transfer: SystemInstruction =
                        bincode::deserialize(&transaction.message().instructions()[0].data)
                            .unwrap();
                    let Transfer{lamports: sleep_ms} = dummy_transfer else { panic!() };
                    std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                });
            }
        }

        enum Step {
            Batch(Vec<TransactionWithIndexForBench>),
            // mimic periodic or contention-induced synchronization with this artificial blocking
            Synchronize,
        }

        fn bench_txes_with_random_execution_durations(bencher: &mut Bencher, synchronize: bool) {
            let GenesisConfigInfo {
                genesis_config,
                mint_keypair,
                ..
            } = create_genesis_config(1_000_000_000);
            let bank = &Arc::new(Bank::new_for_tests(&genesis_config));

            let create_tx_with_index = |index| {
                let tx0 =
                    SanitizedTransaction::from_transaction_for_tests(system_transaction::transfer(
                        &mint_keypair,
                        &solana_sdk::pubkey::new_rand(),
                        thread_rng().gen_range(1, 10),
                        genesis_config.hash(),
                    ));
                TransactionWithIndexForBench::new((tx0, index))
            };

            let _ignored_prioritization_fee_cache = Arc::new(PrioritizationFeeCache::new(0u64));
            let pool = SchedulerPool::new(None, None, None, _ignored_prioritization_fee_cache);
            let context = SchedulingContext::new(SchedulingMode::BlockVerification, bank.clone());
            let mut scheduler =
                NonblockingScheduler::spawn(pool, context.clone(), 10, SleepyHandler);
            let scenario: &Vec<Step> = &((0..10)
                .flat_map(|_| {
                    [
                        Step::Batch((0..20).map(create_tx_with_index).collect()),
                        Step::Synchronize,
                    ]
                })
                .collect());
            bencher.iter(|| {
                for step in scenario {
                    match step {
                        Step::Batch(txes) => {
                            for tx in txes {
                                scheduler.schedule_execution(&[tx.clone()]);
                            }
                        }
                        Step::Synchronize => {
                            if synchronize {
                                assert_matches!(
                                    scheduler.wait_for_termination(&WaitReason::TerminatedToFreeze),
                                    Some((Ok(()), _))
                                );
                                scheduler.replace_context(context.clone());
                            }
                        }
                    }
                }
                assert_matches!(
                    scheduler.wait_for_termination(&WaitReason::TerminatedToFreeze),
                    Some((Ok(()), _))
                );
                scheduler.replace_context(context.clone());
            });
        }

        #[bench]
        fn bench_txes_with_random_execution_durations_with_interleaved_synchronization(
            bencher: &mut Bencher,
        ) {
            bench_txes_with_random_execution_durations(bencher, true);
        }

        #[bench]
        fn bench_txes_with_random_execution_durations_without_interleaved_synchronization(
            bencher: &mut Bencher,
        ) {
            bench_txes_with_random_execution_durations(bencher, false);
        }

// for each index, builds a transaction dependency graph of indices that need to execute before
// the current one.
// The returned Vec<HashSet<usize>> is a 1:1 mapping for the indices that need to be executed
// before that index can be executed
fn build_dependency_graph(tx_account_locks: &[TransactionAccountLocks]) -> Vec<IntSet<usize>> {
    // build a map whose key is a pubkey + value is a sorted vector of all indices that
    // lock that account
    let mut indices_read_locking_account = HashMap::new();
    let mut indicies_write_locking_account = HashMap::new();
    tx_account_locks
        .iter()
        .enumerate()
        .for_each(|(idx, tx_account_locks)| {
            for account in &tx_account_locks.readonly {
                indices_read_locking_account
                    .entry(**account)
                    .and_modify(|indices: &mut Vec<usize>| indices.push(idx))
                    .or_insert_with(|| vec![idx]);
            }
            for account in &tx_account_locks.writable {
                indicies_write_locking_account
                    .entry(**account)
                    .and_modify(|indices: &mut Vec<usize>| indices.push(idx))
                    .or_insert_with(|| vec![idx]);
            }
        });

    tx_account_locks
        .iter()
        .enumerate()
        .map(|(idx, account_locks)| {
            let mut dep_graph: IntSet<usize> = IntSet::default();

            let readlock_conflict_accs = account_locks.writable.iter();
            let writelock_conflict_accs = account_locks
                .readonly
                .iter()
                .chain(account_locks.writable.iter());

            for acc in readlock_conflict_accs {
                if let Some(indices) = indices_read_locking_account.get(acc) {
                    dep_graph.extend(indices.iter().take_while(|l_idx| **l_idx < idx));
                }
            }

            for acc in writelock_conflict_accs {
                if let Some(indices) = indicies_write_locking_account.get(acc) {
                    dep_graph.extend(indices.iter().take_while(|l_idx| **l_idx < idx));
                }
            }
            dep_graph
        })
        .collect()
}

use solana_sdk::transaction::TransactionAccountLocks;
use std::collections::HashMap;
use solana_ledger::blockstore_processor::TransactionStatusSender;
use std::time::Instant;
use solana_sdk::signature::Signature;
use solana_runtime::vote_sender_types::ReplayVoteSender;
use std::sync::RwLock;
use nohash_hasher::IntSet;

fn execute_batches(
    bank: &Arc<Bank>,
    pending_transactions: &[&SanitizedTransaction],
    transaction_status_sender: Option<&TransactionStatusSender>,
    replay_vote_sender: Option<&ReplayVoteSender>,
    receiver: &crossbeam_channel::Receiver<Signature>,
) -> Result<()> {
    if pending_transactions.is_empty() {
        return Ok(());
    }

    let mut tx_account_locks: Vec<_> = Vec::with_capacity(pending_transactions.len());
    for tx in pending_transactions {
        tx_account_locks.push(tx.get_account_locks(bank.get_transaction_account_lock_limit())?);
    }

    // the dependency graph contains the indices that must be executed (marked with State::Done) before they can be executed
    let dependency_graph = build_dependency_graph(&tx_account_locks);

    #[derive(Clone)]
    enum State {
        Blocked,
        Processing,
        Done,
    }

    let mut processing_states: Vec<State> = vec![State::Blocked; dependency_graph.len()];
    let mut signature_indices: HashMap<&Signature, usize> =
        HashMap::with_capacity(dependency_graph.len());
    signature_indices.extend(
        pending_transactions
            .iter()
            .enumerate()
            .map(|(idx, tx)| (tx.signature(), idx)),
    );

    let mut is_done = false;
    while !is_done {
        is_done = true;
        for idx in 0..processing_states.len() {
            match processing_states[idx] {
                State::Blocked => {
                    is_done = false;

                    // if all the dependent txs are executed, this transaction can be scheduled for
                    // execution.
                    if dependency_graph[idx]
                        .iter()
                        .all(|idx| matches!(processing_states[*idx], State::Done))
                    {
                        debug!(
                            "scheduling signature: {}",
                            pending_transactions[idx].signature()
                        );

                        /*
                        let _result = tx_executor_handle
                            .schedule(BankTransactionExecutionRequest {
                                bank: bank.clone(),
                                tx: pending_transactions[idx].clone(),
                                transaction_status_sender: transaction_status_sender.cloned(),
                                replay_vote_sender: replay_vote_sender.cloned(),
                                cost_capacity_meter: cost_capacity_meter.clone(),
                            })
                            .unwrap();
                        */
                        // this idx can be scheduled and moved to processing
                        processing_states[idx] = State::Processing;
                    }
                }
                State::Processing => {
                    is_done = false;
                }
                State::Done => {}
            }
        }

        if is_done {
            break;
        }

        let mut executor_responses: Vec<_> = vec![receiver.recv().unwrap()];
        executor_responses.extend(receiver.try_iter());
        for r in &executor_responses {
            processing_states[*signature_indices.get(r).unwrap()] = State::Done;
        }
    }
    Ok(())
}

        #[derive(Debug, Clone)]
        struct SleepyHandler2(crossbeam_channel::Sender<Signature>);

        impl<SEA: ScheduleExecutionArg> ScheduledTransactionHandler<SEA> for SleepyHandler2 {
            fn handle(
                &self,
                _result: &mut Result<()>,
                _timings: &mut ExecuteTimings,
                _bank: &Arc<Bank>,
                transaction_with_index: &SEA::TransactionWithIndex<'_>,
                _pool: &SchedulerPool,
            ) {
                transaction_with_index.with_transaction_and_index(|transaction, _index| {
                    let dummy_transfer: SystemInstruction =
                        bincode::deserialize(&transaction.message().instructions()[0].data)
                            .unwrap();
                    let Transfer{lamports: sleep_ms} = dummy_transfer else { panic!() };
                    std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                    //self.0.send(transaction.signature().clone()).unwrap();
                });
            }
        }

        #[derive(Debug)]
        struct NonblockingSchedulerWithDepGraph(NonblockingScheduler<SleepyHandler2>, std::sync::Mutex<Vec<SanitizedTransaction>>);

        impl InstalledScheduler<ScheduleExecutionArgForBench> for NonblockingSchedulerWithDepGraph {
            fn id(&self) -> SchedulerId {
                self.0.id()
            }

            fn schedule_execution<'a>(&'a self, transaction_with_index: &'a [TransactionWithIndexForBench]) {
                for t in transaction_with_index {
                    self.1.lock().unwrap().push(t);
                }
            }

            fn pool(&self) -> InstalledSchedulerPoolArc {
                self.0.pool()
            }

            fn context<'a>(&'a self) -> Option<&'a SchedulingContext> {
                self.0.context()
            }

            fn replace_context(&mut self, context: SchedulingContext) {
                self.0.replace_context(context)
            }
        }

        #[bench]
        fn bench_txes_with_long_serialized_runs(_bencher: &Bencher) {
            let GenesisConfigInfo {
                genesis_config,
                mint_keypair,
                ..
            } = create_genesis_config(1_000_000_000);
            let bank = &Arc::new(Bank::new_for_tests(&genesis_config));

            let _ignored_prioritization_fee_cache = Arc::new(PrioritizationFeeCache::new(0u64));
            let pool = SchedulerPool::new(None, None, None, _ignored_prioritization_fee_cache);
            let context = SchedulingContext::new(SchedulingMode::BlockVerification, bank.clone());
            let (sender, receiver) = crossbeam_channel::unbounded();
            let handler2 = SleepyHandler2(sender);
            let mut scheduler =
                NonblockingScheduler::spawn(pool, context.clone(), 10, handler2);
        }
    }
}
