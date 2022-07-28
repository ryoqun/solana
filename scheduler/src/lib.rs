#![feature(map_first_last)]

use {
    atomic_enum::atomic_enum,
    crossbeam_channel::{bounded, unbounded},
    log::*,
    rand::Rng,
    sha2::{Digest, Sha256},
    solana_entry::entry::Entry,
    solana_measure::measure::Measure,
    solana_metrics::datapoint_info,
    solana_sdk::{
        hash::Hash,
        pubkey::Pubkey,
        transaction::{SanitizedTransaction, TransactionAccountLocks, VersionedTransaction},
    },
};

#[derive(Debug)]
pub struct ExecutionEnvironment {
    lock_attempts: Vec<LockAttempt>,
    //accounts: Vec<i8>,
    pub cu: usize,
    pub task: Task,
}

impl ExecutionEnvironment {
    //fn new(cu: usize) -> Self {
    //    Self {
    //        cu,
    //        ..Self::default()
    //    }
    //}

    //fn abort() {
    //  pass AtomicBool into InvokeContext??
    //}
}

#[derive(Debug)]
struct LockAttempt {
    address: Pubkey,
    is_success: bool,
    requested_usage: RequestedUsage,
}

impl LockAttempt {
    fn is_success(&self) -> bool {
        self.is_success
    }

    fn success(address: Pubkey, requested_usage: RequestedUsage) -> Self {
        Self {
            address,
            is_success: true,
            requested_usage,
        }
    }

    fn failure(address: Pubkey, requested_usage: RequestedUsage) -> Self {
        Self {
            address,
            is_success: false,
            requested_usage,
        }
    }
}

type UsageCount = usize;
const SOLE_USE_COUNT: UsageCount = 1;

#[derive(PartialEq)]
enum CurrentUsage {
    Unused,
    // weight to abort running tx?
    // also sum all readonly weights to subvert to write lock with greater weight?
    Readonly(UsageCount),
    Writable,
}

impl CurrentUsage {
    fn renew(requested_usage: RequestedUsage) -> Self {
        match requested_usage {
            RequestedUsage::Readonly => CurrentUsage::Readonly(SOLE_USE_COUNT),
            RequestedUsage::Writable => CurrentUsage::Writable,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum RequestedUsage {
    Readonly,
    Writable,
}

struct Page {
    current_usage: CurrentUsage,
    contended_unique_weights: std::collections::BTreeSet<UniqueWeight>,
    //next_scheduled_task // reserved_task guaranteed_task
    //loaded account
}

type AddressBookMap = std::collections::BTreeMap<Pubkey, Page>;

// needs ttl mechanism and prune
#[derive(Default)]
pub struct AddressBook {
    map: AddressBookMap,
    newly_uncontended_addresses: std::collections::BTreeSet<Pubkey>,
}

impl AddressBook {
    #[inline(never)]
    fn attempt_lock_address(
        &mut self,
        unique_weight: &UniqueWeight,
        address: Pubkey,
        requested_usage: RequestedUsage,
    ) -> LockAttempt {
        use std::collections::btree_map::Entry;

        match self.map.entry(address) {
            // unconditional success if it's initial access
            Entry::Vacant(entry) => {
                entry.insert(Page {
                    current_usage: CurrentUsage::renew(requested_usage),
                    contended_unique_weights: Default::default(),
                });
                LockAttempt::success(address, requested_usage)
            }
            Entry::Occupied(mut entry) => {
                let mut page = entry.get_mut();

                match &mut page.current_usage {
                    CurrentUsage::Unused => {
                        page.current_usage = CurrentUsage::renew(requested_usage);
                        LockAttempt::success(address, requested_usage)
                    }
                    CurrentUsage::Readonly(ref mut current_count) => {
                        match &requested_usage {
                            RequestedUsage::Readonly => {
                                *current_count += 1;
                                LockAttempt::success(address, requested_usage)
                            }
                            RequestedUsage::Writable => {
                                // skip insert if existing
                                page.contended_unique_weights.insert(*unique_weight);
                                LockAttempt::failure(address, requested_usage)
                            }
                        }
                    }
                    CurrentUsage::Writable => {
                        match &requested_usage {
                            RequestedUsage::Readonly | RequestedUsage::Writable => {
                                // skip insert if existing
                                page.contended_unique_weights.insert(*unique_weight);
                                LockAttempt::failure(address, requested_usage)
                            }
                        }
                    }
                }
            }
        }
    }

    #[inline(never)]
    fn remove_contended_unique_weight(&mut self, unique_weight: &UniqueWeight, address: &Pubkey) {
        use std::collections::btree_map::Entry;

        match self.map.entry(*address) {
            Entry::Vacant(entry) => unreachable!(),
            Entry::Occupied(mut entry) => {
                let mut page = entry.get_mut();
                page.contended_unique_weights.remove(unique_weight);
            }
        }
    }

    fn ensure_unlock(&mut self, attempt: &LockAttempt) {
        if attempt.is_success() {
            self.unlock(attempt);
        }
    }

    #[inline(never)]
    fn unlock(&mut self, attempt: &LockAttempt) -> bool {
        debug_assert!(attempt.is_success());

        use std::collections::btree_map::Entry;
        let mut newly_uncontended = false;
        let mut still_queued = false;

        match self.map.entry(attempt.address) {
            Entry::Occupied(mut entry) => {
                let mut page = entry.get_mut();

                match &mut page.current_usage {
                    CurrentUsage::Readonly(ref mut current_count) => {
                        match &attempt.requested_usage {
                            RequestedUsage::Readonly => {
                                if *current_count == SOLE_USE_COUNT {
                                    newly_uncontended = true;
                                } else {
                                    *current_count -= 1;
                                }
                            }
                            RequestedUsage::Writable => unreachable!(),
                        }
                    }
                    CurrentUsage::Writable => match &attempt.requested_usage {
                        RequestedUsage::Writable => {
                            newly_uncontended = true;
                        }
                        RequestedUsage::Readonly => unreachable!(),
                    },
                    CurrentUsage::Unused => unreachable!(),
                }

                if newly_uncontended {
                    page.current_usage = CurrentUsage::Unused;
                    if !page.contended_unique_weights.is_empty() {
                        still_queued = true;
                    }
                }
            }
            Entry::Vacant(_entry) => {
                unreachable!()
            }
        }

        still_queued
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Weight {
    // naming: Sequence Ordering?
    pub ix: usize, // index in ledger entry?
                   // gas fee
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UniqueWeight {
    // naming: Sequence Ordering?
    weight: Weight,
    // we can't use Transaction::message_hash because it's manipulatable to be favorous to the tx
    // submitter
    //unique_key: Hash, // tie breaker? random noise? also for unique identification of txes?
    // fee?
}
/*
pub type Weight = usize;
pub type UniqueWeight = usize;
*/

struct Bundle {
    // what about bundle1{tx1a, tx2} and bundle2{tx1b, tx2}?
}

#[derive(Debug)]
pub struct Task {
    pub tx: Box<SanitizedTransaction>, // actually should be Bundle
}

// RunnableQueue, ContendedQueue?
#[derive(Default)]
pub struct TaskQueue {
    map: std::collections::BTreeMap<UniqueWeight, Task>,
}

struct ContendedQueue {
    map: std::collections::BTreeMap<UniqueWeight, Task>,
}

impl TaskQueue {
    #[inline(never)]
    fn add(&mut self, unique_weight: UniqueWeight, task: Task) {
        //info!("TaskQueue::add(): {:?}", unique_weight);
        let pre_existed = self.map.insert(unique_weight, task);
        debug_assert!(pre_existed.is_none()); //, "identical shouldn't exist: {:?}", unique_weight);
    }

    #[inline(never)]
    fn next_task_unique_weight(&self) -> Option<UniqueWeight> {
        self.map.last_key_value().map(|e| e.0.clone())
    }

    #[inline(never)]
    fn pop_next_task(&mut self) -> Option<(UniqueWeight, Task)> {
        self.map.pop_last()
    }
}

#[inline(never)]
fn attempt_lock_for_execution<'a>(
    address_book: &mut AddressBook,
    unique_weight: &UniqueWeight,
    message_hash: &'a Hash,
    locks: &'a TransactionAccountLocks,
) -> Vec<LockAttempt> {
    // no short-cuircuit; we at least all need to add to the contended queue
    let writable_lock_iter = locks.writable.iter().map(|a| (a, RequestedUsage::Writable));
    let readonly_lock_iter = locks.readonly.iter().map(|a| (a, RequestedUsage::Readonly));
    let chained_iter = writable_lock_iter.chain(readonly_lock_iter);

    chained_iter
        .map(|(a, usage)| address_book.attempt_lock_address(unique_weight, **a, usage))
        .collect::<Vec<_>>()
}

pub struct ScheduleStage {}

impl ScheduleStage {
    fn push_to_queue(
        (weight, tx): (Weight, Box<SanitizedTransaction>),
        runnable_queue: &mut TaskQueue,
    ) {
        // manage randomness properly for future scheduling determinism
        let mut rng = rand::thread_rng();

        //let ix = 23;
        //let tx = bank
        //    .verify_transaction(
        //        tx,
        //        solana_sdk::transaction::TransactionVerificationMode::FullVerification,
        //    )
        //    .unwrap();
        //tx.foo();

        runnable_queue.add(
            UniqueWeight {
                weight,
                //unique_key: solana_sdk::hash::new_rand(&mut rng),
            },
            Task { tx },
        );
    }

    #[inline(never)]
    fn get_newly_u_u_w<'a>(
        address: &'a Pubkey,
        address_book: &'a AddressBook,
    ) -> &'a std::collections::BTreeSet<UniqueWeight> {
        &address_book
            .map
            .get(address)
            .unwrap()
            .contended_unique_weights
    }

    #[inline(never)]
    fn get_weight_from_contended(address_book: &AddressBook) -> Option<UniqueWeight> {
        let mut heaviest_by_address: Option<UniqueWeight> = None;
        //info!("n u a len(): {}", address_book.newly_uncontended_addresses.len());
        for address in address_book.newly_uncontended_addresses.iter() {
            let newly_uncontended_unique_weights = Self::get_newly_u_u_w(address, &address_book);
            if let Some(&uw) = newly_uncontended_unique_weights.last() {
                if let Some(c) = heaviest_by_address {
                    if uw > c {
                        heaviest_by_address = Some(uw);
                    }
                } else {
                    heaviest_by_address = Some(uw);
                }
            }
        }
        heaviest_by_address
    }

    #[inline(never)]
    fn select_next_task(
        runnable_queue: &mut TaskQueue,
        contended_queue: &mut TaskQueue,
        address_book: &mut AddressBook,
    ) -> Option<(bool, UniqueWeight, Task)> {
        match (
            Self::get_weight_from_contended(address_book),
            runnable_queue.next_task_unique_weight(),
        ) {
            (Some(weight_from_contended), Some(weight_from_runnable)) => {
                if weight_from_contended < weight_from_runnable {
                    runnable_queue.pop_next_task().map(|(uw, t)| (true, uw, t))
                } else if weight_from_contended > weight_from_runnable {
                    let task = contended_queue.map.remove(&weight_from_contended).unwrap();
                    Some((false, weight_from_contended, task))
                } else {
                    unreachable!(
                        "identical unique weights shouldn't exist in both runnable and contended"
                    )
                }
            }
            (Some(weight_from_contended), None) => {
                let task = contended_queue.map.remove(&weight_from_contended).unwrap();
                Some((false, weight_from_contended, task))
            }
            (None, Some(weight_from_runnable)) => {
                runnable_queue.pop_next_task().map(|(uw, t)| (true, uw, t))
            }
            (None, None) => None,
        }
    }

    #[inline(never)]
    fn pop_from_queue_then_lock(
        runnable_queue: &mut TaskQueue,
        contended_queue: &mut TaskQueue,
        address_book: &mut AddressBook,
    ) -> Option<(UniqueWeight, Task, Vec<LockAttempt>)> {
        for (from_runnable, unique_weight, next_task) in
            Self::select_next_task(runnable_queue, contended_queue, address_book)
        {
            let message_hash = next_task.tx.message_hash();
            let locks = next_task.tx.get_account_locks().unwrap();

            // plumb message_hash into StatusCache or implmenent our own for duplicate tx
            // detection?

            let lock_attempts =
                attempt_lock_for_execution(address_book, &unique_weight, &message_hash, &locks);
            let is_success = lock_attempts.iter().all(|g| g.is_success());

            if !is_success {
                //info!("ensure_unlock_for_failed_execution(): {:?} {}", (&unique_weight, from_runnable), next_task.tx.signature());
                Self::ensure_unlock_for_failed_execution(
                    address_book,
                    lock_attempts,
                    from_runnable,
                );
                contended_queue.add(unique_weight, next_task);
                continue;
            }

            return Some((unique_weight, next_task, lock_attempts));
        }

        None
    }

    #[inline(never)]
    fn apply_successful_lock_before_execution(
        address_book: &mut AddressBook,
        unique_weight: UniqueWeight,
        lock_attempts: &Vec<LockAttempt>,
    ) {
        for l in lock_attempts {
            // ensure to remove remaining refs of this unique_weight
            address_book.remove_contended_unique_weight(&unique_weight, &l.address);

            // revert because now contended again
            address_book.newly_uncontended_addresses.remove(&l.address);
        }
    }

    #[inline(never)]
    fn ensure_unlock_for_failed_execution(
        address_book: &mut AddressBook,
        lock_attempts: Vec<LockAttempt>,
        from_runnable: bool,
    ) {
        for l in lock_attempts {
            address_book.ensure_unlock(&l);

            // revert because now contended again
            if !from_runnable {
                address_book.newly_uncontended_addresses.remove(&l.address);
            }

            // todo: mem::forget and panic in LockAttempt::drop()
        }
    }

    #[inline(never)]
    fn unlock_after_execution(address_book: &mut AddressBook, lock_attempts: Vec<LockAttempt>) {
        for l in lock_attempts {
            let newly_uncontended_while_queued = address_book.unlock(&l);
            if newly_uncontended_while_queued {
                address_book.newly_uncontended_addresses.insert(l.address);
            }

            // todo: mem::forget and panic in LockAttempt::drop()
        }
    }

    #[inline(never)]
    fn prepare_scheduled_execution(
        address_book: &mut AddressBook,
        unique_weight: UniqueWeight,
        task: Task,
        lock_attempts: Vec<LockAttempt>,
    ) -> Box<ExecutionEnvironment> {
        let mut rng = rand::thread_rng();
        // relock_before_execution() / update_address_book() / update_uncontended_addresses()?
        Self::apply_successful_lock_before_execution(address_book, unique_weight, &lock_attempts);
        // load account now from AccountsDb

        Box::new(ExecutionEnvironment {
            lock_attempts,
            task,
            cu: rng.gen_range(3, 1000),
        })
    }

    #[inline(never)]
    fn commit_result(ee: &mut ExecutionEnvironment, address_book: &mut AddressBook) {
        let lock_attempts = std::mem::take(&mut ee.lock_attempts);
        // do par()-ly?
        Self::unlock_after_execution(address_book, lock_attempts);

        // par()-ly clone updated Accounts into address book
    }

    #[inline(never)]
    fn schedule_next_execution(
        runnable_queue: &mut TaskQueue,
        contended_queue: &mut TaskQueue,
        address_book: &mut AddressBook,
    ) -> Option<Box<ExecutionEnvironment>> {
        let maybe_ee =
            Self::pop_from_queue_then_lock(runnable_queue, contended_queue, address_book)
                .map(|(uw, t, ll)| Self::prepare_scheduled_execution(address_book, uw, t, ll));
        maybe_ee
    }

    #[inline(never)]
    fn register_runnable_task(
        weighted_tx: (Weight, Box<SanitizedTransaction>),
        runnable_queue: &mut TaskQueue,
    ) {
        Self::push_to_queue(weighted_tx, runnable_queue)
    }

    pub fn run(
        runnable_queue: &mut TaskQueue,
        contended_queue: &mut TaskQueue,
        address_book: &mut AddressBook,
        from_previous_stage: &crossbeam_channel::Receiver<(Weight, Box<SanitizedTransaction>)>,
        // ideally want to stop wrapping with Option<...>...
        to_execute_substage: &crossbeam_channel::Sender<Option<Box<ExecutionEnvironment>>>,
        from_execute_substage: &crossbeam_channel::Receiver<Box<ExecutionEnvironment>>,
        to_next_stage: &crossbeam_channel::Sender<Box<ExecutionEnvironment>>, // assume nonblocking
    ) {
        use crossbeam_channel::select;

        let mut maybe_ee = None;
        let (to_full, _r) = bounded(0);

        loop {
            info!("schedule_once!");

            // this trick is needed for conditional (Option<_>) send
            // upstream this to crossbeam-channel...
            let to_execute_substage_if_ready = maybe_ee
                .as_ref()
                .map(|_| to_execute_substage)
                .unwrap_or(&to_full);

            select! {
                recv(from_previous_stage) -> weighted_tx => {
                    info!("recv from previous");
                    let weighted_tx = weighted_tx.unwrap();
                    Self::register_runnable_task(weighted_tx, runnable_queue);
                    if maybe_ee.is_none() {
                        maybe_ee = Self::schedule_next_execution(runnable_queue, contended_queue, address_book);
                    }
                }
                send(to_execute_substage_if_ready, maybe_ee) -> res => {
                    info!("send to execute");
                    res.unwrap();
                    maybe_ee = None;
                }
                recv(from_execute_substage) -> processed_execution_environment => {
                    info!("recv from execute");
                    let mut processed_execution_environment = processed_execution_environment.unwrap();

                    Self::commit_result(&mut processed_execution_environment, address_book);

                    if maybe_ee.is_none() {
                        maybe_ee = Self::schedule_next_execution(runnable_queue, contended_queue, address_book);
                    }

                    // async-ly propagate the result to rpc subsystems
                    // to_next_stage is assumed to be non-blocking so, doesn't need to be one of select! handlers
                    to_next_stage.send(processed_execution_environment).unwrap();
                }
            }
        }
    }
}

struct ExecuteStage {
    //bank: Bank,
}

impl ExecuteStage {}
