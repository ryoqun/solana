//! Transaction scheduling code.
//!
//! This crate implements 3 solana-runtime traits (`InstalledScheduler`, `UninstalledScheduler` and
//! `InstalledSchedulerPool`) to provide a concrete transaction scheduling implementation
//! (including executing txes and committing tx results).
//!
//! At the highest level, this crate takes `SanitizedTransaction`s via its `schedule_execution()`
//! and commits any side-effects (i.e. on-chain state changes) into the associated `Bank` via
//! `solana-ledger`'s helper function called `execute_batch()`.

#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::qualifiers;
use {
    assert_matches::assert_matches,
    crossbeam_channel::{self, never, select_biased, Receiver, RecvError, SendError, Sender},
    dashmap::DashMap,
    derivative::Derivative,
    log::*,
    scopeguard::defer,
    solana_ledger::blockstore_processor::{
        execute_batch, TransactionBatchWithIndexes, TransactionStatusSender,
    },
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{
        bank::Bank,
        installed_scheduler_pool::{
            initialized_result_with_timings, InstalledScheduler, InstalledSchedulerBox,
            InstalledSchedulerPool, InstalledSchedulerPoolArc, ResultWithTimings, ScheduleResult,
            SchedulerError, SchedulerId, SchedulingContext, TimeoutListener,
            UninstalledScheduler, UninstalledSchedulerBox,
        },
        prioritization_fee_cache::PrioritizationFeeCache,
        vote_sender_types::ReplayVoteSender,
    },
    solana_sdk::{
        pubkey::Pubkey,
        transaction::{Result, SanitizedTransaction, TransactionError},
    },
    solana_unified_scheduler_logic::{SchedulingStateMachine, Task, UsageQueue},
    std::{
        fmt::Debug,
        marker::PhantomData,
        mem,
        sync::{
            atomic::{AtomicU64, Ordering::Relaxed},
            Arc, Mutex, OnceLock, Weak,
        },
        thread::{self, sleep, JoinHandle},
        time::{Duration, Instant},
    },
    vec_extract_if_polyfill::MakeExtractIf,
};

mod sleepless_testing;
use crate::sleepless_testing::BuilderTracked;

// dead_code is false positive; these tuple fields are used via Debug.
#[allow(dead_code)]
#[derive(Debug)]
enum CheckPoint {
    NewTask(usize),
    TaskHandled(usize),
    SchedulerThreadAborted,
    IdleSchedulerCleaned(usize),
    TrashedSchedulerCleaned(usize),
    TimeoutListenerTriggered(usize),
}

type AtomicSchedulerId = AtomicU64;

// SchedulerPool must be accessed as a dyn trait from solana-runtime, because SchedulerPool
// contains some internal fields, whose types aren't available in solana-runtime (currently
// TransactionStatusSender; also, PohRecorder in the future)...
#[derive(Debug)]
pub struct SchedulerPool<S: SpawnableScheduler<TH>, TH: TaskHandler> {
    scheduler_inners: Mutex<Vec<(S::Inner, Instant)>>,
    trashed_scheduler_inners: Mutex<Vec<S::Inner>>,
    timeout_listeners: Mutex<Vec<(TimeoutListener, Instant)>>,
    handler_count: usize,
    handler_context: HandlerContext,
    // weak_self could be elided by changing InstalledScheduler::take_scheduler()'s receiver to
    // Arc<Self> from &Self, because SchedulerPool is used as in the form of Arc<SchedulerPool>
    // almost always. But, this would cause wasted and noisy Arc::clone()'s at every call sites.
    //
    // Alternatively, `impl InstalledScheduler for Arc<SchedulerPool>` approach could be explored
    // but it entails its own problems due to rustc's coherence and necessitated newtype with the
    // type graph of InstalledScheduler being quite elaborate.
    //
    // After these considerations, this weak_self approach is chosen at the cost of some additional
    // memory increase.
    weak_self: Weak<Self>,
    next_scheduler_id: AtomicSchedulerId,
    max_usage_queue_count: usize,
    _phantom: PhantomData<TH>,
}

use solana_sdk::transaction::VersionedTransaction;

type DummySender = Sender<Vec<VersionedTransaction>>;

#[derive(Debug)]
pub struct HandlerContext {
    log_messages_bytes_limit: Option<usize>,
    transaction_status_sender: Option<TransactionStatusSender>,
    replay_vote_sender: Option<ReplayVoteSender>,
    prioritization_fee_cache: Arc<PrioritizationFeeCache>,
    transaction_recorder: Option<solana_poh::poh_recorder::TransactionRecorder>,
    dummy_sender: Option<DummySender>,
}

pub type DefaultSchedulerPool =
    SchedulerPool<PooledScheduler<DefaultTaskHandler>, DefaultTaskHandler>;

const DEFAULT_POOL_CLEANER_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_MAX_POOLING_DURATION: Duration = Duration::from_secs(180);
const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(12);
// Rough estimate of max UsageQueueLoader size in bytes:
//   UsageFromTask * UsageQueue's capacity * DEFAULT_MAX_USAGE_QUEUE_COUNT
//   16 bytes      * 128 items             * 262_144 entries               == 512 MiB
// It's expected that there will be 2 or 3 pooled schedulers constantly when running against
// mainnnet-beta. That means the total memory consumption for the idle close-to-be-trashed pooled
// schedulers is set to 1.0 ~ 1.5 GiB. This value is chosen to maximize performance under the
// normal cluster condition to avoid memory reallocation as much as possible. That said, it's not
// likely this would allow unbounded memory growth when the cluster is unstable or under some kind
// of attacks. That's because this limit is enforced at every slot and the UsageQueueLoader itself
// is recreated without any entries at first, needing to repopulate by means of actual use to eat
// the memory.
//
// Along the lines, this isn't problematic for the development settings (= solana-test-validator),
// because UsageQueueLoader won't grow that much to begin with.
const DEFAULT_MAX_USAGE_QUEUE_COUNT: usize = 262_144;

impl<S, TH> SchedulerPool<S, TH>
where
    S: SpawnableScheduler<TH>,
    TH: TaskHandler,
{
    // Some internal impl and test code want an actual concrete type, NOT the
    // `dyn InstalledSchedulerPool`. So don't merge this into `Self::new_dyn()`.
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn new(
        handler_count: Option<usize>,
        log_messages_bytes_limit: Option<usize>,
        transaction_status_sender: Option<TransactionStatusSender>,
        replay_vote_sender: Option<ReplayVoteSender>,
        prioritization_fee_cache: Arc<PrioritizationFeeCache>,
        transaction_recorder: Option<solana_poh::poh_recorder::TransactionRecorder>,
        dummy_sender: Option<DummySender>,
    ) -> Arc<Self> {
        Self::do_new(
            handler_count,
            log_messages_bytes_limit,
            transaction_status_sender,
            replay_vote_sender,
            prioritization_fee_cache,
            transaction_recorder,
            dummy_sender,
            DEFAULT_POOL_CLEANER_INTERVAL,
            DEFAULT_MAX_POOLING_DURATION,
            DEFAULT_MAX_USAGE_QUEUE_COUNT,
            DEFAULT_TIMEOUT_DURATION,
        )
    }

    fn do_new(
        handler_count: Option<usize>,
        log_messages_bytes_limit: Option<usize>,
        transaction_status_sender: Option<TransactionStatusSender>,
        replay_vote_sender: Option<ReplayVoteSender>,
        prioritization_fee_cache: Arc<PrioritizationFeeCache>,
        transaction_recorder: Option<solana_poh::poh_recorder::TransactionRecorder>,
        dummy_sender: Option<DummySender>,
        pool_cleaner_interval: Duration,
        max_pooling_duration: Duration,
        max_usage_queue_count: usize,
        timeout_duration: Duration,
    ) -> Arc<Self> {
        let handler_count = handler_count.unwrap_or(Self::default_handler_count());
        assert!(handler_count >= 1);

        let scheduler_pool = Arc::new_cyclic(|weak_self| Self {
            scheduler_inners: Mutex::default(),
            trashed_scheduler_inners: Mutex::default(),
            timeout_listeners: Mutex::default(),
            handler_count,
            handler_context: HandlerContext {
                log_messages_bytes_limit,
                transaction_status_sender,
                replay_vote_sender,
                prioritization_fee_cache,
                transaction_recorder,
                dummy_sender,
            },
            weak_self: weak_self.clone(),
            next_scheduler_id: AtomicSchedulerId::default(),
            max_usage_queue_count,
            _phantom: PhantomData,
        });

        let cleaner_main_loop = {
            let weak_scheduler_pool = Arc::downgrade(&scheduler_pool);

            move || loop {
                sleep(pool_cleaner_interval);

                let Some(scheduler_pool) = weak_scheduler_pool.upgrade() else {
                    break;
                };

                let now = Instant::now();

                let idle_inner_count = {
                    // Pre-allocate rather large capacity to avoid reallocation inside the lock.
                    let mut idle_inners = Vec::with_capacity(128);

                    let Ok(mut scheduler_inners) = scheduler_pool.scheduler_inners.lock() else {
                        break;
                    };
                    // Use the still-unstable Vec::extract_if() even on stable rust toolchain by
                    // using a polyfill and allowing unstable_name_collisions, because it's
                    // simplest to code and fastest to run (= O(n); single linear pass and no
                    // reallocation).
                    //
                    // Note that this critical section could block the latency-sensitive replay
                    // code-path via ::take_scheduler().
                    #[allow(unstable_name_collisions)]
                    idle_inners.extend(scheduler_inners.extract_if(|(_inner, pooled_at)| {
                        now.duration_since(*pooled_at) > max_pooling_duration
                    }));
                    drop(scheduler_inners);

                    let idle_inner_count = idle_inners.len();
                    drop(idle_inners);
                    idle_inner_count
                };

                let trashed_inner_count = {
                    let Ok(mut trashed_scheduler_inners) =
                        scheduler_pool.trashed_scheduler_inners.lock()
                    else {
                        break;
                    };
                    let trashed_inners: Vec<_> = mem::take(&mut *trashed_scheduler_inners);
                    drop(trashed_scheduler_inners);

                    let trashed_inner_count = trashed_inners.len();
                    drop(trashed_inners);
                    trashed_inner_count
                };

                let triggered_timeout_listener_count = {
                    // Pre-allocate rather large capacity to avoid reallocation inside the lock.
                    let mut expired_listeners = Vec::with_capacity(128);
                    let Ok(mut timeout_listeners) = scheduler_pool.timeout_listeners.lock() else {
                        break;
                    };
                    #[allow(unstable_name_collisions)]
                    expired_listeners.extend(timeout_listeners.extract_if(
                        |(_callback, registered_at)| {
                            now.duration_since(*registered_at) > timeout_duration
                        },
                    ));
                    drop(timeout_listeners);

                    let count = expired_listeners.len();
                    for (timeout_listener, _registered_at) in expired_listeners {
                        timeout_listener.trigger(scheduler_pool.clone());
                    }
                    count
                };

                info!(
                    "Scheduler pool cleaner: dropped {} idle inners, {} trashed inners, triggered {} timeout listeners",
                    idle_inner_count, trashed_inner_count, triggered_timeout_listener_count,
                );
                sleepless_testing::at(CheckPoint::IdleSchedulerCleaned(idle_inner_count));
                sleepless_testing::at(CheckPoint::TrashedSchedulerCleaned(trashed_inner_count));
                sleepless_testing::at(CheckPoint::TimeoutListenerTriggered(
                    triggered_timeout_listener_count,
                ));
            }
        };

        // No need to join; the spawned main loop will gracefully exit.
        thread::Builder::new()
            .name("solScCleaner".to_owned())
            .spawn_tracked(cleaner_main_loop)
            .unwrap();

        scheduler_pool
    }

    // This apparently-meaningless wrapper is handy, because some callers explicitly want
    // `dyn InstalledSchedulerPool` to be returned for type inference convenience.
    pub fn new_dyn(
        handler_count: Option<usize>,
        log_messages_bytes_limit: Option<usize>,
        transaction_status_sender: Option<TransactionStatusSender>,
        replay_vote_sender: Option<ReplayVoteSender>,
        prioritization_fee_cache: Arc<PrioritizationFeeCache>,
        transaction_recorder: Option<solana_poh::poh_recorder::TransactionRecorder>,
        dummy_sender: Option<DummySender>,
    ) -> InstalledSchedulerPoolArc {
        Self::new(
            handler_count,
            log_messages_bytes_limit,
            transaction_status_sender,
            replay_vote_sender,
            prioritization_fee_cache,
            transaction_recorder,
            dummy_sender,
        )
    }

    // See a comment at the weak_self field for justification of this method's existence.
    fn self_arc(&self) -> Arc<Self> {
        self.weak_self
            .upgrade()
            .expect("self-referencing Arc-ed pool")
    }

    fn new_scheduler_id(&self) -> SchedulerId {
        self.next_scheduler_id.fetch_add(1, Relaxed)
    }

    // This fn needs to return immediately due to being part of the blocking
    // `::wait_for_termination()` call.
    fn return_scheduler(&self, scheduler: S::Inner, should_trash: bool) {
        if should_trash {
            // Delay drop()-ing this trashed returned scheduler inner by stashing it in
            // self.trashed_scheduler_inners, which is periodically drained by the `solScCleaner`
            // thread. Dropping it could take long time (in fact,
            // PooledSchedulerInner::usage_queue_loader can contain many entries to drop).
            self.trashed_scheduler_inners
                .lock()
                .expect("not poisoned")
                .push(scheduler);
        } else {
            self.scheduler_inners
                .lock()
                .expect("not poisoned")
                .push((scheduler, Instant::now()));
        }
    }


    fn do_take_resumed_scheduler(
        &self,
        context: SchedulingContext,
        result_with_timings: ResultWithTimings,
    ) -> S {
        assert_matches!(result_with_timings, (Ok(_), _));

        // pop is intentional for filo, expecting relatively warmed-up scheduler due to having been
        // returned recently
        if let Some((inner, _pooled_at)) = self.scheduler_inners.lock().expect("not poisoned").pop()
        {
            S::from_inner(inner, context, result_with_timings)
        } else {
            S::spawn(self.self_arc(), context, result_with_timings)
        }
    }

    #[cfg(feature = "dev-context-only-utils")]
    pub fn pooled_scheduler_count(&self) -> usize {
        self.scheduler_inners.lock().expect("not poisoned").len()
    }

    pub fn default_handler_count() -> usize {
        Self::calculate_default_handler_count(
            thread::available_parallelism()
                .ok()
                .map(|non_zero| non_zero.get()),
        )
    }

    pub fn calculate_default_handler_count(detected_cpu_core_count: Option<usize>) -> usize {
        // Divide by 4 just not to consume all available CPUs just with handler threads, sparing for
        // other active forks and other subsystems.
        // Also, if available_parallelism fails (which should be very rare), use 4 threads,
        // as a relatively conservatism assumption of modern multi-core systems ranging from
        // engineers' laptops to production servers.
        detected_cpu_core_count
            .map(|core_count| (core_count / 4).max(1))
            .unwrap_or(4)
    }

    pub fn cli_message() -> &'static str {
        static MESSAGE: OnceLock<String> = OnceLock::new();

        MESSAGE.get_or_init(|| {
            format!(
                "Change the number of the unified scheduler's transaction execution threads \
                 dedicated to each block, otherwise calculated as cpu_cores/4 [default: {}]",
                Self::default_handler_count()
            )
        })
    }
}

impl<S, TH> InstalledSchedulerPool for SchedulerPool<S, TH>
where
    S: SpawnableScheduler<TH>,
    TH: TaskHandler,
{
    fn take_resumed_scheduler(
        &self,
        context: SchedulingContext,
        result_with_timings: ResultWithTimings,
    ) -> InstalledSchedulerBox {
        Box::new(self.do_take_resumed_scheduler(context, result_with_timings))
    }

    fn register_timeout_listener(&self, timeout_listener: TimeoutListener) {
        self.timeout_listeners
            .lock()
            .unwrap()
            .push((timeout_listener, Instant::now()));
    }
}

pub trait TaskHandler: Send + Sync + Debug + Sized + 'static {
    fn handle(
        result: &mut Result<()>,
        timings: &mut ExecuteTimings,
        bank: &Arc<Bank>,
        transaction: &SanitizedTransaction,
        index: usize,
        handler_context: &HandlerContext,
    );
}

#[derive(Debug)]
pub struct DefaultTaskHandler;

impl TaskHandler for DefaultTaskHandler {
    fn handle(
        result: &mut Result<()>,
        timings: &mut ExecuteTimings,
        bank: &Arc<Bank>,
        transaction: &SanitizedTransaction,
        index: usize,
        handler_context: &HandlerContext,
    ) {
        /*
        // scheduler must properly prevent conflicting tx executions. thus, task handler isn't
        // responsible for locking.
        let batch = bank.prepare_unlocked_batch_from_single_tx(transaction);
        let batch_with_indexes = TransactionBatchWithIndexes {
            batch,
            transaction_indexes: vec![index],
        };

        *result = execute_batch(
            &batch_with_indexes,
            bank,
            handler_context.transaction_status_sender.as_ref(),
            handler_context.replay_vote_sender.as_ref(),
            timings,
            handler_context.log_messages_bytes_limit,
            &handler_context.prioritization_fee_cache,
            || {
                //trace!("poh record start!");
                //let summary = handler_context.transaction_recorder.as_ref().unwrap().record_transactions(bank.slot(), vec![transaction.to_versioned_transaction()]);
                //trace!("poh record end!");
                //summary.result.is_ok()
                handler_context.dummy_sender.as_ref().unwrap().send(vec![transaction.to_versioned_transaction()]).unwrap();
                true
            },
        );
        */
        handler_context.dummy_sender.as_ref().unwrap().send(vec![transaction.to_versioned_transaction()]).unwrap();
        sleepless_testing::at(CheckPoint::TaskHandled(index));
    }
}

struct ExecutedTask {
    task: Task,
    result_with_timings: ResultWithTimings,
}

impl ExecutedTask {
    fn new_boxed(task: Task) -> Box<Self> {
        Box::new(Self {
            task,
            result_with_timings: initialized_result_with_timings(),
        })
    }
}

// A very tiny generic message type to signal about opening and closing of subchannels, which are
// logically segmented series of Payloads (P1) over a single continuous time-span, potentially
// carrying some subchannel metadata (P2) upon opening a new subchannel.
// Note that the above properties can be upheld only when this is used inside MPSC or SPSC channels
// (i.e. the consumer side needs to be single threaded). For the multiple consumer cases,
// ChainedChannel can be used instead.
enum SubchanneledPayload<P1, P2> {
    Payload(P1),
    OpenSubchannel(P2),
    CloseSubchannel,
}

type NewTaskPayload = SubchanneledPayload<Task, (SchedulingContext, ResultWithTimings)>;

// A tiny generic message type to synchronize multiple threads everytime some contextual data needs
// to be switched (ie. SchedulingContext), just using a single communication channel.
//
// Usually, there's no way to prevent one of those threads from mixing current and next contexts
// while processing messages with a multiple-consumer channel. A condvar or other
// out-of-bound mechanism is needed to notify about switching of contextual data. That's because
// there's no way to block those threads reliably on such a switching event just with a channel.
//
// However, if the number of consumer can be determined, this can be accomplished just over a
// single channel, which even carries an in-bound control meta-message with the contexts. The trick
// is that identical meta-messages as many as the number of threads are sent over the channel,
// along with new channel receivers to be used (hence the name of _chained_). Then, the receiving
// thread drops the old channel and is now blocked on receiving from the new channel. In this way,
// this switching can happen exactly once for each thread.
//
// Overall, this greatly simplifies the code, reduces CAS/syscall overhead per messaging to the
// minimum at the cost of a single channel recreation per switching. Needless to say, such an
// allocation can be amortized to be negligible.
//
// Lastly, there's an auxiliary channel to realize a 2-level priority queue. See comment before
// runnable_task_sender.
mod chained_channel {
    use super::*;

    // hide variants by putting this inside newtype
    enum ChainedChannelPrivate<P, C> {
        Payload(P),
        ContextAndChannels(C, Receiver<ChainedChannel<P, C>>, Receiver<P>),
    }

    pub(super) struct ChainedChannel<P, C>(ChainedChannelPrivate<P, C>);

    impl<P, C> ChainedChannel<P, C> {
        fn chain_to_new_channel(
            context: C,
            receiver: Receiver<Self>,
            aux_receiver: Receiver<P>,
        ) -> Self {
            Self(ChainedChannelPrivate::ContextAndChannels(
                context,
                receiver,
                aux_receiver,
            ))
        }
    }

    pub(super) struct ChainedChannelSender<P, C> {
        sender: Sender<ChainedChannel<P, C>>,
        aux_sender: Sender<P>,
    }

    impl<P, C: Clone> ChainedChannelSender<P, C> {
        fn new(sender: Sender<ChainedChannel<P, C>>, aux_sender: Sender<P>) -> Self {
            Self { sender, aux_sender }
        }

        pub(super) fn send_payload(
            &self,
            payload: P,
        ) -> std::result::Result<(), SendError<ChainedChannel<P, C>>> {
            self.sender
                .send(ChainedChannel(ChainedChannelPrivate::Payload(payload)))
        }

        pub(super) fn send_aux_payload(&self, payload: P) -> std::result::Result<(), SendError<P>> {
            self.aux_sender.send(payload)
        }

        pub(super) fn send_chained_channel(
            &mut self,
            context: C,
            count: usize,
        ) -> std::result::Result<(), SendError<ChainedChannel<P, C>>> {
            let (chained_sender, chained_receiver) = crossbeam_channel::unbounded();
            let (chained_aux_sender, chained_aux_receiver) = crossbeam_channel::unbounded();
            for _ in 0..count {
                self.sender.send(ChainedChannel::chain_to_new_channel(
                    context.clone(),
                    chained_receiver.clone(),
                    chained_aux_receiver.clone(),
                ))?
            }
            self.sender = chained_sender;
            self.aux_sender = chained_aux_sender;
            Ok(())
        }

        pub(super) fn len(&self) -> usize {
            self.sender.len()
        }

        pub(super) fn aux_len(&self) -> usize {
            self.aux_sender.len()
        }
    }

    // P doesn't need to be `: Clone`, yet rustc derive can't handle it.
    // see https://github.com/rust-lang/rust/issues/26925
    #[derive(Derivative)]
    #[derivative(Clone(bound = "C: Clone"))]
    pub(super) struct ChainedChannelReceiver<P, C: Clone> {
        receiver: Receiver<ChainedChannel<P, C>>,
        aux_receiver: Receiver<P>,
        context: C,
    }

    impl<P, C: Clone> ChainedChannelReceiver<P, C> {
        fn new(
            receiver: Receiver<ChainedChannel<P, C>>,
            aux_receiver: Receiver<P>,
            initial_context: C,
        ) -> Self {
            Self {
                receiver,
                aux_receiver,
                context: initial_context,
            }
        }

        pub(super) fn context(&self) -> &C {
            &self.context
        }

        pub(super) fn for_select(&self) -> &Receiver<ChainedChannel<P, C>> {
            &self.receiver
        }

        pub(super) fn aux_for_select(&self) -> &Receiver<P> {
            &self.aux_receiver
        }

        pub(super) fn never_receive_from_aux(&mut self) {
            self.aux_receiver = never();
        }

        pub(super) fn after_select(&mut self, message: ChainedChannel<P, C>) -> Option<P> {
            match message.0 {
                ChainedChannelPrivate::Payload(payload) => Some(payload),
                ChainedChannelPrivate::ContextAndChannels(context, channel, idle_channel) => {
                    self.context = context;
                    self.receiver = channel;
                    self.aux_receiver = idle_channel;
                    None
                }
            }
        }
    }

    pub(super) fn unbounded<P, C: Clone>(
        initial_context: C,
    ) -> (ChainedChannelSender<P, C>, ChainedChannelReceiver<P, C>) {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let (aux_sender, aux_receiver) = crossbeam_channel::unbounded();
        (
            ChainedChannelSender::new(sender, aux_sender),
            ChainedChannelReceiver::new(receiver, aux_receiver, initial_context),
        )
    }
}

/// The primary owner of all [`UsageQueue`]s used for particular [`PooledScheduler`].
///
/// Currently, the simplest implementation. This grows memory usage in unbounded way. Cleaning will
/// be added later. This struct is here to be put outside `solana-unified-scheduler-logic` for the
/// crate's original intent (separation of logics from this crate). Some practical and mundane
/// pruning will be implemented in this type.
#[derive(Default, Debug)]
pub struct UsageQueueLoader {
    usage_queues: DashMap<Pubkey, UsageQueue>,
}

impl UsageQueueLoader {
    pub fn load(&self, address: Pubkey) -> UsageQueue {
        self.usage_queues.entry(address).or_default().clone()
    }

    fn count(&self) -> usize {
        self.usage_queues.len()
    }
}

// (this is slow needing atomic mem reads. However, this can be turned into a lot faster
// optimizer-friendly version as shown in this crossbeam pr:
// https://github.com/crossbeam-rs/crossbeam/pull/1047)
fn disconnected<T>() -> Receiver<T> {
    // drop the sender residing at .0, returning an always-disconnected receiver.
    crossbeam_channel::unbounded().1
}

#[derive(Debug)]
pub struct PooledScheduler<TH: TaskHandler> {
    inner: PooledSchedulerInner<Self, TH>,
    context: SchedulingContext,
}

#[derive(Debug)]
pub struct PooledSchedulerInner<S: SpawnableScheduler<TH>, TH: TaskHandler> {
    thread_manager: ThreadManager<S, TH>,
    usage_queue_loader: UsageQueueLoader,
}

impl<S, TH> Drop for ThreadManager<S, TH>
where
    S: SpawnableScheduler<TH>,
    TH: TaskHandler,
{
    fn drop(&mut self) {
        trace!("ThreadManager::drop() is called...");

        if self.are_threads_joined() {
            return;
        }
        // If on-stack ThreadManager is being dropped abruptly while panicking, it's likely
        // ::into_inner() isn't called, which is a critical runtime invariant for the following
        // thread shutdown. Also, the state could be corrupt in other ways too, so just skip it
        // altogether.
        if thread::panicking() {
            error!(
                "ThreadManager::drop(): scheduler_id: {} skipping due to already panicking...",
                self.scheduler_id,
            );
            return;
        }

        // assert that this is called after ::into_inner()
        assert_matches!(self.session_result_with_timings, None);

        // Ensure to initiate thread shutdown via disconnected new_task_receiver by replacing the
        // current new_task_sender with a random one...
        self.new_task_sender = crossbeam_channel::unbounded().0;

        self.ensure_join_threads(true);
        assert_matches!(self.session_result_with_timings, Some((Ok(_), _)));
    }
}

impl<S, TH> PooledSchedulerInner<S, TH>
where
    S: SpawnableScheduler<TH>,
    TH: TaskHandler,
{
    fn id(&self) -> SchedulerId {
        self.thread_manager.scheduler_id
    }

    fn is_trashed(&self) -> bool {
        self.is_aborted() || self.is_overgrown()
    }

    fn is_aborted(&self) -> bool {
        // Schedulers can be regarded as being _trashed_ (thereby will be cleaned up later), if
        // threads are joined. Remember that unified scheduler _doesn't normally join threads_ even
        // across different sessions (i.e. different banks) to avoid thread recreation overhead.
        //
        // These unusual thread joining happens after the blocked thread (= the replay stage)'s
        // detection of aborted scheduler thread, which can be interpreted as an immediate signal
        // about the existence of the transaction error.
        //
        // Note that this detection is done internally every time scheduler operations are run
        // (send_task() and end_session(); or schedule_execution() and wait_for_termination() in
        // terms of InstalledScheduler). So, it's ensured that the detection is done at least once
        // for any scheudler which is taken out of the pool.
        //
        // Thus, any transaction errors are always handled without loss of information and
        // the aborted scheduler itself will always be handled as _trashed_ before returning the
        // scheduler to the pool, considering is_trashed() is checked immediately before that.
        self.thread_manager.are_threads_joined()
    }

    fn is_overgrown(&self) -> bool {
        self.usage_queue_loader.count() > self.thread_manager.pool.max_usage_queue_count
    }
}

// This type manages the OS threads for scheduling and executing transactions. The term
// `session` is consistently used to mean a group of Tasks scoped under a single SchedulingContext.
// This is equivalent to a particular bank for block verification. However, new terms is introduced
// here to mean some continuous time over multiple continuous banks/slots for the block production,
// which is planned to be implemented in the future.
#[derive(Debug)]
struct ThreadManager<S: SpawnableScheduler<TH>, TH: TaskHandler> {
    scheduler_id: SchedulerId,
    pool: Arc<SchedulerPool<S, TH>>,
    new_task_sender: Sender<NewTaskPayload>,
    new_task_receiver: Option<Receiver<NewTaskPayload>>,
    session_result_sender: Sender<ResultWithTimings>,
    session_result_receiver: Receiver<ResultWithTimings>,
    session_result_with_timings: Option<ResultWithTimings>,
    scheduler_thread: Option<JoinHandle<()>>,
    handler_threads: Vec<JoinHandle<()>>,
}

#[derive(Default)]
struct LogInterval(usize);

impl LogInterval {
    fn increment(&mut self) -> bool {
        let should_log = self.0 % 100 == 0;
        self.0 = self.0.checked_add(1).unwrap();
        should_log
    }
}

struct HandlerPanicked;
type HandlerResult = std::result::Result<Box<ExecutedTask>, HandlerPanicked>;

impl<S: SpawnableScheduler<TH>, TH: TaskHandler> ThreadManager<S, TH> {
    fn new(pool: Arc<SchedulerPool<S, TH>>) -> Self {
        let (new_task_sender, new_task_receiver) = crossbeam_channel::unbounded();
        let (session_result_sender, session_result_receiver) = crossbeam_channel::unbounded();
        let handler_count = pool.handler_count;

        Self {
            scheduler_id: pool.new_scheduler_id(),
            pool,
            new_task_sender,
            new_task_receiver: Some(new_task_receiver),
            session_result_sender,
            session_result_receiver,
            session_result_with_timings: None,
            scheduler_thread: None,
            handler_threads: Vec::with_capacity(handler_count),
        }
    }

    fn execute_task_with_handler(
        bank: &Arc<Bank>,
        executed_task: &mut Box<ExecutedTask>,
        handler_context: &HandlerContext,
    ) {
        debug!("handling task at {:?}", thread::current());
        TH::handle(
            &mut executed_task.result_with_timings.0,
            &mut executed_task.result_with_timings.1,
            bank,
            executed_task.task.transaction(),
            executed_task.task.task_index(),
            handler_context,
        );
    }

    #[must_use]
    fn accumulate_result_with_timings(
        (result, timings): &mut ResultWithTimings,
        executed_task: HandlerResult,
    ) -> Option<Box<ExecutedTask>> {
        let Ok(executed_task) = executed_task else {
            return None;
        };
        //trace!("accumulate begin!!");
        //timings.accumulate(&executed_task.result_with_timings.1);
        //trace!("accumulate end!!");
        match executed_task.result_with_timings.0 {
            Ok(()) => Some(executed_task),
            //Err(TransactionError::CommitFailed) => {
            //    info!("maybe reached max tick height...");
            //    Some(executed_task)
            //},
            Err(error) => {
                error!("error is detected while accumulating....: {error:?}");
                *result = Err(error);
                None
            },
        }
    }

    fn take_session_result_with_timings(&mut self) -> ResultWithTimings {
        self.session_result_with_timings.take().unwrap()
    }

    fn put_session_result_with_timings(&mut self, result_with_timings: ResultWithTimings) {
        assert_matches!(
            self.session_result_with_timings
                .replace(result_with_timings),
            None
        );
    }

    // This method must take same set of session-related arguments as start_session() to avoid
    // unneeded channel operations to minimize overhead. Starting threads incurs a very high cost
    // already... Also, pre-creating threads isn't desirable as well to avoid `Option`-ed types
    // for type safety.
    fn start_threads(
        &mut self,
        context: SchedulingContext,
        mut result_with_timings: ResultWithTimings,
    ) {
        let scheduler_id = self.scheduler_id;
        let mut slot = context.bank().slot();

        // Firstly, setup bi-directional messaging between the scheduler and handlers to pass
        // around tasks, by creating 2 channels (one for to-be-handled tasks from the scheduler to
        // the handlers and the other for finished tasks from the handlers to the scheduler).
        // Furthermore, this pair of channels is duplicated to work as a primitive 2-level priority
        // queue, totalling 4 channels. Note that the two scheduler-to-handler channels are managed
        // behind chained_channel to avoid race conditions relating to contexts.
        //
        // This quasi-priority-queue arrangement is desired as an optimization to prioritize
        // blocked tasks.
        //
        // As a quick background, SchedulingStateMachine doesn't throttle runnable tasks at all.
        // Thus, it's likely for to-be-handled tasks to be stalled for extended duration due to
        // excessive buffering (commonly known as buffer bloat). Normally, this buffering isn't
        // problematic and actually intentional to fully saturate all the handler threads.
        //
        // However, there's one caveat: task dependencies. It can be hinted with tasks being
        // blocked, that there could be more similarly-blocked tasks in the future. Empirically,
        // clearing these linearized long runs of blocking tasks out of the buffer is delaying bank
        // freezing while only using 1 handler thread or two near the end of slot, deteriorating
        // the overall concurrency.
        //
        // To alleviate the situation, blocked tasks are exchanged via independent communication
        // pathway as a heuristic for expedite processing. Without prioritization of these tasks,
        // progression of clearing these runs would be severely hampered due to interleaved
        // not-blocked tasks (called _idle_ here; typically, voting transactions) in the single
        // buffer.
        //
        // Concurrent priority queue isn't used to avoid penalized throughput due to higher
        // overhead than crossbeam channel, even considering the doubled processing of the
        // crossbeam channel. Fortunately, just 2-level prioritization is enough. Also, sticking to
        // crossbeam was convenient and there was no popular and promising crate for concurrent
        // priority queue as of writing.
        //
        // It's generally harmless for the blocked task buffer to be flooded, stalling the idle
        // tasks completely. Firstly, it's unlikely without malice, considering all blocked tasks
        // must have independently been blocked for each isolated linearized runs. That's because
        // all to-be-handled tasks of the blocked and idle buffers must not be conflicting with
        // each other by definition. Furthermore, handler threads would still be saturated to
        // maximum even under such a block-verification situation, meaning no remotely-controlled
        // performance degradation.
        //
        // Overall, while this is merely a heuristic, it's effective and adaptive while not
        // vulnerable, merely reusing existing information without any additional runtime cost.
        //
        // One known caveat, though, is that this heuristic is employed under a sub-optimal
        // setting, considering scheduling is done in real-time. Namely, prioritization enforcement
        // isn't immediate, in a sense that the first task of a long run is buried in the middle of
        // a large idle task buffer. Prioritization of such a run will be realized only after the
        // first task is handled with the priority of an idle task. To overcome this, some kind of
        // re-prioritization or look-ahead scheduling mechanism would be needed. However, both
        // isn't implemented. The former is due to complex implementation and the later is due to
        // delayed (NOT real-time) processing, which is against the unified scheduler design goal.
        //
        // Alternatively, more faithful prioritization can be realized by checking blocking
        // statuses of all addresses immediately before sending to the handlers. This would prevent
        // false negatives of the heuristics approach (i.e. the last task of a run doesn't need to
        // be handled with the higher priority). Note that this is the only improvement, compared
        // to the heuristics. That's because this underlying information asymmetry between the 2
        // approaches doesn't exist for all other cases, assuming no look-ahead: idle tasks are
        // always unblocked by definition, and other blocked tasks should always be calculated as
        // blocked by the very existence of the last blocked task.
        //
        // The faithful approach incurs a considerable overhead: O(N), where N is the number of
        // locked addresses in a task, adding to the current bare-minimum complexity of O(2*N) for
        // both scheduling and descheduling. This means 1.5x increase. Furthermore, this doesn't
        // nicely work in practice with a real-time streamed scheduler. That's because these
        // linearized runs could be intermittent in the view with little or no look-back, albeit
        // actually forming a far more longer runs in longer time span. These access patterns are
        // very common, considering existence of well-known hot accounts.
        //
        // Thus, intentionally allowing these false-positives by the heuristic approach is actually
        // helping to extend the logical prioritization session for the invisible longer runs, as
        // long as the last task of the current run is being handled by the handlers, hoping yet
        // another blocking new task is arriving to finalize the tentatively extended
        // prioritization further. Consequently, this also contributes to alleviate the known
        // heuristic's caveat for the first task of linearized runs, which is described above.
        let (mut runnable_task_sender, runnable_task_receiver) =
            chained_channel::unbounded::<Task, SchedulingContext>(context);
        // Create two handler-to-scheduler channels to prioritize the finishing of blocked tasks,
        // because it is more likely that a blocked task will have more blocked tasks behind it,
        // which should be scheduled while minimizing the delay to clear buffered linearized runs
        // as fast as possible.
        let (finished_blocked_task_sender, finished_blocked_task_receiver) =
            crossbeam_channel::unbounded::<HandlerResult>();
        let (finished_idle_task_sender, finished_idle_task_receiver) =
            crossbeam_channel::unbounded::<HandlerResult>();

        assert_matches!(self.session_result_with_timings, None);

        // High-level flow of new tasks:
        // 1. the replay stage thread send a new task.
        // 2. the scheduler thread accepts the task.
        // 3. the scheduler thread dispatches the task after proper locking.
        // 4. the handler thread processes the dispatched task.
        // 5. the handler thread reply back to the scheduler thread as an executed task.
        // 6. the scheduler thread post-processes the executed task.
        let scheduler_main_loop = {
            let handler_count = self.pool.handler_count;
            let session_result_sender = self.session_result_sender.clone();
            // Taking new_task_receiver here is important to ensure there's a single receiver. In
            // this way, the replay stage will get .send() failures reliably, after this scheduler
            // thread died along with the single receiver.
            let new_task_receiver = self
                .new_task_receiver
                .take()
                .expect("no 2nd start_threads()");

            let mut session_ending = false;

            // Now, this is the main loop for the scheduler thread, which is a special beast.
            //
            // That's because it could be the most notable bottleneck of throughput in the future
            // when there are ~100 handler threads. Unified scheduler's overall throughput is
            // largely dependant on its ultra-low latency characteristic, which is the most
            // important design goal of the scheduler in order to reduce the transaction
            // confirmation latency for end users.
            //
            // Firstly, the scheduler thread must handle incoming messages from thread(s) owned by
            // the replay stage or the banking stage. It also must handle incoming messages from
            // the multi-threaded handlers. This heavily-multi-threaded whole processing load must
            // be coped just with the single-threaded scheduler, to attain ideal cpu cache
            // friendliness and main memory bandwidth saturation with its shared-nothing
            // single-threaded account locking implementation. In other words, the per-task
            // processing efficiency of the main loop codifies the upper bound of horizontal
            // scalability of the unified scheduler.
            //
            // Moreover, the scheduler is designed to handle tasks without batching at all in the
            // pursuit of saturating all of the handler threads with maximally-fine-grained
            // concurrency density for throughput as the second design goal. This design goal
            // relies on the assumption that there's no considerable penalty arising from the
            // unbatched manner of processing.
            //
            // Note that this assumption isn't true as of writing. The current code path
            // underneath execute_batch() isn't optimized for unified scheduler's load pattern (ie.
            // batches just with a single transaction) at all. This will be addressed in the
            // future.
            //
            // These two key elements of the design philosophy lead to the rather unforgiving
            // implementation burden: Degraded performance would acutely manifest from an even tiny
            // amount of individual cpu-bound processing delay in the scheduler thread, like when
            // dispatching the next conflicting task after receiving the previous finished one from
            // the handler.
            //
            // Thus, it's fatal for unified scheduler's advertised superiority to squeeze every cpu
            // cycles out of the scheduler thread. Thus, any kinds of unessential overhead sources
            // like syscalls, VDSO, and even memory (de)allocation should be avoided at all costs
            // by design or by means of offloading at the last resort.
            move || {
                let (do_now, dont_now) = (&disconnected::<()>(), &never::<()>());
                let dummy_receiver = |trigger| {
                    if trigger {
                        do_now
                    } else {
                        dont_now
                    }
                };

                let mut state_machine = unsafe {
                    SchedulingStateMachine::exclusively_initialize_current_thread_for_scheduling()
                };
                let mut log_interval = LogInterval::default();
                let session_started_at = Instant::now();

                // The following loop maintains and updates ResultWithTimings as its
                // externally-provided mutable state for each session in this way:
                //
                // 1. Initial result_with_timing is propagated implicitly by the moved variable.
                // 2. Subsequent result_with_timings are propagated explicitly from
                //    the new_task_receiver.recv() invocation located at the end of loop.

                'nonaborted_main_loop: loop {
                    let mut is_finished = false;
                    while !is_finished {
                        // ALL recv selectors are eager-evaluated ALWAYS by current crossbeam impl,
                        // which isn't great and is inconsistent with `if`s in the Rust's match
                        // arm. So, eagerly binding the result to a variable unconditionally here
                        // makes no perf. difference...
                        let dummy_unblocked_task_receiver =
                            dummy_receiver(state_machine.has_unblocked_task());

                        // There's something special called dummy_unblocked_task_receiver here.
                        // This odd pattern was needed to react to newly unblocked tasks from
                        // _not-crossbeam-channel_ event sources, precisely at the specified
                        // precedence among other selectors, while delegating the control flow to
                        // select_biased!.
                        //
                        // In this way, hot looping is avoided and overall control flow is much
                        // consistent. Note that unified scheduler will go
                        // into busy looping to seek lowest latency eventually. However, not now,
                        // to measure _actual_ cpu usage easily with the select approach.
                        trace!("select_biased! begin!");
                        let step = select_biased! {
                            recv(finished_blocked_task_receiver) -> executed_task => {
                                let Some(executed_task) = Self::accumulate_result_with_timings(
                                    &mut result_with_timings,
                                    executed_task.expect("alive handler")
                                ) else {
                                    break 'nonaborted_main_loop;
                                };
                                state_machine.deschedule_task(&executed_task.task);
                                "deschedule_blocked_task"
                            },
                            recv(dummy_unblocked_task_receiver) -> dummy => {
                                assert_matches!(dummy, Err(RecvError));

                                let task = state_machine
                                    .schedule_next_unblocked_task()
                                    .expect("unblocked task");
                                runnable_task_sender.send_payload(task).unwrap();
                                "schedule_blocked_task"
                            },
                            recv(new_task_receiver) -> message => {
                                assert!(!session_ending);

                                match message {
                                    Ok(NewTaskPayload::Payload(task)) => {
                                        sleepless_testing::at(CheckPoint::NewTask(task.task_index()));
                                        if let Some(task) = state_machine.schedule_task(task) {
                                            runnable_task_sender.send_aux_payload(task).unwrap();
                                        }
                                        "new_task"
                                    }
                                    Ok(NewTaskPayload::CloseSubchannel) => {
                                        session_ending = true;
                                        "session_ending"
                                    }
                                    Ok(NewTaskPayload::OpenSubchannel(_context_and_result_with_timings)) =>
                                        unreachable!(),
                                    Err(RecvError) => {
                                        // Mostly likely is that this scheduler is dropped for pruned blocks of
                                        // abandoned forks...
                                        // This short-circuiting is tested with test_scheduler_drop_short_circuiting.
                                        break 'nonaborted_main_loop;
                                    }
                                }
                            },
                            recv(finished_idle_task_receiver) -> executed_task => {
                                //trace!("select_biased! fired!");
                                let Some(executed_task) = Self::accumulate_result_with_timings(
                                    &mut result_with_timings,
                                    executed_task.expect("alive handler")
                                ) else {
                                    break 'nonaborted_main_loop;
                                };
                                //trace!("select_biased! deschedule!!");
                                state_machine.deschedule_task(&executed_task.task);
                                //trace!("select_biased! drop!!");
                                //std::mem::forget(executed_task);
                                "deschedule_idle_task"
                            },
                        };
                        //trace!("logging...");
                        if log_interval.increment() {
                            info!(
                                "[sch_{:0width$x}]: slot: {}[{:12}]({}): state_machine(({}(+{})=>{})/{}|{}) channels(<{} >{}+{} <{}+{})",
                                scheduler_id, slot,
                                (if step == "step" { "interval" } else { step }),
                                (if session_ending {"S"} else {"-"}),
                                state_machine.active_task_count(), state_machine.unblocked_task_queue_count(), state_machine.handled_task_count(),
                                state_machine.total_task_count(),
                                state_machine.unblocked_task_count(),
                                new_task_receiver.len(),
                                runnable_task_sender.len(), runnable_task_sender.aux_len(),
                                finished_blocked_task_receiver.len(), finished_idle_task_receiver.len(),
                                width = SchedulerId::BITS as usize / 4,
                            );
                        } else {
                            trace!(
                                "[sch_{:0width$x}]: slot: {}[{:12}]({}): state_machine(({}(+{})=>{})/{}|{}) channels(<{} >{}+{} <{}+{})",
                                scheduler_id, slot,
                                (if step == "step" { "interval" } else { step }),
                                (if session_ending {"S"} else {"-"}),
                                state_machine.active_task_count(), state_machine.unblocked_task_queue_count(), state_machine.handled_task_count(),
                                state_machine.total_task_count(),
                                state_machine.unblocked_task_count(),
                                new_task_receiver.len(),
                                runnable_task_sender.len(), runnable_task_sender.aux_len(),
                                finished_blocked_task_receiver.len(), finished_idle_task_receiver.len(),
                                width = SchedulerId::BITS as usize / 4,
                            );
                        }

                        is_finished = session_ending && state_machine.has_no_active_task();
                    }

                    // Finalize the current session after asserting it's explicitly requested so.
                    assert!(session_ending);
                    // Send result first because this is blocking the replay code-path.
                    session_result_sender
                        .send(result_with_timings)
                        .expect("always outlived receiver");
                    state_machine.reinitialize();
                    log_interval = LogInterval::default();
                    session_ending = false;

                    // Prepare for the new session.
                    match new_task_receiver.recv() {
                        Ok(NewTaskPayload::OpenSubchannel((
                            new_context,
                            new_result_with_timings,
                        ))) => {
                            // We just received subsequent (= not initial) session and about to
                            // enter into the preceding `while(!is_finished) {...}` loop again.
                            // Before that, propagate new SchedulingContext to handler threads
                            slot = new_context.bank().slot();
                            session_started_at = Instant::now();
                            runnable_task_sender
                                .send_chained_channel(new_context, handler_count)
                                .unwrap();
                            result_with_timings = new_result_with_timings;
                        }
                        Err(_) => {
                            // This unusual condition must be triggered by ThreadManager::drop().
                            // Initialize result_with_timings with a harmless value...
                            result_with_timings = initialized_result_with_timings();
                            break 'nonaborted_main_loop;
                        }
                        Ok(_) => unreachable!(),
                    }
                }

                // There are several code-path reaching here out of the preceding unconditional
                // `loop { ... }` by the use of `break 'nonaborted_main_loop;`. This scheduler
                // thread will now initiate the termination process, indicating an abnormal abortion,
                // in order to be handled gracefully by other threads.

                // Firstly, send result_with_timings as-is, because it's expected for us to put the
                // last result_with_timings into the channel without exception. Usually,
                // result_with_timings will contain the Err variant at this point, indicating the
                // occurrence of transaction error.
                session_result_sender
                    .send(result_with_timings)
                    .expect("always outlived receiver");

                // Next, drop `new_task_receiver`. After that, the paired singleton
                // `new_task_sender` will start to error when called by external threads, resulting
                // in propagation of thread abortion to the external threads.
                drop(new_task_receiver);

                // We will now exit this thread finally... Good bye.
                sleepless_testing::at(CheckPoint::SchedulerThreadAborted);
            }
        };

        let handler_main_loop = || {
            let pool = self.pool.clone();
            let mut runnable_task_receiver = runnable_task_receiver.clone();
            let finished_blocked_task_sender = finished_blocked_task_sender.clone();
            let finished_idle_task_sender = finished_idle_task_sender.clone();

            // The following loop maintains and updates SchedulingContext as its
            // externally-provided state for each session in this way:
            //
            // 1. Initial context is propagated implicitly by the moved runnable_task_receiver,
            //    which is clone()-d just above for this particular thread.
            // 2. Subsequent contexts are propagated explicitly inside `.after_select()` as part of
            //    `select_biased!`, which are sent from `.send_chained_channel()` in the scheduler
            //    thread for all-but-initial sessions.
            move || loop {
                let (task, sender) = select_biased! {
                    recv(runnable_task_receiver.for_select()) -> message => {
                        let Ok(message) = message else {
                            break;
                        };
                        if let Some(task) = runnable_task_receiver.after_select(message) {
                            (task, &finished_blocked_task_sender)
                        } else {
                            continue;
                        }
                    },
                    recv(runnable_task_receiver.aux_for_select()) -> task => {
                        if let Ok(task) = task {
                            (task, &finished_idle_task_sender)
                        } else {
                            runnable_task_receiver.never_receive_from_aux();
                            continue;
                        }
                    },
                };
                defer! {
                    if !thread::panicking() {
                        return;
                    }

                    // The scheduler thread can't detect panics in handler threads with
                    // disconnected channel errors, unless all of them has died. So, send an
                    // explicit Err promptly.
                    let current_thread = thread::current();
                    error!("handler thread is panicking: {:?}", current_thread);
                    if sender.send(Err(HandlerPanicked)).is_ok() {
                        info!("notified a panic from {:?}", current_thread);
                    } else {
                        // It seems that the scheduler thread has been aborted already...
                        warn!("failed to notify a panic from {:?}", current_thread);
                    }
                }
                let mut task = ExecutedTask::new_boxed(task);
                Self::execute_task_with_handler(
                    runnable_task_receiver.context().bank(),
                    &mut task,
                    &pool.handler_context,
                );
                if sender.send(Ok(task)).is_err() {
                    warn!("handler_thread: scheduler thread aborted...");
                    break;
                } else {
                    trace!("returning back task from handler to scheduler...");
                }
            }
        };

        self.scheduler_thread = Some(
            thread::Builder::new()
                .name("solScheduler".to_owned())
                .spawn_tracked(scheduler_main_loop)
                .unwrap(),
        );

        self.handler_threads = (0..self.pool.handler_count)
            .map({
                |thx| {
                    thread::Builder::new()
                        .name(format!("solScHandler{:02}", thx))
                        .spawn_tracked(handler_main_loop())
                        .unwrap()
                }
            })
            .collect();
    }

    fn send_task(&self, task: Task) -> ScheduleResult {
        debug!("send_task()");
        self.new_task_sender
            .send(NewTaskPayload::Payload(task))
            .map_err(|_| SchedulerError::Aborted)
    }

    fn ensure_join_threads(&mut self, should_receive_session_result: bool) {
        trace!("ensure_join_threads() is called");

        fn join_with_panic_message(join_handle: JoinHandle<()>) -> thread::Result<()> {
            let thread = join_handle.thread().clone();
            join_handle.join().inspect_err(|e| {
                // Always needs to try both types for .downcast_ref(), according to
                // https://doc.rust-lang.org/1.78.0/std/macro.panic.html:
                //   a panic can be accessed as a &dyn Any + Send, which contains either a &str or
                //   String for regular panic!() invocations. (Whether a particular invocation
                //   contains the payload at type &str or String is unspecified and can change.)
                let panic_message = match (e.downcast_ref::<&str>(), e.downcast_ref::<String>()) {
                    (Some(&s), _) => s,
                    (_, Some(s)) => s,
                    (None, None) => "<No panic info>",
                };
                panic!("{} (From: {:?})", panic_message, thread);
            })
        }

        if let Some(scheduler_thread) = self.scheduler_thread.take() {
            for thread in self.handler_threads.drain(..) {
                debug!("joining...: {:?}", thread);
                () = join_with_panic_message(thread).unwrap();
            }
            () = join_with_panic_message(scheduler_thread).unwrap();

            if should_receive_session_result {
                let result_with_timings = self.session_result_receiver.recv().unwrap();
                debug!("ensure_join_threads(): err: {:?}", result_with_timings.0);
                self.put_session_result_with_timings(result_with_timings);
            }
        } else {
            warn!("ensure_join_threads(): skipping; already joined...");
        };
    }

    fn ensure_join_threads_after_abort(
        &mut self,
        should_receive_aborted_session_result: bool,
    ) -> TransactionError {
        self.ensure_join_threads(should_receive_aborted_session_result);
        self.session_result_with_timings
            .as_mut()
            .unwrap()
            .0
            .clone()
            .unwrap_err()
    }

    fn are_threads_joined(&self) -> bool {
        if self.scheduler_thread.is_none() {
            // Emptying handler_threads must be an atomic operation with scheduler_thread being
            // taken.
            assert!(self.handler_threads.is_empty());
            true
        } else {
            false
        }
    }

    fn end_session(&mut self) {
        if self.are_threads_joined() {
            assert!(self.session_result_with_timings.is_some());
            debug!("end_session(): skipping; already joined the aborted threads..");
            return;
        } else if self.session_result_with_timings.is_some() {
            debug!("end_session(): skipping; already result resides within thread manager..");
            return;
        }
        debug!(
            "end_session(): will end session at {:?}...",
            thread::current(),
        );

        let mut abort_detected = self
            .new_task_sender
            .send(NewTaskPayload::CloseSubchannel)
            .is_err();

        if abort_detected {
            self.ensure_join_threads_after_abort(true);
            return;
        }

        // Even if abort is detected, it's guaranteed that the scheduler thread puts the last
        // message into the session_result_sender before terminating.
        let result_with_timings = self.session_result_receiver.recv().unwrap();
        abort_detected = result_with_timings.0.is_err();
        self.put_session_result_with_timings(result_with_timings);
        if abort_detected {
            self.ensure_join_threads_after_abort(false);
        }
        debug!("end_session(): ended session at {:?}...", thread::current());
    }

    fn start_session(
        &mut self,
        context: SchedulingContext,
        result_with_timings: ResultWithTimings,
    ) {
        assert!(!self.are_threads_joined());
        assert_matches!(self.session_result_with_timings, None);
        self.new_task_sender
            .send(NewTaskPayload::OpenSubchannel((
                context,
                result_with_timings,
            )))
            .expect("no new session after aborted");
    }
}

pub trait SpawnableScheduler<TH: TaskHandler>: InstalledScheduler {
    type Inner: Debug + Send + Sync;

    fn into_inner(self) -> (ResultWithTimings, Self::Inner);

    fn from_inner(
        inner: Self::Inner,
        context: SchedulingContext,
        result_with_timings: ResultWithTimings,
    ) -> Self;

    fn spawn(
        pool: Arc<SchedulerPool<Self, TH>>,
        context: SchedulingContext,
        result_with_timings: ResultWithTimings,
    ) -> Self
    where
        Self: Sized;
}

impl<TH: TaskHandler> SpawnableScheduler<TH> for PooledScheduler<TH> {
    type Inner = PooledSchedulerInner<Self, TH>;

    fn into_inner(mut self) -> (ResultWithTimings, Self::Inner) {
        let result_with_timings = {
            let manager = &mut self.inner.thread_manager;
            manager.end_session();
            manager.take_session_result_with_timings()
        };
        (result_with_timings, self.inner)
    }

    fn from_inner(
        mut inner: Self::Inner,
        context: SchedulingContext,
        result_with_timings: ResultWithTimings,
    ) -> Self {
        inner
            .thread_manager
            .start_session(context.clone(), result_with_timings);
        Self { inner, context }
    }

    fn spawn(
        pool: Arc<SchedulerPool<Self, TH>>,
        context: SchedulingContext,
        result_with_timings: ResultWithTimings,
    ) -> Self {
        info!("spawning new scheduler pool for slot: {}", context.bank().slot());
        let mut inner = Self::Inner {
            thread_manager: ThreadManager::new(pool),
            usage_queue_loader: UsageQueueLoader::default(),
        };
        inner
            .thread_manager
            .start_threads(context.clone(), result_with_timings);
        Self { inner, context }
    }
}

impl<TH: TaskHandler> InstalledScheduler for PooledScheduler<TH> {
    fn id(&self) -> SchedulerId {
        self.inner.id()
    }

    fn context(&self) -> &SchedulingContext {
        &self.context
    }

    fn schedule_execution(
        &self,
        &(transaction, index): &(&SanitizedTransaction, usize),
    ) -> ScheduleResult {
        let task = SchedulingStateMachine::create_task(transaction.clone(), index, &mut |pubkey| {
            self.inner.usage_queue_loader.load(pubkey)
        });
        self.inner.thread_manager.send_task(task)
    }

    fn recover_error_after_abort(&mut self) -> TransactionError {
        self.inner
            .thread_manager
            .ensure_join_threads_after_abort(true)
    }

    fn wait_for_termination(
        self: Box<Self>,
        _is_dropped: bool,
    ) -> (ResultWithTimings, UninstalledSchedulerBox) {
        let (result_with_timings, uninstalled_scheduler) = self.into_inner();
        (result_with_timings, Box::new(uninstalled_scheduler))
    }

    fn pause_for_recent_blockhash(&mut self) {
        self.inner.thread_manager.end_session();
    }
}

impl<S, TH> UninstalledScheduler for PooledSchedulerInner<S, TH>
where
    S: SpawnableScheduler<TH, Inner = PooledSchedulerInner<S, TH>>,
    TH: TaskHandler,
{
    fn return_to_pool(self: Box<Self>) {
        // Refer to the comment in is_trashed() as to the exact definition of the concept of
        // _trashed_ and the interaction among different parts of unified scheduler.
        let should_trash = self.is_trashed();
        if should_trash {
            info!("trashing scheduler (id: {})...", self.id());
        }
        self.thread_manager
            .pool
            .clone()
            .return_scheduler(*self, should_trash);
    }
}

