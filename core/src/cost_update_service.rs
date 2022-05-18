//! this service receives instruction ExecuteTimings from replay_stage,
//! update cost_model which is shared with banking_stage to optimize
//! packing transactions into block; it also triggers persisting cost
//! table to blockstore.

use {
    solana_ledger::blockstore::Blockstore,
    solana_measure::measure::Measure,
    solana_program_runtime::timings::ExecuteTimings,
    solana_runtime::{bank::Bank, cost_model::CostModel},
    solana_sdk::timing::timestamp,
    std::{
        sync::atomic::{AtomicBool, Ordering},
        sync::{mpsc::Receiver, Arc, RwLock},
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

#[derive(Default)]
pub struct CostUpdateServiceTiming {
    last_print: u64,
    update_cost_model_count: u64,
    update_cost_model_elapsed: u64,
}

impl CostUpdateServiceTiming {
    fn update(&mut self, update_cost_model_count: u64, update_cost_model_elapsed: u64) {
        self.update_cost_model_count += update_cost_model_count;
        self.update_cost_model_elapsed += update_cost_model_elapsed;

        let now = timestamp();
        let elapsed_ms = now - self.last_print;
        if elapsed_ms > 1000 {
            datapoint_info!(
                "cost-update-service-stats",
                ("total_elapsed_us", elapsed_ms * 1000, i64),
                (
                    "update_cost_model_count",
                    self.update_cost_model_count as i64,
                    i64
                ),
                (
                    "update_cost_model_elapsed",
                    self.update_cost_model_elapsed as i64,
                    i64
                ),
            );

            *self = CostUpdateServiceTiming::default();
            self.last_print = now;
        }
    }
}

pub enum CostUpdate {
    FrozenBank {
        bank: Arc<Bank>,
    },
    ExecuteTiming {
        execute_timings: Box<ExecuteTimings>,
    },
}

pub type CostUpdateReceiver = Receiver<CostUpdate>;

pub struct CostUpdateService {
    thread_hdl: JoinHandle<()>,
}

impl CostUpdateService {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        exit: Arc<AtomicBool>,
        blockstore: Arc<Blockstore>,
        cost_model: Arc<RwLock<CostModel>>,
        cost_update_receiver: CostUpdateReceiver,
    ) -> Self {
        let thread_hdl = Builder::new()
            .name("solana-cost-update-service".to_string())
            .spawn(move || {
                Self::service_loop(exit, blockstore, cost_model, cost_update_receiver);
            })
            .unwrap();

        Self { thread_hdl }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }

    fn service_loop(
        exit: Arc<AtomicBool>,
        _blockstore: Arc<Blockstore>,
        cost_model: Arc<RwLock<CostModel>>,
        cost_update_receiver: CostUpdateReceiver,
    ) {
        let mut cost_update_service_timing = CostUpdateServiceTiming::default();
        let mut update_count: u64;
        let wait_timer = Duration::from_millis(100);

        loop {
            if exit.load(Ordering::Relaxed) {
                break;
            }

            update_count = 0_u64;
            let mut update_cost_model_time = Measure::start("update_cost_model_time");
            for cost_update in cost_update_receiver.try_iter() {
                match cost_update {
                    CostUpdate::FrozenBank { bank } => {
                        bank.read_cost_tracker().unwrap().report_stats(bank.slot());
                    }
                    CostUpdate::ExecuteTiming {
                        mut execute_timings,
                    } => {
                        Self::update_cost_model(&cost_model, &mut execute_timings);
                        update_count += 1;
                    }
                }
            }
            update_cost_model_time.stop();

            cost_update_service_timing.update(update_count, update_cost_model_time.as_us());

            thread::sleep(wait_timer);
        }
    }

    fn update_cost_model(
        cost_model: &RwLock<CostModel>,
        execute_timings: &mut ExecuteTimings,
    ) -> bool {
        let mut dirty = false;
        {
            for (program_id, program_timings) in &mut execute_timings.details.per_program_timings {
                let current_estimated_program_cost =
                    cost_model.read().unwrap().find_instruction_cost(program_id);
                program_timings.coalesce_error_timings(current_estimated_program_cost);

                if program_timings.count < 1 {
                    continue;
                }

                let units = program_timings.accumulated_units / program_timings.count as u64;
                match cost_model
                    .write()
                    .unwrap()
                    .upsert_instruction_cost(program_id, units)
                {
                    Ok(c) => {
                        debug!(
                            "after replayed into bank, instruction {:?} has averaged cost {}",
                            program_id, c
                        );
                        dirty = true;
                    }
                    Err(err) => {
                        debug!(
                        "after replayed into bank, instruction {:?} failed to update cost, err: {}",
                        program_id, err
                    );
                    }
                }
            }
        }
        debug!(
           "after replayed into bank, updated cost model instruction cost table, current values: {:?}",
           cost_model.read().unwrap().get_instruction_cost_table()
        );
        dirty
    }
}

