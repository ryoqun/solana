//! PohTimingReportService module
use {
    crate::poh_timing_reporter::PohTimingReporter,
    solana_metrics::poh_timing_point::{PohTimingReceiver, SlotPohTimingInfo},
    std::{
        string::ToString,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

/// Timeout to wait on the poh timing points from the channel
const POH_TIMING_RECEIVER_TIMEOUT_MILLISECONDS: u64 = 1000;

/// The `poh_timing_report_service` receives signals of relevant timing points
/// during the processing of a slot, (i.e. from blockstore and poh), aggregate and
/// report the result as datapoints.
pub struct PohTimingReportService {
    t_poh_timing: JoinHandle<()>,
}

impl PohTimingReportService {
    pub fn new(receiver: PohTimingReceiver, exit: &Arc<AtomicBool>) -> Self {
        let exit_signal = exit.clone();
        let mut poh_timing_reporter = PohTimingReporter::default();
        let t_poh_timing = Builder::new()
            .name("solPohTimingRpt".to_string())
            .spawn(move || loop {
                if exit_signal.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(SlotPohTimingInfo {
                    slot,
                    root_slot,
                    timing_point,
                }) = receiver.recv_timeout(Duration::from_millis(
                    POH_TIMING_RECEIVER_TIMEOUT_MILLISECONDS,
                )) {
                    poh_timing_reporter.process(slot, root_slot, timing_point);
                }
            })
            .unwrap();
        Self { t_poh_timing }
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_poh_timing.join()
    }
}
