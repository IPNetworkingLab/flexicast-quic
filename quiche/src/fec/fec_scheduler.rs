use core::str::FromStr;

use crate::fec::background_fec_scheduler::BackgroundFECScheduler;
use crate::fec::burst_protecting_fec_scheduler::BurstsFECScheduler;
use crate::fec::burst_protecting_fec_scheduler_with_fec_only::BurstsFECSchedulerWithFECOnly;
use crate::fec::fec_scheduler::FECScheduler::BackgroundOnly;
use crate::fec::fec_scheduler::FECScheduler::Bursty;
use crate::fec::fec_scheduler::FECScheduler::BurstyOnFECOnly;
use crate::fec::fec_scheduler::FECScheduler::NoRedundancy;
use crate::fec::fec_scheduler::FECScheduler::RetransmissionFec;
use crate::fec::retransmission_fec_scheduler::RetransmissionFecScheduler;
use crate::path::Path;
use crate::Connection;
use crate::ranges::RangeSet;

/// Available FEC redundancy schedulers.
///
/// This enum provides currently available list of FEC redundancy schedulers.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum FECSchedulerAlgorithm {
    /// Never sends redundancy (default). `noredundancy` in a string form.
    NoRedundancy      = 0,
    /// Only sends redundancy when there is no user data to send. `background`
    /// in a string form.
    BackgroundOnly    = 1,
    /// Sends redundancy only when there is no user data to send and
    /// when a burst of packets has been sent. `bursts` in a string form.
    BurstsOnly        = 2,
    /// Same as above but sends REPAIR symbols only on a fec_only path.
    BurstsOnlyOnFECOnlyPath = 3,
    /// Only sends FEC when a lost packet has been detected by a client.
    RetransmissionFec = 4,
}

impl FromStr for FECSchedulerAlgorithm {
    type Err = crate::Error;

    /// Converts a string to `FECSchedulerAlgorighm`.
    ///
    /// If `name` is not valid, `Error::FECSchedulerAlgorighm` is returned.
    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name {
            "noredundancy" => Ok(FECSchedulerAlgorithm::NoRedundancy),
            "background" => Ok(FECSchedulerAlgorithm::BackgroundOnly),
            "bursts" => Ok(FECSchedulerAlgorithm::BurstsOnly),
            "bursts_feconly" =>
                Ok(FECSchedulerAlgorithm::BurstsOnlyOnFECOnlyPath),
            "retransmission" => Ok(FECSchedulerAlgorithm::RetransmissionFec),
            _ => Err(crate::Error::FECScheduler),
        }
    }
}

pub(crate) enum FECScheduler {
    NoRedundancy,
    BackgroundOnly(BackgroundFECScheduler),
    Bursty(BurstsFECScheduler),
    BurstyOnFECOnly(BurstsFECSchedulerWithFECOnly),
    RetransmissionFec(RetransmissionFecScheduler),
}

pub(crate) fn new_fec_scheduler(alg: FECSchedulerAlgorithm, max_rs: Option<u32>) -> FECScheduler {
    match alg {
        FECSchedulerAlgorithm::NoRedundancy => FECScheduler::NoRedundancy,
        FECSchedulerAlgorithm::BackgroundOnly => new_background_scheduler(),
        FECSchedulerAlgorithm::BurstsOnly => new_bursts_only_scheduler(),
        FECSchedulerAlgorithm::BurstsOnlyOnFECOnlyPath =>
            new_bursts_only_on_fec_only_path_scheduler(),
        FECSchedulerAlgorithm::RetransmissionFec => new_retransmission_fec(max_rs),
    }
}

fn new_background_scheduler() -> FECScheduler {
    BackgroundOnly(BackgroundFECScheduler::new())
}

fn new_bursts_only_scheduler() -> FECScheduler {
    Bursty(BurstsFECScheduler::new())
}

fn new_bursts_only_on_fec_only_path_scheduler() -> FECScheduler {
    BurstyOnFECOnly(BurstsFECSchedulerWithFECOnly::new())
}

fn new_retransmission_fec(max_rs: Option<u32>) -> FECScheduler {
    RetransmissionFec(RetransmissionFecScheduler::new(max_rs))
}

impl FECScheduler {
    pub fn should_send_repair(
        &mut self, conn: &Connection, path: &Path, symbol_size: usize,
    ) -> bool {
        match self {
            BackgroundOnly(scheduler) =>
                scheduler.should_send_repair(conn, path, symbol_size),
            Bursty(scheduler) =>
                scheduler.should_send_repair(conn, path, symbol_size),
            BurstyOnFECOnly(scheduler) =>
                scheduler.should_send_repair(conn, path, symbol_size),
            NoRedundancy => false,
            RetransmissionFec(scheduler) =>
                scheduler.should_send_repair(),
        }
    }

    pub fn sent_repair_symbol(&mut self) {
        match self {
            BackgroundOnly(scheduler) => scheduler.sent_repair_symbol(),
            Bursty(scheduler) => scheduler.sent_repair_symbol(),
            BurstyOnFECOnly(scheduler) => scheduler.sent_repair_symbol(),
            RetransmissionFec(scheduler) => scheduler.sent_repair_symbol(),
            NoRedundancy => (),
        }
    }

    pub fn acked_repair_symbol(&mut self) {
        match self {
            BackgroundOnly(scheduler) => scheduler.acked_repair_symbol(),
            Bursty(scheduler) => scheduler.acked_repair_symbol(),
            BurstyOnFECOnly(scheduler) => scheduler.acked_repair_symbol(),
            RetransmissionFec(scheduler) => scheduler.acked_repair_symbol(),
            NoRedundancy => (),
        }
    }

    pub fn sent_source_symbol(&mut self) {
        match self {
            BackgroundOnly(scheduler) => scheduler.sent_source_symbol(),
            Bursty(scheduler) => scheduler.sent_source_symbol(),
            BurstyOnFECOnly(scheduler) => scheduler.sent_source_symbol(),
            RetransmissionFec(scheduler) => scheduler.sent_source_symbol(),
            NoRedundancy => (),
        }
    }

    pub fn lost_repair_symbol(&mut self) {
        match self {
            BackgroundOnly(scheduler) => scheduler.lost_repair_symbol(),
            Bursty(scheduler) => scheduler.lost_repair_symbol(),
            BurstyOnFECOnly(scheduler) => scheduler.lost_repair_symbol(),
            RetransmissionFec(scheduler) => scheduler.lost_repair_symbol(),
            NoRedundancy => (),
        }
    }

    pub fn lost_source_symbol(&mut self, ranges: &RangeSet, client_cid: &[u8]) {
        if let RetransmissionFec(scheduler) = self {
            scheduler.lost_source_symbol(ranges.to_owned(), client_cid);
        }
    }

    pub fn reset_fec_state(&mut self) {
        if let RetransmissionFec(scheduler) = self {
            scheduler.reset_fec_state();
        }
    }
}
