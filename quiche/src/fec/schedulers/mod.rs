//! FEC Schedulers.

use core::str::FromStr;

use self::FecScheduler::*;
use constant::FecConstantScheduler;
use networkcoding::Encoder;

/// Available FEC redundancy schedulers.
///
/// This enum provides currently available list of FEC redundancy schedulers.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum FecSchedulerAlgorithm {
    /// Never sends redundancy (default). `noredundancy` in a string form.
    NoRedundancy = 0,

    /// Constant FEC Scheduler.
    Constant = 1,
}

impl FromStr for FecSchedulerAlgorithm {
    type Err = crate::Error;

    /// Converts a string to `FecSchedulerAlgorighm`.
    ///
    /// If `name` is not valid, `Error::FecSchedulerAlgorighm` is returned.
    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name {
            "noredundancy" => Ok(FecSchedulerAlgorithm::NoRedundancy),

            "constant" => Ok(FecSchedulerAlgorithm::Constant),

            _ => Err(super::FecError::FecScheduler.into()),
        }
    }
}

/// TODO.
#[derive(Clone, Debug, Copy)]
pub enum FecScheduler {
    /// Do not send FEC Repair packets.
    NoRedundancy,

    /// Send repair symbols at a constant rate.
    Constant(FecConstantScheduler),
}

impl From<FecSchedulerAlgorithm> for FecScheduler {
    fn from(value: FecSchedulerAlgorithm) -> Self {
        match value {
            FecSchedulerAlgorithm::NoRedundancy => FecScheduler::NoRedundancy,
            FecSchedulerAlgorithm::Constant => FecScheduler::Constant(FecConstantScheduler::new(10)),
        }
    }
}

impl FecScheduler {
    /// TODO.
    pub fn should_send_repair(&self, _symbol_size: usize) -> bool {
        match self {
            NoRedundancy => false,
            Constant(c) => c.should_send_repair(),
        }
    }

    /// TODO.
    pub fn sent_repair_symbol(&mut self, _encoder: &Encoder) {
        match self {
            NoRedundancy => (),
            Constant(c) => c.sent_repair_symbol(),
        }
    }

    /// TODO.
    pub fn acked_repair_symbol(&mut self, _encoder: &Encoder) {
        match self {
            NoRedundancy => (),
            Constant(c) => c.acked_repair_symbol(),
        }
    }

    /// TODO.
    pub fn sent_source_symbol(&mut self, _encoder: &Encoder) {
        match self {
            NoRedundancy => (),
            Constant(c) => c.sent_source_symbol(),
        }
    }

    /// TODO.
    pub fn lost_repair_symbol(&mut self, _encoder: &Encoder) {
        match self {
            NoRedundancy => (),
            Constant(c) => c.lost_repair_symbol(),
        }
    }

    /// TODO.
    pub fn timeout(&self) -> Option<std::time::Instant> {
        match self {
            NoRedundancy => None,
            Constant(c) => c.timeout(),
        }
    }
}

mod constant;
