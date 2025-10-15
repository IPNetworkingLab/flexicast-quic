//! A constant-rate FEC scheduler.
//! Generates a repair symbol, if possible, every `n` source symbols.

use std::time;

#[derive(Debug, Clone, Copy)]
pub struct FecConstantScheduler {
    /// The number of source symbols between two repair symbols.
    step: u64,

    /// The number of sent source symbols since the last sent repair symbol.
    nb_source: u64,
}

impl FecConstantScheduler {
    /// Creates a new instance with a given step.
    pub fn new(step: u64) -> Self {
        Self {
            step,
            nb_source: 0,
        }
    }

    pub(super) fn should_send_repair(&self) -> bool {
        self.step <= self.nb_source
    }

    pub(super) fn sent_repair_symbol(&mut self) {
        self.nb_source = 0;
    }

    pub(super) fn acked_repair_symbol(&mut self) {}

    pub(super) fn sent_source_symbol(&mut self) {
        self.nb_source += 1;
    }

    pub(super) fn lost_repair_symbol(&mut self) {}

    pub(super) fn timeout(&self) -> Option<time::Instant> {
        None
    }
}