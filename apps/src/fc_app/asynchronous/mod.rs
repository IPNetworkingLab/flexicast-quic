//! Asynchronous communication module to handle communication between the
//! flexicast source, the unicast instances and the controller.

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod aggregator;
pub mod controller;
pub mod fc;
pub mod messages;
pub mod scheduler;
pub mod sendmmsg;
pub mod uc;