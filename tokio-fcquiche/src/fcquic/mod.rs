//! Asynchronous communication module to handle communication between the
//! flexicast source, the unicast instances and the controller.

mod aggregator;
pub mod controller;
pub mod fc;
pub mod messages;
pub mod scheduler;
pub mod sendmmsg;
pub mod uc;