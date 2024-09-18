//! Asynchronous communication module to handle communication between the flexicast source, the unicast instances and the controller.

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const MAX_DATAGRAM_SIZE: usize = 1350;

pub mod controller;
pub mod fc;
pub mod uc;