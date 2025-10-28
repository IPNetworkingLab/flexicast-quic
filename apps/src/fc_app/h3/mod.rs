//! Handles the HTTP/3 protocol over Flexicast QUIC for file delivery.

use serde::Deserialize;
use serde::Serialize;

pub mod receiver;
pub mod sender;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Structure containing the YAML manifest file.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Manifest {
    size: u64,
    blocks: Vec<(u64, u64)>,
}
