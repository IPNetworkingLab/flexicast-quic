//! File transfer over Flexicast QUIC module.
//! Currently does not support HTTP/3.

pub mod receiver;
pub mod sender;
pub mod fc_flow;
pub mod uc_path;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
