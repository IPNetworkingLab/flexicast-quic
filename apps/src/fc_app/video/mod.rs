//! Video streaming over Flexicast QUIC module.
//! Currently uses native QUIC, no HTTP/3.

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub mod fc_flow;
pub mod rtp_source;
pub mod hls;
pub mod uc_path;