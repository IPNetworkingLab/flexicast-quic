//! Video streaming over Flexicast QUIC module.
//! Currently uses native QUIC, no HTTP/3.

use std::net::SocketAddr;
use std::str::FromStr;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub mod fc_flow;
pub mod hls;
pub mod rtp;
pub mod uc_path;

/// Video stream application being run on top of Flexicast QUIC.
#[derive(Debug, Clone)]
pub enum StreamTransferKind {
    /// HLS.
    /// It uses a directory to fetch the manifest and segments.
    Hls(String),

    /// RTP.
    /// It uses a socket address to receiver/send RTP content.
    Rtp(SocketAddr),
}

impl FromStr for StreamTransferKind {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut tab = s.split(":");

        match tab.next().ok_or("No video transfer kind")? {
            "hls" => {
                let directory_name =
                    tab.next().ok_or("No directory path for HLS")?;

                Ok(StreamTransferKind::Hls(directory_name.to_string()))
            },

            "rtp" => {
                let sockaddr_str = tab.next().ok_or("No RTP socket address")?;
                Ok(StreamTransferKind::Rtp(sockaddr_str.parse().map_err(
                    |_| "Impossible to parse the RTP socket address",
                )?))
            },

            _ => return Err("Wrong video transfer kind".to_string()),
        }
    }
}
