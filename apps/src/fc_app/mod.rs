use std::str::FromStr;

use crate::fc_app::file_transfer::FileTransferKind;
use crate::fc_app::video::StreamTransferKind;

use tokio_fcquiche::*;
pub mod file_transfer;
pub mod h3;
pub mod http3;
pub mod video;

/// Application being run on top of Flexicast QUIC.
#[derive(Debug, Clone)]
pub enum TransferKind {
    /// File transfer.
    File(FileTransferKind),

    /// Video stream.
    Stream(StreamTransferKind),

    /// HTTP/3.
    /// The value is the requested URL.
    HTTP3(String),
}

impl FromStr for TransferKind {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<TransferKind, String> {
        let mut tab = s.split(",");

        match tab.next().ok_or("No transfer kink")? {
            "stream" =>
                Ok(TransferKind::Stream(StreamTransferKind::from_str(s)?)),

            "file" => Ok(TransferKind::File(FileTransferKind::from_str(s)?)),

            "http3" => {
                let file_path = tab.next().ok_or("No path to file provided")?.to_string();
                let manifest_math = tab.next().ok_or("No path to manifest provided")?.to_string();
                Ok(TransferKind::HTTP3(format!("{},{}", file_path, manifest_math).to_string()))
            },

            _ => return Err("Wrong transfer type!".to_string()),
        }
    }
}
