use std::str::FromStr;

use crate::fc_app::file_transfer::sender::FileTransferKind;
use crate::fc_app::video::StreamTransferKind;

pub mod asynchronous;
pub mod cca;
pub mod file_transfer;
pub mod http3;
pub mod rtp;
pub mod video;

/// Application being run on top of Flexicast QUIC.
#[derive(Debug, Clone)]
pub enum TransferKind {
    /// File transfer.
    File(FileTransferKind),

    /// Video stream.
    Stream(StreamTransferKind),
}

impl FromStr for TransferKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut tab = s.split(":");

        match tab.next().ok_or("No transfer kink")? {
            "stream" =>
                Ok(TransferKind::Stream(StreamTransferKind::from_str(s)?)),

            "file" => Ok(TransferKind::File(FileTransferKind::from_str(s)?)),

            _ => return Err("Wrong transfer type!".to_string()),
        }
    }
}
