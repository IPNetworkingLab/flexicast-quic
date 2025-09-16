//! File transfer over Flexicast QUIC module.
//! Currently does not support HTTP/3.

pub mod receiver;
pub mod sender;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use std::{fs, str::FromStr};

use tokio::net::UnixDatagram;

#[derive(Debug, Clone)]
/// File transfer kind.
pub enum FileTransferKind {
    /// File transfer using a real file.
    File(String),

    /// Raw bytes generates by the source.
    Bytes(u64),

    /// The filename is given by the UnixDatagram socket whose path is the inner value.
    UnixDatagram(String),
}

impl FromStr for FileTransferKind {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let mut tab = value.split(",");
        let _ = tab.next();

        match tab.next().ok_or("No transfer kind")? {
            "bytes" => {
                let nb_str = tab.next().ok_or("No number of bytes given")?;
                let nb: u64 = nb_str
                    .parse()
                    .map_err(|_| "Impossible to parse the number of bytes")?;
                Ok(FileTransferKind::Bytes(nb))
            },

            "file" => {
                let filename = tab.next().ok_or("No filename provided")?;
                Ok(FileTransferKind::File(filename.to_string()))
            },

            "socket" => {
                let unix_path = tab.next().ok_or("No socket path provided")?;
                Ok(FileTransferKind::UnixDatagram(unix_path.to_string()))
            },

            _ => {
                return Err(format!(
                    "Wrong transfer kind. Available: bytes, file"
                )
                .to_string())
            },
        }
    }
}

#[derive(Debug)]
/// Inner representation of the file transfer kind.
enum FileTransferKindInner {
    /// Pointer to the file structure to transfer.
    File(fs::File),

    Bytes,

    /// Unix socket to receive the file content.
    Socket((UnixDatagram, Option<fs::File>)),
}