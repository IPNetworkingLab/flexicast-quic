//! Sending-side of the file transfer module.

use super::Result;
use std::fs;
use std::io::Read;
use std::str::FromStr;
use tokio::net::UnixDatagram;
use tokio::sync::mpsc::Sender;

const BUFF_SIZE: usize = 100_000;

#[derive(Debug)]
/// File transfer sending-side specific messages.
pub enum FileTransferSrcMsg {
    /// Data, whether it is the last piece of data (i.e., is fin after), and the stream ID.
    Data((Vec<u8>, bool, u64)),

    /// No more data will be sent.
    Close,
}

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

#[derive(Debug)]
/// Sender structure to handle the emission of file transfer.
pub struct FileTransferSrc {
    /// File transfer kind state.
    state: FileTransferKindInner,

    /// Length of the file at the time it is opened.
    /// None if this transfer is unbounded.
    len: Option<u64>,

    /// Total number of bytes sent so far.
    nb_bytes_sent: u64,

    /// Tokio channel to send the data.
    tx_chan: Sender<FileTransferSrcMsg>,

    /// Stream ID to use.
    stream_id: u64,
}

impl FileTransferSrc {
    /// New structure to handle the file transfer delivery on the sending-side.
    pub fn new(
        kind: &FileTransferKind, tx_chan: Sender<FileTransferSrcMsg>,
    ) -> Result<Self> {
        let (state, len) = match kind {
            FileTransferKind::File(filepath) => {
                let file = fs::File::open(filepath)?;
                let len = file.metadata()?.len();
                (FileTransferKindInner::File(file), Some(len))
            },

            FileTransferKind::Bytes(nb) => {
                (FileTransferKindInner::Bytes, Some(*nb))
            },

            FileTransferKind::UnixDatagram(unix_path) => {
                let _ = std::fs::remove_file(unix_path);
                let socket = UnixDatagram::bind(unix_path)?;
                (FileTransferKindInner::Socket((socket, None)), None)
            },
        };
        Ok(Self {
            state,
            len,
            nb_bytes_sent: 0,
            tx_chan,
            stream_id: 3,
        })
    }

    /// Runs the structure inside a tokio task.
    ///
    /// It will get the data from the file and send them on the channel.
    ///
    /// Because the channel should be bounded, this task will block when the
    /// channel is full with some piece of waiting data.
    pub async fn run(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; BUFF_SIZE];
        loop {
            let nb_read = match &mut self.state {
                FileTransferKindInner::File(file) => file.read(&mut buffer)?,

                FileTransferKindInner::Bytes => {
                    self.len
                        .unwrap()
                        .saturating_sub(self.nb_bytes_sent)
                        .min(buffer.len() as u64) as usize
                },

                FileTransferKindInner::Socket((sock, file_opt)) => {
                    if let Some(file) = file_opt {
                        debug!("Reading from file");
                        file.read(&mut buffer)?
                    } else {
                        // TODO: we may have a problem if we receive too many files at the same time and cannot flush all data directly.
                        // This may add latency in the delivery of data.
                        debug!("Reading from socket a filename");
                        sock.recv_from(&mut buffer[..]).await?.0
                    }
                },
            };

            debug!("Read {} bytes", nb_read);

            if nb_read == 0 {
                // If this is a file given from the socket, we don't finish, instead we close the file and wait for another file being transmitted.
                if let FileTransferKindInner::Socket((_sock, file)) =
                    &mut self.state
                {
                    _ = file.take();
                    continue;
                } else {
                    self.on_finish().await?;
                    break;
                }
            } else {
                // If this is a file given from the socket, we read the data from the socket if the file is empty and don't send it to the network.
                if let FileTransferKindInner::Socket((_sock, file)) =
                    &mut self.state
                {
                    if file.is_none() {
                        *file = Some(fs::File::open(std::str::from_utf8(
                            &buffer[..nb_read],
                        )?)?);
                        self.len = file
                            .as_ref()
                            .map(|f| f.metadata().map(|m| m.len()).ok())
                            .flatten();
                        continue;
                    }
                }
                // Otherwise, we just send the content of the file to the network.
                // TODO: send in a different stream if we change the file we are using (i.e., when nb_read == 0).

                self.nb_bytes_sent += nb_read as u64;
                let fin = self.len.is_some_and(|l| l == self.nb_bytes_sent);

                debug!(
                    "[File App] Send {nb_read} bytes. State = {:?}. fin = {:?}",
                    self.state, fin
                );

                let msg = FileTransferSrcMsg::Data((
                    buffer[..nb_read].to_vec(),
                    fin,
                    self.stream_id,
                ));
                self.tx_chan.send(msg).await?;
                buffer = vec![0u8; BUFF_SIZE];

                // Update the stream ID if this is socket file.
                if let FileTransferKindInner::Socket((_sock, file)) =
                    &mut self.state
                {
                    if fin {
                        self.stream_id += 4;
                        *file = None;
                        self.nb_bytes_sent = 0;
                    }
                }
            }
        }

        Ok(())
    }

    /// Call this function when the file is entirely read.
    /// This will close the sending side of the channel.
    ///
    /// No verification is performed to know if the file is really entirely
    /// read.
    pub async fn on_finish(&mut self) -> Result<()> {
        let msg = FileTransferSrcMsg::Close;
        self.tx_chan.send(msg).await?;
        Ok(())
    }
}
