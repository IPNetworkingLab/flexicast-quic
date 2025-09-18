//! Receiving-side of the file transfer module.

use super::Result;
use std::fs;
use std::io::Write;
use std::path::Path;
use tokio::sync::mpsc::Receiver;
use tokio_fcquiche::FcQuicMsg;

#[derive(Debug)]
/// File transfer receiving-side specific messages.
pub enum FileTransferRecvMsg {
    /// Data.
    /// First value is the data.
    /// The second indicates whether this is the end of this stream.
    /// The third is the stream ID.
    Data((Vec<u8>, bool, u64)),

    /// No more data will be received.
    Close,
}

#[derive(Debug)]
/// Receiver structure to handle reception of file transfer.
pub struct FileTransferRecv {
    /// File to write data in.
    file: Option<fs::File>,

    /// Total number of bytes received so far.
    nb_bytes_recv: usize,

    /// Tokio channel to receive the data.
    rx_chan: Receiver<FcQuicMsg>,

    /// True filename.
    true_filename: String,

    /// Temporary filename.
    tmp_filename: String,
}

impl FileTransferRecv {
    /// New structure to handle the file transfer delivery on the
    /// receiving-side.
    pub fn new(
        filepath: &Path, rx_chan: Receiver<FcQuicMsg>,
        tmp_filename: &Path,
    ) -> Result<Self> {
        let true_filename = filepath
            .to_str()
            .ok_or::<String>("Cannot parse filename".into())?;

        let file = fs::File::create(&tmp_filename)?;

        Ok(Self {
            file: Some(file),
            nb_bytes_recv: 0,
            rx_chan,
            true_filename: true_filename.to_string(),
            tmp_filename: tmp_filename.to_str().unwrap().to_string(),
        })
    }

    /// Runs the structure inside a tokio task.
    ///
    /// It will get data from the channel and write them on disk.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            match self.rx_chan.recv().await {
                Some(FcQuicMsg::Stream((v, fin, stream_id))) =>
                    self.handle_new_data(v, fin, stream_id).await?,
                Some(FcQuicMsg::Close) => {
                    self.rx_chan.close();
                    break;
                },
                None => break,
            }
        }

        Ok(())
    }

    pub async fn handle_new_data(
        &mut self, v: Vec<u8>, fin: bool, _stream_id: u64,
    ) -> Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.write_all(&v)?;
            self.nb_bytes_recv += v.len();

            // If this is the end of the stream, we can move the file to the
            // actual true name.
            if fin {
                debug!("File download is done. Change the filename from {:?} to {:?}", self.tmp_filename, self.true_filename);
                std::fs::rename(&self.tmp_filename, &self.true_filename)?;
                self.file = Some(std::fs::File::create(&self.tmp_filename)?)
            }
        }

        Ok(())
    }
}
