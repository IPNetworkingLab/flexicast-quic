//! Sending-side of the HTTP/3 file transfer module.

use std::io::BufReader;
use std::io::Read;

use quiche::h3::NameValue;
use tokio::sync::mpsc;

use crate::fc_app::h3::Manifest;
use crate::fc_app::Result;
use tokio_fcquiche::FcQuicMsg;

const BUFF_SIZE: usize = 100_000;

#[derive(Debug)]
pub struct Http3Source {
    /// Channel to receive messages from HTTP/3.
    rx: mpsc::Receiver<FcQuicMsg>,

    /// Channel to send messages to the flexicast flow.
    tx: mpsc::Sender<FcQuicMsg>,

    /// File to serve.
    file: std::fs::File,

    /// Path to the file to serve.
    file_path: String,

    /// Path to the manifest.
    manifest_path: String,
}

impl Http3Source {
    /// Creates a new structure.
    pub fn new(
        rx: mpsc::Receiver<FcQuicMsg>, tx: mpsc::Sender<FcQuicMsg>,
        filepath: &str, manifest_path: &str,
    ) -> Result<Self> {
        Ok(Self {
            rx,
            tx,
            file_path: filepath.to_string(),
            file: std::fs::File::open(filepath)?,
            manifest_path: manifest_path.to_string(),
        })
    }

    /// Runs the structure inside a tokio task.
    pub async fn run(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; BUFF_SIZE];

        // Read the manifest to get the information about the file to serve.
        let file = std::fs::File::open(&self.manifest_path)?;
        let reader = BufReader::new(file);
        let manifest: Manifest = serde_json::from_reader(reader)?;

        let mut stream_id = manifest.blocks[0].1;
        let mut id_manifest = 0;

        // Whether we can read new data from the file.
        let mut read_new = false;
        let mut written = 0;
        let mut total_written_stream = 0;

        loop {
            // Drain all pending H3 requests (e.g. manifest GET from late
            // receivers) before entering the blocking select!. Without this,
            // self.tx.send is always immediately ready (large fc_flow buffer)
            // and starves self.rx, causing the rx channel (capacity 10) to
            // fill up and blocking the handshake task.
            while let Ok(msg) = self.rx.try_recv() {
                self.handle_msg(msg)?;
            }

            if read_new {
                let max_write = buffer.len().min(
                    (manifest.blocks[id_manifest].0 as usize)
                        .saturating_sub(total_written_stream),
                );
                if max_write == 0 {
                    // TODO: maybe we will do +8 instead of +4 if we read empty
                    // data!
                    stream_id += 4;
                    total_written_stream = 0;
                    id_manifest = (id_manifest + 1) % manifest.blocks.len();
                }
                written = self.file.read(&mut buffer)?;

                // If written == 0, it means that the file is empty, so we restart
                // reading from the start and a fresh stream id.
                if written == 0 {
                    self.file = std::fs::File::open(&self.file_path)?;

                    // We restart the loop to avoid setting read_new to false.
                    continue;
                }

                // Set that we have to send the data before reading it.
                read_new = false;
            }
            let fin = total_written_stream + written ==
                manifest.blocks[id_manifest].0 as usize;
            let msg =
                FcQuicMsg::Stream((buffer[..written].to_vec(), fin, stream_id));
            tokio::select! {
                Ok(_) = self.tx.send(msg) => {
                    read_new = true;
                    total_written_stream += written;
                },

                Some(msg) = self.rx.recv() => {
                    self.handle_msg(msg)?;
                }
            }
        }
    }

    fn handle_msg(&mut self, msg: FcQuicMsg) -> Result<()> {
        match msg {
            FcQuicMsg::Http3RequestServer((header, one_shot)) => {
                let (headers, body) = self.build_response(&header)?;

                if let Err(_e) = one_shot.send((headers, body)) {
                    return Err("Cannot send HTTP/3 response".into());
                }
            },

            _ => (),
        }

        Ok(())
    }

    /// Builds an HTTP/3 response given a request.
    fn build_response(
        &self, request: &[quiche::h3::Header],
    ) -> Result<(Vec<quiche::h3::Header>, Vec<u8>)> {
        println!("GET A NEW HERE: {:?}", request);
        let mut file_path = std::path::PathBuf::from(".");
        let mut path = std::path::Path::new("");
        let mut method = None;

        // Look for the request's path and method.
        for hdr in request {
            match hdr.name() {
                b":path" =>
                    path = std::path::Path::new(
                        std::str::from_utf8(hdr.value()).unwrap(),
                    ),

                b":method" => method = Some(hdr.value()),

                _ => (),
            }
        }

        let (status, body) = match method {
            Some(b"GET") => {
                for c in path.components() {
                    if let std::path::Component::Normal(v) = c {
                        file_path.push(v)
                    }
                }
                println!(
                    "REQUEST {:?} and I have {:?}",
                    file_path, self.file_path
                );
                // Check if the requested file matches the one we can serve.
                if file_path == std::path::Path::new(&self.file_path) {
                    // Then we return the content of the manifest.
                    let manifest_data = std::fs::read(&self.manifest_path)?;
                    (200, manifest_data)
                } else {
                    (404, b"Not found".to_vec())
                }
            },

            _ => (405, Vec::new()),
        };

        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"server", b"quiche"),
            quiche::h3::Header::new(
                b":content-length",
                body.len().to_string().as_bytes(),
            ),
        ];

        Ok((headers, body))
    }
}
