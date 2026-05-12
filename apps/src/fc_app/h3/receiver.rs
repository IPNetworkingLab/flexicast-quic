//! Receiving-side of the HTTP/3 transfer module.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::collections::HashSet;

use crate::fc_app::h3::Manifest;

use super::Result;
use quiche::h3::Header;
use quiche::h3::NameValue;
use tokio::sync::mpsc;
use tokio_fcquiche::FcQuicMsg;
use url::Url;

#[derive(Debug)]
/// HTTP/3 file download response state for the receiver.
pub struct Http3Receiver {
    /// Channel to receive messages from HTTP/3.
    rx: mpsc::Receiver<FcQuicMsg>,

    /// Channel to send messages to HTTP/3.
    tx: mpsc::Sender<FcQuicMsg>,

    /// Requested URL.
    url: Url,

    /// Path to store the file.
    path: String,

    /// File to write data.
    file: Option<std::fs::File>,
}

impl Http3Receiver {
    /// Creates a new instance.
    pub fn new(
        rx: mpsc::Receiver<FcQuicMsg>, tx: mpsc::Sender<FcQuicMsg>, url: Url,
        path: &str,
    ) -> Self {
        Self {
            rx,
            tx,
            url,
            path: path.to_string(),
            file: None,
        }
    }

    /// Runs the [`Http3Receiver`] file transfer.
    pub async fn run(&mut self) -> Result<()> {
        // Start of the application.
        let start = std::time::Instant::now();

        let mut req_sent = false;

        // Response containing the manifest file.
        let mut manifest_data = Vec::new();
        let mut manifest_size = 0;
        let mut received_size = 0;
        let mut processed_manifest = false;
        let mut stream_id_space = 0;
        let mut min_stream_id = u64::MAX;

        // Offsets of currently written streams.
        let mut written_streams = HashMap::new();
        let mut total_written = 0;
        let mut total_size = 0;

        let mut finished = false;

        // Map of written blocks.
        let mut full_block = HashSet::new();

        loop {
            if !req_sent {
                let headers = send_request(&self.url);
                let msg = FcQuicMsg::Http3Request(headers);
                self.tx.send(msg).await?;
                req_sent = true;
            }

            // Wait for messages from the channel.
            if let Some(msg) = self.rx.recv().await {
                match msg {
                    FcQuicMsg::Http3RespHeader(resp) => {
                        println!("RECEIVED HEADERS: {:?}", resp);
                        manifest_size = self.handle_h3_resp_header(resp)?;
                    },

                    FcQuicMsg::Http3RespBody(resp) => {
                        println!("RECEIVED BODY: {:?}", resp);
                        manifest_data.extend_from_slice(&resp);
                        received_size += resp.len();
                    },

                    FcQuicMsg::Stream((v, fin, stream_id)) => {
                        if finished {
                            continue;
                        }

                        let (v1, v2, v3) = written_streams[&get_init_stream_id(
                            stream_id,
                            min_stream_id,
                            stream_id_space,
                        )];
                        let (offset, size, cum_off) =
                            match written_streams.entry(stream_id) {
                                Entry::Occupied(entry) => entry.into_mut(),
                                Entry::Vacant(entry) => {
                                    // Retrieve the original entry.
                                    let init_value = (v1, v2, v3);
                                    entry.insert(init_value)
                                },
                            };

                        if let Some(file) = self.file.as_mut() {
                            let current_offset = *cum_off + *offset;
                            // TODO: find the correct offest.
                            // let written =
                            //     file.write_at(&v, current_offset)? as u64;
                                let written = v.len() as u64;

                            if fin &&
                                !full_block.contains(&get_init_stream_id(
                                    stream_id,
                                    min_stream_id,
                                    stream_id_space,
                                ))
                            {
                                // Write everything at once.
                                total_written += *offset + written;

                                full_block.insert(get_init_stream_id(
                                    stream_id,
                                    min_stream_id,
                                    stream_id_space,
                                ));
                                println!("FULL BLOCK: {:?} {:?}", stream_id, total_written);
                            }
                            let new_value = (*offset + written, *size, *cum_off);
                            written_streams.insert(
                                stream_id,
                                new_value,
                            );
                        }

                        if total_written == total_size {
                            println!("File download completed.");
                            finished = true;
                            // let msg = FcQuicMsg::Close;
                            // self.tx.send(msg).await?;

                            // Print to NPF the duration.
                            let now = std::time::Instant::now();
                            let rct = now.duration_since(start).as_millis();
                            println!("RESULT-RCT {:?}", rct);
                        }
                    },

                    FcQuicMsg::Close => {
                        self.rx.close();
                        break;
                    },

                    _ => (),
                }
            }

            // Process the manifest data once we receive all data.
            if manifest_size == received_size as u64 && !processed_manifest {
                // Parse the manifest.
                let mut manifest: Manifest = serde_json::from_slice(&manifest_data)?;
                super::expand_implicit_blocks(&mut manifest);

                // Create the file of the correct size.
                let file = std::fs::File::create(&self.path)?;
                file.set_len(100)?;
                self.file = Some(file);

                // Fill the hashmap with the stream current offset (0), cumulated
                // offset, and size.
                let mut cumulated_off = 0;

                let max_stream_id =
                    manifest.blocks.iter().map(|(_, id)| *id).max().unwrap();
                min_stream_id =
                    manifest.blocks.iter().map(|(_, id)| *id).min().unwrap();
                stream_id_space = max_stream_id - min_stream_id + 4;

                for (size, stream_id) in manifest.blocks.iter() {
                    written_streams.insert(
                        get_init_stream_id(
                            *stream_id,
                            min_stream_id,
                            stream_id_space,
                        ),
                        (0, *size, cumulated_off),
                    );
                    cumulated_off += *size;
                }

                total_size = manifest.size;
                processed_manifest = true;
            }
        }

        Ok(())
    }

    fn handle_h3_resp_header(&mut self, resp: Vec<Header>) -> Result<u64> {
        for header in resp.iter() {
            match header.name() {
                b":content-length" => {
                    // Create the file with the correct size already.
                    // TODO: the content length is the length of the manifest
                    // path! Instead, we should fetch the length from the
                    // manifest.
                    let len: u64 = std::str::from_utf8(header.value())
                        .map(|v| v.parse())
                        .map_err(|_| "Cannot parse the content length")??;

                    return Ok(len);
                },

                _ => (),
            }
        }

        Err("No content length provided".into())
    }
}

fn send_request(url: &url::Url) -> Vec<Header> {
    let mut path = String::from(url.path());

    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let request = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        quiche::h3::Header::new(
            b":authority",
            url.host_str().unwrap().as_bytes(),
        ),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
    ];

    request
}

fn get_init_stream_id(stream_id: u64, min: u64, id_space: u64) -> u64 {
    (stream_id - min) % id_space
}
