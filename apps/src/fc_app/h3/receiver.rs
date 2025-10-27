//! Receiving-side of the HTTP/3 transfer module.

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
        let mut req_sent = false;

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
                        self.handle_h3_resp_header(resp)?;
                    },

                    FcQuicMsg::Http3RespBody(resp) => {
                        println!("RECEIVED BODY: {:?}", resp);
                        // TODO: create the file with the correct size.
                    },

                    FcQuicMsg::Stream((v, fin, stream_id)) => {
                        // TODO: handle the data with the correct offset.
                        // Write directly on disk.
                    },

                    FcQuicMsg::Close => {
                        self.rx.close();
                        break;
                    },

                    _ => (),
                }
            }
        }

        Ok(())
    }

    fn handle_h3_resp_header(&mut self, resp: Vec<Header>) -> Result<()> {
        for header in resp.iter() {
            match header.name() {
                b":content-length" => {
                    // Create the file with the correct size already.
                    // TODO: the content length is the length of the manifest path! Instead, we should fetch the length from the manifest.
                    let len: usize = std::str::from_utf8(header.value())
                        .map(|v| v.parse())
                        .map_err(|_| "Cannot parse the content length")??;

                    let file = std::fs::File::create(&self.path)?;
                    file.set_len(len as u64)?;
                    
                    self.file = Some(file);
                },

                _ => (),
            }
        }

        Ok(())
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
