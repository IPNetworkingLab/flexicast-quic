//! Video source.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::Result;

#[derive(Debug)]
/// Video source structure.
pub struct VideoSource {
    /// Socket used to receive RTP content from the video feed, e.g., ffmpeg.
    socket_in: UdpSocket,

    /// Current stream ID used to send RTP frames to QUIC.
    stream_id: u64,

    /// Transmission channel to send the RTP frames to QUIC.
    tx: mpsc::Sender<VideoSourceMsg>,

    /// Optional timeout to the RTP frames.
    timeout_opt: Option<time::Duration>,
}

impl VideoSource {
    /// Creates a new instance.
    pub async fn new(
        video_feed_sockaddr: SocketAddr, tx: mpsc::Sender<VideoSourceMsg>,
        timeout_opt: Option<time::Duration>,
    ) -> Result<Self> {
        let socket_in = UdpSocket::bind(video_feed_sockaddr).await?;

        Ok(Self {
            socket_in,
            stream_id: 3,
            tx,
            timeout_opt,
        })
    }

    /// Asynchronously runs the source.
    pub async fn run(&mut self) -> Result<()> {
        let mut buf = [0u8; 1500];

        loop {
            if let Ok(read) = self.socket_in.recv(&mut buf[..]).await {
                let data = Arc::new(buf[..read].to_vec());
                let msg = VideoSourceMsg::Data((self.stream_id, data));

                match self.timeout_opt {
                    Some(t) => self.tx.send_timeout(msg, t).await?,
                    None => self.tx.send(msg).await?,
                }
            }
        }
    }
}

#[derive(Debug)]
/// Messages between the video source and the QUIC emitter.
pub enum VideoSourceMsg {
    /// New RTP frame.
    /// First value is the stream ID.
    /// Second value is the bytes.
    Data((u64, Arc<Vec<u8>>)),
}
