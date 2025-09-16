//! HLS video.

use std::fs;
use std::io::Read;
use std::io::Write;
use std::path;
use std::time;

use crate::fc_app::Result;
use tokio::sync::mpsc;
use tokio_fcquiche::FcQuicMsg;

const MANIFEST_NAME: &str = "playlist.m3u8";
const SEGMENT_PREFIX: &str = "segment_";
const MANIFEST_STREAM_ID: u64 = 3;
const SEGMENT_STREAM_ID: u64 = 7;
const SEGMENT_DURATION: time::Duration = time::Duration::from_secs(2);

#[derive(Debug)]
/// HLS source structure.
pub struct HlsSource {
    /// Directory to the manifest and segments.
    dir_path: String,

    /// Duration between two manifest updates.
    manifest_update_dur: time::Duration,

    /// Last time we pushed the manifest.
    last_manifest_push: time::Instant,

    /// Last time we pushed a segment.
    last_segment_push: time::Instant,

    /// Current manifest stream ID.
    manifest_sid: u64,

    /// Current segment stream ID.
    segment_sid: u64,

    /// Identifier of the next segment, internal value.
    next_segment_id: usize,

    /// Transmission channel to send the data to QUIC.
    tx: mpsc::Sender<FcQuicMsg>,
}

impl HlsSource {
    /// Creates a new instance with default parameters.
    pub fn new(dir_path: &str, tx: mpsc::Sender<FcQuicMsg>) -> Self {
        let now = time::Instant::now();
        Self {
            dir_path: dir_path.to_string(),
            manifest_update_dur: time::Duration::from_secs(2),
            last_manifest_push: now,
            last_segment_push: now,
            manifest_sid: MANIFEST_STREAM_ID,
            segment_sid: SEGMENT_STREAM_ID,
            next_segment_id: 0,
            tx,
        }
    }

    /// Asynchronously runs the HLS source.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            let now = time::Instant::now();
            let timeout_manifest = self
                .manifest_update_dur
                .saturating_sub(now.duration_since(self.last_manifest_push));
            let timeout_segment = SEGMENT_DURATION
                .saturating_sub(now.duration_since(self.last_segment_push));
            info!(
                "Timeout manifest: {:?} and timeout segment: {:?}",
                timeout_manifest, timeout_segment
            );
            tokio::select! {
                _ = tokio::time::sleep(timeout_manifest) => self.push_manifest().await?,

                _ = tokio::time::sleep(timeout_segment) => self.push_segment().await?,
            }
        }
    }

    /// Push a new version of the manifest.
    async fn push_manifest(&mut self) -> Result<()> {
        info!("PUSH manifest");
        let filename = path::Path::new(&self.dir_path).join(MANIFEST_NAME);
        let mut fd = match fs::File::open(filename.clone()) {
            Ok(fd) => fd,
            Err(_) => {
                error!("Cannot find manifest: {:?}", filename);
                self.last_manifest_push = time::Instant::now();
                return Ok(());
            },
        };
        self.send_all(&mut fd, self.manifest_sid).await?;

        self.manifest_sid += 8;
        self.last_manifest_push = time::Instant::now();
        Ok(())
    }

    /// Push a new segment.
    async fn push_segment(&mut self) -> Result<()> {
        info!("PUSH segment");
        let filename = path::Path::new(&self.dir_path)
            .join(format!("{}{:0>3}.ts", SEGMENT_PREFIX, self.next_segment_id));
        let mut fd = match fs::File::open(filename.clone()) {
            Ok(fd) => fd,
            Err(_) => {
                error!("Cannot find segment: {:?}", filename);
                self.last_segment_push = time::Instant::now();
                return Ok(());
            },
        };
        self.send_all(&mut fd, self.segment_sid).await?;

        self.segment_sid += 8;
        self.next_segment_id += 1;
        self.last_segment_push = time::Instant::now();
        Ok(())
    }

    /// Internal function to read all content from a source and send a message.
    async fn send_all(
        &mut self, fd: &mut fs::File, stream_id: u64,
    ) -> Result<()> {
        let total_size = fd.metadata()?.len();
        let mut total_read = 0;

        let mut buf = [0u8; 10_000];
        loop {
            let read = fd.read(&mut buf[..])?;

            total_read += read as u64;
            let fin = total_read == total_size;

            let msg = FcQuicMsg::Stream((buf[..read].to_vec(), fin, stream_id));
            self.tx.send(msg).await?;

            if fin {
                return Ok(());
            }
        }
    }
}

#[derive(Debug)]
/// HLS receiver structure.
pub struct HlsSink {
    /// The internal stream segment identifier.
    next_segment_id: usize,

    /// Directory to the manifest and segments.
    dir_path: String,

    /// Reception channel for the data.
    rx: mpsc::Receiver<FcQuicMsg>,
}

impl HlsSink {
    /// Creates a new instance with default parameters.
    pub fn new(dir_path: &str, rx: mpsc::Receiver<FcQuicMsg>) -> Self {
        Self {
            dir_path: dir_path.to_string(),
            next_segment_id: 0,
            rx,
        }
    }

    /// Asynchronously runs the HLS sink.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            if let Some(FcQuicMsg::Stream((data, fin, stream_id))) =
                self.rx.recv().await
            {
                if stream_id % 8 == 3 {
                    debug!(
                        "Receive manifest. ID={stream_id}, len={}, fin={fin}",
                        data.len()
                    );
                    // This is a manifest.
                    let filename =
                        path::Path::new(&self.dir_path).join(MANIFEST_NAME);

                    let mut fd = fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .open(filename)?;
                    fd.write_all(&data)?;
                } else if stream_id % 8 == 7 {
                    debug!(
                        "Receive segment. ID={stream_id}, len={}, fin={fin}",
                        data.len()
                    );
                    // This is a segment.
                    let filename = path::Path::new(&self.dir_path).join(format!(
                        "{}{:0>3}.ts",
                        SEGMENT_PREFIX,
                        (stream_id - 7) / 8,
                    ));

                    let mut fd = fs::OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(filename)?;
                    fd.write_all(&data)?;

                    // Increase the segment ID because this is the end of the
                    // current one.
                    if fin {
                        self.next_segment_id += 1;
                    }
                }
            }
        }
    }
}
