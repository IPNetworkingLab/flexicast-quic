//! This application transfers a file (the path to the file is given as argument
//! during the creation of the [`FileServer`] structure). This very specific
//! application sends chunks of the file in separate streams. In this context,
//! each stream contains a single STREAM_FRAME.

use std::io::Write;
use std::time::SystemTime;
use std::time;

pub struct FileClient {
    chunk_recv: Vec<(u64, SystemTime, Vec<u8>)>,
    output_filename: String,
}

impl FileClient {
    pub fn new(output_filename: &str) -> Self {
        FileClient {
            chunk_recv: Vec::new(),
            output_filename: output_filename.to_owned(),
        }
    }

    pub fn on_init(&mut self) {}

    pub fn on_stream_complete(&mut self, buf: &[u8], stream_id: u64) {
        let now = SystemTime::now();
        self.chunk_recv.push((stream_id, now, buf.to_vec()));
    }

    pub fn on_finish(&mut self) {
        let mut file = std::fs::File::create(&self.output_filename).unwrap();
        // for (stream_id, time, bytes) in self.chunk_recv.iter() {
        //     writeln!(
        //         file,
        //         "{} {} {}",
        //         (stream_id - 1) / 4,
        //         time.duration_since(time::UNIX_EPOCH).unwrap().as_micros(),
        //         nb_bytes
        //     )
        //     .unwrap();
        // }
        // Sort the streams according to the stream ID.
        self.chunk_recv.sort_by(|first, second| first.0.cmp(&second.0));
        for (_, _, bytes) in self.chunk_recv.iter() {
            file.write_all(bytes).unwrap();
        }
    }
}

pub struct FileServer {
    chunks: Vec<Vec<u8>>,
    time_sent_to_quic: Vec<(u64, time::Instant)>,
    time_sent_to_wire: Vec<(u64, time::Instant)>,

    sent_chunks: usize,
    stream_id: u64,
    stream_writen: usize,

    active: bool,
    start: Option<time::Instant>,

    to_quic_filename: String,
    to_wire_filename: String,
}

impl FileServer {
    pub fn new(
        filename: Option<&str>, nb_frames: Option<u64>, wait: bool,
        to_quic_filename: &str, to_wire_filename: &str, chunk_size: usize,
    ) -> Result<Self, std::io::Error> {
        let chunks: Vec<_> = if let Some(filepath) = filename {
            std::fs::read(filepath)?
                .chunks(chunk_size)
                .map(|i| i.to_vec())
                .collect()
        } else {
            (0..nb_frames.unwrap_or(1000))
                .map(|_| vec![0u8; chunk_size])
                .collect()
        };

        Ok(Self {
            chunks,
            time_sent_to_quic: Vec::new(),
            time_sent_to_wire: Vec::new(),

            sent_chunks: 0,
            stream_id: 1,
            stream_writen: 0,

            active: !wait,
            start: if wait {
                None
            } else {
                Some(time::Instant::now())
            },

            to_quic_filename: to_quic_filename.to_string(),
            to_wire_filename: to_wire_filename.to_string(),
        })
    }

    pub fn next_timeout(&self) -> Option<time::Duration> {
        // if self.is_active() {
        //     Some(time::Duration::ZERO)
        // } else {
        //     None
        // }
        None
    }

    pub fn start_content_delivery(&mut self) {
        trace!("Start the file transfer delivery content");
        self.active = true;
        self.start = Some(time::Instant::now())
    }

    pub fn get_app_data(&self) -> (u64, Vec<u8>) {
        debug!("Must send data at offset {}", self.stream_writen);
        (self.stream_id, self.chunks[self.sent_chunks][self.stream_writen..].to_vec())
    }

    pub fn gen_nxt_app_data(&mut self) {
        self.sent_chunks += 1;
        if self.sent_chunks >= self.chunks.len() {
            trace!("Set active file transfer to false");
            self.active = false;
        } else {
            self.stream_id += 4;
            self.stream_writen = 0;
        }
    }

    pub fn on_sent_to_quic(&mut self) {
        self.time_sent_to_quic
            .push((self.stream_id, time::Instant::now()));
    }

    pub fn on_sent_to_wire(&mut self) {
        self.time_sent_to_wire
            .push((self.stream_id - 4, time::Instant::now()));
    }

    pub fn on_finish(&self) {
        let mut file = std::fs::File::create(&self.to_quic_filename).unwrap();
        for (stream_id, time) in self.time_sent_to_quic.iter() {
            writeln!(
                file,
                "{} {}",
                (stream_id - 1) / 4,
                time.duration_since(self.start.unwrap()).as_micros(),
            )
            .unwrap();
        }

        let mut file = std::fs::File::create(&self.to_wire_filename).unwrap();
        for (stream_id, time) in self.time_sent_to_quic.iter() {
            writeln!(
                file,
                "{} {}",
                (stream_id - 1) / 4,
                time.duration_since(self.start.unwrap()).as_micros(),
            )
            .unwrap();
        }
    }

    #[inline]
    pub fn app_has_started(&self) -> bool {
        self.start.is_some()
    }

    #[inline]
    pub fn app_has_finished(&self) -> bool {
        self.start.is_some() && !self.active
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.active
    }

    #[inline]
    pub fn should_send_app_data(&self) -> bool {
        self.active
    }

    #[inline]
    pub fn stream_writen(&mut self, v: usize) {
        self.stream_writen = v;
    }
}
