use std::io::BufRead;
use std::io::Write;
use std::time;
use std::time::SystemTime;

pub struct TixeoClient {
    frame_recv: Vec<(u64, SystemTime, usize)>,
    output_filename: String,
}

impl TixeoClient {
    pub fn new(output_filename: &str) -> Self {
        TixeoClient {
            frame_recv: Vec::new(),
            output_filename: output_filename.to_owned(),
        }
    }

    pub fn on_init(&mut self) {}

    pub fn on_stream_complete(&mut self, buf: &[u8], stream_id: u64) {
        let now = SystemTime::now();
        self.frame_recv.push((stream_id, now, buf.len()))
    }

    pub fn on_finish(&self) {
        let mut file = std::fs::File::create(&self.output_filename).unwrap();
        for (stream_id, time, nb_bytes) in self.frame_recv.iter() {
            writeln!(
                file,
                "{} {} {}",
                (stream_id - 1) / 4,
                time.duration_since(time::UNIX_EPOCH).unwrap().as_micros(),
                nb_bytes
            )
            .unwrap();
        }
    }
}

pub struct TixeoServer {
    frames: Vec<(u64, usize)>,
    time_sent_to_quic: Vec<(u64, time::Instant, usize)>,
    time_sent_to_wire: Vec<(u64, time::Instant, usize)>,

    sent_frames: usize,
    cur_stream_id: u64,

    nxt_timestamp: Option<u64>,
    nxt_nb_bytes: usize,

    active_video: bool,
    start_video: Option<time::Instant>,

    to_quic_filename: String,
    to_wire_filename: String,
}

impl TixeoServer {
    pub fn new(
        trace_filename: Option<&str>, nb_frames: Option<u64>, delay: u64,
        wait: bool, to_quic_filename: &str, to_wire_filename: &str,
    ) -> Self {
        let frames = replay_trace(trace_filename, nb_frames, delay).unwrap();
        let (nxt_timestamp, nxt_nb_bytes) = frames[0];

        Self {
            frames,
            time_sent_to_quic: Vec::new(),
            time_sent_to_wire: Vec::new(),

            sent_frames: 0,
            cur_stream_id: 1,

            nxt_timestamp: Some(nxt_timestamp),
            nxt_nb_bytes,

            active_video: !wait,
            start_video: if wait {
                None
            } else {
                Some(time::Instant::now())
            },

            to_quic_filename: to_quic_filename.to_string(),
            to_wire_filename: to_wire_filename.to_string(),
        }
    }

    pub fn next_timeout(&self) -> Option<time::Duration> {
        if let Some(start) = self.start_video {
            let now = time::Instant::now();
            self.nxt_timestamp.map(|v| {
                start
                    .checked_add(time::Duration::from_micros(v))
                    .unwrap()
                    .duration_since(now)
            })
        } else {
            None
        }
    }

    pub fn start_content_delivery(&mut self) {
        trace!("Start the video content delivery");
        self.start_video = Some(time::Instant::now());
        self.active_video = true;
    }

    pub fn get_app_data(&self) -> (u64, Vec<u8>) {
        (self.cur_stream_id, vec![0u8; self.nxt_nb_bytes])
    }

    pub fn gen_nxt_app_data(&mut self) {
        self.sent_frames += 1;
        if self.sent_frames >= self.frames.len() {
            trace!("Set active video to false");
            self.active_video = false;
            self.nxt_timestamp = None;
            self.nxt_nb_bytes = 0;
        } else {
            let (tmp1, tmp2) = self.frames[self.sent_frames];
            self.nxt_timestamp = Some(tmp1);
            self.nxt_nb_bytes = tmp2;
            self.cur_stream_id += 4;
        }
    }

    pub fn on_sent_to_quic(&mut self) {
        self.time_sent_to_quic.push((
            self.cur_stream_id,
            time::Instant::now(),
            self.nxt_nb_bytes,
        ))
    }

    pub fn on_sent_to_wire(&mut self) {
        self.time_sent_to_wire.push((
            self.cur_stream_id - 4,
            time::Instant::now(),
            self.nxt_nb_bytes,
        ));
    }

    pub fn on_finish(&self) {
        let mut file = std::fs::File::create(&self.to_quic_filename).unwrap();
        for (stream_id, time, nb_bytes) in self.time_sent_to_quic.iter() {
            writeln!(
                file,
                "{} {} {}",
                (stream_id - 1) / 4,
                time.duration_since(self.start_video.unwrap()).as_micros(),
                nb_bytes,
            )
            .unwrap();
        }

        let mut file = std::fs::File::create(&self.to_wire_filename).unwrap();
        for (stream_id, time, nb_bytes) in self.time_sent_to_quic.iter() {
            writeln!(
                file,
                "{} {} {}",
                (stream_id - 1) / 4,
                time.duration_since(self.start_video.unwrap()).as_micros(),
                nb_bytes
            )
            .unwrap();
        }
    }

    #[inline]
    pub fn app_has_started(&self) -> bool {
        self.start_video.is_some()
    }

    #[inline]
    pub fn app_has_finished(&self) -> bool {
        self.start_video.is_some() && !self.active_video
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.active_video
    }

    #[inline]
    pub fn should_send_app_data(&self) -> bool {
        let now = time::Instant::now();
        self.is_active() &&
            now.duration_since(self.start_video.unwrap()) >=
                time::Duration::from_micros(self.nxt_timestamp.unwrap())
    }
}

fn replay_trace(
    filepath: Option<&str>, limit: Option<u64>, delay_no_replay: u64,
) -> Result<Vec<(u64, usize)>, std::io::Error> {
    if let Some(filepath) = filepath {
        let file = std::fs::File::open(filepath)?;
        let buf_reader = std::io::BufReader::new(file);

        let v = buf_reader
            .lines()
            .map(|line| {
                let line = line?;

                let mut tab = line[1..].split(',');
                let timestamp: u64 = tab.next().unwrap().parse().unwrap();
                let nb_bytes: usize = tab.next().unwrap().parse().unwrap();

                Ok((timestamp, nb_bytes))
            })
            .collect::<Result<Vec<(u64, usize)>, std::io::Error>>()?;

        Ok(v[..limit.unwrap_or(v.len() as u64) as usize].into())
    } else {
        Ok((0..limit.unwrap_or(1000))
            .map(|i| (delay_no_replay * i, 1000))
            .collect())
    }
}
