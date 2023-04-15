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
