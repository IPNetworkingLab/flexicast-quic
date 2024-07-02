use crate::Connection;
use crate::path::Path;

pub struct BackgroundFECScheduler {
    n_repair_in_flight: u64,
}

impl BackgroundFECScheduler {
    pub fn new() -> BackgroundFECScheduler {
        BackgroundFECScheduler{
            n_repair_in_flight: 0
        }
    }

    pub fn should_send_repair(&self, conn: &Connection, path: &Path, symbol_size: usize) -> bool {
        let dgrams_to_emit = conn.dgram_max_writable_len().is_some();
        let stream_to_emit = conn.streams.has_flushable();
        // send if no more data to send && we sent less repair than half the cwin

        let cwnd = path.recovery.cwnd();
        let max_repair_data = if cwnd < 15000 {
            cwnd*4/5
        } else {
            cwnd/2
        };
        trace!("fec_scheduler dgrams_to_emit={} stream_to_emit={} n_repair_in_flight={} max_repair_data={}",
                dgrams_to_emit, stream_to_emit, self.n_repair_in_flight, max_repair_data);
        !dgrams_to_emit && !stream_to_emit && (self.n_repair_in_flight as usize *symbol_size) < max_repair_data
    }

    pub fn sent_repair_symbol(&mut self) {
        self.n_repair_in_flight += 1;
    }

    pub fn acked_repair_symbol(&mut self) {
        self.n_repair_in_flight -= 1;

    }
    
    pub fn sent_source_symbol(&mut self) {

    }

    pub fn lost_repair_symbol(&mut self) {
        self.acked_repair_symbol()
    }


}
