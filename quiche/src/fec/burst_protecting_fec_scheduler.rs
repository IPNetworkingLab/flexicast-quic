use crate::Connection;
use crate::path::Path;
use std::env;

#[derive(Debug, Clone, Copy)]
struct SendingState {
    start_time: std::time::Instant,
    max_sending_repair_bytes: usize,
}
pub(crate) struct BurstsFECScheduler {
    n_repair_in_flight: u64,
    n_packets_sent_when_nothing_to_send: usize,
    n_bytes_sent_when_nothing_to_send: usize,
    n_sent_bytes_when_last_repair: usize,
    first_source_symbol_in_burst_sent_time: Option<std::time::Instant>,
    state_sending_repair: Option<SendingState>,
}

impl BurstsFECScheduler {
    pub fn new() -> BurstsFECScheduler {
        BurstsFECScheduler{
            n_repair_in_flight: 0,
            n_packets_sent_when_nothing_to_send: 0,
            n_bytes_sent_when_nothing_to_send: 0,
            n_sent_bytes_when_last_repair: 0,
            first_source_symbol_in_burst_sent_time: None,
            state_sending_repair: None,
        }
    }

    pub fn should_send_repair(&mut self, conn: &Connection, path: &Path, symbol_size: usize) -> bool {
        let now = std::time::Instant::now();
        // this variable can be overriden by the DEBUG_QUICHE_FEC_BURST_SIZE_BYTES environment variable for debug purposes
        const DEFAULT_BURST_SIZE: usize = 15000;
        const DEFAULT_COOLDOWN_US: u64 = 0;
        const DEFAULT_FRAC_DENOMINATOR_TO_PROTECT: usize = 2;
        const DEFAULT_MINIMUM_ROOM_IN_CWIN: usize = 5000;
        // const DEFAULT_BANDWIDTH_PROBING_BPS: usize = 0;
        let burst_size: usize = env::var("DEBUG_QUICHE_FEC_BURST_SIZE_BYTES").unwrap_or(DEFAULT_BURST_SIZE.to_string()).parse().unwrap_or(DEFAULT_BURST_SIZE);
        let fec_cooldown_us: u64 = env::var("DEBUG_QUICHE_FEC_COOLDOWN_US").unwrap_or(DEFAULT_COOLDOWN_US.to_string()).parse().unwrap_or(DEFAULT_COOLDOWN_US);
        let fec_cooldown = std::time::Duration::from_micros(fec_cooldown_us);
        let fec_frac_denominator_to_protect: usize = env::var("DEBUG_QUICHE_DEFAULT_FRAC_DENOMINATOR_TO_PROTECT").unwrap_or(DEFAULT_FRAC_DENOMINATOR_TO_PROTECT.to_string()).parse().unwrap_or(DEFAULT_FRAC_DENOMINATOR_TO_PROTECT);
        let minimum_room_in_cwin = env::var("DEBUG_QUICHE_MINIMUM_ROOM_IN_CWIN").unwrap_or(DEFAULT_MINIMUM_ROOM_IN_CWIN.to_string()).parse().unwrap_or(DEFAULT_MINIMUM_ROOM_IN_CWIN);
        // let bandwidth_probing_bps = env::var("DEBUG_QUICHE_BANDWIDTH_PROBING_BPS").unwrap_or(DEFAULT_BANDWIDTH_PROBING_BPS.to_string()).parse().unwrap_or(DEFAULT_BANDWIDTH_PROBING_BPS);
        let dgrams_to_emit = conn.dgram_max_writable_len().is_some();
        let stream_to_emit = conn.streams.has_flushable();
        // send if no more data to send && we sent less repair than half the cwin

        let mut total_bif = 0;
        for (_, path) in conn.paths.iter() {
            if !path.fec_only {
                total_bif += path.recovery.cwnd().saturating_sub(path.recovery.cwnd_available());
            }
        }
        let cwin_available = path.recovery.cwnd_available();
        let enough_room_in_cwin = cwin_available > minimum_room_in_cwin;
        let nothing_to_send = !dgrams_to_emit && !stream_to_emit;
        let current_sent_count = conn.sent_count;
        let current_sent_bytes = conn.sent_bytes as usize;
        let sent_enough_protected_data = current_sent_bytes - self.n_bytes_sent_when_nothing_to_send > burst_size;
        // we should probe using FEC if we are app-limited and the currently sent bitrate is not matching the bandwidth objective
        let should_probe = false; //path.recovery.app_limited() && 8.0*(total_bif as f64)/path.recovery.rtt().as_secs_f64() < bandwidth_probing_bps as f64;

        trace!("fec_scheduler dgrams_to_emit={} stream_to_emit={} n_repair_in_flight={} sending_state={:?} sent_count={} old_sent_count={} should_probe={} 
                current_sent_bytes={} old_sent_bytes={} sent_enough_protected_data={} enough_room_in_cwin={} cwin_available={} minimum_room_in_cwin={}",
                dgrams_to_emit, stream_to_emit, self.n_repair_in_flight, self.state_sending_repair, current_sent_count, self.n_packets_sent_when_nothing_to_send,
                should_probe, current_sent_bytes, self.n_bytes_sent_when_nothing_to_send, sent_enough_protected_data, enough_room_in_cwin,
                cwin_available, minimum_room_in_cwin);

        
        self.state_sending_repair = match self.state_sending_repair {
            Some(state) => {
                if now.duration_since(state.start_time) > path.recovery.rtt() {
                    None
                } else {
                    Some(state)
                }
            }
            None => {
                if nothing_to_send && sent_enough_protected_data && enough_room_in_cwin
                    && (self.first_source_symbol_in_burst_sent_time.is_none() || now > self.first_source_symbol_in_burst_sent_time.unwrap() + fec_cooldown) {
                    // a burst of packets has occurred, so send repair symbols
                    let bytes_to_protect = std::cmp::min(total_bif, current_sent_bytes - self.n_sent_bytes_when_last_repair);
                    let max_repair_data = if bytes_to_protect < 15000 {
                        bytes_to_protect*3/5
                    } else {
                        bytes_to_protect/fec_frac_denominator_to_protect
                    };
                    Some(SendingState{start_time: now, max_sending_repair_bytes: max_repair_data})
                } else {
                    None
                }
            }
        };

        if nothing_to_send {
            self.n_packets_sent_when_nothing_to_send = conn.sent_count;
            self.n_bytes_sent_when_nothing_to_send = conn.sent_bytes as usize;
        }
        let should_send = should_probe || (enough_room_in_cwin && match self.state_sending_repair {
            Some(state) => (self.n_repair_in_flight as usize * symbol_size) < state.max_sending_repair_bytes,
            None => false,
        });
        if should_send {
            self.n_sent_bytes_when_last_repair = current_sent_bytes;
        }
        should_send
    }

    pub fn sent_repair_symbol(&mut self) {
        self.n_repair_in_flight += 1;
        self.first_source_symbol_in_burst_sent_time = None;
    }

    pub fn acked_repair_symbol(&mut self) {
        self.n_repair_in_flight -= 1;
    }

    pub fn sent_source_symbol(&mut self) {
        if self.first_source_symbol_in_burst_sent_time.is_none() {
            self.first_source_symbol_in_burst_sent_time = Some(std::time::Instant::now());
        }
    }

    pub fn lost_repair_symbol(&mut self) {
        self.acked_repair_symbol()
    }


}
