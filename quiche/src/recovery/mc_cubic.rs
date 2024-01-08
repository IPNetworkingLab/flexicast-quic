use std::time::{Duration, Instant};

use crate::packet::Epoch;

use super::{Recovery, SpacedPktNum};

impl Recovery {
    /// Whether the current CUBIC congestion window is smaller than the minimal
    /// multicast sending window. Always returns false if the congestion
    /// control is not CUBIC or there is no minimal congestion window set.
    pub fn mc_cubic_below_minimal(&self) -> bool {
        if let Some(min_cwnd) = self.mc_cwnd {
            self.congestion_window < min_cwnd
        } else {
            false
        }
    }

    /// Sets the congestion window to the value of the multicast minimal
    /// congestion window. If the current congestion window is higher than
    /// this value, this function does nothing.
    pub fn mc_set_min_cwnd(&mut self) {
        if let Some(min_cwnd) = self.mc_cwnd {
            self.congestion_window = self
                .congestion_window
                .max(min_cwnd * self.max_datagram_size);
        }
    }

    /// Forces the congestion window to a specific value.
    pub fn mc_force_cwin(&mut self, cwin: usize) {
        self.congestion_window = cwin;
    }

    /// Sets the minimum RTT to a defined value.
    pub fn mc_set_min_rtt(&mut self, min_rtt: Duration) {
        self.min_rtt = min_rtt;
    }

    /// Sets all RTT values to the values from another recovery mechanism.
    pub fn mc_set_loss_detection_timer(&mut self, timer: Option<Instant>) {
        self.loss_detection_timer = timer;
    }

    pub fn mc_set_rtt(&mut self, expiration_timer: Duration) {
        self.min_rtt = expiration_timer;
        self.rttvar = Duration::from_millis(0);
        self.smoothed_rtt = Some(expiration_timer);
        self.latest_rtt = expiration_timer;
    }

    pub fn set_largest_ack(&mut self, largest: u64) {
        let pn = self.largest_acked_pkt[Epoch::Application].1;
        if pn < largest {
            self.largest_acked_pkt[Epoch::Application] = SpacedPktNum::new(self.largest_acked_pkt[Epoch::Application].0, largest);
        }
    }
}
