use std::time::Duration;

use super::Recovery;

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
}
