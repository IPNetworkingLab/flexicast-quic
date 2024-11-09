//! Flexicast flow scheduler.
//! FC-TODO: define a common trait?

use std::time;

#[derive(Debug)]
/// Structure handling the scheduler of the flexicast flow for a receiver.
///
/// This scheduler only falls back receivers if it seems that the flexicast flow
/// is not working for the receiver. And as soon as the receive starts receiving
/// packets back on the flexicast flow, it will go again it the flexicast flow.
/// This scheduler DOES NOT, e.g., fall back in case of severe losses.
pub struct FcFlowAliveScheduler {
    /// Last (highest) packet number received on the flexicast flow.
    fcf_last_recv: Option<u64>,

    /// The time at which the last (highest) packet number was received on the
    /// flexicast flow.
    fcf_last_time: Option<time::Instant>,

    /// Whether the receiver currently receives data through the flexicast flow,
    /// i.e., the flow is not failing for the receiver.
    fcf_alive: bool,

    /// The delay before fall-backing the receiver on the unicast path.
    fall_back_delay: Option<time::Duration>,

    /// Whether some data have been retransmitted through the unicast path.
    /// This will trigger flexicast flow timeout.
    /// This avoids stating that the flexicast flow is dead when no data is sent.
    did_uc_retransmit: bool,
}

impl FcFlowAliveScheduler {
    /// New scheduler.
    ///
    /// The `now` argument is used whether we want to start listening to the
    /// flexicast flow.
    pub fn new(
        fall_back_delay: Option<time::Duration>, now: Option<time::Instant>,
    ) -> Self {
        Self {
            fcf_last_recv: None,
            fcf_alive: now.is_some(),
            fcf_last_time: now,
            fall_back_delay,
            did_uc_retransmit: false,
        }
    }

    /// Update the state of the receiver regarding the flexicast flow.
    /// This function should be called whenever the source receives an
    /// acknowledgment from the receiver. This function may potentially
    /// advertise the source that the receiver should temporarilly fall back on
    /// unicast delivery.
    ///
    /// Returns whether the flexicast flow was not alive and now is.
    pub fn on_ack_received(&mut self, last_pn: u64, now: time::Instant) -> bool {
        // The receiver received a new packet on the flexicast flow.
        let was_alive = self.fcf_alive;
        if self.fcf_last_recv.map(|pn| pn < last_pn).unwrap_or(true) {
            self.fcf_last_recv = Some(last_pn);
            self.fcf_last_time = Some(now);
            self.fcf_alive = true;

            // Reset the fast that we did unicast retransmission to avoid creating a timeout.
            self.did_uc_retransmit = false;
        } else {
            self.fcf_alive = !self.should_uc_fall_back(now);
        }
        !was_alive && self.fcf_alive
    }

    /// Returns whether the receiver should fall back on unicast.
    pub fn should_uc_fall_back(&self, now: time::Instant) -> bool {
        self.fcf_timeout(now)
            .is_some_and(|t| t == time::Duration::ZERO)
    }

    /// Returns the duration until the flexicast flow timeouts.
    pub fn fcf_timeout(&self, now: time::Instant) -> Option<time::Duration> {
        // Avoid creating a timeout if it is just that no data was sent on the flexicast flow.
        if !self.did_uc_retransmit {
            return None;
        }
        
        // Avoid creating a new timeout if the flexicast flow is already dead.
        if !self.fcf_alive {
            return None;
        }

        if let (Some(last_time), Some(delay)) =
            (self.fcf_last_time, self.fall_back_delay)
        {
            Some(delay.saturating_sub(now.duration_since(last_time)))
        } else {
            None
        }
    }

    /// Advertises whether the receiver falls-back on unicast.
    pub fn uc_fall_back(&mut self) {
        info!("Flexicast flow is dead");
        self.fcf_alive = false;
    }

    /// Whether the flexicast flow is still alive for the receiver.
    pub fn fcf_alive(&self) -> bool {
        self.fcf_alive
    }

    /// Starts listening to the flexicast flow. Consider it alive.
    pub fn set_fcf_alive(&mut self, now: time::Instant) {
        info!("Flexicast flow alive!");
        self.fcf_alive = true;
        self.fcf_last_time = Some(now);
    }

    /// Some data have been retransmitted through the unicast path.
    /// This notifies the scheduler that the flexicast flow may be dead.
    pub fn did_uc_retransmit(&mut self) {
        self.did_uc_retransmit = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fcf_alive_scheduler() {
        let delay = time::Duration::from_millis(100);
        let now = time::Instant::now();

        let mut scheduler = FcFlowAliveScheduler::new(Some(delay), Some(now));
        assert!(scheduler.fcf_alive());
        assert!(!scheduler.should_uc_fall_back(now));

        // Wait too long and so we fall back.
        let now = now + delay * 2;
        assert!(scheduler.should_uc_fall_back(now));
        scheduler.uc_fall_back();
        assert!(!scheduler.fcf_alive());

        // Get a packet.
        assert!(scheduler.on_ack_received(1, now));
        let now = now + delay * 2;
        assert!(scheduler.on_ack_received(2, now));

        // Older packet.
        let now = now + delay * 2;
        assert!(!scheduler.on_ack_received(1, now));
    }
}
