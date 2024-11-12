//! Flexicast flow scheduler.
//! FC-TODO: define a common trait?

use std::time;

use quiche::Connection;

/// Trait defining a single function to determine if bytes are in flight.
pub trait BytesInFlight {
    /// Returns whether bytes are in flight.
    fn bytes_in_flight(&self) -> bool;
}

impl BytesInFlight for Connection {
    fn bytes_in_flight(&self) -> bool {
        self.fc_bytes_in_flight().unwrap_or(false)
    }
}

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

    /// The time of the next timeout of the flexicast flow.
    fcf_next_timeout: Option<time::Instant>,

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
            fcf_next_timeout: None,
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
    pub fn on_ack_received(
        &mut self, last_pn: u64, now: time::Instant, conn: &dyn BytesInFlight,
    ) -> bool {
        // The receiver received a new packet on the flexicast flow.
        let was_alive = self.fcf_alive;
        if self.fcf_last_recv.map(|pn| pn < last_pn).unwrap_or(true) {
            self.fcf_last_recv = Some(last_pn);
            self.fcf_alive = true;

            // Reset the fast that we did unicast retransmission to avoid creating a timeout.
            self.did_uc_retransmit = false;

            // Set the next timeout.
            let idle_timeout = if let (true, Some(d)) =
                (conn.bytes_in_flight(), self.fall_back_delay)
            {
                Some(now + d)
            } else {
                None
            };

            self.fcf_next_timeout = idle_timeout;
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
        // if self.did_uc_retransmit {
        //     println!("LA");
        //     return None;
        // }

        // Avoid creating a new timeout if the flexicast flow is already dead.
        if !self.fcf_alive {
            return None;
        }

        self.fcf_next_timeout.map(|d| d.duration_since(now))
    }

    /// Advertises whether the receiver falls-back on unicast.
    pub fn uc_fall_back(&mut self) {
        self.fcf_alive = false;
    }

    /// Whether the flexicast flow is still alive for the receiver.
    pub fn fcf_alive(&self) -> bool {
        self.fcf_alive
    }

    /// Starts listening to the flexicast flow. Consider it alive.
    /// Do not update the next timeout because no data was sent on the flow.
    pub fn set_fcf_alive(&mut self) {
        self.fcf_alive = true;
        self.fcf_next_timeout = None;
    }

    /// Some data have been retransmitted through the unicast path.
    /// This notifies the scheduler that the flexicast flow may be dead.
    pub fn did_uc_retransmit(&mut self) {
        self.did_uc_retransmit = true;
    }

    /// Update the scheduler on new packets sent on the flexicast flow.
    /// This will trigger the start of a new timeout.
    pub fn on_packet_sent(&mut self, now: time::Instant) {
        // As we sent a new packet, start the timeout.
        self.fcf_next_timeout = self.fall_back_delay.map(|d| now + d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    /// Structure for testing purposes.
    struct Dummy {
        /// Whether some bytes are in flight.
        in_flight: bool,
    }

    impl BytesInFlight for Dummy {
        fn bytes_in_flight(&self) -> bool {
            self.in_flight
        }
    }

    impl Dummy {
        pub fn set(&mut self, v: bool) {
            self.in_flight = v;
        }
    }

    #[test]
    fn test_fc_scheduler_alive() {
        let delay = time::Duration::from_millis(10);
        let now = time::Instant::now();
        let mut c = Box::new(Dummy::default());

        let mut scheduler = FcFlowAliveScheduler::new(Some(delay), Some(now));
        assert!(scheduler.fcf_alive());
        assert!(!scheduler.should_uc_fall_back(now));

        // Wait long enough.
        let now = now + delay * 2;

        // We do not fall-back because no data was sent on the path.
        assert!(!scheduler.should_uc_fall_back(now));
        assert!(scheduler.fcf_alive());

        // Send a packet.
        scheduler.on_packet_sent(now);
        c.set(true);

        // Sleep half the time.
        let now = now + delay / 2;

        // Should not fall-back yet.
        assert!(!scheduler.should_uc_fall_back(now));

        // Send new data.
        scheduler.on_packet_sent(now);

        // Sleep more.
        let now = now + delay;

        // Now should fall back because no feedback.
        assert!(scheduler.should_uc_fall_back(now));
        scheduler.uc_fall_back();
        assert!(!scheduler.fcf_alive());

        // Finally receive some feedback, but still data in flight.
        scheduler.on_ack_received(3, now, c.as_ref());
        assert!(scheduler.fcf_alive());

        // Since we did not get feedback for the second packet flight, we fall back again.
        let now = now + delay;
        assert!(scheduler.should_uc_fall_back(now));
        scheduler.uc_fall_back();
        assert!(!scheduler.fcf_alive());

        // Finally receive some feedback, but still data in flight.
        c.set(false);
        scheduler.on_ack_received(5, now, c.as_ref());
        assert!(scheduler.fcf_alive());

        // Send new data.
        c.set(true);
        scheduler.on_packet_sent(now);
        let now = now + delay / 2;

        // Same ack, so the timeout is still active
        scheduler.on_ack_received(5, now, c.as_ref());
        assert!(!scheduler.should_uc_fall_back(now));
        assert!(scheduler.fcf_next_timeout.is_some());

        let now = now + delay;
        assert!(scheduler.should_uc_fall_back(now));
        scheduler.uc_fall_back();
        assert!(!scheduler.fcf_alive());

        // New ack. Ok flexicast flow.
        c.set(false);
        scheduler.on_ack_received(6, now, c.as_ref());
        assert!(scheduler.fcf_alive());
        assert!(scheduler.fcf_next_timeout.is_none());

        // Finally, the normal case: send packet, receive ack, all is good.
        c.set(true);
        scheduler.on_packet_sent(now);
        let now = now + delay / 2;
        assert!(scheduler.fcf_next_timeout.is_some());

        c.set(false);
        scheduler.on_ack_received(7, now, c.as_ref());
        assert!(scheduler.fcf_next_timeout.is_none());
        assert!(scheduler.fcf_alive());
        assert!(scheduler.fcf_next_timeout.is_none());
    }
}
