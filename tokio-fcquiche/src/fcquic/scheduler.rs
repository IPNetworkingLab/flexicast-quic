//! Flexicast flow scheduler.
//! FC-TODO: define a common trait?

use log::*;
use std::time;

const FALLBACK_DELAY_MULTIPLIER: u64 = 5;

/// The fall-back delay configuration for the unicast scheduler.
#[derive(Debug, Clone)]
pub enum FcFallBackDelay {
    /// A static delay in milliseconds.
    Static(u64),
    /// Adaptive delay (determined at runtime), carrying its current value in
    /// ms.
    Adaptive(u64),
}

impl std::str::FromStr for FcFallBackDelay {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("adaptive") {
            Ok(FcFallBackDelay::Adaptive(0))
        } else {
            s.parse::<u64>().map(FcFallBackDelay::Static).map_err(|_| {
                format!("Expected a millisecond value or 'adaptive', got '{}'", s)
            })
        }
    }
}

impl FcFallBackDelay {
    /// Returns the current delay as a `Duration`.
    /// For [`FcFallBackDelay::Static`] returns the configured value.
    /// For [`FcFallBackDelay::Adaptive`] returns `None` if the value has not
    /// been set yet (i.e. is 0), otherwise returns the current adaptive value.
    pub fn to_duration(&self) -> Option<time::Duration> {
        match self {
            FcFallBackDelay::Static(ms) => Some(time::Duration::from_millis(*ms)),
            FcFallBackDelay::Adaptive(0) => None,
            FcFallBackDelay::Adaptive(ms) =>
                Some(time::Duration::from_millis(*ms)),
        }
    }

    /// Updates the inner value for [`FcFallBackDelay::Adaptive`].
    /// Does nothing if the variant is [`FcFallBackDelay::Static`].
    pub fn update_adaptive(&mut self, v: u64) {
        if let FcFallBackDelay::Adaptive(ms) = self {
            *ms = v;
        }
    }
}

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
    fall_back_delay: Option<FcFallBackDelay>,

    /// Whether some data have been retransmitted through the unicast path.
    /// This will trigger flexicast flow timeout.
    /// This avoids stating that the flexicast flow is dead when no data is
    /// sent.
    did_uc_retransmit: bool,

    /// The highest packet number received on the flexicast flow while the
    /// receiver in the flexicast flow.
    fcf_max_pn_recv_in_flow: Option<u64>,
}

impl FcFlowAliveScheduler {
    /// New scheduler.
    ///
    /// The `now` argument is used whether we want to start listening to the
    /// flexicast flow.
    pub fn new(
        fall_back_delay: Option<FcFallBackDelay>, now: Option<time::Instant>,
    ) -> Self {
        Self {
            fcf_last_recv: None,
            fcf_alive: now.is_some(),
            fcf_next_timeout: None,
            fall_back_delay,
            did_uc_retransmit: false,
            fcf_max_pn_recv_in_flow: None,
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
        if self.fcf_alive {
            self.fcf_max_pn_recv_in_flow = Some(last_pn);
        }

        // The receiver received a new packet on the flexicast flow.
        debug!(
            "Chec, fc flow alive: {:?} vs {:?}",
            self.fcf_last_recv, last_pn
        );
        let was_alive = self.fcf_alive;
        if self.fcf_last_recv.map(|pn| pn < last_pn).unwrap_or(true) {
            self.fcf_last_recv = Some(last_pn);
            self.fcf_alive = true;

            // Reset the fact that we did unicast retransmission to avoid creating
            // a timeout.
            self.did_uc_retransmit = false;

            // Set the next timeout.
            let idle_timeout = if conn.bytes_in_flight() {
                self.fall_back_delay
                    .as_ref()
                    .and_then(|d| d.to_duration())
                    .map(|d| now + d)
            } else {
                None
            };

            self.fcf_next_timeout = idle_timeout;
        }
        !was_alive && self.fcf_alive
    }

    /// Returns whether the receiver should fall back on unicast.
    pub fn should_uc_fall_back(&self, now: time::Instant) -> bool {
        let out = self.fcf_timeout(now)
            .is_some_and(|t| t == time::Duration::ZERO);
        out
    }

    /// Returns the duration until the flexicast flow timeouts.
    pub fn fcf_timeout(&self, now: time::Instant) -> Option<time::Duration> {
        // Avoid creating a timeout if it is just that no data was sent on the
        // flexicast flow. if self.did_uc_retransmit {
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
        self.fcf_next_timeout = None;
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

    /// Update the scheduler on new packets sent on the flexicast flow.
    /// This will trigger the start of a new timeout.
    pub fn on_packet_sent(&mut self, now: time::Instant) {
        // Avoid computing a new timeout if the flexicast flow is not alive.
        if !self.fcf_alive() {
            return;
        }
        // As we sent a new packet, start the timeout.
        if self.fcf_next_timeout.is_none() {
            self.fcf_next_timeout = self
                .fall_back_delay
                .as_ref()
                .and_then(|d| d.to_duration())
                .map(|d| now + d);
        }
    }

    /// Get the last packet number received on the flexicast flow while in it.
    #[inline]
    pub fn get_last_pn_recv_in_flow(&self) -> Option<u64> {
        self.fcf_max_pn_recv_in_flow
    }

    /// Update the fallback delay based on the current RTT on the multicast flow
    /// with the receiver. Only does something if
    /// [`FcFallBackDelay::Adaptive`].
    ///
    /// Returns the new ack delay if modified, used for logging.
    pub fn update_fallback_delay(&mut self, rtt: u64) -> Option<u64> {
        if let Some(FcFallBackDelay::Adaptive(fb_delay)) =
            self.fall_back_delay.as_mut()
        {
            let old_fb_delay = *fb_delay;
            // The timer is set to `FALLBACK_DELAY_MULTIPLIER` times the RTT.
            *fb_delay = (rtt * FALLBACK_DELAY_MULTIPLIER).max(20);

            let now = time::Instant::now();
            if self.fcf_next_timeout.is_some() {
                self.fcf_next_timeout =
                    Some(now + time::Duration::from_millis(*fb_delay));
            }

            if old_fb_delay != *fb_delay {
                return Some(*fb_delay);
            }
        }

        None
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
        let delay = FcFallBackDelay::Static(300);
        let now = time::Instant::now();
        let mut c = Box::new(Dummy::default());

        let mut scheduler =
            FcFlowAliveScheduler::new(Some(delay.clone()), Some(now));
        assert!(scheduler.fcf_alive());
        assert!(!scheduler.should_uc_fall_back(now));
        let delay = delay.to_duration().unwrap();

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

        // Since we did not get feedback for the second packet flight, we fall
        // back again.
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
