use crate::{packet::Epoch, ranges};
use crate::Result;
use std::time::{Duration, Instant};

use super::{HandshakeStatus, SpaceId};

/// Multicast extension of the recovery mechanism of QUIC.
/// This extension attempts to add partial reliability to
/// the multicast extension of QUIC.
pub trait MulticastRecovery {
    /// Removes multicast data that passes above a defined time threshold.
    fn mc_data_timeout(&mut self, space_id: SpaceId, now: Instant, ttl: Duration, handshake_status: HandshakeStatus) -> Result<()>;
}

impl MulticastRecovery for crate::recovery::Recovery {
    fn mc_data_timeout(&mut self, space_id: SpaceId, now: Instant, ttl: Duration, handshake_status: HandshakeStatus) -> Result<()> {
        let mut expired_sent = self.sent[Epoch::Application]
        .iter()
        .take_while(|p| now.saturating_duration_since(p.time_sent) >= ttl)
        .filter(|p| p.time_acked.is_none());
        
        // Take the first and last sent from the iterator.
        // We will make a range for all of them.
        match expired_sent.next() {
            None => (),
            Some(first) => {
                // Create a dummy ack to remove the expired data.
                let mut acked = ranges::RangeSet::default();
                let last = match expired_sent.last() {
                    Some(l) => l,
                    None => first,
                };
                // MC-TODO: be sure that we ack multicast data.
                acked.insert((first.pkt_num.1)..(last.pkt_num.1 + 1));

                self.on_ack_received(space_id, &acked, ttl.as_millis() as u64, Epoch::Application, handshake_status, now, "")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;
    use crate::{recovery::{Recovery, CongestionControlAlgorithm, Sent, HandshakeStatus, SpacedPktNum}, ranges};

    #[test]
    fn mc_data_timeout() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::DISABLED);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();
        let data_expiration = Duration::from_millis(100);

        assert_eq!(r.sent[Epoch::Application].len(), 0);

        // Start by sending a few packets separated by 10ms each.
        let p = Sent {
            pkt_num: SpacedPktNum(0, 0),
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            has_data: false,
        };

        r.on_packet_sent(
            p,
            Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[Epoch::Application].len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);

        let p = Sent {
            pkt_num: SpacedPktNum(0, 1),
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            has_data: false,
        };

        r.on_packet_sent(
            p,
            Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[Epoch::Application].len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);

        let p = Sent {
            pkt_num: SpacedPktNum(0, 2),
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            has_data: false,
        };

        r.on_packet_sent(
            p,
            Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[Epoch::Application].len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        now += Duration::from_millis(10);

        let p = Sent {
            pkt_num: SpacedPktNum(0, 3),
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            has_data: false,
        };

        r.on_packet_sent(
            p,
            Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[Epoch::Application].len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Only the first 2 packets are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                ""
            ),
            Ok((0, 0))
        );

        assert_eq!(r.sent[Epoch::Application].len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);
        assert_eq!(r.lost_count, 0);

        // Wait until the third packet contains expired data, but not the fourth.
        now += data_expiration - Duration::from_millis(10);

        // Filter the expired data.
        // Expect to have packet with packet number 2 timeout.
        let res = r.mc_data_timeout(0, now, data_expiration, HandshakeStatus::default());
        assert!(res.is_ok());

        assert_eq!(r.sent[Epoch::Application].len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        // MC-TODO: I don't understand the meaning of the loss probes.
        assert_eq!(r.loss_probes[Epoch::Application], 1);
        assert_eq!(r.sent[Epoch::Application].len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);
        assert_eq!(r.pto_count, 1);

        let p = Sent {
            pkt_num: SpacedPktNum(0, 4),
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            has_data: false,
        };

        r.on_packet_sent(
            p,
            Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[Epoch::Application].len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);

        now += Duration::from_millis(10);
        acked.insert(4..5);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                ""
            ),
            Ok((1, 1000))
        );

        assert_eq!(r.sent[Epoch::Application].len(), 2);
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.lost_count, 1);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_lost_packets(Epoch::Application, now, "");

        assert_eq!(r.sent[Epoch::Application].len(), 0);

    }
}