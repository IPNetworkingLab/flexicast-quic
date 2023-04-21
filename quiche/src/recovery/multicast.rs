use networkcoding::source_symbol_metadata_to_u64;

use crate::packet::Epoch;
use crate::ranges;
use crate::Result;
use std::time::Duration;
use std::time::Instant;

use super::HandshakeStatus;
use super::SpaceId;

/// Multicast extension of the recovery mechanism of QUIC.
/// This extension attempts to add partial reliability to
/// the multicast extension of QUIC.
pub trait MulticastRecovery {
    /// Removes multicast data that passes above a defined time threshold.
    fn mc_data_timeout(
        &mut self, space_id: SpaceId, now: Instant, ttl: u64,
        handshake_status: HandshakeStatus,
    ) -> Result<(Option<u64>, Option<u64>, Option<u64>)>;

    /// Returns the next expiring event.
    fn mc_next_timeout(&self, ttl_data: std::time::Duration) -> Option<Instant>;

    /// Sets the multicast maximum congestion window size.
    fn set_mc_max_cwnd(&mut self, cwnd: usize);
}

impl MulticastRecovery for crate::recovery::Recovery {
    fn mc_data_timeout(
        &mut self, space_id: SpaceId, now: Instant, ttl: u64,
        handshake_status: HandshakeStatus,
    ) -> Result<(Option<u64>, Option<u64>, Option<u64>)> {
        let mut expired_sent = self.sent[Epoch::Application]
            .iter()
            .take_while(|p| {
                now.saturating_duration_since(p.time_sent) >=
                    Duration::from_millis(ttl)
            })
            .filter(|p| p.time_acked.is_none() && p.pkt_num.0 == space_id);

        // Get the last stream ID which is impacted by the timeout.
        let exp2 = expired_sent.clone();
        let stream_ids = exp2.flat_map(|p| {
            p.frames.as_ref().iter().filter_map(|f| match f {
                crate::frame::Frame::StreamHeader { stream_id, .. } =>
                    Some(*stream_id),
                _ => None,
            })
        });
        let stream_id_removed = stream_ids.max();

        // Get the highest expired FEC metadata.
        let exp3 = expired_sent.clone();
        let fec_medatadas = exp3.flat_map(|p| {
            p.frames.as_ref().iter().filter_map(|f| match f {
                crate::frame::Frame::SourceSymbolHeader { metadata, .. } =>
                    Some(source_symbol_metadata_to_u64(*metadata)),
                _ => None,
            })
        });
        let fec_metadata_removed: Option<u64> = fec_medatadas.max();

        // Take the first and last sent from the iterator.
        // We will make a range for all of them.
        match expired_sent.next() {
            None => Ok((None, None, None)),
            Some(first) => {
                // Create a dummy ack to remove the expired data.
                let mut acked = ranges::RangeSet::default();
                let last = match expired_sent.last() {
                    Some(l) => l,
                    None => first,
                };
                // MC-TODO: be sure that we ack multicast data.
                acked.insert((first.pkt_num.1)..(last.pkt_num.1 + 1));
                let pkt_num_removed = last.pkt_num.1;

                self.on_ack_received(
                    space_id,
                    &acked,
                    ttl,
                    Epoch::Application,
                    handshake_status,
                    now,
                    "",
                )?;

                Ok((
                    Some(pkt_num_removed),
                    stream_id_removed,
                    fec_metadata_removed,
                ))
            },
        }
    }

    fn mc_next_timeout(&self, ttl_data: std::time::Duration) -> Option<Instant> {
        // MC-TODO: be sure that `front()` is correct and not `back`.
        println!("dddddd {:?}. Duration is {:?}", self.sent[Epoch::Application].back()?.pkt_num, ttl_data);

        let a = self.sent[Epoch::Application].back()?.time_sent;
        let b = self.sent[Epoch::Application].front()?.time_sent;
        debug!("This sent of last packet and first packet: {:?} vs {:?}", a, b);
        debug!("Mais la somme: {:?}", b.checked_add(ttl_data));
        b.checked_add(ttl_data)
    }

    fn set_mc_max_cwnd(&mut self, cwnd: usize) {
        self.mc_cwnd = Some(cwnd);
        self.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;
    use crate::ranges;
    use crate::recovery::CongestionControlAlgorithm;
    use crate::recovery::HandshakeStatus;
    use crate::recovery::Recovery;
    use crate::recovery::Sent;
    use crate::recovery::SpacedPktNum;
    use networkcoding::source_symbol_metadata_from_u64;
    use smallvec::smallvec;
    use std::time::Duration;

    /// Helper creating a small [`StreamHeader`] from a stream ID.
    /// The generated [`StreamHeader`] is unique with `fin` set.
    fn get_test_stream_header(stream_id: u64) -> Frame {
        Frame::StreamHeader {
            stream_id,
            offset: 0,
            length: 100,
            fin: true,
        }
    }

    /// Helper creating a small [`SourceSymbolHeader`] from a metadata.
    fn get_test_source_symbol_header(metadata: u64) -> Frame {
        Frame::SourceSymbolHeader {
            metadata: source_symbol_metadata_from_u64(metadata),
            recovered: false,
        }
    }

    #[test]
    fn test_mc_data_timeout() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::DISABLED);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();
        let data_expiration_val = 100;
        let data_expiration = Duration::from_millis(data_expiration_val);

        assert_eq!(r.sent[Epoch::Application].len(), 0);

        // Start by sending a few packets separated by 10ms each.
        let p = Sent {
            pkt_num: SpacedPktNum(0, 0),
            frames: smallvec![
                get_test_stream_header(1),
                get_test_source_symbol_header(0)
            ],
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
            retransmitted_for_probing: false,
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
            frames: smallvec![
                get_test_stream_header(5),
                get_test_source_symbol_header(1)
            ],
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
            retransmitted_for_probing: false,
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
            frames: smallvec![
                get_test_stream_header(9),
                get_test_source_symbol_header(2)
            ],
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
            retransmitted_for_probing: false,
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
            frames: smallvec![
                get_test_stream_header(13),
                get_test_source_symbol_header(3)
            ],
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
            retransmitted_for_probing: false,
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
        let res = r.mc_data_timeout(
            0,
            now,
            data_expiration_val,
            HandshakeStatus::default(),
        );
        assert_eq!(res, Ok((Some(2), Some(9), Some(2))));

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
            frames: smallvec![
                get_test_stream_header(17),
                get_test_source_symbol_header(4)
            ],
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
            retransmitted_for_probing: false,
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
