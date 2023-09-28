use networkcoding::source_symbol_metadata_to_u64;

use crate::frame;
use crate::multicast::reliable::ReliableMulticastConnection;
use crate::multicast::ExpiredPkt;
use crate::multicast::ExpiredStream;
use crate::multicast::MulticastError;
use crate::packet::Epoch;
use crate::ranges;
use crate::stream::StreamMap;
use crate::Connection;
use crate::Error;
use crate::Result;
use std::time::Duration;
use std::time::Instant;

use super::Acked;
use super::HandshakeStatus;
use super::SpaceId;

/// Multicast extension of the recovery mechanism of QUIC.
/// This extension attempts to add partial reliability to
/// the multicast extension of QUIC.
pub trait MulticastRecovery {
    /// Removes multicast data that passes above a defined time threshold.
    ///
    /// Returns the maximum packet number and the FEC Source Symbol ID expired.
    fn mc_data_timeout(
        &mut self, space_id: SpaceId, now: Instant, ttl: u64,
        handshake_status: HandshakeStatus, newly_acked: &mut Vec<Acked>,
    ) -> Result<(ExpiredPkt, ExpiredStream)>;

    /// Returns the next expiring event.
    fn mc_next_timeout(&self, ttl_data: std::time::Duration) -> Option<Instant>;

    /// Sets the multicast maximum congestion window size.
    fn set_mc_max_cwnd(&mut self, cwnd: usize);

    /// Returns the stream IDs that are expired.
    ///
    /// For the server, exactly returns all expired stream IDs based on the
    /// maximum expired packet number and the sent packets.
    fn mc_get_sent_exp_stream_ids(
        &self, pn: u64, space_id: SpaceId,
    ) -> ExpiredStream;

    /// Returns the time sent of the packet with packet number given as
    /// argument.
    fn mc_get_time_sen(&self, pn: u64) -> Option<Instant>;
}

impl MulticastRecovery for crate::recovery::Recovery {
    fn mc_data_timeout(
        &mut self, space_id: SpaceId, now: Instant, ttl: u64,
        handshake_status: HandshakeStatus, newly_acked: &mut Vec<Acked>,
    ) -> Result<(ExpiredPkt, ExpiredStream)> {
        let mut expired_sent = self.sent[Epoch::Application]
            .iter()
            .take_while(|p| {
                now.saturating_duration_since(p.time_sent) >=
                    Duration::from_millis(ttl)
            })
            .filter(|p| p.time_acked.is_none() && p.pkt_num.0 == space_id);

        let mut expired_streams = ExpiredStream::new();

        // Get the highest expired FEC metadata.
        let exp3 = expired_sent.clone();
        let fec_medatadas = exp3.flat_map(|p| {
            p.frames.as_ref().iter().filter_map(|f| match f {
                crate::frame::Frame::SourceSymbolHeader { metadata, .. } =>
                    Some(source_symbol_metadata_to_u64(*metadata)),
                _ => None,
            })
        });
        let expired_ssid: Option<u64> = fec_medatadas.max();

        // Take the first and last sent from the iterator.
        // We will make a range for all of them.
        match expired_sent.next() {
            None => Ok((
                ExpiredPkt {
                    pn: None,
                    ssid: None,
                },
                expired_streams,
            )),
            Some(first) => {
                // Create a dummy ack to remove the expired data.
                let mut acked = ranges::RangeSet::default();
                let last = match expired_sent.last() {
                    Some(l) => l,
                    None => first,
                };

                // Retrieve the list of expired streams based on the last expired
                // packet number.
                expired_streams =
                    self.mc_get_sent_exp_stream_ids(last.pkt_num.1, space_id);

                // MC-TODO: be sure that we ack multicast data.
                acked.insert((first.pkt_num.1)..(last.pkt_num.1 + 1));
                let expired_pn = Some(last.pkt_num.1);

                let cwnd_before = self.congestion_window;

                println!("Before on_ack_received");
                
                self.on_ack_received(
                    space_id,
                    &acked,
                    ttl,
                    Epoch::Application,
                    handshake_status,
                    now,
                    "",
                    newly_acked,
                )?;
                
                println!("RELIABLE MULTICAST. Expiration: increase window {} -> {} and available is {}", cwnd_before, self.congestion_window, self.cwnd_available());

                Ok((
                    ExpiredPkt {
                        pn: expired_pn,
                        ssid: expired_ssid,
                    },
                    expired_streams,
                ))
            },
        }
    }

    fn mc_next_timeout(&self, ttl_data: std::time::Duration) -> Option<Instant> {
        // MC-TODO: be sure that `front()` is correct and not `back`.

        let a = self.sent[Epoch::Application].back()?.time_sent;
        let b = self.sent[Epoch::Application].front()?.time_sent;
        debug!(
            "This sent of last packet and first packet: {:?} vs {:?}",
            a, b
        );
        debug!("Mais la somme: {:?}", b.checked_add(ttl_data));
        b.checked_add(ttl_data)
    }

    fn set_mc_max_cwnd(&mut self, cwnd: usize) {
        self.mc_cwnd = Some(cwnd);
        self.reset();
    }

    fn mc_get_sent_exp_stream_ids(
        &self, pn: u64, space_id: SpaceId,
    ) -> ExpiredStream {
        self.sent[Epoch::Application]
            .iter()
            .take_while(|p| p.pkt_num.1 <= pn)
            .filter(|p| p.time_acked.is_none() && p.pkt_num.0 == space_id)
            .flat_map(|p| {
                p.frames.as_ref().iter().filter_map(|f| match f {
                    crate::frame::Frame::StreamHeader { stream_id, .. } =>
                        Some(*stream_id),
                    _ => None,
                })
            })
            .collect()
    }

    fn mc_get_time_sen(&self, pn: u64) -> Option<Instant> {
        self.sent[Epoch::Application]
            .iter()
            .find(|pkt| pkt.pkt_num.1 == pn)
            .map(|pkt| pkt.time_sent)
    }
}

/// Reliable extensions of the recovery mechanism of Multicast QUIC.
/// This extension attempts to add full reliability to
/// the multicast extension of QUIC.
pub trait ReliableMulticastRecovery {
    /// Deleguates the streams to the unicast connection.
    ///
    /// Returns the number of STREAM frames lost that will be retransmitted to
    /// the client on the unicast path.
    fn deleguate_stream(
        &mut self, uc: &mut Connection, now: Instant, expiration_timer: u64,
        space_id: u32, local_streams: &mut StreamMap,
    ) -> Result<u64>;
}

impl ReliableMulticastRecovery for crate::recovery::Recovery {
    fn deleguate_stream(
        &mut self, uc: &mut Connection, now: Instant, expiration_timer: u64,
        space_id: u32, local_streams: &mut StreamMap,
    ) -> Result<u64> {
        let recv_pn = uc.rmc_get_recv_pn()?.to_owned();
        let reco_ss = uc.rmc_get_rec_ss()?.to_owned();
        let mut nb_lost_mc_stream_frames = 0;
        let expired_sent = self.sent[Epoch::Application]
            .iter()
            .take_while(|p| {
                now.saturating_duration_since(p.time_sent) >=
                    Duration::from_millis(expiration_timer)
            })
            .filter(|p| p.time_acked.is_none() && p.pkt_num.0 == space_id);

        'per_packet: for packet in expired_sent {
            // First check if the packet has been received by the client.
            for r in recv_pn.iter() {
                let lowest_recovered_in_block = r.start;
                let largest_recovered_in_block = r.end - 1;
                if packet.pkt_num.1 >= lowest_recovered_in_block &&
                    packet.pkt_num.1 <= largest_recovered_in_block
                {
                    continue 'per_packet; // Packet was received.
                }
            }

            // At this point, we know that the client did not receive the packet.
            // Maybe it recovered it with FEC.
            // FIXME-RMC-TODO: assumes that the SourceSymbolHeader always preceeds
            // the STREAM frame.
            // FIXME-RMC-TODO: assumes that a StreamHeader always preceeds the
            // McAsym frame.
            let mut protected = false;
            let mut protected_stream_id = None;
            for frame in &packet.frames {
                match frame {
                    frame::Frame::SourceSymbolHeader {
                        metadata,
                        recovered: _,
                    } => {
                        let mdu64 = source_symbol_metadata_to_u64(*metadata);
                        for r in reco_ss.iter() {
                            let lowest_recovered_in_block = r.start;
                            let largest_recovered_in_block = r.end - 1;
                            if mdu64 >= lowest_recovered_in_block &&
                                mdu64 <= largest_recovered_in_block
                            {
                                // Packet has been recovered through FEC.
                                continue 'per_packet;
                            }
                        }
                        protected = true;
                    },
                    frame::Frame::StreamHeader {
                        stream_id,
                        offset,
                        length,
                        fin,
                    } => {
                        if !protected {
                            continue 'per_packet;
                        }

                        nb_lost_mc_stream_frames += 1;

                        // This STREAM frame was lost. Retransmit in a (new)
                        // stream on unicast path.
                        let stream = uc.get_or_create_stream(*stream_id, true)?;
                        let was_flushable = stream.is_flushable();
                        let local_stream = local_streams
                            .get_mut(*stream_id)
                            .ok_or(Error::InvalidStreamState(*stream_id))?;

                        // We "ack" the recovery mechanism by asking to retransmit
                        // the specified data... Since we
                        // call "send" on the data that is
                        // retransmitted, we assume that the call
                        // to "retransmit" wil be cancelled out.
                        local_stream.send.retransmit(*offset, *length);

                        // ...and we get the data. This is not optimized (2
                        // copies) but requires the fewest
                        // changes.
                        let mut buf = vec![0u8; *length];
                        local_stream.send.emit(&mut buf)?;

                        let written = stream.send.write_at_offset(
                            &buf[..],
                            *offset,
                            *fin,
                        )?;
                        assert_eq!(written, *length);

                        // Mark the stream as flushable. We do not take into
                        // account flow limits because the
                        // data has already been sent once on
                        // the multicast channel, and this data should be
                        // considered as a retransmission
                        // only.
                        let urgency = stream.urgency;
                        let incr = stream.incremental;
                        if !was_flushable {
                            uc.streams.push_flushable(*stream_id, urgency, incr);
                        }

                        protected_stream_id = Some(*stream_id);
                    },
                    frame::Frame::McAsym { signature } => {
                        // If such a frame is present, it means that multicast
                        // uses per-stream asymmetric authentication, and that the
                        // STREAM frame contained in this packet is the last frame
                        // of this stream.
                        //
                        // Getting an MC_ASYM frame without the stream it
                        // authenticates is an error.
                        // RMC-TODO: maybe the StreamHeader frame follows this
                        // frame?
                        let stream_id = protected_stream_id.ok_or(
                            Error::Multicast(MulticastError::McInvalidAuth),
                        )?;

                        let stream = uc.get_or_create_stream(stream_id, true)?;

                        stream.mc_set_asym_sign(signature);
                    },
                    _ => (),
                }
            }
        }

        Ok(nb_lost_mc_stream_frames)
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
                "",
                &mut Vec::new(),
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
            &mut Vec::new(),
        );
        assert_eq!(res, Ok(((Some(2), Some(2)).into(), [9].into())));

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
                "",
                &mut Vec::new(),
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
