#[cfg(feature = "qlog")]
use qlog::events::quic::TransportEventType;
#[cfg(feature = "qlog")]
use qlog::events::EventData;
#[cfg(feature = "qlog")]
use qlog::events::EventImportance;
#[cfg(feature = "qlog")]
use qlog::events::EventType;
#[cfg(feature = "qlog")]
const QLOG_DATA_MV: EventType =
    EventType::TransportEventType(TransportEventType::DataMoved);

use networkcoding::source_symbol_metadata_to_u64;

use crate::frame;
use crate::frame::Frame;
use crate::multicast::ack::McAck;
use crate::multicast::reliable::ReliableMulticastConnection;
use crate::multicast::ExpiredPkt;
use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::stream::StreamMap;
use crate::Connection;
use crate::Error;
use crate::Result;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use super::HandshakeStatus;
use super::LostFrame;
use super::Recovery;
use super::SpaceId;

/// Multicast extension of the recovery mechanism of QUIC.
/// This extension attempts to add partial reliability to
/// the multicast extension of QUIC.
pub trait MulticastRecovery {
    /// Removes multicast data that passes above a defined time threshold.
    ///
    /// Returns the maximum packet number and the FEC Source Symbol ID expired.
    #[allow(clippy::too_many_arguments)]
    fn mc_data_timeout(
        &mut self, space_id: SpaceId, now: Instant, ttl: u64,
        handshake_status: HandshakeStatus,
    ) -> Result<ExpiredPkt>;

    #[allow(unused)]
    /// Returns the next expiring event.
    fn mc_next_timeout(
        &self, expiration_timer: std::time::Duration,
    ) -> Option<Instant>;

    /// Sets the multicast maximum congestion window size.
    fn set_mc_max_cwnd(&mut self, cwnd: usize);
}

impl crate::recovery::Recovery {
    pub fn dump_sent(&self, s: &str) {
        debug!(
            "{}: {:?}",
            s,
            self.sent[Epoch::Application]
                .iter()
                .map(|s| s.pkt_num.1)
                .collect::<Vec<_>>()
        );
    }
}

impl MulticastRecovery for crate::recovery::Recovery {
    fn mc_data_timeout(
        &mut self, space_id: SpaceId, now: Instant, timer: u64,
        handshake_status: HandshakeStatus,
    ) -> Result<ExpiredPkt> {
        let mut expired_sent = self.sent[Epoch::Application]
            .iter()
            .take_while(|p| {
                now.saturating_duration_since(p.time_sent) >=
                    Duration::from_millis(timer)
            })
            .filter(|p| p.time_acked.is_none() && p.pkt_num.0 == space_id);

        self.dump_sent("All elements at the beginning of MC_DATA_TIMEOUT");

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
        match expired_sent.next() {
            None => Ok(ExpiredPkt {
                pn: None,
                ssid: None,
            }),
            Some(first) => {
                // Create a dummy ack to remove the expired data.();
                let last = match expired_sent.last() {
                    Some(l) => l,
                    None => first,
                };
                let expired_pn = Some(last.pkt_num.1);
                let (_lost_packets, _lost_bytes) =
                    self.on_loss_detection_timeout(handshake_status, now, "");

                Ok(ExpiredPkt {
                    pn: expired_pn,
                    ssid: expired_ssid,
                })
            },
        }
    }

    fn mc_next_timeout(
        &self, expiration_timer: std::time::Duration,
    ) -> Option<Instant> {
        // MC-TODO: be sure that `front()` is correct and not `back`.

        let a = self.sent[Epoch::Application].back()?.time_sent;
        let b = self.sent[Epoch::Application].front()?.time_sent;
        debug!(
            "This sent of last packet and first packet: {:?} vs {:?}",
            a, b
        );
        debug!("Mais la somme: {:?}", b.checked_add(expiration_timer));
        b.checked_add(expiration_timer)
    }

    fn set_mc_max_cwnd(&mut self, cwnd: usize) {
        self.mc_cwnd = Some(cwnd);
        self.reset();
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
        &mut self, uc: &mut Connection, space_id: u32,
        local_streams: &mut StreamMap, mc_ack: &mut McAck,
    ) -> Result<(u64, (RangeSet, RangeSet))>;

    #[allow(unused)]
    /// Mark all packets in flight in [`Epoch::Application`] up to the precised
    /// packet number.
    fn mark_inflight_as_lost_app_up_to(
        &mut self, now: Instant, trace_id: &str, pn: u64,
    ) -> (usize, usize);

    /// Transfers to the unicast servers the frames sent on the multicast
    /// channel. This is used to allow each unicast server to compute its
    /// congestion window using the data sent by the multicast source.
    fn copy_sent(
        &self, uc: &mut Recovery, space_id: u32, epoch: Epoch,
        handshake_status: HandshakeStatus, trace_id: &str, cur_max_pn: u64,
    ) -> u64;
}

impl ReliableMulticastRecovery for crate::recovery::Recovery {
    fn deleguate_stream(
        &mut self, uc: &mut Connection, space_id: u32,
        local_streams: &mut StreamMap, mc_ack: &mut McAck,
    ) -> Result<(u64, (RangeSet, RangeSet))> {
        let recv_pn = uc.rmc_get_recv_pn()?.to_owned();
        let mut lost_pn = RangeSet::default();
        let reco_ss = uc.rmc_get_rec_ss()?.to_owned();
        debug!(
            "Start deleguate stream for client {:?}. recv_pn={:?}",
            uc.multicast.as_ref().map(|m| m.get_self_client_id()),
            recv_pn
        );

        let mut nb_lost_mc_stream_frames = 0;
        let lost_iter = self.sent[Epoch::Application]
            .iter_mut()
            .take_while(|p| {
                (p.time_lost.is_some() || p.time_acked.is_some()) &&
                    p.pkt_num.0 == space_id
            })
            .filter(|p| p.time_lost.is_some() && p.pkt_num.0 == space_id);

        let mut max_exp_pn: Option<u64> = None;
        let mut max_exp_ss: Option<u64> = None;

        'per_packet: for packet in lost_iter {
            debug!(
                "This is a packet that is lost: {:?} with frames: {:?}",
                packet.pkt_num, packet.frames
            );

            // Indicate that this packet was delegated through unicast.
            packet.is_fc_delegated = true;

            max_exp_pn = if let Some(c) = max_exp_pn {
                Some(c.max(packet.pkt_num.1))
            } else {
                Some(packet.pkt_num.1)
            };
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
            lost_pn.insert(packet.pkt_num.1..packet.pkt_num.1 + 1);
            debug!("Packet was lost");

            // At this point, we know that the client did not receive the packet.
            // Maybe it recovered it with FEC.
            // FIXME-RMC-TODO: assumes that the SourceSymbolHeader always preceeds
            // the STREAM frame.
            // FIXME-RMC-TODO: assumes that a StreamHeader always preceeds the
            // McAsym frame.
            let mut protected_stream_id = None;
            for frame in &packet.frames {
                match frame {
                    frame::Frame::SourceSymbolHeader {
                        metadata,
                        recovered: _,
                    } => {
                        let mdu64 = source_symbol_metadata_to_u64(*metadata);
                        max_exp_ss = if let Some(c) = max_exp_ss {
                            Some(c.max(mdu64))
                        } else {
                            Some(mdu64)
                        };
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
                    },
                    frame::Frame::StreamHeader {
                        stream_id,
                        offset,
                        length,
                        fin,
                    } => {
                        nb_lost_mc_stream_frames += 1;

                        // This STREAM frame was lost. Retransmit in a (new)
                        // stream on unicast path.
                        debug!("Lost STREAM frame. ID={:?}, offset={:?}, length={:?}, fin={:?}", stream_id, offset, length, fin);
                        let is_stream_collected =
                            uc.streams.is_collected(*stream_id);
                        let stream: &mut crate::stream::Stream = match uc
                            .get_or_create_stream(*stream_id, true)
                        {
                            Ok(v) => v,
                            Err(Error::Done) if is_stream_collected => continue,
                            Err(e) => return Err(e),
                        };
                        debug!("After getting the stream. Before getting local stream. The ID is {} from pn={}. Is the stream {} bidi={}", *stream_id, packet.pkt_num.1, *stream_id, stream.bidi);
                        let was_flushable = stream.is_flushable();
                        let local_stream = local_streams
                            .get_mut(*stream_id)
                            .ok_or(Error::InvalidStreamState(*stream_id))?;
                        debug!("After getting local stream");
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
                        if let Err(Error::FinalSize) =
                            local_stream.send.emit(&mut buf)
                        {
                            continue;
                        }

                        // Notify the multicast acknowledgment aggregator that we
                        // deleguate a piece of stream.
                        mc_ack.delegate(*stream_id, *offset, *length as u64);

                        // First mark the stream as rotable for unicast
                        // retransmission if it is the case for the flexicast
                        // source.
                        if local_stream.fc_use_stream_rotation() {
                            stream.fc_mark_rotate_retransmission();
                        }

                        let _written = match stream.send.write_at_offset(
                            &buf[..],
                            *offset,
                            *fin,
                        ) {
                            Ok(v) => v,
                            Err(Error::FinalSize) => continue,
                            Err(e) => return Err(e),
                        };

                        // Mark the stream as flushable. We do not take into
                        // account flow limits because the
                        // data has already been sent once on
                        // the multicast channel, and this data should be
                        // considered as a retransmission
                        // only.
                        let priority_key = Arc::clone(&stream.priority_key);
                        if !was_flushable {
                            uc.streams.insert_flushable(&priority_key);
                        }

                        protected_stream_id = Some(*stream_id);
                        if let Some(_client_id) = uc
                            .multicast
                            .as_ref()
                            .and_then(|m| m.get_self_client_id().ok())
                        {
                            qlog_with_type!(QLOG_DATA_MV, uc.qlog, q, {
                                let ev_data_client = EventData::McRetransmit(
                                    qlog::events::quic::McRetransmit {
                                        stream_id: *stream_id,
                                        offset: *offset,
                                        len: *length,
                                        fin: *fin,
                                        client_id: _client_id,
                                    },
                                );

                                q.add_event_data_with_instant(
                                    ev_data_client,
                                    now,
                                )
                                .ok();
                            });
                        }

                        // Notify the unicast instance that this piece of stream
                        // has been deleguated by the flexicast source.
                        if let Some(mc_ack) = uc
                            .multicast
                            .as_mut()
                            .map(|mc| {
                                mc.rmc_get_mut()
                                    .server_mut()
                                    .map(|s| &mut s.mc_ack)
                            })
                            .flatten()
                        {
                            mc_ack.delegate(*stream_id, *offset, *length as u64);
                        }
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
                        if let Some(stream_id) = protected_stream_id {
                            let stream =
                                uc.get_or_create_stream(stream_id, true)?;

                            stream.mc_set_asym_sign(signature);
                        }
                    },
                    _ => (),
                }
            }
        }

        // Close existing streams on the unicast server if their are closed on the
        // multicast source. RMC-TODO: not optimal because we go over the
        // streams again. It should work by iterating over existing
        // finished streams were all data has already been sent. Not sure though.
        let expired_sent = self.sent[Epoch::Application]
            .iter()
            .take_while(|p| {
                (p.time_lost.is_some() || p.time_acked.is_some()) &&
                    p.pkt_num.0 == space_id
            })
            .filter(|p| p.time_lost.is_some() && p.pkt_num.0 == space_id);

        for pkt in expired_sent {
            for frame in pkt.frames.iter() {
                if let Frame::StreamHeader {
                    stream_id,
                    offset,
                    length,
                    fin,
                } = frame
                {
                    if *fin {
                        // If the stream does not exist for the unicast server, it
                        // means that it did not have to
                        // retransmit frames to the client.
                        if let Some(uc_stream) = uc.streams.get_mut(*stream_id) {
                            // debug!(
                            //     "Here setting close offset for stream {:?}",
                            //     stream_id
                            // );
                            uc_stream.send.rmc_set_close_offset();
                            uc_stream
                                .send
                                .rmc_set_fin_off(*offset + *length as u64);

                            // Maybe the stream is now complete.
                            if uc_stream.is_complete() && !uc_stream.is_readable()
                            {
                                let local = uc_stream.local;
                                uc.streams.collect(*stream_id, local);
                            }
                        }
                    }
                }
            }
        }

        uc.rmc_reset_recv_pn_ss(mc_ack.get_largest_pn(), max_exp_ss);

        Ok((nb_lost_mc_stream_frames, (lost_pn, recv_pn)))
    }

    fn mark_inflight_as_lost_app_up_to(
        &mut self, now: Instant, trace_id: &str, pn: u64,
    ) -> (usize, usize) {
        let mut lost_packets = 0;
        let mut lost_bytes = 0;
        let e = Epoch::Application;
        let mut epoch_lost_bytes = 0;
        let mut largest_lost_pkt = None;
        let idx_last_exp = self.sent[e]
            .iter()
            .map(|s| s.pkt_num.1)
            .position(|s| s == pn)
            .unwrap();
        for sent in self.sent[e].drain(0..idx_last_exp) {
            let last_expired = sent.pkt_num.1 >= pn;
            if sent.time_acked.is_none() {
                let mut contains_recovered_source_symbol = false;
                for frame in &sent.frames {
                    if let frame::Frame::SourceSymbolHeader {
                        recovered, ..
                    } = frame
                    {
                        if *recovered {
                            contains_recovered_source_symbol = true;
                        }
                    }

                    if contains_recovered_source_symbol {
                        self.lost[e]
                            .push(LostFrame::LostAndRecovered(frame.clone()))
                    } else {
                        self.lost[e].push(LostFrame::Lost(frame.clone()))
                    }
                }
                // self.lost[e].extend_from_slice(&sent.frames);
                if sent.in_flight {
                    epoch_lost_bytes += sent.size;

                    self.in_flight_count[e] =
                        self.in_flight_count[e].saturating_sub(1);

                    trace!(
                        "{} packet {:?} lost on epoch {}",
                        trace_id,
                        sent.pkt_num,
                        e
                    );

                    // Frames have already been removed from the packet.
                    largest_lost_pkt = Some(sent);
                }

                lost_packets += 1;
                self.lost_count += 1;
            }

            // Stop the loop if we expired the last packet.
            if last_expired {
                break;
            }
        }

        self.bytes_lost += epoch_lost_bytes as u64;
        lost_bytes += epoch_lost_bytes;

        if let Some(pkt) = largest_lost_pkt {
            self.on_packets_lost(lost_bytes, &pkt, e, now);
        }

        (lost_packets, lost_bytes)
    }

    fn copy_sent(
        &self, uc: &mut Recovery, space_id: u32, epoch: Epoch,
        handshake_status: HandshakeStatus, trace_id: &str, cur_max_pn: u64,
    ) -> u64 {
        let new_max_pn = self.sent[Epoch::Application]
            .back()
            .map(|s| s.pkt_num.1)
            .unwrap_or(0);
        let sent_pkts = self.sent[epoch]
            .iter()
            .filter(|s| s.pkt_num.0 == space_id && s.pkt_num.1 >= cur_max_pn);
        for pkt in sent_pkts {
            trace!(
                "{:?}: Add new packet to unicast: {:?}",
                trace_id,
                pkt.pkt_num
            );
            uc.on_packet_sent(
                pkt.clone(),
                epoch,
                handshake_status,
                pkt.time_sent,
                trace_id,
            );
        }

        new_max_pn + 1
    }
}

impl Recovery {
    /// Returns the lowest packet number still in the sending queue of the
    /// Application Epoch on the provided space ID.
    pub fn get_lowest_pn_app_epoch(&self, space_id: u32) -> Option<u64> {
        self.sent[Epoch::Application]
            .iter()
            .filter(|pkt| pkt.pkt_num.0 == space_id)
            .map(|pkt| pkt.pkt_num.1)
            .min()
    }

    /// Returns a copy of the packets sent.
    /// Only returns once each packet, and assumes that the caller already
    /// processed previously sent ones. Also returns the new paximum packet
    /// number.
    pub fn fc_get_sent_pkt(
        &self, space_id: u32, epoch: Epoch, max_pn: u64,
    ) -> (u64, Vec<super::Sent>) {
        let new_max_pn = self.sent[Epoch::Application]
            .back()
            .map(|s| s.pkt_num.1)
            .unwrap_or(0);

        let sent = self.sent[epoch]
            .iter()
            .filter(|s| s.pkt_num.0 == space_id && s.pkt_num.1 >= max_pn)
            .map(|s| s.to_owned())
            .collect();
        (new_max_pn, sent)
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
            tx_in_flight: 0,
            lost: 0,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
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
            tx_in_flight: 0,
            lost: 0,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
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
            tx_in_flight: 0,
            lost: 0,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
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
            tx_in_flight: 0,
            lost: 0,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
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
        );
        assert_eq!(res, Ok((Some(2), Some(2)).into()));

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
            tx_in_flight: 0,
            lost: 0,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
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

    #[test]
    fn test_mc_recovery_ack_pos_then_neg() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);

        let now = Instant::now();

        assert_eq!(r.sent[Epoch::Application].len(), 0);
        assert_eq!(r.congestion_window, 12_000);

        // Send 12 packets.
        for i in 0..12 {
            let p = Sent {
                pkt_num: SpacedPktNum(0, i),
                frames: smallvec![
                    get_test_stream_header(1 + i * 4),
                    get_test_source_symbol_header(0),
                ],
                time_sent: now + Duration::from_millis(10 * i),
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
                tx_in_flight: 0,
                lost: 0,
                retransmitted_for_probing: false,
                is_fc_delegated: false,
            };

            r.on_packet_sent(
                p,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
            assert_eq!(r.sent[Epoch::Application].len(), i as usize + 1);
            assert_eq!(r.bytes_in_flight, 1000 * (i as usize + 1));
        }

        let mut acked = RangeSet::default();
        acked.insert(0..12);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new()
            ),
            Ok((0, 0))
        );

        assert_eq!(r.congestion_window, 24_000);
        assert_eq!(r.sent[Epoch::Application].len(), 0);

        // Second round.
        // Send 24 packets.
        for i in 12..36 {
            let p = Sent {
                pkt_num: SpacedPktNum(0, i),
                frames: smallvec![
                    get_test_stream_header(1 + i * 4),
                    get_test_source_symbol_header(0),
                ],
                time_sent: now + Duration::from_millis(10 * i),
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
                tx_in_flight: 0,
                lost: 0,
                retransmitted_for_probing: false,
                is_fc_delegated: false,
            };

            r.on_packet_sent(
                p,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
            assert_eq!(r.sent[Epoch::Application].len(), i as usize + 1 - 12);
            assert_eq!(r.bytes_in_flight, 1000 * (i as usize + 1) - 12_000);
        }

        let mut acked = RangeSet::default();
        acked.insert(12..36);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new()
            ),
            Ok((0, 0))
        );

        assert_eq!(r.congestion_window, 48_000);
        assert_eq!(r.sent[Epoch::Application].len(), 0);

        // Now lost packets.
        // Send 48 packets.
        for i in 36..84 {
            let p = Sent {
                pkt_num: SpacedPktNum(0, i),
                frames: smallvec![
                    get_test_stream_header(1 + i * 4),
                    get_test_source_symbol_header(0),
                ],
                time_sent: now + Duration::from_millis(10 * i),
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
                tx_in_flight: 0,
                lost: 0,
                retransmitted_for_probing: false,
                is_fc_delegated: false,
            };

            r.on_packet_sent(
                p,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
            assert_eq!(r.sent[Epoch::Application].len(), i as usize + 1 - 36);
            assert_eq!(r.bytes_in_flight, 1000 * (i as usize + 1) - 36_000);
        }

        assert_eq!(r.sent[Epoch::Application].len(), 48);

        let mut acked = RangeSet::default();
        acked.insert(36..40);
        acked.insert(70..75);
        acked.insert(81..83);
        let mut lost = RangeSet::default();
        // lost.insert(40..70);
        // lost.insert(75..81);
        lost.insert(44..84);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new()
            ),
            Ok((35, 35_000)) /* Why does this value change when increasing the
                              * number of received packets at the max? */
        );

        assert_eq!(r.congestion_window, 33_600);
        // 48 sent packets, but the 4 first are ack "in order".
        assert_eq!(r.sent[Epoch::Application].len(), 44);

        let exp = now + Duration::from_millis(500);
        assert_eq!(
            r.on_ack_received(
                0,
                &lost,
                25,
                Epoch::Application,
                HandshakeStatus::default(),
                exp,
                "",
                &mut Vec::new()
            ),
            Ok((0, 0))
        );

        assert_eq!(r.congestion_window, 33_600);
        assert_eq!(r.sent[Epoch::Application].len(), 0);
        assert_eq!(r.bytes_in_flight, 0);

        // Some more losses but where the losses do occur at the end.
        // The congestion controller increases its window.
        // Send 34 packets.
        for i in 100..134 {
            let p = Sent {
                pkt_num: SpacedPktNum(0, i),
                frames: smallvec![
                    get_test_stream_header(1 + i * 4),
                    get_test_source_symbol_header(0),
                ],
                time_sent: now + Duration::from_millis(10 * i),
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
                tx_in_flight: 0,
                lost: 0,
                retransmitted_for_probing: false,
                is_fc_delegated: false,
            };

            r.on_packet_sent(
                p,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
            assert_eq!(r.sent[Epoch::Application].len(), i as usize + 1 - 100);
            assert_eq!(r.bytes_in_flight, 1000 * (i as usize + 1 - 100));
        }

        let mut acked = RangeSet::default();
        acked.insert(100..120);
        let mut lost = RangeSet::default();
        lost.insert(120..134);
        let exp = now + Duration::from_millis(500);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new()
            ),
            Ok((0, 0))
        );

        assert_eq!(r.congestion_window, 33_600);

        assert_eq!(
            r.on_ack_received(
                0,
                &lost,
                25,
                Epoch::Application,
                HandshakeStatus::default(),
                exp,
                "",
                &mut Vec::new()
            ),
            Ok((0, 0))
        );

        assert_eq!(r.congestion_window, 37_200);
    }

    #[test]
    fn test_mc_data_timeout_only_complete_streams() {
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
            tx_in_flight: 0,
            lost: 0,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
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
                Frame::StreamHeader {
                    stream_id: 5,
                    offset: 0,
                    length: 100,
                    fin: false,
                },
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
            tx_in_flight: 0,
            lost: 0,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
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
            tx_in_flight: 0,
            lost: 0,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
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
            tx_in_flight: 0,
            lost: 0,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
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
        assert_eq!(res, Ok((Some(2), Some(2)).into()));

        assert_eq!(r.sent[Epoch::Application].len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);
    }
}
