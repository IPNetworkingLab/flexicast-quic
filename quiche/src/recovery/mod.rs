// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::cmp;

use std::str::FromStr;

use std::time::Duration;
use std::time::Instant;

use std::collections::VecDeque;

use crate::Config;
use crate::Result;

use crate::frame;
use crate::frame::Frame;
use crate::minmax;
use crate::packet;
use crate::ranges;

use networkcoding::source_symbol_metadata_to_u64;
#[cfg(feature = "qlog")]
use qlog::events::EventData;

use smallvec::SmallVec;

// Loss Recovery
const INITIAL_PACKET_THRESHOLD: u64 = 3;

const MAX_PACKET_THRESHOLD: u64 = 20;

const INITIAL_TIME_THRESHOLD: f64 = 9.0 / 8.0;

const GRANULARITY: Duration = Duration::from_millis(1);

const INITIAL_RTT: Duration = Duration::from_millis(333);

const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

const RTT_WINDOW: Duration = Duration::from_secs(300);

const MAX_PTO_PROBES_COUNT: usize = 2;

const MINIMUM_WINDOW_PACKETS: usize = 2;

const LOSS_REDUCTION_FACTOR: f64 = 0.5;

const PACING_MULTIPLIER: f64 = 1.25;

// How many non ACK eliciting packets we send before including a PING to solicit
// an ACK.
pub(super) const MAX_OUTSTANDING_NON_ACK_ELICITING: usize = 24;

pub type SpaceId = u32;
pub type PktNum = u64;

/// A packet number preceded by its space identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpacedPktNum(SpaceId, PktNum);

impl SpacedPktNum {
    pub fn new(space_id: SpaceId, pkt_num: PktNum) -> Self {
        Self(space_id, pkt_num)
    }

    pub fn pn(&self) -> PktNum {
        self.1
    }
}

pub enum LostFrame {
    Lost(Frame),
    LostAndRecovered(Frame),
}

pub struct Recovery {
    loss_detection_timer: Option<Instant>,

    pto_count: u32,

    time_of_last_sent_ack_eliciting_pkt:
        [Option<Instant>; packet::Epoch::count()],

    largest_acked_pkt: [SpacedPktNum; packet::Epoch::count()],

    largest_sent_pkt: [SpacedPktNum; packet::Epoch::count()],

    latest_rtt: Duration,

    smoothed_rtt: Option<Duration>,

    rttvar: Duration,

    minmax_filter: minmax::Minmax<Duration>,

    min_rtt: Duration,

    pub max_ack_delay: Duration,

    loss_time: [Option<Instant>; packet::Epoch::count()],

    sent: [VecDeque<Sent>; packet::Epoch::count()],

    pub lost: [Vec<LostFrame>; packet::Epoch::count()],

    pub acked: [Vec<frame::Frame>; packet::Epoch::count()],

    pub lost_count: usize,

    pub lost_spurious_count: usize,

    pub loss_probes: [usize; packet::Epoch::count()],

    in_flight_count: [usize; packet::Epoch::count()],

    pub rtt_update_count: usize,

    app_limited: bool,

    delivery_rate: delivery_rate::Rate,

    pkt_thresh: u64,

    time_thresh: f64,

    // Congestion control.
    cc_ops: &'static CongestionControlOps,

    congestion_window: usize,

    bytes_in_flight: usize,

    ssthresh: usize,

    bytes_acked_sl: usize,

    bytes_acked_ca: usize,

    pub bytes_sent: usize,

    pub bytes_lost: u64,

    congestion_recovery_start_time: Option<Instant>,

    max_datagram_size: usize,

    real_time: bool,

    cubic_state: cubic::State,

    // HyStart++.
    hystart: hystart::Hystart,

    // Pacing.
    pub pacer: pacer::Pacer,

    // RFC6937 PRR.
    prr: prr::PRR,

    #[cfg(feature = "qlog")]
    qlog_metrics: QlogMetrics,

    // The maximum size of a data aggregate scheduled and
    // transmitted together.
    send_quantum: usize,

    // BBR state.
    bbr_state: bbr::State,

    // BBRv2 state.
    bbr2_state: bbr2::State,

    /// How many non-ack-eliciting packets have been sent.
    outstanding_non_ack_eliciting: usize,

    /// Maximum congestion window size for the multicast channel.
    mc_cwnd: Option<usize>,

    /// Whether this is the recovery of the Flexicast QUIC source.
    pub(crate) is_fc_source: bool,

    /// Flexicast.
    /// Packet numbers that have been newly acked.
    pub(crate) fc_new_ack_pn: Vec<u64>,

    /// Initial congestion window size in terms of packet count.
    initial_congestion_window_packets: usize,
}

pub struct RecoveryConfig {
    max_send_udp_payload_size: usize,
    pub max_ack_delay: Duration,
    cc_ops: &'static CongestionControlOps,
    hystart: bool,
    pacing: bool,
    real_time: bool,
    max_pacing_rate: Option<u64>,
    initial_congestion_window_packets: usize,
}

impl RecoveryConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_send_udp_payload_size: config.max_send_udp_payload_size,
            max_ack_delay: Duration::ZERO,
            cc_ops: config.cc_algorithm.into(),
            hystart: config.hystart,
            pacing: config.pacing,
            max_pacing_rate: config.max_pacing_rate,
            real_time: config.real_time,
            initial_congestion_window_packets: config
                .initial_congestion_window_packets,
        }
    }
}

impl Recovery {
    pub fn new_with_config(recovery_config: &RecoveryConfig) -> Self {
        let initial_congestion_window = recovery_config.max_send_udp_payload_size *
            recovery_config.initial_congestion_window_packets;

        Recovery {
            loss_detection_timer: None,

            pto_count: 0,

            time_of_last_sent_ack_eliciting_pkt: [None; packet::Epoch::count()],

            largest_acked_pkt: [SpacedPktNum(SpaceId::MAX, PktNum::MAX);
                packet::Epoch::count()],

            largest_sent_pkt: [SpacedPktNum(0, 0); packet::Epoch::count()],

            latest_rtt: Duration::ZERO,

            // This field should be initialized to `INITIAL_RTT` for the initial
            // PTO calculation, but it also needs to be an `Option` to track
            // whether any RTT sample was received, so the initial value is
            // handled by the `rtt()` method instead.
            smoothed_rtt: None,

            minmax_filter: minmax::Minmax::new(Duration::ZERO),

            min_rtt: Duration::ZERO,

            rttvar: INITIAL_RTT / 2,

            max_ack_delay: recovery_config.max_ack_delay,

            loss_time: [None; packet::Epoch::count()],

            sent: [VecDeque::new(), VecDeque::new(), VecDeque::new()],

            lost: [Vec::new(), Vec::new(), Vec::new()],

            acked: [Vec::new(), Vec::new(), Vec::new()],

            lost_count: 0,
            lost_spurious_count: 0,

            loss_probes: [0; packet::Epoch::count()],

            in_flight_count: [0; packet::Epoch::count()],

            congestion_window: initial_congestion_window,

            pkt_thresh: INITIAL_PACKET_THRESHOLD,

            time_thresh: INITIAL_TIME_THRESHOLD,

            bytes_in_flight: 0,

            rtt_update_count: 0,

            ssthresh: usize::MAX,

            bytes_acked_sl: 0,

            bytes_acked_ca: 0,

            bytes_sent: 0,

            bytes_lost: 0,

            congestion_recovery_start_time: None,

            max_datagram_size: recovery_config.max_send_udp_payload_size,

            real_time: recovery_config.real_time,

            cc_ops: recovery_config.cc_ops,

            delivery_rate: delivery_rate::Rate::default(),

            cubic_state: cubic::State::default(),

            app_limited: false,

            hystart: hystart::Hystart::new(recovery_config.hystart),

            pacer: pacer::Pacer::new(
                recovery_config.pacing,
                initial_congestion_window,
                0,
                recovery_config.max_send_udp_payload_size,
                recovery_config.max_pacing_rate,
            ),

            prr: prr::PRR::default(),

            send_quantum: initial_congestion_window,

            #[cfg(feature = "qlog")]
            qlog_metrics: QlogMetrics::default(),

            bbr_state: bbr::State::new(),

            bbr2_state: bbr2::State::new(),

            outstanding_non_ack_eliciting: 0,

            mc_cwnd: None,

            fc_new_ack_pn: Vec::new(),

            is_fc_source: false,

            initial_congestion_window_packets: recovery_config
                .initial_congestion_window_packets,
        }
    }

    pub fn new(config: &Config) -> Self {
        Self::new_with_config(&RecoveryConfig::from_config(config))
    }

    pub fn on_init(&mut self) {
        (self.cc_ops.on_init)(self);
    }

    pub fn reset(&mut self) {
        self.congestion_window =
            self.max_datagram_size * self.initial_congestion_window_packets;
        self.in_flight_count = [0; packet::Epoch::count()];
        self.congestion_recovery_start_time = None;
        self.ssthresh = usize::MAX;
        (self.cc_ops.reset)(self);
        self.hystart.reset();
        self.prr = prr::PRR::default();
    }

    /// Returns whether or not we should elicit an ACK even if we wouldn't
    /// otherwise have constructed an ACK eliciting packet.
    pub fn should_elicit_ack(&self, epoch: packet::Epoch) -> bool {
        self.loss_probes[epoch] > 0 ||
            self.outstanding_non_ack_eliciting >=
                MAX_OUTSTANDING_NON_ACK_ELICITING
    }

    pub fn on_packet_sent(
        &mut self, mut pkt: Sent, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, trace_id: &str,
    ) {
        let ack_eliciting = pkt.ack_eliciting;
        let in_flight = pkt.in_flight;
        let sent_bytes = pkt.size;
        let pkt_num = pkt.pkt_num;

        if ack_eliciting {
            self.outstanding_non_ack_eliciting = 0;
        } else {
            self.outstanding_non_ack_eliciting += 1;
        }

        self.largest_sent_pkt[epoch] =
            cmp::max(self.largest_sent_pkt[epoch], pkt_num);

        if in_flight {
            if ack_eliciting {
                self.time_of_last_sent_ack_eliciting_pkt[epoch] = Some(now);
            }

            self.in_flight_count[epoch] += 1;

            self.update_app_limited(
                (self.bytes_in_flight + sent_bytes) < self.congestion_window,
            );

            self.on_packet_sent_cc(sent_bytes, now);

            self.prr.on_packet_sent(sent_bytes);

            self.set_loss_detection_timer(handshake_status, now);
        }

        // HyStart++: Start of the round in a slow start.
        if self.hystart.enabled() &&
            epoch == packet::Epoch::Application &&
            self.congestion_window < self.ssthresh
        {
            self.hystart.start_round(pkt_num);
        }

        // Pacing: Set the pacing rate if CC doesn't do its own.
        if !(self.cc_ops.has_custom_pacing)() {
            if let Some(srtt) = self.smoothed_rtt {
                let rate = PACING_MULTIPLIER * self.congestion_window as f64 /
                    srtt.as_secs_f64();
                self.set_pacing_rate(rate as u64, now);
            }
        }

        self.schedule_next_packet(epoch, now, sent_bytes);

        pkt.time_sent = self.get_packet_send_time();

        // bytes_in_flight is already updated. Use previous value.
        self.delivery_rate.on_packet_sent(
            &mut pkt,
            self.bytes_in_flight - sent_bytes,
            self.bytes_lost,
        );

        self.sent[epoch].push_back(pkt);

        self.bytes_sent += sent_bytes;
        trace!("{} {:?}", trace_id, self);
    }

    fn on_packet_sent_cc(&mut self, sent_bytes: usize, now: Instant) {
        (self.cc_ops.on_packet_sent)(self, sent_bytes, now);
    }

    pub fn set_pacing_rate(&mut self, rate: u64, now: Instant) {
        self.pacer.update(self.send_quantum, rate, now);
    }

    pub fn get_packet_send_time(&self) -> Instant {
        self.pacer.next_time()
    }

    fn schedule_next_packet(
        &mut self, epoch: packet::Epoch, now: Instant, packet_size: usize,
    ) {
        // Don't pace in any of these cases:
        //   * Packet contains no data.
        //   * Packet epoch is not Epoch::Application.
        //   * The congestion window is within initcwnd.

        let is_app = epoch == packet::Epoch::Application;

        let in_initcwnd = self.bytes_sent <
            self.max_datagram_size * self.initial_congestion_window_packets;

        let sent_bytes = if !self.pacer.enabled() || !is_app || in_initcwnd {
            0
        } else {
            packet_size
        };

        self.pacer.send(sent_bytes, now);
    }

    /// here, the ranges concern source symbol metadata, not packet numbers
    pub fn on_source_symbol_ack_received(
        &mut self, ranges: &ranges::RangeSet, epoch: packet::Epoch,
        trace_id: &str,
    ) {
        // Detect and mark recovered source symbols, without considering them
        // acked or anything
        for r in ranges.iter() {
            let lowest_recovered_in_block = r.start;
            let largest_recovered_in_block = r.end - 1;

            // search in the unacked packets, the one containing source symbols
            // that have been recovered here
            let unacked_iter = self.sent[epoch]
                .iter_mut()
                // Skip packets that have already been acked or lost.
                .filter(|p| p.time_acked.is_none());

            for unacked in unacked_iter {
                for frame in &mut unacked.frames {
                    if let frame::Frame::SourceSymbolHeader {
                        metadata,
                        recovered,
                    } = frame
                    {
                        let mdu64 = source_symbol_metadata_to_u64(*metadata);
                        if lowest_recovered_in_block <= mdu64 &&
                            mdu64 <= largest_recovered_in_block
                        {
                            *recovered = true;
                            trace!(
                                "{} source symbol newly recovered {} in pkt {:?}",
                                trace_id,
                                mdu64,
                                unacked.pkt_num
                            );
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn on_ack_received(
        &mut self, space_id: SpaceId, ranges: &ranges::RangeSet, ack_delay: u64,
        epoch: packet::Epoch, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str, newly_acked: &mut Vec<Acked>,
    ) -> Result<(usize, usize)> {
        let largest_acked = SpacedPktNum(space_id, ranges.last().unwrap());

        // While quiche used to consider ACK frames acknowledging packet numbers
        // larger than the largest sent one as invalid, this is not true anymore
        // if we consider a single packet number space and multiple paths. The
        // simplest example is the case where the host sends a probing packet on
        // a validating path, then receives an acknowledgment for that packet on
        // the active one.

        if self.largest_acked_pkt[epoch] ==
            SpacedPktNum(SpaceId::MAX, PktNum::MAX)
        {
            self.largest_acked_pkt[epoch] = largest_acked;
        } else {
            self.largest_acked_pkt[epoch] =
                cmp::max(self.largest_acked_pkt[epoch], largest_acked);
        }

        let mut has_ack_eliciting = false;

        let mut largest_newly_acked_pkt_num = SpacedPktNum(0, 0);
        let mut largest_newly_acked_sent_time = now;

        let mut undo_cwnd = false;

        let max_rtt = cmp::max(self.latest_rtt, self.rtt());

        let sent = &mut self.sent[epoch];

        // Detect and mark acked packets, without removing them from the sent
        // packets list.
        for r in ranges.iter() {
            let lowest_acked_in_block = SpacedPktNum(space_id, r.start);
            let largest_acked_in_block = SpacedPktNum(space_id, r.end - 1);

            let first_unacked = if sent
                .front()
                .map(|p| p.pkt_num >= lowest_acked_in_block)
                .unwrap_or(true)
            {
                // In the happy case the first sent packet is the first to be
                // acked, so optimize for that case.
                0
            } else {
                // If it is not the first packet, try to find it using binary
                // search.
                sent.binary_search_by_key(&lowest_acked_in_block, |e| e.pkt_num)
                    .unwrap_or_else(|i| i)
            };

            let unacked_iter = sent.range_mut(first_unacked..)
                // Skip packets that follow the largest acked packet in the block.
                .take_while(|p| p.pkt_num <= largest_acked_in_block)
                // Skip packets that have already been acked or lost.
                .filter(|p| p.time_acked.is_none());

            for unacked in unacked_iter {
                unacked.time_acked = Some(now);

                // Check if acked packet was already declared lost.
                if unacked.time_lost.is_some() {
                    // Calculate new packet reordering threshold.
                    let pkt_thresh =
                        self.largest_acked_pkt[epoch].1 - unacked.pkt_num.1 + 1;
                    let pkt_thresh = cmp::min(MAX_PACKET_THRESHOLD, pkt_thresh);

                    self.pkt_thresh = cmp::max(self.pkt_thresh, pkt_thresh);

                    // Calculate new time reordering threshold.
                    let loss_delay = max_rtt.mul_f64(self.time_thresh);

                    // unacked.time_sent can be in the future due to
                    // pacing.
                    if now.saturating_duration_since(unacked.time_sent) >
                        loss_delay
                    {
                        // TODO: do time threshold update
                        self.time_thresh = 5_f64 / 4_f64;
                    }

                    if unacked.in_flight {
                        undo_cwnd = true;
                    }

                    self.lost_spurious_count += 1;
                    continue;
                }

                if unacked.ack_eliciting {
                    has_ack_eliciting = true;
                }

                largest_newly_acked_pkt_num = unacked.pkt_num;
                largest_newly_acked_sent_time = unacked.time_sent;

                self.acked[epoch].extend(unacked.frames.drain(..));

                if unacked.in_flight {
                    self.in_flight_count[epoch] =
                        self.in_flight_count[epoch].saturating_sub(1);
                }

                newly_acked.push(Acked {
                    pkt_num: unacked.pkt_num,

                    time_sent: unacked.time_sent,

                    size: unacked.size,

                    rtt: now.saturating_duration_since(unacked.time_sent),

                    delivered: unacked.delivered,

                    delivered_time: unacked.delivered_time,

                    first_sent_time: unacked.first_sent_time,

                    is_app_limited: unacked.is_app_limited,

                    tx_in_flight: unacked.tx_in_flight,

                    lost: unacked.lost,
                });

                // Flexicast.
                // Push newly acked.
                self.fc_new_ack_pn.push(unacked.pkt_num.1);

                trace!("{} packet newly acked {:?}", trace_id, unacked.pkt_num);
            }
        }

        // Undo congestion window update.
        if undo_cwnd {
            (self.cc_ops.rollback)(self);
        }

        if newly_acked.is_empty() {
            return Ok((0, 0));
        }

        if largest_newly_acked_pkt_num == largest_acked && has_ack_eliciting {
            // The packet's sent time could be in the future if pacing is used
            // and the network has a very short RTT.
            let latest_rtt =
                now.saturating_duration_since(largest_newly_acked_sent_time);

            let ack_delay = if epoch == packet::Epoch::Application {
                Duration::from_micros(ack_delay)
            } else {
                Duration::from_micros(0)
            };

            // Don't update srtt if rtt is zero.
            if !latest_rtt.is_zero() {
                self.update_rtt(latest_rtt, ack_delay, now);
            }
        }

        // Detect and mark lost packets without removing them from the sent
        // packets list.
        let (lost_packets, lost_bytes) =
            self.detect_lost_packets(epoch, now, trace_id);

        self.on_packets_acked(newly_acked, epoch, now);

        self.pto_count = 0;

        self.set_loss_detection_timer(handshake_status, now);

        self.drain_packets(epoch, now);

        Ok((lost_packets, lost_bytes))
    }

    // returns a (packet_number, stream_id, off, len) tuble indicating a stream
    // portion to retransmit when possible, the stream frame will belong to a
    // previously sent packet with a number above sent_after. If not possible,
    // it will be the first stream frame in an unacked packet Returns None if
    // no stream frame could be found.
    pub fn get_unacked_stream_frame_for_probing(
        &mut self, epoch: packet::Epoch,
    ) -> Option<(SpacedPktNum, u64, u64, usize)> {
        let unacked_iter = self.sent[epoch]
                .iter_mut()
                // Skip packets that have already been acked or lost.
                .filter(|p| !p.retransmitted_for_probing && p.time_acked.is_none());
        for unacked in unacked_iter {
            for frame in &unacked.frames {
                if let &Frame::StreamHeader {
                    stream_id,
                    offset,
                    length,
                    ..
                } = frame
                {
                    unacked.retransmitted_for_probing = true;
                    return Some((unacked.pkt_num, stream_id, offset, length));
                }
            }
        }

        for unacked in self.sent[epoch]
            .iter_mut()
            .filter(|p| p.time_acked.is_none())
        {
            for frame in &unacked.frames {
                if let &Frame::StreamHeader {
                    stream_id,
                    offset,
                    length,
                    ..
                } = frame
                {
                    unacked.retransmitted_for_probing = true;
                    return Some((unacked.pkt_num, stream_id, offset, length));
                }
            }
        }

        None
    }

    pub fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> (usize, usize) {
        let (earliest_loss_time, epoch) = self.loss_time_and_space();

        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            let (lost_packets, lost_bytes) =
                self.detect_lost_packets(epoch, now, trace_id);

            self.set_loss_detection_timer(handshake_status, now);

            trace!("{} {:?}", trace_id, self);
            return (lost_packets, lost_bytes);
        }

        let epoch = if self.bytes_in_flight > 0 {
            // Send new data if available, else retransmit old data. If neither
            // is available, send a single PING frame.
            let (_, e) = self.pto_time_and_space(handshake_status, now);

            e
        } else {
            // Client sends an anti-deadlock packet: Initial is padded to earn
            // more anti-amplification credit, a Handshake packet proves address
            // ownership.
            if handshake_status.has_handshake_keys {
                packet::Epoch::Handshake
            } else {
                packet::Epoch::Initial
            }
        };

        self.pto_count += 1;

        self.loss_probes[epoch] =
            cmp::min(self.pto_count as usize, MAX_PTO_PROBES_COUNT);

        let unacked_iter = self.sent[epoch]
            .iter_mut()
            // Skip packets that have already been acked or lost, and packets
            // that don't contain either CRYPTO or STREAM frames.
            .filter(|p| p.has_data && p.time_acked.is_none() && p.time_lost.is_none())
            // Only return as many packets as the number of probe packets that
            // will be sent.
            .take(self.loss_probes[epoch]);

        // Retransmit the frames from the oldest sent packets on PTO. However
        // the packets are not actually declared lost (so there is no effect to
        // congestion control), we just reschedule the data they carried.
        //
        // This will also trigger sending an ACK and retransmitting frames like
        // HANDSHAKE_DONE and MAX_DATA / MAX_STREAM_DATA as well, in addition
        // to CRYPTO and STREAM, if the original packet carried them.
        for unacked in unacked_iter {
            let mut contains_recovered_source_symbol = false;
            for frame in &unacked.frames {
                if let frame::Frame::SourceSymbolHeader { recovered, .. } = frame
                {
                    if *recovered {
                        contains_recovered_source_symbol = true;
                    }
                }

                if contains_recovered_source_symbol {
                    self.lost[epoch]
                        .push(LostFrame::LostAndRecovered(frame.clone()))
                } else {
                    self.lost[epoch].push(LostFrame::Lost(frame.clone()))
                }
            }
        }

        self.set_loss_detection_timer(handshake_status, now);

        trace!("{} {:?}", trace_id, self);

        (0, 0)
    }

    pub fn on_pkt_num_space_discarded(
        &mut self, epoch: packet::Epoch, handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        let unacked_bytes = self.sent[epoch]
            .iter()
            .filter(|p| {
                p.in_flight && p.time_acked.is_none() && p.time_lost.is_none()
            })
            .fold(0, |acc, p| acc + p.size);

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(unacked_bytes);

        self.sent[epoch].clear();
        self.lost[epoch].clear();
        self.acked[epoch].clear();

        self.time_of_last_sent_ack_eliciting_pkt[epoch] = None;
        self.loss_time[epoch] = None;
        self.loss_probes[epoch] = 0;
        self.in_flight_count[epoch] = 0;

        self.set_loss_detection_timer(handshake_status, now);
    }

    pub fn on_path_change(
        &mut self, epoch: packet::Epoch, now: Instant, trace_id: &str,
    ) -> (usize, usize) {
        self.detect_lost_packets(epoch, now, trace_id)
    }

    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_detection_timer
    }

    pub fn cwnd(&self) -> usize {
        self.congestion_window
    }

    pub fn cwnd_available(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        // if self.loss_probes.iter().any(|&x| x > 0) {
        //     info!("HERE QUE C'EST NUL");
        //     return usize::MAX;
        // }
        if self.loss_probes.iter().any(|&x| x > 0) {
            return usize::MAX;
        }

        // Open more space (snd_cnt) for PRR when allowed.
        self.congestion_window.saturating_sub(self.bytes_in_flight) +
            self.prr.snd_cnt
    }

    pub fn rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(INITIAL_RTT)
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        if self.min_rtt == Duration::ZERO {
            return None;
        }

        Some(self.min_rtt)
    }

    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    pub fn pto(&self) -> Duration {
        self.rtt() + cmp::max(self.rttvar * 4, GRANULARITY)
    }

    pub fn delivery_rate(&self) -> u64 {
        self.delivery_rate.sample_delivery_rate()
    }

    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    pub fn update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        let max_datagram_size =
            cmp::min(self.max_datagram_size, new_max_datagram_size);

        // Update cwnd if it hasn't been updated yet.
        if self.congestion_window ==
            self.max_datagram_size * self.initial_congestion_window_packets
        {
            self.congestion_window =
                max_datagram_size * self.initial_congestion_window_packets;
        }

        self.pacer = pacer::Pacer::new(
            self.pacer.enabled(),
            self.congestion_window,
            0,
            max_datagram_size,
            self.pacer.max_pacing_rate(),
        );

        self.max_datagram_size = max_datagram_size;
    }

    fn update_rtt(
        &mut self, latest_rtt: Duration, ack_delay: Duration, now: Instant,
    ) {
        self.rtt_update_count += 1;
        self.latest_rtt = latest_rtt;

        match self.smoothed_rtt {
            // First RTT sample.
            None => {
                self.min_rtt = self.minmax_filter.reset(now, latest_rtt);

                self.smoothed_rtt = Some(latest_rtt);

                self.rttvar = latest_rtt / 2;
            },

            Some(srtt) => {
                self.min_rtt =
                    self.minmax_filter.running_min(RTT_WINDOW, now, latest_rtt);

                let ack_delay = cmp::min(self.max_ack_delay, ack_delay);

                // Adjust for ack delay if plausible.
                let adjusted_rtt = if latest_rtt > self.min_rtt + ack_delay {
                    latest_rtt - ack_delay
                } else {
                    latest_rtt
                };

                self.rttvar = self.rttvar.mul_f64(3.0 / 4.0) +
                    sub_abs(srtt, adjusted_rtt).mul_f64(1.0 / 4.0);

                self.smoothed_rtt = Some(
                    srtt.mul_f64(7.0 / 8.0) + adjusted_rtt.mul_f64(1.0 / 8.0),
                );
            },
        }
    }

    fn loss_time_and_space(&self) -> (Option<Instant>, packet::Epoch) {
        let mut epoch = packet::Epoch::Initial;
        let mut time = self.loss_time[epoch];

        // Iterate over all packet number spaces starting from Handshake.
        for &e in packet::Epoch::epochs(
            packet::Epoch::Handshake..=packet::Epoch::Application,
        ) {
            let new_time = self.loss_time[e];

            if time.is_none() || new_time < time {
                time = new_time;
                epoch = e;
            }
        }

        (time, epoch)
    }

    fn pto_time_and_space(
        &self, handshake_status: HandshakeStatus, now: Instant,
    ) -> (Option<Instant>, packet::Epoch) {
        let mut duration = self.pto() * 2_u32.pow(self.pto_count);

        // Arm PTO from now when there are no inflight packets.
        if self.bytes_in_flight == 0 {
            if handshake_status.has_handshake_keys {
                return (Some(now + duration), packet::Epoch::Handshake);
            } else {
                return (Some(now + duration), packet::Epoch::Initial);
            }
        }

        let mut pto_timeout = None;
        let mut pto_space = packet::Epoch::Initial;

        // Iterate over all packet number spaces.
        for &e in packet::Epoch::epochs(
            packet::Epoch::Initial..=packet::Epoch::Application,
        ) {
            if self.in_flight_count[e] == 0 {
                continue;
            }

            if e == packet::Epoch::Application {
                // Skip Application Data until handshake completes.
                if !handshake_status.completed {
                    return (pto_timeout, pto_space);
                }

                // Include max_ack_delay and backoff for Application Data.
                duration += self.max_ack_delay * 2_u32.pow(self.pto_count);
            }

            let new_time =
                self.time_of_last_sent_ack_eliciting_pkt[e].map(|t| t + duration);

            if pto_timeout.is_none() || new_time < pto_timeout {
                pto_timeout = new_time;
                pto_space = e;
            }
        }

        (pto_timeout, pto_space)
    }

    fn set_loss_detection_timer(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
    ) {
        let (earliest_loss_time, _) = self.loss_time_and_space();

        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            self.loss_detection_timer = earliest_loss_time;
            return;
        }

        if self.bytes_in_flight == 0 && handshake_status.peer_verified_address {
            self.loss_detection_timer = None;
            return;
        }

        // PTO timer.
        let (timeout, _) = self.pto_time_and_space(handshake_status, now);
        self.loss_detection_timer = timeout;
    }

    pub fn mark_all_inflight_as_lost(
        &mut self, now: Instant, trace_id: &str,
    ) -> (usize, usize) {
        let mut lost_packets = 0;
        let mut lost_bytes = 0;
        for &e in packet::Epoch::epochs(
            packet::Epoch::Initial..=packet::Epoch::Application,
        ) {
            let mut epoch_lost_bytes = 0;
            let mut largest_lost_pkt = None;
            for sent in self.sent[e].drain(..) {
                if sent.time_acked.is_none() {
                    let mut contains_recovered_source_symbol = false;
                    for frame in &sent.frames {
                        if let frame::Frame::SourceSymbolHeader {
                            recovered,
                            ..
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
            }

            self.bytes_lost += epoch_lost_bytes as u64;
            lost_bytes += epoch_lost_bytes;

            if let Some(pkt) = largest_lost_pkt {
                self.on_packets_lost(lost_bytes, &pkt, e, now);
            }
        }

        (lost_packets, lost_bytes)
    }

    pub fn detect_lost_packets(
        &mut self, epoch: packet::Epoch, now: Instant, trace_id: &str,
    ) -> (usize, usize) {
        let largest_acked = self.largest_acked_pkt[epoch];

        self.loss_time[epoch] = None;

        let loss_delay =
            cmp::max(self.latest_rtt, self.rtt()).mul_f64(self.time_thresh);

        // Minimum time of kGranularity before packets are deemed lost.
        let loss_delay = cmp::max(loss_delay, GRANULARITY);

        // Packets sent before this time are deemed lost.
        let lost_send_time = now.checked_sub(loss_delay).unwrap();

        let mut lost_packets = 0;
        let mut lost_bytes = 0;

        let mut largest_lost_pkt = None;

        let unacked_iter = self.sent[epoch]
            .iter_mut()
            // Skip packets that follow the largest acked packet.
            .take_while(|p| p.pkt_num <= largest_acked)
            // Skip packets that have already been acked or lost.
            .filter(|p| p.time_acked.is_none() && p.time_lost.is_none());

        for unacked in unacked_iter {
            // Mark packet as lost, or set time when it should be marked.
            if unacked.time_sent <= lost_send_time ||
                largest_acked.1 >= unacked.pkt_num.1 + self.pkt_thresh
            {
                let mut contains_recovered_source_symbol = false;
                for frame in &unacked.frames {
                    if let frame::Frame::SourceSymbolHeader {
                        recovered, ..
                    } = frame
                    {
                        if *recovered {
                            contains_recovered_source_symbol = true;
                        }
                    }

                    if contains_recovered_source_symbol {
                        self.lost[epoch]
                            .push(LostFrame::LostAndRecovered(frame.clone()))
                    } else {
                        self.lost[epoch].push(LostFrame::Lost(frame.clone()))
                    }
                }

                unacked.time_lost = Some(now);

                if unacked.in_flight {
                    lost_bytes += unacked.size;

                    // Frames have already been removed from the packet, so
                    // cloning the whole packet should be relatively cheap.
                    largest_lost_pkt = Some(unacked.clone());

                    self.in_flight_count[epoch] =
                        self.in_flight_count[epoch].saturating_sub(1);

                    trace!(
                        "{} packet {:?} lost on epoch {}",
                        trace_id,
                        unacked.pkt_num,
                        epoch
                    );
                }

                lost_packets += 1;
                self.lost_count += 1;
            } else {
                let loss_time = match self.loss_time[epoch] {
                    None => unacked.time_sent + loss_delay,

                    Some(loss_time) =>
                        cmp::min(loss_time, unacked.time_sent + loss_delay),
                };

                self.loss_time[epoch] = Some(loss_time);
                break;
            }
        }

        self.bytes_lost += lost_bytes as u64;

        if let Some(pkt) = largest_lost_pkt {
            self.on_packets_lost(lost_bytes, &pkt, epoch, now);
        }

        self.drain_packets(epoch, now);

        (lost_packets, lost_bytes)
    }

    fn drain_packets(&mut self, epoch: packet::Epoch, now: Instant) {
        let mut lowest_non_expired_pkt_index = self.sent[epoch].len();

        // In order to avoid removing elements from the middle of the list
        // (which would require copying other elements to compact the list),
        // we only remove a contiguous range of elements from the start of the
        // list.
        //
        // This means that acked or lost elements coming after this will not
        // be removed at this point, but their removal is delayed for a later
        // time, once the gaps have been filled.

        // First, find the first element that is neither acked nor lost.
        for (i, pkt) in self.sent[epoch].iter().enumerate() {
            if let Some(time_lost) = pkt.time_lost {
                if time_lost + self.rtt() > now {
                    lowest_non_expired_pkt_index = i;
                    break;
                }

                // Flexicast extension.
                // If this is the flexicast source, and the packet is not
                // delegated yet, we cannot drain it.
                if self.is_fc_source && !pkt.is_fc_delegated {
                    lowest_non_expired_pkt_index = i;
                    break;
                }
            }

            if pkt.time_acked.is_none() && pkt.time_lost.is_none() {
                lowest_non_expired_pkt_index = i;
                break;
            }
        }

        // Then remove elements up to the previously found index.
        self.sent[epoch].drain(..lowest_non_expired_pkt_index);
    }

    fn on_packets_acked(
        &mut self, acked: &mut Vec<Acked>, epoch: packet::Epoch, now: Instant,
    ) {
        // Update delivery rate sample per acked packet.
        for pkt in acked.iter() {
            self.delivery_rate.update_rate_sample(pkt, now);
        }

        // Fill in a rate sample.
        self.delivery_rate.generate_rate_sample(self.min_rtt);

        // Call congestion control hooks.
        (self.cc_ops.on_packets_acked)(self, acked, epoch, now);
    }

    fn in_congestion_recovery(&self, sent_time: Instant) -> bool {
        match self.congestion_recovery_start_time {
            Some(congestion_recovery_start_time) =>
                sent_time <= congestion_recovery_start_time,

            None => false,
        }
    }

    fn in_persistent_congestion(
        &mut self, _largest_lost_pkt_num: SpacedPktNum,
    ) -> bool {
        let _congestion_period = self.pto() * PERSISTENT_CONGESTION_THRESHOLD;

        // TODO: properly detect persistent congestion
        false
    }

    fn on_packets_lost(
        &mut self, lost_bytes: usize, largest_lost_pkt: &Sent,
        epoch: packet::Epoch, now: Instant,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        self.congestion_event(lost_bytes, largest_lost_pkt, epoch, now);

        if self.in_persistent_congestion(largest_lost_pkt.pkt_num) {
            self.collapse_cwnd();
        }
    }

    pub(crate) fn congestion_event(
        &mut self, lost_bytes: usize, largest_lost_pkt: &Sent,
        epoch: packet::Epoch, now: Instant,
    ) {
        let time_sent = largest_lost_pkt.time_sent;

        if !self.in_congestion_recovery(time_sent) {
            (self.cc_ops.checkpoint)(self);
        }

        (self.cc_ops.congestion_event)(
            self,
            lost_bytes,
            largest_lost_pkt,
            epoch,
            now,
        );
    }

    fn collapse_cwnd(&mut self) {
        (self.cc_ops.collapse_cwnd)(self);
    }

    pub fn update_app_limited(&mut self, v: bool) {
        self.app_limited = v;
    }

    pub fn app_limited(&self) -> bool {
        self.app_limited
    }

    pub fn delivery_rate_update_app_limited(&mut self, v: bool) {
        self.delivery_rate.update_app_limited(v);
    }

    #[cfg(feature = "qlog")]
    pub fn maybe_qlog(&mut self) -> Option<EventData> {
        let qlog_metrics = QlogMetrics {
            min_rtt: self.min_rtt,
            smoothed_rtt: self.rtt(),
            latest_rtt: self.latest_rtt,
            rttvar: self.rttvar,
            cwnd: self.cwnd() as u64,
            bytes_in_flight: self.bytes_in_flight as u64,
            ssthresh: self.ssthresh as u64,
            pacing_rate: self.pacer.rate(),
        };

        self.qlog_metrics.maybe_update(qlog_metrics)
    }

    pub fn send_quantum(&self) -> usize {
        self.send_quantum
    }
}

/// Available congestion control algorithms.
///
/// This enum provides currently available list of congestion control
/// algorithms.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum CongestionControlAlgorithm {
    /// Reno congestion control algorithm. `reno` in a string form.
    Reno     = 0,
    /// CUBIC congestion control algorithm (default). `cubic` in a string form.
    CUBIC    = 1,
    /// BBR congestion control algorithm. `bbr` in a string form.
    BBR      = 2,
    /// BBRv2 congestion control algorithm. `bbr2` in a string form.
    BBR2     = 3,
    /// DISABLED congestion control. `disabled` in a string form.
    DISABLED = 4,
}

impl FromStr for CongestionControlAlgorithm {
    type Err = crate::Error;

    /// Converts a string to `CongestionControlAlgorithm`.
    ///
    /// If `name` is not valid, `Error::CongestionControl` is returned.
    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name {
            "reno" => Ok(CongestionControlAlgorithm::Reno),
            "cubic" => Ok(CongestionControlAlgorithm::CUBIC),
            "bbr" => Ok(CongestionControlAlgorithm::BBR),
            "disabled" => Ok(CongestionControlAlgorithm::DISABLED),
            "bbr2" => Ok(CongestionControlAlgorithm::BBR2),

            _ => Err(crate::Error::CongestionControl),
        }
    }
}

pub struct CongestionControlOps {
    pub on_init: fn(r: &mut Recovery),

    pub reset: fn(r: &mut Recovery),

    pub on_packet_sent: fn(r: &mut Recovery, sent_bytes: usize, now: Instant),

    pub on_packets_acked: fn(
        r: &mut Recovery,
        packets: &mut Vec<Acked>,
        epoch: packet::Epoch,
        now: Instant,
    ),

    pub congestion_event: fn(
        r: &mut Recovery,
        lost_bytes: usize,
        largest_lost_packet: &Sent,
        epoch: packet::Epoch,
        now: Instant,
    ),

    pub collapse_cwnd: fn(r: &mut Recovery),

    pub checkpoint: fn(r: &mut Recovery),

    pub rollback: fn(r: &mut Recovery) -> bool,

    pub has_custom_pacing: fn() -> bool,

    pub debug_fmt:
        fn(r: &Recovery, formatter: &mut std::fmt::Formatter) -> std::fmt::Result,
}

impl From<CongestionControlAlgorithm> for &'static CongestionControlOps {
    fn from(algo: CongestionControlAlgorithm) -> Self {
        match algo {
            CongestionControlAlgorithm::Reno => &reno::RENO,
            CongestionControlAlgorithm::CUBIC => &cubic::CUBIC,
            CongestionControlAlgorithm::BBR => &bbr::BBR,
            CongestionControlAlgorithm::DISABLED => &disabled_cc::DISABLED_CC,
            CongestionControlAlgorithm::BBR2 => &bbr2::BBR2,
        }
    }
}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.loss_detection_timer {
            Some(v) => {
                let now = Instant::now();

                if v > now {
                    let d = v.duration_since(now);
                    write!(f, "timer={d:?} ")?;
                } else {
                    write!(f, "timer=exp ")?;
                }
            },

            None => {
                write!(f, "timer=none ")?;
            },
        };

        write!(f, "latest_rtt={:?} ", self.latest_rtt)?;
        write!(f, "srtt={:?} ", self.smoothed_rtt)?;
        write!(f, "min_rtt={:?} ", self.min_rtt)?;
        write!(f, "rttvar={:?} ", self.rttvar)?;
        write!(f, "loss_time={:?} ", self.loss_time)?;
        write!(f, "loss_probes={:?} ", self.loss_probes)?;
        write!(f, "cwnd={} ", self.congestion_window)?;
        write!(f, "ssthresh={} ", self.ssthresh)?;
        write!(f, "bytes_in_flight={} ", self.bytes_in_flight)?;
        write!(f, "app_limited={} ", self.app_limited)?;
        write!(
            f,
            "congestion_recovery_start_time={:?} ",
            self.congestion_recovery_start_time
        )?;
        write!(f, "{:?} ", self.delivery_rate)?;
        write!(f, "pacer={:?} ", self.pacer)?;

        if self.hystart.enabled() {
            write!(f, "hystart={:?} ", self.hystart)?;
        }

        // CC-specific debug info
        (self.cc_ops.debug_fmt)(self, f)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct Sent {
    pub pkt_num: SpacedPktNum,

    pub frames: SmallVec<[frame::Frame; 1]>,

    pub time_sent: Instant,

    pub time_acked: Option<Instant>,

    pub time_lost: Option<Instant>,

    pub size: usize,

    pub ack_eliciting: bool,

    pub in_flight: bool,

    pub delivered: usize,

    pub delivered_time: Instant,

    pub first_sent_time: Instant,

    pub is_app_limited: bool,

    pub tx_in_flight: usize,

    pub lost: u64,

    pub has_data: bool,

    pub retransmitted_for_probing: bool,

    /// Flexicast extension.
    /// Potentially whether the packet was delegated through unicast.
    pub is_fc_delegated: bool,
}

impl std::fmt::Debug for Sent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pkt_num={:?} ", self.pkt_num)?;
        write!(f, "pkt_sent_time={:?} ", self.time_sent)?;
        write!(f, "pkt_size={:?} ", self.size)?;
        write!(f, "delivered={:?} ", self.delivered)?;
        write!(f, "delivered_time={:?} ", self.delivered_time)?;
        write!(f, "first_sent_time={:?} ", self.first_sent_time)?;
        write!(f, "is_app_limited={} ", self.is_app_limited)?;
        write!(f, "tx_in_flight={} ", self.tx_in_flight)?;
        write!(f, "lost={} ", self.lost)?;
        write!(f, "has_data={} ", self.has_data)?;
        write!(f, "time_acked={:?} ", self.time_acked)?;
        write!(f, "time_lost={:?} ", self.time_lost)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct Acked {
    pub pkt_num: SpacedPktNum,

    pub time_sent: Instant,

    pub size: usize,

    pub rtt: Duration,

    pub delivered: usize,

    pub delivered_time: Instant,

    pub first_sent_time: Instant,

    pub is_app_limited: bool,

    pub tx_in_flight: usize,

    pub lost: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct HandshakeStatus {
    pub has_handshake_keys: bool,

    pub peer_verified_address: bool,

    pub completed: bool,
}

#[cfg(test)]
impl Default for HandshakeStatus {
    fn default() -> HandshakeStatus {
        HandshakeStatus {
            has_handshake_keys: true,

            peer_verified_address: true,

            completed: true,
        }
    }
}

fn sub_abs(lhs: Duration, rhs: Duration) -> Duration {
    if lhs > rhs {
        lhs - rhs
    } else {
        rhs - lhs
    }
}

// We don't need to log all qlog metrics every time there is a recovery event.
// Instead, we can log only the MetricsUpdated event data fields that we care
// about, only when they change. To support this, the QLogMetrics structure
// keeps a running picture of the fields.
#[derive(Default)]
#[cfg(feature = "qlog")]
struct QlogMetrics {
    min_rtt: Duration,
    smoothed_rtt: Duration,
    latest_rtt: Duration,
    rttvar: Duration,
    cwnd: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    pacing_rate: u64,
}

#[cfg(feature = "qlog")]
impl QlogMetrics {
    // Make a qlog event if the latest instance of QlogMetrics is different.
    //
    // This function diffs each of the fields. A qlog MetricsUpdated event is
    // only generated if at least one field is different. Where fields are
    // different, the qlog event contains the latest value.
    fn maybe_update(&mut self, latest: Self) -> Option<EventData> {
        let mut emit_event = false;

        let new_min_rtt = if self.min_rtt != latest.min_rtt {
            self.min_rtt = latest.min_rtt;
            emit_event = true;
            Some(latest.min_rtt.as_secs_f32() * 1000.0)
        } else {
            None
        };

        let new_smoothed_rtt = if self.smoothed_rtt != latest.smoothed_rtt {
            self.smoothed_rtt = latest.smoothed_rtt;
            emit_event = true;
            Some(latest.smoothed_rtt.as_secs_f32() * 1000.0)
        } else {
            None
        };

        let new_latest_rtt = if self.latest_rtt != latest.latest_rtt {
            self.latest_rtt = latest.latest_rtt;
            emit_event = true;
            Some(latest.latest_rtt.as_secs_f32() * 1000.0)
        } else {
            None
        };

        let new_rttvar = if self.rttvar != latest.rttvar {
            self.rttvar = latest.rttvar;
            emit_event = true;
            Some(latest.rttvar.as_secs_f32() * 1000.0)
        } else {
            None
        };

        let new_cwnd = if self.cwnd != latest.cwnd {
            self.cwnd = latest.cwnd;
            emit_event = true;
            Some(latest.cwnd)
        } else {
            None
        };

        let new_bytes_in_flight =
            if self.bytes_in_flight != latest.bytes_in_flight {
                self.bytes_in_flight = latest.bytes_in_flight;
                emit_event = true;
                Some(latest.bytes_in_flight)
            } else {
                None
            };

        let new_ssthresh = if self.ssthresh != latest.ssthresh {
            self.ssthresh = latest.ssthresh;
            emit_event = true;
            Some(latest.ssthresh)
        } else {
            None
        };

        let new_pacing_rate = if self.pacing_rate != latest.pacing_rate {
            self.pacing_rate = latest.pacing_rate;
            emit_event = true;
            Some(latest.pacing_rate)
        } else {
            None
        };

        if emit_event {
            // QVis can't use all these fields and they can be large.
            return Some(EventData::MetricsUpdated(
                qlog::events::quic::MetricsUpdated {
                    min_rtt: new_min_rtt,
                    smoothed_rtt: new_smoothed_rtt,
                    latest_rtt: new_latest_rtt,
                    rtt_variance: new_rttvar,
                    pto_count: None,
                    congestion_window: new_cwnd,
                    bytes_in_flight: new_bytes_in_flight,
                    ssthresh: new_ssthresh,
                    packets_in_flight: None,
                    pacing_rate: new_pacing_rate,
                },
            ));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    #[test]
    fn lookup_cc_algo_ok() {
        let algo = CongestionControlAlgorithm::from_str("reno").unwrap();
        assert_eq!(algo, CongestionControlAlgorithm::Reno);
    }

    #[test]
    fn lookup_cc_algo_bad() {
        assert_eq!(
            CongestionControlAlgorithm::from_str("???"),
            Err(crate::Error::CongestionControl)
        );
    }

    #[test]
    fn collapse_cwnd() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        // cwnd will be reset.
        r.collapse_cwnd();
        assert_eq!(r.cwnd(), r.max_datagram_size * MINIMUM_WINDOW_PACKETS);
    }

    #[test]
    fn loss_on_pto() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent[packet::Epoch::Application].len(), 0);

        // Start by sending a few packets.
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 1);
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 2);
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first 2 packets are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            ),
            Ok((0, 0))
        );

        assert_eq!(r.sent[packet::Epoch::Application].len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);
        assert_eq!(r.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // PTO.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes[packet::Epoch::Application], 1);
        assert_eq!(r.lost_count, 0);
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        let p = Sent {
            pkt_num: SpacedPktNum(0, 5),
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);
        assert_eq!(r.lost_count, 0);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // PTO packets are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(4..6);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            ),
            Ok((2, 2000))
        );

        assert_eq!(r.sent[packet::Epoch::Application].len(), 4);
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.lost_count, 2);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_lost_packets(packet::Epoch::Application, now, "");

        assert_eq!(r.sent[packet::Epoch::Application].len(), 0);
    }

    #[test]
    fn loss_on_timer() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent[packet::Epoch::Application].len(), 0);

        // Start by sending a few packets.
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 1);
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 2);
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first 2 packets and the last one are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);
        acked.insert(3..4);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            ),
            Ok((0, 0))
        );

        assert_eq!(r.sent[packet::Epoch::Application].len(), 2);
        assert_eq!(r.bytes_in_flight, 1000);
        assert_eq!(r.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes[packet::Epoch::Application], 0);

        assert_eq!(r.sent[packet::Epoch::Application].len(), 2);
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.lost_count, 1);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_lost_packets(packet::Epoch::Application, now, "");

        assert_eq!(r.sent[packet::Epoch::Application].len(), 0);
    }

    #[test]
    fn loss_on_reordering() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent[packet::Epoch::Application].len(), 0);

        // Start by sending a few packets.
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 1);
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 2);
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent[packet::Epoch::Application].len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // ACKs are reordered.
        let mut acked = ranges::RangeSet::default();
        acked.insert(2..4);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            ),
            Ok((1, 1000))
        );

        now += Duration::from_millis(9);

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);

        assert_eq!(r.pkt_thresh, INITIAL_PACKET_THRESHOLD);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            ),
            Ok((0, 0))
        );

        assert_eq!(r.sent[packet::Epoch::Application].len(), 4);
        assert_eq!(r.bytes_in_flight, 0);

        // Spurious loss.
        assert_eq!(r.lost_count, 1);
        assert_eq!(r.lost_spurious_count, 1);

        // Packet threshold was increased.
        assert_eq!(r.pkt_thresh, 4);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_lost_packets(packet::Epoch::Application, now, "");

        assert_eq!(r.sent[packet::Epoch::Application].len(), 0);
    }

    #[test]
    fn pacing() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent[packet::Epoch::Application].len(), 0);

        // send out first packet (a full initcwnd).
        let p = Sent {
            pkt_num: SpacedPktNum(0, 0),
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 12000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent[packet::Epoch::Application].len(), 1);
        assert_eq!(r.bytes_in_flight, 12000);

        // First packet will be sent out immediately.
        assert_eq!(r.pacer.rate(), 0);
        assert_eq!(r.get_packet_send_time(), now);

        // Wait 50ms for ACK.
        now += Duration::from_millis(50);

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..1);

        assert_eq!(
            r.on_ack_received(
                0,
                &acked,
                10,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            ),
            Ok((0, 0))
        );

        assert_eq!(r.sent[packet::Epoch::Application].len(), 0);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.smoothed_rtt.unwrap(), Duration::from_millis(50));

        // 1 MSS increased.
        assert_eq!(r.congestion_window, 12000 + 1200);

        // Send out second packet.
        let p = Sent {
            pkt_num: SpacedPktNum(0, 1),
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 6000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent[packet::Epoch::Application].len(), 1);
        assert_eq!(r.bytes_in_flight, 6000);

        // Pacing is not done during initial phase of connection.
        assert_eq!(r.get_packet_send_time(), now);

        // Send the third packet out.
        let p = Sent {
            pkt_num: SpacedPktNum(0, 2),
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 6000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent[packet::Epoch::Application].len(), 2);
        assert_eq!(r.bytes_in_flight, 12000);

        // Send the third packet out.
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
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            retransmitted_for_probing: false,
            is_fc_delegated: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent[packet::Epoch::Application].len(), 3);
        assert_eq!(r.bytes_in_flight, 13000);

        // We pace this outgoing packet. as all conditions for pacing
        // are passed.
        let pacing_rate =
            (r.congestion_window as f64 * PACING_MULTIPLIER / 0.05) as u64;
        assert_eq!(r.pacer.rate(), pacing_rate);

        assert_eq!(
            r.get_packet_send_time(),
            now + Duration::from_secs_f64(12000.0 / pacing_rate as f64)
        );
    }

    #[test]
    fn spaced_pkt_num_ordering() {
        // In same space.
        let a = SpacedPktNum(42, 42);
        let b = SpacedPktNum(42, 120);
        let c = SpacedPktNum(42, 10);

        assert_eq!(std::cmp::max(a, b), b);
        assert_eq!(std::cmp::max(a, c), a);

        // Different spaces.
        let d = SpacedPktNum(42, 9999999);
        let e = SpacedPktNum(43, 1);
        let f = SpacedPktNum(9999, 2);

        assert_eq!(std::cmp::max(d, e), e);
        assert_eq!(std::cmp::max(e, f), f);
    }
}

mod bbr;
mod bbr2;
mod cubic;
mod delivery_rate;
mod disabled_cc;
mod hystart;
mod mc_cubic;
pub mod multicast;
mod pacer;
mod prr;
mod reno;
