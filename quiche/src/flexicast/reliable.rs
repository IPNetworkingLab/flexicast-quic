//! Reliability management for Flexicast QUIC.
//! Depending on the role, the attributes are different.

use crate::flexicast::nack::FcAckDelayStrategy;
use crate::frame;
use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::Connection;
use crate::Error;
use crate::InternalPathId;
use crate::Result;
use std::collections::HashSet;
use std::time;

use super::ack::McAck;
use super::nack::FcNackRecv;
use super::FcError;
use super::McClientStatus;
use super::McRole;

#[derive(Debug)]
/// Reliable flexicast attributes for the receiver.
pub struct RFcRecv {
    /// Negative acknowledgment state for the receiver.
    nack: FcNackRecv,
}

impl RFcRecv {
    /// Creates a new structure from the flexicast flow timer.
    pub fn new(fc_ack_delay: u64) -> Self {
        Self {
            nack: FcNackRecv::new(fc_ack_delay),
        }
    }

    /// Returns a reference to the inner [`FcNackRecv`] state.
    pub fn nack(&self) -> &FcNackRecv {
        &self.nack
    }

    /// Returns a mutable reference to the inner [`FcNackRecv`] state.
    pub fn nack_mut(&mut self) -> &mut FcNackRecv {
        &mut self.nack
    }
}

#[derive(Debug)]
/// Reliable flexicast attributes for the unicast path source.
pub struct RFcUcPath {
    /// Multicast Ack aggregator.
    /// The role of this structure here is different than for the flexicast
    /// source. Here, the structure helps the unicast path to know which
    /// stream offsets have been delegated for unicast retransmission and which
    /// packets have been received to give to the flexicast flow aggregation
    /// of acks.
    pub(crate) mc_ack: McAck,

    /// Range of packet numbers that have been acknowledged by the receiver.
    /// Used for the delegation of streams.
    pub(crate) fc_pn_recv: RangeSet,

    /// Whether the flexicast flow is aware that this client listens to it.
    pub notified_fc_source: bool,

    /// Current highest packet number on the flexicast flow that this receiver
    /// instance sees.
    pub fc_highest_pn: Option<u64>,
}

impl Default for RFcUcPath {
    fn default() -> Self {
        let mut mc_ack = McAck::new(true);

        mc_ack.new_recv(0, false);

        Self {
            mc_ack,
            notified_fc_source: false,
            fc_highest_pn: None,
            fc_pn_recv: RangeSet::default(),
        }
    }
}

#[derive(Debug)]
/// Reliable flexicast attributes for the flexicast flow.
pub struct RFcSource {
    /// Multicast acknowledgment aggregator.
    pub(crate) mc_ack: McAck,

    /// Highest packet number sent on the flexicast flow that was notified to
    /// the unicast path instances.
    pub(crate) last_notified_pn: Option<u64>,

    /// The last time we sent an ack delay update.
    pub(crate) last_time_ack_delay_update: Option<time::Instant>,

    /// The period between two ack delay updates.
    pub(crate) ack_delay_update_delay: time::Duration,

    /// Last sent ack delay value.
    pub(crate) last_sent_ack_delay: u64,

    /// The computed ack delay.
    pub(crate) ack_delay: u64,

    /// Sequence number of the ack delay frame.
    pub(crate) ack_delay_seqnum: u64,

    /// Ack delay strategy to use.
    /// The update of the ack delay is only performed if
    /// [`FcAckDelayStrategy::Adaptive`].
    pub(crate) ack_delay_strategy: FcAckDelayStrategy,
}

impl RFcSource {
    /// Creates a new structure based on the flexicast timer.
    pub(crate) fn new() -> Self {
        Self {
            mc_ack: McAck::new(false),
            last_notified_pn: None,
            last_time_ack_delay_update: None,
            ack_delay_update_delay: time::Duration::from_millis(100),
            ack_delay: 0,
            last_sent_ack_delay: 0,
            ack_delay_seqnum: 0,
            ack_delay_strategy: FcAckDelayStrategy::Immediate,
        }
    }

    /// Sets the last notified packet number to a new value.
    /// Does nothing if the new value is below the old one.
    pub(crate) fn fc_set_last_notified_pn(&mut self, pn: u64) {
        if self.last_notified_pn < Some(pn) {
            self.last_notified_pn = Some(pn);
        }
    }

    /// Whether a new FC_ACK_DELAY should be sent.
    /// If an FC_ACK_DELAY must be sent, this function returns the sequence
    /// number and the ack delay to use. Otherwise, it returns `None`.
    pub fn fc_should_send_ack_delay(
        &self, now: time::Instant,
    ) -> Option<(u64, u64)> {
        (matches!(self.ack_delay_strategy, FcAckDelayStrategy::Adaptive(_)) &&
            self.ack_delay != self.last_sent_ack_delay &&
            self.last_time_ack_delay_update.is_none_or(|last| {
                now.duration_since(last) > self.ack_delay_update_delay
            }))
        .then(|| (self.ack_delay_seqnum, self.ack_delay))
    }

    /// Call this function when a new ack delay is sent.
    pub fn fc_on_new_ack_delay_sent(&mut self, now: time::Instant) {
        self.last_time_ack_delay_update = Some(now);
        self.last_sent_ack_delay = self.ack_delay;
        self.ack_delay_seqnum += 1;
        if self.ack_delay_seqnum % 5 == 0 {
            println!(
                "{}-RESULT-ACKDELAY {}",
                time::SystemTime::now()
                    .duration_since(time::SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_micros(),
                self.ack_delay
            );
        }
    }
}

/// Reliable flexicast attributes.
#[derive(Debug)]
pub enum ReliableFc {
    /// Receiver-specific.
    /// Used to store information about the next acks to send.
    Receiver(RFcRecv),

    /// Unicast-server specific reliable flexicast.
    /// Used to store the positive acks sent by the client about the flexicast
    /// channel.
    UcPath(RFcUcPath),

    /// Multicast source specific reliable flexicast.
    FcFlow(RFcSource),

    /// Undefined role. Used to initialise the structure at first.
    Undefined,
}

impl ReliableFc {
    /// Return a mutable reference to the client inner structure.
    pub fn receiver(&self) -> Option<&RFcRecv> {
        if let Self::Receiver(c) = self {
            Some(c)
        } else {
            None
        }
    }

    /// Return a mutable reference to the server inner structure.
    pub fn server(&self) -> Option<&RFcUcPath> {
        if let Self::UcPath(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return a reference to the source inner structure.
    pub fn source(&self) -> Option<&RFcSource> {
        if let Self::FcFlow(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return a mutable reference to the client inner structure.
    pub fn client_mut(&mut self) -> Option<&mut RFcRecv> {
        if let Self::Receiver(c) = self {
            Some(c)
        } else {
            None
        }
    }

    /// Return a mutable reference to the server inner structure.
    pub fn server_mut(&mut self) -> Option<&mut RFcUcPath> {
        if let Self::UcPath(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return a mutable reference to the source inner structure.
    pub fn source_mut(&mut self) -> Option<&mut RFcSource> {
        if let Self::FcFlow(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

impl Connection {
    /// Gives ranges of received packets from the receivers to the flexicast
    /// flow. Internally calls [`crate::Connection::on_ack_received`].
    pub fn fc_on_ack_received(
        &mut self, ranges: &RangeSet, now: time::Instant,
    ) -> Result<()> {
        let hs = self.handshake_status();

        let fca = fca!(self)?;
        if !matches!(fca.mc_role, McRole::ServerFlexicast) {
            return Err(Error::Flexicast(FcError::McInvalidRole(fca.mc_role)));
        }
        let fc_path_id =
            fca.fc_path_id.ok_or(Error::Flexicast(FcError::McPath))?;

        if let Some(pid) = self.paths.pid_from_path_id(fc_path_id) {
            let is_app_limited = self.delivery_rate_check_if_app_limited(pid);
            let (p, np) = self.paths.get_mut_with_active(pid)?;
            if is_app_limited {
                p.recovery.delivery_rate_update_app_limited(true);
            }

            let (lost_pkt, lost_bytes, acked_bytes) =
                p.recovery.on_ack_received(
                    ranges,
                    0,
                    Epoch::Application,
                    hs,
                    now,
                    &mut np.rtt_stats,
                    &self.trace_id,
                )?;

            self.lost_count += lost_pkt;
            self.lost_bytes += lost_bytes as u64;
            self.acked_bytes += acked_bytes as u64;

            debug!(
                "After fc_on_ack_received called with {:?}, the cwnd: {:?} {:?} {} {} {}",
                ranges,
                p.recovery.cwnd(),
                p.recovery.cwnd_available(),
                is_app_limited,
                self.lost_count,
                self.lost_bytes,
            );

            // Process acked frames.
            // For simplicity, only consider the STREAM frames.
            // Forward Erasure Correction extension: also consider
            // SOURCE_SYMBOL_HEADER and REPAIR frames.
            for acked in p.recovery.get_acked_frames(Epoch::Application) {
                match acked {
                    frame::Frame::StreamHeader {
                        stream_id,
                        offset,
                        length,
                        ..
                    } => {
                        let stream = match self.streams.get_mut(stream_id) {
                            Some(v) => v,

                            None => continue,
                        };

                        stream.send.ack_and_drop(offset, length);

                        self.tx_buffered =
                            self.tx_buffered.saturating_sub(length);

                        // Only collect the stream if it is complete and not
                        // readable. If it is readable, it will get collected when
                        // stream_recv() is used.
                        if stream.is_complete() && !stream.is_readable() {
                            let local = stream.local;
                            self.streams.collect(stream_id, local);
                        }
                    },

                    frame::Frame::Repair { .. } => {
                        if let Some(fec_encoder) = self.fec_encoder.as_mut() {
                            fec_encoder.fec_on_acked_repair_symbol();

                            // Potentially remove landed symbols.
                            fec_encoder.get_encoder().remove_landed_symbols();
                        }
                    },

                    frame::Frame::SourceSymbolHeader { metadata, .. } => {
                        if let Some(fec_encoder) = self.fec_encoder.as_mut() {
                            fec_encoder.get_encoder().symbol_landed(metadata);

                            // Potentially remove landed symbols.
                            fec_encoder.get_encoder().remove_landed_symbols();
                        }
                    },

                    _ => (),
                }
            }

            // Drain packets from the McAck structure.
            let largest_pn = p.recovery.get_lowest_pn_app_epoch();
            if let Some(mc_ack) = self.get_mc_ack_mut() {
                mc_ack.drain_packets(largest_pn);
            }
        }

        self.update_tx_cap();

        Ok(())
    }

    /// Gives ranges of received stream pieces that have been delegated for
    /// unicast retransmission. These pieces of streams have been received
    /// by all receivers and can release memory from the flexicast flow.
    /// This basically copies the portion of code that is processed when a
    /// unicast server receives an ACK frame acknowledging a STREAM frame.
    pub fn fc_on_stream_ack_received(
        &mut self, stream_id: u64, off: u64, len: u64,
    ) -> Result<()> {
        let stream = self.streams.get_mut(stream_id);
        if let Some(stream) = stream {
            stream.send.ack_and_drop(off, len as usize);
            self.tx_buffered = self.tx_buffered.saturating_sub(len as usize);

            // Only collect the stream if it is complete and not
            // readable. If it is readable, it will get collected when
            // stream_recv() is used.
            if stream.is_complete() && !stream.is_readable() {
                let local = stream.local;
                self.streams.collect(stream_id, local);
            }
        } else {
            error!(
                "fc_on_stream_ack_received stream does not exist: {:?}",
                stream_id
            );
        }

        self.update_tx_cap();

        Ok(())
    }

    /// Sets the recovery mode of the flexicast flow.
    pub fn fc_set_recovery_state(&mut self) -> Result<()> {
        if let Some(flexicast) = self.flexicast.as_ref() {
            if flexicast.mc_role != McRole::ServerFlexicast {
                return Err(Error::Flexicast(FcError::McInvalidRole(
                    McRole::ServerFlexicast,
                )));
            }

            if let Some(path_id) = flexicast.get_fc_path_id() {
                let pid = self
                    .paths
                    .pid_from_path_id(path_id)
                    .ok_or(Error::Flexicast(FcError::McPath))?;
                let p = self.paths.get_mut(pid)?;
                p.recovery.init_fc_recovery_state(McRole::ServerFlexicast);
                p.recovery.set_fc_recovery_epoch(true);

                return Ok(());
            }
            return Err(Error::Flexicast(FcError::McPath));
        }
        Err(Error::Flexicast(FcError::McDisabled))
    }

    /// The flexicast flow delegates lost STREAM frames to the unicast paths.
    /// Receivers may receive multiple times the same STREAM frame if some
    /// packets get delayed.
    ///
    /// Requires that the caller is the flexicast flow and the callee the
    /// unicast path.
    ///
    /// The `retr_kind` indicates the type of retransmission that is performed.
    pub fn rfc_delegate_streams(
        &mut self, uc: &mut Connection, now: time::Instant,
        retr_kind: FcUnicastRetransmission,
    ) -> Result<()> {
        if self.flexicast.is_none() || uc.flexicast.is_none() {
            return Ok(());
        }

        let fc_fc = self.flexicast.as_mut().unwrap();
        let fc_uc = uc.flexicast.as_ref().unwrap();

        if !matches!(fc_fc.mc_role, McRole::ServerFlexicast) {
            return Err(Error::Flexicast(FcError::McInvalidRole(fc_fc.mc_role)));
        }

        if !matches!(
            fc_uc.mc_role,
            McRole::ServerUnicast(McClientStatus::ListenMcPath(true)) |
                McRole::ServerUnicast(McClientStatus::UcFallBack)
        ) {
            return Ok(());
        }

        // Delegate the streams on the unicast paths.
        let path_id =
            fc_fc.fc_path_id.ok_or(Error::Flexicast(FcError::McPath))?;
        let pid = self
            .paths
            .pid_from_path_id(path_id)
            .ok_or(Error::Flexicast(FcError::McPath))?;
        let path = self.paths.get_mut(pid)?;
        let streams_fc = &mut self.streams;
        let mc_ack = &mut self
            .flexicast
            .as_mut()
            .unwrap()
            .fc_reliable
            .source_mut()
            .unwrap()
            .mc_ack;
        let (_nb_lost_stream_frames, (lost_pn, recv_pn)) = path
            .recovery
            .delegate_streams(uc, streams_fc, mc_ack, retr_kind)?;

        let highest_pn =
            lost_pn.last().unwrap_or(0).max(recv_pn.last().unwrap_or(0));

        // Get the path on the unicast path.
        let pid = uc.paths.pid_from_path_id(path_id);
        if let Some(pid) = pid {
            if let Ok((path, np)) = uc.paths.get_mut_with_active(pid) {
                path.recovery.set_largest_ack(highest_pn);
                let _out = path.recovery.detect_lost_packets(
                    Epoch::Application,
                    now,
                    &mut np.rtt_stats,
                    &self.trace_id,
                );
            }
        }
        Ok(())
    }

    /// Returns the packet number of packets that have been declared lost on the
    /// flexicast flow.
    pub fn fc_drain_lost_pn(&mut self) -> Result<HashSet<u64>> {
        let fca = fca!(self)?;
        let path = fca
            .fc_path_id
            .and_then(|id| self.paths.pid_from_path_id(id))
            .map(|pid| self.paths.get_mut(pid))
            .ok_or(Error::Flexicast(FcError::McPath))??;

        path.recovery
            .fc_recovery
            .as_mut()
            .map(|r| r.fc_new_lost_pn.drain(..).collect::<HashSet<_>>())
            .ok_or(Error::Flexicast(FcError::McReliableDisabled))
    }

    /// Hardly resets a stream starting offset, potentially breaking things, to
    /// retransmit a whole chunk of data.
    pub fn fc_reset_send_off(&mut self, stream_id: u64, off: u64) -> Result<u64> {
        if !self.flexicast.as_ref().is_some_and(|fc| {
            matches!(fc.get_mc_role(), McRole::ServerUnicast(_))
        }) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                McRole::Undefined,
            )));
        }

        self.get_or_create_stream(stream_id, true)?;

        self.streams.fc_reset_stream_send_at(stream_id, off)
    }

    /// Returns the sending min offset for a given stream.
    pub fn fc_get_stream_off_front(&self, stream_id: u64) -> Option<u64> {
        self.streams.get(stream_id).map(|s| s.send.ack_off())
    }

    /// Update the ack delay on the flexicast flow.
    pub fn fc_update_ack_delay(
        &mut self, nb_active_recv: u64, max_ack_rate: u64,
    ) -> Result<()> {
        if !self
            .flexicast
            .as_ref()
            .is_some_and(|fc| fc.get_mc_role() == McRole::ServerFlexicast)
        {
            return Ok(());
        }

        // Get the rate of the flexicast flow.
        let rate_flow =
            self.paths.get(InternalPathId(1))?.recovery.delivery_rate();

        // The ack rate is +/- 1/12 the sending rate without ack delay.
        let real_ack_rate = rate_flow / 12 * nb_active_recv;

        // If the real ack rate is below the maximum, do not add any ack delay.
        // Otherwise, we set the ack delay expecting ~100 byte ack packets.
        let ack_delay = if real_ack_rate < max_ack_rate {
            0
        } else {
            ((2 * 1600 * nb_active_recv) as f64 / (max_ack_rate as f64) *
                1_000_000f64) as u64 // micro s
        };

        if let Some(source) = self
            .flexicast
            .as_mut()
            .and_then(|fc| fc.fc_reliable.source_mut())
        {
            if let FcAckDelayStrategy::Adaptive(v) =
                &mut source.ack_delay_strategy
            {
                source.ack_delay = ack_delay;
                *v = ack_delay;
            }
        }

        Ok(())
    }

    /// Update the acknowledgment strategy on the flexicast flow.
    pub fn fc_update_ack_delay_strategy(
        &mut self, new_strat: FcAckDelayStrategy,
    ) {
        if let Some(source) = self
            .flexicast
            .as_mut()
            .and_then(|fc| fc.fc_reliable.source_mut())
        {
            source.ack_delay_strategy = new_strat;
        }
    }
}

/// All possible kinds of unicast retransmissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FcUnicastRetransmission {
    /// The source retransmits reliable frames that it considers as lost after
    /// acknowledgment aggregation.
    ///
    /// The boolean value indicates whether the flexicast flow can consider the
    /// packets delegated.
    Delegates(bool),

    /// Full retransmit. Happens when the source falls back on unicast for some
    /// receiver.
    FullRetransmit,

    /// This unicast path sees lost packets on its own and does not wait for the
    /// other receivers to receive the retransmissions. This is an
    /// optimization. The value contains the packet numbers that are lost
    /// for this receiver, using the QUIC reliability mechanism.
    PerUcPath(HashSet<u64>),
}

#[cfg(test)]
mod testing {
    use super::*;
    use crate::flexicast::testing::*;

    impl FlexicastPipe {
        /// Same as `source_delegates_streams` but does not check for
        /// mc_timeout.
        pub fn source_delegates_streams_direct(
            &mut self, expired: time::Instant,
            mut retr_kind: FcUnicastRetransmission,
        ) -> Result<()> {
            let nb_recv = self.unicast_pipes.len();
            let ucs = self.unicast_pipes.iter_mut().take_while(|_| true);
            let mc = &mut self.mc_channel.channel;
            let ucs = ucs.map(|c| &mut c.0.server);

            ucs.enumerate()
                .map(|(idx, uc)| {
                    if matches!(retr_kind, FcUnicastRetransmission::Delegates(_))
                    {
                        if idx < nb_recv - 1 {
                            retr_kind = FcUnicastRetransmission::Delegates(false);
                        } else {
                            retr_kind = FcUnicastRetransmission::Delegates(true);
                        }
                    }
                    mc.rfc_delegate_streams(uc, expired, retr_kind.clone())
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SecureRandom;
    use ring::rand::SystemRandom;

    use super::*;
    use crate::flexicast::testing::*;
    use crate::flexicast::FcConfig;
    use crate::rand::rand_u8;
    use crate::InternalPathId;

    impl FlexicastPipe {
        fn get_uc_path_mc_ack(&self, i: usize) -> Option<&McAck> {
            self.unicast_pipes
                .get(i)?
                .0
                .server
                .flexicast
                .as_ref()?
                .fc_reliable
                .server()
                .map(|s| &s.mc_ack)
        }
    }

    #[test]
    /// Tests that the received packets are correctly forwarded to the receiver
    /// and lie in the ReliableFc structure.
    fn test_fc_reliable_ack() {
        for probe_path in [false, true] {
            let mut fc_config = FcConfig {
                probe_mc_path: probe_path,
                ..Default::default()
            };

            let mut fc_pipe = FlexicastPipe::new(
                1,
                "/tmp/test_fc_reliable_ack",
                &mut fc_config,
            )
            .unwrap();

            assert!(fc_pipe.source_send_single_stream(true, None, 3).is_ok());
            assert!(fc_pipe.source_send_single_stream(true, None, 7).is_ok());
            let now = time::Instant::now();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            let mut readables = fc_pipe.unicast_pipes[0]
                .0
                .client
                .readable()
                .collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![3, 7]);

            assert!(fc_pipe.clients_send().is_ok());

            let mc_ack = fc_pipe.get_uc_path_mc_ack(0).unwrap();
            let (_ack_pn, _streams, nb_recv) = mc_ack.get_state();
            assert_eq!(nb_recv, 1);
            let ack_pn = mc_ack.full_ack_poll().unwrap();
            let mut expected_ack_pn = RangeSet::default();
            expected_ack_pn.insert(2..4);
            assert_eq!(ack_pn, &expected_ack_pn);
        }
    }

    #[test]
    /// Tests the full reliability mechanism of flexicast using the McAck
    /// structure.
    fn test_fc_quic_reliability_with_mc_ack() {
        for probe_path in [false, true] {
            let mut fc_config = FcConfig {
                probe_mc_path: probe_path,
                ..Default::default()
            };
            let mut fc_pipe = FlexicastPipe::new(
                2,
                "/tmp/test_fc_quic_reliability_with_mc_ack",
                &mut fc_config,
            )
            .unwrap();

            let sleep_duration = time::Duration::from_millis(100);
            let now = time::Instant::now();

            // First stream is received by both receivers.
            let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
            let (_, _, nb) = mc_ack.get_state();
            assert_eq!(nb, 2);
            fc_pipe.source_send_single_stream(true, None, 1).unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // The unicast paths have state for the new packets.
            let uc = &mut fc_pipe.unicast_pipes[0].0.server;
            let path = uc.paths.get(InternalPathId(1)).unwrap();
            let sent_pkt = path.recovery.get_sent_pkts();
            assert_eq!(sent_pkt[0].pkt_num, 2);

            // Clients read the stream.
            let mut buf = [0u8; 500];
            let client_0 = &mut fc_pipe.unicast_pipes[0].0.client;
            assert!(client_0.stream_readable(1));
            assert_eq!(client_0.stream_recv(1, &mut buf), Ok((300, true)));
            let client_1 = &mut fc_pipe.unicast_pipes[1].0.client;
            assert!(client_1.stream_readable(1));
            assert_eq!(client_1.stream_recv(1, &mut buf), Ok((300, true)));

            // Flexicast source has a packet in waiting for ack.
            let fc = &mut fc_pipe.mc_channel.channel;
            let path = fc.paths.get(InternalPathId(1)).unwrap();
            let sent_pkt = path.recovery.get_sent_pkts();
            assert_eq!(sent_pkt[0].pkt_num, 1);
            assert_eq!(sent_pkt[1].pkt_num, 2);
            assert!(sent_pkt[1].time_acked.is_none());
            let nb_ack = fc_pipe.mc_channel.channel.acked_bytes;

            // The flexicast source acknowledged the packet because both receivers
            // said it was ok.
            std::thread::sleep(sleep_duration);
            fc_pipe.mc_channel.channel.on_timeout();
            let now = time::Instant::now();
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // The flexicast flow and unicast path have acknowledged packets.
            let fc = &mut fc_pipe.mc_channel.channel;
            let path = fc.paths.get(InternalPathId(1)).unwrap();
            let sent_pkt = path.recovery.get_sent_pkts();
            assert!(sent_pkt[1].time_acked.is_some());

            assert!(fc_pipe.mc_channel.channel.acked_bytes > nb_ack);

            // McAck state is empty.
            let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
            let (pns, ..) = mc_ack.get_state();
            assert_eq!(pns.len(), 0);

            // Second stream is lost for the first client.
            let mut client_losses = RangeSet::default();
            client_losses.insert(0..1);
            fc_pipe
                .source_send_single_stream(true, Some(&client_losses), 7)
                .unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Only second client receives data.
            let client_0 = &mut fc_pipe.unicast_pipes[0].0.client;
            assert!(!client_0.stream_readable(7));
            let client_1 = &mut fc_pipe.unicast_pipes[1].0.client;
            assert!(client_1.stream_readable(7));
            assert_eq!(client_1.stream_recv(7, &mut buf), Ok((300, true)));

            std::thread::sleep(sleep_duration);
            fc_pipe.mc_channel.channel.on_timeout();
            let now = time::Instant::now();
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // No new complete acked packet.
            assert!(fc_pipe.mc_channel.channel.acked_bytes > nb_ack);

            // McAck contains state for this packet because it is not fully acked.
            let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
            let (pns, streams, _) = mc_ack.get_state();
            assert_eq!(pns.len(), 1);
            assert_eq!(*pns.values().next().unwrap(), 1); // Only one client need to ack the packet.
            assert_eq!(streams.len(), 0);

            // The arrival of a new stream will trigger a loss for Stream 7.
            let now = time::Instant::now();
            fc_pipe.source_send_single_stream(true, None, 11).unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            std::thread::sleep(sleep_duration);
            let now = time::Instant::now();
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            fc_pipe
                .source_delegates_streams_direct(
                    now,
                    FcUnicastRetransmission::Delegates(true),
                )
                .unwrap();

            // The unicast server now has state for the expired streams.
            let open_stream_ids = fc_pipe.unicast_pipes[0]
                .0
                .server
                .streams
                .writable()
                .collect::<Vec<_>>();
            assert_eq!(open_stream_ids, vec![7]);

            assert!(!fc_pipe.mc_channel.channel.streams.is_collected(7));

            // And the McAck of both the flexicast source and the unicast server
            // have state.
            let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
            let (_, streams, _) = mc_ack.get_state();
            assert_eq!(streams.len(), 1);
            let value = streams.get(&7).unwrap();
            assert_eq!(value.len(), 1);
            assert_eq!(value.iter().next().unwrap(), (&0, &(300, 1)));

            let mc_ack = &fc_pipe.unicast_pipes[0]
                .0
                .server
                .flexicast
                .as_ref()
                .unwrap()
                .fc_reliable
                .server()
                .unwrap()
                .mc_ack;
            let (_, streams, _) = mc_ack.get_state();
            assert_eq!(streams.len(), 1);
            let value = streams.get(&7).unwrap();
            assert_eq!(value.len(), 1);
            assert_eq!(value.iter().next().unwrap(), (&0, &(300, 1)));

            fc_pipe.unicast_pipes[0].0.advance().unwrap();

            // Client received the stream. State updated on the McAck of the
            // server.
            let mc_ack = &fc_pipe.unicast_pipes[0]
                .0
                .server
                .flexicast
                .as_ref()
                .unwrap()
                .fc_reliable
                .server()
                .unwrap()
                .mc_ack;
            let (_, streams, _) = mc_ack.get_state();
            assert!(streams.is_empty());

            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Now the flexicast source does not have any state for the open
            // stream.
            let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
            let (_, streams, _) = mc_ack.get_state();
            assert!(streams.is_empty());
            assert!(fc_pipe.mc_channel.channel.streams.is_collected(7));

            // First client now has the second stream.
            let client_0 = &mut fc_pipe.unicast_pipes[0].0.client;
            assert!(client_0.stream_readable(7));
            assert_eq!(client_0.stream_recv(7, &mut buf), Ok((300, true)));
        }
    }

    #[test]
    /// Tests the reliability mechanism of Flexicast QUIC with random packet
    /// losses.
    fn test_fc_quic_reliability_short_streams() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = FlexicastPipe::new(
            2,
            "/tmp/test_fc_quic_reliability_short_streams",
            &mut fc_config,
        )
        .unwrap();

        let sleep_duration = time::Duration::from_millis(2);

        // Send multiple short streams that can lie in a single packet.
        let nb_streams = 1000;
        for i in 0..nb_streams {
            // Generate random losses.
            let mask = rand_u8();

            // Do not generate losses for the last 2 streams to ensure that we see
            // gaps.
            let client_loss = if mask & 0b1 > 0 && i < nb_streams - 2 {
                let mut losses = RangeSet::default();
                for j in 1..4 {
                    if mask & 1 << j > 0 {
                        losses.insert(j - 1..j);
                    }
                }
                Some(losses)
            } else {
                None
            };

            // The source sends the stream.
            let now = time::Instant::now();
            fc_pipe
                .source_send_single_stream(true, client_loss.as_ref(), 3 + i * 4)
                .unwrap();

            // The source notifies the unicast instances of the sent packet.
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Wait a bit...
            std::thread::sleep(sleep_duration);
            let now = time::Instant::now();

            // Clients send their feedback to the source.
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Stream deleguation.
            fc_pipe
                .source_delegates_streams_direct(
                    now,
                    FcUnicastRetransmission::Delegates(true),
                )
                .unwrap();

            // Potentially unicast retransmissions.
            fc_pipe
                .unicast_pipes
                .iter_mut()
                .for_each(|(pipe, ..)| pipe.advance().unwrap());
        }

        // Ensure that each client received all the streams.
        for (pipe, ..) in fc_pipe.unicast_pipes.iter_mut() {
            let client = &mut pipe.client;
            for i in 0..nb_streams {
                assert!(client.stream_readable(3 + i * 4));
            }
        }
    }

    #[test]
    /// Tests the reliability mechanism with a single sent stream and relying on
    /// the timeout of the server.
    fn test_fc_quic_reliability_timeout() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = FlexicastPipe::new(
            1,
            "/tmp/test_fc_quic_reliability_timeout",
            &mut fc_config,
        )
        .unwrap();

        let sleep_duration = time::Duration::from_millis(2);

        let mut client_loss = RangeSet::default();
        client_loss.insert(0..1);

        fc_pipe
            .source_send_single_stream(true, Some(&client_loss), 3)
            .unwrap();

        // Looping until we receive the packet. Set a "timeout" to ensure that we
        // don't loop for ever.
        for _ in 0..5 {
            // Timeout of the flexicast source.
            let now = time::Instant::now();
            let _ = fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();

            // Allow the flexicast source to send more packets, e.g., ping frames.
            let _ = fc_pipe.source_send_single(None);

            // The source notifies the unicast instances of the sent packet.
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Wait a bit...
            std::thread::sleep(sleep_duration);
            let now = time::Instant::now();

            // Clients send their feedback to the source.
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Stream delegation.
            fc_pipe
                .source_delegates_streams_direct(
                    now,
                    FcUnicastRetransmission::Delegates(true),
                )
                .unwrap();

            // Potentially unicast retransmissions.
            fc_pipe
                .unicast_pipes
                .iter_mut()
                .for_each(|(pipe, ..)| pipe.advance().unwrap());

            // Test if the stream is readable.
            let client = &fc_pipe.unicast_pipes[0].0.client;
            if client.stream_readable(3) {
                return; // Ok.
            }
        }

        let client = &fc_pipe.unicast_pipes[0].0.client;
        assert!(client.stream_readable(3));
    }

    #[test]
    /// Tests the reliability of Flexicast QUIC with two long streams and random
    /// losses.
    fn test_fc_quic_reliability_long_streams() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = FlexicastPipe::new(
            2,
            "/tmp/test_fc_quic_reliability_long_streams",
            &mut fc_config,
        )
        .unwrap();

        let random = SystemRandom::new();
        let sleep_duration = time::Duration::from_millis(2);

        // Two streams.
        let mut buf = vec![0u8; 40_000];
        random.fill(&mut buf[..]).unwrap();
        fc_pipe
            .mc_channel
            .channel
            .stream_send(3, &buf[..30_000], true)
            .unwrap();
        fc_pipe
            .mc_channel
            .channel
            .stream_send(7, &buf[30_000..], true)
            .unwrap();

        let nb_turns_allowed = 100;

        for i in 0..nb_turns_allowed {
            // Generate random losses.
            let mask = rand_u8();

            // Do not generate losses for the last 2 streams to ensure that we see
            // gaps.
            let client_loss =
                if mask & 0b1 > 0 && i < nb_turns_allowed - 5 && i > 5 {
                    let mut losses = RangeSet::default();
                    for j in 1..4 {
                        if mask & 1 << j > 0 {
                            losses.insert(j - 1..j);
                        }
                    }
                    Some(losses)
                } else {
                    None
                };

            // The source sends the stream or other content.
            let now = time::Instant::now();
            let _ = fc_pipe.source_send_single(client_loss.as_ref());

            // The source notifies the unicast instances of the sent packet.
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Clients set timeout information.
            fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();

            // Wait a bit...
            std::thread::sleep(sleep_duration);
            let now = time::Instant::now();

            // Clients send their feedback to the source.
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Stream deleguation.
            fc_pipe
                .source_delegates_streams_direct(
                    now,
                    FcUnicastRetransmission::Delegates(true),
                )
                .unwrap();

            // Potentially unicast retransmissions.
            fc_pipe
                .unicast_pipes
                .iter_mut()
                .for_each(|(pipe, ..)| pipe.advance().unwrap());
            fc_pipe.server_control_to_mc_source(now).unwrap();
        }

        // Ensure that each client received all the streams.
        let mut out = vec![0u8; 30_001];
        for (pipe, ..) in fc_pipe.unicast_pipes.iter_mut() {
            let client = &mut pipe.client;
            assert!(client.stream_readable(3));
            assert_eq!(client.stream_recv(3, &mut out[..]), Ok((30_000, true)));
            assert_eq!(&out[..30_000], &buf[..30_000]);

            assert!(client.stream_readable(7));
            assert_eq!(client.stream_recv(7, &mut out[..]), Ok((10_000, true)));
            assert_eq!(&out[..10_000], &buf[30_000..]);
        }

        // Streams are collected on the flexicast flow.
        assert!(fc_pipe.mc_channel.channel.streams.is_collected(3));
        assert!(fc_pipe.mc_channel.channel.streams.is_collected(7));

        // Ensure that on all the unicast paths the streams are closed.
        for (pipe, ..) in fc_pipe.unicast_pipes.iter_mut() {
            assert!(
                pipe.server.streams.is_collected(3) ||
                    pipe.server.streams.get(3).is_none()
            );
            assert!(
                pipe.server.streams.is_collected(7) ||
                    pipe.server.streams.get(7).is_none()
            );

            assert!(pipe.client.streams.is_collected(3));
            assert!(pipe.client.streams.is_collected(7));
        }
    }

    #[test]
    /// Tests the reliability mechanism of Flexicast QUIC with multiple timeout.
    /// The source must not drain lost packets that have not been retransmitted
    /// to the unicast path.
    fn test_fc_quic_reliability_no_drain() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = FlexicastPipe::new(
            1,
            "/tmp/test_fc_quic_reliability_no_drain",
            &mut fc_config,
        )
        .unwrap();

        let sleep_duration = time::Duration::from_millis(2);

        let mut client_loss = RangeSet::default();
        client_loss.insert(0..1);

        fc_pipe
            .source_send_single_stream(true, Some(&client_loss), 3)
            .unwrap();

        let now = time::Instant::now();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Timeout of the flexicast source.
        std::thread::sleep(sleep_duration);
        let now = time::Instant::now();
        let _ = fc_pipe.mc_channel.channel.on_timeout();
        fc_pipe
            .mc_channel
            .channel
            .send_ack_eliciting_on_path_with_path_id(1)
            .unwrap();

        // Allow the flexicast source to send more packets, e.g., ping frames.
        let _ = fc_pipe.source_send_single(None);
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.clients_send().unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Wait a bit...
        std::thread::sleep(sleep_duration);
        let now = time::Instant::now();

        // Allow the flexicast source to send more packets, e.g., ping frames.
        let _ = fc_pipe.mc_channel.channel.on_timeout();
        fc_pipe
            .mc_channel
            .channel
            .send_ack_eliciting_on_path_with_path_id(1)
            .unwrap();
        let _ = fc_pipe.source_send_single(None);
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.clients_send().unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        std::thread::sleep(sleep_duration);
        let now = time::Instant::now();

        // Stream deleguation.
        fc_pipe
            .source_delegates_streams_direct(
                now,
                FcUnicastRetransmission::Delegates(true),
            )
            .unwrap();

        // Potentially unicast retransmissions.
        fc_pipe
            .unicast_pipes
            .iter_mut()
            .for_each(|(pipe, ..)| pipe.advance().unwrap());

        // Test if the stream is readable.
        let client = &fc_pipe.unicast_pipes[0].0.client;
        assert!(client.stream_readable(3));
    }

    #[test]
    /// Tests a flexicast channel where the flexicast flow always fails for the
    /// first receiver. The other receivers use normal retransmissions to
    /// recover the loss.
    fn test_fc_quic_reliability_fcf_failing() {
        for fec in [false, true] {
            let mut fc_config = FcConfig {
                probe_mc_path: true,
                fec,
                ..Default::default()
            };
            let mut fc_pipe = FlexicastPipe::new(
                3,
                "/tmp/test_fc_quic_reliability_fcf_failing",
                &mut fc_config,
            )
            .unwrap();

            let sleep_duration = time::Duration::from_millis(2);
            let now = time::Instant::now();

            let mut client_loss = RangeSet::default();
            client_loss.insert(0..1);
            let mut client_loss2 = client_loss.clone();
            client_loss2.insert(1..3);

            // Sends three STREAM frame that is lost.
            fc_pipe
                .source_send_single_stream(true, Some(&client_loss), 3)
                .unwrap();
            fc_pipe
                .source_send_single_stream(true, Some(&client_loss2), 7)
                .unwrap();
            for i in 2..6 {
                fc_pipe
                    .source_send_single_stream(
                        true,
                        Some(&client_loss),
                        3 + i * 4,
                    )
                    .unwrap();
            }
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Sleep to trigger timeout on the flexicast source.
            std::thread::sleep(sleep_duration);
            let _ = fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();
            let _ = fc_pipe.source_send_single(Some(&client_loss)).unwrap();

            // The first receiver leaves for now listening to the flexicast
            // content.
            let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
            mc_ack.remove_recv(None);

            std::thread::sleep(sleep_duration);
            let now = time::Instant::now();

            // The receiver received no packet.
            let recv = &mut fc_pipe.unicast_pipes[0].0.client;
            assert_eq!(recv.readable().next(), None);

            // After some time, a flexicast flow scheduler fall-back to unicast
            // delivery. Future packets will be distributed over unicast.
            // However, we need to ensure that all STREAM frames that were
            // distributed over the flexicast flow are now delegated
            // to the unicast path.
            let uc = &mut fc_pipe.unicast_pipes[0].0.server;
            fc_pipe
                .mc_channel
                .channel
                .rfc_delegate_streams(
                    uc,
                    now,
                    FcUnicastRetransmission::FullRetransmit,
                )
                .unwrap();
            fc_pipe.unicast_pipes[0].0.advance().unwrap();

            // Now, the receiver got all streams.
            let recv = &mut fc_pipe.unicast_pipes[0].0.client;
            for stream_id in 0..6 {
                assert!(recv.stream_readable(3 + stream_id * 4));
            }

            // The second receiver uses now the retransmission.
            let recv = &mut fc_pipe.unicast_pipes[1].0.client;
            let mut readables = recv.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![3, 11, 15, 19, 23]);
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            let uc = &mut fc_pipe.unicast_pipes[1].0.server;
            fc_pipe
                .mc_channel
                .channel
                .rfc_delegate_streams(
                    uc,
                    now,
                    FcUnicastRetransmission::Delegates(false),
                )
                .unwrap();

            // The third receiver uses now the retransmission.
            let recv = &mut fc_pipe.unicast_pipes[2].0.client;
            let mut readables = recv.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![3, 11, 15, 19, 23]);
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            let uc = &mut fc_pipe.unicast_pipes[2].0.server;
            fc_pipe
                .mc_channel
                .channel
                .rfc_delegate_streams(
                    uc,
                    now,
                    FcUnicastRetransmission::Delegates(true),
                )
                .unwrap();

            fc_pipe.unicast_pipes[1].0.advance().unwrap();
            let recv = &mut fc_pipe.unicast_pipes[1].0.client;
            let mut readables = recv.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![3, 7, 11, 15, 19, 23]);

            fc_pipe.unicast_pipes[2].0.advance().unwrap();
            let recv = &mut fc_pipe.unicast_pipes[2].0.client;
            let mut readables = recv.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![3, 7, 11, 15, 19, 23]);
        }
    }

    #[test]
    /// Tests that a unicast path can ask for retransmissions of data on the
    /// flexicast flow even before the acknowledgment aggregation.
    ///
    /// Two receivers, one already sends its acknowledgments, not the other. The
    /// first one should receive the retransmissions.
    fn test_fc_quic_reliability_recv_retransmit() {
        for fec in [true, false] {
            let mut fc_config = FcConfig {
                probe_mc_path: true,
                fec,
                ..Default::default()
            };

            // No expiration timer = no delayed acknowledgment.
            fc_config.mc_announce_data[0].fc_ack_delay = 0;

            let mut fc_pipe = FlexicastPipe::new(
                2,
                "/tmp/test_fc_quic_reliability_recv_retransmit",
                &mut fc_config,
            )
            .unwrap();

            let sleep_duration = time::Duration::from_millis(10);

            let mut client_loss1 = RangeSet::default();
            client_loss1.insert(0..1);
            let mut client_loss2 = RangeSet::default();
            client_loss2.insert(1..2);
            let mut client_loss12 = RangeSet::default();
            client_loss12.insert(0..2);

            // The source sends 3 streams. First lost by recv 1, second lost by
            // recv 2.
            fc_pipe
                .source_send_single_stream(true, Some(&client_loss1), 3)
                .unwrap();
            fc_pipe
                .source_send_single_stream(true, Some(&client_loss12), 7)
                .unwrap();
            fc_pipe.source_send_single_stream(true, None, 11).unwrap();

            // Control to notify the sent packets.
            let now = time::Instant::now();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Acknowledgments from the first receiver.
            fc_pipe.unicast_pipes[0].0.advance().unwrap();

            // Verify that the receiver correctly sent the acknowledgments.
            let rmc_server = fc_pipe.unicast_pipes[0]
                .0
                .server
                .flexicast
                .as_ref()
                .unwrap()
                .fc_reliable
                .server()
                .unwrap();
            let mut ack_pn = RangeSet::default();
            ack_pn.insert(4..5);
            assert_eq!(rmc_server.mc_ack.full_ack_poll().unwrap(), &ack_pn);
            fc_pipe.server_control_to_mc_source(now).unwrap();

            fc_pipe.unicast_pipes[0].0.server.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            std::thread::sleep(sleep_duration);
            fc_pipe.unicast_pipes[0].0.server.on_timeout();

            let now = time::Instant::now();

            // The unicast path of the first receiver has some lost packets.
            let lost_pn_res = fc_pipe.unicast_pipes[0]
                .0
                .server
                .fc_drain_lost_pn()
                .unwrap();
            let lost_pn = [2, 3].iter().map(|i| *i).collect();
            assert_eq!(lost_pn_res, lost_pn);

            // And the receiver cannot read the lost stream.
            let mut readables = fc_pipe.unicast_pipes[0]
                .0
                .client
                .readable()
                .collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![11]);

            // The unicast path of the first receiver asks for retransmissions for
            // this receiver.
            let uc = &mut fc_pipe.unicast_pipes[0].0.server;
            let retr_kind = FcUnicastRetransmission::PerUcPath(lost_pn);
            fc_pipe
                .mc_channel
                .channel
                .rfc_delegate_streams(uc, now, retr_kind)
                .unwrap();

            // Communication on the unicast path.
            fc_pipe.unicast_pipes[0].0.advance().unwrap();

            // And now the receiver has the whole data.
            let mut readables = fc_pipe.unicast_pipes[0]
                .0
                .client
                .readable()
                .collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![3, 7, 11]);

            // The second receiver has two streams.
            let mut readables = fc_pipe.unicast_pipes[1]
                .0
                .client
                .readable()
                .collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![3, 11]);

            // And unicast communication + control to ensure that the source
            // released the whole memory.
            std::thread::sleep(sleep_duration);
            let now = time::Instant::now();
            fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();
            fc_pipe.source_send_single_stream(true, None, 15).unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Now the second receiver sends its acknowledgment.
            std::thread::sleep(sleep_duration);
            let now = time::Instant::now();
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();
            let uc = &mut fc_pipe.unicast_pipes[1].0.server;
            let retr_kind = FcUnicastRetransmission::Delegates(true);
            fc_pipe
                .mc_channel
                .channel
                .rfc_delegate_streams(uc, now, retr_kind)
                .unwrap();
            fc_pipe.unicast_pipes[1].0.advance().unwrap();

            // Now the second receiver has the whole data.
            let mut readables = fc_pipe.unicast_pipes[1]
                .0
                .client
                .readable()
                .collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![3, 7, 11, 15]);

            fc_pipe.source_send_single_stream(true, None, 19).unwrap();
            fc_pipe.source_send_single_stream(true, None, 13).unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            std::thread::sleep(sleep_duration);
            let now = time::Instant::now();
            fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();
            fc_pipe.source_send_single(None).unwrap();
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            for _ in 0..100 {
                fc_pipe.mc_channel.channel.on_timeout();
                fc_pipe
                    .mc_channel
                    .channel
                    .send_ack_eliciting_on_path_with_path_id(1)
                    .unwrap();
                fc_pipe.source_send_single(None).unwrap();
                std::thread::sleep(sleep_duration);
                let now = time::Instant::now();
                fc_pipe.clients_send().unwrap();
                fc_pipe.server_control_to_mc_source(now).unwrap();
            }
        }
    }
}
