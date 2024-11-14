//! Reliability extension for Multicast QUIC.

use super::ack::McAck;
use super::McError;
use super::MulticastAttributes;
use super::MulticastConnection;
use crate::multicast::MissingRangeSet;
use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::recovery::multicast::ReliableMulticastRecovery;
use crate::Connection;
use crate::Error;
use crate::Result;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::time;

use super::McClientStatus;
use super::McRole;

/// On rmc timeout for the server.
#[macro_export]
macro_rules! on_rmc_timeout_server {
    ( $mc:expr, $ucs:expr, $now:expr ) => {
        if $mc.mc_timeout($now) == Some(std::time::Duration::ZERO) {
            $ucs.map(|uc| $mc.rmc_deleguate_streams(uc, $now, false))
                .collect()
        } else {
            Ok(())
        }
    };
}

#[derive(Debug, PartialEq, Eq, Default)]
/// Reliable multicast attributes for the client.
pub struct RMcClient {
    /// Next time the client will send a positive ACK.
    rmc_next_time_ack: Option<time::Instant>,

    /// Whether the client must send positive acknowledgment packets.
    rmc_client_send_ack: bool,

    /// Whether the client must send SourceSymbolAck frames.
    rmc_client_send_ssa: bool,
}

impl RMcClient {
    /// Sets the [`RMcClient::rmc_client_send_ack`].
    pub fn set_rmc_client_send_ack(&mut self, v: bool) {
        self.rmc_client_send_ack = v;
    }

    /// Sets the [`RMcClient::rmc_client_send_ssa`].
    pub fn set_rmc_client_send_ssa(&mut self, v: bool) {
        self.rmc_client_send_ssa = v;
    }
}

#[derive(Debug, Default)]
/// Reliable multicast attributes for the server.
pub struct RMcServer {
    /// Packet numbers received by the client.
    recv_pn_mc: RangeSet,

    /// FEC metadata received by the client.
    recv_fec_mc: RangeSet,

    /// Number of packets containing STREAM frames sent over the multicast path
    /// that expired and must be retransmitted to the client over the unicast
    /// path.
    nb_lost_stream_mc_pkt: u64,

    /// Newly acknowledged packet that were sent on the flexicast path.
    pub(crate) new_ack_pn_fc: RangeSet,

    /// Multicast Ack aggregator.
    /// The role of this structure here is different than for the flexicast
    /// source. Here, the structure helps the unicast server to know which
    /// stream offsets have been deleguated for unicast retransmission.
    pub(crate) mc_ack: McAck,

    /// Whether the Flexicast flow is aware that this client listens to it.
    pub notified_fc_source: bool,
}

impl RMcServer {
    /// Sets the packet number received by the client on the multicast channel.
    pub fn set_rmc_received_pn(&mut self, ranges: RangeSet) {
        for range in ranges.iter() {
            self.recv_pn_mc.insert(range);
        }
    }

    /// Returns the highest packet number received on the flexicast flow.
    pub fn get_highest_pn(&self) -> Option<u64> {
        self.recv_pn_mc.last()
    }

    /// Sets the FEC metadata received bu the client on the multicast channel.
    pub fn set_rmc_received_fec_metadata(&mut self, ranges: RangeSet) {
        for range in ranges.iter() {
            self.recv_fec_mc.insert(range);
        }
    }

    /// Returns the number of packets containing STREAM frames sent over the
    /// multicast path that expired and must be retransmitted to the client over
    /// the unicast path.
    pub fn get_nb_lost_stream_mc_pkt(&self) -> u64 {
        self.nb_lost_stream_mc_pkt
    }
}

#[derive(Debug, Default)]
/// Reliable multicast extension for the multicast source.
pub struct RMcSource {
    /// Maximum rangeset of lost frames for a client.
    pub(crate) max_rangeset: Option<(RangeSet, RangeSet)>,

    /// Multicast acknowledgment aggregator.
    pub(crate) mc_ack: McAck,
}

/// Reliable multicast attributes.
#[derive(Debug)]
pub enum ReliableMc {
    /// Client-specific reliable multicast.
    /// Used to store information about the next positive acks to send.
    Client(RMcClient),

    /// Unicast-server specific reliable multicast.
    /// Used to store the positive acks sent by the client about the multicast
    /// channel.
    Server(RMcServer),

    /// Multicast source specific reliable multicast.
    McSource(RMcSource),

    /// Undefined role. Used to initialise the structure at first.
    Undefined,
}

impl ReliableMc {
    /// Return a mutable reference to the client inner structure.
    pub fn client(&self) -> Option<&RMcClient> {
        if let Self::Client(c) = self {
            Some(c)
        } else {
            None
        }
    }

    /// Return a mutable reference to the server inner structure.
    pub fn server(&self) -> Option<&RMcServer> {
        if let Self::Server(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return a reference to the source inner structure.
    pub fn source(&self) -> Option<&RMcSource> {
        if let Self::McSource(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return a mutable reference to the client inner structure.
    pub fn client_mut(&mut self) -> Option<&mut RMcClient> {
        if let Self::Client(c) = self {
            Some(c)
        } else {
            None
        }
    }

    /// Return a mutable reference to the server inner structure.
    pub fn server_mut(&mut self) -> Option<&mut RMcServer> {
        if let Self::Server(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return a mutable reference to the source inner structure.
    pub fn source_mut(&mut self) -> Option<&mut RMcSource> {
        if let Self::McSource(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

/// Reliable multicast extension behaviour for the QUIC connection.
pub trait ReliableMulticastConnection {
    /// Returns the amount of time until the next reliable multicast timeout
    /// event.
    ///
    /// Once the given duration has elapsed, the [`on_rmc_timeout()`] method
    /// should be called. A timeout of `None` means that the timer sould be
    /// disarmed.
    fn rmc_timeout(&self, now: time::Instant) -> Option<time::Duration>;

    /// Processes a reliable multicast timeout event.
    ///
    /// If no timeout has occurred it does nothing.
    fn on_rmc_timeout(&mut self, now: time::Instant) -> Result<()>;

    /// Sets the next timeout for the client to send a positive acknowledgment.
    fn rmc_set_next_timeout(
        &mut self, now: time::Instant, random: &SystemRandom,
    ) -> Result<()>;

    /// Whether the client should send a positive acknowledgment frame to the
    /// server.
    ///
    /// Returns a [`crate::Error::Multicast`] with
    /// [`crate::multicast::McError::McInvalidRole`] if this is not a
    /// client.
    /// Returns a [`crate::Error::Multicast`] with
    /// [`crate::multicast::McError::McReliableDisabled`] if reliable
    /// multicast is disabled.
    fn rmc_should_send_positive_ack(&self) -> Result<bool>;

    /// Whether the client should send a SourceSymbolAck frame.
    ///
    /// Returns a [`crate::Error::Multicast`] with
    /// [`crate::multicast::McError::McInvalidRole`] if this is not a
    /// client.
    /// Returns a [`crate::Error::Multicast`] with
    /// [`crate::multicast::McError::McReliableDisabled`] if reliable
    /// multicast is disabled.
    fn rmc_should_send_source_symbol_ack(&self) -> Result<bool>;

    /// The multicast source delegates expired streams to the unicast path to
    /// provide full reliability to the transmission. Start the stream at
    /// the first offset of a missing STREAM frame until the end of the stream.
    /// As a result, the client may receive multiple times the same stream
    /// chunks. RMC-TODO: does the stream library handle this correctly?
    ///
    /// Requires that the caller is the multicast source
    /// ([`crate::multicast::McRole::ServerMulticast`]) and the callee
    /// the unicast server ([`crate::multicast::McRole::ServerUnicast`]).
    /// Returns the stream IDs of streams that are deleguated to the unicast
    /// path.
    ///
    /// The `full_retransmit` flag is set whether all packets that are
    /// not acknowledged by the receiver MUST be retransmitted,
    /// even if they are not considered lost by the flexicast source.
    /// This may be used, e.g., when a receiver falls back on unicast.
    fn rmc_deleguate_streams(
        &mut self, uc: &mut Connection, now: time::Instant, full_retransmit: bool,
    ) -> Result<()>;

    /// Returns the [`crate::ranges::RangeSet`] of packet numbers received by
    /// the client on the multicast path.
    fn rmc_get_recv_pn(&self) -> Result<&RangeSet>;

    /// Returns the [`crate::ranges::RangeSet`] of FEC recovered source symbols
    /// received by the client.
    fn rmc_get_rec_ss(&self) -> Result<&RangeSet>;

    /// Resets the set of packet numbers/source symbols received by the client
    /// on the multicast path.
    fn rmc_reset_recv_pn_ss(&mut self, exp_pn: Option<u64>, exp_ss: Option<u64>);
}

impl ReliableMulticastConnection for Connection {
    fn rmc_timeout(&self, now: time::Instant) -> Option<time::Duration> {
        let multicast = self.multicast.as_ref()?;

        // No timeout for client not in the group/transient leaving.
        if matches!(
            multicast.mc_role,
            McRole::Client(McClientStatus::AwareUnjoined)
                | McRole::Client(McClientStatus::Leaving(_))
        ) {
            return None;
        }

        let mc_reliable = &multicast.mc_reliable;

        if let ReliableMc::Client(rmc) = mc_reliable {
            Some(rmc.rmc_next_time_ack?.duration_since(now))
        } else {
            None
        }
    }

    fn on_rmc_timeout(&mut self, now: time::Instant) -> Result<()> {
        if let Some(time::Duration::ZERO) = self.rmc_timeout(now) {
            // Should be the client.
            assert!(!self.is_server);
            if let Some(multicast) = self.multicast.as_mut() {
                if let ReliableMc::Client(rmc) = &mut multicast.mc_reliable {
                    rmc.set_rmc_client_send_ack(true);
                    rmc.set_rmc_client_send_ssa(true);
                    rmc.rmc_next_time_ack = None; // Reset the next time ack.
                }
            }
        }
        Ok(())
    }

    fn rmc_set_next_timeout(
        &mut self, now: time::Instant, random: &SystemRandom,
    ) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            let expiration_timer =
                multicast.get_mc_announce_data(0).unwrap().expiration_timer;

            if let ReliableMc::Client(ref mut rmc) = multicast.mc_reliable {
                // Next time ack already set.
                if rmc.rmc_next_time_ack.is_some() {
                    return Ok(());
                }
                let mut random_v = [0u8; 4];
                random.fill(&mut random_v).ok();
                let additional_timer = i32::from_be_bytes(random_v) as i128;
                let et_with_random = expiration_timer as i128 / 2
                    + (additional_timer
                        % ((expiration_timer / 10).max(1) as i128));
                rmc.rmc_next_time_ack = now.checked_add(
                    time::Duration::from_millis(et_with_random as u64),
                );
                Ok(())
            } else {
                Err(Error::Multicast(McError::McReliableDisabled))
            }
        } else {
            Err(Error::Multicast(McError::McDisabled))
        }
    }

    fn rmc_should_send_positive_ack(&self) -> Result<bool> {
        self.multicast
            .as_ref()
            .ok_or(Error::Multicast(McError::McDisabled))?
            .mc_reliable
            .client()
            .ok_or(Error::Multicast(McError::McInvalidRole(McRole::Undefined)))
            .map(|c| c.rmc_client_send_ack)
    }

    fn rmc_should_send_source_symbol_ack(&self) -> Result<bool> {
        self.multicast
            .as_ref()
            .ok_or(Error::Multicast(McError::McDisabled))?
            .mc_reliable
            .client()
            .ok_or(Error::Multicast(McError::McInvalidRole(McRole::Undefined)))
            .map(|c| c.rmc_client_send_ssa)
    }

    fn rmc_deleguate_streams(
        &mut self, uc: &mut Connection, now: time::Instant, full_retransmit: bool,
    ) -> Result<()> {
        if let (Some(mc_s), Some(mc_u)) =
            (self.multicast.as_mut(), uc.get_multicast_attributes())
        {
            if mc_s.get_mc_role() != McRole::ServerMulticast {
                return Err(Error::Multicast(McError::McInvalidRole(
                    mc_s.get_mc_role(),
                )));
            }
            if !matches!(
                mc_u.get_mc_role(),
                McRole::ServerUnicast(McClientStatus::ListenMcPath(true))
            ) {
                return Ok(());
            }

            // Deleguate streams sent on the multicast path.
            let space_id = mc_s
                .get_mc_space_id()
                .ok_or(Error::Multicast(McError::McPath))?;
            let path = self.paths.get_mut(space_id)?;
            let stream_map = &mut self.streams;
            let mc_ack = mc_s
                .mc_reliable
                .source_mut()
                .map(|s| &mut s.mc_ack)
                .ok_or(Error::Multicast(McError::McReliableDisabled))?;
            let (nb_lost_stream_frames, (mut lost_pn, mut recv_pn)) =
                path.recovery.deleguate_stream(
                    uc,
                    space_id as u32,
                    stream_map,
                    mc_ack,
                    full_retransmit,
                )?;
            if let ReliableMc::Server(ref mut rmc_server) =
                uc.multicast.as_mut().unwrap().mc_reliable
            {
                rmc_server.nb_lost_stream_mc_pkt += nb_lost_stream_frames;
            }

            if let Some(exp) = mc_s.mc_last_expired {
                if let Some(exp_pn) = exp.pn {
                    // Remove already expired feedback from the `recv_pn` value.
                    recv_pn.remove_until(exp_pn);
                    lost_pn.remove_until(exp_pn);

                    // Reset the congestion control state if the expired packet is
                    // less than the first packet of interest given in the MC_KEY.
                    // CHEAT: assume that we consider the first 3 packets sent on
                    // this path.
                    if exp_pn <= 10 {
                        if let Ok(uc_path) = uc.paths.get_mut(1) {
                            debug!("MC-DEBUG: reset the congestion controller state for the server");
                            uc_path.recovery.reset();
                        }
                    }
                }
            }
            let max_pn =
                lost_pn.last().unwrap_or(0).max(recv_pn.last().unwrap_or(0));

            if let Some(rmc) = mc_s.rmc_get_mut().source_mut() {
                if let Some((_, recv)) = &rmc.max_rangeset {
                    if recv.nb_elements() > recv_pn.nb_elements() {
                        rmc.max_rangeset = Some((lost_pn, recv_pn));
                    }
                } else {
                    rmc.max_rangeset = Some((lost_pn, recv_pn));
                }
            }

            if let Ok(path) = uc.paths.get_mut(1) {
                path.recovery.set_largest_ack(max_pn);
                let _out = path.recovery.detect_lost_packets(
                    crate::packet::Epoch::Application,
                    now,
                    &self.trace_id,
                );
            }
        } else {
            return Ok(());
        }

        Ok(())
    }

    fn rmc_get_recv_pn(&self) -> Result<&RangeSet> {
        if let Some(multicast) = self.multicast.as_ref() {
            if let ReliableMc::Server(ref s) = multicast.mc_reliable {
                Ok(&s.recv_pn_mc)
            } else {
                Err(Error::Multicast(McError::McReliableDisabled))
            }
        } else {
            Err(Error::Multicast(McError::McDisabled))
        }
    }

    fn rmc_get_rec_ss(&self) -> Result<&RangeSet> {
        if let Some(multicast) = self.multicast.as_ref() {
            if let ReliableMc::Server(ref s) = multicast.mc_reliable {
                Ok(&s.recv_fec_mc)
            } else {
                Err(Error::Multicast(McError::McReliableDisabled))
            }
        } else {
            Err(Error::Multicast(McError::McDisabled))
        }
    }

    fn rmc_reset_recv_pn_ss(&mut self, exp_pn: Option<u64>, exp_ss: Option<u64>) {
        if let Some(multicast) = self.multicast.as_mut() {
            if let ReliableMc::Server(ref mut s) = multicast.mc_reliable {
                // Instead of resetting the ranges, we remove the expired values.
                if let Some(exp) = exp_pn {
                    s.recv_pn_mc.remove_until(exp);
                } else {
                    // s.recv_pn_mc = RangeSet::default();
                }

                if let Some(exp) = exp_ss {
                    s.recv_fec_mc.remove_until(exp);
                } else {
                    // s.recv_fec_mc = RangeSet::default();
                }
            }
        }
    }
}

impl Connection {
    /// Gives ranges of received packets from all flexicast receiver.
    /// Internally calls `on_ack_receiver`.
    pub fn fc_on_ack_received(
        &mut self, ranges: &RangeSet, now: time::Instant,
    ) -> Result<()> {
        let hs = self.handshake_status();
        let multicast = self
            .multicast
            .as_mut()
            .ok_or(Error::Multicast(McError::McDisabled))?;
        if multicast.mc_role != McRole::ServerMulticast {
            return Err(Error::Multicast(McError::McInvalidRole(
                McRole::ServerMulticast,
            )));
        }
        let fc_space_id = multicast
            .get_mc_space_id()
            .ok_or(Error::Multicast(McError::McPath))?;
        if let Ok(e) = self.ids.get_dcid(fc_space_id as u64) {
            // If this is a multicast MC_NACK packet, the server has no
            // idea of this second path.
            if let Some(path_id) = e.path_id {
                let is_app_limited =
                    self.delivery_rate_check_if_app_limited(path_id);
                let p = self.paths.get_mut(path_id)?;
                if is_app_limited {
                    p.recovery.delivery_rate_update_app_limited(true);
                }
                let (lost_packets, lost_bytes) = p.recovery.on_ack_received(
                    fc_space_id as u32,
                    ranges,
                    0,
                    Epoch::Application,
                    hs,
                    now,
                    &self.trace_id,
                    &mut self.newly_acked,
                )?;
                self.lost_count += lost_packets;
                self.lost_bytes += lost_bytes as u64;

                // Drain packets from the McAck structure.
                let largest_pn =
                    p.recovery.get_lowest_pn_app_epoch(fc_space_id as u32);
                if let Some(mc_ack) = self.get_mc_ack_mut() {
                    if let Some(pn) = largest_pn {
                        mc_ack.drain_packets(pn - 1);
                    }
                }
            }
        }

        Ok(())
    }

    /// Gives ranges of received stream pieces that have been deleguated for
    /// unicast retransmission. These pieces of streams have been received
    /// by all receivers and can release memory from the flexicast source.
    /// This basically copies the portion of code that is processed when a
    /// unicast server receives an ACK frame acknowledging a STREAM frame.
    pub fn fc_on_stream_ack_received(
        &mut self, stream_id: u64, off: u64, len: u64,
    ) -> Result<()> {
        let stream = self.streams.get_mut(stream_id);
        if let Some(stream) = stream {
            stream.send.ack_and_drop(off, len as usize);
            self.tx_buffered = self.tx_buffered.saturating_sub(len as usize);

            qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                let ev_data =
                    EventData::DataMoved(qlog::events::quic::DataMoved {
                        stream_id: Some(stream_id),
                        offset: Some(off),
                        length: Some(len as u64),
                        from: Some(DataRecipient::Transport),
                        to: Some(DataRecipient::Dropped),
                        raw: None,
                    });

                q.add_event_data_with_instant(ev_data, now).ok();
            });

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

        Ok(())
    }

    /// Sets the recovery mode of the flexicast source.
    pub fn fc_set_recovery_state(&mut self) -> Result<()> {
        if let Some(multicast) = self.multicast.as_ref() {
            if multicast.mc_role != McRole::ServerMulticast {
                return Err(Error::Multicast(McError::McInvalidRole(
                    McRole::ServerMulticast,
                )));
            }

            if let Some(space_id) = multicast.get_mc_space_id() {
                let p = self.paths.get_mut(space_id)?;
                p.recovery.is_fc_source = true;
                self.newly_acked.drain(..);
                return Ok(());
            }
            return Err(Error::Multicast(McError::McPath));
        }
        return Err(Error::Multicast(McError::McDisabled));
    }

    /// Returns whether bytes are in flight on the flexicast path.
    pub fn fc_bytes_in_flight(&self) -> Option<bool> {
        fc_chan_idx!(self.multicast.as_ref()?).ok().map(|idx| {
            self.paths.get(idx).ok().map(|p| p.recovery.bytes_in_flight())
        }).flatten()
    }
}

impl MulticastAttributes {
    /// Whether the full reliability structure is already set.
    pub fn rmc_is_set(&self) -> bool {
        !matches!(self.mc_reliable, ReliableMc::Undefined)
    }

    /// Sets the reliable client needing to send positive ack frames.
    pub fn rmc_set_send_ack(&mut self, v: bool) {
        if let ReliableMc::Client(ref mut c) = self.mc_reliable {
            c.set_rmc_client_send_ack(v);
        }
    }

    /// Gets the reliable multicast attributes as a mutable reference.
    pub fn rmc_get_mut(&mut self) -> &mut ReliableMc {
        &mut self.mc_reliable
    }

    /// Gets the reliable multicast attributes as a reference.
    pub fn rmc_get(&self) -> &ReliableMc {
        &self.mc_reliable
    }

    /// Gets the number of STREAM frames that this server-side unicast
    /// connection retransmitted.
    ///
    /// Always `None` for the multicast source and the client.
    /// `None` if reliable multicast is disabled.
    pub fn rmc_get_server_nb_lost_stream(&self) -> Option<u64> {
        if !matches!(self.mc_role, McRole::ServerUnicast(_)) {
            return None;
        }

        self.rmc_get()
            .server()
            .map(|s| s.get_nb_lost_stream_mc_pkt())
    }
}

/// Provide structures and functions to help testing the reliable multicast
/// extension of QUIC.
pub mod testing {
    use super::*;
    use crate::multicast::testing::*;
    use crate::multicast::*;

    impl MulticastPipe {
        /// Generates a new reliable multicast pipe with already defined
        /// configuration.
        pub fn new_reliable(
            nb_clients: usize, keylog_filename: &str, fc_config: &mut FcConfig,
        ) -> Result<MulticastPipe> {
            let probe_path = fc_config.probe_mc_path;
            fc_config
                .mc_announce_data
                .iter_mut()
                .for_each(|mc| mc.probe_path = probe_path);
            Self::new(nb_clients, keylog_filename, fc_config)
        }

        /// Handles the stream delegation from the multicast source to the
        /// unicast server connections.
        pub fn source_deleguates_streams(
            &mut self, expired: time::Instant,
        ) -> Result<()> {
            let ucs = self.unicast_pipes.iter_mut().take_while(|_| true);
            let mc = &mut self.mc_channel.channel;
            let ucs = ucs.map(|c| &mut c.0.server);

            on_rmc_timeout_server!(mc, ucs, expired)
        }

        /// Same as `source_deleguates_streams` but does not check for
        /// mc_timeout.
        pub fn source_deleguates_streams_direct(
            &mut self, expired: time::Instant, full_retransmit: bool,
        ) -> Result<()> {
            let ucs = self.unicast_pipes.iter_mut().take_while(|_| true);
            let mc = &mut self.mc_channel.channel;
            let ucs = ucs.map(|c| &mut c.0.server);

            ucs.map(|uc| mc.rmc_deleguate_streams(uc, expired, full_retransmit))
                .collect()
        }

        /// Sets the RMC next timeout on the client and directly expires it by
        /// calling `on_rmc_timeout` to trigger positive acks to the source.
        /// Does not make the pipes advance.
        pub fn client_rmc_timeout(
            &mut self, now: time::Instant, random: &SystemRandom,
        ) -> Result<()> {
            self.unicast_pipes.iter_mut().try_for_each(|(pipe, ..)| {
                let client = &mut pipe.client;
                client.rmc_set_next_timeout(now, random)?;

                let et_ack_duration = client.rmc_timeout(now).unwrap();
                let et_ack = now
                    .checked_add(
                        et_ack_duration
                            .checked_add(time::Duration::from_millis(1))
                            .unwrap(),
                    )
                    .unwrap();
                client.on_rmc_timeout(et_ack)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multicast::reliable::ReliableMc;
    use crate::multicast::testing::MulticastPipe;
    use crate::multicast::FcConfig;
    use crate::multicast::McAuthType;
    use crate::multicast::McClientTp;
    use crate::rand::rand_u8;
    use crate::ranges::RangeSet;
    use ring::rand::SystemRandom;
    use std::time;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn test_rmc_next_timeout() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::None,
            use_fec: true,
            probe_mc_path: true,
            ..Default::default()
        };
        let mut mc_pipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_next_timeout.txt",
            &mut fc_config,
        )
        .unwrap();
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;

        let server = &mut mc_pipe.unicast_pipes[0].0.server;
        let multicast = server.multicast.as_ref().unwrap();
        let rmc = &multicast.mc_reliable;
        assert!(matches!(rmc, ReliableMc::Server(_)));

        let client = &mut mc_pipe.unicast_pipes[0].0.client;
        let multicast = client.multicast.as_mut().unwrap();
        let rmc = &multicast.mc_reliable;
        assert!(matches!(rmc, ReliableMc::Client(_)));

        // Compute next timeout on the client.
        // The next reliable multicast timeout remains within the bounds.
        let now = time::Instant::now();
        let random = SystemRandom::new();
        for _ in 0..10000 {
            assert_eq!(client.rmc_set_next_timeout(now, &random), Ok(()));
            let rmc_client = client
                .multicast
                .as_ref()
                .unwrap()
                .mc_reliable
                .client()
                .unwrap();
            let next_timeout = rmc_client.rmc_next_time_ack.unwrap();
            let expected_lowest = now
                .checked_add(time::Duration::from_millis(
                    (expiration_timer as f64 * 0.75 * 0.5) as u64,
                ))
                .unwrap();
            let expected_highest = now
                .checked_add(time::Duration::from_millis(
                    (expiration_timer as f64 * 1.25 * 0.5) as u64,
                ))
                .unwrap();
            assert!(next_timeout >= expected_lowest);
            assert!(next_timeout <= expected_highest);
        }

        // The client must now generate a positive ACK to the server for
        // synchronization.
        assert_eq!(client.rmc_should_send_positive_ack(), Ok(false));
        let timeout = now
            .checked_add(time::Duration::from_millis(
                (expiration_timer as f64 * 1.11) as u64,
            ))
            .unwrap();
        assert_eq!(client.on_rmc_timeout(timeout), Ok(()));
        assert_eq!(client.rmc_should_send_positive_ack(), Ok(true));
        assert_eq!(client.rmc_should_send_source_symbol_ack(), Ok(true));
    }

    #[test]
    fn test_rmc_client_send_ack() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::None,
            use_fec: true,
            probe_mc_path: true,
            ..Default::default()
        };
        let mut mc_pipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_client_send_ack.txt",
            &mut fc_config,
        )
        .unwrap();

        mc_pipe.source_send_single_stream(true, None, 1).unwrap();
        mc_pipe.source_send_single_stream(true, None, 5).unwrap();
        mc_pipe.source_send_single_stream(true, None, 9).unwrap();
        mc_pipe.source_send_single_stream(true, None, 13).unwrap();

        let now = time::Instant::now();
        let random = SystemRandom::new();
        let client = &mut mc_pipe.unicast_pipes[0].0.client;
        assert_eq!(client.rmc_set_next_timeout(now, &random), Ok(()));
        let et_ack_duration = client.rmc_timeout(now).unwrap();
        let et_ack = now
            .checked_add(
                et_ack_duration
                    .checked_add(time::Duration::from_millis(1))
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(client.on_rmc_timeout(et_ack), Ok(()));
        assert_eq!(client.rmc_should_send_positive_ack(), Ok(true));
        assert_eq!(client.rmc_should_send_source_symbol_ack(), Ok(true));
        // The client sends the feedback to the source.
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // The source knows the packets received by the client on the multicast
        // channel.
        let server = &mut mc_pipe.unicast_pipes[0].0.server;
        let rmc = server
            .multicast
            .as_ref()
            .unwrap()
            .mc_reliable
            .server()
            .unwrap();
        let mut expected_ranges = RangeSet::default();
        assert_eq!(expected_ranges, rmc.recv_fec_mc);
        // Packet number 0 is received by the unicast source when opening the
        // second path.
        expected_ranges.insert(0..6);
        assert_eq!(expected_ranges, rmc.recv_pn_mc);
    }

    #[test]
    /// Repeat the same test:
    /// * No source authentication,
    /// * Asymmetric signatures,
    /// * Per-stream asymmetric signatures.
    fn test_on_rmc_timeout_server_small_streams() {
        for auth_method in [
            McAuthType::None,
            McAuthType::AsymSign,
            McAuthType::StreamAsym,
        ] {
            let mut fc_config = FcConfig {
                authentication: auth_method,
                use_fec: true,
                probe_mc_path: true,
                ..Default::default()
            };
            let mut mc_pipe = MulticastPipe::new_reliable(
                2,
                "/tmp/test_on_rmc_timeout_server_small_streams.txt",
                &mut fc_config,
            )
            .unwrap();

            let mut client_loss1 = RangeSet::default();
            client_loss1.insert(0..1);
            let mut client_loss2 = RangeSet::default();
            client_loss2.insert(1..2);

            // Source sends four small streams. Second and last are not received
            // on the client.
            assert!(mc_pipe
                .source_send_single_stream(true, Some(&client_loss2), 1)
                .is_ok());
            assert!(mc_pipe
                .source_send_single_stream(true, Some(&client_loss1), 5)
                .is_ok());
            assert!(mc_pipe
                .source_send_single_stream(true, Some(&client_loss2), 9)
                .is_ok());
            assert!(mc_pipe
                .source_send_single_stream(true, Some(&client_loss1), 13)
                .is_ok());

            let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
            let now = time::Instant::now();
            let expired = now
                .checked_add(time::Duration::from_millis(expiration_timer + 100))
                .unwrap();

            // Client sends positive ack to the source.
            let random = SystemRandom::new();
            assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));

            for pipe in mc_pipe.unicast_pipes.iter() {
                let client = &pipe.0.client;
                assert_eq!(client.rmc_should_send_positive_ack(), Ok(true));
                assert_eq!(client.rmc_should_send_source_symbol_ack(), Ok(true));
            }

            // Client has only received 2 streams.
            let client = &mc_pipe.unicast_pipes[0].0.client;
            let mut readables = client.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![1, 9]);

            let client = &mc_pipe.unicast_pipes[1].0.client;
            let mut readables = client.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![5, 13]);

            assert_eq!(mc_pipe.clients_send(), Ok(()));
            assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

            // The unicast server now has state for the expired streams.
            let open_stream_ids = mc_pipe.unicast_pipes[0]
                .0
                .server
                .streams
                .writable()
                .collect::<Vec<_>>();
            assert_eq!(open_stream_ids, vec![5, 13]);

            let open_stream_ids = mc_pipe.unicast_pipes[1]
                .0
                .server
                .streams
                .writable()
                .collect::<Vec<_>>();
            assert_eq!(open_stream_ids, vec![1, 9]);

            // RMC-TODO: assert on the data and offsets of the streams on the
            // server.
            for pipe in mc_pipe.unicast_pipes.iter_mut() {
                assert_eq!(pipe.0.server.streams.has_flushable(), true);
                assert_eq!(pipe.0.advance(), Ok(()));

                // Client now has all four streams.
                let client = &mut pipe.0.client;
                let mut readables = client.readable().collect::<Vec<_>>();
                readables.sort();
                assert_eq!(readables, vec![1, 5, 9, 13]);
                let mut out_buf = [0u8; 1000];
                for stream_id in readables {
                    assert!(client.stream_complete(stream_id));
                    assert_eq!(
                        client.mc_stream_recv(stream_id, &mut out_buf),
                        Ok((300, true))
                    );
                }

                assert_eq!(
                    pipe.0
                        .server
                        .multicast
                        .as_ref()
                        .unwrap()
                        .rmc_get_server_nb_lost_stream(),
                    Some(2)
                );
            }
        }
    }

    #[test]
    /// Repeat the same test:
    /// * No source authentication,
    /// * Asymmetric signatures,
    /// * Per-stream asymmetric signatures.
    fn test_on_rmc_timeout_large_stream() {
        for (auth_method, sign_len) in [
            (McAuthType::None, 0),
            (McAuthType::AsymSign, 64),
            (McAuthType::StreamAsym, 0),
        ] {
            let mut fc_config = FcConfig {
                authentication: auth_method,
                use_fec: true,
                probe_mc_path: true,
                ..Default::default()
            };
            let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
                2,
                "/tmp/test_on_rmc_timeout_large_stream.txt",
                &mut fc_config,
            )
            .unwrap();

            let mut client_loss1 = RangeSet::default();
            client_loss1.insert(0..1);
            let mut client_loss2 = RangeSet::default();
            client_loss2.insert(1..2);

            // Source sends a large (unfinished) stream.
            let random = SystemRandom::new();
            let data_len = 10_000;
            let mut data = vec![0u8; data_len];
            random.fill(&mut data).unwrap();

            assert_eq!(
                mc_pipe.mc_channel.channel.stream_send(1, &data, false),
                Ok(data.len())
            );

            // Send as many packets as needed to forward the stream. Every other
            // packet is lost.
            let mut erase = true;
            loop {
                if let Err(Error::Done) = mc_pipe.source_send_single(if erase {
                    Some(&client_loss1)
                } else {
                    Some(&client_loss2)
                }) {
                    break;
                }
                erase = !erase;
            }

            // Client 1 did not receive the first packet => impossible to read the
            // stream.
            let client = &mc_pipe.unicast_pipes[0].0.client;
            assert!(client.readable().collect::<Vec<u64>>().is_empty());
            // Client 2 received the first packet => possible to read the stream.
            let client = &mc_pipe.unicast_pipes[1].0.client;
            assert_eq!(client.readable().collect::<Vec<u64>>(), vec![1u64]);

            // Client compute positive acknowledgment and send packets to the
            // server.
            let now = time::Instant::now();
            assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
            assert_eq!(mc_pipe.clients_send(), Ok(()));

            // Multicast source deleguates streams.
            let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
            let now = time::Instant::now();
            let expired = now
                .checked_add(time::Duration::from_millis(expiration_timer + 100))
                .unwrap();
            assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

            // Multicast source expires and directly sends notificication to the
            // clients, before the unicast servers can retransmit the lost stream
            // frames.
            let exp_pkt =
                mc_pipe.mc_channel.channel.on_mc_timeout(expired).unwrap();
            assert_eq!(exp_pkt.pn, Some(9 + sign_len as u64 / 64));
            assert_eq!(exp_pkt.ssid, Some(7 + sign_len as u64 / 64));

            // The unicast server sends the retransmissions.
            assert_eq!(
                mc_pipe
                    .unicast_pipes
                    .iter_mut()
                    .map(|(pipe, ..)| pipe.advance())
                    .collect::<Result<()>>(),
                Ok(())
            );

            let data2_len = 7000;
            let mut out_buf = vec![0u8; data_len + data2_len];
            for pipe in mc_pipe.unicast_pipes.iter_mut() {
                // Client now has access to the full stream.
                let client = &mut pipe.0.client;
                assert_eq!(client.readable().collect::<Vec<_>>(), vec![1]);
                assert!(!client.stream_complete(1)); // We do not know the end yet.
                if auth_method == McAuthType::StreamAsym {
                    // No asymmetric signature with the stream...
                    assert_eq!(
                        client.mc_stream_recv(1, &mut out_buf),
                        Err(Error::Done)
                    );
                } else {
                    assert_eq!(
                        client.mc_stream_recv(1, &mut out_buf),
                        Ok((data_len, false))
                    );
                    assert_eq!(data, out_buf[..data_len]);
                }
            }

            // Source sends more data onto that stream.
            let mut data2 = vec![0u8; data2_len];
            random.fill(&mut data2[..]).unwrap();
            assert_eq!(
                mc_pipe.mc_channel.channel.stream_send(1, &data2[..], true),
                Ok(data2_len)
            );

            // Send as many packets as needed to forward the stream. Every other
            // packet is lost.
            let mut erase = false;
            loop {
                if let Err(Error::Done) = mc_pipe.source_send_single(if erase {
                    Some(&client_loss1)
                } else {
                    Some(&client_loss2)
                }) {
                    break;
                }
                erase = !erase;
            }

            // Client 1 received the first packet => possible to read the stream.
            let client = &mc_pipe.unicast_pipes[0].0.client;
            assert_eq!(client.readable().collect::<Vec<u64>>(), vec![1u64]);
            // Client 2 did not receive the first packet => impossible to read the
            // stream.
            let client = &mc_pipe.unicast_pipes[1].0.client;
            if auth_method == McAuthType::StreamAsym {
                assert_eq!(client.readable().collect::<Vec<u64>>(), vec![1u64]);
            } else {
                assert!(client.readable().collect::<Vec<u64>>().is_empty());
            }

            // Client compute positive acknowledgment and send packets to the
            // server.
            let now = time::Instant::now();
            assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
            assert_eq!(mc_pipe.clients_send(), Ok(()));

            // Multicast source deleguates streams.
            let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
            let now = time::Instant::now();
            let expired = now
                .checked_add(time::Duration::from_millis(
                    expiration_timer * 2 + 100,
                ))
                .unwrap();
            assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

            // Multicast source expires and directly sends notificication to the
            // clients, before the unicast servers can retransmit the lost stream
            // frames.
            let exp_pkt =
                mc_pipe.mc_channel.channel.on_mc_timeout(expired).unwrap();
            if auth_method == McAuthType::AsymSign {
                assert_eq!(exp_pkt.pn, Some(16));
                assert_eq!(exp_pkt.ssid, Some(14));
            } else {
                assert_eq!(exp_pkt.pn, Some(15));
                assert_eq!(exp_pkt.ssid, Some(13));
            }

            // The unicast server sends the retransmissions.
            assert_eq!(
                mc_pipe
                    .unicast_pipes
                    .iter_mut()
                    .map(|(pipe, ..)| pipe.advance())
                    .collect::<Result<()>>(),
                Ok(())
            );

            // Client now has access to the full stream.
            for pipe in mc_pipe.unicast_pipes.iter_mut() {
                let client = &mut pipe.0.client;
                assert_eq!(client.readable().collect::<Vec<_>>(), vec![1]);
                assert!(client.stream_complete(1)); // We do not know the end yet.
                if auth_method == McAuthType::StreamAsym {
                    assert_eq!(
                        client.mc_stream_recv(1, &mut out_buf),
                        Ok((data_len + data2_len, true))
                    );
                    assert_eq!(data, out_buf[..data_len]);
                    assert_eq!(data2, out_buf[data_len..]);

                    // Only test for StreamAsym for simplicity.
                    assert_eq!(
                        pipe.0
                            .server
                            .multicast
                            .as_ref()
                            .unwrap()
                            .rmc_get_server_nb_lost_stream(),
                        Some(7)
                    );
                } else {
                    assert_eq!(
                        client.mc_stream_recv(1, &mut out_buf),
                        Ok((data2_len, true))
                    );
                    assert_eq!(data2, out_buf[..data2_len]);
                }
            }
        }
    }

    #[test]
    fn test_rmc_cc2() {
        let max_datagram_size = 1350;
        let mc_cwnd = 15;
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            mc_cwnd: Some(mc_cwnd),
            ..Default::default()
        };
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_cc.txt",
            &mut fc_config,
        )
        .unwrap();

        let cwnd = mc_pipe
            .mc_channel
            .channel
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert_eq!(cwnd, mc_cwnd * max_datagram_size);

        let initial_cwin = mc_pipe.unicast_pipes[0]
            .0
            .server
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();

        let stream = vec![0u8; 40 * max_datagram_size];
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_send(1, &stream, true),
            Ok(10 * max_datagram_size * 4)
        ); // 27,000 because of the two paths.
        while let Ok(_) = mc_pipe.source_send_single(None) {}
        let now = time::Instant::now();
        assert_eq!(mc_pipe.server_control_to_mc_source(now), Ok(()));

        let random = SystemRandom::new();
        assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // Multicast source deleguates streams.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let now = time::Instant::now();
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(17), Some(15)).into()));
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));
        ucs_to_mc_cwnd!(
            &mut mc_pipe.mc_channel.channel,
            mc_pipe
                .unicast_pipes
                .iter_mut()
                .map(|(v, ..)| &mut v.server),
            expired,
            None
        );
        let exp_cwin = mc_pipe.unicast_pipes[0]
            .0
            .server
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();

        let cwnd = mc_pipe
            .mc_channel
            .channel
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert_eq!(cwnd, exp_cwin);
        let new_cwin = mc_pipe.unicast_pipes[0]
            .0
            .server
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert!(new_cwin > initial_cwin);

        let previous_cwin = new_cwin;

        // Now a client does not receive any packet.
        let mut loss_1 = RangeSet::default();
        loss_1.insert(0..1);
        std::thread::sleep(expired.duration_since(time::Instant::now()));
        while let Ok(_) = mc_pipe.source_send_single(Some(&loss_1)) {}
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));

        let now = expired;
        assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // Multicast source deleguates streams.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(45), Some(43)).into()));
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));
        ucs_to_mc_cwnd!(
            &mut mc_pipe.mc_channel.channel,
            mc_pipe
                .unicast_pipes
                .iter_mut()
                .map(|(v, ..)| &mut v.server),
            expired,
            None
        );

        // Source decreases its congestion window to the minimum multicast value.
        let exp_cwin = mc_pipe.unicast_pipes[0]
            .0
            .server
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        let cwnd = mc_pipe
            .mc_channel
            .channel
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert_eq!(cwnd, exp_cwin);

        assert!(exp_cwin < previous_cwin);
    }

    #[test]
    /// Same test as before, but now a packet flight is not received at all on
    /// the clients. As a result, no positive ACK is sent to the source, which
    /// must decrease its congestion window in response.
    fn test_rmc_cc_empty_ack() {
        let max_datagram_size = 1350;
        let mc_cwnd = 15;
        let mut buf = [0u8; 15000];
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            mc_cwnd: Some(mc_cwnd),
            ..Default::default()
        };
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            4,
            "/tmp/test_rmc_cc_no_ack.txt",
            &mut fc_config,
        )
        .unwrap();

        let cwnd = mc_pipe
            .mc_channel
            .channel
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert_eq!(cwnd, mc_cwnd * max_datagram_size);

        let stream = vec![0u8; 40 * max_datagram_size];
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_send(1, &stream, true),
            Ok(10 * max_datagram_size * 4)
        ); // 27,000 because of the two paths.
        while let Ok(_) = mc_pipe.source_send_single(None) {}

        let random = SystemRandom::new();
        let now = time::Instant::now();
        assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // Multicast source deleguates streams.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let now = time::Instant::now();
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(17), Some(15)).into()));
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));

        let cwnd = mc_pipe
            .mc_channel
            .channel
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert_eq!(cwnd, mc_cwnd * max_datagram_size);

        // All clients have congested links and do not receive any message.
        let mut loss = RangeSet::default();
        loss.insert(0..4);
        loop {
            match mc_pipe.source_send_single(Some(&loss)) {
                Err(Error::Done) => {
                    break;
                },
                Ok(_) => (),
                Err(e) => panic!("ERROR: {:?}", e),
            }
        }

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));

        let now = expired;
        assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
        // The ACKs are empty because clients did not receive any new packet.
        for pipe in mc_pipe.unicast_pipes.iter().map(|(p, ..)| p) {
            assert_eq!(pipe.client.rmc_should_send_positive_ack(), Ok(true));
            assert_eq!(pipe.client.rmc_should_send_source_symbol_ack(), Ok(true));
        }
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));

        // Multicast source deleguates streams.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 1000))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(33), Some(31)).into()));

        // Source decreases its congestion window to the minimum multicast value.
        let cwnd = mc_pipe
            .mc_channel
            .channel
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert_eq!(cwnd, mc_cwnd * max_datagram_size);
    }

    #[test]
    fn test_rmc_no_retransmit_on_mc_source() {
        let max_datagram_size = 1350;
        let mut buf = [0u8; 15000];
        let mut fc_config = FcConfig {
            authentication: McAuthType::None,
            use_fec: true,
            probe_mc_path: true,
            mc_cwnd: Some(10),
            ..Default::default()
        };
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_no_retransmit_on_mc_source.txt",
            &mut fc_config,
        )
        .unwrap();

        let stream = vec![0u8; 40 * max_datagram_size];
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_send(1, &stream, true),
            Ok(54_000)
        ); // 27,000 because of the two paths.
        while let Ok(_) = mc_pipe.source_send_single(None) {}

        // Multicast source deleguates streams without feedback from the clients.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let now = time::Instant::now();
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(12), Some(10)).into()));

        // Now able to send the remaining of the stream.
        for _ in 0..11 {
            assert!(mc_pipe.source_send_single(None).is_ok());
        }

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));
    }

    #[test]
    fn test_rmc_not_all_expired() {
        let max_datagram_size = 1350;
        let mut buf = [0u8; 15000];
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            mc_cwnd: Some(10),
            ..Default::default()
        };
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_not_all_expired.txt",
            &mut fc_config,
        )
        .unwrap();

        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;

        let stream = vec![0u8; 40 * max_datagram_size];
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_send(1, &stream, true),
            Ok(54_000)
        ); // 27,000 because of the two paths.

        // Send first packets.
        for _ in 0..5 {
            mc_pipe.source_send_single(None).unwrap();
        }

        // Wait (e.g., some kind of weird pacing).
        let now = time::Instant::now();
        std::thread::sleep(Duration::from_millis(expiration_timer - 100));

        for _ in 0..6 {
            mc_pipe.source_send_single(None).unwrap();
        }

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));

        // Multicast source deleguates streams without feedback from the clients.
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(6), Some(4)).into()));

        // Now able to send the remaining of the stream.
        for _ in 0..8 {
            assert!(mc_pipe.source_send_single(None).is_ok());
        }

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));
    }

    #[test]
    fn test_rmc_not_all_expired_multiple_small() {
        let mut buf = [0u8; 15000];
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            mc_cwnd: Some(10_000),
            ..Default::default()
        };
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_not_all_expired_multiple_small.txt",
            &mut fc_config,
        )
        .unwrap();

        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;

        // First send 3 streams that will be expired.
        for i in 0..3 {
            mc_pipe
                .source_send_single_stream(true, None, 1 + i * 4)
                .unwrap();
        }

        // Wait (e.g., some kind of weird pacing).
        let now = time::Instant::now();
        std::thread::sleep(Duration::from_millis(expiration_timer - 100));

        mc_pipe
            .source_send_single_stream(true, None, 1 + 3 * 4)
            .unwrap();

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));

        // Multicast source deleguates streams without feedback from the clients.
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        assert_eq!(mc_pipe.mc_channel.mc_send(&mut buf), Err(Error::Done));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(4), Some(2)).into()));

        assert!(!mc_pipe.mc_channel.channel.mc_no_stream_active());

        // Multicast source deleguates streams without feedback from the clients.
        let now = expired;
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(5), Some(3)).into()));

        assert!(mc_pipe.mc_channel.channel.mc_no_stream_active());
    }

    #[test]
    /// The multicast channel starts without any client, i.e., the source sends
    /// multiple MC_EXPIRE frames. These frames will not be received by a client
    /// joingning the channel later. This test ensures that the previously not
    /// received packets (i.e., the MC_EXPIRE) do not contribute negatively to
    /// the congestion window state since they MUST NOT be considered as lost.
    fn test_rmc_cc_with_mc_expire_before() {
        let max_datagram_size = 1350;
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            mc_cwnd: Some(15),
            ..Default::default()
        };
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            0,
            "/tmp/test_rmc_cc_with_mc_expire_before.txt",
            &mut fc_config,
        )
        .unwrap();

        // The multicast source sends some MC_EXPIRE even though nobody is in
        // the group. It has for effect that the packet number of the multicast
        // path increases.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let initial = time::Instant::now();
        let mut expired = initial
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();

        let mut res = Ok((None, None).into());
        for _ in 0..100 {
            res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
            assert!(res.is_ok());
            expired = expired
                .checked_add(time::Duration::from_millis(expiration_timer + 100))
                .unwrap();
            mc_pipe.source_send_single(None).unwrap();
        }
        assert_eq!(res, Ok((Some(100), None).into()));

        // A new client joins the channel.
        let mc_client_tp = Some(McClientTp::default());
        let random = SystemRandom::new();
        let mc_announce_data = &mc_pipe.mc_announce_data;

        let mut fc_config = FcConfig {
            mc_client_tp,
            mc_announce_data: vec![mc_announce_data.clone()],
            authentication: McAuthType::StreamAsym,
            probe_mc_path: true,
            ..FcConfig::default()
        };

        let new_client = MulticastPipe::setup_client(
            &mut mc_pipe.mc_channel,
            &mut fc_config,
            &random,
        )
        .unwrap();
        mc_pipe.unicast_pipes.push(new_client);
        let initial_cwin = mc_pipe.unicast_pipes[0]
            .0
            .server
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();

        // Remove manually the first sent packet because I have no idea of how to
        // deal with it cleanly for now. The problem is that the first
        // packet sent by the server on the new path carries PATH_ACCEPT frames or
        // similar, which are not acknowledged by the client since it receives in
        // the MC_KEY frame the first packet of interest which is much higher. As
        // a consequence, the server thinks that the packet is lost (indeed, the
        // client does not ack it).

        // --------------------------------- //

        // Now the server sends some interesting data.
        let stream = vec![0u8; 40 * max_datagram_size];
        assert!(mc_pipe
            .mc_channel
            .channel
            .stream_send(1, &stream, true)
            .is_ok(),);
        while let Ok(_) = mc_pipe.source_send_single(None) {}

        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));

        assert_eq!(mc_pipe.client_rmc_timeout(expired, &random), Ok(()));
        assert_eq!(mc_pipe.clients_send(), Ok(()));
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));

        // Multicast source deleguates streams.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let expired = expired
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(117), Some(15)).into()));
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));
        let new_cwin = mc_pipe.unicast_pipes[0]
            .0
            .server
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert!(new_cwin > initial_cwin);
    }

    #[test]
    fn test_rmc_cc_multiple_clients() {
        let max_datagram_size = 1350;
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            mc_cwnd: Some(15),
            ..Default::default()
        };
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            2,
            "/tmp/test_rmc_cc_multiple_clients.txt",
            &mut fc_config,
        )
        .unwrap();
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;

        let init_cwnd = mc_pipe
            .unicast_pipes
            .iter()
            .map(|(p, ..)| p.server.paths.get(1).unwrap().recovery.cwnd())
            .min()
            .unwrap();

        let stream = vec![0u8; 40 * max_datagram_size];
        assert!(mc_pipe
            .mc_channel
            .channel
            .stream_send(1, &stream, true)
            .is_ok(),);
        while let Ok(_) = mc_pipe.source_send_single(None) {}

        let random = SystemRandom::new();
        let now = time::Instant::now();
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));

        assert_eq!(mc_pipe.client_rmc_timeout(expired, &random), Ok(()));
        assert_eq!(mc_pipe.clients_send(), Ok(()));
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));

        // Multicast source deleguates streams.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let expired = expired
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(17), Some(15)).into()));
        assert_eq!(mc_pipe.server_control_to_mc_source(expired), Ok(()));

        let new_cwnd = mc_pipe
            .unicast_pipes
            .iter()
            .map(|(p, ..)| p.server.paths.get(1).unwrap().recovery.cwnd())
            .min()
            .unwrap();

        assert!(new_cwnd > init_cwnd);
    }

    #[test]
    /// The source sends a stream where the first packet is lost and must be
    /// retransmitted over unicast. The client must receive the entire
    /// stream after unicast retransmission, and the unicast server must drop
    /// state after ACK.
    fn test_rmc_retransmit_start_of_stream() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            mc_cwnd: Some(15),
            ..Default::default()
        };
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_retransmit_start_of_stream.txt",
            &mut fc_config,
        )
        .unwrap();

        let stream = [0u8; 2000];
        mc_pipe
            .mc_channel
            .channel
            .stream_send(3, &stream, true)
            .unwrap();
        let mut client_1 = RangeSet::default();
        client_1.insert(0..1);
        mc_pipe.source_send_single(Some(&client_1)).unwrap();
        mc_pipe.source_send_single(None).unwrap();
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let expired = time::Instant::now()
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(3), Some(1)).into()));

        let server = &mut mc_pipe.unicast_pipes[0].0.server;
        let streams: Vec<_> = server.streams.writable().collect();
        assert_eq!(streams, vec![3]);

        mc_pipe.unicast_pipes[0].0.advance().unwrap();

        let client = &mut mc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![3]);
        let mut buf = [0u8; 3000];
        assert_eq!(client.stream_recv(3, &mut buf), Ok((2000, true)));

        let server = &mut mc_pipe.unicast_pipes[0].0.server;
        let streams: Vec<_> = server.streams.writable().collect();
        assert!(streams.is_empty());
    }

    #[test]
    fn test_rmc_retransmit_lost_stream_different_timeout() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            mc_cwnd: Some(15),
            ..Default::default()
        };
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_retransmit_lost_stream_different_timeout.txt",
            &mut fc_config,
        )
        .unwrap();

        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;

        let stream = [0u8; 2000];
        mc_pipe
            .mc_channel
            .channel
            .stream_send(7, &stream, true)
            .unwrap();
        let mut client_1 = RangeSet::default();
        client_1.insert(0..1);
        mc_pipe.source_send_single(Some(&client_1)).unwrap();
        let now = time::Instant::now();
        std::thread::sleep(time::Duration::from_millis(200));
        // mc_pipe.source_send_single(Some(&client_1), 0).unwrap();
        mc_pipe.source_send_single(None).unwrap();
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(2), Some(0)).into()));

        let server = &mut mc_pipe.unicast_pipes[0].0.server;
        let streams: Vec<_> = server.streams.writable().collect();
        assert_eq!(streams, vec![7]);

        mc_pipe.unicast_pipes[0].0.advance().unwrap();

        assert_eq!(mc_pipe.clients_send(), Ok(()));

        let expired = expired
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(3), Some(1)).into()));

        mc_pipe.unicast_pipes[0].0.advance().unwrap();

        let client = &mut mc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![7]);
        let mut buf = [0u8; 3000];
        assert_eq!(client.stream_recv(7, &mut buf), Ok((2000, true)));

        let server = &mut mc_pipe.unicast_pipes[0].0.server;
        let streams: Vec<_> = server.streams.writable().collect();
        assert!(streams.is_empty());
    }

    #[test]
    /// Tests the full reliability mechanism of flexicast using the McAck
    /// structure.
    fn test_fc_reliability_with_mc_ack() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::None,
            use_fec: false,
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = MulticastPipe::new_reliable(
            2,
            "/tmp/test_fc_reliability_with_mc_ack",
            &mut fc_config,
        )
        .unwrap();

        let expiration_timer = fc_pipe.mc_announce_data.expiration_timer;
        let expiration_timer =
            time::Duration::from_millis(expiration_timer + 100);
        let now = time::Instant::now();

        // First stream is received by both receivers.
        let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
        let (_, _, nb) = mc_ack.get_state();
        assert_eq!(nb, 2);
        fc_pipe.source_send_single_stream(true, None, 1).unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Clients read the stream.
        let mut buf = [0u8; 500];
        let client_0 = &mut fc_pipe.unicast_pipes[0].0.client;
        assert!(client_0.stream_readable(1));
        assert_eq!(client_0.stream_recv(1, &mut buf), Ok((300, true)));
        let client_1 = &mut fc_pipe.unicast_pipes[1].0.client;
        assert!(client_1.stream_readable(1));
        assert_eq!(client_1.stream_recv(1, &mut buf), Ok((300, true)));

        // Flexicast source has a packet in waiting for ack.
        let fc_path = fc_pipe.mc_channel.channel.paths.get(1).unwrap();
        let nb_ack = fc_path.recovery.acked[Epoch::Application].len();

        // The flexicast source acknowledged the packet because both receivers
        // said it was ok.
        std::thread::sleep(expiration_timer);
        let now = time::Instant::now();
        let random = SystemRandom::new();
        assert_eq!(fc_pipe.client_rmc_timeout(now, &random), Ok(()));
        fc_pipe.clients_send().unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        let fc_path = fc_pipe.mc_channel.channel.paths.get(1).unwrap();
        assert_eq!(fc_path.recovery.acked[Epoch::Application].len(), nb_ack + 2);

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

        std::thread::sleep(expiration_timer);
        let now = time::Instant::now();
        assert_eq!(fc_pipe.client_rmc_timeout(now, &random), Ok(()));
        fc_pipe.clients_send().unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // No new complete acked packet.
        let fc_path = fc_pipe.mc_channel.channel.paths.get(1).unwrap();
        assert_eq!(fc_path.recovery.acked[Epoch::Application].len(), nb_ack + 2);

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
        std::thread::sleep(expiration_timer);
        let now = time::Instant::now();
        assert_eq!(fc_pipe.client_rmc_timeout(now, &random), Ok(()));
        fc_pipe.clients_send().unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        // TODO: check McAck here.
        fc_pipe
            .source_deleguates_streams_direct(now, false)
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

        // And the McAck of both the flexicast source and the unicast server have
        // state.
        let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
        let (_, streams, _) = mc_ack.get_state();
        assert_eq!(streams.len(), 1);
        let value = streams.get(&7).unwrap();
        assert_eq!(value.len(), 1);
        assert_eq!(value.iter().next().unwrap(), (&0, &(300, 1)));

        let mc_ack = &fc_pipe.unicast_pipes[0]
            .0
            .server
            .multicast
            .as_ref()
            .unwrap()
            .rmc_get()
            .server()
            .unwrap()
            .mc_ack;
        let (_, streams, _) = mc_ack.get_state();
        assert_eq!(streams.len(), 1);
        let value = streams.get(&7).unwrap();
        assert_eq!(value.len(), 1);
        assert_eq!(value.iter().next().unwrap(), (&0, &(300, 1)));

        fc_pipe.unicast_pipes[0].0.advance().unwrap();

        // Client received the stream. State updated on the McAck of the server.
        let mc_ack = &fc_pipe.unicast_pipes[0]
            .0
            .server
            .multicast
            .as_ref()
            .unwrap()
            .rmc_get()
            .server()
            .unwrap()
            .mc_ack;
        let (_, streams, _) = mc_ack.get_state();
        assert!(streams.is_empty());

        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Now the flexicast source does not have any state for the open stream.
        let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
        let (_, streams, _) = mc_ack.get_state();
        assert!(streams.is_empty());
        assert!(fc_pipe.mc_channel.channel.streams.is_collected(7));

        // First client now has the second stream.
        let client_0 = &mut fc_pipe.unicast_pipes[0].0.client;
        assert!(client_0.stream_readable(7));
        assert_eq!(client_0.stream_recv(7, &mut buf), Ok((300, true)));
    }

    #[test]
    /// Tests the reliability mechanism of Flexicast QUIC with random packet
    /// losses.
    fn test_fc_quic_reliability_short_streams() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::None,
            use_fec: false,
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = MulticastPipe::new_reliable(
            3,
            "/tmp/test_fc_quic_reliability_short_streams",
            &mut fc_config,
        )
        .unwrap();

        let random = SystemRandom::new();
        let expiration_timer = fc_pipe.mc_announce_data.expiration_timer;
        let expiration_timer = Duration::from_millis(expiration_timer);

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

            // Clients set timeout information.
            fc_pipe.client_rmc_timeout(now, &random).unwrap();

            // Wait a bit...
            std::thread::sleep(expiration_timer);
            let now = time::Instant::now();

            // Clients send their feedback to the source.
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Stream deleguation.
            fc_pipe
                .source_deleguates_streams_direct(now, false)
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
            authentication: McAuthType::None,
            use_fec: false,
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_fc_quic_reliability_timeout",
            &mut fc_config,
        )
        .unwrap();

        let random = SystemRandom::new();
        let expiration_timer = fc_pipe.mc_announce_data.expiration_timer;
        let expiration_timer = Duration::from_millis(expiration_timer);

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
            let _ = fc_pipe.mc_channel.channel.on_mc_timeout(now);

            // Allow the flexicast source to send more packets, e.g., ping frames.
            let _ = fc_pipe.source_send_single(None);

            // The source notifies the unicast instances of the sent packet.
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Clients set timeout information.
            fc_pipe.client_rmc_timeout(now, &random).unwrap();

            // Wait a bit...
            std::thread::sleep(expiration_timer);
            let now = time::Instant::now();

            // Clients send their feedback to the source.
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Stream deleguation.
            fc_pipe
                .source_deleguates_streams_direct(now, false)
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
            authentication: McAuthType::None,
            use_fec: false,
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_fc_quic_reliability_long_streams",
            &mut fc_config,
        )
        .unwrap();

        let random = SystemRandom::new();
        let expiration_timer = fc_pipe.mc_announce_data.expiration_timer;
        let expiration_timer = Duration::from_millis(expiration_timer);

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
            let client_loss = if mask & 0b1 > 0 && i < nb_turns_allowed - 5 {
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
            fc_pipe.mc_channel.channel.on_mc_timeout(now).unwrap();
            fc_pipe.client_rmc_timeout(now, &random).unwrap();

            // Wait a bit...
            std::thread::sleep(expiration_timer);
            let now = time::Instant::now();

            // Clients send their feedback to the source.
            fc_pipe.clients_send().unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();

            // Stream deleguation.
            fc_pipe
                .source_deleguates_streams_direct(now, false)
                .unwrap();

            // Potentially unicast retransmissions.
            fc_pipe
                .unicast_pipes
                .iter_mut()
                .for_each(|(pipe, ..)| pipe.advance().unwrap());
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
    }

    #[test]
    /// Tests the reliability mechanism of Flexicast QUIC with multiple timeout.
    /// The source must not drain lost packets that have not been retransmitted
    /// to the unicast path.
    fn test_fc_quic_reliability_no_drain() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::None,
            use_fec: false,
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_fc_quic_reliability_no_drain",
            &mut fc_config,
        )
        .unwrap();

        let random = SystemRandom::new();
        let expiration_timer = fc_pipe.mc_announce_data.expiration_timer;
        let expiration_timer = Duration::from_millis(expiration_timer);

        let mut client_loss = RangeSet::default();
        client_loss.insert(0..1);

        fc_pipe
            .source_send_single_stream(true, Some(&client_loss), 3)
            .unwrap();

        let now = time::Instant::now();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.client_rmc_timeout(now, &random).unwrap();

        // Timeout of the flexicast source.
        std::thread::sleep(expiration_timer * 2);
        let now = time::Instant::now();
        let _ = fc_pipe.mc_channel.channel.on_mc_timeout(now);

        // Allow the flexicast source to send more packets, e.g., ping frames.
        let _ = fc_pipe.source_send_single(None);
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.clients_send().unwrap();
        fc_pipe.client_rmc_timeout(now, &random).unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Wait a bit...
        std::thread::sleep(expiration_timer * 2);
        let now = time::Instant::now();

        // Allow the flexicast source to send more packets, e.g., ping frames.
        let _ = fc_pipe.mc_channel.channel.on_mc_timeout(now);
        let _ = fc_pipe.source_send_single(None);
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.clients_send().unwrap();
        fc_pipe.client_rmc_timeout(now, &random).unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        std::thread::sleep(expiration_timer * 2);
        let now = time::Instant::now();

        // Stream deleguation.
        fc_pipe
            .source_deleguates_streams_direct(now, false)
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
    /// Tests a flexicast channel where the flexicast flow always fails for the first receiver.
    /// The other receivers use normal retransmissions to recover the loss.
    fn test_fc_quic_reliability_fcf_failing() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::None,
            use_fec: false,
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe = MulticastPipe::new_reliable(
            3,
            "/tmp/test_fc_quic_reliability_fcf_failing",
            &mut fc_config,
        )
        .unwrap();

        let sleep_duration = Duration::from_millis(300);
        let random = SystemRandom::new();
        let now = Instant::now();

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
            .source_send_single_stream(true, Some(&client_loss), 3 + i * 4)
            .unwrap();
        }
        fc_pipe.server_control_to_mc_source(now).unwrap();
        for (uc_pipe, _, _) in fc_pipe.unicast_pipes.iter_mut() {
            uc_pipe.client.rmc_set_next_timeout(now, &random).unwrap();
        }

        // Sleep to trigger timeout on the flexicast source.
        std::thread::sleep(sleep_duration);
        let now = Instant::now();
        let _ = fc_pipe.mc_channel.channel.on_mc_timeout(now);
        let _ = fc_pipe.source_send_single(Some(&client_loss)).unwrap();
        for (uc_pipe, _, _) in fc_pipe.unicast_pipes.iter_mut() {
            uc_pipe.client.on_rmc_timeout(now).unwrap();
        }

        // The first receiver leaves for now listening to the flexicast content.
        let mc_ack = fc_pipe.mc_channel.channel.get_mc_ack_mut().unwrap();
        mc_ack.remove_recv();

        std::thread::sleep(sleep_duration);
        let now = Instant::now();

        // The receiver received no packet.
        let recv = &mut fc_pipe.unicast_pipes[0].0.client;
        assert_eq!(recv.readable().next(), None);

        // After some time, a flexicast flow scheduler fall-back to unicast delivery.
        // Future packets will be distributed over unicast.
        // However, we need to ensure that all STREAM frames that were distributed over the flexicast flow are now delegated to the unicast path.
        let uc = &mut fc_pipe.unicast_pipes[0].0.server;
        fc_pipe
            .mc_channel
            .channel
            .rmc_deleguate_streams(uc, now, true)
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
        fc_pipe.mc_channel.channel.rmc_deleguate_streams(uc, now, false).unwrap();

        // The third receiver uses now the retransmission.
        let recv = &mut fc_pipe.unicast_pipes[2].0.client;
        let mut readables = recv.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![3, 11, 15, 19, 23]);
        fc_pipe.client_rmc_timeout(now, &random).unwrap();
        fc_pipe.clients_send().unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        let uc = &mut fc_pipe.unicast_pipes[2].0.server;
        fc_pipe.mc_channel.channel.rmc_deleguate_streams(uc, now, false).unwrap();

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
