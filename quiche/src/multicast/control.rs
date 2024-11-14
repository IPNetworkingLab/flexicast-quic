//! This module defines functions for data and control information exchange
//! between the flexicast source and the unicast instance servers. This module
//! intends to provide "multi-thread" friendly functions to exchange such
//! information.

use std::sync::Arc;
use std::time;

use super::ExpiredPkt;
use super::McError;
use super::McRole;
use crate::multicast::ack::FcDelegatedStream;
use crate::multicast::ack::McStreamOff;
use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::recovery::Sent;
use crate::Connection;
use crate::Error;
use crate::Result;

/// Open version of the Recovery::Sent.
pub type OpenSent = Sent;

impl Connection {
    /// Sets the highest expired packet number sent on the flexicast flow.
    pub fn fc_set_last_expired(&mut self, exp: Option<ExpiredPkt>) {
        if let Some(mc) = self.multicast.as_mut() {
            mc.mc_last_expired = exp;
        }
    }

    /// Returns the packet numbers that have been sent on the flexicast flow and
    /// that the client acknowledged. Also returns the stream ranges that
    /// had been delegated on the unicast path and have been acknowledged by the
    /// client. Returns an error if invalid role.
    ///
    /// Needs mutable.
    pub fn get_new_ack_pn_streams(
        &mut self,
    ) -> Result<(Option<RangeSet>, Option<McStreamOff>)> {
        if let Some(mc) = self.multicast.as_mut() {
            if !matches!(mc.get_mc_role(), McRole::ServerUnicast(_)) {
                return Err(Error::Multicast(McError::McInvalidRole(
                    mc.get_mc_role(),
                )));
            }

            if let Some(rmc) = mc.rmc_get_mut().server_mut() {
                // Get newly acked packet numbers.
                let new_ack_pn = if rmc.new_ack_pn_fc.len() > 0 {
                    Some(rmc.new_ack_pn_fc.clone())
                } else {
                    None
                };

                // Reset the value on the receiver.
                rmc.new_ack_pn_fc = RangeSet::default();

                // Get acked stream pieces.
                let ack_stream_pieces = rmc.mc_ack.acked_stream_off();

                return Ok((new_ack_pn, ack_stream_pieces));
            }
            return Err(Error::Multicast(McError::McReliableDisabled));
        }
        Err(Error::Multicast(McError::McDisabled))
    }

    /// Returns the set of packets that have been sent on the flexicast flow,
    /// since the last time this function was called and that are still in the
    /// sent queue of the flexicast source. Returns an error if this
    /// function is called with the wrong role.
    /// Also resets the RTT to the expiration timer.
    pub fn fc_get_sent_pkt(&mut self, from: Option<u64>) -> Result<Vec<Sent>> {
        if self.multicast.is_none() {
            return Err(Error::Multicast(McError::McDisabled));
        }

        let multicast = self.multicast.as_mut().unwrap();
        if multicast.get_mc_role() != McRole::ServerMulticast {
            return Err(Error::Multicast(McError::McInvalidRole(
                McRole::ServerMulticast,
            )));
        }

        let space_id = multicast
            .mc_space_id
            .ok_or(Error::Multicast(McError::McPath))?;
        let max_pn = match from {
            Some(v) => v,
            None => multicast.cur_max_pn,
        };

        let path = self.paths.get_mut(space_id);
        if let Ok(path) = path {
            let (new_max_pn, sent) = path.recovery.fc_get_sent_pkt(
                space_id as u32,
                Epoch::Application,
                max_pn,
            );
            multicast.cur_max_pn = new_max_pn + 1;
            if sent.is_empty() {
                return Err(Error::Done);
            }

            // Reset the RTT.
            path.recovery.mc_set_rtt(time::Duration::from_millis(
                multicast
                    .get_mc_announce_data(0)
                    .ok_or(Error::Multicast(McError::McAnnounce))?
                    .expiration_timer,
            ));

            Ok(sent)
        } else {
            Err(Error::Multicast(McError::McPath))
        }
    }

    /// Notifies the connection of new packets that have been sent on the
    /// flexicast flow. Only available for the unicast server instances if
    /// the flexicast index is the correct one.
    pub fn fc_on_new_pkt_sent(
        &mut self, fc_id: u64, mut sent: Vec<Sent>,
    ) -> Result<()> {
        if self.multicast.is_none() {
            return Err(Error::Multicast(McError::McDisabled));
        }

        let multicast = self.multicast.as_mut().unwrap();
        if !matches!(multicast.get_mc_role(), McRole::ServerUnicast(_)) {
            return Err(Error::Multicast(McError::McInvalidRole(
                multicast.get_mc_role(),
            )));
        }

        let cur_max_pn = multicast.cur_max_pn;

        // Update new max packet number.
        if let Some(sent) = sent.last() {
            multicast.cur_max_pn = sent.pkt_num.pn() + 1;
        }

        // Maybe during channel change we receive "old" sent packets. Avoid
        // putting them in our state.
        let joined_fc_id = multicast.fc_chan_id.as_ref().map(|(_, id)| *id);
        if joined_fc_id != Some(fc_id as usize) {
            return Ok(());
        }

        let space_id = multicast
            .get_mc_space_id()
            .ok_or(Error::Multicast(McError::McPath))?;

        let handshake_status = self.handshake_status();
        let trace_id = self.trace_id().to_string();
        let path = self.paths.get_mut(space_id)?;
        let now = time::Instant::now();

        for pkt in sent.drain(..).filter(|s| s.pkt_num.pn() >= cur_max_pn) {
            path.recovery.on_packet_sent(
                pkt,
                Epoch::Application,
                handshake_status,
                now,
                &trace_id,
            );
        }

        Ok(())
    }

    /// Returns the set of STREAM frames that must be delegated to the receivers
    /// for unicast retransmission. This function does not take into account
    /// per-receiver reception of a STREAM frame, it will aggregate everything
    /// and forward all frames to the controller that will take the time to
    /// adjust to all clients.
    ///
    /// Returns an error if this is not the flexicast source.
    ///
    /// FC-TODO: this function does not take into account MC_ASYM frames for
    /// per-stream authentication! This will break per-stream authentication
    /// if the frame needs to be retransmitted.
    ///
    /// FC-TODO: also breaks FEC.
    /// 
    /// The `early_retransmit` flag is set whenever the controller asks for
    /// the delegation of STREAM frames early in the process, i.e., frames that
    /// may not be lost will be delegated.
    pub fn fc_get_delegated_stream(&mut self, early_retransmit: bool) -> Result<Vec<FcDelegatedStream>> {
        if self.multicast.is_none() {
            return Err(Error::Multicast(McError::McDisabled));
        }

        let multicast = self.multicast.as_ref().unwrap();
        if multicast.get_mc_role() != McRole::ServerMulticast {
            return Err(Error::Multicast(McError::McInvalidRole(
                McRole::ServerMulticast,
            )));
        }

        let space_id = multicast
            .get_mc_space_id()
            .ok_or(Error::Multicast(McError::McPath))?;
        let fc_path = self.paths.get_mut(space_id)?;

        let streams = &mut self.streams;
        fc_path
            .recovery
            .fc_get_delegated_stream(space_id as u32, streams, early_retransmit)
    }

    /// Inserts in the unicast path delegated streams from the flexicast source.
    /// This creates states for streams that were previously sent on the
    /// flexicast flow and need unicast retransmission.
    ///
    /// Returns an error if this is not a unicast source instance.
    /// Does nothing if this is the wrong flexicast source ID, since we may be
    /// in a transient state because the receiver changed its flexicast flow.
    pub fn fc_delegated_streams(
        &mut self, fc_id: u64, mut delegated_streams: Vec<FcDelegatedStream>,
    ) -> Result<()> {
        let multicast = self
            .multicast
            .as_ref()
            .ok_or(Error::Multicast(McError::McDisabled))?;

        if !matches!(multicast.get_mc_role(), McRole::ServerUnicast(_)) {
            return Err(Error::Multicast(McError::McInvalidRole(
                multicast.get_mc_role(),
            )));
        }

        // Maybe a transient state.
        if multicast
            .fc_chan_id
            .as_ref()
            .map(|(_, id)| *id as u64 != fc_id)
            .unwrap_or(true)
        {
            return Ok(());
        }

        for del_stream in delegated_streams.drain(..) {
            let is_stream_collected =
                self.streams.is_collected(del_stream.stream_id);
            // FC-TODO: Woops, won't work if not local stream!
            let stream =
                match self.get_or_create_stream(del_stream.stream_id, true) {
                    Ok(v) => v,
                    Err(Error::Done) if is_stream_collected => continue,
                    Err(e) => return Err(e),
                };

            let was_flushable = stream.is_flushable();

            debug!(
                "Client unicast retransmits stream piece because lost packet={}",
                del_stream.pn
            );

            // FC-TODO: stream rotation?

            let _written = match stream.send.write_at_offset(
                &del_stream.payload,
                del_stream.offset,
                del_stream.fin,
            ) {
                Ok(v) => v,
                Err(Error::FinalSize) => continue,
                Err(e) => return Err(e),
            };

            // Mark the stream as flushable.
            let priority_key = Arc::clone(&stream.priority_key);
            if !was_flushable {
                self.streams.insert_flushable(&priority_key);
            }
        }

        Ok(())
    }
}
