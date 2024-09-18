//! This module defines functions for data and control information exchange
//! between the flexicast source and the unicast instance servers. This module
//! intends to provide "multi-thread" friendly functions to exchange such
//! information.

use std::time;

use super::ExpiredPkt;
use super::McError;
use super::McRole;
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
    /// Needs mutagle"
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
    pub fn fc_get_sent_pkt(&mut self) -> Result<Vec<Sent>> {
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
        let max_pn = multicast.cur_max_pn;

        let path = self.paths.get(space_id);
        if let Ok(path) = path {
            let (new_max_pn, sent) = path.recovery.fc_get_sent_pkt(
                space_id as u32,
                Epoch::Application,
                max_pn,
            );
            multicast.cur_max_pn = new_max_pn;
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

        let multicast = self.multicast.as_ref().unwrap();
        if !matches!(multicast.get_mc_role(), McRole::ServerUnicast(_)) {
            return Err(Error::Multicast(McError::McInvalidRole(
                multicast.get_mc_role(),
            )));
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

        for pkt in sent.drain(..) {
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
}
