//! This module defines functions for data and control information exchange
//! between the flexicast source and the unicast instance servers. This module
//! intends to provide "multi-thread" friendly functions to exchange such
//! information.

use crate::ranges::RangeSet;
use crate::multicast::ack::McStreamOff;
use crate::Connection;
use crate::Result;
use crate::Error;
use super::ExpiredPkt;
use super::McError;
use super::McRole;

impl Connection {
    /// Sets the highest expired packet number sent on the flexicast flow.
    pub fn fc_set_last_expired(&mut self, exp: Option<ExpiredPkt>) {
        if let Some(mc) = self.multicast.as_mut() {
            mc.mc_last_expired = exp;
        }
    }

    /// Returns the packet numbers that have been sent on the flexicast flow and that the client acknowledged.
    /// Also returns the stream ranges that had been delegated on the unicast path and have been acknowledged by the client.
    /// Returns an error if invalid role.
    /// 
    /// Needs mutagle"
    pub fn get_new_ack_pn_streams(&mut self) -> Result<(Option<RangeSet>, Option<McStreamOff>)> {
        if let Some(mc) = self.multicast.as_mut() {
            if !matches!(mc.get_mc_role(), McRole::ServerUnicast(_)) {
                return Err(Error::Multicast(McError::McInvalidRole(mc.get_mc_role())));
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
    
}
