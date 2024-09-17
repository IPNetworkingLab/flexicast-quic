//! This module defines functions for data and control information exchange
//! between the flexicast source and the unicast instance servers. This module
//! intends to provide "multi-thread" friendly functions to exchange such
//! information.

use crate::Connection;

use super::ExpiredPkt;

impl Connection {
    /// Sets the highest expired packet number sent on the flexicast path.
    pub fn fc_set_last_expired(&mut self, exp: Option<ExpiredPkt>) {
        if let Some(mc) = self.multicast.as_mut() {
            mc.mc_last_expired = exp;
        }
    }
}