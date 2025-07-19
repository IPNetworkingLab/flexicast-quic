//! This module further extends the [`crate::recovery::Recovery`] structure with
//! NACK-based Flexicast reliability mechanisms.

use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::recovery::HandshakeStatus;
use crate::recovery::Recovery;
use crate::recovery::RttStats;
use crate::Result;
use std::time;

impl Recovery {
    #[allow(unused)]
    /// Removes from the sending buffer sent packets that have been sent more
    /// than `timeout` ago.
    /// Only removes contiguous sequences of packets.
    /// Does not remove packets that are considered lost BUT not delegated yet
    /// on the unicast path to avoid releasing memory.
    ///
    /// NACK-based Flexicast extension.
    pub fn fc_nack_release_sent(
        &mut self, epoch: Epoch, now: time::Instant, timeout: time::Duration,
        handshake_status: HandshakeStatus, trace_id: &str,
        rtt_stats: &mut RttStats,
    ) -> Result<Option<u64>> {
        let pns = self.epochs[epoch]
            .sent_packets
            .iter_mut()
            .take_while(|pkt| now.duration_since(pkt.time_sent) >= timeout)
            .map(|pkt| {
                pkt.is_fc_delegated = true;
                pkt.pkt_num
            })
            .collect::<Vec<u64>>();

        // FC-TODO: not optimal way to construct the RangeSet...
        let mut ranges = RangeSet::default();
        for pn in pns {
            ranges.insert(pn..pn + 1);
        }

        // Acknowledge the packets to release them from memory.
        if ranges.len() > 0 {
            self.on_ack_received(
                &ranges,
                0,
                epoch,
                handshake_status,
                now,
                rtt_stats,
                trace_id,
            )?;
        }

        Ok(ranges.last())
    }

    /// Removes from the sending buffer sent packets up to `pn`.
    ///
    /// NACK-based Flexicast extension.
    pub fn fc_nack_release_sent_up_to(
        &mut self, epoch: Epoch, now: time::Instant,
        handshake_status: HandshakeStatus, trace_id: &str, pn: u64,
        rtt_stats: &mut RttStats,
    ) -> Result<()> {
        let pns = self.epochs[epoch]
            .sent_packets
            .iter()
            .take_while(|pkt| pkt.pkt_num <= pn)
            .map(|pkt| pkt.pkt_num)
            .collect::<Vec<u64>>();

        // FC-TODO: not optimal way to construct the RangeSet...
        let mut ranges = RangeSet::default();
        for pn in pns {
            ranges.insert(pn..pn + 1);
        }

        // Acknowledge the packets to release them from memory.
        if ranges.len() > 0 {
            self.on_ack_received(
                &ranges,
                0,
                epoch,
                handshake_status,
                now,
                rtt_stats,
                trace_id,
            )?;
        }

        Ok(())
    }
}
