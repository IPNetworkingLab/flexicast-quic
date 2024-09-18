//! Multicast acknowledgment aggregation module.
//! This module defines the [`McAck`] structure, which aggregates ACKs from
//! multiple recipients to only advertise changes to the source once all
//! receivers received a specific packet.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;

use crate::ranges::RangeSet;
use crate::Connection;

/// Offsets that must be acknowledged by the receivers.
/// Key: offset of the stream.
/// Value: (length of the stream, remaining number of clients that must ACK).
type McStream = BTreeMap<u64, (u64, u64)>;

/// Stream ID and offsets of streams.
pub type McStreamOff = Vec<(u64, RangeSet)>;

/// Public representation of rangesets.
pub type OpenRangeSet = RangeSet;

/// Multicast acknowledgment aggregation structure.
/// This assumes that callers do not call twice with the same received ranges,
/// as it allows strong optimizations. MC-TODO: handle when a client leaves the
/// channel for the aggregate ACK.
#[derive(Debug, Default, Clone)]
pub struct McAck {
    /// Number of receivers.
    nb_recv: u64,

    /// Internal representation of the received ACKs.
    /// Key: packet number. Value: number of received that acknowledged this
    /// packet.
    acked: BTreeMap<u64, u64>,

    /// RangeSet of all fully acknowledged packets that are not yet passed to
    /// the source.
    acked_full: Option<RangeSet>,

    /// Stream deleguation map.
    /// When the flexicast source delegates stream content to unicast, it must
    /// know which receivers correctly received the delegated streams to allow
    /// to release resources on the flexicast source. This structure holds,
    /// for each stream, the state of the stream regarding offsets.
    stream_map: HashMap<u64, McStream>,

    /// Fully acknowledged stream offsets.
    stream_full: HashMap<u64, RangeSet>,

    /// Lowest packet number potentially in the acked ranges.
    largest_pn: Option<u64>,
}

impl McAck {
    /// Creates a new, empty structure.
    pub fn new() -> Self {
        Self {
            nb_recv: 0,
            acked: BTreeMap::new(),
            acked_full: None,
            stream_map: HashMap::new(),
            stream_full: HashMap::new(),
            largest_pn: None,
        }
    }

    /// Returns the fully acknowledged packets. This drains the internal state.
    pub fn full_ack(&mut self) -> Option<RangeSet> {
        self.acked_full.take()
    }

    /// Sets the largest packet number in the structure.
    /// This drains entries that are below this value.
    pub fn drain_packets(&mut self, largest_pn: u64) {
        self.acked = self.acked.split_off(&largest_pn);
        self.largest_pn = Some(largest_pn);
    }

    /// Get largest packet number that is still in the queue.
    pub fn get_largest_pn(&self) -> Option<u64> {
        self.largest_pn
    }

    /// Adds a new receiver to the structure.
    /// This will "simulate" the fact that the new receiver ACKed all packets
    /// before `first_pn`.
    pub fn new_recv(&mut self, first_pn: u64) {
        for (&pn, nb) in self.acked.iter_mut() {
            if pn >= first_pn {
                break;
            }

            *nb += 1;
        }

        self.nb_recv += 1;
    }

    /// Adds a new ACK from a client. Assumes that this is the first time the
    /// client sends this range of ACKs. Potentially generates new fully ack
    /// packets thanks to this range.
    pub fn on_ack_received(&mut self, ranges: &RangeSet) {
        let mut fully_range =
            self.acked_full.take().unwrap_or(RangeSet::default());

        for range in ranges.iter() {
            for recv_pn in range {
                let nb_recv_opt = self.acked.get_mut(&recv_pn);
                let new_nb = if let Some(nb_recv) = nb_recv_opt {
                    *nb_recv += 1;
                    *nb_recv
                } else {
                    // The first receiver to ACK this packet.
                    self.acked.insert(recv_pn, 1);
                    1
                };

                if new_nb == self.nb_recv {
                    // Not opti at all.
                    fully_range.insert(recv_pn..recv_pn + 1);

                    self.acked.remove(&recv_pn);
                }
            }
        }

        if fully_range.len() > 0 {
            self.acked_full = Some(fully_range);
        }
    }

    /// Removes states for packet numbers up to the given value.
    // pub fn remove_up_to(&mut self, to: u64) {
    //     self.acked = self.acked.split_off(&to);
    // }

    /// Delegates a new portion of stream to a client.
    /// Assumes that we do not delegate twice the same stream to the same
    /// client. This allows for strong optimizations.
    pub fn delegate(&mut self, stream_id: u64, off: u64, len: u64) {
        // No need to store empty data.
        if len == 0 {
            return;
        }

        if !self.stream_map.contains_key(&stream_id) {
            self.stream_map.insert(stream_id, BTreeMap::new());
        }
        let stream = self.stream_map.get_mut(&stream_id).unwrap();

        let mut tmp_offs = VecDeque::with_capacity(2);
        tmp_offs.push_back((off, len));

        while let Some((new_off, new_len)) = tmp_offs.pop_front() {
            let offsets: Vec<_> = stream.keys().map(|i| *i).collect();

            for &offset in offsets.iter() {
                // The new range is below existing ranges, so we can fully add it
                // to the buffer.
                if new_off + new_len <= offset {
                    break;
                }

                let (len, _) = stream.get(&offset).unwrap();

                // The new range is above the current range. We do nothing but
                // we wait for the potentially next buffer.
                if offset + *len <= new_off {
                    continue;
                }

                // Remove the current range.
                let (len, nb) = stream.remove(&offset).unwrap();
                let start_overlap = offset.max(new_off);
                let end_overlap = (offset + len).min(new_off + new_len);

                // Add the left-part.
                if offset < new_off {
                    stream.insert(offset, (new_off - offset, nb));
                } else if offset > new_off {
                    stream.insert(new_off, (offset - new_off, nb));
                }

                // Add the right only for the existing range.
                // For the new range, we must check with later ranges.
                if offset + len > new_off + new_len {
                    stream.insert(
                        new_off + new_len,
                        (offset + len - (new_off + new_len), nb),
                    );
                } else if offset + len < new_off + new_len {
                    // We add the remaining of the new range to check with later
                    // ranges.
                    tmp_offs.push_back((
                        offset + len,
                        new_off + new_len - (offset + len),
                    ));
                }

                // Add the middle part, where we overlap.
                stream
                    .insert(start_overlap, (end_overlap - start_overlap, nb + 1));
                continue;
            }

            // One receiver only.
            if new_off != new_len && !stream.contains_key(&new_off) {
                stream.insert(new_off, (new_len, 1));
            }
        }
    }

    /// Receives and process a new stream acknowledgment.
    /// This function potentially creates new "fuly" acknowledged stream
    /// offsets. Assumes that a same receiver only acknowledge a stream
    /// offset only once.
    pub fn on_stream_ack_received(&mut self, stream_id: u64, off: u64, len: u64) {
        if len == 0 {
            return;
        }

        // No data for the stream. Should not happen!
        if !self.stream_map.contains_key(&stream_id) {
            return;
        }
        let stream = self.stream_map.get_mut(&stream_id).unwrap();

        let mut tmp_offs = VecDeque::with_capacity(2);
        tmp_offs.push_back((off, len));

        while let Some((ack_off, ack_len)) = tmp_offs.pop_front() {
            let offsets: Vec<_> = stream.keys().map(|i| *i).collect();

            for &offset in offsets.iter() {
                // The ack range is below the current.
                // This should not happen but we do nothing.
                if ack_off + ack_len <= offset {
                    return;
                }

                // The ack range is above the current. Continue. Will be acked
                // later.
                let (len, _) = stream.get(&offset).unwrap();
                if offset + *len <= ack_off {
                    continue;
                }

                let (len, nb) = stream.remove(&offset).unwrap();
                let start_overlap = offset.max(ack_off);
                let end_overlap = (offset + len).min(ack_off + ack_len);

                // If the ack range starts after the current range, we must split,
                // because only a sub-part is acked now.
                // If the ack range starts before... should not happen.
                if offset < ack_off {
                    stream.insert(offset, (ack_off - offset, nb));
                } else if ack_off < offset {
                    // Should not happen.
                }

                // If the ack range ends before the current range, we must split,
                // because only a sub-part is acked now.
                // If the ack range ends after the current range, we split and
                // check for a later range.
                if offset + len > ack_off + ack_len {
                    stream.insert(
                        ack_off + ack_len,
                        (offset + len - (ack_off + ack_len), nb),
                    );
                } else if offset + len < ack_off + ack_len {
                    tmp_offs.push_back((
                        offset + len,
                        ack_off + ack_len - (offset + len),
                    ));
                }

                // Ack the middle part.
                let new_nb = nb.saturating_sub(1);
                if new_nb > 0 {
                    stream.insert(
                        start_overlap,
                        (end_overlap - start_overlap, nb.saturating_sub(1)),
                    );
                } else {
                    // This range is fully acknowledged.
                    if !self.stream_full.contains_key(&stream_id) {
                        self.stream_full.insert(stream_id, RangeSet::default());
                    }
                    let range_ack = self.stream_full.get_mut(&stream_id).unwrap();
                    range_ack.insert(start_overlap..end_overlap);
                    stream.remove(&start_overlap);
                }
            }
        }

        if stream.is_empty() {
            self.stream_map.remove(&stream_id);
        }
    }

    /// Returns the fully acknowledged stream offsets. This drains the internal
    /// state.
    pub fn acked_stream_off(&mut self) -> Option<McStreamOff> {
        if self.stream_full.is_empty() {
            None
        } else {
            Some(self.stream_full.drain().collect())
        }
    }

    #[cfg(test)]
    /// Returns the internal state of the structure.
    pub fn get_state(
        &self,
    ) -> (&BTreeMap<u64, u64>, &HashMap<u64, McStream>, u64) {
        (&self.acked, &self.stream_map, self.nb_recv)
    }
}

impl Connection {
    /// Shortcut to get the [`McAck`] structure of the flexicast source.
    pub(crate) fn get_mc_ack_mut(&mut self) -> Option<&mut McAck> {
        self.multicast
            .as_mut()
            .map(|mc| mc.rmc_get_mut().source_mut().map(|rs| &mut rs.mc_ack))
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mc_ack_pn() {
        let mut mc_ack = McAck::new();
        mc_ack.new_recv(1);

        let mut ranges = RangeSet::default();
        ranges.insert(1..5);

        assert_eq!(mc_ack.full_ack(), None);
        mc_ack.on_ack_received(&ranges);
        let mut ranges = RangeSet::default();
        ranges.insert(1..5);
        assert_eq!(mc_ack.full_ack(), Some(ranges));
        assert!(mc_ack.acked.is_empty());

        mc_ack.new_recv(5);

        let mut ranges = RangeSet::default();
        ranges.insert(5..9);
        ranges.insert(12..15);
        mc_ack.on_ack_received(&ranges);
        assert_eq!(mc_ack.full_ack(), None);

        let mut ranges = RangeSet::default();
        ranges.insert(7..8);
        ranges.insert(13..16);
        mc_ack.on_ack_received(&ranges);

        let mut ranges = RangeSet::default();
        ranges.insert(7..8);
        ranges.insert(13..15);
        assert_eq!(mc_ack.full_ack(), Some(ranges));
        assert_eq!(mc_ack.full_ack(), None);

        let mut ranges = RangeSet::default();
        ranges.insert(5..7);
        ranges.insert(8..9);
        ranges.insert(12..13);
        ranges.insert(15..16);
        mc_ack.on_ack_received(&ranges);
        assert_eq!(mc_ack.full_ack(), Some(ranges));
    }

    #[test]
    fn test_mc_ack_stream() {
        let mut mc_ack = McAck::new();

        mc_ack.delegate(1, 500, 100);
        mc_ack.delegate(1, 550, 100);

        let stream = mc_ack.stream_map.get(&1).unwrap();
        let keys = stream.keys().map(|i| *i).collect::<Vec<_>>();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys, vec![500, 550, 600]);

        mc_ack.delegate(3, 500, 100);
        mc_ack.delegate(3, 500, 10);

        mc_ack.on_stream_ack_received(1, 500, 25);
        mc_ack.on_stream_ack_received(1, 550, 100);

        let mut ranges = RangeSet::default();
        ranges.insert(500..525);
        ranges.insert(600..650);
        assert_eq!(mc_ack.acked_stream_off(), Some(vec![(1, ranges)]));

        mc_ack.on_stream_ack_received(1, 525, 75);
        let mut ranges = RangeSet::default();
        ranges.insert(525..600);
        assert_eq!(mc_ack.acked_stream_off(), Some(vec![(1, ranges)]));

        mc_ack.on_stream_ack_received(3, 500, 10);
        assert_eq!(mc_ack.acked_stream_off(), None);
        mc_ack.delegate(3, 500, 10);
        mc_ack.on_stream_ack_received(3, 500, 10);
        assert_eq!(mc_ack.acked_stream_off(), None);
        mc_ack.on_stream_ack_received(3, 500, 100);

        let mut ranges = RangeSet::default();
        ranges.insert(500..600);
        assert_eq!(mc_ack.acked_stream_off(), Some(vec![(3, ranges)]));
    }
}
