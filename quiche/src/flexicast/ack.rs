//! Multicast acknowledgment aggregation module.
//! This module defines the [`McAck`] structure, which aggregates ACKs from
//! multiple recipients to only advertise changes to the source once all
//! receivers received a specific packet.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;

use crate::ranges::RangeSet;
use crate::Connection;

/// Number of packets we keep buffered to avoid "jitter".
const MAX_RECV_BUFF_SIZE: u64 = 200_000;

/// Offsets that must be acknowledged by the receivers.
/// Key: offset of the stream.
/// Value: (length of the stream, remaining number of clients that must ACK).
type McStream = BTreeMap<u64, (u64, u64)>;

#[derive(Clone, Debug)]
/// Shorthand for pieces of streams that are delegated.
/// First value: stream ID.
/// Second value: offset.
/// Third value: Payload.
/// The length is induced using the payload.
pub struct FcDelegatedStream {
    /// Stream ID.
    pub stream_id: u64,

    /// Offset of the stream.
    pub offset: u64,

    /// Payload of the stream.
    pub payload: Vec<u8>,

    /// Whether this is the last frame of the stream.
    pub fin: bool,

    /// Packet number of the Flexicast flow initially containing the delegated
    /// STREAM frame.
    pub pn: Option<u64>,

    /// Potential Forward Erasure Correction (FEC) source symbol metadata.
    pub fec_md: Option<u64>,
}

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

    /// Stream delegation map.
    /// When the flexicast source delegates stream content to unicast, it must
    /// know which receivers correctly received the delegated streams to allow
    /// to release resources on the flexicast source. This structure holds,
    /// for each stream, the state of the stream regarding offsets.
    stream_map: HashMap<u64, McStream>,

    /// Fully acknowledged stream offsets.
    stream_full: HashMap<u64, RangeSet>,

    /// Lowest packet number potentially in the acked ranges.
    lowest_pn: Option<u64>,

    /// Largest packet number seen in the ack ranges.
    largest_pn: Option<u64>,

    /// Sets of already received packets numbers.
    /// This set is emptied based on the largest received packet number.
    /// Only not null if this is the unicast path.
    pub(crate) recv_pkt_num: Option<RangeSet>,

    /// First packet number of each late-joining receiver (one that joined
    /// with `emulate_ack=true`).  When a pn is seen for the first time in
    /// `on_ack_received`, the number of thresholds *strictly greater than*
    /// that pn gives the count of receivers that can never ACK it.  The
    /// initial counter is reduced by that count so the entry reaches 0 as
    /// soon as the remaining eligible receivers ACK it.
    late_joiner_thresholds: Vec<u64>,
}

impl McAck {
    /// Creates a new, empty structure.
    pub fn new(is_uc_path: bool) -> Self {
        Self {
            nb_recv: 0,
            acked: BTreeMap::new(),
            acked_full: None,
            stream_map: HashMap::new(),
            stream_full: HashMap::new(),
            lowest_pn: None,
            largest_pn: None,
            recv_pkt_num: is_uc_path.then(RangeSet::default),
            late_joiner_thresholds: Vec::new(),
        }
    }

    /// Returns the fully acknowledged packets. This drains the internal state.
    pub fn full_ack(&mut self) -> Option<RangeSet> {
        self.acked_full.take()
    }

    #[cfg(test)]
    /// Polls the fully acknowledged packets.
    pub fn full_ack_poll(&self) -> Option<&RangeSet> {
        self.acked_full.as_ref()
    }

    /// Sets the largest packet number in the structure.
    /// This drains entries that are below this value.
    pub fn drain_packets(&mut self, lowest_pn: Option<u64>) {
        if let Some(lowest_pn) = lowest_pn {
            self.acked = self.acked.split_off(&lowest_pn);
            self.lowest_pn = Some(lowest_pn - 1);
        } else {
            self.lowest_pn = self.acked.pop_last().map(|(_, v)| v);
            self.acked = BTreeMap::new();
        }
    }

    /// Get largest packet number that is still in the queue.
    pub fn get_largest_pn(&self) -> Option<u64> {
        // self.acked.last_key_value().map(|(pn, _)| *pn)
        self.largest_pn
    }

    /// Get the lowest packet number that is still in the queue.
    pub fn get_lowest_pn(&self) -> Option<u64> {
        self.acked.first_key_value().map(|(pn, _)| *pn)
    }

    /// Adds a new receiver to the structure.
    /// This will "simulate" the fact that the new receiver ACKed all packets
    /// before `first_pn`.
    pub fn new_recv(&mut self, first_pn: u64, emulate_ack: bool) {
        for (&pn, nb) in self.acked.iter_mut() {
            if pn >= first_pn {
                break;
            }
            if emulate_ack {
                *nb = (*nb).saturating_sub(1);
            }
        }

        // Track the late-joiner threshold so that in-flight pns < first_pn
        // that are not yet in `acked` get a corrected initial counter when
        // they are first ACKed (see `on_ack_received`).
        if emulate_ack {
            self.late_joiner_thresholds.push(first_pn);
        }

        // Also for acknowledgment not yet received...
        if let Some(largest) = self.largest_pn {
            if largest < first_pn {
                let mut ranges = RangeSet::default();
                ranges.insert(largest + 1..first_pn + 1);
                println!("Dummy ack for packets not yet received!");
                self.on_ack_received(&ranges);
            }
        }

        self.nb_recv += 1;
    }

    /// Removes a receiver from the structure.
    /// If the receiver was a late joiner (joined via `new_recv` with
    /// `emulate_ack=true`), pass `Some(first_pn)` to also remove its
    /// threshold from `late_joiner_thresholds`.
    pub fn remove_recv(&mut self, late_joiner_first_pn: Option<u64>) {
        warn!("Removing a receiver from the MC ACK. May break things.");
        self.nb_recv = self.nb_recv.saturating_sub(1);
        if let Some(fp) = late_joiner_first_pn {
            // Remove the most-recent matching threshold (rposition handles
            // multiple late joiners with the same first_pn gracefully).
            if let Some(pos) = self
                .late_joiner_thresholds
                .iter()
                .rposition(|&t| t == fp)
            {
                self.late_joiner_thresholds.remove(pos);
            }
        }
    }

    /// Adds a new ACK from a client. Assumes that this is the first time the
    /// client sends this range of ACKs. Potentially generates new fully ack
    /// packets thanks to this range.
    pub fn on_ack_received(&mut self, ranges: &RangeSet) {
        let mut fully_range = self.acked_full.take().unwrap_or_default();

        // Update the largest PN seen.
        if let Some(largest_in_range) = ranges.last() {
            self.largest_pn = Some(
                self.largest_pn
                    .unwrap_or(largest_in_range)
                    .max(largest_in_range),
            );
        }

        // Potential ranges that we must process because they interfering.
        let mut new_rangeset = RangeSet::default();

        for init_range in ranges.clone().iter() {
            let mut range = init_range.clone();
            let mut process_range = true;

            // Check the range of packets that have already been acknowledged.
            if let Some(recv_pkt_num) = self.recv_pkt_num.as_mut() {
                for recv_range in recv_pkt_num.iter() {
                    if recv_range.end < range.start {
                        continue;
                    } else if recv_range.start > range.end {
                        break;
                    } else if recv_range.start <= range.start &&
                        recv_range.end >= range.end
                    {
                        process_range = false;
                        break;
                    } else if recv_range.start <= range.start &&
                        recv_range.end > range.start
                    {
                        range.start = recv_range.end;
                        continue;
                    } else if recv_range.end >= range.end {
                        range.end = recv_range.start;
                    } else if recv_range.start > range.start &&
                        recv_range.end < range.end
                    {
                        // We will have to split the two ranges... Do it the easy
                        // way lol.
                        let end = range.end;
                        range.end = recv_range.start;

                        // And do a recursive call later.
                        new_rangeset.insert(recv_range.end..end);
                    }
                }

                if process_range {
                    recv_pkt_num.insert(range.clone());
                }
            }

            if !process_range {
                continue;
            }

            for recv_pn in range {
                let nb_recv_opt = self.acked.get_mut(&recv_pn);
                let new_nb = if let Some(nb_recv) = nb_recv_opt {
                    *nb_recv = (*nb_recv).saturating_sub(1);
                    *nb_recv
                } else {
                    // The first receiver to ACK this packet.
                    // Subtract late joiners who joined after this pn was sent
                    // and therefore can never ACK it.  Without this adjustment,
                    // the counter would be set to nb_recv-1 but only
                    // (nb_recv - late_count - 1) more ACKs will ever arrive,
                    // causing the entry to be permanently stuck at 1.
                    let late_count = self
                        .late_joiner_thresholds
                        .iter()
                        .filter(|&&fp| fp > recv_pn)
                        .count() as u64;
                    let initial_count =
                        self.nb_recv.saturating_sub(1 + late_count);
                    self.acked.insert(recv_pn, initial_count);
                    initial_count
                };

                if new_nb == 0 {
                    // Not opti at all.
                    fully_range.insert(recv_pn..recv_pn + 1);

                    self.acked.remove(&recv_pn);
                }
            }
        }

        if let Some(recv_pkt_num) = self.recv_pkt_num.as_mut() {
            // Remove too old packets.
            if recv_pkt_num
                .last()
                .unwrap()
                .saturating_sub(recv_pkt_num.first().unwrap()) >
                MAX_RECV_BUFF_SIZE
            {
                recv_pkt_num.remove_until(
                    recv_pkt_num
                        .last()
                        .unwrap()
                        .saturating_sub(MAX_RECV_BUFF_SIZE),
                );
            }
        }

        if fully_range.len() > 0 {
            self.acked_full = Some(fully_range);
        }

        // And do the recursive call.
        if new_rangeset.len() > 0 {
            self.on_ack_received(&new_rangeset);
        }
    }

    /// Delegates a new portion of stream to a client.
    /// Assumes that we do not delegate twice the same stream to the same
    /// client. This allows for strong optimizations.
    pub fn delegate(&mut self, stream_id: u64, off: u64, len: u64) {
        // No need to store empty data.
        if len == 0 {
            return;
        }

        self.stream_map
            .entry(stream_id)
            .or_insert_with(BTreeMap::new);
        let stream = self.stream_map.get_mut(&stream_id).unwrap();

        let mut tmp_offs = VecDeque::with_capacity(2);
        tmp_offs.push_back((off, len));

        while let Some((new_off, new_len)) = tmp_offs.pop_front() {
            let offsets: Vec<_> = stream.keys().copied().collect();

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
            let offsets: Vec<_> = stream.keys().copied().collect();

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
                    self.stream_full
                        .entry(stream_id)
                        .or_insert_with(RangeSet::default);
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

    /// Returns the number of receivers.
    pub fn get_nb_recv(&self) -> u64 {
        self.nb_recv
    }
}

impl Connection {
    /// Shortcut to get the [`McAck`] structure of the flexicast source.
    pub(crate) fn get_mc_ack_mut(&mut self) -> Option<&mut McAck> {
        self.flexicast
            .as_mut()
            .and_then(|mc| mc.fc_reliable.source_mut().map(|rs| &mut rs.mc_ack))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mc_ack_pn() {
        let mut mc_ack = McAck::new(false);
        mc_ack.new_recv(1, false);

        let mut ranges = RangeSet::default();
        ranges.insert(1..5);

        assert_eq!(mc_ack.full_ack(), None);
        mc_ack.on_ack_received(&ranges);
        let mut ranges = RangeSet::default();
        ranges.insert(1..5);
        assert_eq!(mc_ack.full_ack(), Some(ranges));
        assert!(mc_ack.acked.is_empty());

        mc_ack.new_recv(5, false);

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
        let mut mc_ack = McAck::new(false);

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

    #[test]
    fn test_mc_ack_pn_2() {
        let mut mc_ack = McAck::new(true);

        let mut rs1 = RangeSet::default();
        rs1.insert(0..100);
        rs1.insert(150..151);
        mc_ack.on_ack_received(&rs1);

        let full = mc_ack.full_ack();

        assert_eq!(full, Some(rs1));

        let mut rs2 = RangeSet::default();
        rs2.insert(100..200);
        mc_ack.on_ack_received(&rs2);

        let full = mc_ack.full_ack();
        let mut expected = RangeSet::default();
        expected.insert(100..150);
        expected.insert(151..200);
        assert_eq!(full, Some(expected));
    }
}
