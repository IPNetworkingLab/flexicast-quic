//! Multicast acknowledgment aggregation module.
//! This module defines the [`McAck`] structure, which aggregates ACKs from
//! multiple recipients to only advertise changes to the source once all
//! receivers received a specific packet.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;

use crate::crypto::Algorithm;
use crate::flexicast::lkhlib::packet::FCKeyUpdate;
use crate::ranges::RangeSet;
use crate::Connection;

/// Number of packets we keep buffered to avoid "jitter".
const MAX_RECV_BUFF_SIZE: u64 = 200_000;

/// Offsets that must be acknowledged by the receivers.
/// Key: offset of the stream.
/// Value: (length of the stream, remaining number of clients that must ACK).
type McStream = BTreeMap<u64, (u64, u64)>;

/// Generalized delegated frames.
/// These frames can be retransmitted through unicast.
#[derive(Clone, Debug)]
pub enum FcDelegatedFrame {
    /// STREAM frame.
    Stream(FcDelegatedStream),

    /// FC_KEY_LKH.
    FcKeyLkh(FcKeyLkh),
}

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

#[derive(Clone, Debug)]
/// Shorthand for pieces of FC_KEY_LKH frames being delegated.
pub struct FcKeyLkh {
    /// Multicast flow ID.
    pub channel_id: Vec<u8>,

    /// Encryption algorithm being used.
    pub algo: Algorithm,

    /// First packet number used for this new key.
    pub first_pn: u64,

    /// Packet update type.
    pub key_update: FCKeyUpdate,
}

/// Multicast acknowledgment aggregation structure.
/// This assumes that callers do not call twice with the same received ranges,
/// as it allows strong optimizations. MC-TODO: handle when a client leaves the
/// channel for the aggregate ACK.
#[derive(Debug, Default, Clone)]
pub struct McAck {
    /// Number of receivers.
    nb_recv: u64,

    /// Internal representation of the received ACKs.
    /// Key: start of a run of packet numbers. Value: (end_exclusive, number of
    /// receivers that still need to ACK this run).  Consecutive packet numbers
    /// with the same remaining count are stored as a single entry to avoid
    /// O(range_size) per-ACK work.
    acked: BTreeMap<u64, (u64, u64)>,

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
            self.lowest_pn = self.acked.pop_last().map(|(_, (end, _))| end);
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
        if emulate_ack {
            // For entries covering [0, first_pn): C is credited as "already
            // ACKed" for those packets.  The count is nb_recv_old - 1 -
            // others_not_acked.  After C joins (nb_recv += 1) with emulation,
            // the new required count is (nb_recv_old + 1) - 1 - others - 1
            // = nb_recv_old - 1 - others = old count.  The +1 (new receiver)
            // and -1 (emulated ACK) cancel, so NO change to existing counts
            // is needed for pns < first_pn.

            // Track the late-joiner threshold so that in-flight pns < first_pn
            // that are not yet in `acked` get a corrected initial counter when
            // they are first ACKed (see `insert_first_seen`).
            self.late_joiner_thresholds.push(first_pn);
        }

        // The new receiver will ACK all pns >= first_pn, so increment the
        // remaining-count for every existing entry in that range.  Without
        // this, a prior ACK from another receiver could prematurely zero the
        // count before the new receiver has had a chance to ACK.
        //
        // Collect entries starting at >= first_pn BEFORE splitting any
        // straddling entry, so the split's right-hand side isn't double-counted.
        let to_increment: Vec<(u64, u64, u64)> = self
            .acked
            .range(first_pn..)
            .map(|(&s, &(e, c))| (s, e, c))
            .collect();

        // An entry that starts before first_pn but ends after it must be
        // split so only the [first_pn, end) part is incremented.
        if let Some((&s, &(e, c))) = self
            .acked
            .range(..first_pn)
            .next_back()
            .filter(|(_, &(end, _))| end > first_pn)
        {
            self.acked.insert(s, (first_pn, c)); // left: unchanged
            self.acked.insert(first_pn, (e, c + 1)); // right: incremented
        }

        for (s, e, c) in to_increment {
            self.acked.insert(s, (e, c + 1));
        }

        // Increment nb_recv BEFORE the dummy ACK so that insert_first_seen
        // uses the correct (post-join) receiver count.
        self.nb_recv += 1;

        // Issue a dummy ACK for any in-flight pns strictly between the last
        // ACKed pn and first_pn.  These packets were already sent before the
        // receiver joined so the receiver will never ACK them; the dummy
        // counts as their implicit acknowledgment.
        // Note: first_pn itself is NOT included — the receiver is expected
        // to start receiving from first_pn onwards.
        if let Some(largest) = self.largest_pn {
            if largest + 1 < first_pn {
                let mut ranges = RangeSet::default();
                ranges.insert(largest + 1..first_pn);
                println!("Dummy ack for packets not yet received!");
                self.on_ack_received(&ranges);
            }
        }
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
            if let Some(pos) =
                self.late_joiner_thresholds.iter().rposition(|&t| t == fp)
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
                    } else if recv_range.start <= range.start
                        && recv_range.end >= range.end
                    {
                        process_range = false;
                        break;
                    } else if recv_range.start <= range.start
                        && recv_range.end > range.start
                    {
                        range.start = recv_range.end;
                        continue;
                    } else if recv_range.end >= range.end {
                        range.end = recv_range.start;
                    } else if recv_range.start > range.start
                        && recv_range.end < range.end
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

            self.process_acked_range(range, &mut fully_range);
        }

        if let Some(recv_pkt_num) = self.recv_pkt_num.as_mut() {
            // Remove too old packets.
            if recv_pkt_num
                .last()
                .unwrap()
                .saturating_sub(recv_pkt_num.first().unwrap())
                > MAX_RECV_BUFF_SIZE
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
    ) -> (&BTreeMap<u64, (u64, u64)>, &HashMap<u64, McStream>, u64) {
        (&self.acked, &self.stream_map, self.nb_recv)
    }

    /// Returns the number of receivers.
    pub fn get_nb_recv(&self) -> u64 {
        self.nb_recv
    }

    /// Processes a single contiguous ACK range against the RLE `acked` map.
    ///
    /// For each packet number in `range`:
    /// - If already tracked (existing entry), decrement its remaining count.
    /// - If seen for the first time, compute the initial count taking late
    ///   joiners into account (via [`Self::insert_first_seen`]).
    /// - If the count reaches 0, add the run to `fully_range`.
    ///
    /// Runs that straddle the boundary of `range` are split so only the
    /// overlapping sub-run is decremented.
    fn process_acked_range(
        &mut self, range: std::ops::Range<u64>, fully_range: &mut RangeSet,
    ) {
        if range.start >= range.end {
            return;
        }

        // Find the first entry that might cover range.start (its key ≤
        // range.start and its end > range.start).
        let scan_start = self
            .acked
            .range(..=range.start)
            .next_back()
            .filter(|(_, &(end, _))| end > range.start)
            .map(|(&start, _)| start)
            .unwrap_or(range.start);

        // Collect all entries overlapping with `range`.
        let overlapping: Vec<(u64, u64, u64)> = self
            .acked
            .range(scan_start..range.end)
            .filter(|(_, &(end, _))| end > range.start)
            .map(|(&start, &(end, count))| (start, end, count))
            .collect();

        // Remove them; we will re-insert the adjusted versions below.
        for &(start, ..) in &overlapping {
            self.acked.remove(&start);
        }

        let mut cursor = range.start;

        for &(seg_start, seg_end, seg_count) in &overlapping {
            // Restore the part of this segment that lies before range.start.
            if seg_start < range.start {
                self.acked.insert(seg_start, (range.start, seg_count));
            }

            let eff_start = seg_start.max(range.start);
            let eff_end = seg_end.min(range.end);

            // Fill the gap between cursor and this segment with first-seen
            // packet numbers.
            if cursor < eff_start {
                self.insert_first_seen(cursor, eff_start, fully_range);
            }

            // Decrement the overlapping part.
            let new_count = seg_count.saturating_sub(1);
            if new_count == 0 {
                fully_range.insert(eff_start..eff_end);
            } else {
                self.acked.insert(eff_start, (eff_end, new_count));
            }

            cursor = eff_end;

            // Restore the part of this segment that lies after range.end.
            if seg_end > range.end {
                self.acked.insert(range.end, (seg_end, seg_count));
            }
        }

        // Fill any trailing gap after the last overlapping segment.
        if cursor < range.end {
            self.insert_first_seen(cursor, range.end, fully_range);
        }
    }

    /// Inserts a run of packet numbers `[start, end)` that is seen for the
    /// first time.  The initial remaining count is `nb_recv - 1` minus the
    /// number of late joiners whose threshold is strictly greater than the
    /// start of the sub-run.  Because thresholds may fall inside `[start,
    /// end)`, the run is split at each threshold boundary so every sub-run
    /// has a uniform initial count.
    fn insert_first_seen(
        &mut self, start: u64, end: u64, fully_range: &mut RangeSet,
    ) {
        if start >= end {
            return;
        }

        // Collect threshold values that create boundaries inside (start, end).
        let mut boundaries: Vec<u64> = self
            .late_joiner_thresholds
            .iter()
            .copied()
            .filter(|&t| t > start && t < end)
            .collect();
        boundaries.push(start);
        boundaries.push(end);
        boundaries.sort_unstable();
        boundaries.dedup();

        for window in boundaries.windows(2) {
            let (seg_start, seg_end) = (window[0], window[1]);
            // Count late joiners whose threshold is strictly greater than
            // seg_start — these receivers can never ACK packets in this run.
            let late_count = self
                .late_joiner_thresholds
                .iter()
                .filter(|&&fp| fp > seg_start)
                .count() as u64;
            let initial_count = self.nb_recv.saturating_sub(1 + late_count);

            if initial_count == 0 {
                fully_range.insert(seg_start..seg_end);
            } else {
                self.acked.insert(seg_start, (seg_end, initial_count));
            }
        }
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

        // largest+1 == first_pn (4+1 == 5) so the dummy ACK range [5..5) is
        // empty — no dummy fires.  first_pn=5 is the first packet B will
        // actually receive; it is not a "missed" packet.
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

    /// Two receivers, interleaved ACKs over disjoint and overlapping ranges.
    /// Fully-acked ranges must only appear once both receivers have ACKed them.
    #[test]
    fn test_mc_ack_two_receivers_interleaved() {
        let mut mc_ack = McAck::new(false);
        mc_ack.new_recv(0, false); // receiver A
        mc_ack.new_recv(0, false); // receiver B

        // A ACKs [0, 10) — none fully acked yet (B hasn't)
        let mut ra = RangeSet::default();
        ra.insert(0..10);
        mc_ack.on_ack_received(&ra);
        assert_eq!(mc_ack.full_ack(), None);

        // B ACKs [0, 5) — only [0, 5) is now fully acked
        let mut rb = RangeSet::default();
        rb.insert(0..5);
        mc_ack.on_ack_received(&rb);
        let mut expected = RangeSet::default();
        expected.insert(0..5);
        assert_eq!(mc_ack.full_ack(), Some(expected));
        assert_eq!(mc_ack.full_ack(), None); // already drained

        // B ACKs [5, 10) — now [5, 10) is also fully acked
        let mut rb2 = RangeSet::default();
        rb2.insert(5..10);
        mc_ack.on_ack_received(&rb2);
        let mut expected2 = RangeSet::default();
        expected2.insert(5..10);
        assert_eq!(mc_ack.full_ack(), Some(expected2));

        // Both ACK [20, 30) with gaps: A sends [20,25)+[27,30), B sends [20,30)
        let mut ra3 = RangeSet::default();
        ra3.insert(20..25);
        ra3.insert(27..30);
        mc_ack.on_ack_received(&ra3);
        assert_eq!(mc_ack.full_ack(), None);

        let mut rb3 = RangeSet::default();
        rb3.insert(20..30);
        mc_ack.on_ack_received(&rb3);
        // Only [20,25) and [27,30) can be fully acked; [25,27) was only ACKed by B
        let mut expected3 = RangeSet::default();
        expected3.insert(20..25);
        expected3.insert(27..30);
        assert_eq!(mc_ack.full_ack(), Some(expected3));

        // A now ACKs the missing [25, 27) → fully acked
        let mut ra4 = RangeSet::default();
        ra4.insert(25..27);
        mc_ack.on_ack_received(&ra4);
        let mut expected4 = RangeSet::default();
        expected4.insert(25..27);
        assert_eq!(mc_ack.full_ack(), Some(expected4));
    }

    /// Three receivers, each ACKing in a different order, verifying that
    /// full_ack only fires when all three have covered each packet.
    #[test]
    fn test_mc_ack_three_receivers() {
        let mut mc_ack = McAck::new(false);
        mc_ack.new_recv(0, false); // A
        mc_ack.new_recv(0, false); // B
        mc_ack.new_recv(0, false); // C

        // A ACKs [0, 100)
        let mut ra = RangeSet::default();
        ra.insert(0..100);
        mc_ack.on_ack_received(&ra);
        assert_eq!(mc_ack.full_ack(), None);

        // B ACKs [0, 50)
        let mut rb = RangeSet::default();
        rb.insert(0..50);
        mc_ack.on_ack_received(&rb);
        assert_eq!(mc_ack.full_ack(), None);

        // C ACKs [0, 30)
        let mut rc = RangeSet::default();
        rc.insert(0..30);
        mc_ack.on_ack_received(&rc);
        let mut exp1 = RangeSet::default();
        exp1.insert(0..30);
        assert_eq!(mc_ack.full_ack(), Some(exp1));

        // C ACKs [30, 100)
        let mut rc2 = RangeSet::default();
        rc2.insert(30..100);
        mc_ack.on_ack_received(&rc2);
        // B has only ACKed up to 50 so far — [30,50) is now fully acked
        let mut exp2 = RangeSet::default();
        exp2.insert(30..50);
        assert_eq!(mc_ack.full_ack(), Some(exp2));

        // B ACKs [50, 100) — now [50,100) is fully acked
        let mut rb2 = RangeSet::default();
        rb2.insert(50..100);
        mc_ack.on_ack_received(&rb2);
        let mut exp3 = RangeSet::default();
        exp3.insert(50..100);
        assert_eq!(mc_ack.full_ack(), Some(exp3));

        assert!(mc_ack.acked.is_empty());
    }

    /// A late receiver C joins with `emulate_ack=true` while [0,20) is
    /// pending (A has ACKed it, B has not).
    ///
    /// With the corrected `new_recv`:
    ///   - [0,10): count decremented (C emulated) → count 1→0
    ///   - [10,20): count incremented (C will need to ACK) → count 1→2
    ///   - largest_pn=19 >= first_pn=10, so no dummy ACK fires.
    ///   - nb_recv is incremented to 3 before any processing.
    #[test]
    fn test_mc_ack_late_receiver() {
        let mut mc_ack = McAck::new(false);
        mc_ack.new_recv(0, false); // A (nb_recv=1)
        mc_ack.new_recv(0, false); // B (nb_recv=2)

        // A ACKs [0, 20): count = 2-1 = 1 for each pn (single RLE entry).
        let mut ra = RangeSet::default();
        ra.insert(0..20);
        mc_ack.on_ack_received(&ra);
        assert_eq!(mc_ack.full_ack(), None);

        // C joins at pn=10 with emulate_ack=true (nb_recv→3).
        // largest_pn=19 >= first_pn=10 → no dummy ACK.
        mc_ack.new_recv(10, true);
        assert_eq!(mc_ack.nb_recv, 3);

        {
            let (acked, _, _) = mc_ack.get_state();
            // [0,10): count unchanged at 1 — nb_recv +1 and C's emulated ACK
            // -1 cancel out; only B still needs to ACK.
            assert_eq!(acked.get(&0), Some(&(10, 1)));
            // [10,20): count 1→2 — C will need to ACK these for real.
            assert_eq!(acked.get(&10), Some(&(20, 2)));
        }

        // B ACKs [0, 10): count 0→0 → fully acked (A + emulated C + B).
        let mut rb1 = RangeSet::default();
        rb1.insert(0..10);
        mc_ack.on_ack_received(&rb1);
        let mut exp1 = RangeSet::default();
        exp1.insert(0..10);
        assert_eq!(mc_ack.full_ack(), Some(exp1));

        // B ACKs [10, 20): count 2→1. C still needs to ACK.
        let mut rb2 = RangeSet::default();
        rb2.insert(10..20);
        mc_ack.on_ack_received(&rb2);
        assert_eq!(mc_ack.full_ack(), None);

        // C ACKs [10, 20): count 1→0 → fully acked.
        let mut rc = RangeSet::default();
        rc.insert(10..20);
        mc_ack.on_ack_received(&rc);
        let mut exp2 = RangeSet::default();
        exp2.insert(10..20);
        assert_eq!(mc_ack.full_ack(), Some(exp2));

        assert!(mc_ack.acked.is_empty());
    }

    /// Verifies that `new_recv` correctly splits an existing RLE entry that
    /// straddles `first_pn`.  The [0, first_pn) part gets its count decremented
    /// (late receiver emulated), and the [first_pn, end) part is left
    /// unchanged for future ACKs.
    ///
    /// Specifically: A and B are joined from the start (nb_recv=2).
    /// A ACKs [0, 50) creating a single entry with count=1.
    /// Then C joins at pn=20 with emulate_ack=true.
    /// new_recv must split the entry: [0,20) gets count 1→0, [20,50) stays 1.
    /// When B ACKs [0,20): count 0→0 → fully acked (A + emulated C both covered it).
    #[test]
    fn test_mc_ack_late_receiver_splits_existing_entry() {
        let mut mc_ack = McAck::new(false);
        mc_ack.new_recv(0, false); // A
        mc_ack.new_recv(0, false); // B

        // A ACKs [0, 50) — stored as a single RLE entry {0→(50,1)}.
        let mut ra = RangeSet::default();
        ra.insert(0..50);
        mc_ack.on_ack_received(&ra);
        assert_eq!(mc_ack.full_ack(), None);

        // C joins at pn=20 with emulate_ack=true.
        // new_recv must split {0→(50,1)} into {0→(20,0), 20→(50,1)}.
        mc_ack.new_recv(20, true);

        // Verify the split:
        //   [0,20)  → count=1  (nb_recv +1 and C emulated -1 cancel; B must still ACK)
        //   [20,50) → count=2  (A ACKed; both B and C must still ACK)
        {
            let (acked, _, _) = mc_ack.get_state();
            assert_eq!(acked.get(&0), Some(&(20, 1)));
            assert_eq!(acked.get(&20), Some(&(50, 2)));
        }

        // B ACKs [0, 50): count 0→0 → fully acked for [0, 20).
        // (A already ACKed, C was emulated — all three covered [0,20).)
        let mut rb = RangeSet::default();
        rb.insert(0..50);
        mc_ack.on_ack_received(&rb);
        let mut exp1 = RangeSet::default();
        exp1.insert(0..20);
        assert_eq!(mc_ack.full_ack(), Some(exp1));

        let mut rc = RangeSet::default();
        rc.insert(20..50);
        mc_ack.on_ack_received(&rc); // C ACKs → count 1→0 → fully acked
        let mut exp2 = RangeSet::default();
        exp2.insert(20..50);
        assert_eq!(mc_ack.full_ack(), Some(exp2));

        assert!(mc_ack.acked.is_empty());
    }

    /// Four original receivers (A, B, C, D) plus a late joiner E at pn=20,
    /// with partial ACKs already recorded when E arrives.
    ///
    /// Timeline:
    ///   A ACKs [0,50)       → count for [0,50) = 3  (B,C,D needed)
    ///   B ACKs [0,30)       → {[0,30)→2, [30,50)→3}
    ///   E joins  first_pn=20 → split at 20:
    ///                          [0,20)  count stays 2  (C,D; E emulated)
    ///                          [20,30) count 2→3      (C,D,E; +1 for E)
    ///                          [30,50) count 3→4      (B,C,D,E; +1 for E)
    ///   C ACKs [0,50)       → {[0,20)→1, [20,30)→2, [30,50)→3}
    ///   D ACKs [0,50)       → [0,20) fully acked; {[20,30)→1, [30,50)→2}
    ///   E ACKs [20,50)      → [20,30) fully acked; {[30,50)→1}
    ///   B ACKs [30,50)      → [30,50) fully acked
    ///
    /// With the old wrong decrement, E joining would have reduced [20,30)
    /// from 2 to 1, letting D's single ACK fully-ack it without E ever ACKing.
    #[test]
    fn test_mc_ack_late_receiver_many() {
        let mut mc_ack = McAck::new(false);
        mc_ack.new_recv(0, false); // A  nb_recv=1
        mc_ack.new_recv(0, false); // B  nb_recv=2
        mc_ack.new_recv(0, false); // C  nb_recv=3
        mc_ack.new_recv(0, false); // D  nb_recv=4

        let mut range_0_50 = RangeSet::default();
        range_0_50.insert(0..50);
        let mut range_0_30 = RangeSet::default();
        range_0_30.insert(0..30);

        // A ACKs [0,50): count = 4-1 = 3.
        mc_ack.on_ack_received(&range_0_50);
        assert_eq!(mc_ack.full_ack(), None);

        // B ACKs [0,30): [0,30) count 3→2; [30,50) stays 3.
        mc_ack.on_ack_received(&range_0_30);
        assert_eq!(mc_ack.full_ack(), None);

        // E joins at pn=20 with emulate_ack=true (nb_recv→5).
        // largest_pn=49 >= first_pn=20 → no dummy ACK.
        // Straddle at entry [0,30): split into [0,20)=2, [20,30)=3.
        // Entry [30,50) incremented: 3→4.
        mc_ack.new_recv(20, true);
        assert_eq!(mc_ack.nb_recv, 5);

        {
            let (acked, _, _) = mc_ack.get_state();
            assert_eq!(acked.get(&0), Some(&(20, 2)));
            assert_eq!(acked.get(&20), Some(&(30, 3)));
            assert_eq!(acked.get(&30), Some(&(50, 4)));
        }

        // C ACKs [0,50).
        mc_ack.on_ack_received(&range_0_50);
        assert_eq!(mc_ack.full_ack(), None);

        // D ACKs [0,50) → [0,20) reaches 0 → fully acked.
        mc_ack.on_ack_received(&range_0_50);
        let mut exp1 = RangeSet::default();
        exp1.insert(0..20);
        assert_eq!(mc_ack.full_ack(), Some(exp1));

        // E ACKs [20,50) → [20,30) reaches 0 → fully acked.
        let mut range_20_50 = RangeSet::default();
        range_20_50.insert(20..50);
        mc_ack.on_ack_received(&range_20_50);
        let mut exp2 = RangeSet::default();
        exp2.insert(20..30);
        assert_eq!(mc_ack.full_ack(), Some(exp2));

        // B ACKs [30,50) → [30,50) reaches 0 → fully acked.
        let mut range_30_50 = RangeSet::default();
        range_30_50.insert(30..50);
        mc_ack.on_ack_received(&range_30_50);
        let mut exp3 = RangeSet::default();
        exp3.insert(30..50);
        assert_eq!(mc_ack.full_ack(), Some(exp3));

        assert!(mc_ack.acked.is_empty());
    }
}
