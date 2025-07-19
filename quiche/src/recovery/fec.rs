use networkcoding::source_symbol_metadata_to_u64;

use super::Recovery;
use crate::frame;
use crate::packet;
use crate::ranges;

impl Recovery {
    /// Forward Erasure Correction extension.
    ///
    /// Handles the acknowledged source symbols ID in the recovery.
    /// This function does not impact the congestion control algorithm because
    /// the frames were recovered through FEC. It does not consider the
    /// frames as acknowledged, only recovered.
    pub fn fec_on_source_symbol_ack_received(
        &mut self, ranges: &ranges::RangeSet, epoch: packet::Epoch,
        trace_id: &str,
    ) {
        // Detect and mark recovered symbols without considering them acknowledged
        // or lost.
        for r in ranges.iter() {
            let lowest_recovered_in_block = r.start;
            let largest_recovered_in_block = r.end;

            let epoch = &mut self.epochs[epoch];

            // Search in the unacknowledged packets, ones containing source
            // symbols that are being recovered.
            let unacked_iter = epoch
                .sent_packets
                .iter_mut()
                // Skip already acknowledged packets.
                .filter(|p| p.time_acked.is_none());

            for unacked in unacked_iter {
                for frame in unacked.frames.iter_mut() {
                    if let frame::Frame::SourceSymbolHeader {
                        metadata,
                        recovered,
                    } = frame
                    {
                        let mdu64 = source_symbol_metadata_to_u64(*metadata);

                        if lowest_recovered_in_block <= mdu64 &&
                            mdu64 >= largest_recovered_in_block
                        {
                            *recovered = true;
                            trace!(
                                "{} source symbol newly recovered {} in pkt {}",
                                trace_id,
                                mdu64,
                                unacked.pkt_num,
                            );
                        }
                    }
                }
            }
        }
    }
}
