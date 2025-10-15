//! Encoder part of the FEC module.

use networkcoding::source_symbol_metadata_to_u64;
use networkcoding::vandermonde_lc::encoder::VLCEncoder;
use networkcoding::Encoder;

use crate::frame;
use crate::Connection;
use crate::Result;

use super::schedulers::FecScheduler;
use super::schedulers::FecSchedulerAlgorithm;

const FEC_SYMBOL_SIZE_DEFAULT: usize = 1250;
const FEC_MAX_WINDOW_SIZE_DEFAULT: usize = 1_000;

/// FEC Decoder structure.
pub(crate) struct FecEncoder {
    /// Vandermonde linear coding encoder.
    fec_encoder: Encoder,

    /// FEC scheduler algorithm to send repair packets.
    fec_scheduler: FecScheduler,

    /// Latest metadata of source symbol containing frames protected with FEC.
    pub latest_metadata_protected: Option<[u8; 8]>,

    /// Number of sent repair symbols.
    nb_sent_repair: u64,
}

impl FecEncoder {
    /// New instance using the Vandermonde linear coding.
    pub fn new(fec_scheduler: FecScheduler) -> Self {
        Self {
            fec_encoder: Encoder::VLC(VLCEncoder::new(
                FEC_SYMBOL_SIZE_DEFAULT,
                FEC_MAX_WINDOW_SIZE_DEFAULT,
            )),
            fec_scheduler,
            latest_metadata_protected: None,
            nb_sent_repair: 0,
        }
    }

    /// Returns the overhead of adding a FEC SOURCE_SYMBOL_HEADER frame with the
    /// next metadata.
    pub fn fec_overhead(&mut self) -> Result<usize> {
        Ok(32 +
            frame::Frame::SourceSymbolHeader {
                metadata: self.fec_encoder.next_metadata()?,
                recovered: false,
            }
            .wire_len())
    }

    #[inline]
    /// Returns a mutable reference to the inner FEC encoder.
    pub fn get_encoder(&mut self) -> &mut Encoder {
        &mut self.fec_encoder
    }

    /// Notifies the FEC scheduler that a source symbol was sent.
    pub fn fec_sent_source_symbol(&mut self) {
        self.fec_scheduler.sent_source_symbol(&self.fec_encoder);
    }

    /// Whether the FEC encoder should and can send a REPAIR frame, according to
    /// its scheduler.
    pub fn fec_should_send_repair(&self) -> bool {
        let symbol_size = self.fec_encoder.symbol_size();
        self.fec_scheduler.should_send_repair(symbol_size) &&
            self.fec_encoder.can_send_repair_symbols()
    }

    #[inline]
    /// Returns the metadata of the latest protected source symbol.
    pub fn get_latest_md_fec_protected(&self) -> Option<&[u8; 8]> {
        self.latest_metadata_protected.as_ref()
    }

    #[inline]
    /// Updates internal state when a new repair symbol is generated and sent.
    pub fn on_new_fec_repair_sent(&mut self) {
        if let (Some(first), Some(last)) = (
            self.fec_encoder.first_metadata(),
            self.latest_metadata_protected,
        ) {
            trace!(
                "packet REPAIR frame protecting symbols [{}, {}]",
                source_symbol_metadata_to_u64(first),
                source_symbol_metadata_to_u64(last),
            );
        }

        self.fec_scheduler.sent_repair_symbol(&self.fec_encoder);
        self.nb_sent_repair += 1;
    }

    #[inline]
    /// Notifies a lost repair symbol.
    pub fn fec_on_lost_repair_symbol(&mut self) {
        self.fec_scheduler.lost_repair_symbol(&self.fec_encoder);
    }

    #[inline]
    /// Notifies a received repair symbol.
    pub fn fec_on_acked_repair_symbol(&mut self) {
        self.fec_scheduler.acked_repair_symbol(&self.fec_encoder);
    }

    #[cfg(test)]
    pub fn get_nb_sent_repair(&self) -> u64 {
        self.nb_sent_repair
    }
}

impl Connection {
    /// Initiate the FEC encoder if it is not done yet.
    pub(crate) fn init_fec_encoder(&mut self, fec_scheduler: FecScheduler) {
        if self.local_transport_params.send_fec &&
            self.fec_encoder.is_none() &&
            self.peer_transport_params.recv_fec
        {
            self.fec_encoder = Some(FecEncoder::new(fec_scheduler));
        }
    }

    /// Sets the FEC scheduler algorithm.
    /// Only available if the host sends FEC.
    pub fn set_fc_scheduler_algo(&mut self, algo: FecSchedulerAlgorithm) {
        if let Some(encoder) = self.fec_encoder.as_mut() {
            encoder.fec_scheduler = algo.into();
        }
    }
}
