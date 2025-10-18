//! Decoder part of the FEC module.

use std::collections::HashMap;
use std::time;

use crate::packet;
use crate::ranges::RangeSet;
use crate::Connection;
use crate::Result;
use networkcoding::source_symbol_metadata_from_u64;
use networkcoding::source_symbol_metadata_to_u64;
use networkcoding::vandermonde_lc::decoder::VLCDecoder;
use networkcoding::DecoderError;

const FEC_SYMBOL_SIZE_DEFAULT: usize = 1250;
const FEC_MAX_WINDOW_SIZE_DEFAULT: usize = 1_000;

/// FEC Decoder structure.
pub(crate) struct FecDecoder {
    /// Vandermonde linear coding decoder.
    pub fec_decoder: VLCDecoder,

    /// FEC receiving window size.
    pub fec_recv_window_size: usize,

    /// Number of recovered source symbol.
    pub nb_recovered: u64,

    /// Number of received repair symbols.
    pub nb_recv_repair: u64,

    // FEC ESI needing FEC-acknowledgment.
    pub recovered_symbols_need_ack: RangeSet,

    // History of recovered source symbol metadata.
    pub recovered_symbols_md_history: HashMap<u64, RecoveredSymbol>,
}

impl FecDecoder {
    /// New instance using the Vandermonde linear coding.
    pub fn new() -> Self {
        Self {
            fec_decoder: VLCDecoder::new(
                FEC_SYMBOL_SIZE_DEFAULT,
                FEC_MAX_WINDOW_SIZE_DEFAULT,
            ),
            fec_recv_window_size: FEC_MAX_WINDOW_SIZE_DEFAULT,
            nb_recovered: 0,
            nb_recv_repair: 0,
            recovered_symbols_need_ack: RangeSet::default(),
            recovered_symbols_md_history: HashMap::new(),
        }
    }
}

impl Connection {
    /// Initiate the FEC decoder if it is not done yet.
    pub(crate) fn init_fec_decoder(&mut self) {
        if self.local_transport_params.recv_fec &&
            self.fec_decoder.is_none() &&
            self.peer_transport_params.send_fec
        {
            self.fec_decoder = Some(FecDecoder::new());
        }
    }

    /// Process a decoded (i.e., recovered) source symbol.
    fn process_decoded_symbol(
        &mut self, decoded_symbol: networkcoding::SourceSymbol,
        hdr: &packet::Header, recv_path_id: usize, recv_network_path_id: usize, epoch: packet::Epoch,
        now: time::Instant,
    ) -> Result<()> {
        let mdu64 = source_symbol_metadata_to_u64(decoded_symbol.metadata());
        println!("Recover a lost source symbol! {:?}", mdu64);

        self.process_frames_of_source_symbol(
            decoded_symbol,
            now,
            epoch,
            hdr,
            recv_path_id,
            recv_network_path_id,
        )?;

        if let Some(fec_decoder) = self.fec_decoder.as_mut() {
            fec_decoder.nb_recovered += 1;
            fec_decoder.recovered_symbols_need_ack.push_item(mdu64);
            fec_decoder.recovered_symbols_md_history.insert(
                mdu64,
                RecoveredSymbol {
                    recovered_time: now,
                    received_time: None,
                },
            );
        }
        Ok(())
    }

    /// Process an incoming SOURCE_SYMBOL frame.
    pub(crate) fn process_source_symbol_frame(
        &mut self, source_symbol: networkcoding::SourceSymbol,
        hdr: &packet::Header, recv_path_id: usize, recv_network_path_id: usize, epoch: packet::Epoch,
        now: time::Instant,
    ) -> Result<()> {
        if let Some(fec_decoder) = self.fec_decoder.as_mut() {
            let id = source_symbol_metadata_to_u64(source_symbol.metadata());
            if fec_decoder.fec_recv_window_size as u64 <= id {
                fec_decoder.fec_decoder.remove_up_to(
                    source_symbol_metadata_from_u64(
                        id.saturating_sub(
                            fec_decoder.fec_recv_window_size as u64,
                        ) + 1,
                    ),
                    None,
                );
            }

            // Before sending the source symbol to the FEC decoder, we must pad
            // the source symbol to match the correct symbol size. We do this here
            // and not directly in `frame::Frame::from_bytes` to avoid needing to
            // change too much the code.
            let symbol_size = fec_decoder.fec_decoder.symbol_size();
            let source_symbol_md = source_symbol.metadata();
            let mut source_symbol_data = source_symbol.take();
            if symbol_size < source_symbol_data.len() {
                // This should not happen.
                return Err(DecoderError::BufferTooSmall.into());
            } else if symbol_size > source_symbol_data.len() {
                let padding = symbol_size - source_symbol_data.len();
                let mut padded = vec![0u8; symbol_size];
                padded[padding..].copy_from_slice(&source_symbol_data[..]);
                source_symbol_data = padded;
            }

            let padded_source_symbol = networkcoding::SourceSymbol::new(
                source_symbol_md,
                source_symbol_data,
            );

            match fec_decoder
                .fec_decoder
                .receive_source_symbol(padded_source_symbol, now)
            {
                Err(DecoderError::UnusedSourceSymbol) =>
                    info!("Received a source symbol unused by the decoder. "),
                Err(err) => {
                    return Err(err.into());
                },
                Ok(decoded_symbols) =>
                    for decoded_symbol in decoded_symbols {
                        self.process_decoded_symbol(
                            decoded_symbol,
                            hdr,
                            recv_path_id,
                            recv_network_path_id,
                            epoch,
                            now,
                        )?;
                    },
            }
        }

        Ok(())
    }

    /// Process an incoming REPAIR frame.
    pub(crate) fn process_repair_frame(
        &mut self, repair_symbol: networkcoding::RepairSymbol,
        hdr: &packet::Header, recv_path_id: usize, recv_network_path_id: usize, epoch: packet::Epoch,
        now: time::Instant,
    ) -> Result<()> {
        if let Some(decoder) = self.fec_decoder.as_mut() {
            decoder.nb_recv_repair += 1;

            match decoder
                .fec_decoder
                .receive_and_deserialize_repair_symbol(repair_symbol)
            {
                Err(DecoderError::UnusedRepairSymbol) =>
                    debug!("Unused repair symbol"),
                Err(err) => {
                    return Err(err.into());
                },
                Ok((_, decoded_symbols)) => {
                    for decoded_symbol in decoded_symbols {
                        self.process_decoded_symbol(
                            decoded_symbol,
                            hdr,
                            recv_path_id,
                            recv_network_path_id,
                            epoch,
                            now,
                        )?;
                    }
                },
            }
        }
        Ok(())
    }
}

/// Recovered symbol, indicating the time it was recovered and the
/// time it was received from the network if it has been
#[derive(Clone)]
pub struct RecoveredSymbol {
    /// The Instant when it was recovered using FEC.
    pub recovered_time: std::time::Instant,

    /// The Instant when it was received from the network, or None
    /// if it was never received from the network.
    pub received_time: Option<std::time::Instant>,
}
