//! Forward Erasure Correction (FEC) module.
//!
//! Currently, does not consider if the other peer receives FEC to enable us to
//! send FEC.

use crate::flexicast::fec::FcFec;
use crate::frame;
use crate::packet;
use crate::path::NetworkPathId;
use crate::ranges;
use crate::Config;
use crate::Connection;
use crate::Error;
use crate::InternalPathId;
use crate::Result;
use networkcoding::SourceSymbol;
use std::time;

pub mod decoder;
pub mod encoder;
pub mod schedulers;

/// A FEC error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FecError {
    /// Error related to the FEC decoder.
    FecDecoderError(u64),

    /// Error related to the FEC encoder.
    FecEncoderError(u64),

    /// Error related to the FEC scheduler.
    FecScheduler,

    /// Error when generating the source symbol.
    SourceSymbolCreationError,

    /// The SOURCE_SYMBOL_HEADER frame does not preceeds protected data.
    SourceSymbolHeaderAfterData,
}

impl From<FecError> for Error {
    fn from(value: FecError) -> Self {
        Self::Fec(value)
    }
}

impl std::convert::From<networkcoding::DecoderError> for Error {
    fn from(_err: networkcoding::DecoderError) -> Self {
        Error::Fec(FecError::FecDecoderError(_err.to_u64()))
    }
}

impl std::convert::From<networkcoding::EncoderError> for Error {
    fn from(_err: networkcoding::EncoderError) -> Self {
        Error::Fec(FecError::FecEncoderError(_err.to_u64()))
    }
}

impl Connection {
    /// Process frames contained in FEC source symbols.
    pub(crate) fn process_frames_of_source_symbol(
        &mut self, decoded_symbol: SourceSymbol, now: time::Instant,
        epoch: packet::Epoch, hdr: &packet::Header, recv_path_id: usize,
        recv_network_path_id: usize,
    ) -> Result<()> {
        // TODO: ensure epoch and packet type are correct
        let data = decoded_symbol.take();
        let mut source_symbol_payload =
            octets::Octets::with_slice(data.as_slice());
        while source_symbol_payload.cap() > 0 {
            let frame = frame::Frame::from_bytes(
                &mut source_symbol_payload,
                packet::Type::Short,
            )?;
            // FIXME: we currently give the current active path to process_frame,
            // but the frame has been recovered through FEC.
            self.process_frame(
                frame,
                hdr,
                InternalPathId(recv_path_id),
                NetworkPathId(recv_network_path_id),
                epoch,
                now,
            )?;
            // TODO: log the decoded source symbol & announce its recovery to
            // the sender
        }
        Ok(())
    }

    /// Process an incoming SOURCE_SYMBOL_ACK frame.
    pub(crate) fn process_source_symbol_ack_frame(
        &mut self, ranges: ranges::RangeSet, epoch: packet::Epoch,
    ) {
        // If this host is a (flexicast) Unicast Path server, we keep the ranges
        // in state to avoid unicast retransmission because the unicast path does
        // not have any state for FEC encoder.
        if let Some(flexicast) = self.flexicast.as_mut() {
            if let FcFec::UcPath(fc_fec) = &mut flexicast.fc_fec {
                fc_fec.fc_on_new_source_symbol_ack(&ranges);
            }
            // Normally, the next code block should not be processed because FEC
            // encoding should be disabled on the Unicast Path if flexicast is
            // used.
        }

        // Do not process the frame if this host is not a FEC encoder.
        if self.fec_encoder.is_some() {
            for (_, p) in self.paths.iter_mut() {
                p.recovery.fec_on_source_symbol_ack_received(
                    &ranges,
                    epoch,
                    &self.trace_id,
                );
            }
        }
    }
}

impl Config {
    /// Set whether to use FEC to protect data sent toward the peer.
    /// The FEC scheduler must also be set to another value than
    /// [`fec::FecSchedulerAlgorithm::NoRedundancy`].
    pub fn set_send_fec(&mut self, v: bool) {
        self.local_transport_params.send_fec = v;
    }

    /// Set whether to receive FEC to protect data received from the peer.
    pub fn set_recv_fec(&mut self, v: bool) {
        self.local_transport_params.recv_fec = v;
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::Pipe;
    use crate::Config;

    #[test]
    /// Tests the transport parameters to enable Forward Erasure Correction.
    fn test_fec_tp() {
        for send_fec in [true, false] {
            for recv_fec in [true, false] {
                let mut config = Config::new(crate::PROTOCOL_VERSION).unwrap();
                config
                    .load_cert_chain_from_pem_file("examples/cert.crt")
                    .unwrap();
                config
                    .load_priv_key_from_pem_file("examples/cert.key")
                    .unwrap();
                config
                    .set_application_protos(&[b"proto1", b"proto2"])
                    .unwrap();
                config.verify_peer(false);
                config.set_active_connection_id_limit(3);
                config.set_initial_max_data(100000);
                config.set_initial_max_stream_data_bidi_local(100000);
                config.set_initial_max_stream_data_bidi_remote(100000);
                config.set_initial_max_streams_bidi(2);
                // To test with enabled datagrams.
                config.enable_dgram(true, 10, 10);
                config.set_send_fec(send_fec);
                config.set_recv_fec(recv_fec);

                let mut pipe = Pipe::with_config(&mut config).unwrap();
                pipe.advance().unwrap();

                assert_eq!(
                    pipe.client.fec_encoder.is_some(),
                    send_fec && recv_fec
                );
                assert_eq!(
                    pipe.server.fec_encoder.is_some(),
                    send_fec && recv_fec
                );

                assert_eq!(
                    pipe.client.fec_decoder.is_some(),
                    send_fec && recv_fec
                );
                assert_eq!(
                    pipe.server.fec_decoder.is_some(),
                    send_fec && recv_fec
                );
            }
        }
    }
}
