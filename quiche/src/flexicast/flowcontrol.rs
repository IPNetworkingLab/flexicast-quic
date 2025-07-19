//! This module contains the management of the flow control for the flexicast
//! flow. The flow control depends on whether the NACK extension is used on the
//! flexicast flow.
//!
//! 1) "Vanilla" QUIC acknowledgment (aka, positive acknowledgment).
//! Each receiver must send MAX_DATA and MAX_STREAM_DATA frames on its unicast
//! path to increase the flow control limits of both the unicast path and the
//! flexicast flow. The overall flow control on the flexicast flow depends on
//! the minimum flow control among all receivers. The flexicast flow can
//! advertise a minimum flow control threshold (to ensure a minimum quality of
//! service to all receivers). Since the flexicast flow advertise to each
//! unicast path the packets sent on the flow, a unicast path can decide to
//! remove the receiver from the flexicast flow if it sees that sending the
//! packet would violate the flow control limits of the receivers. In that case,
//! the receiver continues receiving data on its unicast path.
//!
//! 2) Negative acknowledgment extension.
//! The flow control requirements are advertised by the source (i.e, bitrate *
//! fc_timer). A receiver can reject to join a flexicast flow if it sees that
//! joining it would violate its flow control limits. Upon NACK timeout, the
//! flow control limits are updated on the flexicast flow source. Similarly to
//! case 1), the unicast path can decide to remove a receiver if sending a
//! packet would violate the flow control limits.
//!
//! The main issue when using the "lowest" flow control limits as the flexicast
//! flow flow control limit is that we must make the difference between (1) a
//! bottleneck receiver that will (hopefully) soon update its flow control and
//! (2) a "dead" connection that will never update its flow control.
//! Because we keep the minimum, the second case might happen if a connection
//! closes before the end of the communication and the flexicast flow used this
//! value for the flexicast flow flow control limits. To avoid this, we keep a
//! "Flexicast flow flow control sequence number" that increases each time we
//! ask for the new values. This quantity ensures that we correctly update the
//! flow control limits on the flexicast flow each time we communicate between
//! the flexicast flow and the unicast path instances.

use std::cmp;
use std::collections::HashMap;
use std::mem;
use std::sync::Arc;

use crate::stream::is_bidi;
use crate::stream::is_local;
use crate::Connection;
use crate::Error;
use crate::Result;

use super::FcError;
use super::McRole;

#[derive(Debug, Default)]
/// Structure handling, on the unicast path, the flexicast flow flow control
/// updates that must be passed to the flexicast flow. For simplicity, I do not
/// add an enum even if this will add state on the receiver and the flexicast
/// flow for nothing.
pub(crate) struct FcFlowControl {
    /// The new MAX_DATA to forward to the flexicast flow flow control.
    max_data: Option<u64>,

    /// The new MAX_STREAM_DATA to forward to the flexicast flow flow control.
    max_stream_datas: HashMap<u64, u64>,
}

impl FcFlowControl {
    /// Insert the new MAX_DATA value.
    pub fn fc_set_max_data(&mut self, max_data: u64) {
        self.max_data = Some(max_data);
    }

    /// Insert the new MAX_STREAM_DATA value.
    pub fn fc_set_max_stream_data(&mut self, stream_id: u64, max_data: u64) {
        self.max_stream_datas.insert(stream_id, max_data);
    }

    /// Retrieves the updated flow control values that must be passed to the
    /// flexicast flow. Takes the elements from the inner structure.
    fn fc_get_flow_control_updates(
        &mut self,
    ) -> (Option<u64>, HashMap<u64, u64>) {
        (self.max_data.take(), mem::take(&mut self.max_stream_datas))
    }
}

/// Extends the [`crate::Connection`] methods to get and set the flow control
/// limits.
impl Connection {
    /// Returns the updates of the flow control that will be passed to the
    /// flexicast flow. Takes the elements from the inner structure.
    ///
    /// Returns an error if this is not the unicast path.
    /// Return [`Error::Done`] if there is no update.
    pub fn fc_get_flow_control_updates(
        &mut self,
    ) -> Result<(Option<u64>, HashMap<u64, u64>)> {
        let flexicast = fca_mut!(self)?;
        if !matches!(flexicast.mc_role, McRole::ServerUnicast(_)) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                flexicast.mc_role,
            )));
        }

        let out = flexicast.fc_flow_control.fc_get_flow_control_updates();
        if out.0.is_none() && out.1.is_empty() {
            return Err(Error::Done);
        }
        Ok(out)
    }

    /// Returns the current flow control limit for the entire connection.
    ///
    /// This method is only available if flexicast is enabled and the caller is
    /// the unicast path server.
    pub fn fc_get_max_tx_data(&mut self) -> Result<u64> {
        let flexicast = fca_mut!(self)?;
        if !matches!(flexicast.mc_role, McRole::ServerUnicast(_)) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                flexicast.mc_role,
            )));
        }

        Ok(self.max_tx_data)
    }

    /// Returns the current flow control limits for the specified stream ID.
    ///
    /// This method is only available if flexicast is enabled and the caller is
    /// the unicast path server. If the stream does not exists, returns the
    /// initial flow control limit.
    pub fn fc_get_max_tx_stream_data(&self, stream_id: u64) -> Result<u64> {
        let flexicast = fca!(self)?;
        if !matches!(flexicast.mc_role, McRole::ServerUnicast(_)) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                flexicast.mc_role,
            )));
        }

        if let Some(stream) = self.streams.get(stream_id) {
            // Only advertise a new value.
            Ok(stream.send.max_off())
        } else {
            let local = is_local(stream_id, true);
            let bidi = is_bidi(stream_id);
            let max_tx = match (local, bidi) {
                (true, true) =>
                    self.peer_transport_params
                        .initial_max_stream_data_bidi_remote,
                (true, false) =>
                    self.peer_transport_params.initial_max_stream_data_uni,
                (false, true) =>
                    self.peer_transport_params
                        .initial_max_stream_data_bidi_local,
                (false, false) => 0,
            };

            Ok(max_tx)
        }
    }

    /// Returns the current flow control limits for all open sending streams.
    ///
    /// This method is only available if flexicast is enabled and the caller is
    /// the unicast path server. If the stream does not exists, returns the
    /// initial flow control limit.
    pub fn fc_get_max_tx_streams_data<'a>(
        &'a self,
    ) -> Result<impl Iterator<Item = (u64, u64)> + use<'a>> {
        let flexicast = fca!(self)?;
        if !matches!(flexicast.mc_role, McRole::ServerUnicast(_)) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                flexicast.mc_role,
            )));
        }

        Ok(self.streams.fc_get_stream_ids().map(move |&stream_id| {
            (
                stream_id,
                self.fc_get_max_tx_stream_data(stream_id).unwrap(),
            )
        }))
    }

    /// Sets the flow control limit for the entire connection.
    ///
    /// Takes the maximum of the two values if the provided sequence number is
    /// higher than the local one, otherwise takes the minimum. Updates the
    /// sequence number.
    ///
    /// This method is only available if flexicast is enabled and the caller is
    /// the flexicast flow source.
    pub fn fc_set_max_tx_data(&mut self, max_tx_data: u64) -> Result<()> {
        let flexicast = fca_mut!(self)?;
        if !matches!(flexicast.mc_role, McRole::ServerFlexicast) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                flexicast.mc_role,
            )));
        }

        self.max_tx_data = cmp::max(self.max_tx_data, max_tx_data);

        // Update the tx cap.
        self.update_tx_cap();

        Ok(())
    }

    /// Sets the flow control limit for the stream specified by `stream_id`.
    ///
    /// Takes the maximum of the two values if the provided sequence number is
    /// higher than the local one, otherwise takes the minimum. Updates the
    /// sequence number.
    ///
    /// This method is only available if flexicast is enabled and the caller is
    /// the flexicast flow source.
    pub fn fc_set_max_tx_stream_data(
        &mut self, max_tx_stream_data: u64, stream_id: u64,
    ) -> Result<()> {
        let flexicast = fca_mut!(self)?;
        if !matches!(flexicast.mc_role, McRole::ServerFlexicast) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                flexicast.mc_role,
            )));
        }

        let stream = match self.get_or_create_stream(stream_id, false) {
            Ok(v) => v,

            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        let was_flushable = stream.is_flushable();

        stream.send.update_max_data(max_tx_stream_data);

        let writable = stream.is_writable();

        let priority_key = Arc::clone(&stream.priority_key);

        // If the stream is now flushable push it to the flushable queue,
        // but only if it wasn't already queued.
        if stream.is_flushable() && !was_flushable {
            let priority_key = Arc::clone(&stream.priority_key);
            self.streams.insert_flushable(&priority_key);
        }

        if writable {
            self.streams.insert_writable(&priority_key);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time;

    use crate::flexicast::testing::FlexicastPipe;
    use crate::flexicast::FcConfig;
    use crate::Error;

    #[test]
    /// Tests that the flow control of the flexicast flow correctly updates when
    /// the receivers send updates on their unicast path.
    fn test_fc_flow_control() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            max_data: 10,
            max_stream_data: 10,
            ..Default::default()
        };

        let mut fc_pipe =
            FlexicastPipe::new(2, "/tmp/test_fc_flow_control", &mut fc_config)
                .unwrap();

        // A stream of 20 bytes. Only the first 10 bytes will be sent.
        let stream = [42u8; 20];
        let written = fc_pipe
            .mc_channel
            .channel
            .stream_send(3, &stream, true)
            .unwrap();
        assert_eq!(written, 10);

        let now = time::Instant::now();
        fc_pipe.source_send_single(None).unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Sending a new packet is not possible.
        let err = fc_pipe
            .mc_channel
            .channel
            .stream_send(3, &stream[5..], true);
        assert_eq!(err, Err(Error::Done));

        // The receivers read the data, then send the acknowledgment to the
        // source.
        let mut buf = [0u8; 10];
        for (pipe, ..) in fc_pipe.unicast_pipes.iter_mut() {
            let read = pipe.client.stream_recv(3, &mut buf);
            assert_eq!(read, Ok((10, false)));
        }
        fc_pipe.clients_send().unwrap();

        // The unicast path forward the new flow control to the flexicast flow.
        let now = time::Instant::now();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // The flexicast flow source can now send the remaining of the stream.
        let ok = fc_pipe
            .mc_channel
            .channel
            .stream_send(3, &stream[10..], true);
        assert_eq!(ok, Ok(10));
        fc_pipe.source_send_single(None).unwrap();

        // The receivers now receive the end of the stream.
        for (pipe, ..) in fc_pipe.unicast_pipes.iter_mut() {
            let read = pipe.client.stream_recv(3, &mut buf);
            assert_eq!(read, Ok((10, true)));
        }
    }
}
