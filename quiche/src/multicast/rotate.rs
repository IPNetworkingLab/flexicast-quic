//! Flexicast extension to allow for stream rotation loops.

use crate::stream;
use crate::stream::flexicast::FcStreamState;
use crate::Connection;
use crate::Error;
use crate::Result;

use super::McClientStatus;
use super::McError;
use super::McRole;
use super::MulticastAttributes;

/// Flexicast stream rotation enum.
pub enum FcRotate {
    /// Flexicast source.
    Src(bool),

    /// Server instance.
    Server(FcRotateServer),
}

/// Flexicast structure for stream rotation for the unicast server instances.
pub struct FcRotateServer {
    /// Stream states of the flexicast source that will be forwarded to the
    /// client.
    stream_states: Vec<FcStreamState>,

    /// Whether the server already gave information about the stream state.
    /// Note that this could be correlated with the fact that the server already
    /// gave the MC_KEY.
    already_drained: bool,
}

impl FcRotateServer {
    /// Creates the structure based on the stream states of the flexicast
    /// source.
    pub fn new(stream_states: Vec<FcStreamState>) -> Self {
        Self {
            stream_states,
            already_drained: false,
        }
    }

    #[inline]
    /// Give the stream state. This will drain the current vector.
    pub fn drain_stream_states(&mut self) -> Vec<FcStreamState> {
        self.already_drained = true;
        self.stream_states.drain(..).collect()
    }

    #[inline]
    /// Whether the stream state was already drained.
    pub fn already_drained(&self) -> bool {
        self.already_drained
    }
}

impl MulticastAttributes {
    /// Activate the stream rotation extension at the source.
    ///
    /// Additionally, sets whether the source must transmit its stream state.
    pub fn fc_enable_stream_rotation(
        &mut self, send_stream_state: bool,
    ) -> Result<()> {
        if matches!(
            self.mc_role,
            McRole::ServerMulticast | McRole::Client(McClientStatus::Unspecified)
        ) {
            self.fc_rotate = Some(FcRotate::Src(send_stream_state));
            Ok(())
        } else {
            Err(Error::Multicast(McError::McInvalidRole(
                McRole::ServerMulticast,
            )))
        }
    }

    #[inline]
    /// Whether the connection uses Flexicast with stream rotation extension.
    pub fn fc_use_stream_rotation(&self) -> bool {
        self.fc_rotate.is_some()
    }

    #[inline]
    /// Whether the source must transmit the stream states to the client.
    pub fn fc_send_stream_states(&self) -> bool {
        matches!(self.fc_rotate, Some(FcRotate::Src(true)))
    }

    #[inline]
    /// Returns the flexicast source stream states that is stored in the unicast
    /// server instance.
    ///
    /// Returns an error if an invalid role.
    pub fn fc_drain_svr_stream_states(&mut self) -> Result<Vec<FcStreamState>> {
        Ok(self
            .fc_rotate_server_mut()
            .ok_or(Error::Multicast(McError::FcStreamRotation))?
            .drain_stream_states())
    }

    #[doc(hidden)]
    pub fn fc_rotate_src(&self) -> Option<bool> {
        if let Some(FcRotate::Src(s)) = self.fc_rotate {
            return Some(s);
        }
        None
    }

    #[doc(hidden)]
    pub fn fc_rotate_server(&self) -> Option<&FcRotateServer> {
        if let Some(FcRotate::Server(s)) = self.fc_rotate.as_ref() {
            return Some(s);
        }
        None
    }

    #[doc(hidden)]
    pub fn fc_rotate_server_mut(&mut self) -> Option<&mut FcRotateServer> {
        if let Some(FcRotate::Server(s)) = self.fc_rotate.as_mut() {
            return Some(s);
        }
        None
    }
}

impl Connection {
    /// Creates streams and resets to the correct offset at the client.
    ///
    /// Flexicast stream rotation extension.
    pub(crate) fn fc_set_stream_states(
        &mut self, stream_states: &[FcStreamState],
    ) -> Result<()> {
        if self.is_server {
            return Err(Error::Multicast(McError::McInvalidRole(
                McRole::Client(McClientStatus::ListenMcPath(true)),
            )));
        }
        // If the MC_ANNOUNCE data indicates that the client should reset its
        // stream state when joining the channel, reset all. Otherwise,
        // set the stream state according to the information given in the MC_KEY.
        if self.multicast.as_ref().is_some_and(|mc| {
            mc.fc_chan_id.as_ref().is_some_and(|(_, idx)| {
                mc.mc_announce_data
                    .get(*idx)
                    .is_some_and(|mc_announce| mc_announce.reset_stream_on_join)
            })
        }) {
            let max_streams_bidi = self.streams.max_streams_bidi();
            let max_streams_uni = self.streams.max_streams_uni_next();
            let max_stream_window = crate::stream::MAX_STREAM_WINDOW;
            self.streams = crate::stream::StreamMap::new(max_streams_bidi, max_streams_uni, max_stream_window);
        } else {
            // The endpoint should not have any state for the streams in
            // `stream_states`.
            for stream_state in stream_states.iter() {
                let stream = self.streams.get_or_create(
                    stream_state.stream_id(),
                    &self.local_transport_params,
                    &self.peer_transport_params,
                    false,
                    self.is_server,
                )?;

                stream.recv.fc_set_offset_at(stream_state.offset() as u64)?;
            }
        }

        Ok(())
    }

    /// Marks a stream as rotable (or not). This means that the stream will not
    /// be collected anymore on the flexicast source. It will only be the
    /// case for the flexicast source, if the flexicast extension is
    /// enabled.
    ///
    /// Flexicast stream rotation extension.
    pub fn fc_mark_rotate_stream(
        &mut self, stream_id: u64, rotate: bool,
    ) -> Result<()> {
        if self
            .multicast
            .as_ref()
            .is_some_and(|mc| mc.fc_rotate_src().is_some())
        {
            // Get the stream.
            if let Some(stream) = self.streams.get_mut(stream_id) {
                stream.fc_mark_rotate(rotate);
                return Ok(());
            }
            return Err(Error::InvalidStreamState(stream_id));
        }
        Err(Error::Multicast(McError::FcStreamRotation))
    }

    /// Restart the sending state of a stream.
    ///
    /// Flexicast stream rotation extension.
    pub fn fc_restart_stream_send_recv(&mut self, stream_id: u64) -> Result<()> {
        if self
            .multicast
            .as_ref()
            .is_some_and(|mc| mc.fc_rotate_src().is_some())
        {
            if let Some(stream) = self.streams.get_mut(stream_id) {
                stream.fc_restart_stream_send_recv();
                return Ok(());
            }
            return Err(Error::InvalidStreamState(stream_id));
        }
        Err(Error::Multicast(McError::FcStreamRotation))
    }

    /// Reads contiguous data from a stream into the provided slice, starting at
    /// a given `offset`.
    ///
    /// This function internally calls [`crate::Connection::stream_recv`] and
    /// enables to read a stream at an offset potentially higher than 0.
    pub fn stream_recv_ooo(
        &mut self, stream_id: u64, out: &mut [u8],
    ) -> Result<(usize, bool, u64)> {
        if !stream::is_bidi(stream_id) &&
            stream::is_local(stream_id, self.is_server)
        {
            return Err(Error::InvalidStreamState(stream_id));
        }

        let stream = self
            .streams
            .get_mut(stream_id)
            .ok_or(Error::InvalidStreamState(stream_id))?;

        // Enable to read the stream out of order.
        stream.recv.fc_enable_out_of_order_read(true)?;
        let init_off = stream.recv.fc_init_offset()?;

        // Store the results for later...
        let out = self.stream_recv(stream_id, out);

        // ... because we must ensure that the stream is not readable anymore out
        // of order. Maybe the stream is collected, so it can be `None`.
        if let Some(stream) = self.streams.get_mut(stream_id) {
            stream.recv.fc_enable_out_of_order_read(false)?;
        }

        out.map(|res| (res.0, res.1, init_off))
    }

    /// Returns the current emit offset of the specified stream, if it exists.
    ///
    /// Flexicast with stream rotation extension.
    pub fn fc_get_stream_emit_off(&self, stream_id: u64) -> Option<u64> {
        self.streams
            .get(stream_id)
            .map(|stream| stream.send.fc_emit_off())
    }

    /// Sets the reception offset of the specified stream, if it exists.
    pub fn fc_set_stream_offset(
        &mut self, stream_id: u64, off: u64,
    ) -> Result<()> {
        self.streams
            .get_mut(stream_id)
            .map(|stream| stream.recv.fc_set_offset_at(off))
            .ok_or(Error::InvalidStreamState(stream_id))?
    }

    /// Returns the maximum offset buffered in the specified stream.
    ///
    /// Flexicast with stream rotation extension.
    pub(crate) fn fc_get_stream_off_back(&self, stream_id: u64) -> Option<u64> {
        self.streams.get(stream_id).map(|s| s.send.off_back())
    }

    /// Activate the stream rotation extension at the source.
    ///
    /// Additionally, sets whether the source must transmit its stream state.
    pub fn fc_enable_stream_rotation(
        &mut self, send_stream_state: bool,
    ) -> Result<()> {
        if let Some(fc) = self.multicast.as_mut() {
            fc.fc_enable_stream_rotation(send_stream_state)
        } else {
            Err(Error::Multicast(McError::McDisabled))
        }
    }

    /// Whether the sending stream is expired on the flexicast path.
    ///
    /// Flexicast extension.
    pub fn fc_is_stream_expired(&self, stream_id: u64) -> Result<bool> {
        if self.multicast.is_none() {
            return Err(Error::Multicast(McError::McDisabled));
        }

        self.streams
            .get(stream_id)
            .ok_or(Error::InvalidStreamState(stream_id))
            .map(|s| s.send.fc_is_stream_expired())
    }
}

#[cfg(test)]
mod tests {
    use crate::multicast::authentication::McAuthType;
    use crate::multicast::testing::MulticastPipe;
    use crate::multicast::FcConfig;
    use crate::multicast::McClientTp;
    use crate::multicast::MulticastConnection;
    use crate::ranges::RangeSet;
    use ring::rand::SystemRandom;
    use std::time;

    use super::*;

    #[test]
    fn test_fc_rotate_stream() {
        let mut buf = [0u8; 50];

        let mut fc_config = FcConfig {
            authentication: McAuthType::None,
            use_fec: true,
            probe_mc_path: true,
            fec_window_size: 5,
            max_data: 100000000,
            ..Default::default()
        };
        let mut mc_pipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_fc_rotate_stream",
            &mut fc_config,
        )
        .unwrap();

        assert!(mc_pipe
            .mc_channel
            .channel
            .multicast
            .as_mut()
            .unwrap()
            .fc_enable_stream_rotation(true)
            .is_ok());

        let stream_data = [42u8; 30];
        mc_pipe
            .mc_channel
            .channel
            .stream_send(3, &stream_data[..], true)
            .unwrap();

        // Mark the stream as rotable.
        mc_pipe
            .mc_channel
            .channel
            .fc_mark_rotate_stream(3, true)
            .unwrap();

        // Send some of the data to the client.
        mc_pipe
            .source_send_single_from_buf(None, &mut buf[..])
            .unwrap();
        mc_pipe
            .source_send_single_from_buf(None, &mut buf[..])
            .unwrap();

        // Timeout of the first part of the data.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let now = time::Instant::now();
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 10000))
            .unwrap();

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(3), None).into()));

        // Add a second client.
        let mc_client_tp = Some(McClientTp::default());
        let random = SystemRandom::new();

        let mut client_loss = RangeSet::default();
        client_loss.insert(1..2);

        let fc_config = FcConfig {
            mc_announce_data: vec![mc_pipe.mc_announce_data.clone()],
            probe_mc_path: true,
            authentication: McAuthType::None,
            mc_client_tp,
            fec_window_size: 1,
            ..FcConfig::default()
        };

        let new_client = MulticastPipe::setup_client(
            &mut mc_pipe.mc_channel,
            &fc_config,
            &random,
        )
        .unwrap();
        mc_pipe.unicast_pipes.push(new_client);

        // Send the remaining of the stream to both clients.
        // The second client loses the packet containing the last frame of the
        // stream.
        mc_pipe
            .source_send_single_from_buf(Some(&client_loss), &mut buf[..])
            .unwrap();
        // No more data to send.
        assert_eq!(
            mc_pipe.source_send_single_from_buf(None, &mut buf[..]),
            Err(Error::Done)
        );

        // Timeout of the first part of the data.
        let expired = expired
            .checked_add(time::Duration::from_millis(expiration_timer + 10000))
            .unwrap();

        // ACK from clients.
        assert_eq!(mc_pipe.client_rmc_timeout(expired, &random), Ok(()));
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        mc_pipe.server_control_to_mc_source(expired).unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        // The unicast server sends the retransmissions.
        assert_eq!(
            mc_pipe
                .unicast_pipes
                .iter_mut()
                .map(|(pipe, ..)| pipe.advance())
                .collect::<Result<()>>(),
            Ok(())
        );

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(4), None).into()));

        // Restart the stream for the second client.
        assert!(mc_pipe
            .mc_channel
            .channel
            .fc_restart_stream_send_recv(3)
            .is_ok());

        // Have to send again the data to quiche...
        mc_pipe
            .mc_channel
            .channel
            .stream_send(3, &stream_data[..], true)
            .unwrap();

        // Send the content of the stream.
        // The second client sees a packet loss that will be retransmitted through
        // unicast.
        mc_pipe
            .source_send_single_from_buf(None, &mut buf[..])
            .unwrap();
        mc_pipe
            .source_send_single_from_buf(Some(&client_loss), &mut buf[..])
            .unwrap();
        mc_pipe
            .source_send_single_from_buf(None, &mut buf[..])
            .unwrap();
        assert_eq!(
            mc_pipe.source_send_single_from_buf(None, &mut buf[..]),
            Err(Error::Done)
        );

        // The first client receives the entire stream in the correct order.
        let mut recv_buf = [99; 100];
        let client = &mut mc_pipe.unicast_pipes[0].0.client;

        // The first client can read the stream because it was created after it
        // joined the flexicast channel.
        let (len, fin) = client.stream_recv(3, &mut recv_buf).unwrap();
        assert!(fin);
        assert_eq!(len, stream_data.len());
        assert_eq!(&recv_buf[..len], &stream_data);

        // The second client receives the stream in two pieces but the entire data
        // is there.
        let client = &mut mc_pipe.unicast_pipes[1].0.client;
        // Cannot use `stream_recv` when the stream uses rotation.
        assert_eq!(
            client.stream_recv(3, &mut recv_buf),
            Err(Error::Multicast(McError::FcStreamOutOfOrder))
        );
        let (len, fin, off) = client.stream_recv_ooo(3, &mut recv_buf).unwrap();
        assert!(!fin);
        assert_eq!(len, 8);
        assert_eq!(off, 22);
        assert_eq!(&recv_buf[..len], &stream_data[..len]);

        // The stream is not finished because of the loss.
        let (len_2, fin, off) = client.stream_recv_ooo(3, &mut recv_buf).unwrap();
        assert!(!fin);
        assert_eq!(len_2, 11);
        assert_eq!(off, 22);
        assert_eq!(&recv_buf[..11], &stream_data[len..len + 11]);

        // ACK from clients.
        assert_eq!(mc_pipe.client_rmc_timeout(expired, &random), Ok(()));
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // Unicast retransmission because of the (R)MC timeout.
        let expired = expired
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();

        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert!(res.is_ok());

        // The unicast server sends the retransmissions.
        assert_eq!(
            mc_pipe
                .unicast_pipes
                .iter_mut()
                .map(|(pipe, ..)| pipe.advance())
                .collect::<Result<()>>(),
            Ok(())
        );

        // The second client can now read everything.
        let client = &mut mc_pipe.unicast_pipes[1].0.client;
        let (len_2, fin, off) =
            client.stream_recv_ooo(3, &mut recv_buf[..]).unwrap();
        assert!(fin);
        assert_eq!(len_2, 11);
        assert_eq!(off, 22);
        assert_eq!(&recv_buf[..len_2], &stream_data[11..22]);
    }
}
