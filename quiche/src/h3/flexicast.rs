//! Flexicast extension for HTTP/3.
//! It enables stream rotation.

use crate::h3::frame;
use crate::h3::grease_value;
use crate::h3::testing::Session;
use crate::h3::Config;
use crate::h3::Connection;
use crate::h3::Error;
use crate::h3::Event;
use crate::h3::Header;
use crate::h3::Result;
use crate::multicast::testing::MulticastPipe;
use crate::multicast::McAnnounceData;
use crate::multicast::McError;
use crate::multicast::MulticastChannelSource;

#[cfg(feature = "qlog")]
use qlog::events::h3::H3FrameCreated;
#[cfg(feature = "qlog")]
use qlog::events::h3::H3FrameParsed;
#[cfg(feature = "qlog")]
use qlog::events::h3::H3Owner;
#[cfg(feature = "qlog")]
use qlog::events::h3::H3PriorityTargetStreamType;
#[cfg(feature = "qlog")]
use qlog::events::h3::H3StreamType;
#[cfg(feature = "qlog")]
use qlog::events::h3::H3StreamTypeSet;
#[cfg(feature = "qlog")]
use qlog::events::h3::Http3EventType;
#[cfg(feature = "qlog")]
use qlog::events::h3::Http3Frame;
#[cfg(feature = "qlog")]
use qlog::events::EventData;
#[cfg(feature = "qlog")]
use qlog::events::EventImportance;
#[cfg(feature = "qlog")]
use qlog::events::EventType;
#[cfg(feature = "qlog")]
const QLOG_FRAME_CREATED: EventType =
    EventType::Http3EventType(Http3EventType::FrameCreated);

use super::stream;
use super::NameValue;
use super::Priority;
use super::PRIORITY_URGENCY_LOWER_BOUND;
use super::PRIORITY_URGENCY_OFFSET;
use super::PRIORITY_URGENCY_UPPER_BOUND;

impl Connection {
    /// Reads request or response body data into the provided buffer,
    /// out-of-order.
    ///
    /// Applications should call this method whenever the [`poll()`] method
    /// returns a [`Data`] event.
    ///
    /// On success the amount of bytes read is returned, or [`Done`] if there is
    /// no data to read, as well as the starting offset of the response.
    ///
    /// The body of the function is quite similar to
    /// [`crate::h3::Connection::recv_body`], but we return the starting offset
    /// as well.
    ///
    /// [`poll()`]: struct.Connection.html#method.poll
    /// [`Data`]: enum.Event.html#variant.Data
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn recv_body_ooo(
        &mut self, conn: &mut crate::Connection, stream_id: u64, out: &mut [u8],
    ) -> Result<(usize, u64)> {
        let mut total = 0;
        let mut off = None;

        // Try to consume all buffered data for the stream, even across multicast
        // DATA frames.
        while total < out.len() {
            let stream = self.streams.get_mut(&stream_id).ok_or(Error::Done)?;

            if stream.state() != stream::State::Data {
                break;
            }

            let (read, fin, cur_off) =
                match stream.try_consume_data_ooo(conn, &mut out[total..]) {
                    Ok(v) => v,

                    Err(Error::Done) => break,

                    Err(e) => return Err(e),
                };

            // The returned offset must be the same.
            off.map(|o| assert_eq!(o, cur_off));
            off = Some(cur_off);

            total += read;

            // No more data to read, we are done.
            if read == 0 || fin {
                break;
            }

            // Process incoming data from the stream. For example, if a whole
            // DATA frame was consumed, and another one is queud behind it, this
            // will ensure the additional data will also be returned to the
            // application.
            match self.process_readable_stream(conn, stream_id, false) {
                Ok(_) => unreachable!(),

                Err(Error::Done) => (),

                Err(e) => return Err(e),
            };

            if conn.stream_finished(stream_id) {
                break;
            }
        }

        // While body is being received, the stream is marked as finished only
        // when all data is read by the application.
        if conn.stream_finished(stream_id) {
            self.process_finished_stream(stream_id);
        }

        if total == 0 {
            return Err(Error::Done);
        }

        Ok((total, off.unwrap_or(0)))
    }

    /// Resets the state of the stream pointed out by `stream_id`, as if it
    /// never existed.
    ///
    /// Flexicast with stream rotation extension.
    pub fn fc_reset_stream(
        &mut self, conn: &mut crate::Connection, stream_id: u64,
    ) -> Result<()> {
        // Only authorize to reset the last stream...
        self.next_request_stream_id = stream_id;

        // Remove the stream.
        _ = self.streams.remove_entry(&stream_id);

        // Reset the grease for the stream... This will be a problem if some
        // clients don't use it and others do.
        self.frames_greased = false;

        // Restart the quic stream.
        conn.fc_restart_stream_send_recv(stream_id)?;

        Ok(())
    }

    /// Returns the HTTP/3 and QUIC offset of the stream.
    ///
    /// Flexicast with stream rotation extension.
    pub fn fc_get_emit_off(&self, stream_id: u64) -> Option<(u64, u64)> {
        self.streams.get(&stream_id).map(|s| s.fc_get_emit_off())
    }

    /// Sends an HTTP/3 body chunk on the given stream.
    ///
    /// On success the number of bytes written is returned, or [`Done`] if no
    /// bytes could be written (e.g. because the stream is blocked).
    ///
    /// Note that the number of written bytes returned can be lower than the
    /// length of the input buffer when the underlying QUIC stream doesn't have
    /// enough capacity for the operation to complete.
    ///
    /// When a partial write happens (including when [`Done`] is returned) the
    /// application should retry the operation once the stream is reported as
    /// writable again.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn send_body_quic_stream_writer<T>(
        &mut self, conn: &mut crate::Connection, stream_id: u64, body: &[u8],
        fin: bool, quic_writer: &mut T
    ) -> Result<usize> where T: QuicStreamWriter {
        let mut d = [42; 10];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        // Validate that it is sane to send data on the stream.
        if stream_id % 4 != 0 {
            return Err(Error::FrameUnexpected);
        }

        match self.streams.get(&stream_id) {
            Some(s) =>
                if !s.local_initialized() {
                    return Err(Error::FrameUnexpected);
                },

            None => {
                return Err(Error::FrameUnexpected);
            },
        };

        // Avoid sending 0-length DATA frames when the fin flag is false.
        if body.is_empty() && !fin {
            return Err(Error::Done);
        }

        let overhead = octets::varint_len(frame::DATA_FRAME_TYPE_ID) +
            octets::varint_len(body.len() as u64);

        let stream_cap = match conn.stream_capacity(stream_id) {
            Ok(v) => v,

            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.streams.remove(&stream_id);
                }

                return Err(e.into());
            },
        };

        // Make sure there is enough capacity to send the DATA frame header.
        if stream_cap < overhead {
            let _ = conn.stream_writable(stream_id, overhead + 1);
            return Err(Error::Done);
        }

        // Cap the frame payload length to the stream's capacity.
        let body_len = std::cmp::min(body.len(), stream_cap - overhead);

        // If we can't send the entire body, set the fin flag to false so the
        // application can try again later.
        let fin = if body_len != body.len() { false } else { fin };

        // Again, avoid sending 0-length DATA frames when the fin flag is false.
        if body_len == 0 && !fin {
            let _ = conn.stream_writable(stream_id, overhead + 1);
            return Err(Error::Done);
        }

        b.put_varint(frame::DATA_FRAME_TYPE_ID)?;
        b.put_varint(body_len as u64)?;
        let off = b.off();
        conn.stream_send(stream_id, &d[..off], false)?;
        quic_writer.write_quic_stream(&d[..off], 0)?;

        // Return how many bytes were written, excluding the frame header.
        // Sending body separately avoids unnecessary copy.
        let written = conn.stream_send(stream_id, &body[..body_len], fin)?;
        quic_writer.write_quic_stream(&body[..body_len], body_len as u64)?;

        trace!(
            "{} tx frm DATA stream={} len={} fin={}",
            conn.trace_id(),
            stream_id,
            written,
            fin
        );

        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let frame = Http3Frame::Data { raw: None };
            let ev_data = EventData::H3FrameCreated(H3FrameCreated {
                stream_id,
                length: Some(written as u64),
                frame,
                raw: None,
            });

            q.add_event_data_now(ev_data).ok();
        });

        if written < body.len() {
            // Ensure the peer is notified that the connection or stream is
            // blocked when the stream's capacity is limited by flow control.
            //
            // We only need enough capacity to send a few bytes, to make sure
            // the stream doesn't hang due to congestion window not growing
            // enough.
            let _ = conn.stream_writable(stream_id, overhead + 1);
        }

        if fin && written == body.len() && conn.stream_finished(stream_id) {
            self.streams.remove(&stream_id);
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            // Get FC-QUIC highest offset for this stream, which is correlated
            // to the last HTTP/3 frame sent.
            let quic_off = conn.fc_get_stream_off_back(stream_id);
            // FC-TODO: what will happen if the stream is finished?
            if let Some(off) = quic_off {
                // Clients that join will only be concerned starting the next
                // HTTP/3 DATA frame.
                stream.fc_set_emit_off(written as u64, off);
                quic_writer.write_quic_h3_offsets(off);
            }
        }

        Ok(written)
    }

    /// Equivalent of the `quiche::h3::Connection::send_response` method with QUIC stream writer.
    pub fn send_response_quic_stream_writer<T: NameValue, S: QuicStreamWriter>(
        &mut self, conn: &mut crate::Connection, stream_id: u64, headers: &[T],
        fin: bool, quic_writer: &mut S,
    ) -> Result<()> {
        let priority = Default::default();

        self.send_response_with_priority_quic_stream_writer(
            conn, stream_id, headers, &priority, fin, quic_writer,
        )?;

        Ok(())
    }

    fn send_response_with_priority_quic_stream_writer<T: NameValue, S: QuicStreamWriter>(
        &mut self, conn: &mut crate::Connection, stream_id: u64, headers: &[T],
        priority: &Priority, fin: bool, quic_writer: &mut S,
    ) -> Result<()> {
        if !self.streams.contains_key(&stream_id) {
            return Err(Error::FrameUnexpected);
        }

        // Clamp and shift urgency into quiche-priority space
        let urgency = priority
            .urgency
            .clamp(PRIORITY_URGENCY_LOWER_BOUND, PRIORITY_URGENCY_UPPER_BOUND) +
            PRIORITY_URGENCY_OFFSET;

        conn.stream_priority(stream_id, urgency, priority.incremental)?;

        self.send_headers_quic_stream_writer(conn, stream_id, headers, fin, quic_writer)?;

        Ok(())
    }

    fn send_headers_quic_stream_writer<T: NameValue, S: QuicStreamWriter>(
        &mut self, conn: &mut crate::Connection, stream_id: u64, headers: &[T],
        fin: bool, quic_writer: &mut S,
    ) -> Result<()> {
        let mut d = [42; 10];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        if !self.frames_greased && conn.grease {
            self.send_grease_frames_quic_stream_writer(conn, stream_id, quic_writer)?;
            self.frames_greased = true;
        }

        let header_block = self.encode_header_block(headers)?;

        let overhead = octets::varint_len(frame::HEADERS_FRAME_TYPE_ID) +
            octets::varint_len(header_block.len() as u64);

        // Headers need to be sent atomically, so make sure the stream has
        // enough capacity.
        match conn.stream_writable(stream_id, overhead + header_block.len()) {
            Ok(true) => (),

            Ok(false) => return Err(Error::StreamBlocked),

            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.streams.remove(&stream_id);
                }

                return Err(e.into());
            },
        };

        b.put_varint(frame::HEADERS_FRAME_TYPE_ID)?;
        b.put_varint(header_block.len() as u64)?;
        let off = b.off();
        conn.stream_send(stream_id, &d[..off], false)?;
        quic_writer.write_quic_stream(&d[..off], 0)?;

        // Sending header block separately avoids unnecessary copy.
        conn.stream_send(stream_id, &header_block, fin)?;
        quic_writer.write_quic_stream(&header_block, 0)?;

        trace!(
            "{} tx frm HEADERS stream={} len={} fin={}",
            conn.trace_id(),
            stream_id,
            header_block.len(),
            fin
        );

        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let qlog_headers = headers
                .iter()
                .map(|h| qlog::events::h3::HttpHeader {
                    name: String::from_utf8_lossy(h.name()).into_owned(),
                    value: String::from_utf8_lossy(h.value()).into_owned(),
                })
                .collect();

            let frame = Http3Frame::Headers {
                headers: qlog_headers,
            };
            let ev_data = EventData::H3FrameCreated(H3FrameCreated {
                stream_id,
                length: Some(header_block.len() as u64),
                frame,
                raw: None,
            });

            q.add_event_data_now(ev_data).ok();
        });

        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.initialize_local();
        }

        if fin && conn.stream_finished(stream_id) {
            self.streams.remove(&stream_id);
        }

        Ok(())
    }

    /// Send GREASE frames on the provided stream ID.
    fn send_grease_frames_quic_stream_writer<T>(
        &mut self, conn: &mut crate::Connection, stream_id: u64, quic_writer: &mut T
    ) -> Result<()> where T: QuicStreamWriter {
        let mut d = [0; 8];

        let stream_cap = match conn.stream_capacity(stream_id) {
            Ok(v) => v,

            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.streams.remove(&stream_id);
                }

                return Err(e.into());
            },
        };

        let grease_frame1 = grease_value();
        let grease_frame2 = grease_value();
        let grease_payload = b"GREASE is the word";

        let overhead = octets::varint_len(grease_frame1) + // frame type
            1 + // payload len
            octets::varint_len(grease_frame2) + // frame type
            1 + // payload len
            grease_payload.len(); // payload

        // Don't send GREASE if there is not enough capacity for it. Greasing
        // will _not_ be attempted again later on.
        if stream_cap < overhead {
            return Ok(());
        }

        // Empty GREASE frame.
        let mut b = octets::OctetsMut::with_slice(&mut d);
        let b_ref = b.put_varint(grease_frame1)?;
        conn.stream_send(stream_id, b_ref, false)?;
        quic_writer.write_quic_stream(b_ref, 0)?;

        let mut b = octets::OctetsMut::with_slice(&mut d);
        let b_ref = b.put_varint(0)?;
        conn.stream_send(stream_id, b_ref, false)?;
        quic_writer.write_quic_stream(b_ref, 0)?;

        trace!(
            "{} tx frm GREASE stream={} len=0",
            conn.trace_id(),
            stream_id
        );

        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let frame = Http3Frame::Reserved { length: Some(0) };
            let ev_data = EventData::H3FrameCreated(H3FrameCreated {
                stream_id,
                length: Some(0),
                frame,
                raw: None,
            });

            q.add_event_data_now(ev_data).ok();
        });

        // GREASE frame with payload.
        let mut b = octets::OctetsMut::with_slice(&mut d);
        let b_ref = b.put_varint(grease_frame2)?;
        conn.stream_send(stream_id, b_ref, false)?;
        quic_writer.write_quic_stream(b_ref, 0)?;

        let mut b = octets::OctetsMut::with_slice(&mut d);
        let b_ref = b.put_varint(18)?;
        conn.stream_send(stream_id, b_ref, false)?;
        quic_writer.write_quic_stream(b_ref, 0)?;

        conn.stream_send(stream_id, grease_payload, false)?;
        quic_writer.write_quic_stream(grease_payload, 0)?;

        trace!(
            "{} tx frm GREASE stream={} len={}",
            conn.trace_id(),
            stream_id,
            grease_payload.len()
        );

        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let frame = Http3Frame::Reserved {
                length: Some(grease_payload.len() as u64),
            };
            let ev_data = EventData::H3FrameCreated(H3FrameCreated {
                stream_id,
                length: Some(grease_payload.len() as u64),
                frame,
                raw: None,
            });

            q.add_event_data_now(ev_data).ok();
        });

        Ok(())
    }
}

/// Writes the content of the QUIC stream into the external writer.
pub trait QuicStreamWriter {
    /// Write the content of the QUIC stream into its external log material.
    fn write_quic_stream(&mut self, data: &[u8], h3_off: u64) -> Result<usize>;

    /// Write the offsets of the QUIC-stream and HTTP/3-stream.
    fn write_quic_h3_offsets(&mut self, quic_off: u64);
}

impl Header {
    /// Replace the content of a header.
    ///
    /// Flexicast with stream rotation extension.
    pub fn fc_replace_hdr_value(&mut self, new_value: &[u8]) {
        self.1 = new_value.to_vec();
    }
}

#[doc(hidden)]
pub mod testing {
    use ring::rand::SystemRandom;

    use crate::multicast::FcConfig;
    use crate::ranges::RangeSet;

    use super::*;

    pub struct FcSessionTranslate {
        pub fc_pipe: MulticastPipe,
        pub sessions: Vec<(Connection, Connection)>,
        pub fc_h3_conn: Connection,
        pub fc_h3_dummy_conn: Connection,
    }

    /// Flexicast equivalent of an HTTP/3 testing session. It holds the server,
    /// the clients and the pipes that allow them to communicate.
    pub struct FcSession {
        /// Flexicast source channel.
        pub fc_pipe: MulticastChannelSource,

        /// Flexicast source HTTP/3 session.
        pub fc_h3_conn: Connection,

        /// Flexicast dummy client HTTP/3 session.
        pub fc_h3_dummy_conn: Connection,

        /// All unicast connections between the clients and the server.
        pub sessions: Vec<Session>,

        /// Multicast channel information (MC_ANNOUNCE data).
        pub mc_announce_data: McAnnounceData,
    }

    impl FcSession {
        /// Generates a new flexicast session with already defined
        /// configuration.
        pub fn new(
            nb_clients: usize, keylog_filename: &str, fc_config: &mut FcConfig,
        ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
            // First create the pipe with 0 client, then add the clients with the
            // HTTP/3 sessions.
            let mut fc_pipe =
                MulticastPipe::new_reliable(0, keylog_filename, fc_config)?;
            let h3_config = Config::new()?;
            let random = ring::rand::SystemRandom::new();
            let mut sessions = Vec::with_capacity(nb_clients);

            for _ in 0..nb_clients {
                let (pipe, ..) = MulticastPipe::setup_client(
                    &mut fc_pipe.mc_channel,
                    &fc_config,
                    &random,
                )
                .ok_or(crate::Error::Multicast(McError::McPipe))?;

                let client_dgram = pipe.client.dgram_enabled();
                let server_dgram = pipe.server.dgram_enabled();
                let session = Session {
                    pipe,
                    client: Connection::new(&h3_config, false, client_dgram)?,
                    server: Connection::new(&h3_config, true, server_dgram)?,
                };

                sessions.push(session);
            }

            Ok(Self {
                mc_announce_data: fc_pipe.mc_announce_data,
                fc_pipe: fc_pipe.mc_channel,
                fc_h3_conn: Connection::new(&h3_config, true, false)?,
                fc_h3_dummy_conn: Connection::new(&h3_config, false, false)?,
                sessions,
            })
            .into()
        }

        /// Advances the flexicast source pipe.
        pub fn fc_advance(&mut self) -> crate::Result<()> {
            MulticastChannelSource::advance(
                &mut self.fc_pipe.channel,
                &mut self.fc_pipe.client_backup,
            )
        }

        /// Handshake of the HTTP/3 sessions.
        pub fn handhakes(&mut self) -> Result<()> {
            for session in self.sessions.iter_mut() {
                session.handshake()?;
            }

            Ok(())
        }

        /// Sends a request from all clients with default headers.
        ///
        /// On success it returns the newly allocated streams and headers.
        pub fn send_requests(
            &mut self, fin: bool,
        ) -> Result<Vec<(u64, Vec<Header>)>> {
            self.sessions
                .iter_mut()
                .map(|session| session.send_request(fin))
                .collect::<Result<Vec<_>>>()
        }

        /// Do the HTTP/3 handshake on the flexicast source. Cannot use directly
        /// the `handshake` method from the `Session` structure because we do
        /// not own a pipe but the behaviour is identical.
        ///
        /// FC-TODO: not sure that doing the entire handshake is necessary for
        /// the flexicast source but we never know.
        pub fn fc_handshake(&mut self) -> Result<()> {
            // Pipe handshake already done.

            // Client streams.
            self.fc_h3_dummy_conn
                .send_settings(&mut self.fc_pipe.client_backup)?;
            self.fc_advance()?;

            self.fc_h3_dummy_conn
                .open_qpack_encoder_stream(&mut self.fc_pipe.client_backup)?;
            self.fc_advance()?;

            self.fc_h3_dummy_conn
                .open_qpack_decoder_stream(&mut self.fc_pipe.client_backup)?;
            self.fc_advance()?;

            if self.fc_pipe.client_backup.grease {
                self.fc_h3_dummy_conn
                    .open_grease_stream(&mut self.fc_pipe.client_backup)?;
            }

            self.fc_advance()?;

            // Server streams.
            self.fc_h3_conn.send_settings(&mut self.fc_pipe.channel)?;
            self.fc_advance()?;

            self.fc_h3_conn
                .open_qpack_encoder_stream(&mut self.fc_pipe.channel)?;
            self.fc_advance()?;

            self.fc_h3_conn
                .open_qpack_decoder_stream(&mut self.fc_pipe.channel)?;
            self.fc_advance()?;

            if self.fc_pipe.channel.grease {
                self.fc_h3_conn
                    .open_grease_stream(&mut self.fc_pipe.channel)?;
            }

            self.fc_advance()?;

            while self
                .fc_h3_dummy_conn
                .poll(&mut self.fc_pipe.client_backup)
                .is_ok()
            {
                // Do nothing.
            }

            while self.fc_h3_conn.poll(&mut self.fc_pipe.channel).is_ok() {
                // Do nothing.
            }

            Ok(())
        }

        /// Do a request from the dummy client to the flexicast source.
        pub fn fc_send_request(
            &mut self, fin: bool,
        ) -> Result<(u64, Vec<Header>)> {
            let req = vec![
                Header::new(b":method", b"GET"),
                Header::new(b":scheme", b"https"),
                Header::new(b":authority", b"quic.tech"),
                Header::new(b":path", b"/test"),
                Header::new(b"user-agent", b"quiche-test"),
            ];

            let stream = self.fc_h3_dummy_conn.send_request(
                &mut self.fc_pipe.client_backup,
                &req,
                fin,
            )?;

            self.fc_advance()?;

            Ok((stream, req))
        }

        /// Polls the flexicast source for events.
        pub fn poll_fc_source(&mut self) -> Result<(u64, Event)> {
            self.fc_h3_conn.poll(&mut self.fc_pipe.channel)
        }

        /// Sends a response from the flexicast source with default headers.
        ///
        /// On success it returns the headers.
        pub fn fc_send_response(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<Header>> {
            let resp = vec![
                Header::new(b":status", b"200"),
                Header::new(
                    b":stream-offset",
                    &format!("{:0>8}", 0).into_bytes(),
                ),
                Header::new(b"server", b"quiche-test"),
            ];

            self.fc_h3_conn.send_response(
                &mut self.fc_pipe.channel,
                stream,
                &resp,
                fin,
            )?;

            // FC-TODO: send to all clients.

            Ok(resp)
        }

        /// Sends some default payload from the flexicast source.
        ///
        /// On success it returns the payload.
        pub fn fc_send_body_source(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<u8>> {
            let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            self.fc_h3_conn.send_body(
                &mut self.fc_pipe.channel,
                stream,
                &bytes,
                fin,
            )?;

            // FC-TODO: send to all clients.

            Ok(bytes)
        }

        /// The flexicast source sends a single packet.
        ///
        /// This is a variant of
        /// [`crate::multicast::testing::MulticastPipe::source_send_single`]
        /// because we need to wrap the structures inside a
        /// [`crate::multicast::testing::MulticastPipe`].
        pub fn fc_source_send_single(
            self, client_loss: Option<&RangeSet>,
        ) -> Result<(Box<Self>, bool)> {
            let mut fc_session_translate: Box<FcSessionTranslate> =
                Box::new(self).into();
            let fin = match fc_session_translate
                .fc_pipe
                .source_send_single(client_loss)
            {
                Ok(_) => false,
                Err(crate::Error::Done) => true,
                Err(e) => return Err(crate::h3::Error::TransportError(e)),
            };

            Ok((fc_session_translate.into(), fin))
        }

        /// Adds a new client with an HTTP/3 session.
        ///
        /// Adds the client and the HTTP/3 session in the self structure.
        /// Do not perform the HTTP/3 handshake.
        pub fn setup_client_with_session(
            &mut self, fc_config: &FcConfig, random: &SystemRandom,
            h3_config: &Config,
        ) -> Result<()> {
            let (pipe, ..) =
                MulticastPipe::setup_client(&mut self.fc_pipe, fc_config, random)
                    .ok_or(crate::Error::Multicast(McError::McPipe))?;

            let client_dgram = pipe.client.dgram_enabled();
            let server_dgram = pipe.server.dgram_enabled();
            let session = Session {
                pipe,
                client: Connection::new(&h3_config, false, client_dgram)?,
                server: Connection::new(&h3_config, true, server_dgram)?,
            };

            self.sessions.push(session);

            Ok(())
        }
    }

    impl Session {
        /// Sends a response from the server with default headers and the
        /// `stream-offset` header.
        ///
        /// On success it returns the headers.
        pub fn send_responses_with_stream_offset(
            &mut self, stream: u64, fin: bool, offset: u64,
        ) -> Result<Vec<Header>> {
            let resp = vec![
                Header::new(b":status", b"200"),
                Header::new(
                    b":stream-offset",
                    &format!("{:0>8}", offset).into_bytes(),
                ),
                Header::new(b"server", b"quiche-test"),
            ];

            self.server.send_response(
                &mut self.pipe.server,
                stream,
                &resp,
                fin,
            )?;

            self.advance().ok();

            Ok(resp)
        }
    }

    impl From<Box<FcSession>> for Box<FcSessionTranslate> {
        fn from(value: Box<FcSession>) -> Self {
            let nb_clients = value.sessions.len();
            let mut pipes = Vec::with_capacity(nb_clients);
            let mut h3_conns = Vec::with_capacity(nb_clients);

            for session in value.sessions {
                h3_conns.push((session.client, session.server));
                pipes.push((
                    session.pipe,
                    "127.0.0.1:5678".parse().unwrap(),
                    crate::testing::Pipe::server_addr(),
                ));
            }

            let fc_pipe = MulticastPipe {
                unicast_pipes: pipes,
                mc_channel: value.fc_pipe,
                mc_announce_data: value.mc_announce_data,
            };

            Box::new(FcSessionTranslate {
                fc_pipe,
                sessions: h3_conns,
                fc_h3_conn: value.fc_h3_conn,
                fc_h3_dummy_conn: value.fc_h3_dummy_conn,
            })
        }
    }

    impl From<Box<FcSessionTranslate>> for Box<FcSession> {
        fn from(value: Box<FcSessionTranslate>) -> Self {
            let nb_clients = value.sessions.len();
            let mut sessions = Vec::with_capacity(nb_clients);

            let mut pipes = value.fc_pipe.unicast_pipes;
            let mut conns = value.sessions;
            for ((pipe, ..), (client, server)) in
                pipes.drain(..).zip(conns.drain(..))
            {
                let session = Session {
                    pipe,
                    client,
                    server,
                };
                sessions.push(session);
            }

            Box::new(FcSession {
                fc_pipe: value.fc_pipe.mc_channel,
                fc_h3_conn: value.fc_h3_conn,
                fc_h3_dummy_conn: value.fc_h3_dummy_conn,
                sessions,
                mc_announce_data: value.fc_pipe.mc_announce_data,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::multicast::authentication::McAuthType;
    use crate::multicast::FcConfig;

    use super::*;
    use crate::multicast::MulticastConnection;
    use ring::rand::SystemRandom;
    use std::time;
    use testing::*;

    #[test]
    /// Test a simple HTTP/3 request/response sent on the flexicast channel with
    /// data received in-order.
    fn fc_h3_simple() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_session =
            FcSession::new(2, "/tmp/fc_h3_simple.txt", &mut fc_config).unwrap();

        assert_eq!(fc_session.fc_handshake(), Ok(()));
        assert_eq!(fc_session.handhakes(), Ok(()));

        let (fc_stream, fc_req) = fc_session.fc_send_request(true).unwrap();
        assert_eq!(fc_stream, 0);
        let requests = fc_session.send_requests(true).unwrap();
        for (stream, ..) in requests.iter() {
            assert_eq!(*stream, 0);
        }

        let ev_headers = Event::Headers {
            list: fc_req,
            has_body: false,
        };

        assert_eq!(fc_session.poll_fc_source(), Ok((fc_stream, ev_headers)));
        assert_eq!(
            fc_session.poll_fc_source(),
            Ok((fc_stream, Event::Finished))
        );

        let resp = fc_session.fc_send_response(fc_stream, false).unwrap();
        let body = fc_session.fc_send_body_source(fc_stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            has_body: true,
        };

        // Send the data to all clients.
        let (fc_session, fin) = fc_session.fc_source_send_single(None).unwrap();
        assert!(!fin);
        let (mut fc_session, fin) =
            fc_session.fc_source_send_single(None).unwrap();
        assert!(fin);

        // The clients received the response through the flexicast path.
        let mut recv_buf = vec![0; body.len()];
        for s in fc_session.sessions.iter_mut() {
            assert_eq!(s.poll_client(), Ok((fc_stream, ev_headers.clone())));
            assert_eq!(s.poll_client(), Ok((fc_stream, Event::Data)));
            assert_eq!(
                s.recv_body_client(fc_stream, &mut recv_buf),
                Ok(body.len())
            );

            assert_eq!(s.poll_client(), Ok((fc_stream, Event::Finished)));
            assert_eq!(s.poll_client(), Err(crate::h3::Error::Done));
        }
    }

    #[test]
    /// Test a simple HTTP/3 request/response sent on the flexicast channel with
    /// data received in-order.
    fn fc_h3_out_of_order() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::StreamAsym,
            use_fec: true,
            probe_mc_path: true,
            fec_window_size: 5,
            ..FcConfig::default()
        };
        let mut fc_session =
            FcSession::new(1, "/tmp/fc_h3_out_of_order.txt", &mut fc_config)
                .unwrap();

        // Enable stream rotation but do not send the stream states because they
        // will be sent through HTTP/3.
        assert!(fc_session
            .fc_pipe
            .channel
            .multicast
            .as_mut()
            .unwrap()
            .fc_enable_stream_rotation(false)
            .is_ok());
        assert!(fc_session
            .fc_pipe
            .client_backup
            .multicast
            .as_mut()
            .unwrap()
            .fc_enable_stream_rotation(false)
            .is_ok());

        assert_eq!(fc_session.fc_handshake(), Ok(()));
        assert_eq!(fc_session.handhakes(), Ok(()));

        let (fc_stream, fc_req) = fc_session.fc_send_request(true).unwrap();
        assert_eq!(fc_stream, 0);
        let requests = fc_session.send_requests(true).unwrap();
        for (stream, ..) in requests.iter() {
            assert_eq!(*stream, 0);
        }

        fc_session
            .fc_pipe
            .channel
            .fc_mark_rotate_stream(fc_stream, true)
            .unwrap();
        fc_session
            .fc_pipe
            .client_backup
            .fc_mark_rotate_stream(fc_stream, true)
            .unwrap();

        let ev_headers = Event::Headers {
            list: fc_req,
            has_body: false,
        };

        assert_eq!(fc_session.poll_fc_source(), Ok((fc_stream, ev_headers)));
        assert_eq!(
            fc_session.poll_fc_source(),
            Ok((fc_stream, Event::Finished))
        );

        let resp = fc_session.fc_send_response(fc_stream, false).unwrap();
        let body = fc_session.fc_send_body_source(fc_stream, false).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            has_body: true,
        };

        // Send the data to the first client.
        let (mut fc_session, mut fin) =
            fc_session.fc_source_send_single(None).unwrap();
        assert!(!fin);
        (fc_session, fin) = fc_session.fc_source_send_single(None).unwrap();
        assert!(fin);

        // The first client received the response through the flexicast path.
        let mut recv_buf = vec![0; 100];
        let s = &mut fc_session.sessions[0];
        assert_eq!(s.poll_client(), Ok((fc_stream, ev_headers.clone())));
        assert_eq!(s.poll_client(), Ok((fc_stream, Event::Data)));
        assert_eq!(s.recv_body_client(fc_stream, &mut recv_buf), Ok(body.len()));

        // Timeout of the first part of the data.
        let expiration_timer = fc_session.mc_announce_data.expiration_timer;
        let now = time::Instant::now();
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();

        let res = fc_session.fc_pipe.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(6), Some(4)).into()));

        // The multicast source sends an MC_EXPIRE to the client.
        let (mut fc_session, _) = fc_session.fc_source_send_single(None).unwrap();

        // The second client joins the flexicast channel.
        let fc_config = FcConfig {
            mc_announce_data: vec![fc_session.mc_announce_data.clone()],
            authentication: McAuthType::AsymSign,
            probe_mc_path: true,
            fec_window_size: 5,
            ..FcConfig::default()
        };
        let random = SystemRandom::new();
        let h3_config = Config::new().unwrap();
        assert_eq!(
            fc_session.setup_client_with_session(&fc_config, &random, &h3_config),
            Ok(())
        );

        // Get the new client to do the handshake and the HTTP/3 request.
        let s = fc_session.sessions.last_mut().unwrap();
        s.handshake().unwrap();
        let (l_stream, l_req) = s.send_request(true).unwrap();
        assert_eq!(l_stream, 0);

        let ev_headers = Event::Headers {
            list: l_req,
            has_body: false,
        };

        assert_eq!(s.poll_server(), Ok((l_stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((l_stream, Event::Finished)));

        // The server sends the response with the HTTP/3 stream-offset header.
        // First ask to the source the stream and offset.
        let (h3_off, quic_off) =
            fc_session.fc_h3_conn.fc_get_emit_off(l_stream).unwrap();
        assert_eq!(h3_off, 10);
        assert_eq!(quic_off, 82);
        let l_resp = s
            .send_responses_with_stream_offset(l_stream, false, quic_off)
            .unwrap();

        let ev_headers = Event::Headers {
            list: l_resp,
            has_body: true,
        };

        assert_eq!(s.poll_client(), Ok((l_stream, ev_headers)));

        // Parse the HTTP/3 streamoffset header and send the information to
        // quiche. For now we do not parse it because we already have the
        // data.
        assert_eq!(
            s.pipe.client.fc_set_stream_offset(l_stream, quic_off),
            Ok(())
        );

        // Now the flexicast source sends the second part of the stream.
        let bytes = (11..20).collect::<Vec<u8>>();
        fc_session
            .fc_h3_conn
            .send_body(&mut fc_session.fc_pipe.channel, l_stream, &bytes, true)
            .unwrap();
        let (mut fc_session, _fin) =
            fc_session.fc_source_send_single(None).unwrap();
        assert!(fin);

        // The first client received the whole HTTP/3 response.
        let s = &mut fc_session.sessions[0];
        assert_eq!(s.poll_client(), Ok((fc_stream, Event::Data)));
        assert_eq!(
            s.recv_body_client(fc_stream, &mut recv_buf),
            Ok(bytes.len())
        );
        assert_eq!(&recv_buf[..bytes.len()], &bytes);

        // The second client only received the second part.
        let s = &mut fc_session.sessions[1];
        assert_eq!(s.poll_client(), Ok((fc_stream, Event::Data)));
        assert_eq!(
            s.client
                .recv_body_ooo(&mut s.pipe.client, fc_stream, &mut recv_buf),
            Ok((bytes.len(), 82))
        );
        assert_eq!(&recv_buf[..bytes.len()], &bytes);

        let expired = expired
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        let res = fc_session.fc_pipe.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(8), Some(5)).into()));

        // The multicast source sends an MC_EXPIRE to the client.
        let (mut fc_session, _) = fc_session.fc_source_send_single(None).unwrap();

        // The source restarts the transmission. Do the same for HTTP/3.
        assert_eq!(
            fc_session
                .fc_h3_conn
                .fc_reset_stream(&mut fc_session.fc_pipe.channel, l_stream),
            Ok(())
        );
        // Same for the dummy connection.
        assert_eq!(
            fc_session
                .fc_h3_dummy_conn
                .fc_reset_stream(&mut fc_session.fc_pipe.client_backup, l_stream),
            Ok(())
        );

        // Send again the data on the stream... We repeat the same process as
        // before on the flexicast source.
        let (fc_stream, _fc_req) = fc_session.fc_send_request(true).unwrap();
        assert!(fc_session.poll_fc_source().is_ok());
        assert_eq!(
            fc_session.poll_fc_source(),
            Ok((fc_stream, Event::Finished))
        );
        let _resp = fc_session.fc_send_response(fc_stream, false).unwrap();
        let body = fc_session.fc_send_body_source(fc_stream, false).unwrap();

        let (fc_session, fin) = fc_session.fc_source_send_single(None).unwrap();
        assert!(!fin);
        let (mut fc_session, fin) =
            fc_session.fc_source_send_single(None).unwrap();
        assert!(fin);

        // The first client does not have any new data to receive.
        let s = &mut fc_session.sessions[0];
        assert_eq!(s.poll_client(), Ok((fc_stream, Event::Finished)));

        // The second client reads the start of the body.
        let s = &mut fc_session.sessions[1];
        // Headers again..
        assert!(s.poll_client().is_ok());
        assert_eq!(s.poll_client(), Ok((fc_stream, Event::Data)));
        assert_eq!(
            s.client
                .recv_body_ooo(&mut s.pipe.client, fc_stream, &mut recv_buf),
            Ok((body.len(), 82))
        );
        assert_eq!(&recv_buf[..body.len()], &body);

        // No more data to read.
        assert_eq!(s.poll_client(), Ok((fc_stream, Event::Finished)));
    }
}
