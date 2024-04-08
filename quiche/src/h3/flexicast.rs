use crate::h3::testing::Session;
use crate::h3::Config;
use crate::h3::Connection;
use crate::h3::Event;
use crate::h3::Header;
use crate::h3::Result;
use crate::multicast::authentication::McAuthType;
use crate::multicast::testing::MulticastPipe;
use crate::multicast::McAnnounceData;
use crate::multicast::McClientTp;
use crate::multicast::McError;
use crate::multicast::MulticastChannelSource;
use crate::Error;

#[doc(hidden)]
pub mod testing {
    use crate::ranges::RangeSet;

    use super::*;

    type FcSessionTranslate = (
        MulticastPipe,
        Vec<(Connection, Connection)>,
        Connection,
        Connection,
    );

    /// Flexicast equivalent of an HTTP/3 testing session. It holds the server,
    /// the clients and the pipes that allow them to communicate.
    pub struct FcSession {
        /// Flexicast source channel.
        pub fc_pipe: MulticastChannelSource,

        /// Flexicast source HTTP/3 session.
        pub fc_h3_conn: Connection,

        /// Flexicast dummy client HTTP/3 session.
        fc_h3_dummy_conn: Connection,

        /// All unicast connections between the clients and the server.
        pub sessions: Vec<Session>,

        /// Multicast channel information (MC_ANNOUNCE data).
        pub mc_announce_data: McAnnounceData,
    }

    impl FcSession {
        /// Generates a new flexicast session with already defined
        /// configuration.
        pub fn new(
            nb_clients: usize, keylog_filename: &str, authentication: McAuthType,
            use_fec: bool, probe_mc_path: bool, max_cwnd: Option<usize>,
        ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
            // First create the pipe with 0 client, then add the clients with the
            // HTTP/3 sessions.
            let mut fc_pipe = MulticastPipe::new(
                0,
                keylog_filename,
                authentication,
                use_fec,
                probe_mc_path,
                max_cwnd,
            )?;
            let h3_config = Config::new()?;
            let random = ring::rand::SystemRandom::new();
            let mut sessions = Vec::with_capacity(nb_clients);
            let fc_client_tp = McClientTp::default();
            for _ in 0..nb_clients {
                let (pipe, ..) = MulticastPipe::setup_client(
                    &mut fc_pipe.mc_channel,
                    &fc_client_tp,
                    &fc_pipe.mc_announce_data,
                    None,
                    authentication,
                    &random,
                    probe_mc_path,
                )
                .ok_or(Error::Multicast(McError::McPipe))?;

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
            self, client_loss: Option<&RangeSet>, signature_len: usize,
        ) -> Result<(Self, bool)> {
            let mut fc_session_translate: FcSessionTranslate = self.into();
            let fin = match fc_session_translate
                .0
                .source_send_single(client_loss, signature_len)
            {
                Ok(_) => false,
                Err(Error::Done) => true,
                Err(e) => return Err(crate::h3::Error::TransportError(e)),
            };

            Ok((fc_session_translate.into(), fin))
        }
    }

    impl From<FcSession> for FcSessionTranslate {
        fn from(value: FcSession) -> Self {
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

            (fc_pipe, h3_conns, value.fc_h3_conn, value.fc_h3_dummy_conn)
        }
    }

    impl From<FcSessionTranslate> for FcSession {
        fn from(mut value: FcSessionTranslate) -> Self {
            let nb_clients = value.1.len();
            let mut sessions = Vec::with_capacity(nb_clients);

            for ((pipe, ..), (client, server)) in
                value.0.unicast_pipes.drain(..).zip(value.1.drain(..))
            {
                let session = Session {
                    pipe,
                    client,
                    server,
                };
                sessions.push(session);
            }

            FcSession {
                fc_pipe: value.0.mc_channel,
                fc_h3_conn: value.2,
                fc_h3_dummy_conn: value.3,
                sessions,
                mc_announce_data: value.0.mc_announce_data,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::*;

    #[test]
    /// Test a simple HTTP/3 request/response sent on the flexicast channel.
    fn fc_h3_simple() {
        let mut fc_session = FcSession::new(
            2,
            "/tmp/fc_h3_simple.txt",
            McAuthType::StreamAsym,
            true,
            true,
            None,
        )
        .unwrap();

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

        // Send the data to all clients.
        let (fc_session, fin) =
            fc_session.fc_source_send_single(None, 0).unwrap();
        assert!(!fin);
        let (fc_session, fin) =
            fc_session.fc_source_send_single(None, 0).unwrap();
        assert!(fin);
    }
}
