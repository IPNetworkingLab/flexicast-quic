//! Reliability extension for Multicast QUIC.

use super::MulticastAttributes;
use super::MulticastConnection;
use super::MulticastError;
use crate::ranges::RangeSet;
use crate::recovery::multicast::ReliableMulticastRecovery;
use crate::Connection;
use crate::Error;
use crate::Result;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::time;

use super::MulticastClientStatus;
use super::MulticastRole;

/// On rmc timeout for the server.
#[macro_export]
macro_rules! on_rmc_timeout_server {
    ( $mc:expr, $ucs:expr, $now:expr ) => {
        if $mc.mc_timeout($now) == Some(time::Duration::ZERO) {
            $ucs.map(|uc| $mc.rmc_deleguate_streams(uc, $now)).collect()
        } else {
            Ok(())
        }
    };
}

#[derive(Debug, PartialEq, Eq, Default)]
/// Reliable multicast attributes for the client.
pub struct RMcClient {
    /// Next time the client will send a positive ACK.
    rmc_next_time_ack: Option<time::Instant>,

    /// Whether the client must send positive acknowledgment packets.
    rmc_client_send_ack: bool,

    /// Whether the client must send SourceSymbolAck frames.
    rmc_client_send_ssa: bool,
}

impl RMcClient {
    /// Sets the [`RMcClient::rmc_client_send_ack`].
    pub fn set_rmc_client_send_ack(&mut self, v: bool) {
        self.rmc_client_send_ack = v;
    }

    /// Sets the [`RMcClient::rmc_client_send_ssa`].
    pub fn set_rmc_client_send_ssa(&mut self, v: bool) {
        self.rmc_client_send_ssa = v;
    }
}

#[derive(Debug, PartialEq, Eq, Default)]
/// Reliable multicast attributes for the server.
pub struct RMcServer {
    /// Packet numbers received by the client.
    recv_pn_mc: RangeSet,

    /// FEC metadata received by the client.
    recv_fec_mc: RangeSet,

    /// Number of packets containing STREAM frames sent over the multicast path
    /// that expired and must be retransmitted to the client over the unicast
    /// path.
    nb_lost_stream_mc_pkt: u64,
}

impl RMcServer {
    /// Sets the packet number received by the client on the multicast channel.
    pub fn set_rmc_received_pn(&mut self, ranges: RangeSet) {
        self.recv_pn_mc = ranges;
    }

    /// Sets the FEC metadata received bu the client on the multicast channel.
    pub fn set_rmc_received_fec_metadata(&mut self, ranges: RangeSet) {
        self.recv_fec_mc = ranges;
    }

    /// Returns the number of packets containing STREAM frames sent over the
    /// multicast path that expired and must be retransmitted to the client over
    /// the unicast path.
    pub fn get_nb_lost_stream_mc_pkt(&self) -> u64 {
        self.nb_lost_stream_mc_pkt
    }
}

#[derive(Debug, PartialEq, Eq, Default)]
/// Reliable multicast extension for the multicast source.
pub struct RMcSource {
    /// Maximum rangeset of lost frames for a client.
    pub(crate) max_rangeset: Option<(RangeSet, RangeSet)>,
}

/// Reliable multicast attributes.
#[derive(Debug, PartialEq, Eq)]
pub enum ReliableMc {
    /// Client-specific reliable multicast.
    /// Used to store information about the next positive acks to send.
    Client(RMcClient),

    /// Unicast-server specific reliable multicast.
    /// Used to store the positive acks sent by the client about the multicast
    /// channel.
    Server(RMcServer),

    /// Multicast source specific reliable multicast.
    McSource(RMcSource),
}

impl ReliableMc {
    /// Return a mutable reference to the client inner structure.
    pub fn client(&self) -> Option<&RMcClient> {
        if let Self::Client(c) = self {
            Some(c)
        } else {
            None
        }
    }

    /// Return a mutable reference to the server inner structure.
    pub fn server(&self) -> Option<&RMcServer> {
        if let Self::Server(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return a reference to the source inner structure.
    pub fn source(&self) -> Option<&RMcSource> {
        if let Self::McSource(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return a mutable reference to the client inner structure.
    pub fn client_mut(&mut self) -> Option<&mut RMcClient> {
        if let Self::Client(c) = self {
            Some(c)
        } else {
            None
        }
    }

    /// Return a mutable reference to the server inner structure.
    pub fn server_mut(&mut self) -> Option<&mut RMcServer> {
        if let Self::Server(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return a mutable reference to the source inner structure.
    pub fn source_mut(&mut self) -> Option<&mut RMcSource> {
        if let Self::McSource(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

/// Reliable multicast extension behaviour for the QUIC connection.
pub trait ReliableMulticastConnection {
    /// Returns the amount of time until the next reliable multicast timeout
    /// event.
    ///
    /// Once the given duration has elapsed, the [`on_rmc_timeout()`] method
    /// should be called. A timeout of `None` means that the timer sould be
    /// disarmed.
    fn rmc_timeout(&self, now: time::Instant) -> Option<time::Duration>;

    /// Processes a reliable multicast timeout event.
    ///
    /// If no timeout has occurred it does nothing.
    fn on_rmc_timeout(&mut self, now: time::Instant) -> Result<()>;

    /// Sets the next timeout for the client to send a positive acknowledgment.
    fn rmc_set_next_timeout(
        &mut self, now: time::Instant, random: &SystemRandom,
    ) -> Result<()>;

    /// Whether the client should send a positive acknowledgment frame to the
    /// server.
    ///
    /// Returns a [`crate::Error::Multicast`] with
    /// [`crate::multicast::MulticastError::McInvalidRole`] if this is not a
    /// client.
    /// Returns a [`crate::Error::Multicast`] with
    /// [`crate::multicast::MulticastError::McReliableDisabled`] if reliable
    /// multicast is disabled.
    fn rmc_should_send_positive_ack(&self) -> Result<bool>;

    /// Whether the client should send a SourceSymbolAck frame.
    ///
    /// Returns a [`crate::Error::Multicast`] with
    /// [`crate::multicast::MulticastError::McInvalidRole`] if this is not a
    /// client.
    /// Returns a [`crate::Error::Multicast`] with
    /// [`crate::multicast::MulticastError::McReliableDisabled`] if reliable
    /// multicast is disabled.
    fn rmc_should_send_source_symbol_ack(&self) -> Result<bool>;

    /// The multicast source delegates expired streams to the unicast path to
    /// provide full reliability to the transmission. Start the stream at
    /// the first offset of a missing STREAM frame until the end of the stream.
    /// As a result, the client may receive multiple times the same stream
    /// chunks. RMC-TODO: does the stream library handle this correctly?
    ///
    /// Requires that the caller is the multicast source
    /// ([`crate::multicast::MulticastRole::ServerMulticast`]) and the callee
    /// the unicast server ([`crate::multicast::MulticastRole::ServerUnicast`]).
    /// Returns the stream IDs of streams that are deleguated to the unicast
    /// path.
    fn rmc_deleguate_streams(
        &mut self, uc: &mut Connection, now: time::Instant,
    ) -> Result<()>;

    /// Returns the [`crate::ranges::RangeSet`] of packet numbers received by
    /// the client on the multicast path.
    fn rmc_get_recv_pn(&self) -> Result<&RangeSet>;

    /// Returns the [`crate::ranges::RangeSet`] of FEC recovered source symbols
    /// received by the client.
    fn rmc_get_rec_ss(&self) -> Result<&RangeSet>;
}

impl ReliableMulticastConnection for Connection {
    fn rmc_timeout(&self, now: time::Instant) -> Option<time::Duration> {
        let multicast = self.multicast.as_ref()?;

        // No timeout for client not in the group/transient leaving.
        if matches!(
            multicast.mc_role,
            MulticastRole::Client(MulticastClientStatus::AwareUnjoined) |
                MulticastRole::Client(MulticastClientStatus::Leaving(_))
        ) {
            return None;
        }

        let mc_reliable = multicast.mc_reliable.as_ref()?;

        if let ReliableMc::Client(rmc) = mc_reliable {
            Some(rmc.rmc_next_time_ack?.duration_since(now))
        } else {
            None
        }
    }

    fn on_rmc_timeout(&mut self, now: time::Instant) -> Result<()> {
        info!("Call on_rmc_timeout");
        if let Some(time::Duration::ZERO) = self.rmc_timeout(now) {
            // Should be the client.
            assert!(!self.is_server);
            if let Some(multicast) = self.multicast.as_mut() {
                if let Some(ReliableMc::Client(rmc)) =
                    multicast.mc_reliable.as_mut()
                {
                    rmc.set_rmc_client_send_ack(true);
                    rmc.set_rmc_client_send_ssa(true);
                }
            }
        }
        Ok(())
    }

    fn rmc_set_next_timeout(
        &mut self, now: time::Instant, random: &SystemRandom,
    ) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            let expiration_timer = multicast
                .get_mc_announce_data_path()
                .unwrap()
                .expiration_timer;

            if let Some(ReliableMc::Client(rmc)) = multicast.mc_reliable.as_mut()
            {
                let mut random_v = [0u8; 4];
                random.fill(&mut random_v).ok();
                let additional_timer = i32::from_be_bytes(random_v) as i128;
                let et_with_random = expiration_timer as i128 +
                    (additional_timer % ((expiration_timer / 10) as i128));
                rmc.rmc_next_time_ack = now.checked_add(
                    time::Duration::from_millis(et_with_random as u64),
                );
                Ok(())
            } else {
                Err(Error::Multicast(MulticastError::McReliableDisabled))
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }

    fn rmc_should_send_positive_ack(&self) -> Result<bool> {
        self.multicast
            .as_ref()
            .ok_or(Error::Multicast(MulticastError::McDisabled))?
            .mc_reliable
            .as_ref()
            .ok_or(Error::Multicast(MulticastError::McReliableDisabled))?
            .client()
            .ok_or(Error::Multicast(MulticastError::McInvalidRole(
                MulticastRole::Undefined,
            )))
            .map(|c| c.rmc_client_send_ack)
    }

    fn rmc_should_send_source_symbol_ack(&self) -> Result<bool> {
        self.multicast
            .as_ref()
            .ok_or(Error::Multicast(MulticastError::McDisabled))?
            .mc_reliable
            .as_ref()
            .ok_or(Error::Multicast(MulticastError::McReliableDisabled))?
            .client()
            .ok_or(Error::Multicast(MulticastError::McInvalidRole(
                MulticastRole::Undefined,
            )))
            .map(|c| c.rmc_client_send_ssa)
    }

    fn rmc_deleguate_streams(
        &mut self, uc: &mut Connection, now: time::Instant,
    ) -> Result<()> {
        if let (Some(mc_s), Some(mc_u)) =
            (self.multicast.as_mut(), uc.get_multicast_attributes())
        {
            if mc_s.get_mc_role() != MulticastRole::ServerMulticast {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    mc_s.get_mc_role(),
                )));
            }
            if !matches!(mc_u.get_mc_role(), MulticastRole::ServerUnicast(_)) {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    mc_u.get_mc_role(),
                )));
            }

            // Deleguate streams sent on the multicast path.
            let expiration_timer = mc_s
                .get_mc_announce_data_path()
                .ok_or(Error::Multicast(MulticastError::McAnnounce))?
                .expiration_timer;
            let space_id = mc_s
                .get_mc_space_id()
                .ok_or(Error::Multicast(MulticastError::McPath))?;
            let path = self.paths.get_mut(space_id)?;
            let stream_map = &mut self.streams;
            println!("Before");
            let (nb_lost_stream_frames, (lost_pn, recv_pn)) = path.recovery.deleguate_stream(
                uc,
                now,
                expiration_timer,
                space_id as u32,
                stream_map,
            )?;
            println!("After");
            if let Some(rmc) = uc.multicast.as_mut().unwrap().mc_reliable.as_mut() {
                rmc.server_mut().unwrap().nb_lost_stream_mc_pkt +=
                    nb_lost_stream_frames;
            }

            if let Some(rmc) = mc_s.rmc_get_mut().map(|rmc| rmc.source_mut()).flatten() {
                if let Some((lost, _)) = &rmc.max_rangeset {
                    if lost.len() < lost_pn.len() {
                        rmc.max_rangeset = Some((lost_pn, recv_pn));
                    }
                } else {
                    rmc.max_rangeset = Some((lost_pn, recv_pn));
                }
            }
        } else {
            return Err(Error::Multicast(MulticastError::McDisabled));
        }

        Ok(())
    }

    fn rmc_get_recv_pn(&self) -> Result<&RangeSet> {
        if let Some(multicast) = self.multicast.as_ref() {
            if let Some(ReliableMc::Server(s)) = multicast.mc_reliable.as_ref() {
                Ok(&s.recv_pn_mc)
            } else {
                Err(Error::Multicast(MulticastError::McReliableDisabled))
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }

    fn rmc_get_rec_ss(&self) -> Result<&RangeSet> {
        if let Some(multicast) = self.multicast.as_ref() {
            if let Some(ReliableMc::Server(s)) = multicast.mc_reliable.as_ref() {
                Ok(&s.recv_fec_mc)
            } else {
                Err(Error::Multicast(MulticastError::McReliableDisabled))
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }
}

impl MulticastAttributes {
    /// Whether the multicast channel uses reliable multicast.
    pub fn mc_is_reliable(&self) -> bool {
        self.get_mc_announce_data_path()
            .map(|d| d.full_reliability)
            .unwrap_or(false)
    }

    /// Sets the reliable client needing to send positive ack frames.
    pub fn rmc_set_send_ack(&mut self, v: bool) {
        if let Some(ReliableMc::Client(c)) = self.mc_reliable.as_mut() {
            c.set_rmc_client_send_ack(v);
        }
    }

    /// Gets the reliable multicast attributes as a mutable reference.
    pub fn rmc_get_mut(&mut self) -> Option<&mut ReliableMc> {
        self.mc_reliable.as_mut()
    }

    /// Gets the reliable multicast attributes as a reference.
    pub fn rmc_get(&self) -> Option<&ReliableMc> {
        self.mc_reliable.as_ref()
    }

    /// Gets the number of STREAM frames that this server-side unicast
    /// connection retransmitted.
    ///
    /// Always `None` for the multicast source and the client.
    /// `None` if reliable multicast is disabled.
    pub fn rmc_get_server_nb_lost_stream(&self) -> Option<u64> {
        if !matches!(self.mc_role, MulticastRole::ServerUnicast(_)) ||
            !self.mc_is_reliable()
        {
            return None;
        }

        self.rmc_get()
            .map(|rmc| rmc.server().map(|s| s.get_nb_lost_stream_mc_pkt()))?
    }
}

/// Provide structures and functions to help testing the reliable multicast
/// extension of QUIC.
pub mod testing {
    use super::*;
    use crate::multicast::testing::*;
    use crate::multicast::*;

    /// Simple McAnnounceData for testing the reliable multicast extension only.
    pub fn get_test_rmc_announce_data() -> McAnnounceData {
        let mut mc_announce_data = get_test_mc_announce_data();
        mc_announce_data.full_reliability = true;

        mc_announce_data
    }

    impl MulticastPipe {
        /// Generates a new reliable multicast pipe with already defined
        /// configuration.
        pub fn new_reliable(
            nb_clients: usize, keylog_filename: &str, authentication: McAuthType,
            use_fec: bool, probe_mc_path: bool, max_cwnd: Option<usize>,
        ) -> Result<MulticastPipe> {
            let mc_announce_data = get_test_rmc_announce_data();
            Self::new_from_mc_announce_data(
                nb_clients,
                keylog_filename,
                authentication,
                use_fec,
                probe_mc_path,
                max_cwnd,
                mc_announce_data,
            )
        }

        /// Handles the stream delegation from the multicast source to the
        /// unicast server connections.
        pub fn source_deleguates_streams(
            &mut self, expired: time::Instant,
        ) -> Result<()> {
            let ucs = self.unicast_pipes.iter_mut().take_while(|_| true);
            let mc = &mut self.mc_channel.channel;
            let ucs = ucs.map(|c| &mut c.0.server);

            on_rmc_timeout_server!(mc, ucs, expired)
        }

        /// Sets the RMC next timeout on the client and directly expires it by
        /// calling `on_rmc_timeout` to trigger positive acks to the source.
        /// Does not make the pipes advance.
        pub fn client_rmc_timeout(
            &mut self, now: time::Instant, random: &SystemRandom,
        ) -> Result<()> {
            self.unicast_pipes.iter_mut().try_for_each(|(pipe, ..)| {
                let client = &mut pipe.client;
                client.rmc_set_next_timeout(now, random)?;

                let et_ack_duration = client.rmc_timeout(now).unwrap();
                let et_ack = now
                    .checked_add(
                        et_ack_duration
                            .checked_add(time::Duration::from_millis(1))
                            .unwrap(),
                    )
                    .unwrap();
                client.on_rmc_timeout(et_ack)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multicast::reliable::RMcClient;
    use crate::multicast::reliable::RMcServer;
    use crate::multicast::reliable::ReliableMc;
    use crate::multicast::testing::MulticastPipe;
    use crate::multicast::McAuthType;
    use crate::ranges::RangeSet;
    use ring::rand::SystemRandom;
    use std::time;

    #[test]
    fn test_rmc_next_timeout() {
        let mut mc_pipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_next_timeout.txt",
            McAuthType::None,
            true,
            true,
            None,
        )
        .unwrap();
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;

        assert!(mc_pipe
            .mc_channel
            .channel
            .multicast
            .as_ref()
            .unwrap()
            .mc_is_reliable());
        assert!(mc_pipe.unicast_pipes[0]
            .0
            .server
            .multicast
            .as_ref()
            .unwrap()
            .mc_is_reliable());
        assert!(mc_pipe.unicast_pipes[0]
            .0
            .client
            .multicast
            .as_ref()
            .unwrap()
            .mc_is_reliable());

        let server = &mut mc_pipe.unicast_pipes[0].0.server;
        let multicast = server.multicast.as_ref().unwrap();
        let rmc = multicast.mc_reliable.as_ref();
        let expected_rmc = ReliableMc::Server(RMcServer {
            recv_pn_mc: RangeSet::default(),
            recv_fec_mc: RangeSet::default(),
            nb_lost_stream_mc_pkt: 0,
        });
        assert_eq!(rmc, Some(&expected_rmc));

        let client = &mut mc_pipe.unicast_pipes[0].0.client;
        let multicast = client.multicast.as_mut().unwrap();
        let rmc = multicast.mc_reliable.as_ref();
        let expected_rmc = ReliableMc::Client(RMcClient {
            rmc_next_time_ack: None,
            rmc_client_send_ack: false,
            rmc_client_send_ssa: false,
        });
        assert_eq!(rmc, Some(&expected_rmc));

        // Compute next timeout on the client.
        // The next reliable multicast timeout remains within the bounds.
        let now = time::Instant::now();
        let random = SystemRandom::new();
        for _ in 0..10000 {
            assert_eq!(client.rmc_set_next_timeout(now, &random), Ok(()));
            let rmc_client = client
                .multicast
                .as_ref()
                .unwrap()
                .mc_reliable
                .as_ref()
                .unwrap()
                .client()
                .unwrap();
            let next_timeout = rmc_client.rmc_next_time_ack.unwrap();
            let expected_lowest = now
                .checked_add(time::Duration::from_millis(
                    (expiration_timer as f64 * 0.9) as u64,
                ))
                .unwrap();
            let expected_highest = now
                .checked_add(time::Duration::from_millis(
                    (expiration_timer as f64 * 1.1) as u64,
                ))
                .unwrap();
            assert!(next_timeout >= expected_lowest);
            assert!(next_timeout <= expected_highest);
        }

        // The client must now generate a positive ACK to the server for
        // synchronization.
        assert_eq!(client.rmc_should_send_positive_ack(), Ok(false));
        let timeout = now
            .checked_add(time::Duration::from_millis(
                (expiration_timer as f64 * 1.11) as u64,
            ))
            .unwrap();
        assert_eq!(client.on_rmc_timeout(timeout), Ok(()));
        assert_eq!(client.rmc_should_send_positive_ack(), Ok(true));
        assert_eq!(client.rmc_should_send_source_symbol_ack(), Ok(true));
    }

    #[test]
    fn test_rmc_client_send_ack() {
        let mut mc_pipe = MulticastPipe::new_reliable(
            1,
            "/tmp/test_rmc_client_send_ack.txt",
            McAuthType::None,
            true,
            true,
            None,
        )
        .unwrap();

        mc_pipe.source_send_single_stream(true, None, 0, 1).unwrap();
        mc_pipe.source_send_single_stream(true, None, 0, 5).unwrap();
        mc_pipe.source_send_single_stream(true, None, 0, 9).unwrap();
        mc_pipe
            .source_send_single_stream(true, None, 0, 13)
            .unwrap();

        let now = time::Instant::now();
        let random = SystemRandom::new();
        let client = &mut mc_pipe.unicast_pipes[0].0.client;
        assert_eq!(client.rmc_set_next_timeout(now, &random), Ok(()));
        let et_ack_duration = client.rmc_timeout(now).unwrap();
        let et_ack = now
            .checked_add(
                et_ack_duration
                    .checked_add(time::Duration::from_millis(1))
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(client.on_rmc_timeout(et_ack), Ok(()));
        assert_eq!(client.rmc_should_send_positive_ack(), Ok(true));
        assert_eq!(client.rmc_should_send_source_symbol_ack(), Ok(true));
        // The client sends the feedback to the source.
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // The source knows the packets received by the client on the multicast
        // channel.
        let server = &mut mc_pipe.unicast_pipes[0].0.server;
        let rmc = server
            .multicast
            .as_ref()
            .unwrap()
            .mc_reliable
            .as_ref()
            .unwrap()
            .server()
            .unwrap();
        let mut expected_ranges = RangeSet::default();
        assert_eq!(expected_ranges, rmc.recv_fec_mc);
        // Packet number 0 is received by the unicast source when opening the
        // second path.
        expected_ranges.insert(0..6);
        assert_eq!(expected_ranges, rmc.recv_pn_mc);
    }

    #[test]
    /// Repeat the same test:
    /// * No source authentication,
    /// * Asymmetric signatures,
    /// * Per-stream asymmetric signatures.
    fn test_on_rmc_timeout_server_small_streams() {
        for (auth_method, sign_len) in [
            (McAuthType::None, 0),
            (McAuthType::AsymSign, 64),
            (McAuthType::StreamAsym, 0),
        ] {
            let mut mc_pipe = MulticastPipe::new_reliable(
                2,
                "/tmp/test_on_rmc_timeout_server_small_streams.txt",
                auth_method,
                true,
                true,
                None,
            )
            .unwrap();

            let mut client_loss1 = RangeSet::default();
            client_loss1.insert(0..1);
            let mut client_loss2 = RangeSet::default();
            client_loss2.insert(1..2);

            // Source sends four small streams. Second and last are not received
            // on the client.
            assert!(mc_pipe
                .source_send_single_stream(true, Some(&client_loss2), sign_len, 1)
                .is_ok());
            assert!(mc_pipe
                .source_send_single_stream(true, Some(&client_loss1), sign_len, 5)
                .is_ok());
            assert!(mc_pipe
                .source_send_single_stream(true, Some(&client_loss2), sign_len, 9)
                .is_ok());
            assert!(mc_pipe
                .source_send_single_stream(
                    true,
                    Some(&client_loss1),
                    sign_len,
                    13
                )
                .is_ok());

            let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
            let now = time::Instant::now();
            let expired = now
                .checked_add(time::Duration::from_millis(expiration_timer + 100))
                .unwrap();

            // Client sends positive ack to the source.
            let random = SystemRandom::new();
            assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));

            for pipe in mc_pipe.unicast_pipes.iter() {
                let client = &pipe.0.client;
                assert_eq!(client.rmc_should_send_positive_ack(), Ok(true));
                assert_eq!(client.rmc_should_send_source_symbol_ack(), Ok(true));
            }

            // Client has only received 2 streams.
            let client = &mc_pipe.unicast_pipes[0].0.client;
            let mut readables = client.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![1, 9]);

            let client = &mc_pipe.unicast_pipes[1].0.client;
            let mut readables = client.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![5, 13]);

            assert_eq!(mc_pipe.clients_send(), Ok(()));
            assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

            // The unicast server now has state for the expired streams.
            let open_stream_ids = mc_pipe.unicast_pipes[0]
                .0
                .server
                .streams
                .iter()
                .map(|(sid, _)| *sid)
                .collect::<Vec<_>>();
            assert_eq!(open_stream_ids, vec![5, 13]);

            let open_stream_ids = mc_pipe.unicast_pipes[1]
                .0
                .server
                .streams
                .iter()
                .map(|(sid, _)| *sid)
                .collect::<Vec<_>>();
            assert_eq!(open_stream_ids, vec![1, 9]);

            // RMC-TODO: assert on the data and offsets of the streams on the
            // server.
            for pipe in mc_pipe.unicast_pipes.iter_mut() {
                assert_eq!(pipe.0.server.streams.has_flushable(), true);
                assert_eq!(pipe.0.advance(), Ok(()));

                // Client now has all four streams.
                let client = &mut pipe.0.client;
                let mut readables = client.readable().collect::<Vec<_>>();
                readables.sort();
                assert_eq!(readables, vec![1, 5, 9, 13]);
                let mut out_buf = [0u8; 1000];
                for stream_id in readables {
                    assert!(client.stream_complete(stream_id));
                    assert_eq!(
                        client.mc_stream_recv(stream_id, &mut out_buf),
                        Ok((300, true))
                    );
                }

                assert_eq!(
                    pipe.0
                        .server
                        .multicast
                        .as_ref()
                        .unwrap()
                        .rmc_get_server_nb_lost_stream(),
                    Some(2)
                );
            }
        }
    }

    #[test]
    /// Repeat the same test:
    /// * No source authentication,
    /// * Asymmetric signatures,
    /// * Per-stream asymmetric signatures.
    fn test_on_rmc_timeout_large_stream() {
        for (auth_method, sign_len) in [
            (McAuthType::None, 0),
            (McAuthType::AsymSign, 64),
            (McAuthType::StreamAsym, 0),
        ] {
            let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
                2,
                "/tmp/test_on_rmc_timeout_large_stream.txt",
                auth_method,
                true,
                true,
                None,
            )
            .unwrap();

            let mut client_loss1 = RangeSet::default();
            client_loss1.insert(0..1);
            let mut client_loss2 = RangeSet::default();
            client_loss2.insert(1..2);

            // Source sends a large (unfinished) stream.
            let random = SystemRandom::new();
            let data_len = 10_000;
            let mut data = vec![0u8; data_len];
            random.fill(&mut data).unwrap();

            assert_eq!(
                mc_pipe.mc_channel.channel.stream_send(1, &data, false),
                Ok(data.len())
            );

            // Send as many packets as needed to forward the stream. Every other
            // packet is lost.
            let mut erase = true;
            loop {
                if let Err(Error::Done) = mc_pipe.source_send_single(
                    if erase {
                        Some(&client_loss1)
                    } else {
                        Some(&client_loss2)
                    },
                    sign_len,
                ) {
                    break;
                }
                erase = !erase;
            }

            // Client 1 did not receive the first packet => impossible to read the
            // stream.
            let client = &mc_pipe.unicast_pipes[0].0.client;
            assert!(client.readable().collect::<Vec<u64>>().is_empty());
            // Client 2 received the first packet => possible to read the stream.
            let client = &mc_pipe.unicast_pipes[1].0.client;
            assert_eq!(client.readable().collect::<Vec<u64>>(), vec![1u64]);

            // Client compute positive acknowledgment and send packets to the
            // server.
            let now = time::Instant::now();
            assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
            assert_eq!(mc_pipe.clients_send(), Ok(()));

            // Multicast source deleguates streams.
            let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
            let now = time::Instant::now();
            let expired = now
                .checked_add(time::Duration::from_millis(expiration_timer + 100))
                .unwrap();
            assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

            // Multicast source expires and directly sends notificication to the
            // clients, before the unicast servers can retransmit the lost stream
            // frames.
            let exp_pkt =
                mc_pipe.mc_channel.channel.on_mc_timeout(expired).unwrap();
            assert_eq!(exp_pkt.pn, Some(9 + sign_len as u64 / 64));
            assert_eq!(exp_pkt.ssid, Some(7 + sign_len as u64 / 64));

            // The unicast server sends the retransmissions.
            assert_eq!(
                mc_pipe
                    .unicast_pipes
                    .iter_mut()
                    .map(|(pipe, ..)| pipe.advance())
                    .collect::<Result<()>>(),
                Ok(())
            );

            let data2_len = 7000;
            let mut out_buf = vec![0u8; data_len + data2_len];
            for pipe in mc_pipe.unicast_pipes.iter_mut() {
                // Client now has access to the full stream.
                let client = &mut pipe.0.client;
                assert_eq!(client.readable().collect::<Vec<_>>(), vec![1]);
                assert!(!client.stream_complete(1)); // We do not know the end yet.
                if auth_method == McAuthType::StreamAsym {
                    // No asymmetric signature with the stream...
                    assert_eq!(
                        client.mc_stream_recv(1, &mut out_buf),
                        Err(Error::Done)
                    );
                } else {
                    assert_eq!(
                        client.mc_stream_recv(1, &mut out_buf),
                        Ok((data_len, false))
                    );
                    assert_eq!(data, out_buf[..data_len]);
                }
            }

            // Source sends more data onto that stream.
            let mut data2 = vec![0u8; data2_len];
            random.fill(&mut data2[..]).unwrap();
            assert_eq!(
                mc_pipe.mc_channel.channel.stream_send(1, &data2[..], true),
                Ok(data2_len)
            );

            // Send as many packets as needed to forward the stream. Every other
            // packet is lost.
            let mut erase = false;
            loop {
                if let Err(Error::Done) = mc_pipe.source_send_single(
                    if erase {
                        Some(&client_loss1)
                    } else {
                        Some(&client_loss2)
                    },
                    sign_len,
                ) {
                    break;
                }
                erase = !erase;
            }

            // Client 1 received the first packet => possible to read the stream.
            let client = &mc_pipe.unicast_pipes[0].0.client;
            assert_eq!(client.readable().collect::<Vec<u64>>(), vec![1u64]);
            // Client 2 did not receive the first packet => impossible to read the
            // stream.
            let client = &mc_pipe.unicast_pipes[1].0.client;
            if auth_method == McAuthType::StreamAsym {
                assert_eq!(client.readable().collect::<Vec<u64>>(), vec![1u64]);
            } else {
                assert!(client.readable().collect::<Vec<u64>>().is_empty());
            }

            // Client compute positive acknowledgment and send packets to the
            // server.
            let now = time::Instant::now();
            assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
            assert_eq!(mc_pipe.clients_send(), Ok(()));

            // Multicast source deleguates streams.
            let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
            let now = time::Instant::now();
            let expired = now
                .checked_add(time::Duration::from_millis(
                    expiration_timer * 2 + 100,
                ))
                .unwrap();
            assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

            // Multicast source expires and directly sends notificication to the
            // clients, before the unicast servers can retransmit the lost stream
            // frames.
            let exp_pkt =
                mc_pipe.mc_channel.channel.on_mc_timeout(expired).unwrap();
            if auth_method == McAuthType::AsymSign {
                assert_eq!(exp_pkt.pn, Some(16));
                assert_eq!(exp_pkt.ssid, Some(14));
            } else {
                assert_eq!(exp_pkt.pn, Some(15));
                assert_eq!(exp_pkt.ssid, Some(13));
            }

            // The unicast server sends the retransmissions.
            assert_eq!(
                mc_pipe
                    .unicast_pipes
                    .iter_mut()
                    .map(|(pipe, ..)| pipe.advance())
                    .collect::<Result<()>>(),
                Ok(())
            );

            // Client now has access to the full stream.
            for pipe in mc_pipe.unicast_pipes.iter_mut() {
                let client = &mut pipe.0.client;
                assert_eq!(client.readable().collect::<Vec<_>>(), vec![1]);
                assert!(client.stream_complete(1)); // We do not know the end yet.
                if auth_method == McAuthType::StreamAsym {
                    assert_eq!(
                        client.mc_stream_recv(1, &mut out_buf),
                        Ok((data_len + data2_len, true))
                    );
                    assert_eq!(data, out_buf[..data_len]);
                    assert_eq!(data2, out_buf[data_len..]);

                    // Only test for StreamAsym for simplicity.
                    assert_eq!(
                        pipe.0
                            .server
                            .multicast
                            .as_ref()
                            .unwrap()
                            .rmc_get_server_nb_lost_stream(),
                        Some(7)
                    );
                } else {
                    assert_eq!(
                        client.mc_stream_recv(1, &mut out_buf),
                        Ok((data2_len, true))
                    );
                    assert_eq!(data2, out_buf[..data2_len]);
                }
            }
        }
    }

    #[test]
    fn test_rmc_cc() {
        let max_datagram_size = 1350;
        let auth_method = McAuthType::StreamAsym;
        let mc_cwnd = 15;
        let mut mc_pipe: MulticastPipe = MulticastPipe::new_reliable(
            4,
            "/tmp/test_rmc_cc.txt",
            auth_method,
            true,
            true,
            Some(mc_cwnd),
        )
        .unwrap();

        let cwnd = mc_pipe
            .mc_channel
            .channel
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert_eq!(cwnd, 10 * max_datagram_size);

        let stream = vec![0u8; 40 * max_datagram_size];
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_send(1, &stream, true),
            Ok(10 * max_datagram_size * 2)
        ); // 27,000 because of the two paths.
        while let Ok(_) = mc_pipe.source_send_single(None, 0) {}

        let random = SystemRandom::new();
        let now = time::Instant::now();
        assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // Multicast source deleguates streams.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let now = time::Instant::now();
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(12), Some(10)).into()));

        let cwnd = mc_pipe
            .mc_channel
            .channel
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert_eq!(cwnd, 19 * max_datagram_size);

        // Now a client does not receive any packet.
        let stream = vec![0u8; 40 * max_datagram_size];
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_send(1, &stream, true),
            Ok(25650) // Why so little? -> because there is still buffered stream.
        ); // 27,000 because of the two paths.
        let mut loss_1 = RangeSet::default();
        loss_1.insert(1..2);
        let mut i = 0;
        while let Ok(_) = mc_pipe.source_send_single(if i > 18 { None } else { Some(&loss_1) }, 0) { i += 1; }

        let now = expired;
        assert_eq!(mc_pipe.client_rmc_timeout(now, &random), Ok(()));
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // Multicast source deleguates streams.
        let expiration_timer = mc_pipe.mc_announce_data.expiration_timer;
        let expired = now
            .checked_add(time::Duration::from_millis(expiration_timer + 100))
            .unwrap();
        assert_eq!(mc_pipe.source_deleguates_streams(expired), Ok(()));

        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired);
        assert_eq!(res, Ok((Some(32), Some(30)).into()));

        // Source decreases its congestion window to the minimum multicast value.
        let cwnd = mc_pipe
            .mc_channel
            .channel
            .paths
            .get(1)
            .unwrap()
            .recovery
            .cwnd();
        assert_eq!(cwnd, mc_cwnd * max_datagram_size);
    }
}
