//! Reliability extension for Multicast QUIC.

use super::MulticastAttributes;
use super::MulticastError;
use crate::ranges::RangeSet;
use crate::Connection;
use crate::Error;
use crate::Result;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::time;

use super::MulticastClientStatus;
use super::MulticastRole;

#[derive(Debug, PartialEq, Eq, Default)]
/// Reliable multicast attributes for the client.
pub struct RMcClient {
    /// Next time the client will send a positive ACK.
    rmc_next_time_ack: Option<time::Instant>,

    /// Whether the client must send a positive acknowledgment packet.
    rmc_client_send_ack: bool,
}

impl RMcClient {
    /// Sets the [`RMcClient::rmc_client_send_ack`].
    pub fn set_rmc_client_send_ack(&mut self, v: bool) {
        self.rmc_client_send_ack = v;
    }
}

#[derive(Debug, PartialEq, Eq, Default)]
/// Reliable multicast attributes for the server.
pub struct RMcServer {
    /// Positive acks sent by the client.
    recv_acks_mc: RangeSet,
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
}

impl ReliableMc {
    /// Return the client inner structure.
    pub fn client(&self) -> Option<&RMcClient> {
        if let Self::Client(c) = self {
            Some(c)
        } else {
            None
        }
    }

    /// Return the server inner structure.
    pub fn server(&self) -> Option<&RMcServer> {
        if let Self::Server(s) = self {
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
    /// Once the fiven duration has elapsed, the [`on_rmc_timeout()`] method
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

        if let ReliableMc::Client(ref rmc) = mc_reliable {
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
                }
            }
        }
        Ok(())
    }

    fn rmc_set_next_timeout(
        &mut self, now: time::Instant, random: &SystemRandom,
    ) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            let expiration_timer =
                multicast.get_mc_announce_data_path().unwrap().ttl_data;

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
                Err(Error::Multicast(MulticastError::ReliableDisabled))
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
        let expiration_timer = mc_pipe.mc_announce_data.ttl_data;

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
            recv_acks_mc: RangeSet::default(),
        });
        assert_eq!(rmc, Some(&expected_rmc));

        let client = &mut mc_pipe.unicast_pipes[0].0.client;
        let multicast = client.multicast.as_mut().unwrap();
        let rmc = multicast.mc_reliable.as_ref();
        let expected_rmc = ReliableMc::Client(RMcClient {
            rmc_next_time_ack: None,
            rmc_client_send_ack: false,
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
        let rmc_client = client
            .multicast
            .as_ref()
            .unwrap()
            .mc_reliable
            .as_ref()
            .unwrap()
            .client()
            .unwrap();
        assert!(!rmc_client.rmc_client_send_ack);
        let timeout = now
            .checked_add(time::Duration::from_millis(
                (expiration_timer as f64 * 1.11) as u64,
            ))
            .unwrap();
        assert_eq!(client.on_rmc_timeout(timeout), Ok(()));
        let rmc_client = client
            .multicast
            .as_ref()
            .unwrap()
            .mc_reliable
            .as_ref()
            .unwrap()
            .client()
            .unwrap();
        assert!(rmc_client.rmc_client_send_ack);
    }
}
