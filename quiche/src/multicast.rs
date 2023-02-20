//! Multicast extension for QUIC.

use std::convert::TryFrom;
use std::convert::TryInto;

use crate::crypto::Algorithm;
use crate::crypto::Open;
use crate::crypto::Seal;
use crate::Connection;
use crate::Error;
use crate::Result;

/// Multicast extension errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulticastError {
    /// Incorrect McAnnounce data.
    McAnnounce,

    /// Incomplete server channel initiation.
    McServerInit,

    /// Invalid symetric key.
    McInvalidSymKey,

    /// Attempts to perform server-specific function if a client
    /// and conversely.
    McInvalidRole(MulticastRole),

    /// Multicast is disabled.
    McDisabled,

    /// Invalid asymetric key.
    McInvalidAsymKey,

    /// Invalid asymetric signature.
    McInvalidSign,

    /// Invalid status state machine move for the client.
    McInvalidAction,
}

/// MC_ANNOUNCE frame type.
pub const MC_ANNOUNCE_CODE: u64 = 0xf3;
/// MC_STATE frame type.
pub const MC_STATE_CODE: u64 = 0xf4;
/// MC_KEY frame type.
pub const MC_KEY_CODE: u64 = 0xf5;

/// States of a multicast client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum MulticastClientStatus {
    /// Left the multicast channel.
    Left,

    /// Refused to join the multicast channel.
    DeclinedJoin,

    /// Joined the multicast channel, but does not have the key yet.
    JoinedNoKey,

    /// Aware of a multicast channel but not joined.
    AwareUnjoined,

    /// Sent information to join the multicast channel but not confirmed yet.
    WaitingToJoin,

    /// Joined and got the decryption key.
    JoinedAndKey,

    /// The client is not aware of the multicast channel.
    Unaware,

    /// This is used when the status is of no importance.
    Unspecified,
}

/// Actions of multicast client in the finite state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum MulticastClientAction {
    /// Knows the existence of the multicast channel.
    Notify,

    /// Joins the multicast channel.
    Join,

    /// Leaves the multicast channel.
    Leave,

    /// Receives the decryption key.
    DecryptionKey,
}

impl TryFrom<u64> for MulticastClientAction {
    type Error = crate::Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => MulticastClientAction::Notify,
            1 => MulticastClientAction::Join,
            2 => MulticastClientAction::Leave,
            3 => MulticastClientAction::DecryptionKey,
            _ => return Err(Error::Multicast(MulticastError::McInvalidAction)),
        })
    }
}

impl TryInto<u64> for MulticastClientAction {
    type Error = crate::Error;

    fn try_into(self) -> std::result::Result<u64, Self::Error> {
        Ok(match self {
            MulticastClientAction::Notify => 0,
            MulticastClientAction::Join => 1,
            MulticastClientAction::Leave => 2,
            MulticastClientAction::DecryptionKey => 3,
        })
    }
}

/// Role of the connection
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulticastRole {
    /// Server multicast channel. Not directly connected to any
    /// connection with a client.
    ServerMulticast,

    /// Server unicast channel. Directly connected to its client.
    ServerUnicast(MulticastClientStatus),

    /// Receiver. As it uses multipath, it uses both unicast and multicast.
    Client(MulticastClientStatus),

    /// Undefined role. Used for debugging and as temporary value.
    Undefined,
}

/// Structure containing all multicast-related variables of the extension
/// in a quiche::Connection.
pub struct MulticastAttributes {
    /// Role of the extension.
    mc_role: MulticastRole,

    /// Multicast channel information that is shared in a MC_ANNOUNCE frame.
    /// Server-side: the information to share.
    /// Client-side: the received information.
    /// This is an option because it may be null initially (for example
    /// the client did not receive the MC_ANNOUNCE yet).
    /// MC-TODO: multiple MC channels => vector instead of single value.
    mc_announce_data: Option<McAnnounceData>,

    /// Whether the MC_ANNOUNCE frame has been processed.
    /// Server-side: it is sent.
    /// Client-side: it is received.
    mc_announce_is_processed: bool,

    /// Multicast channel decryption key.
    mc_channel_key: Option<Vec<u8>>,

    /// Multicast crypto Open. Used for the multicast channel only.
    mc_crypto_open: Option<Open>,

    /// Multicast crypto Open. Used for the multicast channel only.
    mc_crypto_seal: Option<Seal>,

    /// Whether the key is up to date.
    mc_key_up_to_date: bool,
}

impl MulticastAttributes {
    /// Returns a reference to the MC_ANNOUNCE data.
    pub fn get_mc_announce_data(&self) -> Option<&McAnnounceData> {
        self.mc_announce_data.as_ref()
    }

    /// Sets the processed state of the MC_ANNOUNCE data.
    /// If set to true, means that the last data has been processed on the host.
    /// Returns an Error if attempting to setting to true whereas no MC_ANNOUNCE
    /// data is found.
    pub fn set_mc_announce_processed(&mut self, val: bool) -> Result<()> {
        if self.mc_announce_data.is_some() {
            self.mc_announce_is_processed = val;
            Ok(())
        } else {
            Err(Error::Multicast(MulticastError::McAnnounce))
        }
    }

    /// Sets the client status following the state machine.
    /// Returns an error if the client would do an invalid move in the state
    /// machine. MC-TODO: complete the finite state machine.
    pub fn update_client_state(
        &mut self, action: MulticastClientAction,
    ) -> Result<MulticastClientStatus> {
        let (is_server, current_status) = match self.mc_role {
            MulticastRole::Client(status) => (false, status),
            MulticastRole::ServerUnicast(status) => (true, status),
            _ =>
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    self.mc_role,
                ))),
        };

        let new_status = match (current_status, action) {
            (MulticastClientStatus::Unaware, MulticastClientAction::Notify) =>
                MulticastClientStatus::AwareUnjoined,
            (
                MulticastClientStatus::AwareUnjoined,
                MulticastClientAction::Join,
            ) if !is_server => MulticastClientStatus::WaitingToJoin,
            (
                MulticastClientStatus::AwareUnjoined,
                MulticastClientAction::Join,
            ) if is_server => MulticastClientStatus::JoinedNoKey,
            (
                MulticastClientStatus::WaitingToJoin,
                MulticastClientAction::Join,
            ) => MulticastClientStatus::JoinedNoKey,
            (
                MulticastClientStatus::JoinedNoKey,
                MulticastClientAction::DecryptionKey,
            ) => MulticastClientStatus::JoinedAndKey,
            (
                MulticastClientStatus::JoinedAndKey,
                MulticastClientAction::Leave,
            ) => MulticastClientStatus::Left,
            _ => return Err(Error::Multicast(MulticastError::McInvalidAction)),
        };

        self.mc_role = match self.mc_role {
            MulticastRole::Client(_) => MulticastRole::Client(new_status),
            MulticastRole::ServerUnicast(_) =>
                MulticastRole::ServerUnicast(new_status),
            other => other,
        };

        Ok(new_status)
    }

    /// Returns whether the client should send an MC_STATE to join the channel.
    /// Always false for a server.
    /// True if the client application explicitly asked to join the channel.
    pub fn should_send_mc_state(&self) -> bool {
        match self.mc_role {
            MulticastRole::Client(status) => match status {
                MulticastClientStatus::WaitingToJoin => true,
                _ => false,
            },

            _ => false,
        }
    }
}

impl Default for MulticastAttributes {
    fn default() -> Self {
        Self {
            mc_role: MulticastRole::Undefined,
            mc_announce_data: None,
            mc_announce_is_processed: false,
            mc_channel_key: None,
            mc_crypto_open: None,
            mc_crypto_seal: None,
            mc_key_up_to_date: false,
        }
    }
}

/// Multicast channel announcement information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McAnnounceData {
    /// Replaces the Connection ID for multicast.
    pub channel_id: u64,

    /// Set to `true` if it is an IPv6 multicast group, `false` for IPv4.
    pub is_ipv6: bool,

    /// IP address of the multicast source (IPv4 only WIP).
    pub source_ip: [u8; 4],

    /// IP address of the multicast group (IPv4 only WIP).
    pub group_ip: [u8; 4],

    /// Source UDP port to use for the clients.
    pub udp_port: u16,

    /// Eddssa public key to authenticate the multicast source.
    pub public_key: Vec<u8>,

    /// Time-to-live (ms) of multicast packets.
    /// After this time, the packets SHOULD NOT be retransmitted.
    pub ttl_data: u64,
}

/// Multicast extension behaviour for the QUIC connection.
pub trait MulticastConnection {
    /// Whether the server should send MC_ANNOUNCE data to the client.
    /// Always false for a client.
    fn mc_should_send_mc_announce(&self) -> bool;

    /// Sets the MC_ANNOUNCE data on the server and the client.
    /// Creates the multicast extension attributes if it does not exist yet.
    /// Returns an Error if multicast is not supported.
    ///
    /// MC-TODO: currently if there is a new MC_ANNOUNCE sent by the server,
    /// the client will move again in the AwareUnjoined role
    /// without notifying the application. This is not currently handled.
    /// However, it is a nice feature because we want to be sure that the client
    /// can control its willing to listen to the multicast channel if the
    /// MC_ANNOUNCE data changes during the communication.
    fn mc_set_mc_announce_data(
        &mut self, mc_announce_data: &McAnnounceData,
    ) -> Result<()>;

    /// Sets the symetric keys from the secrets. Only used in multicast.
    /// Updates the MC_ANNOUNCE data if it exists, or adds a new structure.
    /// Creates the multicast structure if it does not exist.
    fn mc_set_multicast_receiver(&mut self, secret: &[u8]) -> Result<()>;

    /// Returns true if the multicast extension has control data to send.
    fn mc_has_control_data(&self) -> bool;

    /// Joins a multicast channel advertised by a server.
    /// Returns an Error if:
    /// * This is not a client
    /// * There is no multicast state with valid MC_ANNOUNCE data
    /// * The status is not AwareUnjoined
    fn mc_join_channel(&mut self) -> Result<MulticastClientStatus>;
}

impl MulticastConnection for Connection {
    fn mc_should_send_mc_announce(&self) -> bool {
        if !self.is_server {
            return false;
        }

        if !(self.local_transport_params.multicast_server_params &&
            self.peer_transport_params.multicast_client_params.is_some())
        {
            return false;
        }

        if let Some(multicast) = self.multicast.as_ref() {
            multicast.mc_role ==
                MulticastRole::ServerUnicast(MulticastClientStatus::Unaware) &&
                multicast.mc_announce_data.is_some() &&
                !multicast.mc_announce_is_processed
        } else {
            false
        }
    }

    fn mc_set_multicast_receiver(&mut self, secret: &[u8]) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            match multicast.mc_role {
                MulticastRole::Client(MulticastClientStatus::WaitingToJoin) => {
                    // Do not perform the handshake because we already have the
                    // key.
                    self.handshake_completed = true;

                    // Derive the keys from the secret shared by the receiver.
                    let aead_open =
                        Open::from_secret(Algorithm::AES128_GCM, secret).unwrap();
                    let aead_seal =
                        Seal::from_secret(Algorithm::AES128_GCM, secret).unwrap();

                    // Do not change the global context.
                    // We will use this crypto when needed by manually getting it.
                    multicast.mc_crypto_open = Some(aead_open);
                    multicast.mc_crypto_seal = Some(aead_seal);

                    Ok(())
                },
                _ => Err(Error::Multicast(MulticastError::McInvalidRole(
                    multicast.mc_role,
                ))),
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }

    fn mc_set_mc_announce_data(
        &mut self, mc_announce_data: &McAnnounceData,
    ) -> Result<()> {
        if (self.is_server &&
            !(self.local_transport_params.multicast_server_params &&
                self.peer_transport_params
                    .multicast_client_params
                    .is_some())) ||
            (!self.is_server &&
                !(self.peer_transport_params.multicast_server_params &&
                    self.local_transport_params
                        .multicast_client_params
                        .is_some()))
        {
            return Err(Error::Multicast(MulticastError::McDisabled));
        }

        if let Some(multicast) = self.multicast.as_mut() {
            if multicast.mc_role == MulticastRole::ServerMulticast {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    multicast.mc_role,
                )));
            }
            multicast.mc_announce_data = Some(mc_announce_data.clone());
            multicast.mc_announce_is_processed = false; // New data!
        } else {
            // Multicast structure does not exist yet.
            // The client considers the MC_ANNOUNCE as processed because it
            // received it.
            let mc_role = if self.is_server {
                MulticastRole::ServerUnicast(MulticastClientStatus::Unaware)
            } else {
                MulticastRole::Client(MulticastClientStatus::AwareUnjoined)
            };
            self.multicast = Some(MulticastAttributes {
                mc_role,
                mc_announce_data: Some(mc_announce_data.clone()),
                mc_announce_is_processed: !self.is_server,
                ..Default::default()
            });
        }

        Ok(())
    }

    fn mc_has_control_data(&self) -> bool {
        // MC-TODO: complete
        self.mc_should_send_mc_announce() ||
            match self.multicast.as_ref() {
                None => false,
                Some(multicast) => multicast.should_send_mc_state(),
            }
    }

    fn mc_join_channel(&mut self) -> Result<MulticastClientStatus> {
        let multicast = match self.multicast.as_mut() {
            None => return Err(Error::Multicast(MulticastError::McDisabled)),
            Some(multicast) => match multicast.mc_role {
                MulticastRole::Client(MulticastClientStatus::AwareUnjoined) =>
                    multicast,
                _ =>
                    return Err(Error::Multicast(MulticastError::McInvalidRole(
                        multicast.mc_role,
                    ))),
            },
        };
        multicast.update_client_state(MulticastClientAction::Join)
    }
}

#[derive(Clone, PartialEq, Debug)]
/// Multicast parameters advertised by a client.
/// TODO: complete the structure and documentation.
pub struct MulticastClientTp {
    /// Allow IPv6 multicast channels.
    pub ipv6_channels_allowed: bool,
    /// Allows IPv4 multicast channels.
    pub ipv4_channels_allowed: bool,
}

impl Default for MulticastClientTp {
    #[inline]
    fn default() -> Self {
        MulticastClientTp {
            ipv6_channels_allowed: true,
            ipv4_channels_allowed: true,
        }
    }
}

impl From<Vec<u8>> for MulticastClientTp {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self {
            ipv6_channels_allowed: v[0] != 0,
            ipv4_channels_allowed: v[1] != 0,
        }
    }
}

impl From<&MulticastClientTp> for Vec<u8> {
    fn from(v: &MulticastClientTp) -> Self {
        vec![
            if v.ipv6_channels_allowed { 1 } else { 0 },
            if v.ipv4_channels_allowed { 1 } else { 0 },
        ]
    }
}

#[cfg(test)]
mod tests {
    use crate::testing;
    use crate::Config;

    use super::*;

    /// Simple config used for testing the multicast extension only.
    pub fn get_test_mc_config(
        mc_server: bool, mc_client: Option<&MulticastClientTp>,
    ) -> Config {
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
        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.set_enable_server_multicast(mc_server);
        config.set_enable_client_multicast(mc_client);
        config
    }

    /// Simple McAnnounceData for testing the multicast extension only.
    fn get_test_mc_announce_data() -> McAnnounceData {
        McAnnounceData {
            channel_id: 0xfefefd,
            is_ipv6: false,
            source_ip: std::net::Ipv4Addr::new(127, 0, 0, 1).octets(),
            group_ip: std::net::Ipv4Addr::new(224, 0, 0, 1).octets(),
            udp_port: 7676,
            public_key: vec![1; 32],
            ttl_data: 1_000_000,
        }
    }

    #[test]
    /// The server adds MC_ANNOUNCE data and should send it to the client.
    /// Both added the multicast extension in their transport parameters.
    /// The sharing of the transport parameters are already tested in lib.rs.
    fn mc_announce_data_init() {
        let mc_client_tp = MulticastClientTp::default();
        let mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(true, Some(&mc_client_tp));

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));

        assert!(pipe.server.multicast.is_none());
        assert!(pipe.client.multicast.is_none());
        assert!(!pipe.server.mc_should_send_mc_announce());
        assert!(!pipe.client.mc_should_send_mc_announce());

        assert!(pipe
            .server
            .mc_set_mc_announce_data(&mc_announce_data)
            .is_ok());

        assert!(pipe.server.multicast.is_some());
        assert_eq!(
            pipe.server
                .multicast
                .as_ref()
                .unwrap()
                .mc_announce_data
                .as_ref()
                .unwrap(),
            &mc_announce_data
        );

        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            MulticastRole::ServerUnicast(MulticastClientStatus::Unaware)
        );
        assert!(pipe.server.mc_should_send_mc_announce());
    }

    #[test]
    /// Setting of the MC_ANNOUNCE processed.
    fn set_mc_announce_processed() {
        let mut mc_attributes = MulticastAttributes::default();

        assert_eq!(
            mc_attributes.set_mc_announce_processed(true).unwrap_err(),
            Error::Multicast(MulticastError::McAnnounce)
        );
        assert_eq!(
            mc_attributes.set_mc_announce_processed(false).unwrap_err(),
            Error::Multicast(MulticastError::McAnnounce)
        );

        let mc_announce_data = get_test_mc_announce_data();
        mc_attributes.mc_announce_data = Some(mc_announce_data);

        assert!(mc_attributes.set_mc_announce_processed(true).is_ok());
        assert!(mc_attributes.set_mc_announce_processed(false).is_ok());
    }

    #[test]
    /// Exchange of the MC_ANNOUNCE data between the client and the server.
    /// The client receives the MC_ANNOUNCE.
    /// It creates a multicast state on the client.
    fn mc_announce_data_exchange() {
        let mc_client_tp = MulticastClientTp::default();
        let mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(true, Some(&mc_client_tp));

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));
        pipe.server
            .mc_set_mc_announce_data(&mc_announce_data)
            .unwrap();

        assert!(pipe.server.mc_should_send_mc_announce());
        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            MulticastRole::ServerUnicast(MulticastClientStatus::Unaware)
        );
        assert_eq!(pipe.advance(), Ok(()));

        // MC_ANNOUNCE sent.
        // The client has the data, and the server should not send it anymore.
        assert!(!pipe.server.mc_should_send_mc_announce());
        // The reception created a MulticastAttributes in for client.
        assert!(pipe.client.multicast.is_some());
        assert_eq!(
            pipe.client
                .multicast
                .as_ref()
                .unwrap()
                .mc_announce_data
                .as_ref(),
            Some(&mc_announce_data)
        );
        // The client has the role Client.
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            MulticastRole::Client(MulticastClientStatus::AwareUnjoined)
        );
        // The server updates the role of the client because now the frame is
        // sent.
        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            MulticastRole::ServerUnicast(MulticastClientStatus::AwareUnjoined)
        );
    }

    #[test]
    /// The client sends an MC_STATE to join the multicast channel
    /// advertised by the server.
    /// This is triggered when the client receives the channel information
    /// through the MC_ANNOUNCE frame and it accepts to join this channel.
    ///
    /// MC-TODO: also test when the client refuses to join the channel.
    fn client_join_mc_channel() {
        let mc_client_tp = MulticastClientTp::default();
        let mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(true, Some(&mc_client_tp));

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));
        pipe.server
            .mc_set_mc_announce_data(&mc_announce_data)
            .unwrap();

        assert_eq!(pipe.advance(), Ok(()));

        // Client joins the multicast channel.
        // It changes its status to WaitingToJoin.
        // It sends an MC_STATE with a JOIN notification to the server.
        let res = pipe.client.mc_join_channel();
        assert!(res.is_ok());
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            MulticastRole::Client(MulticastClientStatus::WaitingToJoin)
        );

        assert_eq!(pipe.advance(), Ok(()));

        // The client sent its willing to join.
        // It will listen to the multicast channel once it has the key.
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            MulticastRole::Client(MulticastClientStatus::JoinedNoKey)
        );
        // Server received the MC_STATE frame from the client. Its state changed.
        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            MulticastRole::ServerUnicast(MulticastClientStatus::JoinedNoKey)
        );
    }

    #[test]
    fn test_mc_set_receiver() {
        assert!(true);
    }
}
