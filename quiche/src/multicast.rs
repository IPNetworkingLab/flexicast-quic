//! Multicast extension for QUIC.

use crate::crypto::Algorithm;
use crate::crypto::Open;
use crate::crypto::Seal;
use crate::Config;
use crate::Connection;
use crate::ConnectionId;
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
    McInvalidRole,

    /// Client already joined a multicast channel.
    McAlreadyJoin,

    /// Multicast is disabled.
    McDisabled,

    /// Invalid asymetric key.
    McInvalidAsymKey,

    /// Invalid asymetric signature.
    McInvalidSign,
}

/// MC_ANNOUNCE frame type.
pub const MC_ANNOUNCE_CODE: u64 = 0xf3;
/// MC_STATE frame type.
pub const MC_STATE_CODE: u64 = 0xf4;
/// MC_KEY frame type.
pub const MC_KEY_CODE: u64 = 0xf5;
/// MC_ACK frame type.
pub const MC_ACK_CODE: u64 = 0xf6;

/// Role of the connection
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulticastRole {
    /// Server multicast channel. Not directly connected to any
    /// connection with a client.
    ServerMulticast,

    /// Server unicast channel. Directly connected to its client.
    ServerUnicast,

    /// Receiver. As it uses multipath, it uses both unicast and multicast.
    Client,

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

    /// Client (receiver) status. None if server.
    mc_client_status: Option<MulticastClientStatus>,

    /// Whether the key is up to date.
    mc_key_up_to_date: bool,
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
            mc_client_status: None,
            mc_key_up_to_date: false,
        }
    }
}

/// Multicast channel announcement information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McAnnounceData {
    /// Replaces the Connection ID for multicast.
    pub channel_id: Vec<u8>,

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

/// States of a multicast client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulticastClientStatus {
    /// Left the multicast channel.
    Left,

    /// Refused to join the multicast channel.
    DeclinedJoin,

    /// Joined the multicast channel, but does not have the key yet.
    JoinedNoKey,

    /// Aware of a multicast channel but not joined.
    Unjoined,

    /// Sent information to join the multicast channel but not confirmed yet.
    WaitingToJoin,

    /// Joined and got the decryption key.
    JoinedAndKey,
}

/// Multicast extension behaviour for the QUIC connection.
pub trait MulticastConnection {
    /// Whether the server should send MC_ANNOUNCE data to the client.
    /// Always false for a client.
    fn mc_should_send_mc_announce(&mut self) -> bool;

    /// Sets the MC_ANNOUNCE data on the server.
    /// Always returns an Err if it is a client.
    fn mc_set_mc_announce_data(
        &mut self, mc_announce_data: &McAnnounceData,
    ) -> Result<()>;

    /// Sets the symetric keys from the secrets. Only used in multicast.
    /// Updates the MC_ANNOUNCE data if it exists, or adds a new structure.
    /// Creates the multicast structure if it does not exist.
    fn mc_set_multicast_receiver(&mut self, secret: &[u8]) -> Result<()>;
}

impl MulticastConnection for Connection {
    fn mc_should_send_mc_announce(&mut self) -> bool {
        if !self.is_server {
            return false;
        }

        if !(self.local_transport_params.multicast_server_params &&
            self.peer_transport_params.multicast_client_params.is_some())
        {
            return false;
        }

        if let Some(multicast) = self.multicast.as_ref() {
            multicast.mc_announce_data.is_some() &&
                !multicast.mc_announce_is_processed
        } else {
            false
        }
    }

    fn mc_set_multicast_receiver(&mut self, secret: &[u8]) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            match multicast.mc_role {
                MulticastRole::Client => {
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
                _ => Err(Error::Multicast(MulticastError::McInvalidRole)),
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }

    fn mc_set_mc_announce_data(
        &mut self, mc_announce_data: &McAnnounceData,
    ) -> Result<()> {
        if !self.is_server {
            return Err(Error::Multicast(MulticastError::McInvalidRole));
        }

        if let Some(multicast) = self.multicast.as_mut() {
            multicast.mc_announce_data = Some(mc_announce_data.clone());
        } else {
            // Multicast structure does not exist yet.
            self.multicast = Some(MulticastAttributes {
                mc_role: MulticastRole::ServerUnicast,
                mc_announce_data: Some(mc_announce_data.clone()),
                ..Default::default()
            });
        }

        Ok(())
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

    use super::*;

    /// Simple config used for testing the multicast extension only.
    pub fn get_simple_mc_config(
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
            channel_id: [1; crate::MAX_CONN_ID_LEN].to_vec(),
            is_ipv6: false,
            source_ip: std::net::Ipv4Addr::new(127, 0, 0, 1).octets(),
            group_ip: std::net::Ipv4Addr::new(224, 0, 0, 1).octets(),
            udp_port: 7676,
            public_key: vec![1; 32],
            ttl_data: 1_000_000,
        }
    }

    #[test]
    /// The client and server negociate succesfully the multicast extension.
    /// Both added the multicast extension in their transport parameters.
    /// The sharing of the transport parameters are already tested in lib.rs.
    fn mc_announce_data() {
        let mc_client_tp = MulticastClientTp::default();
        let mc_announce_data = get_test_mc_announce_data();
        let mut config = get_simple_mc_config(true, Some(&mc_client_tp));

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));

        assert!(pipe.server.multicast.is_none());
        assert!(pipe.client.multicast.is_none());
        assert!(!pipe.server.mc_should_send_mc_announce());
        assert!(!pipe.client.mc_should_send_mc_announce());

        assert!(pipe
            .client
            .mc_set_mc_announce_data(&mc_announce_data)
            .is_err());
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

        assert!(pipe.server.mc_should_send_mc_announce());
    }

    #[test]
    fn test_mc_set_receiver() {
        assert!(true);
    }
}
