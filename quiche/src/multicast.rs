//! Multicast extension for QUIC.

use crate::{Config, Connection, ConnectionId, Error, Result};
use crate::crypto::{Seal, Open, Algorithm};

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
    mc_announce_data: Option<MulticastChannelAnnounce>,

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
#[derive(Clone, Debug)]
pub struct MulticastChannelAnnounce {
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

pub trait MulticastConnection {
    /// Sets the symetric keys from the secrets. Only used in multicast.
    fn set_multicast_receiver(&mut self, secret: &[u8]) -> Result<()>;
}

impl MulticastConnection for Connection {
    fn set_multicast_receiver(&mut self, secret: &[u8]) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            match multicast.mc_role {
                MulticastRole::Client => {
                    // Do not perform the handshake because we already have the key.
                    self.handshake_completed = true;

                    // Derive the keys from the secret shared by the receiver.
                    let aead_open = Open::from_secret(
                        Algorithm::AES128_GCM,
                        secret,
                    )
                    .unwrap();
                    let aead_seal = Seal::from_secret(
                        Algorithm::AES128_GCM,
                        secret,
                    )
                    .unwrap();

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
            ipv6_channels_allowed: false,
            ipv4_channels_allowed: false,
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
    use super::*;

    #[test]
    fn test_mc_set_receiver() {
        assert!(true);
    }

}