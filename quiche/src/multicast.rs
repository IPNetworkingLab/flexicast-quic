//! Multicast extension for QUIC.

use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::BufRead;
use std::net::SocketAddr;

use crate::rand::rand_bytes;
use ring::rand;
use ring::rand::SecureRandom;
use ring::signature;
use ring::signature::KeyPair;

use crate::accept;
use crate::connect;
use crate::crypto::Algorithm;
use crate::crypto::Open;
use crate::crypto::Seal;
use crate::testing::emit_flight;
use crate::testing::process_flight;
use crate::Config;
use crate::Connection;
use crate::ConnectionId;
use crate::Error;
use crate::RecvInfo;
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

    /// Handshake of the multicast server channel failed.
    McChannelHandshake,
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

    /// Multicast channel decryption key secret.
    mc_channel_key: Option<Vec<u8>>,

    /// Multicast crypto Open. Used for the multicast channel only.
    mc_crypto_open: Option<Open>,

    /// Multicast crypto Open. Used for the multicast channel only.
    mc_crypto_seal: Option<Seal>,

    /// Whether the key is up to date.
    mc_key_up_to_date: bool,

    /// Signature public key.
    /// Used for authentication of the source for data received on the multicast
    /// channel. Derived from the McAnnounceData::public_key.
    mc_public_key: Option<signature::UnparsedPublicKey<Vec<u8>>>,

    /// Signature private key.
    /// Only present for the multicast source.
    mc_private_key: Option<signature::Ed25519KeyPair>,
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

    /// Returns whether the client should send an MC_STATE frame to join the
    /// channel. Always false for a server.
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

    /// Returns whether the server should send an MC_KEY frame
    /// to share the public authentication key to the client.
    /// True if the client has joined the multicast channel
    /// but has received not the authentication key yet.
    /// Always false for a client.
    pub fn should_send_mc_key(&self) -> bool {
        if self.mc_key_up_to_date {
            return false;
        }
        if self.mc_channel_key.is_none() {
            return false;
        }
        match self.mc_role {
            MulticastRole::ServerUnicast(MulticastClientStatus::JoinedNoKey) =>
                true,
            _ => false,
        }
    }

    /// Read the last multicast decryption key secret.
    pub fn read_mc_key(&mut self) {
        self.mc_key_up_to_date = true;
    }

    /// Get the channel decryption key secret.
    pub fn get_decryption_key_secret(&self) -> Result<&[u8]> {
        match self.mc_role {
            MulticastRole::ServerUnicast(MulticastClientStatus::JoinedNoKey) =>
                Ok(self
                    .mc_channel_key
                    .as_ref()
                    .ok_or(Error::Multicast(MulticastError::McInvalidSymKey))?),
            _ => Err(Error::Multicast(MulticastError::McInvalidRole(
                self.mc_role,
            ))),
        }
    }

    /// Sets the channel decryption key secret.
    pub fn set_decryption_key_secret(&mut self, key: Vec<u8>) -> Result<()> {
        match self.mc_role {
            MulticastRole::Client(MulticastClientStatus::JoinedNoKey) => {
                let aead_open = Open::from_secret(Algorithm::AES128_GCM, &key)?;
                self.mc_crypto_open = Some(aead_open);
                let aead_seal = Seal::from_secret(Algorithm::AES128_GCM, &key)?;
                self.mc_crypto_seal = Some(aead_seal);

                self.mc_channel_key = Some(key);

                self.update_client_state(MulticastClientAction::DecryptionKey)?;
                Ok(())
            },
            _ => Err(Error::Multicast(MulticastError::McInvalidRole(
                self.mc_role,
            ))),
        }
    }

    /// Gives the decryption context for the multicast channel.
    pub fn get_mc_crypto_open(&self) -> Option<&Open> {
        self.mc_crypto_open.as_ref()
    }

    /// Gives the public key of the multicast source as an array reference.
    ///
    /// Returns an error if it is not the multicast source.
    pub fn get_mc_pub_key(&self) -> Result<&[u8]> {
        if self.mc_role == MulticastRole::ServerMulticast {
            if let Some(private_key) = self.mc_private_key.as_ref() {
                Ok(private_key.public_key().as_ref())
            } else {
                Err(Error::Multicast(MulticastError::McInvalidAsymKey))
            }
        } else {
            Err(Error::Multicast(MulticastError::McInvalidRole(
                self.mc_role,
            )))
        }
    }

    /// Whether authentication is used to send packets.
    ///
    /// Only true for a multicast source that has a non-empty signature key.
    pub fn is_mc_source_and_auth(&self) -> bool {
        self.mc_role == MulticastRole::ServerMulticast &&
            self.mc_private_key.is_some()
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
            mc_public_key: None,
            mc_private_key: None,
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

    /// EdDSA public key to authenticate the multicast source.
    /// None if authentication is not used.
    pub public_key: Option<Vec<u8>>,

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

    /// Multicast-version of the [`recv`] method of the crate.
    ///
    /// This function is equivalent to [`recv`] and authenticate
    /// the source of the data. It uses the public key announced
    /// by the server to verify the signature of the packet.
    /// This function is strictly equivalent to [`recv`] if the
    /// packet is not received on a multicast path.
    /// The client and server should have agreed on the use of authentication.
    /// If the received key is None, it means that we do not use authentication.
    /// Returns an Error [`McInvalidSign`] if the signature is incorrect,
    /// and do not process the packet.
    ///
    /// MC-TODO: only Ed25519 is used at the moment.
    /// The last bytes of the packet contain the signature.
    fn mc_recv(&mut self, buf: &mut [u8], info: RecvInfo) -> Result<usize>;

    /// Generates a signature on the given QUIC packet.
    /// The caller is responsible to give a mutable slice
    /// with enough space to add the signature.
    /// Otherwise, the method returns an Error [`BufferTooShort`].
    /// Only available for the multicast source.
    /// On success, returns the additional number of bytes used by the
    /// signature. The signature is added at the end of the data in the
    /// buffer.
    fn mc_sign(&self, buf: &mut [u8], data_len: usize) -> Result<usize>;
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
            match multicast.mc_role {
                MulticastRole::ServerMulticast =>
                    return Err(Error::Multicast(MulticastError::McInvalidRole(
                        multicast.mc_role,
                    ))),
                MulticastRole::Client(_) => {
                    // Client generates the public key from the received vector.
                    if let Some(key_vec) = mc_announce_data.public_key.as_ref() {
                        multicast.mc_public_key =
                            Some(signature::UnparsedPublicKey::new(
                                &signature::ED25519,
                                key_vec.to_owned(),
                            ));
                    }
                },
                _ => (),
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
                mc_public_key: if let Some(key_vec) =
                    mc_announce_data.public_key.as_ref()
                { 
                    Some(signature::UnparsedPublicKey::new(
                        &signature::ED25519,
                        key_vec.to_owned(),
                    ))
                } else {
                    None
                },
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
                Some(multicast) =>
                    multicast.should_send_mc_state() ||
                        multicast.should_send_mc_key(),
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

    fn mc_recv(&mut self, buf: &mut [u8], info: RecvInfo) -> Result<usize> {
        let buf_len = if info.from_mc {
            if let Some(multicast) = self.multicast.as_ref() {
                let len = buf.len();
                if let Some(public_key) = multicast.mc_public_key.as_ref() {
                    debug!("mc_rev: Verify the signature of the received packet");
                    let signature_len = 64;
                    let buf_data_len = len - signature_len;

                    let signature = &buf[buf_data_len..];
                    public_key.verify(&buf[..buf_data_len], signature).map_err(
                        |_| Error::Multicast(MulticastError::McInvalidSign),
                    )?;

                    len - signature_len
                } else {
                    len
                }
            } else {
                return Err(Error::Multicast(MulticastError::McDisabled));
            }
        } else {
            // Without authentication nor public key, the entire buffer contains
            // application data.
            buf.len()
        };
        self.recv(&mut buf[..buf_len], info)
    }

    fn mc_sign(&self, buf: &mut [u8], data_len: usize) -> Result<usize> {
        if let Some(multicast) = self.multicast.as_ref() {
            if multicast.mc_role != MulticastRole::ServerMulticast {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    multicast.mc_role,
                )));
            }

            // Asymmetric signature on the last bytes of the packet.
            if let Some(private_key) = multicast.mc_private_key.as_ref() {
                let signature = private_key.sign(&buf[..data_len]);
                let signature_len = signature.as_ref().len();
                assert_eq!(signature_len, 64);
                buf[data_len..data_len + signature_len]
                    .copy_from_slice(signature.as_ref());

                Ok(signature_len)
            } else {
                Err(Error::Multicast(MulticastError::McInvalidAsymKey))
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

/// Represents a source multicast channel.
/// A multicast channel is like a unicast connection without the handshake
/// with the clients because it has no explicit set of connected client.
pub struct MulticastChannelSource {
    /// Connection representing the channel.
    pub channel: Connection,

    /// Back-up connection for the multicast channel setup.
    /// This is used because the source has no direct connection with
    /// any receiver.
    pub client_backup: Connection,

    /// Master secret used to derive the symmetric key used to encrypt
    /// the traffic with the clients.
    pub master_secret: Vec<u8>,

    /// Connection ID that the clients use for the multicast path.
    /// This tuple contains the Connection Id and the reset token.
    pub mc_path_conn_id: (ConnectionId<'static>, u128),

    /// Address used to trigger sending packets on the multicast path.
    pub mc_path_peer: SocketAddr,
}

impl MulticastChannelSource {
    /// Creates a new source multicast channel.
    fn new_with_tls(
        channel_id: &ConnectionId, config_server: &mut Config,
        config_client: &mut Config, peer: SocketAddr, peer2: SocketAddr,
        keylog_filename: &str, do_auth: bool,
    ) -> Result<Self> {
        let scid = ConnectionId::from_ref(channel_id);

        // Add the keylog file.
        let key_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(keylog_filename)
            .map_err(|_| Error::Multicast(MulticastError::McInvalidSymKey))?;
        let keylog = Some(key_file);
        config_client.log_keys();

        // Creates the "dummy client" connection to derive the keys.
        let mut conn_client = connect(None, &scid, peer, peer, config_client)?;
        if let Some(keylog) = keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn_client.set_keylog(Box::new(keylog));
            }
        }
        let mut conn_server = accept(&scid, None, peer, peer, config_server)?;
        Self::handshake(&mut conn_server, &mut conn_client)?;
        Self::advance(&mut conn_server, &mut conn_client)?;

        // Add a new Connection ID for the multicast path.
        let mut channel_id = [0; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut channel_id[..])
            .unwrap();
        let channel_id = ConnectionId::from_ref(&channel_id);
        conn_server.new_source_cid(&channel_id, 0x1, true)?;
        conn_client.new_source_cid(&channel_id, 0x1, true)?;
        Self::advance(&mut conn_server, &mut conn_client)?;

        // Probe the new path.
        conn_client.probe_path(peer2, peer2)?;
        Self::advance(&mut conn_server, &mut conn_client)?;

        // Set the new path active.
        conn_client.set_active(peer2, peer2, true)?;
        conn_server.set_active(peer2, peer2, true)?;
        Self::advance(&mut conn_server, &mut conn_client)?;

        let exporter_secret =
            MulticastChannelSource::get_exporter_secret(keylog_filename)?;

        let signature_eddsa = if do_auth {
            Some(MulticastChannelSource::compute_asymetric_signature_keys()?)
        } else {
            None
        };

        // // Create Connection ID and reset token.
        // let mut cid = vec![0; channel_id.len()];
        // rand_bytes(&mut cid[..]);
        // let cid = ConnectionId::from_ref(&cid).into_owned();
        let cid = channel_id.clone().into_owned();

        let mut reset_token = [0; 16];
        rand_bytes(&mut reset_token);
        let reset_token = u128::from_be_bytes(reset_token);

        conn_server.multicast = Some(MulticastAttributes {
            mc_private_key: signature_eddsa,
            mc_role: MulticastRole::ServerMulticast,
            ..Default::default()
        });

        Ok(Self {
            channel: conn_server,
            client_backup: conn_client,
            master_secret: exporter_secret,
            mc_path_conn_id: (cid, reset_token),
            mc_path_peer: peer2,
        })
    }

    /// Copy of the Pipe::handshake method. Used for the setup
    /// to create the source multicast channel.
    pub fn handshake(
        server: &mut Connection, client: &mut Connection,
    ) -> Result<()> {
        while !client.is_established() || !server.is_established() {
            let flight = emit_flight(client)?;
            process_flight(server, flight)?;

            let flight = emit_flight(server)?;
            process_flight(client, flight)?;
        }

        Ok(())
    }

    /// Copy of the Pipe::advance method. Used for the setup
    /// to create the source multicast channel.
    fn advance(server: &mut Connection, client: &mut Connection) -> Result<()> {
        let mut client_done = false;
        let mut server_done = false;

        while !client_done || !server_done {
            match emit_flight(client) {
                Ok(flight) => process_flight(server, flight)?,

                Err(Error::Done) => client_done = true,

                Err(e) => return Err(e),
            };

            match emit_flight(server) {
                Ok(flight) => process_flight(client, flight)?,

                Err(Error::Done) => server_done = true,

                Err(e) => return Err(e),
            };
        }

        Ok(())
    }

    /// Retrieve the SERVER_TRAFFIC_SECRET_0 secret negotiated by TLS.
    fn get_exporter_secret(keylog_filename: &str) -> Result<Vec<u8>> {
        let fd = std::fs::File::open(keylog_filename)
            .map_err(|_| Error::Multicast(MulticastError::McInvalidSymKey))?;
        let mut reader = std::io::BufReader::new(fd);
        let mut in_string = String::new();
        for _ in 0..3 {
            reader
                .read_line(&mut in_string)
                .map_err(|_| Error::Multicast(MulticastError::McInvalidSymKey))?;
            in_string = String::new();
        }
        reader
            .read_line(&mut in_string)
            .map_err(|_| Error::Multicast(MulticastError::McInvalidSymKey))?; // This is very ugly, erk
        let splited = in_string.split(' ');
        let a = splited
            .last()
            .ok_or(Error::Multicast(MulticastError::McInvalidSymKey))?;
        (0..a.len() - 1)
            .step_by(2)
            .map(|i| {
                a.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
                    .ok_or(Error::Multicast(MulticastError::McInvalidSymKey))
            })
            .collect()
    }

    /// Computes a new asymetric key pair.
    fn compute_asymetric_signature_keys() -> Result<signature::Ed25519KeyPair> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| {
                crate::Error::Multicast(MulticastError::McInvalidAsymKey)
            })?;

        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            pkcs8_bytes.as_ref(),
        )
        .map_err(|_| crate::Error::Multicast(MulticastError::McInvalidAsymKey))?;

        Ok(key_pair)
    }

    /// Multicast-version of the [`send`] method of the crate.
    /// It sends on the multicast path always.
    /// Internally, it uses [`send_on_path`] with the multicast addresses
    /// specified during the source multicast channel configuration.
    ///
    /// This function is equivalent to [`send`] and authenticate
    /// the source of the data. It uses the private key computed internaly
    /// by the server to generate a signature of the packet.
    /// This function is strictly equivalent to [`send`] if the server
    /// does not authenticate data.
    /// The client and server should have agreed on the use of authentication.
    /// If the private is None, it means that we do not use authentication.
    ///
    /// MC-TODO: only Ed25519 is used at the moment.
    /// The last bytes of the packet contain the signature.
    fn mc_send(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.channel
            .send_on_path(buf, Some(self.mc_path_peer), Some(self.mc_path_peer))
            .map(|(written, _)| written)
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SecureRandom;

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
        config.set_active_connection_id_limit(3);
        config.verify_peer(false);
        config.set_multipath(true);
        config.set_enable_server_multicast(mc_server);
        config.set_enable_client_multicast(mc_client);
        config
    }

    /// Simple McAnnounceData for testing the multicast extension only.
    fn get_test_mc_announce_data() -> McAnnounceData {
        McAnnounceData {
            channel_id: [0xff, 0xdd, 0xee, 0xaa, 0xbb, 0x33, 0x66].to_vec(),
            is_ipv6: false,
            source_ip: std::net::Ipv4Addr::new(127, 0, 0, 1).octets(),
            group_ip: std::net::Ipv4Addr::new(224, 0, 0, 1).octets(),
            udp_port: 7676,
            public_key: Some(vec![1; 32]),
            ttl_data: 1_000_000,
        }
    }

    /// Simple source multicast channel for the tests.
    fn get_test_mc_channel_source(
        config_server: &mut Config, config_client: &mut Config, do_auth: bool,
    ) -> Result<MulticastChannelSource> {
        let mut channel_id = [0; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut channel_id[..])
            .unwrap();
        let channel_id = ConnectionId::from_ref(&channel_id);

        let dummy_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
        let dummy_port = 1234;
        let to = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            dummy_ip, dummy_port,
        ));
        let to2 = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            dummy_ip,
            dummy_port + 1,
        ));

        MulticastChannelSource::new_with_tls(
            &channel_id,
            config_server,
            config_client,
            to,
            to2,
            "/tmp/mc_channel_text.txt",
            do_auth,
        )
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
    fn test_mc_client_state_machine() {
        let mut multicast = MulticastAttributes {
            mc_role: MulticastRole::Client(MulticastClientStatus::Unaware),
            ..Default::default()
        };

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Join),
            Err(Error::Multicast(MulticastError::McInvalidAction))
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Leave),
            Err(Error::Multicast(MulticastError::McInvalidAction))
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::DecryptionKey),
            Err(Error::Multicast(MulticastError::McInvalidAction))
        );

        // This is a good move.
        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Notify),
            Ok(MulticastClientStatus::AwareUnjoined)
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Join),
            Ok(MulticastClientStatus::WaitingToJoin)
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Join),
            Ok(MulticastClientStatus::JoinedNoKey)
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::DecryptionKey),
            Ok(MulticastClientStatus::JoinedAndKey)
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Leave),
            Ok(MulticastClientStatus::Left)
        );
    }

    #[test]
    /// Tests the MC_KEY processing.
    /// The server sends an MC_KEY frame to the client once it joined the
    /// multicast group.
    ///
    /// Both the client and the server move to the JoinedAndKey state.
    fn test_mc_key() {
        let mc_client_tp = MulticastClientTp::default();
        let mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(true, Some(&mc_client_tp));

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));
        pipe.server
            .mc_set_mc_announce_data(&mc_announce_data)
            .unwrap();

        assert_eq!(pipe.advance(), Ok(()));
        assert!(pipe.client.mc_join_channel().is_ok());
        assert_eq!(pipe.advance(), Ok(()));

        assert!(!pipe.server.multicast.as_ref().unwrap().should_send_mc_key());

        let multicast = pipe.server.multicast.as_mut().unwrap();
        let mc_channel_key: Vec<_> = (0..32).collect();
        multicast.mc_channel_key = Some(mc_channel_key.clone());

        assert!(pipe.server.multicast.as_ref().unwrap().should_send_mc_key());
        assert_eq!(pipe.advance(), Ok(()));

        assert!(!pipe.server.multicast.as_ref().unwrap().should_send_mc_key());
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            MulticastRole::Client(MulticastClientStatus::JoinedAndKey)
        );
        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            MulticastRole::ServerUnicast(MulticastClientStatus::JoinedAndKey)
        );

        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_channel_key,
            Some(mc_channel_key.clone())
        );
    }

    #[test]
    /// Tests the dummy handshake for the creation of the multicast channel
    /// of the server.
    fn test_mc_channel_server_handshake() {
        let mc_client_tp = MulticastClientTp::default();
        let mut server_config = get_test_mc_config(true, None);
        let mut client_config = get_test_mc_config(false, Some(&mc_client_tp));

        let mc_channel = get_test_mc_channel_source(
            &mut server_config,
            &mut client_config,
            false,
        );
        assert!(mc_channel.is_ok());
    }

    #[test]
    /// Tests the client joining a multicast channel
    /// and creating the multicast path to listen to the source.
    fn test_mc_client_create_multicast_path() {
        let mc_client_tp = MulticastClientTp::default();
        let mut server_config = get_test_mc_config(true, None);
        let mut client_config = get_test_mc_config(false, Some(&mc_client_tp));
        let mut mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(true, Some(&mc_client_tp));

        // Multicast path.
        let mut mc_channel = get_test_mc_channel_source(
            &mut server_config,
            &mut client_config,
            false,
        )
        .unwrap();

        // Copy the channel ID derived from the multicast channel.
        mc_announce_data.channel_id =
            mc_channel.mc_path_conn_id.0.as_ref().to_vec();

        // This is copied from crate::tests::multipath.
        let mut pipe =
            testing::Pipe::with_config_and_scid_lengths(&mut config, 16, 16)
                .unwrap();
        assert_eq!(pipe.handshake(), Ok(()));
        assert_eq!(pipe.client.is_multipath_enabled(), true);
        assert_eq!(pipe.server.is_multipath_enabled(), true);

        // Server announces and client joins.
        pipe.server
            .mc_set_mc_announce_data(&mc_announce_data)
            .unwrap();
        let multicast = pipe.server.multicast.as_mut().unwrap();
        multicast.mc_channel_key = Some(mc_channel.master_secret.clone());
        assert!(pipe.advance().is_ok());

        // Client joins the multicast channel, and the server gives the master
        // key.
        pipe.client.mc_join_channel().unwrap();
        assert!(pipe.advance().is_ok());

        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            MulticastRole::Client(MulticastClientStatus::JoinedAndKey)
        );

        // Issue a new connection ID for the client using the channel ID
        let reset_token = 0xffeeddccu128;
        let client_mc_announce = pipe
            .client
            .multicast
            .as_ref()
            .unwrap()
            .mc_announce_data
            .as_ref()
            .unwrap();
        let cid =
            ConnectionId::from_ref(&client_mc_announce.channel_id).into_owned();
        println!("Client will add this CID: {:?}", cid);
        pipe.client.new_source_cid(&cid, reset_token, true).unwrap();
        pipe.server.new_source_cid(&cid, reset_token, true).unwrap();

        let client_addr = testing::Pipe::client_addr();
        let server_addr = testing::Pipe::server_addr();
        let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
        // let cid_c2s_0 = pipe.client.destination_id().into_owned();
        // let cid_s2c_0 = pipe.server.destination_id().into_owned();

        // Probe a second path that will listen to the multicast source.
        assert_eq!(pipe.advance(), Ok(()));
        assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));
        assert_eq!(pipe.advance(), Ok(()));

        let pid_c2s_0 = pipe
            .client
            .paths
            .path_id_from_addrs(&(client_addr, server_addr))
            .expect("no such path");
        let pid_c2s_1 = pipe
            .client
            .paths
            .path_id_from_addrs(&(client_addr_2, server_addr))
            .expect("no such path");
        let pid_s2c_0 = pipe
            .server
            .paths
            .path_id_from_addrs(&(server_addr, client_addr))
            .expect("no such path");

        let path_c2s_0 = pipe.client.paths.get(pid_c2s_0).expect("no such path");
        let path_c2s_1 = pipe.client.paths.get(pid_c2s_1).expect("no such path");
        let path_s2c_0 = pipe.server.paths.get(pid_s2c_0).expect("no such path");

        assert_eq!(path_c2s_0.active(), true);
        assert_eq!(path_c2s_1.active(), false);
        assert_eq!(path_s2c_0.active(), true);

        assert_eq!(
            pipe.client.set_active(client_addr_2, server_addr, true,),
            Ok(())
        );

        let path_c2s_0 = pipe.client.paths.get(pid_c2s_0).expect("no such path");
        let path_c2s_1 = pipe.client.paths.get(pid_c2s_1).expect("no such path");
        let path_s2c_0 = pipe.server.paths.get(pid_s2c_0).expect("no such path");

        assert_eq!(path_c2s_0.active(), true);
        assert_eq!(path_c2s_1.active(), true);
        assert_eq!(path_s2c_0.active(), true);

        assert_eq!(pipe.advance(), Ok(()));
        println!("pid_c2s_1: {:?}", pid_c2s_1);

        // The multicast channel sends some data to the client.
        let mut mc_pipe = [0u8; 4096];
        let mut back = [0u8; 4096];
        let data: Vec<_> = (0..255).collect();
        // mc_channel.channel.stream_send(1, &data, true).unwrap();
        mc_channel.channel.stream_send(1, &data, true).unwrap();
        let res = mc_channel.channel.send(&mut mc_pipe[..]);
        assert!(res.is_ok());
        let (written, info) = res.unwrap();
        println!("Written: {}", written);
        back.copy_from_slice(&mc_pipe[..]);
        let recv_info = RecvInfo {
            from: info.from,
            to: info.to,
            from_mc: false,
        };
        println!("-- Before client backup");
        let res = mc_channel
            .client_backup
            .recv(&mut back[..written], recv_info);
        assert!(res.is_ok());
        assert!(mc_channel.client_backup.stream_readable(1));
        println!("-- After client backup");

        let recv_info = RecvInfo {
            from: server_addr,
            to: client_addr_2,
            from_mc: true,
        };
        let res = pipe.client.recv(&mut mc_pipe[..written], recv_info);
        assert!(res.is_ok());
        let read = res.unwrap();
        println!("READ: {}", read);
        assert!(pipe.client.stream_readable(1));
        assert_eq!(
            pipe.client.stream_recv(1, &mut mc_pipe[..]),
            Ok((255, true))
        );
    }

    #[test]
    fn test_mc_channel_alone() {
        let mc_client_tp = MulticastClientTp::default();
        let mut server_config = get_test_mc_config(true, None);
        let mut client_config = get_test_mc_config(false, Some(&mc_client_tp));
        let mut mc_channel = get_test_mc_channel_source(
            &mut server_config,
            &mut client_config,
            false,
        )
        .unwrap();

        let data: Vec<_> = (0..255).collect();
        mc_channel.channel.stream_send(1, &data, true).unwrap();

        let mut pipe = [0u8; 4096];
        let (written, to) = mc_channel.channel.send(&mut pipe[..]).unwrap();

        let recv_info = RecvInfo {
            from: to.from,
            to: to.to,
            from_mc: false,
        };
        let res = mc_channel
            .client_backup
            .recv(&mut pipe[..written], recv_info);
        assert!(res.is_ok());
        assert_eq!(mc_channel.client_backup.readable().len(), 1);
        assert!(mc_channel.client_backup.stream_readable(1));

        // Send data on the second path.
        mc_channel.channel.stream_send(3, &data, true).unwrap();
        let res = mc_channel.channel.send_on_path(
            &mut pipe[..],
            Some(mc_channel.mc_path_peer),
            Some(mc_channel.mc_path_peer),
        );
        assert!(res.is_ok());
        let (written, to) = res.unwrap();

        let recv_info = RecvInfo {
            from: to.from,
            to: to.to,
            from_mc: false,
        };
        let res = mc_channel
            .client_backup
            .recv(&mut pipe[..written], recv_info);
        assert!(res.is_ok());
        assert_eq!(mc_channel.client_backup.readable().len(), 2);
        assert!(mc_channel.client_backup.stream_readable(3));
    }

    #[test]
    /// Tests the authentication process for data sent over the multicast
    /// channel in the multicast path.
    fn test_mc_channel_auth() {
        let mc_client_tp = MulticastClientTp::default();
        let mut server_config = get_test_mc_config(true, None);
        let mut client_config = get_test_mc_config(false, Some(&mc_client_tp));
        let mut mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(true, Some(&mc_client_tp));

        // Multicast path.
        let mut mc_channel = get_test_mc_channel_source(
            &mut server_config,
            &mut client_config,
            true,
        )
        .unwrap();

        // Copy the channel ID derived from the multicast channel.
        mc_announce_data.channel_id =
            mc_channel.mc_path_conn_id.0.as_ref().to_vec();

        // Copy the public key from the multicast channel.
        mc_announce_data.public_key = Some(
            mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .get_mc_pub_key()
                .unwrap()
                .to_vec(),
        );

        let mut pipe =
            testing::Pipe::with_config_and_scid_lengths(&mut config, 16, 16)
                .unwrap();
        assert_eq!(pipe.handshake(), Ok(()));

        // Server announces and client joins.
        pipe.server
            .mc_set_mc_announce_data(&mc_announce_data)
            .unwrap();
        let multicast = pipe.server.multicast.as_mut().unwrap();
        multicast.mc_channel_key = Some(mc_channel.master_secret.clone());
        assert!(pipe.advance().is_ok());

        // Client joins the multicast channel, and the server gives the master
        // key.
        pipe.client.mc_join_channel().unwrap();
        assert!(pipe.advance().is_ok());

        let reset_token = 0xffeeddccu128;
        let client_mc_announce = pipe
            .client
            .multicast
            .as_ref()
            .unwrap()
            .mc_announce_data
            .as_ref()
            .unwrap();
        let cid =
            ConnectionId::from_ref(&client_mc_announce.channel_id).into_owned();
        println!("Client will add this CID: {:?}", cid);
        pipe.client.new_source_cid(&cid, reset_token, true).unwrap();
        pipe.server.new_source_cid(&cid, reset_token, true).unwrap();

        let server_addr = testing::Pipe::server_addr();
        let client_addr_2 = "127.0.0.1:5678".parse().unwrap();

        assert_eq!(pipe.advance(), Ok(()));
        assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));
        assert_eq!(pipe.advance(), Ok(()));

        assert_eq!(
            pipe.client.set_active(client_addr_2, server_addr, true,),
            Ok(())
        );

        assert_eq!(pipe.advance(), Ok(()));

        // The multicast channel sends some data to the client.
        let mut mc_pipe = [0u8; 4096];
        let data: Vec<_> = (0..255).collect();

        mc_channel.channel.stream_send(1, &data, true).unwrap();
        let res = mc_channel.channel.send(&mut mc_pipe[..]);
        assert!(res.is_ok());
        let (written, _) = res.unwrap();

        let recv_info = RecvInfo {
            from: server_addr,
            to: client_addr_2,
            from_mc: true,
        };

        // First a message with an invalid authentication signature.
        // Change a byte in the signature.
        let mut mc_pipe2 = mc_pipe[..written].to_owned();
        mc_pipe2[written - 1] = mc_pipe2[written - 1].wrapping_add(1);
        let res = pipe.client.mc_recv(&mut mc_pipe2[..written], recv_info);
        assert_eq!(res, Err(Error::Multicast(MulticastError::McInvalidSign)));
        assert_eq!(pipe.client.readable().len(), 0);
        assert!(!pipe.client.stream_readable(1));

        // Change a byte in the packet.
        let mut mc_pipe2 = mc_pipe[..written].to_owned();
        mc_pipe2[5] = mc_pipe2[5].wrapping_add(1);
        let res = pipe.client.mc_recv(&mut mc_pipe2[..written], recv_info);
        assert_eq!(res, Err(Error::Multicast(MulticastError::McInvalidSign)));
        assert_eq!(pipe.client.readable().len(), 0);
        assert!(!pipe.client.stream_readable(1));

        // Now a valid signature.
        let res = pipe.client.mc_recv(&mut mc_pipe[..written], recv_info);
        assert!(res.is_ok());
        let read = res.unwrap();
        println!("READ: {}", read);
        assert!(pipe.client.stream_readable(1));
        assert_eq!(
            pipe.client.stream_recv(1, &mut mc_pipe[..]),
            Ok((255, true))
        );
    }
}
