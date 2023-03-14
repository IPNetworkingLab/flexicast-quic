//! Multicast extension for QUIC.

use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::BufRead;
use std::net::SocketAddr;
use std::time;

use crate::packet::Epoch;
use crate::rand::rand_bytes;
use crate::ranges;
use crate::ranges::RangeSet;
use crate::recovery::multicast::MulticastRecovery;
use crate::CongestionControlAlgorithm;
use networkcoding::source_symbol_metadata_from_u64;
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

    /// Invalid multipath path used, or invalid space id.
    McPath,

    #[cfg(test)]
    /// Error when initiating the multicast pipe.
    McPipe,
}

/// MC_ANNOUNCE frame type.
pub const MC_ANNOUNCE_CODE: u64 = 0xf3;
/// MC_STATE frame type.
pub const MC_STATE_CODE: u64 = 0xf4;
/// MC_KEY frame type.
pub const MC_KEY_CODE: u64 = 0xf5;
/// MC_EXPIRE frame type.
pub const MC_EXPIRE_CODE: u64 = 0xf6;

type ExpiredData = (Option<u64>, Option<u64>, Option<u64>);

/// States of a multicast client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum MulticastClientStatus {
    /// Leaving the multicast channel. The client waits for acknowledgment.
    /// In the meantime, the client can still listen to multicast traffic.
    /// The inner value is `true` if the client already sent the notification to
    /// the server.
    Leaving(bool),

    /// Left the multicast channel. Acknowledged by the unicast server.
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

    /// Has a multicast path. Listens to multicast data.
    ListenMcPath,

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

    /// Multicast path created.
    McPath,
}

impl TryFrom<u64> for MulticastClientAction {
    type Error = crate::Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => MulticastClientAction::Notify,
            1 => MulticastClientAction::Join,
            2 => MulticastClientAction::Leave,
            3 => MulticastClientAction::DecryptionKey,
            4 => MulticastClientAction::McPath,
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
            MulticastClientAction::McPath => 4,
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

    /// Space ID of the multicast path.
    mc_space_id: Option<usize>,

    /// Nack ranges received by the server from the client.
    /// Only present for the server unicast.
    /// For the client, it contains the last sent nack ranges.
    mc_nack_ranges: Option<RangeSet>,

    /// Last expired packet num (0) and stream ID (1).
    pub(crate) mc_last_expired: Option<ExpiredData>,

    /// Last expired data needs to trigger an MC_EXPIRE frame.
    pub(crate) mc_last_expired_needs_notif: bool,
}

impl MulticastAttributes {
    #[inline]
    /// Returns a reference to the MC_ANNOUNCE data.
    pub fn get_mc_announce_data(&self) -> Option<&McAnnounceData> {
        self.mc_announce_data.as_ref()
    }

    #[inline]
    /// Returns the current multicast role.
    pub fn get_mc_role(&self) -> MulticastRole {
        self.mc_role
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
        &mut self, action: MulticastClientAction, action_data: Option<u64>,
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
                MulticastClientStatus::ListenMcPath,
                MulticastClientAction::Leave,
            ) if !is_server => MulticastClientStatus::Leaving(false),
            (
                MulticastClientStatus::ListenMcPath,
                MulticastClientAction::Leave,
            ) if is_server => MulticastClientStatus::Left,
            (
                MulticastClientStatus::Leaving(false),
                MulticastClientAction::Leave,
            ) => MulticastClientStatus::Leaving(true),
            (
                MulticastClientStatus::Leaving(true),
                MulticastClientAction::Leave,
            ) => MulticastClientStatus::Left,
            (
                MulticastClientStatus::JoinedAndKey,
                MulticastClientAction::McPath,
            ) if action_data.is_some() => {
                self.mc_space_id = Some(action_data.unwrap() as usize);
                MulticastClientStatus::ListenMcPath
            },
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
    /// True if the client application explicitly asked to join the channel
    /// of if the client created the multicast path.
    pub fn should_send_mc_state(&self) -> bool {
        match self.mc_role {
            MulticastRole::Client(status) => match status {
                MulticastClientStatus::WaitingToJoin => true,
                MulticastClientStatus::JoinedAndKey
                    if self.mc_space_id.is_some() =>
                    true,
                MulticastClientStatus::Leaving(false) => true,
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
        matches!(
            self.mc_role,
            MulticastRole::ServerUnicast(MulticastClientStatus::JoinedNoKey)
        )
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

                self.update_client_state(
                    MulticastClientAction::DecryptionKey,
                    None,
                )?;
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
    pub fn get_mc_pub_key(&self) -> Option<&[u8]> {
        if self.mc_role == MulticastRole::ServerMulticast {
            if let Some(private_key) = self.mc_private_key.as_ref() {
                Some(private_key.public_key().as_ref())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Whether authentication is used to send packets.
    ///
    /// Only true for a multicast source that has a non-empty signature key.
    pub fn is_mc_source_and_auth(&self) -> bool {
        self.mc_role == MulticastRole::ServerMulticast &&
            self.mc_private_key.is_some()
    }

    /// Sets the multicast path space identifier.
    /// This is used to alwasy refer to the correct multicast path
    /// when processing packets.
    pub fn set_mc_space_id(&mut self, space_id: usize) {
        self.mc_space_id = Some(space_id);
    }

    /// Gets the multicast space ID.
    pub fn get_mc_space_id(&self) -> Option<usize> {
        self.mc_space_id
    }

    /// Sets the multicast nack ranges received from the client.
    /// Returns an error if it is not a [`ServerUnicast`].
    pub fn set_mc_nack_ranges(
        &mut self, ranges_opt: Option<&ranges::RangeSet>,
    ) -> Result<()> {
        if !matches!(
            self.mc_role,
            MulticastRole::ServerUnicast(_) | MulticastRole::Client(_)
        ) {
            return Err(Error::Multicast(MulticastError::McInvalidRole(
                self.mc_role,
            )));
        }

        if let Some(ranges) = ranges_opt {
            if let Some(current_ranges) = self.mc_nack_ranges.as_mut() {
                for range in ranges.iter() {
                    current_ranges.insert(range);
                }
            } else {
                self.mc_nack_ranges = Some(ranges.clone());
            }
        } else {
            self.mc_nack_ranges = None;
        }

        Ok(())
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
            mc_space_id: None,
            mc_nack_ranges: None,
            mc_last_expired: None,
            mc_last_expired_needs_notif: false,
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
    ///
    /// Also sets the multicast channel decryption key secret on the unicast
    /// server. MC-TODO: change the name to be more explicit.
    fn mc_set_multicast_receiver(&mut self, secret: &[u8]) -> Result<()>;

    /// Returns true if the multicast extension has control data to send.
    fn mc_has_control_data(&self) -> bool;

    /// Joins a multicast channel advertised by a server.
    /// Returns an Error if:
    /// * This is not a client
    /// * There is no multicast state with valid MC_ANNOUNCE data
    /// * The status is not AwareUnjoined
    fn mc_join_channel(&mut self) -> Result<MulticastClientStatus>;

    /// Leaves a previously joined multicast channel.
    /// Returns an Error if:
    /// * This is not a client
    /// * There is no multicst state with valid MC_ANNOUNCE data
    /// * The client did not joined the channel
    fn mc_leave_channel(&mut self) -> Result<MulticastClientStatus>;

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

    /// Returns an AckRange of packets that are considered as lost.
    /// Returns None if multicast is disabled or the caller has an invalid
    /// role. Also returns None if the nack range is empty.
    ///
    /// A packet is considered as lost if we see a gap in the packet number
    /// sequence. This implies that the packet number MUST be monotically
    /// increasing by 1.
    fn mc_nack_range(&self, epoch: Epoch, space_id: u64) -> Option<RangeSet>;

    /// Removes from internal state all frames and packet numbers
    /// before the argument values. This is used to ensure that a client
    /// does not ask for retransmission of too old data.
    /// This removes from the RangeSet the too old packet numbers and
    /// resets the streams having an ID below the given ID.
    ///
    /// Only availble for a multicast client.
    fn mc_expire(
        &mut self, epoch: Epoch, space_id: u64,
        expired_data: Option<&ExpiredData>, now: time::Instant,
    ) -> Result<ExpiredData>;

    /// Returns the amount of time until the next multicast timeout event.
    ///
    /// Once the given duration has elapsted, the [`on_mc_timeout()`] method
    /// should be called. A timeout of `None` means that the timer should be
    /// disarmed.
    fn mc_timeout(&self) -> Option<time::Duration>;

    /// Processes a multicast timeout event.
    ///
    /// If no timeout has occurred it does nothing.
    fn on_mc_timeout(&mut self, now: time::Instant) -> Result<ExpiredData>;

    /// Returns whether the path id given as argument is a multicast path.
    /// False if multicast is disabled or if the path is not a multicast path.
    fn is_mc_path(&self, space_id: usize) -> bool;

    /// Creates a multicast path on the client.
    /// This is done manually by the client without contacting the unicast
    /// server to avoid sharing a same path for the multicast and unicast
    /// source.
    fn create_mc_path(
        &mut self, cid: &ConnectionId, client_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<u64>;

    /// The unicast server connection sends control messages to the multicast
    /// source.
    ///
    /// Possible messages are:
    ///     * MC_NACK received from the client on the unicast channel
    ///
    /// Returns an error if this method is called by another entity than the
    /// unicast server.
    fn uc_to_mc_control(&mut self, mc_channel: &mut Connection) -> Result<()>;

    /// Returns the multicast attributes.
    fn get_multicast_attributes(&self) -> Option<&MulticastAttributes>;
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
                MulticastRole::ServerUnicast(_) => {
                    multicast.mc_channel_key = Some(secret.to_owned());

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
        if self.is_server && !self.local_transport_params.multicast_server_params
        {
            return Err(Error::Multicast(MulticastError::McDisabled));
        }

        if let Some(multicast) = self.multicast.as_mut() {
            if let MulticastRole::Client(_) = multicast.mc_role {
                if let Some(key_vec) = mc_announce_data.public_key.as_ref() {
                    // Client generates the public key from the received vector.
                    multicast.mc_public_key =
                        Some(signature::UnparsedPublicKey::new(
                            &signature::ED25519,
                            key_vec.to_owned(),
                        ));
                }
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
                mc_public_key: mc_announce_data.public_key.as_ref().map(
                    |key_vec| {
                        signature::UnparsedPublicKey::new(
                            &signature::ED25519,
                            key_vec.to_owned(),
                        )
                    },
                ),
                ..Default::default()
            });
        }

        Ok(())
    }

    fn mc_has_control_data(&self) -> bool {
        // MC-TODO: complete
        self.multicast.is_some() &&
            (self.mc_should_send_mc_announce() ||
                match self.multicast.as_ref() {
                    None => false,
                    Some(multicast) =>
                        multicast.should_send_mc_state() ||
                            multicast.should_send_mc_key() ||
                            self.mc_nack_range(
                                Epoch::Application,
                                multicast.mc_space_id.unwrap_or(0) as u64,
                            )
                            .is_some() ||
                            multicast.mc_last_expired_needs_notif,
                })
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
        multicast.update_client_state(MulticastClientAction::Join, None)
    }

    fn mc_leave_channel(&mut self) -> Result<MulticastClientStatus> {
        let multicast = match self.multicast.as_mut() {
            None => return Err(Error::Multicast(MulticastError::McDisabled)),
            Some(multicast) => match multicast.mc_role {
                MulticastRole::Client(MulticastClientStatus::ListenMcPath) =>
                    multicast,
                _ =>
                    return Err(Error::Multicast(MulticastError::McInvalidRole(
                        multicast.mc_role,
                    ))),
            },
        };
        multicast.update_client_state(MulticastClientAction::Leave, None)
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

    fn mc_nack_range(&self, epoch: Epoch, space_id: u64) -> Option<RangeSet> {
        if let Some(multicast) = self.multicast.as_ref() {
            if !matches!(multicast.mc_role, MulticastRole::Client(_)) {
                return None;
            }

            if let Ok(pns) = self.pkt_num_spaces.get(epoch, space_id) {
                let nack_range = pns.recv_pkt_need_ack.get_missing();
                if nack_range.len() == 0 {
                    None
                } else if multicast.mc_nack_ranges.as_ref() == Some(&nack_range) {
                    // Avoid sending exactly the same nack range as before.
                    println!("Same ranges as before {:?}", nack_range);
                    None
                } else {
                    Some(nack_range)
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    fn mc_expire(
        &mut self, epoch: Epoch, space_id: u64,
        expired_data: Option<&ExpiredData>, now: time::Instant,
    ) -> Result<ExpiredData> {
        let (mut pkt_num_opt, mut stream_id_opt, mut fec_metadata_opt) =
            expired_data.unwrap_or(&(None, None, None));

        let multicast = if let Some(multicast) = self.multicast.as_ref() {
            if !matches!(
                multicast.mc_role,
                MulticastRole::Client(MulticastClientStatus::ListenMcPath) |
                    MulticastRole::ServerMulticast,
            ) {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    multicast.mc_role,
                )));
            }
            multicast
        } else {
            return Err(Error::Multicast(MulticastError::McDisabled));
        };

        let hs_status = self.handshake_status();

        // Remove expired packets.
        if self.is_server {
            let p = self.paths.get_mut(space_id as usize)?;
            let res = p.recovery.mc_data_timeout(
                space_id as u32,
                now,
                multicast
                    .mc_announce_data
                    .as_ref()
                    .ok_or(Error::Multicast(MulticastError::McAnnounce))?
                    .ttl_data,
                hs_status,
            )?;
            pkt_num_opt = res.0;
            stream_id_opt = res.1;
            fec_metadata_opt = res.2;
        } else if let Some(exp_pkt_num) = pkt_num_opt {
            let pkt_num_space = self.pkt_num_spaces.get_mut(epoch, space_id)?;
            pkt_num_space.recv_pkt_need_ack.remove_until(exp_pkt_num);
            println!(
                "Remove packets until {} for space id {}",
                exp_pkt_num, space_id
            );
        }

        // Reset expired (but still open) streams.
        if let Some(exp_stream_id) = stream_id_opt {
            let iterable: Vec<_> = self
                .streams
                .iter()
                .map(|(stream_id, _)| *stream_id)
                .collect();
            for stream_id in iterable {
                if stream_id <= exp_stream_id {
                    let stream_opt = self.streams.get_mut(stream_id);
                    if let Some(stream) = stream_opt {
                        if self.is_server {
                            stream.send.reset()?;
                        } else {
                            // Maybe the final size is already known.
                            let final_size = stream.recv.max_off();
                            stream.recv.reset(0, final_size)?;
                        }
                        let local = stream.local;
                        self.streams.collect(stream_id, local);
                    };
                }
            }
        }

        // Reset FEC state to remove old source symbols.
        if let Some(exp_fec_metadata) = fec_metadata_opt {
            if self.is_server {
                // Reset FEC encoder state.
                self.fec_encoder
                    .remove_up_to(source_symbol_metadata_from_u64(
                        exp_fec_metadata,
                    ));
            } else {
                // Reset FEC decoder state.
                self.fec_decoder
                    .remove_up_to(source_symbol_metadata_from_u64(
                        exp_fec_metadata,
                    ));
            }
        }

        Ok((pkt_num_opt, stream_id_opt, fec_metadata_opt))
    }

    fn mc_timeout(&self) -> Option<time::Duration> {
        let space_id = self.multicast.as_ref()?.get_mc_space_id()?;
        self.paths
            .get(space_id)
            .ok()?
            .recovery
            .mc_next_timeout()
            .map(|timeout| {
                let now = time::Instant::now();

                if timeout <= now {
                    time::Duration::ZERO
                } else {
                    timeout.duration_since(now)
                }
            })
    }

    fn on_mc_timeout(&mut self, now: time::Instant) -> Result<ExpiredData> {
        // Some data has expired.
        if let Some(time::Duration::ZERO) = self.mc_timeout() {
            if let Some(multicast) = self.multicast.as_ref() {
                if let Some(space_id) = multicast.get_mc_space_id() {
                    let res = self.mc_expire(
                        Epoch::Application,
                        space_id as u64,
                        None,
                        now,
                    );
                    if let Ok(v) = res {
                        self.multicast.as_mut().unwrap().mc_last_expired =
                            Some(v);
                        self.multicast
                            .as_mut()
                            .unwrap()
                            .mc_last_expired_needs_notif =
                            v.0.is_some() || v.1.is_some() || v.2.is_some();
                        debug!(
                            "Last expired data updated: {:?}",
                            self.multicast.as_ref().unwrap().mc_last_expired
                        );
                        self.update_tx_cap();
                        return Ok(v);
                    }
                }
            }
        }

        Ok((None, None, None))
    }

    fn is_mc_path(&self, space_id: usize) -> bool {
        if let Some(multicast) = self.multicast.as_ref() {
            if let Some(mc_id) = multicast.get_mc_space_id() {
                return space_id == mc_id;
            }
        }
        false
    }

    fn create_mc_path(
        &mut self, cid: &ConnectionId, client_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<u64> {
        if let Some(multicast) = self.multicast.as_ref() {
            if !matches!(multicast.mc_role, MulticastRole::Client(_)) {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    multicast.mc_role,
                )));
            }
        }

        // Add the connection ID for the client without advertising it to the
        // unicast server.
        let mut reset_token = [0; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut reset_token)
            .unwrap();
        let reset_token = u128::from_be_bytes(reset_token);
        self.new_source_cid(cid, reset_token, true)?;
        let seq_num = self.ids.next_advertise_new_scid_seq().unwrap();
        self.ids.mark_advertise_new_scid_seq(seq_num, true);

        // Add the destination Connection ID.
        let conn_id = cid.as_ref().to_owned();
        self.ids.new_dcid(conn_id.into(), seq_num, reset_token, 0)?;

        // Create a new path on the client.
        let pid = self.create_path_on_client(client_addr, server_addr)?;
        self.set_active(client_addr, server_addr, true)?;

        let path = self.paths.get_mut(pid)?;
        let pid = path.active_dcid_seq.ok_or(Error::InvalidState)?;

        // Add the first packet number of interest for the new path if possible.
        if let Some((Some(first_pn), ..)) =
            self.multicast.as_ref().unwrap().mc_last_expired
        {
            self.pkt_num_spaces
                .get_mut_or_create(Epoch::Application, pid)
                .recv_pkt_need_ack
                .insert(first_pn..first_pn + 1);
        }

        self.multicast
            .as_mut()
            .unwrap()
            .set_mc_space_id(pid as usize);

        Ok(pid)
    }

    fn uc_to_mc_control(&mut self, mc_channel: &mut Connection) -> Result<()> {
        if let Some(multicast) = mc_channel.multicast.as_ref() {
            if !matches!(multicast.mc_role, MulticastRole::ServerMulticast) {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    MulticastRole::ServerMulticast,
                )));
            }
        } else {
            return Err(Error::Multicast(MulticastError::McDisabled));
        }

        if let Some(multicast) = self.multicast.as_mut() {
            if !matches!(multicast.mc_role, MulticastRole::ServerUnicast(_)) {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    MulticastRole::ServerUnicast(
                        MulticastClientStatus::Unspecified,
                    ),
                )));
            }

            // MC_NACK ranges.
            if let Some(nack_ranges) = multicast.mc_nack_ranges.as_mut() {
                // Filter from the nack ranges packets that are expired on the
                // source. This is necessary in case of
                // desynchronization with the client.
                if let Some((Some(last_expired_pn), ..)) =
                    mc_channel.multicast.as_ref().unwrap().mc_last_expired
                {
                    nack_ranges.remove_until(last_expired_pn + 1);
                }

                // The multicast source updates its FEC scheduler with the
                // received losses.
                let conn_id_ref = self.ids.get_dcid(0)?; // MC-TODO: replace hard-coded value.
                if let Some(fec_scheduler) = mc_channel.fec_scheduler.as_mut() {
                    fec_scheduler.lost_source_symbol(
                        nack_ranges,
                        conn_id_ref.cid.as_ref(),
                    );

                    // Reset nack ranges of the unicast server to avoid loops.
                    multicast.set_mc_nack_ranges(None)?;
                }
            }

            // Unicast connection asks for the oldest valid packet number of the
            // multicast path.
            if let Some((Some(pn), ..)) =
                mc_channel.multicast.as_ref().unwrap().mc_last_expired
            {
                if let Some((_, v, w)) = multicast.mc_last_expired {
                    multicast.mc_last_expired = Some((Some(pn), v, w));
                } else {
                    multicast.mc_last_expired = Some((Some(pn), None, None));
                }
            }
        } else {
            return Err(Error::Multicast(MulticastError::McDisabled));
        }

        Ok(())
    }

    fn get_multicast_attributes(&self) -> Option<&MulticastAttributes> {
        self.multicast.as_ref()
    }
}

/// Extension of a RangeSet to support missing ranges.
pub trait MissingRangeSet {
    /// Returns a RangeSet containing the numbers missing in the RangeSet.
    fn get_missing(&self) -> Self;
}

impl MissingRangeSet for ranges::RangeSet {
    fn get_missing(&self) -> Self {
        let mut missing = Self::default();

        // MC-TODO: find a better way to detect the lost frames.
        // Currently we simply iterate over the ranges of received packets and
        // add a range of lost packet with previous.last..current.first.
        let ranges: Vec<_> = self.iter().collect();

        // Returns no value if less than 2 elements.
        for range in ranges.windows(2) {
            let first = &range[0];
            let second = &range[1];
            missing.insert(first.end..second.start);
        }

        missing
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

    /// Multicast send address.
    pub mc_send_addr: SocketAddr,
}

impl MulticastChannelSource {
    /// Creates a new source multicast channel.
    pub fn new_with_tls(
        channel_id: &ConnectionId, config_server: &mut Config,
        config_client: &mut Config, peer: SocketAddr, peer2: SocketAddr,
        keylog_filename: &str, do_auth: bool,
    ) -> Result<Self> {
        if !(config_client.cc_algorithm == CongestionControlAlgorithm::DISABLED &&
            config_server.cc_algorithm == CongestionControlAlgorithm::DISABLED)
        {
            return Err(Error::CongestionControl);
        }

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

        let pid_c2s_1 = conn_client
            .paths
            .path_id_from_addrs(&(peer2, peer2))
            .expect("no such path");

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
        let cid = channel_id.clone().into_owned();

        let mut reset_token = [0; 16];
        rand_bytes(&mut reset_token);
        let reset_token = u128::from_be_bytes(reset_token);

        conn_server.multicast = Some(MulticastAttributes {
            mc_private_key: signature_eddsa,
            mc_role: MulticastRole::ServerMulticast,
            mc_space_id: Some(pid_c2s_1),
            ..Default::default()
        });

        Ok(Self {
            channel: conn_server,
            client_backup: conn_client,
            master_secret: exporter_secret,
            mc_path_conn_id: (cid, reset_token),
            mc_path_peer: peer2,
            mc_send_addr: peer,
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
    pub fn mc_send(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.channel
            .send_on_path(buf, Some(self.mc_path_peer), Some(self.mc_path_peer))
            .map(|(written, _)| written)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use ring::rand::SecureRandom;

    use crate::testing;
    use crate::testing::Pipe;
    use crate::Config;

    use super::*;

    /// Multicast extension of crate::testing::Pipe.
    ///
    /// Contains a Pipe for each unicast connection and multicast source
    /// channel. Performs the multicast extension negociation for each client
    /// in the pipe.
    pub struct MulticastPipe {
        pub unicast_pipes: Vec<(Pipe, SocketAddr, SocketAddr)>,
        pub mc_channel: MulticastChannelSource,
        pub mc_announce_data: McAnnounceData,
    }

    impl MulticastPipe {
        pub fn new(
            nb_clients: usize, keylog_filename: &str, do_auth: bool,
            use_fec: bool,
        ) -> Result<MulticastPipe> {
            let mc_client_tp = MulticastClientTp::default();
            let mut server_config = get_test_mc_config(true, None, use_fec);
            let mut client_config =
                get_test_mc_config(false, Some(&mc_client_tp), use_fec);
            let mut mc_announce_data = get_test_mc_announce_data();

            // Multicast path.
            let mut mc_channel = get_test_mc_channel_source(
                &mut server_config,
                &mut client_config,
                do_auth,
                keylog_filename,
            )
            .unwrap();

            // Copy the channel ID derived from the multicast channel.
            mc_announce_data.channel_id =
                mc_channel.mc_path_conn_id.0.as_ref().to_vec();

            mc_channel
                .channel
                .multicast
                .as_mut()
                .unwrap()
                .mc_announce_data = Some(mc_announce_data.clone());

            // Copy the public key from the multicast channel.
            if let Some(public_key) = mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .get_mc_pub_key()
            {
                mc_announce_data.public_key = Some(public_key.to_vec());
            }

            let pipes: Vec<_> = (0..nb_clients)
                .flat_map(|_| {
                    let mut config =
                        get_test_mc_config(true, Some(&mc_client_tp), true);
                    let mut pipe =
                        Pipe::with_config_and_scid_lengths(&mut config, 16, 16)
                            .ok()?;
                    pipe.handshake().ok()?;

                    pipe.server
                        .mc_set_mc_announce_data(&mc_announce_data)
                        .unwrap();
                    let multicast = pipe.server.multicast.as_mut().unwrap();
                    multicast.mc_channel_key =
                        Some(mc_channel.master_secret.clone());
                    assert!(pipe.advance().is_ok());

                    // Client joins the multicast channel, and the server gives
                    // the master key.
                    pipe.client.mc_join_channel().unwrap();
                    pipe.advance().unwrap();

                    let client_mc_announce = pipe
                        .client
                        .multicast
                        .as_ref()
                        .unwrap()
                        .mc_announce_data
                        .as_ref()
                        .unwrap();
                    let cid =
                        ConnectionId::from_ref(&client_mc_announce.channel_id)
                            .into_owned();

                    let server_addr = testing::Pipe::server_addr();
                    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();

                    pipe.client
                        .create_mc_path(&cid, client_addr_2, server_addr)
                        .unwrap();

                    let pid_c2s_1 = pipe
                        .client
                        .paths
                        .path_id_from_addrs(&(client_addr_2, server_addr))
                        .expect("no such path");

                    pipe.client
                        .multicast
                        .as_mut()
                        .unwrap()
                        .set_mc_space_id(pid_c2s_1);

                    assert_eq!(pipe.advance(), Ok(()));

                    Some((pipe, client_addr_2, server_addr))
                })
                .collect();

            if pipes.len() != nb_clients {
                return Err(Error::Multicast(MulticastError::McPipe));
            }

            Ok(MulticastPipe {
                unicast_pipes: pipes,
                mc_channel,
                mc_announce_data,
            })
        }

        /// The multicast source sends a single packet.
        /// Returns the number of bytes sent by the source.
        ///
        /// `client_loss` is a RangeSet containing the indexes of clients that
        /// DO NOT receive the packet. `None` if all clients receive the packet.
        fn source_send_single(
            &mut self, client_loss: Option<&RangeSet>, signature_len: usize,
        ) -> Result<usize> {
            let mut mc_buf = [0u8; 1500];
            let written = self.mc_channel.mc_send(&mut mc_buf[..])?;

            // This is not optimal but it works...
            let client_loss = if let Some(client_loss) = client_loss {
                client_loss.flatten().collect()
            } else {
                HashSet::new()
            };
            let idx_client_receive = (0..self.unicast_pipes.len())
                .filter(|&idx| !client_loss.contains(&(idx as u64)));

            for client_idx in idx_client_receive {
                let mut recv_buf = mc_buf.clone();
                let (pipe, client_addr, server_addr) =
                    self.unicast_pipes.get_mut(client_idx as usize).unwrap();

                let recv_info = RecvInfo {
                    from: *server_addr,
                    to: *client_addr,
                    from_mc: true,
                };

                let res = pipe
                    .client
                    .mc_recv(&mut recv_buf[..written], recv_info)
                    .unwrap();
                assert_eq!(res, written - signature_len);
            }

            Ok(written)
        }

        /// The multicast source sends a single small stream of 300 bytes to fit
        /// in a single QUIC packet.
        /// Calls [`MulticastPipe::source_send_single`].
        ///
        /// `client_loss` is a RangeSet containing the indexes of clients that
        /// DO NOT receive the packet. `None` if all clients receive the packet.
        fn source_send_single_stream(
            &mut self, client_loss: Option<&RangeSet>, signature_len: usize,
            stream_id: u64,
        ) -> Result<usize> {
            let mut mc_buf = [0u8; 300];
            ring::rand::SystemRandom::new()
                .fill(&mut mc_buf[..])
                .unwrap();
            self.mc_channel.channel.stream_send(
                stream_id,
                &mut mc_buf[..],
                true,
            )?;

            self.source_send_single(client_loss, signature_len)
        }

        /// The clients send feedback using the unicast connection to the
        /// server.
        fn clients_send(&mut self) -> Result<()> {
            let mut buf = [0u8; 1500];
            for (pipe, ..) in self.unicast_pipes.iter_mut() {
                loop {
                    let (written, send_info) = match pipe.client.send(&mut buf) {
                        Ok(v) => v,
                        Err(Error::Done) => break,
                        Err(e) => return Err(e),
                    };

                    let recv_info = RecvInfo {
                        from: send_info.from,
                        to: send_info.to,
                        from_mc: false,
                    };

                    pipe.server.recv(&mut buf[..written], recv_info)?;

                    // The unicast server propagates potential NACK to the
                    // server. MC-TODO.
                }
            }

            Ok(())
        }

        /// UnicasT server sends multicast feedback control from the client to
        /// the multicast source.
        fn server_control_to_mc_source(&mut self) -> Result<()> {
            let mc_channel = &mut self.mc_channel.channel;
            for (pipe, ..) in self.unicast_pipes.iter_mut() {
                pipe.server.uc_to_mc_control(mc_channel)?;
            }

            Ok(())
        }

        // MC-TODO: maybe a new_from_mc_announce_data.
    }

    /// Simple config used for testing the multicast extension only.
    pub fn get_test_mc_config(
        mc_server: bool, mc_client: Option<&MulticastClientTp>, use_fec: bool,
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
        config.set_active_connection_id_limit(5);
        config.verify_peer(false);
        config.set_multipath(true);
        config.set_enable_server_multicast(mc_server);
        config.set_enable_client_multicast(mc_client);
        config.send_fec(use_fec);
        config.receive_fec(use_fec);
        config.set_fec_scheduler_algorithm(
            crate::fec::fec_scheduler::FECSchedulerAlgorithm::RetransmissionFec,
        );
        config.set_fec_symbol_size(1280 - 64); // MC-TODO: make dynamic with auth.
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
            public_key: None,
            ttl_data: 1_000_000,
        }
    }

    /// Simple source multicast channel for the tests.
    fn get_test_mc_channel_source(
        config_server: &mut Config, config_client: &mut Config, do_auth: bool,
        keylog_filename: &str,
    ) -> Result<MulticastChannelSource> {
        // Set the disabled congestion control for the multicast channel.
        config_client.set_cc_algorithm(CongestionControlAlgorithm::DISABLED);
        config_server.set_cc_algorithm(CongestionControlAlgorithm::DISABLED);
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
            keylog_filename,
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
        let mut config = get_test_mc_config(true, Some(&mc_client_tp), false);

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
        let mut config = get_test_mc_config(true, Some(&mc_client_tp), false);

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
        let mut config = get_test_mc_config(true, Some(&mc_client_tp), false);

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
            multicast.update_client_state(MulticastClientAction::Join, None),
            Err(Error::Multicast(MulticastError::McInvalidAction))
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Leave, None),
            Err(Error::Multicast(MulticastError::McInvalidAction))
        );

        assert_eq!(
            multicast
                .update_client_state(MulticastClientAction::DecryptionKey, None),
            Err(Error::Multicast(MulticastError::McInvalidAction))
        );

        // This is a good move.
        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Notify, None),
            Ok(MulticastClientStatus::AwareUnjoined)
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Join, None),
            Ok(MulticastClientStatus::WaitingToJoin)
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Join, None),
            Ok(MulticastClientStatus::JoinedNoKey)
        );

        assert_eq!(
            multicast
                .update_client_state(MulticastClientAction::DecryptionKey, None),
            Ok(MulticastClientStatus::JoinedAndKey)
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::McPath, Some(1)),
            Ok(MulticastClientStatus::ListenMcPath)
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Leave, None),
            Ok(MulticastClientStatus::Leaving(false))
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Leave, None),
            Ok(MulticastClientStatus::Leaving(true))
        );

        assert_eq!(
            multicast.update_client_state(MulticastClientAction::Leave, None),
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
        let mut config = get_test_mc_config(true, Some(&mc_client_tp), false);

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
        let mut server_config = get_test_mc_config(true, None, false);
        let mut client_config =
            get_test_mc_config(false, Some(&mc_client_tp), false);

        let mc_channel = get_test_mc_channel_source(
            &mut server_config,
            &mut client_config,
            false,
            "/tmp/test_mc_channel_server_handshake.txt",
        );
        assert!(mc_channel.is_ok());
    }

    #[test]
    fn test_mc_channel_alone() {
        let mc_client_tp = MulticastClientTp::default();
        let mut server_config = get_test_mc_config(true, None, false);
        let mut client_config =
            get_test_mc_config(false, Some(&mc_client_tp), false);
        let mut mc_channel = get_test_mc_channel_source(
            &mut server_config,
            &mut client_config,
            false,
            "/tmp/test_mc_channel_alone.txt",
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
        let mc_pipe =
            MulticastPipe::new(1, "/tmp/test_mc_channel_auth.txt", true, false);
        assert!(mc_pipe.is_ok());
        let mut mc_pipe = mc_pipe.unwrap();

        let mc_channel = &mut mc_pipe.mc_channel;
        let uc_pipe = &mut mc_pipe.unicast_pipes[0];
        let pipe = &mut uc_pipe.0;
        let client_addr_2 = uc_pipe.1;
        let server_addr = uc_pipe.2;

        // The multicast channel sends some data to the client.
        let mut mc_buf = [0u8; 4096];
        let data: Vec<_> = (0..255).collect();

        mc_channel.channel.stream_send(1, &data, true).unwrap();
        let res = mc_channel.mc_send(&mut mc_buf[..]);
        assert!(res.is_ok());
        let written = res.unwrap();

        let recv_info = RecvInfo {
            from: server_addr,
            to: client_addr_2,
            from_mc: true,
        };

        // First a message with an invalid authentication signature.
        // Change a byte in the signature.
        let mut mc_buf2 = mc_buf[..written].to_owned();
        mc_buf2[written - 1] = mc_buf2[written - 1].wrapping_add(1);
        let res = pipe.client.mc_recv(&mut mc_buf2[..written], recv_info);
        assert_eq!(res, Err(Error::Multicast(MulticastError::McInvalidSign)));
        assert_eq!(pipe.client.readable().len(), 0);
        assert!(!pipe.client.stream_readable(1));

        // Change a byte in the packet.
        let mut mc_buf2 = mc_buf[..written].to_owned();
        mc_buf2[5] = mc_buf2[5].wrapping_add(1);
        let res = pipe.client.mc_recv(&mut mc_buf2[..written], recv_info);
        assert_eq!(res, Err(Error::Multicast(MulticastError::McInvalidSign)));
        assert_eq!(pipe.client.readable().len(), 0);
        assert!(!pipe.client.stream_readable(1));

        // Now a valid signature.
        let res = pipe.client.mc_recv(&mut mc_buf[..written], recv_info);
        assert!(res.is_ok());
        assert!(pipe.client.stream_readable(1));
        assert_eq!(pipe.client.stream_recv(1, &mut mc_buf[..]), Ok((255, true)));
    }

    #[test]
    fn test_missing_range_set() {
        let mut r = RangeSet::default();

        r.insert(4..7);
        r.insert(9..12);
        r.insert(15..20);
        r.insert(16..21);
        r.insert(22..30);
        r.insert(30..34);
        r.insert(36..40);

        let missing = r.get_missing();
        assert_eq!(&missing.flatten().collect::<Vec<u64>>(), &[
            7, 8, 12, 13, 14, 21, 34, 35
        ]);
    }

    #[test]
    /// Tests that the client will correctly generates an MC_NACK to the server.
    fn test_mc_nack() {
        let use_auth = false;
        let mut mc_pipe =
            MulticastPipe::new(1, "/tmp/test_mc_nack.txt", use_auth, false)
                .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };

        let mc_channel = &mut mc_pipe.mc_channel;
        let uc_pipe = &mut mc_pipe.unicast_pipes[0];
        let pipe = &mut uc_pipe.0;
        let client_addr_2 = uc_pipe.1;
        let server_addr = uc_pipe.2;
        let mut mc_buf = [0u8; 4096];

        let mut data = [0u8; 4000];
        ring::rand::SystemRandom::new().fill(&mut data[..]).unwrap();

        mc_channel.channel.stream_send(1, &data, true).unwrap();
        let recv_info = RecvInfo {
            from: server_addr,
            to: client_addr_2,
            from_mc: true,
        };

        let client_mc_space_id =
            pipe.client.multicast.as_ref().unwrap().get_mc_space_id();
        assert_eq!(client_mc_space_id, Some(1));
        let client_mc_space_id = client_mc_space_id.unwrap();

        // The source multicast sends multiple packets. The second is lost to
        // trigger the nack.
        let res = mc_channel.mc_send(&mut mc_buf[..]);
        assert_eq!(res, Ok(1350));
        let written = res.unwrap();

        let res = pipe.client.mc_recv(&mut mc_buf[..written], recv_info);
        assert_eq!(res, Ok(written - signature_len));

        // Second packet... lost
        let res = mc_channel.mc_send(&mut mc_buf[..]);
        assert_eq!(res, Ok(1350));

        // Third packet... received.
        let res = mc_channel.mc_send(&mut mc_buf[..]);
        assert_eq!(res, Ok(1350));
        let written = res.unwrap();

        let res = pipe.client.mc_recv(&mut mc_buf[..written], recv_info);
        assert_eq!(res, Ok(written - signature_len));

        // The client sees a gap in the ack ranges.
        let nack_ranges = pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);

        let mut expected_range_set = ranges::RangeSet::default();
        expected_range_set.insert(3..4);
        assert_eq!(nack_ranges, Some(expected_range_set));
    }

    #[test]
    /// Tests the process of MC_EXPIRE from the server to the client.
    /// The server sends an MC_EXPIRE when the data expires with the `ttl_data`
    /// value of the multicast attributes.
    fn test_on_mc_timeout() {
        let use_auth = false;
        let mut mc_pipe =
            MulticastPipe::new(1, "/tmp/test_mc_expire.txt", use_auth, false)
                .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };

        let mc_channel = &mut mc_pipe.mc_channel;
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        let mut data = [0u8; 4000];
        ring::rand::SystemRandom::new().fill(&mut data[..]).unwrap();

        mc_channel.channel.stream_send(1, &data, true).unwrap();

        // First packet is received.
        let res = mc_pipe.source_send_single(None, signature_len);
        assert_eq!(res, Ok(1350));

        // Second packet is lost.
        let res = mc_pipe
            .source_send_single(Some(&clients_losing_packets), signature_len);
        assert_eq!(res, Ok(1350));

        // Third packet is lost.
        let res = mc_pipe
            .source_send_single(Some(&clients_losing_packets), signature_len);
        assert_eq!(res, Ok(1350));

        // Last packet is received.
        let res = mc_pipe.source_send_single(None, signature_len);
        assert_eq!(res, Ok(109));

        // The stream is is still open.
        assert!(!mc_pipe.mc_channel.channel.stream_finished(1));
        assert!(!mc_pipe.unicast_pipes[0].0.client.stream_finished(1));

        // The expiration timeout is exceeded. Closes the stream and removes the
        // packets from the sending queue.
        let now = time::Instant::now();
        let expired_timer = now +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.ttl_data + 100,
            ); // Margin
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired_timer);
        assert_eq!(res, Ok((Some(5), Some(1), None)));

        // MC-TODO: assert that the packets are not in the sending state anymore.
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(5), Some(1), None))
        );

        // The stream is closed now.
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_writable(1, 0),
            Err(Error::InvalidStreamState(1))
        );

        // The multicast source sends an MC_EXPIRE to the client.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(56));

        // The stream is also closed on the client now.
        assert!(mc_pipe.unicast_pipes[0].0.client.stream_finished(1));

        // Send another stream that will timeout without receiving the end of the
        // stream.
        let mc_channel = &mut mc_pipe.mc_channel;
        ring::rand::SystemRandom::new().fill(&mut data[..]).unwrap();
        mc_channel.channel.stream_send(3, &data, false).unwrap();

        // First packet is received.
        let res = mc_pipe.source_send_single(None, signature_len);
        assert_eq!(res, Ok(1350));

        // Second packet is lost.
        let res = mc_pipe
            .source_send_single(Some(&clients_losing_packets), signature_len);
        assert_eq!(res, Ok(1350));

        // Third packet is lost.
        let res = mc_pipe
            .source_send_single(Some(&clients_losing_packets), signature_len);
        assert_eq!(res, Ok(1350));

        // Fourth packet is lost.
        // At this stage, all stream data has been sent but the stream is not
        // finished.
        let res = mc_pipe
            .source_send_single(Some(&clients_losing_packets), signature_len);
        assert_eq!(res, Ok(109));

        // The stream is is still open.
        assert!(!mc_pipe.mc_channel.channel.stream_finished(3));
        assert!(!mc_pipe.unicast_pipes[0].0.client.stream_finished(3));

        // The expiration timeout is exceeded. Closes the stream and removes the
        // packets from the sending queue.
        let now = time::Instant::now();
        let expired_timer = now +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.ttl_data + 100,
            ); // Margin
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired_timer);
        assert_eq!(res, Ok((Some(10), Some(3), None)));

        // MC-TODO: assert that the packets are not in the sending state anymore.
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(10), Some(3), None))
        );

        // The stream is closed now.
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_writable(3, 0),
            Err(Error::InvalidStreamState(3))
        );

        // The multicast source sends an MC_EXPIRE to the client.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(56));

        // The stream is also closed on the client now.
        assert!(mc_pipe.unicast_pipes[0].0.client.stream_finished(3));
    }

    #[test]
    /// Tests the multicast source sending multiple short streams and some of
    /// them expire.
    fn test_mc_multiple_streams_expire() {
        let use_auth = false;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_multiple_streams_expire.txt",
            use_auth,
            false,
        )
        .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };

        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 1),
            Ok(339)
        );

        // Second stream is not received.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                3
            ),
            Ok(339)
        );

        // Third stream is not received.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                5
            ),
            Ok(339)
        );

        // Fourth stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 7),
            Ok(339)
        );

        // Fifth stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 9),
            Ok(339)
        );

        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![1, 7, 9]);

        let client_mc_space_id = uc_pipe
            .client
            .multicast
            .as_ref()
            .unwrap()
            .get_mc_space_id()
            .unwrap();
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        let mut expected_ranges = ranges::RangeSet::default();
        expected_ranges.insert(3..5);
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        let timer = time::Instant::now();
        let timer = timer +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.ttl_data + 100,
            );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((Some(6), Some(9), None)));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(6), Some(9), None))
        );

        // Multicast source sends an MC_EXPIRE to the client.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(56));

        // Sixth stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 11),
            Ok(339)
        );

        let open_streams = mc_pipe
            .mc_channel
            .channel
            .streams
            .iter()
            .map(|(sid, _)| *sid)
            .collect::<Vec<_>>();
        assert_eq!(open_streams, vec![11]);

        // The client has no missing packet.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        assert_eq!(nack_ranges.as_ref(), None);

        // Only the last stream did not timeout.
        // All timeout streams are still redeables but finished.
        let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![1, 7, 9, 11]);
        assert!(uc_pipe.client.stream_finished(1));
        assert!(uc_pipe.client.stream_finished(7));
        assert!(uc_pipe.client.stream_finished(9));
    }

    #[test]
    fn test_mc_client_nack_to_source_and_recovery() {
        let use_auth = false;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_client_nack_to_source_and_recovery.txt",
            use_auth,
            true,
        )
        .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First two streams are received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 1),
            Ok(348)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 3),
            Ok(348)
        );

        // Third and fourth streams are lost.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                5
            ),
            Ok(348)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                7
            ),
            Ok(348)
        );

        // Fifth stream is received and triggers NACK from the client.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 9),
            Ok(348)
        );

        // The client has correctly received the three streams.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![1, 3, 9]);

        // And has a NACK range for the lost streams.
        let client_mc_space_id = uc_pipe
            .client
            .multicast
            .as_ref()
            .unwrap()
            .get_mc_space_id()
            .unwrap();
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        let mut expected_ranges = ranges::RangeSet::default();
        expected_ranges.insert(4..6);
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        // The client generates an MC_NACK frame.
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // The client stores the last sent nack ranges.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        assert_eq!(
            uc_pipe
                .client
                .multicast
                .as_ref()
                .unwrap()
                .mc_nack_ranges
                .as_ref(),
            Some(&expected_ranges)
        );

        // The unicast server receives the MC_NACK.
        let nack_on_source = uc_pipe
            .server
            .multicast
            .as_ref()
            .unwrap()
            .mc_nack_ranges
            .as_ref();
        assert_eq!(nack_on_source, Some(&expected_ranges));

        // The unicast server forwards information to the multicast source.
        assert_eq!(mc_pipe.server_control_to_mc_source(), Ok(()));

        // The server generates FEC repair packets and forwards them to the
        // client.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1271));
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1271));
        // No need to send additional repair symbols.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Err(Error::Done)
        );

        // The client recovers the lost packets with FEC.
        // This results in receiving all streams.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![1, 3, 5, 7, 9]);
        assert_eq!(uc_pipe.client.recov_count, 2);

        // And the client has no lost packets anymore.
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        assert_eq!(nack_ranges.as_ref(), None);
    }

    #[test]
    /// Tests client MC_NACK feedback on the server with multiple clients losing
    /// different packets. Additionally, it uses authentication.
    /// MC-TODO: currently with authentication the test fails because the
    /// signature takes too much room for the REPAIR frames.
    fn test_mc_fec_reliable_multiple_clients_with_auth() {
        let use_auth = true;
        let mut mc_pipe = MulticastPipe::new(
            2,
            "/tmp/test_mc_fec_reliable_multiple_clients_with_auth.txt",
            use_auth,
            true,
        )
        .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };
        let mut client_loss_0 = RangeSet::default();
        client_loss_0.insert(0..1);
        let mut client_loss_1 = RangeSet::default();
        client_loss_1.insert(1..2);
        let mut client_loss_all = RangeSet::default();
        client_loss_all.insert(0..2);

        // First stream is received by both clients.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Second stream is received by the second client only.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&client_loss_0),
                signature_len,
                3
            ),
            Ok(348 + signature_len),
        );

        // Third stream is lost by the first client only.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&client_loss_1),
                signature_len,
                5
            ),
            Ok(348 + signature_len)
        );

        // Fourth stream is received by none client.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&client_loss_all),
                signature_len,
                7
            ),
            Ok(348 + signature_len)
        );

        // Fifth stream is received by both.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 9),
            Ok(348 + signature_len)
        );

        // The first client has received 3 streams.
        let uc_pipe_0 = &mc_pipe.unicast_pipes.get(0).unwrap().0;
        let mut readables = uc_pipe_0.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![1, 5, 9]);

        // And has a NACK range for the lost streams.
        let client_mc_space_id_0 = uc_pipe_0
            .client
            .multicast
            .as_ref()
            .unwrap()
            .get_mc_space_id()
            .unwrap();
        let nack_ranges = uc_pipe_0
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id_0 as u64);
        let mut expected_ranges = ranges::RangeSet::default();
        expected_ranges.insert(3..4);
        expected_ranges.insert(5..6);
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        // The second client has received 2 streams.
        let uc_pipe_1 = &mc_pipe.unicast_pipes.get(1).unwrap().0;
        let mut readables = uc_pipe_1.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![1, 3, 9]);

        // And has a NACK range for the lost streams.
        let client_mc_space_id_1 = uc_pipe_1
            .client
            .multicast
            .as_ref()
            .unwrap()
            .get_mc_space_id()
            .unwrap();
        let nack_ranges = uc_pipe_1
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id_1 as u64);
        let mut expected_ranges = ranges::RangeSet::default();
        expected_ranges.insert(4..6);
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        // The clients generate an MC_NACK frame.
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // MC-TODO: verify that both servers have the correct nack ranges.

        // Communication to unicast servers.
        assert_eq!(mc_pipe.server_control_to_mc_source(), Ok(()));

        // The server generates FEC repair packets and forwards them to the
        // client. Only two repair symbols are needed.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1335));
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1335));
        // No need to send additional repair symbols.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Err(Error::Done)
        );

        // The clients recover the lost packets with FEC.
        // Even if the lost packet were not the same, both clients recover all of
        // them using FEC. This results in receiving all streams.
        for (uc_pipe, ..) in mc_pipe.unicast_pipes.iter_mut() {
            let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![1, 3, 5, 7, 9]);
            assert_eq!(uc_pipe.client.recov_count, 2);

            // And the clients have no lost packets anymore.
            let client_mc_space_id = uc_pipe
                .client
                .multicast
                .as_ref()
                .unwrap()
                .get_mc_space_id()
                .unwrap();
            let nack_ranges = uc_pipe
                .client
                .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
            assert_eq!(nack_ranges.as_ref(), None);
        }
    }

    #[test]
    /// Tests the reset of the FEC state upon data timeout.
    fn test_mc_fec_on_mc_timeout() {
        let use_auth = true;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_fec_on_mc_timeout.txt",
            use_auth,
            true,
        )
        .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Two consecutive streams are lost.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                3
            ),
            Ok(348 + signature_len)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                5
            ),
            Ok(348 + signature_len)
        );

        // A last stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 7),
            Ok(348 + signature_len)
        );

        // The client has two missing packets.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let client_mc_space_id = uc_pipe
            .client
            .multicast
            .as_ref()
            .unwrap()
            .get_mc_space_id()
            .unwrap();
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        let mut expected_ranges = ranges::RangeSet::default();
        expected_ranges.insert(3..5);
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        // Timeout of the four streams.
        let timer = time::Instant::now();
        let timer = timer +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.ttl_data + 100,
            );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((Some(5), Some(7), Some(3))));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(5), Some(7), Some(3)))
        );

        // Multicast source sends an MC_EXPIRE to the client.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Ok(57 + signature_len)
        );

        // The client has no missing packet.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        assert_eq!(nack_ranges.as_ref(), None);

        // The server sends a stream of 4 packets.
        let mut data = [0u8; 4000];
        ring::rand::SystemRandom::new().fill(&mut data[..]).unwrap();
        mc_pipe
            .mc_channel
            .channel
            .stream_send(9, &data, true)
            .unwrap();

        // MC-TODO: because the client received the packet containing the
        // MC_EXPIRE frame, it has received the packet with packet number=6. It is
        // thanks to this packet that the client knows that the packet with packet
        // number=7 is lost, otherwise it would think that it joined the multicast
        // channel 'late'. Should we fix this in the future?
        // First packet is lost.
        assert_eq!(
            mc_pipe
                .source_send_single(Some(&clients_losing_packets), signature_len),
            Ok(1314)
        );

        // All subsequent packets are received.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1314));
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1314));
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(509));

        // The client knows that they lost the first packet.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        let mut expected_ranges = ranges::RangeSet::default();
        expected_ranges.insert(7..8);
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        // The client sends an MC_NACK to the server.
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // Communication to unicast servers.
        assert_eq!(mc_pipe.server_control_to_mc_source(), Ok(()));

        // The server generates FEC a single repair packet because the client lost
        // the first frame of the stream. Recall that the previous packets have
        // been removed due to a timeout.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1335));
        // No need to send additional repair symbols.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Err(Error::Done)
        );

        // The client recovers the lost packet and can read the stream.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        assert_eq!(nack_ranges.as_ref(), None);
        let mut tmp_buf = [42u8; 4096];
        assert_eq!(
            uc_pipe.client.stream_recv(9, &mut tmp_buf[..]),
            Ok((4000, true))
        );
        assert_eq!(tmp_buf[..4000], data[..4000]);
    }

    #[test]
    /// Tests the case where the client did not receive the MC_EXPIRE from the
    /// multicast source. In this case, they will send an MC_NACK frame with
    /// expired packet numbers. The server must not generate FEC repair symbols
    /// for these lost source symbols that are expired.
    fn source_does_not_generate_mc_fec_repair_for_expired() {
        let use_auth = true;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/source_does_not_generate_mc_fec_repair_for_expired.txt",
            use_auth,
            true,
        )
        .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Two consecutive streams are lost.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                3
            ),
            Ok(348 + signature_len)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                5
            ),
            Ok(348 + signature_len)
        );

        // A last stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 7),
            Ok(348 + signature_len)
        );

        // The client has two missing packets.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let client_mc_space_id = uc_pipe
            .client
            .multicast
            .as_ref()
            .unwrap()
            .get_mc_space_id()
            .unwrap();
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        let mut expected_ranges = ranges::RangeSet::default();
        expected_ranges.insert(3..5);
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        // Timeout of the three streams.
        let timer = time::Instant::now();
        let timer = timer +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.ttl_data + 100,
            );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((Some(5), Some(7), Some(3))));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(5), Some(7), Some(3)))
        );

        // Multicast source sends an MC_EXPIRE. The packet is lost.
        assert_eq!(
            mc_pipe
                .source_send_single(Some(&clients_losing_packets), signature_len),
            Ok(57 + signature_len)
        );

        // The client still has two lost packets.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        // The server sends a stream of 4 packets.
        let mut data = [0u8; 4000];
        ring::rand::SystemRandom::new().fill(&mut data[..]).unwrap();
        mc_pipe
            .mc_channel
            .channel
            .stream_send(9, &data, true)
            .unwrap();

        // First packet is lost.
        assert_eq!(
            mc_pipe
                .source_send_single(Some(&clients_losing_packets), signature_len),
            Ok(1314)
        );

        // All subsequent packets are received.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1314));
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1314));
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(509));

        // The client knows that they lost the first packet of the new stream, but
        // also the two older (and expired!) packets because they did not receive
        // the MC_EXPIRE frame from the multicast source..
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        expected_ranges.insert(6..8); // The client also lost the packet with the MC_EXPIRE.
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        // The client sends an MC_NACK to the server.
        // This MC_NACK also contains expired data.
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // Communication to unicast servers.
        assert_eq!(mc_pipe.server_control_to_mc_source(), Ok(()));

        // The server generates FEC a single repair packet because the client lost
        // the first frame of the stream. Recall that the previous packets have
        // been removed due to a timeout. Even if the MC_NACK of the client
        // contains more packets, the source filters them out.
        // MC-TODO: verify the nack ranges on the source to be sure?
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1335));
        // No need to send additional repair symbols.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Err(Error::Done)
        );

        // The client recovers the lost packet and can read the stream.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        assert_eq!(nack_ranges.as_ref(), None);
        let mut tmp_buf = [42u8; 4096];
        assert_eq!(
            uc_pipe.client.stream_recv(9, &mut tmp_buf[..]),
            Ok((4000, true))
        );
        assert_eq!(tmp_buf[..4000], data[..4000]);
    }

    #[test]
    /// The `first_pn` value of the MC_KEY frame enables the client to detect
    /// lost packets even if the first multicast packets are lost.
    fn test_mc_client_first_pn_utility() {
        let use_auth = true;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/source_does_not_generate_mc_fec_repair_for_expired.txt",
            use_auth,
            true,
        )
        .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First two streams are lost.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                1
            ),
            Ok(348 + signature_len)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(
                Some(&clients_losing_packets),
                signature_len,
                3
            ),
            Ok(348 + signature_len)
        );

        // Third stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 5),
            Ok(348 + signature_len)
        );

        // With the first packet from the MC_KEY frame, the client detects the two
        // first missing packets.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let client_mc_space_id = uc_pipe
            .client
            .multicast
            .as_ref()
            .unwrap()
            .get_mc_space_id()
            .unwrap();
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        let mut expected_ranges = ranges::RangeSet::default();
        expected_ranges.insert(2..4);
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));
    }

    #[test]
    /// Tests the client leaving the multicast channel.
    fn test_client_leave_mc_channel() {
        let use_auth = true;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_client_leave_mc_channel.txt",
            use_auth,
            true,
        )
        .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };

        // First stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Second stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 3),
            Ok(348 + signature_len)
        );

        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![1, 3]);

        let client_mc_space_id = uc_pipe
            .client
            .multicast
            .as_ref()
            .unwrap()
            .get_mc_space_id()
            .unwrap();
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        assert_eq!(nack_ranges.as_ref(), None);

        // Client leaves the multicast channel.
        assert_eq!(
            uc_pipe.client.mc_leave_channel(),
            Ok(MulticastClientStatus::Leaving(false))
        );

        // The client notifies the unicast server.
        assert_eq!(uc_pipe.advance(), Ok(()));

        // The client has left the multicast channel.
        assert_eq!(
            uc_pipe.client.multicast.as_ref().unwrap().mc_role,
            MulticastRole::Client(MulticastClientStatus::Left)
        );
        assert_eq!(
            uc_pipe.server.multicast.as_ref().unwrap().mc_role,
            MulticastRole::ServerUnicast(MulticastClientStatus::Left)
        );
    }

    #[test]
    /// Test the MC_EXPIRE mechanism. After a first MC_EXPIRE is sent, if no
    /// further data is expired, the source must not send an MC_EXPIRE. This
    /// test is created to fix an existing issue in the code at the time of
    /// writing.
    fn test_mc_expire_do_not_send_useless() {
        let use_auth = true;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_expire_do_not_send_useless.txt",
            use_auth,
            true,
        )
        .unwrap();
        let signature_len = if use_auth { 64 } else { 0 };

        // Source sends one stream.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Expiration of the stream.
        let timer = time::Instant::now();
        let timer = timer +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.ttl_data + 100,
            );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((Some(2), Some(1), Some(0))));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(2), Some(1), Some(0)))
        );

        // Multicast source sends an MC_EXPIRE to the client.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Ok(57 + signature_len)
        );

        // Send new stream.
        assert_eq!(
            mc_pipe.source_send_single_stream(None, signature_len, 5),
            Ok(348 + signature_len)
        );

        // New timer triggering but no expiration.
        let timer = time::Instant::now();
        let timer = timer + time::Duration::from_millis(5);
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((None, None, None)));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((None, None, None))
        );

        // The multicast source does not send any packet because no data
        // expiration.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Err(Error::Done)
        );
    }
}
