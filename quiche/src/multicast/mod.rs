//! Multicast extension for QUIC.

use std::cmp;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::BufRead;
use std::net::SocketAddr;
use std::time;

use crate::multicast::reliable::RMcSource;
use crate::packet;
use crate::packet::Epoch;
use crate::rand::rand_bytes;
use crate::ranges;
use crate::ranges::RangeSet;
use crate::recovery::multicast::MulticastRecovery;
use crate::stream::McStream;
use crate::CongestionControlAlgorithm;
use crate::SendInfo;
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

/// Communication between the multicast channel and the unicast connections.
#[macro_export]
macro_rules! ucs_to_mc_cwnd {
    ( $mc:expr, $ucs: expr, $now: expr, $cwnd_limit: expr ) => {
        let min_cwnd = $ucs
            .filter_map(|uc| {
                let cwnd = uc.mc_get_uc_cwnd();

                if let (Some(c), Some(cl)) = (cwnd, $cwnd_limit) {
                    if c < cl {
                        _ = uc.mc_leave_channel();
                    }
                }

                cwnd
            })
            .min();
        // debug!(
        //     "MC-DEBUG: This is the source new congestion window: {:?}",
        //     min_cwnd
        // );
        if let Some(cwnd) = min_cwnd {
            $mc.mc_set_cwnd(cwnd);
        }
    };
}

/// Multicast extension errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McError {
    /// Incorrect McAnnounce data.
    McAnnounce,

    /// Incomplete server channel initiation.
    McServerInit,

    /// Invalid symetric key.
    McInvalidSymKey,

    /// Attempts to perform server-specific function if a client
    /// and conversely.
    McInvalidRole(McRole),

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

    /// Error when initiating the multicast pipe.
    McPipe,

    /// Invalid new client ID.
    McInvalidClientId,

    /// Invalid authentication information.
    McInvalidAuth,

    /// No authentication packet available to verify the source of the multicast
    /// data packet.
    McNoAuthPacket,

    /// Invalid crypto context on the multicast channel.
    McInvalidCrypto,

    /// Attempt to use reliable multicast which is disabled.
    McReliableDisabled,

    /// Stream rotation is disabled or invalid role.
    FcStreamRotation,

    /// Attempt to read a stream in-order while it uses stream rotation.
    FcStreamOutOfOrder,
}

/// MC_ANNOUNCE frame type.
pub const MC_ANNOUNCE_CODE: u64 = 0xf3;
/// MC_STATE frame type.
pub const MC_STATE_CODE: u64 = 0xf4;
/// MC_KEY frame type.
pub const MC_KEY_CODE: u64 = 0xf5;
/// MC_EXPIRE frame type.
pub const MC_EXPIRE_CODE: u64 = 0xf6;
/// MC_AUTH frame type.
pub const MC_AUTH_CODE: u64 = 0xf7;
/// MC_ASYM frame type.
pub const MC_ASYM_CODE: u64 = 0xf8;
/// MC_NACK frame type.
pub const MC_NACK_CODE: u64 = 0xf9;

/// The leaving action is requested by the client.
pub const LEAVE_FROM_CLIENT: u64 = 0x0;
/// The leaving action is requested by the server.
pub const LEAVE_FROM_SERVER: u64 = 0x1;

/// States of a multicast client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum McClientStatus {
    /// Leaving the multicast channel. The client waits for acknowledgment.
    /// In the meantime, the client can still listen to multicast traffic.
    /// The inner value is `true` if the client already sent the notification to
    /// the server.
    Leaving(bool),

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
    ListenMcPath(bool),

    /// The client is not aware of the multicast channel.
    Unaware,

    /// This is used when the status is of no importance.
    Unspecified,
}

/// Actions of multicast client in the finite state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum McClientAction {
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

impl TryFrom<u64> for McClientAction {
    type Error = crate::Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => McClientAction::Notify,
            1 => McClientAction::Join,
            2 => McClientAction::Leave,
            3 => McClientAction::DecryptionKey,
            4 => McClientAction::McPath,
            _ => return Err(Error::Multicast(McError::McInvalidAction)),
        })
    }
}

impl TryInto<u64> for McClientAction {
    type Error = crate::Error;

    fn try_into(self) -> std::result::Result<u64, Self::Error> {
        Ok(match self {
            McClientAction::Notify => 0,
            McClientAction::Join => 1,
            McClientAction::Leave => 2,
            McClientAction::DecryptionKey => 3,
            McClientAction::McPath => 4,
        })
    }
}

/// Multicast extensions for a connection configuration.
pub trait McConfig {
    /// Sets the `multicast_server_params` transport parameter.
    ///
    /// The default value is `false`.
    fn set_enable_server_multicast(&mut self, v: bool);

    /// Sets the maximum number of FEC repair symbols that can be sent. Only
    /// used for the Retransmission FEC scheduler.
    fn set_mc_max_nb_repair_symbols(&mut self, v: Option<u32>);

    /// Sets the `multicast_client_params` transport parameter.
    /// Clones the transport parameter values given as argument.
    ///
    /// The default value is `None`.
    fn set_enable_client_multicast(&mut self, v: Option<&McClientTp>);
}

impl McConfig for crate::Config {
    fn set_enable_server_multicast(&mut self, v: bool) {
        self.local_transport_params.multicast_server_params = v;
    }

    fn set_mc_max_nb_repair_symbols(&mut self, v: Option<u32>) {
        self.mc_fec_max_rs = v;
    }

    fn set_enable_client_multicast(&mut self, v: Option<&McClientTp>) {
        self.local_transport_params.multicast_client_params = v.cloned();
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Copy)]
/// Multicast path type.
pub enum McPathType {
    /// Multicast data exchanged on this channel.
    Data,

    /// Only used for symetric authentication.
    Authentication,
}

impl TryFrom<u64> for McPathType {
    type Error = crate::Error;

    fn try_from(v: u64) -> Result<Self> {
        match v {
            0 => Ok(Self::Data),
            1 => Ok(Self::Authentication),
            _ => Err(Error::Multicast(McError::McPath)),
        }
    }
}

impl From<McPathType> for u64 {
    fn from(v: McPathType) -> Self {
        match v {
            McPathType::Data => 0,
            McPathType::Authentication => 1,
        }
    }
}

/// Role of the connection
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McRole {
    /// Server multicast channel. Not directly connected to any
    /// connection with a client.
    ServerMulticast,

    /// Server unicast channel. Directly connected to its client.
    ServerUnicast(McClientStatus),

    /// Receiver. As it uses multipath, it uses both unicast and multicast.
    Client(McClientStatus),

    /// Undefined role. Used for debugging and as temporary value.
    Undefined,
}

/// Structure containing all multicast-related variables of the extension
/// in a quiche::Connection.
pub struct MulticastAttributes {
    /// Role of the extension.
    mc_role: McRole,

    /// Multicast channel information that is shared in a MC_ANNOUNCE frame.
    /// Server-side: the information to share.
    /// Client-side: the received information.
    /// This is an option because it may be null initially (for example
    /// the client did not receive the MC_ANNOUNCE yet).
    mc_announce_data: Vec<McAnnounceData>,

    /// Multicast channel decryption key secret.
    mc_channel_key: Option<Vec<u8>>,

    /// Algorithm used for the channel symmetric encryption.
    mc_channel_algo: Algorithm,

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

    /// Space ID of the multicast data path.
    mc_space_id: Option<usize>,

    /// Space ID of the multicast authentication path.
    mc_auth_space_id: Option<usize>,

    /// Nack ranges received by the server from the client.
    /// Only present for the server unicast.
    /// For the client, it contains the last sent nack ranges.
    /// Contains the maximum received packet number (on the client) at which
    /// this range was sent by the client.
    mc_nack_ranges: (Option<(RangeSet, u64)>, Option<u64>),

    /// Last expired packet num and FEC state.
    pub(crate) mc_last_expired: Option<ExpiredPkt>,

    /// Last expired data needs to trigger an MC_EXPIRE frame.
    pub(crate) mc_last_expired_needs_notif: bool,

    /// Time at which the client received the last packet.
    mc_last_recv_time: Option<time::Instant>,

    /// Set to true if the client just left the multicast channel and the
    /// synchronisation step is not performed yet.
    mc_client_left_need_sync: bool,

    /// Multicast clients Ids.
    mc_client_id: Option<McClientId>,

    /// Multicast authentication type.
    /// Currently this disables the possibility to have a chain of
    /// verifications, as we overwrite this value for each McPathType::Data
    /// MC_ANNOUNCE data received.
    pub(crate) mc_auth_type: McAuthType,

    /// Packet number and packet content sent on the multicast data channel that
    /// must be authenticated with a symetric MC_AUTH frame on the
    /// authentication channel.
    pub(crate) mc_pn_need_sym_sign: Option<VecDeque<(u64, Vec<u8>)>>,

    /// All symetric signatures that must be sent inside MC_AUTH frames on a
    /// multicast authentication path.
    /// For a client, it contains the set of received signatures concerning this
    /// client.
    ///
    /// It is up to the application to fill this vector with signatures to send
    /// to the clients. This design choice ensures that the [`send`] methods
    /// from the library must not take a reference to all the clients of the
    /// channel. Instead, this library provides a function MC-TODO to fill this
    /// vector by the application before calling the send functions.
    pub(crate) mc_sym_signs: McSymSign,

    /// MC_STATE frame in flight.
    mc_state_in_flight: bool,

    /// Ordered list of streams received that need authentication.
    /// Only used for [`McAuthType::StreamAsym`] method.
    mc_recv_stream: VecDeque<u64>,

    /// The multicast state has been updated.
    pub mc_need_ack: bool,

    /// Highest packet number received on the multicast channel.
    pub mc_max_pn: u64,

    /// Range of packet numbers not expired yet where a REPAIR frame was sent.
    /// Only some for [`McRole::ServerMulticast`].
    pub mc_sent_repairs: Option<RangeSet>,

    /// The client leaves the multicast channel on timeout, i.e., in
    /// [`MulticastConnection::on_mc_timeout`].
    mc_leave_on_timeout: bool,

    /// Send FEC repair packets instead of source symbols if possible.
    pub(crate) mc_prioritize_fec: bool,

    /// Packet numbers containing FEC source symbols.
    pub(crate) mc_ss_pn: RangeSet,

    /// Reliable multicast attributes.
    mc_reliable: Option<ReliableMc>,

    /// Packet numbers received on the multicast channel containing STREAM
    /// frames. This structure is used to correctly remove expired streams
    /// when the client receives an MC_EXPIRE frame from the multicast source.
    mc_pn_stream_id: BTreeMap<u64, u64>,

    /// I need this variable because when receiving a frame, we do not have
    /// access anymore to the packet numer...
    pub(crate) mc_last_recv_pn: u64,

    /// Maximum packet number already given to the unicast connection.
    cur_max_pn: u64,

    /// Flexicast source stream rotation structure.
    fc_rotate: Option<FcRotate>,
}

impl MulticastAttributes {
    #[inline]
    /// Returns a reference to the first MC_ANNOUNCE data for a
    /// [`McPathType::Data`] path.
    pub fn get_mc_announce_data_path(&self) -> Option<&McAnnounceData> {
        self.mc_announce_data
            .iter()
            .find(|mc_data| mc_data.path_type == McPathType::Data)
    }

    #[inline]
    /// Returns a mutable reference to the first MC_ANNOUNCE data for a
    /// [`McPathType::Data`] path.
    pub fn get_mut_mc_announce_data_path(
        &mut self,
    ) -> Option<&mut McAnnounceData> {
        self.mc_announce_data
            .iter_mut()
            .find(|mc_data| mc_data.path_type == McPathType::Data)
    }

    #[inline]
    /// Returns a mutable reference to the MC_ANNOUNCE data given by the index.
    pub fn get_mut_mc_announce_data(
        &mut self, idx: usize,
    ) -> Option<&mut McAnnounceData> {
        self.mc_announce_data.get_mut(idx)
    }

    #[inline]
    /// Returns a mutable reference to the MC_ANNOUNCE data given by the Channel
    /// ID.
    pub fn get_mut_mc_announce_data_by_cid(
        &mut self, cid: &[u8],
    ) -> Option<&mut McAnnounceData> {
        self.mc_announce_data
            .iter_mut()
            .find(|mc_data| mc_data.channel_id == cid)
    }

    #[inline]
    /// Returns a reference to the MC_ANNOUNCE data given by the index.
    pub fn get_mc_announce_data(&self, idx: usize) -> Option<&McAnnounceData> {
        self.mc_announce_data.get(idx)
    }

    #[inline]
    /// Returns the current multicast role.
    pub fn get_mc_role(&self) -> McRole {
        self.mc_role
    }

    #[inline]
    /// Sets the MC_STATE frame in flight.
    pub fn set_mc_state_in_flight(&mut self, v: bool) {
        self.mc_state_in_flight = v;
    }

    #[inline]
    /// Returns the multicast authentication method.
    pub fn get_mc_auth_type(&self) -> McAuthType {
        self.mc_auth_type
    }

    /// Sets the client status following the state machine.
    /// Returns an error if the client would do an invalid move in the state
    /// machine. MC-TODO: complete the finite state machine.
    pub fn update_client_state(
        &mut self, action: McClientAction, action_data: Option<u64>,
    ) -> Result<McClientStatus> {
        let (is_server, current_status) = match self.mc_role {
            McRole::Client(status) => (false, status),
            McRole::ServerUnicast(status) => (true, status),
            _ =>
                return Err(Error::Multicast(McError::McInvalidRole(
                    self.mc_role,
                ))),
        };

        let new_status = match (current_status, action) {
            (McClientStatus::Unaware, McClientAction::Notify) =>
                McClientStatus::AwareUnjoined,
            (McClientStatus::AwareUnjoined, McClientAction::Join)
                if !is_server =>
                McClientStatus::WaitingToJoin,
            (McClientStatus::AwareUnjoined, McClientAction::Join)
                if is_server =>
                McClientStatus::JoinedNoKey,
            (McClientStatus::Unaware, McClientAction::Join)
                if is_server &&
                    self.get_mc_announce_data_path().unwrap().is_processed =>
                McClientStatus::JoinedNoKey,
            (McClientStatus::WaitingToJoin, McClientAction::Join) =>
                McClientStatus::JoinedNoKey,
            (McClientStatus::JoinedNoKey, McClientAction::DecryptionKey) =>
                McClientStatus::JoinedAndKey,
            (McClientStatus::WaitingToJoin, McClientAction::DecryptionKey)
                if is_server && self.mc_key_up_to_date =>
                McClientStatus::JoinedAndKey,
            (McClientStatus::WaitingToJoin, McClientAction::DecryptionKey)
                if !is_server =>
                McClientStatus::JoinedAndKey,
            (McClientStatus::ListenMcPath(_), McClientAction::Leave) =>
                if let Some(leaving_from) = action_data {
                    if leaving_from == LEAVE_FROM_CLIENT {
                        if is_server {
                            self.mc_client_left_need_sync = true;
                            McClientStatus::AwareUnjoined
                        } else {
                            McClientStatus::Leaving(false)
                        }
                    } else if leaving_from == LEAVE_FROM_SERVER {
                        if is_server {
                            self.mc_client_left_need_sync = true;
                            McClientStatus::Leaving(false)
                        } else {
                            McClientStatus::AwareUnjoined
                        }
                    } else {
                        debug!("Invalid action 1");
                        return Err(Error::Multicast(McError::McInvalidAction));
                    }
                } else {
                    debug!("Invalid action 2");
                    return Err(Error::Multicast(McError::McInvalidAction));
                },
            (McClientStatus::Leaving(false), McClientAction::Leave) =>
                McClientStatus::AwareUnjoined,
            (McClientStatus::Leaving(true), McClientAction::Leave) =>
                McClientStatus::AwareUnjoined,
            (
                McClientStatus::JoinedAndKey | McClientStatus::JoinedNoKey,
                McClientAction::McPath,
            ) if action_data.is_some() && is_server => {
                self.mc_space_id = Some(action_data.unwrap() as usize);
                McClientStatus::ListenMcPath(true)
            },
            (McClientStatus::JoinedAndKey, McClientAction::McPath)
                if action_data.is_some() && !is_server =>
            {
                self.mc_space_id = Some(action_data.unwrap() as usize);
                McClientStatus::ListenMcPath(true)
            },
            (McClientStatus::AwareUnjoined, McClientAction::Leave) =>
                McClientStatus::AwareUnjoined,
            (McClientStatus::ListenMcPath(_), _) => current_status,
            (McClientStatus::JoinedAndKey, McClientAction::Join) =>
                current_status,
            _ => {
                debug!(
                    "Invalid action 3: current={:?} and action is {:?}",
                    current_status, action
                );
                current_status
            },
        };

        // If the client leaves the multicast group, its key is not longer up to
        // date.
        if action == McClientAction::Leave && is_server {
            self.mc_key_up_to_date = false;
        }

        self.mc_need_ack = true;

        self.mc_role = match self.mc_role {
            McRole::Client(_) => McRole::Client(new_status),
            McRole::ServerUnicast(_) => McRole::ServerUnicast(new_status),
            other => other,
        };

        Ok(new_status)
    }

    /// Returns whether the client should send an MC_STATE frame to join the
    /// channel. Always false for a server.
    /// True if the client application explicitly asked to join the channel
    /// of if the client created the multicast path.
    pub fn should_send_mc_state(&self) -> bool {
        if self.mc_state_in_flight {
            return false;
        }
        match self.mc_role {
            McRole::Client(status) => match status {
                McClientStatus::WaitingToJoin => true,
                McClientStatus::JoinedAndKey if self.mc_space_id.is_some() =>
                    true,
                McClientStatus::Leaving(false) => true,
                _ => false,
            },
            McRole::ServerUnicast(McClientStatus::Leaving(false)) => true,
            _ => false,
        }
    }

    /// Returns whether the server should send an MC_KEY frame
    /// to share the public authentication key to the client.
    /// True if the client has joined the multicast channel
    /// but has received not the authentication key yet.
    /// Always false for a client.
    pub fn should_send_mc_key(&self) -> bool {
        if self.mc_channel_key.is_none() {
            return false;
        }
        if self.mc_key_up_to_date {
            return false;
        }
        if let McRole::ServerUnicast(status) = self.mc_role {
            match status {
                McClientStatus::JoinedAndKey |
                McClientStatus::ListenMcPath(_) => true,
                McClientStatus::JoinedNoKey if self.mc_client_id.is_some() =>
                    true,
                _ => false,
            }
        } else {
            false
        }
    }

    /// Read the last multicast decryption key secret.
    pub fn set_mc_key_read(&mut self, v: bool) {
        self.mc_key_up_to_date = v;
    }

    /// Whether the multicast decryption key is received by the client.
    pub fn mc_client_has_key(&self) -> bool {
        self.mc_key_up_to_date
    }

    /// Get the channel decryption key secret.
    pub fn get_decryption_key_secret(&self) -> Result<&[u8]> {
        match self.mc_role {
            McRole::ServerUnicast(McClientStatus::JoinedNoKey) => Ok(self
                .mc_channel_key
                .as_ref()
                .ok_or(Error::Multicast(McError::McInvalidSymKey))?),
            _ => Err(Error::Multicast(McError::McInvalidRole(self.mc_role))),
        }
    }

    /// Get the channel decryption algorithm.
    pub fn get_decryption_key_algo(&self) -> Algorithm {
        self.mc_channel_algo
    }

    /// Sets the channel decryption key secret.
    pub fn set_decryption_key_secret(
        &mut self, key: Vec<u8>, algo: Algorithm,
    ) -> Result<()> {
        match self.mc_role {
            McRole::Client(McClientStatus::JoinedNoKey) |
            McRole::Client(McClientStatus::WaitingToJoin) => {
                let aead_open = Open::from_secret(algo, &key)?;
                self.mc_crypto_open = Some(aead_open);
                let aead_seal = Seal::from_secret(algo, &key)?;
                self.mc_crypto_seal = Some(aead_seal);

                self.mc_channel_key = Some(key);
                self.mc_channel_algo = algo;
                Ok(())
            },
            _ => Err(Error::Multicast(McError::McInvalidRole(self.mc_role))),
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
        if self.mc_role == McRole::ServerMulticast {
            if let Some(private_key) = self.mc_private_key.as_ref() {
                Some(private_key.public_key().as_ref())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the authentication method used.
    ///
    /// Makes verification to ensure that the returned verification method can
    /// be executed. For example, an asymetric authentication cannot be done
    /// if there is no private key. Returns [`McAuthType::None`] otherwise.
    pub fn get_mc_authentication_method(&self) -> McAuthType {
        match self.mc_auth_type {
            McAuthType::AsymSign | McAuthType::StreamAsym
                if self.mc_role == McRole::ServerMulticast &&
                    self.mc_private_key.is_some() =>
                self.mc_auth_type,
            McAuthType::AsymSign => {
                if matches!(self.mc_role, McRole::Client(_)) &&
                    self.mc_public_key.is_some()
                {
                    self.mc_auth_type
                } else {
                    McAuthType::None
                }
            },
            McAuthType::SymSign
                if self
                    .mc_announce_data
                    .iter()
                    .filter(|mc_data| {
                        mc_data.path_type == McPathType::Authentication
                    })
                    .last()
                    .is_some() =>
                McAuthType::SymSign,
            _ => McAuthType::None,
        }
    }

    /// Sets the multicast path space identifier.
    /// This is used to alwasy refer to the correct multicast path
    /// when processing packets.
    pub fn set_mc_space_id(&mut self, space_id: usize, path_type: McPathType) {
        match path_type {
            McPathType::Data => self.mc_space_id = Some(space_id),
            McPathType::Authentication => self.mc_auth_space_id = Some(space_id),
        }
    }

    /// Gets the multicast space ID.
    pub fn get_mc_space_id(&self) -> Option<usize> {
        self.mc_space_id
    }

    /// Gets the multicast authentication path space ID.
    pub fn get_mc_auth_space_id(&self) -> Option<usize> {
        self.mc_auth_space_id
    }

    /// Sets the multicast nack ranges received from the client.
    /// Returns an error if it is not a [`ServerUnicast`] or a Client.
    pub fn set_mc_nack_ranges(
        &mut self, ranges_opt: Option<(&ranges::RangeSet, u64)>,
        nb_degree_needed: Option<u64>,
    ) -> Result<()> {
        if !matches!(self.mc_role, McRole::ServerUnicast(_) | McRole::Client(_)) {
            return Err(Error::Multicast(McError::McInvalidRole(self.mc_role)));
        }

        if let Some((ranges, pn)) = ranges_opt {
            self.mc_nack_ranges = (Some((ranges.clone(), pn)), nb_degree_needed);
        } else {
            self.mc_nack_ranges = (None, None);
        }

        Ok(())
    }

    /// Sets the client ID for the client and the unicast server (i.e., the id
    /// of their client).
    pub fn set_client_id(&mut self, client_id: u64) -> Result<()> {
        if !matches!(self.mc_role, McRole::Client(_) | McRole::ServerUnicast(_)) {
            return Err(Error::Multicast(McError::McInvalidRole(self.mc_role)));
        }
        self.mc_client_id = Some(McClientId::Client(client_id));

        Ok(())
    }

    /// Gets the client ID.
    pub fn get_self_client_id(&self) -> Result<u64> {
        match self.mc_client_id {
            Some(McClientId::Client(v)) => Ok(v),
            Some(McClientId::MulticastServer(_)) =>
                Err(Error::Multicast(McError::McInvalidRole(self.mc_role))),
            None => Err(Error::Multicast(McError::McInvalidClientId)),
        }
    }

    /// Whether the multicast source must send authentication packets with
    /// symetric signature.
    pub fn should_send_mc_auth_packets(&self) -> bool {
        if self.mc_role == McRole::ServerMulticast &&
            self.mc_auth_type == McAuthType::SymSign
        {
            if let McSymSign::McSource(v) = &self.mc_sym_signs {
                return !v.is_empty();
            }
        }
        false
    }

    /// Sets the [`MulticastAttributes::mc_space_id`] or
    /// [`MulticastAttributes::mc_space_id_auth`] depending on the given local
    /// address from the quiche library.
    pub fn set_mc_space_id_from_addr(
        &mut self, local_addr: SocketAddr, pid: u64,
    ) -> Result<()> {
        for mc_data in self.mc_announce_data.iter() {
            let ip = std::net::Ipv4Addr::from(mc_data.group_ip.to_owned());
            if local_addr.ip() == ip && local_addr.port() == mc_data.udp_port {
                self.set_mc_space_id(pid as usize, mc_data.path_type);
                return Ok(());
            }
        }

        Err(Error::Multicast(McError::McPath))
    }

    /// Add a new stream ID that has known size.
    pub fn push_new_mc_stream_fin(&mut self, stream_id: u64) {
        self.mc_recv_stream.push_back(stream_id);
    }

    /// Pop a stream ID that has been received.
    pub fn pop_new_mc_stream_fin(&mut self) -> Option<u64> {
        self.mc_recv_stream.pop_front()
    }

    /// Reset the received streams.
    pub fn reset_recv_mc_stream(&mut self) {
        self.mc_recv_stream = VecDeque::new();
    }

    /// Returns the expired received stream IDs based on the highest
    /// expired packet number. Does not expire the streams nor remove the values
    /// from the inner structure. Returns an error if the caller is not a
    /// multicast client.
    ///
    /// For the client, it can either be one of the three following cases:
    /// * The client received all data of a specific stream. In that case, it
    ///   has the same properties as the server.
    /// * The client did not receive any data of a specific stream. In that
    ///   case, the client will not reset the stream because it has no clue of
    ///   that stream. It should not be a problem.
    /// * The client partially received data of a specific stream. Either the
    ///   client received a packet for that stream that is now expired, and the
    ///   client will correctly reset the stream; or the client did not received
    ///   any data for that stream that is now expired (the only received data
    ///   is not expired yet). In that case, the client will not reset the
    ///   stream, and the client will see a pending stream until the not-yet
    ///   expired packets for that stream will be expired (later).
    fn mc_get_recv_expired_stream_ids(
        &self, exp_pn: u64,
    ) -> Result<ExpiredStream> {
        if !matches!(self.mc_role, McRole::Client(_)) {
            return Err(Error::Multicast(McError::McInvalidRole(self.mc_role)));
        }

        Ok(self
            .mc_pn_stream_id
            .iter()
            .take_while(|(&pn, _)| pn <= exp_pn)
            .map(|(_, &sid)| sid)
            .collect())
    }

    /// Removes the expired packet numbers from the inner structure, based on
    /// the highest expired packet number given as argument. Returns an erorr if
    /// the caller is not a multicast client.
    fn mc_rm_recv_expired_pns(&mut self, exp_pn: u64) -> Result<()> {
        if !matches!(self.mc_role, McRole::Client(_)) {
            return Err(Error::Multicast(McError::McInvalidRole(self.mc_role)));
        }

        // Not efficient but the desired library function is unstable :(.
        self.mc_pn_stream_id = self
            .mc_pn_stream_id
            .iter()
            .filter(|(&pn, _)| pn > exp_pn)
            .map(|(&pn, &sid)| (pn, sid))
            .collect();
        Ok(())
    }

    /// Inserts a new packet number - stream ID pair in the inner structure. The
    /// packet with the indicated packet number transmitted a frame of the
    /// stream ID given as argument.
    pub fn mc_add_recv_pn_sid(&mut self, pn: u64, sid: u64) -> Result<()> {
        if !matches!(self.mc_role, McRole::Client(_)) {
            return Err(Error::Multicast(McError::McInvalidRole(self.mc_role)));
        }

        self.mc_pn_stream_id.insert(pn, sid);
        Ok(())
    }
}

impl Default for MulticastAttributes {
    fn default() -> Self {
        Self {
            mc_role: McRole::Undefined,
            mc_announce_data: Vec::with_capacity(2),
            mc_channel_key: None,
            mc_channel_algo: Algorithm::AES128_GCM,
            mc_crypto_open: None,
            mc_crypto_seal: None,
            mc_key_up_to_date: false,
            mc_public_key: None,
            mc_private_key: None,
            mc_space_id: None,
            mc_nack_ranges: (None, None),
            mc_last_expired: None,
            mc_last_expired_needs_notif: false,
            mc_last_recv_time: None,
            mc_client_left_need_sync: false,
            mc_client_id: None,
            mc_auth_space_id: None,
            mc_auth_type: McAuthType::None,
            mc_pn_need_sym_sign: None,
            mc_sym_signs: McSymSign::Client(HashMap::new()),
            mc_state_in_flight: false,
            mc_recv_stream: VecDeque::new(),
            mc_need_ack: false,
            mc_max_pn: 0,
            mc_sent_repairs: None,
            mc_leave_on_timeout: true,
            mc_prioritize_fec: false,
            mc_ss_pn: RangeSet::default(),
            mc_reliable: None,
            mc_pn_stream_id: BTreeMap::default(),
            mc_last_recv_pn: 0,
            cur_max_pn: 0,
            fc_rotate: None,
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
    pub expiration_timer: u64,

    /// Path type.
    pub path_type: McPathType,

    /// True if this multicast announce data is processed.
    /// For a server, it means that the data is sent to the client.
    /// For a client, it means that the data is received.
    pub is_processed: bool,

    /// Authentication used for this path.
    pub auth_type: McAuthType,

    /// Whether this multicast channel uses full reliability.
    pub full_reliability: bool,
}

impl McAnnounceData {
    /// Sets the processed state of the MC_ANNOUNCE data.
    /// If set to true, means that the last data has been processed on the host.
    pub fn set_mc_announce_processed(&mut self, v: bool) {
        self.is_processed = v;
    }
}

/// Multicast extension behaviour for the QUIC connection.
pub trait MulticastConnection {
    /// Returns the index of the first MC_ANNOUNCE data that should be
    /// announced. Always `None` for a client.
    fn mc_should_send_mc_announce(&self) -> Option<usize>;

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
    fn mc_set_multicast_receiver(
        &mut self, secret: &[u8], mc_space_id: usize, algo: Algorithm,
    ) -> Result<()>;

    /// Returns true if the multicast extension has control data to send.
    fn mc_has_control_data(&self, send_pid: usize) -> bool;

    /// Joins a multicast channel advertised by a server.
    /// Sets the possibility to leave the multicast channel on timeout on this
    /// multicast channel, i.e., in [`MulticastConnection::on_mc_timeout`].
    /// Returns an Error if:
    /// * This is not a client
    /// * There is no multicast state with valid MC_ANNOUNCE data
    /// * The status is not AwareUnjoined
    fn mc_join_channel(
        &mut self, leave_on_timeout: bool,
    ) -> Result<McClientStatus>;

    /// Leaves a previously joined multicast channel.
    /// Returns an Error if:
    /// * This is not a client or a unicast server
    /// * There is no multicast state with valid MC_ANNOUNCE data
    /// * The client did not joined the channel
    fn mc_leave_channel(&mut self) -> Result<McClientStatus>;

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
    /// MC-TODO: symmetric authentication documentation.
    ///
    /// MC-TODO: only Ed25519 is used at the moment.
    /// The last bytes of the packet contain the signature.
    fn mc_recv(&mut self, buf: &mut [u8], info: RecvInfo) -> Result<usize>;

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
        &mut self, epoch: Epoch, space_id: u64, expired_pkt: ExpiredPkt,
        now: time::Instant,
    ) -> Result<(ExpiredPkt, ExpiredStream)>;

    /// Returns the amount of time until the next multicast timeout event.
    ///
    /// Once the given duration has elapsted, the [`on_mc_timeout()`] method
    /// should be called. A timeout of `None` means that the timer should be
    /// disarmed.
    fn mc_timeout(&self, now: time::Instant) -> Option<time::Duration>;

    /// Processes a multicast timeout event.
    ///
    /// If no timeout has occurred it does nothing.
    fn on_mc_timeout(&mut self, now: time::Instant) -> Result<ExpiredPkt>;

    /// Returns whether the path id given as argument is a multicast path.
    /// False if multicast is disabled or if the path is not a multicast path.
    fn is_mc_path(&self, space_id: usize) -> bool;

    /// Adds the new connection IDs for the multicast client.
    /// Previously, this was done in the [`MulticastConnection::create_mc_path`]
    /// function but not this is separated because the two frames were sent on
    /// the same path
    fn add_mc_cid(&mut self, cid: &ConnectionId) -> Result<()>;

    /// Creates a multicast path on the client.
    /// This is done manually by the client without contacting the unicast
    /// server to avoid sharing a same path for the multicast and unicast
    /// source.
    fn create_mc_path(
        &mut self, client_addr: SocketAddr, server_addr: SocketAddr,
        to_uc_server: bool,
    ) -> Result<u64>;

    /// The unicast server connection sends control messages to the multicast
    /// source.
    ///
    /// Possible messages are:
    ///     * MC_NACK received from the client on the unicast channel
    ///
    /// Returns an error if this method is called by another entity than the
    /// unicast server.
    fn uc_to_mc_control(
        &mut self, mc_channel: &mut Connection, now: time::Instant,
    ) -> Result<()>;

    /// Returns the multicast attributes.
    fn get_multicast_attributes(&self) -> Option<&MulticastAttributes>;

    /// Sets the multicast path ID. Internally calls
    /// [`MulticastAttributes::set_mc_space_id`].
    fn set_mc_space_id(
        &mut self, space_id: u64, path_type: McPathType,
    ) -> Result<()>;

    /// Whether it is safe to close the multicast channel.
    /// In this context, 'safe' means that all stream data reached its
    /// expiration timer, i.e., that no data can be retransmitted on the
    /// multicast channel.
    ///
    /// Attention: this function returns true whether no streams are expirable.
    /// This means that the function can return true even before the multicast
    /// content started.
    fn mc_no_stream_active(&self) -> bool;

    /// Sets the multicast pacing. Only available for the multicast source if
    /// the disabled_cc congestion control algorithm is used.
    fn mc_set_constant_pacing(&mut self, rate: u64) -> Result<()>;

    /// Update send capacity for the multicast source channel.
    fn mc_update_tx_cap(&mut self);

    /// Multicast version of [`crate::Connection::stream_recv`].
    ///
    /// * If the multicast authentication method is
    ///   [`authentication::McAuthType::StreamAsym`]: This version verifies the
    ///   asymmetric signature sent alongside the stream. Returns a
    ///   [McError::McInvalidSign] if the signature is invalid. Returns a
    ///   [`McError::Done`] if the stream is not fully readable in the sense of
    ///   [`crate::stream::Stream::RecvBuf::is_fully_readable`] (which should be
    ///   verified beforehand).
    /// * The behaviour of this function is strictly equivalent to the unicast
    ///   version otherwise.
    fn mc_stream_recv(
        &mut self, stream_id: u64, out: &mut [u8],
    ) -> Result<(usize, bool)>;

    /// Sets the [`MulticastAttributes::mc_prioritize_fec`].
    fn set_mc_prioritize_fec(&mut self, v: bool);
}

impl MulticastConnection for Connection {
    fn mc_should_send_mc_announce(&self) -> Option<usize> {
        if !self.is_server {
            return None;
        }
        if !(self.local_transport_params.multicast_server_params &&
            self.peer_transport_params.multicast_client_params.is_some())
        {
            return None;
        }

        if let Some(multicast) = self.multicast.as_ref() {
            let idx = multicast
                .mc_announce_data
                .iter()
                .position(|mc_data| !mc_data.is_processed);
            if idx.is_some() &&
                (multicast.mc_role ==
                    McRole::ServerUnicast(McClientStatus::Unaware) ||
                    multicast
                        .mc_announce_data
                        .get(idx.unwrap())
                        .unwrap()
                        .path_type ==
                        McPathType::Authentication)
            {
                idx
            } else {
                None
            }
        } else {
            None
        }
    }

    fn mc_set_multicast_receiver(
        &mut self, secret: &[u8], mc_space_id: usize, algo: Algorithm,
    ) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            match multicast.mc_role {
                McRole::Client(McClientStatus::WaitingToJoin) => {
                    // Do not perform the handshake because we already have the
                    // key.
                    self.handshake_completed = true;

                    // Derive the keys from the secret shared by the receiver.
                    let aead_open =
                        Open::from_secret(multicast.mc_channel_algo, secret)
                            .unwrap();
                    let aead_seal =
                        Seal::from_secret(multicast.mc_channel_algo, secret)
                            .unwrap();

                    // Do not change the global context.
                    // We will use this crypto when needed by manually getting it.
                    multicast.mc_crypto_open = Some(aead_open);
                    multicast.mc_crypto_seal = Some(aead_seal);

                    Ok(())
                },
                McRole::ServerUnicast(_) => {
                    multicast.mc_channel_key = Some(secret.to_owned());
                    multicast.mc_space_id = Some(mc_space_id);
                    multicast.mc_channel_algo = algo;

                    Ok(())
                },
                _ => Err(Error::Multicast(McError::McInvalidRole(
                    multicast.mc_role,
                ))),
            }
        } else {
            Err(Error::Multicast(McError::McDisabled))
        }
    }

    fn mc_set_mc_announce_data(
        &mut self, mc_announce_data: &McAnnounceData,
    ) -> Result<()> {
        if self.is_server && !self.local_transport_params.multicast_server_params
        {
            return Err(Error::Multicast(McError::McDisabled));
        }

        if let Some(multicast) = self.multicast.as_mut() {
            multicast.mc_announce_data.push(mc_announce_data.clone());
            match multicast.mc_role {
                McRole::Client(_) => {
                    if let Some(key_vec) = mc_announce_data.public_key.as_ref() {
                        // Client generates the public key from the received
                        // vector.
                        multicast.mc_public_key =
                            Some(signature::UnparsedPublicKey::new(
                                &signature::ED25519,
                                key_vec.to_owned(),
                            ));
                    }
                },
                McRole::ServerMulticast if mc_announce_data.full_reliability =>
                    if multicast.mc_reliable.is_none() {
                        multicast.mc_reliable =
                            Some(ReliableMc::McSource(RMcSource::default()));
                    },
                _ => (),
            }
        } else {
            // Multicast structure does not exist yet.
            // The client considers the MC_ANNOUNCE as processed because it
            // received it.
            let mc_role = if self.is_server {
                McRole::ServerUnicast(McClientStatus::Unaware)
            } else {
                McRole::Client(McClientStatus::AwareUnjoined)
            };
            let mut mc_data_cloned = mc_announce_data.clone();
            mc_data_cloned.is_processed = !self.is_server;
            self.multicast = Some(MulticastAttributes {
                mc_role,
                mc_announce_data: vec![mc_data_cloned],
                mc_public_key: mc_announce_data.public_key.as_ref().map(
                    |key_vec| {
                        signature::UnparsedPublicKey::new(
                            &signature::ED25519,
                            key_vec.to_owned(),
                        )
                    },
                ),
                mc_reliable: if mc_announce_data.full_reliability {
                    Some(if self.is_server {
                        ReliableMc::Server(RMcServer::default())
                    } else {
                        ReliableMc::Client(RMcClient::default())
                    })
                } else {
                    None
                },
                ..Default::default()
            });
        }

        // Set the multicast path authentication method.
        if let (Some(multicast), McPathType::Data) =
            (self.multicast.as_mut(), mc_announce_data.path_type)
        {
            // Only allow for asymetric authentication if we have a key in the
            // MC_ANNOUNCE.
            if matches!(multicast.mc_role, McRole::Client(_)) &&
                matches!(
                    mc_announce_data.auth_type,
                    McAuthType::AsymSign | McAuthType::StreamAsym
                ) &&
                multicast.mc_public_key.is_none()
            {
                return Err(Error::Multicast(McError::McInvalidAuth));
            }
            multicast.mc_auth_type = mc_announce_data.auth_type;
        }

        Ok(())
    }

    fn mc_has_control_data(&self, send_pid: usize) -> bool {
        if let Some(multicast) = self.multicast.as_ref() {
            if let Some(mc_auth_space_id) = multicast.mc_auth_space_id {
                // Do not send other information on the authentication path.
                return mc_auth_space_id == send_pid &&
                    multicast.should_send_mc_auth_packets();
            }

            return self.mc_should_send_mc_announce().is_some() ||
                multicast.should_send_mc_state() ||
                multicast.should_send_mc_key() ||
                self.mc_nack_range(
                    Epoch::Application,
                    multicast.mc_space_id.unwrap_or(0) as u64,
                )
                .is_some() ||
                multicast.mc_last_expired_needs_notif;
        }
        false
    }

    fn mc_join_channel(
        &mut self, leave_on_timeout: bool,
    ) -> Result<McClientStatus> {
        let multicast = match self.multicast.as_mut() {
            None => return Err(Error::Multicast(McError::McDisabled)),
            Some(multicast) => match multicast.mc_role {
                McRole::Client(McClientStatus::AwareUnjoined) => multicast,
                _ =>
                    return Err(Error::Multicast(McError::McInvalidRole(
                        multicast.mc_role,
                    ))),
            },
        };
        multicast.mc_leave_on_timeout = leave_on_timeout;
        multicast.update_client_state(McClientAction::Join, None)
    }

    fn mc_leave_channel(&mut self) -> Result<McClientStatus> {
        let multicast = match self.multicast.as_mut() {
            None => return Err(Error::Multicast(McError::McDisabled)),
            Some(multicast) => match multicast.mc_role {
                McRole::Client(McClientStatus::ListenMcPath(_)) => multicast,
                McRole::ServerUnicast(McClientStatus::ListenMcPath(_)) =>
                    multicast,
                _ =>
                    return Err(Error::Multicast(McError::McInvalidRole(
                        multicast.mc_role,
                    ))),
            },
        };
        let leaving_action_from = if self.is_server {
            LEAVE_FROM_SERVER
        } else {
            LEAVE_FROM_CLIENT
        };
        multicast
            .update_client_state(McClientAction::Leave, Some(leaving_action_from))
    }

    fn mc_recv(&mut self, buf: &mut [u8], info: RecvInfo) -> Result<usize> {
        let buf_len = if info.from_mc.is_some() {
            if let Some(multicast) = self.multicast.as_mut() {
                // Update the last time the client received a packet on the
                // multicast channel.
                let now = time::Instant::now();
                multicast.mc_last_recv_time = Some(now);

                let len = buf.len();
                let auth_method = multicast.get_mc_authentication_method();
                if auth_method == McAuthType::AsymSign {
                    self.mc_verify_asym(buf)?
                } else {
                    len
                }
            } else {
                return Err(Error::Multicast(McError::McDisabled));
            }
        } else {
            // Without authentication nor public key, the entire buffer contains
            // application data.
            buf.len()
        };
        self.recv(&mut buf[..buf_len], info)
    }

    fn mc_nack_range(&self, epoch: Epoch, space_id: u64) -> Option<RangeSet> {
        if let Some(multicast) = self.multicast.as_ref() {
            if !matches!(multicast.mc_role, McRole::Client(_)) {
                return None;
            }

            if let Ok(pns) = self.pkt_num_spaces.spaces.get(epoch, space_id) {
                let nack_range = pns.recv_pkt_need_ack.get_missing();
                if nack_range.len() == 0 {
                    return None;
                } else if let Some((range, _)) =
                    multicast.mc_nack_ranges.0.as_ref()
                {
                    if range == &nack_range {
                        return None;
                    }
                }
                Some(nack_range)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn mc_expire(
        &mut self, epoch: Epoch, space_id: u64, mut expired_pkt: ExpiredPkt,
        now: time::Instant,
    ) -> Result<(ExpiredPkt, ExpiredStream)> {
        let multicast = if let Some(multicast) = self.multicast.as_ref() {
            if !matches!(
                multicast.mc_role,
                McRole::Client(McClientStatus::ListenMcPath(true)) |
                    McRole::Client(McClientStatus::JoinedAndKey) |
                    McRole::ServerMulticast,
            ) {
                return Err(Error::Multicast(McError::McInvalidRole(
                    multicast.mc_role,
                )));
            }
            multicast
        } else {
            return Err(Error::Multicast(McError::McDisabled));
        };

        let hs_status = self.handshake_status();

        let mut expired_streams = ExpiredStream::new();

        // Remove expired packets.
        if self.is_server {
            let pns_client = self
                .get_multicast_attributes()
                .unwrap()
                .rmc_get()
                .and_then(|rmc| rmc.source())
                .and_then(|rmc| rmc.max_rangeset.to_owned());
            let p = self.paths.get_mut(space_id as usize)?;
            p.recovery.mc_set_min_rtt(time::Duration::from_millis(
                multicast
                    .get_mc_announce_data_path()
                    .unwrap()
                    .expiration_timer,
            ));
            let use_complete_streams = self
                .multicast
                .as_ref()
                .and_then(|m| m.rmc_get())
                .and_then(|r| r.source())
                .is_some();
            (expired_pkt, expired_streams) = p.recovery.mc_data_timeout(
                space_id as u32,
                now,
                multicast
                    .get_mc_announce_data_path()
                    .ok_or(Error::Multicast(McError::McAnnounce))?
                    .expiration_timer,
                hs_status,
                &mut self.newly_acked,
                pns_client,
                use_complete_streams,
            )?;
            if let Some(rmc) = self
                .multicast
                .as_mut()
                .unwrap()
                .rmc_get_mut()
                .and_then(|rmc| rmc.source_mut())
            {
                rmc.max_rangeset = None;
            }
            self.blocked_limit = None;
            self.update_tx_cap();
            debug!(
                "Expired streams on the server based on pn={:?}: {:?}",
                expired_pkt.pn, expired_streams
            );
        } else if let Some(exp_pn) = expired_pkt.pn {
            let pkt_num_space =
                self.pkt_num_spaces.spaces.get_mut(epoch, space_id)?;
            pkt_num_space.recv_pkt_need_ack.remove_until(exp_pn);
            trace!("Remove packets until {} for space id {}", exp_pn, space_id);

            expired_streams = self
                .multicast
                .as_mut()
                .unwrap()
                .mc_get_recv_expired_stream_ids(exp_pn)?;
            debug!(
                "Expired streams on the client based on pn={:?}: {:?}",
                exp_pn, expired_streams
            );
        }

        // Reset expired (but still open) streams.
        // This does not happen if reliable multicast is used for the client as
        // lost streams can be retransmitted on the unicast path.
        // For the server, we only expire finished streams.
        let multicast = self.multicast.as_mut().unwrap();
        if !multicast.mc_is_reliable() || self.is_server {
            for &exp_stream_id in expired_streams.iter() {
                let stream_opt = self.streams.get_mut(exp_stream_id);
                if let Some(stream) = stream_opt {
                    if self.is_server &&
                        (multicast.mc_is_reliable() && stream.send.is_fin() ||
                            !multicast.mc_is_reliable())
                    {
                        // Only reset the sending stream if:
                        // * Non-reliable multicast,
                        // * Reliable multicast and the sending stream is
                        //   complete.
                        stream.send.reset();
                        let local = stream.local;
                        self.streams.collect(exp_stream_id, local);
                    } else if !self.is_server {
                        // Maybe the final size is already known.
                        let final_size = stream.recv.max_off();
                        stream.recv.reset(0, final_size)?;
                        let local = stream.local;
                        self.streams.collect(exp_stream_id, local);
                    } else if self.is_server && multicast.mc_is_reliable() {
                        // Need to reset the stream to the correct offset to avoid
                        // double retransmission.
                        stream.send.reset_at(stream.send.off_back())?;
                    }
                };
            }
        }

        // Mark expired streams.
        for &exp_stream_id in expired_streams.iter() {
            if let Some(stream) = self.streams.get_mut(exp_stream_id) {
                debug!("Set stream {} as totally expired.", exp_stream_id);
                stream.send.fc_set_stream_expired(true);
            }
        }

        // Remove from the inner structure the expired packet number - stream ID
        // mapping.
        if !self.is_server {
            if let Some(exp_pn) = expired_pkt.pn {
                multicast.mc_rm_recv_expired_pns(exp_pn)?;
            }
        }

        // Reset FEC state to remove old source symbols.
        if let Some(exp_ssid) = expired_pkt.ssid {
            info!("Remove FEC up to: {}", exp_ssid);
            if self.is_server {
                // Reset FEC encoder state.
                self.fec_encoder
                    .remove_up_to(source_symbol_metadata_from_u64(exp_ssid));
            } else {
                // Reset FEC decoder state.
                self.fec_decoder.remove_up_to(
                    source_symbol_metadata_from_u64(exp_ssid),
                    None,
                );
            }
        }
        self.paths
            .get(1)
            .unwrap()
            .recovery
            .dump_sent("At the end of mc_expire");
        Ok((expired_pkt, expired_streams))
    }

    fn mc_timeout(&self, now: time::Instant) -> Option<time::Duration> {
        // MC-TODO: maybe the timeout should be using timers of all paths?

        let expiration_timer = self
            .multicast
            .as_ref()?
            .get_mc_announce_data_path()?
            .expiration_timer;

        // MC-TODO: should use mc_role instead of server.
        let multicast = self.multicast.as_ref()?;
        if matches!(
            multicast.mc_role,
            McRole::Client(McClientStatus::AwareUnjoined) |
                McRole::Client(McClientStatus::Leaving(_))
        ) {
            return None;
        }
        let timeout = if self.is_server {
            multicast.mc_last_recv_time? +
                time::Duration::from_millis(expiration_timer)
        } else {
            multicast.mc_last_recv_time? +
                time::Duration::from_millis(expiration_timer * 3)
        };
        if timeout <= now {
            Some(time::Duration::ZERO)
        } else {
            Some(timeout.duration_since(now))
        }
    }

    fn on_mc_timeout(&mut self, now: time::Instant) -> Result<ExpiredPkt> {
        // Some data has expired.
        if let Some(time::Duration::ZERO) = self.mc_timeout(now) {
            if let Some(multicast) = self.multicast.as_mut() {
                if self.is_server {
                    // Reset the number of FEC repair packets in flight.
                    if let Some(fec_scheduler) = self.fec_scheduler.as_mut() {
                        fec_scheduler.reset_fec_state();
                    }

                    let mc_auth_space_id = multicast.mc_auth_space_id;

                    // Expire packets from the authentication path.
                    if let Some(auth_id) = mc_auth_space_id {
                        // We expire packets but do not record them.
                        self.mc_expire(
                            Epoch::Application,
                            auth_id as u64,
                            ExpiredPkt::default(),
                            now,
                        )?;
                    }

                    let multicast = self.multicast.as_ref().unwrap();
                    if let Some(space_id) = multicast.get_mc_space_id() {
                        let res = self.mc_expire(
                            Epoch::Application,
                            space_id as u64,
                            ExpiredPkt::default(),
                            now,
                        );
                        let res = if let Ok((exp_pkt, _)) = res {
                            self.multicast
                                .as_mut()
                                .unwrap()
                                .mc_last_expired_needs_notif = !exp_pkt.is_none();
                            self.multicast.as_mut().unwrap().mc_last_expired =
                                Some(exp_pkt);
                            self.mc_update_tx_cap();

                            // Update last time a timeout event occured.
                            self.multicast.as_mut().unwrap().mc_last_recv_time =
                                Some(now);

                            if let Some(e) = exp_pkt.pn {
                                self.multicast
                                    .as_mut()
                                    .unwrap()
                                    .mc_ss_pn
                                    .remove_until(e);
                                if let Some(mc_repairs) = self
                                    .multicast
                                    .as_mut()
                                    .unwrap()
                                    .mc_sent_repairs
                                    .as_mut()
                                {
                                    debug!("Repairs before: {:?}", mc_repairs);
                                    mc_repairs.remove_until(e);
                                    debug!("Repairs after: {:?}", mc_repairs);
                                }
                            }

                            Ok(exp_pkt)
                        } else {
                            Ok(ExpiredPkt::default())
                        };

                        // Server updates its congestion window based on the
                        // multicast

                        return res;
                    }
                } else if multicast.mc_leave_on_timeout {
                    debug!("Will leave the multicast channel");
                    self.mc_leave_channel()?;
                } else {
                    debug!("Cannot leave the multicast channel");
                }
            }
        }
        Ok(ExpiredPkt::default())
    }

    fn is_mc_path(&self, space_id: usize) -> bool {
        if let Some(multicast) = self.multicast.as_ref() {
            if let Some(mc_id) = multicast.get_mc_space_id() {
                return space_id == mc_id;
            }
        }
        false
    }

    fn add_mc_cid(&mut self, cid: &ConnectionId) -> Result<()> {
        if let Some(multicast) = self.multicast.as_ref() {
            if !matches!(
                multicast.mc_role,
                McRole::Client(_) | McRole::ServerUnicast(_)
            ) {
                return Err(Error::Multicast(McError::McInvalidRole(
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

        Ok(())
    }

    fn create_mc_path(
        &mut self, client_addr: SocketAddr, server_addr: SocketAddr,
        to_uc_server: bool,
    ) -> Result<u64> {
        if let Some(multicast) = self.multicast.as_ref() {
            if !matches!(multicast.mc_role, McRole::Client(_)) {
                return Err(Error::Multicast(McError::McInvalidRole(
                    multicast.mc_role,
                )));
            }
        }

        let pid = if to_uc_server {
            info!("Client creates multicast path?");
            self.probe_path(client_addr, server_addr)
        } else {
            // Create a new path on the client.
            let pid = self.create_path_on_client(client_addr, server_addr)?;
            self.set_active(client_addr, server_addr, true)?;

            let path = self.paths.get_mut(pid)?;
            let pid = path.active_dcid_seq.ok_or(Error::InvalidState)?;

            Ok(pid)
        }?;

        // Add the first packet number of interest for the new path if possible.
        if let Some(exp_pkt) = self.multicast.as_ref().unwrap().mc_last_expired {
            if let Some(exp_pn) = exp_pkt.pn {
                self.pkt_num_spaces
                    .spaces
                    .get_mut_or_create(Epoch::Application, pid)
                    .recv_pkt_need_ack
                    .remove_until(exp_pn + 1);
                self.pkt_num_spaces
                    .spaces
                    .get_mut_or_create(Epoch::Application, pid)
                    .recv_pkt_need_ack
                    .insert(exp_pn + 1..exp_pn + 2);
            }
        }

        Ok(pid)
    }

    fn uc_to_mc_control(
        &mut self, mc_channel: &mut Connection, now: time::Instant,
    ) -> Result<()> {
        if let Some(multicast) = mc_channel.multicast.as_ref() {
            if !matches!(multicast.mc_role, McRole::ServerMulticast) {
                return Err(Error::Multicast(McError::McInvalidRole(
                    McRole::ServerMulticast,
                )));
            }
        } else {
            return Err(Error::Multicast(McError::McDisabled));
        }

        if let Some(multicast) = self.multicast.as_mut() {
            if !matches!(multicast.mc_role, McRole::ServerUnicast(_)) {
                return Err(Error::Multicast(McError::McInvalidRole(
                    McRole::ServerUnicast(McClientStatus::Unspecified),
                )));
            }

            // MC_NACK ranges.
            let nb_degree_opt = multicast.mc_nack_ranges.1;
            if let Some((mut nack_ranges, pn)) =
                multicast.mc_nack_ranges.0.to_owned()
            {
                // Filter from the nack ranges packets that are expired on the
                // source. This is necessary in case of
                // desynchronization with the client.
                if let Some(exp_pkt) =
                    mc_channel.multicast.as_ref().unwrap().mc_last_expired
                {
                    if let Some(pn) = exp_pkt.pn {
                        nack_ranges.remove_until(pn);
                    }
                }

                // Filter from the nack ranges packets that are not mapped to
                // source symbols.
                if nb_degree_opt.is_none() || nb_degree_opt == Some(0) {
                    let mc_ss_pn: HashSet<u64> = mc_channel
                        .multicast
                        .as_ref()
                        .unwrap()
                        .mc_ss_pn
                        .flatten()
                        .collect();
                    let mut new_nack = RangeSet::default();
                    for elem in nack_ranges.iter() {
                        for pn in elem {
                            if mc_ss_pn.contains(&pn) {
                                new_nack.insert(pn..pn + 1);
                            }
                        }
                    }
                    nack_ranges = new_nack;
                }

                // The multicast source updates its FEC scheduler with the
                // received losses.
                if let Some(fec_scheduler) = mc_channel.fec_scheduler.as_mut() {
                    if let Some(sent_repairs) = mc_channel
                        .multicast
                        .as_ref()
                        .unwrap()
                        .mc_sent_repairs
                        .to_owned()
                    {
                        let new_lost_pkts = fec_scheduler.recv_nack(
                            pn,
                            &nack_ranges,
                            sent_repairs,
                            nb_degree_opt,
                        );

                        if new_lost_pkts > 0 {
                            // New loss events occured. Handle them as congestion
                            // events.
                            // Get the multicast path.
                            let path = mc_channel
                                .paths
                                .get_mut(multicast.get_mc_space_id().unwrap())?;

                            // Get the first packet indicated in this NACK.
                            // RMC-TODO: ideally, we should only consider packet
                            // numbers that were not taken into account before
                            // that, not simply the first packet.
                            let largest_lost = path
                                .recovery
                                .mc_get_sent_pkt(nack_ranges.last().unwrap());
                            path.recovery.congestion_event(
                                0,
                                &largest_lost.unwrap(),
                                packet::Epoch::Application,
                                now,
                            );

                            // Force to have a minimum window, if set by the
                            // application.
                            // RMC-TODO: remove clients if they cannot support
                            // this minimum congestion window.
                            // path.recovery.mc_set_min_cwnd();
                        }
                    } else {
                        debug!("No sent repairs but received an MC_NACK");
                    }

                    // Reset nack ranges of the unicast server to avoid loops.
                    multicast.set_mc_nack_ranges(None, None)?;
                } else {
                    debug!("FEC disabled but received MC_NACK");
                }
            }

            // Unicast connection asks for the oldest valid packet number of the
            // multicast path.
            if let Some(exp_pkt) =
                mc_channel.multicast.as_ref().unwrap().mc_last_expired
            {
                multicast.mc_last_expired = Some(exp_pkt);
                // if let Some((_, v, w)) = multicast.mc_last_expired {
                //     multicast.mc_last_expired = Some((Some(pn), v, w));
                // } else {
                //     multicast.mc_last_expired = Some((Some(pn), None, None));
                // }
            }

            // Flexicast stream rotation.
            // Unicast server asks for the stream state of the flexicast source.
            // Ideally, this should be computed based on the expired packet
            // number, but for simplicity now, just look at the current stream
            // state of the flexicast source.
            // Additionally, only forward the stream states if the source is
            // authorised to.
            if (multicast
                .fc_rotate_server()
                .is_some_and(|s| !s.already_drained()) ||
                multicast.fc_rotate_server().is_none()) &&
                mc_channel
                    .multicast
                    .as_ref()
                    .map(|m| m.fc_send_stream_states())
                    .unwrap_or(false)
            {
                multicast.fc_rotate = Some(FcRotate::Server(
                    FcRotateServer::new(mc_channel.streams.to_fc_stream_state()),
                ));
            }

            // Unicast connection asks the multicast channel for a new client ID.
            // MC-TODO: now we assign a new client ID even before the client joins
            // the multicast channel.
            if matches!(
                multicast.mc_role,
                McRole::ServerUnicast(McClientStatus::JoinedNoKey)
            ) && multicast.mc_client_id.is_none()
            {
                let client_id = if let Some(McClientId::MulticastServer(map)) =
                    mc_channel.multicast.as_mut().unwrap().mc_client_id.as_mut()
                {
                    map.new_client(self.source_id().as_ref())?
                } else {
                    return Err(Error::Multicast(McError::McInvalidClientId));
                };

                let multicast = self.multicast.as_mut().unwrap();

                multicast.mc_client_id = Some(McClientId::Client(client_id));
            }

            // Unicast connection asks the multicast channel to remove its client
            // ID. This is done because the client left the multicast
            // channel.
            let multicast = self.multicast.as_ref().unwrap();
            if matches!(
                multicast.mc_role,
                McRole::ServerUnicast(McClientStatus::AwareUnjoined)
            ) && multicast.mc_client_id.is_some()
            {
                if let Some(McClientId::MulticastServer(map)) =
                    mc_channel.multicast.as_mut().unwrap().mc_client_id.as_mut()
                {
                    map.remove_from_cid(self.source_id().as_ref())
                        .ok_or(Error::Multicast(McError::McInvalidClientId))?;

                    // Remove the client ID from the server.
                    // MC-TODO: this currently disables the possibility of a
                    // client re-joinging the channel.
                    let multicast = self.multicast.as_mut().unwrap();
                    multicast.mc_client_id = None;
                }
            }

            // Unicast connection asks the multicast channel for open streams.
            // This is only once when the client leaves the multicast channel
            // and relies on the unicast connection to get the data.
            // The unicast server must retransmit streams that are still valid
            // but that the client did not get from the multicast channel.
            // let multicast = self.multicast.as_mut().unwrap();
            // if multicast.mc_client_left_need_sync {
            //     debug!("NEED SYNC BECAUSE CLIENT LEAVES");
            //     multicast.mc_client_left_need_sync = false;

            //     for (&stream_id, stream) in mc_channel.streams.iter() {
            //         let data_vec = stream.send.emit_poll();
            //         for data in &data_vec[..data_vec.len() - 1] {
            //             self.stream_send(stream_id, data, false)?;
            //         }
            //         self.stream_send(stream_id, data_vec.last().unwrap(),
            // true)?;     }
            // }
        } else {
            return Err(Error::Multicast(McError::McDisabled));
        }

        // Multicast source notifies the unicast server with the packets sent on
        // the multicast channel. This is used for the unicast server to compute
        // the congestion window.
        mc_channel.mc_notify_sent_packets(self);

        // Force multicast congestion window.
        // let cwnd = mc_channel.paths.get(1).unwrap().recovery.cwnd();
        // mc_channel.mc_set_cwin(self);
        // let cwnd2 = mc_channel.paths.get(1).unwrap().recovery.cwnd();
        // debug!("After uc_to_mc_control congestion window for client {:?}: {} ->
        // {}", self.multicast.as_ref().map(|m| m.mc_client_id.as_ref()), cwnd,
        // cwnd2);

        if let Some(multicast) = self.multicast.as_ref() {
            if let Some(mc_space_id) = multicast.get_mc_space_id() {
                // let uc_path = &self.paths.get(0).unwrap();
                // let loss_detection_timer =
                //     uc_path.recovery.loss_detection_timer();
                if let Ok(mc_path) = self.paths.get_mut(mc_space_id) {
                    // mc_path.recovery.
                    // mc_set_loss_detection_timer(loss_detection_timer);
                    let expiration_timer = multicast
                        .get_mc_announce_data_path()
                        .unwrap()
                        .expiration_timer;
                    mc_path.recovery.mc_set_rtt(time::Duration::from_millis(
                        expiration_timer,
                    ));

                    // Sets the largest acked packet as the maximum between the
                    // largest actually received and the last expired.
                    if let Some(last_exp) = mc_channel
                        .multicast
                        .as_ref()
                        .unwrap()
                        .mc_last_expired
                        .and_then(|exp| exp.pn)
                    {
                        mc_path.recovery.set_largest_ack(last_exp);
                    }
                }
            }
        }

        Ok(())
    }

    fn get_multicast_attributes(&self) -> Option<&MulticastAttributes> {
        self.multicast.as_ref()
    }

    fn set_mc_space_id(
        &mut self, space_id: u64, path_type: McPathType,
    ) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            multicast.set_mc_space_id(space_id as usize, path_type);
            Ok(())
        } else {
            Err(Error::Multicast(McError::McDisabled))
        }
    }

    fn mc_no_stream_active(&self) -> bool {
        self.multicast.is_some() && self.streams.len() == 0
    }

    fn mc_set_constant_pacing(&mut self, rate: u64) -> Result<()> {
        if let Some(multicast) = self.multicast.as_ref() {
            let now = time::Instant::now();
            if multicast.mc_role != McRole::ServerMulticast {
                return Err(Error::Multicast(McError::McInvalidRole(
                    multicast.mc_role,
                )));
            }
            if let Some(space_id) = multicast.get_mc_space_id() {
                let p = self.paths.get_mut(space_id)?;
                p.recovery.set_pacing_rate(rate, now);
            } else {
                return Err(Error::Multicast(McError::McPath));
            }

            if let Some(space_id) = multicast.get_mc_auth_space_id() {
                let p = self.paths.get_mut(space_id)?;
                p.recovery.set_pacing_rate(rate, now);
            }

            Ok(())
        } else {
            Err(Error::Multicast(McError::McDisabled))
        }
    }

    fn mc_update_tx_cap(&mut self) {
        if let Some(multicast) = self.multicast.as_ref() {
            if multicast.mc_role == McRole::ServerMulticast {
                if let Some(space_id) = multicast.mc_space_id {
                    if let Ok(path) = self.paths.get(space_id) {
                        let cwin_available = path.recovery.cwnd_available();
                        self.max_tx_data += self.tx_data;
                        self.tx_cap = cmp::min(
                            cwin_available,
                            (self.max_tx_data - self.tx_data)
                                .try_into()
                                .unwrap_or(usize::MAX),
                        );
                    }
                }
            }
        }
    }

    fn mc_stream_recv(
        &mut self, stream_id: u64, out: &mut [u8],
    ) -> Result<(usize, bool)> {
        let multicast = self
            .multicast
            .as_ref()
            .ok_or(Error::Multicast(McError::McDisabled))?;

        if multicast.mc_auth_type == McAuthType::StreamAsym {
            if !matches!(multicast.mc_role, McRole::Client(_)) {
                return Err(Error::Multicast(McError::McInvalidRole(
                    multicast.mc_role,
                )));
            }

            let stream = self
                .streams
                .get_mut(stream_id)
                .ok_or(Error::InvalidStreamState(stream_id))?;
            if !stream.mc_asym_verified {
                if !stream.recv.is_fully_readable() {
                    return Err(Error::Done);
                }

                // MC-TODO: 32 should not be hardcoded.
                let authentication = stream
                    .mc_get_asym_sign()
                    .ok_or(Error::Multicast(McError::McInvalidAuth))?;
                let mut buf = vec![0u8; 32 + authentication.len()];
                let mut data = stream.recv.hash_stream(&mut buf[..32])?;
                // let mut data = stream.recv.hash_stream_incr()?.to_vec();
                buf[32..].copy_from_slice(authentication);
                data.extend_from_slice(authentication);
                self.mc_verify_asym(&data)?;
                let stream = self
                    .streams
                    .get_mut(stream_id)
                    .ok_or(Error::InvalidStreamState(stream_id))?;
                stream.mc_asym_verified = true;
            }
        }

        self.stream_recv(stream_id, out)
    }

    fn set_mc_prioritize_fec(&mut self, v: bool) {
        if let Some(multicast) = self.multicast.as_mut() {
            multicast.mc_prioritize_fec = v;
        }
    }
}

impl Connection {
    /// The multicast source notifies the unicast server of the packets sent.
    fn mc_notify_sent_packets(&mut self, uc: &mut Connection) {
        if let Some(multicast) = self.multicast.as_ref() {
            // This just delays the problem.
            // if let Some(mc_uc) = uc.get_multicast_attributes() {
            //     if !matches!(mc_uc.get_mc_role(),
            // McRole::ServerUnicast(McClientStatus::ListenMcPath(_)))
            // {         return;
            //     }
            // } else {
            //     return;
            // }
            if let Some(mc_space_id) = multicast.get_mc_space_id() {
                let mc_path = self.paths.get(mc_space_id);
                let uc_trace_id = uc.trace_id().to_string();
                let cur_max_pn = if let Some(mc) = uc.multicast.as_ref() {
                    mc.cur_max_pn
                } else {
                    return;
                };
                let uc_path = uc.paths.get_mut(mc_space_id);
                if let (Ok(mc_path), Ok(uc_path)) = (mc_path, uc_path) {
                    let new_max_pn = mc_path.recovery.copy_sent(
                        &mut uc_path.recovery,
                        mc_space_id as u32,
                        Epoch::Application,
                        self.handshake_status(),
                        &uc_trace_id,
                        cur_max_pn,
                    );
                    let uc_mc = uc.multicast.as_mut().unwrap();
                    uc_mc.cur_max_pn = new_max_pn;
                    // self.multicast.as_mut().unwrap().cur_max_pn = new_max_pn;
                    uc_mc.mc_last_expired =
                        self.multicast.as_ref().unwrap().mc_last_expired;
                }
            }
        }
    }

    /// Sets the congestion window of the multicast source based on the
    /// congestion window of the unicast connection.
    pub fn mc_get_uc_cwnd(&self) -> Option<usize> {
        // Get paths.
        if let Some(multicast) = self.multicast.as_ref() {
            // Do not give the multicast window if not in the multicast channel.
            if matches!(
                multicast.get_mc_role(),
                McRole::ServerUnicast(McClientStatus::ListenMcPath(_))
            ) {
                if let Some(_mc_space_id) = multicast.get_mc_space_id() {
                    let uc_path = self.paths.get(1);
                    if let Ok(uc_path) = uc_path {
                        if uc_path.recovery.cwnd_available() == usize::MAX {
                            return None;
                        }
                        debug!(
                            "Client {:?} has a cwnd of {:?}",
                            multicast.get_self_client_id(),
                            uc_path.recovery.cwnd()
                        );
                        return Some(uc_path.recovery.cwnd());
                        // return Some(uc_path.recovery.cwnd_available());
                    }
                }
            }
        }
        None
    }

    /// Sets the congestion window of the multicast source.
    pub fn mc_set_cwnd(&mut self, cwnd: usize) {
        if let Some(multicast) = self.multicast.as_ref() {
            if let Some(mc_space_id) = multicast.get_mc_space_id() {
                if let Ok(path) = self.paths.get_mut(mc_space_id) {
                    path.recovery.mc_force_cwin(cwnd);
                }
            }
        }
    }
}

/// Extension of a RangeSet to support missing ranges.
pub trait MissingRangeSet {
    /// Returns a RangeSet containing the numbers missing in the RangeSet.
    fn get_missing(&self) -> Self;

    /// Returns the number of elements in the RangeSet.
    fn nb_elements(&self) -> usize;
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

    fn nb_elements(&self) -> usize {
        self.flatten().collect::<Vec<_>>().len()
    }
}

#[derive(Clone, PartialEq, Debug)]
/// Multicast parameters advertised by a client.
/// TODO: complete the structure and documentation.
pub struct McClientTp {
    /// Allow IPv6 multicast channels.
    pub ipv6_channels_allowed: bool,
    /// Allows IPv4 multicast channels.
    pub ipv4_channels_allowed: bool,
}

impl Default for McClientTp {
    #[inline]
    fn default() -> Self {
        McClientTp {
            ipv6_channels_allowed: true,
            ipv4_channels_allowed: true,
        }
    }
}

impl From<Vec<u8>> for McClientTp {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self {
            ipv6_channels_allowed: v[0] != 0,
            ipv4_channels_allowed: v[1] != 0,
        }
    }
}

impl From<&McClientTp> for Vec<u8> {
    fn from(v: &McClientTp) -> Self {
        vec![
            if v.ipv6_channels_allowed { 1 } else { 0 },
            if v.ipv4_channels_allowed { 1 } else { 0 },
        ]
    }
}

impl Connection {
    /// Prints the list of streams that are still open.
    pub fn see_streams(&self) -> bool {
        self.streams.len() == 0
        // debug!("This is the streams for client id {:?}: {:?}",
        // self.multicast.as_ref().map(|m| m.mc_client_id.as_ref()),
        // self.streams.iter().map(|(id, _)| id).collect::<Vec<_>>());
        // debug!("And this is the list of I don't know: {:?}",
        // self.streams.iter().map(|(_, s)|
        // s.is_complete()).collect::<Vec<_>>());
    }
}

#[doc(hidden)]
pub struct McPathInfo<'a> {
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub cid: ConnectionId<'a>,
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

    /// Authentication channel information.
    pub mc_auth_info: Option<(ConnectionId<'static>, u128, SocketAddr)>,
}

impl MulticastChannelSource {
    #[allow(clippy::too_many_arguments)]
    /// Creates a new source multicast channel.
    pub fn new_with_tls(
        mc_path_info: McPathInfo, config_server: &mut Config,
        config_client: &mut Config, peer: SocketAddr, keylog_filename: &str,
        authentication: authentication::McAuthType,
        auth_path_info: Option<McPathInfo>, mc_cwnd: Option<usize>,
    ) -> Result<Self> {
        if mc_cwnd.is_some() {
            config_client.cc_algorithm = CongestionControlAlgorithm::DISABLED;
            config_server.cc_algorithm = CongestionControlAlgorithm::DISABLED;
        } else if !(config_client.cc_algorithm ==
            CongestionControlAlgorithm::DISABLED &&
            config_server.cc_algorithm == CongestionControlAlgorithm::DISABLED)
        {
            return Err(Error::CongestionControl);
        }

        let mut scid = [0; 16];
        ring::rand::SystemRandom::new().fill(&mut scid[..]).unwrap();
        let scid = ConnectionId::from_ref(&scid);

        // Add the keylog file.
        let key_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(keylog_filename)
            .map_err(|_| Error::Multicast(McError::McInvalidSymKey))?;
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

        let exporter_secret =
            MulticastChannelSource::get_exporter_secret(keylog_filename)?;

        // Get the encryption algorithm.
        let encryption_algo =
            conn_server.handshake.cipher().ok_or(Error::CryptoFail)?;

        let signature_eddsa = match authentication {
            McAuthType::AsymSign | McAuthType::StreamAsym =>
                Some(MulticastChannelSource::compute_asymetric_signature_keys()?),
            _ => None,
        };

        conn_server.multicast = Some(MulticastAttributes {
            mc_private_key: signature_eddsa,
            mc_role: McRole::ServerMulticast,
            mc_client_id: Some(McClientId::MulticastServer(
                McClientIdSource::default(),
            )),
            mc_auth_type: authentication,
            mc_pn_need_sym_sign: Some(VecDeque::new()),
            mc_last_recv_time: Some(time::Instant::now()),
            mc_sent_repairs: Some(ranges::RangeSet::default()),
            mc_channel_algo: encryption_algo,
            ..Default::default()
        });

        let mut reset_token = [0; 16];
        rand_bytes(&mut reset_token);
        let reset_token = u128::from_be_bytes(reset_token);

        // Add a new Connection ID for the multicast path.
        let channel_id = ConnectionId::from_ref(mc_path_info.cid.as_ref());
        conn_server.new_source_cid(&channel_id, reset_token, true)?;
        conn_client.new_source_cid(&channel_id, reset_token, true)?;
        Self::advance(&mut conn_server, &mut conn_client)?;

        // Probe the new path.
        conn_client.probe_path(mc_path_info.local, mc_path_info.peer)?;
        let pid_c2s_1 = conn_client
            .paths
            .path_id_from_addrs(&(mc_path_info.local, mc_path_info.peer))
            .expect("no such path");
        let mc_path_client = conn_client.paths.get_mut(pid_c2s_1)?;
        mc_path_client.recovery.reset();
        Self::advance(&mut conn_server, &mut conn_client)?;
        let pid_s2c_1 = conn_server
            .paths
            .path_id_from_addrs(&(mc_path_info.peer, mc_path_info.local))
            .expect("no such path");
        let mc_path_server = conn_server.paths.get_mut(pid_s2c_1)?;
        // Set the congestion window of the multicast source for the data path.
        if let Some(cwnd) = mc_cwnd {
            mc_path_server.recovery.set_mc_max_cwnd(cwnd);
        }
        mc_path_server.recovery.reset();

        conn_server.multicast.as_mut().unwrap().mc_space_id = Some(pid_s2c_1);

        // Set the new path active.
        conn_client.set_active(mc_path_info.local, mc_path_info.peer, true)?;
        conn_server.set_active(mc_path_info.peer, mc_path_info.local, true)?;
        Self::advance(&mut conn_server, &mut conn_client)?;

        // Same with the authentication multicast path.
        let mc_auth_info = if let Some(auth) = auth_path_info {
            conn_server.new_source_cid(&auth.cid, reset_token, true)?;
            conn_client.new_source_cid(&auth.cid, reset_token, true)?;
            Self::advance(&mut conn_server, &mut conn_client)?;

            conn_client.probe_path(auth.local, auth.peer)?;
            let pid_c2s_1 = conn_client
                .paths
                .path_id_from_addrs(&(auth.local, auth.peer))
                .expect("no such path");
            let mc_path_client = conn_client.paths.get_mut(pid_c2s_1)?;
            mc_path_client.recovery.reset();
            Self::advance(&mut conn_server, &mut conn_client)?;
            let pid_s2c_1 = conn_server
                .paths
                .path_id_from_addrs(&(auth.peer, auth.local))
                .expect("no such path");
            let mc_path_server = conn_server.paths.get_mut(pid_s2c_1)?;

            // Set the congestion window of the multicast source for the auth
            // path.
            if let Some(cwnd) = mc_cwnd {
                mc_path_server.recovery.set_mc_max_cwnd(cwnd);
            }
            // } else {
            //     mc_path_server.recovery.set_mc_max_cwnd(std::usize::MAX - 1);
            // }
            mc_path_server.recovery.reset();

            conn_server.multicast.as_mut().unwrap().mc_auth_space_id =
                Some(pid_s2c_1);

            // Set the new path active.
            conn_client.set_active(auth.local, auth.peer, true)?;
            conn_server.set_active(auth.peer, auth.local, true)?;
            Self::advance(&mut conn_server, &mut conn_client)?;

            Some((auth.cid.clone().into_owned(), reset_token, auth.peer))
        } else {
            None
        };

        conn_client.multicast = Some(MulticastAttributes {
            mc_role: McRole::Client(McClientStatus::Unspecified),
            fc_rotate: Some(FcRotate::Src(false)),
            ..MulticastAttributes::default()
        });
        conn_client.multicast.as_mut().unwrap().mc_space_id = Some(pid_c2s_1);

        let cid = channel_id.clone().into_owned();
        Ok(Self {
            channel: conn_server,
            client_backup: conn_client,
            master_secret: exporter_secret,
            mc_path_conn_id: (cid, reset_token),
            mc_path_peer: mc_path_info.peer,
            mc_send_addr: peer,
            mc_auth_info,
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
    pub fn advance(
        server: &mut Connection, client: &mut Connection,
    ) -> Result<()> {
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
            .map_err(|_| Error::Multicast(McError::McInvalidSymKey))?;
        let mut reader = std::io::BufReader::new(fd);
        let mut in_string = String::new();
        for _ in 0..3 {
            reader
                .read_line(&mut in_string)
                .map_err(|_| Error::Multicast(McError::McInvalidSymKey))?;
            in_string = String::new();
        }
        reader
            .read_line(&mut in_string)
            .map_err(|_| Error::Multicast(McError::McInvalidSymKey))?; // This is very ugly, erk
        let splited = in_string.split(' ');
        let a = splited
            .last()
            .ok_or(Error::Multicast(McError::McInvalidSymKey))?;
        (0..a.len() - 1)
            .step_by(2)
            .map(|i| {
                a.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
                    .ok_or(Error::Multicast(McError::McInvalidSymKey))
            })
            .collect()
    }

    /// Computes a new asymetric key pair.
    fn compute_asymetric_signature_keys() -> Result<signature::Ed25519KeyPair> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| crate::Error::Multicast(McError::McInvalidAsymKey))?;

        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            pkcs8_bytes.as_ref(),
        )
        .map_err(|_| crate::Error::Multicast(McError::McInvalidAsymKey))?;

        Ok(key_pair)
    }

    /// Multicast-version of the [`send`] method of the crate.
    /// It sends on the multicast path always.
    /// Internally, it uses [`send_on_path`] with the multicast addresses
    /// specified during the source multicast channel configuration.
    ///
    /// This function is equivalent to [`send`] and authenticate
    /// the source of the data. If the path authentication method is asymetric
    /// signature, it uses the private key computed internaly by the server
    /// to generate a signature of the packet. If it is symetric HMACs, signals
    /// that an additional packet with the signatures must be sent by the source
    /// on the authentication path. This function is strictly equivalent to
    /// [`send`] if the server does not authenticate data.
    /// The client and server should have agreed on the use of authentication.
    /// The choice of the authentication is done by
    /// [`MulticastAttributes::mc_auth_type`].
    ///
    /// MC-TODO: only Ed25519 is used at the moment.
    /// The last bytes of the packet contain the signature.
    pub fn mc_send(&mut self, buf: &mut [u8]) -> Result<(usize, SendInfo)> {
        self.channel.send_on_path(
            buf,
            Some(self.mc_path_peer),
            Some(self.mc_path_peer),
        )
    }

    /// Equivalent of the [`MulticastChannelSource::mc_send`] method but for
    /// authentication packetss. Send on the authentication multicast path if it
    /// exists.
    ///
    /// Generates a [`McError::McInvalidAuth`] error if the
    /// authentication method is not symetric signature.
    pub fn mc_send_sym_auth(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(mc_auth) = self.mc_auth_info.as_ref() {
            self.channel
                .send_on_path(buf, Some(mc_auth.2), Some(mc_auth.2))
                .map(|(written, _)| written)
        } else {
            Err(Error::Multicast(McError::McInvalidAuth))
        }
    }
}

#[derive(Default, Debug)]
/// Client connection ID to client ID mapping. Used by the server to
/// authenticate message with a symetric signature.
pub struct McClientIdSource {
    max_client_id: u64,
    id_to_cid: HashMap<u64, Vec<u8>>,
    cid_to_id: HashMap<Vec<u8>, u64>,
}

impl McClientIdSource {
    /// Returns a new client ID based on a connection ID.
    /// Ask for a slice of u8 because it may be more convenient in some cases.
    ///
    /// Inserts the new client ID in the map.
    /// Returns an error if the connection ID is already in the map.
    pub fn new_client(&mut self, cid: &[u8]) -> Result<u64> {
        if self.cid_to_id.contains_key(cid) {
            return Err(Error::Multicast(McError::McInvalidClientId));
        }

        let client_id = self.max_client_id;
        self.max_client_id += 1;
        self.cid_to_id.insert(cid.to_vec(), client_id);
        self.id_to_cid.insert(client_id, cid.to_vec());

        Ok(client_id)
    }

    /// Retrieves the client ID based on the connection ID.
    pub fn get_client_id(&self, cid: &[u8]) -> Option<u64> {
        self.cid_to_id.get(cid).copied()
    }

    /// Retrieves the connection id based on the client ID.
    pub fn get_client_cid(&self, client_id: u64) -> Option<&[u8]> {
        match self.id_to_cid.get(&client_id) {
            Some(v) => Some(v),
            None => None,
        }
    }

    /// Remove a client using the connection ID.
    pub fn remove_from_cid(&mut self, cid: &[u8]) -> Option<u64> {
        let client_id = self.cid_to_id.get(cid)?.to_owned();
        self.cid_to_id.remove(cid)?;
        self.id_to_cid.remove(&client_id);

        Some(client_id)
    }

    /// Remove a client using the client ID.
    pub fn remove_from_id(&mut self, id: u64) -> Option<u64> {
        let cid = self.id_to_cid.get(&id)?;
        self.cid_to_id.remove(cid)?;
        self.id_to_cid.remove(&id)?;

        Some(id)
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Copy)]
/// Structure containing expired packets information.
pub struct ExpiredPkt {
    /// Maximum packet number expired.
    pub pn: Option<u64>,

    /// Maximum FEC Source Symbol ID (ssid) expired.
    pub ssid: Option<u64>,
}

impl From<(Option<u64>, Option<u64>)> for ExpiredPkt {
    fn from(value: (Option<u64>, Option<u64>)) -> Self {
        ExpiredPkt {
            pn: value.0,
            ssid: value.1,
        }
    }
}

impl ExpiredPkt {
    /// Whether the structure is full of `None`.
    pub(crate) fn is_none(&self) -> bool {
        self.pn.is_none() && self.ssid.is_none()
    }
}

/// List of expired stream IDs.
pub type ExpiredStream = HashSet<u64>;

#[derive(Debug)]
/// Client ID for the different multicast roles.
pub enum McClientId {
    /// Clients stores its client ID.
    /// Unicast server store the client ID of its unicast client.
    Client(u64),

    /// The multicast server maintains a mapping for all its clients.
    MulticastServer(McClientIdSource),
}

/// Provide structures and functions to help testing the multicast extension of
/// QUIC.
pub mod testing {
    use std::collections::HashSet;
    use std::ops::Range;

    use networkcoding::SourceSymbolMetadata;
    use ring::rand::SecureRandom;
    use ring::rand::SystemRandom;

    use crate::testing;
    use crate::testing::Pipe;
    use crate::Config;

    use super::*;

    #[doc(hidden)]
    pub const CLIENT_AUTH_ADDR: &str = "127.0.0.1:5679";

    #[doc(hidden)]
    /// Flexicast configuration for testing.
    pub struct FcConfigTest {
        pub mc_client_tp: McClientTp,

        pub mc_announce_data: McAnnounceData,

        pub mc_data_auth: Option<McAnnounceData>,

        pub authentication: McAuthType,

        pub probe_mc_path: bool,
    }

    impl Default for FcConfigTest {
        fn default() -> Self {
            Self {
                mc_announce_data: get_test_mc_announce_data(),
                authentication: McAuthType::None,
                probe_mc_path: true,
                mc_client_tp: McClientTp::default(),
                mc_data_auth: None,
            }
        }
    }

    /// Multicast extension of crate::testing::Pipe.
    ///
    /// Contains a Pipe for each unicast connection and multicast source
    /// channel. Performs the multicast extension negociation for each client
    /// in the pipe.
    pub struct MulticastPipe {
        /// All unicast connections between the clients and the server.
        pub unicast_pipes: Vec<(Pipe, SocketAddr, SocketAddr)>,

        /// Multicast source channel.
        pub mc_channel: MulticastChannelSource,

        /// Multicast channel infirmation (MC_ANNOUNCE data).
        pub mc_announce_data: McAnnounceData,
    }

    impl MulticastPipe {
        /// Generates a new multicast pipe with already defined configuration.
        pub fn new(
            nb_clients: usize, keylog_filename: &str, authentication: McAuthType,
            use_fec: bool, probe_mc_path: bool, max_cwnd: Option<usize>,
        ) -> Result<MulticastPipe> {
            let mc_announce_data = get_test_mc_announce_data();
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

        /// Generates a new multicast pipe with already defined configuration
        /// and Mc announce data.
        pub fn new_from_mc_announce_data(
            nb_clients: usize, keylog_filename: &str, authentication: McAuthType,
            use_fec: bool, probe_mc_path: bool, max_cwnd: Option<usize>,
            mut mc_announce_data: McAnnounceData,
        ) -> Result<MulticastPipe> {
            let mc_client_tp = McClientTp::default();
            let mut server_config =
                get_test_mc_config(true, None, use_fec, authentication);
            let mut client_config = get_test_mc_config(
                false,
                Some(&mc_client_tp),
                use_fec,
                authentication,
            );
            mc_announce_data.auth_type = authentication;

            // Change the config to set the maximum number of bytes that can be
            // sent if the congestion window is fixed.
            // if let Some(cwnd) = max_cwnd {
            //     server_config.set_initial_max_data(cwnd as u64);
            //     client_config.set_initial_max_data(cwnd as u64);
            // }

            // Create a new announce data if the channel uses symetric
            // authentication.
            let mut mc_data_auth = if authentication == McAuthType::SymSign {
                let mut data = get_test_mc_announce_data();
                data.udp_port += 10;
                data.path_type = McPathType::Authentication;
                data.channel_id =
                    [0xff, 0xdd, 0xee, 0xaa, 0xbb, 0x33, 0x44].to_vec();

                Some(data)
            } else {
                None
            };

            // Multicast path.
            let mut mc_channel = get_test_mc_channel_source(
                &mut server_config,
                &mut client_config,
                authentication,
                keylog_filename,
                max_cwnd,
            )
            .unwrap();

            mc_channel
                .channel
                .mc_set_mc_announce_data(&mc_announce_data)?;

            // Copy the channel ID derived from the multicast channel.
            mc_announce_data.channel_id =
                mc_channel.mc_path_conn_id.0.as_ref().to_vec();

            if let Some(mc_data) = mc_data_auth.as_mut() {
                mc_data.channel_id = mc_channel
                    .mc_auth_info
                    .as_ref()
                    .unwrap()
                    .0
                    .as_ref()
                    .to_vec();
            }

            mc_channel
                .channel
                .multicast
                .as_mut()
                .unwrap()
                .mc_announce_data
                .push(mc_announce_data.clone());

            // Push the authentication data if it exists.
            if let Some(mc_data) = mc_data_auth.as_ref() {
                mc_channel
                    .channel
                    .multicast
                    .as_mut()
                    .unwrap()
                    .mc_announce_data
                    .push(mc_data.clone());
            }

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

            let random = ring::rand::SystemRandom::new();

            let fc_config = FcConfigTest {
                mc_client_tp,
                mc_announce_data: mc_announce_data.clone(),
                mc_data_auth,
                authentication,
                probe_mc_path,
                ..FcConfigTest::default()
            };

            let pipes: Vec<_> = (0..nb_clients)
                .flat_map(|_| {
                    MulticastPipe::setup_client(
                        &mut mc_channel,
                        &fc_config,
                        &random,
                    )
                })
                .collect();

            if pipes.len() != nb_clients {
                return Err(Error::Multicast(McError::McPipe));
            }

            Ok(MulticastPipe {
                unicast_pipes: pipes,
                mc_channel,
                mc_announce_data,
            })
        }

        /// The multicast source sends a single packet using the buffer given as
        /// argument. Returns the number of bytes sent by the source and writes
        /// the packet content in the input buffer.
        ///
        /// `client_loss` is a RangeSet containing the indexes of clients that
        /// DO NOT receive the packet. `None` if all clients receive the packet.
        pub fn source_send_single_from_buf(
            &mut self, client_loss: Option<&RangeSet>, signature_len: usize,
            mc_buf: &mut [u8],
        ) -> Result<usize> {
            let (written, _) = self.mc_channel.mc_send(&mut mc_buf[..])?;

            // This is not optimal but it works...
            let client_loss = if let Some(client_loss) = client_loss {
                client_loss.flatten().collect()
            } else {
                HashSet::new()
            };
            let idx_client_receive = (0..self.unicast_pipes.len())
                .filter(|&idx| !client_loss.contains(&(idx as u64)));

            for client_idx in idx_client_receive {
                let mut recv_buf = mc_buf.to_owned();
                let (pipe, client_addr, server_addr) =
                    self.unicast_pipes.get_mut(client_idx).unwrap();

                let recv_info = RecvInfo {
                    from: *server_addr,
                    to: *client_addr,
                    from_mc: Some(McPathType::Data),
                };

                let res =
                    pipe.client.mc_recv(&mut recv_buf[..written], recv_info)?;
                assert_eq!(res, written - signature_len);
            }

            Ok(written)
        }

        /// Creates a new client and initiate the handshake to use multicast.
        pub fn setup_client(
            mc_channel: &mut MulticastChannelSource, fc_config: &FcConfigTest,
            random: &SystemRandom,
        ) -> Option<(Pipe, SocketAddr, SocketAddr)> {
            let mut config = get_test_mc_config(
                true,
                Some(&fc_config.mc_client_tp),
                true,
                fc_config.authentication,
            );
            let mut pipe =
                Pipe::with_config_and_scid_lengths(&mut config, 16, 16).ok()?;
            pipe.handshake().ok()?;

            pipe.server
                .mc_set_mc_announce_data(&fc_config.mc_announce_data)
                .unwrap();
            if let Some(mc_data) = &fc_config.mc_data_auth {
                pipe.server.mc_set_mc_announce_data(mc_data).unwrap();
            }
            let multicast = pipe.server.multicast.as_mut().unwrap();
            multicast.mc_channel_key = Some(mc_channel.master_secret.clone());

            // The server adds the connection IDs of the multicast
            // channel.
            let mut scid = [0; 16];
            random.fill(&mut scid[..]).unwrap();

            let scid = ConnectionId::from_ref(&scid);
            let mut reset_token = [0; 16];
            random.fill(&mut reset_token).unwrap();
            let reset_token = u128::from_be_bytes(reset_token);
            pipe.server
                .new_source_cid(&scid, reset_token, true)
                .unwrap();

            if fc_config.mc_data_auth.is_some() {
                let mut scid = [0; 16];
                random.fill(&mut scid[..]).unwrap();

                let scid = ConnectionId::from_ref(&scid);
                let mut reset_token = [0; 16];
                random.fill(&mut reset_token).unwrap();
                let reset_token = u128::from_be_bytes(reset_token);
                pipe.server
                    .new_source_cid(&scid, reset_token, true)
                    .unwrap();
            }

            assert!(pipe.advance().is_ok());

            // Client joins the multicast channel.
            pipe.client.mc_join_channel(true).unwrap();
            pipe.advance().unwrap();

            // Server computes the client ID.
            pipe.server
                .uc_to_mc_control(&mut mc_channel.channel, time::Instant::now())
                .unwrap();

            // The server gives the master key.
            pipe.advance().unwrap();

            let scid =
                ConnectionId::from_ref(&fc_config.mc_announce_data.channel_id);
            pipe.client.add_mc_cid(&scid).unwrap();
            assert_eq!(pipe.advance(), Ok(()));

            let server_addr = testing::Pipe::server_addr();
            let client_addr_2 = "127.0.0.1:5678".parse().unwrap();

            pipe.client
                .create_mc_path(
                    client_addr_2,
                    server_addr,
                    fc_config.probe_mc_path,
                )
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
                .set_mc_space_id(pid_c2s_1, McPathType::Data);

            assert_eq!(pipe.advance(), Ok(()));

            if pipe
                .client
                .multicast
                .as_ref()
                .unwrap()
                .get_mc_announce_data(1)
                .is_some()
            {
                let scid = crate::ConnectionId::from_ref(
                    &fc_config.mc_data_auth.as_ref().unwrap().channel_id,
                );

                pipe.client.add_mc_cid(&scid).unwrap();
                assert_eq!(pipe.advance(), Ok(()));

                let server_addr = testing::Pipe::server_addr();
                let client_addr_2 = CLIENT_AUTH_ADDR.parse().unwrap();

                pipe.client
                    .create_mc_path(
                        client_addr_2,
                        server_addr,
                        fc_config.probe_mc_path,
                    )
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
                    .set_mc_space_id(pid_c2s_1, McPathType::Authentication);

                assert_eq!(pipe.advance(), Ok(()));
            }

            assert_eq!(pipe.advance(), Ok(()));

            if let Ok(p) = pipe.server.paths.get_mut(1) {
                p.recovery.set_mc_max_cwnd(10);
            }

            Some((pipe, client_addr_2, server_addr))
        }

        /// The multicast source sends a single packet.
        /// Returns the number of bytes sent by the source.
        ///
        /// `client_loss` is a RangeSet containing the indexes of clients that
        /// DO NOT receive the packet. `None` if all clients receive the packet.
        pub fn source_send_single(
            &mut self, client_loss: Option<&RangeSet>, signature_len: usize,
        ) -> Result<usize> {
            let mut mc_buf = [0u8; 1500];
            self.source_send_single_from_buf(
                client_loss,
                signature_len,
                &mut mc_buf,
            )
        }

        /// The multicast source sends a single small stream of 300 bytes to fit
        /// in a single QUIC packet.
        /// Calls [`MulticastPipe::source_send_single`].
        ///
        /// `client_loss` is a RangeSet containing the indexes of clients that
        /// do not receive the packet. `None` if all clients receive the packet.
        pub fn source_send_single_stream(
            &mut self, send: bool, client_loss: Option<&RangeSet>,
            signature_len: usize, stream_id: u64,
        ) -> Result<usize> {
            let mut mc_buf = [0u8; 300];
            ring::rand::SystemRandom::new()
                .fill(&mut mc_buf[..])
                .unwrap();
            self.mc_channel
                .channel
                .stream_send(stream_id, &mc_buf, true)?;

            if send {
                self.source_send_single(client_loss, signature_len)
            } else {
                Ok(0)
            }
        }

        /// The clients send feedback using the unicast connection to the
        /// server.
        pub fn clients_send(&mut self) -> Result<()> {
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
                        from_mc: None,
                    };
                    pipe.server.recv(&mut buf[..written], recv_info)?;
                }
            }

            Ok(())
        }

        /// The unicast server sends multicast feedback control from the client
        /// to the multicast source.
        pub fn server_control_to_mc_source(
            &mut self, now: time::Instant,
        ) -> Result<()> {
            let mc_channel = &mut self.mc_channel.channel;
            for (pipe, ..) in self.unicast_pipes.iter_mut() {
                pipe.server.uc_to_mc_control(mc_channel, now)?;
            }

            Ok(())
        }

        /// The unicast server specified by the index argument sends a single
        /// stream to its client.
        pub fn uc_server_send_single_stream(
            &mut self, stream_id: u64, pipe_idx: usize,
        ) -> Result<()> {
            let mut buf = [0u8; 300];
            ring::rand::SystemRandom::new().fill(&mut buf[..]).unwrap();

            let pipe = &mut self.unicast_pipes.get_mut(pipe_idx).unwrap().0;
            pipe.server.stream_send(stream_id, &buf, true)?;
            pipe.advance()
        }

        /// The multicast source sends as much authentication packets as needed.
        pub fn mc_source_sends_auth_packets(
            &mut self, client_loss: Option<&RangeSet>,
        ) -> Result<usize> {
            let mut mc_buf = [0u8; 1500];
            let written = self.mc_channel.mc_send_sym_auth(&mut mc_buf[..])?;

            // This is not optimal but it works...
            let client_loss = if let Some(client_loss) = client_loss {
                client_loss.flatten().collect()
            } else {
                HashSet::new()
            };
            let idx_client_receive = (0..self.unicast_pipes.len())
                .filter(|&idx| !client_loss.contains(&(idx as u64)));

            for client_idx in idx_client_receive {
                let mut recv_buf = mc_buf;
                let (pipe, _, server_addr) =
                    self.unicast_pipes.get_mut(client_idx).unwrap();

                let recv_info = RecvInfo {
                    from: *server_addr,
                    to: CLIENT_AUTH_ADDR.parse().unwrap(),
                    from_mc: Some(McPathType::Authentication),
                };

                let res = pipe
                    .client
                    .mc_recv(&mut recv_buf[..written], recv_info)
                    .unwrap();
                assert_eq!(res, written);
            }

            Ok(written)
        }
    }

    /// Simple config used for testing the multicast extension only.
    pub fn get_test_mc_config(
        mc_server: bool, mc_client: Option<&McClientTp>, use_fec: bool,
        auth: McAuthType,
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
        populate_test_mc_config(&mut config, mc_server, mc_client, use_fec, auth);
        config
    }

    /// Populate a configuration with multicast values.
    pub fn populate_test_mc_config(
        config: &mut Config, mc_server: bool, mc_client: Option<&McClientTp>,
        use_fec: bool, auth: McAuthType,
    ) {
        config
            .set_application_protos(&[b"proto1", b"proto2"])
            .unwrap();
        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(5_000_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000_000);
        config.set_initial_max_stream_data_uni(1_000_000_000);
        config.set_initial_max_streams_bidi(1_000_000_000);
        config.set_initial_max_streams_uni(1_000_000_000);
        config.set_active_connection_id_limit(5);
        config.verify_peer(false);
        config.set_multipath(true);
        config.set_enable_server_multicast(mc_server);
        config.set_enable_client_multicast(mc_client);
        config.send_fec(use_fec);
        config.receive_fec(use_fec);
        config.set_fec_window_size(500_000);
        config.set_mc_max_nb_repair_symbols(Some(std::u32::MAX));
        config.set_fec_scheduler_algorithm(
            crate::fec::fec_scheduler::FECSchedulerAlgorithm::RetransmissionFec,
        );
        config.set_cc_algorithm(CongestionControlAlgorithm::Reno);
        if auth == McAuthType::AsymSign {
            config.set_fec_symbol_size(1280 - 64);
        } else {
            config.set_fec_symbol_size(1280);
        }
    }

    /// Simple McAnnounceData for testing the multicast extension only.
    pub fn get_test_mc_announce_data() -> McAnnounceData {
        McAnnounceData {
            channel_id: [0xff, 0xdd, 0xee, 0xaa, 0xbb, 0x33, 0x66].to_vec(),
            is_ipv6: false,
            path_type: McPathType::Data,
            source_ip: std::net::Ipv4Addr::new(127, 0, 0, 1).octets(),
            group_ip: std::net::Ipv4Addr::new(224, 0, 0, 1).octets(),
            udp_port: 7676,
            public_key: None,
            expiration_timer: 1_000_000,
            is_processed: false,
            auth_type: McAuthType::None,
            full_reliability: false,
        }
    }

    /// Simple source multicast channel for the tests.
    pub fn get_test_mc_channel_source(
        config_server: &mut Config, config_client: &mut Config,
        authentication: McAuthType, keylog_filename: &str,
        max_cwnd: Option<usize>,
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

        let mc_path_info = McPathInfo {
            local: to2,
            peer: to2,
            cid: channel_id,
        };

        let mut channel_id_auth = [0; 16];
        let auth_path_info = if authentication == McAuthType::SymSign {
            ring::rand::SystemRandom::new()
                .fill(&mut channel_id_auth[..])
                .unwrap();
            let channel_id = ConnectionId::from_ref(&channel_id_auth);

            let dummy_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
            let dummy_port = 1239;
            let to2 = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                dummy_ip,
                dummy_port + 1,
            ));

            Some(McPathInfo {
                local: to2,
                peer: to2,
                cid: channel_id,
            })
        } else {
            None
        };

        MulticastChannelSource::new_with_tls(
            mc_path_info,
            config_server,
            config_client,
            to,
            keylog_filename,
            authentication,
            auth_path_info,
            max_cwnd,
        )
    }

    impl MulticastChannelSource {
        /// Only used for tests and benchmarks.
        /// Sets the source nack range directly in the FEC scheduler.
        pub fn set_source_nack_range(
            &mut self, rangeset: &OpenRangeSet, pn: u64,
        ) -> Result<()> {
            if let Some(fec_scheduler) = self.channel.fec_scheduler.as_mut() {
                // fec_scheduler.lost_source_symbol(
                //     &rangeset.ranges,
                //     conn_id_ref.cid.as_ref(),
                // );
                fec_scheduler.recv_nack(
                    pn,
                    &rangeset.ranges,
                    RangeSet::default(),
                    Some(rangeset.ranges.len() as u64),
                );
            }

            Ok(())
        }

        /// Only used for tests and benchmarks.
        /// Removes all source symbols in the FEC window.
        pub fn remove_source_symbols(&mut self, up_to: [u8; 8]) {
            self.channel.fec_encoder.remove_up_to(up_to);
            // self.channel.fec_encoder.n_protected_symbols());
        }

        /// Only used for tests and benchmarks.
        /// Returns the metadata of the source symbols to remove.
        #[inline]
        pub fn fec_sliding_window_metadata(
            &self, window_size: usize,
        ) -> Option<SourceSymbolMetadata> {
            let first_metadata = self.channel.fec_encoder.first_metadata()?;
            let sid = u64::from_be_bytes(first_metadata);
            let too_many_symbols = self
                .channel
                .fec_encoder
                .n_protected_symbols()
                .saturating_sub(window_size);
            if too_many_symbols > 0 {
                Some((sid + too_many_symbols as u64).to_be_bytes())
            } else {
                None
            }
        }
    }

    #[allow(missing_docs)]
    /// Open public [`crate::ranges::RangeSet`] wrapper.
    pub struct OpenRangeSet {
        pub ranges: RangeSet,
    }

    impl Default for OpenRangeSet {
        fn default() -> Self {
            Self::new()
        }
    }

    #[allow(missing_docs)]
    impl OpenRangeSet {
        pub fn new() -> Self {
            Self {
                ranges: RangeSet::default(),
            }
        }

        pub fn populate(&mut self, range: Range<u64>) {
            self.ranges.insert(range);
        }
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SecureRandom;

    use crate::multicast::authentication::McSymAuth;
    use crate::multicast::testing::CLIENT_AUTH_ADDR;
    use crate::testing;

    use crate::multicast::testing::get_test_mc_announce_data;
    use crate::multicast::testing::get_test_mc_channel_source;
    use crate::multicast::testing::get_test_mc_config;
    use crate::multicast::testing::MulticastPipe;

    use super::*;

    #[test]
    /// The server adds MC_ANNOUNCE data and should send it to the client.
    /// Both added the multicast extension in their transport parameters.
    /// The sharing of the transport parameters are already tested in lib.rs.
    fn mc_announce_data_init() {
        let mc_client_tp = McClientTp::default();
        let mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(
            true,
            Some(&mc_client_tp),
            false,
            McAuthType::None,
        );

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));

        assert!(pipe.server.multicast.is_none());
        assert!(pipe.client.multicast.is_none());
        assert_eq!(pipe.server.mc_should_send_mc_announce(), None);
        assert_eq!(pipe.client.mc_should_send_mc_announce(), None);

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
                .get(0)
                .unwrap(),
            &mc_announce_data
        );

        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::Unaware)
        );
        assert_eq!(pipe.server.mc_should_send_mc_announce(), Some(0));
    }

    #[test]
    /// Exchange of the MC_ANNOUNCE data between the client and the server.
    /// The client receives the MC_ANNOUNCE.
    /// It creates a multicast state on the client.
    fn mc_announce_data_exchange() {
        let mc_client_tp = McClientTp::default();
        let mut mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(
            true,
            Some(&mc_client_tp),
            false,
            McAuthType::None,
        );

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));
        pipe.server
            .mc_set_mc_announce_data(&mc_announce_data)
            .unwrap();

        assert_eq!(pipe.server.mc_should_send_mc_announce(), Some(0));
        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::Unaware)
        );
        assert_eq!(pipe.advance(), Ok(()));

        // MC_ANNOUNCE sent.
        // The client has the data, and the server should not send it anymore.
        assert_eq!(pipe.server.mc_should_send_mc_announce(), None);
        mc_announce_data.is_processed = true;
        // The reception created a MulticastAttributes in for client.
        assert!(pipe.client.multicast.is_some());
        assert_eq!(
            pipe.client
                .multicast
                .as_ref()
                .unwrap()
                .mc_announce_data
                .get(0),
            Some(&mc_announce_data)
        );
        // The client has the role Client.
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            McRole::Client(McClientStatus::AwareUnjoined)
        );
        // The server updates the role of the client because now the frame is
        // sent.
        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::AwareUnjoined)
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
        let mc_client_tp = McClientTp::default();
        let mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(
            true,
            Some(&mc_client_tp),
            false,
            McAuthType::None,
        );

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));
        pipe.server
            .mc_set_mc_announce_data(&mc_announce_data)
            .unwrap();

        assert_eq!(pipe.advance(), Ok(()));

        // Client joins the multicast channel.
        // It changes its status to WaitingToJoin.
        // It sends an MC_STATE with a JOIN notification to the server.
        let res = pipe.client.mc_join_channel(true);
        assert!(res.is_ok());
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            McRole::Client(McClientStatus::WaitingToJoin)
        );

        assert_eq!(pipe.advance(), Ok(()));

        // The client sent its willing to join.
        // It will listen to the multicast channel once it has the key.
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            McRole::Client(McClientStatus::JoinedNoKey)
        );
        // Server received the MC_STATE frame from the client. Its state changed.
        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::JoinedNoKey)
        );
    }

    #[test]
    fn test_mc_client_state_machine() {
        let mut multicast = MulticastAttributes {
            mc_role: McRole::Client(McClientStatus::Unaware),
            ..Default::default()
        };

        assert_eq!(
            multicast.update_client_state(McClientAction::Join, None),
            Ok(McClientStatus::Unaware),
        );

        assert_eq!(
            multicast.update_client_state(McClientAction::Leave, None),
            Ok(McClientStatus::Unaware),
        );

        assert_eq!(
            multicast.update_client_state(McClientAction::DecryptionKey, None),
            Ok(McClientStatus::Unaware),
        );

        // This is a good move.
        assert_eq!(
            multicast.update_client_state(McClientAction::Notify, None),
            Ok(McClientStatus::AwareUnjoined)
        );

        assert_eq!(
            multicast.update_client_state(McClientAction::Join, None),
            Ok(McClientStatus::WaitingToJoin)
        );

        assert_eq!(
            multicast.update_client_state(McClientAction::Join, None),
            Ok(McClientStatus::JoinedNoKey)
        );

        assert_eq!(
            multicast.update_client_state(McClientAction::DecryptionKey, None),
            Ok(McClientStatus::JoinedAndKey)
        );

        assert_eq!(
            multicast.update_client_state(McClientAction::McPath, Some(1)),
            Ok(McClientStatus::ListenMcPath(true))
        );

        assert_eq!(
            multicast.update_client_state(
                McClientAction::Leave,
                Some(LEAVE_FROM_CLIENT)
            ),
            Ok(McClientStatus::Leaving(false))
        );

        assert_eq!(
            multicast.update_client_state(McClientAction::Leave, None),
            Ok(McClientStatus::AwareUnjoined)
        );
    }

    #[test]
    /// Tests the MC_KEY processing.
    /// The server sends an MC_KEY frame to the client once it joined the
    /// multicast group.
    ///
    /// Both the client and the server move to the JoinedAndKey state.
    fn test_mc_key() {
        let mc_client_tp = McClientTp::default();
        let mc_announce_data = get_test_mc_announce_data();
        let mut config = get_test_mc_config(
            true,
            Some(&mc_client_tp),
            false,
            McAuthType::None,
        );

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));
        pipe.server
            .mc_set_mc_announce_data(&mc_announce_data)
            .unwrap();

        assert_eq!(pipe.advance(), Ok(()));
        assert!(pipe.client.mc_join_channel(true).is_ok());
        assert_eq!(pipe.advance(), Ok(()));

        assert!(!pipe.server.multicast.as_ref().unwrap().should_send_mc_key());

        let multicast = pipe.server.multicast.as_mut().unwrap();
        let mc_channel_key: Vec<_> = (0..32).collect();
        multicast.mc_channel_key = Some(mc_channel_key.clone());

        assert!(!pipe.server.multicast.as_ref().unwrap().should_send_mc_key());
        assert_eq!(
            pipe.server.multicast.as_mut().unwrap().set_client_id(0),
            Ok(())
        );
        assert!(pipe.server.multicast.as_ref().unwrap().should_send_mc_key());
        assert_eq!(pipe.advance(), Ok(()));

        assert!(!pipe.server.multicast.as_ref().unwrap().should_send_mc_key());
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            McRole::Client(McClientStatus::JoinedAndKey)
        );
        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::JoinedAndKey)
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
        let mc_client_tp = McClientTp::default();
        let mut server_config =
            get_test_mc_config(true, None, false, McAuthType::None);
        let mut client_config = get_test_mc_config(
            false,
            Some(&mc_client_tp),
            false,
            McAuthType::None,
        );

        let mc_channel = get_test_mc_channel_source(
            &mut server_config,
            &mut client_config,
            McAuthType::AsymSign,
            "/tmp/test_mc_channel_server_handshake.txt",
            None,
        );
        assert!(mc_channel.is_ok());
    }

    #[test]
    /// This tests the multicast channel on the backup path (using the dummy
    /// client), not the multicast path.
    fn test_mc_channel_alone() {
        let mc_client_tp = McClientTp::default();
        let mut server_config =
            get_test_mc_config(true, None, false, McAuthType::None);
        let mut client_config = get_test_mc_config(
            false,
            Some(&mc_client_tp),
            false,
            McAuthType::None,
        );
        let mut mc_channel = get_test_mc_channel_source(
            &mut server_config,
            &mut client_config,
            McAuthType::None,
            "/tmp/test_mc_channel_alone.txt",
            None,
        )
        .unwrap();

        let data: Vec<_> = (0..255).collect();
        mc_channel.channel.stream_send(1, &data, true).unwrap();

        let mut pipe = [0u8; 4096];
        let (written, to) = mc_channel.channel.send(&mut pipe[..]).unwrap();

        let recv_info = RecvInfo {
            from: to.from,
            to: to.to,
            from_mc: None,
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
            from_mc: None,
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
        let mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_channel_auth.txt",
            McAuthType::AsymSign,
            false,
            false,
            None,
        );
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
        let (written, _) = res.unwrap();

        let recv_info = RecvInfo {
            from: server_addr,
            to: client_addr_2,
            from_mc: Some(McPathType::Data),
        };

        // First a message with an invalid authentication signature.
        // Change a byte in the signature.
        let mut mc_buf2 = mc_buf[..written].to_owned();
        mc_buf2[written - 1] = mc_buf2[written - 1].wrapping_add(1);
        let res = pipe.client.mc_recv(&mut mc_buf2[..written], recv_info);
        assert_eq!(res, Err(Error::Multicast(McError::McInvalidSign)));
        assert_eq!(pipe.client.readable().len(), 0);
        assert!(!pipe.client.stream_readable(1));

        // Change a byte in the packet.
        let mut mc_buf2 = mc_buf[..written].to_owned();
        mc_buf2[5] = mc_buf2[5].wrapping_add(1);
        let res = pipe.client.mc_recv(&mut mc_buf2[..written], recv_info);
        assert_eq!(res, Err(Error::Multicast(McError::McInvalidSign)));
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
        let use_auth = McAuthType::None;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_nack.txt",
            use_auth,
            false,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };

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
            from_mc: Some(McPathType::Data),
        };

        let client_mc_space_id =
            pipe.client.multicast.as_ref().unwrap().get_mc_space_id();
        assert_eq!(client_mc_space_id, Some(1));
        let client_mc_space_id = client_mc_space_id.unwrap();

        // The source multicast sends multiple packets. The second is lost to
        // trigger the nack.
        let res = mc_channel.mc_send(&mut mc_buf[..]).map(|(w, _)| w);
        assert_eq!(res, Ok(1350));
        let written = res.unwrap();

        let res = pipe.client.mc_recv(&mut mc_buf[..written], recv_info);
        assert_eq!(res, Ok(written - signature_len));

        // Second packet... lost
        let res = mc_channel.mc_send(&mut mc_buf[..]).map(|(w, _)| w);
        assert_eq!(res, Ok(1350));

        // Third packet... received.
        let res = mc_channel.mc_send(&mut mc_buf[..]).map(|(w, _)| w);
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
    /// The server sends an MC_EXPIRE when the data expires with the
    /// `expiration_timer` value of the multicast attributes. Also tests
    /// that the multicast source regularly sends MC_EXPIRE containing empty
    /// data if no new data is sent to the client, to ensure that the
    /// multicast channel does not timeout.
    fn test_on_mc_timeout() {
        let use_auth = McAuthType::None;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_on_mc_timeout.txt",
            use_auth,
            false,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };

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
                mc_pipe.mc_announce_data.expiration_timer + 100,
            ); // Margin
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired_timer);
        assert_eq!(res, Ok((Some(5), None).into()));

        // MC-TODO: assert that the packets are not in the sending state anymore.
        // URMC-TODO: verify the expired streams.
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(5), None).into())
        );

        // The stream is closed now.
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_writable(1, 0),
            Err(Error::InvalidStreamState(1))
        );

        // The multicast source sends an MC_EXPIRE to the client.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(46));

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
        let mut expired_timer = expired_timer +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.expiration_timer + 100,
            ); // Margin
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired_timer);
        assert_eq!(res, Ok((Some(10), None).into()));
        // URMC-TODO: check that the stream 1 is closed.

        // MC-TODO: assert that the packets are not in the sending state anymore.
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(10), None).into())
        );

        // The stream is closed now.
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_writable(3, 0),
            Err(Error::InvalidStreamState(3))
        );

        // The multicast source sends an MC_EXPIRE to the client.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(46));

        // The stream is also closed on the client now.
        assert!(mc_pipe.unicast_pipes[0].0.client.stream_finished(3));

        // The source did not send data for a long time. An MC_EXPIRE containing
        // empty information is sent by the source.
        let client_last_received = mc_pipe.unicast_pipes[0]
            .0
            .client
            .multicast
            .as_ref()
            .unwrap()
            .mc_last_recv_time;
        expired_timer += time::Duration::from_millis(
            mc_pipe.mc_announce_data.expiration_timer + 100,
        );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired_timer);
        assert_eq!(res, Ok((Some(11), None).into()));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(11), None).into())
        );
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(46));
        let client_last_received_now = mc_pipe.unicast_pipes[0]
            .0
            .client
            .multicast
            .as_ref()
            .unwrap()
            .mc_last_recv_time;
        assert!(client_last_received.is_some());
        assert!(client_last_received_now.is_some());
        assert!(
            client_last_received_now
                .unwrap()
                .duration_since(client_last_received.unwrap()) >
                time::Duration::ZERO
        );

        // Repeat the same thing...
        let client_last_received = mc_pipe.unicast_pipes[0]
            .0
            .client
            .multicast
            .as_ref()
            .unwrap()
            .mc_last_recv_time;
        expired_timer += time::Duration::from_millis(
            mc_pipe.mc_announce_data.expiration_timer + 100,
        );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired_timer);
        assert_eq!(res, Ok((Some(12), None).into()));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(12), None).into())
        );
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(46));
        let client_last_received_now = mc_pipe.unicast_pipes[0]
            .0
            .client
            .multicast
            .as_ref()
            .unwrap()
            .mc_last_recv_time;
        assert!(client_last_received.is_some());
        assert!(client_last_received_now.is_some());
        assert!(
            client_last_received_now
                .unwrap()
                .duration_since(client_last_received.unwrap()) >
                time::Duration::ZERO
        );
    }

    #[test]
    /// Tests the multicast source sending multiple short streams and some of
    /// them expire.
    fn test_mc_multiple_streams_expire() {
        let use_auth = McAuthType::None;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_multiple_streams_expire.txt",
            use_auth,
            false,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };

        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 1),
            Ok(339)
        );

        // Second stream is not received.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                3
            ),
            Ok(339)
        );

        // Third stream is not received.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                5
            ),
            Ok(339)
        );

        // Fourth stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 7),
            Ok(339)
        );

        // Fifth stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 9),
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
                mc_pipe.mc_announce_data.expiration_timer + 100,
            );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((Some(6), None).into()));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(6), None).into())
        );
        // URMC-TODO: check that the stream 9 is closed.

        // Multicast source sends an MC_EXPIRE to the client.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(46));

        // Sixth stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 11),
            Ok(339)
        );

        // let open_streams = mc_pipe
        //     .mc_channel
        //     .channel
        //     .streams
        //     .writable()
        //     // .map(|(sid, _)| *sid)
        //     .collect::<Vec<_>>();
        // assert_eq!(open_streams, vec![11]);

        // The client has no missing packet.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        assert_eq!(nack_ranges.as_ref(), None);

        // Only the last stream did not timeout.
        // All timeout streams are still redeables but finished.
        // => This last sentence is not valid since a recent change in quiche.
        // Reset streams are also removed from the readable state.
        let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![11]);
        assert!(uc_pipe.client.stream_finished(1));
        assert!(uc_pipe.client.stream_finished(7));
        assert!(uc_pipe.client.stream_finished(9));
    }

    #[test]
    fn test_mc_client_nack_to_source_and_recovery() {
        let use_auth = McAuthType::None;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_client_nack_to_source_and_recovery.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First two streams are received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 1),
            Ok(348)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 3),
            Ok(348)
        );

        // Third and fourth streams are lost.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                5
            ),
            Ok(348)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                7
            ),
            Ok(348)
        );

        // Fifth stream is received and triggers NACK from the client.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 9),
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
                .0
                .as_ref(),
            Some(&(expected_ranges.clone(), 6))
        );

        // The unicast server receives the MC_NACK.
        let nack_on_source = uc_pipe
            .server
            .multicast
            .as_ref()
            .unwrap()
            .mc_nack_ranges
            .0
            .as_ref();
        assert_eq!(nack_on_source, Some(&(expected_ranges.clone(), 6)));

        // The unicast server forwards information to the multicast source.
        assert_eq!(
            mc_pipe.server_control_to_mc_source(time::Instant::now()),
            Ok(())
        );

        // The server generates FEC repair packets and forwards them to the
        // client.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1335));
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1335));
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
        let use_auth = McAuthType::AsymSign;
        let mut mc_pipe = MulticastPipe::new(
            2,
            "/tmp/test_mc_fec_reliable_multiple_clients_with_auth.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };
        let mut client_loss_0 = RangeSet::default();
        client_loss_0.insert(0..1);
        let mut client_loss_1 = RangeSet::default();
        client_loss_1.insert(1..2);
        let mut client_loss_all = RangeSet::default();
        client_loss_all.insert(0..2);

        // First stream is received by both clients.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Second stream is received by the second client only.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&client_loss_0),
                signature_len,
                3
            ),
            Ok(348 + signature_len),
        );

        // Third stream is lost by the first client only.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&client_loss_1),
                signature_len,
                5
            ),
            Ok(348 + signature_len)
        );

        // Fourth stream is received by none client.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&client_loss_all),
                signature_len,
                7
            ),
            Ok(348 + signature_len)
        );

        // Fifth stream is received by both.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 9),
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
        assert_eq!(uc_pipe_0.client.fec_decoder.nb_missing_degrees(), Some(0));

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
        assert_eq!(
            mc_pipe.server_control_to_mc_source(time::Instant::now()),
            Ok(())
        );

        // The server generates FEC repair packets and forwards them to the
        // client. Only two repair symbols are needed.
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1335));
        assert_eq!(mc_pipe.source_send_single(None, signature_len), Ok(1335));
        // No need to send additional repair symbols.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Err(Error::Done)
        );

        let mut expected_sources_symbols_pn = RangeSet::default();
        expected_sources_symbols_pn.insert(2..7);
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_ss_pn,
            expected_sources_symbols_pn
        );

        let sent_repairs = mc_pipe
            .mc_channel
            .channel
            .multicast
            .as_ref()
            .unwrap()
            .mc_sent_repairs
            .clone();
        let mut expected = RangeSet::default();
        expected.insert(7..9);
        assert_eq!(sent_repairs, Some(expected));

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

        // Timeout on the server. It removes the sent repair symbols from its
        // window.
        let now = time::Instant::now();
        let expired_timer = now +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.expiration_timer * 3 + 100,
            ); // Margin

        assert_eq!(
            mc_pipe.mc_channel.channel.on_mc_timeout(expired_timer),
            Ok((Some(8), Some(4)).into())
        );
        // URMC-TODO: check that the stream 9 is closed.

        let sent_repairs = mc_pipe
            .mc_channel
            .channel
            .multicast
            .as_ref()
            .unwrap()
            .mc_sent_repairs
            .clone();
        let expected = RangeSet::default();
        assert_eq!(sent_repairs, Some(expected));

        let expected_sources_symbols_pn = RangeSet::default();
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_ss_pn,
            expected_sources_symbols_pn
        );
    }

    #[test]
    /// Tests the reset of the FEC state upon data timeout.
    fn test_mc_fec_on_mc_timeout() {
        let use_auth = McAuthType::AsymSign;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_fec_on_mc_timeout.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Two consecutive streams are lost.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                3
            ),
            Ok(348 + signature_len)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                5
            ),
            Ok(348 + signature_len)
        );

        // A last stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 7),
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
                mc_pipe.mc_announce_data.expiration_timer + 100,
            );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((Some(5), Some(3)).into()));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(5), Some(3)).into())
        );
        // URMC-TODO: check that the stream 7 is closed.

        // Multicast source sends an MC_EXPIRE to the client.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Ok(47 + signature_len)
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
        assert_eq!(
            mc_pipe.server_control_to_mc_source(time::Instant::now()),
            Ok(())
        );

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
    /// multicast source. In this case, it will send an MC_NACK frame with
    /// expired packet numbers. The server must not generate FEC repair symbols
    /// for these lost source symbols that are expired.
    fn source_does_not_generate_mc_fec_repair_for_expired() {
        let use_auth = McAuthType::AsymSign;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/source_does_not_generate_mc_fec_repair_for_expired.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Two consecutive streams are lost.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                3
            ),
            Ok(348 + signature_len)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                5
            ),
            Ok(348 + signature_len)
        );

        // A last stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 7),
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
                mc_pipe.mc_announce_data.expiration_timer + 100,
            );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((Some(5), Some(3)).into()));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(5), Some(3)).into())
        );
        // URMC-TODO: check that the stream 7 is closed.

        // Multicast source sends an MC_EXPIRE. The packet is lost.
        assert_eq!(
            mc_pipe
                .source_send_single(Some(&clients_losing_packets), signature_len),
            Ok(47 + signature_len)
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
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Err(Error::Done)
        );

        // The client knows that it lost the first packet of the new stream, but
        // also the two older (and expired!) packets because it did not receive
        // the MC_EXPIRE frame from the multicast source..
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let nack_ranges = uc_pipe
            .client
            .mc_nack_range(Epoch::Application, client_mc_space_id as u64);
        expected_ranges.insert(6..8); // The client also lost the packet with the MC_EXPIRE.
        assert_eq!(nack_ranges.as_ref(), Some(&expected_ranges));

        // The client has a missing source symbol only.
        assert_eq!(uc_pipe.client.fec_decoder.nb_missing_degrees(), Some(0));

        // The client sends an MC_NACK to the server.
        // This MC_NACK also contains expired data.
        assert_eq!(mc_pipe.clients_send(), Ok(()));

        // Communication to unicast servers.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Err(Error::Done)
        );
        assert_eq!(
            mc_pipe.server_control_to_mc_source(time::Instant::now()),
            Ok(())
        );

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

        // The source records the sent repair symbol.
        let sent_repairs = mc_pipe
            .mc_channel
            .channel
            .multicast
            .as_ref()
            .unwrap()
            .mc_sent_repairs
            .clone();
        let mut expected = RangeSet::default();
        expected.insert(11..12);
        assert_eq!(sent_repairs, Some(expected));

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
        let use_auth = McAuthType::AsymSign;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_client_first_pn_utility.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First two streams are lost.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                1
            ),
            Ok(348 + signature_len)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                3
            ),
            Ok(348 + signature_len)
        );

        // Third stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 5),
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
        let use_auth = McAuthType::AsymSign;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_client_leave_mc_channel.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };

        assert_eq!(
            mc_pipe.unicast_pipes[0]
                .0
                .client
                .multicast
                .as_ref()
                .unwrap()
                .get_mc_role(),
            McRole::Client(McClientStatus::ListenMcPath(true))
        );

        // First stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Second stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 3),
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
            Ok(McClientStatus::Leaving(false))
        );

        // The client notifies the unicast server.
        assert_eq!(uc_pipe.advance(), Ok(()));

        // The client has left the multicast channel.
        assert_eq!(
            uc_pipe.client.multicast.as_ref().unwrap().mc_role,
            McRole::Client(McClientStatus::AwareUnjoined)
        );
        assert_eq!(
            uc_pipe.server.multicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::AwareUnjoined)
        );
    }

    #[test]
    /// Test the MC_EXPIRE mechanism. After a first MC_EXPIRE is sent, if no
    /// further data is expired, the source must not send an MC_EXPIRE. This
    /// test is created to fix an existing issue in the code at the time of
    /// writing.
    fn test_mc_expire_do_not_send_useless() {
        let use_auth = McAuthType::AsymSign;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_expire_do_not_send_useless.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };

        // Source sends one stream.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Expiration of the stream.
        let timer = time::Instant::now();
        let timer = timer +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.expiration_timer + 100,
            );
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((Some(2), Some(0)).into()));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(2), Some(0)).into())
        );
        // URMC-TODO: check that the stream 1 is closed.

        // Multicast source sends an MC_EXPIRE to the client.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Ok(47 + signature_len)
        );

        // Send new stream.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 5),
            Ok(348 + signature_len)
        );

        // New timer triggering but no expiration.
        let timer = time::Instant::now();
        let timer = timer + time::Duration::from_millis(5);
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(timer);
        assert_eq!(res, Ok((None, None).into()));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_last_expired,
            Some((Some(2), Some(0)).into())
        );
        // URMC-TODO: check that the stream 1 is closed.

        // The multicast source does not send any packet because no data
        // expiration.
        assert_eq!(
            mc_pipe.source_send_single(None, signature_len),
            Err(Error::Done)
        );
    }

    #[test]
    fn test_mc_channel_cwnd() {
        let use_auth = McAuthType::None;
        let mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_channel_cwnd.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();

        let mc_path_id = mc_pipe
            .mc_channel
            .channel
            .multicast
            .as_ref()
            .unwrap()
            .get_mc_space_id()
            .unwrap();
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .paths
                .get(mc_path_id)
                .unwrap()
                .recovery
                .cwnd(),
            usize::MAX - 1
        );
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .paths
                .get(mc_path_id)
                .unwrap()
                .recovery
                .cwnd_available(),
            usize::MAX - 1
        );
    }

    #[test]
    /// This tests the multicast-as-a-service feature.
    /// The client starts listening to the multicast channel. Due to poor
    /// connectivity, the server/client decides to stop the transmission using
    /// the multicast channel, and falls back on the unicast connection to
    /// distribute the content.
    fn test_mc_as_a_service_fallback() {
        for i in 0..2 {
            let use_auth = McAuthType::AsymSign;
            let mut mc_pipe = MulticastPipe::new(
                1,
                "/tmp/test_mc_as_a_service_fallback.txt",
                use_auth,
                true,
                false,
                None,
            )
            .unwrap();
            let signature_len = if use_auth == McAuthType::AsymSign {
                64
            } else {
                0
            };

            assert_eq!(
                mc_pipe.source_send_single_stream(true, None, signature_len, 1),
                Ok(348 + signature_len)
            );

            // A second stream sent on the unicast connection.
            assert_eq!(mc_pipe.uc_server_send_single_stream(5, 0), Ok(()));

            assert_eq!(
                mc_pipe.source_send_single_stream(true, None, signature_len, 9),
                Ok(348 + signature_len)
            );

            // The client has two readable streams thanks to multipath.
            let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
            let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![1, 5, 9]);

            // The server asks the client to leave the multicast channel.
            let pipe = &mut mc_pipe.unicast_pipes[0].0;
            if i == 0 {
                // Server asks the client to leave the channel.
                assert_eq!(
                    pipe.server.mc_leave_channel(),
                    Ok(McClientStatus::Leaving(false))
                );
            } else {
                // Client leaves the channel by itself.
                assert_eq!(
                    pipe.client.mc_leave_channel(),
                    Ok(McClientStatus::Leaving(false))
                );
            }
            assert_eq!(pipe.advance(), Ok(()));

            // The client left the multicast channel.
            assert_eq!(
                pipe.server.multicast.as_ref().unwrap().mc_role,
                McRole::ServerUnicast(McClientStatus::AwareUnjoined)
            );
            assert_eq!(
                pipe.client.multicast.as_ref().unwrap().mc_role,
                McRole::Client(McClientStatus::AwareUnjoined)
            );

            // Data received on the multicast channel is not handled by the
            // client.
            assert_eq!(
                mc_pipe.source_send_single_stream(true, None, signature_len, 13),
                Ok(348 + signature_len)
            );
            let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
            let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![1, 5, 9]); // No new stream is readable.

            // The same data sent on the unicast connection is correctly received.
            assert_eq!(mc_pipe.uc_server_send_single_stream(13, 0), Ok(()));
            let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
            let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
            readables.sort();
            assert_eq!(readables, vec![1, 5, 9, 13]); // No new stream is
                                                      // readable.
        }
    }

    #[test]
    /// Test that the client leaves the multicast channel on timeout.
    /// A timeout occurs if the client does not receive data from the channel.
    fn test_on_mc_timeout_client() {
        let use_auth = McAuthType::AsymSign;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_on_mc_timeout_client.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();
        let signature_len = if use_auth == McAuthType::AsymSign {
            64
        } else {
            0
        };
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        // First stream is received.
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, signature_len, 1),
            Ok(348 + signature_len)
        );

        // Second stream is lost.
        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                signature_len,
                5
            ),
            Ok(348 + signature_len)
        );

        // Timeout on the client: they leave the multicast channel because no data
        // has been received for too long.
        let now = time::Instant::now();
        let expired_timer = now +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.expiration_timer * 3 + 100,
            ); // Margin

        let pipe = &mut mc_pipe.unicast_pipes[0].0;

        // The client has a single stream.
        let mut readables = pipe.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![1]);

        // The client does not generate expired data.
        assert_eq!(
            pipe.client.on_mc_timeout(expired_timer),
            Ok((None, None).into())
        );

        // Upon timeout, the client leaves the multicast channel.
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            McRole::Client(McClientStatus::Leaving(false))
        );

        assert_eq!(pipe.advance(), Ok(()));

        // The client has left the multicast channel.
        assert_eq!(
            pipe.client.multicast.as_ref().unwrap().mc_role,
            McRole::Client(McClientStatus::AwareUnjoined)
        );
        assert_eq!(
            pipe.server.multicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::AwareUnjoined)
        );
    }

    #[test]
    /// Tests the client ID given by the multicast source.
    fn test_mc_client_id() {
        let use_auth = McAuthType::AsymSign;
        let nb_clients = 5;
        let mut mc_pipe = MulticastPipe::new(
            nb_clients,
            "/tmp/test_mc_client_id.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();

        let client_id_map = mc_pipe
            .mc_channel
            .channel
            .multicast
            .as_ref()
            .unwrap()
            .mc_client_id
            .as_ref();
        let client_id_map = match client_id_map {
            Some(McClientId::MulticastServer(v)) => v,
            _ => return assert!(false),
        };
        assert_eq!(client_id_map.max_client_id, 5);

        for (i, pipe) in mc_pipe.unicast_pipes.iter().enumerate() {
            let client_id = pipe
                .0
                .client
                .multicast
                .as_ref()
                .unwrap()
                .get_self_client_id();
            assert_eq!(client_id, Ok(i as u64));

            let client_id = pipe
                .0
                .server
                .multicast
                .as_ref()
                .unwrap()
                .get_self_client_id();
            assert_eq!(client_id, Ok(i as u64));

            let cid = client_id_map.get_client_cid(i as u64);
            assert_eq!(cid, Some(pipe.0.server.source_id().as_ref()));
            assert_eq!(
                client_id_map.get_client_id(cid.unwrap()),
                Some(client_id.unwrap())
            );
        }

        // A client leave the multicast channel. The multicast source removes
        // the associated client ID.
        assert_eq!(
            mc_pipe.unicast_pipes[2].0.client.mc_leave_channel(),
            Ok(McClientStatus::Leaving(false))
        );
        assert_eq!(mc_pipe.unicast_pipes[2].0.advance(), Ok(()));
        assert_eq!(
            mc_pipe.server_control_to_mc_source(time::Instant::now()),
            Ok(())
        );
        if let Some(McClientId::MulticastServer(map)) = mc_pipe
            .mc_channel
            .channel
            .multicast
            .as_ref()
            .unwrap()
            .mc_client_id
            .as_ref()
        {
            assert_eq!(map.cid_to_id.len(), nb_clients - 1);
            assert_eq!(map.id_to_cid.len(), nb_clients - 1);
            let mut ids: Vec<_> = map.id_to_cid.keys().map(|&i| i).collect();
            ids.sort();
            assert_eq!(ids, vec![0, 1, 3, 4]);

            let mut ids: Vec<_> = map.cid_to_id.values().map(|&i| i).collect();
            ids.sort();
            assert_eq!(ids, vec![0, 1, 3, 4]);
        }
    }

    #[test]
    fn test_mc_authentication_methods() {
        let use_auth = McAuthType::AsymSign;
        let mc_pipe = MulticastPipe::new(
            2,
            "/tmp/test_mc_authentication_methods.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();

        let multicast = mc_pipe.mc_channel.channel.multicast.as_ref().unwrap();
        assert_eq!(multicast.mc_auth_type, McAuthType::AsymSign);
        assert_eq!(multicast.mc_space_id, Some(1));
        assert_eq!(multicast.mc_auth_space_id, None);
        assert!(multicast.mc_private_key.is_some());
        assert_eq!(
            multicast.get_mc_authentication_method(),
            McAuthType::AsymSign
        );

        for (pipe, ..) in mc_pipe.unicast_pipes.iter() {
            let multicast = pipe.client.multicast.as_ref().unwrap();
            assert_eq!(multicast.mc_auth_type, McAuthType::AsymSign);
            assert_eq!(multicast.mc_space_id, Some(1));
            assert_eq!(multicast.mc_auth_space_id, None);
            assert!(multicast.mc_public_key.is_some());
            assert_eq!(
                multicast.get_mc_authentication_method(),
                McAuthType::AsymSign
            );

            let multicast = pipe.client.multicast.as_ref().unwrap();
            assert_eq!(multicast.mc_auth_type, McAuthType::AsymSign);
            assert_eq!(multicast.mc_space_id, Some(1));
            assert_eq!(multicast.mc_auth_space_id, None);
            assert!(multicast.mc_public_key.is_some());
        }

        let use_auth = McAuthType::SymSign;
        let mc_pipe = MulticastPipe::new(
            2,
            "/tmp/test_authentication_methods.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();

        let multicast = mc_pipe.mc_channel.channel.multicast.as_ref().unwrap();
        assert_eq!(multicast.mc_auth_type, McAuthType::SymSign);
        assert_eq!(multicast.mc_space_id, Some(1));
        assert_eq!(multicast.mc_auth_space_id, Some(2));
        assert_eq!(
            multicast.get_mc_authentication_method(),
            McAuthType::SymSign
        );

        for (pipe, ..) in mc_pipe.unicast_pipes.iter() {
            let multicast = pipe.client.multicast.as_ref().unwrap();
            assert_eq!(multicast.mc_auth_type, McAuthType::SymSign);
            assert_eq!(multicast.mc_space_id, Some(1));
            assert_eq!(multicast.mc_auth_space_id, Some(2));
            assert_eq!(
                multicast.get_mc_authentication_method(),
                McAuthType::SymSign
            );

            let multicast = pipe.server.multicast.as_ref().unwrap();
            assert_eq!(multicast.mc_auth_type, McAuthType::SymSign);
            assert_eq!(multicast.mc_space_id, Some(1));
            assert_eq!(multicast.mc_auth_space_id, None);
        }
    }

    #[test]
    /// Tests the symmetric signature process. In a nutshell, this test
    /// evaluates that:
    /// * The multicast channel creates a third path used for authentication
    ///   only,
    /// * The multicast channel sends MC_AUTH frames containing symetric
    ///   signatures on this third path,
    /// * The MC_AUTH frames contain a signature for each client, linked to
    ///   their client ID,
    /// * The signatures are correctly signed by the clients.
    fn test_mc_auth_sym_process() {
        let use_auth = McAuthType::SymSign;
        let mut mc_pipe = MulticastPipe::new(
            2,
            "/tmp/test_mc_auth_sym_process.txt",
            use_auth,
            false,
            false,
            None,
        )
        .unwrap();

        let auth_info = mc_pipe.mc_channel.mc_auth_info.as_ref();
        assert!(auth_info.is_some());
        let auth_info = auth_info.unwrap();

        // The third path used for authentication-only exists.
        assert_eq!(mc_pipe.mc_channel.channel.paths.len(), 3);
        let auth_path_id = mc_pipe
            .mc_channel
            .channel
            .paths
            .path_id_from_addrs(&(auth_info.2, auth_info.2));
        assert_eq!(auth_path_id, Some(2));
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_auth_space_id,
            Some(2)
        );
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_auth_type,
            McAuthType::SymSign
        );

        // There is a third path for symetric authentication.
        for (pipe, ..) in mc_pipe.unicast_pipes.iter() {
            assert_eq!(pipe.client.paths.len(), 3);
            let auth_path_id = pipe.client.paths.path_id_from_addrs(&(
                CLIENT_AUTH_ADDR.parse().unwrap(),
                testing::Pipe::server_addr(),
            ));
            assert_eq!(auth_path_id, Some(2));
            assert_eq!(
                pipe.client.multicast.as_ref().unwrap().mc_auth_space_id,
                Some(2)
            );
            assert_eq!(
                pipe.client.multicast.as_ref().unwrap().mc_auth_type,
                McAuthType::SymSign
            );
            assert_eq!(
                pipe.server.multicast.as_ref().unwrap().mc_auth_type,
                McAuthType::SymSign
            );
        }

        // Multicast source has no data to send on the authentication path.
        let multicast = mc_pipe.mc_channel.channel.multicast.as_ref().unwrap();
        let auth_pid = multicast.mc_auth_space_id.unwrap();
        assert!(!mc_pipe.mc_channel.channel.mc_has_control_data(auth_pid));

        // Multicast source sends two data packets.
        assert_eq!(mc_pipe.source_send_single_stream(true, None, 0, 1), Ok(339));
        assert_eq!(mc_pipe.source_send_single_stream(true, None, 0, 5), Ok(339));

        // Multicast source must send authentication packets.
        let multicast = mc_pipe.mc_channel.channel.multicast.as_ref().unwrap();
        let pn_need_sign = multicast.mc_pn_need_sym_sign.as_ref().unwrap();
        let mut pn_need_sign_vec: Vec<_> =
            pn_need_sign.iter().map(|(i, _)| *i).collect();
        pn_need_sign_vec.sort();
        assert_eq!(pn_need_sign_vec, vec![2, 3]);

        // Multicast source generates the authentication tag.
        let clients: Vec<_> = mc_pipe
            .unicast_pipes
            .iter_mut()
            .map(|(conn, ..)| &mut conn.server)
            .collect();
        assert_eq!(mc_pipe.mc_channel.channel.mc_sym_sign(&clients), Ok(()));
        let multicast = mc_pipe.mc_channel.channel.multicast.as_ref().unwrap();

        // All packets that needed to be authenticated have been processed.
        assert_eq!(multicast.mc_pn_need_sym_sign, Some(VecDeque::new()));

        // Two packets have been signed, for pn=2 and pn=3.
        if let McSymSign::McSource(signatures) = &multicast.mc_sym_signs {
            assert_eq!(signatures.len(), 2);
            for (i, (pn, sign, ..)) in signatures.iter().enumerate() {
                assert_eq!(i as u64 + 2, *pn);
                assert_eq!(sign.len(), 2);
                let mut ids: Vec<_> =
                    sign.iter().map(|mc_sym| mc_sym.mc_client_id).collect();
                ids.sort();
                assert_eq!(ids, vec![0, 1]);
            }
        } else {
            assert!(false);
        }

        // Multicast source has packets to send on the authentication path.
        assert!(mc_pipe.mc_channel.channel.mc_has_control_data(auth_pid));

        // Multicast source sends the authentication packets to the clients.
        assert_eq!(mc_pipe.mc_source_sends_auth_packets(None), Ok(130));

        // Multicast source must not send any authentication packet because
        // everything as been sent.
        assert!(!mc_pipe.mc_channel.channel.mc_has_control_data(auth_pid));
        let multicast = mc_pipe.mc_channel.channel.multicast.as_ref().unwrap();
        assert_eq!(multicast.mc_pn_need_sym_sign, Some(VecDeque::new()));
        let signatures = &multicast.mc_sym_signs;
        if let McSymSign::McSource(signatures) = signatures {
            assert_eq!(signatures.len(), 0);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn my_test_mc() {
        let auth = McAuthType::SymSign;
        let mut pipe =
            MulticastPipe::new(2, "/tmp/bench", auth, false, false, None)
                .unwrap();

        let stream = vec![0u8; 1_000_000];
        pipe.mc_channel
            .channel
            .stream_send(1, &stream, true)
            .unwrap();
        let mut buf = [0u8; 4000];

        let clients: Vec<_> = pipe
            .unicast_pipes
            .iter_mut()
            .map(|(conn, ..)| &mut conn.server)
            .collect();

        for _ in 0..100 {
            pipe.mc_channel.mc_send(&mut buf).unwrap();
            pipe.mc_channel.channel.mc_sym_sign(&clients).unwrap();
            pipe.mc_channel.mc_send_sym_auth(&mut buf[..]).unwrap();
        }
    }

    #[test]
    /// The default behaviour of a QUIC-multicast client is to simulate the
    /// creation of a new path without probing it with the (unicast) server.
    /// This allows for fewer RTTs to setup the multicast channel. However, due
    /// to several mechanisms (e.g., NAT), opening the new path at a new address
    /// (because of multipath) is not always possible. The [`create_mc_path`]
    /// function is extended to also do the real path probing with the unicast
    /// server. This test evaluates that the behaviour of the multicast
    /// extension works as expected even if the unicast server is fully aware of
    /// the (potentially two) added path(s).
    fn test_mc_create_mc_paths_probe() {
        let use_auth = McAuthType::SymSign;
        let mut mc_pipe = MulticastPipe::new(
            2,
            "/tmp/test_mc_create_mc_paths_probe.txt",
            use_auth,
            true,
            true,
            None,
        )
        .unwrap();

        let stream = vec![0u8; 1_000_000];
        mc_pipe
            .mc_channel
            .channel
            .stream_send(1, &stream, true)
            .unwrap();
        let mut buf = [0u8; 4000];

        let clients: Vec<_> = mc_pipe
            .unicast_pipes
            .iter_mut()
            .map(|(conn, ..)| &mut conn.server)
            .collect();

        for _ in 0..100 {
            mc_pipe.mc_channel.mc_send(&mut buf).unwrap();
            mc_pipe.mc_channel.channel.mc_sym_sign(&clients).unwrap();
            mc_pipe.mc_channel.mc_send_sym_auth(&mut buf[..]).unwrap();
        }
    }

    #[test]
    /// This test evaluates how a client behaves when it joins an ongoing
    /// multicast channel using path probing to create the multicast paths. The
    /// path creation and path listening is (at the time of writing this test)
    /// decoupled, creating a [`crate::Error::MultipathViolation`]. The client
    /// sends an MP_ACK (which serves as an MC_NACK) to get the data that has
    /// not been received (at the time the client was not listening the channel)
    /// and that is not expired yet. However, this MP_ACK is received by the
    /// unicast server while the path is not fully established, creating a
    /// [`Error::MultipathViolation`].
    fn test_mc_client_send_mp_ack_with_probe() {}

    #[test]
    /// The server should see the new connection IDs and path challenges of the
    /// client.
    fn test_cid_and_path_explicit() {
        let mut mc_announce_data = get_test_mc_announce_data();
        mc_announce_data.is_ipv6 = true; // Explicit notification.

        let mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_cid_and_path_explicit.txt",
            McAuthType::SymSign,
            true,
            true,
            None,
        )
        .unwrap();

        // The server received the new connection ID from the client.
        assert_eq!(
            mc_pipe.unicast_pipes[0].0.client.ids.active_source_cids(),
            3
        );
        assert!(mc_pipe.unicast_pipes[0].0.server.ids.get_dcid(0).is_ok());
        assert!(mc_pipe.unicast_pipes[0].0.server.ids.get_dcid(1).is_ok());
        assert!(mc_pipe.unicast_pipes[0].0.server.ids.get_dcid(2).is_ok());
        // MC-TODO: should ensure that this is equivalent to the client sCID.

        assert_eq!(mc_pipe.unicast_pipes[0].0.server.paths.len(), 3);

        let mut mc_announce_data = get_test_mc_announce_data();
        mc_announce_data.is_ipv6 = false; // Explicit notification.

        let mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_cid_and_path_explicit.txt",
            McAuthType::SymSign,
            true,
            false,
            None,
        )
        .unwrap();

        // The server received the new connection ID from the client.
        assert_eq!(
            mc_pipe.unicast_pipes[0].0.client.ids.active_source_cids(),
            3
        );
        assert!(mc_pipe.unicast_pipes[0].0.server.ids.get_dcid(0).is_ok());
        assert!(mc_pipe.unicast_pipes[0].0.server.ids.get_dcid(1).is_ok());
        assert!(mc_pipe.unicast_pipes[0].0.server.ids.get_dcid(2).is_ok());
        // MC-TODO: should ensure that this is equivalent to the client sCID.

        assert_eq!(mc_pipe.unicast_pipes[0].0.server.paths.len(), 1);
    }

    #[test]
    /// Symmetric authentication adds a new multicast path.
    fn test_mc_symmetric_auth_path() {
        let use_auth = McAuthType::SymSign;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_symmetric_auth_path.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();

        assert_eq!(mc_pipe.source_send_single_stream(true, None, 0, 1), Ok(348));
        assert_eq!(mc_pipe.source_send_single_stream(true, None, 0, 5), Ok(348));
        assert_eq!(mc_pipe.source_send_single_stream(true, None, 0, 9), Ok(348));

        // The client received all streams.
        let uc_pipe = &mut mc_pipe.unicast_pipes.get_mut(0).unwrap().0;
        let mut readables = uc_pipe.client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![1, 5, 9]);

        // The client received all streams. They must not send packets to the
        // source.
        let mut out = [0u8; 2048];
        assert_eq!(uc_pipe.client.stream_send(2, &out[..100], true), Ok(100));
        assert_eq!(uc_pipe.client.send(&mut out).map(|(w, _)| w), Ok(148));
        // The client does not send ACK_MP frames for the authentication path.
    }

    #[test]
    /// Tests the multicast handshake in case of packet losses.
    fn test_mc_handshake_with_losses() {
        // MC-TODO!
    }

    #[test]
    /// Tests the [`authentication::McAuthType::StreamAsym`] authentication
    /// method.
    fn test_mc_stream_asym() {
        let use_auth = McAuthType::StreamAsym;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_stream_asym.txt",
            use_auth,
            true,
            true,
            None,
        )
        .unwrap();

        // Source has the correct authentication type and has a private key.
        let mc = mc_pipe.mc_channel.channel.multicast.as_ref().unwrap();
        assert_eq!(mc.mc_auth_type, McAuthType::StreamAsym);
        assert!(mc.mc_private_key.is_some());

        // Client has the correct authentication type and has a public key.
        let mc = mc_pipe.unicast_pipes[0]
            .0
            .client
            .multicast
            .as_ref()
            .unwrap();
        assert_eq!(mc.mc_auth_type, McAuthType::StreamAsym);
        assert!(mc.mc_public_key.is_some());

        // Source sends a single long stream (fiting in a single frame).
        let mut buf = [43u8; 5000];
        mc_pipe
            .mc_channel
            .channel
            .stream_send(1, &buf, true)
            .unwrap();

        // First packet is not sufficient to carry all the stream.
        mc_pipe
            .source_send_single_from_buf(None, 0, &mut buf[..1500])
            .unwrap();

        // The client received the beginning of the stream, but cannot
        // authenticate it.
        let client = &mc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![1]);
        let stream = client.streams.get(1).unwrap();
        assert_eq!(stream.mc_get_asym_sign(), None);
        assert!(!stream.recv.is_fully_readable());
        assert!(!stream.mc_asym_verified);

        // Now we sent the remaining of the stream.
        loop {
            match mc_pipe.source_send_single(None, 0) {
                Ok(_) => (),
                Err(Error::Done) => break,
                Err(e) => panic!("Error: {}", e),
            }
        }

        let client = &mut mc_pipe.unicast_pipes[0].0.client;
        assert_eq!(readables, vec![1]);
        let stream = client.streams.get(1).unwrap();

        // Stream is complete for authentication.
        assert!(stream.mc_get_asym_sign().is_some());
        assert!(stream.recv.is_fully_readable());
        assert!(!stream.mc_asym_verified);

        // Verifying the stream.
        assert_eq!(client.mc_stream_recv(1, &mut buf), Ok((5000, true)));
        let stream = client.streams.get(1).unwrap();
        assert!(stream.mc_asym_verified);

        // Source sends another stream. We will change the authentication tag
        // received by the client.
        mc_pipe.source_send_single_stream(true, None, 0, 5).unwrap();
        let client = &mut mc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![5]);
        let stream = client.streams.get_mut(5).unwrap();
        assert!(stream.mc_get_asym_sign().is_some());
        assert!(stream.recv.is_fully_readable());
        assert!(!stream.mc_asym_verified);

        stream
            .mc_get_mut_asym_sign()
            .map(|auth| auth[3] = auth[3].wrapping_add(10));
        assert_eq!(
            client.mc_stream_recv(5, &mut buf),
            Err(Error::Multicast(McError::McInvalidSign))
        );
    }

    #[test]
    /// Tests that the source correctly splits the stream if there is not enough
    /// space for the end of the stream and the MC_ASYM frame for
    /// [`authentication::McAuthType::StreamAsym`].
    fn test_mc_stream_asym_split_stream() {
        let use_auth = McAuthType::StreamAsym;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_stream_asym_split_stream.txt",
            use_auth,
            true,
            true,
            None,
        )
        .unwrap();

        let mut buf = [44u8; 1500];
        let channel = &mut mc_pipe.mc_channel.channel;
        channel.stream_send(1, &buf[..1300], true).unwrap();

        // Cannot fit the entire stream in the first packet because the MC_ASYM
        // would not fit.
        mc_pipe.mc_channel.mc_send(&mut buf).unwrap();
        let channel = &mut mc_pipe.mc_channel.channel;
        assert_eq!(
            channel.streams.get(1).unwrap().send.total_remaining(),
            Some(34)
        );

        mc_pipe.mc_channel.mc_send(&mut buf).unwrap();
        let channel = &mut mc_pipe.mc_channel.channel;
        assert_eq!(channel.streams.get(1).unwrap().send.total_remaining(), None);
    }

    #[test]
    fn test_rangeset_get_size() {
        let mut range = ranges::RangeSet::default();
        range.insert(0..100);
        range.insert(90..101);
        range.insert(200..201);
        assert_eq!(range.nb_elements(), 102);
    }

    #[test]
    fn test_mc_fec_lost_useless_packets() {
        let use_auth = McAuthType::None;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_fec_lost_useless_packets.txt",
            use_auth,
            true,
            true,
            None,
        )
        .unwrap();
        let mut clients_losing_packets = RangeSet::default();
        clients_losing_packets.insert(0..1);

        assert_eq!(
            mc_pipe.unicast_pipes[0]
                .0
                .client
                .fec_decoder
                .nb_missing_degrees(),
            Some(0)
        );

        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                0,
                1
            ),
            Ok(348)
        );
        assert_eq!(mc_pipe.source_send_single_stream(true, None, 0, 5), Ok(348));

        // Client did not receive the first source symbol.
        assert_eq!(mc_pipe.clients_send(), Ok(()));
        assert_eq!(
            mc_pipe.server_control_to_mc_source(time::Instant::now()),
            Ok(())
        );

        // The source sends a repair symbol.
        assert_eq!(mc_pipe.source_send_single(None, 0), Ok(1335));
        assert_eq!(
            mc_pipe.unicast_pipes[0]
                .0
                .client
                .fec_decoder
                .nb_missing_degrees(),
            Some(1)
        );

        assert_eq!(
            mc_pipe.source_send_single_stream(
                true,
                Some(&clients_losing_packets),
                0,
                9
            ),
            Ok(348)
        );
        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, 0, 13),
            Ok(348)
        );

        assert_eq!(
            mc_pipe.unicast_pipes[0]
                .0
                .client
                .fec_decoder
                .nb_missing_degrees(),
            Some(1)
        );
        // Client did not receive the source symbol.
        assert_eq!(mc_pipe.clients_send(), Ok(()));
        assert_eq!(
            mc_pipe.server_control_to_mc_source(time::Instant::now()),
            Ok(())
        );

        // The source sends a repair symbol.
        assert_eq!(
            mc_pipe.source_send_single(Some(&clients_losing_packets), 0),
            Ok(1335)
        );

        assert_eq!(
            mc_pipe.source_send_single_stream(true, None, 0, 17),
            Ok(348)
        );

        // Client did not receive the repair packet. Asks for two repair symbols
        // but not useful. The source only generates one.
        let nack_ranges = mc_pipe.unicast_pipes[0]
            .0
            .client
            .multicast
            .as_ref()
            .unwrap()
            .mc_nack_ranges
            .0
            .as_ref()
            .unwrap();
        let mut expected_nack_ranges = RangeSet::default();
        expected_nack_ranges.insert(2..3);
        expected_nack_ranges.insert(5..6);
        assert_eq!(nack_ranges, &(expected_nack_ranges, 6));
        assert_eq!(mc_pipe.clients_send(), Ok(()));
        assert_eq!(
            mc_pipe.server_control_to_mc_source(time::Instant::now()),
            Ok(())
        );
        assert_eq!(
            mc_pipe.source_send_single(Some(&clients_losing_packets), 0),
            Ok(1335)
        );
        assert_eq!(
            mc_pipe.source_send_single(Some(&clients_losing_packets), 0),
            Err(Error::Done)
        );

        let mut expected_sources_symbols_pn = RangeSet::default();
        expected_sources_symbols_pn.insert(2..4);
        expected_sources_symbols_pn.insert(5..7);
        expected_sources_symbols_pn.insert(8..9);
        assert_eq!(
            mc_pipe
                .mc_channel
                .channel
                .multicast
                .as_ref()
                .unwrap()
                .mc_ss_pn,
            expected_sources_symbols_pn
        );
    }

    #[test]
    /// Tests that the client can leave and join the multicast channel on the
    /// fly.
    fn test_mc_client_loop_join_leave() {
        let use_auth = McAuthType::None;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_client_loop_join_leave.txt",
            use_auth,
            true,
            true,
            None,
        )
        .unwrap();

        let mut client = &mut mc_pipe.unicast_pipes[0].0.client;
        assert_eq!(
            client.multicast.as_ref().unwrap().get_mc_role(),
            McRole::Client(McClientStatus::ListenMcPath(true))
        );

        for _ in 0..100 {
            client = &mut mc_pipe.unicast_pipes[0].0.client;
            assert_eq!(
                client.mc_leave_channel(),
                Ok(McClientStatus::Leaving(false))
            );

            mc_pipe.unicast_pipes[0].0.advance().unwrap();

            let server = &mut mc_pipe.unicast_pipes[0].0.server;
            assert_eq!(
                server.multicast.as_ref().unwrap().mc_role,
                McRole::ServerUnicast(McClientStatus::AwareUnjoined)
            );

            client = &mut mc_pipe.unicast_pipes[0].0.client;
            assert_eq!(
                client.multicast.as_ref().unwrap().mc_role,
                McRole::Client(McClientStatus::AwareUnjoined)
            );

            assert_eq!(
                client.mc_join_channel(false),
                Ok(McClientStatus::WaitingToJoin)
            );

            mc_pipe.unicast_pipes[0].0.advance().unwrap();

            client = &mut mc_pipe.unicast_pipes[0].0.client;
            assert_eq!(
                client.multicast.as_ref().unwrap().mc_role,
                McRole::Client(McClientStatus::ListenMcPath(true))
            );
            let server = &mut mc_pipe.unicast_pipes[0].0.server;
            assert_eq!(
                server.multicast.as_ref().unwrap().mc_role,
                McRole::ServerUnicast(McClientStatus::ListenMcPath(true))
            );
        }
    }

    #[test]
    fn test_mc_unordered_streams() {
        let use_auth = McAuthType::StreamAsym;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_unordered_streams.txt",
            use_auth,
            true,
            true,
            None,
        )
        .unwrap();
        let signature_len = 0;

        assert!(mc_pipe
            .source_send_single_stream(true, None, signature_len, 100 * 4 + 1)
            .is_ok());
        assert!(mc_pipe
            .source_send_single_stream(true, None, signature_len, 30 * 4 + 1)
            .is_ok());
        assert!(mc_pipe
            .source_send_single_stream(true, None, signature_len, 1000 * 4 + 1)
            .is_ok());

        let mut readables: Vec<u64> =
            mc_pipe.unicast_pipes[0].0.client.readable().collect();
        readables.sort();
        assert_eq!(readables, vec![30 * 4 + 1, 100 * 4 + 1, 1000 * 4 + 1]);

        let now = time::Instant::now();
        let expired_timer = now +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.expiration_timer + 100,
            ); // Margin
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired_timer);
        assert_eq!(res, Ok((Some(4), Some(2)).into()));

        assert!(mc_pipe
            .source_send_single_stream(true, None, signature_len, 10 * 4 + 1)
            .is_ok());
        assert!(mc_pipe
            .source_send_single_stream(true, None, signature_len, 0 * 4 + 1)
            .is_ok());
        assert!(mc_pipe
            .source_send_single_stream(true, None, signature_len, 10_000 * 4 + 1)
            .is_ok());

        let mut readables: Vec<u64> =
            mc_pipe.unicast_pipes[0].0.client.readable().collect();
        readables.sort();
        assert_eq!(readables, vec![0 * 4 + 1, 10 * 4 + 1, 10_000 * 4 + 1]);

        let now = time::Instant::now();
        let expired_timer = now +
            time::Duration::from_millis(
                mc_pipe.mc_announce_data.expiration_timer * 2 + 100,
            ); // Margin
        let res = mc_pipe.mc_channel.channel.on_mc_timeout(expired_timer);
        assert_eq!(res, Ok((Some(7), Some(5)).into()));
    }

    #[test]
    fn test_mc_no_retransmit_timer() {
        let use_auth = McAuthType::StreamAsym;
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_no_retransmit_timer.txt",
            use_auth,
            true,
            true,
            None,
        )
        .unwrap();

        mc_pipe.source_send_single_stream(true, None, 0, 1).unwrap();

        // The stream is sent to the clients.
        assert_eq!(mc_pipe.source_send_single(None, 0), Err(Error::Done));
        std::thread::sleep(time::Duration::from_millis(100));
        let conn = &mut mc_pipe.mc_channel.channel;
        conn.on_timeout();

        // The server must not retransmit STREAM data on the multicast channel.
        assert_eq!(mc_pipe.source_send_single(None, 0), Err(Error::Done));
    }
}

pub mod authentication;
use authentication::McAuthType;
pub mod reliable;
pub mod rotate;

use self::authentication::McAuthentication;
use self::authentication::McSymSign;
use self::reliable::RMcClient;
use self::reliable::RMcServer;
use self::reliable::ReliableMc;
use self::rotate::FcRotate;
use self::rotate::FcRotateServer;
use super::recovery::multicast::ReliableMulticastRecovery;
