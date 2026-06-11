//! Flexicast extension for QUIC.
/// Module relating to everything of the logical key hierarchy
pub mod lkhlib;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time;
use std::time::Duration;
use std::time::Instant;

use crate::fc_nack_recv;
use crate::fc_nack_recv_mut;
use crate::fec::decoder::FecDecoder;
use crate::fec::encoder::FecEncoder;
use crate::fec::schedulers::FecSchedulerAlgorithm;
use crate::flexicast::cca::FcFlowCwnd;
use crate::flexicast::McRole::ServerFlexicast;
use crate::flexicast::McRole::ServerUnicast;
use crate::flexicast::McRole::Undefined;
//use crate::flexicast::lkhlib::lkh::LKHPlus;
//use crate::flexicast::lkhlib::lkh::LogicalTree;
use crate::flexicast::lkhlib::lkhcrypto::lkh_decrypt;
use crate::flexicast::lkhlib::packet;
use crate::flexicast::lkhlib::packet::FCKeyUpdate;
use crate::flexicast::lkhlib::packet::KeyUpdatePacket;
use crate::flexicast::nack::FcAckDelayStrategy;
use crate::packet::Epoch;
use crate::packet::KeyUpdate;
use crate::path;
use crate::path::NetworkPathId;
use crate::rand;
use crate::rand::rand_bytes;
use crate::ranges;
use crate::ranges::RangeSet;
use crate::CongestionControlAlgorithm;
use crate::InternalPathId;
use crate::SendInfo;
use crate::MIN_CLIENT_INITIAL_LEN;
use flowcontrol::FcFlowControl;
use reliable::RFcRecv;
use reliable::RFcSource;
use reliable::RFcUcPath;
use reliable::ReliableFc;
use ring::hmac::Key;

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

/// Communication between the flexicast channel and the unicast connections.
#[macro_export]
macro_rules! ucs_to_mc_cwnd {
    ( $mc:expr, $ucs: expr, $now: expr, $cwnd_limit: expr ) => {
        let min_cwnd = $ucs
            .filter_map(|uc| {
                let cwnd = uc.fc_get_cwnd_recv();

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

macro_rules! fc_chan_idx {
    ($s:expr) => {
        $s.fc_chan_id
            .as_ref()
            .map(|(_, idx)| *idx)
            .ok_or(Error::Flexicast(FcError::McAnnounce))
    };
}

/// Shortcut to get the flexicast attributes.
#[macro_export]
macro_rules! fca {
    ( $conn:expr ) => {
        $conn
            .flexicast
            .as_ref()
            .ok_or(Error::Flexicast(FcError::McDisabled))
    };
}

/// Shortcut to get the flexicast attributes as mutable.
#[macro_export]
macro_rules! fca_mut {
    ( $conn:expr ) => {
        $conn
            .flexicast
            .as_mut()
            .ok_or(Error::Flexicast(FcError::McDisabled))
    };
}

/// Flexicast extension errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FcError {
    /// Incorrect McAnnounce data.
    McAnnounce,
    Debug, // TO REMOVE
    /// Incomplete server channel initiation.
    McServerInit,

    /// Invalid symetric key.
    McInvalidSymKey,

    /// Attempts to perform server-specific function if a client
    /// and conversely.
    McInvalidRole(McRole),

    /// Flexicast is disabled.
    McDisabled,

    /// Invalid asymetric key.
    McInvalidAsymKey,

    /// Invalid asymetric signature.
    McInvalidSign,

    /// Invalid status state machine move for the client.
    McInvalidAction,

    /// Handshake of the flexicast server channel failed.
    McChannelHandshake,

    /// Invalid multipath path used, or invalid space id.
    McPath,

    /// Error when initiating the flexicast pipe.
    McPipe,

    /// Invalid new client ID.
    McInvalidClientId,

    /// Invalid authentication information.
    McInvalidAuth,

    /// No authentication packet available to verify the source of the flexicast
    /// data packet.
    McNoAuthPacket,

    /// Invalid crypto context on the flexicast channel.
    McInvalidCrypto,

    /// Attempt to use reliable flexicast which is disabled.
    McReliableDisabled,

    /// Stream rotation is disabled or invalid role.
    FcStreamRotation,

    /// Attempt to read a stream in-order while it uses stream rotation.
    FcStreamOutOfOrder,

    /// Attempt to change channel ID in 1 RTT but path probing is used.
    FcChangeChan,

    /// The receiver doesn't know the key that was used to encrypt the new key
    FcLKHKeyUnknown,
    /// Timer error,
    FcTimeError,
    /// FcPath id mistakenly uninitialized
    FcPathId,
}

/// MC_ANNOUNCE frame type.
pub const MC_ANNOUNCE_CODE: u64 = 0xf2;
/// MC_ANNOUNCE with bandwidth information frame type.
pub const MC_ANNOUNCE_BW_CODE: u64 = 0xf3;
/// MC_STATE frame type.
pub const MC_STATE_CODE: u64 = 0xf4;
/// MC_KEY frame type.
pub const MC_KEY_CODE: u64 = 0xf5;
/// MC_ASYM frame type.
pub const MC_ASYM_CODE: u64 = 0xf8;
/// FC_ACK_DELAY frame type.
pub const FC_ACK_DELAY_CODE: u64 = 0xf9;

/// The leaving action is requested by the client.
pub const LEAVE_FROM_CLIENT: u64 = 0x0;
/// The leaving action is requested by the server.
pub const LEAVE_FROM_SERVER: u64 = 0x1;

/// States of a flexicast client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum McClientStatus {
    /// Leaving the flexicast channel. The client waits for acknowledgment.
    /// In the meantime, the client can still listen to flexicast traffic.
    /// The inner value is `true` if the client already sent the notification to
    /// the server.
    Leaving(bool),

    /// Refused to join the flexicast channel.
    DeclinedJoin,

    /// Joined the flexicast channel, but does not have the key yet.
    JoinedNoKey,

    /// Aware of a flexicast channel but not joined.
    AwareUnjoined,

    /// Sent information to join the flexicast channel but not confirmed yet.
    WaitingToJoin,

    /// Joined and got the decryption key.
    JoinedAndKey,

    /// Has a flexicast path. Listens to flexicast data.
    ListenMcPath(bool),

    /// The client is not aware of the flexicast channel.
    Unaware,

    /// This is used when the status is of no importance.
    Unspecified,

    /// The client is changing the channel it listens to.
    Changing,

    /// The receiver falled back on unicast.
    UcFallBack,
}

/// Actions of flexicast client in the finite state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum FcClientAction {
    /// Knows the existence of the flexicast channel.
    Notify,

    /// Joins the flexicast channel.
    Join,

    /// Leaves the flexicast channel.
    Leave,

    /// Receives the decryption key.
    DecryptionKey,

    /// Flexicast path created.
    McPath,

    /// Change to another flexicast channel in 1 RTT.
    /// Only if both channels do not use path probing and the client already
    /// listens to a channel.
    Change,

    /// The unicast path notifies the new highest packet number sent on the
    /// flexicast flow. This is required to resync the receiver with the
    /// flexicast flow.
    Sync,
}

impl TryFrom<u64> for FcClientAction {
    type Error = crate::Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => FcClientAction::Notify,
            1 => FcClientAction::Join,
            2 => FcClientAction::Leave,
            3 => FcClientAction::DecryptionKey,
            4 => FcClientAction::McPath,
            5 => FcClientAction::Change,
            6 => FcClientAction::Sync,
            _ => return Err(Error::Flexicast(FcError::McInvalidAction)),
        })
    }
}

impl TryInto<u64> for FcClientAction {
    type Error = crate::Error;

    fn try_into(self) -> std::result::Result<u64, Self::Error> {
        Ok(match self {
            FcClientAction::Notify => 0,
            FcClientAction::Join => 1,
            FcClientAction::Leave => 2,
            FcClientAction::DecryptionKey => 3,
            FcClientAction::McPath => 4,
            FcClientAction::Change => 5,
            FcClientAction::Sync => 6,
        })
    }
}

/// Flexicast extensions for a connection configuration.
pub trait McConfig {
    /// Sets the `flexicast_support` transport parameter.
    ///
    /// The default value is `false`.
    fn set_enable_flexicast(&mut self, v: bool);
    /// Set the `lkh_support` transport parameter.
    ///
    /// Default to `false`
    fn set_enable_lkh(&mut self, v: bool);
}

impl McConfig for crate::Config {
    fn set_enable_flexicast(&mut self, v: bool) {
        self.local_transport_params.flexicast_support = v;
    }
    fn set_enable_lkh(&mut self, v: bool) {
        self.local_transport_params.lkh_support = v;
    }
}

/// Role of the connection
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McRole {
    /// Server flexicast channel. Not directly connected to any
    /// connection with a client.
    ServerFlexicast,

    /// Server unicast channel. Directly connected to its client.
    ServerUnicast(McClientStatus),

    /// Receiver. As it uses multipath, it uses both unicast and flexicast.
    Client(McClientStatus),

    /// Undefined role. Used for debugging and as temporary value.
    Undefined,
}

impl std::fmt::Display for McRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerFlexicast => write!(f, "[Flexicast multicast server]"),
            ServerUnicast(_) => write!(f, "[Flexicast unicast server]"),
            McRole::Client(_) => write!(f, "[Flexicast client]"),
            Undefined => write!(f, "[undefined]"),
        }
    }
}

/// Structure containing all flexicast-related variables of the extension
/// in a quiche::Connection.
pub struct FlexicastAttributes {
    /// Role of the extension.
    mc_role: McRole,

    /// Flexicast channel information that is shared in a MC_ANNOUNCE frame.
    /// Server-side: the information to share.
    /// Client-side: the received information.
    /// This is an option because it may be null initially (for example
    /// the client did not receive the MC_ANNOUNCE yet).
    mc_announce_data: Vec<McAnnounceData>,

    /// Flexicast crypto Open. Used for the flexicast channel only.
    mc_crypto_open: Option<Open>,

    /// Flexicast crypto Open. Used for the flexicast channel only.
    mc_crypto_seal: Option<Seal>,

    /// Whether the key is up to date.
    mc_key_up_to_date: bool,

    /// Contain the current key transition ()
    mc_key_update: Option<KeyUpdate>,

    /// Set to true if the client just left the flexicast channel and the
    /// synchronisation step is not performed yet.
    mc_client_left_need_sync: bool,

    /// MC_STATE frame in flight.
    pub(crate) mc_state_in_flight: bool,

    /// The first packet number that the receiver must listen to.
    /// Transmitted in the FC_KEY frame.
    pub(crate) fc_first_pn: Option<u64>,

    /// Path ID linked to the flexicast flow.
    fc_path_id: Option<u64>,

    /// Flexicast channel ID that the client joins, and index in the list of
    /// received McAnnounceData.
    pub(crate) fc_chan_id: Option<(Vec<u8>, usize)>,

    /// Whether the receiver must do explicit PATH_ACK acknowledgment.
    /// Concretelly, it will make PATH_ACK frames for the flexicast flow ack
    /// eliciting by adding a PING frame.
    pub(crate) _fc_make_ack_elicit: bool,

    /// Structure handling the reliability between the flexicast flow and the
    /// unicast paths.
    pub(crate) fc_reliable: ReliableFc,

    /// Structure handling the flow control between the flexicast flow and the
    /// receivers.
    pub(crate) fc_flow_control: FcFlowControl,

    /// Structure handling the Forward Erasure Correction.
    pub fc_fec: fec::FcFec,

    /// Highest packet number acknowledged on the flexicast flow.
    pub fc_highest_ack_pn: Option<u64>,
    /// Does the flexicast flow uses the LKH key system
    pub fc_uses_lkh: bool,

    /// Queue of LKH key update to send
    pub lkh_keys_to_send: VecDeque<FCKeyUpdate>,
    /// Key phase of the multicast flow
    pub fc_key_phase: bool,
    /// Session key not yet applied,
    /// contain NewSessionKey, first pn to encrypt with the new key
    pub fc_lkh_server_updates: HashMap<u64, (Algorithm, Vec<u8>)>,
}

impl FlexicastAttributes {
    #[inline]
    /// Returns the Flexicast channel ID that the client joins, and its index in
    /// the list of received McAnnounceData.
    pub fn get_fc_chan_id(&self) -> Option<&(Vec<u8>, usize)> {
        self.fc_chan_id.as_ref()
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
    /// Returns a reference to the MC_ANNOUNCE data of the flexicast channel
    /// that the client listens to.
    pub fn get_mc_announce_data_active(&self) -> Option<&McAnnounceData> {
        self.mc_announce_data.get(fc_chan_idx!(self).ok()?)
    }

    #[inline]
    /// Returns a the index of an MC_ANNOUNCE data based on the flexicast
    /// channel ID.
    pub fn get_mc_announce_data_index(&self, fc_chan_id: &[u8]) -> Option<usize> {
        self.mc_announce_data
            .iter()
            .position(|announce| announce.channel_id == fc_chan_id)
    }

    #[inline]
    /// Returns the current flexicast role.
    pub fn get_mc_role(&self) -> McRole {
        self.mc_role
    }

    #[inline]
    /// Sets the MC_STATE frame in flight.
    pub fn set_mc_state_in_flight(&mut self, v: bool) {
        self.mc_state_in_flight = v;
    }

    #[inline]
    /// Get the current key transition
    pub fn get_fc_key_update(&self) -> &Option<KeyUpdate> {
        &self.mc_key_update
    }

    #[inline]
    /// Take the current key transition
    pub fn take_fc_key_update(&mut self) -> Option<KeyUpdate> {
        println!("Taking key update");
        self.mc_key_update.take()
    }

    /// Sets the client status following the state machine.
    /// Returns an error if the client would do an invalid move in the state
    /// machine. MC-TODO: complete the finite state machine.
    pub fn update_client_state(
        &mut self, action: FcClientAction, action_data: Option<u64>,
    ) -> Result<McClientStatus> {
        let (is_server, current_status) = match self.mc_role {
            McRole::Client(status) => (false, status),
            McRole::ServerUnicast(status) => (true, status),
            _ => {
                return Err(Error::Flexicast(FcError::McInvalidRole(
                    self.mc_role,
                )))
            },
        };

        let new_status = match (current_status, action) {
            (McClientStatus::Unaware, FcClientAction::Notify) => {
                McClientStatus::AwareUnjoined
            },
            (McClientStatus::AwareUnjoined, FcClientAction::Join)
                if !is_server =>
            {
                println!("Transition to waiting to join");
                McClientStatus::WaitingToJoin
            },
            (McClientStatus::AwareUnjoined, FcClientAction::Join)
                if is_server =>
            {
                McClientStatus::JoinedNoKey
            },
            (McClientStatus::Unaware, FcClientAction::Join)
                if is_server
                    && self.get_mc_announce_data(0).unwrap().is_processed =>
            {
                McClientStatus::JoinedNoKey
            },
            (McClientStatus::WaitingToJoin, FcClientAction::Join) => {
                println!("Transitioned to joined no key");
                McClientStatus::JoinedNoKey
            },
            (McClientStatus::JoinedNoKey, FcClientAction::DecryptionKey) => {
                McClientStatus::JoinedAndKey
            },
            (McClientStatus::WaitingToJoin, FcClientAction::DecryptionKey)
                if is_server && self.mc_key_up_to_date =>
            {
                McClientStatus::JoinedAndKey
            },
            (McClientStatus::WaitingToJoin, FcClientAction::DecryptionKey)
                if !is_server =>
            {
                McClientStatus::JoinedAndKey
            },
            (McClientStatus::ListenMcPath(_), FcClientAction::Leave) => {
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
                        return Err(Error::Flexicast(FcError::McInvalidAction));
                    }
                } else {
                    debug!("Invalid action 2");
                    return Err(Error::Flexicast(FcError::McInvalidAction));
                }
            },
            (McClientStatus::Leaving(false), FcClientAction::Leave) => {
                McClientStatus::AwareUnjoined
            },
            (McClientStatus::Leaving(true), FcClientAction::Leave) => {
                McClientStatus::AwareUnjoined
            },
            (
                McClientStatus::JoinedAndKey | McClientStatus::JoinedNoKey,
                FcClientAction::McPath,
            ) if action_data.is_some() && is_server => {
                self.fc_path_id = Some(action_data.unwrap());
                McClientStatus::ListenMcPath(true)
            },
            (McClientStatus::JoinedAndKey, FcClientAction::McPath)
                if action_data.is_some() && !is_server =>
            {
                self.fc_path_id = Some(action_data.unwrap());
                McClientStatus::ListenMcPath(true)
            },
            (McClientStatus::ListenMcPath(true), FcClientAction::Change)
                if action_data.is_some() =>
            {
                self.mc_key_up_to_date = false;
                self.fc_path_id = Some(action_data.unwrap());
                McClientStatus::Changing
            },
            (McClientStatus::Changing, FcClientAction::DecryptionKey) => {
                McClientStatus::ListenMcPath(true)
            },
            (McClientStatus::AwareUnjoined, FcClientAction::Leave) => {
                McClientStatus::AwareUnjoined
            },
            (McClientStatus::ListenMcPath(_), _) => current_status,
            (McClientStatus::JoinedAndKey, FcClientAction::Join) => {
                current_status
            },
            _ => {
                debug!(
                    "Invalid action 3: current={:?} and action is {:?}",
                    current_status, action
                );
                current_status
            },
        };

        // If the client leaves the flexicast group, its key is not longer up to
        // date.
        if action == FcClientAction::Leave && is_server {
            self.mc_key_up_to_date = false;
        }

        // If the client left the group, it no longer has a space id.
        if new_status == McClientStatus::AwareUnjoined
            && matches!(current_status, McClientStatus::Leaving(_))
        {
            self.fc_path_id = None;
        }

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
    /// of if the client created the flexicast path.
    pub fn should_send_fc_state(&self) -> bool {
        if self.mc_state_in_flight {
            return false;
        }
        match self.mc_role {
            McRole::Client(status) => match status {
                McClientStatus::WaitingToJoin => true,
                McClientStatus::JoinedAndKey => self.fc_path_id.is_some(),
                McClientStatus::Leaving(false) => true,
                McClientStatus::Changing => true,
                _ => false,
            },
            McRole::ServerUnicast(McClientStatus::Leaving(false)) => true,
            McRole::ServerUnicast(McClientStatus::UcFallBack) => self
                .fc_reliable
                .server()
                .is_some_and(|r| r.fc_highest_pn.is_some()),
            _ => false,
        }
    }

    /// Returns whether the server should send an MC_KEY frame
    /// to share the public authentication key to the client.
    /// True if the client has joined the flexicast channel
    /// but has received not the authentication key yet.
    /// Always false for a client.
    pub fn should_send_fc_key(&self) -> bool {
        if self.fc_uses_lkh {
            return false;
        }
        if let Some((_, idx)) = self.fc_chan_id {
            if self.mc_announce_data[idx].fc_channel_secret.is_none() {
                return false;
            }
        }
        if self.mc_key_up_to_date {
            return false;
        }
        if self.fc_first_pn.is_none() {
            return false;
        }
        if let McRole::ServerUnicast(status) = self.mc_role {
            matches!(
                status,
                McClientStatus::JoinedAndKey
                    | McClientStatus::ListenMcPath(_)
                    | McClientStatus::Changing
                    | McClientStatus::JoinedNoKey
            )
        } else {
            false
        }
    }
    /// Should the server send fc lkh keys
    pub fn should_send_fc_lkh_key(&self) -> bool {
        !self.lkh_keys_to_send.is_empty()
            && self.fc_uses_lkh
            && match self.mc_role {
                McRole::ServerUnicast(status) => {
                    matches!(
                        status,
                        McClientStatus::JoinedAndKey
                            | McClientStatus::ListenMcPath(_)
                            | McClientStatus::Changing
                            | McClientStatus::JoinedNoKey
                    )
                },
                ServerFlexicast => true,
                _ => false,
            }
    }

    /// Read the last flexicast decryption key secret.
    pub fn set_mc_key_read(&mut self, v: bool) {
        self.mc_key_up_to_date = v;
    }

    /// Whether the flexicast decryption key is received by the client.
    pub fn mc_client_has_key(&self) -> bool {
        self.mc_key_up_to_date
    }
    //FC-LKH-TODO: switch depending on the presence of a lkh tree
    /// Get the channel decryption key secret.
    pub fn get_decryption_key_secret(&self) -> Result<&[u8]> {
        match self.mc_role {
            McRole::ServerUnicast(McClientStatus::JoinedNoKey)
            | McRole::ServerUnicast(McClientStatus::Changing) => Ok(self
                .mc_announce_data[fc_chan_idx!(self)?]
            .fc_channel_secret
            .as_ref()
            .ok_or(Error::Flexicast(FcError::McInvalidSymKey))?),
            _ => Err(Error::Flexicast(FcError::McInvalidRole(self.mc_role))),
        }
    }

    /// Get the channel decryption algorithm.
    pub fn get_decryption_key_algo(&self) -> Algorithm {
        // FC-TODO: panic?
        self.mc_announce_data[fc_chan_idx!(self).unwrap_or(0)]
            .fc_channel_algo
            .unwrap_or(Algorithm::AES128_GCM)
    }

    /// Sets the channel decryption key secret.
    pub fn set_decryption_key_secret(
        &mut self, key: Vec<u8>, algo: Algorithm,
    ) -> Result<()> {
        match self.mc_role {
            McRole::Client(McClientStatus::JoinedNoKey)
            | McRole::Client(McClientStatus::WaitingToJoin)
            | McRole::Client(McClientStatus::Changing)
            | McRole::Client(McClientStatus::JoinedAndKey) => {
                let aead_open = Open::from_secret(algo, &key)?;
                self.mc_crypto_open = Some(aead_open);
                let aead_seal = Seal::from_secret(algo, &key)?;
                self.mc_crypto_seal = Some(aead_seal);

                self.mc_announce_data[fc_chan_idx!(self)?].fc_channel_secret =
                    Some(key);
                self.mc_announce_data[fc_chan_idx!(self)?].fc_channel_algo =
                    Some(algo);

                Ok(())
            },

            _ => Err(Error::Flexicast(FcError::McInvalidRole(self.mc_role))),
        }
    }
    /// Update the client keys and session key according to the packet recieved
    pub fn lkh_update_client_keys(
        &mut self, algo: Algorithm, packet: lkhlib::packet::FCKeyUpdate,
        first_pn: u64,
    ) -> Result<()> {
        match self.mc_role {
            McRole::Client(_) => match packet {
                lkhlib::packet::FCKeyUpdate::KeyUpdate(packet) => {
                    self.process_lkh_update_packet(algo, packet, first_pn)
                },
                lkhlib::packet::FCKeyUpdate::KeylessWrappedKeyUpdate(packet) => {
                    //This packet is encrypted with the key that may be stored with the key ksk_id
                    let mc_data = &mut self.mc_announce_data[fc_chan_idx!(self)?];
                    let ksk_id = packet.ksk_id;
                    if let Some(ksk) = mc_data.fc_key_dict.get(&packet.ksk_id) {
                        let counter =
                            mc_data.fc_lkh_counters.get(&ksk_id).unwrap_or(&0);

                        if *counter >= packet.counter {
                            println!("[LKH] Got a key with counter {} but last one was {}",packet.counter,*counter);
                            return Err(Error::Flexicast(
                                FcError::FcLKHKeyUnknown,
                            ));
                        }

                        let new_counter = packet.counter;

                        println!("[LKH] Received a protected key update : ksk_id:{:?}, counter : {}",packet.ksk_id,packet.counter);
                        let clear = lkh_decrypt(packet, ksk.clone(), algo)?;
                        mc_data.fc_lkh_counters.insert(ksk_id, new_counter);
                        self.process_lkh_update_packet(algo, clear, first_pn)
                    } else {
                        // We are unable to decrypt the packet so we drop it ?
                        Ok(())
                    }
                },
                lkhlib::packet::FCKeyUpdate::RawKey(key) => {
                    // standard update
                    self.add_key_update(algo, key, first_pn) //TODO incorrect
                },
                //lkhlib::packet::FCKeyUpdate::WrappedKeyUpdate$(_) => Err(Error::Flexicast(FcError::McInvalidAsymKey) )
            },
            role => Err(Error::Flexicast(FcError::McInvalidRole(role))),
        }
    }
    /// Prepare for a mc key change on the clien side
    fn add_key_update(
        &mut self, algo: Algorithm, key: Vec<u8>, first_pn: u64,
    ) -> Result<()> {
        //println!("[LKH] Adding key update");

        println!(
            "[LKH] {:#?} Preparing new key {:?} to be used at PN={first_pn}",
            time::SystemTime::now(),
            key
        );
        if self.mc_crypto_open.is_none() {
            println!("No mc crypto open specified, skipping wait");
            self.mc_crypto_open.replace(Open::from_secret(algo, &key)?);
        } else {
            let new_update = KeyUpdate {
                crypto_open: Open::from_secret(algo, &key)?,
                pn_on_update: first_pn,
                update_acked: true, //TODO change to a smart way of doing that
                timer: Instant::now()
                    .checked_add(Duration::new(5, 0))
                    .ok_or(Error::Flexicast(FcError::FcTimeError))?, //TODO change to use RTT
            };
            println!("Replacing the old update");
            let update = self.mc_key_update.replace(new_update);
            println!("Old update : {:?}", update);
        }

        /*if let Some(old_update) = update {
            self.fc_key_phase = !self.fc_key_phase;
            self.mc_crypto_open.replace(old_update.crypto_open);
        }*/

        Ok(())
    }
    fn process_lkh_update_packet(
        &mut self, algo: Algorithm, packet: KeyUpdatePacket, first_pn: u64,
    ) -> Result<()> {
        trace!("[LKH] trying to update key {}", &packet.new_key_id);

        let key_dict =
            &mut self.mc_announce_data[fc_chan_idx!(self)?].fc_key_dict;

        if !packet.delete_new_key {
            println!("[LKH] Received a keyupdate : key={:?}, key_id={:?} to be used at PN>={first_pn}",packet.new_key,packet.new_key_id);
            key_dict.insert(packet.new_key_id, packet.new_key.clone());

            if packet.is_session_key {
                trace!("[LKH] new session secret : {:?}", &packet.new_key);
                //self.set_decryption_key_secret(packet.new_key, algo)
                self.add_key_update(algo, packet.new_key, first_pn)
            } else {
                Ok(())
            }
        } else {
            trace!("[LKH] trying to remove key {}", &packet.new_key_id);
            key_dict
                .remove(&packet.new_key_id)
                .map(|_| ())
                .ok_or(Error::Flexicast(FcError::FcLKHKeyUnknown))?;
            self.mc_announce_data[fc_chan_idx!(self)?]
                .fc_lkh_counters
                .remove(&packet.new_key_id)
                .map(|_| ())
                .ok_or(Error::Flexicast(FcError::FcLKHKeyUnknown))
        }
    }

    /// Process a lkh keyupdate and, if it's a session key, adds it to the backlog of session key change
    pub fn lkh_server_update_key_backlog(
        &mut self, update: FCKeyUpdate, next_pn: u64,
    ) -> Result<()> {
        let (is_session, key) = match update {
            FCKeyUpdate::KeyUpdate(packet) => {
                (packet.is_session_key, packet.new_key.clone())
            },
            FCKeyUpdate::KeylessWrappedKeyUpdate(packet) => return Ok(()),
            FCKeyUpdate::RawKey(key) => (true, key.clone()),
        };
        if is_session {
            println!("[LKH] Scheduling a session key change for PN={next_pn}, role : {:?}",self.get_mc_role());

            self.fc_lkh_server_updates
                .insert(next_pn, (self.get_decryption_key_algo(), key));
        };

        Ok(())
    }

    /// Gives the decryption context for the flexicast channel.

    pub fn get_mc_crypto_open(&self) -> Option<&Open> {
        self.mc_crypto_open.as_ref()
    }
    /// Apply the pending lkh session key update if it exist
    pub fn apply_key_update(&mut self) {
        if self.mc_key_update.is_some() {
            let open = self.mc_key_update.take().unwrap().crypto_open;
            self.mc_crypto_open.replace(open);
        }
    }

    /// Sets the flexicast path space identifier.
    /// This is used to alwasy refer to the correct flexicast path
    /// when processing packets.
    pub fn set_fc_path_id(&mut self, space_id: u64) {
        self.fc_path_id = Some(space_id)
    }

    /// Gets the flexicast space ID.
    pub fn get_fc_path_id(&self) -> Option<u64> {
        self.fc_path_id
    }

    /// Sets the [`FlexicastAttributes::fc_path_id`] or
    /// [`FlexicastAttributes::fc_path_id_auth`] depending on the given local
    /// address from the quiche library.
    pub fn set_fc_path_id_from_addr(
        &mut self, local_addr: SocketAddr, pid: u64,
    ) -> Result<()> {
        for mc_data in self.mc_announce_data.iter() {
            let ip = std::net::Ipv4Addr::from(mc_data.group_ip.to_owned());
            if local_addr.ip() == ip && local_addr.port() == mc_data.udp_port {
                self.set_fc_path_id(pid);
                return Ok(());
            }
        }

        Err(Error::Flexicast(FcError::McPath))
    }

    /// Returns a reference to the reliability mechanism.
    pub fn get_fc_reliable(&self) -> &ReliableFc {
        &self.fc_reliable
    }
}

impl Default for FlexicastAttributes {
    fn default() -> Self {
        Self {
            mc_role: McRole::Undefined,
            mc_announce_data: Vec::with_capacity(2),
            mc_crypto_open: None,
            mc_crypto_seal: None,
            mc_key_up_to_date: false,
            mc_key_update: None,
            fc_path_id: None,
            mc_client_left_need_sync: false,
            mc_state_in_flight: false,
            fc_chan_id: None,
            _fc_make_ack_elicit: false,
            fc_first_pn: None,
            fc_reliable: ReliableFc::Undefined,
            fc_flow_control: FcFlowControl::default(),
            fc_fec: fec::FcFec::Undefined,
            fc_highest_ack_pn: None,
            //fc_lkh: None,
            lkh_keys_to_send: VecDeque::new(),
            fc_key_phase: false,
            fc_uses_lkh: true,
            fc_lkh_server_updates: HashMap::new(),
        }
    }
}

/// Flexicast channel announcement information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McAnnounceData {
    /// Replaces the Connection ID for flexicast.
    pub channel_id: Vec<u8>,

    /// Set to `true` if it is an IPv6 flexicast group, `false` for IPv4.
    pub is_ipv6_addr: bool,

    /// Whether path probing is required to create the flexicast path.
    pub probe_path: bool,

    /// IP address of the flexicast source (IPv4 only WIP).
    pub source_ip: [u8; 4],

    /// IP address of the flexicast group (IPv4 only WIP).
    pub group_ip: [u8; 4],

    /// Source UDP port to use for the clients.
    pub udp_port: u16,

    /// Flexicast-specific timer.
    /// The main purpose of this timer is to use negative acknowledgments only
    /// for the receivers. If the timer is set to a value different than 0,
    /// it means that the receivers MUST expect to receive at least a packet
    /// every `fc_ack_delay` ms on the flexicast flow. Otherwise, there may be a
    /// flexicast flow and the receiver SHOULD send a PATH_ACK frame to trigger
    /// retransmission.
    pub fc_ack_delay: u64,

    /// True if this flexicast announce data is processed.
    /// For a server, it means that the data is sent to the client.
    /// For a client, it means that the data is received.
    pub is_processed: bool,

    /// Flexicast channel decryption key material.
    ///
    /// Distributed in the MC_KEY frame.
    pub fc_channel_secret: Option<Vec<u8>>,

    /// Flexicast channel encryption algorithm.
    ///
    /// Distributed in the MC_KEY frame.
    /// mc_channel_algo: Algorithm::AES128_GCM,
    pub fc_channel_algo: Option<Algorithm>,

    /// Dictionnary to store the LKH keys and their associated counter
    pub fc_key_dict: HashMap<u64, Vec<u8>>,
    /// Anti replay counters for LKH
    pub fc_lkh_counters: HashMap<u64, u64>,
}

impl McAnnounceData {
    /// Sets the processed state of the MC_ANNOUNCE data.
    /// If set to true, means that the last data has been processed on the host.
    pub fn set_mc_announce_processed(&mut self, v: bool) {
        self.is_processed = v;
    }
}

/// Flexicast extension behaviour for the QUIC connection.
pub trait FlexicastConnection {
    /// Returns the index of the first MC_ANNOUNCE data that should be
    /// announced. Always `None` for a client.
    fn fc_should_send_fc_announce(&self) -> Option<usize>;

    /// Sets the MC_ANNOUNCE data on the server and the client.
    /// Creates the flexicast extension attributes if it does not exist yet.
    /// Returns an Error if flexicast is not supported.
    ///
    /// MC-TODO: currently if there is a new MC_ANNOUNCE sent by the server,
    /// the client will move again in the AwareUnjoined role
    /// without notifying the application. This is not currently handled.
    /// However, it is a nice feature because we want to be sure that the client
    /// can control its willing to listen to the flexicast channel if the
    /// MC_ANNOUNCE data changes during the communication.
    fn fc_set_announce_data(
        &mut self, mc_announce_data: &McAnnounceData,
    ) -> Result<()>;

    /// Sets the symetric keys from the secrets. Only used in flexicast.
    /// Updates the MC_ANNOUNCE data if it exists, or adds a new structure.
    /// Creates the flexicast structure if it does not exist.
    ///
    /// Also sets the flexicast channel decryption key secret on the unicast
    /// server.
    /// Sets the flexicast receiver key for the specified MC_ANNOUNCE data, if
    /// any. Otherwise, rely on the `fc_chan_id`.
    /// Returns an McAnnounce error if no of the above conditions are met.
    ///
    /// MC-TODO: change the name to be more explicit.
    fn mc_set_flexicast_receiver(
        &mut self, secret: &[u8], fc_path_id: u64, algo: Algorithm,
        mc_announce_id: Option<usize>,
    ) -> Result<()>;

    /// Returns true if the flexicast extension has control data to send.
    fn fc_has_control_data(&self, send_pid: usize) -> bool;

    /// Joins a flexicast channel advertised by a server.
    /// Sets the possibility to leave the flexicast channel on timeout on this
    /// flexicast channel, i.e., in [`FlexicastConnection::on_mc_timeout`].
    /// Returns an Error if:
    /// * This is not a client
    /// * There is no flexicast state with valid MC_ANNOUNCE data
    /// * The status is not AwareUnjoined
    fn mc_join_channel(
        &mut self, leave_on_timeout: bool, fc_chan_id: Option<&[u8]>,
    ) -> Result<McClientStatus>;

    /// Leaves a previously joined flexicast channel.
    /// Returns an Error if:
    /// * This is not a client or a unicast server
    /// * There is no flexicast state with valid MC_ANNOUNCE data
    /// * The client did not joined the channel
    fn mc_leave_channel(&mut self) -> Result<McClientStatus>;

    /// Returns whether the path id given as argument is a flexicast path.
    /// False if flexicast is disabled or if the path is not a flexicast path.
    fn is_mc_path(&self, space_id: u64) -> bool;

    /// Adds the new connection IDs for the flexicast client.
    /// Previously, this was done in the [`FlexicastConnection::create_mc_path`]
    /// function but not this is separated because the two frames were sent on
    /// the same path
    fn add_mc_cid(&mut self, cid: &ConnectionId) -> Result<()>;

    /// Creates a flexicast path on the client.
    /// This is done manually by the client without contacting the unicast
    /// server to avoid sharing a same path for the flexicast and unicast
    /// source.
    fn create_mc_path(
        &mut self, client_addr: SocketAddr, server_addr: SocketAddr,
        to_uc_server: bool,
    ) -> Result<u64>;

    /// Returns the flexicast attributes.
    fn get_flexicast_attributes(&self) -> Option<&FlexicastAttributes>;

    /// Synchronous communication between the unicast path and the flexicast
    /// flows. The unicast server connection sends control messages to the
    /// multicast source.
    fn uc_to_fc_control(
        &mut self, fc_flow: &mut Connection, now: time::Instant,
    ) -> Result<()>;
}

impl FlexicastConnection for Connection {
    fn fc_should_send_fc_announce(&self) -> Option<usize> {
        if !self.is_server {
            return None;
        }
        if !self.local_transport_params.flexicast_support {
            return None;
        }

        if let Some(flexicast) = self.flexicast.as_ref() {
            let idx = flexicast
                .mc_announce_data
                .iter()
                .position(|mc_data| !mc_data.is_processed);
            if idx.is_some()
                && flexicast.mc_role
                    == McRole::ServerUnicast(McClientStatus::Unaware)
            {
                idx
            } else {
                None
            }
        } else {
            None
        }
    }

    fn mc_set_flexicast_receiver(
        &mut self, secret: &[u8], fc_path_id: u64, algo: Algorithm,
        mc_announce_id: Option<usize>,
    ) -> Result<()> {
        if let Some(flexicast) = self.flexicast.as_mut() {
            match flexicast.mc_role {
                McRole::Client(McClientStatus::WaitingToJoin) => {
                    // Do not perform the handshake because we already have the
                    // key.
                    self.handshake_completed = true;

                    // Derive the keys from the secret shared by the receiver.
                    let algo = flexicast.mc_announce_data
                        [fc_chan_idx!(flexicast)?]
                    .fc_channel_algo
                    .unwrap_or(Algorithm::AES128_GCM);
                    let aead_open = Open::from_secret(algo, secret).unwrap();
                    let aead_seal = Seal::from_secret(algo, secret).unwrap();

                    // Do not change the global context.
                    // We will use this crypto when needed by manually getting it.
                    flexicast.mc_crypto_open = Some(aead_open);
                    flexicast.mc_crypto_seal = Some(aead_seal);

                    Ok(())
                },
                McRole::ServerUnicast(_) => {
                    // let id = mc_announce_id.unwrap_or(fc_chan_idx!(flexicast)?
                    // );
                    let id = if let Some(idx) = mc_announce_id {
                        idx
                    } else {
                        fc_chan_idx!(flexicast)?
                    };
                    flexicast.mc_announce_data[id].fc_channel_secret =
                        Some(secret.to_owned());
                    flexicast.mc_announce_data[id].fc_channel_algo = Some(algo);
                    flexicast.fc_path_id = Some(fc_path_id);

                    Ok(())
                },
                _ => Err(Error::Flexicast(FcError::McInvalidRole(
                    flexicast.mc_role,
                ))),
            }
        } else {
            Err(Error::Flexicast(FcError::McDisabled))
        }
    }

    fn fc_set_announce_data(
        &mut self, mc_announce_data: &McAnnounceData,
    ) -> Result<()> {
        if self.is_server && !self.local_transport_params.flexicast_support {
            return Err(Error::Flexicast(FcError::McDisabled));
        }

        if let Some(flexicast) = self.flexicast.as_mut() {
            flexicast.mc_announce_data.push(mc_announce_data.clone());

            // Create the reliable structure on the flexicast flow.
            if let McRole::ServerFlexicast = flexicast.mc_role {
                if matches!(flexicast.fc_reliable, ReliableFc::Undefined) {
                    flexicast.fc_reliable = ReliableFc::FcFlow(RFcSource::new());
                }
            }
        } else {
            // Flexicast structure does not exist yet.
            let mc_role = if self.is_server {
                McRole::ServerUnicast(McClientStatus::Unaware)
            } else {
                McRole::Client(McClientStatus::AwareUnjoined)
            };
            let mut mc_data_cloned = mc_announce_data.clone();
            mc_data_cloned.is_processed = !self.is_server;

            let fc_reliable = if self.is_server {
                ReliableFc::UcPath(RFcUcPath::default())
            } else {
                ReliableFc::Receiver(RFcRecv::new(mc_data_cloned.fc_ack_delay))
            };

            // Add Flexicast Forward Erasure Correction state for the unicast path
            // if FEC is enabled on the receiver.
            let fc_fec =
                if self.peer_transport_params().is_some_and(|tp| tp.recv_fec)
                    && matches!(mc_role, McRole::ServerUnicast(_))
                {
                    fec::FcFec::UcPath(fec::FcFecUcPath::default())
                } else {
                    fec::FcFec::Undefined
                };

            self.flexicast = Some(FlexicastAttributes {
                mc_role,
                mc_announce_data: vec![mc_data_cloned],
                fc_reliable,
                fc_fec,
                fc_uses_lkh: self.local_transport_params.lkh_support,
                ..Default::default()
            });
        }

        Ok(())
    }

    fn fc_has_control_data(&self, _send_pid: usize) -> bool {
        if let Some(flexicast) = self.flexicast.as_ref() {
            return self.fc_should_send_fc_announce().is_some()
                || flexicast.should_send_fc_state()
                || flexicast.should_send_fc_key()
                || flexicast.fc_use_nack_and_should_send_positive()
                || (flexicast.fc_uses_lkh
                    && !flexicast.lkh_keys_to_send.is_empty());
        }
        false
    }

    fn mc_join_channel(
        &mut self, _leave_on_timeout: bool, fc_chan_id: Option<&[u8]>,
    ) -> Result<McClientStatus> {
        let flexicast = match self.flexicast.as_mut() {
            None => return Err(Error::Flexicast(FcError::McDisabled)),
            Some(flexicast) => match flexicast.mc_role {
                McRole::Client(McClientStatus::AwareUnjoined) => flexicast,
                McRole::Client(McClientStatus::Leaving(_)) => flexicast, /* Client attempting to change the channel. */
                _ => {
                    return Err(Error::Flexicast(FcError::McInvalidRole(
                        flexicast.mc_role,
                    )))
                },
            },
        };

        // Specify the flexicast channel ID that the client joins.
        flexicast.fc_chan_id = Some(if let Some(chan_id) = fc_chan_id {
            // Find index by flexicast channel ID.
            let id = flexicast
                .mc_announce_data
                .iter()
                .position(|announce| announce.channel_id == chan_id)
                .ok_or(Error::Flexicast(FcError::McAnnounce))?;
            (chan_id.to_owned(), id)
        } else {
            (flexicast.mc_announce_data[0].channel_id.clone(), 0)
        });
        // Create the reliability structure on the receiver.
        flexicast.fc_reliable = ReliableFc::Receiver(RFcRecv::new(
            flexicast
                .get_mc_announce_data_active()
                .unwrap()
                .fc_ack_delay,
        ));

        let new_status =
            flexicast.update_client_state(FcClientAction::Join, None)?;

        // Create the FEC decoder if this receiver enabled the extension locally.
        if self.local_transport_params.recv_fec {
            self.fec_decoder = Some(FecDecoder::new());
        }

        Ok(new_status)
    }

    fn mc_leave_channel(&mut self) -> Result<McClientStatus> {
        let flexicast = match self.flexicast.as_mut() {
            None => return Err(Error::Flexicast(FcError::McDisabled)),
            Some(flexicast) => match flexicast.mc_role {
                McRole::Client(McClientStatus::ListenMcPath(_)) => flexicast,
                McRole::ServerUnicast(McClientStatus::ListenMcPath(_)) => {
                    flexicast
                },
                _ => {
                    return Err(Error::Flexicast(FcError::McInvalidRole(
                        flexicast.mc_role,
                    )))
                },
            },
        };
        let leaving_action_from = if self.is_server {
            LEAVE_FROM_SERVER
        } else {
            LEAVE_FROM_CLIENT
        };

        flexicast
            .update_client_state(FcClientAction::Leave, Some(leaving_action_from))
    }

    fn is_mc_path(&self, space_id: u64) -> bool {
        if let Some(flexicast) = self.flexicast.as_ref() {
            if let Some(mc_id) = flexicast.get_fc_path_id() {
                return space_id == mc_id;
            }
        }
        false
    }

    fn add_mc_cid(&mut self, cid: &ConnectionId) -> Result<()> {
        if let Some(flexicast) = self.flexicast.as_ref() {
            if !matches!(
                flexicast.mc_role,
                McRole::Client(_) | McRole::ServerUnicast(_)
            ) {
                return Err(Error::Flexicast(FcError::McInvalidRole(
                    flexicast.mc_role,
                )));
            }
        }

        // Add the connection ID for the client without advertising it to the
        // unicast server.
        let mut reset_token = [0; 16];
        rand::rand_bytes(&mut reset_token);
        let reset_token = u128::from_be_bytes(reset_token);
        self.new_scid_on_path(1, cid, reset_token, true)?;

        Ok(())
    }

    fn create_mc_path(
        &mut self, client_addr: SocketAddr, server_addr: SocketAddr,
        to_uc_server: bool,
    ) -> Result<u64> {
        if let Some(flexicast) = self.flexicast.as_ref() {
            if matches!(flexicast.mc_role, McRole::ServerFlexicast) {
                return Err(Error::Flexicast(FcError::McInvalidRole(
                    flexicast.mc_role,
                )));
            }
        }

        let path_id = if to_uc_server {
            println!("In to_uc_server");
            let next_available = self.next_available_path_id()?;

            self.probe_path(next_available, client_addr, server_addr)
                .map(|(pid, _)| pid)
        } else {
            // Create a new path on the client.
            // If this is the server, temporarily give "client" behaviour to
            // create the path implicitly.
            let was_server = self.is_server;
            self.is_server = false;
            let next_available = self.next_available_path_id()?;

            let mut network_path = path::NetworkPath::new(
                client_addr,
                server_addr,
                self.path_challenge_recv_max_queue_len,
                MIN_CLIENT_INITIAL_LEN,
                false,
                &self.recovery_config,
            );
            println!("Created network path");
            network_path.verified_peer_address = true;
            self.paths.insert_network_path(network_path, None, false)?;
            println!("Added network path");
            let pid = match self.create_path_on_client(
                next_available,
                NetworkPathId(next_available as usize),
            ) {
                Ok(v) => v,
                Err(e) => {
                    self.is_server = was_server;
                    return Err(e);
                },
            };
            println!("Created mc path");
            match self.set_active(pid.0 as u64, true) {
                Ok(()) => (),
                Err(e) => {
                    self.is_server = was_server;
                    return Err(e);
                },
            }
            println!("Path set as active");
            let path = match self.paths.get_mut(pid) {
                Ok(v) => v,
                Err(e) => {
                    self.is_server = was_server;
                    return Err(e);
                },
            };

            self.is_server = was_server;

            Ok(path.path_id())
        }?;

        let pid = self.paths.pid_from_path_id(path_id).unwrap();
        let path = self.paths.get_mut(pid)?;

        // Add the first packet number of interest for the new path if possible.
        if let Some(flexicast) = self.flexicast.as_ref() {
            println!("Doing some flex kst ");
            path.recovery
                .init_fc_recovery_state(flexicast.get_mc_role());
            if let Some(pn) = flexicast
                .fc_reliable
                .server()
                .map(|rfc| rfc.fc_highest_pn.unwrap_or(0))
            {
                self.pkt_num_spaces
                    .spaces
                    .get_mut_or_create(Epoch::Application, path_id)
                    .recv_pkt_need_ack
                    .insert(pn..pn + 1);
            }
        }
        println!("End create mc path");
        Ok(path_id)
    }

    fn get_flexicast_attributes(&self) -> Option<&FlexicastAttributes> {
        self.flexicast.as_ref()
    }

    fn uc_to_fc_control(
        &mut self, fc_flow: &mut Connection, now: time::Instant,
    ) -> Result<()> {
        // Sanity check.
        if let Some(flexicast) = fc_flow.flexicast.as_ref() {
            if !matches!(flexicast.mc_role, McRole::ServerFlexicast) {
                return Err(Error::Flexicast(FcError::McInvalidRole(
                    McRole::ServerFlexicast,
                )));
            }
        } else {
            return Err(Error::Flexicast(FcError::McDisabled));
        }

        // First packet that the receiver must receive.
        // This value will be forwarded in the FC_KEY frame.
        if let Some(rfc) = self
            .flexicast
            .as_mut()
            .and_then(|fc| fc.fc_reliable.server_mut())
        {
            let fc_pn: Option<(u64, u64)> = fc_flow.fc_next_and_first_pn();
            if rfc.fc_highest_pn.is_none() {
                rfc.fc_highest_pn = fc_pn.map(|(highest, _)| highest);
            }

            // Notify the flexicast flow that there is a new receiver.
            if let Some(rfc_source) = fc_flow.get_mc_ack_mut() {
                if !rfc.notified_fc_source {
                    rfc_source.new_recv(fc_pn.unwrap_or((0, 0)).0, false);

                    rfc.notified_fc_source = true;
                }
            }

            self.fc_set_first_pn(fc_pn.map(|(next, _)| next));
        }

        // The unicast path notifies the flexicast flow through the McAck the new
        // packets that have been acked by the receiver. Also notifies the
        // streams.
        if let (Some(rfc), Some(mc_ack)) = (
            self.flexicast
                .as_mut()
                .and_then(|fc| fc.fc_reliable.server_mut()),
            fc_flow.get_mc_ack_mut(),
        ) {
            // Value consumed.
            let new_ack_pn = rfc.mc_ack.full_ack();
            if new_ack_pn.as_ref().is_some_and(|rs| rs.len() > 0) {
                mc_ack.on_ack_received(new_ack_pn.as_ref().unwrap());

                // Maybe now the flexicast flow can process packets.
                if let Some(fully_acked) = mc_ack.full_ack() {
                    fc_flow.fc_on_ack_received(&fully_acked, now)?;
                }
            }

            // Notify for the pieces of stream that have been correctly received.
            if let Some(mut ack_stream_pieces) = rfc.mc_ack.acked_stream_off() {
                let mc_ack = fc_flow.get_mc_ack_mut().unwrap();
                for (stream_id, ranges) in ack_stream_pieces.drain(..) {
                    for range in ranges.iter() {
                        mc_ack.on_stream_ack_received(
                            stream_id,
                            range.start,
                            range.end - range.start,
                        );
                    }
                }

                // Maybe now we can also fully acknowledge some streams on the
                // flexicast flow.
                if let Some(mut fully_acked_stream_pieces) =
                    mc_ack.acked_stream_off()
                {
                    for (stream_id, ranges) in fully_acked_stream_pieces.drain(..)
                    {
                        for range in ranges.iter() {
                            fc_flow.fc_on_stream_ack_received(
                                stream_id,
                                range.start,
                                range.end - range.start,
                            )?;
                        }
                    }
                }
            }
        }

        // The flexicast flow notifies the unicast path the packets that have been
        // sent.
        let _ = fc_flow.fc_notify_sent_packets(self);

        // The unicast path asks the flexicast flow if some streams have a fin
        // offset. This happens when the flexicast flow collected some
        // streams.
        fc_flow.fc_notify_collected_streams(self);

        Ok(())
    }
}

impl Connection {
    /// Returns whether flexicast is enabled and the path ID corresponds to the
    /// flexicast flow.
    pub fn is_flexicast_flow(&self, path_id: u64) -> bool {
        self.flexicast
            .as_ref()
            .is_some_and(|fc| fc.fc_path_id.is_some_and(|fcid| fcid == path_id))
    }

    /// Returns the highest packet number received and acknowledged on the
    /// flexicast flow.
    pub fn fc_get_highest_ack_pn(&self) -> Option<u64> {
        self.flexicast.as_ref().and_then(|fc| fc.fc_highest_ack_pn)
    }

    /// Returns the next packet number that will be sent on the flexicast flow,
    /// and the lowest packet number still in the sending queue.
    pub fn fc_next_and_first_pn(&self) -> Option<(u64, u64)> {
        let fc_path_id = self.flexicast.as_ref().and_then(|fc| fc.fc_path_id)?;

        let next_pn = self.ids.get_next_pkt_num(fc_path_id).ok()?;

        let pid = self.paths.pid_from_path_id(fc_path_id)?;
        let path = self.paths.get(pid).ok()?;
        let first_pn = path.recovery.get_lowest_pn_app_epoch()?;

        Some((next_pn, first_pn))
    }

    /// The flexicast flow notifies the unicast path the new packets sents.
    fn fc_notify_sent_packets(&mut self, uc: &mut Connection) -> Result<()> {
        let fca = fca!(uc)?;
        let highest_pn = fca
            .fc_reliable
            .server()
            .ok_or(Error::Flexicast(FcError::McReliableDisabled))?
            .fc_highest_pn;

        let sent = Arc::new(self.fc_get_sent_pkt(highest_pn)?);
        let fc_id = fc_chan_idx!(fca)?;
        uc.fc_on_new_pkt_sent(fc_id, sent)
    }

    /// Returns whether bytes are in flight on the flexicast path.
    pub fn fc_bytes_in_flight(&self) -> Option<bool> {
        fc_chan_idx!(self.flexicast.as_ref()?).ok().and_then(|idx| {
            self.paths
                .get(InternalPathId(idx))
                .ok()
                .map(|p| p.recovery.bytes_in_flight())
        })
    }

    /// Sets the path ID of the flexicast flow.
    pub fn fc_set_path_id(&mut self, path_id: Option<u64>) -> Result<()> {
        if let Some(flexicast) = self.flexicast.as_mut() {
            flexicast.fc_path_id = path_id;
            Ok(())
        } else {
            Err(Error::Flexicast(FcError::McDisabled))
        }
    }

    /// Returns whether the receiving side of the stream is finished and the
    /// stream can be read until its end sequentially now. This means that
    /// all the data of the stream can be read until its end without any loss.
    #[inline]
    pub fn stream_fully_readable(&self, stream_id: u64) -> bool {
        let stream = match self.streams.get(stream_id) {
            Some(v) => v,

            None => return true,
        };

        stream.recv.is_fully_readable()
    }

    /// Returns when the next flexicast-related timeout will occur.
    pub(crate) fn fc_timeout_instant(&self) -> Option<time::Instant> {
        let flexicast = self.flexicast.as_ref()?;

        match flexicast.mc_role {
            McRole::Client(_) => {
                let nack = fc_nack_recv!(self)?;
                nack.fc_next_timeout()
            },

            _ => None,
        }
    }

    /// Processes a flexicast timeout event.
    ///
    /// If no timeout has occurred it does nothing.
    pub(crate) fn fc_on_timeout(&mut self, now: time::Instant) -> Result<()> {
        if let Some(flexicast) = self.flexicast.as_ref() {
            if self.fc_timeout_instant() <= Some(now) {
                #[allow(clippy::single_match)]
                match flexicast.mc_role {
                    McRole::Client(_) => {
                        if let Some(nack) = fc_nack_recv_mut!(self) {
                            nack.fc_on_timeout(now);
                        }
                    },

                    _ => (),
                }
            }
        }

        Ok(())
    }

    /// Returns whether a PATH_ACK frame must be sent to acknowledge data from
    /// the flexicast flow. This function returns true if:
    /// 1) This is a receiver listening to the flexicast flow;
    /// 2) Either:
    ///     - The flexicast flow uses positive acknowledgment or
    ///     - The flexicast flow uses negative acknowledgments and the receiver
    ///       must send a NACK.
    pub fn fc_should_send_path_ack(&mut self, now: time::Instant) -> bool {
        self.flexicast.as_mut().is_some_and(|fc| {
            matches!(
                fc.get_mc_role(),
                McRole::Client(McClientStatus::ListenMcPath(true))
            ) && fc
                .fc_reliable
                .client_mut()
                .map(|c| c.nack_mut())
                .map(|nack| nack.fc_should_send_ack(now))
                .unwrap_or(true)
        })
    }

    /// Returns the next packet number to send on the specified path on the
    /// Application epoch.
    pub fn fc_get_next_pkt_num(&self, pid: u64) -> Result<u64> {
        self.ids.get_next_pkt_num(pid)
    }

    /// Falls back on unicast delivery (depending on `do_fall_back`).
    /// If the value is `true`, falls back on unicast.
    /// If the value is `galse`, enters back on flexicast.
    /// This function does nothing if this is not a unicast path instance.
    pub fn fc_fall_back_unicast(&mut self, do_fall_back: bool) {
        if let Some(fc) = self.flexicast.as_mut() {
            match (fc.get_mc_role(), do_fall_back) {
                (
                    McRole::ServerUnicast(McClientStatus::ListenMcPath(true)),
                    true,
                ) => {
                    fc.mc_role =
                        McRole::ServerUnicast(McClientStatus::UcFallBack);
                },
                (McRole::ServerUnicast(McClientStatus::UcFallBack), false) => {
                    fc.mc_role =
                        McRole::ServerUnicast(McClientStatus::ListenMcPath(true));
                },
                _ => (),
            }
        }
    }
    /// Add a key update to queue of key update to be sent
    pub fn schedule_lkh_update(&mut self, raw: FCKeyUpdate) {
        if let Some(fc) = self.flexicast.as_mut() {
            fc.lkh_keys_to_send.push_back(raw);
            println!("[LKH] {} Adding key to the schedule", fc.get_mc_role());
            println!("[LKH] current schedule : {:?}", fc.lkh_keys_to_send);
        } else {
            println!("Flexicast does not yet exist");
        }
    }

    fn update_session_key(
        &mut self, algo: Algorithm, key: Vec<u8>, first_pn: u64,
    ) -> Result<()> {
        let path_id = self
            .flexicast
            .as_ref()
            .unwrap()
            .get_fc_path_id()
            .ok_or(Error::InvalidState)?;
        let new_seal = Seal::from_secret(algo, &key)?;
        let new_open = Open::from_secret(algo, &key)?;

        //Il faudrait checker l'epoch
        let space = self.pkt_num_spaces.crypto.get_mut(Epoch::Application);
        let open_prev = space
            .crypto_os
            .replace_open(path_id, new_open)
            .ok_or(Error::CryptoFail)?;
        space.crypto_os.replace_seal(path_id, new_seal);

        let key_update = KeyUpdate {
            crypto_open: open_prev,
            pn_on_update: first_pn,
            timer: Instant::now()
                .checked_add(Duration::new(60, 0))
                .ok_or(Error::CryptoFail)?,
            update_acked: false,
        };

        space.key_update = Some(key_update);
        self.key_phase = !self.key_phase;

        Ok(())
    }
    pub fn update_session_key_now(
        &mut self, packet: KeyUpdatePacket,
    ) -> Result<()> {
        if let Some(fc) = &self.flexicast {
            let path_id = self
                .flexicast
                .as_ref()
                .unwrap()
                .get_fc_path_id()
                .ok_or(Error::InvalidState)?;
            let key = packet.new_key;
            let algo = fc.get_decryption_key_algo();
            let new_seal = Seal::from_secret(algo, &key)?;
            let new_open = Open::from_secret(algo, &key)?;
            let space = self.pkt_num_spaces.crypto.get_mut(Epoch::Application);
            space
                .crypto_os
                .replace_open(path_id, new_open)
                .ok_or(Error::Flexicast(FcError::McInvalidCrypto))?;
            space
                .crypto_os
                .replace_seal(path_id, new_seal)
                .ok_or(Error::Flexicast(FcError::McInvalidCrypto))?;
            self.key_phase = !self.key_phase;
            println!("Replaced the crypto");
        }
        Ok(())
    }
}

/// Extension of a RangeSet to support missing ranges.
pub trait MissingRangeSet {
    /// Returns a RangeSet containing the numbers missing in the RangeSet.
    fn get_missing(&self) -> Self;

    /// Returns the number of elements in the RangeSet.
    fn nb_elements(&self) -> usize;

    /// Returns a RangeSet containing the number missing in the RangeSet up to.
    fn get_missing_up_to(&self, pn: u64) -> Self;
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

    fn get_missing_up_to(&self, pn: u64) -> Self {
        let mut new_range = self.clone();
        new_range.insert(pn..pn + 1);

        new_range.get_missing()
    }
}

#[doc(hidden)]
pub struct McPathInfo<'a> {
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub cid: ConnectionId<'a>,
}

/// Represents a source flexicast channel.
/// A flexicast channel is like a unicast connection without the handshake
/// with the clients because it has no explicit set of connected client.
pub struct FlexicastChannelSource {
    /// Connection representing the channel.
    pub channel: Connection,

    /// Back-up connection for the flexicast channel setup.
    /// This is used because the source has no direct connection with
    /// any receiver.
    pub client_backup: Connection,

    /// Master secret used to derive the symmetric key used to encrypt
    /// the traffic with the clients.
    pub master_secret: Vec<u8>,

    /// Encryption algorithm.
    pub algo: Algorithm,

    /// Connection ID that the clients use for the flexicast path.
    /// This tuple contains the Connection Id and the reset token.
    pub mc_path_conn_id: (ConnectionId<'static>, u128),

    /// Address used to trigger sending packets on the flexicast path.
    pub mc_path_peer: SocketAddr,

    /// Flexicast send address.
    pub mc_send_addr: SocketAddr,
    // LKH ?
    //pub fc_lkh : Option<LKHPlus>
}

impl FlexicastChannelSource {
    #[allow(clippy::too_many_arguments)]
    /// Creates a new source flexicast channel.
    pub fn new_with_tls(
        mc_path_info: McPathInfo, config_server: &mut Config,
        config_client: &mut Config, peer: SocketAddr, keylog_filename: &str,
        fc_config: &FcConfig,
    ) -> Result<Self> {
        let mut scid = [0; 16];
        rand::rand_bytes(&mut scid[..]);
        let scid = ConnectionId::from_ref(&scid);

        // Add the keylog file.
        let key_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(keylog_filename)
            .map_err(|_| Error::Flexicast(FcError::McInvalidSymKey))?;
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
            FlexicastChannelSource::get_exporter_secret(keylog_filename)?;

        // Get the encryption algorithm.
        let encryption_algo =
            conn_server.handshake.cipher().ok_or(Error::CryptoFail)?;

        conn_server.flexicast = Some(FlexicastAttributes {
            mc_role: McRole::ServerFlexicast,
            ..Default::default()
        });

        let mut reset_token = [0; 16];
        rand_bytes(&mut reset_token);
        let reset_token = u128::from_be_bytes(reset_token);

        // Add a new Connection ID for the flexicast path.
        let channel_id = ConnectionId::from_ref(mc_path_info.cid.as_ref());

        // Sets the channel ID to the path ID 1.
        // This is negotiated during connection establishment.
        let path_id = 1;
        conn_server.new_scid_on_path(path_id, &channel_id, reset_token, true)?;
        conn_client.new_scid_on_path(path_id, &channel_id, reset_token, true)?;
        Self::advance(&mut conn_server, &mut conn_client)?;

        // Probe the new path.
        conn_client.probe_path(1, mc_path_info.local, mc_path_info.peer)?;
        let pid_c2s_1 = conn_client
            .paths
            .pid_from_path_id(path_id)
            .expect("no such path");
        let _mc_path_client = conn_client.paths.get_mut(pid_c2s_1)?;
        Self::advance(&mut conn_server, &mut conn_client)?;
        let pid_s2c_1 = conn_server
            .paths
            .pid_from_path_id(path_id)
            .expect("no such path");
        let _mc_path_server = conn_server.paths.get_mut(pid_s2c_1)?;

        conn_server.flexicast.as_mut().unwrap().fc_path_id = Some(path_id);

        // Set the new path active.
        conn_client.set_active(path_id, true)?;
        conn_server.set_active(path_id, true)?;
        Self::advance(&mut conn_server, &mut conn_client)?;

        conn_client.flexicast = Some(FlexicastAttributes {
            mc_role: McRole::Client(McClientStatus::Unspecified),
            ..FlexicastAttributes::default()
        });
        conn_client.flexicast.as_mut().unwrap().fc_path_id = Some(path_id);

        // Remove packets that need acknowledgment from the flexicast source.
        conn_server
            .pkt_num_spaces
            .spaces
            .get_mut(Epoch::Application, 1)
            .unwrap()
            .recv_pkt_need_ack = RangeSet::default();

        conn_client
            .pkt_num_spaces
            .spaces
            .get_mut(Epoch::Application, 1)
            .unwrap()
            .recv_pkt_need_ack = RangeSet::default();

        // Set state of the recovery receiver.
        conn_server.fc_set_recovery_state()?;

        // Set the state for FEC.
        conn_server.flexicast.as_mut().unwrap().fc_fec =
            fec::FcFec::FcFlow(fc_config.fec_scheduler.into());
        if fc_config.fec {
            conn_server.fec_encoder =
                Some(FecEncoder::new(fc_config.fec_scheduler.into()));
        }

        //let lkh = LKHPlus::new(encryption_algo.key_len(), send_group, 32);

        let cid = channel_id.clone().into_owned();
        Ok(Self {
            channel: conn_server,
            client_backup: conn_client,
            master_secret: exporter_secret,
            algo: encryption_algo,
            mc_path_conn_id: (cid, reset_token),
            mc_path_peer: mc_path_info.peer,
            mc_send_addr: peer,
            //fc_lkh:Some(lkh)
        })
    }

    /// Copy of the Pipe::handshake method. Used for the setup
    /// to create the source flexicast channel.
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
    /// to create the source flexicast channel.
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
            .map_err(|_| Error::Flexicast(FcError::McInvalidSymKey))?;
        let mut reader = std::io::BufReader::new(fd);
        let mut in_string = String::new();
        for _ in 0..3 {
            reader
                .read_line(&mut in_string)
                .map_err(|_| Error::Flexicast(FcError::McInvalidSymKey))?;
            in_string = String::new();
        }
        reader
            .read_line(&mut in_string)
            .map_err(|_| Error::Flexicast(FcError::McInvalidSymKey))?; // This is very ugly, erk
        let mut splited = in_string.split(' ');
        let a = splited
            .next_back()
            .ok_or(Error::Flexicast(FcError::McInvalidSymKey))?;
        (0..a.len() - 1)
            .step_by(2)
            .map(|i| {
                a.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
                    .ok_or(Error::Flexicast(FcError::McInvalidSymKey))
            })
            .collect()
    }

    /// Flexicast-version of the [`send`] method of the crate.
    /// It sends on the flexicast path always.
    /// Internally, it uses [`send_on_path`] with the flexicast addresses
    /// specified during the source flexicast channel configuration.
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
    /// [`FlexicastAttributes::mc_auth_type`].
    ///
    /// MC-TODO: only Ed25519 is used at the moment.
    /// The last bytes of the packet contain the signature.
    pub fn mc_send(&mut self, buf: &mut [u8]) -> Result<(usize, SendInfo)> {
        self.channel.send_on_path(
            buf,
            Some(1),
            Some(self.mc_path_peer),
            Some(self.mc_path_peer),
        )
    }
}

#[doc(hidden)]
#[derive(Clone, Debug)]
/// Flexicast configuration.
pub struct FcConfig {
    pub fc_tp: bool,
    /// Flexicast LKH transport parameter
    pub fc_lkh_tp: bool,

    pub mc_announce_data: Vec<McAnnounceData>,

    pub mc_announce_to_join: usize,

    pub probe_mc_path: bool,

    pub max_data: u64,

    pub max_stream_data: u64,

    pub fc_ack_delay: FcAckDelayStrategy,

    pub fec: bool,

    pub fec_scheduler: FecSchedulerAlgorithm,

    pub src_addr: SocketAddr,

    pub mc_addr: SocketAddr,

    pub crt_path: String,

    pub fc_cca: FcFlowCwnd,

    pub ack_delay_latency: time::Duration,
}

impl Default for FcConfig {
    fn default() -> Self {
        let mut fc_config = Self {
            mc_announce_data: vec![testing::get_test_mc_announce_data()],
            mc_announce_to_join: 0,
            probe_mc_path: true,
            fc_tp: true,
            fc_lkh_tp: false,
            max_data: 5_000_000_000,
            max_stream_data: 1_000_000_000,
            fc_ack_delay: FcAckDelayStrategy::Immediate,
            fec: false,
            fec_scheduler: FecSchedulerAlgorithm::NoRedundancy,
            src_addr: "127.0.0.1:4433".parse().unwrap(),
            mc_addr: "239.239.239.35:4434".parse().unwrap(),
            crt_path: ".".to_string(),
            fc_cca: FcFlowCwnd::CCA(CongestionControlAlgorithm::CUBIC),
            ack_delay_latency: time::Duration::from_millis(100),
        };
        fc_config.mc_announce_data[0].probe_path = fc_config.probe_mc_path;
        fc_config.mc_announce_data[0].fc_ack_delay = 0;

        fc_config
    }
}

/// Provide structures and functions to help testing the flexicast extension of
/// QUIC.
pub mod testing {
    use rand;
    use std::collections::HashSet;
    use std::ops::Range;

    use crate::testing;
    use crate::testing::Pipe;
    use crate::Config;

    use super::*;

    #[doc(hidden)]
    pub const CLIENT_AUTH_ADDR: &str = "127.0.0.1:5679";

    /// Flexicast extension of [`crate::testing::Pipe`].
    ///
    /// Contains a Pipe for each unicast connection and flexicast source
    /// channel. Performs the flexicast extension negociation for each client
    /// in the pipe.
    pub struct FlexicastPipe {
        /// All unicast connections between the clients and the server.
        pub unicast_pipes: Vec<(Pipe, SocketAddr, SocketAddr)>,

        /// Flexicast source channel.
        pub mc_channel: FlexicastChannelSource,

        /// Flexicast channel infirmation (MC_ANNOUNCE data).
        pub mc_announce_data: McAnnounceData,
    }

    impl FlexicastPipe {
        /// Generates a new flexicast pipe with already defined configuration.
        pub fn new(
            nb_clients: usize, keylog_filename: &str, fc_config: &mut FcConfig,
        ) -> Result<FlexicastPipe> {
            let probe_mc_path = fc_config.probe_mc_path;
            fc_config
                .mc_announce_data
                .iter_mut()
                .for_each(|ad| ad.probe_path = probe_mc_path);
            println!("Before mcannonce");
            Self::new_from_mc_announce_data(
                nb_clients,
                keylog_filename,
                fc_config,
            )
        }

        /// Generates a new flexicast pipe with already defined configuration
        /// and Mc announce data.
        pub fn new_from_mc_announce_data(
            nb_clients: usize, keylog_filename: &str, fc_config: &mut FcConfig,
        ) -> Result<FlexicastPipe> {
            let mut client_config = get_test_mc_config(true, fc_config);
            let mut server_config = get_test_mc_config(true, fc_config);

            server_config.set_send_fec(fc_config.fec);
            client_config.set_recv_fec(fc_config.fec);

            // Flexicast path.
            let mut mc_channel = get_test_mc_channel_source(
                &mut server_config,
                &mut client_config,
                keylog_filename,
                fc_config,
            )
            .unwrap();

            let mc_announce_data =
                &mut fc_config.mc_announce_data[fc_config.mc_announce_to_join];

            mc_channel.channel.fc_set_announce_data(mc_announce_data)?;

            // Copy the channel ID derived from the flexicast channel.
            mc_announce_data.channel_id =
                mc_channel.mc_path_conn_id.0.as_ref().to_vec();

            mc_channel
                .channel
                .flexicast
                .as_mut()
                .unwrap()
                .mc_announce_data
                .push(mc_announce_data.clone());
            println!("Before setup");
            let pipes: Vec<_> = (0..nb_clients)
                .flat_map(|i| {
                    println!("Setting up {i}");
                    FlexicastPipe::setup_client(&mut mc_channel, fc_config)
                })
                .collect();
            println!("After setup");
            if pipes.len() != nb_clients {
                return Err(Error::Flexicast(FcError::McPipe));
            }

            Ok(FlexicastPipe {
                unicast_pipes: pipes,
                mc_channel,
                mc_announce_data: fc_config.mc_announce_data
                    [fc_config.mc_announce_to_join]
                    .clone(),
            })
        }

        /// The flexicast source sends a single packet using the buffer given as
        /// argument. Returns the number of bytes sent by the source and writes
        /// the packet content in the input buffer.
        ///
        /// `client_loss` is a RangeSet containing the indexes of clients that
        /// DO NOT receive the packet. `None` if all clients receive the packet.
        pub fn source_send_single_from_buf(
            &mut self, client_loss: Option<&RangeSet>, mc_buf: &mut [u8],
        ) -> Result<usize> {
            let (written, _) = self.mc_channel.mc_send(&mut mc_buf[..])?;

            // This is not optimal but it works...
            let client_loss = if let Some(client_loss) = client_loss {
                client_loss.flatten().collect()
            } else {
                HashSet::new()
            };
            let idx_client_receive =
                (0..self.unicast_pipes.len()).filter(|&idx| {
                    !client_loss.contains(&(u64::try_from(idx).unwrap()))
                });

            for client_idx in idx_client_receive {
                let mut recv_buf = mc_buf.to_owned();
                let (pipe, client_addr, server_addr) =
                    self.unicast_pipes.get_mut(client_idx).unwrap();

                let recv_info = RecvInfo {
                    from: *server_addr,
                    to: *client_addr,
                    from_mc: true,
                };

                let _res =
                    pipe.client.recv(&mut recv_buf[..written], recv_info)?;
            }

            Ok(written)
        }

        /// Creates a new client and initiate the handshake to use flexicast.
        pub fn setup_client(
            mc_channel: &mut FlexicastChannelSource, fc_config: &FcConfig,
        ) -> Option<(Pipe, SocketAddr, SocketAddr)> {
            let mut config = get_test_mc_config(true, fc_config);
            let mut pipe =
                Pipe::with_config_and_scid_lengths(&mut config, 16, 16).ok()?;
            pipe.handshake().ok()?;
            println!("After handshake");
            for mc_announce_data in fc_config.mc_announce_data.iter() {
                pipe.server.fc_set_announce_data(mc_announce_data).unwrap();
            }
            let flexicast = pipe.server.flexicast.as_mut().unwrap();
            flexicast.mc_announce_data[fc_config.mc_announce_to_join]
                .fc_channel_secret = Some(mc_channel.master_secret.clone());

            // The server adds the connection IDs of the flexicast
            // channel.
            println!("After secret");
            let mut scid = [0; 16];
            rand::rand_bytes(&mut scid[..]);

            let scid = ConnectionId::from_ref(&scid);
            let mut reset_token = [0; 16];
            rand::rand_bytes(&mut reset_token[..]);
            let reset_token = u128::from_be_bytes(reset_token);
            pipe.server
                .new_scid_on_path(1, &scid, reset_token, true)
                .unwrap();

            pipe.advance().unwrap();
            println!("After token");
            // Client joins the flexicast channel.
            let chan_id =
                pipe.client.flexicast.as_ref().unwrap().mc_announce_data
                    [fc_config.mc_announce_to_join]
                    .channel_id
                    .to_owned();
            pipe.client.mc_join_channel(true, Some(&chan_id)).unwrap();
            pipe.advance().unwrap();
            println!("After join");
            pipe.server
                .uc_to_fc_control(&mut mc_channel.channel, time::Instant::now())
                .unwrap();

            // The server gives the master key.
            pipe.advance().unwrap();
            println!("After the mc key");
            let scid = ConnectionId::from_ref(
                &fc_config.mc_announce_data[fc_config.mc_announce_to_join]
                    .channel_id,
            );
            pipe.client.add_mc_cid(&scid).unwrap();
            assert_eq!(pipe.advance(), Ok(()));
            println!("After  cid ?");

            let server_addr = testing::Pipe::server_addr();
            let client_addr_2 = "127.0.0.1:5678".parse().unwrap();

            pipe.client
                .create_mc_path(
                    client_addr_2,
                    server_addr,
                    fc_config.probe_mc_path,
                )
                .unwrap();
            println!("Successful create_mc_path");
            let _pid_c2s_1 =
                pipe.client.paths.pid_from_path_id(1).expect("no such path");

            pipe.client.flexicast.as_mut().unwrap().set_fc_path_id(1);
            println!("before computing set path_id");
            assert_eq!(pipe.advance(), Ok(()));
            println!("After mc state");

            Some((pipe, client_addr_2, server_addr))
        }

        /// The flexicast source sends a single packet.
        /// Returns the number of bytes sent by the source.
        ///
        /// `client_loss` is a RangeSet containing the indexes of clients that
        /// DO NOT receive the packet. `None` if all clients receive the packet.
        pub fn source_send_single(
            &mut self, client_loss: Option<&RangeSet>,
        ) -> Result<usize> {
            let mut mc_buf = [0u8; 1500];
            self.source_send_single_from_buf(client_loss, &mut mc_buf)
        }

        /// The flexicast source sends a single small stream of 300 bytes to fit
        /// in a single QUIC packet.
        /// Calls [`FlexicastPipe::source_send_single`].
        ///
        /// `client_loss` is a RangeSet containing the indexes of clients that
        /// do not receive the packet. `None` if all clients receive the packet.
        pub fn source_send_single_stream(
            &mut self, send: bool, client_loss: Option<&RangeSet>, stream_id: u64,
        ) -> Result<usize> {
            let mut mc_buf = [0u8; 300];
            rand::rand_bytes(&mut mc_buf[..]);
            self.mc_channel
                .channel
                .stream_send(stream_id, &mc_buf, true)?;

            if send {
                self.source_send_single(client_loss)
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
                        from_mc: false,
                    };
                    pipe.server.recv(&mut buf[..written], recv_info)?;
                }
            }

            Ok(())
        }

        /// The unicast server sends flexicast feedback control from the client
        /// to the flexicast source.
        pub fn server_control_to_mc_source(
            &mut self, now: time::Instant,
        ) -> Result<()> {
            let mc_channel = &mut self.mc_channel.channel;
            let n = self.unicast_pipes.len();
            let uc_paths = self
                .unicast_pipes
                .iter_mut()
                .map(|(pipe, ..)| &mut pipe.server);
            mc_channel.fc_flow_uc_paths_control(uc_paths, now, Some(n))?;
            Ok(())
        }

        /// The unicast server specified by the index argument sends a single
        /// stream to its client.
        pub fn uc_server_send_single_stream(
            &mut self, stream_id: u64, pipe_idx: usize,
        ) -> Result<()> {
            let mut buf = [0u8; 300];
            rand::rand_bytes(&mut buf[..]);

            let pipe = &mut self.unicast_pipes.get_mut(pipe_idx).unwrap().0;
            pipe.server.stream_send(stream_id, &buf, true)?;
            pipe.advance()
        }
    }

    /// Simple config used for testing the flexicast extension only.
    pub fn get_test_mc_config(fc_enabled: bool, fc_config: &FcConfig) -> Config {
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
        populate_test_mc_config(&mut config, fc_enabled, fc_config);
        config
    }

    /// Populate a configuration with flexicast values.
    fn populate_test_mc_config(
        config: &mut Config, fc_enabled: bool, fc_config: &FcConfig,
    ) {
        config
            .set_application_protos(&[b"proto1", b"proto2"])
            .unwrap();
        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(fc_config.max_data);
        config.set_initial_max_stream_data_bidi_local(fc_config.max_stream_data);
        config.set_initial_max_stream_data_bidi_remote(fc_config.max_stream_data);
        config.set_initial_max_stream_data_uni(fc_config.max_stream_data);
        config.set_initial_max_streams_bidi(1_000_000_000);
        config.set_initial_max_streams_uni(1_000_000_000);
        config.set_active_connection_id_limit(2);
        config.verify_peer(false);
        config.set_initial_max_path_id(5);
        config.set_enable_flexicast(fc_enabled);
        config.set_cc_algorithm(CongestionControlAlgorithm::DISABLED);
        config.set_recv_fec(fc_config.fec);
    }

    /// Simple McAnnounceData for testing the flexicast extension only.
    pub fn get_test_mc_announce_data() -> McAnnounceData {
        McAnnounceData {
            channel_id: [0xff, 0xdd, 0xee, 0xaa, 0xbb, 0x33, 0x66].to_vec(),
            probe_path: false,
            is_ipv6_addr: false,
            source_ip: std::net::Ipv4Addr::new(127, 0, 0, 1).octets(),
            group_ip: std::net::Ipv4Addr::new(224, 0, 0, 1).octets(),
            udp_port: 7676,
            fc_ack_delay: 0,
            is_processed: false,
            fc_channel_algo: None,
            fc_channel_secret: None,
            fc_key_dict: HashMap::new(),
            fc_lkh_counters: HashMap::new(),
        }
    }

    /// Simple source flexicast channel for the tests.
    pub fn get_test_mc_channel_source(
        config_server: &mut Config, config_client: &mut Config,
        keylog_filename: &str, fc_config: &FcConfig,
    ) -> Result<FlexicastChannelSource> {
        // Set the disabled congestion control for the flexicast channel.
        // config_client.set_cc_algorithm(CongestionControlAlgorithm::DISABLED);
        // config_server.set_cc_algorithm(CongestionControlAlgorithm::DISABLED);
        let mut channel_id = [0; 16];
        rand::rand_bytes(&mut channel_id[..]);
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

        FlexicastChannelSource::new_with_tls(
            mc_path_info,
            config_server,
            config_client,
            to,
            keylog_filename,
            fc_config,
        )
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

    use crate::flexicast::reliable::FcUnicastRetransmission;
    use crate::flexicast::testing::get_test_mc_config;
    use crate::testing;

    use super::testing::FlexicastPipe;
    use super::*;

    #[test]
    /// The server adds MC_ANNOUNCE data and should send it to the client.
    /// Both added the flexicast extension in their transport parameters.
    /// The sharing of the transport parameters are already tested in lib.rs.
    fn mc_announce_data_init() {
        let fc_config = FcConfig {
            ..Default::default()
        };
        let mc_announce_data =
            &fc_config.mc_announce_data[fc_config.mc_announce_to_join];
        let mut config = get_test_mc_config(true, &fc_config);

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));

        assert!(pipe.server.flexicast.is_none());
        assert!(pipe.client.flexicast.is_none());
        assert_eq!(pipe.server.fc_should_send_fc_announce(), None);
        assert_eq!(pipe.client.fc_should_send_fc_announce(), None);

        assert!(pipe.server.fc_set_announce_data(&mc_announce_data).is_ok());

        assert!(pipe.server.flexicast.is_some());
        assert_eq!(
            pipe.server
                .flexicast
                .as_ref()
                .unwrap()
                .mc_announce_data
                .get(0)
                .unwrap(),
            mc_announce_data
        );

        assert_eq!(
            pipe.server.flexicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::Unaware)
        );
        assert_eq!(pipe.server.fc_should_send_fc_announce(), Some(0));
    }

    #[test]
    /// Exchange of the MC_ANNOUNCE data between the client and the server.
    /// The client receives the MC_ANNOUNCE.
    /// It creates a flexicast state on the client.
    fn mc_announce_data_exchange() {
        let mut fc_config = FcConfig {
            ..Default::default()
        };
        let mut config = get_test_mc_config(true, &fc_config);
        let mc_announce_data =
            &mut fc_config.mc_announce_data[fc_config.mc_announce_to_join];

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));
        pipe.server.fc_set_announce_data(&mc_announce_data).unwrap();

        assert_eq!(pipe.server.fc_should_send_fc_announce(), Some(0));
        assert_eq!(
            pipe.server.flexicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::Unaware)
        );
        assert_eq!(pipe.advance(), Ok(()));

        // MC_ANNOUNCE sent.
        // The client has the data, and the server should not send it anymore.
        assert_eq!(pipe.server.fc_should_send_fc_announce(), None);
        mc_announce_data.is_processed = true;
        // The reception created a FlexicastAttributes in for client.
        assert!(pipe.client.flexicast.is_some());
        assert_eq!(
            pipe.client
                .flexicast
                .as_ref()
                .unwrap()
                .mc_announce_data
                .get(0),
            Some(mc_announce_data).as_deref()
        );
        // The client has the role Client.
        assert_eq!(
            pipe.client.flexicast.as_ref().unwrap().mc_role,
            McRole::Client(McClientStatus::AwareUnjoined)
        );
        // The server updates the role of the client because now the frame is
        // sent.
        assert_eq!(
            pipe.server.flexicast.as_ref().unwrap().mc_role,
            McRole::ServerUnicast(McClientStatus::AwareUnjoined)
        );
    }

    #[test]
    fn test_mc_client_state_machine() {
        let mut flexicast = FlexicastAttributes {
            mc_role: McRole::Client(McClientStatus::Unaware),
            ..Default::default()
        };

        assert_eq!(
            flexicast.update_client_state(FcClientAction::Join, None),
            Ok(McClientStatus::Unaware),
        );

        assert_eq!(
            flexicast.update_client_state(FcClientAction::Leave, None),
            Ok(McClientStatus::Unaware),
        );

        assert_eq!(
            flexicast.update_client_state(FcClientAction::DecryptionKey, None),
            Ok(McClientStatus::Unaware),
        );

        // This is a good move.
        assert_eq!(
            flexicast.update_client_state(FcClientAction::Notify, None),
            Ok(McClientStatus::AwareUnjoined)
        );

        assert_eq!(
            flexicast.update_client_state(FcClientAction::Join, None),
            Ok(McClientStatus::WaitingToJoin)
        );

        assert_eq!(
            flexicast.update_client_state(FcClientAction::Join, None),
            Ok(McClientStatus::JoinedNoKey)
        );

        assert_eq!(
            flexicast.update_client_state(FcClientAction::DecryptionKey, None),
            Ok(McClientStatus::JoinedAndKey)
        );

        assert_eq!(
            flexicast.update_client_state(FcClientAction::McPath, Some(1)),
            Ok(McClientStatus::ListenMcPath(true))
        );

        assert_eq!(
            flexicast.update_client_state(
                FcClientAction::Leave,
                Some(LEAVE_FROM_CLIENT)
            ),
            Ok(McClientStatus::Leaving(false))
        );

        assert_eq!(
            flexicast.update_client_state(FcClientAction::Leave, None),
            Ok(McClientStatus::AwareUnjoined)
        );
    }

    #[test]
    /// Tests that the flexicast pipe correctly initiates and sends some data.
    fn test_fc_pipe_initiates_and_sends() {
        for probe_path in [true, false] {
            let mut fc_config = FcConfig {
                probe_mc_path: probe_path,
                ..Default::default()
            };
            let mut fc_pipe =
                FlexicastPipe::new(3, "/tmp/test_fc_pipe.txt", &mut fc_config)
                    .unwrap();

            assert!(fc_pipe.source_send_single_stream(true, None, 3).is_ok());
            assert!(fc_pipe.source_send_single_stream(true, None, 7).is_ok());
            assert!(fc_pipe.source_send_single_stream(true, None, 11).is_ok());

            // Assert all receivers correctly receive the stream.
            for i in 0..3 {
                let mut readables = fc_pipe.unicast_pipes[i]
                    .0
                    .client
                    .readable()
                    .collect::<Vec<_>>();
                readables.sort();
                assert_eq!(readables, vec![3, 7, 11]);
            }
        }
    }

    #[test]
    /// Tests that a receiver can fall back on unicast and receive
    /// [`FcClientAction::Sync`] messages from the unicast path to be able to
    /// receive again packets from the flexicast flow.
    fn fc_test_fall_back_uc() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            max_data: 10,
            max_stream_data: 10,
            ..Default::default()
        };
        let mut fc_pipe =
            FlexicastPipe::new(2, "/tmp/fc_test_fall_back_uc", &mut fc_config)
                .unwrap();

        let mut fail = RangeSet::default();
        fail.insert(0..1);

        let written = fc_pipe.source_send_single_stream(true, None, 3);
        assert_eq!(written, Ok(51));
        let now = time::Instant::now();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Read the content to increase the flow control limit.
        let mut buf = [0u8; 300];
        for (pipe, ..) in fc_pipe.unicast_pipes.iter_mut() {
            let out = pipe.client.stream_recv(3, &mut buf[..]);
            assert_eq!(out, Ok((10, false)));
        }

        fc_pipe.clients_send().unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Get highest packet number received on the flexicast flow for the first
        // receiver.
        let pipe = &mut fc_pipe.unicast_pipes[0].0;
        let pns = pipe
            .client
            .pkt_num_spaces
            .spaces
            .get(Epoch::Application, 1)
            .unwrap();
        let highest_pn_0 = pns.largest_rx_pkt_num;

        // The receiver falls back.
        pipe.server.fc_fall_back_unicast(true);

        // The source can continue sending data.
        let written = fc_pipe.source_send_single_stream(true, Some(&fail), 3);
        assert_eq!(written, Ok(54));
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // The failing receiver does not know about the new packet.
        let pipe = &mut fc_pipe.unicast_pipes[0].0;
        let pns = pipe
            .client
            .pkt_num_spaces
            .spaces
            .get(Epoch::Application, 1)
            .unwrap();
        let highest_pn_1 = pns.largest_rx_pkt_num;
        assert_eq!(highest_pn_0, highest_pn_1);

        // The first unicast path advertises to the receiver the new highest
        // packet number sent on the flexicast flow.
        let highest_pn_2 = pipe
            .server
            .flexicast
            .as_ref()
            .unwrap()
            .fc_reliable
            .server()
            .unwrap()
            .fc_highest_pn;
        assert_eq!(highest_pn_2, Some(highest_pn_0 + 2));
        fc_pipe
            .unicast_pipes
            .iter_mut()
            .for_each(|pipe| pipe.0.advance().unwrap());

        let pipe = &mut fc_pipe.unicast_pipes[0].0;
        let pns = pipe
            .client
            .pkt_num_spaces
            .spaces
            .get(Epoch::Application, 1)
            .unwrap();
        let highest_pn_3 = pns.largest_rx_pkt_num;
        assert_eq!(highest_pn_0 + 2, highest_pn_3);

        // Because the receiver fall backed on unicast, it receives the content
        // through unicast. But the flexicast flow must still wait for the flow
        // control limits updates before sending new data.
        let uc = &mut fc_pipe.unicast_pipes[0].0.server;
        fc_pipe
            .mc_channel
            .channel
            .rfc_delegate_streams(
                uc,
                now,
                FcUnicastRetransmission::FullRetransmit,
            )
            .unwrap();
        fc_pipe.unicast_pipes[0].0.advance().unwrap();

        // The two receivers can read the new data.
        for (pipe, ..) in fc_pipe.unicast_pipes.iter_mut() {
            let out = pipe.client.stream_recv(3, &mut buf[..]);
            assert_eq!(out, Ok((10, false)));
        }
        fc_pipe.clients_send().unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // The source can continue sending data.
        let written = fc_pipe.source_send_single_stream(true, None, 3);
        assert_eq!(written, Ok(65));
        fc_pipe.server_control_to_mc_source(now).unwrap();
    }
    #[test]
    fn fc_lkh_test_new_mc_key() {
        // A simple test not actually using flexicast but just trying to update the keys using mckeylkh frames
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            ..Default::default()
        };
        let mut fc_pipe =
            FlexicastPipe::new(1, "/tmp/test_fc_pipe.txt", &mut fc_config)
                .unwrap();
        let key: Vec<u8> = vec![0 as u8; fc_pipe.mc_channel.algo.key_len()];
        fc_pipe
            .mc_channel
            .channel
            .schedule_lkh_update(FCKeyUpdate::RawKey(key));
        fc_pipe.source_send_single_stream(true, None, 1);

        assert_eq!(fc_pipe.clients_send(), Ok(()));
    }
}

pub mod ack;
pub mod cca;
pub mod control;
pub(crate) mod fec;
pub mod flowcontrol;
pub mod nack;
pub mod reliable;
