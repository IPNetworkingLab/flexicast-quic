//! Multicast time-to-live application over Flexicast QUIC module.
//! This module allows the flexicast QUIC source to determine the reachability
//! distance of each receiver.

use std::net::IpAddr;

use quiche::flexicast::ack::OpenRangeSet;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Messages from the flexicast flow and unicast path to the application
/// controller. This is responsible to aggregate the results regarding the
/// losses and the distance from the receivers to the flexicast flow.
pub enum FcTtlMsg {
    /// The flexicast flow sent a packet with a DATAGRAM frame.
    /// First value is the packet number. Second value is the IP ttl.
    SentPkt(Vec<(u64, u8)>),

    /// The ranges of packets received by the receiver.
    /// First value is the IP address of the receiver.
    /// Second value is the ranges of received packet number.
    RecvPkt((IpAddr, OpenRangeSet)),
}

pub mod fc_flow;
pub mod uc_path;
pub mod ttl;