//! Asynchronous communication module to handle communication between the flexicast source, the unicast instances and the controller.

use socket2;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const MAX_DATAGRAM_SIZE: usize = 1350;

pub mod controller;
pub mod fc;
pub mod uc;

pub fn new_udp_socket_reuseport(bind_addr: SocketAddr) -> io::Result<UdpSocket> {
    // Use socket2 sockets to set reuse port.
    let socket =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    socket.set_reuse_port(true)?;
    socket.bind(&bind_addr.into())?;

    // Convert to tokio socket.
    let socket = UdpSocket::from_std(socket.into())?;
    Ok(socket)
}