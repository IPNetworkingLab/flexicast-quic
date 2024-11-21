//! Module for the sendmmsg extension allowing to replicate packet bytes to
//! multiple receivers instead of relying on a real multicast network.

use tokio::{net::UdpSocket, sync::mpsc};
use std::{net::SocketAddr, os::fd::{AsFd, AsRawFd}, sync::Arc};
use super::Result;
use std::io;
use libc::*;
use std::mem;

/// Structure to manipulate the sendmmsg instance.
pub struct SendMMsg {
    /// Communication channel.
    pub rx: mpsc::Receiver<MsgSmsg>,

    /// List of all addresses that must receive the packets.
    pub recv_sockaddr: Vec<SocketAddr>,
    
    /// The UDP socket to send the packets.
    pub socket: Arc<UdpSocket>,
}

impl SendMMsg {
    /// Creates a new instance.
    pub fn new(rx: mpsc::Receiver<MsgSmsg>, socket: Arc<UdpSocket>) -> Self {
        Self {
            rx,
            recv_sockaddr: Vec::new(),
            socket,
        }
    }

    /// Run the instance.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            let msg = match self.rx.recv().await {
                Some(v) => v,
                None => break,
            };

            match msg {
                MsgSmsg::Packet(mut packet) => {
                    unsafe {
                        my_sendmmsg(&self.socket, &mut packet, &self.recv_sockaddr)?;
                    }
                },

                MsgSmsg::NewRecv(recv_addr) => self.recv_sockaddr.push(recv_addr),

                MsgSmsg::Stop => break,
            }
        }
        
        Ok(())
    }
}

/// Messages that are transmitted to the SendMMsg instance.
pub enum MsgSmsg {
    /// A new packet must be delivered to the network.
    Packet(Vec<u8>),

    /// There is a new receiver to which to forward packets.
    NewRecv(SocketAddr),

    /// Stop the processing.
    Stop,
}

/* WARNING: the following code is unsafe. */
/// A custom wrapper funciton of sendmmsg.
unsafe fn my_sendmmsg(
    socket: &tokio::net::UdpSocket, buf: &mut [u8], sock_addrs: &[std::net::SocketAddr]
) -> io::Result<usize> {
    if sock_addrs.is_empty() {
        return Ok(0);
    }
    let sock_fd = socket.as_fd().as_raw_fd();
    debug!("Sockaddrs: {:?}", sock_addrs);
    
    // Declare structures.
    let n = sock_addrs.len();
    let mut msgs: Vec<libc::mmsghdr> = vec![mem::zeroed(); n];
    let mut iovecs: Vec<libc::iovec> = vec![mem::zeroed(); n];
    let mut addresses: Vec<libc::sockaddr_in> = vec![mem::zeroed(); n];

    // Fill in the buffers.
    for i in 0..n {
        iovecs[i].iov_base = buf.as_mut_ptr() as *mut libc::c_void;
        iovecs[i].iov_len = buf.len();
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i] as *mut _ as *mut libc::iovec;
        msgs[i].msg_hdr.msg_iovlen = 1;
        match &sock_addrs[i] {
            SocketAddr::V4(v4) => {
                addresses[i].sin_family = libc::AF_INET as u16;
                addresses[i].sin_port = u16::to_be(v4.port());
                addresses[i].sin_addr = in_addr { s_addr: u32::to_be(v4.ip().to_owned().into()) };

                msgs[i].msg_hdr.msg_name = &mut addresses[i] as *mut _ as *mut libc::c_void;
                msgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;

                debug!("address: {:?} and {:?} and {:?}", addresses[i].sin_addr, addresses[i].sin_addr.s_addr, msgs[i].msg_hdr.msg_namelen);
            },
            SocketAddr::V6(_) => todo!("Not implemented for IPv6"),
        }

    }

    let _retval = sendmmsg(sock_fd, &mut msgs[0] as *mut libc::mmsghdr, n as u32, 0);

    Ok(0)
    
}
