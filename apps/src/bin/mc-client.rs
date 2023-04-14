// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use ring::rand::*;
use std::collections::HashMap;
use std::io::Write;
use std::net::ToSocketAddrs;

use clap::Parser;
use quiche::multicast::MulticastConnection;

use quiche_apps::multicast::mc_client;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Parser)]
struct Args {
    /// Activate multicast extension.
    #[clap(short = 'm', long)]
    multicast: bool,

    /// Path to the file containing the reception results.
    #[clap(
        short = 'o',
        long,
        value_parser,
        default_value = "client_trace.trace"
    )]
    output_latency: String,

    /// Address of the server.
    #[clap()]
    address: String,
}

fn main() {
    env_logger::init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    // Video output.
    let mut video_frame_recv = Vec::with_capacity(100);

    // Multicast data.
    let mut mc_socket_opt: Option<mio::net::UdpSocket> = None;
    let mc_addr = "0.0.0.0:8889".parse().unwrap();

    // Multicast authentication.
    let mut mc_socket_auth_opt: Option<mio::net::UdpSocket> = None;
    let mc_addr_auth = "0.0.0.0:8890".parse().unwrap();

    // In a multicast communication where symmetric tags is used as authentication
    // mechanism, the client application is responsible of buffering
    // non-authenticated (na) packets as long as they desire (i.e., until an
    // expiration event or the associated authentication tag is received).
    // This lets the application decide to consume the packets even if it cannot
    // ensure authentication. Moreover, the application can decide the data
    // structure to use to buffer these multicast data packets.
    let mut mc_na_packets: mc_client::McUnsigned = HashMap::new();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let peer_addr = args.address.to_socket_addrs().unwrap().next().unwrap();

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:9999",
        std::net::SocketAddr::V6(_) => "[::]:9999",
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = mc_client::get_mc_config(args.multicast, MAX_DATAGRAM_SIZE);

    // Generate a random source connection ID for the connection.
    let mut scid = [0; 16];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Get local address.
    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(None, &scid, local_addr, peer_addr, &mut config).unwrap();

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    mc_client::client_connect(&mut conn, &mut socket, &mut out[..]).unwrap();

    'main_loop: loop {
        let now = std::time::Instant::now();
        let timers = [conn.timeout(), conn.mc_timeout(now)];
        let timeout = timers.iter().flatten().min().copied();
        debug!("Timeout: {:?}", timeout);
        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out");
                if mc_client::handle_empty_events(&mut conn) {
                    break 'main_loop;
                }
                break 'read;
            }

            if mc_client::read_socket_to_quiche(&mut conn, &mut socket, &mut buf)
                .unwrap()
            {
                break 'read;
            }
        }

        // Read incomming UDP packets from the multicast data socket and feed them
        // to multicast quiche.
        if let Some(mc_socket) = mc_socket_opt.as_mut() {
            'mc_read: loop {
                if mc_client::read_mc_data_socket_to_quiche(
                    &mut conn,
                    mc_socket,
                    &mut buf,
                    &mut mc_na_packets,
                    mc_addr,
                    peer_addr,
                ) {
                    break 'mc_read;
                }
            }
        }

        // Read incomming UDP packets from the multicast authentication socket and
        // feed them to multicast quiche.
        if let Some(mc_socket_auth) = mc_socket_auth_opt.as_mut() {
            'mc_read_auth: loop {
                if mc_client::read_mc_auth_socket_to_quiche(
                    &mut conn,
                    mc_socket_auth,
                    &mut buf,
                    &mut mc_na_packets,
                    mc_addr,
                    mc_addr_auth,
                    peer_addr,
                ) {
                    break 'mc_read_auth;
                }
            }
        }

        if conn.is_closed() || conn.is_draining() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Process multicast events.
        if conn.get_multicast_attributes().is_some() {
            let (mc_sock, mc_sock_auth) = mc_client::process_mc_events(
                &mut conn,
                mc_addr,
                mc_addr_auth,
                peer_addr,
                &socket,
                mc_socket_auth_opt.is_none(),
            );
            if let Some(sock) = mc_sock {
                mc_socket_opt = Some(sock);
                poll.registry()
                    .register(
                        mc_socket_opt.as_mut().unwrap(),
                        mio::Token(1),
                        mio::Interest::READABLE,
                    )
                    .unwrap();
            }
            if let Some(sock) = mc_sock_auth {
                mc_socket_auth_opt = Some(sock);
                poll.registry()
                    .register(
                        mc_socket_auth_opt.as_mut().unwrap(),
                        mio::Token(2),
                        mio::Interest::READABLE,
                    )
                    .unwrap();
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            if mc_client::client_send(
                &mut conn,
                &mut out,
                &mut socket,
                mc_socket_opt.as_mut(),
                mc_socket_auth_opt.as_mut(),
                mc_addr,
                mc_addr_auth,
            ) {
                break;
            }
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Process all readable streams.
        'read_stream: for s in conn.readable() {
            if !conn.stream_complete(s) {
                continue 'read_stream;
            }

            if !conn.stream_readable(s) {
                // Application only reads full video frame.
                continue 'read_stream;
            }
            let mut total = 0;

            while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                total += read;
                if fin {
                    debug!("Add a new stream in the list of received.");
                    let now = std::time::SystemTime::now();
                    video_frame_recv.push((s, now, total));
                }
            }
        }
    }

    // Record the timestamp results.
    let mut file = std::fs::File::create(&args.output_latency).unwrap();
    for (stream_id, time, nb_bytes) in &video_frame_recv {
        writeln!(
            file,
            "{} {} {}",
            (stream_id - 1) / 4,
            time.duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros(),
            nb_bytes
        )
        .unwrap();
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}
