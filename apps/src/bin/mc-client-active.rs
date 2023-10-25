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

use std::collections::HashMap;
use std::net;
use std::net::Ipv4Addr;
use std::net::ToSocketAddrs;

use quiche::multicast::authentication::McAuthentication;
use quiche::multicast::McConfig;
use quiche::multicast::MulticastClientStatus;
use quiche::multicast::MulticastError;
use quiche::multicast::MulticastRole;
use quiche::multicast::reliable::ReliableMulticastConnection;
use quiche_apps::mc_app;
use ring::rand::*;

use clap::Parser;
use quiche::multicast;
use quiche::multicast::McPathType;
use quiche::multicast::MulticastConnection;
use quiche::ConnectionId;
use std::io::Write;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Clone, Copy)]
enum FromSocket {
    Unicast,
    Multicast,
}

impl From<FromSocket> for u64 {
    fn from(value: FromSocket) -> Self {
        match value {
            FromSocket::Multicast => 0,
            FromSocket::Unicast => 1,
        }
    }
}

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

    /// Application over (multicast) QUIC.
    #[clap(long = "app", default_value = "tixeo")]
    app: mc_app::McApp,

    /// Unicast source port.
    #[clap(short = 'p', long = "port", default_value = "9999")]
    source_port: u16,

    /// Multicast local IP.
    #[clap(
        short = 'l',
        long = "local",
        default_value = "127.0.0.1",
        value_parser
    )]
    local_ip: Ipv4Addr,

    #[clap(long = "soft-wait")]
    /// Waits before joining the multicast channel, then waits the same amount
    /// of time before leaving.
    delay_in_mc_group: Option<u64>,
}

fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    // Application handler.
    let mut app_handler =
        mc_app::AppDataClient::new(args.app, &args.output_latency);

    let mc_client_params = multicast::MulticastClientTp {
        ipv4_channels_allowed: true,
        ipv6_channels_allowed: true,
    };
    let mut added_mc_cid = false;
    let mut probe_mc_path = false;
    let mut added_mc_auth_cid = false;
    let mut probe_mc_auth_path = false;

    // Multicast data.
    let mut mc_socket_opt: Option<mio::net::UdpSocket> = None;
    let mc_addr = "0.0.0.0:8889".parse().unwrap();

    // Multicast authentication.
    let mut mc_socket_auth_opt: Option<mio::net::UdpSocket> = None;
    let mc_addr_auth = "0.0.0.0:8890".parse().unwrap();

    // Multicast delay before joining and leaving.
    let delay_join_leave =
        args.delay_in_mc_group.map(std::time::Duration::from_millis);
    let mut times_join_leave = Vec::with_capacity(5);
    times_join_leave.push(std::time::SystemTime::now());
    let mut recv_packets = Vec::with_capacity(10000);

    // Whether reliable multicast (RMC) is used.
    let mut is_mc_reliable = false;

    // In a multicast communication where symmetric tags is used as authentication
    // mechanism, the client application is responsible of buffering
    // non-authenticated (na) packets as long as they desire (i.e., until an
    // expiration event or the associated authentication tag is received).
    // This lets the application decide to consume the packets even if it cannot
    // ensure authentication. Moreover, the application can decide the data
    // structure to use to buffer these multicast data packets.
    let mut mc_na_packets: HashMap<u64, Vec<u8>> = HashMap::new();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let peer_addr = args.address.to_socket_addrs().unwrap().next().unwrap();

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => format!("0.0.0.0:{}", args.source_port),
        std::net::SocketAddr::V6(_) => format!("[::]:{}", args.source_port),
    };

    // Log every packet sent on unicast.
    let mut log_uc_pkt = Vec::with_capacity(10000);

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // *CAUTION*: this should not be set to `false` in production!!!
    config.verify_peer(false);

    config
        .set_application_protos(&[
            b"hq-interop",
            b"hq-29",
            b"hq-28",
            b"hq-27",
            b"http/0.9",
        ])
        .unwrap();

    if !args.multicast {
        config.set_max_idle_timeout(10_000);
    }
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(1_000_000);
    config.set_initial_max_streams_uni(1_000_000);
    config.set_active_connection_id_limit(5);
    config.verify_peer(false);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::CUBIC);
    // config.set_cc_algorithm(quiche::CongestionControlAlgorithm::DISABLED);

    if args.multicast {
        config.set_multipath(true);
        config.set_enable_client_multicast(Some(&mc_client_params));
        config.receive_fec(true);
        config.set_fec_scheduler_algorithm(
            quiche::FECSchedulerAlgorithm::RetransmissionFec,
        );
        config.set_fec_symbol_size(1280 - 64);
        config.set_fec_window_size(2000);
    }

    // Generate a random source connection ID for the connection.
    let mut scid = [0; 16];
    let random = SystemRandom::new();
    random.fill(&mut scid[..]).unwrap();

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

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }

        panic!("send() failed: {:?}", e);
    }
    log_uc_pkt.push(write);

    debug!("written {}", write);

    'main_loop: loop {
        let now = std::time::Instant::now();
        if is_mc_reliable {
            conn.rmc_set_next_timeout(now, &random).unwrap();
        }
        let timers = [conn.timeout(), conn.mc_timeout(now), conn.rmc_timeout(now)];
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

                conn.on_timeout();
                debug!(
                    "Is connection closed after timeout: {}",
                    conn.is_closed()
                );

                let now = std::time::Instant::now();
                conn.on_rmc_timeout(now).unwrap();
                if conn.on_mc_timeout(now) ==
                    Err(quiche::Error::Multicast(
                        multicast::MulticastError::McInvalidRole(
                            MulticastRole::Client(
                                MulticastClientStatus::Leaving(true),
                            ),
                        ),
                    ))
                {
                    break 'main_loop;
                }
                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        // debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("Recv from socket unicast");

            debug!("got {} bytes", len);

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
                from_mc: None,
            };

            debug!(
                "Received a packet on the unicast channel. Is it closed? {}",
                conn.is_closed()
            );

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                },
            };

            recv_packets.push((
                std::time::SystemTime::now(),
                read,
                FromSocket::Unicast,
            ));
        }

        // Read incomming UDP packets from the multicast data socket and feed them
        // to multicast quiche.
        if let Some(mc_socket) = mc_socket_opt.as_mut() {
            'mc_read: loop {
                let (len, _) = match mc_socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            // debug!("recv() would block");
                            break 'mc_read;
                        }

                        panic!("recv() failed: {:?}", e);
                    },
                };

                debug!("Recv from socket multicast");

                // If symmetric authentication is used, buffer the packets as long
                // as the corresponding authentication packet is not received.
                let recv_info = quiche::RecvInfo {
                    to: mc_addr,
                    from: peer_addr,
                    from_mc: Some(McPathType::Data),
                };
                if conn.get_multicast_attributes().unwrap().get_mc_role() ==
                    MulticastRole::Client(MulticastClientStatus::ListenMcPath(
                        true,
                    ))
                {
                    let can_read_pkt = if conn
                        .get_multicast_attributes()
                        .unwrap()
                        .get_mc_auth_type() ==
                        quiche::multicast::authentication::McAuthType::SymSign
                    {
                        debug!("Ici appelle symetrique ?");
                        // Get the packet number used as identifier. Woops for the
                        // unwrap.
                        let pn = match conn.mc_get_pn(&buf[..len]) {
                            Ok(v) => v,
                            Err(e) => {
                                error!(
                                    "Error when reading the packet number: {:?}",
                                    e
                                );
                                continue 'mc_read;
                            },
                        };

                        debug!("Recv data packet with pn={}", pn);

                        // Maybe the application already received the
                        // authentication tag?
                        match conn.mc_verify_sym(&buf[..len], pn) {
                            Ok(()) => true,
                            Err(quiche::Error::Multicast(
                                MulticastError::McNoAuthPacket,
                            )) => {
                                // The authentication packet is not received yet.
                                // Store the packet until we receive it.
                                mc_na_packets.insert(pn, buf[..len].to_vec());
                                false
                            },
                            Err(e) => panic!(
                                "Err trying to authenticate with symmetric tag: {:?}",
                                e
                            ),
                        }
                    } else {
                        debug!("Set to true read incoming packet");
                        true
                    };
                    if can_read_pkt {
                        debug!("Can read incomming packet");

                        let read = match conn.mc_recv(&mut buf[..len], recv_info)
                        {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Multicast failed: {:?}", e);
                                continue 'mc_read;
                            },
                        };

                        recv_packets.push((
                            std::time::SystemTime::now(),
                            read,
                            FromSocket::Multicast,
                        ));
                    } // Else: it is buffered until we receive the
                      // authentication tag.
                } else {
                    let read = match conn.recv(&mut buf[..len], recv_info) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Multicast failed: {:?}", e);
                            continue 'mc_read;
                        },
                    };

                    recv_packets.push((
                        std::time::SystemTime::now(),
                        read,
                        FromSocket::Unicast,
                    ));
                }
            }
        }

        // Read incomming UDP packets from the multicast authentication socket and
        // feed them to multicast quiche
        debug!("Before authentication");
        if let Some(mc_socket_auth) = mc_socket_auth_opt.as_mut() {
            'mc_read_auth: loop {
                let (len, _) = match mc_socket_auth.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        // There are no more UDP packet to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            // debug!("recv() would block for auth mc");
                            break 'mc_read_auth;
                        }

                        panic!("recv() mc auth failed: {:?}", e);
                    },
                };
                debug!("Recv from socket multicast auth");

                let recv_info = quiche::RecvInfo {
                    to: mc_addr_auth,
                    from: peer_addr,
                    from_mc: Some(McPathType::Authentication),
                };

                if conn.get_multicast_attributes().unwrap().get_mc_role() ==
                    MulticastRole::Client(MulticastClientStatus::ListenMcPath(
                        true,
                    ))
                {
                    let _read = match conn.mc_recv(&mut buf[..len], recv_info) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Multicast auth failed: {:?}", e);
                            continue 'mc_read_auth;
                        },
                    };

                    debug!("Recv a packet on the authentication path. Use {:?} recv_info", recv_info);

                    // Check if some previously non-authenticated packets can now
                    // be processed.
                    let recv_tags = conn.mc_get_client_auth_tags().unwrap();
                    let pn_na_packets: Vec<_> =
                        mc_na_packets.keys().copied().collect();
                    for pn in pn_na_packets {
                        if recv_tags.contains(&pn) {
                            // This packet can be authenticated and processed.
                            let mut pkt_na = mc_na_packets.remove(&pn).unwrap();
                            match conn.mc_verify_sym(&pkt_na, pn) {
                                    Ok(()) => (),
                                    Err(quiche::Error::Multicast(MulticastError::McInvalidSign)) => error!("Packet {} has invalid authentication!", pn),
                                    Err(e) => panic!("Unknown error when authenticating a previously received packet with symmetric tags: {:?}", e)
                                }
                            debug!("Can read packet 2 with pn={}", pn);
                            let recv_info = quiche::RecvInfo {
                                to: mc_addr,
                                from: peer_addr,
                                from_mc: Some(McPathType::Data),
                            };

                            let read =
                                match conn.mc_recv(&mut pkt_na[..], recv_info) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        error!("Multicast failed: {:?}", e);
                                        continue;
                                    },
                                };
                            debug!("Multicast QUIC read {} bytes", read);
                            debug!(
                                "Readable streams: {:?}",
                                conn.readable().collect::<Vec<_>>()
                            );
                        }
                    }
                } else {
                    info!("Path probe received for auth?");
                    let _read = match conn.recv(&mut buf[..len], recv_info) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Multicast failed: {:?}", e);
                            continue 'mc_read_auth;
                        },
                    };
                }
            }
        }

        if conn.is_closed() || conn.is_draining() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        if let Some(multicast) = conn.get_multicast_attributes() {
            if matches!(
                multicast.get_mc_role(),
                multicast::MulticastRole::Client(MulticastClientStatus::Leaving(
                    _
                ))
            ) && delay_join_leave.is_none()
            {
                info!("Client leaves the multicast channel. Closing...");
                break;
            }
        }

        // Process multicast events.
        debug!("Before processing multicast events");
        if conn.get_multicast_attributes().is_some() {
            let mut probe_already = false;
            // Join the multicast channel and create the listening socket if not
            // already done.
            if conn.get_multicast_attributes().unwrap().get_mc_role() ==
                MulticastRole::Client(MulticastClientStatus::AwareUnjoined)
            {
                info!("Before acting role");
                // Did not join the multicast channel before.
                let multicast = conn.get_multicast_attributes().unwrap();
                let mc_announce_data =
                    multicast.get_mc_announce_data_path().unwrap().to_owned();
                
                is_mc_reliable = mc_announce_data.full_reliability;

                // Add the new connection ID for the announce data.
                if !added_mc_cid {
                    info!("Add a new connection ID");
                    let scid =
                        ConnectionId::from_ref(&mc_announce_data.channel_id);
                    conn.add_mc_cid(&scid).unwrap();
                }

                // Create a second path
                // MC-TODO: do we have to put another address here?
                if !probe_mc_path && added_mc_cid {
                    info!(
                        "Create second path. Client addr={:?}. Server addr={:?}",
                        mc_addr, peer_addr
                    );
                    let mc_space_id = conn.create_mc_path(
                        mc_addr,
                        peer_addr,
                        mc_announce_data.is_ipv6,
                    );
                    if let Ok(mc_space_id) = mc_space_id {
                        conn.set_mc_space_id(mc_space_id, McPathType::Data)
                            .unwrap();

                        // If soft-multicast is used by the source, the client
                        // will receive multicast QUIC
                        // packets with its unicast
                        // address as destination of the IP packet. Bind the
                        // socket to the local address
                        // with the multicast destination
                        // port.
                        let mc_group_sockaddr: net::SocketAddr =
                            if mc_announce_data.is_ipv6 {
                                let ip = socket.local_addr().unwrap().ip();
                                net::SocketAddr::new(
                                    ip,
                                    mc_announce_data.udp_port,
                                )
                            } else {
                                let group_ip = net::Ipv4Addr::from(
                                    mc_announce_data.group_ip.to_owned(),
                                );
                                net::SocketAddr::V4(net::SocketAddrV4::new(
                                    group_ip,
                                    mc_announce_data.udp_port,
                                ))
                            };
                        // MC-TODO: join the multicast group.
                        let mut mc_socket =
                            mio::net::UdpSocket::bind(mc_group_sockaddr).unwrap();
                        debug!(
                            "Multicast client binds on address: {:?}",
                            mc_group_sockaddr
                        );

                        poll.registry()
                            .register(
                                &mut mc_socket,
                                mio::Token(1),
                                mio::Interest::READABLE,
                            )
                            .unwrap();
                        probe_mc_path = true;
                        if delay_join_leave.is_none() {
                            conn.mc_join_channel(
                                app_handler.leave_on_mc_timeout(),
                            )
                            .unwrap();
                            mc_socket
                                .join_multicast_v4(
                                    &net::Ipv4Addr::from(
                                        mc_announce_data.group_ip.to_owned(),
                                    ),
                                    &args.local_ip,
                                )
                                .unwrap();
                        }
                        mc_socket_opt = Some(mc_socket);
                        probe_already = true;
                    }
                }
                added_mc_cid = true;
            }
            if let Some(delay) = delay_join_leave {
                if args.multicast && probe_mc_path && added_mc_cid {
                    let now = std::time::SystemTime::now();
                    if now
                        .duration_since(
                            times_join_leave.last().unwrap().to_owned(),
                        )
                        .unwrap() >=
                        delay
                    {
                        // Change in the client status in the multicast channel.
                        // If a single value in the Vec => join the multicast
                        // group.
                        if times_join_leave.len() == 1 {
                            conn.mc_join_channel(
                                app_handler.leave_on_mc_timeout(),
                            )
                            .unwrap();
                            let multicast =
                                conn.get_multicast_attributes().unwrap();
                            let mc_announce_data = multicast
                                .get_mc_announce_data_path()
                                .unwrap()
                                .to_owned();
                            mc_socket_opt
                                .as_mut()
                                .unwrap()
                                .join_multicast_v4(
                                    &net::Ipv4Addr::from(
                                        mc_announce_data.group_ip.to_owned(),
                                    ),
                                    &args.local_ip,
                                )
                                .unwrap();
                            times_join_leave.push(now);
                        } else if times_join_leave.len() == 2 {
                            conn.mc_leave_channel().unwrap();
                            times_join_leave.push(now);
                        }
                    }
                }
            }

            // Stop the socket if the client left the group and it was
            // acknowledged.
            if let Some(multicast) = conn.get_multicast_attributes() {
                if multicast.get_mc_role() ==
                    MulticastRole::Client(MulticastClientStatus::AwareUnjoined) &&
                    mc_socket_opt.is_some()
                {
                    println!("Leave the multicast socket!");
                    let mc_announce_data =
                        multicast.get_mc_announce_data_path().unwrap().to_owned();
                    mc_socket_opt
                        .as_mut()
                        .unwrap()
                        .leave_multicast_v4(
                            &net::Ipv4Addr::from(
                                mc_announce_data.group_ip.to_owned(),
                            ),
                            &args.local_ip,
                        )
                        .unwrap();
                    mc_socket_opt = None;
                }
            }

            // Authentication path data not yet installed.
            if let (None, Some(mc_announce_auth)) = (
                mc_socket_auth_opt.as_ref(),
                conn.get_multicast_attributes()
                    .unwrap()
                    .get_mc_announce_data(1),
            ) {
                let mc_announce_auth = mc_announce_auth.to_owned();
                info!("This is the received mc announce: {:?}", mc_announce_auth);
                if mc_announce_auth.path_type == McPathType::Authentication {
                    if !added_mc_auth_cid {
                        let scid =
                            ConnectionId::from_ref(&mc_announce_auth.channel_id);
                        conn.add_mc_cid(&scid).unwrap();
                    }

                    if !probe_mc_auth_path && added_mc_auth_cid && !probe_already
                    {
                        debug!("Create third path for authentication. Client addr={:?}. Server addr={:?}", mc_addr_auth, peer_addr);
                        let mc_space_id = conn.create_mc_path(
                            mc_addr_auth,
                            peer_addr,
                            mc_announce_auth.is_ipv6,
                        );
                        if let Ok(mc_space_id) = mc_space_id {
                            conn.set_mc_space_id(
                                mc_space_id,
                                McPathType::Authentication,
                            )
                            .unwrap();
                            let mc_group_sockaddr = if mc_announce_auth.is_ipv6 {
                                let ip = socket.local_addr().unwrap().ip();
                                net::SocketAddr::new(
                                    ip,
                                    mc_announce_auth.udp_port,
                                )
                            } else {
                                let group_ip = net::Ipv4Addr::from(
                                    mc_announce_auth.group_ip.to_owned(),
                                );
                                net::SocketAddr::V4(net::SocketAddrV4::new(
                                    group_ip,
                                    mc_announce_auth.udp_port,
                                ))
                            };
                            let mut mc_socket_auth =
                                mio::net::UdpSocket::bind(mc_group_sockaddr)
                                    .unwrap();
                            debug!(
                            "Multicast client binds on address for authentication: {:?}",
                            mc_group_sockaddr
                        );
                            if !mc_announce_auth.is_ipv6 {
                                mc_socket_auth
                                    .join_multicast_v4(
                                        &net::Ipv4Addr::from(
                                            mc_announce_auth.group_ip.to_owned(),
                                        ),
                                        &args.local_ip,
                                    )
                                    .unwrap();
                            }
                            poll.registry()
                                .register(
                                    &mut mc_socket_auth,
                                    mio::Token(2),
                                    mio::Interest::READABLE,
                                )
                                .unwrap();
                            mc_socket_auth_opt = Some(mc_socket_auth);
                            probe_mc_auth_path = true;
                        }
                    }
                    added_mc_auth_cid = true;
                }
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        debug!("Before outgoing");
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    // debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            // Depending on the send_info, use the associated socket.
            // For simplicity use IPv4 only and match on the udp source port.
            let port_from = send_info.from.port();
            let socket_from = if port_from == socket.local_addr().unwrap().port()
            {
                &mut socket
            } else if port_from == mc_addr.port() {
                mc_socket_opt.as_mut().unwrap()
            } else if port_from == mc_addr_auth.port() {
                mc_socket_auth_opt
                    .as_mut()
                    .expect("Multicast auth socket is None")
            } else {
                panic!("Unknown port: {}", port_from);
            };

            if let Err(e) = socket_from.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // debug!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }
            log_uc_pkt.push(write);
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Process all readable streams.
        debug!(
            "All readable streams: {:?}",
            conn.readable().collect::<Vec<_>>()
        );
        'read_stream: for s in conn.readable() {
            if !conn.stream_complete(s) {
                debug!("Stream {} is not complete", s);
                continue 'read_stream;
            }

            if !conn.stream_readable(s) {
                // Application only reads full video frame.
                continue 'read_stream;
            }
            let mut total = 0;

            while let Ok((read, fin)) = conn.stream_recv(s, &mut buf[total..]) {
                if !fin {
                    debug!("Not fin and read: {}", read);
                }
                total += read;
                if fin {
                    debug!("Add a new stream in the list of received: {} of length: {}.", s, total);
                    app_handler.on_stream_complete(&buf[..total], s);
                }
            }
        }
    }

    // Record the application results.
    app_handler.on_finish();

    // Write the number of packets sent.
    let mut file =
        std::fs::File::create(format!("{}-uc-pkt.txt", &args.output_latency))
            .unwrap();
    for nb_bytes in log_uc_pkt.iter() {
        writeln!(file, "{}", nb_bytes).unwrap();
    }

    // Write the times the client left and all the packets.
    let mut file = std::fs::File::create(format!(
        "{}-times-change-uc-pkt.txt",
        &args.output_latency
    ))
    .unwrap();
    for time in times_join_leave.iter() {
        writeln!(
            file,
            "{}",
            time.duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_micros(),
        )
        .unwrap()
    }

    let mut file =
        std::fs::File::create(format!("{}-pns-uc-pkt.txt", &args.output_latency))
            .unwrap();
    for (time, nb, from) in recv_packets.iter() {
        writeln!(
            file,
            "{} {} {}",
            time.duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_micros(),
            nb,
            u64::from(*from)
        )
        .unwrap();
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}
