#[macro_use]
extern crate log;

use clap::Parser;
use quiche::h3::NameValue;
use quiche::multicast;
use quiche::multicast::reliable::ReliableMulticastConnection;
use quiche::multicast::McClientStatus;
use quiche::multicast::McConfig;
use quiche::multicast::McPathType;
use quiche::multicast::McRole;
use quiche::multicast::MulticastConnection;
use quiche::ConnectionId;
#[cfg(feature = "qlog")]
use quiche_apps::common::make_qlog_writer;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::net;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::time::SystemTime;

use quiche_apps::mc_app::rtp::RtpClient;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Parser)]
struct Args {
    /// Activate multicast extension.
    #[clap(long)]
    flexicast: bool,

    /// URL of the server to contact.
    url: url::Url,

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

    #[clap(long = "proxy")]
    /// Multicast packets are proxied using packet replication for this client.
    /// This argument is a trick to avoid out-of-band computation by the source
    /// of the proxies to the clients. If this value is true, instead of
    /// binding to the multicast address given in the MC_ANNOUNCE frame, the
    /// client will listen to its own address and the port advertised by the
    /// source.
    proxy_uc: bool,

    #[clap(short = 'o', long = "output", value_parser, default_value = "output.avi")]
    output_file: String,

    /// Address of the RTP sink.
    #[clap(short = 'r', long = "rtp-addr", value_parser)]
    rtp_sink_addr: SocketAddr,
}

fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    let mc_client_params = multicast::McClientTp {
        ipv4_channels_allowed: true,
        ipv6_channels_allowed: true,
    };
    let mut is_mc_reliable = false;

    // Creation of the multicast path.
    let mut added_mc_cid = false;
    let mut probe_mc_path = false;

    let mut mc_socket_opt: Option<mio::net::UdpSocket> = None;
    let mut joined_mc_ip = false;
    let mc_addr: SocketAddr = "0.0.0.0:8889".parse().unwrap();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let url = args.url;
    let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => format!("0.0.0.0:{}", args.source_port),
        std::net::SocketAddr::V6(_) => format!("[::]:{}", args.source_port),
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = get_config(args.flexicast, &mc_client_params);

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

    // Only bother with qlog if the user specified it.
    #[cfg(feature = "qlog")]
    {
        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let id = format!("Client-{}", args.local_ip.to_string());
            let writer = make_qlog_writer(&dir, "client", &id);

            conn.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("{} id={}", "quiche-client qlog", id),
            );
        }
    }

    // Create the RTP application handler at the client.
    let mut rtp_client = RtpClient::new(&args.output_file, args.rtp_sink_addr).unwrap();

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

    'main_loop: loop {
        // Compute (FC-)QUIC timeout.
        let now = std::time::Instant::now();
        if is_mc_reliable {
            conn.rmc_set_next_timeout(now, &random).unwrap();
        }
        let timers = [
            conn.timeout(),        // QUIC timeout
            conn.mc_timeout(now),  // FC-QUIC timeout
            conn.rmc_timeout(now), // Reliable FC-QUIC timeout
        ];
        let timeout = timers.iter().flatten().min().copied();

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'uc_read: loop {
            let now = std::time::Instant::now();
            conn.on_rmc_timeout(now).unwrap();

            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                conn.on_timeout();
                if conn.on_mc_timeout(now) ==
                    Err(quiche::Error::Multicast(
                        multicast::McError::McInvalidRole(McRole::Client(
                            McClientStatus::Leaving(true),
                        )),
                    ))
                {
                    break 'main_loop;
                }

                break 'uc_read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        // debug!("recv() would block");
                        break 'uc_read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };
            info!("Recv from socket unicast");

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
                from_mc: None,
            };

            // Process potentially coalesced packets.
            let _read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'uc_read;
                },
            };
        }

        // Read incomming UDP packets from the multicast socket and feed them to
        // flexicast quiche.
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

                let recv_info = quiche::RecvInfo {
                    to: mc_addr,
                    from: peer_addr,
                    from_mc: Some(McPathType::Data),
                };

                // Only feed the packet to quiche if the client listens to the
                // multicast channel.
                let err_opt =
                    if conn.get_multicast_attributes().unwrap().get_mc_role() ==
                        McRole::Client(McClientStatus::ListenMcPath(true))
                    {
                        conn.mc_recv(&mut buf[..len], recv_info)
                    } else {
                        conn.recv(&mut buf[..len], recv_info)
                    };

                let _read = match err_opt {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Multicast failed: {:?}", e);
                        continue 'mc_read;
                    },
                };
                debug!("Recv from socket multicast processed");
            }
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
        }

        // Process Flexicast events.
        if conn.get_multicast_attributes().is_some() {
            // Join the flexicast channel and creates the listening socket if not
            // already done.
            if conn.get_multicast_attributes().unwrap().get_mc_role() ==
                McRole::Client(McClientStatus::AwareUnjoined)
            {
                debug!("Client joins the flexicast channel.");

                // Did not join the flexicast channel before.
                let multicast = conn.get_multicast_attributes().unwrap();
                let mc_announce_data =
                    multicast.get_mc_announce_data_path().unwrap().to_owned();

                is_mc_reliable = mc_announce_data.full_reliability;

                // Add the new connection ID for the announce data.
                if !added_mc_cid {
                    debug!("Add a new connection ID");
                    let scid =
                        ConnectionId::from_ref(&mc_announce_data.channel_id);
                    conn.add_mc_cid(&scid).unwrap();
                }

                // Create a second path.
                if !probe_mc_path && added_mc_cid {
                    debug!("Create the second path. Client addr={:?}. Server addr={:?}", mc_addr, peer_addr);
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
                                let group_ip = if args.proxy_uc {
                                    args.local_ip
                                } else {
                                    net::Ipv4Addr::from(
                                        mc_announce_data.group_ip.to_owned(),
                                    )
                                };
                                net::SocketAddr::V4(net::SocketAddrV4::new(
                                    group_ip,
                                    mc_announce_data.udp_port,
                                ))
                            };

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
                        conn.mc_join_channel(false, None).unwrap();
                        mc_socket_opt = Some(mc_socket);
                    }
                }
                added_mc_cid = true;
            }

            // Join the multicast socket.
            if let Some(multicast) = conn.get_multicast_attributes() {
                if multicast.get_mc_role() ==
                    McRole::Client(McClientStatus::ListenMcPath(true)) &&
                    !joined_mc_ip
                {
                    if !args.proxy_uc {
                        mc_socket_opt
                            .as_mut()
                            .unwrap()
                            .join_multicast_v4(
                                &net::Ipv4Addr::from(
                                    multicast
                                        .get_mc_announce_data(0)
                                        .unwrap()
                                        .group_ip
                                        .to_owned(),
                                ), // &args.local_ip
                                &"11.1.5.1".parse().unwrap(),
                            )
                            .unwrap();
                    }
                    joined_mc_ip = true;
                }
            }

            // Stop the socket if the client left the group and it was
            // acknowledged.
            if let Some(multicast) = conn.get_multicast_attributes() {
                if multicast.get_mc_role() ==
                    McRole::Client(McClientStatus::AwareUnjoined) &&
                    mc_socket_opt.is_some()
                {
                    info!("Leave the multicast socket!");
                    let mc_announce_data =
                        multicast.get_mc_announce_data_path().unwrap().to_owned();
                    if !args.proxy_uc {
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
                    }
                    mc_socket_opt = None;
                }
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            // Depending on `send_info`, use the appropriate socket.
            // The client may send packets on the multicast channel for the path
            // probing phase.
            let src_port = send_info.from.port();
            let out_socket = if src_port == socket.local_addr().unwrap().port() {
                &mut socket
            } else if src_port == mc_addr.port() {
                mc_socket_opt.as_mut().expect("Multicast socket is None")
            } else {
                panic!("Unknown source addr to send packets: {:?}", send_info);
            };

            if let Err(e) = out_socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }

                panic!("send() failed: {:?}", e);
            }
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Process all readable streams.
        'streams: for stream_id in conn.readable() {
            if !conn.stream_fully_readable(stream_id) {
                continue 'streams;
            }

            if !conn.stream_readable(stream_id) {
                continue 'streams;
            }

            // We should be able to read the stream until its end.
            let mut total = 0;
            while let Ok((read, fin)) = conn.mc_stream_recv(stream_id, &mut buf[..]) {
                total += read;

                rtp_client.on_sequential_stream_recv(&buf[..read]);

                if fin {
                    let now_st = SystemTime::now();
                    rtp_client.on_stream_complete(stream_id, now_st, total);
                }
            }
        }
    }
}

fn get_config(
    multicast: bool, mc_client_params: &multicast::McClientTp,
) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false); // Not prodction-ready.

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    if !multicast {
        config.set_max_idle_timeout(10_000);
    }
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(100_000_000_000);
    config.set_initial_max_stream_data_bidi_local(100_000_000_000);
    config.set_initial_max_stream_data_bidi_remote(100_000_000_000);
    config.set_initial_max_stream_data_uni(100_000_000_000);
    config.set_initial_max_streams_bidi(100_000_000_000);
    config.set_initial_max_streams_uni(100_000_000_000);
    config.set_active_connection_id_limit(5);
    config.verify_peer(false);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::CUBIC);

    if multicast {
        config.set_multipath(true);
        config.set_enable_client_multicast(Some(mc_client_params));
        config.receive_fec(true);
        config.set_fec_scheduler_algorithm(
            quiche::FECSchedulerAlgorithm::RetransmissionFec,
        );
        config.set_fec_symbol_size(1280 - 64);
        config.set_fec_window_size(50_000);
    }

    config
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}
