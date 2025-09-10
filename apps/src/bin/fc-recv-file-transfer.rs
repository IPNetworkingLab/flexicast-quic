#[macro_use]
extern crate log;

use clap::Parser;
use quiche::flexicast::FlexicastConnection;
use quiche::flexicast::McClientStatus;
use quiche::flexicast::McConfig;
use quiche::flexicast::McRole;
use quiche::h3::NameValue;
use quiche::ConnectionId;
#[cfg(feature = "qlog")]
use quiche_apps::common::make_qlog_writer;
use quiche_apps::fc_app::file_transfer::receiver::FileTransferRecv;
use quiche_apps::fc_app::file_transfer::receiver::FileTransferRecvMsg;
use quiche_apps::fc_app::file_transfer::sender::FileTransferKind;
use quiche_apps::fc_app::video::hls::HlsSink;
use quiche_apps::fc_app::video::rtp::RtpSink;
use quiche_apps::fc_app::video::rtp::VideoSourceMsg;
use quiche_apps::fc_app::video::StreamTransferKind;
use quiche_apps::fc_app::TransferKind;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::io::Write;
use std::net;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::time;
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Parser)]
struct Args {
    /// Activate flexicast extension.
    #[clap(long)]
    flexicast: bool,

    /// URL of the server to contact.
    url: url::Url,

    /// Unicast source port.
    #[clap(short = 'p', long = "port", default_value = "9999")]
    source_port: u16,

    /// Multicast local IP.
    #[clap(short = 'l', long = "local", default_value = "0.0.0.0", value_parser)]
    local_ip: Ipv4Addr,

    /// Multicast packets are proxied using packet replication for this client.
    /// This argument is a trick to avoid out-of-band computation by the source
    /// of the proxies to the clients. If this value is true, instead of
    /// binding to the flexicast address given in the MC_ANNOUNCE frame, the
    /// client will listen to its own address and the port advertised by the
    /// source.
    #[clap(long = "proxy")]
    proxy_uc: bool,

    /// Sets the initial flow control limits on the receiver.
    /// If this parameter is not set, the receiver uses unlimited flow control.
    #[clap(long = "flow-control")]
    initial_flow_control: Option<u64>,

    /// Receiving-side transfer kind.
    #[clap(long = "transfer-kind", default_value = "file,file,.")]
    transfer_kind: TransferKind,

    /// Whether the receiver does not expect the connection to close after
    /// receiving a finished stream. E.g., used for application with updated
    /// content.
    #[clap(long = "stay-open")]
    stay_open_on_fin: bool,

    /// Whether the client sends transport feedback data to the server.
    #[clap(long = "transport-feedback")]
    transport_feedback: bool,

    /// JSON output of received packets.
    #[clap(long = "json-output")]
    json_output: Option<String>,
}

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    let current_fc_idx = 0;
    let mut nb_recv = 0;
    let mut uc_recv = 0;
    let mut mc_recv = 0;
    let mut uc_send = 0;

    // Same but for bytes.
    let mut uc_recv_bytes = 0;
    let mut mc_recv_bytes = 0;
    let mut uc_send_bytes = 0;

    // Last time we displayed the stats.
    let mut last_stat_print = time::Instant::now();

    // Socket to send information about received packets.
    let mut fd_json = args
        .json_output
        .as_ref()
        .and_then(|name| std::fs::File::create(name).ok());
    let mut last_data_received_was_mc = false;

    // Whether we have to stop process multicast packets.
    let mut stop_mc = false;
    let socket_stop = UnixDatagram::bind("/tmp/fcquic_stop").unwrap();

    let mut total_read = 0;

    // Transport metrics for feedback.
    let start_connection = time::Instant::now();
    let mut time_first_byte: Option<time::Instant> = None;
    let mut sent_time_to_first_byte = false;
    let mut send_stream_id = 2;

    // Creation of the flexicast path.
    let mut added_mc_cid = false;
    let mut probe_mc_path = false;

    let mut mc_socket_opt: Option<mio::net::UdpSocket> = None;
    let mut joined_mc_ip = false;
    let mc_addr: SocketAddr = "0.0.0.0:4433".parse().unwrap();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let url = args.url.clone();
    let peer_addr = *url.socket_addrs(|| None).unwrap().first().unwrap();

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
    let mut config = get_config(&args);

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

    // Create the receiver application.
    let tx_app = match args.transfer_kind {
        TransferKind::File(file_transfer_kind) => {
            match file_transfer_kind {
                FileTransferKind::File(output_prefix) => {
                    let (tx_app, rx_app) = mpsc::channel(100);
                    // Create the application handler at the client.
                    let out_filename =
                        Path::new(url.path_segments().unwrap().last().unwrap());
                    let output_prefix = Path::new(&output_prefix);

                    let tmp_filename = if args.stay_open_on_fin {
                        // Path::new("tmp_filename.txt").into()
                        Path::new("/shared/tmp_filename.txt").into()
                    } else {
                        Path::new("/dev/shm").join(out_filename)
                    };
                    let mut fc_app = FileTransferRecv::new(
                        &output_prefix.join(out_filename),
                        rx_app,
                        &tmp_filename,
                    )
                    .unwrap();

                    tokio::spawn(async move {
                        fc_app.run().await.unwrap();
                    });

                    TxApp::File(tx_app)
                },

                _ => panic!(
                    "Receiver cannot have another file transfer kind than a file"
                ),
            }
        },

        TransferKind::Stream(stream_transfer_kind) => {
            let (tx_app, rx_app) = mpsc::channel(100);
            match stream_transfer_kind {
                StreamTransferKind::Hls(output_dir) => {
                    let mut fc_app = HlsSink::new(&output_dir, rx_app);
                    tokio::spawn(async move {
                        fc_app.run().await.unwrap();
                    });
                },

                StreamTransferKind::Rtp(sockaddr) => {
                    let mut fc_app =
                        RtpSink::new(rx_app, sockaddr).await.unwrap();
                    tokio::spawn(async move {
                        fc_app.run().await.unwrap();
                    });
                },
            }

            TxApp::Stream(tx_app)
        },
    };

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    socket.send_to(&out[..write], send_info.to).unwrap();

    loop {
        let timers = [
            conn.timeout(), /* QUIC timeout
                             * conn.mc_timeout(now),  // FC-QUIC timeout
                             * conn.rmc_timeout(now), // Reliable FC-QUIC
                             * timeout */
        ];
        let timeout = timers.iter().flatten().min().copied();

        poll.poll(&mut events, timeout).unwrap();

        // Let's see if we have to stop multicast.
        if let Ok(v) = socket_stop.try_recv(&mut buf[..]) {
            if buf[v] == 0 {
                stop_mc = true;
            } else {
                stop_mc = false;
            }
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'uc_read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                conn.on_timeout();

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

            trace!("Recv from socket unicast");
            uc_recv += 1;
            uc_recv_bytes += len;

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
                from_mc: false,
            };

            // Process potentially coalesced packets.
            let _read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'uc_read;
                },
            };

            // Only if we receive data (heuristic: more than 1000 bytes).
            if _read > 1000 && last_data_received_was_mc {
                if let Some(file) = fd_json.as_mut() {
                    let msg = format!(
                        "{{\"ts\": {},\"mode\": \"unicast\"}}\n",
                        time::SystemTime::now()
                            .duration_since(time::SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_millis()
                    );

                    let _ = file.write(msg.as_bytes());
                    last_data_received_was_mc = false;
                }
            }
        }

        // Read incomming UDP packets from the flexicast socket and feed them to
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

                // Do not process the packet if we say so.
                if stop_mc {
                    continue 'mc_read;
                }

                mc_recv += 1;
                mc_recv_bytes += len;
                trace!("Recv from socket multicast");

                let recv_info = quiche::RecvInfo {
                    to: mc_addr,
                    from: peer_addr,
                    from_mc: true,
                };

                // Only feed the packet to quiche if the client listens to the
                // flexicast channel.
                let err_opt =
                    if conn.get_flexicast_attributes().unwrap().get_mc_role() ==
                        McRole::Client(McClientStatus::ListenMcPath(true))
                    {
                        conn.recv(&mut buf[..len], recv_info)
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

                if !last_data_received_was_mc {
                    if let Some(file) = fd_json.as_mut() {
                        let msg = format!(
                            "{{\"ts\": {},\"mode\": \"multicast\"}}\n",
                            time::SystemTime::now()
                                .duration_since(time::SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_millis()
                        );

                        let _ = file.write(msg.as_bytes());
                    }
                    last_data_received_was_mc = true;
                }
            }
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
        }

        // Process Flexicast events.
        if conn.get_flexicast_attributes().is_some() && args.flexicast {
            // Join the flexicast channel and creates the listening socket if not
            // already done.
            if matches!(
                conn.get_flexicast_attributes().unwrap().get_mc_role(),
                McRole::Client(McClientStatus::AwareUnjoined) |
                    McRole::Client(McClientStatus::Changing)
            ) {
                debug!("Client joins the flexicast channel.");

                // Did not join the flexicast channel before.
                let flexicast = conn.get_flexicast_attributes().unwrap();
                let mc_announce_data = flexicast
                    .get_mc_announce_data(current_fc_idx)
                    .unwrap()
                    .to_owned();

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
                    let fc_path_id = conn.create_mc_path(
                        mc_addr,
                        peer_addr,
                        mc_announce_data.probe_path,
                    );
                    println!("Out of create mc path:{:?}", fc_path_id);
                    if let Ok(fc_path_id) = fc_path_id {
                        conn.fc_set_path_id(Some(fc_path_id)).unwrap();

                        // If soft-flexicast is used by the source, the client
                        // will receive flexicast QUIC
                        // packets with its unicast
                        // address as destination of the IP packet. Bind the
                        // socket to the local address
                        // with the flexicast destination
                        // port.
                        let mc_group_sockaddr: net::SocketAddr =
                            if mc_announce_data.probe_path {
                                let ip = socket.local_addr().unwrap().ip();
                                net::SocketAddr::new(
                                    ip,
                                    mc_announce_data.udp_port,
                                )
                            } else {
                                let group_ip = if args.proxy_uc {
                                    "0.0.0.0".parse().unwrap()
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

                        if let Some(sock) = mc_socket_opt.as_mut() {
                            poll.registry().deregister(sock).unwrap();
                        }

                        let mut mc_socket =
                            mio::net::UdpSocket::bind(mc_group_sockaddr).unwrap();
                        info!(
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
                        mc_socket_opt = Some(mc_socket);

                        conn.mc_join_channel(
                            false,
                            Some(&mc_announce_data.channel_id),
                        )
                        .unwrap();
                    }
                }
                added_mc_cid = true;
            }

            // Join the flexicast socket.
            if let Some(flexicast) = conn.get_flexicast_attributes() {
                if flexicast.get_mc_role() ==
                    McRole::Client(McClientStatus::ListenMcPath(true)) &&
                    !joined_mc_ip
                {
                    if !args.proxy_uc {
                        info!("Join MULTICAST");
                        mc_socket_opt
                            .as_mut()
                            .unwrap()
                            .join_multicast_v4(
                                &net::Ipv4Addr::from(
                                    flexicast
                                        .get_mc_announce_data(current_fc_idx)
                                        .unwrap()
                                        .group_ip
                                        .to_owned(),
                                ),
                                &args.local_ip,
                            )
                            .unwrap();
                    }
                    joined_mc_ip = true;
                }
            }
        }

        // Process all readable streams.
        'streams: for stream_id in conn.readable() {
            // if !conn.stream_fully_readable(stream_id) {
            //     continue 'streams;
            // }

            if !conn.stream_readable(stream_id) {
                continue 'streams;
            }

            // We should be able to read the stream until its end.
            while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf[..])
            {
                if time_first_byte.is_none() {
                    time_first_byte = Some(time::Instant::now());
                }

                total_read += read;
                info!(
                    "TOTAL READ: {total_read} because now incremented by {read}"
                );

                match &tx_app {
                    TxApp::File(tx) => {
                        let msg = FileTransferRecvMsg::Data((
                            buf[..read].to_vec(),
                            fin,
                            stream_id,
                        ));
                        tx.send(msg).await.unwrap();

                        if fin & !args.stay_open_on_fin {
                            let _ = conn.close(true, 0, &[0]);
                            nb_recv += 1;
                        }
                    },

                    TxApp::Stream(tx) => {
                        let msg = VideoSourceMsg::Data((
                            stream_id,
                            std::sync::Arc::new(buf[..read].to_vec()),
                            fin,
                        ));

                        tx.send(msg).await.unwrap();
                    },
                }
            }
        }

        // Stream data to send.
        // In this application we only send data for transport feedback metrics.
        if args.transport_feedback &&
            time_first_byte.is_some() &&
            !sent_time_to_first_byte
        {
            let data = format!(
                ":time-to-first-byte:{}",
                time_first_byte
                    .unwrap()
                    .duration_since(start_connection)
                    .as_millis()
            );
            match conn.stream_send(send_stream_id, data.as_str().as_bytes(), true)
            {
                Ok(v) if v == data.len() => {
                    send_stream_id += 4;
                    sent_time_to_first_byte = true;
                },

                _ => (),
            }
        }

        // Limit the number of packets we send in a single loop.
        let mut n_loop = 0;

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            n_loop += 1;
            if n_loop > 2 {
                break;
            }

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
            // The client may send packets on the flexicast channel for the path
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

            uc_send += 1;
            uc_send_bytes += write;
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Print the statistics.
        if time::Instant::now().duration_since(last_stat_print) >
            time::Duration::from_secs(1)
        {
            last_stat_print = time::Instant::now();

            println!("STATS: Bytes received:\n\tFlexicast flow: {} B ({} packets)\n\tUnicast path: {} B ({} packets)\nBytes sent: {} B ({} packets)\n", mc_recv_bytes, mc_recv, uc_recv_bytes, uc_recv, uc_send_bytes, uc_send);
        }
    }

    if let TxApp::File(tx) = &tx_app {
        let msg = FileTransferRecvMsg::Close;
        tx.send(msg).await.unwrap();
    }

    println!("RESULT-NB-STREAM-RECV {nb_recv}");
    println!("{} {} {}", mc_recv, uc_recv, uc_send);
}

fn get_config(args: &Args) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false); // Not prodction-ready.

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    if !args.flexicast {
        config.set_max_idle_timeout(100_000);
    }
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);

    let initial_max_data = match args.initial_flow_control {
        Some(v) => v,
        None => 100_000_000_000,
    };
    config.set_initial_max_data(initial_max_data);
    config.set_initial_max_stream_data_bidi_local(initial_max_data);
    config.set_initial_max_stream_data_bidi_remote(initial_max_data);
    config.set_initial_max_stream_data_uni(initial_max_data);
    config.set_initial_max_streams_bidi(initial_max_data);
    config.set_initial_max_streams_uni(initial_max_data);
    config.set_active_connection_id_limit(10);
    config.verify_peer(false);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::CUBIC);

    if args.flexicast {
        config.set_initial_max_path_id(10);
        config.set_enable_flexicast(args.flexicast);
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

enum TxApp {
    File(mpsc::Sender<FileTransferRecvMsg>),

    Stream(mpsc::Sender<VideoSourceMsg>),
}
