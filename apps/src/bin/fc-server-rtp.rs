#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::net;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::path::Path;

use clap::Parser;
use quiche::multicast;
use quiche::multicast::authentication::McAuthType;
use quiche::multicast::reliable::ReliableMulticastConnection;
use quiche::multicast::FcConfig;
use quiche::multicast::McAnnounceData;
use quiche::multicast::McClientTp;
use quiche::multicast::McConfig;
use quiche::multicast::McRole;
use quiche::multicast::MulticastChannelSource;
use quiche::multicast::MulticastConnection;
use quiche::on_rmc_timeout_server;
use quiche::ucs_to_mc_cwnd;
#[cfg(feature = "qlog")]
use quiche_apps::common::make_qlog_writer;
use quiche_apps::common::ClientIdMap;
use quiche_apps::mc_app::rtp::RtpServer;
use quiche_apps::sendto::send_to;

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

const MAX_DATAGRAM_SIZE: usize = 1350;
const RTP_SOCKET_TOKEN: mio::Token = mio::Token(1);

struct Client {
    conn: quiche::Connection,
    client_id: u64,
    listen_fc_channel: bool,
}

type ClientMap = HashMap<u64, Client>;

#[derive(Parser)]
struct Args {
    /// Activate flexicast extension.
    #[clap(long)]
    flexicast: bool,

    /// Keylog file for flexicast channel.
    #[clap(long = "keylog", value_parser, default_value = "/tmp/fc-server.txt")]
    fc_keylog_file: Box<Path>,

    /// Flexicast source authentication method.
    #[clap(long = "auth", default_value = "none")]
    authentication: McAuthType,

    /// Wait that the indicated number of clients are ready to receive the data.
    /// If flexicast is enabled, waits for flexicast channel establishement.
    /// If unicast is used, waits for the connections to be established.
    #[clap(long = "wait", value_parser)]
    wait_clients: Option<u32>,

    /// Source address of the server.
    #[clap(long = "src", default_value = "127.0.0.1:4433")]
    src_addr: net::SocketAddr,

    /// Certificate path.
    #[clap(long = "cert-path", value_parser, default_value = "./src/bin")]
    cert_path: Box<Path>,

    /// Whether the multicast packet is proxied. In this case, the provided
    /// address will receive the multicast packet to transmit.
    #[clap(long = "proxy")]
    proxy_addr: Option<net::SocketAddr>,

    /// Multicast address.
    #[clap(
        long = "mc-addr",
        value_parser,
        default_value = "239.239.239.35:4434"
    )]
    mc_addr: net::SocketAddr,

    /// FEC max repair symbols within an expiration timer.
    #[clap(long = "max-fec-rs", value_parser)]
    max_fec_rs: Option<u32>,

    /// Expiration timer on the flexicast path.
    #[clap(long, value_parser, default_value = "600")]
    expiration_timer: u64,

    /// Sent video frames results (timestamps sent on the wire).
    #[clap(
        short = 'r',
        long,
        value_parser,
        default_value = "mc-server-result-wire.txt"
    )]
    result_wire_trace: String,

    /// Keylog file for multicast channel.
    #[clap(
        short = 'k',
        long,
        value_parser,
        default_value = "/tmp/mc-server.txt"
    )]
    mc_keylog_file: String,

    /// Sets the flexicast source congestion window to a fixed value.
    #[clap(long = "fc-cwnd")]
    fc_cwnd: Option<usize>,

    /// List of bitrates of the flexicast channels.
    /// If this parameter is used with `n` values, it means that `n` flexicast
    /// channels will be created, each with the values given as argument as the
    /// bitrate of the channel. Incomming clients will be aware of every
    /// channels through MC_ANNOUNCE frames and will be able to choose one of
    /// the channels depending on the advertised bitrate. The bitrate is in
    /// bits per second.
    #[clap(long = "bitrates", value_delimiter = ',', num_args=1..)]
    bitrates: Option<Vec<u64>>,

    /// Address of the RTP source.
    #[clap(long = "rtp-addr", value_parser)]
    rtp_src_addr: SocketAddr,

    /// RTP message to indicate the end of the stream.
    #[clap(long = "rtp-stop", value_parser, default_value = "STOP RTP")]
    rtp_stop: String,
}

fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    let mut nb_active_fc_clients = None;

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket = mio::net::UdpSocket::bind(args.src_addr).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = get_config(&args);

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();
    let mut clients_ids = ClientIdMap::new();
    let mut next_client_id = 0;
    let local_addr = socket.local_addr().unwrap();

    // List of all flexicast channels with different bitrates.
    // If no bitrate is provided (i.e., the `bitrates` parameter is not used),
    // creates a single flexicast channel with the classical implemented
    // congestion control algorithm.
    let mut fc_channels = if args.flexicast {
        if let Some(bitrates) = args.bitrates.as_ref() {
            (0..bitrates.len() as u8)
                .map(|i| get_multicast_channel(&args, &rng, Some(i)))
                .collect()
        } else {
            vec![get_multicast_channel(&args, &rng, None)]
        }
    } else {
        Vec::new() // Empty.
    };

    // Compute the mapping between Flexicast channel ID and index.
    let _fcid_to_idx: HashMap<Vec<u8>, usize> = fc_channels
        .iter()
        .enumerate()
        .map(|(i, fc_chan)| (fc_chan.mc_announce_data.channel_id.to_owned(), i))
        .collect();

    debug!("AFTER FLEXICAST CHANNELS SETUP.");

    // Register the flexicast sockets on the poll.
    // FC-TODO: is it really necessary as we only send data on it?
    for (i, fc_chan) in fc_channels.iter_mut().enumerate() {
        poll.registry()
            .register(&mut fc_chan.socket, mio::Token(i), mio::Interest::READABLE)
            .unwrap();
    }

    // Register RTP source handler.
    let mut rtp_server = RtpServer::new(
        args.rtp_src_addr,
        &args.result_wire_trace,
        &args.result_wire_trace,
        &args.rtp_stop,
    )
    .unwrap();

    // Register the RTP source socket.
    if let Some(add_socket) = rtp_server.additional_udp_socket() {
        poll.registry().register(add_socket, RTP_SOCKET_TOKEN, mio::Interest::READABLE).unwrap();
    }

    // Stop RTP timer.
    // Once the RTP source sends a STOP RTP message, the source waits for 5 * flexicast timer before closing the connection.
    let rtp_stop_timer = std::time::Duration::from_millis(args.expiration_timer) * 5;
    let mut start_rtp_timer: Option<std::time::Instant> = None;
    let mut can_close_conn_after_rtp = false;

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let now = std::time::Instant::now();
        let mut timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        // Timeout of all flexicast channels.
        let timeout_fc = fc_channels
            .iter()
            .map(|fc_chan| fc_chan.fc_chan.channel.mc_timeout(now))
            .flatten()
            .min();

        // Timeout after the RTP source finished.
        let timeout_rtp = start_rtp_timer.map(|timer| rtp_stop_timer.saturating_sub(now.duration_since(timer)));

        timeout = [timeout, timeout_fc, rtp_server.next_timeout(), timeout_rtp].iter().flatten().min().copied();

        debug!("TIMEOUT: {:?}", timeout);

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'uc_read: loop {
            // Received content on the RTP source socket.
            for event in events.iter() {
                if event.token() == RTP_SOCKET_TOKEN {
                    rtp_server.on_additional_udp_socket_readable();

                    if rtp_server.is_source_rtp_stopped() && start_rtp_timer.is_none() {
                        debug!("Start RTP end timer");
                        start_rtp_timer = Some(std::time::Instant::now());
                    }
                }
            }

            // We can close the connection now.
            if let Some(timer) = start_rtp_timer {
                if rtp_stop_timer.saturating_sub(now.duration_since(timer)) == std::time::Duration::ZERO {
                    // Yes, we can close now...
                    can_close_conn_after_rtp = true;

                    // Empty the timer to avoid going over and over here.
                    start_rtp_timer = None;
                }
            }

            let contains_quic_socket_event = events.iter().any(|e| e.token() != RTP_SOCKET_TOKEN);

            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if !contains_quic_socket_event {
                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'uc_read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so send the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break 'uc_read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(pkt_buf, 16) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'uc_read;
                },
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..16];

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients_ids.contains_key(&hdr.dcid) &&
                !clients_ids.contains_key(&hdr.dcid)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'uc_read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'uc_read;
                }

                let mut scid = [0; 16];
                scid.copy_from_slice(conn_id);

                let scid = quiche::ConnectionId::from_ref(&scid);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'uc_read;
                }

                let odcid = validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'uc_read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'uc_read;
                }

                // Reuse the source connection ID we sent in the Retry packet,
                // instead of changing it again.
                let scid = hdr.dcid.clone();

                let conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                let client_id = next_client_id;

                let client = Client {
                    conn,
                    client_id,
                    listen_fc_channel: false,
                };

                next_client_id += 1;
                clients.insert(client_id, client);
                clients_ids.insert(scid.clone(), client_id);

                debug!(
                    "New connection: dcid={:?} scid={:?}. Client id: {}",
                    hdr.dcid, scid, client_id
                );

                let client = clients.get_mut(&client_id).unwrap();

                // Only bother with qlog if the user specified it.
                #[cfg(feature = "qlog")]
                {
                    if let Some(dir) = std::env::var_os("QLOGDIR") {
                        let id = format!("server-{:?}", client_id);
                        let writer = make_qlog_writer(&dir, "server", &id);

                        client.conn.set_qlog(
                            std::boxed::Box::new(writer),
                            "quiche-server qlog".to_string(),
                            format!("{} id={}", "quiche-server qlog", id),
                        );
                    }
                }

                for (i, fc_chan) in fc_channels.iter().enumerate() {
                    client
                        .conn
                        .mc_set_mc_announce_data(
                            &fc_chan.mc_announce_data,
                        )
                        .unwrap();
                    // FC-TODO: not sure that this will work if it
                    // replaces the decryption key everytime we
                    // add a new one :/. We should see this in the
                    // tests but it actually works... lol.
                    client
                        .conn
                        .mc_set_multicast_receiver(
                            &fc_chan.fc_chan.master_secret,
                            fc_chan
                                .fc_chan
                                .channel
                                .get_multicast_attributes()
                                .unwrap()
                                .get_mc_space_id()
                                .unwrap(),
                            fc_chan
                                .fc_chan
                                .channel
                                .get_multicast_attributes()
                                .unwrap()
                                .get_decryption_key_algo(),
                            Some(i),
                        )
                        .unwrap();
                }

                client
            } else {
                let cid = match clients_ids.get(&hdr.dcid) {
                    Some(v) => v,

                    None => clients_ids.get(&hdr.scid).unwrap(),
                };

                clients.get_mut(cid).unwrap()
            };

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
                from_mc: None,
            };

            // Process potentially coalesced packets.
            let _read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'uc_read;
                },
            };

            // Sets the client listens to the flexicast channel.
            if !client.listen_fc_channel &&
                client
                    .conn
                    .get_multicast_attributes()
                    .map(|mc| {
                        matches!(
                            mc.get_mc_role(),
                            McRole::ServerUnicast(
                                multicast::McClientStatus::ListenMcPath(true),
                            )
                        )
                    })
                    .unwrap_or(false)
            {
                client.listen_fc_channel = true;
                nb_active_fc_clients =
                    Some(nb_active_fc_clients.unwrap_or(0) + 1);
            }

            handle_path_events(client);

            // Provides as many CIDs as possible.
            while client.conn.source_cids_left() > 0 {
                let (scid, reset_token) = {
                    let mut scid = [0; 16];
                    rng.fill(&mut scid).unwrap();
                    let scid = scid.to_vec().into();
                    let mut reset_token = [0; 16];
                    rng.fill(&mut reset_token).unwrap();
                    let reset_token = u128::from_be_bytes(reset_token);
                    (scid, reset_token)
                };
                if client
                    .conn
                    .new_source_cid(&scid, reset_token, false)
                    .is_err()
                {
                    break;
                }
                info!("add a new source cid: {:?}", scid.as_ref());
                clients_ids.insert(scid, client.client_id);
            }
        }

        // Handle time to live timeout of data of the multicast channel.
        let now = std::time::Instant::now();
        for fc_chan in fc_channels.iter_mut() {
            // Before expiring the data, deleguate to unicast connections if
            // reliable multicast is enabled.
            let clients_conn = clients.iter_mut().map(|c| &mut c.1.conn);
            on_rmc_timeout_server!(
                &mut fc_chan.fc_chan.channel,
                clients_conn,
                now
            )
            .unwrap();
            let _expired_pkt =
                fc_chan.fc_chan.channel.on_mc_timeout(now).unwrap();
        }

        // Generate video content frames.
        // Repeat to ensure to dequeue all pending streams if needed.
        'app_data: loop {
            if rtp_server.should_send_app_data() {
                let (stream_id, app_data) = rtp_server.get_app_data();
                if let Some(fc_chan) = fc_channels.get_mut(0) {
                    match fc_chan.fc_chan.channel.stream_priority(stream_id, 0, false) {
                        Ok(()) => (),
                        Err(quiche::Error::StreamLimit) => (),
                        Err(quiche::Error::Done) => (),
                        Err(e) => panic!("Error while setting stream priority: {:?}", e),
                    }
    
                    let written = match fc_chan.fc_chan.channel.stream_send(stream_id, &app_data, true) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => break 'app_data,
                        Err(e) => panic!("Other error: {:?}", e),
                    };
    
                    rtp_server.stream_written(written);
                }
            } else {
                break 'app_data;
            }
        }

        // Generate outgoing Flexicast QUIC packets for each flexicast channel.
        for fc_chan in fc_channels.iter_mut() {
            let fc_conn = &mut fc_chan.fc_chan;
            let fc_sock = &mut fc_chan.socket;
            'flexicast: loop {
                let (write, mut send_info) = match fc_conn.mc_send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => break,

                    Err(e) => {
                        error!("Flexicast out failed: {:?}", e);
                        break 'flexicast;
                    },
                };

                // The source may send to the proxy its content instead of
                // injecting in the multicast network.
                send_info.to = args.proxy_addr.unwrap_or(fc_conn.mc_send_addr);

                if nb_active_fc_clients >= Some(1) {
                    let err = send_to(
                        fc_sock,
                        &out[..write],
                        &send_info,
                        MAX_DATAGRAM_SIZE,
                        false,
                        false,
                    );
                    if let Err(e) = err {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("mc_send() would block");
                            break 'flexicast;
                        }

                        panic!("mc_send() failed: {:?}", e);
                    }
                    debug!(
                        "Flexicast written {} bytes to {:?}",
                        write, send_info
                    );
                } else {
                    debug!("not actually sending on the wire for flexicast");
                }
            }
        }

        // Generate outgoing QUIC packets for all active connections and
        // send them on the UDP socket, until quiche
        // reports that there are no more packets to be sent.
        for client in clients.values_mut() {
            // Close the connections with the clients whether RTP is finished and we waited enough.
            if can_close_conn_after_rtp {
                info!("Closing connection {:?}", client.conn.trace_id());
                _ = client.conn.close(true, 1, &[1]);
            }

            'uc_send: loop {
                // Communication between the unicast and flexicast channels.
                // FC-TODO: use here the index to determine on which flexicast
                // instance is attached the client. Currently uses
                // the index 0, if it exists.
                if let Some(fc_chan) = fc_channels.get_mut(0) {
                    match client
                        .conn
                        .uc_to_mc_control(&mut fc_chan.fc_chan.channel, now)
                    {
                        Ok(()) => (),
                        Err(quiche::Error::Multicast(
                            quiche::multicast::McError::McDisabled,
                        )) => debug!("uc_to_mc_control with flexicast disabled"),
                        Err(e) => panic!("error: {:?}", e),
                    }
                }

                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => break 'uc_send,

                    Err(e) => {
                        error!("{} send failed: {:}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break 'uc_send;
                    },
                };

                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send() would block");
                        break 'uc_send;
                    }

                    panic!("send() failed: {:?}", e);
                }

                debug!("{} written {} bytes", client.conn.trace_id(), write);
            }

            // Communication between the unicast and flexicast channels.
            // FC-TODO: use here the index to determine on which flexicast
            // instance is attached the client. Currently uses the
            // index 0, if it exists.
            if let Some(fc_chan) = fc_channels.get_mut(0) {
                match client
                    .conn
                    .uc_to_mc_control(&mut fc_chan.fc_chan.channel, now)
                {
                    Ok(()) => (),
                    Err(quiche::Error::Multicast(
                        quiche::multicast::McError::McDisabled,
                    )) => debug!("uc_to_mc_control with flexicast disabled"),
                    Err(e) => panic!("error: {:?}", e),
                }
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                );
                if nb_active_fc_clients.is_some() {
                    nb_active_fc_clients =
                        Some(nb_active_fc_clients.unwrap() - 1);
                }
            }

            !c.conn.is_closed()
        });
        clients_ids.retain(|_, id| clients.contains_key(id));

        // Set the congestion window for each flexicast channel.
        for (i, fc_chan) in fc_channels.iter_mut().enumerate() {
            if let Some(ref bitrates) = args.bitrates {
                // Set the bitrate of each channel accordingly.
                fc_chan.fc_chan.channel.mc_set_cwnd(
                    (bitrates[i] /
                        (8 * fc_chan.mc_announce_data.expiration_timer))
                        as usize,
                );
            } else {
                // Rely on the congestion control.
                let clients_conn = clients.iter_mut().map(|c| &mut c.1.conn);
                ucs_to_mc_cwnd!(
                    &mut fc_chan.fc_chan.channel,
                    clients_conn,
                    now,
                    None
                );
            }
        }

        // Stop sending data if all clients left the communication.
        if let Some(nb) = nb_active_fc_clients {
            if nb == 0 {
                break;
            }
        }
    }
}

fn get_config(args: &Args) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file(
            Path::new(args.cert_path.as_ref())
                .join("cert.crt")
                .to_str()
                .unwrap(),
        )
        .unwrap();
    config
        .load_priv_key_from_pem_file(
            Path::new(args.cert_path.as_ref())
                .join("cert.key")
                .to_str()
                .unwrap(),
        )
        .unwrap();

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(100_000_000_000);
    config.set_initial_max_stream_data_bidi_local(100_000_000_000);
    config.set_initial_max_stream_data_bidi_remote(100_000_000_000);
    config.set_initial_max_stream_data_uni(100_000_000_000);
    config.set_initial_max_streams_bidi(100_000_000_000);
    config.set_initial_max_streams_uni(100_000_000_000);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(5);
    config.enable_early_data();
    config.set_real_time(true);
    if args.flexicast {
        config.set_multipath(true);
        config.set_enable_server_multicast(true);
        config.set_fec_window_size(2000);
    }
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::CUBIC);
    config.enable_pacing(false);

    config
}

struct FcChannelInfo {
    socket: mio::net::UdpSocket,
    fc_chan: MulticastChannelSource,
    mc_announce_data: McAnnounceData,
}

fn get_multicast_channel(
    args: &Args, rng: &SystemRandom, fc_conn_idx: Option<u8>,
) -> FcChannelInfo {
    // Index of the flexicast channel.
    let idx_addr = fc_conn_idx.unwrap_or(0);

    // Source address.
    let mut src_addr = args.src_addr;
    src_addr.set_port(4434 + idx_addr as u16);

    // Multicast destination address.
    // We increase the address and port depending on the index of the channel.
    let mc_addr = args.mc_addr;
    let mc_addr_bytes = match mc_addr {
        net::SocketAddr::V4(ip) => {
            let mut bytes = ip.ip().octets();
            bytes[3] += idx_addr;
            bytes
        },
        _ => unreachable!("Only support IPv4 multicast addresses"),
    };
    let mc_addr = net::SocketAddr::V4(SocketAddrV4::new(
        mc_addr_bytes.into(),
        mc_addr.port() + idx_addr as u16,
    ));
    let mc_port = mc_addr.port();

    let socket = mio::net::UdpSocket::bind(src_addr).unwrap();
    socket.set_multicast_ttl_v4(56 + idx_addr as u32).unwrap();

    let mc_client_tp = McClientTp::default();
    let mut server_config = get_mc_config(
        true,
        None,
        true,
        args.cert_path.as_ref().to_str().unwrap(),
        args.max_fec_rs,
    );
    let mut client_config = get_mc_config(
        false,
        Some(&mc_client_tp),
        true,
        args.cert_path.as_ref().to_str().unwrap(),
        None,
    );

    // Generate a random source connection ID for the connection.
    let mut channel_id = [0; 16];
    rng.fill(&mut channel_id[..]).unwrap();

    let channel_id = quiche::ConnectionId::from_ref(&channel_id);
    let channel_id_vec = channel_id.as_ref().to_vec();

    let mc_path_info = multicast::McPathInfo {
        local: src_addr,
        peer: src_addr,
        cid: channel_id,
    };

    let fc_config = FcConfig {
        authentication: args.authentication,
        use_fec: true,
        probe_mc_path: true,
        mc_cwnd: args.fc_cwnd,
        ..Default::default()
    };

    let mut fc_chan = MulticastChannelSource::new_with_tls(
        mc_path_info,
        &mut server_config,
        &mut client_config,
        mc_addr,
        args.fc_keylog_file.as_ref().to_str().unwrap(),
        None,
        &fc_config,
    )
    .unwrap();

    let mc_announce_data = McAnnounceData {
        channel_id: channel_id_vec,
        path_type: multicast::McPathType::Data,
        auth_type: args.authentication,
        is_ipv6: true,
        full_reliability: true,
        source_ip: [127, 0, 0, 1],
        group_ip: mc_addr_bytes,
        udp_port: mc_port,
        public_key: fc_chan
            .channel
            .get_multicast_attributes()
            .unwrap()
            .get_mc_pub_key()
            .map(|i| i.to_vec()),
        expiration_timer: args.expiration_timer,
        is_processed: false,
        bitrate: None,
        fc_channel_algo: None,
        fc_channel_secret: None,
    };

    fc_chan
        .channel
        .mc_set_mc_announce_data(&mc_announce_data)
        .unwrap();

    FcChannelInfo {
        socket,
        fc_chan,
        mc_announce_data,
    }
}

pub fn get_mc_config(
    mc_server: bool, mc_client: Option<&McClientTp>, use_fec: bool,
    cert_path: &str, max_fec_rs: Option<u32>,
) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file(
            Path::new(cert_path).join("cert.crt").to_str().unwrap(),
        )
        .unwrap();
    config
        .load_priv_key_from_pem_file(
            Path::new(cert_path).join("cert.key").to_str().unwrap(),
        )
        .unwrap();
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    // let use_fec = false;
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(100_000_000_000);
    config.set_initial_max_stream_data_bidi_local(100_000_000_000);
    config.set_initial_max_stream_data_bidi_remote(100_000_000_000);
    config.set_initial_max_stream_data_uni(100_000_000_000);
    config.set_initial_max_streams_bidi(100_000_000_000);
    config.set_initial_max_streams_uni(100_000_000_000);
    config.set_active_connection_id_limit(5);
    config.verify_peer(false);
    config.set_multipath(true);
    config.set_enable_server_multicast(mc_server);
    config.set_enable_client_multicast(mc_client);
    config.send_fec(use_fec);
    config.receive_fec(use_fec);
    config.set_mc_max_nb_repair_symbols(max_fec_rs);
    config.set_fec_scheduler_algorithm(
        quiche::FECSchedulerAlgorithm::RetransmissionFec,
    );
    config.enable_pacing(false);
    config.set_real_time(false);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::DISABLED);
    config.set_fec_symbol_size(1280 - 64); // MC-TODO: make dynamic with auth.
    config.set_fec_window_size(50_000);
    config
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

fn handle_path_events(client: &mut Client) {
    while let Some(qe) = client.conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(local_addr, peer_addr) => {
                info!(
                    "{} Seen new path ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );

                // Directly probe the new path.
                client
                    .conn
                    .probe_path(local_addr, peer_addr)
                    .map_err(|e| error!("cannot probe: {}", e))
                    .ok();
            },

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now validated",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
                if client.conn.is_multipath_enabled() {
                    client
                        .conn
                        .set_active(local_addr, peer_addr, true)
                        .map_err(|e| error!("cannot set path active: {}", e))
                        .ok();
                }
            },

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) failed validation",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::Closed(local_addr, peer_addr, err, reason) => {
                info!(
                    "{} Path ({}, {}) is now closed and unusable; err = {} reason = {:?}",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr,
                    err,
                    reason,
                );
            },

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    client.conn.trace_id(),
                    cid_seq,
                    old,
                    new
                );
            },

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                info!(
                    "{} Connection migrated to ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::PeerPathStatus(addr, path_status) => {
                info!("Peer asks status {:?} for {:?}", path_status, addr,);
                client
                    .conn
                    .set_path_status(addr.0, addr.1, path_status, false)
                    .map_err(|e| error!("cannot follow status request: {}", e))
                    .ok();
            },
        }
    }
}
