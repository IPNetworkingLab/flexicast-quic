#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::net;
use std::path::Path;

use clap::Parser;
use quiche::multicast;
use quiche::multicast::authentication::McAuthType;
use quiche::multicast::reliable::ReliableMulticastConnection;
use quiche::multicast::McAnnounceData;
use quiche::multicast::McClientTp;
use quiche::multicast::McConfig;
use quiche::multicast::MulticastChannelSource;
use quiche::multicast::MulticastConnection;
use quiche::on_rmc_timeout_server;
use quiche::ucs_to_mc_cwnd;
use quiche_apps::common::ClientIdMap;
use quiche_apps::sendto::send_to;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

const MAX_DATAGRAM_SIZE: usize = 1350;

struct Client {
    conn: quiche::Connection,
    client_id: u64,
    active_client: bool, // TODO: define what it is?
    listen_fc_channel: bool,
}

type ClientMap = HashMap<u64, Client>;

#[derive(Parser)]
struct Args {
    /// Activate flexicast extension.
    #[clap(long)]
    flexicast: bool,

    /// Path to the directory containing the files for the transfer.
    #[clap(long)]
    root: Box<Path>,

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

    /// Disable the congestion control for the multicast channel. In practice,
    /// set the congestion window of the multicast channel to the maximum value.
    #[clap(long = "disable-cc")]
    disable_cc: bool,

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

    /// File path to read and transmit through HTTP/3.
    ///
    /// FC-TODO: This should be updated if we want to deliver different files at
    /// the same time.
    #[clap(long = "file")]
    file: Box<String>,
}

fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    let mut nb_active_fc_clients = 0;

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
    let h3_config = quiche::h3::Config::new().unwrap();

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();
    let mut clients_ids = ClientIdMap::new();
    let mut next_client_id = 0;

    let local_addr = socket.local_addr().unwrap();

    let (mut mc_socket_opt, mut mc_channel_opt, mut mc_announce_dta_opt) =
        if args.flexicast {
            get_multicast_channel(&args, &rng)
        } else {
            (None, None, None)
        };

    #[cfg(feature = "qlog")]
    if let Some(mc_channel) = mc_channel_opt.as_mut() {
        // Only bother with qlog if the user specified it.
        {
            if let Some(dir) = std::env::var_os("QLOGDIR") {
                let id = format!("MCS");
                let writer = make_qlog_writer(&dir, "server", &id);

                mc_channel.channel.set_qlog(
                    std::boxed::Box::new(writer),
                    "quiche-server qlog".to_string(),
                    format!("{} id={}", "quiche-server qlog", id),
                );
            }
        }
    }

    debug!("AFTER MULTICAST CHANNEL SETUP");

    if let Some(mc_socket) = mc_socket_opt.as_mut() {
        // Register multicast socket to the poll.
        poll.registry()
            .register(mc_socket, mio::Token(1), mio::Interest::READABLE)
            .unwrap();
    }

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let now = std::time::Instant::now();
        let mut timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        // FC-TODO: application timeout and timeout when the application did not
        // start.
        if let Some(mc_channel) = mc_channel_opt.as_ref() {
            let mc_timeout = mc_channel.channel.mc_timeout(now);
            timeout = [timeout, mc_timeout].iter().flatten().min().copied();
        }

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'uc_read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
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
                    active_client: false,
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

                // Add the multicast channel announcement for the new client.
                if let (Some(mc_announce_data), Some(mc_channel)) =
                    (mc_announce_dta_opt.as_ref(), mc_channel_opt.as_ref())
                {
                    // Only advertise the MC_ANNOUNCE data directly to the clients
                    // if no dymanic scaling (i.e., creation of the multicast
                    // group when enough receivers are connected).
                    client
                        .conn
                        .mc_set_mc_announce_data(mc_announce_data)
                        .unwrap();
                    client
                        .conn
                        .mc_set_multicast_receiver(
                            &mc_channel.master_secret,
                            mc_channel
                                .channel
                                .get_multicast_attributes()
                                .unwrap()
                                .get_mc_space_id()
                                .unwrap(),
                            mc_channel
                                .channel
                                .get_multicast_attributes()
                                .unwrap()
                                .get_decryption_key_algo(),
                        )
                        .unwrap();
                }

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

            // FC-TODO: process readable streams?

            // FC-TODO: consider the client as active if either (1) it listens to
            // unicast and connection is established or (2) it listens to
            // flexicast and the flexicast path is active.
            // FC-TODO: start the content delivery when all intended clients
            // joined the channel.

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
        if let Some(mc_channel) = mc_channel_opt.as_mut() {
            // Before expiring the data, deleguate to unicast connections if
            // reliable multicast is enabled.
            let clients_conn = clients.iter_mut().map(|c| &mut c.1.conn);
            on_rmc_timeout_server!(&mut mc_channel.channel, clients_conn, now)
                .unwrap();
            let expired_pkt = mc_channel.channel.on_mc_timeout(now).unwrap();
            if expired_pkt.pn.is_some() {
                // FC-TODO: On application expiring.
            }
        }

        // Send as much application data as possible.
        // FC-TODO.

        // For each client, try to send as much stream data as
        // possible.
        // FC-TODO.

        // Generate outgoing Flexicast QUIC packets for the flexicast channel.
        if let (Some(mc_socket), Some(mc_channel)) =
            (mc_socket_opt.as_mut(), mc_channel_opt.as_mut())
        {
            'flexicast: loop {
                let (write, mut send_info) = match mc_channel.mc_send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => break,

                    Err(e) => {
                        error!("Flexicast out failed: {:?}", e);
                        break 'flexicast;
                    },
                };

                // The source may send to the proxy its content instead of
                // injecting in the multicast network.
                send_info.to = args.proxy_addr.unwrap_or(mc_channel.mc_send_addr);

                let err = send_to(
                    mc_socket,
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

                debug!("Flexicast written {} bytes to {:?}", write, send_info);
            }
        }

        // Generate outgoing QUIC packets for all active connections and
        // send them on the UDP socket, until quiche
        // reports that there are no more packets to be sent.
        for client in clients.values_mut() {
            // FC-TODO: check if can close the connection.
            // FC-TODO: close the connection if possible.

            'uc_send: loop {
                // Communication between the unicast and flexicast channels.
                if let Some(mc_channel) = mc_channel_opt.as_mut() {
                    client
                        .conn
                        .uc_to_mc_control(&mut mc_channel.channel, now)
                        .unwrap();
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
            if let Some(mc_channel) = mc_channel_opt.as_mut() {
                client
                    .conn
                    .uc_to_mc_control(&mut mc_channel.channel, now)
                    .unwrap();
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
            }

            !c.conn.is_closed()
        });
        clients_ids.retain(|_, id| clients.contains_key(id));

        // Set the congestion window of the multicast channel.
        if let Some(mc_channel) = mc_channel_opt.as_mut() {
            let clients_conn = clients.iter_mut().map(|c| &mut c.1.conn);
            if args.disable_cc {
                mc_channel.channel.mc_set_cwnd(usize::MAX - 2);
            } else {
                ucs_to_mc_cwnd!(&mut mc_channel.channel, clients_conn, now, None);
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
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(1_000_000);
    config.set_initial_max_streams_uni(1_000_000);
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

fn get_multicast_channel(
    args: &Args, rng: &SystemRandom,
) -> (
    Option<mio::net::UdpSocket>,
    Option<MulticastChannelSource>,
    Option<McAnnounceData>,
) {
    let mc_addr = args.mc_addr;
    let mc_addr_bytes = match mc_addr {
        net::SocketAddr::V4(ip) => ip.ip().octets(),
        _ => unreachable!("Only support IPv4 multicast addresses"),
    };
    let mc_port = mc_addr.port();
    let socket = mio::net::UdpSocket::bind(args.mc_addr).unwrap();
    socket.set_multicast_ttl_v4(56).unwrap();

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
        local: args.mc_addr,
        peer: args.mc_addr,
        cid: channel_id,
    };

    let mut mc_channel = MulticastChannelSource::new_with_tls(
        mc_path_info,
        &mut server_config,
        &mut client_config,
        mc_addr,
        args.fc_keylog_file.as_ref().to_str().unwrap(),
        args.authentication,
        None,
        None,
    )
    .unwrap();

    let mc_announce_data = McAnnounceData {
        channel_id: channel_id_vec,
        path_type: multicast::McPathType::Data,
        auth_type: args.authentication,
        is_ipv6: false,
        full_reliability: true,
        source_ip: [127, 0, 0, 1],
        group_ip: mc_addr_bytes,
        udp_port: mc_port,
        public_key: mc_channel
            .channel
            .get_multicast_attributes()
            .unwrap()
            .get_mc_pub_key()
            .map(|i| i.to_vec()),
        expiration_timer: args.expiration_timer,
        is_processed: false,
    };

    mc_channel
        .channel
        .mc_set_mc_announce_data(&mc_announce_data)
        .unwrap();

    (Some(socket), Some(mc_channel), Some(mc_announce_data))
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
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(1_000_000);
    config.set_initial_max_streams_uni(1_000_000);
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
    config.set_real_time(true);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::DISABLED);
    config.set_fec_symbol_size(1280 - 64); // MC-TODO: make dynamic with auth.
    config.set_fec_window_size(2000);
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
