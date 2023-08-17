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

use std::collections::VecDeque;
use std::io;
use std::net;
use std::path::Path;
use std::rc::Rc;

use quiche::multicast;
use quiche::multicast::authentication::McAuthType;
use quiche::multicast::authentication::McSymAuth;
use quiche::multicast::McAnnounceData;
use quiche::multicast::McConfig;
use quiche::multicast::McPathType;
use quiche::multicast::MulticastChannelSource;
use quiche::multicast::MulticastClientTp;
use quiche::multicast::MulticastConnection;
use quiche::multicast::MulticastRole;
use quiche::SendInfo;
use quiche::multicast::reliable::ReliableMulticastConnection;
use quiche::on_rmc_timeout_server;
use quiche_apps::common::ClientIdMap;
use quiche_apps::mc_app;
use quiche_apps::sendto::*;
use std::time;
use std::collections::HashMap;
use std::io::Write;

use clap::Parser;
use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

struct Client {
    conn: quiche::Connection,
    soft_mc_addr: net::SocketAddr,
    soft_mc_addr_auth: net::SocketAddr,
    client_id: u64,
    active_client: bool,
    stream_buf: VecDeque<(u64, usize, Rc<Vec<u8>>)>,
    mc_client_listen_uc: bool,
}

type ClientMap = HashMap<u64, Client>;

#[derive(Parser)]
struct Args {
    /// Activate multicast extension.
    #[clap(short = 'm', long)]
    multicast: bool,

    /// Multicast application.
    /// Choices are: tixeo, file.
    #[clap(long = "app", default_value = "tixeo")]
    app: mc_app::McApp,

    /// File to transfer.
    /// For Tixeo, this is the trace of the video.
    /// For the file transfer, this is the file to send to the clients.
    #[clap(short = 'f', long = "file", value_parser)]
    filepath: Option<String>,

    /// Sent video frames results (timestamps sent on the wire).
    #[clap(
        short = 'r',
        long,
        value_parser,
        default_value = "mc-server-result-wire.txt"
    )]
    result_wire_trace: String,

    /// Sent video frames results (timestamps sent to QUIC).
    #[clap(
        short = 'q',
        long,
        value_parser,
        default_value = "mc-server-result-quic.txt"
    )]
    result_quic_trace: String,

    /// Keylog file for multicast channel.
    #[clap(
        short = 'k',
        long,
        value_parser,
        default_value = "/tmp/mc-server.txt"
    )]
    mc_keylog_file: String,

    /// Multicast source authentication.
    /// Choices are: asymmetric, symmetric, none.
    /// This argument is read only if multicast is enabled.
    /// Default is `none`.
    #[clap(short = 'a', long, default_value = "none")]
    authentication: McAuthType,

    /// Number of video frames to send. Used to shorten the trace.
    #[clap(short = 'n', long, value_parser)]
    nb_frames: Option<u64>,

    /// Delay between packets in case no trace is replayed and the source sends
    /// manual data. In ms.
    #[clap(short = 'd', long, value_parser, default_value = "1000")]
    delay_no_replay: u64,

    /// Time-to-live of video frames [ms].
    #[clap(long, value_parser, default_value = "600")]
    ttl_data: u64,

    /// Close the multicast channel and stop the server when the video
    /// transmission is completed.
    #[clap(long)]
    close_complete: bool,

    /// Waits that at least a client connects before starting the video content.
    /// If multicast is enabled, waits for a first multicast client to connect.
    /// If multicast is disabled, waits for a first unicast client to connect.
    #[clap(short, long = "wait-client")]
    wait_first_client: Option<u32>,

    /// Soft wait: if `wait_first_client` is set, just waits for the connections
    /// to be established, but not that the clients are listening to multicast.
    /// This is used to show the alternance between unicast and multicast.
    #[clap(long = "soft-wait")]
    soft_wait: bool,

    /// Soft-multicast option.
    /// If set alongside the `--multicast` flag, uses multicast QUIC with
    /// unicast delivery. This option enables to use multicast QUIC without
    /// IP multicast (or equivalent) support. The multicast QUIC packets are
    /// delivered on the unicast address given by the client, using the
    /// multicast port advertised in the MC_ANNOUNCE data.
    ///
    /// For the time beeing, use the `is_ipv6` field of the MC_ANNOUNCE data
    /// frame to advertise the client if soft multicast is used. This is
    /// necessary so that the client knows which address they should listen to.
    #[clap(short = 'u', long = "soft-mc")]
    soft_mc: bool,

    /// Source address/port of the server.
    #[clap(short = 's', long, default_value = "127.0.0.1:4433")]
    addr: net::SocketAddr,

    /// Set the pacing of the multicast channel in Mbps. Disabled by default.
    /// Only used for the multicast channel.
    #[clap(long = "pacing")]
    pacing: Option<u64>,

    /// Chunk size of packets if `file` application is used.
    #[clap(long = "chunk-size", value_parser, default_value = "1100")]
    chunk_size: usize,

    /// Certificate path.
    #[clap(long = "cert-path", value_parser, default_value = "./src/bin")]
    cert_path: String,

    /// Maximum number of FEC repair symbols that can be sent in a single TTL
    /// expiration window.
    #[clap(long = "max-fec-rs", value_parser, default_value = "5")]
    max_fec_rs: u32,

    /// Use reliable multicast.
    #[clap(long = "reliable")]
    reliable_mc: bool,
}

fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    let mut app_handler = mc_app::AppDataServer::new(
        args.app,
        args.filepath.as_deref(),
        args.nb_frames,
        args.delay_no_replay,
        args.wait_first_client.is_some(),
        &args.result_quic_trace,
        &args.result_wire_trace,
        args.chunk_size,
    );

    let authentication = args.authentication;
    let mut nb_active_mc_receivers = 0;

    // Log every packet sent on unicast and multicast.
    let mut log_uc_pkt = Vec::with_capacity(10000);
    let mut log_mc_pkt = Vec::with_capacity(10000);

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket = mio::net::UdpSocket::bind(args.addr).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    debug!(
        "Debug: {}",
        Path::new(&args.cert_path)
            .join("cert.crt")
            .to_str()
            .unwrap()
    );

    config
        .load_cert_chain_from_pem_file(
            Path::new(&args.cert_path)
                .join("cert.crt")
                .to_str()
                .unwrap(),
        )
        .unwrap();
    config
        .load_priv_key_from_pem_file(
            Path::new(&args.cert_path)
                .join("cert.key")
                .to_str()
                .unwrap(),
        )
        .unwrap();

    config
        .set_application_protos(&[
            b"hq-interop",
            b"hq-29",
            b"hq-28",
            b"hq-27",
            b"http/0.9",
        ])
        .unwrap();

    // config.set_max_idle_timeout(5000);
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
    if args.multicast {
        config.set_multipath(true);
        config.set_enable_server_multicast(true);
        config.set_fec_window_size(2000);
        debug!("Set multicase true");
    }
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::DISABLED);

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();
    let mut clients_ids = ClientIdMap::new();
    let mut next_client_id = 0;

    let local_addr = socket.local_addr().unwrap();

    // Multicast channel and sockets.
    let mc_cwnd = if let Some(rate) = args.pacing {
        let rate = rate as f64;
        let ttl = args.ttl_data as f64 / 1000f64; // In seconds
        Some((rate * ttl * 1.25).round() as usize)
    } else {
        None
    };
    let (
        mut mc_socket_opt,
        mut mc_channel_opt,
        mc_announce_data_opt,
        mc_announce_auth_opt,
    ) = if args.multicast {
        let mut source_addr = args.addr;
        source_addr.set_port(4434);
        debug!("Create multicast channel");
        get_multicast_channel(
            &args.mc_keylog_file,
            authentication,
            args.ttl_data,
            &rng,
            args.soft_mc,
            mc_cwnd,
            source_addr,
            &args.cert_path,
            Some(args.max_fec_rs),
            args.reliable_mc,
        )
    } else {
        (None, None, None, None)
    };

    if let (Some(mc_channel), Some(rate)) = (mc_channel_opt.as_mut(), args.pacing)
    {
        // let cwnd = rate * args.ttl_data;
        let cwnd = ((rate * args.ttl_data) as f64 / 1000f64).round() as u64;
        mc_channel.channel.mc_set_constant_pacing(cwnd).unwrap();
        debug!(
            "Set the multicast channel pacing to {} and cwnd {}",
            rate, cwnd
        );
    }

    debug!("AFTER MULTICAST CHANNEL SETUP");

    if let Some(mc_socket) = mc_socket_opt.as_mut() {
        // Register multicast socket to the poll.
        poll.registry()
            .register(mc_socket, mio::Token(1), mio::Interest::READABLE)
            .unwrap();

        if args.pacing.is_some() {
            // set_txtime_sockopt(mc_socket).unwrap();
            // set_max_pacing(mc_socket).unwrap();
        }
    }

    let mut pacing_timeout: Option<std::time::Instant> = None;
    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let now = std::time::Instant::now();
        let mut timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        if let Some(pacing) = pacing_timeout {
            let t = pacing.duration_since(now);
            timeout = [timeout, Some(t)].iter().flatten().min().copied();
        }

        if let Some(app_timeout) = app_handler.next_timeout() {
            debug!("Application timeout: {:?}", app_timeout);
            timeout =
                [timeout, Some(app_timeout)].iter().flatten().min().copied();
        }

        if !app_handler.has_sent_some_data() && args.wait_first_client.is_none() {
            let first_timeout = std::time::Duration::ZERO;
            timeout = [timeout, Some(first_timeout)]
                .iter()
                .flatten()
                .min()
                .copied()
        } else if let Some(mc_channel) = mc_channel_opt.as_ref() {
            let mc_timeout = mc_channel.channel.mc_timeout(now);
            timeout = [timeout, mc_timeout].iter().flatten().min().copied()
        }

        debug!("Next timeout in {:?}", timeout);
        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                // debug!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(pkt_buf, 16) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
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
                    continue 'read;
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
                    continue 'read;
                }
                log_uc_pkt.push(len);

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
                    log_uc_pkt.push(len);
                    continue 'read;
                }

                let odcid = validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'read;
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
                    soft_mc_addr: net::SocketAddr::new(from.ip(), 8889),
                    soft_mc_addr_auth: net::SocketAddr::new(from.ip(), 8890),
                    client_id,
                    active_client: false,
                    stream_buf: VecDeque::new(),
                    mc_client_listen_uc: false,
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
                    (mc_announce_data_opt.as_ref(), mc_channel_opt.as_ref())
                {
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
                        )
                        .unwrap();
                    debug!("Sets MC_ANNOUNCE data for new client");

                    // Add the multicast authetication channel announcement if
                    // symmetric authentication is used.
                    if let Some(mc_announce_auth) = mc_announce_auth_opt.as_ref()
                    {
                        client
                            .conn
                            .mc_set_mc_announce_data(mc_announce_auth)
                            .unwrap();
                        debug!(
                            "Sets the MC_ANNOUNCE authentication for new client"
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
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            debug!(
                "{} ({}) processed {} bytes",
                client.conn.trace_id(),
                client.client_id,
                read
            );

            if client.conn.is_in_early_data() || client.conn.is_established() {
                // Process all readable streams.
                for s in client.conn.readable() {
                    while let Ok((read, fin)) =
                        client.conn.stream_recv(s, &mut buf)
                    {
                        debug!(
                            "{} received {} bytes",
                            client.conn.trace_id(),
                            read
                        );

                        let stream_buf = &buf[..read];

                        debug!(
                            "{} stream {} has {} bytes (fin? {})",
                            client.conn.trace_id(),
                            s,
                            stream_buf.len(),
                            fin
                        );

                        // handle_stream(client, s, stream_buf,
                        // "examples/root");
                    }
                }
            }

            // If it is the first client, start the multicast content
            // directly.
            if !app_handler.app_has_started() {
                // Is the client listening to the multicast content?
                let uc_server_role = client
                    .conn
                    .get_multicast_attributes()
                    .map(|mc| (mc.get_mc_role(), mc.mc_client_has_key()));
                info!("APP HAS NOT STARTED: {:?}", uc_server_role);
                if uc_server_role ==
                    Some((
                        MulticastRole::ServerUnicast(
                            multicast::MulticastClientStatus::ListenMcPath(true),
                        ),
                        true,
                    )) &&
                    !client.active_client ||
                    !args.multicast &&
                        client.conn.is_established() &&
                        !client.active_client
                {
                    info!("New client!");
                    nb_active_mc_receivers += 1;
                    client.active_client = true;
                } else if args.multicast &&
                    client.conn.is_established() &&
                    !client.active_client &&
                    args.soft_wait
                {
                    info!("New soft client!");
                    nb_active_mc_receivers += 1;
                    client.active_client = true;
                    client.mc_client_listen_uc = true;
                }

                // Enough clients to start the content delivery.
                if Some(nb_active_mc_receivers) == args.wait_first_client {
                    app_handler.start_content_delivery();
                }

                // Is multicast disabled?
                if !args.multicast &&
                    client.conn.is_established() &&
                    Some(nb_active_mc_receivers) == args.wait_first_client
                {
                    app_handler.start_content_delivery();
                }
            }

            // Maybe the status of the multicast client changed.
            if let Some(multicast) = client.conn.get_multicast_attributes() {
                if client.mc_client_listen_uc &&
                    matches!(
                        multicast.get_mc_role(),
                        MulticastRole::ServerUnicast(
                            multicast::MulticastClientStatus::ListenMcPath(_)
                        )
                    )
                {
                    println!("Client now joins the multicast channel");
                    client.mc_client_listen_uc = false;
                } else if !client.mc_client_listen_uc &&
                    matches!(
                        multicast.get_mc_role(),
                        MulticastRole::ServerUnicast(
                            multicast::MulticastClientStatus::Leaving(_)
                        )
                    )
                {
                    println!("Client now leaves the multicast channel");
                    client.mc_client_listen_uc = true;
                }
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
        if let Some(mc_channel) = mc_channel_opt.as_mut() {
            // Before expiring the data, deleguate to unicast connections if reliable multicast is enabled.
            if args.reliable_mc {
                let clients_conn = clients.iter_mut().map(|c| &mut c.1.conn);
                on_rmc_timeout_server!(&mut mc_channel.channel, clients_conn, now).unwrap();
            }
            let expired_pkt =
                mc_channel.channel.on_mc_timeout(now).unwrap();
            if expired_pkt.pn.is_some() {
                app_handler.on_expiring();
            }
        }

        // Generate video content frames if the timeout is expired.
        // This is independent of multicast beeing used or not.
        let mut can_go_to_next = false;
        let before = std::time::Instant::now();
        if pacing_timeout.is_none() ||
            pacing_timeout.unwrap().duration_since(now) ==
                std::time::Duration::ZERO
        {
            pacing_timeout = None;
            let app_data_to_send = if app_handler.should_send_app_data() {
                let (stream_id, app_data) = app_handler.get_app_data();

                let to_send = if let Some(mc_channel) = mc_channel_opt.as_mut() {
                    // Either once if multicast is enabled...
                    let written = match mc_channel
                        .channel
                        .stream_send(stream_id, &app_data, true)
                    {
                        Ok(v) => Some(v),
                        Err(quiche::Error::Done) => None,
                        Err(e) => panic!("Other error: {:?}", e),
                    };

                    if args.soft_wait {
                        // Also send to clients that are not yet in the channel and
                        // receive through unicast.
                        for (_, client) in clients.iter_mut() {
                            if client.mc_client_listen_uc {
                                info!("Will send to client unicast");
                                client
                                    .conn
                                    .stream_send(stream_id, &app_data, true)
                                    .unwrap();
                            }
                        }
                    }

                    if written == Some(app_data.len()) {
                        can_go_to_next = true;
                    }

                    if let Some(v) = written {
                        app_handler.stream_written(v);
                        true
                    } else {
                        false
                    }
                } else {
                    // ... or for every client otherwise.
                    // Buffer the data to allow clients to go on different paces.
                    let data = Rc::new(app_data);
                    clients.values_mut().for_each(|client| {
                        client.stream_buf.push_back((stream_id, 0, data.clone()))
                    });

                    // For each client, try to send as much stream data as
                    // possible.
                    clients.values_mut().for_each(|client| {
                        loop {
                            if client.stream_buf.is_empty() {
                                break;
                            }

                            let (s_id, off, data) = client.stream_buf.pop_front().unwrap();
                            let w = match client.conn.stream_send(s_id, &data.as_ref()[off..], true) {
                                Ok(v) => v,
                                Err(quiche::Error::Done) => {
                                    info!("Break on client {} stream {} because done", client.client_id, s_id);
                                    break;
                                },
                                Err(e) => panic!("Error stream send unicast: {}", e),
                            };
                            if off + w < data.len() {
                                client.stream_buf.push_front((s_id, off + w, data));
                                info!("Break on client {} stream {}", client.client_id, s_id);
                                break; // Full, no utility to continue.
                            }
                        }
                    });

                    can_go_to_next = true;
                    app_handler.stream_written(data.as_ref().len());
                    true
                };
                info!(
                    "Sent application frame in stream {}. Must send: {}. Can go next: {}",
                    stream_id, to_send, can_go_to_next
                );

                // Get next video values.
                if can_go_to_next {
                    app_handler.on_sent_to_quic();
                    app_handler.gen_nxt_app_data();
                }
                to_send
            } else {
                false
            };

            // Generate outgoing Multicast-QUIC packets for the multicast
            // channel.
            if let (Some(mc_socket), Some(mc_channel)) =
                (mc_socket_opt.as_mut(), mc_channel_opt.as_mut())
            {
                loop {
                    let (write, mut send_info) =
                        match mc_channel.mc_send(&mut out) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => {
                                debug!("Multicast done writing");
                                break;
                            },
                            Err(e) => {
                                error!("Multicast send failed: {:?}", e);
                                break;
                            },
                        };

                    // If soft-multicast is used, send individually to each
                    // client. The SocketAddr is created using
                    // the client unicast address and
                    // the multicast destination port.
                    send_info.to = mc_channel.mc_send_addr;
                    let err = if args.soft_mc {
                        clients.values().try_for_each(|client| {
                            let send_info_uc = SendInfo {
                                from: send_info.from,
                                to: client.soft_mc_addr,
                                at: send_info.at,
                            };
                            send_to(
                                &socket,
                                &out[..write],
                                &send_info_uc,
                                MAX_DATAGRAM_SIZE,
                                args.pacing.is_some(),
                                false,
                            )
                            .map(|r| log_uc_pkt.push(r))
                        })
                    } else {
                        // Use pacing socket.
                        send_to(
                            mc_socket,
                            &out[..write],
                            &send_info,
                            MAX_DATAGRAM_SIZE,
                            args.pacing.is_some(),
                            false,
                        )
                        .map(|r| log_mc_pkt.push(r))
                    };

                    if let Err(e) = err {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }

                    debug!(
                        "Multicast written {} bytes to {:?}",
                        write, mc_channel.mc_send_addr
                    );

                    // Stop sending further streams if the pacing states that
                    // we should not send further
                    // packets.
                    // if now < send_info.at {
                    //     pacing_timeout = Some(send_info.at);
                    //     break 'app;
                    // }
                }

                // If symmetric authentication is used alongside multicast,
                // generate authentication packets and send them
                // on the multicast authentication path.
                if let (McAuthType::SymSign, Some(mc_auth_info)) =
                    (authentication, mc_channel.mc_auth_info.as_ref())
                {
                    mc_channel
                        .channel
                        .mc_sym_sign(
                            &clients
                                .values_mut()
                                .map(|client| &mut client.conn)
                                .collect::<Vec<_>>(),
                        )
                        .unwrap();

                    let mc_auth_addr = mc_auth_info.2;

                    loop {
                        let write = match mc_channel.mc_send_sym_auth(&mut out) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => {
                                debug!("Multicast done writing authentication");
                                break;
                            },
                            Err(e) => {
                                error!("Multicast send auth failed: {:?}", e);
                                break;
                            },
                        };

                        // If soft-multicast is used, send individually to
                        // each client. The
                        // SocketAddr is created using
                        // the client unicast address and
                        // the multicast destination port.
                        let err = if args.soft_mc {
                            clients.values().try_for_each(|client| {
                                socket
                                    .send_to(
                                        &out[..write],
                                        client.soft_mc_addr_auth,
                                    )
                                    .map(|r| log_uc_pkt.push(r))
                            })
                        } else {
                            mc_socket
                                .send_to(&out[..write], mc_auth_addr)
                                .map(|r| log_mc_pkt.push(r))
                        };

                        if let Err(e) = err {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send() auth would block");
                                break;
                            }

                            panic!("send() auth failed: {:?}", e);
                        }

                        debug!(
                        "Multicast written {} bytes on authentication channel at address {:?}",
                        write, mc_auth_addr
                    );
                    }
                }

                // // Stop sending additional data if we need to pace the
                // production. if pacing_timeout.is_some() {
                //     debug!("Break because pacing timeout is some");
                //     break 'app;
                // }
            }

            // Generate outgoing QUIC packets for all active connections and
            // send them on the UDP socket, until quiche
            // reports that there are no more packets to be
            // sent.
            for client in clients.values_mut() {
                if app_handler.app_has_finished() && client.conn.is_established()
                {
                    let can_close =
                        if let Some(mc_channel) = mc_channel_opt.as_ref() {
                            mc_channel.channel.mc_no_stream_active()
                        } else {
                            client.stream_buf.is_empty()
                        };
                    if can_close {
                        let res = client.conn.close(true, 1, &[0, 1]);
                        info!(
                        "Closing the the connection for {} because no active video.. Res={:?}",
                        client.conn.trace_id(), res,
                    );
                    }
                }
                loop {
                    let (write, send_info) = match client.conn.send(&mut out) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            break;
                        },

                        Err(e) => {
                            error!(
                                "{} send failed: {:?}",
                                client.conn.trace_id(),
                                e
                            );

                            client.conn.close(false, 0x1, b"fail").ok();
                            break;
                        },
                    };

                    if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    log_uc_pkt.push(write);

                    debug!("{} written {} bytes", client.conn.trace_id(), write);

                    // Communication between the unicast session and the
                    // multicast channel.
                    if let Some(mc_channel) = mc_channel_opt.as_mut() {
                        client
                            .conn
                            .uc_to_mc_control(&mut mc_channel.channel)
                            .unwrap();
                    }
                }
            }

            // This could be improved. In case QUIC is unable to send the
            // video frame (e.g., due to congestion control),
            // we will record an invalid (too early)
            // timestamp.
            if app_data_to_send && can_go_to_next {
                let after = std::time::Instant::now();
                info!("On sent to wire: {:?}", after.duration_since(before));
                app_handler.on_sent_to_wire();
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });

        clients_ids.retain(|_, id| clients.contains_key(id));

        // Exist the I/O loop when the transmission is finished and there are no
        // more client. This may cause a problem if clients keep arriving
        // even after the video transmission is complete, but this is a proof of
        // concept... right?
        if clients.is_empty() && app_handler.app_has_finished() {
            break;
        }
    }

    // Record the timestamp results.
    app_handler.on_finish();

    // Write the number of packets sent.
    let mut file =
        std::fs::File::create(format!("{}-uc-pkt.txt", &args.result_wire_trace))
            .unwrap();
    for nb_bytes in log_uc_pkt.iter() {
        writeln!(file, "{}", nb_bytes).unwrap();
    }

    let mut file =
        std::fs::File::create(format!("{}-mc-pkt.txt", &args.result_wire_trace))
            .unwrap();
    for nb_bytes in log_mc_pkt.iter() {
        writeln!(file, "{}", nb_bytes).unwrap();
    }
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

#[allow(clippy::too_many_arguments)]
fn get_multicast_channel(
    mc_keylog_file: &str, authentication: multicast::authentication::McAuthType,
    ttl_data: u64, rng: &SystemRandom, soft_mc: bool, mc_cwnd: Option<usize>,
    source_addr: net::SocketAddr, cert_path: &str, max_fec_rs: Option<u32>, reliable_mc: bool,
) -> (
    Option<mio::net::UdpSocket>,
    Option<MulticastChannelSource>,
    Option<McAnnounceData>, // Data.
    Option<McAnnounceData>, // Authentication.
) {
    let mc_addr = "224.3.0.225:8889".parse().unwrap();
    // let mc_addr = "127.0.0.1:8889".parse().unwrap();
    let mc_addr_bytes = [224, 3, 0, 225];
    // let mc_addr_bytes = [127, 0, 0, 1];
    let mc_port = 8889;
    // let source_addr = "127.0.0.1:4434".parse().unwrap();
    let socket = mio::net::UdpSocket::bind(source_addr).unwrap();
    socket.set_multicast_ttl_v4(10).unwrap();

    let mc_client_tp = MulticastClientTp::default();
    let mut server_config =
        get_test_mc_config(true, None, true, mc_cwnd, cert_path, max_fec_rs);
    let mut client_config = get_test_mc_config(
        false,
        Some(&mc_client_tp),
        true,
        mc_cwnd,
        cert_path,
        None,
    );

    // Generate a random source connection ID for the connection.
    let mut channel_id = [0; 16];
    rng.fill(&mut channel_id[..]).unwrap();

    let channel_id = quiche::ConnectionId::from_ref(&channel_id);
    let channel_id_vec = channel_id.as_ref().to_vec();

    let mc_path_info = multicast::McPathInfo {
        local: source_addr,
        peer: source_addr,
        cid: channel_id,
    };

    // Authentication path information if symmetric authentication is used.
    let mut channel_id_auth = [0; 16];
    let mc_auth_info = if authentication == McAuthType::SymSign {
        rng.fill(&mut channel_id_auth).unwrap();
        let channel_id = quiche::ConnectionId::from_ref(&channel_id_auth);

        let dummy_ip = std::net::Ipv4Addr::new(224, 3, 0, 225);
        // let dummy_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
        let to2 = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            dummy_ip,
            mc_port + 1,
        ));

        Some(multicast::McPathInfo {
            local: to2,
            peer: to2,
            cid: channel_id,
        })
    } else {
        None
    };

    let mut mc_channel = MulticastChannelSource::new_with_tls(
        mc_path_info,
        &mut server_config,
        &mut client_config,
        mc_addr,
        mc_keylog_file,
        authentication,
        mc_auth_info,
        mc_cwnd,
    )
    .unwrap();

    let mc_announce_data = McAnnounceData {
        // channel_id: mc_channel.mc_path_conn_id.0.as_ref().to_vec(),
        channel_id: channel_id_vec,
        path_type: McPathType::Data,
        auth_type: authentication,
        is_ipv6: soft_mc,
        full_reliability: reliable_mc,
        source_ip: [127, 0, 0, 1],
        group_ip: mc_addr_bytes,
        udp_port: mc_port,
        public_key: mc_channel
            .channel
            .get_multicast_attributes()
            .unwrap()
            .get_mc_pub_key()
            .map(|i| i.to_vec()),
        ttl_data,
        is_processed: false,
    };

    mc_channel
        .channel
        .mc_set_mc_announce_data(&mc_announce_data)
        .unwrap();

    // MC_ANNOUNCE data of the authentication path.
    let mc_announce_auth = if authentication == McAuthType::SymSign {
        let data = McAnnounceData {
            channel_id: channel_id_auth.to_vec(),
            path_type: McPathType::Authentication,
            auth_type: McAuthType::None,
            is_ipv6: soft_mc,
            full_reliability: false,
            source_ip: [127, 0, 0, 1],
            group_ip: mc_addr_bytes,
            udp_port: mc_port + 1,
            public_key: None,
            ttl_data,
            is_processed: false,
        };

        mc_channel.channel.mc_set_mc_announce_data(&data).unwrap();

        Some(data)
    } else {
        None
    };

    (
        Some(socket),
        Some(mc_channel),
        Some(mc_announce_data),
        mc_announce_auth,
    )
}

pub fn get_test_mc_config(
    mc_server: bool, mc_client: Option<&MulticastClientTp>, use_fec: bool,
    mc_cwnd: Option<usize>, cert_path: &str, max_fec_rs: Option<u32>,
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
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    // config.set_max_idle_timeout(0);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    if let Some(cwnd) = mc_cwnd {
        config.set_initial_max_data(cwnd as u64);
    } else {
        config.set_initial_max_data(10_000_000);
    }
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
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::DISABLED);
    config.set_fec_symbol_size(1280 - 64); // MC-TODO: make dynamic with auth.
    config.set_fec_window_size(2000);
    config
}

#[cfg(target_os = "linux")]
fn _set_max_pacing(sock: &mio::net::UdpSocket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let rate: u32 = 1000;

    let result = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MAX_PACING_RATE,
            &rate as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as u32,
        )
    };

    debug!("result is {}", result);

    Ok(())
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
