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

use std::io::BufRead;
use std::net;

use quiche::multicast::McAnnounceData;
use quiche::multicast::MulticastChannelSource;
use quiche::multicast::MulticastClientTp;
use quiche::multicast::MulticastConnection;
use std::collections::HashMap;
use std::time;

use clap::Parser;
use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

struct Client {
    conn: quiche::Connection,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

#[derive(Parser)]
struct Args {
    /// Activate multicast extension.
    #[clap(short = 'm', long)]
    multicast: bool,

    /// Video replay trace.
    #[clap(short = 't', long = "trace", value_parser)]
    trace_filename: Option<String>,

    /// Sent video frames results.
    #[clap(
        short = 'r',
        long,
        value_parser,
        default_value = "mc-server-result.txt"
    )]
    result_trace: String,

    /// Keylog file for multicast channel.
    #[clap(
        short = 'k',
        long,
        value_parser,
        default_value = "/tmp/mc-server.txt"
    )]
    mc_keylog_file: String,

    /// Do source authentication.
    #[clap(short = 'a', long)]
    authentication: bool,

    /// Number of video frames to send. Used to shorten the trace.
    #[clap(short = 'n', long, value_parser)]
    nb_frames: Option<u64>,

    /// Delay between packets in case no trace is replayed and the source sends
    /// manual data. In ms.
    #[clap(short = 'd', long, value_parser, default_value = "1000")]
    delay_no_replay: u64,

    /// Time-to-live of video frames.
    #[clap(long, value_parser, default_value = "600")]
    ttl_data: u64,

    /// Close the multicast channel and stop the server when the video
    /// transmission is completed.
    #[clap(long)]
    close_complete: bool,
}

fn main() {
    env_logger::init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket =
        mio::net::UdpSocket::bind("127.0.0.1:4433".parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
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
    config.enable_early_data();
    if args.multicast {
        config.set_multipath(true);
        config.set_enable_server_multicast(true);
        debug!("Set multicase true");
    }

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();

    let local_addr = socket.local_addr().unwrap();

    // Multicast channel and sockets.
    let (mut mc_socket_opt, mut mc_channel_opt, mc_announce_data_opt) =
        if args.multicast {
            debug!("Create multicast channel");
            get_multicast_channel(
                &args.mc_keylog_file,
                args.authentication,
                args.ttl_data,
            )
        } else {
            (None, None, None)
        };

    // Register multicast socket to the poll.
    if let Some(mc_socket) = mc_socket_opt.as_mut() {
        poll.registry()
            .register(mc_socket, mio::Token(1), mio::Interest::READABLE)
            .unwrap();
    }

    // Get multicast content: video sending timestamp and frame sizes.
    let video_content = replay_trace(
        args.trace_filename.as_deref(),
        args.nb_frames,
        args.delay_no_replay,
    )
    .unwrap();
    let mut video_content = video_content.iter();
    let starting_video = time::Instant::now();
    let mut active_video = true;
    let mut sent_frames = 0;
    let mut video_stream_id = 1;

    let (video_nxt_timestamp, mut video_nxt_nb_bytes) =
        *video_content.next().unwrap();

    let mut video_nxt_timestamp = Some(video_nxt_timestamp);

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();
        let timeout_video =
            get_next_timeout_video(starting_video, video_nxt_timestamp);

        let timeout = [timeout, timeout_video].iter().flatten().min().copied();

        debug!(
            "Next timeout in {:?} (video is {:?})",
            timeout, timeout_video
        );

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out");

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
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients.contains_key(&hdr.dcid) &&
                !clients.contains_key(&conn_id)
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

                let mut scid = [0; 16];
                scid.copy_from_slice(&conn_id);

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

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                let client = Client { conn };

                clients.insert(scid.clone(), client);

                let client = clients.get_mut(&scid).unwrap();

                // Add the multicast channel announcement for the new client.
                if let (Some(mc_announce_data), Some(mc_channel)) =
                    (mc_announce_data_opt.as_ref(), mc_channel_opt.as_ref())
                {
                    client
                        .conn
                        .mc_set_mc_announce_data(&mc_announce_data)
                        .unwrap();
                    client
                        .conn
                        .mc_set_multicast_receiver(&mc_channel.master_secret)
                        .unwrap();
                    debug!("Sets MC_ANNOUNCE data for new client");
                }

                client
            } else {
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
                from_mc: false,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            debug!("{} processed {} bytes", client.conn.trace_id(), read);

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
        }

        // Handle time to live timeout of data of the multicast channel.
        let now = std::time::Instant::now();
        if let Some(mc_channel) = mc_channel_opt.as_mut() {
            mc_channel.channel.on_mc_timeout(now).unwrap();
        }

        // Generate video content frames if the timeout is expired.
        // This is independent of multicast beeing used or not.
        if active_video &&
            now.duration_since(starting_video) >=
                time::Duration::from_millis(video_nxt_timestamp.unwrap())
        {
            // Send the video frame in a dedicated stream.
            let video_data = vec![0u8; video_nxt_nb_bytes];

            if let Some(mc_channel) = mc_channel_opt.as_mut() {
                // Either once if multicast is enabled...
                mc_channel
                    .channel
                    .stream_send(video_stream_id, &video_data, true)
                    .unwrap();
            } else {
                // ... or for every client otherwise.
                clients.values_mut().for_each(|client| {
                    client
                        .conn
                        .stream_send(video_stream_id, &video_data, true)
                        .unwrap();
                });
            }
            debug!(
                "Sent video frame {} in stream {}",
                sent_frames, video_stream_id
            );

            // Get next video values.
            if sent_frames >= video_content.len() {
                active_video = false;
                info!("SET ACTIVE VIDEO TO FALSE");
                video_nxt_timestamp = None;
            } else {
                sent_frames += 1;
                let (tmp1, tmp2) = video_content.next().unwrap().to_owned();
                video_nxt_timestamp = Some(tmp1);
                video_nxt_nb_bytes = tmp2;
                video_stream_id += 4;
            }
        }

        // Generate outgoing Multicast-QUIC packets for the multicast channel.
        if let (Some(mc_socket), Some(mc_channel)) =
            (mc_socket_opt.as_mut(), mc_channel_opt.as_mut())
        {
            loop {
                let write = match mc_channel.mc_send(&mut out) {
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

                if let Err(e) =
                    mc_socket.send_to(&out[..write], mc_channel.mc_send_addr)
                {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send() would block");
                        break;
                    }

                    panic!("send() failed: {:?}", e);
                }

                debug!("Multicast written {} bytes", write);
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for client in clients.values_mut() {
            if !active_video && client.conn.is_established() {
                let res = client.conn.close(true, 1, &[0, 1]);
                debug!(
                    "Closing the the connection for {} because no active video.. Res={:?}",
                    client.conn.trace_id(), res,
                );
            }
            loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

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

                debug!("{} written {} bytes", client.conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            debug!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });

        // Exist the I/O loop when the transmission is finished and there are no
        // more client. This may cause a problem if clients keep arriving
        // even after the video transmission is complete, but this is a proof of
        // concept... right?
        if clients.is_empty() && !active_video {
            break;
        }
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

fn replay_trace(
    filepath: Option<&str>, limit: Option<u64>, delay_no_replay: u64,
) -> Result<Vec<(u64, usize)>, std::io::Error> {
    if let Some(filepath) = filepath {
        let file = std::fs::File::open(filepath)?;
        let buf_reader = std::io::BufReader::new(file);

        let v = buf_reader
            .lines()
            .map(|line| {
                let line = line?;

                let mut tab = line[1..].split(",");
                let timestamp: u64 = tab.next().unwrap().parse().unwrap();
                let nb_bytes: usize = tab.next().unwrap().parse().unwrap();

                Ok((timestamp, nb_bytes))
            })
            .collect::<Result<Vec<(u64, usize)>, std::io::Error>>()?;

        Ok(v[..limit.unwrap_or(v.len() as u64) as usize].into())
    } else {
        Ok((0..limit.unwrap_or(1000))
            .map(|i| (delay_no_replay * i, 1000))
            .collect())
    }
}

fn get_multicast_channel(
    mc_keylog_file: &str, authentication: bool, ttl_data: u64,
) -> (
    Option<mio::net::UdpSocket>,
    Option<MulticastChannelSource>,
    Option<McAnnounceData>,
) {
    let mc_addr = "224.3.0.225:8889".parse().unwrap();
    let mc_addr_bytes = [224, 3, 0, 225];
    let mc_port = 8889;
    let source_addr = "127.0.0.1:4434".parse().unwrap();
    let socket = mio::net::UdpSocket::bind(source_addr).unwrap();

    let mc_client_tp = MulticastClientTp::default();
    let mut server_config = get_test_mc_config(true, None, true);
    let mut client_config = get_test_mc_config(false, Some(&mc_client_tp), true);

    // Generate a random source connection ID for the connection.
    let mut channel_id = [0; 16];
    SystemRandom::new().fill(&mut channel_id[..]).unwrap();

    let channel_id = quiche::ConnectionId::from_ref(&channel_id);

    let mut mc_channel = MulticastChannelSource::new_with_tls(
        &channel_id,
        &mut server_config,
        &mut client_config,
        mc_addr,
        source_addr,
        mc_keylog_file,
        authentication,
    )
    .unwrap();

    let mc_announce_data = McAnnounceData {
        // channel_id: mc_channel.mc_path_conn_id.0.as_ref().to_vec(),
        channel_id: channel_id.as_ref().to_vec(),
        is_ipv6: false,
        source_ip: [127, 0, 0, 1],
        group_ip: mc_addr_bytes,
        udp_port: mc_port,
        public_key: Some(
            mc_channel
                .channel
                .get_multicast_attributes()
                .unwrap()
                .get_mc_pub_key()
                .unwrap()
                .to_owned(),
        ),
        ttl_data,
    };

    mc_channel
        .channel
        .mc_set_mc_announce_data(&mc_announce_data)
        .unwrap();

    (Some(socket), Some(mc_channel), Some(mc_announce_data))
}

pub fn get_test_mc_config(
    mc_server: bool, mc_client: Option<&MulticastClientTp>, use_fec: bool,
) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    // config.set_max_idle_timeout(0);
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
    config.set_fec_scheduler_algorithm(
        quiche::FECSchedulerAlgorithm::RetransmissionFec,
    );
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::DISABLED);
    config.set_fec_symbol_size(1280 - 64); // MC-TODO: make dynamic with auth.
    config
}

fn get_next_timeout_video(
    start_video: time::Instant, next_video: Option<u64>,
) -> Option<time::Duration> {
    let now = time::Instant::now();
    match next_video {
        Some(v) => Some(time::Duration::from_millis(
            v.saturating_sub((now - start_video).as_millis() as u64),
        )),
        None => None,
    }
}
