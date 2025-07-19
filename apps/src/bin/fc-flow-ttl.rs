#[macro_use]
extern crate log;

use core::time;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::net;
use std::net::SocketAddrV4;
use std::path::Path;
use std::sync::Arc;
use std::u64;

use quiche::flexicast::ack::OpenRangeSet;
use quiche::flexicast::FlexicastChannelSource;
use quiche::flexicast::FlexicastConnection;
use quiche::flexicast::McConfig;
use quiche::CongestionControlAlgorithm;
use quiche_apps::fc_app::asynchronous::controller::handle_msg;
use quiche_apps::fc_app::asynchronous::fc::FcChannelInfo;
use quiche_apps::fc_app::asynchronous::fc::FcFlowRun;
use quiche_apps::fc_app::asynchronous::messages::*;
use quiche_apps::fc_app::asynchronous::uc::UcPathRun;
use quiche_apps::fc_app::cca::FcFlowCwnd;
use quiche_apps::fc_app::mc_ttl::fc_flow::FcFlowTtl;
use quiche_apps::fc_app::mc_ttl::ttl::TtlApp;
use quiche_apps::fc_app::mc_ttl::uc_path::UcPathTtl;
use quiche_apps::fc_app::mc_ttl::FcTtlMsg;
use tokio::sync::mpsc;

use clap::Parser;
use quiche::flexicast;
use quiche::flexicast::FcConfig;
use quiche::flexicast::McAnnounceData;

#[cfg(feature = "qlog")]
use quiche_apps::common::make_qlog_writer;
use quiche_apps::common::ClientIdMap;
use quiche_apps::fc_app::asynchronous;
use quiche_apps::fc_app::asynchronous::fc::FcChannelAsync;

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

const MAX_DATAGRAM_SIZE: usize = 1350;
const CHANNEL_BUFFER_SIZE: usize = 100;

#[derive(Parser)]
struct Args {
    /// Keylog file for flexicast channel.
    #[clap(long = "keylog", value_parser, default_value = "/tmp/fc-server.txt")]
    fc_keylog_file: Box<Path>,

    /// Source address of the server.
    #[clap(long = "src", default_value = "127.0.0.1:4433")]
    src_addr: net::SocketAddr,

    /// Certificate path.
    #[clap(long = "cert-path", value_parser, default_value = "./src/bin")]
    cert_path: Box<Path>,

    /// Multicast address.
    #[clap(
        long = "mc-addr",
        value_parser,
        default_value = "239.239.239.35:4434"
    )]
    mc_addr: net::SocketAddr,

    /// Flexicast flow timer.
    #[clap(long, value_parser, default_value = "0")]
    fc_timer: u64,

    /// Keylog file for flexicast channel.
    #[clap(
        short = 'k',
        long,
        value_parser,
        default_value = "/tmp/mc-server.txt"
    )]
    mc_keylog_file: String,

    /// Whether the flexicast flow must be created using path probing.
    #[clap(long = "probe-path")]
    probe_path: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    // Create the general UDP socket that will listen to new incoming connections.
    let socket =
        Arc::new(tokio::net::UdpSocket::bind(args.src_addr).await.unwrap());

    // Create the configuration for the QUIC connections.
    let mut config = get_config(&args);

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients_ids = ClientIdMap::new();
    let mut next_client_id = 0;
    let local_addr = socket.local_addr().unwrap();

    // Flexicast flow initial structure.
    let fc_chan_info = get_flexicast_channel(&args, &rng, Some(0)).await;

    // Channel to communicate with the main thread (this one). Used to notify of
    // new Connection IDs mapped to specific clients.
    let (tx_main, mut rx_main) = mpsc::channel(CHANNEL_BUFFER_SIZE);

    // Create the communication channel. Because it is a MPSC, we can just clone
    // the sender.
    let (tx_fc_ctl, rx_fc_ctl) = mpsc::channel(CHANNEL_BUFFER_SIZE);

    // Get the McAnnounceData to forward them to the clients.
    let mc_announce_data = fc_chan_info.mc_announce_data.clone();

    // Also get the decryption keys and algos, indexed in the same order as the
    // McAnnounceData.
    let mc_master_secret: Vec<u8> = fc_chan_info.fc_chan.master_secret.clone();
    let mc_key_algo: u8 = fc_chan_info.fc_chan.algo.try_into().unwrap();

    // Spawn tokio task for the flexicast channel.
    let (tx_fc_source, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);

    let mut fc_struct = FcChannelAsync {
        fc_chan: fc_chan_info.fc_chan,
        mc_announce_data: fc_chan_info.mc_announce_data,
        socket: fc_chan_info.socket,
        rtp_stop_timer: time::Duration::from_millis(100),
        sync_tx: tx_fc_ctl.clone(),
        id: 0,
        rx_ctl: rx,
        must_wait: false,
        cca: FcFlowCwnd::Unlimited,
        allow_unicast: false,
        do_flexicast: true,
        sendmmsg_txs: None,
        transfer_kind:
            quiche_apps::fc_app::file_transfer::sender::FileTransferKind::Bytes(0),
        pending_data: None,
        pending_data_sent_uc: false,
        pending_sent_pkt: Vec::new(),
    };

    // Initialize QLOG for the flexicast flow.
    #[cfg(feature = "qlog")]
    {
        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let id = format!("fc-flow-{:?}", 0);
            let writer = make_qlog_writer(&dir, "server", &id);

            fc_struct.fc_chan.channel.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-server qlog".to_string(),
                format!("{} id={}", "quiche-server qlog", id),
            );
        }
    }

    let (tx_app, rx_app) = mpsc::channel::<FcTtlMsg>(CHANNEL_BUFFER_SIZE);

    // Create the file transfer structure.
    let mut fc_ttl = FcFlowTtl {
        fc_flow: fc_struct,
        ttl_duration: time::Duration::from_millis(100),
        max_ttl: 10,
        tx_app: tx_app.clone(),
    };

    tokio::spawn(async move {
        fc_ttl.run().await.unwrap();
    });

    // Create TTL application.
    let mut ttl_app = TtlApp::new(rx_app, time::Duration::from_secs(1));
    tokio::spawn(async move {
        ttl_app.run().await.unwrap();
    });

    // Create the controller structure that will manage the communication between
    // the flexicast source and the unicast server instances.
    let mut controller = asynchronous::controller::FcController::new(
        rx_fc_ctl,
        vec![mc_announce_data.clone()],
        vec![tx_fc_source],
        tx_main.clone(),
        None,
        None,
    );
    tokio::spawn(async move {
        controller.run().await.unwrap();
    });

    // All the transmission channels for the client.
    let mut clients_tx: Vec<mpsc::Sender<MsgRecv>> = Vec::new();

    // All the flexicast flows that are stopped.
    let mut fc_flows_stopped = HashSet::new();

    // Listens to incoming connections from new clients.
    loop {
        tokio::select! {
            // Receive new packet from unconnected address.
            _ = socket.readable() => (),

            // Receive a message for control.
            Some(msg) = rx_main.recv() => {
                handle_msg(msg, &mut clients_ids, &socket, &mut fc_flows_stopped).await.unwrap();
            },
        }

        let (len, from) = match socket.try_recv_from(&mut buf) {
            Ok(v) => v,

            Err(e) => {
                // There are no more UDP packets to read, so send the read
                // loop.
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    continue;
                }

                panic!("recv() failed: {:?}", e);
            },
        };

        debug!("Receive a packet from the global socket!");

        let pkt_buf = &mut buf[..len];

        // Parse the QUIC packet's header.
        let hdr = match quiche::Header::from_slice(pkt_buf, 16) {
            Ok(v) => v,

            Err(e) => {
                error!("Parsing packet header failed: {:?}", e);
                continue;
            },
        };

        trace!("got packet {:?}", hdr);

        let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
        let conn_id = &conn_id.as_ref()[..16];

        // Lookup a connection based on the packet's connection ID. If there
        // is no connection matching, create a new one.
        // We should not enter in the else case because the UDP socket should be
        // connected.
        let mut client = if !clients_ids.contains_key(&hdr.dcid) &&
            !clients_ids.contains_key(&hdr.dcid)
        {
            if hdr.ty != quiche::Type::Initial {
                error!("Packet is not Initial");
                continue;
            }

            if !quiche::version_is_supported(hdr.version) {
                warn!("Doing version negotiation");

                let len =
                    quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                        .unwrap();

                let out = &out[..len];

                if let Err(e) = socket.send_to(out, from).await {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send() would block");
                        break;
                    }

                    panic!("send() failed: {:?}", e);
                }
                continue;
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

                if let Err(e) = socket.send_to(out, from).await {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send() would block");
                        break;
                    }

                    panic!("send() failed: {:?}", e);
                }
                debug!("Sent a packet to {:?}", from);
                continue;
            }

            let odcid = validate_token(&from, token);

            // The token was not valid, meaning the retry failed, so
            // drop the packet.
            if odcid.is_none() {
                error!("Invalid address validation token");
                continue;
            }

            if scid.len() != hdr.dcid.len() {
                error!("Invalid destination connection ID");
                continue;
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

            // Create a new channel to communicate with the client.
            let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
            clients_tx.push(tx.clone());

            let mut client = quiche_apps::fc_app::asynchronous::uc::UcPath {
                conn,
                client_id,
                listen_fc_channel: false,
                rng: rng.clone(),
                mc_announce_data: vec![mc_announce_data.clone()],
                mc_master_secret: vec![mc_master_secret.clone()],
                mc_key_algo: vec![mc_key_algo],
                rx_ctl: rx,
                tx_tcl: tx_fc_ctl.clone(),
                tx_main: tx_main.clone(),
                pending_data: Vec::new(),
                pending_data_off: 0,
                uc_sock: socket.clone(),
                unlimited_cwnd: false,
                fcf_scheduler: None,
                previous_cwnd: None,
                pending_ack: OpenRangeSet::default(),
                pending_stream_ack: HashMap::new(),
            };

            // Notify the controller with a new receiver.
            let msg = MsgFcCtl::NewClient((next_client_id, tx.clone()));
            tx_fc_ctl.send(msg).await.unwrap();

            next_client_id += 1;
            clients_ids.insert(scid.clone(), client_id);

            debug!(
                "New connection: dcid={:?} scid={:?}. Client id: {}",
                hdr.dcid, scid, client_id
            );

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
            // This is an existing receiver that sends a QUIC packet from a new
            // address. We notify the receiver that it must handle
            // this packet and all new packets from this address.
            let client_id = clients_ids.get(&hdr.dcid).unwrap();
            let recv_info = quiche::RecvInfo {
                from,
                to: socket.local_addr().unwrap(),
                from_mc: false,
            };
            let msg = MsgRecv::NewPkt((pkt_buf.to_vec(), recv_info));
            debug!(
                "Send message to {:?} because recv_info={:?}",
                client_id, recv_info
            );
            clients_tx[*client_id as usize].send(msg).await.unwrap();
            continue;
        };

        let recv_info = quiche::RecvInfo {
            to: socket.local_addr().unwrap(),
            from,
            from_mc: false,
        };

        // First recv is handled by the main thread. Subsequent recv are handled
        // by the tokio task.
        let _read = match client.conn.recv(pkt_buf, recv_info) {
            Ok(v) => v,

            Err(e) => {
                error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                continue;
            },
        };

        let mut uc_path = UcPathTtl {
            uc_path: client,
            tx_app: tx_app.clone(),
        };

        tokio::spawn(async move {
            uc_path.run().await.unwrap();
        });
    }

    println!("Finishing!");
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

    let initial_max_data = 100_000_000_000;
    config.set_initial_max_data(initial_max_data);
    config.set_initial_max_stream_data_bidi_local(initial_max_data);
    config.set_initial_max_stream_data_bidi_remote(initial_max_data);
    config.set_initial_max_stream_data_uni(initial_max_data);
    config.set_initial_max_streams_bidi(initial_max_data);
    config.set_initial_max_streams_uni(initial_max_data);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(5);
    config.enable_early_data();
    config.enable_pacing(false);
    config.set_enable_flexicast(true);
    config.set_initial_max_path_id(10);

    config
}

async fn get_flexicast_channel(
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
        _ => unreachable!("Only support IPv4 flexicast addresses"),
    };
    let mc_addr = net::SocketAddr::V4(SocketAddrV4::new(
        mc_addr_bytes.into(),
        mc_addr.port() + idx_addr as u16,
    ));
    let mc_port = mc_addr.port();

    let socket = tokio::net::UdpSocket::bind(src_addr).await.unwrap();
    socket.set_multicast_ttl_v4(56 + idx_addr as u32).unwrap();

    let mut server_config =
        get_mc_config(true, args.cert_path.as_ref().to_str().unwrap());
    let mut client_config =
        get_mc_config(true, args.cert_path.as_ref().to_str().unwrap());

    // Generate a random source connection ID for the connection.
    let mut channel_id = [0; 16];
    rng.fill(&mut channel_id[..]).unwrap();

    let channel_id = quiche::ConnectionId::from_ref(&channel_id);
    let channel_id_vec = channel_id.as_ref().to_vec();

    let mc_path_info = flexicast::McPathInfo {
        local: src_addr,
        peer: src_addr,
        cid: channel_id,
    };

    let fc_config = FcConfig {
        probe_mc_path: args.probe_path,
        ..Default::default()
    };

    let mut fc_chan = FlexicastChannelSource::new_with_tls(
        mc_path_info,
        &mut server_config,
        &mut client_config,
        mc_addr,
        args.fc_keylog_file.as_ref().to_str().unwrap(),
        &fc_config,
    )
    .unwrap();

    let mc_announce_data = McAnnounceData {
        channel_id: channel_id_vec,
        is_ipv6_addr: false,
        probe_path: args.probe_path,
        reset_stream_on_join: true,
        source_ip: [127, 0, 0, 1],
        group_ip: mc_addr_bytes,
        udp_port: mc_port,
        public_key: None,
        fc_timer: args.fc_timer,
        is_processed: false,
        bitrate: None,
        fc_channel_algo: None,
        fc_channel_secret: None,
    };

    fc_chan
        .channel
        .fc_set_announce_data(&mc_announce_data)
        .unwrap();

    FcChannelInfo {
        socket,
        fc_chan,
        mc_announce_data,
    }
}

fn get_mc_config(enable_fc: bool, cert_path: &str) -> quiche::Config {
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

    let initial_max_data = 100_000_000_000;
    config.set_initial_max_data(initial_max_data);
    config.set_initial_max_stream_data_bidi_local(initial_max_data);
    config.set_initial_max_stream_data_bidi_remote(initial_max_data);
    config.set_initial_max_stream_data_uni(initial_max_data);
    config.set_initial_max_streams_bidi(initial_max_data);
    config.set_initial_max_streams_uni(initial_max_data);
    config.set_active_connection_id_limit(5);
    config.verify_peer(false);
    config.set_initial_max_path_id(10);
    config.set_enable_flexicast(enable_fc);
    config.enable_pacing(false);
    let cca_to_use = CongestionControlAlgorithm::DISABLED;
    config.set_cc_algorithm(cca_to_use);
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
