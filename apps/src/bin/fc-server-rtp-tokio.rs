#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::net;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::path::Path;
use std::u64;

use quiche_apps::mc_app::asynchronous::controller::handle_msg;
use quiche_apps::mc_app::asynchronous::controller::optional_timeout;
use quiche_apps::mc_app::asynchronous::controller::MsgFcCtl;
use quiche_apps::mc_app::asynchronous::controller::MsgRecv;
use quiche_apps::mc_app::asynchronous::fc::FcChannelInfo;
use tokio::sync::mpsc;

use clap::Parser;
use quiche::multicast;
use quiche::multicast::authentication::McAuthType;
use quiche::multicast::FcConfig;
use quiche::multicast::McAnnounceData;
use quiche::multicast::McClientTp;
use quiche::multicast::McConfig;
use quiche::multicast::MulticastChannelSource;
use quiche::multicast::MulticastConnection;

#[cfg(feature = "qlog")]
use quiche_apps::common::make_qlog_writer;
use quiche_apps::common::ClientIdMap;
use quiche_apps::mc_app::asynchronous;
use quiche_apps::mc_app::asynchronous::fc::FcChannelAsync;
use quiche_apps::mc_app::rtp::RtpServer;

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

const MAX_DATAGRAM_SIZE: usize = 1350;

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
    rtp_src_addr: Vec<SocketAddr>,

    /// RTP message to indicate the end of the stream.
    #[clap(long = "rtp-stop", value_parser, default_value = "STOP RTP")]
    rtp_stop: String,

    /// Number of clients to listen before actually sending data to the wire.
    #[clap(long = "wait", value_parser)]
    wait: Option<u64>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    // Create the general UDP socket that will listen to new incoming connections.
    let socket = tokio::net::UdpSocket::bind(args.src_addr).await.unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = get_config(&args);

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients_ids = ClientIdMap::new();
    let mut next_client_id = 0;
    let local_addr = socket.local_addr().unwrap();

    // Sanity check: there are the same number of flexicast instances as RTP
    // sources, if flexicast is enabled.
    if args.flexicast &&
        (args
            .bitrates
            .as_ref()
            .is_some_and(|b| b.len() != args.rtp_src_addr.len())) ||
        args.bitrates.as_ref().is_none()
    {
        error!("If flexicast is enabled, the number of flexicast instances must be the same as the number of RTP sources!");
        std::process::exit(1);
    }

    // List of all flexicast channels with different bitrates.
    // If no bitrate is provided (i.e., the `bitrates` parameter is not used),
    // creates a single flexicast channel with the classical implemented
    // congestion control algorithm.
    let mut fc_channels = if args.flexicast {
        if let Some(bitrates) = args.bitrates.as_ref() {
            let mut chans = Vec::with_capacity(bitrates.len());
            for i in 0..bitrates.len() as u8 {
                let chan = get_multicast_channel(&args, &rng, Some(i)).await;
                chans.push(chan);
            }
            chans
        } else {
            let chan = get_multicast_channel(&args, &rng, None).await;
            vec![chan]
        }
    } else {
        Vec::new() // Empty.
    };

    // Channel to communicate with the main thread (this one). Used to notify of
    // new Connection IDs mapped to specific clients.
    let (tx_main, mut rx_main) = mpsc::channel(20);

    // Compute the mapping between Flexicast channel ID and index.
    let _fcid_to_idx: HashMap<Vec<u8>, usize> = fc_channels
        .iter()
        .enumerate()
        .map(|(i, fc_chan)| (fc_chan.mc_announce_data.channel_id.to_owned(), i))
        .collect();

    // RTP instances to deliver data.
    let mut rtp_servers = Vec::with_capacity(args.rtp_src_addr.len());
    for rtp_addr in args.rtp_src_addr.iter() {
        let rtp_server = RtpServer::new_with_tokio(
            *rtp_addr,
            &args.result_wire_trace,
            &args.result_wire_trace,
            &args.rtp_stop,
        )
        .await
        .unwrap();
        rtp_servers.push(rtp_server);
    }

    let rtp_stop_timer =
        std::time::Duration::from_millis(args.expiration_timer) * 5;

    // Create the communication channel. Because it is a MPSC, we can just clone
    // the sender.
    let (tx_fc_ctl, rx_fc_ctl) = mpsc::channel(20);

    // Get the McAnnounceData to forward them to the clients.
    let mc_announce_data: Vec<_> = fc_channels
        .iter()
        .map(|fc| fc.mc_announce_data.clone())
        .collect();

    // Also get the decryption keys and algos, indexed in the same order as the
    // McAnnounceData.
    let mc_master_secret: Vec<Vec<u8>> = fc_channels
        .iter()
        .map(|fc| fc.fc_chan.master_secret.clone())
        .collect();
    let mc_key_algo: Vec<u8> = fc_channels
        .iter()
        .map(|fc| fc.fc_chan.algo.try_into().unwrap())
        .collect();

    // Create the communication channels towards the flexicast sources.
    let mut tx_fc_source = Vec::with_capacity(fc_channels.len());

    // Spawn tokio tasks for the flexicast channel(s).
    let mut id_fc_chan = 0;
    for (fc_chan_info, rtp_server) in
        fc_channels.drain(..).zip(rtp_servers.drain(..))
    {
        let (tx, rx) = mpsc::channel(20);

        let mut fc_struct = FcChannelAsync {
            fc_chan: fc_chan_info.fc_chan,
            mc_announce_data: fc_chan_info.mc_announce_data,
            socket: fc_chan_info.socket,
            rtp_server,
            rtp_stop_timer,
            sync_tx: tx_fc_ctl.clone(),
            id: id_fc_chan,
            rx_ctl: rx,
            must_wait: args.wait.is_some(),
        };

        tx_fc_source.push(tx);

        tokio::spawn(async move {
            fc_struct.run().await.unwrap();
        });

        id_fc_chan += 1;
    }

    // Create the controller structure that will manage the communication between
    // the flexicast source and the unicast server instances.
    let mut controller = asynchronous::controller::FcController::new(
        rx_fc_ctl,
        mc_announce_data.clone(),
        tx_fc_source,
        tx_main.clone(),
        args.wait,
    );
    tokio::spawn(async move {
        controller.run().await.unwrap();
    });

    // All the transmission channels for the client.
    let mut clients_tx: Vec<mpsc::Sender<MsgRecv>> = Vec::new();

    // All the flexicast flows that are stopped.
    let mut fc_flows_stopped = HashSet::new();

    // Timer once all receivers and flexicast flows stopped.
    let mut end_time: Option<std::time::Instant> = None;
    let end_sleep = std::time::Duration::from_secs(5);

    // Listens to incoming connections from new clients.
    loop {
        let now = std::time::Instant::now();

        // Comute the timeout once all connections are closed before exiting.
        let exit_timeout = end_time
            .map(|t| t.checked_add(end_sleep).map(|t| t.duration_since(now)))
            .flatten();

        tokio::select! {
            // Receive new packet from unconnected address.
            _ = socket.readable() => (),

            // Receive a message for control.
            Some(msg) = rx_main.recv() => {
                handle_msg(msg, &mut clients_ids, &socket, &mut fc_flows_stopped).await.unwrap();

                // Stop the loop only if all flexicast flows stopped and all active receiver stopped.
                if fc_flows_stopped.len() == args.rtp_src_addr.len() {
                    // Try to poll any receiver.
                    let mut any_not_none = false;
                    'ping_client: for client_tx in clients_tx.iter() {
                        if !client_tx.is_closed() {
                            any_not_none = true;
                            break 'ping_client;
                        }
                    }

                    // Break only now.
                    if !any_not_none {
                        end_time = Some(std::time::Instant::now());
                    }
                }
            },

            // Exit timer.
            Some(_) = optional_timeout(exit_timeout) => {
                debug!("Exiting main thread");
                break;
            }
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
            let (tx, rx) = mpsc::channel(10);
            clients_tx.push(tx.clone());

            let client = quiche_apps::mc_app::asynchronous::uc::Client {
                conn,
                client_id,
                listen_fc_channel: false,
                rng: rng.clone(),
                mc_announce_data: mc_announce_data.clone(),
                mc_master_secret: mc_master_secret.clone(),
                mc_key_algo: mc_key_algo
                    .iter()
                    .map(|key| *key)
                    .collect::<Vec<_>>(),
                rx_ctl: rx,
                tx_tcl: tx_fc_ctl.clone(),
                tx_main: tx_main.clone(),
            };

            // Notify the controller with a new client.
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

        tokio::spawn(async move {
            client.run().await.unwrap();
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

async fn get_multicast_channel(
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

    let socket = tokio::net::UdpSocket::bind(src_addr).await.unwrap();
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
        probe_mc_path: false,
        mc_cwnd: args.fc_cwnd,
        ..Default::default()
    };

    let mut fc_chan = MulticastChannelSource::new_with_tls(
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
        auth_type: args.authentication,
        is_ipv6_addr: false,
        probe_path: true,
        reset_stream_on_join: true,
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
