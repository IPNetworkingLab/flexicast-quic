#[macro_use]
extern crate log;

use std::cmp;
use std::collections::HashMap;
use std::io;
use std::net;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::path::Path;
use std::time;
use std::u64;

use quiche_apps::mc_app::control::FcController;
use socket2;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

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
use quiche_apps::mc_app::control;
use quiche_apps::mc_app::rtp::RtpServer;

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

const MAX_DATAGRAM_SIZE: usize = 1350;

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
    rtp_src_addr: Vec<SocketAddr>,

    /// RTP message to indicate the end of the stream.
    #[clap(long = "rtp-stop", value_parser, default_value = "STOP RTP")]
    rtp_stop: String,
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args = Args::parse();

    // Create the general UDP socket that will listen to new incoming connections.
    let socket = new_udp_socket_reuseport(args.src_addr).unwrap();

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

    // Register the McAnnounceData to forward them to the clients.
    let mc_announce_data: Vec<_> = fc_channels
        .iter()
        .map(|fc| fc.mc_announce_data.clone())
        .collect();

    // Spawn tokio tasks for the flexicast channel(s).
    let mut id_fc_chan = 0;
    for (fc_chan_info, rtp_server) in
        fc_channels.drain(..).zip(rtp_servers.drain(..))
    {
        let mut fc_struct = FcChannelAsync {
            fc_chan: fc_chan_info.fc_chan,
            mc_announce_data: fc_chan_info.mc_announce_data,
            socket: fc_chan_info.socket,
            rtp_server,
            rtp_stop_timer,
            sync_tx: tx_fc_ctl.clone(),
            id: id_fc_chan,
        };

        tokio::spawn(async move {
            fc_struct.run().await.unwrap();
        });

        id_fc_chan += 1;
    }

    // Create the controller structure that will manage the communication between
    // the flexicast source and the unicast server instances.
    let mut controller = FcController::new(rx_fc_ctl, mc_announce_data.clone());
    tokio::spawn(async move {
        controller.run().await.unwrap();
    });

    // All the transmission channels for the client.
    let mut clients_tx = Vec::new();

    // Listens to incoming connections from new clients.
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
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

            let udp_socket = new_udp_socket_reuseport(args.src_addr).unwrap();
            udp_socket.connect(from).await.unwrap();

            // Create a new channel to communicate with the client.
            let (tx, rx) = mpsc::channel(10);
            clients_tx.push(tx.clone());

            let client = Client {
                conn,
                client_id,
                listen_fc_channel: false,
                udp_socket,
                rng: rng.clone(),
                mc_announce_data: mc_announce_data.clone(),
                rx_ctl: rx,
            };

            // Notify the controller with a new client.

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
            panic!("This socket should not receive a packet for an existing client because its corresponding socket should be connected");
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

struct Client {
    conn: quiche::Connection,
    client_id: u64,
    listen_fc_channel: bool,
    udp_socket: UdpSocket,
    rng: SystemRandom,
    rx_ctl: mpsc::Receiver<control::MsgRecv>,
    mc_announce_data: Vec<McAnnounceData>,
}

impl Client {
    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Before entering the loop, set the McAnnounceData to the client.
        for (i, mc_announce_data) in self.mc_announce_data.iter().enumerate() {
            self
                .conn
                .mc_set_mc_announce_data(mc_announce_data)
                .unwrap();
            // FC-TODO: not sure that this will work if it
            // replaces the decryption key everytime we
            // add a new one :/. We should see this in the
            // tests but it actually works... lol.
            self
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

        let mut buf = [0u8; 1500];
        loop {
            let timeout = self
                .conn
                .timeout()
                .unwrap_or(time::Duration::from_secs(10));

            tokio::select! {
                // Timeout sleep.
                _ = tokio::time::sleep(timeout) => self.conn.on_timeout(),

                // Data on the udp socket.
                _ = self.udp_socket.readable() => (),

                // Data on the control channel.
                Some(msg) = self.rx_ctl.recv() => self.handle_ctl_msg(msg).await?,
            }

            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            'read: loop {
                let len = match self.udp_socket.try_recv(&mut buf[..]) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read, so exit the read
                        // loop.
                        if e.kind() == io::ErrorKind::WouldBlock {
                            break 'read;
                        }

                        panic!("recv() failed: {:?}", e);
                    },
                };

                let pkt_buf = &mut buf[..len];

                let recv_info = quiche::RecvInfo {
                    to: self.udp_socket.local_addr()?,
                    from: self.udp_socket.peer_addr()?,
                    from_mc: false,
                };

                // Process potentially coalesced packets.
                let _read = match self.conn.recv(pkt_buf, recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("{} recv failed: {:?}", self.conn.trace_id(), e);
                        continue 'read;
                    },
                };

                // Provides as many CIDs as possible.
                self.handle_path_events();

                while self.conn.source_cids_left() > 0 {
                    let (scid, reset_token) = {
                        let mut scid = [0; 16];
                        self.rng.fill(&mut scid).unwrap();
                        let scid = scid.to_vec().into();
                        let mut reset_token = [0; 16];
                        self.rng.fill(&mut reset_token).unwrap();
                        let reset_token = u128::from_be_bytes(reset_token);
                        (scid, reset_token)
                    };
                    if self
                        .conn
                        .new_source_cid(&scid, reset_token, false)
                        .is_err()
                    {
                        break;
                    }
                    info!("add a new source cid: {:?}", scid.as_ref());
                    // TODO!!!
                    // clients_ids.insert(scid, client.client_id);
                }
            }

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            'send: loop {
                let (write, _send_info) = match self.conn.send(&mut buf[..]) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => break 'send,

                    Err(e) => {
                        error!("{} send failed: {:?}", self.conn.trace_id(), e);

                        self.conn.close(false, 0x1, b"fail").ok();
                        break 'send;
                    },
                };

                // Here we do wait to send the packets.
                if let Err(e) = self.udp_socket.send(&buf[..write]).await {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        debug!("send() would block, should not happen");
                        break 'send;
                    }

                    panic!("send() failed: {:?}", e);
                }
            }

            // Exit the stap if the connection is closed.
            if self.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    self.conn.trace_id(),
                    self.conn.stats(),
                );
                break;
            }
        }

        Ok(())
    }

    async fn handle_ctl_msg(&mut self, msg: control::MsgRecv) -> control::Result<()> {
        Ok(())
    }

    fn handle_path_events(&mut self) {
        while let Some(qe) = self.conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(local_addr, peer_addr) => {
                    info!(
                        "{} Seen new path ({}, {})",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );

                    // Directly probe the new path.
                    self.conn
                        .probe_path(local_addr, peer_addr)
                        .map_err(|e| error!("cannot probe: {}", e))
                        .ok();
                },

                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) is now validated",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                    if self.conn.is_multipath_enabled() {
                        self.conn
                            .set_active(local_addr, peer_addr, true)
                            .map_err(|e| error!("cannot set path active: {}", e))
                            .ok();
                    }
                },

                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) failed validation",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },

                quiche::PathEvent::Closed(local_addr, peer_addr, err, reason) => {
                    info!(
                        "{} Path ({}, {}) is now closed and unusable; err = {} reason = {:?}",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr,
                        err,
                        reason,
                    );
                },

                quiche::PathEvent::ReusedSourceConnectionId(
                    cid_seq,
                    old,
                    new,
                ) => {
                    info!(
                        "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                        self.conn.trace_id(),
                        cid_seq,
                        old,
                        new
                    );
                },

                quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                    info!(
                        "{} Connection migrated to ({}, {})",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },

                quiche::PathEvent::PeerPathStatus(addr, path_status) => {
                    info!("Peer asks status {:?} for {:?}", path_status, addr,);
                    self.conn
                        .set_path_status(addr.0, addr.1, path_status, false)
                        .map_err(|e| {
                            error!("cannot follow status request: {}", e)
                        })
                        .ok();
                },
            }
        }
    }
}

fn new_udp_socket_reuseport(bind_addr: SocketAddr) -> io::Result<UdpSocket> {
    // Use socket2 sockets to set reuse port.
    let socket =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    socket.set_reuse_port(true)?;
    socket.bind(&bind_addr.into())?;

    // Convert to tokio socket.
    let socket = UdpSocket::from_std(socket.into())?;
    Ok(socket)
}

struct FcChannelInfo {
    socket: UdpSocket,
    fc_chan: MulticastChannelSource,
    mc_announce_data: McAnnounceData,
}

struct FcChannelAsync {
    socket: UdpSocket,
    fc_chan: MulticastChannelSource,
    mc_announce_data: McAnnounceData,

    rtp_server: RtpServer,

    /// Stop RTP timer.
    /// Once the RTP source sends a STOP RTP message, the source waits for 5 *
    /// flexicast timer before closing the connection.
    rtp_stop_timer: time::Duration,

    /// Communication between entities, using tokio mpsc.
    sync_tx: mpsc::Sender<control::MsgFcCtl>,

    /// ID of the flexicast channel.
    id: u64,
}

impl FcChannelAsync {
    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = [0u8; 1500];

        // Timer to stop the RTP transmission.
        let mut rtp_stopped = None;
        let mut can_close_conn_after_rtp = false;

        loop {
            let now = time::Instant::now();
            let timeout = self
                .fc_chan
                .channel
                .mc_timeout(now)
                .unwrap_or(time::Duration::from_secs(u64::MAX - 1));

            let sock_rtp = self
                .rtp_server
                .additional_udp_socket_tokio()
                .ok_or(String::from("Using invalid socket for RTP"))?;
            if let Err(_) =
                tokio::time::timeout(timeout, sock_rtp.readable()).await
            {
                debug!("Flexicast source timeout");
                // TODO: on_rmc_timeout_server!

                let now = time::Instant::now();
                self.fc_chan.channel.on_mc_timeout(now)?;
            }

            // Generate video content frames.
            // First read the socket.
            self.rtp_server.on_additional_udp_socket_readable();
            if self.rtp_server.is_source_rtp_stopped() && rtp_stopped.is_none() {
                rtp_stopped = Some(time::Instant::now());
                debug!("Start RTP end timer");
            }

            // Maybe we can close the connection.
            if let Some(timer) = rtp_stopped {
                if self
                    .rtp_stop_timer
                    .saturating_sub(now.duration_since(timer)) ==
                    time::Duration::ZERO
                {
                    // Yes, we can close now.
                    can_close_conn_after_rtp = true;

                    // Empty the timer to avoid goind over and over here.
                    rtp_stopped = None;
                }
            }

            // If we can close the connection, send a message to the control and
            // exit.
            if can_close_conn_after_rtp {
                self.sync_tx
                    .send(control::MsgFcCtl::CloseRtp(self.id))
                    .await?;

                break;
            }

            // Loop to ensure to dequeue all pending data.
            'rtp: loop {
                if self.rtp_server.should_send_app_data() {
                    let (stream_id, app_data) = self.rtp_server.get_app_data();
                    match self
                        .fc_chan
                        .channel
                        .stream_priority(stream_id, 0, false)
                    {
                        Ok(()) => (),
                        Err(quiche::Error::StreamLimit) => (),
                        Err(quiche::Error::Done) => (),
                        Err(e) =>
                            panic!("Error while setting stream priority: {:?}", e),
                    }

                    let written = match self
                        .fc_chan
                        .channel
                        .stream_send(stream_id, &app_data, true)
                    {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => break 'rtp,
                        Err(e) => panic!("Other error: {:?}", e),
                    };

                    self.rtp_server.stream_written(written);
                } else {
                    break;
                }
            }

            // Generate outgoing QUIC packets to send on the Flexicast path.
            'fc: loop {
                // Ask quiche to generate the packets.
                let (write, _send_info) = match self.fc_chan.mc_send(&mut buf[..])
                {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => break,

                    Err(e) => {
                        error!("Flexicast send() failed: {:?}", e);
                        break 'fc;
                    },
                };

                // Send the packets on the wire.
                let mut off = 0;
                let mut left = write;
                let mut written = 0;

                while left > 0 {
                    let pkt_len = cmp::min(left, MAX_DATAGRAM_SIZE);

                    match self.socket.send(&buf[off..off + pkt_len]).await {
                        Ok(v) => written += v,
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                debug!("Flexicast send() would block");
                                break 'fc;
                            }

                            panic!("Flexicast send() failed: {:?}", e);
                        },
                    }
                    off += pkt_len;
                    left -= pkt_len;
                }

                debug!("Flexicast written {:?} bytes", written);
            }
        }

        Ok(())
    }
}
