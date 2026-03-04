use crate::fcquic::controller::ClientIdMap;
use crate::fcquic::messages::*;
use crate::fcquic::scheduler::FcFallBackDelay;
use crate::fcquic::scheduler::FcFlowAliveScheduler;
use crate::fcquic::uc::UcPathRun;
use crate::io::uc_path::UcPathFileTransfer;
use crate::io::TokioFcQuicConfig;
use crate::FcQuicMsg;
use crate::Result;
use crate::CHANNEL_BUFFER_SIZE;
use crate::MAX_DATAGRAM_SIZE;
use log::*;
use quiche::flexicast::ack::OpenRangeSet;
use quiche::flexicast::McConfig;
use quiche::Config;
use quiche::CongestionControlAlgorithm;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use quiche::flexicast;
use quiche::flexicast::FcConfig;
use quiche::flexicast::McAnnounceData;

use crate::fcquic::sendmmsg::MsgSmsg;
#[cfg(feature = "qlog")]
use crate::make_qlog_writer;
#[cfg(feature = "tokio-tracing")]
use std::fs::OpenOptions;
#[cfg(feature = "tokio-tracing")]
use std::io::Write;
#[cfg(feature = "tokio-tracing")]
use tokio_metrics::TaskMonitor;

use ring::rand::SystemRandom;

/// This structure handles new handshakes and dispatches the packets from the
/// unicast paths.
pub struct Handshake {
    /// Client ID map.
    client_ids: ClientIdMap,

    /// General socket handling packet I/O.
    socket: Arc<UdpSocket>,

    /// All the transmission channels towards the receivers.
    tx_recvs: Vec<mpsc::Sender<MsgRecv>>,

    /// All the flexicast flows that are stopped.
    fc_flows_stopped: HashSet<u64>,

    /// Channel to send messages to the handshake (this) task.
    tx_main: mpsc::Sender<MsgMain>,

    /// Channel to receive messages on this task.
    rx_main: mpsc::Receiver<MsgMain>,

    /// Unicast path config.
    uc_path_config: Config,

    /// The transmission channels towards the controllers.
    tx_ctls: Vec<mpsc::Sender<MsgFcCtl>>,

    /// All the FC_ANNOUNCE content.
    fc_announce_data: Vec<McAnnounceData>,

    /// All the flexicast flow master secrets.
    fc_master_secret: Vec<Vec<u8>>,

    /// The the flexicast flow key algo.
    fc_key_algo: Vec<u8>,

    /// Whether the unicast paths have unlimited congestion windows.
    uc_unlimited_cwnd: bool,

    /// The fallback delay of the unicast path.
    fallback_delay: Option<FcFallBackDelay>,

    /// The transmission channels towards the sendmmsg.
    txs_sendmmsg: Option<Vec<mpsc::Sender<MsgSmsg>>>,

    /// Random number generator.
    rng: SystemRandom,

    /// Potential HTTP/3 config.
    h3_config: Option<quiche::h3::Config>,

    /// Transmission channel to the applications.
    tx_app: mpsc::Sender<FcQuicMsg>,
}

impl Handshake {
    /// Creates a new handshake task.
    pub async fn new(
        config: &TokioFcQuicConfig, uc_path_config: Config,
        fc_master_secret: Vec<Vec<u8>>, fc_key_algo: Vec<u8>,
        fc_announce_data: &[McAnnounceData], rng: SystemRandom,
        txs_sendmmsg: Option<Vec<mpsc::Sender<MsgSmsg>>>,
        h3_config: Option<quiche::h3::Config>, tx_app: mpsc::Sender<FcQuicMsg>,
    ) -> Result<Self> {
        let (tx_main, rx_main) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let new_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            None,
        )?;
        new_socket.set_reuse_address(true)?;
        new_socket.set_nonblocking(true)?;
        new_socket.bind(&config.uc_src_addr.into())?;
        let new_socket = UdpSocket::from_std(new_socket.into())?;
        Ok(Self {
            client_ids: HashMap::new(),
            socket: Arc::new(new_socket),
            tx_recvs: Vec::new(),
            fc_flows_stopped: HashSet::new(),
            tx_main,
            rx_main,
            uc_path_config,
            tx_ctls: Vec::new(),
            fc_announce_data: fc_announce_data.to_owned(),
            fc_master_secret,
            fc_key_algo,
            uc_unlimited_cwnd: config.unicast_unlimited_cwnd,
            fallback_delay: config.fallback_delay.clone(),
            txs_sendmmsg,
            rng,
            h3_config,
            tx_app,
        })
    }

    /// Returns the transmission channel to communicate.
    pub fn get_tx(&self) -> mpsc::Sender<MsgMain> {
        self.tx_main.clone()
    }

    pub async fn run(&mut self) -> Result<()> {
        #[cfg(feature = "tokio-tracing")]
        let start = time::Instant::now();
        #[cfg(feature = "tokio-tracing")]
        let frequency = std::time::Duration::from_millis(200);

        // Create receiver monitor.
        #[cfg(feature = "tokio-tracing")]
        let monitor_recv = TaskMonitor::new();
        #[cfg(feature = "tokio-tracing")]
        {
            let monitor_recv_clone = monitor_recv.clone();
            tokio::spawn(async move {
                for metrics in monitor_recv_clone.intervals() {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open("tokio_recv.log")
                        .unwrap();

                    writeln!(
                        file,
                        "{:?} {:?}",
                        time::Instant::now().duration_since(start).as_millis(),
                        metrics
                    )
                    .unwrap();
                    tokio::time::sleep(frequency).await;
                }
            });
        }

        // Timer once all receivers and flexicast flows stopped.
        let mut end_time: Option<std::time::Instant> = None;
        let end_sleep = std::time::Duration::from_secs(5);

        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        let mut next_client_id = 0;
        let local_addr = self.socket.local_addr().unwrap();

        let conn_id_seed =
            ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &self.rng)
                .unwrap();

        // Listens to incoming connections from new clients.
        loop {
            let now = std::time::Instant::now();

            // Comute the timeout once all connections are closed before exiting.
            let exit_timeout = end_time
                .map(|t| t.checked_add(end_sleep).map(|t| t.duration_since(now)))
                .flatten();

            tokio::select! {
                // Receive new packet from unconnected address.
                _ = self.socket.readable() => (),

                // Receive a message for control.
                Some(msg) = self.rx_main.recv() => {
                    self.handle_msg(msg).await.unwrap();

                    // Stop the loop only if all flexicast flows stopped and all active receiver stopped.
                    if self.fc_flows_stopped.len() == 1 {
                        // Try to poll any receiver.
                        let mut any_not_none = false;
                        'ping_client: for client_tx in self.tx_recvs.iter() {
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

            let (len, from) = match self.socket.try_recv_from(&mut buf) {
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
            // We should not enter in the else case because the UDP socket should
            // be connected.
            let mut client = if !self.client_ids.contains_key(&hdr.dcid) &&
                !self.client_ids.contains_key(&hdr.dcid)
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

                    if let Err(e) = self.socket.send_to(out, from).await {
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

                    if let Err(e) = self.socket.send_to(out, from).await {
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
                    &mut self.uc_path_config,
                )
                .unwrap();

                let client_id = next_client_id;
                info!("I give client_id={client_id} to sockaddr={:?}", from);

                // Create a new channel to communicate with the client.
                let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
                self.tx_recvs.push(tx.clone());

                // We round-robin the receivers on the different instances of ctl
                // leaves.
                let tx_ctl =
                    self.tx_ctls[client_id as usize % self.tx_ctls.len()].clone();

                let new_socket = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    None,
                )?;
                new_socket.set_reuse_address(true)?;
                new_socket.set_nonblocking(true)?;
                new_socket.bind(&self.socket.local_addr().unwrap().into())?;
                let new_socket = UdpSocket::from_std(new_socket.into())?;
                new_socket.connect(from).await?;

                #[allow(unused_mut)]
                let mut client = crate::fcquic::uc::UcPath {
                    conn,
                    client_id,
                    listen_fc_channel: false,
                    rng: self.rng.clone(),
                    mc_announce_data: self.fc_announce_data.clone(),
                    mc_master_secret: self.fc_master_secret.clone(),
                    mc_key_algo: self
                        .fc_key_algo
                        .iter()
                        .map(|key| *key)
                        .collect::<Vec<_>>(),
                    rx_ctl: rx,
                    tx_tcl: tx_ctl.clone(),
                    tx_main: self.tx_main.clone(),
                    pending_data: HashMap::new(),
                    uc_sock: new_socket,
                    unlimited_cwnd: self.uc_unlimited_cwnd,
                    fcf_scheduler: self
                        .fallback_delay
                        .clone()
                        .map(|fb| FcFlowAliveScheduler::new(Some(fb), None)),
                    pending_ack: OpenRangeSet::default(),
                    pending_stream_ack: HashMap::new(),
                    h3_conn: None,
                    h3_config: self.h3_config.to_owned(),
                    tx_app: self.tx_app.clone(),
                };

                // Notify the controller with a new receiver.
                let msg = MsgFcCtl::NewClient((next_client_id, tx.clone()));
                tx_ctl.send(msg).await.unwrap();

                // Also notify the SendMMsg instances that there is a new
                // receiver.
                if let Some(txs) = self.txs_sendmmsg.as_ref() {
                    for tx in txs.iter() {
                        // Fc-TODO: This is hardcoded, not beautiful.
                        let mut from_mc = from;
                        from_mc.set_port(self.fc_announce_data[0].udp_port);
                        let msg = MsgSmsg::NewRecv(from_mc);
                        tx.send(msg).await.unwrap();
                    }
                }

                next_client_id += 1;
                self.client_ids.insert(scid.clone(), client_id);

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
                // This is an existing receiver that sends a QUIC packet from a
                // new address. We notify the receiver that it
                // must handle this packet and all new packets
                // from this address.
                let client_id = self.client_ids.get(&hdr.dcid).unwrap();
                let recv_info = quiche::RecvInfo {
                    from,
                    to: self.socket.local_addr().unwrap(),
                    from_mc: false,
                };
                debug!(
                    "Send message to {:?} because recv_info={:?}",
                    client_id, recv_info
                );
                continue;
            };

            let recv_info = quiche::RecvInfo {
                to: self.socket.local_addr().unwrap(),
                from,
                from_mc: false,
            };

            // First recv is handled by the main thread. Subsequent recv are
            // handled by the tokio task.
            let _read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue;
                },
            };

            let mut uc_path = UcPathFileTransfer { 0: client };

            #[cfg(feature = "tokio-tracing")]
            {
                let monitor_recv = monitor_recv.clone();
                tokio::spawn(async move {
                    monitor_recv.instrument(uc_path.run()).await.unwrap();
                });
            }
            #[cfg(not(feature = "tokio-tracing"))]
            {
                tokio::spawn(async move {
                    uc_path.run().await.unwrap();
                });
            }
        }

        Ok(())
    }

    async fn handle_msg(&mut self, msg: MsgMain) -> Result<()> {
        match msg {
            MsgMain::NewCID((client_id, cid)) => {
                debug!("Receiver {client_id} adds a new CID!");
                self.client_ids.insert(cid.into(), client_id);
            },

            MsgMain::FcFlowStop(id) => {
                debug!("New flexicast flow stopped: {}", id);
                self.fc_flows_stopped.insert(id);
            },
        }

        Ok(())
    }

    /// Adds a new leaf controller transmission channel.
    pub fn add_leaf_ctl(&mut self, tx: mpsc::Sender<MsgFcCtl>) {
        self.tx_ctls.push(tx);
    }
}

pub fn get_mc_config(enable_fc: bool, fc_config: &FcConfig) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file(
            Path::new(&fc_config.crt_path)
                .join("cert.crt")
                .to_str()
                .unwrap(),
        )
        .unwrap();
    config
        .load_priv_key_from_pem_file(
            Path::new(&fc_config.crt_path)
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

    config.set_initial_max_data(fc_config.max_data);
    config.set_initial_max_stream_data_bidi_local(fc_config.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(fc_config.max_stream_data);
    config.set_initial_max_stream_data_uni(fc_config.max_stream_data);
    config.set_initial_max_streams_bidi(fc_config.max_stream_data);
    config.set_initial_max_streams_uni(fc_config.max_stream_data);
    config.set_active_connection_id_limit(5);
    config.verify_peer(false);
    config.set_initial_max_path_id(10);
    config.set_enable_flexicast(enable_fc);
    config.set_send_fec(fc_config.fec);
    config.set_recv_fec(fc_config.fec);
    config.enable_pacing(false);
    match fc_config.fc_cca {
        flexicast::cca::FcFlowCwnd::CCA(cca) => config.set_cc_algorithm(cca),
        _ => config.set_cc_algorithm(CongestionControlAlgorithm::DISABLED),
    }
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

pub async fn optional_timeout(
    timeout: Option<std::time::Duration>,
) -> Option<()> {
    match timeout {
        Some(t) => {
            if t != std::time::Duration::ZERO {
                tokio::time::sleep(t).await;
            }
            Some(())
        },
        None => None,
    }
}
