//! Flexicast QUIC receiver wrapped in tokio.

use crate::Result;
use log::*;
use quiche::flexicast::FlexicastConnection;
use quiche::flexicast::McClientStatus;
use quiche::flexicast::McRole;
use quiche::h3::Connection as H3Conn;
use quiche::h3::Header;
use quiche::Config;
use quiche::ConnectionId;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::fs::File;
use std::net;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::FcQuicMsg;
use crate::CHANNEL_BUFFER_SIZE;
use crate::MAX_DATAGRAM_SIZE;

#[cfg(feature = "qlog")]
use crate::make_qlog_writer;

/// Creates a Flexicast QUIC receiver using tokio.
pub struct TokioFcQuicRecv {
    /// QUIC configuration.
    config: Config,

    /// Local IP to bind to multicast.
    local_ip: Ipv4Addr,

    /// Whether to perform flexicast.
    flexicast: bool,

    /// Transmission channel to send data from QUIC to the app.
    /// Quiche -> App
    tx_app: mpsc::Sender<FcQuicMsg>,

    /// Reception channel to receive data from the app to QUIC.
    /// App -> Quiche
    rx_app: mpsc::Receiver<FcQuicMsg>,

    /// Address of the server to contact.
    peer_addr: SocketAddr,

    /// Whether we do unicast proxy.
    proxy_uc: bool,

    h3_config: Option<quiche::h3::Config>,

    /// Potential HTTP/3 request state on the receiver.
    h3_conn: Option<H3Conn>,

    /// Potential HTTP/3 pending request.
    h3_pending_request: Option<Vec<Header>>,

    keylog_file: Option<File>,
}

impl TokioFcQuicRecv {
    /// Creates a new instance.
    pub fn new(
        peer_addr: SocketAddr, config: Config, local_ip: Ipv4Addr,
        flexicast: bool, proxy_uc: bool,
        rx_app_quiche: mpsc::Receiver<FcQuicMsg>,
        h3_config: Option<quiche::h3::Config>, keylog_file: Option<File>,
    ) -> (Self, mpsc::Receiver<FcQuicMsg>) {
        // Tokio Channel Quiche -> App
        let (tx_quiche_app, rx_quiche_app) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        (
            Self {
                peer_addr,
                config,
                local_ip,
                flexicast,
                tx_app: tx_quiche_app,
                rx_app: rx_app_quiche,
                proxy_uc,
                h3_config,
                h3_conn: None,
                h3_pending_request: None,
                keylog_file,
            },
            rx_quiche_app,
        )
    }

    /// Asynchronously runs the Flexicast QUIC receiver, sending data to the
    /// application.
    pub async fn run(&mut self) -> crate::Result<()> {
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // Creation of the flexicast path.
        let mut added_mc_cid = false;
        let mut probe_mc_path = false;

        let mut mc_socket_opt: Option<UdpSocket> = None;
        let mut joined_mc_ip = false;
        let mc_addr: SocketAddr = "0.0.0.0:4433".parse()?;

        // Create the UDP socket backing the QUIC connection.
        let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse()?;
        let mut socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        // Generate a random source connection ID for the connection.
        let mut scid = [0; 16];
        let random = SystemRandom::new();
        random.fill(&mut scid[..]).unwrap();

        let scid = quiche::ConnectionId::from_ref(&scid);
        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(
            None,
            &scid,
            local_addr,
            self.peer_addr,
            &mut self.config,
        )?;
        if let Some(keylog) = &self.keylog_file {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }

        // Stream ID of the HTTP/3 request.
        let mut _h3_stream_id: Option<u64> = None;

        // Only bother with qlog if the user specified it.
        #[cfg(feature = "qlog")]
        {
            if let Some(dir) = std::env::var_os("QLOGDIR") {
                let id = format!("Client-{}", self.local_ip.to_string());
                let writer = make_qlog_writer(&dir, "client", &id);

                conn.set_qlog(
                    std::boxed::Box::new(writer),
                    "quiche-client qlog".to_string(),
                    format!("{} id={}", "quiche-client qlog", id),
                );
            }
        }

        info!(
            "connecting to {:} from {:} with scid {}",
            self.peer_addr,
            socket.local_addr()?,
            hex_dump(&scid)
        );

        let (write, send_info) =
            conn.send(&mut out).expect("initial send failed");
        socket.send_to(&out[..write], send_info.to).await?;

        loop {
            let timeout = conn.timeout();
            let mut read_uc = false;
            let mut read_mc = false;

            tokio::select! {
                Some(_) = optional_timeout(timeout) => {
                    conn.on_timeout();
                },

                Ok((len, from)) = socket.recv_from(&mut buf) => {
                    let recv_info = quiche::RecvInfo {
                        to: socket.local_addr()?,
                        from,
                        from_mc: false,
                    };
                    conn.recv(&mut buf[..len], recv_info)?;
                    read_uc = true;
                },

                Ok((len, from)) = optional_recv_from(mc_socket_opt.as_ref(), &mut out) => {
                    let recv_info = quiche::RecvInfo {
                        to: mc_addr,
                        from,
                        from_mc: true,
                    };
                    conn.recv(&mut out[..len], recv_info)?;
                    read_mc = true;
                },

                Some(msg) = self.rx_app.recv() => {
                    if self.recv_app_msg(msg)? {
                        conn.close(true, 0x00, b"bye")?;
                    }
                }
            }

            // Sets the HTTP/3 connection if a configuration was provided.
            if conn.is_established() && self.h3_conn.is_none() {
                if let Some(h3_config) = self.h3_config.as_ref() {
                    self.h3_conn =
                        Some(H3Conn::with_transport(&mut conn, h3_config)?);
                }
            }

            // Going out of the tokio select. Process all incomming packets at
            // once, avoiding costly sent of packets.
            let mut i = 0;
            let nb_read_max = 10;
            if read_uc {
                'uc_read: loop {
                    if let Ok((len, from)) = socket.try_recv_from(&mut buf) {
                        let recv_info = quiche::RecvInfo {
                            to: socket.local_addr()?,
                            from,
                            from_mc: false,
                        };
                        conn.recv(&mut buf[..len], recv_info)?;
                    } else {
                        break 'uc_read;
                    }
                    i += 1;
                    if i > nb_read_max {
                        debug!("READ {i} packets through UC. Going out...");
                        break;
                    }
                }
            }
            i = 0;
            if read_mc {
                if let Some(mc_socket) = mc_socket_opt.as_ref() {
                    'mc_read: loop {
                        if let Ok((len, from)) = mc_socket.try_recv_from(&mut buf)
                        {
                            let recv_info = quiche::RecvInfo {
                                to: mc_addr,
                                from,
                                from_mc: true,
                            };
                            conn.recv(&mut buf[..len], recv_info)?;
                        } else {
                            break 'mc_read;
                        }
                        i += 1;
                        if i > nb_read_max {
                            debug!("READ {i} packets through MC. Going out...");
                            break;
                        }
                    }
                }
            }

            // Process flexicast events.
            if conn.get_flexicast_attributes().is_some() && self.flexicast {
                // Join the flexicast channel and creates the listening socket if
                // not already done.
                if matches!(
                    conn.get_flexicast_attributes().unwrap().get_mc_role(),
                    McRole::Client(McClientStatus::AwareUnjoined)
                        | McRole::Client(McClientStatus::Changing)
                ) {
                    debug!("Client joins the flexicast channel.");

                    // Did not join the flexicast channel before.
                    let flexicast = conn.get_flexicast_attributes().unwrap();
                    let mc_announce_data =
                        flexicast.get_mc_announce_data(0).unwrap().to_owned();

                    // Add the new connection ID for the announce data.
                    if !added_mc_cid {
                        debug!("Add a new connection ID");
                        let scid =
                            ConnectionId::from_ref(&mc_announce_data.channel_id);
                        conn.add_mc_cid(&scid)?;
                    }

                    // Create a second path.
                    if !probe_mc_path && added_mc_cid {
                        debug!("Create the second path. Client addr={:?}. Server addr={:?}", mc_addr, self.peer_addr);
                        let src_ip = Ipv4Addr::from(mc_announce_data.source_ip);
                        let src_addr =
                            SocketAddr::V4(SocketAddrV4::new(src_ip, 4443));
                        let fc_path_id = conn.create_mc_path(
                            mc_addr,
                            src_addr,
                            mc_announce_data.probe_path,
                        );
                        println!("Out of create mc path:{:?}", fc_path_id);
                        if let Ok(fc_path_id) = fc_path_id {
                            conn.fc_set_path_id(Some(fc_path_id))?;

                            // If soft-flexicast is used by the source, the client
                            // will receive flexicast QUIC
                            // packets with its unicast
                            // address as destination of the IP packet. Bind the
                            // socket to the local address
                            // with the flexicast destination
                            // port.
                            let mc_group_sockaddr: net::SocketAddr =
                                if mc_announce_data.probe_path {
                                    let ip = socket.local_addr()?.ip();
                                    net::SocketAddr::new(
                                        ip,
                                        mc_announce_data.udp_port,
                                    )
                                } else {
                                    let group_ip = if self.proxy_uc {
                                        "0.0.0.0".parse()?
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

                            let mc_socket =
                                UdpSocket::bind(mc_group_sockaddr).await?;

                            info!(
                                "Multicast client binds on address: {:?}",
                                mc_group_sockaddr
                            );
                            probe_mc_path = true;
                            mc_socket_opt = Some(mc_socket);

                            conn.mc_join_channel(
                                false,
                                Some(&mc_announce_data.channel_id),
                            )?;
                        }
                    }
                    added_mc_cid = true;
                }

                // Join the flexicast socket.
                if let Some(flexicast) = conn.get_flexicast_attributes() {
                    if flexicast.get_mc_role()
                        == McRole::Client(McClientStatus::ListenMcPath(true))
                        && !joined_mc_ip
                        && !self.proxy_uc
                    {
                        info!("Join MULTICAST");
                        mc_socket_opt.as_mut().unwrap().join_multicast_v4(
                            net::Ipv4Addr::from(
                                flexicast
                                    .get_mc_announce_data(0).ok_or("Impossible to fetch the FC_ANNOUNCE_DATA")?
                                    .group_ip
                                    .to_owned(),
                            ),
                            self.local_ip,
                        )?;
                        joined_mc_ip = true;
                    }
                }
            }

            // Process all readable streams.
            'streams: for stream_id in conn.readable() {
                if stream_id & 0b11 == 0b11 && stream_id > 30 {
                    if !conn.stream_readable(stream_id) {
                        continue 'streams;
                    }

                    while let Ok((read, fin)) =
                        conn.stream_recv(stream_id, &mut buf[..])
                    {
                        let msg = FcQuicMsg::Stream((
                            buf[..read].to_vec(),
                            fin,
                            stream_id,
                        ));
                        self.tx_app.send(msg).await?;
                    }
                }
            }

            // Sends the HTTP/3 request.
            if let Some(h3_conn) = self.h3_conn.as_mut() {
                if let Some(headers) = self.h3_pending_request.take() {
                    let _ = h3_conn.send_request(&mut conn, &headers, true);
                }
            }

            // Processes HTTP/3 events.
            loop {
                if let Some(h3_conn) = self.h3_conn.as_mut() {
                    match h3_conn.poll(&mut conn) {
                        Ok((
                            _stream_id,
                            quiche::h3::Event::Headers { list, .. },
                        )) => {
                            let msg = FcQuicMsg::Http3RespHeader(list);
                            self.tx_app.send(msg).await?;
                        },

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            while let Ok(read) =
                                h3_conn.recv_body(&mut conn, stream_id, &mut buf)
                            {
                                let msg = FcQuicMsg::Http3RespBody(
                                    buf[..read].to_vec(),
                                );
                                self.tx_app.send(msg).await?;
                            }
                        },

                        Err(quiche::h3::Error::Done) => break,

                        Ok(_) => (),

                        Err(e) => return Err(e.into()),
                    }
                } else {
                    break;
                }
            }

            // Generate outgoing QUIC packets and send them on the UDP socket,
            // until quiche reports that there are no more packets to
            // be sent.
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
                // The client may send packets on the flexicast channel for the
                // path probing phase.
                let src_port = send_info.from.port();
                let out_socket =
                    if src_port == socket.local_addr().unwrap().port() {
                        &mut socket
                    } else if src_port == mc_addr.port() {
                        mc_socket_opt.as_mut().expect("Multicast socket is None")
                    } else {
                        panic!(
                            "Unknown source addr to send packets: {:?}",
                            send_info
                        );
                    };
                out_socket.send_to(&out[..write], send_info.to).await?;
            }

            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                break;
            }
        }

        Ok(())
    }

    /// Receives a message from the application to send to QUIC.
    pub fn recv_app_msg(&mut self, msg: FcQuicMsg) -> Result<bool> {
        match msg {
            FcQuicMsg::Http3Request(headers) => {
                self.h3_pending_request = Some(headers);
            },

            FcQuicMsg::Close => {
                return Ok(true); // Close.
            },

            _ => panic!("Cannot send other message from the receiving-side"),
        }

        Ok(false)
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
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

async fn optional_recv_from(
    opt_sock: Option<&UdpSocket>, buf: &mut [u8],
) -> Result<(usize, SocketAddr)> {
    match opt_sock {
        Some(socket) => socket.recv_from(buf).await.map_err(|e| e.into()),
        None => Err(Box::new(quiche::Error::Done)),
    }
}
