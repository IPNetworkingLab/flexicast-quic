//! Module for the asynchronous communication with the flexicast source.

use super::controller;
use super::controller::MsgFcSource;
use super::sendmmsg::MsgSmsg;
use super::Result;
use quiche::multicast::McAnnounceData;
use quiche::multicast::MulticastChannelSource;
use quiche::multicast::MulticastConnection;
use tokio::net::UdpSocket;

use crate::mc_app::asynchronous::controller::optional_timeout;
use crate::mc_app::asynchronous::controller::MsgFcCtl;
use crate::mc_app::rtp::RtpServer;
use std::cmp;
use std::io;
use std::sync::Arc;
use std::time;
use std::usize;
use tokio::sync::mpsc;

pub struct FcChannelInfo {
    pub socket: UdpSocket,
    pub fc_chan: MulticastChannelSource,
    pub mc_announce_data: McAnnounceData,
}

pub struct FcChannelAsync {
    pub socket: UdpSocket,
    pub fc_chan: MulticastChannelSource,
    pub mc_announce_data: McAnnounceData,

    pub rtp_server: RtpServer,

    /// Stop RTP timer.
    /// Once the RTP source sends a STOP RTP message, the source waits for 5 *
    /// flexicast timer before closing the connection.
    pub rtp_stop_timer: time::Duration,

    /// Communication between entities, using tokio mpsc.
    pub sync_tx: mpsc::Sender<controller::MsgFcCtl>,

    /// ID of the flexicast channel.
    pub id: u64,

    /// Reception channel for the flexicast source.
    pub rx_ctl: mpsc::Receiver<MsgFcSource>,

    /// Whether the flexicast source must wait to send packets on the wire.
    pub must_wait: bool,

    /// Whether the flexicast channel will be limited by the application or not.
    /// If set to true, will set an almost infinite congestion window.
    pub bitrate_unlimited: bool,

    /// Whether unicast fall-back is used.
    /// Used to know whether the source must forward application data to the
    /// controller.
    pub allow_unicast: bool,

    /// Whether flexicast is enabled.
    /// Used to know whether the source must send data on the wire.
    pub do_flexicast: bool,

    /// The SendMMsg instances.
    /// If this value is not `None`, it means that we use `sendmmsg` instead of relying
    /// on a multicast network to send the packets on the flexicast flow.
    pub sendmmsg_txs: Option<Vec<mpsc::Sender<MsgSmsg>>>,
}

impl FcChannelAsync {
    pub async fn run(&mut self) -> Result<()> {
        let mut buf = [0u8; 1500];

        // Timer to stop the RTP transmission.
        let mut rtp_stopped = None;
        let mut can_close_conn_after_rtp = false;

        // Compute a second mc send address.
        let mut addr_buf = self.mc_announce_data.group_ip;
        addr_buf[0] += 1;
        let second_mc_ip_addr = std::net::Ipv4Addr::from(addr_buf);
        let _second_mc_addr =
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                second_mc_ip_addr,
                self.mc_announce_data.udp_port,
            ));

        // If we use `sendmmsg` insteaf or real multicast, we will round-robin to spread the traffic.
        let mut sendmmsg_idx = 0;

        loop {
            let now = time::Instant::now();
            let timeout = self.fc_chan.channel.mc_timeout(now);

            let sock_rtp = self
                .rtp_server
                .additional_udp_socket_tokio()
                .ok_or(String::from("Using invalid socket for RTP"))?;

            tokio::select! {
                // Timeout sleep.
                Some(_) = optional_timeout(timeout) => {
                    self.on_timeout().await?;
                },

                // Generate video content frames.
                _ = sock_rtp.readable() => {
                    self.rtp_server.on_additional_udp_socket_readable();
                    if self.rtp_server.is_source_rtp_stopped() && rtp_stopped.is_none() {
                        rtp_stopped = Some(time::Instant::now());
                        debug!("Start RTP end timer");
                    }
                },

                // Data on the control channel.
                Some(msg) = self.rx_ctl.recv() => self.handle_ctl_msg(msg).await?,
            }

            // Check again if there is some timeout there.
            let now = time::Instant::now();
            if let Some(time::Duration::ZERO) = self.fc_chan.channel.mc_timeout(now) {
                self.on_timeout().await?;
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
                    .send(controller::MsgFcCtl::CloseRtp(self.id))
                    .await?;

                // Notify the SendMMsg instances.
                if let Some(txs) = self.sendmmsg_txs.as_ref() {
                    for tx in txs.iter() {
                        let msg = MsgSmsg::Stop;
                        tx.send(msg).await?;
                    }
                }

                break;
            }

            // Loop to ensure to dequeue all pending data.
            'rtp: loop {
                if self.rtp_server.should_send_app_data() {
                    let (stream_id, app_data) = self.rtp_server.get_app_data();

                    // If allow unicast, sends the data to the controller to
                    // ensure that all unicast receiver get it.
                    if self.allow_unicast {
                        let msg = MsgFcCtl::RtpData((
                            Arc::new(app_data.clone()),
                            stream_id,
                        ));
                        self.sync_tx.send(msg).await?;
                    }

                    let written = if self.must_wait || !self.do_flexicast {
                        app_data.len()
                    } else {
                        match self
                            .fc_chan
                            .channel
                            .stream_priority(stream_id, 0, false)
                        {
                            Ok(()) => (),
                            Err(quiche::Error::StreamLimit) => (),
                            Err(quiche::Error::Done) => (),
                            Err(e) => panic!(
                                "Error while setting stream priority: {:?}",
                                e
                            ),
                        }

                        match self
                            .fc_chan
                            .channel
                            .stream_send(stream_id, &app_data, true)
                        {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => break 'rtp,
                            Err(e) => panic!("Other error: {:?}", e),
                        }
                    };

                    self.rtp_server.stream_written(written);
                } else {
                    break;
                }
            }

            // Do nothing if flexicast is disabled.
            if self.do_flexicast {
                // Generate outgoing QUIC packets to send on the Flexicast path.
                'fc: loop {
                    // Ask quiche to generate the packets.
                    let (write, send_info) =
                        match self.fc_chan.mc_send(&mut buf[..]) {
                            Ok(v) => v,

                            Err(quiche::Error::Done) => break,

                            Err(e) => {
                                error!("Flexicast send() failed: {:?}", e);
                                break 'fc;
                            },
                        };

                    // Send the packets on the wire.
                    if !self.must_wait {
                        // Use `sendmmsg` instead.
                        if let Some(sendmmsg_tx) = &self.sendmmsg_txs {
                            let tx = sendmmsg_tx.get(sendmmsg_idx);
                            if let Some(tx) = tx {
                                let msg = MsgSmsg::Packet(buf[..write].to_vec());
                                tx.send(msg).await?;
                            }

                            // Next time we use another instance.
                            sendmmsg_idx = (sendmmsg_idx + 1) % sendmmsg_tx.len();
                        } else {
                            let mut off = 0;
                            let mut left = write;
                            let mut written = 0;
    
                            while left > 0 {
                                let pkt_len =
                                    cmp::min(left, super::MAX_DATAGRAM_SIZE);
    
                                match self
                                    .socket
                                    .send_to(
                                        &buf[off..off + pkt_len],
                                        self.fc_chan.mc_send_addr,
                                    )
                                    .await
                                {
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
                            debug!(
                                "Flexicast written {:?} bytes to {:?}",
                                written, send_info
                            );
                        }
                    } else {
                        debug!("Not actually sending data on the wire because we wait...");
                    }
                }

                // Notify the controller of the sent packets.
                self.sent_pkt_to_controller().await?;

                // Potentially unlimit the congestion window.
                if self.bitrate_unlimited {
                    self.fc_chan.channel.mc_set_cwnd(usize::MAX - 1000);
                }
            }
        }

        Ok(())
    }

    async fn on_timeout(&mut self) -> Result<()> {
        debug!("Flexicast source timeout");

        let now = time::Instant::now();
        let exp_pkt = self.fc_chan.channel.on_mc_timeout(now)?;

        // On timeout, inform the controller of the last expired packet.
        let new_exp_pkt_msg = MsgFcCtl::NewExpiredPkt((self.id, exp_pkt));
        self.sync_tx.send(new_exp_pkt_msg).await?;

        // On timeout, also delegate lost STREAM frames to the controller,
        // that will dispatch them to all unicast paths for retransmission.
        let delegated_streams =
            self.fc_chan.channel.fc_get_delegated_stream(false)?;
        debug!("Delegates streams: {:?}", delegated_streams.len());
        let del_streams_msg =
            MsgFcCtl::DelegateStreams((self.id, delegated_streams, false));
        self.sync_tx.send(del_streams_msg).await?;

        Ok(())
    }

    async fn handle_ctl_msg(&mut self, msg: MsgFcSource) -> Result<()> {
        let now = time::Instant::now();

        match msg {
            MsgFcSource::AckPn(ranges) => {
                self.fc_chan.channel.fc_on_ack_received(&ranges, now)?;
            },

            MsgFcSource::AckStreamPieces(mut stream_pieces) => {
                for (stream_id, ranges) in stream_pieces.drain(..) {
                    for range in ranges.iter() {
                        self.fc_chan.channel.fc_on_stream_ack_received(
                            stream_id,
                            range.start,
                            range.end - range.start,
                        )?;
                    }
                }
            },

            MsgFcSource::Ready => {
                self.must_wait = false;
            },

            MsgFcSource::AskStreamPieces => {
                let delegated_streams =
                    self.fc_chan.channel.fc_get_delegated_stream(true)?;
                let del_streams_msg =
                    MsgFcCtl::DelegateStreams((self.id, delegated_streams, true));
                self.sync_tx.send(del_streams_msg).await?;
            },
        }

        Ok(())
    }

    async fn sent_pkt_to_controller(&mut self) -> Result<()> {
        let sent = match self.fc_chan.channel.fc_get_sent_pkt(None) {
            Ok(v) => v,
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let msg = MsgFcCtl::Sent((self.id, sent));
        self.sync_tx.send(msg).await?;

        Ok(())
    }
}
