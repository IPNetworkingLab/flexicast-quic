//! Module for the asynchronous communication with the flexicast source.

use super::controller;
use super::controller::MsgFcSource;
use super::Result;
use quiche::multicast::McAnnounceData;
use quiche::multicast::MulticastChannelSource;
use quiche::multicast::MulticastConnection;
use tokio::net::UdpSocket;

use crate::mc_app::asynchronous::controller::MsgFcCtl;
use crate::mc_app::rtp::RtpServer;
use std::cmp;
use std::io;
use std::time;
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
}

impl FcChannelAsync {
    pub async fn run(&mut self) -> Result<()> {
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
                .unwrap_or(time::Duration::from_secs(10));

            let sock_rtp = self
                .rtp_server
                .additional_udp_socket_tokio()
                .ok_or(String::from("Using invalid socket for RTP"))?;

            tokio::select! {
                // Timeout sleep.
                _ = tokio::time::sleep(timeout) => {
                    debug!("Flexicast source timeout");
                    // TODO: on_rmc_timeout_server!

                    let now = time::Instant::now();
                    let exp_pkt = self.fc_chan.channel.on_mc_timeout(now)?;

                    // On timeout, inform the controller of the last expired packet.
                    let new_exp_pkt_msg = MsgFcCtl::NewExpiredPkt((self.id, exp_pkt));
                    self.sync_tx.send(new_exp_pkt_msg).await?;
                },

                // Generate video content frames.
                _ = sock_rtp.readable() => {
                    self.rtp_server.on_additional_udp_socket_readable();
                    if self.rtp_server.is_source_rtp_stopped() && rtp_stopped.is_none() {
                        rtp_stopped = Some(time::Instant::now());
                        debug!("Start RTP end timer");
                    }
                },

                // Data on the UDP socket. Do not read it, as we will do it below.
                _ = self.socket.readable() => (),

                // Data on the control channel.
                Some(msg) = self.rx_ctl.recv() => self.handle_ctl_msg(msg).await?,
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
                    let pkt_len = cmp::min(left, super::MAX_DATAGRAM_SIZE);

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

            // Notify the controller of the sent packets.
            self.sent_pkt_to_controller().await?;
        }

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
        }

        Ok(())
    }

    async fn sent_pkt_to_controller(&mut self) -> Result<()> {
        let sent = self.fc_chan.channel.fc_get_sent_pkt()?;

        let msg = MsgFcCtl::Sent((self.id, sent));
        self.sync_tx.send(msg).await?;
        
        Ok(())
    }
}
