//! Module for the asynchronous communication with the unicast server instances.

use crate::mc_app::asynchronous::controller::optional_timeout;
use crate::mc_app::rtp::BufType;
use crate::mc_app::rtp::RtpServer;

use super::controller;
use super::controller::MsgFcCtl;
use super::controller::MsgMain;
use super::controller::MsgRecv;
use super::scheduler::FcFlowAliveScheduler;
use super::Result;
use quiche::multicast::McAnnounceData;
use quiche::multicast::McClientStatus;
use quiche::multicast::McRole;
use quiche::multicast::MulticastConnection;

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc;

pub struct Client {
    pub conn: quiche::Connection,
    pub client_id: u64,
    pub listen_fc_channel: bool,
    pub rng: SystemRandom,
    pub rx_ctl: mpsc::Receiver<controller::MsgRecv>,
    pub tx_tcl: mpsc::Sender<controller::MsgFcCtl>,

    pub mc_announce_data: Vec<McAnnounceData>,
    pub mc_master_secret: Vec<Vec<u8>>,
    pub mc_key_algo: Vec<u8>,

    pub tx_main: mpsc::Sender<MsgMain>,

    /// Give an RTP source in case the receiver uses unicast.
    pub rtp_source: RtpServer,

    /// Give a socket to send data in the network using unicast.
    pub uc_sock: Arc<tokio::net::UdpSocket>,

    /// Whether the unicast path has unlimited congestion window.
    pub unlimited_cwnd: bool,

    /// Previously sent congestion window update.
    /// Only send new congestion window updates if it changed.
    /// `None` means that we should never forward the cwnd.
    pub previous_cwnd: Option<usize>,

    pub fcf_scheduler: Option<FcFlowAliveScheduler>,
}

impl Client {
    pub async fn run(&mut self) -> Result<()> {
        // Before entering the loop, set the McAnnounceData to the client.
        for (i, mc_announce_data) in self.mc_announce_data.iter().enumerate() {
            self.conn.mc_set_mc_announce_data(mc_announce_data).unwrap();
            // FC-TODO: now we set to 1 the space ID but it is not ideal...
            self.conn
                .mc_set_multicast_receiver(
                    &self.mc_master_secret[i],
                    1,
                    self.mc_key_algo[i].try_into().unwrap(),
                    Some(i),
                )
                .unwrap();
        }

        // The first read was already performed. Directly go to the write.
        let mut first_read = true;

        // Whether it already notified the controller that it is ready.
        let mut sent_ready = false;

        let mut buf = [0u8; 1500];
        loop {
            let timeout = self.conn.timeout();
            let now = std::time::Instant::now();
            let fcf_timeout = self
                .fcf_scheduler
                .as_ref()
                .map(|s| s.fcf_timeout(now))
                .flatten();
            let fc_chan_id = self
                .conn
                .get_multicast_attributes()
                .map(|mc| mc.get_fc_chan_id().map(|(_, id)| *id as u64))
                .flatten();

            if !first_read {
                tokio::select! {
                    // Timeout sleep.
                    Some(_) = optional_timeout(timeout) => self.conn.on_timeout(),

                    // Flexicast flow timeout sleep.
                    Some(_) = optional_timeout(fcf_timeout) => {
                        if let Some(scheduler) = self.fcf_scheduler.as_mut() {
                            let now = std::time::Instant::now();
                            if scheduler.should_uc_fall_back(now) {
                                self.fcf_scheduler.as_mut().map(|s| s.uc_fall_back());
                                let msg = MsgFcCtl::RecvUcFallBack((self.client_id, fc_chan_id.unwrap()));
                                self.tx_tcl.send(msg).await?;
                                let now = SystemTime::now();
                                println!("{}-RESULT-RECV{} 1", now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_micros(), self.client_id);
                            }
                        }
                    },

                    // Data on the control channel.
                    Some(msg) = self.rx_ctl.recv() => self.handle_ctl_msg(msg).await?,
                }
            }

            first_read = false;

            // Informs the controller whether the client listens to a flexicast
            // flow.
            if let (false, Some(mc)) =
                (self.listen_fc_channel, self.conn.get_multicast_attributes())
            {
                if let Some((_, fc_id)) = mc.get_fc_chan_id() {
                    self.listen_fc_channel = true;
                    self.tx_tcl
                        .send(controller::MsgFcCtl::Join((
                            self.client_id,
                            *fc_id as u64,
                        )))
                        .await?;
                }
            }

            // Informs the controller that it is ready to listen to flexicast
            // content.
            if let Some(mc) = self.conn.get_multicast_attributes() {
                if let (
                    false,
                    McRole::ServerUnicast(McClientStatus::ListenMcPath(true)),
                ) = (sent_ready, mc.get_mc_role())
                {
                    let msg = MsgFcCtl::RecvReady(self.client_id);
                    self.tx_tcl.send(msg).await.unwrap();
                    sent_ready = true;
                    if let Some(ref mut scheduler) = self.fcf_scheduler {
                        scheduler.set_fcf_alive();
                    }
                }
            }

            // Sends to QUIC RTP frames that must be sent through unicast.
            'rtp: loop {
                if self.rtp_source.should_send_app_data() {
                    let (stream_id, app_data) = self.rtp_source.get_app_data();

                    match self.conn.stream_priority(stream_id, 0, false) {
                        Ok(()) => (),
                        Err(quiche::Error::StreamLimit) => (),
                        Err(quiche::Error::Done) => (),
                        Err(e) => {
                            panic!("Error while setting stream priority: {:?}", e)
                        },
                    }

                    let written =
                        match self.conn.stream_send(stream_id, &app_data, true) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => break 'rtp,
                            Err(e) => panic!("Other error: {:?}", e),
                        };

                    self.rtp_source.stream_written(written);
                } else {
                    break;
                }
            }

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            'send: loop {
                let (write, send_info) = match self.conn.send(&mut buf[..]) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("QUICHE says DONE here");
                        break 'send;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", self.conn.trace_id(), e);

                        self.conn.close(false, 0x1, b"fail").ok();
                        break 'send;
                    },
                };

                // Send the packet directly to the wire without going by the main
                // thread.
                self.uc_sock.send_to(&buf[..write], send_info.to).await?;
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

            // Send control information to the controller.
            self.send_ctl_info().await?;

            // Force an unlimited window if asked.
            if self.unlimited_cwnd {
                self.conn.fc_force_cwin_path_id(0, usize::MAX - 1000);
            }
        }

        Ok(())
    }

    async fn handle_ctl_msg(&mut self, msg: MsgRecv) -> Result<()> {
        match msg {
            MsgRecv::CloseRtp => {
                debug!("Server {} close RTP", self.client_id);
                _ = self.conn.close(true, 1, &[1]);
            },

            MsgRecv::NewExpiredPkt((_id, exp_pkt)) => {
                self.conn.fc_set_last_expired(Some(exp_pkt));
            },

            MsgRecv::Sent((fc_id, sent)) => {
                let _ = self.conn.fc_on_new_pkt_sent(fc_id, sent);
                if let Some(scheduler) = self.fcf_scheduler.as_mut() {
                    let now = std::time::Instant::now();
                    scheduler.on_packet_sent(now);
                }
            },

            MsgRecv::DelegateStreams((fc_id, delegated_streams)) => {
                self.conn.fc_delegated_streams(fc_id, delegated_streams)?;
            },

            MsgRecv::NewPkt((pkt_to_read, new_addr)) => {
                self.handle_new_pkt(pkt_to_read, new_addr).await?;
            },

            MsgRecv::RtpData((data, stream_id)) => {
                self.handle_new_rtp(data, stream_id).await?;
            },
        }

        Ok(())
    }

    async fn send_ctl_info(&mut self) -> Result<()> {
        // Do nothing if multicast is disabled.
        if self.conn.get_multicast_attributes().is_none() {
            return Ok(());
        }

        let fc_id = self
            .conn
            .get_multicast_attributes()
            .as_ref()
            .unwrap()
            .get_fc_chan_id()
            .map(|(_, id)| *id);

        // Send new acknowledgment information to the controller.
        // This information will be propagated to the flexicast source to release
        // state.
        let (ack_pn, ack_stream) = self.conn.get_new_ack_pn_streams()?;
        // Skip if nothing to send.
        if fc_id.is_some() && (ack_pn.is_some() || ack_stream.is_some()) {
            let msg = MsgFcCtl::AckData((
                self.client_id,
                fc_id.unwrap() as u64,
                ack_pn.clone(),
                ack_stream,
            ));
            self.tx_tcl.send(msg).await?;
        }

        // Send new congestion window update if the new value is significantly different from the previously sent value.
        if let (Some(cwnd), Some(previous_cwnd)) =
            (self.conn.fc_get_cwnd_recv(), self.previous_cwnd)
        {
            // TODO: define "significant".
            if cwnd > previous_cwnd || cwnd < previous_cwnd {
                self.previous_cwnd = Some(cwnd);
                let msg =
                    MsgFcCtl::Cwnd((self.client_id, fc_id.unwrap() as u64, cwnd));
                self.tx_tcl.send(msg).await?;
            }
        }

        Ok(())
    }

    async fn recv(
        &mut self, pkt_buf: &mut [u8], recv_info: quiche::RecvInfo,
    ) -> Result<()> {
        debug!(
            "Receive a packet from the client socket! recv_info={:?}",
            recv_info
        );

        // Process potentially coalesced packets.
        let _read = match self.conn.recv(pkt_buf, recv_info) {
            Ok(v) => v,

            Err(e) => {
                error!("{} recv failed: {:?}", self.conn.trace_id(), e);
                return Err(e.into());
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
            if self.conn.new_source_cid(&scid, reset_token, false).is_err() {
                error!("Error while sending new source CID");
                break;
            }
            info!("add a new source cid: {:?}", scid.as_ref());

            // Notifies the main thread that this connection has a new source CID.
            self.notify_new_cid(scid.as_ref()).await?;
        }

        // Also update state of the scheduler.
        // Maybe now we received acknowkledgment from the receiver that will
        // update its state in the flexicast flow.
        if let Some(fc_scheduler) = self.fcf_scheduler.as_mut() {
            let last_pn = self
                .conn
                .get_multicast_attributes()
                .map(|mc| {
                    mc.rmc_get().server().map(|s| s.get_highest_pn()).flatten()
                })
                .flatten();
            if let Some(pn) = last_pn {
                if let Some(fc_chan_id) = self
                    .conn
                    .get_multicast_attributes()
                    .unwrap()
                    .get_fc_chan_id()
                    .map(|(_, id)| *id)
                {
                    let now = std::time::Instant::now();
                    let fcf_now_alive =
                        fc_scheduler.on_ack_received(pn, now, &self.conn);
                    if fcf_now_alive {
                        self.tx_tcl
                            .send(controller::MsgFcCtl::Join((
                                self.client_id,
                                fc_chan_id as u64,
                            )))
                            .await?;

                        // Must also send a message to notify
                        // its state regarding the congestion window,
                        // because the controller might have erased state for this receiver.
                        if let Some(cwnd) = self.conn.fc_get_cwnd_recv() {
                            self.previous_cwnd = Some(cwnd);
                            let msg = MsgFcCtl::Cwnd((
                                self.client_id,
                                fc_chan_id as u64,
                                cwnd,
                            ));
                            self.tx_tcl.send(msg).await?;
                        }

                        // Record on NPF.
                        let now = SystemTime::now();
                        println!(
                            "{}-RESULT-RECV{} 2",
                            now.duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_micros(),
                            self.client_id
                        );
                    }
                }
            }
        }

        Ok(())
    }

    async fn notify_new_cid(&self, cid: &[u8]) -> Result<()> {
        let msg = MsgMain::NewCID((self.client_id, cid.to_vec()));
        self.tx_main.send(msg).await?;
        debug!("Client sends a new CID message to the main thread");
        Ok(())
    }

    async fn handle_new_pkt(
        &mut self, mut pkt_to_read: Vec<u8>, recv_info: quiche::RecvInfo,
    ) -> Result<()> {
        self.recv(&mut pkt_to_read, recv_info).await?;
        Ok(())
    }

    async fn handle_new_rtp(
        &mut self, data: Arc<Vec<u8>>, stream_id: u64,
    ) -> Result<()> {
        // Do not say it is an error, but it should not happen.
        if self.listen_fc_channel
            && self
                .fcf_scheduler
                .as_ref()
                .map(|fcs| fcs.fcf_alive())
                .unwrap_or(true)
        {
            return Ok(());
        }

        self.rtp_source
            .handle_new_rtp_frame(BufType::Buffer(&data), stream_id);

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
