//! Module for the asynchronous communication with the unicast server instances.

use crate::mc_app::asynchronous::controller::optional_timeout;

use super::controller;
use super::controller::MsgFcCtl;
use super::controller::MsgMain;
use super::controller::MsgRecv;
use super::Result;
use quiche::multicast::McAnnounceData;
use quiche::multicast::MulticastConnection;

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::convert::TryInto;
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

        let mut buf = [0u8; 1500];
        loop {
            let timeout = self.conn.timeout();

            if !first_read {
                tokio::select! {
                    // Timeout sleep.
                    Some(_) = optional_timeout(timeout) => self.conn.on_timeout(),

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

                // Send the packet to the main thread to send it on the wire.
                let msg = MsgMain::SendPkt((buf[..write].to_vec(), send_info));
                debug!(
                    "Send packet to main thread with send_info={:?}",
                    send_info
                );
                self.tx_main.send(msg).await?;
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
                self.conn.fc_on_new_pkt_sent(fc_id, sent)?;
            },

            MsgRecv::DelegateStreams((fc_id, delegated_streams)) => {
                self.conn.fc_delegated_streams(fc_id, delegated_streams)?;
            },

            MsgRecv::NewPkt((pkt_to_read, new_addr)) => {
                self.handle_new_pkt(pkt_to_read, new_addr).await?;
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
                ack_pn,
                ack_stream,
            ));
            self.tx_tcl.send(msg).await?;
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
