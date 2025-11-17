//! Module for the asynchronous communication with the unicast server instances.

use super::aggregator::FcAggregatedMsg;
use super::messages::*;
use super::scheduler::FcFlowAliveScheduler;
use crate::FcQuicMsg;
use crate::Result;
use quiche::flexicast::ack::OpenRangeSet;
use quiche::flexicast::FlexicastConnection;
use quiche::flexicast::McAnnounceData;
use quiche::h3::Connection as H3Conn;

use log::*;
use quiche::flexicast::McRole;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::collections::hash_map::Entry::Occupied;
use std::collections::hash_map::Entry::Vacant;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc;

pub struct UcPath {
    pub conn: quiche::Connection,
    pub client_id: u64,
    pub listen_fc_channel: bool,
    pub rng: SystemRandom,
    pub rx_ctl: mpsc::Receiver<MsgRecv>,
    pub tx_tcl: mpsc::Sender<MsgFcCtl>,

    pub mc_announce_data: Vec<McAnnounceData>,
    pub mc_master_secret: Vec<Vec<u8>>,
    pub mc_key_algo: Vec<u8>,

    pub tx_main: mpsc::Sender<MsgMain>,

    /// Data received from the application and not yet delivered to QUIC.
    /// If some, we avoid listening again on the data channel to avoid having
    /// too much pending data.
    /// The second value indicates whether this is the last piece of data, i.e.,
    /// 'fin'.
    /// The last value indicates the stream ID.
    pub pending_data: HashMap<u64, BTreeMap<u64, (Arc<Vec<u8>>, bool, usize)>>,

    /// Give a socket to send data in the network using unicast.
    pub uc_sock: tokio::net::UdpSocket,

    /// Whether the unicast path has unlimited congestion window.
    pub unlimited_cwnd: bool,

    pub fcf_scheduler: Option<FcFlowAliveScheduler>,

    /// Pending acknowledgments for the controller.
    pub pending_ack: OpenRangeSet,

    /// Pending aggregated stream acknowledgments from the receivers to the
    /// flexicast flow.
    pub pending_stream_ack: HashMap<u64, OpenRangeSet>,

    /// Potential HTTP/3 connection with the client.
    pub h3_conn: Option<H3Conn>,

    /// Potential HTTP/3 config.
    pub h3_config: Option<quiche::h3::Config>,

    /// Transmission channel to the app.
    pub tx_app: mpsc::Sender<FcQuicMsg>,
}

/// Trait defining a unique function, `run`, which must be implemented by the
/// application to handle the unicast paths.
pub trait UcPathRun {
    /// Main asynchronous I/O and control loop for the unicast path, depending
    /// on the application.
    fn run(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;
}

impl UcPath {
    pub async fn handle_ctl_msg(&mut self, msg: MsgRecv) -> Result<()> {
        // Avoid processing some messages if flexicast is not enabled yet
        // (HTTP/3).
        if self.conn.get_flexicast_attributes().is_none() &&
            !matches!(msg, MsgRecv::DelegateStreams(_) | MsgRecv::Sent(_))
        {
            return Ok(());
        }

        match msg {
            MsgRecv::CloseRtp => {
                debug!("Server {} close RTP", self.client_id);
                _ = self.conn.close(true, 1, &[1]);
            },

            MsgRecv::NewHighestPn((_id, highest_pn, _lowest_pn)) => {
                self.conn.fc_set_highest_fc_pn(highest_pn)?;
            },

            MsgRecv::Sent((fc_id, sent)) => {
                debug!("Notify new sent packets received: {:?}", sent);
                let _ = self.conn.fc_on_new_pkt_sent(fc_id as usize, sent);
                if let Some(scheduler) = self.fcf_scheduler.as_mut() {
                    let now = std::time::Instant::now();
                    scheduler.on_packet_sent(now);
                }
            },

            MsgRecv::DelegateStreams((fc_id, delegated_streams, do_delegate)) => {
                for (delegated_stream, do_del) in
                    delegated_streams.iter().zip(do_delegate.iter())
                {
                    if !*do_del {
                        continue;
                    }

                    // Append data in the hashmap of pending data and don't
                    // directly delegate it.
                    let stream_map =
                        match self.pending_data.entry(delegated_stream.stream_id)
                        {
                            Vacant(entry) => entry.insert(BTreeMap::new()),
                            Occupied(entry) => entry.into_mut(),
                        };
                    let v = stream_map.insert(
                        delegated_stream.offset,
                        (
                            Arc::new(delegated_stream.payload.clone()),
                            delegated_stream.fin,
                            0,
                        ),
                    );
                    if v.is_some() {
                        println!(
                            "Old value for offset {}: {:?} and new length={:?}",
                            delegated_stream.offset,
                            v.unwrap().0.len(),
                            delegated_stream.payload.len()
                        );
                    }
                }

                self.conn.fc_delegated_streams(
                    fc_id,
                    delegated_streams,
                    do_delegate,
                    false,
                )?;
            },

            MsgRecv::StreamData((data, stream_id, off, fin)) => {
                self.handle_new_stream_data(data, stream_id, off, fin)
                    .await?;
            },
        }

        Ok(())
    }

    pub async fn send_ctl_info(&mut self) -> Result<()> {
        // Do nothing if flexicast is disabled.
        if self.conn.get_flexicast_attributes().is_none() {
            return Ok(());
        }

        let fc_id = self
            .conn
            .get_flexicast_attributes()
            .as_ref()
            .unwrap()
            .get_fc_chan_id()
            .map(|(_, id)| *id);

        // Send new acknowledgment information to the controller.
        // This information will be propagated to the flexicast source to release
        // state.
        let (ack_pn, ack_stream) = self.conn.get_new_ack_pn_streams()?;

        // Maybe some pending data.
        let mut pn = std::mem::take(&mut self.pending_ack);
        if let Some(ack) = ack_pn {
            for range in ack.iter() {
                pn.insert(range);
            }
        }

        let mut stream = std::mem::take(&mut self.pending_stream_ack);
        if let Some(mut ack) = ack_stream {
            for (stream_id, ranges) in ack.drain(..) {
                let entry = match stream.entry(stream_id) {
                    Vacant(entry) => entry.insert(OpenRangeSet::default()),
                    Occupied(entry) => entry.into_mut(),
                };

                for range in ranges.iter() {
                    entry.insert(range);
                }
            }
        }

        // Skip if nothing to send.
        if fc_id.is_some() && (pn.len() > 0 || !stream.is_empty()) {
            let fec_rec_md = self
                .conn
                .get_flexicast_attributes()
                .map(|fc| {
                    fc.fc_fec
                        .get_uc_path()
                        .map(|fc_fec| fc_fec.fc_get_recovered_esi())
                })
                .flatten();
            let msg = MsgFcCtl::AckData((
                self.client_id,
                fc_id.unwrap() as u64,
                Some(pn.clone()),
                Some(stream.iter().map(|(s, r)| (*s, r.clone())).collect()),
                fec_rec_md.cloned(),
            ));

            if let Err(_e) = self.tx_tcl.try_send(msg) {
                info!(
                    "Recv {} cannot send the ack because full..",
                    self.client_id
                );
                self.pending_ack = pn;
                self.pending_stream_ack = stream;
            }
        }

        if fc_id.is_none() {
            return Ok(());
        }

        // Sends flow control updates to the controller.
        if let Ok((max_data, max_stream_datas)) =
            self.conn.fc_get_flow_control_updates()
        {
            let aggr_info = FcAggregatedMsg {
                max_data: max_data.unwrap_or(self.conn.fc_get_max_tx_data()?),
                max_stream_datas,
            };
            let msg = MsgFcCtl::AggregatedInfo((
                self.client_id,
                fc_id.unwrap() as u64,
                aggr_info,
            ));
            self.tx_tcl.send(msg).await?;
        }

        Ok(())
    }

    pub async fn recv(
        &mut self, pkt_buf: &mut [u8], recv_info: quiche::RecvInfo,
    ) -> Result<()> {
        debug!(
            "Receive a packet from the client socket! recv_info={:?}",
            recv_info
        );

        // Process potentially coalesced packets.
        let _read = match self.conn.recv(pkt_buf, recv_info) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                error!("{} recv failed: {:?}", self.conn.trace_id(), e);
                return Err(e.into());
            },
        };

        // Provides as many CIDs as possible.
        self.handle_path_events();

        while self.conn.scids_left() > 0 {
            let (scid, reset_token) = {
                let mut scid = [0; 16];
                self.rng.fill(&mut scid).unwrap();
                let scid = scid.to_vec().into();
                let mut reset_token = [0; 16];
                self.rng.fill(&mut reset_token).unwrap();
                let reset_token = u128::from_be_bytes(reset_token);
                (scid, reset_token)
            };
            if let Err(_e) = self.conn.new_scid(&scid, reset_token, false) {
                // error!("Error while sending new source CID: {:?}", e);
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
            let was_fall_back = self
                .conn
                .get_flexicast_attributes()
                .map(|fc| {
                    fc.get_mc_role() ==
                        McRole::ServerUnicast(
                            quiche::flexicast::McClientStatus::UcFallBack,
                        )
                })
                .unwrap_or(false);
            debug!("Recv {} was fallback: {}", self.client_id, was_fall_back);
            if let Some(pn) = self.conn.fc_get_highest_ack_pn() {
                if let Some(fc_chan_id) = self
                    .conn
                    .get_flexicast_attributes()
                    .unwrap()
                    .get_fc_chan_id()
                    .map(|(_, id)| *id)
                {
                    let now = std::time::Instant::now();
                    let fcf_now_alive =
                        fc_scheduler.on_ack_received(pn, now, &self.conn);
                    if was_fall_back && fcf_now_alive {
                        info!("Was fall_back: {was_fall_back}. Now alive={fcf_now_alive}");
                    }
                    if fcf_now_alive && was_fall_back {
                        self.conn.fc_fall_back_unicast(false);

                        // Because the receiver (re-)joins a flexicast flow, give
                        // the updates regarding flow control.
                        let max_data = self.conn.fc_get_max_tx_data()?;
                        let max_stream_datas: HashMap<u64, u64> =
                            self.conn.fc_get_max_tx_streams_data()?.collect();

                        self.tx_tcl
                            .send(MsgFcCtl::Join((
                                self.client_id,
                                fc_chan_id as u64,
                                Some(FcAggregatedMsg {
                                    max_data,
                                    max_stream_datas,
                                }),
                                fc_scheduler.get_last_pn_recv_in_flow(),
                            )))
                            .await?;

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

    pub async fn notify_new_cid(&self, cid: &[u8]) -> Result<()> {
        let msg = MsgMain::NewCID((self.client_id, cid.to_vec()));
        self.tx_main.send(msg).await?;
        debug!("Client sends a new CID message to the main thread");
        Ok(())
    }

    pub async fn handle_new_pkt(
        &mut self, pkt_to_read: &mut [u8], recv_info: quiche::RecvInfo,
    ) -> Result<()> {
        self.recv(pkt_to_read, recv_info).await?;
        Ok(())
    }

    pub async fn handle_new_stream_data(
        &mut self, data: Arc<Vec<u8>>, stream_id: u64, off: u64, fin: bool,
    ) -> Result<()> {
        // Do not say it is an error, but it should not happen.
        if self.listen_fc_channel &&
            self.fcf_scheduler
                .as_ref()
                .map(|fcs| fcs.fcf_alive())
                .unwrap_or(true)
        {
            info!("Recv {} says it's okay, don't need the data. It is still important to send data if there is an offset: {off:?}", self.client_id);
        }

        let stream_map = match self.pending_data.entry(stream_id) {
            Vacant(entry) => entry.insert(BTreeMap::new()),
            Occupied(entry) => entry.into_mut(),
        };
        stream_map.insert(off, (data, fin, 0));

        Ok(())
    }

    pub fn handle_path_events(&mut self) {
        while let Some((path_id, qe)) = self.conn.path_event_next() {
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
                        .probe_path(path_id, local_addr, peer_addr)
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
                            .set_active(path_id, true)
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

                quiche::PathEvent::Closed(local_addr, peer_addr, err) => {
                    info!(
                        "{} Path ({}, {}) is now closed and unusable; err = {}",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr,
                        err,
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
                        .set_path_status(path_id, path_status, false)
                        .map_err(|e| {
                            error!("cannot follow status request: {}", e)
                        })
                        .ok();
                },
            }
        }
    }
}
