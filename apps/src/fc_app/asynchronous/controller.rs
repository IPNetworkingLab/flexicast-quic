//! Asynchronous control loop between flexicast source and unicast server with
//! tokio.

use std::collections::hash_map::Entry::Occupied;
use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time;

use crate::common::ClientIdMap;
use crate::send_uc_path;

use super::aggregator::FcAggregatedMsg;
use super::aggregator::FcAggregator;
use super::messages::*;
use super::Result;
use quiche::flexicast::ack::FcDelegatedStream;
use quiche::flexicast::ack::McAck;
use quiche::flexicast::ack::McStreamOff;
use quiche::flexicast::ack::OpenRangeSet;
use quiche::flexicast::control::OpenSent;
use quiche::flexicast::McAnnounceData;
use tokio;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Controller structure using tokio to handle messages between the flexicast
/// source and the unicast server instances.
pub struct FcController {
    /// The reception channel for the controller.
    rx_fc_ctl: mpsc::Receiver<MsgFcCtl>,

    /// All McAnnounceData to send to new clients.
    _mc_announce_data: Vec<McAnnounceData>,

    /// Number of clients.
    nb_clients: Option<u64>,

    /// All transmission channels to communicate with the receivers.
    /// Indexed by the client ID, and the ID of the channel they listen to,
    /// `None` if they listen only on unicast.
    tx_clients: HashMap<u64, mpsc::Sender<MsgRecv>>,

    /// Mapping between the ID of the flexicast source and the IDs of the
    /// clients. Indexed by the the flexicast source ID.
    active_clients: Vec<HashSet<u64>>,

    /// Mapping between the ID of the flexicast source and the IDs of the
    /// receivers that need early retransmission.
    /// Indexed by the flexicast source ID.
    delegated_recv: Vec<HashSet<u64>>,

    /// All receivers that currently do not listen to any flexicast flow.
    /// Indexed by the receiver ID.
    unicast_recv: HashSet<u64>,

    /// All McAck structures that the controller maintains.
    mc_acks: Vec<McAck>,

    /// Last expired packets for each flexicast flow.
    last_drained_pn: Vec<Option<u64>>,

    /// Communication channels with towards flexicast sources.
    tx_fc_sources: Vec<mpsc::Sender<MsgFcSource>>,

    /// Keeps state of the received packet numbers for each client.
    /// This state is used to delegated STREAM frames that were lost on the
    /// flexicast flow and need unicast retransmission to the receivers.
    /// It is regularly populated with the acknowledgements from the receivers
    /// through the [`MsgFcCtl::AckData`] message, and erased when the
    /// controller delegates STREAM frames to the receiver. Indexed through
    /// the receiver ID.
    recv_ack: HashMap<u64, OpenRangeSet>,

    /// Keeps state of the recovered source symbol metadata for each receiver.
    /// This is not optimal, but we won't clear this structure, hoping that it
    /// will not consume a lot of memory. FC-TODO: clean it.
    rec_fec_md: HashMap<u64, OpenRangeSet>,

    /// Communication towards the main thread.
    tx_main: mpsc::Sender<MsgMain>,

    /// Number of clients to wait before actually sending data.
    wait: Option<u64>,

    /// Number of receivers ready to receive content?
    nb_ready: u64,

    /// Last time an aggregated ack was (tried to be) sent.
    last_ack_sent: Option<time::Instant>,

    /// Delay between two aggregated ack instants.
    ack_delay: Option<time::Duration>,

    /// Aggregator to handle all-receivers-one-flexicast-flow control data.
    fc_aggregator: FcAggregator,

    /// Pending aggregated acknowledgments from the receivers to the flexicast
    /// flow.
    pending_ack: Vec<OpenRangeSet>,

    /// Pending aggregated stream acknowledgments from the receivers to the
    /// flexicast flow.
    pending_stream_ack: Vec<HashMap<u64, OpenRangeSet>>,

    /// Remember, for each receiver, the set of delegated stream pieces.
    /// This structure is used to avoid delegating multiple times the same
    /// stream piece for the same receiver, as well as handling the case of a
    /// leaving flexicast receiver. The first u64 is the receiver ID.
    /// The second is the stream ID.
    /// The third is the offset.
    /// The final value is the length.
    /// We make the assumption that the STREAM frames sent on the flexicast flow
    /// are indempotent, which is a strong assumption.
    delegated_streams: HashMap<u64, HashSet<(u64, u64, u64)>>,

    /// Remember the stream data sent by the flexicast flow, in case of unicast
    /// fall-back.
    app_data: Vec<u8>,

    /// Minimum offset of buffered data.
    app_data_min_off: u64,

    /// Whether the buffered data is fin.
    app_data_fin: bool,

    /// Remember the app data stream ID.
    app_data_stream_id: u64,
}

impl FcController {
    /// New controller.
    pub fn new(
        rx_fc_ctl: mpsc::Receiver<MsgFcCtl>,
        mc_announce_data: Vec<McAnnounceData>,
        tx_fc_sources: Vec<mpsc::Sender<MsgFcSource>>,
        tx_main: mpsc::Sender<MsgMain>, wait: Option<u64>,
        ack_delay: Option<time::Duration>,
    ) -> Self {
        Self {
            rx_fc_ctl,
            nb_clients: None,
            tx_clients: HashMap::new(),
            active_clients: vec![HashSet::new(); mc_announce_data.len()],
            delegated_recv: vec![HashSet::new(); mc_announce_data.len()],
            unicast_recv: HashSet::new(),
            mc_acks: vec![McAck::new(false); mc_announce_data.len()],
            last_drained_pn: vec![None; mc_announce_data.len()],
            recv_ack: HashMap::new(),
            rec_fec_md: HashMap::new(),
            pending_ack: vec![OpenRangeSet::default(); mc_announce_data.len()],
            pending_stream_ack: vec![HashMap::new(); mc_announce_data.len()],
            _mc_announce_data: mc_announce_data,
            tx_fc_sources,
            tx_main,
            wait,
            nb_ready: 0,
            last_ack_sent: None,
            ack_delay,
            fc_aggregator: FcAggregator::new(),
            delegated_streams: HashMap::new(),
            app_data: Vec::new(),
            app_data_min_off: 0,
            app_data_fin: false,
            app_data_stream_id: 0,
        }
    }

    /// Run the controller.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            // Compute timeout of acknowledgment forwarding to the source.
            let timeout = self.send_ack_timeout();
            tokio::select! {
                // Timeout to send acknowledgment to the flexicast source.
                Some(_) = optional_timeout(timeout) => self.handle_send_ack().await?,

                // Receive message.
                Some(msg) = self.rx_fc_ctl.recv() => self.handle_fc_msg(msg).await?,

                else => debug!("Error in select controller"),
            }

            // Exit controller when no more clients listen to the group.
            if self.nb_clients == Some(0) {
                // break;
            }
        }

        // Ok(())
    }

    /// Handle the reception of a message from the flexicast source channel.
    async fn handle_fc_msg(&mut self, msg: MsgFcCtl) -> Result<()> {
        match msg {
            MsgFcCtl::CloseRtp(id) => self.send_close_rtp(id).await?,

            MsgFcCtl::NewClient((id, tx)) => {
                // Push new client.
                self.nb_clients =
                    Some(self.nb_clients.unwrap_or(0).saturating_add(1));
                self.tx_clients.insert(id, tx);
                self.recv_ack.insert(id, OpenRangeSet::default());
                self.rec_fec_md.insert(id, OpenRangeSet::default());
                self.unicast_recv.insert(id);
            },

            MsgFcCtl::Join((client_id, fc_chan_id, aggr_msg)) => {
                debug!("New client {client_id} joins flow {fc_chan_id}");
                let new_insert =
                    self.active_clients[fc_chan_id as usize].insert(client_id);
                _ = self.unicast_recv.remove(&client_id);
                _ = self.delegated_recv[fc_chan_id as usize].remove(&client_id);
                if new_insert {
                    self.mc_acks[fc_chan_id as usize].new_recv(
                        self.last_drained_pn[fc_chan_id as usize].unwrap_or(0),
                    );
                }

                // Must notify this new client of the first packet number of
                // interest.
                let pn = self.last_drained_pn[fc_chan_id as usize]
                    .unwrap_or(0)
                    .saturating_sub(1);
                let msg = MsgRecv::NewHighestPn((fc_chan_id, pn, pn));
                send_uc_path!(self, client_id, msg);

                // Update flow control limits.
                if let Some(aggr_msg) = aggr_msg {
                    self.on_new_aggr_msg(client_id, fc_chan_id, aggr_msg)
                        .await?;
                }
            },

            MsgFcCtl::Change((client_id, old_fc_chan_id, new_fc_chan_id)) => {
                debug!("Client {client_id} changes flow {old_fc_chan_id} -> {new_fc_chan_id}");
                _ = self.active_clients[old_fc_chan_id as usize]
                    .remove(&client_id);
                _ = self.active_clients[new_fc_chan_id as usize]
                    .insert(client_id);
            },

            MsgFcCtl::NewHighestPn((fc_id, highest_pn, lowest_pn)) => {
                debug!("New expired packet from {fc_id}: {highest_pn:?} {lowest_pn:?}");
                self.last_drained_pn[fc_id as usize] =
                    Some(lowest_pn.saturating_sub(1));
                for client_idx in self.active_clients[fc_id as usize].iter() {
                    let msg =
                        MsgRecv::NewHighestPn((fc_id, highest_pn, lowest_pn));
                    send_uc_path!(self, *client_idx, msg);
                }
            },

            MsgFcCtl::AckData((
                recv_id,
                fc_id,
                ack_pn,
                ack_stream_pieces,
                rec_md,
            )) => {
                debug!("Client {recv_id} acknowledges for flexicast flow {fc_id}: pn={ack_pn:?} and streams={ack_stream_pieces:?}");
                self.handle_ack_pn_stream_pieces(
                    recv_id,
                    fc_id,
                    ack_pn,
                    ack_stream_pieces,
                    rec_md,
                )
                .await?;
            },

            MsgFcCtl::Sent((fc_id, sent)) => {
                self.handle_sent_pkt(fc_id, sent).await?;
            },

            MsgFcCtl::DelegateStreams((
                fc_id,
                delegated_streams,
                early_retransmit,
            )) => {
                debug!(
                    "Flexicast source delegated streams: {:?}",
                    delegated_streams.len()
                );
                self.handle_delegated_streams(
                    fc_id,
                    delegated_streams,
                    early_retransmit,
                )
                .await?;
            },

            MsgFcCtl::RecvReady(id) => {
                debug!("New ready client {id}");
                self.handle_new_ready(id).await?;
            },

            MsgFcCtl::StreamData((data, stream_id, fin, min_off)) => {
                // Buffer the data, up to the flow control limits.
                self.app_data.extend_from_slice(&data);

                
                let index = min_off.saturating_sub(self.app_data_min_off);
                debug!("WE GET INFO FROM FC FLOW: stream_id={stream_id}, fin={fin}, min_off={min_off} while app_data_min_off={:?}", self.app_data_min_off);
                if index > 0 {
                    self.app_data = self.app_data.split_off(index as usize);
                    self.app_data_min_off = min_off;
                }

                self.app_data_fin = fin;
                self.app_data_stream_id = stream_id;

                for recv_id in self.unicast_recv.iter() {
                    let msg =
                        MsgRecv::StreamData((data.clone(), stream_id, None, fin));
                    send_uc_path!(self, *recv_id, msg);
                }
            },

            MsgFcCtl::RecvUcFallBack((id, fc_chan_id)) => {
                _ = self.active_clients[fc_chan_id as usize].remove(&id);
                _ = self.unicast_recv.insert(id);
                _ = self.delegated_recv[fc_chan_id as usize].insert(id);
                // FC-TODO: remove the receiver from the mc_acks!
                self.mc_acks[fc_chan_id as usize].remove_recv();

                // And potentially "ack" stream pieces delegated to this receiver
                // because we will fall back on unicast for this receiver.
                if let Some(recv_del) = self.delegated_streams.get_mut(&id) {
                    for (stream_id, off, len) in recv_del.drain() {
                        self.mc_acks[fc_chan_id as usize]
                            .on_stream_ack_received(stream_id, off, len);
                    }
                }

                // Instead of asking for a retransmission, we give the stream data
                // directly.
                let msg = MsgRecv::StreamData((
                    Arc::new(self.app_data.clone()),
                    self.app_data_stream_id,
                    Some(self.app_data_min_off),
                    self.app_data_fin,
                ));
                send_uc_path!(self, id, msg);

                // let msg = MsgFcSource::AskStreamPieces;
                // self.tx_fc_sources[fc_chan_id as usize].send(msg).await?;

                // // Potentially have updates concerning the flow control now
                // that a receiver left. let out = self.
                // fc_aggregator.remove_recv(id)?;
                // if let Some(out) = out {
                //     let msg = MsgFcSource::AggregatedInfo(out);
                //     self.tx_fc_sources[fc_chan_id as usize].send(msg).await?;
                // }
            },

            MsgFcCtl::PerUcRetransmission((fc_id, recv_id, lost_pn)) => {
                // FC-TODO: buffer here the retransmissions to avoid asking the
                // flexicast flow each time there is a loss.

                let msg = MsgFcSource::PerUcRetransmission((recv_id, lost_pn));
                self.tx_fc_sources[fc_id as usize].send(msg).await?;
            },

            MsgFcCtl::PerUcRetransmitted((fc_id, recv_id, delegated_streams)) => {
                let delegate = vec![true; delegated_streams.len()];
                let msg = MsgRecv::DelegateStreams((
                    fc_id,
                    delegated_streams,
                    delegate,
                ));
                send_uc_path!(self, recv_id, msg);
            },

            MsgFcCtl::AggregatedInfo((recv_id, fc_id, aggr_info)) =>
                self.on_new_aggr_msg(recv_id, fc_id, aggr_info).await?,
        }

        Ok(())
    }

    /// Sends to clients listening to a particular flexicast flow that RTP is
    /// closed.
    /// Also notifies the main thread that a flexicast flow stopped to close the
    /// main loop.
    async fn send_close_rtp(&mut self, id: u64) -> Result<()> {
        debug!("Close RTP {id}");
        if let Some(group) = self.active_clients.get(id as usize) {
            for &id_client in group.iter() {
                send_uc_path!(self, id_client, MsgRecv::CloseRtp);
                self.nb_clients = self.nb_clients.map(|n| n.saturating_sub(1));
            }
        }
        let msg = MsgMain::FcFlowStop(id);
        self.tx_main.send(msg).await?;

        Ok(())
    }

    /// A new receiver is ready to listen to multicast content.
    /// If all receivers are ready, the controller notifies the flexicast
    /// sources.
    async fn handle_new_ready(&mut self, _id: u64) -> Result<()> {
        self.nb_ready += 1;

        if Some(self.nb_ready) == self.wait {
            // Notify all flexicast flows.
            for tx_fc in self.tx_fc_sources.iter() {
                let msg = MsgFcSource::Ready;
                tx_fc.send(msg).await?;
            }

            // Reset to avoid going multiple times here.
            self.wait = None;
        }

        Ok(())
    }

    /// Sends to the flexicast source the acknowledged packets and stream
    /// pieces.
    async fn handle_ack_pn_stream_pieces(
        &mut self, recv_id: u64, fc_id: u64, ack_pn: Option<OpenRangeSet>,
        ack_stream_pieces: Option<McStreamOff>, rec_md: Option<OpenRangeSet>,
    ) -> Result<()> {
        let mc_ack = &mut self.mc_acks[fc_id as usize];

        // Packet numbers acknowledgment.
        if let Some(rs) = ack_pn {
            mc_ack.on_ack_received(&rs);

            // Store per-receiver acknowledgments.
            for range in rs.iter() {
                self.recv_ack.get_mut(&recv_id).map(|r| r.insert(range));
            }
        }

        // Stream pieces.
        if let Some(mut ack_stream) = ack_stream_pieces {
            for (stream_id, ranges) in ack_stream.drain(..) {
                for range in ranges.iter() {
                    mc_ack.on_stream_ack_received(
                        stream_id,
                        range.start,
                        range.end - range.start,
                    );
                }
            }
        }

        // FEC recovered metadata.
        if let Some(rs) = rec_md {
            // Store per-receiver recovered source symbol metadata.
            for range in rs.iter() {
                self.rec_fec_md.get_mut(&recv_id).map(|r| r.insert(range));
            }
        }

        // Only bother if no ack delay is provided.
        // Otherwise we will aggregate acknowledgment notification later.
        if self.ack_delay.is_none() {
            panic!("Should not use without ack delay for now!");
            // // Maybe now the controller can acknowledge some packets numbers.
            // if let Some(fully_acked) = mc_ack.full_ack() {
            //     let msg = MsgFcSource::AckPn(fully_acked);
            //     self.tx_fc_sources[fc_id as usize].send(msg).await?;
            // }

            // // And stream pieces may also be acknowledged now.
            // if let Some(fully_acked_stream_pieces) =
            // mc_ack.acked_stream_off() {     let msg =
            // MsgFcSource::AckStreamPieces(fully_acked_stream_pieces);
            //     self.tx_fc_sources[fc_id as usize].send(msg).await?;
            // }
        }

        Ok(())
    }

    /// Forwards to the unicast instances the packets sent on the flexicast flow
    /// by the source.
    async fn handle_sent_pkt(
        &mut self, fc_id: u64, sent: Arc<Vec<OpenSent>>,
    ) -> Result<()> {
        for &client_id in self.active_clients[fc_id as usize].iter() {
            let msg = MsgRecv::Sent((fc_id, sent.clone()));
            send_uc_path!(self, client_id, msg);
        }

        Ok(())
    }

    /// Dispatchs delegated streams to receivers.
    async fn handle_delegated_streams(
        &mut self, fc_id: u64, delegated_streams: Arc<Vec<FcDelegatedStream>>,
        early_retransmit: bool,
    ) -> Result<()> {
        // Iterate over all clients listening to this flexicast source to delegate
        // the appropriate STREAM frame retransmissions.
        // Avoid retransmitting frames that may not be lost if this is an early
        // retransmit.
        let _hs = HashSet::new();
        let iter = if early_retransmit {
            debug!("DOING EARLY RETRANSMIT ONLY: {:?}", delegated_streams.len());
            self.delegated_recv[fc_id as usize].iter().chain(_hs.iter())
        } else {
            debug!("DOING LOSS RETRANSMIT: {:?}", delegated_streams.len());
            self.delegated_recv[fc_id as usize]
                .iter()
                .chain(self.active_clients[fc_id as usize].iter())
        };

        // There is a rare case where the flexicast flow delegates stream pieces
        // while all receivers actually received/recovered it. This may happen,
        // for example, when the receivers recover it through FEC.
        // To handle this case, we record whether each stream piece was delegated
        // at least once.
        let mut delegated_once = vec![false; delegated_streams.len()];

        for &client_id in iter {
            let client_ack: HashSet<u64> =
                self.recv_ack.get(&client_id).unwrap().flatten().collect();
            let recv_rec_fec_md: HashSet<u64> =
                self.rec_fec_md.get(&client_id).unwrap().flatten().collect();

            // Get the entry for this receiver.
            let delegated_entry = match self.delegated_streams.entry(client_id) {
                Occupied(entry) => entry.into_mut(),
                Vacant(entry) => entry.insert(HashSet::new()),
            };

            // Delegate the STREAM frames for unicast retransmission.
            let mut do_delegate = vec![false; delegated_streams.len()];
            for (i, delegated_piece) in delegated_streams.iter().enumerate() {
                if delegated_piece
                    .pn
                    .is_some_and(|pn| !client_ack.contains(&pn))
                {
                    // The packet containing this STREAM frame was maybe recovered
                    // through FEC, thus avoiding a retransmission.
                    if delegated_piece
                        .fec_md
                        .is_some_and(|md| recv_rec_fec_md.contains(&md))
                    {
                        continue;
                    }

                    // Don't delegate twice the same stream piece.
                    // We make the hypothesis that delegated stream frames are
                    // indempotent.
                    if delegated_entry.contains(&(
                        delegated_piece.stream_id,
                        delegated_piece.offset,
                        delegated_piece.payload.len() as u64,
                    )) {
                        continue;
                    }

                    // Insert.
                    delegated_entry.insert((
                        delegated_piece.stream_id,
                        delegated_piece.offset,
                        delegated_piece.payload.len() as u64,
                    ));

                    // Mark that the unicast path must retransmit this piece.
                    do_delegate[i] = true;

                    if !early_retransmit {
                        // Lost packet on this client, so we mark to delegate it.
                        self.mc_acks[fc_id as usize].delegate(
                            delegated_piece.stream_id,
                            delegated_piece.offset,
                            delegated_piece.payload.len() as u64,
                        );

                        // At least delegated once.
                        delegated_once[i] = true;
                    }
                }
            }

            // Send the delegated pieces to the client.
            // Optimistation: we send all delegated streams and rely on the
            // unicast path to filter the ones to send.
            debug!(
                "Delegate stream {:?} to {client_id}",
                delegated_streams
                    .iter()
                    .map(|s| (s.stream_id, s.offset))
                    .collect::<Vec<_>>()
            );
            let msg = MsgRecv::DelegateStreams((
                fc_id,
                delegated_streams.clone(),
                do_delegate,
            ));
            send_uc_path!(self, client_id, msg);

            // Release memory based on the highest packet number.
            // Fc-TODO: not sure this will work because the last expired may be
            // another than the largest lost.
            if let Some(max_pn) = self.last_drained_pn[fc_id as usize] {
                self.recv_ack
                    .get_mut(&client_id)
                    .map(|r| r.remove_until(max_pn));
            }
        }

        // Remove delegated receivers.
        if early_retransmit {
            _ = self.delegated_recv[fc_id as usize].drain();
        }

        // If some stream pieces were considered lost while received/recovered by
        // all receivers, notify the flexicast flow. To decrease the amount of
        // work, we add them to the set of pending stream ack, and send a message
        // to the flexicast flow.
        let pending_ack_stream = &mut self.pending_stream_ack[fc_id as usize];
        for (stream_piece, is_delegated) in
            delegated_streams.iter().zip(delegated_once)
        {
            if !is_delegated {
                let entry = match pending_ack_stream.entry(stream_piece.stream_id)
                {
                    Vacant(entry) => entry.insert(OpenRangeSet::default()),
                    Occupied(entry) => entry.into_mut(),
                };

                entry.insert(
                    stream_piece.offset..
                        stream_piece.offset + stream_piece.payload.len() as u64,
                );
            }
        }

        self.handle_send_ack().await?;

        Ok(())
    }

    /// Computes the next timeout to send an acknowledgment aggregation to the
    /// source.
    fn send_ack_timeout(&self) -> Option<time::Duration> {
        if self.ack_delay.is_none() {
            return None;
        }

        if let Some(t) = self.last_ack_sent {
            let now = time::Instant::now();
            Some(
                self.ack_delay
                    .unwrap()
                    .saturating_sub(now.duration_since(t)),
            )
        } else {
            Some(time::Duration::ZERO)
        }
    }

    /// Sends acknowledgment to the flexicast sources if an ack delay is
    /// provided.
    async fn handle_send_ack(&mut self) -> Result<()> {
        if self.ack_delay.is_none() {
            return Ok(());
        }

        for (i, mc_ack) in self.mc_acks.iter_mut().enumerate() {
            // Fully acknowledged packet numbers.
            // Maybe we have some pending data.
            let pending_ack = &mut self.pending_ack[i];

            if let Some(fully_acked) = mc_ack.full_ack() {
                if pending_ack.len() == 0 {
                    *pending_ack = fully_acked;
                } else {
                    for range in fully_acked.iter() {
                        pending_ack.insert(range);
                    }
                }
            }
            if pending_ack.len() > 0 {
                // Also send to the unicast fall-back receivers the lowest sent
                // packet number.
                if let Some(first) = pending_ack.first() {
                    for &client_id in self.unicast_recv.iter() {
                        let msg = MsgRecv::NewHighestPn((i as u64, first, first));
                        send_uc_path!(self, client_id, msg);
                    }
                }
                let msg = MsgFcSource::AckPn(pending_ack.clone());
                match self.tx_fc_sources[i].try_send(msg) {
                    Ok(_) => self.pending_ack[i] = OpenRangeSet::default(),
                    Err(_e) => (),
                }
            }

            // Stream pieces.
            // Maybe we have some pending data.
            let pending_stream_ack = &mut self.pending_stream_ack[i];

            if let Some(mut fully_acked_stream_pieces) = mc_ack.acked_stream_off()
            {
                if pending_stream_ack.is_empty() {
                    *pending_stream_ack =
                        fully_acked_stream_pieces.drain(..).collect();
                } else {
                    for (stream_id, ranges) in fully_acked_stream_pieces.drain(..)
                    {
                        let entry = match pending_stream_ack.entry(stream_id) {
                            Vacant(entry) =>
                                entry.insert(OpenRangeSet::default()),
                            Occupied(entry) => entry.into_mut(),
                        };
                        for range in ranges.iter() {
                            entry.insert(range);
                        }
                    }
                }
            }

            if !pending_stream_ack.is_empty() {
                let msg = MsgFcSource::AckStreamPieces(
                    pending_stream_ack
                        .iter()
                        .map(|(pn, rs)| (*pn, rs.clone()))
                        .collect(),
                );
                match self.tx_fc_sources[i].try_send(msg) {
                    Ok(_) => self.pending_stream_ack[i] = HashMap::new(),
                    Err(_e) => (),
                }
            }
        }

        let now = time::Instant::now();
        self.last_ack_sent = Some(now);

        Ok(())
    }

    /// Handles a new aggregated control data message from a receiver.
    /// Potentially triggers a new message on the flexicast flow if some data is
    /// updated.
    async fn on_new_aggr_msg(
        &mut self, recv_id: u64, fc_id: u64, aggr_msg: FcAggregatedMsg,
    ) -> Result<()> {
        let out = self.fc_aggregator.on_new_aggr_msg(recv_id, aggr_msg)?;
        if let Some(aggr_out) = out {
            let msg = MsgFcSource::AggregatedInfo(aggr_out);
            self.tx_fc_sources[fc_id as usize].send(msg).await?;
        }

        Ok(())
    }
}

/// Wrapper around the [`tokio::sync::mpsc::bounded`] function
/// to remove a unicast path that is not active anymore, i.e., we receive a
/// SendError.
#[macro_export]
macro_rules! send_uc_path {
    ($ctl:expr, $recv_id:expr, $msg:expr) => {
        if let Some(tx_client) = $ctl.tx_clients.get(&$recv_id) {
            if let Err(_send_error) = tx_client.send($msg).await {
                // Remove this unicast path from the structure.
                let _ = $ctl.tx_clients.remove(&$recv_id);
                let _ = $ctl.recv_ack.remove(&$recv_id);
                let _ = $ctl.rec_fec_md.remove(&$recv_id);
            }
        }
    };
}

pub async fn handle_msg(
    msg: MsgMain, clients_ids: &mut ClientIdMap, socket: &UdpSocket,
    stopped_flows: &mut HashSet<u64>,
) -> Result<()> {
    match msg {
        MsgMain::NewCID((client_id, cid)) => {
            debug!("Receiver {client_id} adds a new CID!");
            clients_ids.insert(cid.into(), client_id);
        },

        MsgMain::SendPkt((pkt_buf, send_info)) => {
            debug!(
                "Will send the packet to the wire with send_info={:?}",
                send_info
            );
            socket.send_to(&pkt_buf, send_info.to).await?;
        },

        MsgMain::FcFlowStop(id) => {
            debug!("New flexicast flow stopped: {}", id);
            stopped_flows.insert(id);
        },
    }

    Ok(())
}

pub async fn optional_timeout(
    timeout: Option<std::time::Duration>,
) -> Option<()> {
    match timeout {
        Some(t) => {
            tokio::time::sleep(t).await;
            Some(())
        },
        None => None,
    }
}
