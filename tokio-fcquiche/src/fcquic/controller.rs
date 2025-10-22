//! Asynchronous control loop between flexicast source and unicast server with
//! tokio.

use super::aggregator::FcAggregatedMsg;
use super::aggregator::FcAggregator;
use super::messages::*;
use crate::Result;
use crate::send_uc_path;
use log::*;
use quiche::ConnectionId;
use quiche::flexicast::ack::FcDelegatedStream;
use quiche::flexicast::ack::McAck;
use quiche::flexicast::ack::McStreamOff;
use quiche::flexicast::ack::OpenRangeSet;
use quiche::flexicast::control::OpenSent;
use quiche::flexicast::McAnnounceData;
use quiche::flexicast::MissingRangeSet;
use std::collections::hash_map::Entry::Occupied;
use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time;
use tokio;
use tokio::sync::mpsc;

/// Controller structure using tokio to handle messages between the flexicast
/// source and the unicast server instances.
pub struct FcController {
    /// Role and transmissions channels of the controller.
    controller_role: ControllerRole,

    /// The reception channel for the controller.
    rx_fc_ctl: mpsc::Receiver<MsgFcCtl>,

    /// All McAnnounceData to send to new clients.
    _mc_announce_data: Vec<McAnnounceData>,

    /// Number of clients.
    nb_clients: Option<u64>,

    /// Mapping between the ID of the flexicast source and the IDs of the
    /// clients. Indexed by the the flexicast source ID.
    active_clients: Vec<HashMap<u64, u64>>,

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
    app_data: HashMap<u64, Vec<u8>>,

    /// Minimum offset of buffered data.
    app_data_min_off: HashMap<u64, u64>,

    /// Whether the buffered data is fin.
    app_data_fin: HashMap<u64, bool>,

    /// Whether new acknowledgment could be sent to the flexicast flow.
    /// This is done to prevent infinite polling.
    /// TODO: instead, directly call the handle_send_ack function when we
    /// receive info from receivers.
    possible_send_ack: bool,
}

impl FcController {
    /// New controller.
    pub fn new(
        rx_fc_ctl: mpsc::Receiver<MsgFcCtl>,
        mc_announce_data: Vec<McAnnounceData>, controller_role: ControllerRole,
        tx_main: mpsc::Sender<MsgMain>, wait: Option<u64>,
        ack_delay: Option<time::Duration>,
    ) -> Self {
        Self {
            controller_role,
            rx_fc_ctl,
            nb_clients: None,
            active_clients: vec![HashMap::new(); mc_announce_data.len()],
            delegated_recv: vec![HashSet::new(); mc_announce_data.len()],
            unicast_recv: HashSet::new(),
            mc_acks: vec![McAck::new(false); mc_announce_data.len()],
            last_drained_pn: vec![None; mc_announce_data.len()],
            recv_ack: HashMap::new(),
            rec_fec_md: HashMap::new(),
            pending_ack: vec![OpenRangeSet::default(); mc_announce_data.len()],
            pending_stream_ack: vec![HashMap::new(); mc_announce_data.len()],
            _mc_announce_data: mc_announce_data,
            tx_main,
            wait,
            nb_ready: 0,
            last_ack_sent: None,
            ack_delay,
            fc_aggregator: FcAggregator::new(),
            delegated_streams: HashMap::new(),
            app_data: HashMap::new(),
            app_data_min_off: HashMap::new(),
            app_data_fin: HashMap::new(),
            possible_send_ack: false,
        }
    }

    /// Run the controller.
    pub async fn run(&mut self) -> Result<()> {
        let mut vec_of_msg = Vec::with_capacity(1000);

        loop {
            info!("Before call recv_many: {:?}", self.controller_role.name());
            let nb_recv = self.rx_fc_ctl.recv_many(&mut vec_of_msg, 1000).await;
            if nb_recv == 0 {
                info!("{} closing the channel RX.", self.controller_role.name());
                break;
            }
            for msg in vec_of_msg.drain(..nb_recv) {
                if let Err(e) = self.handle_fc_msg(msg).await {
                    info!("ERROR {:?}: {e:?}.", self.controller_role.name());
                    return Err(e);
                }
            }

            if self.possible_send_ack || true {
                if let Err(e) = self.handle_send_ack().await {
                    info!("ERROR2 {:?}: {e:?}.", self.controller_role.name());
                    return Err(e);
                }
            }

            // Exit controller when no more clients listen to the group.
            if self.nb_clients == Some(0) {
                // break;
            }
        }

        Ok(())
    }

    /// Handle the reception of a message from the flexicast source channel.
    async fn handle_fc_msg(&mut self, msg: MsgFcCtl) -> Result<()> {
        match msg {
            MsgFcCtl::CloseRtp(id) => self.send_close_rtp(id).await?,

            MsgFcCtl::NewClient((id, tx)) => {
                self.new_recv(id, tx);
            },

            MsgFcCtl::Join((recv_id, fc_id, aggr_msg, max_pn)) => {
                self.on_join(recv_id, fc_id, aggr_msg, max_pn).await?;
            },

            MsgFcCtl::Change(_) => {
                todo!();
            },

            MsgFcCtl::NewHighestPn((fc_id, highest_pn, lowest_pn)) => {
                debug!("{}: New expired packet from {fc_id}: {highest_pn:?} {lowest_pn:?}", self.controller_role.name());
                self.on_new_highest_pn(fc_id, highest_pn, lowest_pn).await?;
            },

            MsgFcCtl::AckData((
                recv_id,
                fc_id,
                ack_pn,
                ack_stream_pieces,
                rec_md,
            )) => {
                self.on_new_ack_data(
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
                    "{} Flexicast source delegated streams: {:?}",
                    self.controller_role.name(),
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
                debug!("{} New ready client {id}", self.controller_role.name());
                self.handle_new_ready(id).await?;
            },

            MsgFcCtl::StreamData((data, stream_id, fin, min_off)) => {
                // Buffer the data, up to the flow control limits.
                let app_data = match self.app_data.entry(stream_id) {
                    Vacant(entry) => entry.insert(Vec::new()),
                    Occupied(entry) => entry.into_mut(),
                };
                let original_len = app_data.len();
                app_data.extend_from_slice(&data);

                let app_data_min_off =
                    match self.app_data_min_off.entry(stream_id) {
                        Vacant(entry) => entry.insert(0),
                        Occupied(entry) => entry.into_mut(),
                    };
                let original_off = *app_data_min_off;

                let index = min_off.saturating_sub(*app_data_min_off);
                // info!("WE GET INFO FROM FC FLOW: stream_id={stream_id},
                // fin={fin}, min_off={min_off} while app_data_min_off={:?}",
                // self.app_data_min_off);
                if index > 0 {
                    *app_data = app_data.split_off(index as usize);
                    *app_data_min_off = min_off;
                }

                let _ = self.app_data_fin.insert(stream_id, fin);

                info!("{:?} StreamData. Before updating: off={original_off} and len={original_len}. Given by msg len={}, off={min_off}. Cut at {index} after extend from slice. So total min_off={} and len={}", self.controller_role.name(), data.len(), app_data_min_off, app_data.len());

                // info!("Send to UC path: stream_id={stream_id}, fin={fin},
                // len={}, off={min_off}", data.len());

                match &self.controller_role {
                    ControllerRole::Leaf(_leaf) => {
                        // The offset of the new given piece of data.
                        // It is important to give the exact offset to the
                        // receiver to let them know where to put this data.
                        let new_data_off = *app_data_min_off +
                            app_data.len() as u64 -
                            data.len() as u64;
                        for recv_id in self.unicast_recv.iter() {
                            let msg = MsgRecv::StreamData((
                                data.clone(),
                                stream_id,
                                new_data_off,
                                fin,
                            ));
                            send_uc_path!(self, *recv_id, msg);
                        }
                    },

                    ControllerRole::Root(root) => {
                        for tx in root.tx_down.values() {
                            let msg = MsgFcCtl::StreamData((
                                data.clone(),
                                stream_id,
                                fin,
                                min_off,
                            ));
                            info!("Waiting before sending stream data. Root controller.");
                            tx.send(msg).await?;
                        }
                    },
                }
            },

            MsgFcCtl::RecvUcFallBack((id, fc_chan_id)) => {
                // Do nothing if this is the root.
                if matches!(self.controller_role, ControllerRole::Root(_)) {
                    return Ok(());
                }

                info!(
                    "{} Before fall back of receiver: {id}, this is the state of
                the McAck: {:?}",
                    self.controller_role.name(),
                    self.mc_acks[fc_chan_id as usize]
                );
                let pn_drain =
                    self.active_clients[fc_chan_id as usize].remove(&id);
                _ = self.unicast_recv.insert(id);
                // _ = self.delegated_recv[fc_chan_id as usize].insert(id);

                if let Some(mut acks_) = self.recv_ack.get(&id).cloned() {
                    let largest_pn =
                        self.mc_acks[fc_chan_id as usize].get_largest_pn();
                    if let Some(largest) = largest_pn {
                        // Also add potential packets that were before what we
                        // ACK.
                        if let Some(first_pn) =
                            self.last_drained_pn[fc_chan_id as usize]
                        {
                            acks_.insert(first_pn..first_pn + 1);
                        }

                        let largest_pn_considered =
                            largest.max(acks_.last().unwrap_or(0));
                        let mut missing =
                            acks_.get_missing_up_to(largest_pn_considered + 1);
                        info!("Largest={largest_pn:?}. Largest pn considered={largest_pn_considered:?}. ack_to_use={acks_:?}. Missing={missing:?}. Remove_until={pn_drain:?}");
                        // Also remove older, out of interest, values!
                        if let Some(pn) = pn_drain {
                            missing.remove_until(pn - 1);
                        }
                        info!(
                            "{} UC FB. Hack for {} missing: {:?}",
                            self.controller_role.name(),
                            id,
                            missing
                        );
                        self.mc_acks[fc_chan_id as usize]
                            .on_ack_received(&missing);
                    }
                }

                // And potentially "ack" stream pieces delegated to this receiver
                // because we will fall back on unicast for this receiver.
                if let Some(recv_del) = self.delegated_streams.get_mut(&id) {
                    for (stream_id, off, len) in recv_del.drain() {
                        // info!("During fallback {}. on_stream_ack_received:
                        // id={}, off={}, len={}", id, stream_id, off, len);
                        self.mc_acks[fc_chan_id as usize]
                            .on_stream_ack_received(stream_id, off, len);
                    }
                }

                self.mc_acks[fc_chan_id as usize].remove_recv();

                // Instead of asking for a retransmission, we give the stream data
                // directly.
                for (stream_id, app_data) in self.app_data.iter() {
                    let msg = MsgRecv::StreamData((
                        Arc::new(app_data.clone()),
                        *stream_id,
                        *self.app_data_min_off.get(stream_id).unwrap_or(&0),
                        *self.app_data_fin.get(stream_id).unwrap_or(&false),
                    ));
                    info!(
                        "Send StreamData len={} with off={}",
                        self.app_data.len(),
                        *self.app_data_min_off.get(stream_id).unwrap_or(&0)
                    );
                    send_uc_path!(self, id, msg);
                }

                info!(
                    "{} After fall back of receiver: {id}, this is the state
                of the McAck: {:?}",
                    self.controller_role.name(),
                    self.mc_acks[fc_chan_id as usize]
                );

                self.possible_send_ack = true;

                // If everyone fell back, the controller will ACK one every two
                // packets to decrease the source's congestion window while
                // keeping sending data.
                if self.mc_acks[fc_chan_id as usize].get_nb_recv() == 0 {
                    if let ControllerRole::Leaf(leaf) = &mut self.controller_role
                    {
                        let pn =
                            self.mc_acks[fc_chan_id as usize].get_largest_pn();
                        leaf.set_dummy_ack(true, pn);
                    }
                }
            },

            MsgFcCtl::AggregatedInfo((recv_id, fc_id, aggr_info)) =>
                self.on_new_aggr_msg(recv_id, fc_id, aggr_info).await?,

            MsgFcCtl::CollectRecv((recv_id, fc_id)) =>
                self.on_collect_recv(recv_id, fc_id).await?,
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
            for (&id_client, _) in group.iter() {
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
        let name = self.controller_role.name();
        info!("{name} receives a RecvReady!");
        self.nb_ready += 1;

        match &self.controller_role {
            // The leaf controller directly notifies the root for each new
            // arriving receiver. The root is responsible to handle
            // the number of receivers.
            ControllerRole::Leaf(leaf) => {
                let msg = MsgFcCtl::RecvReady(leaf.leaf_id);
                leaf.tx_up.send(msg).await?;
            },

            ControllerRole::Root(root) => {
                if Some(self.nb_ready) == self.wait {
                    for tx in root.tx_up.iter() {
                        let msg = MsgFcSource::Ready;
                        tx.send(msg).await?;
                    }
                    // Reset to avoid going multiple times here.
                    self.wait = None;
                }
            },
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
        } else {
            self.possible_send_ack = true;
        }

        Ok(())
    }

    /// Forwards to the unicast instances the packets sent on the flexicast flow
    /// by the source.
    async fn handle_sent_pkt(
        &mut self, fc_id: u64, sent: Arc<Vec<OpenSent>>,
    ) -> Result<()> {
        match &mut self.controller_role {
            ControllerRole::Leaf(leaf) => {
                // If the leaf controller is in the dummy ack mode, it means that
                // it currently does not have any receiver in the flexicast flow.
                // To avoid blocking the flexicast flow from sending new data, we
                // ack one every two packets directly.
                // This is ugly, I know, but it is the simplest way to keep
                // advancing.
                if let Some(dummy_ack_pn) = leaf.get_dummy_ack() {
                    // Only keep even packets.
                    let mut rs = OpenRangeSet::default();
                    sent.iter()
                        .skip_while(|s| s.pkt_num < dummy_ack_pn)
                        .filter(|s| s.pkt_num % 2 == 0)
                        .for_each(|s| rs.insert(s.pkt_num..s.pkt_num + 1));

                    // Send the dummy ACK to the root controller.
                    let msg = MsgFcCtl::AckData((
                        leaf.leaf_id,
                        fc_id,
                        Some(rs.clone()),
                        None,
                        None,
                    ));
                    info!("Before leaf{:?} send dummy ack", leaf.leaf_id);
                    leaf.tx_up.send(msg).await?;

                    // Update the largest pn dummy acked.
                    if let Some(new_highest) = rs.last() {
                        leaf.set_dummy_ack(true, Some(new_highest));
                    }
                }

                for (&down_id, _) in self.active_clients[fc_id as usize].iter() {
                    let msg = MsgRecv::Sent((fc_id, sent.clone()));
                    send_uc_path!(self, down_id, msg);
                }
            },

            ControllerRole::Root(root) => {
                for (down_id, _) in self.active_clients[fc_id as usize].iter() {
                    let msg = MsgFcCtl::Sent((fc_id, sent.clone()));
                    if let Some(tx) = root.tx_down.get(down_id) {
                        info!("Before root sending SentPkt");
                        tx.send(msg).await?;
                    }
                }
            },
        }
        info!("After sending message: {:?}", self.controller_role.name());

        Ok(())
    }

    /// Dispatchs delegated streams to receivers.
    async fn handle_delegated_streams(
        &mut self, fc_id: u64, delegated_streams: Arc<Vec<FcDelegatedStream>>,
        early_retransmit: bool,
    ) -> Result<()> {
        let name = self.controller_role.name().to_string();

        // Iterate over all clients listening to this flexicast source to delegate
        // the appropriate STREAM frame retransmissions.
        // Avoid retransmitting frames that may not be lost if this is an early
        // retransmit.
        let _hs = HashSet::new();
        let iter_set: HashSet<u64> = self.active_clients[fc_id as usize]
            .iter()
            .map(|(id, _)| *id)
            .collect();
        let iter = if early_retransmit {
            debug!(
                "{name}: DOING EARLY RETRANSMIT ONLY: {:?}",
                delegated_streams.len()
            );
            self.delegated_recv[fc_id as usize].iter().chain(_hs.iter())
        } else {
            debug!(
                "{name}: DOING LOSS RETRANSMIT: {:?}",
                delegated_streams.len()
            );
            self.delegated_recv[fc_id as usize]
                .iter()
                .chain(iter_set.iter())
        };

        // There is a rare case where the flexicast flow delegates stream pieces
        // while all receivers actually received/recovered it. This may happen,
        // for example, when the receivers recover it through FEC.
        // To handle this case, we record whether each stream piece was delegated
        // at least once.
        let mut delegated_once = vec![false; delegated_streams.len()];

        for &client_id in iter {
            if !self.recv_ack.contains_key(&client_id) {
                continue;
            }
            let client_ack: HashSet<u64> =
                self.recv_ack.get(&client_id).unwrap().flatten().collect();
            let recv_rec_fec_md: HashSet<u64> = self
                .rec_fec_md
                .get(&client_id)
                .unwrap_or(&OpenRangeSet::default())
                .flatten()
                .collect();

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
                        debug!("DO NOT RETRANSMIT THIS STREAM BECAUSE RECOVERED: {:?} of len {:?}", delegated_piece.offset, delegated_piece.payload.len());
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
                        // info!("Delegates id={}, off={}, len={} to {}",
                        // delegated_piece.stream_id, delegated_piece.offset,
                        // delegated_piece.payload.len(), client_id);
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
            info!(
                "{name}: Delegate stream {:?} to {client_id}",
                delegated_streams
                    .iter()
                    .map(|s| (s.stream_id, s.offset))
                    .collect::<Vec<_>>()
            );

            match &self.controller_role {
                ControllerRole::Leaf(_leaf) => {
                    let msg = MsgRecv::DelegateStreams((
                        fc_id,
                        delegated_streams.clone(),
                        do_delegate,
                    ));
                    send_uc_path!(self, client_id, msg);
                },

                ControllerRole::Root(root) => {
                    if let Some(tx) = root.tx_down.get(&client_id) {
                        let msg = MsgFcCtl::DelegateStreams((
                            fc_id,
                            delegated_streams.clone(),
                            early_retransmit,
                        ));
                        info!("Before root controller sends DelegatedStreams to {client_id}");
                        tx.send(msg).await?;
                    }
                },
            }

            // Release memory based on the highest packet number.
            // Fc-TODO: not sure this will work because the last expired may be
            // another than the largest lost.
            if let Some(max_pn) = self.last_drained_pn[fc_id as usize] {
                if let Some(recv_ack) = self.recv_ack.get_mut(&client_id) {
                    // Keep in memory the last received to be sure that this is
                    // not empty except if something is actually missing.
                    let max_ack_pn = recv_ack.last();

                    recv_ack.remove_until(max_pn);

                    if let Some(pn) = max_ack_pn {
                        recv_ack.insert(pn..pn + 1);
                    }
                }
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

    /// Sends acknowledgment to the flexicast sources if an ack delay is
    /// provided.
    async fn handle_send_ack(&mut self) -> Result<()> {
        if self.ack_delay.is_none() {
            return Ok(());
        }
        self.possible_send_ack = false;

        for (i, mc_ack) in self.mc_acks.iter_mut().enumerate() {
            let fc_id = i as u64;
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
                    match &self.controller_role {
                        ControllerRole::Leaf(_leaf) => {
                            for &client_id in self.unicast_recv.iter() {
                                let msg = MsgRecv::NewHighestPn((
                                    i as u64, first, first,
                                ));
                                send_uc_path!(self, client_id, msg);
                            }
                        },

                        ControllerRole::Root(root) => {
                            for client_id in self.unicast_recv.iter() {
                                let msg = MsgFcCtl::NewHighestPn((
                                    i as u64, first, first,
                                ));
                                if let Some(tx) = root.tx_down.get(client_id) {
                                    info!("Before root controller sends NewhighestPN to {client_id}");
                                    tx.send(msg).await?;
                                }
                            }
                        },
                    }
                }
                match &self.controller_role {
                    ControllerRole::Leaf(leaf) => {
                        let msg = MsgFcCtl::AckData((
                            leaf.leaf_id,
                            fc_id,
                            Some(self.pending_ack[i].clone()),
                            None,
                            None,
                        ));
                        match leaf.tx_up.try_send(msg) {
                            Ok(_) =>
                                self.pending_ack[i] = OpenRangeSet::default(),
                            Err(_e) => info!(
                                "Leaf {} cannot send ACK to the root.",
                                leaf.leaf_id
                            ),
                        }
                    },

                    ControllerRole::Root(root) => {
                        let msg = MsgFcSource::AckPn(self.pending_ack[i].clone());
                        match root.tx_up[i].try_send(msg) {
                            Ok(_) =>
                                self.pending_ack[i] = OpenRangeSet::default(),
                            Err(_e) =>
                                info!("Root cannot send ACK to the source"),
                        }
                    },
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
                match &self.controller_role {
                    ControllerRole::Leaf(leaf) => {
                        let msg = MsgFcCtl::AckData((
                            leaf.leaf_id,
                            fc_id,
                            None,
                            Some(
                                self.pending_stream_ack[i]
                                    .iter()
                                    .map(|(pn, rs)| (*pn, rs.clone()))
                                    .collect(),
                            ),
                            None,
                        ));

                        match leaf.tx_up.try_send(msg) {
                            Ok(_) => self.pending_stream_ack[i] = HashMap::new(),
                            Err(_e) => (),
                        }
                    },

                    ControllerRole::Root(root) => {
                        let msg = MsgFcSource::AckStreamPieces(
                            self.pending_stream_ack[i]
                                .iter()
                                .map(|(pn, rs)| (*pn, rs.clone()))
                                .collect(),
                        );
                        match root.tx_up[i].try_send(msg) {
                            Ok(_) => self.pending_stream_ack[i] = HashMap::new(),
                            Err(_e) => (),
                        }
                    },
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
            match &self.controller_role {
                ControllerRole::Leaf(leaf) => {
                    let msg =
                        MsgFcCtl::AggregatedInfo((leaf.leaf_id, fc_id, aggr_out));
                    info!("Before leaf{} sends aggregate info to root with msg: {:?}", leaf.leaf_id, msg);
                    leaf.tx_up.send(msg).await?;
                },

                ControllerRole::Root(root) => {
                    info!("Before root controller sends aggregate to fc with msg: {:?}", aggr_out);
                    let msg = MsgFcSource::AggregatedInfo(aggr_out);
                    root.tx_up[fc_id as usize].send(msg).await?;
                },
            }
        }

        Ok(())
    }

    /// Handles a collect from a receiver.
    /// Internally removes all state related to this receiver.
    async fn on_collect_recv(&mut self, recv_id: u64, fc_id: u64) -> Result<()> {
        debug!(
            "{} Collect {recv_id} for FC flow {fc_id}",
            self.controller_role.name()
        );
        let value = self.active_clients[fc_id as usize].remove(&recv_id);
        if value.is_some() {
            self.mc_acks[fc_id as usize].remove_recv();
        }

        // And potentially "ack" stream pieces delegated to this receiver
        // because we will fall back on unicast for this receiver.
        if let Some(recv_del) = self.delegated_streams.get_mut(&recv_id) {
            for (stream_id, off, len) in recv_del.drain() {
                self.mc_acks[fc_id as usize]
                    .on_stream_ack_received(stream_id, off, len);
            }
        }
        _ = self.delegated_streams.remove(&recv_id);
        _ = self.unicast_recv.remove(&recv_id);
        _ = self.recv_ack.remove(&recv_id);
        _ = self.rec_fec_md.remove(&recv_id);
        self.nb_clients = self.nb_clients.map(|nb| nb.saturating_sub(1));
        match &mut self.controller_role {
            ControllerRole::Leaf(leaf) => _ = leaf.tx_down.remove(&recv_id),
            ControllerRole::Root(root) => _ = root.tx_down.remove(&recv_id),
        }

        // If this is a leaf and there is no more receiver, indicate it to the
        // root.
        if self.nb_clients == Some(0) {
            if let ControllerRole::Leaf(leaf) = &self.controller_role {
                info!(
                    "{} sends CollectRecv to root",
                    self.controller_role.name()
                );
                let msg = MsgFcCtl::CollectRecv((leaf.leaf_id, fc_id));
                leaf.tx_up.send(msg).await?;
            }
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
        if let ControllerRole::Leaf(leaf) = &mut $ctl.controller_role {
            if let Some(tx_client) = leaf.tx_down.get(&$recv_id) {
                if let Err(_send_error) = tx_client.send($msg).await {
                    info!("Error for this client: {:?}. Remove it from the structure", $recv_id);
                    // Remove this unicast path from the structure.
                    let _ = $ctl.recv_ack.remove(&$recv_id);
                    let _ = $ctl.rec_fec_md.remove(&$recv_id);
                    if let ControllerRole::Leaf(leaf) = &mut $ctl.controller_role
                    {
                        leaf.tx_down.remove(&$recv_id);
                    }
                }
            }
        }
    };
}

pub type ClientIdMap = HashMap<ConnectionId<'static>, u64>;

impl FcController {
    /// Inserts a new receiver in the state.
    /// This only has an effect on the Leaf controller.
    fn new_recv(&mut self, id: u64, tx: mpsc::Sender<MsgRecv>) {
        if let ControllerRole::Leaf(leaf) = &mut self.controller_role {
            self.nb_clients =
                Some(self.nb_clients.unwrap_or(0).saturating_add(1));
            self.recv_ack.insert(id, OpenRangeSet::default());
            self.rec_fec_md.insert(id, OpenRangeSet::default());
            self.unicast_recv.insert(id);
            leaf.tx_down.insert(id, tx);
        }
    }

    /// A receiver joins a flexicast flow.
    /// This only has an effect on the Leaf controller.
    async fn on_join(
        &mut self, recv_id: u64, fc_id: u64, aggr_msg: Option<FcAggregatedMsg>,
        max_pn: Option<u64>,
    ) -> Result<()> {
        let name = self.controller_role.name();
        info!(
            "{name} enters on_join for client {recv_id} and max_pn: {max_pn:?}"
        );
        if let ControllerRole::Leaf(_leaf) = &self.controller_role {
            let pn_drain = max_pn
                .unwrap_or(0)
                .max(self.mc_acks[fc_id as usize].get_largest_pn().unwrap_or(0));
            let new_insert =
                self.active_clients[fc_id as usize].insert(recv_id, pn_drain + 1);
            _ = self.unicast_recv.remove(&recv_id);
            _ = self.delegated_recv[fc_id as usize].remove(&recv_id);
            if new_insert.is_none() {
                // info!("Insert received {recv_id} and indicate that up to
                // {:?} was ok", pn_drain);
                self.mc_acks[fc_id as usize].new_recv(pn_drain);
            }

            // Must notify this new client of the first packet number of
            // interest.
            let pn = self.last_drained_pn[fc_id as usize]
                .unwrap_or(0)
                .saturating_sub(1);
            let msg = MsgRecv::NewHighestPn((fc_id, pn, pn));
            info!("SEND NEW HIGHEST PN??");
            send_uc_path!(self, recv_id, msg);

            // Update flow control limits.
            if let Some(aggr_msg) = aggr_msg {
                self.on_new_aggr_msg(recv_id, fc_id, aggr_msg).await?;
            }

            // If everyone fell back, the controller will ACK one every two
            // packets to decrease the source's congestion window while keeping
            // sending data.
            if self.mc_acks[fc_id as usize].get_nb_recv() == 1 {
                if let ControllerRole::Leaf(leaf) = &mut self.controller_role {
                    leaf.set_dummy_ack(false, None);
                }
            }
        }

        Ok(())
    }

    /// Handles a new highest packet number received.
    async fn on_new_highest_pn(
        &mut self, fc_id: u64, highest_pn: u64, lowest_pn: u64,
    ) -> Result<()> {
        self.last_drained_pn[fc_id as usize] = Some(lowest_pn.saturating_sub(1));
        match &mut self.controller_role {
            ControllerRole::Leaf(_leaf) => {
                for (recv_id, _) in self.active_clients[fc_id as usize].iter() {
                    let msg =
                        MsgRecv::NewHighestPn((fc_id, highest_pn, lowest_pn));
                    send_uc_path!(self, *recv_id, msg);
                }
            },

            ControllerRole::Root(root) => {
                for (ctl_id, _) in self.active_clients[fc_id as usize].iter() {
                    let msg =
                        MsgFcCtl::NewHighestPn((fc_id, highest_pn, lowest_pn));
                    if let Some(tx_leaf) = root.tx_down.get(ctl_id) {
                        info!("Before root controller sends NewhighestPn 2 to {ctl_id}");
                        tx_leaf.send(msg).await?;
                    }
                }
            },
        }

        Ok(())
    }

    /// Handles a new acknowledgment message from downwards.
    async fn on_new_ack_data(
        &mut self, recv_id: u64, fc_id: u64, mut ack_pn: Option<OpenRangeSet>,
        ack_stream_pieces: Option<Vec<(u64, OpenRangeSet)>>,
        rec_md: Option<OpenRangeSet>,
    ) -> Result<()> {
        // let name = self.controller_role.name();
        // info!(
        //     "{} receives an ACK: {} acknowledges for flexicast flow
        //         {}: pn={:?} and streams={:?}. Current mc ack: {:?}",
        //     name,
        //     recv_id,
        //     fc_id,
        //     ack_pn,
        //     ack_stream_pieces,
        //     self.mc_acks[fc_id as usize]
        // );

        if let Some(pn) = self.active_clients[fc_id as usize].get(&recv_id) {
            debug!(
                "{} Remove until {pn} for this range",
                self.controller_role.name()
            );
            if *pn > 0 {
                ack_pn.as_mut().map(|rs| rs.remove_until(*pn - 1));
            }
            self.handle_ack_pn_stream_pieces(
                recv_id,
                fc_id,
                ack_pn,
                ack_stream_pieces,
                rec_md,
            )
            .await?;
        }

        Ok(())
    }

    /// Add a new leaf controller to the root controller.
    pub fn add_new_leaf_ctl(&mut self, leaf_id: u64, tx: mpsc::Sender<MsgFcCtl>) {
        if let ControllerRole::Root(root) = &mut self.controller_role {
            root.add_leaf_tx(tx, leaf_id);

            self.nb_clients =
                Some(self.nb_clients.unwrap_or(0).saturating_add(1));
            self.recv_ack.insert(leaf_id, OpenRangeSet::default());
            self.rec_fec_md.insert(leaf_id, OpenRangeSet::default());
            self.unicast_recv.insert(leaf_id);

            for fc_id in 0..root.tx_up.len() {
                let pn_drain =
                    self.mc_acks[fc_id as usize].get_largest_pn().unwrap_or(0);
                let new_insert = self.active_clients[fc_id as usize]
                    .insert(leaf_id, pn_drain + 1);
                _ = self.unicast_recv.remove(&leaf_id);
                _ = self.delegated_recv[fc_id as usize].remove(&leaf_id);
                if new_insert.is_none() {
                    // info!("Insert received {recv_id} and indicate that up to
                    // {:?} was ok", pn_drain);
                    self.mc_acks[fc_id as usize].new_recv(pn_drain);
                }
            }
        }
    }
}

#[derive(Debug)]
/// Role of the controller.
/// The controller may either be a final controller (i.e., directly
/// communicating with the flexicast flow) or an initial controller (i.e.,
/// directly communicating with the unicast paths). Future extensions will also
/// include intermediate controller, only communicating with controllers.
/// The first value is the tx towards the leaves.
/// The second value is the tx towards the root.
pub enum ControllerRole {
    /// Root controller.
    /// It communicates with the flexicast flow.
    Root(ControllerRoot),

    /// Leaf controller.
    /// It communicates with the unicat paths.
    Leaf(ControllerLeaf),
}

impl ControllerRole {
    /// Returns the name.
    pub fn name(&self) -> String {
        match self {
            ControllerRole::Leaf(leaf) => format!("leaf {:?}", leaf.leaf_id),
            ControllerRole::Root(_) => "root".to_string(),
        }
    }
}

#[derive(Debug, Default)]
/// Root controller.
pub struct ControllerRoot {
    /// TX towards the leaf controllers.
    tx_down: HashMap<u64, mpsc::Sender<MsgFcCtl>>,

    /// TX towards the flexicast flows.
    tx_up: Vec<mpsc::Sender<MsgFcSource>>,
}

impl ControllerRoot {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new flexicast flow tx.
    pub fn add_flow_tx(&mut self, tx: mpsc::Sender<MsgFcSource>) {
        self.tx_up.push(tx);
    }

    /// Inserts a new leaf controller tx.
    fn add_leaf_tx(&mut self, tx: mpsc::Sender<MsgFcCtl>, leaf_id: u64) {
        self.tx_down.insert(leaf_id, tx);
    }
}

#[derive(Debug)]
/// Leaf controller.
pub struct ControllerLeaf {
    /// TX towards the unicast paths.
    tx_down: HashMap<u64, mpsc::Sender<MsgRecv>>,

    /// TX towards the root controller.
    tx_up: mpsc::Sender<MsgFcCtl>,

    /// Identifier of the leaf controller.
    leaf_id: u64,

    /// Whether the leaf controller enters the dummy ack mode.
    dummy_ack: bool,

    /// To avoid dummy ack multiple times the same packet, we keep in memory the
    /// highest packet number dummy acked.
    highest_pn_dummy_ack: u64,
}

impl ControllerLeaf {
    /// Creates a new instance with a defined root controller tx and ID.
    pub fn new(leaf_id: u64, tx_up: mpsc::Sender<MsgFcCtl>) -> Self {
        Self {
            tx_down: HashMap::new(),
            tx_up,
            leaf_id,
            dummy_ack: false,
            highest_pn_dummy_ack: 0,
        }
    }

    /// Returns the leaf ID.
    pub fn leaf_id(&self) -> u64 {
        self.leaf_id
    }

    /// Returns whether the leaf controller is in the dummy ack mode.
    pub fn get_dummy_ack(&self) -> Option<u64> {
        self.dummy_ack.then(|| self.highest_pn_dummy_ack)
    }

    /// Sets whether the leaf controller is in the dummy ack mode.
    pub fn set_dummy_ack(&mut self, v: bool, pn: Option<u64>) {
        self.dummy_ack = v;
        if let Some(v) = pn {
            self.highest_pn_dummy_ack = self.highest_pn_dummy_ack.max(v);
        }
    }
}
