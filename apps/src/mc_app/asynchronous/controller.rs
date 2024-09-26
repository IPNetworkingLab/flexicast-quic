//! Asynchronous control loop between flexicast source and unicast server with
//! tokio.

use std::collections::HashSet;

use crate::common::ClientIdMap;

use super::Result;
use quiche::multicast::ack::FcDelegatedStream;
use quiche::multicast::ack::McAck;
use quiche::multicast::ack::McStreamOff;
use quiche::multicast::ack::OpenRangeSet;
use quiche::multicast::control::OpenSent;
use quiche::multicast::ExpiredPkt;
use quiche::multicast::McAnnounceData;
use quiche::RecvInfo;
use quiche::SendInfo;
use tokio;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Messages sent to the controller.
pub enum MsgFcCtl {
    /// Stop RTP.
    /// Receivers listening to this flexicast channel can close their
    /// communication.
    CloseRtp(u64),

    /// New connection from a client.
    /// Indicate the channel to communicate with it and its client ID.
    NewClient((u64, mpsc::Sender<MsgRecv>)),

    /// The receiver joins a new flexicast flow.
    /// The first value is the client ID.
    /// The second value is the index of the flexicast flow.
    Join((u64, u64)),

    /// The receiver changes its flexicast flow.
    /// The first value is the client ID.
    /// The second value is the index of the old flexicast flow (to leave).
    /// The third value is the index of the new flexicast flow (to join).
    Change((u64, u64, u64)),

    /// New last expired packet from the flexicast source.
    /// The controller informs all clients listening to this source.
    /// The first value is the index of the flexicast flow.
    /// The second value is the expired packet.
    NewExpiredPkt((u64, ExpiredPkt)),

    /// The receiver acknowledges packets received on the flexicast flow.
    /// It also acknowledges stream pieces that have been delegated through the
    /// unicast path.
    AckData((u64, u64, Option<OpenRangeSet>, Option<McStreamOff>)),

    /// The flexicast source forwards to the controller the packet it just sent
    /// on the flexicast flow.
    Sent((u64, Vec<OpenSent>)),

    /// The flexicast source forwards to the controller the delegated streams.
    /// These are the STREAM frames that have been lost, considering all
    /// receivers (using their ACK). The controller will handle the dispatch
    /// of the unicast retransmission to simplify the work of the flexicast
    /// source.
    DelegateStreams((u64, Vec<FcDelegatedStream>)),
}

/// Messages sent to the receiver.
pub enum MsgRecv {
    /// Stop RTP.
    CloseRtp,

    /// New last expired packet from the flexicast source.
    /// The controller informs all clients listening to this source.
    /// The first value is the index of the flexicast flow.
    /// The second value is the expired packet.
    NewExpiredPkt((u64, ExpiredPkt)),

    /// Packets sent on the flexicast flow that will be part of the state.
    Sent((u64, Vec<OpenSent>)),

    /// Identical semantic as [`MsgFcCtl::DelegateStreams`].
    DelegateStreams((u64, Vec<FcDelegatedStream>)),

    /// New packet from this receiver for the unicast instance to handle.
    NewPkt((Vec<u8>, RecvInfo)),
}

/// Messages sent to the flexicast source.
pub enum MsgFcSource {
    /// Packet numbers acknowledged by all clients listening to the flexicast
    /// flow.
    AckPn(OpenRangeSet),

    /// Stream pieces that were delegated and now received by all clients that
    /// should receive it.
    AckStreamPieces(McStreamOff),
}

/// Messages sent to the main thread.
pub enum MsgMain {
    /// A receiver notifies that a new connection ID is mapped to its
    /// connection.
    NewCID((u64, Vec<u8>)),

    /// A receiver notifies that a new packet must be sent on the wire.
    SendPkt((Vec<u8>, SendInfo)),

    /// The flexicast flow stopped.
    FcFlowStop(u64),
}

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
    /// Indexed by the client ID.
    tx_clients: Vec<mpsc::Sender<MsgRecv>>,

    /// Mapping between the ID of the flexicast source and the IDs of the
    /// clients. Indexed by the the flexicast source ID.
    active_clients: Vec<HashSet<u64>>,

    /// All McAck structures that the controller maintains.
    mc_acks: Vec<McAck>,

    /// Last expired packets for each flexicast flow.
    last_expired_pn: Vec<Option<u64>>,

    /// Communication channels with towards flexicast sources.
    tx_fc_sources: Vec<mpsc::Sender<MsgFcSource>>,

    /// Keeps state of the received packet numbers for each client.
    /// This state is used to delegated STREAM frames that were lost on the
    /// flexicast flow and need unicast retransmission to the receivers.
    /// It is regularly populated with the acknowledgements from the receivers
    /// through the [`MsgFcCtl::AckData`] message, and erased when the
    /// controller delegates STREAM frames to the receiver. Indexed through
    /// the receiver ID.
    recv_ack: Vec<OpenRangeSet>,

    /// Communication towards the main thread.
    tx_main: mpsc::Sender<MsgMain>,
}

impl FcController {
    /// New controller.
    pub fn new(
        rx_fc_ctl: mpsc::Receiver<MsgFcCtl>,
        mc_announce_data: Vec<McAnnounceData>,
        tx_fc_sources: Vec<mpsc::Sender<MsgFcSource>>,
        tx_main: mpsc::Sender<MsgMain>,
    ) -> Self {
        Self {
            rx_fc_ctl,
            nb_clients: None,
            tx_clients: Vec::new(),
            active_clients: vec![HashSet::new(); mc_announce_data.len()],
            mc_acks: vec![McAck::new(); mc_announce_data.len()],
            last_expired_pn: vec![None; mc_announce_data.len()],
            recv_ack: vec![OpenRangeSet::default(); mc_announce_data.len()],
            _mc_announce_data: mc_announce_data,
            tx_fc_sources,
            tx_main,
        }
    }

    /// Run the controller.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                Some(msg) = self.rx_fc_ctl.recv() => self.handle_fc_msg(msg).await?,
                else => debug!("Error in select controller"),
            }

            // Exit controller when no more clients listen to the group.
            if self.nb_clients == Some(0) {
                break;
            }
        }

        Ok(())
    }

    /// Handle the reception of a message from the flexicast source channel.
    async fn handle_fc_msg(&mut self, msg: MsgFcCtl) -> Result<()> {
        match msg {
            MsgFcCtl::CloseRtp(id) => self.send_close_rtp(id).await?,

            MsgFcCtl::NewClient((_id, tx)) => {
                // Push new client.
                debug!("New receiver connected to the source");
                self.nb_clients =
                    Some(self.nb_clients.unwrap_or(0).saturating_add(1));
                self.tx_clients.push(tx);
            },

            MsgFcCtl::Join((client_id, fc_chan_id)) => {
                debug!("New client {client_id} joins flow {fc_chan_id}");
                _ = self.active_clients[fc_chan_id as usize].insert(client_id);
                self.mc_acks[fc_chan_id as usize].new_recv(
                    self.last_expired_pn[fc_chan_id as usize].unwrap_or(0),
                );
            },

            MsgFcCtl::Change((client_id, old_fc_chan_id, new_fc_chan_id)) => {
                debug!("Client {client_id} changes flow {old_fc_chan_id} -> {new_fc_chan_id}");
                _ = self.active_clients[old_fc_chan_id as usize]
                    .remove(&client_id);
                _ = self.active_clients[new_fc_chan_id as usize]
                    .insert(client_id);
            },

            MsgFcCtl::NewExpiredPkt((fc_id, exp_pkt)) => {
                debug!("New expired packet from {fc_id}: {exp_pkt:?}");
                self.last_expired_pn[fc_id as usize] = exp_pkt.pn;
                for client_idx in self.active_clients[fc_id as usize].iter() {
                    self.tx_clients[*client_idx as usize]
                        .send(MsgRecv::NewExpiredPkt((fc_id, exp_pkt)))
                        .await?;
                }
            },

            MsgFcCtl::AckData((recv_id, fc_id, ack_pn, ack_stream_pieces)) => {
                debug!("Client {recv_id} acknowledges for flexicast flow {fc_id}: pn={ack_pn:?} and streams={ack_stream_pieces:?}");
                self.handle_ack_pn_stream_pieces(
                    recv_id,
                    fc_id,
                    ack_pn,
                    ack_stream_pieces,
                )
                .await?;
            },

            MsgFcCtl::Sent((fc_id, sent)) => {
                debug!("Flexicast source {fc_id} sent {:?}", sent.len());
                self.handle_sent_pkt(fc_id, sent).await?;
            },

            MsgFcCtl::DelegateStreams((fc_id, delegated_streams)) => {
                debug!("Flexicast source delegated streams");
                self.handle_delegated_streams(fc_id, delegated_streams)
                    .await?;
            },
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
                self.tx_clients[id_client as usize]
                    .send(MsgRecv::CloseRtp)
                    .await?;
                self.nb_clients = self.nb_clients.map(|n| n.saturating_sub(1));
            }
        }
        let msg = MsgMain::FcFlowStop(id);
        self.tx_main.send(msg).await?;

        Ok(())
    }

    /// Sends to the flexicast source the acknowledged packets and stream
    /// pieces.
    async fn handle_ack_pn_stream_pieces(
        &mut self, recv_id: u64, fc_id: u64, ack_pn: Option<OpenRangeSet>,
        ack_stream_pieces: Option<McStreamOff>,
    ) -> Result<()> {
        let mc_ack = &mut self.mc_acks[fc_id as usize];

        // Packet numbers acknowledgment.
        if let Some(rs) = ack_pn {
            mc_ack.on_ack_received(&rs);

            // Store per-receiver acknowledgments.
            for range in rs.iter() {
                self.recv_ack[recv_id as usize].insert(range);
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

        // Maybe now the controller can acknowledge some packets numbers.
        if let Some(fully_acked) = mc_ack.full_ack() {
            let msg = MsgFcSource::AckPn(fully_acked);
            self.tx_fc_sources[fc_id as usize].send(msg).await?;
        }

        // And stream pieces may also be acknowledged now.
        if let Some(fully_acked_stream_pieces) = mc_ack.acked_stream_off() {
            let msg = MsgFcSource::AckStreamPieces(fully_acked_stream_pieces);
            self.tx_fc_sources[fc_id as usize].send(msg).await?;
        }

        Ok(())
    }

    /// Forwards to the unicast instances the packets sent on the flexicast flow
    /// by the source.
    async fn handle_sent_pkt(
        &self, fc_id: u64, sent: Vec<OpenSent>,
    ) -> Result<()> {
        for &client_id in self.active_clients[fc_id as usize].iter() {
            let msg = MsgRecv::Sent((fc_id, sent.clone()));
            self.tx_clients[client_id as usize].send(msg).await?;
        }

        Ok(())
    }

    /// Dispatchs delegated streams to receivers.
    async fn handle_delegated_streams(
        &mut self, fc_id: u64, delegated_streams: Vec<FcDelegatedStream>,
    ) -> Result<()> {
        // Iterate over all clients listening to this flexicast source to delegate
        // the appropriate STREAM frame retransmissions.
        for &client_id in self.active_clients[fc_id as usize].iter() {
            let client_ack: HashSet<u64> =
                self.recv_ack[client_id as usize].flatten().collect();
            let tx_client = &self.tx_clients[client_id as usize];

            // Delegate the STREAM frames for unicast retransmission.
            // FC-TODO: maybe not optimal, create a new message for every streams?
            let mut del_streams_to_client = Vec::new();
            for delegated_piece in delegated_streams.iter() {
                if !client_ack.contains(&delegated_piece.pn) {
                    // Lost packet on this client.
                    del_streams_to_client.push(delegated_piece.to_owned());
                }
            }

            // Send the delegated pieces to the client.
            let msg = MsgRecv::DelegateStreams((fc_id, del_streams_to_client));
            tx_client.send(msg).await?;

            // Release memory based on the highest packet number.
            // Fc-TODO: not sure this will work because the last expired may be
            // another than the largest lost.
            if let Some(max_pn) = self.last_expired_pn[fc_id as usize] {
                self.recv_ack[client_id as usize].remove_until(max_pn);
            }
        }

        Ok(())
    }
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
