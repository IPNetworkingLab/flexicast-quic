//! Asynchronous control loop between flexicast source and unicast server with
//! tokio.

use std::collections::HashSet;

use super::Result;
use quiche::multicast::ack::McAck;
use quiche::multicast::ack::McStreamOff;
use quiche::multicast::ack::OpenRangeSet;
use quiche::multicast::control::OpenSent;
use quiche::multicast::ExpiredPkt;
use quiche::multicast::McAnnounceData;
use tokio;
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

    /// The flexicast source forwards to the controller the packet it just sent on the flexicast flow.
    Sent((u64, Vec<OpenSent>)),
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
}

impl FcController {
    /// New controller.
    pub fn new(
        rx_fc_ctl: mpsc::Receiver<MsgFcCtl>,
        mc_announce_data: Vec<McAnnounceData>,
        tx_fc_sources: Vec<mpsc::Sender<MsgFcSource>>,
    ) -> Self {
        Self {
            rx_fc_ctl,
            nb_clients: None,
            tx_clients: Vec::new(),
            active_clients: vec![HashSet::new(); mc_announce_data.len()],
            mc_acks: vec![McAck::new(); mc_announce_data.len()],
            last_expired_pn: vec![None; mc_announce_data.len()],
            _mc_announce_data: mc_announce_data,
            tx_fc_sources,
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

            MsgFcCtl::AckData((client_id, fc_id, ack_pn, ack_stream_pieces)) => {
                debug!("Client {client_id} acknowledges for flexicast flow {fc_id}: pn={ack_pn:?} and streams={ack_stream_pieces:?}");
                self.handle_ack_pn_stream_pieces(fc_id, ack_pn, ack_stream_pieces).await?;
            },

            MsgFcCtl::Sent((fc_id, sent)) => {
                debug!("Flexicast source {fc_id} sent {:?}", sent.len());
                self.handle_sent_pkt(fc_id, sent).await?;
            }
        }

        Ok(())
    }

    /// Sends to clients listening to a particular flexicast flow that RTP is
    /// closed.
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

        Ok(())
    }

    /// Sends to the flexicast source the acknowledged packets and stream
    /// pieces.
    async fn handle_ack_pn_stream_pieces(
        &mut self, fc_id: u64, ack_pn: Option<OpenRangeSet>,
        ack_stream_pieces: Option<McStreamOff>,
    ) -> Result<()> {
        let mc_ack = &mut self.mc_acks[fc_id as usize];

        // Packet numbers acknowledgment.
        if let Some(rs) = ack_pn {
            mc_ack.on_ack_received(&rs);
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

    /// Forwards to the unicast instances the packets sent on the flexicast flow by the source.
    async fn handle_sent_pkt(&self, fc_id: u64, sent: Vec<OpenSent>) -> Result<()> {
        for &client_id in self.active_clients[fc_id as usize].iter() {
            let msg = MsgRecv::Sent((fc_id, sent.clone()));
            self.tx_clients[client_id as usize].send(msg).await?;
        }

        Ok(())
    }
}
