//! Module for the asynchronous communication with the flexicast source.

use super::sendmmsg::MsgSmsg;
use super::Result;
use quiche::flexicast::control::OpenSent;
use quiche::flexicast::reliable::FcUnicastRetransmission;
use quiche::flexicast::FlexicastChannelSource;
use quiche::flexicast::McAnnounceData;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Receiver;

use super::messages::*;

use crate::fc_app::cca::FcFlowCwnd;
use crate::fc_app::file_transfer::sender::FileTransferKind;
use crate::fc_app::file_transfer::sender::FileTransferSrcMsg;
use std::sync::Arc;
use std::time;
use std::time::Instant;
use tokio::sync::mpsc;

pub struct FcChannelInfo {
    pub socket: UdpSocket,
    pub fc_chan: FlexicastChannelSource,
    pub mc_announce_data: McAnnounceData,
}

pub struct FcChannelAsync {
    pub socket: UdpSocket,
    pub fc_chan: FlexicastChannelSource,
    pub mc_announce_data: McAnnounceData,

    /// Stop timer.
    /// Once the source sends a STOP RTP message, the source waits for 5 *
    /// flexicast timer before closing the connection.
    pub rtp_stop_timer: time::Duration,

    /// Communication between entities, using tokio mpsc.
    pub sync_tx: mpsc::Sender<MsgFcCtl>,

    /// ID of the flexicast channel.
    pub id: u64,

    /// Reception channel for the flexicast source.
    pub rx_ctl: mpsc::Receiver<MsgFcSource>,

    /// Whether the flexicast source must wait to send packets on the wire.
    pub must_wait: bool,

    /// Whether the flexicast channel will be limited by the application or not.
    /// If set to true, will set an almost infinite congestion window.
    pub cca: FcFlowCwnd,

    /// Whether unicast fall-back is used.
    /// Used to know whether the source must forward application data to the
    /// controller.
    pub allow_unicast: bool,

    /// Whether flexicast is enabled.
    /// Used to know whether the source must send data on the wire.
    pub do_flexicast: bool,

    /// The SendMMsg instances.
    /// If this value is not `None`, it means that we use `sendmmsg` instead of
    /// relying on a multicast network to send the packets on the flexicast
    /// flow.
    pub sendmmsg_txs: Option<Vec<mpsc::Sender<MsgSmsg>>>,

    /// Transfer kind.
    pub transfer_kind: FileTransferKind,

    /// Data received from the application and not yet delivered to QUIC.
    /// If some, we avoid listening again on the data channel to avoid having
    /// too much pending data.
    /// The second value indicates whether this is the last piece of data, i.e.,
    /// 'fin'.
    /// The last value indicates the stream ID.
    pub pending_data: Option<(Vec<u8>, bool, u64)>,

    /// Whether the pending data was already sent to the unicast receivers, if
    /// allow_unicast is enabled.
    pub pending_data_sent_uc: bool,

    /// Pending rangeset to send to the controller.
    pub pending_sent_pkt: Vec<OpenSent>,
}

/// Trait defining a unique function, `run`, which must be implemented by the
/// application to handle the flexicast flow.
pub trait FcFlowRun {
    /// Main asynchronous I/O and control loop for the flexicast flow, depending
    /// on the application.
    fn run(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;
}

impl FcChannelAsync {
    pub async fn on_timeout(&mut self) -> Result<()> {
        self.fc_chan.channel.on_timeout();

        let pn = self.fc_chan.channel.fc_next_and_first_pn();
        if let Some((highest_pn, lowest_pn)) = pn {
            let new_exp_pkt_msg =
                MsgFcCtl::NewHighestPn((self.id, highest_pn, lowest_pn));
            let _ = self.sync_tx.try_send(new_exp_pkt_msg);
        }

        Ok(())
    }

    pub async fn handle_ctl_msg(&mut self, msg: MsgFcSource) -> Result<()> {
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
                tokio::time::sleep(time::Duration::from_millis(500)).await;
                self.must_wait = false;
            },

            MsgFcSource::AskStreamPieces => {
                let delegated_streams =
                    self.fc_chan.channel.fc_get_delegated_stream(
                        FcUnicastRetransmission::FullRetransmit,
                    )?;
                let del_streams_msg = MsgFcCtl::DelegateStreams((
                    self.id,
                    Arc::new(delegated_streams),
                    true,
                ));
                self.sync_tx.send(del_streams_msg).await?;
            },

            MsgFcSource::AggregatedInfo(aggr_info) => {
                info!("New AggregatedInfo message: {:?}", aggr_info);
                // Get the updated MAX_DATA and MAX_STREAM_DATA for existing
                // streams.
                self.fc_chan
                    .channel
                    .fc_set_max_tx_data(aggr_info.max_data)?;

                for (stream_id, max_stream_data) in aggr_info.max_stream_datas {
                    self.fc_chan
                        .channel
                        .fc_set_max_tx_stream_data(max_stream_data, stream_id)?;
                }
            },
        }

        Ok(())
    }

    pub async fn sent_pkt_to_controller(&mut self) -> Result<()> {
        let mut sent = match self.fc_chan.channel.fc_get_sent_pkt(None) {
            Ok(v) => v,
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let inner_value = &mut self.pending_sent_pkt;
        inner_value.extend(sent.drain(..));

        let sent_arc = Arc::new(self.pending_sent_pkt.clone());

        info!("Fc Flow has new sent packets: {:?}", sent_arc.iter().map(|sent| sent.pkt_num).collect::<Vec<_>>());
        let msg = MsgFcCtl::Sent((self.id, sent_arc.clone()));
        if let Err(_e) = self.sync_tx.try_send(msg) {
            debug!("This is a timeout on the fc flow. send later");
        } else {
            self.pending_sent_pkt = Vec::new();
        }

        Ok(())
    }

    pub async fn handle_app_data(
        &mut self, msg: FileTransferSrcMsg, app_stopped: &mut Option<Instant>,
    ) -> Result<()> {
        if self.pending_data.is_some() {
            return Err("Pending data is not None and attempting to read!"
                .to_string()
                .into());
        }
        match msg {
            FileTransferSrcMsg::Close => {
                *app_stopped = Some(Instant::now());
                info!("Modify app stopped to now!");
            },
            FileTransferSrcMsg::Data(v) => {
                self.pending_data = Some(v);
            },
        }

        Ok(())
    }
}

pub async fn conditional_wait_on_app(
    rx_app: &mut Receiver<FileTransferSrcMsg>, v: bool,
) -> Option<FileTransferSrcMsg> {
    if v {
        rx_app.recv().await
    } else {
        None
    }
}
