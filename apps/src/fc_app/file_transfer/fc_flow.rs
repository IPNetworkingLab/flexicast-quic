use crate::fc_app::asynchronous;
use crate::fc_app::asynchronous::fc::conditional_wait_on_app;
use crate::fc_app::asynchronous::fc::FcChannelAsync;
use crate::fc_app::asynchronous::fc::FcFlowRun;
use crate::fc_app::asynchronous::messages::MsgFcCtl;
use crate::fc_app::asynchronous::sendmmsg::MsgSmsg;
use crate::fc_app::cca::FcFlowCwnd;
use crate::fc_app::file_transfer::sender::FileTransferSrc;
use quiche::flexicast::reliable::FcUnicastRetransmission;
use std::cmp;
use std::io;
use std::sync::Arc;
use std::time;
use tokio::sync::mpsc;
const CHANNEL_BUFFER_SIZE: usize = 10;
const MAX_DATAGRAM_SIZE: usize = 1350;

pub struct FcFlowfileTransfer(pub FcChannelAsync);

impl FcFlowRun for FcFlowfileTransfer {
    async fn run(&mut self) -> asynchronous::Result<()> {
        let mut buf = [0u8; 1500];

        // Timer to stop the RTP transmission.
        let mut rtp_stopped = None;
        let mut can_close_conn_after_rtp = false;
        let mut closed = false;

        // Compute a second mc send address.
        let mut addr_buf = self.0.mc_announce_data.group_ip;
        addr_buf[0] += 1;
        let second_mc_ip_addr = std::net::Ipv4Addr::from(addr_buf);
        let _second_mc_addr =
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                second_mc_ip_addr,
                self.0.mc_announce_data.udp_port,
            ));

        // If we use `sendmmsg` instead or real multicast, we will round-robin to
        // spread the traffic.
        let mut sendmmsg_idx = 0;

        // Execute the file transfer application on the source.
        let (tx_app, mut rx_app) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let mut fc_app = FileTransferSrc::new(&self.0.transfer_kind, tx_app)?;
        tokio::spawn(async move {
            let _ = fc_app.run().await;
        });

        loop {
            let now = time::Instant::now();
            let timeout = self.0.fc_chan.channel.timeout();
            let app_close_timeout = rtp_stopped.map(|timer| {
                self.0
                    .rtp_stop_timer
                    .saturating_sub(now.duration_since(timer))
            });

            if timeout.is_none() &&
                self.0.pending_data.is_none() &&
                app_close_timeout.is_none() &&
                self.0.rx_ctl.is_closed()
            {
                break;
            }

            tokio::select! {
                // Timeout sleep.
                Some(_) = optional_timeout(timeout) => {
                    self.0.on_timeout().await?;
                },

                // Application timeout.
                Some(_) = optional_timeout(app_close_timeout) => (),

                Some(msg) = conditional_wait_on_app(&mut rx_app, self.0.pending_data.is_none()) => self.0.handle_app_data(msg, &mut rtp_stopped).await?,

                // Data on the control channel.
                Some(msg) = self.0.rx_ctl.recv() => self.0.handle_ctl_msg(msg).await?,
            }
            let now = time::Instant::now();

            // Check again if there is some timeout there.
            if let Some(time::Duration::ZERO) = self.0.fc_chan.channel.timeout() {
                self.0.on_timeout().await?;
            }

            // Delegate lost STREAM frames to the controller,
            // that will dispatch them to all unicast paths for retransmission.
            let delegated_streams =
                self.0.fc_chan.channel.fc_get_delegated_stream(
                    FcUnicastRetransmission::Delegates(true),
                )?;
            if !delegated_streams.is_empty() {
                debug!(
                    "Delegates streams: {:?} offsets: {:?}",
                    delegated_streams.len(),
                    delegated_streams
                        .iter()
                        .map(|d| (d.offset, d.payload.len()))
                        .collect::<Vec<_>>()
                );
                let del_streams_msg = MsgFcCtl::DelegateStreams((
                    self.0.id,
                    Arc::new(delegated_streams),
                    false,
                ));
                self.0.sync_tx.send(del_streams_msg).await?;
            }

            // Maybe we can close the connection.
            if let Some(timer) = rtp_stopped {
                if rtp_stopped.is_some() {
                    trace!(
                        "SET APP STOPPED TO SOME IN {:?}",
                        self.0
                            .rtp_stop_timer
                            .saturating_sub(now.duration_since(timer))
                    );
                }
                if self
                    .0
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
            if can_close_conn_after_rtp && !closed {
                println!("APP_FINISHED");
                closed = true;
                // self.0.sync_tx.send(MsgFcCtl::CloseRtp(self.0.id)).await?;

                // Notify the SendMMsg instances.
                if let Some(txs) = self.0.sendmmsg_txs.as_ref() {
                    for tx in txs.iter() {
                        let msg = MsgSmsg::Stop;
                        tx.send(msg).await?;
                    }
                }

                // break;
            }

            // Loop to ensure to dequeue all pending data.
            'rtp: loop {
                if self.0.must_wait {
                    break;
                }
                if let Some((app_data, fin, stream_id)) =
                    self.0.pending_data.as_ref()
                {
                    debug!("PENDING DATA IS READ: {:?} {:?}", stream_id, fin);

                    // If allow unicast, sends the data to the controller to
                    // ensure that all unicast receiver get it.
                    if self.0.allow_unicast && !self.0.pending_data_sent_uc {
                        let msg = MsgFcCtl::StreamData((
                            Arc::new(app_data.clone()),
                            *stream_id,
                            *fin,
                            self.0
                                .fc_chan
                                .channel
                                .fc_get_stream_off_front(*stream_id)
                                .unwrap_or(0),
                        ));
                        self.0.sync_tx.send(msg).await?;
                        self.0.pending_data_sent_uc = true;
                    }

                    let written = if !self.0.do_flexicast {
                        app_data.len()
                    } else {
                        match self
                            .0
                            .fc_chan
                            .channel
                            .stream_priority(*stream_id, 0, false)
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
                            .0
                            .fc_chan
                            .channel
                            .stream_send(*stream_id, &app_data, *fin)
                        {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => {
                                break 'rtp;
                            },
                            Err(e) => panic!("Other error: {:?}", e),
                        }
                    };

                    if written == app_data.len() {
                        self.0.pending_data = None;
                        self.0.pending_data_sent_uc = false;
                    } else {
                        self.0.pending_data = self.0.pending_data.as_mut().map(
                            |(d, f, stream_id)| {
                                (d[written..].to_vec(), *f, *stream_id)
                            },
                        );
                        if self
                            .0
                            .pending_data
                            .as_ref()
                            .is_some_and(|(d, ..)| d.is_empty())
                        {
                            self.0.pending_data = None;
                            self.0.pending_data_sent_uc = false;
                        }
                    }
                } else {
                    break;
                }
            }

            // Do nothing if flexicast is disabled.
            // Ensure that we regularly notify the controller of the sent packets.
            // let nb_max_sent_pkt: u64 = 100;
            let mut nb_sent_pkt = 0;
            if self.0.do_flexicast {
                // Generate outgoing QUIC packets to send on the Flexicast path.
                'fc: loop {
                    // Ask quiche to generate the packets.
                    let (write, _send_info) =
                        match self.0.fc_chan.mc_send(&mut buf[..]) {
                            Ok(v) => v,

                            Err(quiche::Error::Done) => break,

                            Err(e) => {
                                error!("Flexicast send() failed: {:?}", e);
                                break 'fc;
                            },
                        };

                    // Send the packets on the wire.
                    if !self.0.must_wait {
                        // Use `sendmmsg` instead.
                        if let Some(sendmmsg_tx) = &self.0.sendmmsg_txs {
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
                                let pkt_len = cmp::min(left, MAX_DATAGRAM_SIZE);

                                match self
                                    .0
                                    .socket
                                    .send_to(
                                        &buf[off..off + pkt_len],
                                        self.0.fc_chan.mc_send_addr,
                                    )
                                    .await
                                {
                                    Ok(v) => written += v,
                                    Err(e) => {
                                        if e.kind() == io::ErrorKind::WouldBlock {
                                            debug!(
                                                "Flexicast send() would block"
                                            );
                                            break 'fc;
                                        }

                                        panic!(
                                            "Flexicast send() failed: {:?}",
                                            e
                                        );
                                    },
                                }
                                off += pkt_len;
                                left -= pkt_len;
                            }
                            debug!(
                                "Flexicast written {:?} bytes to {:?}",
                                written, self.0.fc_chan.mc_send_addr
                            );
                        }
                    } else {
                        debug!("Not actually sending data on the wire because we wait...");
                    }

                    nb_sent_pkt += 1;
                }

                // Notify the controller of the sent packets.
                if nb_sent_pkt > 0 {
                    self.0.sent_pkt_to_controller().await?;
                }

                // Potentially unlimit the congestion window.
                match self.0.cca {
                    FcFlowCwnd::Unlimited =>
                        self.0.fc_chan.channel.fc_set_flow_cwnd(usize::MAX - 1000),
                    FcFlowCwnd::Limited(v) =>
                        self.0.fc_chan.channel.fc_set_flow_cwnd(v as usize),
                    _ => (),
                }
            }
        }

        Ok(())
    }
}

pub async fn optional_timeout(
    timeout: Option<std::time::Duration>,
) -> Option<()> {
    match timeout {
        Some(t) => {
            if t != time::Duration::ZERO {
                tokio::time::sleep(t).await;
            }
            Some(())
        },
        None => None,
    }
}
