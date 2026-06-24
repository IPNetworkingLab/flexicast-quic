use crate::fcquic::fc::conditional_wait_on_app;
use crate::fcquic::fc::FcChannelAsync;
use crate::fcquic::fc::FcFlowRun;
use crate::fcquic::messages::MsgFcCtl;
use crate::fcquic::sendmmsg::MsgSmsg;
use crate::FcQuicMsg;
use crate::Result;
use crate::MAX_DATAGRAM_SIZE;
use log::*;
use quiche::fec::FecError;
use quiche::flexicast::cca::FcFlowCwnd;
use quiche::flexicast::reliable::FcUnicastRetransmission;
use quiche::flexicast::FlexicastConnection;
use std::cmp;
use std::io;
use std::sync::Arc;
use std::time;
use tokio::sync::mpsc;

pub struct FcFlowfileTransfer {
    pub fc: FcChannelAsync,
    pub(crate) rx: mpsc::Receiver<FcQuicMsg>,
}

impl FcFlowRun for FcFlowfileTransfer {
    async fn run(&mut self) -> Result<()> {
        let mut buf = [0u8; 1500];

        let mut start = time::Instant::now();

        // Timer to stop the RTP transmission.
        let mut rtp_stopped = None;
        let mut can_close_conn_after_rtp = false;
        let mut closed = false;

        // Compute a second mc send address.
        let mut addr_buf = self.fc.mc_announce_data.group_ip;
        addr_buf[0] += 1;
        let second_mc_ip_addr = std::net::Ipv4Addr::from(addr_buf);
        let _second_mc_addr =
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                second_mc_ip_addr,
                self.fc.mc_announce_data.udp_port,
            ));

        // If we use `sendmmsg` instead or real multicast, we will round-robin to
        // spread the traffic.
        let mut sendmmsg_idx = 0;

        loop {
            let now = time::Instant::now();
            let timeout = self.fc.fc_chan.channel.timeout();
            info!("timeout of the flexicast flow: {timeout:?}");
            let app_close_timeout = rtp_stopped.map(|timer| {
                self.fc
                    .fc_flow_stop_timer
                    .saturating_sub(now.duration_since(timer))
            });

            if timeout.is_none()
                && self.fc.pending_data.is_none()
                && app_close_timeout.is_none()
                && self.fc.rx_ctl.is_closed()
            {
                info!("Exiting the flexicast flow");
                break;
            }

            tokio::select! {
                // Timeout sleep.
                Some(_) = optional_timeout(timeout) => {
                    self.fc.on_timeout().await?;
                },

                // Application timeout.
                Some(_) = optional_timeout(app_close_timeout) => (),

                Some(msg) = conditional_wait_on_app(&mut self.rx, self.fc.pending_data.is_none()) => self.fc.handle_app_data(msg, &mut rtp_stopped).await?,

                // Data on the control channel.
                Some(msg) = self.fc.rx_ctl.recv() => self.fc.handle_ctl_msg(msg).await?,
            }
            let now = time::Instant::now();

            // Check again if there is some timeout there.
            if let Some(time::Duration::ZERO) = self.fc.fc_chan.channel.timeout()
            {
                self.fc.on_timeout().await?;
            }

            // Check again if we can receive some data.
            if self.fc.pending_data.is_none() {
                if let Ok(msg) = self.rx.try_recv() {
                    self.fc.handle_app_data(msg, &mut rtp_stopped).await?
                }
            }

            // Delegate lost STREAM frames to the controller,
            // that will dispatch them to all unicast paths for retransmission.
            let mut delegated_streams =
                self.fc.fc_chan.channel.fc_get_delegated_stream(
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

                // Push with old ones.
                self.fc.pending_stream_pieces.append(&mut delegated_streams);

                // Give an Arc of it.
                let stream_pieces_arc: Arc<Vec<_>> =
                    Arc::new(self.fc.pending_stream_pieces.drain(..).collect());

                let del_streams_msg = MsgFcCtl::DelegateStreams((
                    self.fc.id,
                    stream_pieces_arc.clone(),
                    false,
                ));
                match self.fc.sync_tx.try_send(del_streams_msg) {
                    Ok(_) => (),
                    Err(_e) => {
                        // We can do this because we are the only having the Arc.
                        self.fc.pending_stream_pieces =
                            Arc::try_unwrap(stream_pieces_arc).unwrap()
                    },
                }
            }

            // Maybe we can close the connection.
            if let Some(timer) = rtp_stopped {
                if rtp_stopped.is_some() {
                    trace!(
                        "SET APP STOPPED TO SOME IN {:?}",
                        self.fc
                            .fc_flow_stop_timer
                            .saturating_sub(now.duration_since(timer))
                    );
                }
                if self
                    .fc
                    .fc_flow_stop_timer
                    .saturating_sub(now.duration_since(timer))
                    == time::Duration::ZERO
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
                // self.fc.sync_tx.send(MsgFcCtl::CloseRtp(self.fc.id)).await?;

                // Notify the SendMMsg instances.
                if let Some(txs) = self.fc.sendmmsg_txs.as_ref() {
                    for tx in txs.iter() {
                        let msg = MsgSmsg::Stop;
                        tx.send(msg).await?;
                    }
                }

                // break;
            }

            // Loop to ensure to dequeue all pending data.
            'rtp: loop {
                if self.fc.must_wait {
                    break;
                }
                if let Some((app_data, fin, stream_id)) =
                    self.fc.pending_data.as_ref()
                {
                    debug!("PENDING DATA IS READ: {:?} {:?}", stream_id, fin);

                    // If allow unicast, sends the data to the controller to
                    // ensure that all unicast receiver get it.
                    if self.fc.allow_unicast && !self.fc.pending_data_sent_uc {
                        let msg = MsgFcCtl::StreamData((
                            Arc::new(app_data.clone()),
                            *stream_id,
                            *fin,
                            self.fc
                                .fc_chan
                                .channel
                                .fc_get_stream_off_front(*stream_id)
                                .unwrap_or(0),
                        ));
                        match self.fc.sync_tx.try_send(msg) {
                            Ok(_) => self.fc.pending_data_sent_uc = true,
                            Err(_e) => {
                                // Avoid sending data if we cannot forward it to
                                // unicast.
                                // FC-TODO: not sure this will work.
                                println!("HERE WE ARE BLOCKING SENDING DATA...");
                                break 'rtp;
                            },
                        }
                    }

                    let written = if !self.fc.do_flexicast {
                        app_data.len()
                    } else {
                        match self
                            .fc
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
                            .fc
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
                        self.fc.pending_data = None;
                        self.fc.pending_data_sent_uc = false;
                        // Immediately try to get the next chunk and keep it in
                        // pending_data so the 'rtp loop continues. This batches
                        // multiple chunks into quiche's send buffer before
                        // mc_send is called, avoiding send-buffer starvation.
                        if let Ok(msg) = self.rx.try_recv() {
                            self.fc
                                .handle_app_data(msg, &mut rtp_stopped)
                                .await?;
                        }
                    } else {
                        self.fc.pending_data = self.fc.pending_data.as_mut().map(
                            |(d, f, stream_id)| {
                                (d[written..].to_vec(), *f, *stream_id)
                            },
                        );
                        if self
                            .fc
                            .pending_data
                            .as_ref()
                            .is_some_and(|(d, ..)| d.is_empty())
                        {
                            self.fc.pending_data = None;
                            self.fc.pending_data_sent_uc = false;
                        }
                    }
                } else {
                    break;
                }
            }

            // Potentially unlimit the congestion window.
            match self.fc.cca {
                FcFlowCwnd::Unlimited => {
                    self.fc.fc_chan.channel.fc_set_flow_cwnd(usize::MAX - 1000)
                },
                FcFlowCwnd::Limited(v) => {
                    self.fc.fc_chan.channel.fc_set_flow_cwnd(v as usize)
                },
                _ => (),
            }

            // Do nothing if flexicast is disabled.
            // Ensure that we regularly notify the controller of the sent packets.
            // let nb_max_sent_pkt: u64 = 100;
            let mut nb_sent_pkt = 0;
            if self.fc.do_flexicast {
                // Whether we already had an error due to FEC.
                let mut fec_error = false;

                // Generate outgoing QUIC packets to send on the Flexicast path.
                'fc: loop {
                    let has_key_to_send = self
                            .fc
                            .fc_chan
                            .channel
                            .get_flexicast_attributes()
                            .is_some_and(|fc| !fc.lkh_keys_to_send.is_empty());
                    // Ask quiche to generate the packets.
                    let (write, _send_info) =
                        match self.fc.fc_chan.mc_send(&mut buf[..]) {
                            Ok(v) => v,

                            Err(quiche::Error::Done) => {
                                break;
                            },

                            Err(quiche::Error::Fec(
                                FecError::FecEncoderError(_),
                            )) if !fec_error => {
                                fec_error = true;
                                continue 'fc;
                            },

                            Err(e) => {
                                error!("Flexicast send() failed: {:?}", e);
                                break 'fc;
                            },
                        };
                    println!("Packet info? : {_send_info:?} [{write}]");
                    // Send the packets on the wire.
                    if !self.fc.must_wait {
                        println!("No waiting required");
                    }
                    
                    println!("[FC] Has keys to send ? : {has_key_to_send}");
                    if true {
                        if self
                            .fc
                            .fc_chan
                            .channel
                            .get_flexicast_attributes()
                            .is_some_and(|fc| fc.lkh_keys_to_send.is_empty())
                        {
                            self.fc.has_control_packet_to_send = false; //TODO: faire ça proprement
                        }
                        // Use `sendmmsg` instead.
                        if let Some(sendmmsg_tx) = &self.fc.sendmmsg_txs {
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
                                    .fc
                                    .socket
                                    .send_to(
                                        &buf[off..off + pkt_len],
                                        self.fc.fc_chan.mc_send_addr,
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
                                written, self.fc.fc_chan.mc_send_addr
                            );
                        }
                    } else {
                        println!("Not actually sending data on the wire because we wait...");
                    }

                    nb_sent_pkt += 1;
                }

                // Notify the controller of the sent packets.
                if nb_sent_pkt > 0 {
                    self.fc.sent_pkt_to_controller().await?;
                }

                // Update the maximum sent packet number for the multicast flow
                // scheduler.
                if nb_sent_pkt > 0 {
                    if let Some(largest_pn) =
                        self.fc.fc_chan.channel.fc_get_largest_sent_pn()
                    {
                        // Atomic update.
                        self.fc.largest_pn_atomic.store(
                            largest_pn,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                }

                // Fall back on unicast if the performance is too low.
                if let Some(cwnd) = self.fc.fc_chan.channel.fc_get_flow_cwnd() {
                    if time::Instant::now().duration_since(start).as_secs() > 30
                        && cwnd.0 < 12_000
                    {
                        // println!("FALL BACK ON UNICAST BECAUSE: {:?}", cwnd);
                        // self.fc.do_flexicast = false;
                    }
                }

                // Potentially update the ack delay.
                self.fc.fc_chan.channel.fc_update_ack_delay(
                    self.fc.nb_active_receivers,
                    self.fc.max_ack_rate,
                )?;
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
