use log::*;
use quiche::flexicast::FlexicastConnection;
use quiche::flexicast::McClientStatus;
use quiche::flexicast::McRole;
use std::convert::TryInto;
use std::time;

use crate::fcquic::messages::MsgFcCtl;
use crate::fcquic::uc::UcPath;
use crate::fcquic::uc::UcPathRun;
use crate::Result;

pub struct UcPathFileTransfer(pub UcPath);

impl UcPathRun for UcPathFileTransfer {
    async fn run(&mut self) -> Result<()> {
        // Before entering the loop, set the McAnnounceData to the client.
        for (i, mc_announce_data) in self.0.mc_announce_data.iter().enumerate() {
            self.0.conn.fc_set_announce_data(mc_announce_data).unwrap();
            // FC-TODO: now we set to 1 the space ID but it is not ideal...
            self.0
                .conn
                .mc_set_flexicast_receiver(
                    &self.0.mc_master_secret[i],
                    1,
                    self.0.mc_key_algo[i].try_into().unwrap(),
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
            let timeout = self.0.conn.timeout();
            let now = std::time::Instant::now();
            let fcf_timeout = self
                .0
                .fcf_scheduler
                .as_ref()
                .map(|s| s.fcf_timeout(now))
                .flatten();
            let fc_chan_id = self
                .0
                .conn
                .get_flexicast_attributes()
                .map(|mc| mc.get_fc_chan_id().map(|(_, id)| *id as u64))
                .flatten();

            let is_listening_to_fc = self
                .0
                .conn
                .get_flexicast_attributes()
                .map(|fc| {
                    fc.get_mc_role() ==
                        McRole::ServerUnicast(McClientStatus::ListenMcPath(
                            true,
                        ))
                })
                .unwrap_or(false);

            if !first_read {
                tokio::select! {
                    // Timeout sleep.
                    Some(_) = optional_timeout(timeout) => self.0.conn.on_timeout(),

                    // Flexicast flow timeout sleep.
                    Some(_) = optional_timeout(fcf_timeout) => {
                        if let Some(scheduler) = self.0.fcf_scheduler.as_mut() {
                            let now = std::time::Instant::now();
                            if scheduler.should_uc_fall_back(now) && is_listening_to_fc {
                                self.0.fcf_scheduler.as_mut().map(|s| s.uc_fall_back());
                                self.0.conn.fc_fall_back_unicast(true);

                                let msg = MsgFcCtl::RecvUcFallBack((self.0.client_id, fc_chan_id.unwrap()));
                                self.0.tx_tcl.send(msg).await?;
                                let now = time::SystemTime::now();
                                println!("{}-RESULT-RECV{} 1", now.duration_since(time::SystemTime::UNIX_EPOCH).unwrap().as_micros(), self.0.client_id);
                            }
                        }
                    },

                    // Data on the control channel.
                    Some(msg) = self.0.rx_ctl.recv() => self.0.handle_ctl_msg(msg).await?,

                    // Packet on the socket.
                    Ok(len) = self.0.uc_sock.recv(&mut buf[..]) => {
                        let recv_info = quiche::RecvInfo {
                            from: self.0.uc_sock.peer_addr().unwrap(),
                            to: self.0.uc_sock.local_addr().unwrap(),
                            from_mc: false,
                        };
                        self.0.handle_new_pkt(&mut buf[..len], recv_info).await?;
                    },
                }
            }

            first_read = false;

            // Informs the controller whether the client listens to a flexicast
            // flow.
            if let (false, Some(mc)) = (
                self.0.listen_fc_channel,
                self.0.conn.get_flexicast_attributes(),
            ) {
                if let Some((_, fc_id)) = mc.get_fc_chan_id() {
                    self.0.listen_fc_channel = true;
                    self.0
                        .tx_tcl
                        .send(MsgFcCtl::Join((
                            self.0.client_id,
                            *fc_id as u64,
                            None,
                            None,
                        )))
                        .await?;
                }
            }

            // Informs the controller that it is ready to listen to flexicast
            // content.
            if let Some(mc) = self.0.conn.get_flexicast_attributes() {
                if let (
                    false,
                    McRole::ServerUnicast(McClientStatus::ListenMcPath(true)),
                ) = (sent_ready, mc.get_mc_role())
                {
                    let msg = MsgFcCtl::RecvReady(self.0.client_id);
                    self.0.tx_tcl.send(msg).await.unwrap();
                    sent_ready = true;
                    if let Some(ref mut scheduler) = self.0.fcf_scheduler {
                        scheduler.set_fcf_alive();
                    }
                }
            }

            // Sends to QUIC RTP frames that must be sent through unicast.
            // if !self.0.pending_data.is_empty() {
            //     info!(
            //         "Before stream data loop: {:?} for {}",
            //         self.0
            //             .pending_data
            //             .iter()
            //             .map(|(d, fin, off, sid)| (d.len(), fin, off, sid))
            //             .collect::<Vec<_>>(),
            //         self.0.client_id
            //     );
            // }
            'stream_data: loop {
                let stream_ids: Vec<_> =
                    self.0.pending_data.keys().map(|id| *id).collect();
                if stream_ids.is_empty() {
                    break 'stream_data;
                }
                debug!(
                    "Enter stream_data loop for receiver {}. state: {:?}",
                    self.0.client_id,
                    self.0
                        .pending_data
                        .iter()
                        .map(|(_k, v)| v.keys())
                        .collect::<Vec<_>>()
                );
                for stream_id in stream_ids.iter() {
                    loop {
                        if let Some((&first_off, (data_arc, fin))) = self
                            .0
                            .pending_data
                            .get(stream_id)
                            .and_then(|btree_map| btree_map.iter().next())
                        {
                            match self
                                .0
                                .conn
                                .stream_priority(*stream_id, 0, false)
                            {
                                Ok(()) => (),
                                Err(quiche::Error::StreamLimit) => (),
                                Err(quiche::Error::Done) => (),
                                Err(e) => {
                                    panic!(
                                    "Error while setting stream priority: {:?}",
                                    e
                                )
                                },
                            }
                            if self.0.pending_data_off > data_arc.len() {
                                println!("WTF here? {:?}", first_off);
                            }
                            let data = &data_arc[self.0.pending_data_off..];
                            let off = first_off + self.0.pending_data_off as u64;
                            let buf_off = self
                                .0
                                .conn
                                .fc_reset_send_off(*stream_id, off)
                                .map_err(|e| {
                                    debug!(
                                        "{} Error reset send off: {e:?}",
                                        self.0.client_id
                                    );
                                    e
                                })?;
                            info!(
                                "Recv {}: RESET THE FC SEND OFF stream_id={:?} off={:?}.
                        Off given by quiche: {:?} for {}. Pending_data_off={}",
                                self.0.client_id, stream_id, off, buf_off, self.0.client_id, self.0.pending_data_off
                            );

                            let (data, stripped_nb) = if off + (data.len() as u64) <
                                buf_off
                            {
                                info!(
                                    "Recv {}: Giving empty data for {}.",
                                    self.0.client_id, self.0.client_id,
                                );
                                (&data[0..0], data.len()) // Empty data.
                                                          // Everything
                                                          // that we could
                                                          // delegate
                                                          // is already
                                                          // received.
                            } else {
                                info!(
                                    "Recv {}: Giving data after {}. So remaining
                            length={:?}. Offset={:?} for {}",
                                    self.0.client_id,
                                    buf_off.saturating_sub(off),
                                    data[buf_off.saturating_sub(off) as usize..]
                                        .len(),
                                    buf_off,
                                    self.0.client_id
                                );
                                (
                                    &data[buf_off.saturating_sub(off) as usize..],
                                    buf_off.saturating_sub(off) as usize,
                                )
                            };

                            let written = if !data.is_empty() {
                                match self
                                    .0
                                    .conn
                                    .stream_send(*stream_id, &data, *fin)
                                {
                                    Ok(v) => v,
                                    Err(quiche::Error::Done) => {
                                        debug!("Recv {}: breaks stream send because done", self.0.client_id);
                                        break 'stream_data;
                                    },
                                    Err(e) => panic!("Other error: {:?}", e),
                                }
                            } else {
                                debug!(
                                    "Recv {}: stream send with empty data",
                                    self.0.client_id
                                );
                                0
                            };

                            if self.0.pending_data_off + written >= data_arc.len() ||
                                data.is_empty()
                            {
                                debug!("Recv {}: Drain pending data because pending off={} + written={} >= data.len={}, first_off={}", self.0.client_id, self.0.pending_data_off, written, data.len(), first_off);
                                self.0.pending_data.get_mut(stream_id).and_then(
                                    |btree_map| {
                                        btree_map.remove_entry(&first_off)
                                    },
                                );
                                self.0.pending_data_off = 0;
                                // info!(
                                //     "Draining element and reset pending data
                                // for {}",
                                //     self.0.client_id
                                // );
                            } else {
                                self.0.pending_data_off += written + stripped_nb;
                                info!(
                                "Recv {}: Increasing pending data off by {}. Now={} for
                            {}",
                                self.0.client_id,
                                written + stripped_nb,
                                self.0.pending_data_off,
                                self.0.client_id
                            );
                            }
                        } else {
                            break 'stream_data;
                        }
                    }
                }
            }

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            'send: loop {
                let (write, send_info) = match self.0.conn.send(&mut buf[..]) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("QUICHE says DONE here unicast");
                        break 'send;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", self.0.conn.trace_id(), e);

                        self.0.conn.close(false, 0x1, b"fail").ok();
                        break 'send;
                    },
                };

                // Send the packet directly to the wire without going by the main
                // thread.
                self.0.uc_sock.send_to(&buf[..write], send_info.to).await?;
                trace!("UC path sent packet of len {write}");
            }

            // Exit the stap if the connection is closed.
            if self.0.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    self.0.conn.trace_id(),
                    self.0.conn.stats(),
                );

                if let Some(fc_id) = fc_chan_id {
                    let msg = MsgFcCtl::CollectRecv((self.0.client_id, fc_id));
                    self.0.tx_tcl.send(msg).await?;
                }

                break;
            }

            // Send control information to the controller.
            if let Err(e) = self.0.send_ctl_info().await {
                debug!(
                    "Error when sending control info for {}: {:?}",
                    self.0.client_id, e
                );
                return Err(e);
            }

            // Force an unlimited window if asked.
            if self.0.unlimited_cwnd {
                self.0.conn.fc_set_cwnd_from_path_id(0, usize::MAX - 1000);
            }
        }

        info!("STOP CONNECTION: {:?}", self.0.client_id);

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
