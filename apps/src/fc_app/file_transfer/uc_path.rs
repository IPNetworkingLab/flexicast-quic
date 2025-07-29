use quiche::flexicast::FlexicastConnection;
use quiche::flexicast::McClientStatus;
use quiche::flexicast::McRole;
use std::convert::TryInto;
use std::time;

use crate::fc_app::asynchronous::controller::optional_timeout;
use crate::fc_app::asynchronous::messages::MsgFcCtl;
use crate::fc_app::asynchronous::uc::UcPath;
use crate::fc_app::asynchronous::uc::UcPathRun;
use crate::fc_app::asynchronous::Result;

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
                        .send(MsgFcCtl::Join((self.0.client_id, *fc_id as u64, None)))
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
            'stream_data: loop {
                if let Some((data, fin, off, stream_id)) =
                    self.0.pending_data.iter().next()
                {
                    match self.0.conn.stream_priority(*stream_id, 0, false) {
                        Ok(()) => (),
                        Err(quiche::Error::StreamLimit) => (),
                        Err(quiche::Error::Done) => (),
                        Err(e) => {
                            panic!("Error while setting stream priority: {:?}", e)
                        },
                    }

                    let (data, stripped_nb) = if let (Some(off), 0) = (off, self.0.pending_data_off) {
                        let buf_off = self.0.conn.fc_reset_send_off(*stream_id, *off)?;
                        info!("RESET THE FC SEND OFF stream_id={:?} off={:?}. Off given by quiche: {:?}", stream_id, off, buf_off);

                        if *off + (data.len() as u64) < buf_off {
                            (&data[0..0], data.len()) // Empty data. Everything that we could delegate is already received.
                        } else {
                            (&data[buf_off.saturating_sub(*off) as usize..], buf_off.saturating_sub(*off) as usize)
                        }
                    } else {
                        (data.as_slice(), 0)
                    };

                    let written = match self.0.conn.stream_send(
                        *stream_id,
                        &data[self.0.pending_data_off..],
                        *fin,
                    ) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => break 'stream_data,
                        Err(e) => panic!("Other error: {:?}", e),
                    };

                    debug!("{written} was written on the stream!");

                    if self.0.pending_data_off + written == data.len() {
                        let _ = self.0.pending_data.drain(0..1);
                        self.0.pending_data_off = 0;
                    } else {
                        self.0.pending_data_off += written + stripped_nb;
                    }
                } else {
                    break;
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
                info!("UC path sent packet of len {write}");
            }

            // Exit the stap if the connection is closed.
            if self.0.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    self.0.conn.trace_id(),
                    self.0.conn.stats(),
                );
                break;
            }

            // Send control information to the controller.
            self.0.send_ctl_info().await?;

            // Force an unlimited window if asked.
            if self.0.unlimited_cwnd {
                self.0.conn.fc_set_cwnd_from_path_id(0, usize::MAX - 1000);
            }
        }

        Ok(())
    }
}
