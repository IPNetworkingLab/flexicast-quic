use crate::fc_app::asynchronous::controller::optional_timeout;
use crate::fc_app::asynchronous::messages::MsgFcCtl;
use crate::fc_app::asynchronous::uc::UcPath;
use crate::fc_app::asynchronous::uc::UcPathRun;
use crate::fc_app::asynchronous::Result;
use quiche::flexicast::FlexicastConnection;
use quiche::flexicast::McClientStatus;
use quiche::flexicast::McRole;
use std::convert::TryInto;
use tokio::sync::mpsc;

use super::FcTtlMsg;

pub struct UcPathTtl {
    pub uc_path: UcPath,

    pub tx_app: mpsc::Sender<FcTtlMsg>,
}

impl UcPathRun for UcPathTtl {
    async fn run(&mut self) -> Result<()> {
        // Before entering the loop, set the McAnnounceData to the client.
        for (i, mc_announce_data) in
            self.uc_path.mc_announce_data.iter().enumerate()
        {
            self.uc_path
                .conn
                .fc_set_announce_data(mc_announce_data)
                .unwrap();
            // FC-TODO: now we set to 1 the space ID but it is not ideal...
            self.uc_path
                .conn
                .mc_set_flexicast_receiver(
                    &self.uc_path.mc_master_secret[i],
                    1,
                    self.uc_path.mc_key_algo[i].try_into().unwrap(),
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
            let timeout = self.uc_path.conn.timeout();

            if !first_read {
                tokio::select! {
                    // Timeout sleep.
                    Some(_) = optional_timeout(timeout) => self.uc_path.conn.on_timeout(),

                    // Data on the control channel.
                    Some(msg) = self.uc_path.rx_ctl.recv() => self.uc_path.handle_ctl_msg(msg).await?,
                }
            }

            first_read = false;

            // Informs the controller whether the client listens to a flexicast
            // flow.
            if let (false, Some(mc)) = (
                self.uc_path.listen_fc_channel,
                self.uc_path.conn.get_flexicast_attributes(),
            ) {
                if let Some((_, fc_id)) = mc.get_fc_chan_id() {
                    self.uc_path.listen_fc_channel = true;
                    self.uc_path
                        .tx_tcl
                        .send(MsgFcCtl::Join((
                            self.uc_path.client_id,
                            *fc_id as u64,
                            None,
                            None,
                        )))
                        .await?;
                }
            }

            // Informs the controller that it is ready to listen to flexicast
            // content.
            if let Some(mc) = self.uc_path.conn.get_flexicast_attributes() {
                if let (
                    false,
                    McRole::ServerUnicast(McClientStatus::ListenMcPath(true)),
                ) = (sent_ready, mc.get_mc_role())
                {
                    let msg = MsgFcCtl::RecvReady(self.uc_path.client_id);
                    self.uc_path.tx_tcl.send(msg).await.unwrap();
                    sent_ready = true;
                    if let Some(ref mut scheduler) = self.uc_path.fcf_scheduler {
                        scheduler.set_fcf_alive();
                    }
                }
            }

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            'send: loop {
                let (write, send_info) =
                    match self.uc_path.conn.send(&mut buf[..]) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            trace!("QUICHE says DONE here");
                            break 'send;
                        },

                        Err(e) => {
                            error!(
                                "{} send failed: {:?}",
                                self.uc_path.conn.trace_id(),
                                e
                            );

                            self.uc_path.conn.close(false, 0x1, b"fail").ok();
                            break 'send;
                        },
                    };

                // Send the packet directly to the wire without going by the main
                // thread.
                self.uc_path
                    .uc_sock
                    .send_to(&buf[..write], send_info.to)
                    .await?;
            }

            // Exit the stap if the connection is closed.
            if self.uc_path.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    self.uc_path.conn.trace_id(),
                    self.uc_path.conn.stats(),
                );
                break;
            }

            // Send control information to the controller.
            self.uc_path.send_ctl_info().await?;
        }

        Ok(())
    }
}
