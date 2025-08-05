use std::cmp;
use std::io;
use std::sync::Arc;
use std::time;

use quiche::flexicast::reliable::FcUnicastRetransmission;
use tokio::sync::mpsc;

use crate::fc_app::asynchronous;
use crate::fc_app::asynchronous::fc::FcChannelAsync;
use crate::fc_app::asynchronous::fc::FcFlowRun;
use crate::fc_app::asynchronous::messages::MsgFcCtl;
use crate::fc_app::cca::FcFlowCwnd;
use crate::fc_app::video::hls::HlsSource;
use crate::fc_app::video::rtp_source::VideoSourceMsg;
const MAX_DATAGRAM_SIZE: usize = 1350;

pub struct FcFlowVideo {
    pub fc: FcChannelAsync,
    pub dir_path: String,
}

const CHANNEL_BUFFER_SIZE: usize = 10;

impl FcFlowRun for FcFlowVideo {
    async fn run(&mut self) -> asynchronous::Result<()> {
        let mut buf = [0u8; 1500];

        // Create communication channel between the application and the flexicast
        // flow.
        let (tx_app, mut rx_app) = mpsc::channel(CHANNEL_BUFFER_SIZE);

        // Start the application in its task.
        // let timeout_opt = None;
        // let video_feed_sockaddr = "127.0.0.1:5555".parse().unwrap();
        // tokio::spawn(async move {
        //     RtpSource::new(video_feed_sockaddr, tx_app, timeout_opt)
        //         .await
        //         .unwrap();
        // });
        let dir_path = self.dir_path.clone();
        tokio::spawn(async move {
            HlsSource::new(&dir_path, tx_app).run().await.unwrap();
        });

        loop {
            let timeout = self.fc.fc_chan.channel.timeout();

            tokio::select! {
                // Timeout sleep.
                Some(_) = optional_timeout(timeout) => {
                    self.fc.on_timeout().await?;
                },

                Some(msg) = conditional_wait_on_app(&mut rx_app, self.fc.pending_data.is_none()) => self.handle_new_app_msg(msg)?,

                // Data on the control channel.
                Some(msg) = self.fc.rx_ctl.recv() => self.fc.handle_ctl_msg(msg).await?,
            }

            // Check again for a timeout.
            if let Some(time::Duration::ZERO) = self.fc.fc_chan.channel.timeout()
            {
                self.fc.on_timeout().await?;
            }

            // Delegate lost STREAM frames to the controller.
            let delegated_streams =
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
                let del_streams_msg = MsgFcCtl::DelegateStreams((
                    self.fc.id,
                    Arc::new(delegated_streams),
                    false,
                ));
                self.fc.sync_tx.send(del_streams_msg).await?;
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
                        self.fc.sync_tx.send(msg).await?;
                        self.fc.pending_data_sent_uc = true;
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

            // Do nothing if flexicast is disabled.
            // Ensure that we regularly notify the controller of the sent packets.
            // let nb_max_sent_pkt: u64 = 100;
            let mut nb_sent_pkt = 0;
            if self.fc.do_flexicast {
                // Generate outgoing QUIC packets to send on the Flexicast path.
                'fc: loop {
                    // Ask quiche to generate the packets.
                    let (write, _send_info) =
                        match self.fc.fc_chan.mc_send(&mut buf[..]) {
                            Ok(v) => v,

                            Err(quiche::Error::Done) => break,

                            Err(e) => {
                                error!("Flexicast send() failed: {:?}", e);
                                break 'fc;
                            },
                        };

                    // Send the packets on the wire.
                    if !self.fc.must_wait {
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
                                        debug!("Flexicast send() would block");
                                        break 'fc;
                                    }

                                    panic!("Flexicast send() failed: {:?}", e);
                                },
                            }
                            off += pkt_len;
                            left -= pkt_len;
                        }
                        debug!(
                            "Flexicast written {:?} bytes to {:?}",
                            written, self.fc.fc_chan.mc_send_addr
                        );
                    } else {
                        debug!("Not actually sending data on the wire because we wait...");
                    }

                    nb_sent_pkt += 1;
                }

                // Notify the controller of the sent packets.
                if nb_sent_pkt > 0 {
                    self.fc.sent_pkt_to_controller().await?;
                }

                // Potentially unlimit the congestion window.
                match self.fc.cca {
                    FcFlowCwnd::Unlimited => self
                        .fc
                        .fc_chan
                        .channel
                        .fc_set_flow_cwnd(usize::MAX - 1000),
                    FcFlowCwnd::Limited(v) =>
                        self.fc.fc_chan.channel.fc_set_flow_cwnd(v as usize),
                    _ => (),
                }
            }
        }
    }
}

impl FcFlowVideo {
    fn handle_new_app_msg(
        &mut self, msg: VideoSourceMsg,
    ) -> asynchronous::Result<()> {
        match msg {
            VideoSourceMsg::Data((stream_id, data, fin)) => {
                self.fc.pending_data = Some((data.to_vec(), fin, stream_id));
            },
        }

        Ok(())
    }
}

async fn conditional_wait_on_app(
    rx_app: &mut mpsc::Receiver<VideoSourceMsg>, v: bool,
) -> Option<VideoSourceMsg> {
    // TODO: how do we do a timeout?
    if v {
        rx_app.recv().await
    } else {
        None
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
