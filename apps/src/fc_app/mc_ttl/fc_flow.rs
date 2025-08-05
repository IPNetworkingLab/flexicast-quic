use super::FcTtlMsg;
use crate::fc_app::asynchronous;
use crate::fc_app::asynchronous::fc::FcChannelAsync;
use crate::fc_app::asynchronous::fc::FcFlowRun;
use std::time;
use std::usize;
use tokio::sync::mpsc;

/// Time to live application using Flexicast QUIC.
/// Regularly sends DATAGRAM frames with increasing TTL to see the reachability
/// of the receivers, and reports metrics such as loss ratio.
///
/// Runs indefinitely.
pub struct FcFlowTtl {
    pub fc_flow: FcChannelAsync,

    /// Duration between two TTL probes.
    pub ttl_duration: time::Duration,

    /// Maximum TTL value.
    pub max_ttl: u8,

    /// TX channel to the application aggregator.
    pub tx_app: mpsc::Sender<FcTtlMsg>,
}

impl FcFlowRun for FcFlowTtl {
    async fn run(&mut self) -> asynchronous::Result<()> {
        let mut buf = [0u8; 1500];

        let mut last_ttl = time::Instant::now();

        loop {
            let now = time::Instant::now();
            let timeout = self.fc_flow.fc_chan.channel.timeout();
            let ttl_timeout = (last_ttl + self.ttl_duration).duration_since(now);

            let mut did_ttl_timeout = false;

            tokio::select! {
                // Flexicast flow timeout.
                Some(_) = optional_timeout(timeout) => {
                    self.fc_flow.on_timeout().await?;
                },

                // Control channel.
                Some(msg) = self.fc_flow.rx_ctl.recv() => self.fc_flow.handle_ctl_msg(msg).await?,

                // Application TTL timeout.
                _ = tokio::time::sleep(ttl_timeout) => did_ttl_timeout = true,
            }

            // Check again if there is some timeout there.
            if let Some(time::Duration::ZERO) =
                self.fc_flow.fc_chan.channel.timeout()
            {
                self.fc_flow.on_timeout().await?;
            }

            // Send all TTL messages on the flexicast flow.
            if did_ttl_timeout {
                // Set of sent packets with the TTL value.
                let mut sent_ttl_pkt = Vec::new();

                for ttl_value in 0..=self.max_ttl {
                    // Send a new datagram with the value being the TTL value.
                    buf[0] = ttl_value;

                    // Send to the flexicast flow.
                    // An error should not happen, because we unlimit the
                    // congestion window, and the flow control values should
                    // also be OK.
                    self.fc_flow.fc_chan.channel.dgram_send(&buf[..1])?;

                    // Change the TTL value on the socket.
                    // This may decrease performance.
                    self.fc_flow.socket.set_multicast_ttl_v4(ttl_value as u32)?;

                    // Directly generate the QUIC packet and flush it to the
                    // wire.
                    let (write, _) =
                        self.fc_flow.fc_chan.mc_send(&mut buf[..])?;
                    self.fc_flow
                        .socket
                        .send_to(&buf[..write], self.fc_flow.fc_chan.mc_send_addr)
                        .await?;

                    // Get the packet number, and as we know that we did +1, we
                    // "hack" it.
                    let pn = self
                        .fc_flow
                        .fc_chan
                        .channel
                        .fc_get_next_pkt_num(1)?
                        .saturating_sub(1);
                    sent_ttl_pkt.push((pn, ttl_value));
                }

                if !sent_ttl_pkt.is_empty() {
                    // Notify the controller of the sent packets.
                    self.fc_flow.sent_pkt_to_controller().await?;

                    // Notify the application of the TTL packtets.
                    let msg = FcTtlMsg::SentPkt(sent_ttl_pkt);
                    self.tx_app.send(msg).await?;
                }

                last_ttl = time::Instant::now();
            }

            // Unlimit the congestion window.
            self.fc_flow
                .fc_chan
                .channel
                .fc_set_flow_cwnd(usize::MAX - 1000);
        }
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
