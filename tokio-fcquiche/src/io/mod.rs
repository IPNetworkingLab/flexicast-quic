//! Flexicast QUIC module.
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use crate::fcquic::controller::ControllerLeaf;
use crate::fcquic::controller::ControllerRole;
use crate::fcquic::controller::ControllerRoot;
use crate::fcquic::messages::MsgFcCtl;
use crate::fcquic::fc::FcChannelAsync;
use crate::fcquic::fc::FcFlowRun;
use crate::fcquic::scheduler::FcFallBackDelay;
use crate::fcquic::sendmmsg::SendMMsg;
use crate::io::fc_flow::FcFlowfileTransfer;
use crate::Result;
use quiche::flexicast;
use quiche::flexicast::FcConfig;
use quiche::flexicast::FlexicastChannelSource;
use quiche::flexicast::FlexicastConnection;
use quiche::flexicast::McAnnounceData;
use quiche::Config;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::time;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::fcquic::fc::FcChannelInfo;
use crate::io::handshake::get_mc_config;
use crate::io::handshake::Handshake;
use crate::FcQuicMsg;
use crate::CHANNEL_BUFFER_SIZE;

#[cfg(feature = "qlog")]
use crate::make_qlog_writer;
#[cfg(feature = "tokio-tracing")]
use std::fs::OpenOptions;
#[cfg(feature = "tokio-tracing")]
use std::io::Write;
#[cfg(feature = "tokio-tracing")]
use tokio_metrics::TaskMonitor;

pub struct TokioFcQuicConfig {
    /// Whether to do unicast delivery.
    pub unicast: bool,

    /// Whether unicast uses unlimited congestion window.
    pub unicast_unlimited_cwnd: bool,

    /// (Possible) number of sendmmsg instances.
    pub sendmmsg: Option<u64>,

    /// Whether the flexicast flow waits and the number of receivers to wait.
    pub wait: Option<u64>,

    /// Whether to enable Flexicast delivery.
    pub flexicast: bool,

    /// Path to the flexicast flow keylog file.
    pub fc_keylog_file: String,

    /// The fallback delay of the unicast path.
    pub fallback_delay: Option<FcFallBackDelay>,

    /// Source address of the (unicast path) server.
    pub uc_src_addr: SocketAddr,

    /// Numbere of leaf controllers to use.
    pub nb_leaf_controllers: u64,

    /// Potential HTTP/3 config.
    pub h3_config: Option<quiche::h3::Config>,

    /// Maximum expected acknowledgment rate, in bps.
    pub max_ack_rate: u64,

    /// Minimum bandwidth gain ratio to trigger unicast fallback for the
    /// slowest receiver (leaf controller bottleneck check).
    /// `None` disables the auto-ejection entirely.
    pub fallback_gain_ratio: Option<f64>,

    /// Minimum delivery-rate samples before a receiver is eligible for
    /// auto fallback. `None` uses the compiled-in default.
    pub fallback_min_samples: Option<u64>,

    /// Delay between reintegration eligibility checks.
    /// `None` disables reintegration entirely.
    pub reintegration_delay: Option<time::Duration>,
}

pub struct TokioFcQuic {
    /// Transmission channel for the application to send content to
    /// [`TokioFcQuic`].
    tx: Vec<mpsc::Sender<FcQuicMsg>>,

    /// Transmission channel for [`TokioFcQuic`] to receive content from the
    /// application.
    rx: Vec<mpsc::Receiver<FcQuicMsg>>,

    /// Transmission channel for [`TokioFcQuic`] to send content to the
    /// application.
    tx_app: mpsc::Sender<FcQuicMsg>,

    /// Tokio Flexicast QUIC configuration.
    config: TokioFcQuicConfig,

    /// Random number generator.
    rng: SystemRandom,

    /// All flexicast flows information.
    fc_flows: Vec<FcChannelInfo>,

    /// All the flexicast flows configs.
    fc_flow_configs: Vec<FcConfig>,
}

impl TokioFcQuic {
    /// Creates a new instance with configurations.
    pub fn new(
        config: TokioFcQuicConfig, tx_app: mpsc::Sender<FcQuicMsg>,
    ) -> Self {
        Self {
            tx: Vec::new(),
            rx: Vec::new(),
            tx_app,
            config,
            rng: SystemRandom::new(),
            fc_flows: Vec::new(),
            fc_flow_configs: Vec::new(),
        }
    }

    /// Adds a new flexicast flow with a given [`FcConfig`].
    pub async fn add_fc_flow(
        &mut self, fc_config: FcConfig, path_keylog: &str,
    ) -> Result<()> {
        let new_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            None,
        )?;
        new_socket.set_reuse_address(true)?;
        new_socket.set_nonblocking(true)?;
        new_socket.bind(&fc_config.src_addr.into())?;
        let socket = UdpSocket::from_std(new_socket.into())?;
        socket.set_multicast_ttl_v4(64)?;

        let mut server_config = get_mc_config(true, &fc_config);
        let mut client_config = get_mc_config(true, &fc_config);

        // Generate a random source connection ID for the connection.
        let mut channel_id = [0; 16];
        self.rng.fill(&mut channel_id[..]).unwrap();

        let channel_id = quiche::ConnectionId::from_ref(&channel_id);
        let channel_id_vec = channel_id.as_ref().to_vec();

        let mc_path_info = flexicast::McPathInfo {
            local: fc_config.src_addr,
            peer: fc_config.src_addr,
            cid: channel_id,
        };

        let mut fc_chan = FlexicastChannelSource::new_with_tls(
            mc_path_info,
            &mut server_config,
            &mut client_config,
            fc_config.mc_addr,
            path_keylog,
            &fc_config,
        )
        .unwrap();

        let mc_addr_bytes = match fc_config.mc_addr {
            std::net::SocketAddr::V4(ip) => ip.ip().octets(),
            _ => unreachable!("Only support IPv4 flexicast addresses"),
        };

        let src_addr_bytes = match fc_config.src_addr {
            std::net::SocketAddr::V4(ip) => ip.ip().octets(),
            _ => unreachable!("Only support IPv4 flexicast addresses"),
        };

        let mc_announce_data = McAnnounceData {
            channel_id: channel_id_vec,
            is_ipv6_addr: false,
            probe_path: fc_config.probe_mc_path,
            source_ip: src_addr_bytes,
            group_ip: mc_addr_bytes,
            udp_port: fc_config.mc_addr.port(),
            fc_ack_delay: fc_config.fc_ack_delay.into(),
            is_processed: false,
            fc_channel_algo: None,
            fc_channel_secret: None,
        };

        fc_chan
            .channel
            .fc_set_announce_data(&mc_announce_data)
            .unwrap();

        // Set the ack delay strategy.
        fc_chan.channel.fc_update_ack_delay_strategy(
            fc_config.fc_ack_delay,
            fc_config.ack_delay_latency,
        );

        let fc_chan_info = FcChannelInfo {
            socket,
            fc_chan,
            mc_announce_data,
        };

        // Create the transmission channel with the application.
        let (tx_app, rx_app) = mpsc::channel(10);
        self.tx.push(tx_app);
        self.rx.push(rx_app);

        self.fc_flows.push(fc_chan_info);
        self.fc_flow_configs.push(fc_config);

        Ok(())
    }

    /// Returns the transmission channel towards the specified flexicast flow.
    pub fn get_tx_fc_flow(
        &self, index: usize,
    ) -> Option<mpsc::Sender<FcQuicMsg>> {
        self.tx.get(index).cloned()
    }

    /// Asynchronously runs Flexicast QUIC using tokio, creating tasks for new
    /// receivers, the flexicast flow, the controller(s).
    pub async fn run(&mut self, uc_path_config: Config) -> Result<()> {
        // This will create a monitor for the *whole* application.
        #[cfg(feature = "tokio-tracing")]
        console_subscriber::init();
        #[cfg(feature = "tokio-tracing")]
        let start = time::Instant::now();
        #[cfg(feature = "tokio-tracing")]
        let frequency = std::time::Duration::from_millis(200);
        #[cfg(feature = "tokio-tracing")]
        {
            let handle: tokio::runtime::Handle =
                tokio::runtime::Handle::current();
            let runtime_monitor = tokio_metrics::RuntimeMonitor::new(&handle);
            tokio::spawn(async move {
                for metrics in runtime_monitor.intervals() {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open("tokio_total.log")
                        .unwrap();

                    writeln!(
                        file,
                        "{:?} {:?}",
                        time::Instant::now().duration_since(start).as_millis(),
                        metrics
                    )
                    .unwrap();
                    tokio::time::sleep(frequency).await;
                }
            });
        }

        // Create the atomic update.
        let largest_pn_atomic = Arc::new(AtomicU64::new(u64::MAX));

        // Collect all flexicast flows information.
        let fc_announce_data = if self.config.flexicast {
            self.fc_flows
                .iter()
                .map(|fc| fc.mc_announce_data.clone())
                .collect()
        } else {
            Vec::new()
        };

        // Also get the decryption keys and algos, indexed in the same order as
        // the McAnnounceData.
        let fc_master_secret: Vec<Vec<u8>> = self
            .fc_flows
            .iter()
            .map(|fc| fc.fc_chan.master_secret.clone())
            .collect();
        let fc_key_algo: Vec<u8> = self
            .fc_flows
            .iter()
            .map(|fc| fc.fc_chan.algo.try_into().unwrap())
            .collect();

        // Create the sendmmsg instances.
        let sendmmsg_txs = if let (true, Some(nb_instances)) =
            (self.config.flexicast, self.config.sendmmsg)
        {
            // Not using functionnal programming but it will be clearer.
            let mut txs = Vec::new();

            for i in 0..nb_instances {
                let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
                txs.push(tx);

                // Directly run the instance.
                let mut src_addr = self.config.uc_src_addr;
                src_addr.set_port(4534 + i as u16);
                let new_socket =
                    tokio::net::UdpSocket::bind(src_addr).await.unwrap();
                let mut sendmmsg =
                    SendMMsg::new(rx, std::sync::Arc::new(new_socket));
                tokio::spawn(async move {
                    sendmmsg.run().await.unwrap();
                });
            }

            Some(txs)
        } else {
            None
        };

        // Create the handshake task.
        let mut task_hs = Handshake::new(
            &self.config,
            uc_path_config,
            fc_master_secret,
            fc_key_algo,
            &fc_announce_data,
            self.rng.clone(),
            sendmmsg_txs.clone(),
            self.config.h3_config.clone(),
            self.tx_app.clone(),
            largest_pn_atomic.clone(),
        )
        .await?;

        let tx_main = task_hs.get_tx();

        // All communication channels.
        let mut tx_fc_flows = Vec::new();
        let (tx_ctl_root, rx_ctl_root) = mpsc::channel(CHANNEL_BUFFER_SIZE);

        // Create the flexicast flows.
        let mut id_fc_chan = 0;
        for (fc_chan_info, rx_app) in
            self.fc_flows.drain(..).zip(self.rx.drain(..))
        {
            // Transmission channel between the controllers and the flexicast
            // flow.
            let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);

            let mut fc_struct = FcChannelAsync {
                fc_chan: fc_chan_info.fc_chan,
                mc_announce_data: fc_chan_info.mc_announce_data,
                socket: fc_chan_info.socket,
                fc_flow_stop_timer: std::time::Duration::from_secs(3),
                sync_tx: tx_ctl_root.clone(),
                id: id_fc_chan,
                rx_ctl: rx,
                must_wait: self.config.wait.is_some(),
                cca: self.fc_flow_configs[id_fc_chan as usize].fc_cca.clone(),
                allow_unicast: self.config.unicast,
                do_flexicast: self.config.flexicast,
                sendmmsg_txs: sendmmsg_txs.clone(),
                pending_data: None,
                pending_data_sent_uc: false,
                pending_sent_pkt: Vec::new(),
                pending_stream_pieces: Vec::new(),
                nb_active_receivers: 0,
                max_ack_rate: self.config.max_ack_rate,
                largest_pn_atomic: largest_pn_atomic.clone(),
            };

            id_fc_chan += 1;

            tx_fc_flows.push(tx);

            // Initialize QLOG for the flexicast flow.
            #[cfg(feature = "qlog")]
            {
                if let Some(dir) = std::env::var_os("QLOGDIR") {
                    let id = format!("fc-flow-{:?}", id_fc_chan);
                    let writer = make_qlog_writer(&dir, "server", &id);

                    fc_struct.fc_chan.channel.set_qlog(
                        std::boxed::Box::new(writer),
                        "quiche-server qlog".to_string(),
                        format!("{} id={}", "quiche-server qlog", id),
                    );
                }
            }

            let mut fc_flow = FcFlowfileTransfer {
                fc: fc_struct,
                rx: rx_app,
            };

            // Start Flexicast flow task.
            #[cfg(feature = "tokio-tracing")]
            let monitor_flow = TaskMonitor::new();
            #[cfg(feature = "tokio-tracing")]
            {
                let monitor_flow = monitor_flow.clone();
                tokio::spawn(async move {
                    monitor_flow.instrument(fc_flow.run()).await.unwrap();
                });
            }
            #[cfg(not(feature = "tokio-tracing"))]
            tokio::spawn(async move {
                fc_flow.run().await.unwrap();
            });
        }

        // Create the controllers.
        // Create the controller structures that will manage the communication
        // between the flexicast source and the unicast server instances.
        // We create two levels of controllers to improve scalability: leaves and
        // root.
        let mut ctl_root_struct = ControllerRoot::new();
        tx_fc_flows
            .iter()
            .for_each(|tx| ctl_root_struct.add_flow_tx(tx.clone()));
        let mut controller = crate::fcquic::controller::FcController::new(
            rx_ctl_root,
            fc_announce_data.clone(),
            ControllerRole::Root(ctl_root_struct),
            tx_main.clone(),
            self.config.wait,
            Some(time::Duration::from_secs(0)),
            self.config.fallback_gain_ratio,
            self.config.fallback_min_samples,
            self.config.reintegration_delay,
        );

        let mut ctl_leaves_struct = (0..self.config.nb_leaf_controllers)
            .map(|id| ControllerLeaf::new(id, tx_ctl_root.clone()))
            .collect::<Vec<_>>();

        // Keep the leaf controller txs.
        for (_i, ctl_leaf_struct) in ctl_leaves_struct.drain(..).enumerate() {
            let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
            controller.add_new_leaf_ctl(ctl_leaf_struct.leaf_id(), tx.clone());
            task_hs.add_leaf_ctl(tx);

            let mut ctl_leaf = crate::fcquic::controller::FcController::new(
                rx,
                fc_announce_data.clone(),
                ControllerRole::Leaf(ctl_leaf_struct),
                tx_main.clone(),
                self.config
                    .wait
                    .map(|n| n / self.config.nb_leaf_controllers),
                Some(time::Duration::from_secs(0)),
                self.config.fallback_gain_ratio,
                self.config.fallback_min_samples,
                self.config.reintegration_delay,
            );

            #[cfg(feature = "tokio-tracing")]
            {
                let monitor_controller_leaf = TaskMonitor::new();
                let monitor_controller_leaf_clone =
                    monitor_controller_leaf.clone();
                tokio::spawn(async move {
                    for metrics in monitor_controller_leaf_clone.intervals() {
                        let mut file = OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(format!("tokio_controller_leaf_{_i}.log"))
                            .unwrap();

                        writeln!(
                            file,
                            "{:?} {:?}",
                            time::Instant::now()
                                .duration_since(start)
                                .as_millis(),
                            metrics
                        )
                        .unwrap();
                        tokio::time::sleep(frequency).await;
                    }
                });
                tokio::spawn(async move {
                    monitor_controller_leaf
                        .instrument(ctl_leaf.run())
                        .await
                        .unwrap();
                });
            }

            #[cfg(not(feature = "tokio-tracing"))]
            {
                tokio::spawn(async move {
                    ctl_leaf.run().await.unwrap();
                });
            }
        }

        // Create controller monitor.
        #[cfg(feature = "tokio-tracing")]
        {
            let monitor_controller = TaskMonitor::new();
            let monitor_controller_clone = monitor_controller.clone();
            tokio::spawn(async move {
                for metrics in monitor_controller_clone.intervals() {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open("tokio_controller.log")
                        .unwrap();

                    writeln!(
                        file,
                        "{:?} {:?}",
                        time::Instant::now().duration_since(start).as_millis(),
                        metrics
                    )
                    .unwrap();
                    tokio::time::sleep(frequency).await;
                }
            });
            tokio::spawn(async move {
                monitor_controller
                    .instrument(controller.run())
                    .await
                    .unwrap();
            });
        }

        #[cfg(not(feature = "tokio-tracing"))]
        {
            tokio::spawn(async move {
                controller.run().await.unwrap();
            });
        }

        // Start the handshake task.
        task_hs.run().await.unwrap();

        Ok(())
    }
}

mod fc_flow;
mod handshake;
pub mod receiver;
mod uc_path;
