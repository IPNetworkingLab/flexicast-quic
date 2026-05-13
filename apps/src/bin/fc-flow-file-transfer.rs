use std::net;
use std::path::Path;
use std::u64;

use quiche::fec::schedulers::FecSchedulerAlgorithm;
use quiche::flexicast::cca::FcFlowCwnd;
use quiche::flexicast::nack::FcAckDelayStrategy;
use quiche::flexicast::FcConfig;
use quiche::flexicast::McConfig;
use quiche_apps::fc_app::TransferKind;

use clap::Parser;
use quiche_apps::fc_app::file_transfer::sender::FileTransferSrc;
use quiche_apps::fc_app::h3::sender::Http3Source;
use quiche_apps::fc_app::video::hls::HlsSource;
use quiche_apps::fc_app::video::rtp::RtpSource;
use quiche_apps::fc_app::video::StreamTransferKind;
use tokio_fcquiche::io::TokioFcQuicConfig;
use tokio_fcquiche::FcFallBackDelay;

#[derive(Parser)]
struct Args {
    /// Activate flexicast extension.
    #[clap(long)]
    flexicast: bool,

    /// Keylog file for flexicast channel.
    #[clap(long = "keylog", value_parser, default_value = "/tmp/fc-server.txt")]
    fc_keylog_file: String,

    /// Source address of the server.
    #[clap(long = "src", default_value = "127.0.0.1:4433")]
    src_addr: net::SocketAddr,

    /// Certificate path.
    #[clap(long = "cert-path", value_parser, default_value = "./src/bin")]
    cert_path: String,

    /// Multicast address.
    #[clap(
        long = "mc-addr",
        value_parser,
        default_value = "239.239.239.35:4434"
    )]
    mc_addr: net::SocketAddr,

    /// Multicast source address.
    /// Must be different from the source address.
    #[clap(long = "mc-src-addr", value_parser, default_value = "127.0.0.1:4567")]
    mc_src_addr: net::SocketAddr,

    /// Flexicast flow timer.
    #[clap(long = "fc-timer", value_parser, default_value = "0")]
    fc_ack_delay: FcAckDelayStrategy,

    /// Specify the congestion window for the flexicast flow.
    /// The possible values are:
    /// - A string value representing a congestion control algorithm;
    /// - An integer value representing the fixed congestion window;
    /// - The 'disabled' string, representing an unlimited congestion window.
    #[clap(long = "fc-cwnd", default_value = "cubic")]
    fc_cwnd: FcFlowCwnd,

    /// RTP message to indicate the end of the stream.
    #[clap(long = "rtp-stop", value_parser, default_value = "STOP RTP")]
    rtp_stop: String,

    /// Number of clients to listen before actually sending data to the wire.
    #[clap(long = "wait", value_parser)]
    wait: Option<u64>,

    /// Whether the application allows unicast delivery instead of flexicast.
    #[clap(long = "unicast")]
    allow_unicast: bool,

    /// Whether the unicast path has unlimited congestion window.
    #[clap(long = "unicast-unlimited-cwnd")]
    uc_unlimited_cwnd: bool,

    /// Whether the flexicast flow must be created using path probing.
    #[clap(long = "probe-path")]
    probe_path: bool,

    /// Unicast fall-back delay for the scheduler.
    /// Either a static value in ms (e.g. 500) or 'adaptive'.
    #[clap(long = "fall-back-delay", value_parser)]
    fall_back_delay: Option<FcFallBackDelay>,

    /// Whether to use `sendmmsg` instead of relying on real flexicast
    /// to distribute data on the flexicast flow.
    /// The value is the number of instances of sendmmsg to use.
    /// For now, creates 'sendmmsg' instances for each flexicast flow.
    #[clap(long = "sendmmsg", value_parser)]
    sendmmsg: Option<u64>,

    /// Application kind.
    /// Can be a file transfer (bytes, file, unix datagram) or a video stream
    /// (hls, rtp). The second value is specific on the application being
    /// used.
    #[clap(long = "transfer-kind", default_value = "file,bytes,1000")]
    transfer_kind: TransferKind,

    /// Sets the delay (in ms) before sending aggregated acknowledgments to the
    /// flexicast flow for the controller. Used to avoid saturating with
    /// messages the flexicast flow source.
    #[clap(long = "ctl-ack-delay")]
    ctl_ack_delay: Option<u64>,

    /// Sets the initial flow control for the flexicast flow.
    #[clap(long = "initial-fc-flow")]
    initial_fc_flow: Option<u64>,

    /// Path to the directory where we store per-receiver transport metrics
    /// feedback. Does not store per-receiver transport feedback if the
    /// value is not set.
    #[clap(long = "transport-feedback")]
    transport_feedback_dir: Option<String>,

    /// Whether to use FEC for flexicast.
    /// If set, defines the FEC scheduler to use.
    #[clap(long = "fec-scheduler")]
    fec_scheduler: Option<FecSchedulerAlgorithm>,

    /// Number of leaf controllers to use.
    #[clap(long = "nb-controllers", default_value = "1")]
    nb_controllers: u64,

    /// Minimum bandwidth gain ratio to trigger unicast fallback for the
    /// slowest receiver. The slowest receiver is ejected when removing it
    /// would multiply the group's bottleneck rate by at least this factor.
    /// If not set, the controller never auto-ejects slow receivers.
    #[clap(long = "fallback-gain-ratio")]
    fallback_gain_ratio: Option<f64>,

    /// Maximum expected acknowledgment rate, in bps.
    #[clap(long = "max-ack-rate", default_value = "100000000")]
    max_ack_rate: u64,

    /// Time between two ack delay updates.
    #[clap(long = "ack-delay-frame", default_value = "100")]
    ack_delay_latency: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();
    let args = Args::parse();

    let h3_config = if matches!(args.transfer_kind, TransferKind::HTTP3(_)) {
        Some(quiche::h3::Config::new().unwrap())
    } else {
        None
    };

    // Create Flexicast Quiche tokio config.
    let fc_quic_tokio_config = TokioFcQuicConfig {
        unicast: args.allow_unicast,
        unicast_unlimited_cwnd: args.uc_unlimited_cwnd,
        sendmmsg: args.sendmmsg,
        wait: args.wait,
        flexicast: args.flexicast,
        fc_keylog_file: args.fc_keylog_file.clone(),
        fallback_delay: args.fall_back_delay.clone(),
        uc_src_addr: args.src_addr,
        nb_leaf_controllers: args.nb_controllers,
        h3_config,
        max_ack_rate: args.max_ack_rate,
        fallback_gain_ratio: args.fallback_gain_ratio,
    };

    // Transmission channel towards the application, supposed to be unique because
    // the receivers may send messages without knowing to which flexicast flow it
    // belongs.
    let (tx_app, rx_app) = tokio::sync::mpsc::channel(100);

    let mut fcquiche =
        tokio_fcquiche::io::TokioFcQuic::new(fc_quic_tokio_config, tx_app);
    // Create a single flexicast flow.
    let flow_config = FcConfig {
        fc_tp: args.flexicast,
        probe_mc_path: false,
        max_data: args.initial_fc_flow.unwrap_or(1_000_000),
        max_stream_data: args.initial_fc_flow.unwrap_or(1_000_000),
        fc_ack_delay: args.fc_ack_delay,
        fec: args.fec_scheduler.is_some(),
        fec_scheduler: args
            .fec_scheduler
            .unwrap_or(FecSchedulerAlgorithm::NoRedundancy),
        src_addr: args.mc_src_addr,
        mc_addr: args.mc_addr,
        crt_path: args.cert_path.clone(),
        fc_cca: args.fc_cwnd,
        ack_delay_latency: std::time::Duration::from_millis(
            args.ack_delay_latency,
        ),
        ..Default::default()
    };

    fcquiche
        .add_fc_flow(flow_config, &args.fc_keylog_file)
        .await
        .unwrap();

    // Get the transmission channel to send application content.
    let tx_app = fcquiche.get_tx_fc_flow(0).unwrap();

    // Start Tokio Flexicast Quiche.
    let uc_config = get_config(&args);

    // Start the application.
    match &args.transfer_kind {
        TransferKind::File(file_transfer_kind) => {
            let mut file_transfer_src =
                FileTransferSrc::new(&file_transfer_kind, tx_app).unwrap();
            file_transfer_src.run().await.unwrap();
        },

        TransferKind::Stream(stream_transfer_kind) =>
            match stream_transfer_kind {
                StreamTransferKind::Hls(path) => {
                    let mut hls_src = HlsSource::new(&path, tx_app);
                    hls_src.run().await.unwrap();
                },

                StreamTransferKind::Rtp(addr) => {
                    let mut rtp_src =
                        RtpSource::new(*addr, tx_app, None).await.unwrap();
                    rtp_src.run().await.unwrap();
                },
            },

        TransferKind::HTTP3(path) => {
            let mut tab = path.split(",");
            let file_path = tab.next().unwrap().to_string();
            let manifest_path = tab.next().unwrap().to_string();
            let mut fc_app =
                Http3Source::new(rx_app, tx_app, &file_path, &manifest_path)
                    .unwrap();
            tokio::spawn(async move {
                fc_app.run().await.unwrap();
            });
        },
    }

    fcquiche.run(uc_config).await.unwrap();
}

fn get_config(args: &Args) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file(
            Path::new(&args.cert_path)
                .join("cert.crt")
                .to_str()
                .unwrap(),
        )
        .unwrap();
    config
        .load_priv_key_from_pem_file(
            Path::new(&args.cert_path)
                .join("cert.key")
                .to_str()
                .unwrap(),
        )
        .unwrap();

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    config.set_max_recv_udp_payload_size(tokio_fcquiche::MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(tokio_fcquiche::MAX_DATAGRAM_SIZE);

    let initial_max_data = match args.initial_fc_flow {
        Some(v) => v,
        None => 100_000_000_000,
    };
    config.set_initial_max_data(initial_max_data);
    config.set_initial_max_stream_data_bidi_local(initial_max_data);
    config.set_initial_max_stream_data_bidi_remote(initial_max_data);
    config.set_initial_max_stream_data_uni(initial_max_data);
    config.set_initial_max_streams_bidi(initial_max_data);
    config.set_initial_max_streams_uni(initial_max_data);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(5);
    config.enable_early_data();
    config.enable_pacing(false);
    config.set_send_fec(args.fec_scheduler.is_some());
    config.set_recv_fec(args.fec_scheduler.is_some());
    config.set_enable_flexicast(args.flexicast);
    config.set_initial_max_path_id(10);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::CUBIC);

    config
}
