use clap::Parser;
use quiche::flexicast::McConfig;
use quiche_apps::fc_app::file_transfer::receiver::FileTransferRecv;
use quiche_apps::fc_app::file_transfer::FileTransferKind;
use quiche_apps::fc_app::h3::receiver::Http3Receiver;
use quiche_apps::fc_app::video::hls::HlsSink;
use quiche_apps::fc_app::video::rtp::RtpSink;
use quiche_apps::fc_app::video::StreamTransferKind;
use quiche_apps::fc_app::TransferKind;
use std::net::Ipv4Addr;
use std::path::Path;
use tokio_fcquiche::io::receiver::TokioFcQuicRecv;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Parser)]
struct Args {
    /// Activate flexicast extension.
    #[clap(long)]
    flexicast: bool,

    /// URL of the server to contact.
    url: url::Url,

    /// Unicast source port.
    #[clap(short = 'p', long = "port", default_value = "9999")]
    source_port: u16,

    /// Multicast local IP.
    #[clap(short = 'l', long = "local", default_value = "0.0.0.0", value_parser)]
    local_ip: Ipv4Addr,

    /// Multicast packets are proxied using packet replication for this client.
    /// This argument is a trick to avoid out-of-band computation by the source
    /// of the proxies to the clients. If this value is true, instead of
    /// binding to the flexicast address given in the MC_ANNOUNCE frame, the
    /// client will listen to its own address and the port advertised by the
    /// source.
    #[clap(long = "proxy")]
    proxy_uc: bool,

    /// Sets the initial flow control limits on the receiver.
    /// If this parameter is not set, the receiver uses unlimited flow control.
    #[clap(long = "flow-control")]
    initial_flow_control: Option<u64>,

    /// Receiving-side transfer kind.
    #[clap(long = "transfer-kind", default_value = "file,file,.")]
    transfer_kind: TransferKind,

    /// Whether the receiver does not expect the connection to close after
    /// receiving a finished stream. E.g., used for application with updated
    /// content.
    #[clap(long = "stay-open")]
    stay_open_on_fin: bool,

    /// Whether the client sends transport feedback data to the server.
    #[clap(long = "transport-feedback")]
    transport_feedback: bool,

    /// JSON output of received packets.
    #[clap(long = "json-output")]
    json_output: Option<String>,

    /// Socket stop path.
    #[clap(long = "file-stop", default_value = "/tmp/fcquic_stop")]
    stop_file_path: String,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();
    let args = Args::parse();

    let h3_config = if matches!(args.transfer_kind, TransferKind::HTTP3(_)) {
        Some(quiche::h3::Config::new().unwrap())
    } else {
        None
    };

    let (tx_app, rx_app) = tokio::sync::mpsc::channel(1000);

    // Create the Flexicast Quiche tokio receiver.
    let peer_addr = *args.url.socket_addrs(|| None).unwrap().first().unwrap();
    let config = get_config(&args);
    let (mut tfc_recv, rx_app) = TokioFcQuicRecv::new(
        peer_addr,
        config,
        args.local_ip,
        args.flexicast,
        args.proxy_uc,
        rx_app,
        h3_config,
    );

    // Create the receiver application.
    match args.transfer_kind {
        TransferKind::File(file_transfer_kind) => {
            match file_transfer_kind {
                FileTransferKind::File(output_prefix) => {
                    // Create the application handler at the client.
                    let out_filename = Path::new(
                        args.url.path_segments().unwrap().last().unwrap(),
                    );
                    let output_prefix = Path::new(&output_prefix);

                    let tmp_filename = if args.stay_open_on_fin {
                        // Path::new("tmp_filename.txt").into()
                        Path::new("/shared/tmp_filename.txt").into()
                    } else {
                        Path::new(".").join(out_filename)
                    };
                    let mut fc_app = FileTransferRecv::new(
                        &output_prefix.join(out_filename),
                        rx_app,
                        tx_app,
                        &tmp_filename,
                    )
                    .unwrap();

                    tokio::spawn(async move {
                        fc_app.run().await.unwrap();
                    });
                },

                _ => panic!(
                    "Receiver cannot have another file transfer kind than a file"
                ),
            }
        },

        TransferKind::Stream(stream_transfer_kind) =>
            match stream_transfer_kind {
                StreamTransferKind::Hls(output_dir) => {
                    let mut fc_app = HlsSink::new(&output_dir, rx_app);
                    tokio::spawn(async move {
                        fc_app.run().await.unwrap();
                    });
                },

                StreamTransferKind::Rtp(sockaddr) => {
                    let mut fc_app =
                        RtpSink::new(rx_app, sockaddr).await.unwrap();
                    tokio::spawn(async move {
                        fc_app.run().await.unwrap();
                    });
                },
            },

        TransferKind::HTTP3(path_to_store) => {
            let mut fc_app = Http3Receiver::new(
                rx_app,
                tx_app,
                args.url,
                &path_to_store.split(",").next().unwrap(),
            );

            tokio::spawn(async move {
                fc_app.run().await.unwrap();
            });
        },
    };

    // Start the Flexicast QUIC receiver.
    tfc_recv.run().await.unwrap();
}

fn get_config(args: &Args) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false); // Not prodction-ready.

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    if !args.flexicast {
        config.set_max_idle_timeout(100_000);
    }
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);

    let initial_max_data = match args.initial_flow_control {
        Some(v) => v,
        None => 100_000_000_000,
    };
    config.set_initial_max_data(initial_max_data);
    config.set_initial_max_stream_data_bidi_local(initial_max_data);
    config.set_initial_max_stream_data_bidi_remote(initial_max_data);
    config.set_initial_max_stream_data_uni(initial_max_data);
    config.set_initial_max_streams_bidi(initial_max_data);
    config.set_initial_max_streams_uni(initial_max_data);
    config.set_active_connection_id_limit(10);
    config.verify_peer(false);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::CUBIC);

    if args.flexicast {
        config.set_initial_max_path_id(10);
        config.set_enable_flexicast(args.flexicast);
        config.set_recv_fec(true);
    }

    config
}
