use quiche::flexicast::FcConfig;
use quiche::flexicast::McConfig;
use std::path::Path;
use std::time;
use tokio::sync::mpsc;
use tokio_fcquiche::io::receiver::TokioFcQuicRecv;
use tokio_fcquiche::io::TokioFcQuic;
use tokio_fcquiche::io::TokioFcQuicConfig;
use tokio_fcquiche::FcQuicMsg;
use tokio_fcquiche::MAX_DATAGRAM_SIZE;

pub async fn fcquiche_server(keylog_path: &str) -> TokioFcQuic {
    let config = get_fcquiche_server_config(keylog_path);

    let mut fcquic = TokioFcQuic::new(config);

    let flow_config = FcConfig {
        fc_tp: true,
        probe_mc_path: false,
        max_data: 1_000_000,
        max_stream_data: 1_000_000,
        fc_timer: 0,
        fec: false,
        src_addr: "127.0.0.1:12346".parse().unwrap(),
        mc_addr: "239.239.239.35:12346".parse().unwrap(),
        crt_path: "tests".to_string(),
        fc_cca: quiche::flexicast::cca::FcFlowCwnd::CCA(
            quiche::CongestionControlAlgorithm::CUBIC,
        ),
        ..Default::default()
    };

    fcquic.add_fc_flow(flow_config, keylog_path).await.unwrap();

    fcquic
}

pub async fn fcquiche_client() -> (TokioFcQuicRecv, mpsc::Receiver<FcQuicMsg>) {
    let config = get_config(true);
    let peer_addr = "127.0.0.1:12345".parse().unwrap();
    let local_ip = "127.0.0.1".parse().unwrap();
    TokioFcQuicRecv::new(peer_addr, config, local_ip, true, false)
}

pub fn get_fcquiche_server_config(keylog_path: &str) -> TokioFcQuicConfig {
    TokioFcQuicConfig {
        unicast: true,
        unicast_unlimited_cwnd: false,
        sendmmsg: Some(1),
        wait: Some(1),
        flexicast: true,
        fc_keylog_file: keylog_path.to_string(),
        fallback_delay: Some(time::Duration::from_millis(300)),
        uc_src_addr: "127.0.0.1:12345".parse().unwrap(),
        nb_leaf_controllers: 1,
    }
}

pub fn get_config(flexicast: bool) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false); // Not prodction-ready.

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    if flexicast {
        config.set_max_idle_timeout(100_000);
    }
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);

    let initial_max_data = 1_000_000;
    config.set_initial_max_data(initial_max_data);
    config.set_initial_max_stream_data_bidi_local(initial_max_data);
    config.set_initial_max_stream_data_bidi_remote(initial_max_data);
    config.set_initial_max_stream_data_uni(initial_max_data);
    config.set_initial_max_streams_bidi(initial_max_data);
    config.set_initial_max_streams_uni(initial_max_data);
    config.set_active_connection_id_limit(10);
    config.verify_peer(false);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::CUBIC);

    config.set_initial_max_path_id(10);
    config.set_enable_flexicast(flexicast);

    config
}

pub fn get_uc_path_config(flexicast: bool) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file(
            Path::new("tests")
                .join("cert.crt")
                .to_str()
                .unwrap(),
        )
        .unwrap();
    config
        .load_priv_key_from_pem_file(
            Path::new("tests")
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

    let initial_max_data = 1_000_000;
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
    config.set_enable_flexicast(flexicast);
    config.set_initial_max_path_id(10);

    config
}