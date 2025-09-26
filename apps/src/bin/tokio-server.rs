use std::error::Error;

use foundations::telemetry::log;
use futures::SinkExt as _;
use futures::StreamExt as _;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::quiche::h3;
use tokio_quiche::ConnectionParams;
use tokio_quiche::ServerH3Controller;
use tokio_quiche::ServerH3Driver;

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main(){
    let socket = tokio::net::UdpSocket::bind("192.168.1.165:4789").await.unwrap();
    let mut listeners = listen(
        [socket],
        ConnectionParams::new_server(
            Default::default(),
            tokio_quiche::settings::TlsCertificatePaths {
                cert: "/home/louisna/multicast-quic/apps/src/bin/cert.crt",
                private_key: "/home/louisna/multicast-quic/apps/src/bin/cert.key",
                kind: tokio_quiche::settings::CertificateKind::X509,
            },
            Default::default(),
        ),
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    ).unwrap();
    let accept_stream = &mut listeners[0];

    while let Some(conn) = accept_stream.next().await {
        let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
        conn.unwrap().start(driver);
        tokio::spawn(handle_connection(controller));
    }
}

async fn handle_connection(mut controller: ServerH3Controller) {
    while let Some(ServerH3Event::Core(event)) =
        controller.event_receiver_mut().recv().await
    {
        match event {
            H3Event::IncomingHeaders(IncomingH3Headers {
                mut send,
                headers,
                ..
            }) => {
                send.send(OutboundFrame::Headers(vec![h3::Header::new(
                    b":status", b"200",
                )]))
                .await
                .unwrap();

                send.send(OutboundFrame::body(
                    BufFactory::buf_from_slice(b"hello from TQ!"),
                    true,
                ))
                .await
                .unwrap();
            },
            event => {
                log::info!("event: {event:?}");
            },
        }
    }
}
