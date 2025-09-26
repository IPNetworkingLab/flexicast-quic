use foundations::telemetry::log;
use tokio_quiche::http3::driver::ClientH3Event;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::InboundFrame;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::quiche::h3;

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    socket.connect("192.168.1.165:4789").await.unwrap();
    let (_, mut controller) = tokio_quiche::quic::connect(socket, None).await.unwrap();

    controller
        .request_sender()
        .send(tokio_quiche::http3::driver::NewClientRequest {
            request_id: 0,
            headers: vec![h3::Header::new(b":method", b"GET")],
            body_writer: None,
        })
        .unwrap();

    while let Some(event) = controller.event_receiver_mut().recv().await {
        match event {
            ClientH3Event::Core(H3Event::IncomingHeaders(
                IncomingH3Headers {
                    stream_id,
                    headers,
                    mut recv,
                    ..
                },
            )) => {
                'body: while let Some(frame) = recv.recv().await {
                    match frame {
                        InboundFrame::Body(pooled, fin) => {
                            if fin {
                                break 'body;
                            }
                        },
                        InboundFrame::Datagram(pooled) => {
                        },
                    }
                }
            },
            ClientH3Event::Core(H3Event::BodyBytesReceived {
                fin: true, ..
            }) => {
                log::info!("fin received");
                break;
            },
            ClientH3Event::Core(event) => log::info!("received event: {event:?}"),
            ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id,
            } => (),
        }
    }
}
