use std::{io, net::SocketAddr};
use clap::Parser;
use mio::net::UdpSocket;

#[derive(Parser)]
struct Args {
    /// Address to listen to incoming data.
    in_addr: SocketAddr,

    /// Address to forward packets to.
    out_addr: SocketAddr,

    /// Message to indicate the end of the stream.
    #[clap(long = "stop", value_parser, default_value = "STOP RTP")]
    stop_msg: String,
}

fn main() {
    let args = Args::parse();

    let stop_msg = args.stop_msg.as_bytes().to_vec();

    let mut in_sock = UdpSocket::bind(args.in_addr).unwrap();
    let out_sock = UdpSocket::bind("0.0.0.0:4433".parse().unwrap()).unwrap();

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    poll.registry()
        .register(&mut in_sock, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let mut buf = [0u8; 1500];

    loop {
        poll.poll(&mut events, None).unwrap();

        let (len, _from) = match in_sock.recv_from(&mut buf) {
            Ok(v) => v,

            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }

                panic!("Error: {:?}", e);
            },
        };

        let _ = out_sock.send_to(&buf[..len], args.out_addr);

        // Stop if received the specific message.
        if len - 1 == stop_msg.len() && &buf[..len - 1] == &stop_msg {
            break;
        }
    }
}