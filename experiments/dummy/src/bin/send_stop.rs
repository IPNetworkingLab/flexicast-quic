use std::net::SocketAddr;
use clap::Parser;
use mio::net::UdpSocket;


#[derive(Parser)]
struct Args {
    /// Address where to send packets.
    to_addr: SocketAddr,

    /// Stop message.
    stop_msg: String,
}

fn main() {
    let args = Args::parse();

    let mut src_addr = args.to_addr.clone();
    src_addr.set_port(src_addr.port() + 1);
    let socket = UdpSocket::bind(src_addr).unwrap();

    socket.send_to(args.stop_msg.as_bytes(), args.to_addr).unwrap();
}