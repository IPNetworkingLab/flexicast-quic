use clap::Parser;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;

#[derive(Parser)]
struct Args {
    /// Local address to listen to.
    addr: SocketAddr,

    /// Message to indicate the end of the stream.
    #[clap(long = "stop", value_parser, default_value = "STOP RTP")]
    stop_msg: String,
}

fn main() {
    let args = Args::parse();
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    socket.bind(&args.addr.into()).unwrap();
    let stop_msg = args.stop_msg.as_bytes().to_vec();
    println!("Will enter loop to listen to packets");

    let mut buf = Vec::with_capacity(2000);
    loop {
        match socket.recv_from(buf.spare_capacity_mut()) {
            Ok((len, _from)) => {
                // Stop if received the specific message.
                if len - 1 == stop_msg.len() && &buf[..len - 1] == &stop_msg {
                    break;
                }
            }
            Err(e) => eprintln!("Error: {:?}", e),
        }
    }
}
