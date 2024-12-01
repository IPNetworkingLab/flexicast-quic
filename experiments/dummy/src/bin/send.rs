use std::net::SocketAddr;
use std::thread;
use std::time;
use socket2::{Socket, Domain, Type};
use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Local address.
    addr: SocketAddr,

    /// Destination address.
    dst: SocketAddr,

    #[clap(short = 'n', value_parser)]
    nb_to_send: Option<usize>,
}

fn main() {
    let args = Args::parse();
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    socket.bind(&args.addr.into()).unwrap();

    let buf = [0u8; 2000];
    let mut nb_sent = 0;
    loop {
        match socket.send_to(&buf[..300], &args.dst.into()) {
            Ok(v) => println!("Sent {} bytes", v),
            Err(e) => eprintln!("Error: {:?}", e),
        }

        thread::sleep(time::Duration::from_millis(10));
        nb_sent += 1;
        if args.nb_to_send.is_some_and(|v| v < nb_sent) {
            break;
        }
    }
}
