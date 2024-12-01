use clap::Parser;
use socket2::{Domain, Socket, Type};
use std::net::{IpAddr, SocketAddr};

#[derive(Parser)]
struct Args {
    /// Multicast address to listen to.
    mc_addr: SocketAddr,

    /// List of nodes to duplicate the traffic.
    #[clap(short = 'c', value_parser, num_args(0..))]
    proxy_addresses: Vec<SocketAddr>,

    /// Local IP address.
    local_ip: IpAddr,
}

fn main() {
    let args = Args::parse();

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    socket.bind(&args.mc_addr.into()).unwrap();
    // match (args.mc_addr, args.local_ip) {
    //     (SocketAddr::V4(mc), IpAddr::V4(local)) => {
    //         socket.join_multicast_v4(mc.ip(), &local).unwrap()
    //     }
    //     _ => panic!("Only support V4"),
    // }

    println!("Start the UC proxy.");
    let mut buf = Vec::with_capacity(2000);
    loop {
        match socket.recv_from(buf.spare_capacity_mut()) {
            Ok((len, _)) => {
                unsafe {
                    buf.set_len(len);
                }
                println!("Received a packet");
                // Copy the bytes to each destination.
                args.proxy_addresses
                    .iter()
                    .for_each(|addr| { socket.send_to(&buf[..len], &(*addr).into()).unwrap(); });
                unsafe {
                    buf.set_len(0);
                }
            }
            Err(e) => eprintln!("Error: {:?}", e),
        }
    }
}
