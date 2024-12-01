use clap::Parser;
use std::net::SocketAddr;
use socket2::{Socket, Domain, Type};

#[derive(Parser)]
struct Args {
    /// Local address of the proxy.
    local_ip: SocketAddr,

    /// Out address of the proxy.
    out_ip: SocketAddr,

    /// Multicast destination address.
    mc_addr: SocketAddr,
}

fn main() {
    let args = Args::parse();

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    socket.bind(&args.local_ip.into()).unwrap();

    let out_socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    out_socket.bind(&args.out_ip.into()).unwrap();
    out_socket.set_multicast_ttl_v4(100).unwrap();

    let mut buf = Vec::with_capacity(4096);
    loop {
        match socket.recv_from(buf.spare_capacity_mut()) {
            Ok((len, from)) => {
                println!("Received a packet of length {} from {:?}", len, from);
                unsafe {
                    buf.set_len(len);
                }
                let written = out_socket.send_to(&buf[..len], &args.mc_addr.into()).unwrap();
                unsafe {
                    buf.set_len(0);
                }
                println!("Sent a packet of len {} to the wire.", written);
            },
            Err(e) => eprintln!("Error: {:?}", e),
        }
    }
}
