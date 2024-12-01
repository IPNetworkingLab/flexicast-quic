use socket2::{Socket, Domain, Type};
use std::net::SocketAddr;

fn main() {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    let address: SocketAddr = "224.3.0.225:4433".parse().unwrap();
    socket.bind(&address.into()).unwrap();
    socket.join_multicast_v4(&"224.3.0.225".parse().unwrap(), &"11.1.5.2".parse().unwrap()).unwrap();
    println!("Will enter loop to listen to packets");

    let mut buf = Vec::with_capacity(2000);
    loop {
        match socket.recv_from(buf.spare_capacity_mut()) {
            Ok((len, from)) => {
                println!("Received a packet of length {} from {:?}", len, from);
            },
            Err(e) => eprintln!("Error: {:?}", e),
        }
    }
}