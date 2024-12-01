use socket2::{Socket, Domain, Type};
use std::net::SocketAddr;
use std::time;
use std::thread;

fn main() {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    let address: SocketAddr = "239.239.239.35:4411".parse().unwrap();
    socket.bind(&address.into()).unwrap();
    loop {
        let _ = socket.join_multicast_v4(&"239.239.239.35".parse().unwrap(), &"0.0.0.0".parse().unwrap());
        thread::sleep(time::Duration::from_secs(1));
    }
}