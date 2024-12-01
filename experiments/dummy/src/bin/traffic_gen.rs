use std::net::SocketAddr;
use std::time;
use clap::Parser;
use mio::net::UdpSocket;


#[derive(Parser)]
struct Args {
    /// Address where to send packets.
    to_addr: SocketAddr,

    /// Datagram size.
    dg_size: usize,

    /// Rate in Mbps.
    rate: u64,

    /// Duration of the traffic in seconds.
    duration: u64,
}

fn main() {
    let args = Args::parse();

    let socket = UdpSocket::bind("127.0.0.1:0000".parse().unwrap()).unwrap();

    // Compute the sleep time as datagram size / target bitrate.
    // Rate in Mbps -> in bps -> in bpns.
    let target_bitrate = args.rate as f64 * 1_000_000f64 / 1_000_000_000f64;

    let sleep_duration_in_ns = (args.dg_size * 8) as f64 / target_bitrate;
    let sleep_duration = time::Duration::from_nanos(sleep_duration_in_ns as u64);
    println!("Sleep duration: {:?}", sleep_duration);

    let start = time::Instant::now();
    let duration = time::Duration::from_secs(args.duration);

    let mut previous_sent = start;

    // Buffer to send.
    let buffer = vec![42u8; args.dg_size];

    let mut nb_sent = 0;

    loop {
        let now = time::Instant::now();
        
        // Should we stop?
        if now.duration_since(start) >= duration {
            break;
        }

        // Compute the next timeout based on the previous one not to accumulate lateness.
        let timeout = next_timeout(previous_sent, now, sleep_duration);
        std::thread::sleep(timeout);

        // Send next packet.
        nb_sent += socket.send_to(&buffer, args.to_addr).unwrap();
        previous_sent = time::Instant::now();
    }

    // Compute statistics based on the sent packets.
    let sent_bitrate = nb_sent * 8 / duration.as_secs() as usize / 1_000_000;
    println!("A posteriori bitrate: {:?}", sent_bitrate);
}

fn next_timeout(previous: time::Instant, now: time::Instant, sleep_duration: time::Duration) -> time::Duration {
    let next_timeout = previous + sleep_duration;
    next_timeout.duration_since(now)
}