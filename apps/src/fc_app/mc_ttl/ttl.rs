use super::FcTtlMsg;
use super::Result;
use quiche::flexicast::ack::OpenRangeSet;
use std::collections::hash_map::Entry;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time;
use tokio::sync::mpsc;

pub struct TtlApp {
    /// Maintains, for each IP address, the set of pair time-TTL values that
    /// have been correctly received and acknowledged.
    recv_ttl: HashMap<IpAddr, Vec<(u8, time::SystemTime)>>,

    /// Maintains, for each packet number, the according TTL value.
    pn_ttl: BTreeMap<u64, u8>,

    /// RX channel for the messages of the flexicast flow and unicast paths.
    rx_app: mpsc::Receiver<FcTtlMsg>,

    /// Duration between two results print.
    print_delay: time::Duration,
}

impl TtlApp {
    pub fn new(rx_app: mpsc::Receiver<FcTtlMsg>, print_delay: time::Duration) -> Self {
        Self {
            rx_app,
            recv_ttl: HashMap::new(),
            pn_ttl: BTreeMap::new(),
            print_delay,
        }
    }


    pub async fn run(&mut self) -> Result<()> {
        let mut last_print = time::Instant::now();

        loop {
            let now = time::Instant::now();
            let print_timeout = (last_print + self.print_delay).duration_since(now);
            tokio::select! {
                // New message.
                Some(msg) = self.rx_app.recv() => {
                    match msg {
                        FcTtlMsg::SentPkt(v) => self.handle_sent_pkt(v),
    
                        FcTtlMsg::RecvPkt((ip, rangeset)) =>
                            self.handle_recv_pkt(ip, rangeset),
                    }
                }

                // Print timeout.
                _ = tokio::time::sleep(print_timeout) => {
                    self.handle_print();
                    last_print = time::Instant::now();
                }
            }
        }
    }

    fn handle_sent_pkt(&mut self, mut v: Vec<(u64, u8)>) {
        for (pn, ttl) in v.drain(..) {
            self.pn_ttl.insert(pn, ttl);
        }
    }

    fn handle_recv_pkt(&mut self, ip: IpAddr, rangeset: OpenRangeSet) {
        let entry = match self.recv_ttl.entry(ip) {
            Entry::Vacant(v) => v.insert(Vec::new()),
            Entry::Occupied(o) => o.into_mut(),
        };
        
        let now = time::SystemTime::now();
        for range in rangeset.iter() {
            for pn in range {
                // Get the TTL of this packet.
                if let Some(ttl) = self.pn_ttl.get(&pn) {
                    entry.push((*ttl, now));
                }
            }
        }
    }

    /// For each IP address, record the minimum received TTL since the last print and resets the results state.
    fn handle_print(&mut self) {
        for (ip, mut recv) in self.recv_ttl.drain() {
            recv.sort();
            if let Some(data) = recv.first() {
                print!("{:?}: {:?}\t", ip, data.0);
            }
        }
        println!();
    }
}
