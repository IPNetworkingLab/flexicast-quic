use crate::ranges::RangeSet;
use std::collections::HashMap;

pub struct RetransmissionFecScheduler {
    n_repair_in_flight: u64,
    client_losses: HashMap<Vec<u8>, RangeSet>,
    n_repair_to_send: u64,
    new_nack: bool,
    max_n_repair_in_flight: Option<u32>,
}

impl RetransmissionFecScheduler {
    pub fn new(max_rs: Option<u32>) -> RetransmissionFecScheduler {
        RetransmissionFecScheduler {
            n_repair_in_flight: 0,
            client_losses: HashMap::new(),
            n_repair_to_send: 0,
            new_nack: false,
            max_n_repair_in_flight: max_rs,
        }
    }

    pub fn should_send_repair(&mut self) -> bool {
        // Compute the maximum number of repair symbols to generate.
        if self.new_nack {
            self.n_repair_to_send = self
                .client_losses
                .values()
                .map(|rs| rs.flatten().count())
                .max()
                .unwrap_or(0) as u64;
            self.new_nack = false;
            info!("Number of repair to send: {} because: {:?}", self.n_repair_to_send, self.client_losses);
        }

        if !self.client_losses.is_empty() &&
            self.n_repair_in_flight >= self.n_repair_to_send
        {
            // We sent enough repair symbols. We flush the hashmap to avoid
            // sending repair symbols for old data.
            self.client_losses = HashMap::new();
        }

        self.n_repair_in_flight < self.n_repair_to_send && (if let Some(max_rs) = self.max_n_repair_in_flight {
            info!("Sent repair in flight: {} and max: {:?}", self.n_repair_in_flight, self.max_n_repair_in_flight);
            self.n_repair_in_flight < max_rs as u64
        } else {
            true
        })

        // trace!("fec_scheduler dgrams_to_emit={} stream_to_emit={}
        // n_repair_in_flight={} max_repair_data={}",
        //         dgrams_to_emit, stream_to_emit, self.n_repair_in_flight,
        // max_repair_data); !dgrams_to_emit && !stream_to_emit &&
        // (self.n_repair_in_flight as usize *symbol_size) < max_repair_data
    }

    pub fn sent_repair_symbol(&mut self) {
        self.n_repair_in_flight += 1;
    }

    pub fn acked_repair_symbol(&mut self) {
        self.n_repair_in_flight -= 1;
    }

    pub fn sent_source_symbol(&mut self) {}

    pub fn lost_repair_symbol(&mut self) {
        self.acked_repair_symbol()
    }

    pub fn lost_source_symbol(&mut self, ranges: RangeSet, client_cid: &[u8]) {
        self.client_losses.insert(client_cid.into(), ranges);
        self.new_nack = true;
    }

    pub fn reset_fec_state(&mut self) {
        info!("Reset FEC state");
        self.n_repair_in_flight = 0;
        self.n_repair_to_send = 0;
        self.client_losses = HashMap::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_repair_using_nack() {
        let mut scheduler = RetransmissionFecScheduler::new(None);
        let cid = vec![1, 2, 3];

        let mut nack = RangeSet::default();
        nack.insert(1..2); // A single packet.
        nack.insert(4..7); // Three lost packets.

        scheduler.lost_source_symbol(nack, &cid);

        // The scheduler should send 3 repair symbols.
        for nb_repair in 1..5 {
            assert!(scheduler.should_send_repair());
            scheduler.sent_repair_symbol();
            assert_eq!(scheduler.n_repair_in_flight, nb_repair);
            assert_eq!(scheduler.n_repair_to_send, 4);
        }
    }

    #[test]
    /// Test with multiple clients. The number of repair symbols to generate is the maximum among all clients.
    fn test_send_repair_using_nack_two_clients() {
        let mut scheduler = RetransmissionFecScheduler::new(None);
        let cid_1 = vec![1, 2, 3];
        let cid_2 = vec![4, 5, 6, 7, 8];

        // Nack for the first client.
        let mut nack = RangeSet::default();
        nack.insert(1..2); // A single packet.
        nack.insert(4..7); // Three lost packets.

        scheduler.lost_source_symbol(nack, &cid_1);

        // The second client lost only three, but different, packets.
        let mut nack = RangeSet::default();
        nack.insert(2..3);
        nack.insert(10..12);

        scheduler.lost_source_symbol(nack, &cid_2);

        // The scheduler should send 3 repair symbols.
        for nb_repair in 1..5 {
            assert!(scheduler.should_send_repair());
            scheduler.sent_repair_symbol();
            assert_eq!(scheduler.n_repair_in_flight, nb_repair);
            assert_eq!(scheduler.n_repair_to_send, 4);
        }
    }
}
