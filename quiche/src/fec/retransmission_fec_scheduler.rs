use crate::multicast::MissingRangeSet;
use crate::ranges::RangeSet;

pub struct RetransmissionFecScheduler {
    n_repair_in_flight: u64,
    n_repair_to_send: u64,
    max_n_repair_in_flight: Option<u32>,
}

impl RetransmissionFecScheduler {
    pub fn new(max_rs: Option<u32>) -> RetransmissionFecScheduler {
        RetransmissionFecScheduler {
            n_repair_in_flight: 0,
            n_repair_to_send: 0,
            max_n_repair_in_flight: max_rs,
        }
    }

    pub fn should_send_repair(&mut self) -> bool {
        self.n_repair_to_send > 0 &&
            (if let Some(max_rs) = self.max_n_repair_in_flight {
                // info!(
                //     "Sent repair in flight: {} and max: {:?}",
                //     self.n_repair_in_flight, self.max_n_repair_in_flight
                // );
                self.n_repair_in_flight < max_rs as u64
            } else {
                true
            })
    }

    pub fn sent_repair_symbol(&mut self) {
        self.n_repair_in_flight += 1;
        self.n_repair_to_send -= 1;
    }

    pub fn acked_repair_symbol(&mut self) {
        self.n_repair_in_flight -= 1;
    }

    pub fn sent_source_symbol(&mut self) {}

    pub fn lost_repair_symbol(&mut self) {
        self.acked_repair_symbol()
    }

    pub fn reset_fec_state(&mut self) {
        info!("Reset FEC state");
        self.n_repair_in_flight = 0;
        self.n_repair_to_send = 0;
    }

    /// Receives a negative acknowledgment (NACK) from the client through the
    /// unicast channel (and using the unicast server). Based on the feedback of
    /// the client, computes the number of FEC repair symbols to generate. The
    /// source may potentially already need to generate some symbols, and the
    /// maximum value between the current value and the new value computed from
    /// the feedback is kept. Returns the additional number of repair symbols to
    /// generate following this call (may be 0 if no additional repair symbol
    /// must be generated).
    pub fn recv_nack(
        &mut self, pn: u64, ranges: &RangeSet, mut repairs: RangeSet,
        nb_degree: Option<u64>,
    ) -> u64 {
        // Total number of repair asked.
        let nb_required = ranges.nb_elements(); // MC-TODO: number of ranges or of values?

        // The client is desynchronized with the source, so it may receive a
        // REPAIR that we sent earlier after sending this MC_NACK.
        repairs.remove_until(pn);
        let sent_repairs_not_received = repairs.nb_elements();
        let to_send_local =
            nb_required.saturating_sub(sent_repairs_not_received) as u64;
        // let to_send_local = to_send_local.min(5);

        let n_repair_to_send = if let Some(degree) = nb_degree {
            let degree_after_already_sent =
                degree.saturating_sub(sent_repairs_not_received as u64);
            degree_after_already_sent.min(to_send_local)
        } else {
            to_send_local
        };

        let additional = n_repair_to_send.saturating_sub(self.n_repair_to_send);
        self.n_repair_to_send = self.n_repair_to_send.max(n_repair_to_send);

        additional
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_repair_using_nack() {
        let mut scheduler = RetransmissionFecScheduler::new(None);

        let mut nack = RangeSet::default();
        nack.insert(1..2); // A single packet.
        nack.insert(4..7); // Three lost packets.

        let sent_repairs = RangeSet::default();

        scheduler.recv_nack(10, &nack, sent_repairs, None);

        // The scheduler should send 4 repair symbols.
        for nb_repair in 1..5 {
            assert!(scheduler.should_send_repair());
            scheduler.sent_repair_symbol();
            assert_eq!(scheduler.n_repair_in_flight, nb_repair);
            assert_eq!(scheduler.n_repair_to_send, 4 - nb_repair);
        }
    }

    #[test]
    /// Test with multiple clients. The number of repair symbols to generate is
    /// the maximum among all clients.
    fn test_send_repair_using_nack_two_clients() {
        let mut scheduler = RetransmissionFecScheduler::new(None);

        // Nack for the first client.
        let mut nack = RangeSet::default();
        nack.insert(1..2); // A single packet.
        nack.insert(4..7); // Three lost packets.

        let sent_repairs = RangeSet::default();
        scheduler.recv_nack(10, &nack, sent_repairs.clone(), None);

        // The second client lost only three, but different, packets.
        let mut nack = RangeSet::default();
        nack.insert(2..3);
        nack.insert(10..12);

        scheduler.recv_nack(10, &nack, sent_repairs.clone(), None);

        // The scheduler should send 3 repair symbols.
        for nb_repair in 1..5 {
            assert!(scheduler.should_send_repair());
            scheduler.sent_repair_symbol();
            assert_eq!(scheduler.n_repair_in_flight, nb_repair);
            assert_eq!(scheduler.n_repair_to_send, 4 - nb_repair);
        }
    }

    #[test]
    /// Tests the FEC scheduler with multiple clients and already sent repair
    /// frames.
    fn test_send_repair_and_record() {
        let mut scheduler = RetransmissionFecScheduler::new(None);

        let mut nack = RangeSet::default();
        nack.insert(5..10);
        nack.insert(8..11);

        let mut repairs = RangeSet::default();
        scheduler.recv_nack(12, &nack, repairs.clone(), None);
        assert_eq!(scheduler.n_repair_to_send, 6);

        nack.insert(13..15);
        scheduler.recv_nack(15, &nack, repairs.clone(), None);
        assert_eq!(scheduler.n_repair_to_send, 8);

        for i in 0..scheduler.n_repair_to_send {
            scheduler.sent_repair_symbol();
            assert_eq!(scheduler.n_repair_to_send, 8 - i - 1);
        }
        assert_eq!(scheduler.n_repair_in_flight, 8);
        assert_eq!(scheduler.n_repair_to_send, 0);

        // 8 repair symbols have been sent.
        repairs.insert(5..6);
        repairs.insert(7..8);
        repairs.insert(9..10);
        repairs.insert(11..12);
        repairs.insert(13..17);

        // A client notifies 5 lost packets but has only received packets up to 9.
        // It means that the client has only received 2 repair symbols. The source
        // does not send any repair packet because it already sent repair frames
        // in packets 11, 13, 14, 15 and 16.
        let mut nack_client = RangeSet::default();
        nack_client.insert(6..8);
        nack_client.insert(2..5);
        scheduler.recv_nack(9, &nack_client, repairs.clone(), None);
        assert_eq!(scheduler.n_repair_to_send, 0);

        // A client notifies it lost all packets but did not receive any packet.
        // Same result: no repair packet must be sent.
        let nack_client = RangeSet::default();
        scheduler.recv_nack(0, &nack_client, repairs.clone(), None);
        assert_eq!(scheduler.n_repair_to_send, 0);

        // A client asks for retransmission of four packets and received all but
        // two repair symbols yet. The source must generate 3 repair
        // symbols.
        let mut nack_client = RangeSet::default();
        nack_client.insert(3..4);
        nack_client.insert(7..8);
        nack_client.insert(12..13);
        nack_client.insert(14..15);
        scheduler.recv_nack(14, &nack_client, repairs.clone(), None);
        assert_eq!(scheduler.n_repair_to_send, 2);

        // The same client asks for a new recent lost symbol but recovered the two
        // old ones. The raw number of lost symbols decreased but we
        // increase the number of repairs to send.
        let mut nack_client = RangeSet::default();
        nack_client.insert(3..4);
        nack_client.insert(7..8);
        nack_client.insert(17..18);
        scheduler.recv_nack(19, &nack_client, repairs.clone(), None);
        assert_eq!(scheduler.n_repair_to_send, 3);

        // Another client has lost only a single symbol that has not been
        // receiving reparation. But it does not change the amount of
        // repair symbols to send.
        let mut nack_client = RangeSet::default();
        nack_client.insert(19..20);
        scheduler.recv_nack(20, &nack_client, repairs.clone(), None);
        assert_eq!(scheduler.n_repair_to_send, 3);
    }

    #[test]
    fn test_send_repair_and_degree() {
        let mut scheduler = RetransmissionFecScheduler::new(None);

        let mut nack = RangeSet::default();
        nack.insert(5..10);
        nack.insert(8..11);

        let repairs = RangeSet::default();
        // Send fewer repair symbols using the degree.
        scheduler.recv_nack(12, &nack, repairs.clone(), Some(1));
        assert_eq!(scheduler.n_repair_to_send, 1);

        scheduler.recv_nack(12, &nack, repairs.clone(), Some(12));
        assert_eq!(scheduler.n_repair_to_send, 6);

        scheduler.recv_nack(230, &nack, repairs.clone(), Some(12));
        assert_eq!(scheduler.n_repair_to_send, 6);

        scheduler.recv_nack(230, &nack, repairs.clone(), Some(4));
        assert_eq!(scheduler.n_repair_to_send, 6);
    }
}
