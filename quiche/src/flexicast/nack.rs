//! This module further extends the Flexicast extension of QUIC to provide
//! paced acknowledgment based reliability. That is, to avoid
//! ACK-implosion, the flexicast receiver will only send PATH_ACK frames when:
//! 1) it sees gaps in the packet number sequence or
//! 2) it does not receive packets on the flexicast flow for 3 * `fc_ack_delay`.
//!    The flexicast flow source commits to regularly send packets (possibly
//!    PING frames) to ensure that this timer only expires whenever packets are
//!    lost in the network, i.e., there is a transmission problem between the
//!    source and the receiver.
//! 3) If the standard QUIC reliability mechanism is used.
//!
//! Concretely, this module does the following:
//! 1) Avoid sending positive PATH_ACK by default
//! 2) Send PATH_ACK frames when there is a gap in the packet number sequence
//!    for packets received on the flexicast flow
//! 3) Add a timer expiring after 3 * `fc_ack_delay` if no packet is received on
//!    the flexicast flow
//! 4) Trigger a PATH_ACK frame when the aforementionned timer expired

use crate::flexicast::FcError;
use crate::packet::Epoch;
use crate::rand;
use crate::ranges::RangeSet;
use crate::Connection;
use crate::Error;
use crate::Result;
use std::cmp;
use std::str::FromStr;
use std::time;

use super::FlexicastAttributes;
use super::McRole;

/// Shortcut to get access to the Flexicast receiver [`FcNackState`] from the
/// [`crate::Connection`].
#[macro_export]
macro_rules! fc_nack_recv {
    ( $conn:expr ) => {
        $conn
            .flexicast
            .as_ref()
            .map(|fc| fc.fc_reliable.receiver().map(|n| n.nack()))
            .flatten()
    };
}

/// Shortcut to get mutable access to the Flexicast receiver [`FcNackState`]
/// from the [`crate::Connection`]. Returns an `Option<FcNackState>` or `None`.
#[macro_export]
macro_rules! fc_nack_recv_mut {
    ( $conn:expr ) => {
        $conn
            .flexicast
            .as_mut()
            .map(|fc| fc.fc_reliable.client_mut().map(|n| n.nack_mut()))
            .flatten()
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Whether a PATH_ACK must be sent for the flexicast flow and the potential
/// reason.
enum FcNackState {
    /// Does not send a PATH_ACK.
    NoSend          = 0,

    /// Send a PATH_ACK because of the idle timeout.
    SendPositiveAck = 1,

    /// Send a PATH_ACK because there is a gap in the received packet number
    /// sequence.
    SendGap         = 2,

    /// Send a PATH_ACK because we use the standard reliability mechanism.
    SendRfc9000     = 3,
}

#[derive(Debug)]
/// Handles the NACK-based reliability of the flexicast flow receiver.
/// FC-TODO: add exponential back-off.
pub struct FcNackRecv {
    /// Last time a PATH_ACK was sent for packets on the flexicast flow.
    last_path_ack_sent: time::Instant,

    /// The 'flexicast flow' timeout before triggering a PATH_ACK frame from the
    /// flexicast flow.
    /// This value is chosen randomly within the flexicast timer to ensure that
    /// the receivers do not send positive acknowledgment at the same time.
    fc_next_positive_ack_time: time::Duration,

    /// Whether the receiver must send a PATH_ACK on the flexicast flow.
    /// This can be true for two reasons:
    /// 1) the flexicast flow idle timeout expired;
    /// 2) the receiver saw a gap in the packet number sequence on the flexicast
    ///    flow.
    send_path_ack_on_fc: FcNackState,

    /// Highest missing packet number.
    /// Used to avoid sending multiple times a PATH_ACK for the same gap.
    max_gap_pn: Option<u64>,

    /// The maximum time between two PATH_ACK, in ms.
    /// If the value is 0, it means that there is no ack delay, and classical
    /// ACK mechanism from QUIC is used.
    fc_max_time_ack: u64,

    /// Sequence number of the update of the ack delay.
    update_seqnum: u64,
}

impl FcNackRecv {
    /// New structure instance given the `fc_ack_delay`.
    pub fn new(fc_ack_delay: u64) -> Self {
        Self {
            last_path_ack_sent: time::Instant::now(),
            fc_next_positive_ack_time: Self::fc_get_next_timeout(fc_ack_delay),
            send_path_ack_on_fc: FcNackState::NoSend,
            max_gap_pn: None,
            fc_max_time_ack: fc_ack_delay,
            update_seqnum: 0,
        }
    }

    /// Updates the flexicast max ack timer.
    pub fn update_fc_ack_delay(&mut self, timer: u64, seqnum: u64) {
        if seqnum <= self.update_seqnum {
            return;
        }

        self.fc_max_time_ack = timer;
        self.update_seqnum = seqnum;

        if timer == 0 {
            self.send_path_ack_on_fc = FcNackState::SendRfc9000;
        } else {
            self.send_path_ack_on_fc = FcNackState::NoSend;
        }
    }

    /// This function is called whenever a new packet is received on the
    /// flexicast flow. If there is a gap in the packet number sequence,
    /// i.e., `last_max_pn` + 1 != `new_pn`, trigger a new PATH_ACK frame.
    /// If the receiver should initially send a PATH_ACK because of the idle
    /// timeout expiration, but `last_max_pn` + 1 == `new_pn`, it means that no
    /// packet was lost, just that it was delayed, so cancel the PATH_ACK.
    ///
    /// TODO: what do we do if we have a gap that is now filled, i.e., the
    /// packet was jitted?
    pub fn fc_on_pkt_recv(&mut self, recv_pkt_need_ack: &RangeSet) {
        if self.send_path_ack_on_fc == FcNackState::SendRfc9000 {
            return;
        }
        if recv_pkt_need_ack.len() == 1 {
            // There is no gap in the packet number sequence that needs to be
            // acked. If the previous state was
            // [`FcNackState::SendGap`], it means that there
            // was a jitted packet that is now received.
            self.send_path_ack_on_fc = FcNackState::NoSend;
        } else if let Some(missing) =
            recv_pkt_need_ack.iter().last().map(|l| l.start)
        {
            // There is (still) a gap. If it is the same as before, do not count
            // it twice.
            if self.max_gap_pn.is_none() || Some(missing) > self.max_gap_pn {
                self.send_path_ack_on_fc = FcNackState::SendGap;
                self.max_gap_pn = Some(missing);
            }
        }
    }

    /// Next flexicast flow idle timeout.
    pub fn fc_next_timeout(&self) -> Option<time::Instant> {
        if self.send_path_ack_on_fc == FcNackState::SendRfc9000 {
            None
        } else {
            Some(self.last_path_ack_sent + self.fc_next_positive_ack_time)
        }
    }

    /// Upon timeout, trigger the fact that the receiver must sent a PATH_ACK
    /// frame. There is a preceding rule: always prioritize a PATH_ACK
    /// because of a gap.
    pub fn fc_on_timeout(&mut self, now: time::Instant) {
        if Some(now) >= self.fc_next_timeout() {
            self.send_path_ack_on_fc =
                cmp::max(self.send_path_ack_on_fc, FcNackState::SendPositiveAck);
        }
    }

    /// Whether the receiver must send a PATH_ACK.
    pub fn fc_should_send_ack(&mut self, now: time::Instant) -> bool {
        if self.send_path_ack_on_fc == FcNackState::SendRfc9000 {
            true
        } else {
            self.fc_on_timeout(now);
            self.send_path_ack_on_fc > FcNackState::NoSend
        }
    }

    /// This function is called when a PATH_ACK is sent for the flexicast flow.
    pub fn fc_on_path_ack_sent(&mut self, now: time::Instant) {
        if self.send_path_ack_on_fc != FcNackState::SendRfc9000 {
            self.send_path_ack_on_fc = FcNackState::NoSend;
            self.last_path_ack_sent = now;
            self.fc_next_positive_ack_time =
                Self::fc_get_next_timeout(self.fc_max_time_ack)
        }
    }

    /// Returns a value between 0 and `v` using the provided `random`.
    fn fc_get_next_timeout(v: u64) -> time::Duration {
        let mut buffer = [0u8; 8];
        rand::rand_bytes(&mut buffer[..]);

        let value = u64::from_be_bytes(buffer);
        time::Duration::from_micros(value % v)
    }

    /// Returns whether the receiver must send a positive ACK.
    fn fc_should_send_ack_ref(&self, now: time::Instant) -> bool {
        if self.send_path_ack_on_fc == FcNackState::SendRfc9000 {
            true
        } else {
            let mut send_path_ack_on_fc = self.send_path_ack_on_fc;
            if Some(now) >= self.fc_next_timeout() {
                send_path_ack_on_fc =
                    cmp::max(send_path_ack_on_fc, FcNackState::SendPositiveAck);
            }
            send_path_ack_on_fc > FcNackState::NoSend
        }
    }
}

impl Connection {
    /// Process for the flexicast receiver the reception of a new packet on the
    /// flexicast flow for negative acknowledgment. This function checks if
    /// the sequence of received packet numbers is contiguous, otherwise the
    /// receiver should send a PATH_ACK as a negative acknowledgment.
    pub fn fc_on_pkt_recv(&mut self, space_id: u64) -> Result<()> {
        let flexicast = fca!(self)?;

        if !matches!(flexicast.mc_role, McRole::Client(_)) {
            return Ok(());
        }

        if fc_nack_recv!(self).is_none() {
            return Ok(());
        }

        let fc_id = match flexicast.fc_path_id {
            Some(v) => v,
            None => return Ok(()),
        };

        if space_id != fc_id {
            return Ok(());
        }

        let recv_pkt_need_ack = &self
            .pkt_num_spaces
            .spaces
            .get(Epoch::Application, space_id)?
            .recv_pkt_need_ack;

        if let Some(nack) = fc_nack_recv_mut!(self) {
            nack.fc_on_pkt_recv(recv_pkt_need_ack);
        }

        Ok(())
    }
}

impl FlexicastAttributes {
    /// The flexicast receiver previously sent a PATH_ACK frame for packets
    /// received on the flexciast flow while the NACK extension is used, and
    /// this PATH_ACK frame is lost. For simplification, we assume that this
    /// frame was sent because of a gap in the packet number sequence to be sure
    /// that we will send it again.
    ///
    /// We do this in the flexicast attributes because we do not have fully
    /// access to the Connection. This is Rust.
    pub(crate) fn fc_on_path_nack_lost(&mut self, path_id: u64) {
        if self.fc_path_id == Some(path_id) {
            if let Some(nack) =
                self.fc_reliable.client_mut().map(|r| r.nack_mut())
            {
                if nack.send_path_ack_on_fc != FcNackState::SendRfc9000 {
                    nack.send_path_ack_on_fc = FcNackState::SendGap;
                }
            }
        }
    }

    /// Returns whether NACK-based reliability is used and the receiver must
    /// send a positive PATH_ACK.
    pub(crate) fn fc_use_nack_and_should_send_positive(&self) -> bool {
        self.fc_reliable
            .receiver()
            .map(|r| r.nack())
            .map(|n| n.fc_should_send_ack_ref(time::Instant::now()))
            .unwrap_or(false)
    }

    /// Update the flexicast flow timer for delayed acknowledgment.
    pub(crate) fn fc_update_ack_delay(&mut self, ack_delay: u64, seqnum: u64) {
        self.fc_reliable
            .client_mut()
            .map(|r| r.nack_mut())
            .map(|n| n.update_fc_ack_delay(ack_delay, seqnum));
    }
}

/// Enumeration of the ack delay strategy.
#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub enum FcAckDelayStrategy {
    /// Similar strategy to RFC9000: immediate ack.
    Immediate,

    /// Constant ACK delay, value in micro seconds.
    Constant(u64),

    /// Adaptive strategy, based on the number of receivers and the maximum ack
    /// rate. The value is the current acknowledgment delay, with 0 meaning
    /// immediate.
    Adaptive(u64),
}

impl FromStr for FcAckDelayStrategy {
    type Err = std::num::ParseIntError;

    /// Converts a string to `FcAckDelayStrategy`.
    ///
    /// `name` is only valid if `immediate`, `adaptive`, or any integer is
    /// provided. A value of 0 also means `immediate` for legacy.
    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name {
            "immediate" | "0" => Ok(FcAckDelayStrategy::Immediate),
            "adaptive" => Ok(FcAckDelayStrategy::Adaptive(0)), // Start at 0
            v => {
                let value: u64 = v.parse()?;
                Ok(FcAckDelayStrategy::Constant(value))
            },
        }
    }
}

impl From<FcAckDelayStrategy> for u64 {
    fn from(value: FcAckDelayStrategy) -> Self {
        match value {
            FcAckDelayStrategy::Adaptive(v) => v,
            FcAckDelayStrategy::Constant(v) => v,
            FcAckDelayStrategy::Immediate => 0,
        }
    }
}

impl From<u64> for FcAckDelayStrategy {
    // Does not support adaptive in this way.
    fn from(value: u64) -> Self {
        if value == 0 {
            FcAckDelayStrategy::Immediate
        } else {
            FcAckDelayStrategy::Constant(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time;

    use super::*;
    use crate::flexicast::reliable::FcUnicastRetransmission;
    use crate::flexicast::testing::FlexicastPipe;
    use crate::flexicast::FcConfig;
    use crate::ranges::RangeSet;
    use crate::InternalPathId;

    #[test]
    /// Tests the negative acknowledgment reliability module of Flexicast QUIC
    /// under no losses. With a non-zero flexicast timer, the flexicast flow
    /// source and receivers MUST use negative acknowledgments only. In this
    /// scenario (i.e., no losses), the receivers never send PATH_ACK frames and
    /// the source will release memory upon 'timeout'.
    fn test_fc_nack_no_loss() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            fc_ack_delay: 30.into(), // MUST use negative acknowledgment.
            ..Default::default()
        };
        fc_config.mc_announce_data[0].fc_ack_delay =
            fc_config.fc_ack_delay.into();

        let mut fc_pipe =
            FlexicastPipe::new(1, "/tmp/test_fc_nack_no_loss", &mut fc_config)
                .unwrap();

        // State for negative acknowledgment.
        let client = &mut fc_pipe.unicast_pipes[0].0.client;
        let nack = client
            .flexicast
            .as_ref()
            .map(|fc| fc.fc_reliable.receiver().map(|c| c.nack()))
            .flatten();
        assert!(nack.is_some());

        let mut buf = [0u8; 1500];

        // The source sends 3 streams without loss.
        let now = time::Instant::now();
        fc_pipe.source_send_single_stream(true, None, 3).unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Before the source sends data, the receiver MIGHT have to send a
        // PATH_ACK because there is a gap in the packet number sequence, because
        // it joined the flexicast flow later. Hence, we ask the receiver
        // to send a PATH_ACK if needed to "reset" its state.
        // Receiving the first stream will trigger the PATH_ACK on the receiver.
        fc_pipe.clients_send().unwrap();

        // Ensure that now the state of the receiver is reset.
        // let nack = fc_nack_recv!(fc_pipe.unicast_pipes[0].0.client).unwrap();
        // assert!(nack.send_path_ack_on_fc == FcNackState::NoSend);

        fc_pipe.source_send_single_stream(true, None, 7).unwrap();
        fc_pipe.source_send_single_stream(true, None, 11).unwrap();

        // Control to notify the send packets.
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // The receiver MUST NOT send PATH_ACK frame for the received data.
        let client = &mut fc_pipe.unicast_pipes[0].0.client;
        assert_eq!(client.send(&mut buf), Err(Error::Done));

        // Assert that the source has some packets in the sending queue.
        let p = fc_pipe
            .mc_channel
            .channel
            .paths
            .get(InternalPathId(1))
            .unwrap();
        let sent = p.recovery.get_sent_pkts();
        assert!(sent.len() > 3);

        let uc = &mut fc_pipe.unicast_pipes[0].0.server;
        let retr_kind = FcUnicastRetransmission::Delegates(true);
        fc_pipe
            .mc_channel
            .channel
            .rfc_delegate_streams(uc, now, retr_kind)
            .unwrap();

        // The source releases data upon PATH_ACK from the receivers.
        let ack_delay: u64 = fc_config.fc_ack_delay.into();
        let sleep_duration = time::Duration::from_micros(ack_delay * 2);
        for _ in 0..20 {
            fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();
            fc_pipe.source_send_single(None).unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            std::thread::sleep(sleep_duration);
            fc_pipe.clients_send().unwrap();
            let now = time::Instant::now();
            fc_pipe.server_control_to_mc_source(now).unwrap();
        }

        // Verify that the flexicast flow released resources on flexicast timeout.
        let p = fc_pipe
            .mc_channel
            .channel
            .paths
            .get(InternalPathId(1))
            .unwrap();
        let sent = p.recovery.get_sent_pkts();
        assert_eq!(sent.len(), 0);

        // Also check that the unicast path released the data packets of the
        // flexicast flow.
        let now = time::Instant::now();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        let uc_path = &mut fc_pipe.unicast_pipes[0].0.server;
        uc_path.on_timeout();
        let p = uc_path.paths.get(InternalPathId(1)).unwrap();
        let sent = p.recovery.get_sent_pkts();
        assert_eq!(sent.len(), 0);
    }

    #[test]
    /// Tests the negative acknowledgment reliability module of the flexicast
    /// extension. This test creates gaps in the packet number sequence
    /// (i.e., losses) to trigger PATH_ACK from the receivers which will trigger
    /// retransmission.
    fn test_fc_nack_loss() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            fc_ack_delay: 200.into(), // MUST use negative acknowledgment.
            ..Default::default()
        };
        fc_config.mc_announce_data[0].fc_ack_delay =
            fc_config.fc_ack_delay.into();

        let mut client_loss = RangeSet::default();
        client_loss.insert(0..1);

        let mut fc_pipe =
            FlexicastPipe::new(1, "/tmp/test_fc_nack_loss", &mut fc_config)
                .unwrap();

        fc_pipe.source_send_single_stream(true, None, 3).unwrap();

        // To reset the NACK state.
        let now = time::Instant::now();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.clients_send().unwrap();

        fc_pipe.source_send_single_stream(true, None, 7).unwrap();
        fc_pipe
            .source_send_single_stream(true, Some(&client_loss), 11)
            .unwrap();

        // The unicast path source does not have ACK for these two packets even if
        // the receivers have the opportunity to send data.
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.clients_send().unwrap();
        let uc_path = &fc_pipe.unicast_pipes[0].0.server;
        let mc_ack = &uc_path
            .flexicast
            .as_ref()
            .unwrap()
            .fc_reliable
            .server()
            .unwrap()
            .mc_ack;
        let full_ack = mc_ack.full_ack_poll();
        assert_eq!(full_ack, None);

        let nack = fc_nack_recv!(fc_pipe.unicast_pipes[0].0.client).unwrap();
        assert!(nack.send_path_ack_on_fc == FcNackState::NoSend);

        // The receiver will see a gap in the packet number sequence.
        fc_pipe.source_send_single_stream(true, None, 15).unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        let nack = fc_nack_recv!(fc_pipe.unicast_pipes[0].0.client).unwrap();
        assert!(nack.send_path_ack_on_fc == FcNackState::SendGap);

        // The receiver will send a PATH_ACK for NACK purposes.
        fc_pipe.clients_send().unwrap();
        let uc_path = &fc_pipe.unicast_pipes[0].0.server;
        let mc_ack = &uc_path
            .flexicast
            .as_ref()
            .unwrap()
            .fc_reliable
            .server()
            .unwrap()
            .mc_ack;
        let full_ack = mc_ack.full_ack_poll().unwrap().to_owned();
        let mut expected_full_ack = RangeSet::default();
        expected_full_ack.insert(3..4);
        expected_full_ack.insert(5..6);
        assert_eq!(full_ack, expected_full_ack);

        // And the receiver cannot read all streams.
        let client = &fc_pipe.unicast_pipes[0].0.client;
        let mut readables = client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![3, 7, 15]);

        // Unicast retransmissions.
        let ack_delay: u64 = fc_config.fc_ack_delay.into();
        let sleep_duration = time::Duration::from_micros(ack_delay * 3,
        );
        std::thread::sleep(sleep_duration);
        fc_pipe.unicast_pipes[0].0.server.on_timeout();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.mc_channel.channel.on_timeout();
        let lost_pn_res = fc_pipe.unicast_pipes[0]
            .0
            .server
            .fc_drain_lost_pn()
            .unwrap();
        let lost_pn = [4].iter().map(|i| *i).collect();
        assert_eq!(lost_pn_res, lost_pn);
        let retr_kind = FcUnicastRetransmission::Delegates(true);
        let uc = &mut fc_pipe.unicast_pipes[0].0.server;
        let now = time::Instant::now();
        fc_pipe
            .mc_channel
            .channel
            .rfc_delegate_streams(uc, now, retr_kind)
            .unwrap();
        fc_pipe.unicast_pipes[0].0.advance().unwrap();

        // Now the receiver can read all streams.
        let client = &fc_pipe.unicast_pipes[0].0.client;
        let mut readables = client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![3, 7, 11, 15]);

        // New timeout to release all data on the flexicast flow source.
        let ack_delay: u64 = fc_config.fc_ack_delay.into();
        let sleep_duration = time::Duration::from_micros(ack_delay * 2,
        );
        for _ in 0..10 {
            fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();
            fc_pipe.source_send_single(None).unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            std::thread::sleep(sleep_duration);
            fc_pipe.clients_send().unwrap();
            let now = time::Instant::now();
            fc_pipe.server_control_to_mc_source(now).unwrap();
        }
        let p = fc_pipe
            .mc_channel
            .channel
            .paths
            .get(InternalPathId(1))
            .unwrap();
        let sent = p.recovery.get_sent_pkts();
        assert_eq!(sent.len(), 0);

        // Also check that the unicast path released the data packets of the
        // flexicast flow.
        let now = time::Instant::now();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        let uc_path = &mut fc_pipe.unicast_pipes[0].0.server;
        uc_path.on_timeout();
        let p = uc_path.paths.get(InternalPathId(1)).unwrap();
        let sent = p.recovery.get_sent_pkts();
        assert_eq!(sent.len(), 0);
    }

    #[test]
    /// Tests the negative acknowledgment reliability module of the flexicast
    /// extension. This test creates tail losses and waits for the receiver to
    /// send a PATH_ACK because of the idle timeout on the flexicast flow.
    fn test_fc_nack_tail_loss() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            fc_ack_delay: 100.into(), // MUST use negative acknowledgment.
            ..Default::default()
        };
        fc_config.mc_announce_data[0].fc_ack_delay =
            fc_config.fc_ack_delay.into();

        let mut client_loss = RangeSet::default();
        client_loss.insert(0..1);

        let mut fc_pipe =
            FlexicastPipe::new(1, "/tmp/test_fc_nack_tail_loss", &mut fc_config)
                .unwrap();

        fc_pipe.source_send_single_stream(true, None, 3).unwrap();

        // To reset the NACK state.
        let now = time::Instant::now();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.clients_send().unwrap();

        fc_pipe.source_send_single_stream(true, None, 7).unwrap();
        fc_pipe
            .source_send_single_stream(true, Some(&client_loss), 11)
            .unwrap();

        // The unicast path source does not have ACK for these two packets even if
        // the receivers have the opportunity to send data.
        fc_pipe.server_control_to_mc_source(now).unwrap();
        fc_pipe.clients_send().unwrap();
        let uc_path = &fc_pipe.unicast_pipes[0].0.server;
        let mc_ack = &uc_path
            .flexicast
            .as_ref()
            .unwrap()
            .fc_reliable
            .server()
            .unwrap()
            .mc_ack;
        let full_ack = mc_ack.full_ack_poll();
        assert_eq!(full_ack, None);

        let nack = fc_nack_recv!(fc_pipe.unicast_pipes[0].0.client).unwrap();
        assert!(nack.send_path_ack_on_fc == FcNackState::NoSend);

        // The flexicast flow remains idle for too long, thus triggering a
        // PATH_ACK on the receiver.
        let ack_delay: u64 = fc_config.fc_ack_delay.into();
        let sleep_duration = time::Duration::from_micros(ack_delay * 2,
        );
        std::thread::sleep(sleep_duration);
        fc_pipe.unicast_pipes[0].0.client.on_timeout();
        let nack = fc_nack_recv!(fc_pipe.unicast_pipes[0].0.client).unwrap();
        assert!(nack.send_path_ack_on_fc == FcNackState::SendPositiveAck);

        // And the receiver cannot read all streams.
        let client = &fc_pipe.unicast_pipes[0].0.client;
        let mut readables = client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![3, 7]);
        fc_pipe.unicast_pipes[0].0.advance().unwrap();

        // The unicast path source received the PATH_ACK and the McAck structure
        // now has data to poll.
        let uc_path = &fc_pipe.unicast_pipes[0].0.server;
        let mc_ack = &uc_path
            .flexicast
            .as_ref()
            .unwrap()
            .fc_reliable
            .server()
            .unwrap()
            .mc_ack;
        let full_ack = mc_ack.full_ack_poll().unwrap().to_owned();
        let mut expected_full_ack = RangeSet::default();
        expected_full_ack.insert(3..4);
        assert_eq!(full_ack, expected_full_ack);

        // Communication between the flexicast flow and unicast path.
        fc_pipe.server_control_to_mc_source(now).unwrap();

        // Wait to trigger timeout and retransmission.
        for _ in 0..5 {
            let sleep_duration =
                time::Duration::from_micros(fc_config.fc_ack_delay.into());
            std::thread::sleep(sleep_duration);
            fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();
            fc_pipe.source_send_single(None).unwrap();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            fc_pipe.clients_send().unwrap();
        }

        // Do the retransmission.
        let retr_kind = FcUnicastRetransmission::Delegates(true);
        let uc = &mut fc_pipe.unicast_pipes[0].0.server;
        let now = time::Instant::now();
        fc_pipe
            .mc_channel
            .channel
            .rfc_delegate_streams(uc, now, retr_kind)
            .unwrap();
        fc_pipe.unicast_pipes[0].0.advance().unwrap();

        // Now the receiver can read all streams.
        let client = &fc_pipe.unicast_pipes[0].0.client;
        let mut readables = client.readable().collect::<Vec<_>>();
        readables.sort();
        assert_eq!(readables, vec![3, 7, 11]);

        // New timeout to release all data on the flexicast flow source.
        // let sleep_duration = time::Duration::from_micros(fc_config.fc_ack_delay
        // * 10); std::thread::sleep(sleep_duration);
        // fc_pipe.mc_channel.channel.on_timeout();
        fc_pipe.clients_send().unwrap();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        let p = fc_pipe
            .mc_channel
            .channel
            .paths
            .get(InternalPathId(1))
            .unwrap();
        let sent = p.recovery.get_sent_pkts();
        assert_eq!(sent.len(), 0);

        // Also check that the unicast path released the data packets of the
        // flexicast flow.
        let now = time::Instant::now();
        fc_pipe.server_control_to_mc_source(now).unwrap();
        let uc_path = &mut fc_pipe.unicast_pipes[0].0.server;
        uc_path.on_timeout();
        let p = uc_path.paths.get(InternalPathId(1)).unwrap();
        let sent = p.recovery.get_sent_pkts();
        assert_eq!(sent.len(), 0);
    }
}
