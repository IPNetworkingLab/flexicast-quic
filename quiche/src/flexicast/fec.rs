//! Module handling the Forward Erasure Correction extension for Flexicast.
//! This module primarily exists to ensure forwarding the SOURCE_SYMBOL_ACK
//! frames from the unicast path "to the" flexicast flow, because the unicast
//! paths do not have any state for the Forward Erasure Correction.

use crate::ranges;

/// Flexicast extension of the Forward Erasure Correction extension.
#[derive(Debug)]
pub enum FcFec {
    /// FEC extension for the unicast path.
    UcPath(FcFecUcPath),

    /// Other nodes (Flexicast source, Flexicast receiver), currently not
    /// needing a flexicast FEC structure, or if FEC is not used.
    Undefined,
}

impl FcFec {
    /// Returns a reference to the [`FcFec::UcPath`] with [`FcFecUcPath`]
    /// instance if it is the correct type, `None` otherwise.
    pub fn get_uc_path(&self) -> Option<&FcFecUcPath> {
        if let FcFec::UcPath(ucp) = self {
            Some(ucp)
        } else {
            None
        }
    }

    #[allow(unused)]
    /// Returns a mutable reference to the [`FcFec::UcPath`] with
    /// [`FcFecUcPath`] instance if it is the correct type, `None` otherwise.
    pub fn get_uc_path_mut(&mut self) -> Option<&mut FcFecUcPath> {
        if let FcFec::UcPath(ucp) = self {
            Some(ucp)
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct FcFecUcPath {
    /// Ranges of recovered source symbols for this receiver/unicast path.
    recovered_source_symbols: ranges::RangeSet,
}

impl FcFecUcPath {
    /// Inserts new ranges of recovered source symbols.
    pub fn fc_on_new_source_symbol_ack(&mut self, ranges: &ranges::RangeSet) {
        for range in ranges.iter() {
            self.recovered_source_symbols.insert(range);
        }
    }

    /// Get the list of recovered source symbols ID.
    pub fn fc_get_recovered_esi(&self) -> &ranges::RangeSet {
        &self.recovered_source_symbols
    }
}

#[cfg(test)]
mod tests {
    use super::FcFec;
    use crate::fec::schedulers::FecSchedulerAlgorithm;
    use crate::flexicast::reliable::FcUnicastRetransmission;
    use crate::flexicast::testing::FlexicastPipe;
    use crate::flexicast::FcConfig;
    use crate::ranges::RangeSet;
    use crate::Error;
    use std::time;

    #[test]
    /// Tests that the flexicast flow sends REPAIR packets with a constant FEC
    /// scheduler, and that the receivers can actually recover the losses.
    /// We do this by sending 3 streams, then checking that the source sends a
    /// fourth packet (containing the REPAIR frame), and then check the
    /// statistics.
    ///
    /// The first receivers loses the first stream, the second loses the second.
    /// A single repair symbol is sufficient to recover both losses.
    fn test_fc_fec_send_constant() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            fec: true,
            fec_scheduler: FecSchedulerAlgorithm::Constant,
            ..Default::default()
        };

        // No delayed acknowledgment.
        fc_config.mc_announce_data[0].fc_timer = 0;

        let mut fc_pipe = FlexicastPipe::new(
            2,
            "/tmp/test_fc_fec_send_constant",
            &mut fc_config,
        )
        .unwrap();

        fc_pipe
            .mc_channel
            .channel
            .set_fc_scheduler_algo(fc_config.fec_scheduler);

        let mut losses_0 = RangeSet::default();
        let mut losses_1 = RangeSet::default();
        losses_0.insert(0..1);
        losses_1.insert(1..2);

        fc_pipe
            .source_send_single_stream(true, Some(&losses_0), 3)
            .unwrap();
        fc_pipe
            .source_send_single_stream(true, Some(&losses_1), 7)
            .unwrap();
        fc_pipe.source_send_single_stream(true, None, 11).unwrap();

        // Send the REPAIR frame.
        fc_pipe.source_send_single(None).unwrap();

        // Check that the source actually sent the repair symbol.
        let fec_encoder = fc_pipe.mc_channel.channel.fec_encoder.as_ref();
        assert!(fec_encoder.is_some());
        let fec_encoder = fec_encoder.unwrap();
        assert_eq!(
            fec_encoder.latest_metadata_protected,
            Some(2u64.to_be_bytes())
        );
        assert_eq!(fec_encoder.get_nb_sent_repair(), 1);

        // Both receivers managed to recover the losses.
        let mut buf = [0u8; 500];
        for recv_id in 0..2 {
            for stream_idx in 0..3 {
                assert_eq!(
                    fc_pipe.unicast_pipes[recv_id]
                        .0
                        .client
                        .stream_recv(stream_idx * 4 + 3, &mut buf[..]),
                    Ok((300, true))
                );
            }
        }

        // The first receiver must send a SOURCE_SYMBOL_ACK frame for range 0..1.
        let fec_decoder = fc_pipe.unicast_pipes[0]
            .0
            .client
            .fec_decoder
            .as_ref()
            .unwrap();
        assert_eq!(fec_decoder.recovered_symbols_need_ack, losses_0);

        // The second receiver must send a SOURCE_SYMBOL_ACK frame for range 1..2.
        let fec_decoder = fc_pipe.unicast_pipes[1]
            .0
            .client
            .fec_decoder
            .as_ref()
            .unwrap();
        assert_eq!(fec_decoder.recovered_symbols_need_ack, losses_1);

        // The Unicast path have state for Flexicast FEC.
        for (pipe, ..) in fc_pipe.unicast_pipes.iter() {
            assert!(matches!(
                pipe.server.flexicast.as_ref().unwrap().fc_fec,
                FcFec::UcPath(_)
            ))
        }

        // The receivers send the SOURCE_SYMBOL_ACK frames to their unicast
        // path. The receivers must not directly process these frames as
        // they do not have any FEC state.
        assert_eq!(fc_pipe.clients_send(), Ok(()));

        // The unicast paths have updated state for the recovered symbols.
        for (id, ranges_recovered) in (0..2).zip([&losses_0, &losses_1]) {
            let fc_fec = &fc_pipe.unicast_pipes[id]
                .0
                .server
                .flexicast
                .as_ref()
                .unwrap()
                .fc_fec;
            if let FcFec::UcPath(up_fec) = fc_fec {
                assert_eq!(&up_fec.recovered_source_symbols, ranges_recovered);
            } else {
                assert!(false);
            }
        }

        fc_pipe
            .unicast_pipes
            .iter_mut()
            .for_each(|(pipe, ..)| pipe.advance().unwrap());

        // The flexicast flow does not need to delegate the lost STREAM frames
        // because they were recovered through FEC. Because the last
        // STREAM frame and the REPAIR frames were received, a time-based loss
        // detection is enough.
        let sleep_duration = time::Duration::from_millis(10);
        for _ in 0..3 {
            std::thread::sleep(sleep_duration);
            fc_pipe.mc_channel.channel.on_timeout();
            fc_pipe
                .mc_channel
                .channel
                .send_ack_eliciting_on_path_with_path_id(1)
                .unwrap();
            fc_pipe.source_send_single(None).unwrap();
            fc_pipe.clients_send().unwrap();
            let now = time::Instant::now();
            fc_pipe.server_control_to_mc_source(now).unwrap();
        }

        fc_pipe
            .source_delegates_streams_direct(
                time::Instant::now(),
                FcUnicastRetransmission::Delegates(true),
            )
            .unwrap();

        // No unicast retransmission.
        let mut buf = [0u8; 1500];
        for id in 0..2 {
            let server = &mut fc_pipe.unicast_pipes[id].0.server;
            assert_eq!(server.send(&mut buf[..]), Err(Error::Done));
        }
    }

    #[test]
    /// Tests that a flexicast receiver can join later a Flexicast flow with
    /// Forward Erasure Correction, despite the FEC window being "advanced" for
    /// some time.
    fn test_fc_fec_late_receiver() {
        let mut fc_config = FcConfig {
            probe_mc_path: true,
            fec: true,
            fec_scheduler: FecSchedulerAlgorithm::Constant,
            ..Default::default()
        };

        // No delayed acknowledgment.
        fc_config.mc_announce_data[0].fc_timer = 0;

        let mut fc_pipe = FlexicastPipe::new(
            2,
            "/tmp/test_fc_fec_late_receiver",
            &mut fc_config,
        )
        .unwrap();

        let nb_streams = 3000;

        // Send a lot of streams to ensure that we go above the initial FEC window.
        let mut stream_id = 3;
        for _ in 0..nb_streams {
            fc_pipe.source_send_single_stream(true, None, stream_id).unwrap();
            stream_id += 4;

            // To allow receivers to send the PATH_ACK and SOURCE_SYMBOL_ACK frames.
            let now = time::Instant::now();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            // fc_pipe.unicast_pipes.iter_mut().for_each(|(p, ..)| p.advance().unwrap());
            fc_pipe.clients_send().unwrap();
            let now = time::Instant::now();
            fc_pipe.server_control_to_mc_source(now).unwrap();
        }

        // The first two receivers get all the streams.
        let mut recv_stream_id = 3;
        let mut buf = [0u8; 1500];
        for _ in 0..nb_streams {
            for recv_id in 0..2 {
                let recv = &mut fc_pipe.unicast_pipes[recv_id].0.client;
                assert_eq!(recv.stream_recv(recv_stream_id, &mut buf[..]), Ok((300, true)));
            }
            recv_stream_id += 4;
        }

        // Add a new receiver in the flexicast flow.
        let new_client = FlexicastPipe::setup_client(
                &mut fc_pipe.mc_channel,
                &fc_config,
            )
            .unwrap();

        fc_pipe.unicast_pipes.push(new_client);

        // Send new more streams to check that the added receiver can receive source symbols with a start offset.
        for _ in 0..nb_streams {
            fc_pipe.source_send_single_stream(true, None, stream_id).unwrap();
            stream_id += 4;

            // To allow receivers to send the PATH_ACK and SOURCE_SYMBOL_ACK frames.
            let now = time::Instant::now();
            fc_pipe.server_control_to_mc_source(now).unwrap();
            // fc_pipe.unicast_pipes.iter_mut().for_each(|(p, ..)| p.advance().unwrap());
            fc_pipe.clients_send().unwrap();
            let now = time::Instant::now();
            fc_pipe.server_control_to_mc_source(now).unwrap();
        }

        // The three receivers get all the subsequent streams.
        for _ in 0..nb_streams {
            for recv_id in 0..3 {
                let recv = &mut fc_pipe.unicast_pipes[recv_id].0.client;
                assert_eq!(recv.stream_recv(recv_stream_id, &mut buf[..]), Ok((300, true)));
            }
            recv_stream_id += 4;
        }
    }
}
