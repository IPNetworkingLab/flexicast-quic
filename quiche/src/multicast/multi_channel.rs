//! This module extends Flexicast QUIC by providing methods and tests to allow
//! multiple parallel flexicast groups simultaneously.
//!
//! It does so by having a Flexicast source connection per channel (e.g., at a
//! given bit-rate). This is not the most efficient way regarding memory
//! consumption, as each instance must store on its own the same application
//! stream data. However, it is WAY more easy to implement and more efficient
//! regarding performance because it will be possible to run each instance in
//! its own thread instead of having everythin in the same [`crate::Connection`]
//! instance.

#[cfg(test)]
pub mod testing {
    use crate::multicast::testing::get_test_mc_announce_data;
    use crate::multicast::testing::MulticastPipe;
    use crate::multicast::FcConfig;
    use crate::multicast::McAnnounceData;
    use crate::multicast::McError;
    use crate::testing::Pipe;
    use crate::Error;
    use crate::Result;
    use core::net::SocketAddr;

    /// Extension of the [`crate::multicast::testing::MulticastPipe`].
    /// It contains several Flexicast pipes, one for each MC_ANNOUNCE frame, and
    /// a vector of unatached clients. The `unicast_pipes` of the
    /// [`crate::multicast::testing::MulticastPipe`] now only contains the
    /// clients that are attached to this specific Flexicast pipe.
    pub struct MultiFcPipe {
        /// Flexicast pipes.
        pub fc_pipes: Vec<MulticastPipe>,

        /// Flexicast pipe configurations, in the same index as `fc_pipes`.
        pub fc_configs: Vec<FcConfig>,
    }

    impl MultiFcPipe {
        /// Generates a new instance of the structure with the mentionned
        /// flexicast configurations.
        /// Each [`super::super::testing::FcConfig`] will generate a new
        /// flexicast pipe with no attached client. Clients will receive
        /// an MC_ANNOUNCE frame for each creates flexicast pipe, but won't be
        /// attached to any of them.
        pub fn new(
            keylog_filename: &str, mut fc_configs: Vec<FcConfig>,
        ) -> Result<Self> {
            let fc_pipes = fc_configs
                .iter_mut()
                .enumerate()
                .map(|(i, fc_config)| {
                    MulticastPipe::new_reliable(
                        0,
                        &format!("{keylog_filename}_{i}.txt"),
                        fc_config,
                    )
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(Self {
                fc_pipes,
                fc_configs,
            })
        }

        /// Generates a new [`MultiFcPipe`] with default McAnnounceData and `nb`
        /// instances.
        pub fn new_defaults(keylog_filename: &str, nb: u8) -> Result<Self> {
            let fc_configs = (0..nb)
                .map(|idx| FcConfig {
                    mc_announce_data: vec![get_test_mc_announce_data_idx(idx)],
                    probe_mc_path: true,
                    authentication:
                        crate::multicast::authentication::McAuthType::None,
                    ..FcConfig::default()
                })
                .collect();

            MultiFcPipe::new(keylog_filename, fc_configs)
        }

        /// Adds a new client in the flexicast pipe indexed by `idx`.
        ///
        /// Returns an error if the index of the flexicast pipe is out of range.
        pub fn add_client(
            &mut self, client: (Pipe, SocketAddr, SocketAddr), idx: usize,
        ) -> Result<()> {
            self.fc_pipes
                .get_mut(idx)
                .ok_or(Error::Multicast(McError::McPipe))?
                .unicast_pipes
                .push(client);
            Ok(())
        }
    }

    /// Simple McAnnounceData for testing the flexicast extension only. It is
    /// unique depending on the given index.
    fn get_test_mc_announce_data_idx(idx: u8) -> McAnnounceData {
        let mut mc_announce_data = get_test_mc_announce_data();
        mc_announce_data.channel_id = vec![0xff, 0xdd, 0xee, idx];
        mc_announce_data.group_ip =
            std::net::Ipv4Addr::new(224, 0, 0, 1 + idx).octets();
        mc_announce_data.udp_port += idx as u16;
        mc_announce_data
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use testing::MultiFcPipe;

    use crate::multicast::testing::MulticastPipe;
    use crate::multicast::FcConfig;
    use crate::multicast::MulticastConnection;

    use super::*;

    #[test]
    /// The unicast server transmits several MC_ANNOUNCE frames, one for each
    /// possible flexicast channel. The client receives them all. It then
    /// joins one of them, correctly.
    fn test_fc_multiple_announces() {
        for idx_to_join in 0..3 {
            let mut mfc_pipe =
                MultiFcPipe::new_defaults("/tmp/test_fc_multiple_announces", 3)
                    .unwrap();
            let random = SystemRandom::new();

            // Add a new client that will listen to the second channel.
            let fc_config = FcConfig {
                mc_announce_data: mfc_pipe
                    .fc_configs
                    .iter()
                    .map(|f| f.mc_announce_data[0].clone())
                    .collect(),
                probe_mc_path: true,
                mc_announce_to_join: idx_to_join,
                ..FcConfig::default()
            };
            let new_client = MulticastPipe::setup_client(
                &mut mfc_pipe.fc_pipes.get_mut(idx_to_join).unwrap().mc_channel,
                &fc_config,
                &random,
            )
            .unwrap();

            // The new client has the list of all channels, even though it joined only
            // one.
            let mc_announces = &new_client
                .0
                .client
                .get_multicast_attributes()
                .unwrap()
                .mc_announce_data;
            assert_eq!(mc_announces.len(), 3);
            for i in 0..3 {
                assert_eq!(
                    mc_announces[i].channel_id,
                    mfc_pipe.fc_configs[i].mc_announce_data[0].channel_id
                );
                assert_eq!(
                    mc_announces[i].group_ip,
                    mfc_pipe.fc_configs[i].mc_announce_data[0].group_ip
                );
                assert_eq!(
                    mc_announces[i].udp_port,
                    mfc_pipe.fc_configs[i].mc_announce_data[0].udp_port
                );
            }

            // Since the client joined the second channel, we add it to the
            // corresponding flexicast pipe.
            mfc_pipe.add_client(new_client, idx_to_join).unwrap();

            // And the client start receiving data.
            let fc_pipe = &mut mfc_pipe.fc_pipes[idx_to_join];
            assert_eq!(fc_pipe.source_send_single_stream(true, None, 3), Ok(348));

            let client = &mut fc_pipe.unicast_pipes[0].0.client;
            let readables: Vec<_> = client.readable().collect();
            assert_eq!(readables, vec![3]);
            let mut buf = [0; 500];
            assert_eq!(client.stream_recv(3, &mut buf), Ok((300, true)));
        }
    }
}
