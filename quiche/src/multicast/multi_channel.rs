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

use networkcoding::vandermonde_lc::decoder::VLCDecoder;

use super::McClientStatus;
use super::McError;
use super::McRole;
use crate::Connection;
use crate::Error;
use crate::Result;

impl Connection {
    /// Joins another Flexicast channel while already beeing in one.
    /// This internally leaves the first channel and joined the second to enable
    /// 1-RTT re-join, but only if both used implicit path negotiation.
    pub fn fc_change_channel(
        &mut self, leave_on_timeout: bool, fc_chan_id: &[u8],
    ) -> Result<McClientStatus> {
        // Only allow to change the flexicast channel if the client is already
        // listening to one, and both channels don't do path probing.
        let multicast = match self.multicast.as_mut() {
            Some(v) => v,
            None => return Err(Error::Multicast(McError::McDisabled)),
        };

        if multicast.mc_role != McRole::Client(McClientStatus::ListenMcPath(true)) &&
            multicast.mc_role !=
                McRole::ServerUnicast(McClientStatus::ListenMcPath(true))
        {
            return Err(Error::Multicast(McError::McInvalidRole(
                multicast.mc_role,
            )));
        }

        let old_idx = multicast
            .fc_chan_id
            .as_ref()
            .map(|(_, idx)| *idx)
            .ok_or(Error::Multicast(McError::McPath))?;

        let new_idx = multicast
            .mc_announce_data
            .iter()
            .position(|announce| &announce.channel_id == fc_chan_id)
            .ok_or(Error::Multicast(McError::McAnnounce))?;

        // Only bother if both channels do not use path probing to use single RTT.
        if multicast.mc_announce_data[old_idx].probe_path ||
            multicast.mc_announce_data[new_idx].probe_path
        {
            return Err(Error::Multicast(McError::FcChangeChan));
        }

        // Get the old and new space ID.
        // FC-TODO: not sure this will work because we infer the new space id.
        let old_fc_space_id = multicast
            .get_mc_space_id()
            .ok_or(Error::Multicast(McError::McPath))?;
        let new_fc_space_id = old_fc_space_id + 1;

        // Remove all FEC state.
        let fec_symbol_size = self.fec_decoder.symbol_size();
        let fec_window_size = self.fec_window_size;
        self.fec_decoder = networkcoding::Decoder::VLC(VLCDecoder::new(
            fec_symbol_size,
            fec_window_size,
        ));

        // Update the Flexicast channel ID.
        multicast.fc_chan_id = Some((fc_chan_id.to_vec(), new_idx));
        multicast.set_mc_space_id(new_fc_space_id);

        multicast.mc_leave_on_timeout = leave_on_timeout;
        multicast.update_client_state(
            super::McClientAction::Change,
            Some(new_fc_space_id as u64),
        )
    }
}

#[cfg(test)]
pub mod testing {
    use ring::rand::SecureRandom;
    use ring::rand::SystemRandom;

    use crate::multicast::testing::get_test_mc_announce_data;
    use crate::multicast::testing::MulticastPipe;
    use crate::multicast::FcConfig;
    use crate::multicast::McAnnounceData;
    use crate::multicast::McError;
    use crate::multicast::MulticastConnection;
    use crate::testing::Pipe;
    use crate::ConnectionId;
    use crate::Error;
    use crate::Result;
    use std::net::IpAddr;
    use std::net::SocketAddr;

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

        /// Generates a new [`MultiFcPipe`] with McAnnounceData asking for
        /// stream resrt and `nb` instances.
        pub fn new_with_stream_reset(
            keylog_filename: &str, nb: u8,
        ) -> Result<Self> {
            let fc_configs = (0..nb)
                .map(|idx| {
                    let mut mc_announce_data = get_test_mc_announce_data_idx(idx);
                    mc_announce_data.reset_stream_on_join = true;
                    FcConfig {
                        mc_announce_data: vec![mc_announce_data],
                        probe_mc_path: true,
                        authentication:
                            crate::multicast::authentication::McAuthType::None,
                        ..FcConfig::default()
                    }
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

        /// Moves client `i` of channel `from` to channel `to`.
        /// The client leaves the first channel and performs the new path
        /// probing to join the second channel.
        pub fn move_client(
            &mut self, i: usize, from: usize, to: usize, now: std::time::Instant,
            random: &SystemRandom,
        ) -> Result<()> {
            let (mut pipe, sock_from, sock_to) =
                self.fc_pipes[from].unicast_pipes.remove(i);

            // Leave the channel.
            pipe.client.mc_leave_channel()?;
            pipe.advance()?;

            // Remove the path.
            pipe.client.abandon_path(
                sock_from,
                sock_to,
                0,
                b"change-channel".to_vec(),
            )?;

            pipe.advance()?;

            // Give the new key to the server.
            let secret = self.fc_pipes[to].mc_channel.master_secret.clone();
            let algo = self.fc_pipes[to].mc_channel.algo;
            pipe.server.multicast.as_mut().unwrap().mc_announce_data[to]
                .fc_channel_secret = Some(secret);
            pipe.server.multicast.as_mut().unwrap().mc_announce_data[to]
                .fc_channel_algo = Some(algo);

            // Join the other channel.
            let fc_chan_id =
                pipe.client.multicast.as_ref().unwrap().mc_announce_data[to]
                    .channel_id
                    .to_owned();
            pipe.client.mc_join_channel(false, Some(&fc_chan_id))?;
            pipe.advance()?;

            // Just to be sure, the server communicates with the flexicast source.
            let fc_chan = &mut self.fc_pipes[to].mc_channel.channel;
            pipe.server.uc_to_mc_control(fc_chan, now)?;

            // And again a small pipe advance to be sure.
            pipe.advance()?;

            // The server adds the connection IDs of the multicast
            // channel.
            let mut scid = [0; 16];
            random.fill(&mut scid[..]).unwrap();
            let scid = ConnectionId::from_ref(&scid);
            let mut reset_token = [0; 16];
            random.fill(&mut reset_token).unwrap();
            let reset_token = u128::from_be_bytes(reset_token);
            pipe.server
                .new_source_cid(&scid, reset_token, true)
                .unwrap();

            pipe.advance()?;

            let scid = ConnectionId::from_ref(&fc_chan_id);
            pipe.client.add_mc_cid(&scid)?;
            pipe.advance()?;

            let mc_announce =
                pipe.client.multicast.as_ref().unwrap().mc_announce_data[to]
                    .clone();
            let server_addr =
                SocketAddr::new(IpAddr::V4(mc_announce.source_ip.into()), 4567);
            let client_addr = SocketAddr::new(
                IpAddr::V4(mc_announce.group_ip.into()),
                mc_announce.udp_port,
            );

            // Path probe for the new channel.
            pipe.client.create_mc_path(client_addr, server_addr, true)?;
            let path_id = pipe
                .client
                .paths
                .path_id_from_addrs(&(client_addr, server_addr))
                .expect("no such path");
            pipe.client
                .multicast
                .as_mut()
                .unwrap()
                .set_mc_space_id(path_id);

            pipe.advance()?;

            self.add_client((pipe, client_addr, server_addr), to)
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
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::time;

    use ring::rand::SecureRandom;
    use ring::rand::SystemRandom;
    use testing::MultiFcPipe;

    use crate::multicast::testing::MulticastPipe;
    use crate::multicast::FcConfig;
    use crate::multicast::MulticastConnection;
    use crate::testing::emit_flight;
    use crate::testing::process_flight;
    use crate::ConnectionId;

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

            // The new client has the list of all channels, even though it joined
            // only one.
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

    #[test]
    /// Tests that a client can switch from a flexicast channel to another by
    /// updating the flexicast space id.
    fn test_change_fc_chan_space_id() {
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
            mc_announce_to_join: 1, // Joins the second channel.
            ..FcConfig::default()
        };
        let new_client = MulticastPipe::setup_client(
            &mut mfc_pipe.fc_pipes.get_mut(1).unwrap().mc_channel,
            &fc_config,
            &random,
        )
        .unwrap();
        mfc_pipe.add_client(new_client, 1).unwrap();

        // The multicast space id is 1 (i.e., this is the first path created)...
        let (pipe, ..) = &mut mfc_pipe.fc_pipes[1].unicast_pipes[0];
        // ... for the client...
        let mc_space_id = pipe.client.multicast.as_ref().unwrap().mc_space_id;
        assert_eq!(mc_space_id, Some(1));

        // ... and the server.
        let mc_space_id = pipe.server.multicast.as_ref().unwrap().mc_space_id;
        assert_eq!(mc_space_id, Some(1));

        // The client receives data from the second channel.
        let fc_pipe = &mut mfc_pipe.fc_pipes[1];
        assert_eq!(fc_pipe.source_send_single_stream(true, None, 3), Ok(348));
        let client = &mut fc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![3]);
        let mut buf = [0; 500];
        assert_eq!(client.stream_recv(3, &mut buf), Ok((300, true)));

        // The client leaves the second channel and joins the first one.
        let now = time::Instant::now();
        assert_eq!(mfc_pipe.move_client(0, 1, 0, now, &random), Ok(()));

        // The multicast space id changed from 1 to 2 (because new path).
        let (pipe, ..) = &mut mfc_pipe.fc_pipes[0].unicast_pipes[0];
        // ... for the client...
        let mc_space_id = pipe.client.multicast.as_ref().unwrap().mc_space_id;
        assert_eq!(mc_space_id, Some(2));

        // ... and the server.
        let mc_space_id = pipe.server.multicast.as_ref().unwrap().mc_space_id;
        assert_eq!(mc_space_id, Some(2));

        // The client can receive data from the first channel now.
        let fc_pipe = &mut mfc_pipe.fc_pipes[0];
        assert_eq!(fc_pipe.source_send_single_stream(true, None, 7), Ok(348));
        let client = &mut fc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![7]);
        let mut buf = [0; 500];
        assert_eq!(client.stream_recv(7, &mut buf), Ok((300, true)));
    }

    #[test]
    /// Tests a client joining a first channel and receiving some data. Then it
    /// joins another channel and receives new stream data with stream IDs
    /// similar to previously received streams. Because the channel
    /// advertisement indicated that the client should reset its stream state on
    /// joining the new channel, it should accept the data.
    fn test_change_fc_chan_reset_stream_state() {
        let mut mfc_pipe = MultiFcPipe::new_with_stream_reset(
            "/tmp/test_change_fc_chan_reset_stream_state",
            3,
        )
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
            mc_announce_to_join: 1, // Joins the second channel.
            ..FcConfig::default()
        };
        let new_client = MulticastPipe::setup_client(
            &mut mfc_pipe.fc_pipes.get_mut(1).unwrap().mc_channel,
            &fc_config,
            &random,
        )
        .unwrap();
        mfc_pipe.add_client(new_client, 1).unwrap();

        // The client receives data from the second channel.
        let fc_pipe = &mut mfc_pipe.fc_pipes[1];
        let first_data = b"first stream data";
        fc_pipe
            .mc_channel
            .channel
            .stream_send(3, first_data, true)
            .unwrap();
        assert!(fc_pipe.source_send_single(None).is_ok());
        let client = &mut fc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![3]);
        let mut buf = [0; 500];
        assert_eq!(
            client.stream_recv(3, &mut buf),
            Ok((first_data.len(), true))
        );
        assert_eq!(&buf[..first_data.len()], first_data);

        // The client leaves the second channel and joins the first one.
        let now = time::Instant::now();
        assert_eq!(mfc_pipe.move_client(0, 1, 0, now, &random), Ok(()));

        // The multicast space id changed from 1 to 2 (because new path).
        let (pipe, ..) = &mut mfc_pipe.fc_pipes[0].unicast_pipes[0];
        // ... for the client...
        let mc_space_id = pipe.client.multicast.as_ref().unwrap().mc_space_id;
        assert_eq!(mc_space_id, Some(2));

        // ... and the server.
        let mc_space_id = pipe.server.multicast.as_ref().unwrap().mc_space_id;
        assert_eq!(mc_space_id, Some(2));

        // The client can receive data from the first channel now.
        // It receives data using the same stream ID (3) as in the first channel
        // but it's ok.
        let fc_pipe = &mut mfc_pipe.fc_pipes[0];
        let second_data = b"second piece of information";
        fc_pipe
            .mc_channel
            .channel
            .stream_send(3, second_data, true)
            .unwrap();
        assert_eq!(fc_pipe.source_send_single(None), Ok(75));
        let client = &mut fc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![3]);
        let mut buf = [0; 500];
        assert_eq!(
            client.stream_recv(3, &mut buf),
            Ok((second_data.len(), true))
        );
        assert_eq!(&buf[..second_data.len()], second_data);
    }

    #[test]
    /// Client joining another flexicast channel.
    /// This test evaluates that the client joins another channel and the
    /// negotiation is performed in a single round-trip-time to ensure that the
    /// client joins fastly the other channel.
    /// The single RTT is only possible if the client did not perform mc_path
    /// probing and only used the implicit path negotiation because this is a
    /// multicast address.
    fn test_change_fc_chan_single_rtt() {
        let mut mfc_pipe = MultiFcPipe::new_with_stream_reset(
            "/tmp/test_change_fc_chan_single_rtt",
            3,
        )
        .unwrap();
        let random = SystemRandom::new();

        // Add a new client that will listen to the second channel.
        let fc_config = FcConfig {
            mc_announce_data: mfc_pipe
                .fc_configs
                .iter()
                .map(|f| f.mc_announce_data[0].clone())
                .collect(),
            probe_mc_path: false,
            mc_announce_to_join: 1, // Joins the second channel.
            ..FcConfig::default()
        };
        let new_client = MulticastPipe::setup_client(
            &mut mfc_pipe.fc_pipes.get_mut(1).unwrap().mc_channel,
            &fc_config,
            &random,
        )
        .unwrap();
        mfc_pipe.add_client(new_client, 1).unwrap();

        // The client receives data from the second channel.
        let fc_pipe = &mut mfc_pipe.fc_pipes[1];
        let first_data = b"first stream data";
        fc_pipe
            .mc_channel
            .channel
            .stream_send(3, first_data, true)
            .unwrap();
        assert!(fc_pipe.source_send_single(None).is_ok());
        let client = &mut fc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![3]);
        let mut buf = [0; 500];
        assert_eq!(
            client.stream_recv(3, &mut buf),
            Ok((first_data.len(), true))
        );
        assert_eq!(&buf[..first_data.len()], first_data);

        // The client changes the flexicast channel.
        let (mut pipe, sock_from, sock_to) = fc_pipe.unicast_pipes.remove(0);

        let to = 0; // Index of the channel to join.
        let fc_chan_id = pipe.client.multicast.as_ref().unwrap().mc_announce_data
            [to]
            .channel_id
            .to_owned();
        pipe.client.fc_change_channel(false, &fc_chan_id).unwrap();
        pipe.client
            .abandon_path(sock_from, sock_to, 0, b"change-channel".to_vec())
            .unwrap();

        // Set the source connection ID.
        let scid = ConnectionId::from_ref(&fc_chan_id);
        pipe.client.add_mc_cid(&scid).unwrap();

        // And already probe the new path.
        let mc_announce =
            pipe.client.multicast.as_ref().unwrap().mc_announce_data[to].clone();
        let server_addr =
            SocketAddr::new(IpAddr::V4(mc_announce.source_ip.into()), 4567);
        let client_addr = SocketAddr::new(
            IpAddr::V4(mc_announce.group_ip.into()),
            mc_announce.udp_port,
        );

        // The client sends the information to the server.
        let flight = emit_flight(&mut pipe.client).unwrap();
        process_flight(&mut pipe.server, flight).unwrap();

        // Server gives the keys.
        let secret = mfc_pipe.fc_pipes[to].mc_channel.master_secret.clone();
        let algo = mfc_pipe.fc_pipes[to].mc_channel.algo;
        pipe.server.multicast.as_mut().unwrap().mc_announce_data[to]
            .fc_channel_secret = Some(secret);
        pipe.server.multicast.as_mut().unwrap().mc_announce_data[to]
            .fc_channel_algo = Some(algo);

        // Just to be sure, the server communicates with the flexicast source.
        let now = std::time::Instant::now();
        let fc_chan = &mut mfc_pipe.fc_pipes[to].mc_channel.channel;
        pipe.server.uc_to_mc_control(fc_chan, now).unwrap();

        // The server adds the connection IDs of the multicast channel.
        let mut scid = [0; 16];
        let random = SystemRandom::new();
        random.fill(&mut scid[..]).unwrap();
        let scid = ConnectionId::from_ref(&scid);
        let mut reset_token = [0; 16];
        random.fill(&mut reset_token).unwrap();
        let reset_token = u128::from_be_bytes(reset_token);
        pipe.server
            .new_source_cid(&scid, reset_token, true)
            .unwrap();

        // Server sends data to the client.
        let flight = emit_flight(&mut pipe.server).unwrap();
        process_flight(&mut pipe.client, flight).unwrap();

        pipe.client
            .create_mc_path(client_addr, server_addr, false)
            .unwrap();
        let path_id = pipe
            .client
            .paths
            .path_id_from_addrs(&(client_addr, server_addr))
            .expect("no such path");
        pipe.client
            .multicast
            .as_mut()
            .unwrap()
            .set_mc_space_id(path_id);

        // Add to the pipe.
        mfc_pipe
            .add_client((pipe, client_addr, server_addr), 0)
            .unwrap();

        // Now the client is in the second channel.
        let (pipe, ..) = &mut mfc_pipe.fc_pipes[0].unicast_pipes[0];
        // ... for the client...
        let mc_space_id = pipe.client.multicast.as_ref().unwrap().mc_space_id;
        assert_eq!(mc_space_id, Some(2));

        // ... and the server.
        let mc_space_id = pipe.server.multicast.as_ref().unwrap().mc_space_id;
        assert_eq!(mc_space_id, Some(2));

        // The client can receive data from the first channel now.
        // It receives data using the same stream ID (3) as in the first channel
        // but it's ok.
        let fc_pipe = &mut mfc_pipe.fc_pipes[0];
        let second_data = b"second piece of information";
        fc_pipe
            .mc_channel
            .channel
            .stream_send(3, second_data, true)
            .unwrap();
        assert_eq!(fc_pipe.source_send_single(None), Ok(75));
        let client = &mut fc_pipe.unicast_pipes[0].0.client;
        let readables: Vec<_> = client.readable().collect();
        assert_eq!(readables, vec![3]);
        let mut buf = [0; 500];
        assert_eq!(
            client.stream_recv(3, &mut buf),
            Ok((second_data.len(), true))
        );
        assert_eq!(&buf[..second_data.len()], second_data);
    }
}
