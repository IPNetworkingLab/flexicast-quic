//! Handles the signatures for authentication of the multicast source.
use crate::crypto::mc_crypto::McVerifySymSign;
use crate::multicast::McClientId;
use crate::multicast::MulticastError;
use crate::multicast::MulticastRole;
use crate::packet::Epoch;
use crate::packet::MAX_PKT_NUM_LEN;
use crate::Connection;
use crate::Error;
use crate::Result;

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::str::FromStr;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
/// Authentication type used for the multicast channel.
pub enum McAuthType {
    /// Use asymmetric signature at the end of each Multicast QUIC packet.
    AsymSign,

    /// Create a new Multicast QUIC packet on the authentication path containing
    /// an MC_AUTH frame with the list of symetric signatures, using the keys of
    /// the unicast connection for all clients of the multicast channel.
    SymSign,

    /// Dynamically changes the signature process.
    /// Currently only supports symetric -> asymmetric.
    /// The inner value is the threshold number of receivers.
    Dynamic(u32),

    /// No authentication used.
    None,

    /// Add an MC_ASYM frame at the end of the QUIC packet. This frame contains
    /// the asymmetric signature of either a whole stream or other control
    /// frames. The frame is added in an MCQUIC packet if there is a STREAM
    /// frame which is now complete (i.e., the STREAM frame is the last frame
    /// that will be send for this stream, excluding possible retransmission).
    StreamAsym,
}

impl TryFrom<u64> for McAuthType {
    type Error = crate::Error;

    fn try_from(v: u64) -> Result<Self> {
        match v {
            0 => Ok(Self::AsymSign),
            1 => Ok(Self::SymSign),
            2 => Ok(Self::Dynamic(20)),
            3 => Ok(Self::None),
            4 => Ok(Self::StreamAsym),
            _ => Err(Error::Multicast(MulticastError::McInvalidAuth)),
        }
    }
}

impl From<McAuthType> for u64 {
    fn from(v: McAuthType) -> Self {
        match v {
            McAuthType::AsymSign => 0,
            McAuthType::SymSign => 1,
            McAuthType::Dynamic(_) => 2,
            McAuthType::None => 3,
            McAuthType::StreamAsym => 4,
        }
    }
}

impl FromStr for McAuthType {
    type Err = Error;

    /// Converts a string to `McAuthType`.
    ///
    /// If `name` is not valid,
    /// `Error::Multicast(MulticastError::McInvalidAuth)` is returned.
    fn from_str(name: &str) -> Result<Self> {
        match name {
            "asymmetric" => Ok(McAuthType::AsymSign),
            "symmetric" => Ok(McAuthType::SymSign),
            "none" => Ok(McAuthType::None),
            "stream" => Ok(McAuthType::StreamAsym),
            _ => Err(Error::Multicast(MulticastError::McInvalidAuth)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Structure containing symetric signatures for each of the multicast clients
/// for a given packet number.
pub struct McSymSignature {
    /// Client ID given by the multicast source to the client.
    /// The client uses this value instead of the Connection ID because it is
    /// encoded in less bytes.
    pub mc_client_id: u64,

    /// AEAD tag using information from the unicast session.
    pub sign: Vec<u8>,
}

/// Multicast authentication.
/// Exposes asymmetric and symetric signatures.
pub trait McAuthentication {
    /// Generates a signature on the given QUIC packet.
    /// The caller is responsible to give a mutable slice
    /// with enough space to add the signature.
    /// Otherwise, the method returns an Error [`BufferTooShort`].
    /// Only available for the multicast source.
    /// On success, returns the additional number of bytes used by the
    /// signature. The signature is added at the end of the data in the
    /// buffer.
    fn mc_sign_asym(&self, buf: &mut [u8], data_len: usize) -> Result<usize>;

    /// Sign a slice using the session key.
    fn mc_sign_sym_slice(&self, buf: &[u8], pn: u64) -> Result<Vec<u8>>;

    /// Verify an asymmetric signature.
    ///
    /// Returns the length of the buffer payload, i.e., without the signature.
    /// The signature is assumed to be in the last bytes of the buffer.
    fn mc_verify_asym(&self, buf: &[u8]) -> Result<usize>;

    /// Verify a symmetric signature given the packet slice and its packet
    /// number.
    ///
    /// Requires that the client has a valid multicast client ID.
    fn mc_verify_sym(&mut self, buf: &[u8], pn: u64) -> Result<()>;

    /// Receive a multicast data packet that is authenticated with
    /// [`McAuthType::SymSign`].
    ///
    /// This function decrypts the header of the packet and retrieves the packet
    /// number. This packet decryption is not performed on the original
    /// packet. Hence, it must be performed again by the library. Even this is
    /// not optimal (because we decrypt the packet header twice) and it requires
    /// some code dupplication, it simplifies a lot the processing as there
    /// is no requirement to further change the quiche library :-).
    /// Concerning the code duplication, it is a modified version of
    /// [`crate::packet::decrypt_hdr`].
    /// // We assume having only valid packets, i.e., this is a
    /// [`crate::packet::Type::Short`] header.
    fn mc_get_pn(&self, buf: &[u8]) -> Result<u64>;

    /// Returns an immutable reference to the client HashSet containing the
    /// packet number of packets that can be authenticated with the symmetric
    /// tag.
    ///
    /// This is used to fasten the processing of non-authenticated packets in
    /// the application. Returns an error if the role is invalid.
    fn mc_get_client_auth_tags(&self) -> Result<HashSet<u64>>;
}

impl McAuthentication for Connection {
    fn mc_sign_asym(&self, buf: &mut [u8], data_len: usize) -> Result<usize> {
        if let Some(multicast) = self.multicast.as_ref() {
            if multicast.mc_role != MulticastRole::ServerMulticast {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    multicast.mc_role,
                )));
            }

            // Asymmetric signature on the last bytes of the packet.
            if let Some(private_key) = multicast.mc_private_key.as_ref() {
                let signature = private_key.sign(&buf[..data_len]);
                let signature_len = signature.as_ref().len();
                buf[data_len..data_len + signature_len]
                    .copy_from_slice(signature.as_ref());

                Ok(signature_len)
            } else {
                Err(Error::Multicast(MulticastError::McInvalidAsymKey))
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }

    fn mc_sign_sym_slice(&self, buf: &[u8], pn: u64) -> Result<Vec<u8>> {
        let aead = self
            .pkt_num_spaces
            .crypto(Epoch::Application)
            .crypto_seal
            .as_ref()
            .unwrap();
        let tag_len = aead.alg().tag_len();
        // Copy like a shlag.
        let mut my_buf_vec = vec![0u8; buf.len() + tag_len];
        my_buf_vec[..buf.len()].copy_from_slice(buf);
        let space_id = self.multicast.as_ref().unwrap().mc_space_id.unwrap();
        let hdr = [0u8; 0];
        let mut my_buf = octets::OctetsMut::with_slice(&mut my_buf_vec);

        let written = if self.is_server {
            aead.seal_with_u64_counter(
                space_id as u32,
                pn,
                hdr.as_ref(),
                my_buf.as_mut(),
                buf.len(),
                None,
            )?
        } else {
            let open = &self
                .pkt_num_spaces
                .crypto(Epoch::Application)
                .crypto_open
                .as_ref()
                .unwrap();
            open.mc_seal_with_u64_counter(
                space_id as u32,
                pn,
                hdr.as_ref(),
                my_buf.as_mut(),
                buf.len(),
                None,
            )?
        };

        Ok(my_buf_vec[buf.len()..written].to_vec())
    }

    #[inline]
    fn mc_verify_asym(&self, buf: &[u8]) -> Result<usize> {
        if let Some(public_key) =
            self.multicast.as_ref().unwrap().mc_public_key.as_ref()
        {
            let signature_len = 64;
            let buf_data_len = buf.len() - signature_len;

            let signature = &buf[buf_data_len..];
            public_key
                .verify(&buf[..buf_data_len], signature)
                .map_err(|_| Error::Multicast(MulticastError::McInvalidSign))?;
            Ok(buf_data_len)
        } else {
            Err(Error::Multicast(MulticastError::McInvalidAsymKey))
        }
    }

    fn mc_verify_sym(&mut self, buf: &[u8], pn: u64) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            if let McSymSign::Client(signatures) = &mut multicast.mc_sym_signs {
                // Recompute the packet hash. This will be used to find the
                // correct packet to authenticate.
                if signatures.contains_key(&pn) {
                    let recv_tag = signatures.remove(&pn).unwrap();
                    let tag = self.mc_sign_sym_slice(buf, pn)?;
                    if recv_tag == tag {
                        Ok(())
                    } else {
                        error!("Invalid sign sign for packet {}: {:?} vs {:?}. My client id {:?}", pn, recv_tag, tag, self.multicast.as_ref().unwrap().mc_client_id);
                        Err(Error::Multicast(MulticastError::McInvalidSign))
                    }
                } else {
                    Err(Error::Multicast(MulticastError::McNoAuthPacket))
                }
            } else {
                Err(Error::Multicast(MulticastError::McInvalidSign))
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }

    fn mc_get_pn(&self, buf: &[u8]) -> Result<u64> {
        if let Some(multicast) = self.multicast.as_ref() {
            let cid_len = multicast
                .get_mc_announce_data_path()
                .ok_or(Error::Multicast(MulticastError::McAnnounce))?
                .channel_id
                .len();

            // Copy the strict minimum: packet type (1) + packet num max length +
            // cid_length + minimum payload length (16).
            let mut hdr_copy =
                buf[..1 + MAX_PKT_NUM_LEN + cid_len + 16].to_owned();
            let mut b = octets::OctetsMut::with_slice(&mut hdr_copy);
            let mut header = crate::packet::Header::from_bytes(&mut b, cid_len)?;
            let aead = multicast
                .get_mc_crypto_open()
                .ok_or(Error::Multicast(MulticastError::McInvalidCrypto))?;

            crate::packet::decrypt_hdr(&mut b, &mut header, aead)?;
            Ok(header.pkt_num)
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }

    fn mc_get_client_auth_tags(&self) -> Result<HashSet<u64>> {
        if let Some(multicast) = self.multicast.as_ref() {
            match &multicast.mc_sym_signs {
                McSymSign::Client(m) =>
                    Ok(m.keys().copied().collect::<HashSet<u64>>()),
                _ => Err(Error::Multicast(MulticastError::McInvalidRole(
                    multicast.mc_role,
                ))),
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }
}

#[derive(Debug)]
/// Multicast symmetric signatures.
/// For the multicast source, it is a Vec of signatures for each packet and each
/// client. For the clients, it is a Vec of signatures for each packet only.
pub enum McSymSign {
    /// The client must only remember which packet number corresponds to a given
    /// tag.
    Client(HashMap<u64, Vec<u8>>),

    /// The multicast source must remember the tag for each of its clients.
    McSource(VecDeque<(u64, Vec<McSymSignature>)>),
}

#[doc(hidden)]
pub type ClientMap<'a> = Vec<&'a mut Connection>;

/// Symetric signature for the multicast source channel.
/// Handles the generation of the signatures for all clients in the mapping.
pub trait McSymAuth {
    /// Generates an AEAD taf for each connection in the connection mapping for
    /// all packets sent on the multicast channel that still need to be
    /// authenticated using symetric signatures.
    fn mc_sym_sign(&mut self, clients: &ClientMap) -> Result<()>;

    /// Generates an AEAD for each connection in the connection mapping for the
    /// given slice and packet number.
    ///
    /// This function assumes that all check related to the role of the caller
    /// is performed, i.e., that the caller is the multicast source.
    fn mc_sym_sign_single(
        &self, data: &[u8], clients: &ClientMap, pn: u64,
    ) -> Result<Vec<McSymSignature>>;
}

impl McSymAuth for Connection {
    fn mc_sym_sign(&mut self, clients: &ClientMap) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            if !matches!(multicast.mc_role, MulticastRole::ServerMulticast) {
                return Err(Error::Multicast(MulticastError::McInvalidRole(
                    multicast.mc_role,
                )));
            }

            if let Some(mut need_sign) = multicast.mc_pn_need_sym_sign.take() {
                let mut signatures_pn = Vec::with_capacity(need_sign.len());
                while let Some((pn, data)) = need_sign.pop_front() {
                    // Compute the AEAD tag.
                    signatures_pn
                        .push((pn, self.mc_sym_sign_single(&data, clients, pn)?));
                }

                // Reset the state because of ownership we took.
                let multicast = self.multicast.as_mut().unwrap();
                multicast.mc_sym_signs =
                    McSymSign::McSource(VecDeque::from(signatures_pn));
                multicast.mc_pn_need_sym_sign = Some(VecDeque::new());
            }

            Ok(())
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }

    fn mc_sym_sign_single(
        &self, data: &[u8], clients: &ClientMap, pn: u64,
    ) -> Result<Vec<McSymSignature>> {
        if let Some(multicast) = self.multicast.as_ref() {
            if let Some(McClientId::MulticastServer(map)) =
                multicast.mc_client_id.as_ref()
            {
                let mut signatures = Vec::with_capacity(map.cid_to_id.len());

                for conn in clients.iter() {
                    let mc_client_id =
                        map.get_client_id(conn.source_id().as_ref()).ok_or(
                            Error::Multicast(MulticastError::McInvalidClientId),
                        );
                    let mc_client_id = match mc_client_id {
                        Ok(v) => v,
                        Err(_) => {
                            error!(
                                "Error for source id: {:?} VS map: {:?}",
                                conn.source_id(),
                                map
                            );
                            continue;
                        },
                    };
                    let sign = conn.mc_sign_sym_slice(data, pn)?;
                    signatures.push(McSymSignature { mc_client_id, sign })
                }

                Ok(signatures)
            } else {
                error!("No map");
                Err(Error::Multicast(MulticastError::McInvalidClientId))
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::multicast::testing::MulticastPipe;
    use crate::multicast::McPathType;
    use crate::multicast::MulticastConnection;
    use crate::RecvInfo;

    use super::*;

    #[test]
    fn test_mc_get_pn() {
        let mut mc_pipe = MulticastPipe::new(
            1,
            "/tmp/test_mc_get_pn.txt",
            McAuthType::SymSign,
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(mc_pipe.source_send_single_stream(false, None, 0, 1), Ok(0));

        let mut buf = [0u8; 1500];
        let written = mc_pipe.mc_channel.mc_send(&mut buf).map(|(w, _)| w);
        assert_eq!(written, Ok(339));

        // Get the packet number without impacting the original packet.
        let pn = mc_pipe.unicast_pipes[0]
            .0
            .client
            .mc_get_pn(&buf[..written.unwrap()]);
        assert_eq!(pn, Ok(2));

        // The client decrypts the packet without alteration.
        let recv_info = RecvInfo {
            from: mc_pipe.unicast_pipes[0].2,
            to: mc_pipe.unicast_pipes[0].1,
            from_mc: Some(McPathType::Data),
        };
        assert_eq!(
            mc_pipe.unicast_pipes[0]
                .0
                .client
                .mc_recv(&mut buf[..written.unwrap()], recv_info),
            Ok(339)
        );
        // No harm. Nice.
        assert_eq!(mc_pipe.unicast_pipes[0].0.client.readable().next(), Some(1));
    }

    #[test]
    /// The multicast source sends multicast traffic with a symmetric
    /// authentication method. The clients verify the signatures to assert
    /// that the packets are correctly authenticated.
    fn test_mc_sym_auth_sign() {
        for probe_mc_path in [true, false] {
            let use_auth = McAuthType::SymSign;
            let mut mc_pipe = MulticastPipe::new(
                5,
                "/tmp/test_mc_sym_auth_sign.txt",
                use_auth,
                false,
                probe_mc_path,
                None,
            )
            .unwrap();

            let mut mc_buf = [0u8; 1500];

            // Multicast source sends a multicast stream.
            assert_eq!(
                mc_pipe.source_send_single_stream(false, None, 0, 1),
                Ok(0)
            );
            let written =
                mc_pipe.source_send_single_from_buf(None, 0, &mut mc_buf);
            assert_eq!(written, Ok(339));

            // Multicast source generates the AEAD tags for the clients.
            let clients: Vec<_> = mc_pipe
                .unicast_pipes
                .iter_mut()
                .map(|(conn, ..)| &mut conn.server)
                .collect();
            assert_eq!(mc_pipe.mc_channel.channel.mc_sym_sign(&clients), Ok(()));

            // Multicast source sends the authentication packet.
            assert_eq!(mc_pipe.mc_source_sends_auth_packets(None), Ok(145));

            // The clients verify the authentication of the multicast data packets
            // with the received tags.
            for (pipe, ..) in mc_pipe.unicast_pipes.iter_mut() {
                // Get the packet number of the received (and unauthenticated)
                // packet.
                let pn =
                    pipe.client.mc_get_pn(&mc_buf[..written.unwrap()]).unwrap();

                assert_eq!(
                    pipe.client.mc_verify_sym(&mc_buf[..written.unwrap()], pn),
                    Ok(())
                );

                // No more authentication packet for the client.
                let sign = if let McSymSign::Client(c) =
                    &pipe.client.multicast.as_ref().unwrap().mc_sym_signs
                {
                    c
                } else {
                    panic!()
                };
                assert!(sign.is_empty());
            }

            // Unicast connection stops the communication.
            for (pipe, ..) in mc_pipe.unicast_pipes.iter_mut() {
                assert_eq!(pipe.server.close(false, 0x1234, b"done"), Ok(()));
                assert_eq!(
                    pipe.server.close(false, 0x1234, b"done"),
                    Err(Error::Done)
                );

                assert_eq!(pipe.advance(), Ok(()));
                assert_eq!(pipe.advance(), Ok(()));

                assert!(pipe.client.is_closed() || pipe.client.is_draining());
                assert!(pipe.server.is_closed() || pipe.server.is_draining());
            }
        }
    }

    #[test]
    /// The multicast source sends a long stream consisting of several packets.
    /// The server generates MC_AUTH frames for all the STREAM frames.
    /// This tests is added to correct an existing bug where the source does not
    /// send all the MC_AUTH frames that they should.
    fn test_mc_sym_lot_of_data() {
        let use_auth = McAuthType::SymSign;
        let mut mc_pipe = MulticastPipe::new(
            10,
            "/tmp/test_mc_sym_lot_of_data.txt",
            use_auth,
            true,
            false,
            None,
        )
        .unwrap();

        let mut buf = vec![0u8; 10_000];
        assert_eq!(
            mc_pipe.mc_channel.channel.stream_send(1, &buf, true),
            Ok(buf.len())
        );

        let mut all_pns = Vec::with_capacity(1000);

        loop {
            if let Ok((w, _)) = mc_pipe.mc_channel.mc_send(&mut buf[..]) {
                let pn = mc_pipe.unicast_pipes[0].0.client.mc_get_pn(&buf[..w]);
                assert!(pn.is_ok());
                all_pns.push(pn.unwrap());

                for (pipe, client_addr, server_addr) in
                    mc_pipe.unicast_pipes.iter_mut()
                {
                    let recv_info = RecvInfo {
                        from: *server_addr,
                        to: *client_addr,
                        from_mc: Some(McPathType::Data),
                    };
                    pipe.client.mc_recv(&mut buf[..w], recv_info).unwrap();
                }
            } else {
                break;
            }
        }

        // Multicast source generates the AEAD tags for the clients.
        let clients: Vec<_> = mc_pipe
            .unicast_pipes
            .iter_mut()
            .map(|(conn, ..)| &mut conn.server)
            .collect();
        assert_eq!(mc_pipe.mc_channel.channel.mc_sym_sign(&clients), Ok(()));
        while let Ok(_) = mc_pipe.mc_source_sends_auth_packets(None) {}

        for (pipe, ..) in mc_pipe.unicast_pipes.iter_mut() {
            let client = &mut pipe.client;

            let tags = client.mc_get_client_auth_tags();
            assert!(tags.is_ok());
            let tags = tags.unwrap();
            for pn in all_pns.iter() {
                assert!(tags.contains(&pn));
            }
        }
    }
}
