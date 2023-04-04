//! Handles the signatures for authentication of the multicast source.
use crate::crypto::mc_crypto::McVerifySymSign;
use crate::multicast::McClientId;
use crate::multicast::MulticastError;
use crate::multicast::MulticastRole;
use crate::packet::Epoch;
use crate::Connection;
use crate::Error;
use crate::Result;
use std::collections::VecDeque;
use std::convert::TryFrom;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
/// Authentication type used for the multicast channel.
pub enum McAuthType {
    /// Use asymetric signature at the end of each Multicast QUIC packet.
    AsymSign,

    /// Create a new Multicast QUIC packet on the authentication path containing
    /// an MC_AUTH frame with the list of symetric signatures, using the keys of
    /// the unicast connection for all clients of the multicast channel.
    SymSign,

    /// Dynamically changes the signature process.
    /// Currently only supports symetric -> asymetric.
    /// The inner value is the threshold number of receivers.
    Dynamic(u32),

    /// No authentication used.
    None,
}

impl TryFrom<u64> for McAuthType {
    type Error = crate::Error;

    fn try_from(v: u64) -> Result<Self> {
        match v {
            0 => Ok(Self::AsymSign),
            1 => Ok(Self::SymSign),
            2 => Ok(Self::Dynamic(20)),
            3 => Ok(Self::None),
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

    /// HMAC signature using information from the unicast session.
    pub sign: Vec<u8>,
}

/// Multicast authentication.
/// Exposes asymetric and symetric signatures.
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

    /// Verify a symmetric signature.
    ///
    /// Requires that the client has a valid multicast client ID.
    fn mc_verify_sym(&mut self, buf: &[u8]) -> Result<()>;
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

    fn mc_verify_sym(&mut self, buf: &[u8]) -> Result<()> {
        if let Some(multicast) = self.multicast.as_mut() {
            if let McSymSign::Client(signatures) = &mut multicast.mc_sym_signs {
                // MC-TODO: for now, assume that the first received signature
                // maps to the buffer. This is not really good but for now that
                // will work.
                let recv_tag = signatures
                    .pop_front()
                    .ok_or(Error::Multicast(MulticastError::McNoAuthPacket))?;
                let tag = self.mc_sign_sym_slice(buf, recv_tag.0)?;
                println!("Recv tag: {:?}. Computed tag: {:?}", recv_tag, tag);
                if recv_tag.1 == tag {
                    Ok(())
                } else {
                    Err(Error::Multicast(MulticastError::McInvalidSign))
                }
            } else {
                Err(Error::Multicast(MulticastError::McInvalidSign))
            }
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }
}

#[doc(hidden)]
pub type McSymSignPn = (u64, Vec<McSymSignature>);

/// Multicast symmetric signatures.
/// For the multicast source, it is a Vec of signatures for each packet and each
/// client. For the clients, it is a Vec of signatures for each packet only.
pub enum McSymSign {
    /// The client must only remember which packet number corresponds to a given
    /// tag.
    Client(VecDeque<(u64, Vec<u8>)>),

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
                    signatures_pn
                        .push((pn, self.mc_sym_sign_single(&data, clients, pn)?));
                }

                // Reset the state because of ownership we took.
                let mut multicast = self.multicast.as_mut().unwrap();
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

                for (i, conn) in clients.iter().enumerate() {
                    let sign = conn.mc_sign_sym_slice(data, pn)?;
                    signatures.push(McSymSignature {
                        mc_client_id: i as u64,
                        sign,
                    })
                }

                Ok(signatures)
            } else {
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

    use super::*;

    #[test]
    /// The multicast source sends multicast traffic with a symmetric
    /// authentication method. The clients verify the signatures to assert
    /// that the packets are correctly authenticated.
    fn test_mc_sym_auth_sign() {
        let use_auth = McAuthType::SymSign;
        let mut mc_pipe = MulticastPipe::new(
            5,
            "/tmp/test_mc_sym_auth_sign.txt",
            use_auth,
            false,
        )
        .unwrap();

        let mut mc_buf = [0u8; 1500];

        // Multicast source sends a multicast stream.
        assert_eq!(mc_pipe.source_send_single_stream(false, None, 0, 1), Ok(0));
        assert_eq!(
            mc_pipe.source_send_single_from_buf(None, 0, &mut mc_buf),
            Ok(339)
        );

        // Multicast source generates the AEAD tags for the clients.
        let clients: Vec<_> = mc_pipe
            .unicast_pipes
            .iter_mut()
            .map(|(conn, ..)| &mut conn.server)
            .collect();
        assert_eq!(mc_pipe.mc_channel.channel.mc_sym_sign(&clients), Ok(()));

        // Multicast source sends the authentication packet.
        assert_eq!(mc_pipe.mc_source_sends_auth_packets(None), Ok(145)); // 145 for 5 clients. 73 for a single client.

        // The clients verify the authentication of the multicast data packets
        // with the received tags.
        for (pipe, ..) in mc_pipe.unicast_pipes.iter_mut() {
            assert_eq!(pipe.client.mc_verify_sym(&mc_buf[..339]), Ok(()));

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
    }
}
