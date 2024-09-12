//! Handles the signatures for authentication of the multicast source.
use crate::multicast::McError;
use crate::multicast::McRole;
use crate::packet::MAX_PKT_NUM_LEN;
use crate::Connection;
use crate::Error;
use crate::Result;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::str::FromStr;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
/// Authentication type used for the multicast channel.
pub enum McAuthType {
    /// Use asymmetric signature at the end of each Multicast QUIC packet.
    AsymSign,

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
            2 => Ok(Self::Dynamic(20)),
            3 => Ok(Self::None),
            4 => Ok(Self::StreamAsym),
            _ => Err(Error::Multicast(McError::McInvalidAuth)),
        }
    }
}

impl From<McAuthType> for u64 {
    fn from(v: McAuthType) -> Self {
        match v {
            McAuthType::AsymSign => 0,
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
    /// `Error::Multicast(McError::McInvalidAuth)` is returned.
    fn from_str(name: &str) -> Result<Self> {
        match name {
            "asymmetric" => Ok(McAuthType::AsymSign),
            "none" => Ok(McAuthType::None),
            "stream" => Ok(McAuthType::StreamAsym),
            _ => Err(Error::Multicast(McError::McInvalidAuth)),
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

    /// Verify an asymmetric signature.
    ///
    /// Returns the length of the buffer payload, i.e., without the signature.
    /// The signature is assumed to be in the last bytes of the buffer.
    fn mc_verify_asym(&self, buf: &[u8]) -> Result<usize>;

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
}

impl McAuthentication for Connection {
    fn mc_sign_asym(&self, buf: &mut [u8], data_len: usize) -> Result<usize> {
        if let Some(multicast) = self.multicast.as_ref() {
            if multicast.mc_role != McRole::ServerMulticast {
                return Err(Error::Multicast(McError::McInvalidRole(
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
                Err(Error::Multicast(McError::McInvalidAsymKey))
            }
        } else {
            Err(Error::Multicast(McError::McDisabled))
        }
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
                .map_err(|_| Error::Multicast(McError::McInvalidSign))?;
            Ok(buf_data_len)
        } else {
            Err(Error::Multicast(McError::McInvalidAsymKey))
        }
    }

    fn mc_get_pn(&self, buf: &[u8]) -> Result<u64> {
        if let Some(multicast) = self.multicast.as_ref() {
            let cid_len = multicast
                .get_mc_announce_data(0)
                .ok_or(Error::Multicast(McError::McAnnounce))?
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
                .ok_or(Error::Multicast(McError::McInvalidCrypto))?;

            crate::packet::decrypt_hdr(&mut b, &mut header, aead)?;
            Ok(header.pkt_num)
        } else {
            Err(Error::Multicast(McError::McDisabled))
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

#[cfg(test)]
mod tests {
    use crate::multicast::FcConfig;
    use crate::multicast::testing::MulticastPipe;
    use crate::multicast::MulticastConnection;
    use crate::RecvInfo;

    use super::*;

    #[test]
    fn test_mc_get_pn() {
        let mut fc_config = FcConfig {
            authentication: McAuthType::AsymSign,
            use_fec: false,
            probe_mc_path: false,
            ..Default::default()
        };
        let mut mc_pipe =
            MulticastPipe::new(1, "/tmp/test_mc_get_pn.txt", &mut fc_config).unwrap();
        assert_eq!(mc_pipe.source_send_single_stream(false, None, 1), Ok(0));

        let mut buf = [0u8; 1500];
        let written = mc_pipe.mc_channel.mc_send(&mut buf).map(|(w, _)| w);
        assert_eq!(written, Ok(403));

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
            from_mc: true,
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
}
