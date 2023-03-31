//! Handles the signatures for authentication of the multicast source.
use crate::multicast::McClientId;
use crate::multicast::MulticastError;
use crate::multicast::MulticastRole;
use crate::Connection;
use crate::Error;
use crate::Result;
use ring::hmac;
use ring::rand;
use ring::rand::SecureRandom;
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
pub struct McSymSignatures {
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
    fn mc_sign_sym_slice(
        &self, buf: &[u8], key: Option<&hmac::Key>,
    ) -> Result<Vec<u8>>;
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
                assert_eq!(signature_len, 64);
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

    fn mc_sign_sym_slice(
        &self, buf: &[u8], key: Option<&hmac::Key>,
    ) -> Result<Vec<u8>> {
        // MC-TODO: give a valid signature.
        // Ok(self.source_id().as_ref().to_vec())
        let signature = if let Some(k) = key {
            hmac::sign(k, buf)
        } else {
            if true {
                panic!();
            }
            let mut key_value = [0u8; 48];
                let rng = rand::SystemRandom::new();
                rng.fill(&mut key_value).map_err(|_| {
                    Error::Multicast(MulticastError::McInvalidSymKey)
                })?;
                let k = hmac::Key::new(hmac::HMAC_SHA256, &key_value);
                hmac::sign(&k, buf)
        };

        Ok(signature.as_ref().to_vec())
    }
}

#[doc(hidden)]
pub type McSymSignPn = (u64, Vec<McSymSignatures>);

#[doc(hidden)]
pub type ClientMap<'a> = Vec<&'a mut Connection>;

/// Symetric signature for the multicast source channel.
/// Handles the generation of the signatures for all clients in the mapping.
pub trait McSymAuth {
    /// Generates HMAC for each connection in the connection mapping for all
    /// packets sent on the multicast channel that still need to be
    /// authenticated using symetric signatures.
    fn mc_sym_sign(&mut self, clients: &ClientMap) -> Result<()>;

    /// Generates HMAC for each connection in the connection mapping for the
    /// given slice and packet number.
    ///
    /// This function assumes that all check related to the role of the caller
    /// is performed, i.e., that the caller is the multicast source.
    fn mc_sym_sign_single(
        &self, data: &[u8], clients: &ClientMap,
    ) -> Result<Vec<McSymSignatures>>;
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
                        .push((pn, self.mc_sym_sign_single(&data, clients)?));
                }

                // Reset the state because of ownership we took.
                let mut multicast = self.multicast.as_mut().unwrap();
                multicast.mc_sym_signs = Some(VecDeque::from(signatures_pn));
                multicast.mc_pn_need_sym_sign = Some(VecDeque::new());
            }

            Ok(())
        } else {
            Err(Error::Multicast(MulticastError::McDisabled))
        }
    }

    fn mc_sym_sign_single(
        &self, data: &[u8], clients: &ClientMap,
    ) -> Result<Vec<McSymSignatures>> {
        if let Some(multicast) = self.multicast.as_ref() {
            if let Some(McClientId::MulticastServer(map)) =
                multicast.mc_client_id.as_ref()
            {
                let mut signatures = Vec::with_capacity(map.cid_to_id.len());

                for (i, conn) in clients.iter().enumerate() {
                    // let cid = conn.source_id();
                    // let cid = cid.as_ref();
                    // let client_id = map.cid_to_id.get(cid).ok_or(
                    //     Error::Multicast(MulticastError::McInvalidClientId),
                    // )?;
                    let key = if let Some(v) = multicast.hmac_keys.as_ref() {
                        v.get(i)
                    } else {
                        None
                    };
                    let sign = conn.mc_sign_sym_slice(data, key)?;
                    signatures.push(McSymSignatures {
                        mc_client_id: i as u64,
                        // sign: vec![0u8;16],//conn.mc_sign_sym_slice(data, key)?,
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
