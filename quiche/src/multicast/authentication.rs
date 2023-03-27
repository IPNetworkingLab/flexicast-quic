//! Handles the signatures for authentication of the multicast source.

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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Structure containing symetric signatures for each of the multicast clients
/// for a given packet number.
pub struct McSign {
    mc_client_id: u64,
    sign: Vec<u8>,
}
