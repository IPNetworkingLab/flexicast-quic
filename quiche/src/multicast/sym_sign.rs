//! Handles the signatures for authentication of the multicast source.

#[derive(Debug, Clone, PartialEq, Eq)]
/// Structure containing symetric signatures for each of the multicast clients
/// for a given packet number.
pub struct McSign {
    mc_client_id: u64,
    sign: Vec<u8>,
}
