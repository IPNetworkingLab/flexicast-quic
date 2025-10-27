//! Handles the HTTP/3 protocol over Flexicast QUIC for file delivery.

pub mod sender;
pub mod receiver;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
/// An HTTP/3 over Flexicast QUIC error.
pub enum H3FcError {

}
