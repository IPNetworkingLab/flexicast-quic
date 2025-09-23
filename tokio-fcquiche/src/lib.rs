//! Asynchronous wrapper around Flexicast QUIC using tokio.
//! The objective is to enable applications to entirely rely on this module to
//! write their own application, forwarding and receiving data through channels.

mod fcquic;
pub mod io;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub const MAX_DATAGRAM_SIZE: usize = 1350;
const CHANNEL_BUFFER_SIZE: usize = 100_000;

#[derive(Debug)]
/// Messages between the appplication and Flexicast QUIC.
pub enum FcQuicMsg {
    /// Data, whether it is the last piece of data (i.e., is fin after), and the stream ID.
    Stream((Vec<u8>, bool, u64)),

    /// No more data will be sent.
    Close,
}

#[cfg(feature = "qlog")]
/// Makes a buffered writer for a qlog.
pub(crate) fn make_qlog_writer(
    dir: &std::ffi::OsStr, role: &str, id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{role}-{id}.sqlog");
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}