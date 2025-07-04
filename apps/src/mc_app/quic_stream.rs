//! This module allows an FC-QUIC stack to replay a stream.
//! We replay a stream by storing the QUIC stream into a file, then replay the
//! content of the file to quiche.

use quiche::h3::flexicast::QuicStreamWriter;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::Write;

macro_rules! get_reader {
    ($replay:expr, $idx:expr) => {
        $replay.readers.get_mut($idx).ok_or(Error::OutOfBound($idx))
    };
}

#[derive(Debug)]
/// A QUIC stream repeater error.
pub enum Error {
    /// A QUIC error.
    Quic(quiche::Error),

    /// IO error.
    IO(io::Error),

    /// The asked stream repeater does not exist.
    OutOfBound(usize),

    /// No file.
    File(usize),

    /// An attempt to read in write-only mode, or to write in read-only.
    WrongMode,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Quic(l0), Self::Quic(r0)) => l0 == r0,
            (Self::IO(_), Self::IO(_)) => false,
            (Self::OutOfBound(l0), Self::OutOfBound(r0)) => l0 == r0,
            (Self::File(l0), Self::File(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// An FC-QUIC stream replay structure.
pub struct FcQuicStreamReplay {
    /// Stream replay file with write permissions.
    file: fs::File,

    /// All instances of file descriptors to replay the stream.
    readers: Vec<FcQuicStreamRead>,

    /// Whether we are in read-only mode.
    /// Once this mode is enabled, it is impossible to write again on that file,
    /// because the stream is in read-mode.
    read_only: bool,

    /// Total number of bytes writen into the stream.
    len: usize,

    /// File path.
    path: String,

    /// Records all QUIC-stream:HTTP/3-stream offsets.
    /// We need this step because we replay the QUIC stream only,
    /// but clients need the HTTP/3 offset to start delivering data as soon as
    /// possible to the application.
    /// This vector must be sorted because we perform a binary search on it.
    quic_to_h3_off: Vec<(u64, u64)>,

    /// Current HTTP/3 offset.
    h3_off: u64,
}

struct FcQuicStreamRead {
    /// Data already read from the internal file that is not already sent to
    /// quiche. It needs to be buffered until the next call.
    buf: Vec<u8>,

    /// Offset of the buffered data, if any.
    /// Start and end offsets.
    buf_off: Option<(usize, usize)>,

    /// Instance of the file with read access.
    file: Option<fs::File>,

    /// Total number of bytes writen into the stream.
    len: usize,

    /// Index of the stream reader.
    idx: usize,

    /// Current offset of data delivered to QUIC.
    quic_stream_off: u64,

    /// Whether this instance is the fastest instance, i.e., the one that will
    /// write on the first loop. This role is important as it must ensure
    /// that all other instances are slower than itself.
    is_writer: bool,
}

impl FcQuicStreamRead {
    fn new(
        buf_size: usize, len: usize, idx: usize, is_writer: bool, path: &str,
    ) -> Result<Self> {
        Ok(Self {
            buf_off: None,
            buf: vec![0u8; buf_size],
            file: if is_writer {
                None
            } else {
                Some(fs::File::open(path).map_err(|e| Error::IO(e.into()))?)
            },
            len,
            idx,
            quic_stream_off: 0,
            is_writer,
        })
    }

    fn repeat_stream(&mut self, path: &str, len: usize) -> Result<()> {
        self.file = Some(fs::File::open(path).map_err(|e| Error::IO(e.into()))?);
        self.buf_off = None;
        self.len = len;
        self.quic_stream_off = 0;
        Ok(())
    }

    fn read_stream(&mut self) -> Result<(&[u8], bool)> {
        // Maybe some data is already buffered.
        if let Some((start_off, end_off)) = self.buf_off {
            debug!(
                "Read remaining of data that was buffered at {} -> {}",
                start_off, end_off
            );
            let fin = self.is_fin();
            return Ok((&self.buf[start_off..end_off], fin));
        }

        if let Some(file) = self.file.as_mut() {
            let out = file.read(&mut self.buf).map_err(|e| Error::IO(e))?;
            println!(
                "Instance {} new offset after read stream {:?}",
                self.idx,
                file.stream_position()
            );
            self.buf_off = Some((0, out));
            let fin = self.is_fin();
            Ok((&self.buf[..out], fin))
        } else {
            Err(Error::File(self.idx))
        }
    }

    /// Whether the stream is finished.
    /// If this function returns true, the caller must expect a value of Ok(0)
    /// on `FcQuicStreamReplay::read_stream`. The caller should call
    /// `repeat_stream`.
    fn is_fin(&mut self) -> bool {
        let len = self.len as u64;
        self.file
            .as_mut()
            .is_some_and(|f| f.stream_position().ok().is_some_and(|v| v == len))
    }

    fn stream_written(&mut self, written: usize) {
        self.quic_stream_off += written as u64;

        if let Some((start_off, end_off)) = self.buf_off {
            // Everything is written from the local buffer.
            if start_off + written >= end_off {
                debug!("Everything written because written {} and start={} and end={}", written, start_off, end_off);
                self.buf_off = None;
            } else {
                debug!("NOT everything written because written {} and start={} and end={}", written, start_off, end_off);
                self.buf_off = Some((start_off + written, end_off));
            }
        }
    }

    fn can_restart(&mut self) -> bool {
        self.is_fin() && self.buf_off.is_none()
    }

    fn get_quic_stream_off(&self) -> u64 {
        self.quic_stream_off
    }
}

impl FcQuicStreamReplay {
    /// Creates a new instance from a filename given as argument.
    pub fn new(
        filename: &str, buf_size: usize, nb_readers: usize, writer_idx: usize,
    ) -> Result<Self> {
        Ok(Self {
            file: fs::File::create(filename).map_err(|e| Error::IO(e.into()))?,
            readers: (0..nb_readers)
                .map(|i| {
                    FcQuicStreamRead::new(
                        buf_size,
                        0,
                        i,
                        i == writer_idx,
                        filename,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
            read_only: false,
            path: filename.to_string(),
            len: 0,
            quic_to_h3_off: Vec::new(),
            h3_off: 0,
        })
    }

    /// Repeat the stream in read-only mode.
    /// Calling this function means that the application finished writing on
    /// this stream. This function will open again the file.
    pub fn repeat_stream(&mut self, idx: usize) -> Result<()> {
        get_reader!(self, idx)?.repeat_stream(&self.path, self.len)?;

        // If it is the first time we replay the stream, set the length to all instances.
        if !self.read_only {
            let len = self.len;
            self.readers.iter_mut().for_each(|r| r.len = len);
        }

        // Once one instance repeats, all the others do the same.
        self.read_only = true;

        Ok(())
    }

    /// Read some data (in-order) and buffer them into the stream.
    pub fn read_stream(&mut self, idx: usize) -> Result<(&[u8], bool)> {
        let reader = get_reader!(self, idx)?;

        // The writer cannnot read until everything is written.
        if !self.read_only && reader.is_writer {
            return Err(Error::WrongMode);
        }

        get_reader!(self, idx)?.read_stream()
    }

    /// Number of bytes actually written to quiche.
    pub fn stream_written(&mut self, written: usize, idx: usize) -> Result<()> {
        let reader = get_reader!(self, idx)?;
        
        if !self.read_only && reader.is_writer {
            return Err(Error::WrongMode);
        }

        reader.stream_written(written);

        Ok(())
    }

    /// Whether the stream is finished.
    /// If this function returns true, the caller must expect a value of Ok(0)
    /// on `FcQuicStreamReplay::read_stream`. The caller should call
    /// `repeat_stream`.
    pub fn is_fin(&mut self, idx: usize) -> bool {
        self.read_only && get_reader!(self, idx).is_ok_and(|r| r.is_fin())
    }

    /// Whether the stream is finished and can restart.
    pub fn can_restart(&mut self, idx: usize) -> bool {
        get_reader!(self, idx).is_ok_and(|r| r.can_restart())
    }

    /// Return the next QUIC/HTTP/3 offsets of the stream, if any.
    /// This may return `None` if the next offset is 0, or if it is not in
    /// read-only mode.
    pub fn get_next_quic_h3_off(&self, idx: usize) -> Option<(u64, u64)> {
        let reader = self.readers.get(idx)?;

        if !self.read_only && reader.is_writer {
            return None;
        }

        let quic_stream_off = reader.get_quic_stream_off();

        // Perform a binary search to find the right index.
        // We use the current index of data that has been served to know the next
        // QUIC offset.
        let out = match self
            .quic_to_h3_off
            .binary_search_by(|(quic_off, _)| quic_off.cmp(&quic_stream_off))
        {
            // Exact match.
            Ok(v) => {
                let a = self.quic_to_h3_off.get(v);
                let a = a.map(|&(q, h)| (h, q));
                a
            },
            Err(v) => {
                // No index after this, so we will loop again and wait for the
                // first offset.
                if v == self.quic_to_h3_off.len() - 1 {
                    None
                } else {
                    // Return the next offset that will appear.
                    let a = self.quic_to_h3_off.get(v + 1);
                    let a = a.map(|&(q, h)| (h, q));
                    a
                }
            },
        };

        debug!("Get next quic h3 off: {:?}", out);
        out
    }
}

impl QuicStreamWriter for FcQuicStreamReplay {
    fn write_quic_stream(
        &mut self, data: &[u8], h3_len: u64,
    ) -> quiche::h3::Result<usize> {
        if self.read_only {
            return Err(quiche::h3::Error::Done);
        }
        let out = self
            .file
            .write(data)
            .map_err(|_| quiche::h3::Error::InternalError)?;

        self.len += out;
        self.h3_off += h3_len;
        debug!("Write data of length: {} to {}", out, self.len);
        assert_eq!(out, data.len());

        Ok(out)
    }

    fn write_quic_h3_offsets(&mut self, quic_off: u64) {
        debug!(
            "Record QUIC off={} and HTTP/3 off={}",
            quic_off, self.h3_off
        );
        self.quic_to_h3_off.push((quic_off, self.h3_off));
    }
}

#[cfg(test)]
mod tests {
    use quiche::h3::flexicast::QuicStreamWriter;

    use super::FcQuicStreamReplay;
    use super::Error;

    #[test]
    fn test_quic_stream() {
        let mut replay =
            FcQuicStreamReplay::new("/tmp/test_quic_stream.txt", 1500, 2, 0)
                .unwrap();

        let first = b"first";
        let second = b"second";
        let third = b"third";
        let fourth = b"fourth";

        // Writer writes some data.
        assert_eq!(replay.write_quic_stream(first, first.len() as u64), Ok(first.len()));
        assert_eq!(replay.write_quic_stream(second, second.len() as u64), Ok(second.len()));

        // The other instance can already read the data...
        let out = replay.read_stream(1);
        assert!(out.is_ok());
        let (buf, fin) = out.unwrap();
        assert!(!fin);
        assert_eq!(&buf[..first.len()], first);
        assert_eq!(&buf[first.len()..], second);
        let len = buf.len();
        replay.stream_written(len, 1).unwrap();

        // ... but the first instance (i.e., the writer) cannot read.
        assert_eq!(replay.read_stream(0), Err(Error::WrongMode));

        // And the second instance cannot read anymore.
        let empty = Vec::new();
        assert_eq!(replay.read_stream(1), Ok((&empty[..0], false)));
        replay.stream_written(len, 1).unwrap();

        // Now the writer writes the last pieces of data.
        assert_eq!(replay.write_quic_stream(third, third.len() as u64), Ok(third.len()));
        let out = replay.read_stream(1);
        assert!(out.is_ok());
        let (buf, fin) = out.unwrap();
        assert!(!fin);
        assert_eq!(&buf[..third.len()], third);
        replay.stream_written(len, 1).unwrap();

        // And the writer indicates that it is the end of the data.
        assert_eq!(replay.write_quic_stream(fourth, fourth.len() as u64), Ok(fourth.len()));
        assert_eq!(replay.repeat_stream(0), Ok(()));
        let out = replay.read_stream(1);
        assert!(out.is_ok());
        let (buf, fin) = out.unwrap();
        assert!(fin);
        assert_eq!(&buf[..fourth.len()], fourth);
        replay.stream_written(len, 1).unwrap();

        // The writer now is able to read everything.
        let out = replay.read_stream(0);
        assert!(out.is_ok());
        let (buf, fin) = out.unwrap();
        assert!(fin);
        let mut total_data = vec![0u8; first.len() + second.len() + third.len() + fourth.len()];
        total_data[..first.len()].copy_from_slice(first);
        total_data[first.len()..first.len() + second.len()].copy_from_slice(second);
        total_data[first.len() + second.len()..first.len() + second.len() + third.len()].copy_from_slice(third);
        total_data[first.len() + second.len() + third.len()..].copy_from_slice(fourth);
        assert_eq!(buf, &total_data);
        replay.stream_written(len, 0).unwrap();

        // And the second instance repeats and reads everything.
        assert_eq!(replay.repeat_stream(0), Ok(()));
        let out = replay.read_stream(0);
        assert!(out.is_ok());
        let (buf, fin) = out.unwrap();
        assert!(fin);
        assert_eq!(buf, &total_data);
        replay.stream_written(len, 1).unwrap();
    }
}
