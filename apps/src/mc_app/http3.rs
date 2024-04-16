use std::convert::TryInto;
use std::io::Write;
use std::path::Path;

use quiche::h3::Connection as H3Conn;
use quiche::h3::Header;
use quiche::h3::NameValue;
use quiche::multicast::MulticastChannelSource;
use std::time::Instant;
use url::Url;

pub const FC_H3_OFF_HDR: &'static [u8] = b":fc-http3-offset";
pub const FC_H3_QUIC_OFF_HDR: &'static [u8] = b":fc-quic-offset";

#[derive(Debug)]
/// An FC-QUIC HTTP/3 error.
pub enum FcH3Error {
    /// Wrong or incomplete HTTP/3 response header.
    Header,

    /// I/O error.
    Io(std::io::Error),

    /// Invalid request.
    Request,

    /// Invalid stream ID.
    StreamId(u64),

    /// HTTP/3 error.
    HTTP3(quiche::h3::Error),

    /// Quiche error.
    QUIC(quiche::Error),
}

pub type Result<T> = core::result::Result<T, FcH3Error>;

#[derive(Default)]
/// HTTP/3 response state for the client.
///
/// TODO: replace by directly writing the data on disk, especially for large
/// files...
pub struct Http3Client {
    /// Initial offset of the HTTP3 response. Used because we might receive at
    /// the middle if we join the flexicast group later.
    h3_off: u64,

    /// Initial offset of the response for QUIC.
    quic_off: u64,

    /// Whether the client received the reponse headers.
    recv_hdr: bool,

    /// Data buffer.
    data: Vec<u8>,

    /// Offset of the data buffer.
    off: usize,

    /// Whether the HTTP/3 request is sent.
    pub request_sent: bool,

    /// Time at which the request was sent,
    pub request_start: Option<Instant>,
}

impl Http3Client {
    pub fn send_request(url: &url::Url) -> Vec<Header> {
        let mut path = String::from(url.path());

        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }

        let request = vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
            quiche::h3::Header::new(
                b":authority",
                url.host_str().unwrap().as_bytes(),
            ),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"user-agent", b"quiche"),
        ];

        request
    }

    pub fn recv_hdr(&mut self, headers: &[Header]) -> Result<()> {
        if self.recv_hdr {
            return Err(FcH3Error::Header);
        }

        // Whether the HTTP3 and QUIC offset headers are received.
        let mut recv_h3_off = false;
        let mut recv_quic_off = false;
        let mut recv_content_length = false;

        for header in headers.iter() {
            match header.name() {
                FC_H3_OFF_HDR => {
                    if recv_h3_off {
                        return Err(FcH3Error::Header);
                    }
                    recv_h3_off = true;

                    self.h3_off = u64::from_be_bytes(
                        header
                            .value()
                            .try_into()
                            .map_err(|_| FcH3Error::Header)?,
                    );

                    self.off = self.h3_off as usize;
                },

                FC_H3_QUIC_OFF_HDR => {
                    if recv_quic_off {
                        return Err(FcH3Error::Header);
                    }
                    recv_quic_off = true;

                    self.quic_off = u64::from_be_bytes(
                        header
                            .value()
                            .try_into()
                            .map_err(|_| FcH3Error::Header)?,
                    );
                },

                b":content-length" => {
                    if recv_content_length {
                        return Err(FcH3Error::Header);
                    }
                    recv_content_length = true;

                    let len = u64::from_be_bytes(
                        header
                            .value()
                            .try_into()
                            .map_err(|_| FcH3Error::Header)?,
                    ) as usize;

                    self.data = vec![0u8; len];
                },

                _ => (),
            }
        }

        if !(recv_h3_off && recv_quic_off) {
            return Err(FcH3Error::Header);
        }

        self.recv_hdr = true;

        Ok(())
    }

    pub fn recv_body(&mut self, data: &[u8]) -> Result<()> {
        // Maybe the data wraps up (it should not because of the design of stream
        // rotation). First part.
        let off = data.len().min(self.data.len() - self.off);
        self.data[self.off..self.off + off].copy_from_slice(&data[..off]);

        // Second part.
        if data.len() > self.data.len() - self.off {
            let off_end = data.len() - (self.data.len() - self.off);
            self.data[..off_end].copy_from_slice(&data[..data.len() - off]);
        }

        self.off += data.len();

        Ok(())
    }

    pub fn write_all(&self, output: &Path) -> Result<()> {
        let mut file =
            std::fs::File::create(output).map_err(|e| FcH3Error::Io(e))?;

        file.write_all(&self.data).map_err(|e| FcH3Error::Io(e))?;

        Ok(())
    }
}

#[derive(Debug)]
/// HTTP/3 response state for the server.
///
/// FC-TODO: replace by directly writing the data on disk, especially for large
/// files...
pub struct Http3Server {
    /// File path.
    filepath: String,

    /// Offset of the data already sent to QUIC.
    offset: u64,

    /// The actual data.
    data: Vec<u8>,

    /// The HTTP/3 and QUIC stream ID for this response.
    stream_id: u64,
}

impl Http3Server {
    pub fn new(filepath: &str) -> Result<Self> {
        // Read the data from the file.
        let data = std::fs::read(filepath).map_err(|e| FcH3Error::Io(e))?;

        Ok(Self {
            filepath: filepath.to_string(),
            offset: 0,
            data,
            stream_id: 0, // Fc-TODO: Maybe an error here because we assume 0?
        })
    }

    pub fn send_hdr(
        &self, headers: &[Header], fh3_conn: &H3Conn,
    ) -> Result<Vec<Header>> {
        let mut method = None;
        let mut path = vec![];

        for header in headers.iter() {
            match header.name() {
                b":path" => path = header.value().to_vec(),
                b":method" => method = Some(header.value()),
                _ => (),
            }
        }

        let status = match method {
            Some(b"GET") =>
                if &path == self.filepath.as_bytes() {
                    200
                } else {
                    404
                },

            _ => 405,
        };

        // Get the HTTP/3 and FC-QUIC offset to advertise to the client to allow
        // for out-of-order delivery.
        let (h3_off, quic_off) = fh3_conn
            .fc_get_emit_off(self.stream_id)
            .ok_or(FcH3Error::StreamId(self.stream_id))?;

        let resp_headers = vec![
            Header::new(b":status", status.to_string().as_bytes()),
            Header::new(b"server", b"quiche"),
            Header::new(
                b"content-length",
                self.data.len().to_string().as_bytes(),
            ),
            Header::new(FC_H3_OFF_HDR, &format!("{:0>8}", h3_off).into_bytes()),
            Header::new(
                FC_H3_QUIC_OFF_HDR,
                &format!("{:0>8}", quic_off).into_bytes(),
            ),
        ];

        Ok(resp_headers)
    }

    pub fn send_body(
        &mut self, fh3_conn: &mut H3Conn, fc_conn: &mut quiche::Connection,
    ) -> Result<usize> {
        let written = fh3_conn
            .send_body(
                fc_conn,
                self.stream_id,
                &self.data[self.offset as usize..],
                true,
            )
            .map_err(|e| FcH3Error::HTTP3(e))?;

        self.offset += written as u64;

        Ok(written)
    }

    pub fn is_fin(&self) -> bool {
        self.data.len() == self.offset as usize
    }

    pub fn restart_stream(
        &mut self, fh3_conn: &mut H3Conn, fc_chan: &mut MulticastChannelSource,
        fh3_back: &mut H3Conn,
    ) -> Result<()> {
        // Reset the state of the flexicast source.
        fh3_conn
            .fc_reset_stream(&mut fc_chan.channel, self.stream_id)
            .map_err(|e| FcH3Error::HTTP3(e))?;
        fh3_back
            .fc_reset_stream(&mut fc_chan.client_backup, self.stream_id)
            .map_err(|e| FcH3Error::HTTP3(e))?;

        // Reset the state of the response.
        self.offset = 0;

        // The dummy client has to send again the request.
        // This is ugly, but it should work.
        self.start_request_on_fc_source(fh3_conn, fc_chan, fh3_back)?;

        Ok(())
    }

    pub fn start_request_on_fc_source(
        &mut self, fh3_conn: &mut H3Conn, fc_chan: &mut MulticastChannelSource,
        fh3_back: &mut H3Conn,
    ) -> Result<()> {
        // Backup client sends the request.
        let url: Url = format!("https://localhost:4433/{}", self.filepath)
            .parse()
            .map_err(|_| FcH3Error::Request)?;
        let headers = Http3Client::send_request(&url);

        let stream_id = fh3_back
            .send_request(&mut fc_chan.client_backup, &headers, true)
            .map_err(|e| FcH3Error::HTTP3(e))?;

        assert_eq!(self.stream_id, stream_id);

        MulticastChannelSource::advance(
            &mut fc_chan.channel,
            &mut fc_chan.client_backup,
        )
        .map_err(|e| FcH3Error::QUIC(e))?;

        // Poll the flexicast source connection.
        let (stream_id, event) = fh3_conn
            .poll(&mut fc_chan.channel)
            .map_err(|e| FcH3Error::HTTP3(e))?;

        // Send the response from the flexicast source.
        if let quiche::h3::Event::Headers { list, .. } = event {
            let _headers = self.send_hdr(&list, &fh3_conn)?;
        } else {
            return Err(FcH3Error::Request);
        }

        assert_eq!(self.stream_id, stream_id);

        Ok(())
    }
}
