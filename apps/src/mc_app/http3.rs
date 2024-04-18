use std::convert::TryInto;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;

use quiche::h3::Connection as H3Conn;
use quiche::h3::Header;
use quiche::h3::NameValue;
use quiche::multicast::MulticastChannelSource;
use quiche::Connection;
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

    /// Finished to transmit the data.
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Flexicast action that the client must perform based on its HTTP/3 query.
pub enum FH3Action {
    /// Join the flexicast channel.
    Join,

    /// Do nothing.
    Nothing,

    /// Leave the flexicast channel.
    Leave,
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
    data: Rc<Vec<u8>>,

    /// HTTP/3 headers sent to the client.
    pub headers: Option<Vec<Header>>,

    /// The HTTP/3 and QUIC stream ID for this response.
    stream_id: u64,

    /// Whether the transfer is active.
    active: bool,

    /// Status of the client regarding the flexicast channel for this HTTP/3
    /// response.
    fh3_action: FH3Action,

    /// Whether the HTTP/3 response headers can be sent.
    pub send_h3_headers: bool,
}

impl Http3Server {
    pub fn new(filepath: &str) -> Result<Self> {
        // Read the data from the file.
        let data = std::fs::read(filepath).map_err(|e| FcH3Error::Io(e))?;

        Ok(Self {
            filepath: filepath.to_string(),
            offset: 0,
            data: Rc::new(data),
            headers: None,
            stream_id: 0, // Fc-TODO: Maybe an error here because we assume 0?
            active: false,
            fh3_action: FH3Action::Join,
            send_h3_headers: true, // True for the flexicast channel.
        })
    }

    pub fn handle_request(
        headers: &[Header], fh3_conn: &mut H3Conn, conn: &mut Connection,
        stream_id: u64, filepath: &str, data: &Rc<Vec<u8>>,
        h3_conn: Option<&mut H3Conn>,
    ) -> Result<Self> {
        let mut method = None;
        let mut path = vec![];

        info!(
            "{} got request {:?} on stream id {}",
            conn.trace_id(),
            headers,
            stream_id,
        );

        // We decide the response based on headers alone, so stop reading the
        // request stream so that any body is ignored and pointless Data events
        // are not generated.
        conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
            .unwrap();

        for header in headers.iter() {
            match header.name() {
                b":path" => path = header.value().to_vec(),
                b":method" => method = Some(header.value()),
                _ => (),
            }
        }

        let (status, action) = match method {
            Some(b"GET") =>
                if &path == filepath.as_bytes() {
                    (200, FH3Action::Join)
                } else {
                    (404, FH3Action::Nothing)
                },

            _ => (405, FH3Action::Nothing),
        };

        // Get the HTTP/3 and FC-QUIC offset to advertise to the client to allow
        // for out-of-order delivery.
        let (h3_off, quic_off) = fh3_conn
            .fc_get_emit_off(stream_id)
            .ok_or(FcH3Error::StreamId(stream_id))?;

        let resp_headers = vec![
            Header::new(b":status", status.to_string().as_bytes()),
            Header::new(b"server", b"quiche"),
            Header::new(b"content-length", data.len().to_string().as_bytes()),
            Header::new(FC_H3_OFF_HDR, &format!("{:0>8}", h3_off).into_bytes()),
            Header::new(
                FC_H3_QUIC_OFF_HDR,
                &format!("{:0>8}", quic_off).into_bytes(),
            ),
        ];

        let mut h3_resp = Self {
            filepath: filepath.to_string(),
            offset: 0,
            data: Rc::clone(data),
            headers: None,
            stream_id,
            // By default the HTTP/3 response is not active for the unicast
            // server.
            active: if action == FH3Action::Join {
                false
            } else {
                true
            },
            fh3_action: action,
            send_h3_headers: if action == FH3Action::Join {
                false
            } else {
                true
            },
        };

        // Send the response headers to the client.
        let h3_conn_to_use = h3_conn.unwrap_or(fh3_conn);
        match h3_conn_to_use.send_response(conn, stream_id, headers, false) {
            Ok(v) => v,

            Err(quiche::h3::Error::StreamBlocked) => {
                // Store headers for later delivery.
                h3_resp.headers = Some(resp_headers);
            },

            Err(e) => {
                error!("{} stream send failed: {:?}", conn.trace_id(), e);
                return Err(FcH3Error::HTTP3(e));
            },
        }

        Ok(h3_resp)
    }

    pub fn send_body(
        &mut self, h3_conn: &mut H3Conn, conn: &mut quiche::Connection,
    ) -> Result<usize> {
        if !self.is_active() {
            return Ok(0);
        }
        
        let written = h3_conn
            .send_body(
                conn,
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
        self, fh3_conn: &mut H3Conn, fc_chan: &mut MulticastChannelSource,
        fh3_back: &mut H3Conn,
    ) -> Result<Self> {
        // Reset the state of the flexicast source.
        fh3_conn
            .fc_reset_stream(&mut fc_chan.channel, self.stream_id)
            .map_err(|e| FcH3Error::HTTP3(e))?;
        fh3_back
            .fc_reset_stream(&mut fc_chan.client_backup, self.stream_id)
            .map_err(|e| FcH3Error::HTTP3(e))?;

        // The dummy client has to send again the request.
        // This is ugly, but it should work.
        let out = self.start_request_on_fc_source(fh3_conn, fc_chan, fh3_back)?;

        Ok(out)
    }

    pub fn start_request_on_fc_source(
        self, fh3_conn: &mut H3Conn, fc_chan: &mut MulticastChannelSource,
        fh3_back: &mut H3Conn,
    ) -> Result<Self> {
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
            let out = Http3Server::handle_request(
                &list,
                fh3_conn,
                &mut fc_chan.channel,
                stream_id,
                &self.filepath,
                &self.data,
                None,
            )?;
            Ok(out)
        } else {
            Err(FcH3Error::Request)
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn set_active(&mut self, v: bool) {
        self.active = v;
    }

    pub fn data(&self) -> &Rc<Vec<u8>> {
        &self.data
    }

    pub fn offset(&self) -> usize {
        self.offset as usize
    }

    pub fn action(&self) -> FH3Action {
        self.fh3_action
    }
}
