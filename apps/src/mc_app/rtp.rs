use mio::net::UdpSocket;
use std::collections::VecDeque;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::time;
use std::time::SystemTime;

pub enum SockType {
    Mio(mio::net::UdpSocket),
    Tokio(tokio::net::UdpSocket),
    None,
}

impl SockType {
    fn mio_mut(&mut self) -> Option<&mut mio::net::UdpSocket> {
        match self {
            Self::Mio(ref mut s) => Some(s),
            _ => None,
        }
    }

    fn tokio(&self) -> Option<&tokio::net::UdpSocket> {
        match self {
            Self::Tokio(ref s) => Some(s),
            _ => None,
        }
    }
}

pub struct RtpClient {
    frame_recv: Vec<(u64, SystemTime, usize, Option<u8>)>,

    output_filename: String,

    udp_sink: Option<UdpSocket>,
}

impl RtpClient {
    pub fn new(
        output_filename: &str, udp_sink_addr: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let udp_sink = if let Some(addr) = udp_sink_addr {
            let udp_sink = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
            udp_sink.connect(addr)?;
            Some(udp_sink)
        } else {
            None
        };

        Ok(Self {
            frame_recv: Vec::new(),
            output_filename: output_filename.to_owned(),
            udp_sink,
        })
    }

    pub fn on_stream_complete(
        &mut self, stream_id: u64, now: SystemTime, len: usize, from: Option<u8>,
    ) {
        self.frame_recv.push((stream_id, now, len, from));
        trace!("RTP Client: stream {stream_id} complete, send {len} bytes to UDP sink");
    }

    pub fn on_sequential_stream_recv(&mut self, buf: &[u8]) {
        if let Some(socket) = self.udp_sink.as_ref() {
            if let Err(e) = socket.send(buf) {
                error!(
                    "RTP Client: error when sending data to UDP sink: {:?}",
                    e
                );
            }
        }
    }

    pub fn on_finish(&mut self) {
        let mut file = std::fs::File::create(&self.output_filename).unwrap();
        for (stream_id, time, len, from) in self.frame_recv.drain(..) {
            writeln!(
                file,
                "{} {} {} {}",
                (stream_id - 1) / 4,
                time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_micros(),
                len,
                from.unwrap_or(10),
            ).unwrap();
        }
    }
}

struct UDPPacketSendingBuf {
    queued_packet: (u64, Vec<u8>),
    sent: usize,
}

pub enum BufType<'a> {
    Size(usize),
    Buffer(&'a [u8]),
}

pub struct RtpServer {
    socket: SockType,
    queued_streams: VecDeque<UDPPacketSendingBuf>,
    time_sent_to_quic: Vec<(u64, time::Instant)>,
    time_sent_to_wire: Vec<(u64, time::Instant)>,

    start_rtp: Option<time::Instant>,

    to_quic_filename: String,
    to_wire_filename: String,

    last_provided_stream: u64,
    next_stream_id: u64,
    buf: [u8; 2000],

    stop_msg: Vec<u8>,
    is_stopped: bool,
}

impl RtpServer {
    pub fn new(
        bind_addr: std::net::SocketAddr, to_quic_filename: &str,
        to_wire_filename: &str, stop_msg: &str,
    ) -> io::Result<Self> {
        info!("new RTP server listening for RTP in {}", bind_addr);
        info!("Stop msg in bytes: {:?}", stop_msg.as_bytes());
        Ok(Self {
            socket: SockType::Mio(mio::net::UdpSocket::bind(bind_addr)?),
            queued_streams: VecDeque::new(),
            time_sent_to_quic: Vec::new(),
            time_sent_to_wire: Vec::new(),
            start_rtp: Some(time::Instant::now()),

            last_provided_stream: 0,
            next_stream_id: 3,

            to_quic_filename: to_quic_filename.to_string(),
            to_wire_filename: to_wire_filename.to_string(),
            buf: [0; 2000],

            stop_msg: stop_msg.as_bytes().to_vec(),
            is_stopped: false,
        })
    }

    pub async fn new_with_tokio(
        bind_addr: std::net::SocketAddr, to_quic_filename: &str,
        to_wire_filename: &str, stop_msg: &str,
    ) -> io::Result<Self> {
        info!("new RTP server listening for RTP in {}", bind_addr);
        info!("Stop msg in bytes: {:?}", stop_msg.as_bytes());
        Ok(Self {
            socket: SockType::Tokio(
                tokio::net::UdpSocket::bind(bind_addr).await?,
            ),
            queued_streams: VecDeque::new(),
            time_sent_to_quic: Vec::new(),
            time_sent_to_wire: Vec::new(),
            start_rtp: Some(time::Instant::now()),

            last_provided_stream: 0,
            next_stream_id: 3,

            to_quic_filename: to_quic_filename.to_string(),
            to_wire_filename: to_wire_filename.to_string(),
            buf: [0; 2000],

            stop_msg: stop_msg.as_bytes().to_vec(),
            is_stopped: false,
        })
    }

    pub fn new_without_socket(stop_msg: &str) -> Self {
        Self {
            socket: SockType::None,
            queued_streams: VecDeque::new(),
            time_sent_to_quic: Vec::new(),
            time_sent_to_wire: Vec::new(),
            start_rtp: Some(time::Instant::now()),

            last_provided_stream: 0,
            next_stream_id: 3,

            to_quic_filename: "/tmp/out.txt".to_string(),
            to_wire_filename: "/tmp/out2.txt".to_string(),
            buf: [0; 2000],

            stop_msg: stop_msg.as_bytes().to_vec(),
            is_stopped: false,
        }
    }

    #[inline]
    pub fn additional_udp_socket(&mut self) -> Option<&mut mio::net::UdpSocket> {
        self.socket.mio_mut()
    }

    #[inline]
    pub fn additional_udp_socket_tokio(&self) -> Option<&tokio::net::UdpSocket> {
        self.socket.tokio()
    }

    pub fn get_app_data(&mut self) -> (u64, Vec<u8>) {
        let front = self.queued_streams.front().unwrap();
        self.last_provided_stream = front.queued_packet.0;
        debug!(
            "Send data on stream {}, offset={}, len={}",
            self.last_provided_stream,
            front.sent,
            front.queued_packet.1.len() - front.sent
        );
        (
            front.queued_packet.0,
            front.queued_packet.1[front.sent..].to_vec(),
        )
    }

    pub fn on_sent_to_quic(&mut self) {
        self.time_sent_to_quic
            .push((self.last_provided_stream, time::Instant::now()))
    }

    pub fn on_sent_to_wire(&mut self) {
        self.time_sent_to_wire
            .push((self.last_provided_stream, time::Instant::now()));
    }

    pub fn on_finish(&self) {
        let mut file = std::fs::File::create(&self.to_quic_filename).unwrap();
        for (stream_id, time) in self.time_sent_to_quic.iter() {
            writeln!(
                file,
                "{} {}",
                (stream_id - 1) / 4,
                time.duration_since(self.start_rtp.unwrap()).as_micros(),
            )
            .unwrap();
        }

        let mut file = std::fs::File::create(&self.to_wire_filename).unwrap();
        for (stream_id, time) in self.time_sent_to_wire.iter() {
            writeln!(
                file,
                "{} {}",
                (stream_id - 1) / 4,
                time.duration_since(self.start_rtp.unwrap()).as_micros(),
            )
            .unwrap();
        }
    }

    #[inline]
    pub fn on_additional_udp_socket_readable(&mut self) {
        let mut nb = 0;

        loop {
            let res = match &self.socket {
                SockType::Mio(s) => s.recv_from(&mut self.buf[..]),
                SockType::Tokio(s) => s.try_recv_from(&mut self.buf[..]),
                SockType::None => return,
            };
            match res {
                Ok((n, _)) => {
                    self.handle_new_rtp_frame(BufType::Size(n), self.next_stream_id);
                    self.next_stream_id += 4;
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("stop reading RTP socket, would block");
                        break;
                    }
                    panic!("unexpected error when readin on RTP socket: {}", e);
                },
            }

            nb += 1;

            // Avoid generating too many packets RTP frames at once.
            if nb > 100 {
                break;
            }
        }
    }

    #[inline]
    pub fn handle_new_rtp_frame(&mut self, buf_type: BufType, next_stream_id: u64) {
        let (n, buf) = match buf_type {
            BufType::Size(n) => (n, &self.buf[..n]),
            BufType::Buffer(buff) => (buff.len(), buff),
        };
        trace!(
            "read {} bytes from RTP socket, enqueue in stream {}",
            n,
            next_stream_id
        );
        if n >= self.stop_msg.len() && n.abs_diff(self.stop_msg.len()) <= 1 && &buf[..self.stop_msg.len()] == &self.stop_msg {
            // STOP RTP message.
            self.is_stopped = true;
            debug!("Received the end of the RTP stream");
            return;
        }

        self.queued_streams.push_back(UDPPacketSendingBuf {
            queued_packet: (next_stream_id, buf[..n].to_vec()),
            sent: 0,
        });
        self.next_stream_id = next_stream_id;
    }

    #[inline]
    pub fn app_has_started(&self) -> bool {
        self.start_rtp.is_some()
    }

    #[inline]
    pub fn should_send_app_data(&self) -> bool {
        !self.queued_streams.is_empty()
    }

    #[inline]
    pub fn stream_written(&mut self, v: usize) {
        let udp_packet_buf = self.queued_streams.front_mut().unwrap();
        udp_packet_buf.sent += v;
        trace!(
            "written {} bytes, {} bytes remaining",
            v,
            udp_packet_buf.queued_packet.1.len() - udp_packet_buf.sent
        );
        if udp_packet_buf.sent == udp_packet_buf.queued_packet.1.len() {
            self.queued_streams.pop_front();
        }
    }

    #[inline]
    pub fn has_sent_some_data(&self) -> bool {
        self.last_provided_stream > 0
    }

    #[inline]
    pub fn is_source_rtp_stopped(&self) -> bool {
        self.is_stopped
    }
}
