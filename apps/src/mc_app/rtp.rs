use mio::net::UdpSocket;
use std::collections::VecDeque;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::time;
use std::time::SystemTime;

pub struct RtpClient {
    frame_recv: Vec<(u64, SystemTime, usize)>,

    output_filename: String,

    udp_sink: UdpSocket,
}

impl RtpClient {
    pub fn new(
        output_filename: &str, udp_sink_addr: SocketAddr,
    ) -> io::Result<Self> {
        let udp_sink = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
        udp_sink.connect(udp_sink_addr)?;

        Ok(Self {
            frame_recv: Vec::new(),
            output_filename: output_filename.to_owned(),
            udp_sink,
        })
    }

    pub fn on_stream_complete(
        &mut self, stream_id: u64, now: SystemTime, len: usize,
    ) {
        self.frame_recv.push((stream_id, now, len));
        trace!("RTP Client: stream {stream_id} complete, send {len} bytes to UDP sink");
    }

    pub fn on_sequential_stream_recv(&mut self, buf: &[u8]) {
        if let Err(e) = self.udp_sink.send(buf) {
            error!("RTP Client: error when sending data to UDP sink: {:?}", e);
        }
    }
}

struct UDPPacketSendingBuf {
    queued_packet: (u64, Vec<u8>),
    sent: usize,
}

pub struct RtpServer {
    socket: mio::net::UdpSocket,
    queued_streams: VecDeque<UDPPacketSendingBuf>,
    time_sent_to_quic: Vec<(u64, time::Instant)>,
    time_sent_to_wire: Vec<(u64, time::Instant)>,

    start_rtp: Option<time::Instant>,

    to_quic_filename: String,
    to_wire_filename: String,

    last_provided_stream: u64,
    next_stream_id: u64,
    buf: [u8; 2000],
}

impl RtpServer {
    pub fn new(
        bind_addr: std::net::SocketAddr, to_quic_filename: &str,
        to_wire_filename: &str,
    ) -> io::Result<Self> {
        info!("new RTP server listening for RTP in {}", bind_addr);
        Ok(Self {
            socket: mio::net::UdpSocket::bind(bind_addr)?,
            queued_streams: VecDeque::new(),
            time_sent_to_quic: Vec::new(),
            time_sent_to_wire: Vec::new(),
            start_rtp: Some(time::Instant::now()),

            last_provided_stream: 0,
            next_stream_id: 3,

            to_quic_filename: to_quic_filename.to_string(),
            to_wire_filename: to_wire_filename.to_string(),
            buf: [0; 2000],
        })
    }

    pub fn next_timeout(&self) -> Option<time::Duration> {
        // the RTP stream has started and there are data to send, but waking up
        // whould all be handled by pulling the additional_udp_socket
        None
    }

    #[inline]
    pub fn additional_udp_socket(&mut self) -> Option<&mut mio::net::UdpSocket> {
        Some(&mut self.socket)
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
        loop {
            match self.socket.recv_from(&mut self.buf[..]) {
                Ok((n, _)) => {
                    trace!(
                        "read {} bytes from RTP socket, enqueue in stream {}",
                        n,
                        self.next_stream_id
                    );
                    self.queued_streams.push_back(UDPPacketSendingBuf {
                        queued_packet: (
                            self.next_stream_id,
                            self.buf[..n].to_vec(),
                        ),
                        sent: 0,
                    });
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
        }
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
}
