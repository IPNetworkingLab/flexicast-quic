use std::fmt::Display;

use quiche::multicast::authentication::McAuthType;
use quiche::multicast::authentication::McSymAuth;
use quiche::multicast::testing::get_test_mc_config;
use quiche::multicast::testing::MulticastPipe;
use quiche::multicast::testing::CLIENT_AUTH_ADDR;
use quiche::multicast::McPathType;
use quiche::multicast::MulticastConnection;
use quiche::testing::Pipe;
use quiche::Connection;
use quiche::RecvInfo;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize::PerIteration;
use criterion::BenchmarkId;
use criterion::Criterion;
use std::collections::VecDeque;

const BENCH_STREAM_SIZE: usize = 10_000_000;
const BENCH_NB_RECV_MAX: usize = 40;
const BENCH_STEP_RECV: usize = 10;

/// Sets up the benchmark for multicast.
/// This function emulates the client sending [`BENCH_STREAM_SIZE`] bytes in a
/// single stream to the clients. The function returns a single Client
/// connection, and the set of packets that they will receive.
/// The last part of the returned tuple is the potential data and
/// [`quiche::RecvInfo`] for the authentication path if symmetric authentication
/// is used.
fn setup_mc(
    buf: &[u8], nb_recv: usize, auth: McAuthType,
) -> (
    Connection,
    VecDeque<Vec<u8>>,
    RecvInfo,
    Option<(VecDeque<Vec<u8>>, RecvInfo)>,
) {
    let mut pipe =
        MulticastPipe::new(nb_recv, "/tmp/bench", auth, false, false, None).unwrap();
    pipe.mc_channel.channel.stream_send(1, buf, true).unwrap();

    // Generate the packets all at once.
    let mut packets = VecDeque::with_capacity(buf.len() / 2000);
    let mut packets_auth = VecDeque::with_capacity(100);
    loop {
        let mut buf = vec![0u8; 1500]; // Or allocate on the stack?
        match pipe.mc_channel.mc_send(&mut buf) {
            Ok((w, _)) => packets.push_back(buf[..w].to_vec()),
            Err(quiche::Error::Done) => break,
            Err(e) => panic!("Setup mc errror: {}", e),
        }
        if auth == McAuthType::SymSign {
            let mut buf = vec![0u8; 1500];
            let clients: Vec<_> = pipe
                .unicast_pipes
                .iter_mut()
                .map(|(conn, ..)| &mut conn.server)
                .collect();
            pipe.mc_channel.channel.mc_sym_sign(&clients).unwrap();
            match pipe.mc_channel.mc_send_sym_auth(&mut buf) {
                Ok(w) => packets_auth.push_back(buf[..w].to_vec()),
                Err(e) => panic!("Setup mc auth error: {}", e),
            }
        }
    }

    let pipe = pipe.unicast_pipes.remove(0);
    let recv_info = RecvInfo {
        from: pipe.2,
        to: pipe.1,
        from_mc: Some(McPathType::Data),
    };
    let auth_info = if auth == McAuthType::SymSign {
        Some((packets_auth, RecvInfo {
            from: pipe.2,
            to: CLIENT_AUTH_ADDR.parse().unwrap(),
            from_mc: Some(McPathType::Authentication),
        }))
    } else {
        None
    };
    let out_conn = pipe.0.client;
    (out_conn, packets, recv_info, auth_info)
}

fn setup_uc(buf: &[u8]) -> (Connection, VecDeque<Vec<u8>>, RecvInfo) {
    let mut config = get_test_mc_config(false, None, false, McAuthType::None);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::DISABLED);
    let mut pipe = Pipe::with_config(&mut config).unwrap();
    pipe.handshake().unwrap();

    pipe.server.stream_send(1, buf, true).unwrap();
    let mut recv_info = None;

    let mut packets = VecDeque::with_capacity(buf.len() / 2000);
    loop {
        let mut buf = vec![0u8; 1500];
        match pipe.server.send(&mut buf) {
            Ok((w, send_info)) => {
                packets.push_back(buf[..w].to_vec());
                if recv_info.is_none() {
                    recv_info = Some(RecvInfo {
                        from: send_info.from,
                        to: send_info.to,
                        from_mc: None,
                    });
                }
            },
            Err(quiche::Error::Done) => break,
            Err(e) => panic!("Setup uc error: {}", e),
        }
    }

    (pipe.client, packets, recv_info.unwrap())
}

struct McTuple {
    auth: McAuthType,
    nb_recv: usize,
}

impl Display for McTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}-{}", self.auth, self.nb_recv)
    }
}

impl From<(McAuthType, usize)> for McTuple {
    fn from(value: (McAuthType, usize)) -> Self {
        Self {
            auth: value.0,
            nb_recv: value.1,
        }
    }
}

fn mc_client_bench(c: &mut Criterion) {
    let buf = vec![0; BENCH_STREAM_SIZE];

    let mut group = c.benchmark_group("multicast-client-1G");
    // for &auth in &[McAuthType::AsymSign, McAuthType::None, McAuthType::SymSign]
    // { for &auth in &[McAuthType::AsymSign, McAuthType::None] {
    for &auth in &[McAuthType::SymSign] {
        for nb_recv in (1..2).chain(
            (BENCH_STEP_RECV..BENCH_NB_RECV_MAX + 1).step_by(BENCH_STEP_RECV),
        ) {
            group.bench_with_input(
                BenchmarkId::from_parameter(McTuple::from((auth, nb_recv))),
                &(auth, nb_recv),
                |b, &(auth, nb_recv)| {
                    b.iter_batched(
                        || setup_mc(&buf, nb_recv, auth),
                        |(mut conn, mut packets, recv_info, mut auth_info)| {
                            // We do not need to verify for a
                            // [`quiche::Error::Done`] because the client should
                            // process all incomming packets.
                            while let Some(mut packet) = packets.pop_front() {
                                // Consume data packet.
                                conn.mc_recv(&mut packet, recv_info).unwrap();

                                // Symmetric authentication?
                                if let Some((auth_pkts, auth_recv)) =
                                    auth_info.as_mut()
                                {
                                    let mut auth_pkt =
                                        auth_pkts.pop_front().unwrap();
                                    conn.mc_recv(&mut auth_pkt, *auth_recv)
                                        .unwrap();
                                }
                            }
                        },
                        PerIteration,
                    );
                },
            );
        }
    }
}

fn uc_client_bench(c: &mut Criterion) {
    // A benchmark consists in sending a fixed amount of bytes to the lib.
    let buf = vec![0; BENCH_STREAM_SIZE];

    let mut group = c.benchmark_group("unicast-client-1G");

    for nb_recv in (1..2)
        .chain((BENCH_STEP_RECV..BENCH_NB_RECV_MAX + 1).step_by(BENCH_STEP_RECV))
    {
        group.bench_function(BenchmarkId::from_parameter(nb_recv), |b| {
            b.iter_batched(
                || setup_uc(&buf),
                |(mut conn, mut packets, recv_info)| {
                    while let Some(mut packet) = packets.pop_front() {
                        conn.recv(&mut packet, recv_info).unwrap();
                    }
                },
                PerIteration,
            );
        });
    }
}

criterion_group!(benches, mc_client_bench, uc_client_bench);
// criterion_group!(benches, mc_client_bench);
// criterion_group!(benches, uc_client_bench);
criterion_main!(benches);
