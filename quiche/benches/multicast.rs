use std::fmt::Display;
use std::time;
use std::thread;

use quiche::multicast::authentication::McAuthType;
use quiche::multicast::authentication::McSymAuth;
use quiche::multicast::testing::get_test_mc_config;
use quiche::multicast::testing::MulticastPipe;
use quiche::multicast::MulticastConnection;
use quiche::testing::Pipe;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize::PerIteration;
use criterion::BenchmarkId;
use criterion::Criterion;

const BENCH_STREAM_SIZE: usize = 10_000_000;
const BENCH_NB_RECV_MAX: usize = 10;
const BENCH_STEP_RECV: usize = 10;

fn setup_mc(buf: &[u8], nb_recv: usize, auth: McAuthType) -> MulticastPipe {
    let mut pipe =
        MulticastPipe::new(nb_recv, "/tmp/bench", auth, false).unwrap();

    pipe.mc_channel.channel.stream_send(1, buf, true).unwrap();

    pipe
}

fn setup_uc(buf: &[u8], nb_recv: usize) -> Vec<quiche::Connection> {
    (0..nb_recv)
        .map(|_| {
            let mut config =
                get_test_mc_config(false, None, false, McAuthType::None);
            config.set_cc_algorithm(quiche::CongestionControlAlgorithm::DISABLED);
            let mut pipe = Pipe::with_config(&mut config).unwrap();
            pipe.handshake().unwrap();

            pipe.server.stream_send(1, buf, true).unwrap();

            pipe.server
        })
        .collect()
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

fn mc_channel_bench(c: &mut Criterion) {
    let buf = vec![0; BENCH_STREAM_SIZE];

    let mut group = c.benchmark_group("multicast-1G");
    // for &auth in &[McAuthType::AsymSign, McAuthType::None, McAuthType::SymSign]
    // {
    for &auth in &[McAuthType::SymSign] {
        for nb_recv in // (1..2).chain(
            (BENCH_STEP_RECV..BENCH_NB_RECV_MAX + 1)
                .step_by(BENCH_STEP_RECV)
        {
            group.bench_with_input(
                BenchmarkId::from_parameter(McTuple::from((auth, nb_recv))),
                &(auth, nb_recv),
                |b, &(auth, nb_recv)| {
                    b.iter_batched(
                        || setup_mc(&buf, nb_recv, auth),
                        |mut conn| {
                            let clients: Vec<_> = conn
                                .unicast_pipes
                                .iter_mut()
                                .map(|(conn, ..)| &mut conn.server)
                                .collect();
                            // Ask quiche to generate the outgoing packets with
                            // authentication.
                            let mut buffer = [0u8; 1500];
                            loop {
                                match conn.mc_channel.mc_send(&mut buffer[..]) {
                                    Ok(_) => (),
                                    Err(quiche::Error::Done) => break,
                                    Err(e) => panic!("Error: {}", e),
                                }

                                if auth == McAuthType::SymSign {
                                    // Generate the signatures.
                                    conn.mc_channel
                                        .channel
                                        .mc_sym_sign(&clients)
                                        .unwrap();
                                    let written = conn.mc_channel
                                        .mc_send_sym_auth(&mut buffer[..])
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

fn uc_channel_bench(c: &mut Criterion) {
    // A benchmark consists in sending a fixed amount of bytes to the lib.
    let buf = vec![0; BENCH_STREAM_SIZE];

    let mut group = c.benchmark_group("unicast-1G");
    for nb_recv in //(1..2)
        (BENCH_STEP_RECV..BENCH_NB_RECV_MAX + 1).step_by(BENCH_STEP_RECV)
    {
        group.bench_with_input(
            BenchmarkId::from_parameter(nb_recv),
            &nb_recv,
            |b, &nb_recv| {
                b.iter_batched(
                    || setup_uc(&buf, nb_recv),
                    |all_conn| {
                        // Ask quiche to generate the outgoing packets with
                        // authentication.
                        let mut buffer = [0u8; 1500];
                        for mut conn in all_conn {
                            loop {
                                match conn.send(&mut buffer) {
                                    Ok(_) => (),
                                    Err(quiche::Error::Done) => break,
                                    Err(e) => panic!("Error: {}", e),
                                }
                            }
                        }
                    },
                    PerIteration,
                );
            },
        );
    }
}

// criterion_group!(benches, mc_channel_bench, uc_channel_bench);
criterion_group!(benches, mc_channel_bench);
criterion_main!(benches);
