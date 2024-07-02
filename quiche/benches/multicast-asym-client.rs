use std::fmt::Display;

use quiche::multicast::authentication::McAuthType;
use quiche::multicast::testing::MulticastPipe;
use quiche::multicast::McPathType;
use quiche::multicast::MulticastConnection;
use quiche::Connection;
use quiche::RecvInfo;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize::PerIteration;
use criterion::BenchmarkId;
use criterion::Criterion;
use std::collections::VecDeque;

const BENCH_STREAM_TOTAL_SIZE: usize = 10_000_000;
const BENCH_STEP_SIZE: usize = 10;
const NB_RECV: usize = 1;

/// Sets up the benchmark for multicast.
/// This function emulates the client sending [`BENCH_STREAM_SIZE`] bytes in a
/// single stream to the clients. The function returns a single Client
/// connection, and the set of packets that they will receive.
/// The last part of the returned tuple is the potential data and
/// [`quiche::RecvInfo`] for the authentication path if symmetric authentication
/// is used.
fn setup_mc(
    buf: &[u8], stream_size: usize, auth: McAuthType,
) -> (
    Connection,
    VecDeque<Vec<u8>>,
    RecvInfo,
) {
    let mut pipe =
        MulticastPipe::new(NB_RECV, "/tmp/bench", auth, false, false, None).unwrap();
    
        let nb_streams = buf.len() / stream_size;
        for i in 0..nb_streams {
            pipe.mc_channel
                .channel
                .stream_send(
                    i as u64 * 4 + 1,
                    &buf[i * stream_size..(i + 1) * stream_size],
                    true,
                )
                .unwrap();
        }

    // Generate the packets all at once.
    let mut packets = VecDeque::with_capacity(buf.len() / 2000);
    loop {
        let mut buf = vec![0u8; 1500]; // Or allocate on the stack?
        match pipe.mc_channel.mc_send(&mut buf) {
            Ok((w, _)) => packets.push_back(buf[..w].to_vec()),
            Err(quiche::Error::Done) => break,
            Err(e) => panic!("Setup mc errror: {}", e),
        }
    }

    let pipe = pipe.unicast_pipes.remove(0);
    let recv_info = RecvInfo {
        from: pipe.2,
        to: pipe.1,
        from_mc: Some(McPathType::Data),
    };
    let out_conn = pipe.0.client;
    (out_conn, packets, recv_info)
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
    let buf = vec![0; BENCH_STREAM_TOTAL_SIZE];

    let mut stream_sizes = vec![100];
    loop {
        let last = stream_sizes.last().unwrap();
        if *last >= BENCH_STREAM_TOTAL_SIZE {
            break;
        }
        stream_sizes.push(last * BENCH_STEP_SIZE);
    }

    // let stream_sizes = vec![BENCH_STREAM_TOTAL_SIZE];

    let mut group = c.benchmark_group("multicast-client-asym");
    // for &auth in &[McAuthType::AsymSign, McAuthType::None, McAuthType::StreamAsym] {
    for &auth in &[McAuthType::None, McAuthType::StreamAsym] {
    // for &auth in &[McAuthType::StreamAsym] {
        for &stream_size in
            stream_sizes.iter() {
            group.bench_with_input(
                BenchmarkId::from_parameter(McTuple::from((auth, stream_size))),
                &(auth, stream_size),
                |b, &(auth, nb_recv)| {
                    b.iter_batched(
                        || setup_mc(&buf, nb_recv, auth),
                        |(mut conn, mut packets, recv_info)| {
                            // We do not need to verify for a
                            // [`quiche::Error::Done`] because the client should
                            // process all incomming packets.
                            // println!("New benchmark.");
                            while let Some(mut packet) = packets.pop_front() {
                                // Consume data packet.
                                conn.mc_recv(&mut packet, recv_info).unwrap();
                            }
                            let mut buf = [0u8; 1500];
                            for stream_id in conn.readable() {
                                conn.mc_stream_recv(stream_id, &mut buf).unwrap();
                            }

                        },
                        PerIteration,
                    );
                },
            );
        }
    }
}

criterion_group!(benches, mc_client_bench);
criterion_main!(benches);
