use std::fmt::Display;

use quiche::multicast::authentication::McAuthType;
use quiche::multicast::testing::MulticastPipe;
use quiche::multicast::MulticastChannelSource;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize::PerIteration;
use criterion::BenchmarkId;
use criterion::Criterion;

const BENCH_STREAM_TOTAL_SIZE: usize = 10_000_000;
const BENCH_STEP_SIZE: usize = 10;
const NB_RECV: usize = 1;

fn setup_mc_only_source(
    buf: &[u8], auth: McAuthType, stream_size: usize,
) -> MulticastChannelSource {
    let mut pipe =
        MulticastPipe::new(NB_RECV, "/tmp/bench", auth, false, false, None)
            .unwrap();

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

    pipe.mc_channel
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
    let buf = vec![0; BENCH_STREAM_TOTAL_SIZE];
    // let mut stream_sizes = vec![100];
    // loop {
    //     let last = stream_sizes.last().unwrap();
    //     if *last >= BENCH_STREAM_TOTAL_SIZE {
    //         break;
    //     }
    //     stream_sizes.push(last * BENCH_STEP_SIZE);
    // }
    let stream_sizes = vec![BENCH_STREAM_TOTAL_SIZE / 2];

    let mut group = c.benchmark_group("multicast-asym-tmp");
    for &auth in &[
        // McAuthType::AsymSign,
        // McAuthType::None,
        McAuthType::StreamAsym,
    ] {
        for &stream_size in
            stream_sizes.iter()
        {
            group.bench_with_input(
                BenchmarkId::from_parameter(McTuple::from((auth, stream_size))),
                &(auth, stream_size),
                |b, &(auth, stream_size)| {
                    b.iter_batched(
                        || setup_mc_only_source(&buf, auth, stream_size),
                        |mut mc_channel| {
                            // Ask quiche to generate the outgoing packets with
                            // authentication.
                            println!("New benchmark");
                            let mut buffer = [0u8; 1500];
                            loop {
                                match mc_channel.mc_send(&mut buffer[..]) {
                                    Ok(_) => (),
                                    Err(quiche::Error::Done) => break,
                                    Err(e) => panic!("Error: {}", e),
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

criterion_group!(benches, mc_channel_bench);
criterion_main!(benches);
