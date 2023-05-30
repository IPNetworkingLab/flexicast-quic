use std::fmt::Display;

use quiche::multicast::authentication::McAuthType;
use quiche::multicast::testing::MulticastPipe;
use quiche::multicast::MulticastChannelSource;
use quiche::multicast::testing::OpenRangeSet;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize::PerIteration;
use criterion::BenchmarkId;
use criterion::Criterion;

const BENCH_STREAM_TOTAL_SIZE: usize = 30_000_000;
const BENCH_LOST_STEP: u64 = 10_000;
const BENCH_LOST_MAX_GAP: u64 = 10_000;
const BENCH_LOST_MIN_GAP: u64 = 1000;
const NB_RECV: usize = 1;

fn setup_mc_only_source(buf: &[u8], auth: McAuthType) -> MulticastChannelSource {
    let mut pipe =
        MulticastPipe::new(NB_RECV, "/tmp/bench", auth, true, false, None)
            .unwrap();

    pipe.mc_channel.channel.stream_send(1, buf, true).unwrap();

    pipe.mc_channel
}

struct McTuple {
    auth: McAuthType,
    nb_recv: u64,
    remove_source_symbols: bool,
}

impl Display for McTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}-{}-{}", self.auth, self.nb_recv, self.remove_source_symbols)
    }
}

impl From<(McAuthType, u64, bool)> for McTuple {
    fn from(value: (McAuthType, u64, bool)) -> Self {
        Self {
            auth: value.0,
            nb_recv: value.1,
            remove_source_symbols: value.2,
        }
    }
}

fn mc_channel_bench(c: &mut Criterion) {
    let buf = vec![0; BENCH_STREAM_TOTAL_SIZE];
    let mut lost_gap = vec![BENCH_LOST_MIN_GAP];
    loop {
        let last = lost_gap.last().unwrap();
        if *last >= BENCH_LOST_MAX_GAP {
            break;
        }
        lost_gap.push(last + BENCH_LOST_STEP);
    }

    let mut group = c.benchmark_group("multicast-repair");
    for &auth in &[McAuthType::None] {
        for &remove_source_symbols in &[true, false] {
            for &lost_gap in lost_gap.iter() {
                group.bench_with_input(
                    BenchmarkId::from_parameter(McTuple::from((auth, lost_gap, remove_source_symbols))),
                    &(auth, lost_gap, remove_source_symbols),
                    |b, &(auth, lost_gap, remove_source_symbols)| {
                        b.iter_batched(
                            || setup_mc_only_source(&buf, auth),
                            |mut mc_channel| {
                                // Number of sent packets. Used to add losses.
                                let mut nb_sent = 0;
                                let mut nack_ranges = OpenRangeSet::new();
    
                                // Ask quiche to generate the outgoing packets with
                                // authentication.
                                let mut buffer = [0u8; 1500];
                                loop {
                                    if nb_sent % lost_gap == 0 {
                                        // Generate a loss.
                                        #[cfg(test)]
                                        {
                                            nack_ranges.populate(nb_sent - 3..nb_sent - 2);
    
                                            mc_channel
                                                .set_source_nack_range(&nack_ranges)
                                                .unwrap();
                                        }
                                    }

                                    match mc_channel.mc_send(&mut buffer[..]) {
                                        Ok(_) => nb_sent += 1,
                                        Err(quiche::Error::Done) => break,
                                        Err(e) => panic!("Error: {}", e),
                                    }

                                    if nb_sent % lost_gap == 0 {
                                        if remove_source_symbols {
                                            mc_channel.remove_source_symbols(nb_sent);
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
    }
}

criterion_group!(benches, mc_channel_bench);
criterion_main!(benches);
