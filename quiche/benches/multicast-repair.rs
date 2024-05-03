use std::fmt::Display;

use quiche::multicast::authentication::McAuthType;
use quiche::multicast::testing::MulticastPipe;
use quiche::multicast::testing::OpenRangeSet;
use quiche::multicast::MulticastChannelSource;
use quiche::multicast::FcConfig;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize::PerIteration;
use criterion::BenchmarkId;
use criterion::Criterion;

const BENCH_STREAM_TOTAL_SIZE: usize = 100_000_000;
const BENCH_LOST_STEP: u64 = 2;
const BENCH_LOST_MAX_GAP: u64 = 10_000;
const BENCH_LOST_MIN_GAP: u64 = 10;
const NB_RECV: usize = 1;

#[derive(Copy, Clone)]
enum FecResetFreq {
    Sliding(u64),
    NoFec(u64),
}

impl Display for FecResetFreq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            FecResetFreq::NoFec(v) => format!("false-{}", v).to_string(),
            FecResetFreq::Sliding(v) => v.to_string(),
        })
    }
}

fn setup_mc_only_source(buf: &[u8], auth: McAuthType) -> MulticastChannelSource {
    let mut fc_config = FcConfig {
        use_fec: true,
        probe_mc_path: false,
        authentication: auth,
        ..FcConfig::default()
    };
    let mut pipe =
        MulticastPipe::new(NB_RECV, "/tmp/bench", &mut fc_config)
            .unwrap();

    pipe.mc_channel.channel.stream_send(1, buf, true).unwrap();

    pipe.mc_channel
}

struct McTuple {
    auth: McAuthType,
    nb_recv: u64,
    remove_source_symbols: FecResetFreq,
}

impl Display for McTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}-{}-{}",
            self.auth, self.nb_recv, self.remove_source_symbols
        )
    }
}

impl From<(McAuthType, u64, FecResetFreq)> for McTuple {
    fn from(value: (McAuthType, u64, FecResetFreq)) -> Self {
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
        lost_gap.push(last * BENCH_LOST_STEP);
    }

    let mut group = c.benchmark_group("multicast-repair");
    for &auth in &[McAuthType::None] {
        for &remove_source_symbols in &[
            FecResetFreq::Sliding(1_000),
            FecResetFreq::Sliding(100),
            FecResetFreq::Sliding(10_000),
            FecResetFreq::NoFec(100),
        ] {
            for &lost_gap in lost_gap.iter() {
                group.bench_with_input(
                    BenchmarkId::from_parameter(McTuple::from((
                        auth,
                        lost_gap,
                        remove_source_symbols,
                    ))),
                    &(auth, lost_gap, remove_source_symbols),
                    |b, &(auth, lost_gap, remove_source_symbols)| {
                        b.iter_batched(
                            || setup_mc_only_source(&buf, auth),
                            |mut mc_channel| {
                                // Number of sent packets. Used to add losses.
                                let mut nb_sent = 0;
                                let mut nack_ranges = OpenRangeSet::new();

                                // Ask quiche to generate the outgoing packets
                                // with
                                // authentication.
                                let mut buffer = [0u8; 1500];
                                loop {
                                    let mut remove = match remove_source_symbols {
                                        FecResetFreq::NoFec(v) => mc_channel
                                            .fec_sliding_window_metadata(
                                                v as usize,
                                            ),
                                        FecResetFreq::Sliding(v) => mc_channel
                                            .fec_sliding_window_metadata(
                                                v as usize,
                                            ),
                                    };

                                    if nb_sent % lost_gap == 0 {
                                        // Generate a loss.
                                        #[cfg(test)]
                                        {
                                            nack_ranges.populate(
                                                nb_sent - 3..nb_sent - 2,
                                            );
                                            if matches!(
                                                remove_source_symbols,
                                                FecResetFreq::Sliding(_)
                                            ) {
                                                mc_channel
                                                    .set_source_nack_range(
                                                        &nack_ranges,
                                                        u64::MAX
                                                    )
                                                    .unwrap();
                                            }

                                            // Use this time to remove old source
                                            // symbols that are not in the window
                                            // anymore.
                                            if let (
                                                FecResetFreq::Sliding(_) |
                                                FecResetFreq::NoFec(_),
                                                Some(md),
                                            ) = (remove_source_symbols, remove)
                                            {
                                                mc_channel
                                                    .remove_source_symbols(md);
                                                remove = None;
                                            }
                                        }
                                    }

                                    match mc_channel.mc_send(&mut buffer[..]) {
                                        Ok(_) => nb_sent += 1,
                                        Err(quiche::Error::Done) => break,
                                        Err(e) => panic!("Error: {}", e),
                                    }

                                    if let Some(metadata) = remove {
                                        mc_channel
                                            .remove_source_symbols(metadata);
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
