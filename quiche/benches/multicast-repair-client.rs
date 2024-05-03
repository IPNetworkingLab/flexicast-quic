use std::collections::VecDeque;
use std::fmt::Display;

use quiche::multicast::authentication::McAuthType;
use quiche::multicast::testing::MulticastPipe;
use quiche::multicast::testing::OpenRangeSet;
use quiche::multicast::FcConfig;
use quiche::multicast::McPathType;
use quiche::multicast::MulticastConnection;
use quiche::Connection;
use quiche::RecvInfo;

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
            FecResetFreq::Sliding(v) => v.to_string(),
            FecResetFreq::NoFec(v) => format!("false-{}", v).to_string(),
        })
    }
}

fn setup_mc(
    buf: &[u8], auth: McAuthType, lost_gap: u64,
    remove_source_symbols: FecResetFreq,
) -> (Connection, VecDeque<Vec<u8>>, RecvInfo) {
    let mut fc_config = FcConfig {
        use_fec: false,
        probe_mc_path: false,
        authentication: auth,
        ..FcConfig::default()
    };
    let mut pipe =
        MulticastPipe::new(NB_RECV, "/tmp/bench", &mut fc_config).unwrap();

    pipe.mc_channel.channel.stream_send(1, buf, true).unwrap();

    let mut packets = VecDeque::with_capacity(buf.len() / 2000);
    let mut nb_sent = 0;
    let mut nack_ranges = OpenRangeSet::new();
    loop {
        let mut buf = vec![0u8; 1500];

        let written = match pipe.mc_channel.mc_send(&mut buf) {
            Ok((w, _)) => {
                nb_sent += 1;
                w
            },
            Err(quiche::Error::Done) => break,
            Err(e) => panic!("Setup mc error: {}", e),
        };

        if nb_sent % lost_gap == 0 {
            // Generate a loss.
            #[cfg(test)]
            {
                nack_ranges.populate(nb_sent - 3..nb_sent - 2);

                if matches!(remove_source_symbols, FecResetFreq::Sliding(_)) {
                    pipe.mc_channel
                        .set_source_nack_range(&nack_ranges, u64::MAX)
                        .unwrap();
                }

                // Use this time to remove old source symbols that are not in the
                // window anymore.
                let w = match remove_source_symbols {
                    FecResetFreq::NoFec(v) => v,
                    FecResetFreq::Sliding(v) => v,
                };
                if let Some(md) =
                    pipe.mc_channel.fec_sliding_window_metadata(w as usize)
                {
                    pipe.mc_channel.remove_source_symbols(md);
                }
            }
        } else {
            packets.push_back(buf[..written].to_vec());
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

    let mut group = c.benchmark_group("multicast-repair-client");
    for &auth in &[McAuthType::None] {
        for &remove_source_symbols in &[
            // FecResetFreq::Auto,
            // FecResetFreq::Never,
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
                            || {
                                setup_mc(
                                    &buf,
                                    auth,
                                    lost_gap,
                                    remove_source_symbols,
                                )
                            },
                            |(mut conn, mut packets, recv_info)| {
                                while let Some(mut packet) = packets.pop_front() {
                                    conn.mc_recv(&mut packet, recv_info).unwrap();
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
