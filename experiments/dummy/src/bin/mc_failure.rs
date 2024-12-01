#[macro_use]
extern crate log;

use tokio::process::Command;
use std::{collections::HashSet, time::Duration, time::Instant};
use clap::Parser;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use tokio::sync::mpsc;

#[derive(Parser)]
struct Args {
    /// Number of receivers.
    nb_recv: usize,

    /// Link name prefix.
    #[clap(long = "link-prefix", default_value = "npfnsXXX-vethmc")]
    link_prefix: String,

    /// Duration of a link failure, in ms.
    #[clap(long = "fail-duration", value_parser, default_value = "1000")]
    fail_duration: u64,

    /// Duration between two link failures, in ms.
    /// This is the time between two STARTS of failures,
    /// so failures may overlap depending on the failure duration.
    #[clap(long = "fail-dist", value_parser, default_value = "1000")]
    fail_distance: u64,

    /// Total duration, in seconds.
    #[clap(long = "duration", value_parser, default_value = "10")]
    duration: u64,

    /// Probability to drop a link.
    #[clap(long = "proba", value_parser, default_value="1.0")]
    probability: f64,

    /// Seed of the failure sequence.
    #[clap(long = "seed", value_parser, default_value="42")]
    seed: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    let args = Args::parse();
    let fail_duration = Duration::from_millis(args.fail_duration);
    let fail_dist = Duration::from_millis(args.fail_distance);
    let exp_duration = Duration::from_secs(args.duration);

    // Remember the IDs that are available for failures
    let mut table: HashSet<usize> = (1..args.nb_recv + 1).collect();

    // Communication channel to receive up links back.
    let (tx, mut rx) = mpsc::channel(1000);

    let mut last_failure = None;
    let start = Instant::now();

    // Random with seed.
    let mut rng = SmallRng::seed_from_u64(args.seed);

    loop {
        // Computing next timeout.
        let next_timeout = match last_failure {
            Some(v) => {
                let now = Instant::now();
                fail_dist.saturating_sub(now.duration_since(v))
                    .min(
                        exp_duration.saturating_sub(now.duration_since(start))
                    )
            },
            None => Duration::ZERO
        };

        tokio::select! {
            Some(idx) = rx.recv() => {
                table.insert(idx);
                
                // Continue looping.
                continue;
            },

            _ = tokio::time::sleep(next_timeout) => (),
        }

        let now = Instant::now();
        last_failure = Some(now);
        if exp_duration.saturating_sub(now.duration_since(start)) == Duration::ZERO {
            if table.len() == args.nb_recv {
                break;
            } else {
                continue;
            }
        }

        // Only generate a failure with a given probability.
        let do_fail = rng.gen_bool(args.probability);
        if do_fail {
            // Find IDs that are available.
            if table.is_empty() {
                info!("Cannot set any link down... All are already. Restart the timer");
                continue;
            }
            let next_idx = rng.gen_range(0..table.len());

            // Sort to be sure that it is reproducible, even if not optimal.
            let mut ids_sort: Vec<_> = table.iter().collect();
            ids_sort.sort();

            let next_id = *ids_sort[next_idx];
            table.remove(&next_id);
    
            let link_name = args.link_prefix.replace("XXX", &format!("{:?}", next_id));
            let tx_clone = tx.clone();
    
            tokio::spawn(async move {
                fail_and_recover(fail_duration, link_name, tx_clone, next_id).await;
            });
        }
    }
    
}

async fn fail_and_recover(fail_duration: Duration, link_name: String, tx: mpsc::Sender<usize>, id: usize) {
    // Failure of the link.
    info!("Set link {link_name} down");
    let mut cmd = Command::new("ip");
    cmd.args(&["netns", "exec", &format!("npfns{id}"), "ip", "link", "set", &link_name, "down"]);
    _ = cmd.output().await.unwrap();
    let now = std::time::SystemTime::now();
    println!("{}-RESULT-RECV{} 5", now.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_micros(), id - 1);
        

    // Wait.
    tokio::time::sleep(fail_duration).await;

    // Replenish the link.
    let mut cmd = Command::new("ip");
    cmd.args(&["netns", "exec", &format!("npfns{id}"), "ip", "link", "set", &link_name, "up"]);
    _ = cmd.output().await.unwrap();

    info!("Set link {link_name} up");
    let now = std::time::SystemTime::now();
    println!("{}-RESULT-RECV{} 6", now.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_micros(), id - 1);

    // Notify that the link is up now.
    _ = tx.send(id).await.unwrap();
}