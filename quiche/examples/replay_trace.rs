use std::io::BufRead;

fn replay_trace(filepath: &str) -> Result<Vec<(u64, usize)>, std::io::Error> {
    let file = std::fs::File::open(filepath)?;
        let buf_reader = std::io::BufReader::new(file);
    
        buf_reader.lines().map(|line| {
            let line = line?;
    
            let mut tab = line[1..].split(",");
            let timestamp: u64 = tab.next().unwrap().parse().unwrap();
            let nb_bytes: usize = tab.next().unwrap().parse().unwrap();
    
            Ok((timestamp, nb_bytes))
        }).collect::<Result<Vec<(u64, usize)>, std::io::Error>>()
}

fn main() {
    let trace = replay_trace("perf/tixeo_trace.repr").unwrap();

    println!("This is the trace: {:?}", trace);
}