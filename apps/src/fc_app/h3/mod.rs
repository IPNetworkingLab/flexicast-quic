//! Handles the HTTP/3 protocol over Flexicast QUIC for file delivery.

use serde::Deserialize;
use serde::Serialize;

pub mod receiver;
pub mod sender;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Structure containing the YAML manifest file.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Manifest {
    size: u64,
    blocks: Vec<(u64, u64)>,
}

/// Expands implicit blocks in a manifest that was truncated by blockize.py.
///
/// blockize.py only writes the first 10 blocks. The remaining blocks are
/// implicit: they all have the same size as the first block (except possibly
/// the last one), and their stream IDs continue incrementing by 4.
fn expand_implicit_blocks(manifest: &mut Manifest) {
    if manifest.blocks.is_empty() {
        return;
    }
    let block_size = manifest.blocks[0].0;
    let total_blocks = (manifest.size + block_size - 1) / block_size;
    let explicit_count = manifest.blocks.len() as u64;
    if explicit_count >= total_blocks {
        return;
    }
    let mut next_stream_id = manifest.blocks.last().unwrap().1 + 4;
    for i in explicit_count..total_blocks {
        let size = if i == total_blocks - 1 {
            let rem = manifest.size % block_size;
            if rem == 0 { block_size } else { rem }
        } else {
            block_size
        };
        manifest.blocks.push((size, next_stream_id));
        next_stream_id += 4;
    }
}
