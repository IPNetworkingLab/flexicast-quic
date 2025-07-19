//! This module is an extension of the controller.
//! It handles control information that must be aggregated between all unicast
//! path servers. It includes:
//! - Flow control
//! - TODO
//!
//! FC-TODO: currently does not handle a leaving receiver.

use super::Result;
use std::collections::HashMap;

#[derive(Debug)]
pub struct FcAggregator {
    /// All MAX_DATA, indexed by the receiver ID.
    max_datas: HashMap<u64, u64>,

    /// All MAX_STREAM_DATA, first indexed by the stream ID, then by the
    /// receiver ID. FC-TODO: better structure (e.g., BTreeMap?).
    max_stream_datas: HashMap<u64, HashMap<u64, u64>>,

    /// Currently the minimum MAX_DATA among all receiver, with the receiver ID.
    min_max_data: Option<(u64, u64)>,

    /// Currently the minimum MAX_STREAM_DATA, indexed by the stream ID, with
    /// the receiver ID.
    min_max_stream_datas: HashMap<u64, (u64, u64)>,
}

impl FcAggregator {
    /// Creates a new aggregator.
    pub fn new() -> Self {
        Self {
            max_datas: HashMap::new(),
            max_stream_datas: HashMap::new(),
            min_max_data: None,
            min_max_stream_datas: HashMap::new(),
        }
    }

    /// Handles the reception of a new [`FcAggregatedMsg`] from a receiver
    /// through the unicast path. The return value indicates whether new
    /// aggregated information must be passed to the flexicast flow.
    pub fn on_new_aggr_msg(
        &mut self, recv_id: u64, aggr_msg: FcAggregatedMsg,
    ) -> Result<Option<FcAggregatedMsg>> {
        // 1) Insert the new MAX_DATA value.
        self.max_datas.insert(recv_id, aggr_msg.max_data);

        // 2) Insert the new MAX_STREAM_DATA for all streams.
        for (sid, max) in aggr_msg.max_stream_datas.iter() {
            // Check if we already have a value for this stream ID.
            if !self.max_stream_datas.contains_key(sid) {
                self.max_stream_datas.insert(*sid, HashMap::new());
            }

            // Then insert the element.
            self.max_stream_datas
                .get_mut(sid)
                .map(|sid_max| sid_max.insert(recv_id, *max));
        }

        if let Some((_current_id, current_max)) = self.min_max_data {
            // Check: if the new max is below the current, this is an error.
            if current_max > aggr_msg.max_data {
                error!(
                    "Flexicast Flow error!! {} < {} for recv {}",
                    aggr_msg.max_data, current_max, recv_id
                );
            }
        }

        Ok(self.flow_control_limits(
            aggr_msg.max_stream_datas.iter().map(|(sid, _)| *sid),
        ))
    }

    /// Run the flow control selection process to determine the new minimum flow
    /// control limits.
    fn flow_control_limits<I>(&mut self, stream_ids: I) -> Option<FcAggregatedMsg>
    where
        I: Iterator<Item = u64>,
    {
        // Check if there is a new MAX_DATA limit.
        let max_data_updated =
            match self.max_datas.iter().map(|(k, v)| (v, k)).min() {
                Some((new_max, new_id)) => {
                    let max_data_updated =
                        self.min_max_data.is_some_and(|(_, v)| v < *new_max);
                    self.min_max_data = Some((*new_id, *new_max));
                    max_data_updated
                },
                None => false,
            };

        // 4) Check if there is a new stream data minimum.
        let mut stream_updates = HashMap::new();
        for sid in stream_ids {
            let stream_map = match self.max_stream_datas.get(&sid) {
                Some(v) => v,
                None => continue,
            };

            let (new_max, new_id) =
                match stream_map.iter().map(|(k, v)| (v, k)).min() {
                    Some(v) => v,
                    None => continue,
                };

            let stream_max_data_updated = self
                .min_max_stream_datas
                .get(&sid)
                .is_none_or(|(_, v)| *v < *new_max);
            self.min_max_stream_datas.insert(sid, (*new_id, *new_max));

            if stream_max_data_updated {
                stream_updates.insert(sid, *new_max);
            }
        }

        let out_aggr = if max_data_updated || !stream_updates.is_empty() {
            Some(FcAggregatedMsg {
                max_data: self.min_max_data.unwrap().1,
                max_stream_datas: stream_updates,
            })
        } else {
            None
        };

        out_aggr
    }
}

#[derive(Debug)]
/// Aggregated information from the unicast path instances.
pub struct FcAggregatedMsg {
    /// MAX_DATA for the unicast path.
    pub max_data: u64,

    /// MAX_STREAM_DATA, indexed by the stream ID.
    pub max_stream_datas: HashMap<u64, u64>,
}
