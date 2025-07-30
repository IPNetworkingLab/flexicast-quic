//! This module defines functions for data and control information exchange
//! between the flexicast source and the unicast instance servers. This module
//! intends to provide "multi-thread" friendly functions to exchange such
//! information.

use std::cmp;
use std::collections::HashMap;
use std::sync::Arc;
use std::time;

use super::reliable::FcUnicastRetransmission;
use super::FcError;
use super::FlexicastConnection;
use super::McClientStatus;
use super::McRole;
use crate::flexicast::ack::FcDelegatedStream;
use crate::flexicast::ack::McStreamOff;
use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::recovery::Sent;
use crate::Connection;
use crate::Error;
use crate::InternalPathId;
use crate::Result;

/// Open version of the Recovery::Sent.
pub type OpenSent = Sent;

impl Connection {
    /// Sets the first packet number that the receiver must listen to.
    pub fn fc_set_first_pn(&mut self, pn: Option<u64>) {
        if let Some(fc) = self.flexicast.as_mut() {
            if fc.fc_first_pn.is_none() {
                fc.fc_first_pn = pn;
            }
        }
    }

    /// Returns the packet numbers that have been sent on the flexicast flow and
    /// that the receiver acknowledged. Also returns the stream ranges that
    /// had been delegated on the unicast path and have been acknowledged by the
    /// receiver. Returns an error if invalid role.
    ///
    /// Needs mutable.
    pub fn get_new_ack_pn_streams(
        &mut self,
    ) -> Result<(Option<RangeSet>, Option<McStreamOff>)> {
        if let Some(fc) = self.flexicast.as_mut() {
            if !matches!(fc.get_mc_role(), McRole::ServerUnicast(_)) {
                return Err(Error::Flexicast(FcError::McInvalidRole(
                    fc.get_mc_role(),
                )));
            }

            if let Some(rfc) = fc.fc_reliable.server_mut() {
                // Get newly acked packet numbers.
                let new_ack_pn = rfc.mc_ack.full_ack();

                // Get acked stream pieces.
                let ack_stream_pieces = rfc.mc_ack.acked_stream_off();

                return Ok((new_ack_pn, ack_stream_pieces));
            }
            return Err(Error::Flexicast(FcError::McReliableDisabled));
        }
        Err(Error::Flexicast(FcError::McDisabled))
    }

    /// Returns the set of packets that have been sent on the flexicast flow,
    /// since the last time this function was called and that are still in the
    /// sent queue of the flexicast source. Returns an error if this
    /// function is called with the wrong role.
    pub fn fc_get_sent_pkt(&mut self, _from: Option<u64>) -> Result<Vec<Sent>> {
        if self.flexicast.is_none() {
            return Err(Error::Flexicast(FcError::McDisabled));
        }

        let flexicast = self.flexicast.as_mut().unwrap();
        if flexicast.get_mc_role() != McRole::ServerFlexicast {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                McRole::ServerFlexicast,
            )));
        }

        let max_pn = flexicast
            .fc_reliable
            .source()
            .and_then(|rfc| rfc.last_notified_pn)
            .unwrap_or(0);

        let pid = flexicast
            .fc_path_id
            .and_then(|path_id| self.paths.pid_from_path_id(path_id))
            .ok_or(Error::Flexicast(FcError::McPath))?;

        let path = self.paths.get_mut(pid);
        if let Ok(path) = path {
            let (new_max_pn, sent) =
                path.recovery.fc_get_sent_pkt(Epoch::Application, max_pn);
            self.flexicast
                .as_mut()
                .unwrap()
                .fc_reliable
                .source_mut()
                .ok_or(Error::Flexicast(FcError::McReliableDisabled))?
                .fc_set_last_notified_pn(new_max_pn);
            if sent.len() == 0 {
                return Err(Error::Done);
            }

            Ok(sent)
        } else {
            Err(Error::Flexicast(FcError::McPath))
        }
    }

    /// Notifies the connection of new packets that have been sent on the
    /// flexicast flow. Only available for the unicast server instances if
    /// the flexicast index is the correct one.
    pub fn fc_on_new_pkt_sent(
        &mut self, fc_id: usize, sent: Arc<Vec<Sent>>,
    ) -> Result<()> {
        if self.flexicast.is_none() {
            return Err(Error::Flexicast(FcError::McDisabled));
        }

        let flexicast = self.flexicast.as_mut().unwrap();
        if !matches!(flexicast.get_mc_role(), McRole::ServerUnicast(_)) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                flexicast.get_mc_role(),
            )));
        }

        let frc = flexicast
            .fc_reliable
            .server_mut()
            .ok_or(Error::Flexicast(FcError::McReliableDisabled))?;

        let highest_pn = frc.fc_highest_pn;
        let recv_acks = frc.mc_ack.recv_pkt_num.as_ref().unwrap().clone();

        // Update the new highest packet number.
        if let Some(last) = sent.last() {
            frc.fc_highest_pn = Some(last.pkt_num + 1);
        }

        // Maybe during channel change we receive "old" sent packets. Avoid
        // putting them in our state.
        let joined_fc_id = flexicast.fc_chan_id.as_ref().map(|(_, id)| *id);
        if joined_fc_id != Some(fc_id) {
            return Ok(());
        }

        let pid = flexicast
            .get_fc_path_id()
            .and_then(|path_id| self.paths.pid_from_path_id(path_id))
            .ok_or(Error::Flexicast(FcError::McPath))?;

        let handshake_status = self.handshake_status();
        let trace_id = self.trace_id().to_string();
        let (path, np) = self.paths.get_mut_with_active(pid)?;
        let now = time::Instant::now();

        for sent_pkt in sent.iter() {
            if sent_pkt.pkt_num < highest_pn.unwrap_or(0) {
                continue;
            }

            path.recovery.on_packet_sent(
                sent_pkt.clone(),
                Epoch::Application,
                handshake_status,
                now,
                &mut np.rtt_stats,
                &trace_id,
            );
        }

        // If there are some packets that have already been acknowledged to the
        // flexicast flow before the unicast path is aware, directly ACK them.
        if recv_acks.len() > 0 {
            path.recovery.on_ack_received(
                &recv_acks,
                0,
                Epoch::Application,
                handshake_status,
                now,
                &mut np.rtt_stats,
                &trace_id,
            )?;
        }

        Ok(())
    }

    /// Returns the set of STREAM frames that must be delegated to the receivers
    /// for unicast retransmission. This function does not take into account
    /// per-receiver reception of a STREAM frame, it will aggregate everything
    /// and forward all frames to the controller that will take the time to
    /// adjust to all clients.
    ///
    /// Returns an error if this is not the flexicast source.
    ///
    /// FC-TODO: this function does not take into account MC_ASYM frames for
    /// per-stream authentication! This will break per-stream authentication
    /// if the frame needs to be retransmitted.
    ///
    /// FC-TODO: also breaks FEC.
    ///
    /// The `early_retransmit` flag is set whenever the controller asks for
    /// the delegation of STREAM frames early in the process, i.e., frames that
    /// may not be lost will be delegated.
    pub fn fc_get_delegated_stream(
        &mut self, retr_kind: FcUnicastRetransmission,
    ) -> Result<Vec<FcDelegatedStream>> {
        if self.flexicast.is_none() {
            return Err(Error::Flexicast(FcError::McDisabled));
        }

        let flexicast = self.flexicast.as_ref().unwrap();
        if flexicast.get_mc_role() != McRole::ServerFlexicast {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                McRole::ServerFlexicast,
            )));
        }

        let fc_path_id = flexicast
            .get_fc_path_id()
            .ok_or(Error::Flexicast(FcError::McPath))?;
        let fc_path = self.paths.get_mut(InternalPathId(fc_path_id as usize))?;

        let streams = &mut self.streams;
        fc_path.recovery.fc_get_delegated_stream(streams, retr_kind)
    }

    /// Inserts in the unicast path delegated streams from the flexicast source.
    /// This creates states for streams that were previously sent on the
    /// flexicast flow and need unicast retransmission.
    ///
    /// Returns an error if this is not a unicast source instance.
    /// Does nothing if this is the wrong flexicast source ID, since we may be
    /// in a transient state because the receiver changed its flexicast flow.
    pub fn fc_delegated_streams(
        &mut self, fc_id: u64, delegated_streams: Arc<Vec<FcDelegatedStream>>,
        do_delegate: Vec<bool>,
    ) -> Result<()> {
        let flexicast = self
            .flexicast
            .as_ref()
            .ok_or(Error::Flexicast(FcError::McDisabled))?;

        if !matches!(flexicast.get_mc_role(), McRole::ServerUnicast(_)) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                flexicast.get_mc_role(),
            )));
        }

        // Maybe a transient state.
        if flexicast
            .fc_chan_id
            .as_ref()
            .map(|(_, id)| *id as u64 != fc_id)
            .unwrap_or(true)
        {
            return Ok(());
        }

        for (del_stream, delegate) in
            delegated_streams.iter().zip(do_delegate.iter())
        {
            // Don't retransmit on the unicast path if not indicated by the
            // controller.
            if !*delegate {
                continue;
            }

            // Insert inside McAck structure.
            if let Some(rfc) = self
                .flexicast
                .as_mut()
                .and_then(|fc| fc.fc_reliable.server_mut())
            {
                rfc.mc_ack.delegate(
                    del_stream.stream_id,
                    del_stream.offset,
                    del_stream.payload.len() as u64,
                );
            }

            let is_stream_collected =
                self.streams.is_collected(del_stream.stream_id);
            // FC-TODO: Woops, won't work if not local stream!
            let stream =
                match self.get_or_create_stream(del_stream.stream_id, true) {
                    Ok(v) => v,
                    Err(Error::Done) if is_stream_collected => {
                        continue;
                    },
                    Err(e) => return Err(e),
                };

            let was_flushable = stream.is_flushable();

            let _written = match stream.send.write_at_offset(
                &del_stream.payload,
                del_stream.offset,
                del_stream.fin,
            ) {
                Ok(v) => v,
                Err(Error::FinalSize) => {
                    // Hack by saying that it is correctly received.
                    // FC-TODO: will it work?
                    // Insert inside McAck structure.
                    if let Some(rfc) = self
                        .flexicast
                        .as_mut()
                        .and_then(|fc| fc.fc_reliable.server_mut())
                    {
                        rfc.mc_ack.on_stream_ack_received(
                            del_stream.stream_id,
                            del_stream.offset,
                            del_stream.payload.len() as u64,
                        );
                    }

                    continue;
                },
                Err(e) => {
                    return Err(e);
                },
            };

            // Mark the stream as flushable.
            let priority_key = Arc::clone(&stream.priority_key);
            if !was_flushable {
                self.streams.insert_flushable(&priority_key);
            }
        }

        Ok(())
    }

    /// Notifies the unicast path that some streams have been collected on the
    /// flexicast flow. If this happens, the unicast path knows that it will
    /// not receive new unicast retransmissions and it can collect its
    /// stream once all data is acknowledged.
    pub fn fc_notify_collected_streams(&self, uc: &mut Connection) {
        let stream_ids =
            uc.streams.fc_get_stream_ids().copied().collect::<Vec<_>>();
        for &stream_id in stream_ids.iter() {
            if self.streams.is_collected(stream_id) {
                if let Some(stream) = uc.streams.get_mut(stream_id) {
                    stream.send.fc_set_close_offset();

                    // Maybe the stream is now complete.
                    if stream.is_complete() && !stream.is_readable() {
                        let local = stream.local;
                        uc.streams.collect(stream_id, local);
                    }
                }
            }
        }
    }

    /// Returns the per-receiver unicast path point of view of the flexicast
    /// flow. This is possible since the unicast path instance has a view of
    /// the sent packets.
    ///
    /// Returns `None` if this is not the unicast path source.
    pub fn fc_get_flow_cwnd(&self) -> Option<usize> {
        if let Some(flexicast) = self.flexicast.as_ref() {
            if matches!(
                flexicast.get_mc_role(),
                McRole::ServerUnicast(McClientStatus::ListenMcPath(_))
            ) {
                if let Some(pid) = flexicast
                    .get_fc_path_id()
                    .and_then(|path_id| self.paths.pid_from_path_id(path_id))
                {
                    if let Ok(uc_path) = self.paths.get(pid) {
                        if uc_path.recovery.cwnd_available() == usize::MAX {
                            return None;
                        }
                        return Some(uc_path.recovery.cwnd());
                    }
                }
            }
        }
        None
    }

    /// Sets the congestion window of the flexicast flow on the flexicast
    /// source.
    ///
    /// This function should be called with the minimum per-receiver congestion
    /// window.
    ///
    /// Does nothing if this is not the flexicast flow.
    pub fn fc_set_flow_cwnd(&mut self, cwnd: usize) {
        if let Some(flexicast) = self.flexicast.as_ref() {
            if let Some(path_id) = flexicast.get_fc_path_id() {
                self.fc_set_cwnd_from_path_id(path_id, cwnd);
            }
        }
    }

    /// Force the congestion window to a given value on the given path id, if it
    /// exists.
    pub fn fc_set_cwnd_from_path_id(&mut self, path_id: u64, cwin: usize) {
        if let Some(pid) = self.paths.pid_from_path_id(path_id) {
            if let Ok(path) = self.paths.get_mut(pid) {
                path.recovery.fc_set_cwnd(cwin);
                self.update_tx_cap();
            }
        }
    }

    /// Sets the highest packet number that was sent on the flexicast flow.
    pub fn fc_set_highest_fc_pn(&mut self, pn: u64) -> Result<()> {
        if self.flexicast.is_none() {
            return Err(Error::Flexicast(FcError::McDisabled));
        }

        let flexicast = self.flexicast.as_mut().unwrap();
        flexicast.fc_first_pn = Some(pn);
        if let Some(rfc) = flexicast.fc_reliable.server_mut() {
            rfc.fc_highest_pn = Some(pn);
        }

        Ok(())
    }

    /// Releases, on the unicast path, the expired packets that were sent on the
    /// flexicast flow.
    pub fn fc_nack_release_expired_packets_on_uc_path(
        &mut self, pn: u64, now: time::Instant,
    ) -> Result<()> {
        // First ensure that this is the unicast path.
        let fca_path = fca!(self)?;
        if !matches!(fca_path.mc_role, McRole::ServerUnicast(_)) {
            return Err(Error::Flexicast(FcError::McInvalidRole(
                fca_path.mc_role,
            )));
        }

        let handshake_status = self.handshake_status();
        let trace_id = self.trace_id.as_str();

        let fc_id = fca_path
            .fc_path_id
            .ok_or(Error::Flexicast(FcError::McPath))?;
        let pid = self
            .paths
            .pid_from_path_id(fc_id)
            .ok_or(Error::Flexicast(FcError::McPath))?;
        let (path, np) = self.paths.get_mut_with_active(pid)?;
        path.recovery.fc_nack_release_sent_up_to(
            Epoch::Application,
            now,
            handshake_status,
            trace_id,
            pn,
            &mut np.rtt_stats,
        )
    }

    /// Single-threaded iterator over all unicast path servers for the
    /// communication with the flexicast flow.
    ///
    /// The output is a vector of [`crate::Result`] for the result of each item
    /// of the iterator.
    /// If the outer result is an error, it means an error with the flexicast
    /// flow. The last argument, `n`, can contain the number of elements in
    /// the iterator to optimize the creation of this output vector.
    pub fn fc_flow_uc_paths_control<'a, I>(
        &'a mut self, uc_paths: I, now: time::Instant, n: Option<usize>,
    ) -> Result<Vec<Result<()>>>
    where
        I: Iterator<Item = &'a mut Connection>,
    {
        let mut output = if let Some(v) = n {
            Vec::with_capacity(v)
        } else {
            Vec::new()
        };

        // Get the flow control limits over all unicast paths.
        // Max TX data.
        let mut max_tx_data = None;

        // Max stream TX data.
        let mut max_stream_tx_datas = HashMap::new();
        let stream_ids: Vec<_> =
            self.streams.fc_get_stream_ids().copied().collect();

        for uc_path in uc_paths {
            // Max TX data.
            let uc_path_max_tx_data = match uc_path.fc_get_max_tx_data() {
                Ok(v) => v,
                Err(e) => {
                    output.push(Err(e));
                    continue;
                },
            };

            max_tx_data = if let Some(tx) = max_tx_data {
                Some(cmp::min(tx, uc_path_max_tx_data))
            } else {
                Some(uc_path_max_tx_data)
            };

            // Max stream TX data.
            for stream_id in stream_ids.iter() {
                if let Ok(max_stream_tx_data) =
                    uc_path.fc_get_max_tx_stream_data(*stream_id)
                {
                    let value_to_insert =
                        if let Some(&v) = max_stream_tx_datas.get(stream_id) {
                            cmp::min(v, max_stream_tx_data)
                        } else {
                            max_stream_tx_data
                        };
                    max_stream_tx_datas.insert(*stream_id, value_to_insert);
                }
            }

            output.push(uc_path.uc_to_fc_control(self, now));
        }

        // Set the max tx data on the flexicast flow.
        if let Some(max_tx_data) = max_tx_data {
            self.fc_set_max_tx_data(max_tx_data)?;
        }

        // Set the max tx data for all streams.
        for (&stream_id, &max_stream_tx_data) in max_stream_tx_datas.iter() {
            self.fc_set_max_tx_stream_data(max_stream_tx_data, stream_id)?;
        }

        Ok(output)
    }
}
