use super::StreamMap;

impl StreamMap {
    /// Returns the set of open streams IDs.
    pub(crate) fn fc_get_stream_ids(&self) -> impl Iterator<Item = &u64> {
        self.streams.keys()
    }

    /// Resets hardly the sending side of a stream.
    /// Returns the real offset at which the stream was reset.
    pub(crate) fn fc_reset_stream_send_at(
        &mut self, stream_id: u64, off: u64,
    ) -> crate::Result<u64> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            // // Only reset if we have to come back earlier, otherwise we set at.
            // if stream.send.off_back() > off {
            //     let max_data = stream.send.max_off();
            //     stream.send = SendBuf::new(max_data);
            // }

            // let _ = stream.send.reset_at(off);

            // The current highest buffered offset.
            let buf_off = stream.send.off_back();

            // We reset the stream at the new offset if it is higher. Otherwise,
            // the "previous" data is useless because it is either already
            // received, or already inside the send buffer.
            if buf_off < off {
                let _ = stream.send.reset_at(off);
                Ok(off)
            } else {
                Ok(buf_off)
            }
        } else {
            Err(crate::Error::InvalidStreamState(stream_id))
        }
    }
}
