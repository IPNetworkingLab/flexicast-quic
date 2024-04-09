// Copyright (C) 2023, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::cmp;

use std::collections::VecDeque;
use std::convert::TryInto;

use crate::Error;
use crate::Result;

use crate::ranges;

use super::RangeBuf;

#[cfg(test)]
const SEND_BUFFER_SIZE: usize = 5;

#[cfg(not(test))]
const SEND_BUFFER_SIZE: usize = 4096;

/// Send-side stream buffer.
///
/// Stream data scheduled to be sent to the peer is buffered in a list of data
/// chunks ordered by offset in ascending order. Contiguous data can then be
/// read into a slice.
///
/// By default, new data is appended at the end of the stream, but data can be
/// inserted at the start of the buffer (this is to allow data that needs to be
/// retransmitted to be re-buffered).
#[derive(Debug, Default)]
pub struct SendBuf {
    /// Chunks of data to be sent, ordered by offset.
    data: VecDeque<RangeBuf>,

    /// The index of the buffer that needs to be sent next.
    pos: usize,

    /// The maximum offset of data buffered in the stream.
    off: u64,

    /// The maximum offset of data sent to the peer, regardless of
    /// retransmissions.
    emit_off: u64,

    /// The amount of data currently buffered.
    len: u64,

    /// The maximum offset we are allowed to send to the peer.
    max_data: u64,

    /// The last offset the stream was blocked at, if any.
    blocked_at: Option<u64>,

    /// The final stream offset written to the stream, if any.
    fin_off: Option<u64>,

    /// Whether the stream's send-side has been shut down.
    shutdown: bool,

    /// Ranges of data offsets that have been acked.
    acked: ranges::RangeSet,

    /// The error code received via STOP_SENDING.
    error: Option<u64>,

    /// Hash of the stream in the order of sending.
    /// This variable has a meaning only if multicast is enabled and
    /// [`crate::multicast::authentication::McAuthType::StreamAsym`] method is
    /// used, while the stream is not authenticated yet by the signature.
    pub hash: [u8; 32],

    /// Used for multicast. Set the maximum offset that the unicast source will
    /// transmit. After that, it can consider that the stream is complete.
    rmc_max_offset: Option<u64>,

    /// Whether the sending-side of the stream rotates and will potentially
    /// start again after completion.
    ///
    /// Flexicast with stream rotation extension.
    pub(super) fc_stream_rotate: bool,
}

impl SendBuf {
    /// Creates a new send buffer.
    pub fn new(max_data: u64) -> SendBuf {
        SendBuf {
            max_data,
            ..SendBuf::default()
        }
    }

    /// Inserts the given slice of data at the end of the buffer.
    ///
    /// The number of bytes that were actually stored in the buffer is returned
    /// (this may be lower than the size of the input buffer, in case of partial
    /// writes).
    pub fn write(&mut self, mut data: &[u8], mut fin: bool) -> Result<usize> {
        let max_off = self.off + data.len() as u64;

        // Get the stream send capacity. This will return an error if the stream
        // was stopped.
        let capacity = self.cap()?;

        if data.len() > capacity {
            // Truncate the input buffer according to the stream's capacity.
            let len = capacity;
            data = &data[..len];

            // We are not buffering the full input, so clear the fin flag.
            fin = false;
        }

        if let Some(fin_off) = self.fin_off {
            // Can't write past final offset.
            if max_off > fin_off {
                return Err(Error::FinalSize);
            }

            // Can't "undo" final offset.
            if max_off == fin_off && !fin {
                return Err(Error::FinalSize);
            }
        }

        if fin {
            self.fin_off = Some(max_off);
        }

        // Don't queue data that was already fully acked.
        if self.ack_off() >= max_off {
            return Ok(data.len());
        }

        // We already recorded the final offset, so we can just discard the
        // empty buffer now.
        if data.is_empty() {
            return Ok(data.len());
        }

        let mut len = 0;

        // Split the remaining input data into consistently-sized buffers to
        // avoid fragmentation.
        for chunk in data.chunks(SEND_BUFFER_SIZE) {
            len += chunk.len();

            let fin = len == data.len() && fin;

            let buf = RangeBuf::from(chunk, self.off, fin);

            // The new data can simply be appended at the end of the send buffer.
            self.data.push_back(buf);

            self.off += chunk.len() as u64;
            self.len += chunk.len() as u64;
        }

        Ok(len)
    }

    /// Writes data from the send buffer into the given output buffer.
    pub fn emit(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut out_len = out.len();
        let out_off = self.off_front();

        let mut next_off = out_off;

        while out_len > 0 &&
            self.ready() &&
            self.off_front() == next_off &&
            self.off_front() < self.max_data
        {
            let buf = match self.data.get_mut(self.pos) {
                Some(v) => v,

                None => break,
            };

            if buf.is_empty() {
                self.pos += 1;
                continue;
            }

            let buf_len = cmp::min(buf.len(), out_len);
            let partial = buf_len < buf.len();

            // Copy data to the output buffer.
            let out_pos = (next_off - out_off) as usize;
            out[out_pos..out_pos + buf_len].copy_from_slice(&buf[..buf_len]);

            self.len -= buf_len as u64;

            out_len -= buf_len;

            next_off = buf.off() + buf_len as u64;

            buf.consume(buf_len);

            if partial {
                // We reached the maximum capacity, so end here.
                break;
            }

            self.pos += 1;
        }

        // Override the `fin` flag set for the output buffer by matching the
        // buffer's maximum offset against the stream's final offset (if known).
        //
        // This is more efficient than tracking `fin` using the range buffers
        // themselves, and lets us avoid queueing empty buffers just so we can
        // propagate the final size.
        let fin = self.fin_off == Some(next_off);

        // Record the largest offset that has been sent so we can accurately
        // report final_size
        self.emit_off = cmp::max(self.emit_off, next_off);

        Ok((out.len() - out_len, fin))
    }

    /// Updates the max_data limit to the given value.
    pub fn update_max_data(&mut self, max_data: u64) {
        self.max_data = cmp::max(self.max_data, max_data);
    }

    /// Updates the last offset the stream was blocked at, if any.
    pub fn update_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.blocked_at = blocked_at;
    }

    /// The last offset the stream was blocked at, if any.
    pub fn blocked_at(&self) -> Option<u64> {
        self.blocked_at
    }

    /// Increments the acked data offset.
    pub fn ack(&mut self, off: u64, len: usize) {
        self.acked.insert(off..off + len as u64);
    }

    pub fn ack_and_drop(&mut self, off: u64, len: usize) {
        self.ack(off, len);

        let ack_off = self.ack_off();

        if self.data.is_empty() {
            return;
        }

        if off > ack_off {
            return;
        }

        let mut drop_until = None;

        // Drop contiguously acked data from the front of the buffer.
        for (i, buf) in self.data.iter_mut().enumerate() {
            // Newly acked range is past highest contiguous acked range, so we
            // can't drop it.
            if buf.off >= ack_off {
                break;
            }

            // Highest contiguous acked range falls within newly acked range,
            // so we can't drop it.
            if buf.off < ack_off && ack_off < buf.max_off() {
                break;
            }

            // Newly acked range can be dropped.
            drop_until = Some(i);
        }

        if let Some(drop) = drop_until {
            self.data.drain(..=drop);

            // When a buffer is marked for retransmission, but then acked before
            // it could be retransmitted, we might end up decreasing the SendBuf
            // position too much, so make sure that doesn't happen.
            self.pos = self.pos.saturating_sub(drop + 1);
        }
    }

    pub fn retransmit(&mut self, off: u64, len: usize) {
        let max_off = off + len as u64;
        let ack_off = self.ack_off();

        if self.data.is_empty() {
            return;
        }

        if max_off <= ack_off {
            return;
        }

        for i in 0..self.data.len() {
            let buf = &mut self.data[i];

            if buf.off >= max_off {
                break;
            }

            if off > buf.max_off() {
                continue;
            }

            // Split the buffer into 2 if the retransmit range ends before the
            // buffer's final offset.
            let new_buf = if buf.off < max_off && max_off < buf.max_off() {
                Some(buf.split_off((max_off - buf.off) as usize))
            } else {
                None
            };

            let prev_pos = buf.pos;

            // Reduce the buffer's position (expand the buffer) if the retransmit
            // range is past the buffer's starting offset.
            buf.pos = if off > buf.off && off <= buf.max_off() {
                cmp::min(buf.pos, buf.start + (off - buf.off) as usize)
            } else {
                buf.start
            };

            self.pos = cmp::min(self.pos, i);

            self.len += (prev_pos - buf.pos) as u64;

            if let Some(b) = new_buf {
                self.data.insert(i + 1, b);
            }
        }
    }

    /// Resets the stream at the current offset and clears all buffered data.
    pub fn reset(&mut self) -> (u64, u64) {
        let unsent_off = cmp::max(self.off_front(), self.emit_off);
        let unsent_len = self.off_back().saturating_sub(unsent_off);

        self.fin_off = Some(unsent_off);

        // Drop all buffered data.
        self.data.clear();

        // Mark all data as acked.
        self.ack(0, self.off as usize);

        self.pos = 0;
        self.len = 0;
        self.off = unsent_off;

        (self.emit_off, unsent_len)
    }

    /// Resets the streams and records the received error code.
    ///
    /// Calling this again after the first time has no effect.
    pub fn stop(&mut self, error_code: u64) -> Result<(u64, u64)> {
        if self.error.is_some() {
            return Err(Error::Done);
        }

        let (max_off, unsent) = self.reset();

        self.error = Some(error_code);

        Ok((max_off, unsent))
    }

    /// Shuts down sending data.
    pub fn shutdown(&mut self) -> Result<(u64, u64)> {
        if self.shutdown {
            return Err(Error::Done);
        }

        self.shutdown = true;

        Ok(self.reset())
    }

    /// Returns the largest offset of data buffered.
    pub fn off_back(&self) -> u64 {
        self.off
    }

    /// Returns the lowest offset of data buffered.
    pub fn off_front(&self) -> u64 {
        let mut pos = self.pos;

        // Skip empty buffers from the start of the queue.
        while let Some(b) = self.data.get(pos) {
            if !b.is_empty() {
                return b.off();
            }

            pos += 1;
        }

        self.off
    }

    /// The maximum offset we are allowed to send to the peer.
    pub fn max_off(&self) -> u64 {
        self.max_data
    }

    /// Returns true if all data in the stream has been sent.
    ///
    /// This happens when the stream's send final size is known, and the
    /// application has already written data up to that point.
    pub fn is_fin(&self) -> bool {
        if self.fin_off == Some(self.off) {
            return true;
        }

        false
    }

    /// Returns true if the send-side of the stream is complete.
    ///
    /// This happens when the stream's send final size is known, and the peer
    /// has already acked all stream data up to that point.
    pub fn is_complete(&self) -> bool {
        if let Some(fin_off) = self.fin_off {
            if self.acked == (0..fin_off) {
                return true;
            }
        }

        if let Some(rmc_fin_off) = self.rmc_max_offset {
            if self.acked == (0..rmc_fin_off) {
                return true;
            }
        }

        false
    }

    /// Returns true if the stream was stopped before completion.
    pub fn is_stopped(&self) -> bool {
        self.error.is_some()
    }

    /// Returns true if the stream was shut down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Returns true if there is data to be written.
    pub fn ready(&self) -> bool {
        !self.data.is_empty() && self.off_front() < self.off
    }

    /// Returns the highest contiguously acked offset.
    pub fn ack_off(&self) -> u64 {
        match self.acked.iter().next() {
            // Only consider the initial range if it contiguously covers the
            // start of the stream (i.e. from offset 0).
            Some(std::ops::Range { start: 0, end }) => end,

            Some(_) | None => 0,
        }
    }

    /// Returns the outgoing flow control capacity.
    pub fn cap(&self) -> Result<usize> {
        // The stream was stopped, so return the error code instead.
        if let Some(e) = self.error {
            return Err(Error::StreamStopped(e));
        }

        Ok((self.max_data - self.off) as usize)
    }

    /// Returns the number of bytes that still need to be sent to complete the
    /// stream. `None` if the final size is not known.
    pub fn total_remaining(&self) -> Option<u64> {
        self.fin_off
            .map(|off| off - self.off_front())
            .filter(|&off| off > 0)
    }

    /// Returns the number of separate buffers stored.
    #[allow(dead_code)]
    pub fn bufs_count(&self) -> usize {
        self.data.len()
    }
}

impl super::McStream for SendBuf {
    fn hash_stream(&self, buf: &mut [u8]) -> Result<Vec<u8>> {
        if buf.len() < 32 {
            return Err(Error::BufferTooShort);
        }
        if !self.is_fin() {
            return Err(Error::Done);
        }
        let mut stream_data =
            Vec::with_capacity(self.fin_off.unwrap() as usize + 64);

        let mut offset = 0;
        for range_buf in self.data.iter() {
            if offset == range_buf.off {
                stream_data.extend_from_slice(&range_buf.data);
                offset += range_buf.data.len() as u64;
            }
        }
        // let digest = ring::digest::digest(&ring::digest::SHA256, &stream_data);
        // buf[..32].copy_from_slice(digest.as_ref());
        Ok(stream_data)
    }
}

impl SendBuf {
    #[allow(unused)]
    /// Hash the stream data using [`ring::digest::SHA256`].
    /// Hashes the stream incrementally.
    /// [`data`] is the pointer to the stream data piece that is sent.
    ///
    /// This function should be called with the result of [`SendBuf::emit`].
    pub fn hash_stream_incr(&mut self, data: &[u8]) -> Result<()> {
        let mut buffer = vec![0; data.len() + self.hash.len()];
        buffer[..self.hash.len()].copy_from_slice(&self.hash);
        buffer[self.hash.len()..].copy_from_slice(data);

        let digest = ring::digest::digest(&ring::digest::SHA256, &buffer);
        self.hash = digest.as_ref().try_into().map_err(|_| {
            Error::Multicast(crate::multicast::McError::McInvalidSign)
        })?;

        Ok(())
    }

    /// Start a `SendBuf` from a given offset.
    ///
    /// This function is used for reliable multicast as the unicast server may
    /// need to retransmit some parts of a stream that has started on the
    /// multicast path.
    pub fn reset_at(&mut self, off: u64) -> Result<()> {
        let cur_off = self.off;
        self.ack(cur_off, (off - cur_off) as usize);
        self.off = off;
        self.emit_off = off;
        Ok(())
    }

    /// Inserts the given slice of data at the specified offset in the buffer.
    ///
    /// The number of bytes that were actually stored in the buffer is returned
    /// (this may be lower than the size of the input buffer, in case of partial
    /// writes).
    ///
    /// For simplification, only allow to write at offsets not already spanned
    /// by the buffer. For example, calling this function with an offset of
    /// 300 after a call with offset 500 will result in a [`Error::FinalSize`]
    /// error. Future work may extend this to enable for in-between insertion of
    /// stream data.
    pub fn write_at_offset(
        &mut self, data: &[u8], offset: u64, fin: bool,
    ) -> Result<usize> {
        // We "fill" the buffer with no data until we reach the expected offset.
        // This "no data" is never sent, and we ask to retransmit this chunk of
        // data only.
        if self.off > offset {
            return Err(Error::FinalSize);
        } else if self.off != offset {
            self.reset_at(offset)?;
        }
        let written = self.write(data, fin)?;
        self.retransmit(offset, written);

        Ok(written)
    }

    /// Used for multicast purpose. This `SendBuf` stream will not receive any
    /// more data, even if the stream is not finished regarding the initial
    /// version of QUIC. Returns an error if the value was already set
    /// previously.
    pub fn rmc_set_close_offset(&mut self) {
        self.rmc_max_offset = Some(self.off);
        // debug!("Set the closing offset to {:?}", self.rmc_max_offset);
    }

    /// Sets the fin offset.
    pub fn rmc_set_fin_off(&mut self, off: u64) {
        self.fin_off = Some(off);
    }
}

impl SendBuf {
    pub(crate) fn fc_emit_off(&self) -> u64 {
        self.emit_off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_write() {
        let mut buf = [0; 5];

        let mut send = SendBuf::new(u64::MAX);
        assert_eq!(send.len, 0);

        let (written, fin) = send.emit(&mut buf).unwrap();
        assert_eq!(written, 0);
        assert!(!fin);
    }

    #[test]
    fn multi_write() {
        let mut buf = [0; 128];

        let mut send = SendBuf::new(u64::MAX);
        assert_eq!(send.len, 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.len, 19);

        let (written, fin) = send.emit(&mut buf[..128]).unwrap();
        assert_eq!(written, 19);
        assert!(fin);
        assert_eq!(&buf[..written], b"somethinghelloworld");
        assert_eq!(send.len, 0);
    }

    #[test]
    fn split_write() {
        let mut buf = [0; 10];

        let mut send = SendBuf::new(u64::MAX);
        assert_eq!(send.len, 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.len, 19);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 10);
        assert!(!fin);
        assert_eq!(&buf[..written], b"somethingh");
        assert_eq!(send.len, 9);

        assert_eq!(send.off_front(), 10);

        let (written, fin) = send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"ellow");
        assert_eq!(send.len, 4);

        assert_eq!(send.off_front(), 15);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 4);
        assert!(fin);
        assert_eq!(&buf[..written], b"orld");
        assert_eq!(send.len, 0);

        assert_eq!(send.off_front(), 19);
    }

    #[test]
    fn resend() {
        let mut buf = [0; 15];

        let mut send = SendBuf::new(u64::MAX);
        assert_eq!(send.len, 0);
        assert_eq!(send.off_front(), 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.off_front(), 0);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.off_front(), 0);

        assert_eq!(send.len, 19);

        let (written, fin) = send.emit(&mut buf[..4]).unwrap();
        assert_eq!(written, 4);
        assert!(!fin);
        assert_eq!(&buf[..written], b"some");
        assert_eq!(send.len, 15);
        assert_eq!(send.off_front(), 4);

        let (written, fin) = send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"thing");
        assert_eq!(send.len, 10);
        assert_eq!(send.off_front(), 9);

        let (written, fin) = send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"hello");
        assert_eq!(send.len, 5);
        assert_eq!(send.off_front(), 14);

        send.retransmit(4, 5);
        assert_eq!(send.len, 10);
        assert_eq!(send.off_front(), 4);

        send.retransmit(0, 4);
        assert_eq!(send.len, 14);
        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..11]).unwrap();
        assert_eq!(written, 9);
        assert!(!fin);
        assert_eq!(&buf[..written], b"something");
        assert_eq!(send.len, 5);
        assert_eq!(send.off_front(), 14);

        let (written, fin) = send.emit(&mut buf[..11]).unwrap();
        assert_eq!(written, 5);
        assert!(fin);
        assert_eq!(&buf[..written], b"world");
        assert_eq!(send.len, 0);
        assert_eq!(send.off_front(), 19);
    }

    #[test]
    fn write_blocked_by_off() {
        let mut buf = [0; 10];

        let mut send = SendBuf::default();
        assert_eq!(send.len, 0);

        let first = b"something";
        let second = b"helloworld";

        assert_eq!(send.write(first, false), Ok(0));
        assert_eq!(send.len, 0);

        assert_eq!(send.write(second, true), Ok(0));
        assert_eq!(send.len, 0);

        send.update_max_data(5);

        assert_eq!(send.write(first, false), Ok(5));
        assert_eq!(send.len, 5);

        assert_eq!(send.write(second, true), Ok(0));
        assert_eq!(send.len, 5);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"somet");
        assert_eq!(send.len, 0);

        assert_eq!(send.off_front(), 5);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 0);
        assert!(!fin);
        assert_eq!(&buf[..written], b"");
        assert_eq!(send.len, 0);

        send.update_max_data(15);

        assert_eq!(send.write(&first[5..], false), Ok(4));
        assert_eq!(send.len, 4);

        assert_eq!(send.write(second, true), Ok(6));
        assert_eq!(send.len, 10);

        assert_eq!(send.off_front(), 5);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 10);
        assert!(!fin);
        assert_eq!(&buf[..10], b"hinghellow");
        assert_eq!(send.len, 0);

        send.update_max_data(25);

        assert_eq!(send.write(&second[6..], true), Ok(4));
        assert_eq!(send.len, 4);

        assert_eq!(send.off_front(), 15);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 4);
        assert!(fin);
        assert_eq!(&buf[..written], b"orld");
        assert_eq!(send.len, 0);
    }

    #[test]
    fn zero_len_write() {
        let mut buf = [0; 10];

        let mut send = SendBuf::new(u64::MAX);
        assert_eq!(send.len, 0);

        let first = b"something";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.write(&[], true).is_ok());
        assert_eq!(send.len, 9);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 9);
        assert!(fin);
        assert_eq!(&buf[..written], b"something");
        assert_eq!(send.len, 0);
    }

    /// Check SendBuf::len calculation on a retransmit case
    #[test]
    fn send_buf_len_on_retransmit() {
        let mut buf = [0; 15];

        let mut send = SendBuf::new(u64::MAX);
        assert_eq!(send.len, 0);
        assert_eq!(send.off_front(), 0);

        let first = b"something";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.off_front(), 0);

        assert_eq!(send.len, 9);

        let (written, fin) = send.emit(&mut buf[..4]).unwrap();
        assert_eq!(written, 4);
        assert!(!fin);
        assert_eq!(&buf[..written], b"some");
        assert_eq!(send.len, 5);
        assert_eq!(send.off_front(), 4);

        send.retransmit(3, 5);
        assert_eq!(send.len, 6);
        assert_eq!(send.off_front(), 3);
    }

    #[test]
    fn send_buf_final_size_retransmit() {
        let mut buf = [0; 50];
        let mut send = SendBuf::new(u64::MAX);

        send.write(&buf, false).unwrap();
        assert_eq!(send.off_front(), 0);

        // Emit the whole buffer
        let (written, _fin) = send.emit(&mut buf).unwrap();
        assert_eq!(written, buf.len());
        assert_eq!(send.off_front(), buf.len() as u64);

        // Server decides to retransmit the last 10 bytes. It's possible
        // it's not actually lost and that the client did receive it.
        send.retransmit(40, 10);

        // Server receives STOP_SENDING from client. The final_size we
        // send in the RESET_STREAM should be 50. If we send anything less,
        // it's a FINAL_SIZE_ERROR.
        let (fin_off, unsent) = send.stop(0).unwrap();
        assert_eq!(fin_off, 50);
        assert_eq!(unsent, 0);
    }

    #[test]
    fn send_buf_reset_at() {
        let mut send = SendBuf::new(std::u64::MAX);
        let mut buf = [0u8; 10];

        assert_eq!(send.reset_at(500), Ok(()));
        assert_eq!(send.data, VecDeque::new());
        assert_eq!(send.emit_off, 500);
        assert_eq!(send.off, 500);
        assert_eq!(send.len, 0);

        assert_eq!(send.write(b"hello", false), Ok(5));
        assert_eq!(send.write(b", world", true), Ok(7));
        assert!(send.is_fin());

        assert_eq!(send.emit(&mut buf), Ok((10, false)));
        assert_eq!(&buf[..], b"hello, wor");
        assert_eq!(send.emit_off, 510);
        assert_eq!(send.off, 512);

        assert_eq!(send.emit(&mut buf), Ok((2, true)));
        assert_eq!(send.emit_off, 512);
        assert_eq!(send.off, 512);
        assert_eq!(&buf[..2], b"ld");

        send.retransmit(500, 5);
        assert_eq!(send.emit(&mut buf), Ok((5, false)));
        assert_eq!(&buf[..5], b"hello");

        send.ack(500, 12);
    }

    #[test]
    /// Tests the extensions of `StreamBuf` to create a stream and send only
    /// chunks at specific offsets.
    fn send_buf_partial_chunks() {
        let mut send = SendBuf::new(std::u64::MAX);
        let mut buf = [0u8; 10];

        assert_eq!(send.write_at_offset(b"hello", 100, false), Ok(5));
        assert_eq!(send.write_at_offset(b", world!", 500, false), Ok(8));
        assert_eq!(send.emit(&mut buf), Ok((5, false)));
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(send.emit(&mut buf), Ok((8, false)));
        assert_eq!(&buf[..8], b", world!");

        assert_eq!(send.write_at_offset(b"test1000", 1000, false), Ok(8));
        assert_eq!(
            send.write_at_offset(b"test1000+8", 1007, false),
            Err(Error::FinalSize)
        );
        assert_eq!(send.write_at_offset(b"test1000+8", 1008, false), Ok(10));
        assert_eq!(
            send.write_at_offset(b"test1000+8", 1017, false),
            Err(Error::FinalSize)
        );
        assert_eq!(send.write_at_offset(b"test1000+1xx", 1100, true), Ok(12));
        assert_eq!(send.emit(&mut buf), Ok((10, false)));
        assert_eq!(&buf[..], b"test1000te");
        assert_eq!(send.emit(&mut buf), Ok((8, false)));
        assert_eq!(&buf[..8], b"st1000+8");
        assert_eq!(send.emit(&mut buf), Ok((10, false)));
        assert_eq!(&buf[..], b"test1000+1");
        assert_eq!(send.emit(&mut buf), Ok((2, true)));
        assert_eq!(&buf[..2], b"xx");

        send.ack(100, 5);
        send.ack(500, 8);
        send.ack(1000, 8);
        send.ack(1008, 10);
        send.ack(1100, 12);
        assert!(send.is_complete());
    }

    #[test]
    fn send_buf_partial_chunks_unifished() {
        let mut send = SendBuf::new(std::u64::MAX);
        let mut buf = [0u8; 10];

        assert_eq!(send.write_at_offset(b"hello", 100, false), Ok(5));
        assert_eq!(send.rmc_max_offset, None);
        send.rmc_set_close_offset();
        assert_eq!(send.rmc_max_offset, Some(105));
        assert_eq!(send.write_at_offset(b", world!", 500, false), Ok(8));
        send.rmc_set_close_offset();
        assert_eq!(send.rmc_max_offset, Some(508));
        assert_eq!(send.emit(&mut buf), Ok((5, false)));
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(send.emit(&mut buf), Ok((8, false)));
        assert_eq!(&buf[..8], b", world!");

        send.ack(100, 5);
        send.ack(500, 8);
        assert!(send.is_complete());
    }
}
