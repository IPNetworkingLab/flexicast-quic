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
use std::time;

use std::collections::BTreeMap;
use std::collections::VecDeque;

use crate::multicast::McError;
use crate::Error;
use crate::Result;

use crate::flowcontrol;

use super::flexicast::FcRecvBuf;
use super::RangeBuf;
use super::DEFAULT_STREAM_WINDOW;

/// Receive-side stream buffer.
///
/// Stream data received by the peer is buffered in a list of data chunks
/// ordered by offset in ascending order. Contiguous data can then be read
/// into a slice.
#[derive(Debug, Default)]
pub struct RecvBuf {
    /// Chunks of data received from the peer that have not yet been read by
    /// the application, ordered by offset.
    data: BTreeMap<u64, RangeBuf>,

    /// The lowest data offset that has yet to be read by the application.
    off: u64,

    /// The total length of data received on this stream.
    len: u64,

    /// Receiver flow controller.
    flow_control: flowcontrol::FlowControl,

    /// The final stream offset received from the peer, if any.
    fin_off: Option<u64>,

    /// The error code received via RESET_STREAM.
    error: Option<u64>,

    /// Whether incoming data is validated but not buffered.
    drain: bool,

    /// Flexicast receiving buffer extension.
    fc_data: Option<FcRecvBuf>,
}

impl RecvBuf {
    /// Creates a new receive buffer.
    pub fn new(max_data: u64, max_window: u64) -> RecvBuf {
        RecvBuf {
            flow_control: flowcontrol::FlowControl::new(
                max_data,
                cmp::min(max_data, DEFAULT_STREAM_WINDOW),
                max_window,
            ),
            ..RecvBuf::default()
        }
    }

    /// Inserts the given chunk of data in the buffer.
    ///
    /// This also takes care of enforcing stream flow control limits, as well
    /// as handling incoming data that overlaps data that is already in the
    /// buffer.
    pub fn write(&mut self, buf: RangeBuf) -> Result<()> {
        if buf.max_off() > self.max_data() {
            return Err(Error::FlowControl);
        }

        if let Some(fin_off) = self.fin_off {
            // Stream's size is known, forbid data beyond that point.
            if buf.max_off() > fin_off {
                return Err(Error::FinalSize);
            }

            // Stream's size is already known, forbid changing it.
            if buf.fin() && fin_off != buf.max_off() {
                return Err(Error::FinalSize);
            }
        }

        // Stream's known size is lower than data already received.
        if buf.fin() && buf.max_off() < self.len {
            return Err(Error::FinalSize);
        }

        // We already saved the final offset, so there's nothing else we
        // need to keep from the RangeBuf if it's empty.
        if self.fin_off.is_some() && buf.is_empty() {
            return Ok(());
        }

        if buf.fin() {
            self.fin_off = Some(buf.max_off());
        }

        // No need to store empty buffer that doesn't carry the fin flag.
        if !buf.fin() && buf.is_empty() {
            return Ok(());
        }

        // Check if data is fully duplicate, that is the buffer's max offset is
        // lower or equal to the offset already stored in the recv buffer.
        if self.off >= buf.max_off() {
            // An exception is applied to empty range buffers, because an empty
            // buffer's max offset matches the max offset of the recv buffer.
            //
            // By this point all spurious empty buffers should have already been
            // discarded, so allowing empty buffers here should be safe.
            if !buf.is_empty() {
                // There is an exception if Flexicast is
                // used with the ability to start reading the
                // stream at a specific (potentially non-zero)
                // offset. In this case, we still need to buffer the beginning
                // of the data to allow to loop back to the
                // beginning.
                if let Some(fc_data) = self.fc_data.as_mut() {
                    let buf_is_fin = buf.fin();
                    let buf_max_off = buf.max_off();

                    fc_data.write(buf)?;

                    // In the unlikely case the flexicast init offset is the fin
                    // offset, we must directly wrap around the receiving buffer
                    // because we won't have any more data in the "offset-ed"
                    // part of the buffer. We know this if
                    // the rangebuf has the `fin` set and the offset is the
                    // same. If the offset is lower, return a FinalSize error.
                    if buf_is_fin {
                        if fc_data.init_off() > buf_max_off {
                            return Err(Error::FinalSize);
                        }

                        if fc_data.init_off() == buf_max_off {
                            self.fc_loop_recv()?;
                        }
                    }
                }
                return Ok(());
            }
        }

        let mut tmp_bufs = VecDeque::with_capacity(2);
        tmp_bufs.push_back(buf);

        'tmp: while let Some(mut buf) = tmp_bufs.pop_front() {
            // Discard incoming data below current stream offset. Bytes up to
            // `self.off` have already been received so we should not buffer
            // them again. This is also important to make sure `ready()` doesn't
            // get stuck when a buffer with lower offset than the stream's is
            // buffered.
            if self.off_front() > buf.off() {
                let buf_after =
                    buf.split_off((self.off_front() - buf.off()) as usize);

                // There is an exception if Flexicast is
                // used with the ability to start reading the
                // stream at a specific (potentially non-zero)
                // offset. In this case, we still need to buffer the beginning
                // of the data to allow to loop back to the
                // beginning.
                if let Some(fc_data) = self.fc_data.as_mut() {
                    fc_data.write(buf)?;
                }
                buf = buf_after;
            }

            // Handle overlapping data. If the incoming data's starting offset
            // is above the previous maximum received offset, there is clearly
            // no overlap so this logic can be skipped. However do still try to
            // merge an empty final buffer (i.e. an empty buffer with the fin
            // flag set, which is the only kind of empty buffer that should
            // reach this point).
            if buf.off() < self.max_off() || buf.is_empty() {
                for (_, b) in self.data.range(buf.off()..) {
                    let off = buf.off();

                    // We are past the current buffer.
                    if b.off() > buf.max_off() {
                        break;
                    }

                    // New buffer is fully contained in existing buffer.
                    if off >= b.off() && buf.max_off() <= b.max_off() {
                        continue 'tmp;
                    }

                    // New buffer's start overlaps existing buffer.
                    if off >= b.off() && off < b.max_off() {
                        buf = buf.split_off((b.max_off() - off) as usize);
                    }

                    // New buffer's end overlaps existing buffer.
                    if off < b.off() && buf.max_off() > b.off() {
                        tmp_bufs
                            .push_back(buf.split_off((b.off() - off) as usize));
                    }
                }
            }

            self.len = cmp::max(self.len, buf.max_off());

            if !self.drain {
                self.data.insert(buf.max_off(), buf);
            }
        }

        Ok(())
    }

    /// Writes data from the receive buffer into the given output buffer.
    ///
    /// Only contiguous data is written to the output buffer, starting from
    /// offset 0. The offset is incremented as data is read out of the receive
    /// buffer into the application buffer. If there is no data at the expected
    /// read offset, the `Done` error is returned.
    ///
    /// On success the amount of data read, and a flag indicating if there is
    /// no more data in the buffer, are returned as a tuple.
    pub fn emit(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut len = 0;
        let mut cap = out.len();

        if !self.ready() {
            return Err(Error::Done);
        }

        // The stream was reset, so clear its data and return the error code
        // instead.
        if let Some(e) = self.error {
            self.data.clear();
            return Err(Error::StreamReset(e));
        }

        while cap > 0 && self.ready() {
            let mut entry = match self.data.first_entry() {
                Some(entry) => entry,
                None => break,
            };

            let buf = entry.get_mut();

            let mut buf_len = cmp::min(buf.len(), cap);

            // If Flexicast stream offset init is done and we already looped, take
            // care that we do not send twice the same data (at
            // self.fc_init_offset). So we constraint the size of the
            // buffer to ensure that this does not happen.
            if let Some(fc_data) = self.fc_data.as_ref() {
                if fc_data.looped() {
                    let gap_until_fc_off =
                        fc_data.init_off().saturating_sub(self.off) as usize;
                    buf_len = cmp::min(buf_len, gap_until_fc_off);
                }
            }

            out[len..len + buf_len].copy_from_slice(&buf[..buf_len]);

            self.off += buf_len as u64;

            len += buf_len;
            cap -= buf_len;

            if buf_len < buf.len() {
                buf.consume(buf_len);

                // We reached the maximum capacity, so end here.
                break;
            }

            entry.remove();
        }

        // Update consumed bytes for flow control.
        self.flow_control.add_consumed(len as u64);

        // If the stream was set with Flexicast at a specific value and quiche
        // provided the data until the end, it means that we must still loop back
        // to the beginning to read the remaining of the stream.
        if self.is_fin() && self.fc_data.as_mut().is_some() {
            self.fc_loop_recv()?;
            return Ok((len, self.is_fin()));
        }

        // If the thread already looped and reaches back the initial offset.
        if self.fc_data.as_ref().is_some_and(|fc_data| {
            fc_data.looped() && fc_data.init_off() <= self.off
        }) {
            return Ok((len, true));
        }

        Ok((len, self.is_fin()))
    }

    /// Resets the stream at the given offset.
    pub fn reset(&mut self, error_code: u64, final_size: u64) -> Result<usize> {
        // Stream's size is already known, forbid changing it.
        if let Some(fin_off) = self.fin_off {
            if fin_off != final_size {
                return Err(Error::FinalSize);
            }
        }

        // Stream's known size is lower than data already received.
        if final_size < self.len {
            return Err(Error::FinalSize);
        }

        // Calculate how many bytes need to be removed from the connection flow
        // control.
        let max_data_delta = final_size - self.len;

        if self.error.is_some() {
            return Ok(max_data_delta as usize);
        }

        self.error = Some(error_code);

        // Clear all data already buffered.
        self.off = final_size;

        self.data.clear();

        // In order to ensure the application is notified when the stream is
        // reset, enqueue a zero-length buffer at the final size offset.
        let buf = RangeBuf::from(b"", final_size, true);
        self.write(buf)?;

        Ok(max_data_delta as usize)
    }

    /// Commits the new max_data limit.
    pub fn update_max_data(&mut self, now: time::Instant) {
        self.flow_control.update_max_data(now);
    }

    /// Return the new max_data limit.
    pub fn max_data_next(&mut self) -> u64 {
        self.flow_control.max_data_next()
    }

    /// Return the current flow control limit.
    pub fn max_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Return the current window.
    pub fn window(&self) -> u64 {
        self.flow_control.window()
    }

    /// Autotune the window size.
    pub fn autotune_window(&mut self, now: time::Instant, rtt: time::Duration) {
        self.flow_control.autotune_window(now, rtt);
    }

    /// Shuts down receiving data.
    pub fn shutdown(&mut self) -> Result<()> {
        if self.drain {
            return Err(Error::Done);
        }

        self.drain = true;

        self.data.clear();

        self.off = self.max_off();

        Ok(())
    }

    /// Returns the lowest offset of data buffered.
    pub fn off_front(&self) -> u64 {
        self.off
    }

    /// Returns true if we need to update the local flow control limit.
    pub fn almost_full(&self) -> bool {
        self.fin_off.is_none() && self.flow_control.should_update_max_data()
    }

    /// Returns the largest offset ever received.
    pub fn max_off(&self) -> u64 {
        self.len
    }

    /// Returns true if the receive-side of the stream is complete.
    ///
    /// This happens when the stream's receive final size is known, and the
    /// application has read all data from the stream.
    pub fn is_fin(&self) -> bool {
        if self.fin_off == Some(self.off) {
            return true;
        }

        false
    }

    /// Returns true if the stream is not storing incoming data.
    pub fn is_draining(&self) -> bool {
        self.drain
    }

    /// Returns true if the stream has data to be read.
    pub fn ready(&self) -> bool {
        let (_, buf) = match self.data.first_key_value() {
            Some(v) => v,
            None => {
                return false;
            },
        };

        buf.off() == self.off
    }

    /// Returns whether the final size of the stream is known.
    pub fn has_fin(&self) -> bool {
        self.fin_off.is_some()
    }

    /// Returns true if the stream can be read until its end.
    pub fn is_fully_readable(&self) -> bool {
        if self.fin_off.is_none() {
            return false;
        }

        let mut off = self.off;
        for (_, entry) in self.data.iter() {
            if off != entry.off {
                return false; // Not contiguous.
            }
            off += entry.len() as u64;
        }

        Some(off) == self.fin_off
    }
}

impl super::McStream for RecvBuf {
    fn hash_stream(&self, buf: &mut [u8]) -> Result<Vec<u8>> {
        if buf.len() < 32 {
            return Err(Error::BufferTooShort);
        }
        if !self.is_fully_readable() {
            return Err(Error::Done);
        }
        let mut stream_data: Vec<u8> =
            Vec::with_capacity(self.fin_off.unwrap() as usize + 64);
        for (_, range_buf) in self.data.iter() {
            stream_data.extend_from_slice(range_buf);
        }
        // let digest = ring::digest::digest(&ring::digest::SHA256, &stream_data);
        // buf[..32].copy_from_slice(digest.as_ref());
        Ok(stream_data)
    }
}

impl RecvBuf {
    #[allow(unused)]
    /// Hash the stream data using [`ring::digest::SHA256`].
    /// Hashes the stream incrementally.
    /// As the receiver may receive Stream data out of order, this function must
    /// be called once the stream is complete. Ideally, it should also be
    /// incremental, and if a piece of stream is received out of order, the
    /// function should try to hash as much as possible.
    ///
    /// Returns the hash.
    pub fn hash_stream_incr(&self) -> Result<[u8; 32]> {
        if !self.is_fully_readable() {
            return Err(Error::Done);
        }
        let mut hash = [0u8; 32];
        for (_, range_buf) in self.data.iter() {
            let mut buffer = vec![0; hash.len() + range_buf.len()];
            buffer[..hash.len()].copy_from_slice(&hash);
            buffer[hash.len()..].copy_from_slice(range_buf);

            let digest = ring::digest::digest(&ring::digest::SHA256, &buffer);
            hash.copy_from_slice(digest.as_ref());
        }

        Ok(hash)
    }

    /// Specifies that this [`RecvBuf`] starts receiving data at a specific
    /// offset, thus allowing kind of 'out of order' delivery.
    ///
    /// This completely changes the state of the structure, as it will consider
    /// that any byte before `offset` has already been received.
    /// Internally, it creates a [`super::flexicast::FcRecvBuf`] structure to
    /// allow to loop.
    pub(crate) fn fc_set_offset_at(&mut self, offset: u64) -> Result<()> {
        self.fc_data = Some(FcRecvBuf::new(
            offset,
            self.flow_control.max_data(),
            DEFAULT_STREAM_WINDOW,
        ));

        self.off = offset;

        Ok(())
    }

    /// Loops the receiving buffer to the beginning.
    ///
    /// Flexicast with stream rotation extension.
    fn fc_loop_recv(&mut self) -> Result<()> {
        if let Some(fc_data) = self.fc_data.as_mut() {
            if !fc_data.looped() {
                // We looped back to the beginning of the stream.
                fc_data.set_looped(true);

                // Change the data to read the beginning of the stream.
                let fc_recv_buf = *fc_data
                    .take_recv_buf()
                    .ok_or(Error::Multicast(McError::FcStreamRotation))?;
                let fc_init_off = fc_data.init_off();
                self.fc_copy(fc_recv_buf, fc_init_off);
            }
            Ok(())
        } else {
            Err(Error::Multicast(McError::FcStreamRotation))
        }
    }

    /// Copies the state of another [`RecvBuf`] into self.
    ///
    /// Flexicast with stream rotation extension.
    fn fc_copy(&mut self, other: RecvBuf, fin_off: u64) {
        self.data = other.data;
        self.off = other.off;
        self.len = other.len;
        self.flow_control = other.flow_control;
        self.error = other.error;
        self.drain = other.drain;
        self.fin_off = Some(fin_off);
    }

    /// Stream rotation initial offset.
    ///
    /// Flexicast with stream rotation extension.
    pub(crate) fn fc_init_offset(&self) -> Result<u64> {
        self.fc_data
            .as_ref()
            .map(|d| d.init_off())
            .ok_or(Error::Multicast(McError::FcStreamRotation))
    }

    /// Whether the stream uses rotation and can be read out of order.
    ///
    /// Flexicast with stream rotation extension.
    pub(crate) fn fc_can_be_read_out_of_order(&self) -> bool {
        self.fc_data
            .as_ref()
            .map(|d| d.fc_can_be_read())
            .unwrap_or(true)
    }

    /// Give temporarly access to read to the stream out of order.
    ///
    /// Flexicast with stream rotation extension.
    pub(crate) fn fc_enable_out_of_order_read(&mut self, v: bool) -> Result<()> {
        self.fc_data
            .as_mut()
            .map(|d| d.fc_set_can_read(v))
            .ok_or(Error::Multicast(McError::FcStreamRotation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn empty_stream_frame() {
        let mut recv = RecvBuf::new(15, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let buf = RangeBuf::from(b"hello", 0, false);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let mut buf = [0; 32];
        assert_eq!(recv.emit(&mut buf), Ok((5, false)));

        // Don't store non-fin empty buffer.
        let buf = RangeBuf::from(b"", 10, false);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 0);

        // Check flow control for empty buffer.
        let buf = RangeBuf::from(b"", 16, false);
        assert_eq!(recv.write(buf), Err(Error::FlowControl));

        // Store fin empty buffer.
        let buf = RangeBuf::from(b"", 5, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Don't store additional fin empty buffers.
        let buf = RangeBuf::from(b"", 5, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Don't store additional fin non-empty buffers.
        let buf = RangeBuf::from(b"aa", 3, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Validate final size with fin empty buffers.
        let buf = RangeBuf::from(b"", 6, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));
        let buf = RangeBuf::from(b"", 4, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));

        let mut buf = [0; 32];
        assert_eq!(recv.emit(&mut buf), Ok((0, true)));
    }

    #[test]
    fn ordered_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 19);
        assert!(fin);
        assert_eq!(&buf[..len], b"helloworldsomething");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn split_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let (len, fin) = recv.emit(&mut buf[..10]).unwrap();
        assert_eq!(len, 10);
        assert!(!fin);
        assert_eq!(&buf[..len], b"somethingh");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 10);

        let (len, fin) = recv.emit(&mut buf[..5]).unwrap();
        assert_eq!(len, 5);
        assert!(!fin);
        assert_eq!(&buf[..len], b"ellow");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 15);

        let (len, fin) = recv.emit(&mut buf[..10]).unwrap();
        assert_eq!(len, 4);
        assert!(fin);
        assert_eq!(&buf[..len], b"orld");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn incomplete_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 19);
        assert!(fin);
        assert_eq!(&buf[..len], b"somethinghelloworld");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn zero_len_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert!(fin);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
    }

    #[test]
    fn past_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let third = RangeBuf::from(b"ello", 4, true);
        let fourth = RangeBuf::from(b"ello", 5, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert!(!fin);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.write(third), Err(Error::FinalSize));

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 4, false);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert!(!fin);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read2() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 4, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert!(!fin);
        assert_eq!(&buf[..len], b"somehello");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read3() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert!(!fin);
        assert_eq!(&buf[..len], b"somhellog");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read_multi() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"somethingsomething", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let third = RangeBuf::from(b"hello", 12, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 17);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 18);
        assert!(!fin);
        assert_eq!(&buf[..len], b"somhellogsomhellog");
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 18);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_start_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 8, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 13);
        assert!(fin);
        assert_eq!(&buf[..len], b"somethingello");
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 13);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_end_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"something", 3, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 12);
        assert!(fin);
        assert_eq!(&buf[..len], b"helsomething");
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 12);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_end_twice_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"he", 0, false);
        let second = RangeBuf::from(b"ow", 4, false);
        let third = RangeBuf::from(b"rl", 7, false);
        let fourth = RangeBuf::from(b"helloworld", 0, true);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 6);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 10);
        assert!(fin);
        assert_eq!(&buf[..len], b"helloworld");
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 10);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_end_twice_and_contained_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hellow", 0, false);
        let second = RangeBuf::from(b"barfoo", 10, true);
        let third = RangeBuf::from(b"rl", 7, false);
        let fourth = RangeBuf::from(b"elloworldbarfoo", 1, true);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 16);
        assert!(fin);
        assert_eq!(&buf[..len], b"helloworldbarfoo");
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 16);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn partially_multi_overlapping_reordered_read() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 8, false);
        let second = RangeBuf::from(b"something", 0, false);
        let third = RangeBuf::from(b"moar", 11, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 15);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 15);
        assert!(fin);
        assert_eq!(&buf[..len], b"somethinhelloar");
        assert_eq!(recv.len, 15);
        assert_eq!(recv.off, 15);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn partially_multi_overlapping_reordered_read2() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"aaa", 0, false);
        let second = RangeBuf::from(b"bbb", 2, false);
        let third = RangeBuf::from(b"ccc", 4, false);
        let fourth = RangeBuf::from(b"ddd", 6, false);
        let fifth = RangeBuf::from(b"eee", 9, false);
        let sixth = RangeBuf::from(b"fff", 11, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 4);

        assert!(recv.write(sixth).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        assert!(recv.write(fifth).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 6);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 14);
        assert!(!fin);
        assert_eq!(&buf[..len], b"aabbbcdddeefff");
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 14);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    /// Flexicast setting the offset to a different value and receiving data in
    /// order.
    fn fc_set_offset_at_middle() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);
        assert!(recv.fc_set_offset_at(5).is_ok());
        assert_eq!(recv.off, 5);

        let mut buf = [0; 11];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 9, true);

        // assert!(recv.write(first).is_ok());
        recv.write(first).unwrap();
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert!(!fin);
        assert_eq!(&buf[..len], b"hinghello");
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);

        // Loop back to the beginning.
        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 5);
        assert!(fin);
        assert_eq!(&buf[..len], b"somet");
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);

        // All data is read.
        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    /// Flexicast setting the offset to a different value and receiving data in
    /// order with a first block below the offset.
    fn fc_set_offset_at_above_first_block() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        let off = 9;
        assert_eq!(recv.len, 0);
        assert!(recv.fc_set_offset_at(off).is_ok());
        assert_eq!(recv.off, off);

        let mut buf = [0; 11];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 9, true);

        recv.write(first).unwrap();
        // Because the data is stored in the flexicast recveiving buffer.
        assert_eq!(recv.len, 0);
        assert_eq!(recv.off, off);
        assert_eq!(recv.data.len(), 0);

        // But the flexicast RecvBuf contains the buffer.
        let fc_recv = recv.fc_data.as_mut().unwrap().peek_recv_buf().unwrap();
        assert_eq!(fc_recv.len, 9);
        assert_eq!(fc_recv.off, 0);
        assert_eq!(fc_recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, off);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 5);
        assert!(!fin);
        assert_eq!(&buf[..len], b"hello");
        assert_eq!(recv.len, off);
        assert_eq!(recv.off, 0);

        // Loop back to the beginning.
        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert!(fin);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, off);
        assert_eq!(recv.off, off);

        // The flexicast RecvBuf is now empty because we took it.
        assert!(recv.fc_data.as_mut().unwrap().peek_recv_buf().is_none());

        // All data is read.
        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    /// Flexicast setting the offset to a different value and receiving data not
    /// in order.
    fn fc_set_offset_at_unordered() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        let off = 9;
        assert_eq!(recv.len, 0);
        assert!(recv.fc_set_offset_at(off).is_ok());
        assert_eq!(recv.off, off);

        let mut buf = [0; 11];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 9, true);

        recv.write(first).unwrap();
        // Because the data is stored in the flexicast recveiving buffer.
        assert_eq!(recv.len, 0);
        assert_eq!(recv.off, off);
        assert_eq!(recv.data.len(), 0);

        // But the flexicast RecvBuf contains the buffer.
        let fc_recv = recv.fc_data.as_mut().unwrap().peek_recv_buf().unwrap();
        assert_eq!(fc_recv.len, 9);
        assert_eq!(fc_recv.off, 0);
        assert_eq!(fc_recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, off);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 5);
        assert!(!fin);
        assert_eq!(&buf[..len], b"hello");
        assert_eq!(recv.len, off);
        assert_eq!(recv.off, 0);

        // Loop back to the beginning.
        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert!(fin);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, off);
        assert_eq!(recv.off, off);

        // The flexicast RecvBuf is now empty because we took it.
        assert!(recv.fc_data.as_mut().unwrap().peek_recv_buf().is_none());

        // All data is read.
        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    /// Flexicast setting the offset to the complete end of the buffer.
    /// Because the second [`RangeBuf`] indicates that this is the end of the
    /// buffer, the structure automatically wraps.
    fn fc_set_offset_at_end() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        let off = 14;
        assert_eq!(recv.len, 0);
        assert!(recv.fc_set_offset_at(off).is_ok());
        assert_eq!(recv.off, off);

        let mut buf = [0; 14];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 9, true);

        recv.write(first).unwrap();
        assert_eq!(recv.len, 0);
        assert_eq!(recv.off, off);
        assert_eq!(recv.data.len(), 0);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        // The write contains all data after the wrapping.
        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 14);
        assert!(fin);
        assert_eq!(&buf[..len], b"somethinghello");
        assert_eq!(recv.len, off);
        assert_eq!(recv.off, off);
    }

    #[test]
    /// Flexicast setting the offset to the beginning of the buffer, simulating
    /// a state where the client joins the channel when the stream starts
    /// (again).
    fn fc_set_offset_at_0() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        let off = 0;
        assert_eq!(recv.len, 0);
        assert!(recv.fc_set_offset_at(off).is_ok());
        assert_eq!(recv.off, off);

        let mut buf = [0; 14];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 9, true);

        recv.write(first).unwrap();
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, off);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        // The write contains all data after the wrapping.
        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 14);
        assert!(fin);
        assert_eq!(&buf[..len], b"somethinghello");
        assert_eq!(recv.len, off);
        assert_eq!(recv.off, off);
    }

    #[test]
    /// Flexicast setting the offset at a value above the maximum offset of the
    /// stream.
    fn fc_set_offset_at_above_fin_off() {
        let mut recv = RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW);
        let off = 15;
        assert_eq!(recv.len, 0);
        assert!(recv.fc_set_offset_at(off).is_ok());
        assert_eq!(recv.off, off);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 9, true);

        recv.write(first).unwrap();
        // Because the data is stored in the flexicast recveiving buffer.
        assert_eq!(recv.len, 0);
        assert_eq!(recv.off, off);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.write(second), Err(Error::FinalSize));
    }
}
