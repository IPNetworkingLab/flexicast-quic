use super::recv_buf::RecvBuf;
use super::send_buf::SendBuf;
use super::RangeBuf;
use super::Stream;
use super::StreamMap;
use crate::Result;
use octets;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// State of stream for out-of-order handling.
pub struct FcStreamState {
    stream_id: u64,
    offset: usize,
}

impl FcStreamState {
    #[inline]
    /// Reads an FcStreamState from bytes.
    pub fn from_bytes(b: &mut octets::Octets) -> Result<Self> {
        let stream_id = b.get_varint()?;
        let offset = b.get_varint()? as usize;

        Ok(FcStreamState { stream_id, offset })
    }

    #[inline]
    /// Transform an FcStreamState to bytes.
    pub fn fc_to_bytes(&self, b: &mut octets::OctetsMut) -> Result<()> {
        b.put_varint(self.stream_id)?;
        b.put_varint(self.offset as u64)?;
        Ok(())
    }

    #[inline]
    /// Length in byte of the structure.
    pub fn len(&self) -> usize {
        octets::varint_len(self.stream_id) +
            octets::varint_len(self.offset as u64)
    }

    #[inline]
    /// New FcStream State.
    pub fn new(stream_id: u64, offset: usize) -> Self {
        Self { stream_id, offset }
    }

    #[inline]
    /// Get the stream id.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    #[inline]
    /// Get the offset.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl StreamMap {
    /// Returns a vector of [`FcStreamState`] based on active streams.
    pub(crate) fn to_fc_stream_state(&self) -> Vec<FcStreamState> {
        self.streams
            .iter()
            .filter(|(_, stream)| stream.local)
            .map(|(stream_id, stream)| {
                FcStreamState::new(*stream_id, stream.send.fc_emit_off() as usize)
            })
            .collect()
    }
}

impl Stream {
    /// Mark the stream as rotable.
    ///
    /// Flexicast with stream rotation extension.
    pub fn fc_mark_rotate(&mut self, v: bool) {
        self.send.fc_stream_rotate = v;
    }

    /// Restart the sending and receiving state of a stream.
    /// This will restart the stream state to send again the same data.
    /// Returns true if the stream is started again.
    /// FC-TODO: URGENT!!!
    /// Currently it is possible to send different data on the same stream
    /// because we do not buffer the data, we consume it.
    ///
    /// Flexicast with stream rotation extension.
    pub(crate) fn fc_restart_stream_send_recv(&mut self) -> bool {
        if !self.send.fc_stream_rotate {
            return false;
        }
        self.send = SendBuf::new(self.send.max_off());
        self.send.fc_stream_rotate = true;
        self.recv = RecvBuf::new(self.recv.max_data(), self.recv.max_data());
        true
    }
}

#[derive(Debug, Default)]
/// Flexicast receiving buffer extension.
///
/// Allows to start a stream reception at a given offset and loop back to the
/// beginning.
pub(crate) struct FcRecvBuf {
    /// Flexicast initial offset. This is the offset at which the stream is
    /// created.
    fc_init_off: u64,

    /// Whether the read already looped.
    fc_looped: bool,

    /// Real start of the stream. It will be read once we loop.
    fc_recv_buf: Option<Box<RecvBuf>>,

    /// Whether the stream can be read with [`crate::Connection::stream_recv`].
    ///
    /// Flexicast with stream rotation extension.
    fc_can_read: bool,
}

#[allow(missing_docs)]
impl FcRecvBuf {
    pub fn new(offset: u64, max_data: u64, max_window: u64) -> Self {
        Self {
            fc_init_off: offset,
            fc_looped: false,
            fc_recv_buf: Some(Box::new(RecvBuf::new(max_data, max_window))),
            fc_can_read: false,
        }
    }

    pub fn init_off(&self) -> u64 {
        self.fc_init_off
    }

    pub fn looped(&self) -> bool {
        self.fc_looped
    }

    pub fn set_looped(&mut self, v: bool) {
        self.fc_looped = v;
    }

    pub fn take_recv_buf(&mut self) -> Option<Box<RecvBuf>> {
        self.fc_recv_buf.take()
    }

    pub fn write(&mut self, buf: RangeBuf) -> Result<()> {
        if let Some(recv) = self.fc_recv_buf.as_mut() {
            recv.write(buf)
        } else {
            Err(crate::Error::Multicast(
                crate::multicast::McError::FcStreamRotation,
            ))
        }
    }

    pub fn fc_can_be_read(&self) -> bool {
        self.fc_can_read
    }

    pub(super) fn fc_set_can_read(&mut self, v: bool) {
        self.fc_can_read = v;
    }

    #[cfg(test)]
    pub fn peek_recv_buf(&self) -> Option<&Box<RecvBuf>> {
        self.fc_recv_buf.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::stream::DEFAULT_STREAM_WINDOW;

    use super::*;

    #[test]
    fn fc_send_buf_restart_state() {
        let mut buf = [0; 20];

        let mut stream =
            Stream::new(0, 0, 20, true, false, DEFAULT_STREAM_WINDOW);
        stream.fc_mark_rotate(true);

        let first = b"hello";
        let second = b"world";
        let third = b"rotation";
        assert_eq!(stream.send.write(first, false), Ok(5));
        assert_eq!(stream.send.write(second, false), Ok(5));
        assert_eq!(stream.send.write(third, true), Ok(8));
        assert!(stream.send.is_fin());

        // First write, normal behaviour.
        let (written, fin) = stream.send.emit(&mut buf[..]).unwrap();
        assert_eq!(written, 18);
        assert!(fin);
        assert_eq!(&buf[..written], b"helloworldrotation");
        assert_eq!(stream.send.off_front(), 18);

        // Should not send any more data.
        assert_eq!(stream.send.emit(&mut buf[..]), Ok((0, true)));

        // Restart the stream.
        assert!(stream.fc_restart_stream_send_recv());

        // Send again the data.
        let first = b"hello";
        let second = b"world";
        let third = b"rotation";
        assert_eq!(stream.send.write(first, false), Ok(5));
        assert_eq!(stream.send.write(second, false), Ok(5));
        assert_eq!(stream.send.write(third, true), Ok(8));
        assert!(stream.send.is_fin());

        // Second write, same behaviour.
        let (written, fin) = stream.send.emit(&mut buf[..]).unwrap();
        assert_eq!(written, 18);
        assert!(fin);
        assert_eq!(&buf[..written], b"helloworldrotation");
        assert_eq!(stream.send.off_front(), 18);

        // Should not send any more data.
        assert_eq!(stream.send.emit(&mut buf[..]), Ok((0, true)));
    }
}
