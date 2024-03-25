use super::recv_buf::RecvBuf;
use super::RangeBuf;
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
                FcStreamState::new(*stream_id, stream.send.off_back() as usize)
            })
            .collect()
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
}

#[allow(missing_docs)]
impl FcRecvBuf {
    pub fn new(offset: u64, max_data: u64, max_window: u64) -> Self {
        Self {
            fc_init_off: offset,
            fc_looped: false,
            fc_recv_buf: Some(Box::new(RecvBuf::new(max_data, max_window))),
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
                crate::multicast::McError::FcStreamLoop,
            ))
        }
    }
}
