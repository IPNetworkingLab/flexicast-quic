use super::recv_buf::RecvBuf;
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
    pub fn to_bytes(&self, b: &mut octets::OctetsMut) -> Result<()> {
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
