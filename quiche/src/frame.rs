// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use networkcoding::source_symbol_metadata_to_u64;
use networkcoding::Decoder;
use networkcoding::RepairSymbol;
use networkcoding::SourceSymbol;
use networkcoding::SourceSymbolMetadata;
use std::convert::TryInto;

use crate::Error;
use crate::Result;

use crate::crypto::Algorithm;
use crate::multicast::authentication::McSymSignature;
use crate::multicast::MC_ANNOUNCE_CODE;
use crate::multicast::MC_ASYM_CODE;
use crate::multicast::MC_AUTH_CODE;
use crate::multicast::MC_EXPIRE_CODE;
use crate::multicast::MC_KEY_CODE;
use crate::multicast::MC_NACK_CODE;
use crate::multicast::MC_STATE_CODE;
use crate::packet;
use crate::ranges;
use crate::stream;
use crate::stream::flexicast::FcStreamState;

#[cfg(feature = "qlog")]
use qlog::events::quic::AckedRanges;
#[cfg(feature = "qlog")]
use qlog::events::quic::ErrorSpace;
#[cfg(feature = "qlog")]
use qlog::events::quic::QuicFrame;
#[cfg(feature = "qlog")]
use qlog::events::quic::StreamType;

pub const MAX_CRYPTO_OVERHEAD: usize = 8;
pub const MAX_DGRAM_OVERHEAD: usize = 2;
pub const MAX_STREAM_OVERHEAD: usize = 12;
pub const MAX_STREAM_SIZE: u64 = 1 << 62;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcnCounts {
    ect0_count: u64,
    ect1_count: u64,
    ecn_ce_count: u64,
}

impl EcnCounts {
    pub fn new(ect0: u64, ect1: u64, ecn_ce: u64) -> Self {
        Self {
            ect0_count: ect0,
            ect1_count: ect1,
            ecn_ce_count: ecn_ce,
        }
    }

    pub fn get_ect0(&self) -> u64 {
        self.ect0_count
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Frame {
    Padding {
        len: usize,
    },

    Ping,

    ACK {
        ack_delay: u64,
        ranges: ranges::RangeSet,
        ecn_counts: Option<EcnCounts>,
    },

    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    StopSending {
        stream_id: u64,
        error_code: u64,
    },

    Crypto {
        data: stream::RangeBuf,
    },

    CryptoHeader {
        offset: u64,
        length: usize,
    },

    NewToken {
        token: Vec<u8>,
    },

    Stream {
        stream_id: u64,
        data: stream::RangeBuf,
    },

    StreamHeader {
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
    },

    MaxData {
        max: u64,
    },

    MaxStreamData {
        stream_id: u64,
        max: u64,
    },

    MaxStreamsBidi {
        max: u64,
    },

    MaxStreamsUni {
        max: u64,
    },

    DataBlocked {
        limit: u64,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },

    StreamsBlockedBidi {
        limit: u64,
    },

    StreamsBlockedUni {
        limit: u64,
    },

    NewConnectionId {
        seq_num: u64,
        retire_prior_to: u64,
        conn_id: Vec<u8>,
        reset_token: [u8; 16],
    },

    RetireConnectionId {
        seq_num: u64,
    },

    PathChallenge {
        data: [u8; 8],
    },

    PathResponse {
        data: [u8; 8],
    },

    ConnectionClose {
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },

    ApplicationClose {
        error_code: u64,
        reason: Vec<u8>,
    },

    HandshakeDone,

    Datagram {
        data: Vec<u8>,
    },

    DatagramHeader {
        length: usize,
    },

    ACKMP {
        space_identifier: u64,
        ack_delay: u64,
        ranges: ranges::RangeSet,
        ecn_counts: Option<EcnCounts>,
    },

    PathAbandon {
        dcid_seq_num: u64,
        error_code: u64,
        reason: Vec<u8>,
    },

    McAnnounce {
        channel_id: Vec<u8>,
        path_type: u64,
        auth_type: u64,
        is_ipv6: u8,
        full_reliability: u8,
        source_ip: [u8; 4],
        group_ip: [u8; 4],
        udp_port: u16,
        expiration_timer: u64, // In ms
        public_key: Vec<u8>,
    },

    McState {
        channel_id: Vec<u8>,
        // MC-TODO: sequence number?
        action: u64,
        action_data: u64,
        // MC-TODO: reason code?
    },

    McKey {
        channel_id: Vec<u8>,
        key: Vec<u8>,
        algo: Algorithm,
        first_pn: u64,
        client_id: u64,
        stream_states: Vec<FcStreamState>,
    },

    McExpire {
        channel_id: Vec<u8>,
        expiration_type: u8,
        pkt_num: Option<u64>,
        fec_metadata: Option<u64>,
    },

    McAuth {
        channel_id: Vec<u8>,
        pn: u64,
        signatures: Vec<McSymSignature>,
    },

    McAsym {
        signature: Vec<u8>,
    },

    McNack {
        channel_id: Vec<u8>,
        last_pn: u64,
        nb_repair_needed: u64,
        ranges: ranges::RangeSet,
    },

    Repair {
        repair_symbol: RepairSymbol,
    },

    SourceSymbolHeader {
        metadata: SourceSymbolMetadata,
        recovered: bool,
    },

    SourceSymbol {
        source_symbol: SourceSymbol,
    },

    SourceSymbolACK {
        ranges: ranges::RangeSet,
    },

    PathStandby {
        dcid_seq_num: u64,
        seq_num: u64,
    },

    PathAvailable {
        dcid_seq_num: u64,
        seq_num: u64,
    },
}

impl Frame {
    pub fn from_bytes(
        b: &mut octets::Octets, pkt: packet::Type, nc_decoder: &Decoder,
    ) -> Result<Frame> {
        let frame_type = b.get_varint()?;

        let frame = match frame_type {
            0x00 => {
                let mut len = 1;

                while b.peek_u8() == Ok(0x00) {
                    b.get_u8()?;

                    len += 1;
                }

                Frame::Padding { len }
            },

            0x01 => Frame::Ping,

            0x02..=0x03 => parse_ack_frame(frame_type, b)?,

            0x04 => Frame::ResetStream {
                stream_id: b.get_varint()?,
                error_code: b.get_varint()?,
                final_size: b.get_varint()?,
            },

            0x05 => Frame::StopSending {
                stream_id: b.get_varint()?,
                error_code: b.get_varint()?,
            },

            0x06 => {
                let offset = b.get_varint()?;
                let data = b.get_bytes_with_varint_length()?;
                let data = stream::RangeBuf::from(data.as_ref(), offset, false);

                Frame::Crypto { data }
            },

            0x07 => Frame::NewToken {
                token: b.get_bytes_with_varint_length()?.to_vec(),
            },

            0x08..=0x0f => parse_stream_frame(frame_type, b)?,

            0x10 => Frame::MaxData {
                max: b.get_varint()?,
            },

            0x11 => Frame::MaxStreamData {
                stream_id: b.get_varint()?,
                max: b.get_varint()?,
            },

            0x12 => Frame::MaxStreamsBidi {
                max: b.get_varint()?,
            },

            0x13 => Frame::MaxStreamsUni {
                max: b.get_varint()?,
            },

            0x14 => Frame::DataBlocked {
                limit: b.get_varint()?,
            },

            0x15 => Frame::StreamDataBlocked {
                stream_id: b.get_varint()?,
                limit: b.get_varint()?,
            },

            0x16 => Frame::StreamsBlockedBidi {
                limit: b.get_varint()?,
            },

            0x17 => Frame::StreamsBlockedUni {
                limit: b.get_varint()?,
            },

            0x18 => Frame::NewConnectionId {
                seq_num: b.get_varint()?,
                retire_prior_to: b.get_varint()?,
                conn_id: b.get_bytes_with_u8_length()?.to_vec(),
                reset_token: b
                    .get_bytes(16)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?,
            },

            0x19 => Frame::RetireConnectionId {
                seq_num: b.get_varint()?,
            },

            0x1a => Frame::PathChallenge {
                data: b
                    .get_bytes(8)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?,
            },

            0x1b => Frame::PathResponse {
                data: b
                    .get_bytes(8)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?,
            },

            0x1c => Frame::ConnectionClose {
                error_code: b.get_varint()?,
                frame_type: b.get_varint()?,
                reason: b.get_bytes_with_varint_length()?.to_vec(),
            },

            0x1d => Frame::ApplicationClose {
                error_code: b.get_varint()?,
                reason: b.get_bytes_with_varint_length()?.to_vec(),
            },

            0x1e => Frame::HandshakeDone,

            0x30 | 0x31 => parse_datagram_frame(frame_type, b)?,

            MC_ANNOUNCE_CODE => {
                let channel_id = b.get_bytes_with_u8_length()?.to_vec();
                let path_type = b.get_varint()?;
                let auth_type = b.get_varint()?;
                let is_ipv6 = b.get_u8()?;
                let full_reliability = b.get_u8()?;
                let source_ip = b
                    .get_bytes(4)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?;
                let group_ip = b
                    .get_bytes(4)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?;
                let udp_port = b.get_u16()?;
                let expiration_timer = b.get_u64()?;
                let key_len = b.get_varint()? as usize;
                let public_key = b
                    .get_bytes(key_len)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?;

                Frame::McAnnounce {
                    channel_id,
                    path_type,
                    auth_type,
                    is_ipv6,
                    full_reliability,
                    source_ip,
                    group_ip,
                    udp_port,
                    expiration_timer,
                    public_key,
                }
            },

            MC_STATE_CODE => Frame::McState {
                channel_id: b.get_bytes_with_u8_length()?.to_vec(),
                action: b.get_varint()?,
                action_data: b.get_varint()?,
            },

            MC_KEY_CODE => {
                let channel_id = b.get_bytes_with_u8_length()?.to_vec();
                let key_len = b.get_varint()?;
                let key = b
                    .get_bytes(key_len as usize)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?;
                let algo =
                    b.get_u8()?.try_into().map_err(|_| Error::CryptoFail)?;
                let first_pn = b.get_varint()?;
                let client_id = b.get_varint()?;
                let nb_stream_states = b.get_varint()?;
                let stream_states = (0..nb_stream_states)
                    .map(|_| FcStreamState::from_bytes(b))
                    .collect::<Result<Vec<_>>>()?;
                Frame::McKey {
                    channel_id,
                    key,
                    algo,
                    first_pn,
                    client_id,
                    stream_states,
                }
            },

            MC_EXPIRE_CODE => {
                let channel_id = b.get_bytes_with_u8_length()?.to_vec();
                let expiration_type = b.get_u8()?;
                let pkt_num = if expiration_type & 1 > 0 {
                    Some(b.get_varint()?)
                } else {
                    None
                };
                let fec_metadata = if expiration_type & 4 > 0 {
                    Some(b.get_varint()?)
                } else {
                    None
                };

                Frame::McExpire {
                    channel_id,
                    expiration_type,
                    pkt_num,
                    fec_metadata,
                }
            },

            MC_AUTH_CODE => {
                let channel_id = b.get_bytes_with_u8_length()?.to_vec();
                let pn = b.get_varint()?;
                let nb_signatures = b.get_u8()?;
                let signatures: Vec<_> = (0..nb_signatures)
                    .map(|_| {
                        let mc_client_id = b.get_varint()?;
                        let sign = b.get_bytes_with_u8_length()?.to_vec();
                        Ok(McSymSignature { mc_client_id, sign })
                    })
                    .collect::<Result<Vec<_>>>()?;

                Frame::McAuth {
                    channel_id,
                    pn,
                    signatures,
                }
            },

            MC_ASYM_CODE => {
                let signature = b.get_bytes_with_u8_length()?.to_vec();

                Frame::McAsym { signature }
            },

            MC_NACK_CODE => {
                let channel_id = b.get_bytes_with_u8_length()?.to_vec();
                let last_pn = b.get_varint()?;
                let nb_repair_needed = b.get_varint()?;
                let (_, ranges, _) = parse_common_ack_frame(b, false)?;

                Frame::McNack {
                    channel_id,
                    last_pn,
                    nb_repair_needed,
                    ranges,
                }
            },

            0x32 => {
                let (read, repair_symbol) =
                    nc_decoder.read_repair_symbol(b.to_vec().as_slice())?;
                b.skip(read)?;
                Frame::Repair { repair_symbol }
            },

            0x33 => {
                let symbol_size = nc_decoder.symbol_size();
                let (read, source_symbol_metadata) =
                    nc_decoder.read_source_symbol_metadata(b.as_ref())?;
                b.skip(read)?;
                let mut source_symbol_data = vec![0; symbol_size];
                // copy the remaining payload but be careful to place padding at
                // the start of the symbol if the remaining paylaod does not match
                // the symbol size
                source_symbol_data[symbol_size - b.as_ref().len()..]
                    .copy_from_slice(b.as_ref());
                Frame::SourceSymbol {
                    source_symbol: SourceSymbol::new(
                        source_symbol_metadata,
                        source_symbol_data,
                    ),
                }
            },

            0x34 => parse_source_symbol_ack_frame(b)?,

            0x15228c00..=0x15228c01 => parse_ack_mp_frame(frame_type, b)?,

            0x15228c05 => Frame::PathAbandon {
                dcid_seq_num: b.get_varint()?,
                error_code: b.get_varint()?,
                reason: b.get_bytes_with_varint_length()?.to_vec(),
            },

            0x15228c07 => Frame::PathStandby {
                dcid_seq_num: b.get_varint()?,
                seq_num: b.get_varint()?,
            },

            0x15228c08 => Frame::PathAvailable {
                dcid_seq_num: b.get_varint()?,
                seq_num: b.get_varint()?,
            },

            _ => return Err(Error::InvalidFrame),
        };

        let allowed = match (pkt, &frame) {
            // PADDING and PING are allowed on all packet types.
            (_, Frame::Padding { .. }) | (_, Frame::Ping { .. }) => true,

            // ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, and
            // RETIRE_CONNECTION_ID can't be sent on 0-RTT packets. Multipath
            // frames are only available in 1-RTT packets.
            (packet::Type::ZeroRTT, Frame::ACK { .. }) => false,
            (packet::Type::ZeroRTT, Frame::Crypto { .. }) => false,
            (packet::Type::ZeroRTT, Frame::HandshakeDone) => false,
            (packet::Type::ZeroRTT, Frame::NewToken { .. }) => false,
            (packet::Type::ZeroRTT, Frame::PathResponse { .. }) => false,
            (packet::Type::ZeroRTT, Frame::RetireConnectionId { .. }) => false,
            (packet::Type::ZeroRTT, Frame::ConnectionClose { .. }) => false,
            (packet::Type::ZeroRTT, Frame::ACKMP { .. }) => false,
            (packet::Type::ZeroRTT, Frame::PathAbandon { .. }) => false,
            (packet::Type::ZeroRTT, Frame::PathStandby { .. }) => false,
            (packet::Type::ZeroRTT, Frame::PathAvailable { .. }) => false,

            // ACK, CRYPTO and CONNECTION_CLOSE can be sent on all other packet
            // types.
            (_, Frame::ACK { .. }) => true,
            (_, Frame::Crypto { .. }) => true,
            (_, Frame::ConnectionClose { .. }) => true,

            // All frames are allowed on 0-RTT and 1-RTT packets.
            (packet::Type::Short, _) => true,
            (packet::Type::ZeroRTT, _) => true,

            // All other cases are forbidden.
            (..) => false,
        };

        if !allowed {
            error!("Bad frame: {:?}", frame);
            return Err(Error::InvalidPacket);
        }

        Ok(frame)
    }

    pub fn to_bytes(&self, b: &mut octets::OctetsMut) -> Result<usize> {
        let before = b.cap();

        match self {
            Frame::Padding { len } => {
                let mut left = *len;

                while left > 0 {
                    b.put_varint(0x00)?;

                    left -= 1;
                }
            },

            Frame::Ping => {
                b.put_varint(0x01)?;
            },

            Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                if ecn_counts.is_none() {
                    b.put_varint(0x02)?;
                } else {
                    b.put_varint(0x03)?;
                }
                common_ack_to_bytes(b, ack_delay, ranges, ecn_counts)?;
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                b.put_varint(0x04)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*error_code)?;
                b.put_varint(*final_size)?;
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                b.put_varint(0x05)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*error_code)?;
            },

            Frame::Crypto { data } => {
                encode_crypto_header(data.off(), data.len() as u64, b)?;

                b.put_bytes(data)?;
            },

            Frame::CryptoHeader { .. } => (),

            Frame::NewToken { token } => {
                b.put_varint(0x07)?;

                b.put_varint(token.len() as u64)?;
                b.put_bytes(token)?;
            },

            Frame::Stream { stream_id, data } => {
                encode_stream_header(
                    *stream_id,
                    data.off(),
                    data.len() as u64,
                    data.fin(),
                    b,
                )?;

                b.put_bytes(data)?;
            },

            Frame::StreamHeader { .. } => (),

            Frame::MaxData { max } => {
                b.put_varint(0x10)?;

                b.put_varint(*max)?;
            },

            Frame::MaxStreamData { stream_id, max } => {
                b.put_varint(0x11)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*max)?;
            },

            Frame::MaxStreamsBidi { max } => {
                b.put_varint(0x12)?;

                b.put_varint(*max)?;
            },

            Frame::MaxStreamsUni { max } => {
                b.put_varint(0x13)?;

                b.put_varint(*max)?;
            },

            Frame::DataBlocked { limit } => {
                b.put_varint(0x14)?;

                b.put_varint(*limit)?;
            },

            Frame::StreamDataBlocked { stream_id, limit } => {
                b.put_varint(0x15)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*limit)?;
            },

            Frame::StreamsBlockedBidi { limit } => {
                b.put_varint(0x16)?;

                b.put_varint(*limit)?;
            },

            Frame::StreamsBlockedUni { limit } => {
                b.put_varint(0x17)?;

                b.put_varint(*limit)?;
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                b.put_varint(0x18)?;

                b.put_varint(*seq_num)?;
                b.put_varint(*retire_prior_to)?;
                b.put_u8(conn_id.len() as u8)?;
                b.put_bytes(conn_id.as_ref())?;
                b.put_bytes(reset_token.as_ref())?;
            },

            Frame::RetireConnectionId { seq_num } => {
                b.put_varint(0x19)?;

                b.put_varint(*seq_num)?;
            },

            Frame::PathChallenge { data } => {
                b.put_varint(0x1a)?;

                b.put_bytes(data.as_ref())?;
            },

            Frame::PathResponse { data } => {
                b.put_varint(0x1b)?;

                b.put_bytes(data.as_ref())?;
            },

            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                b.put_varint(0x1c)?;

                b.put_varint(*error_code)?;
                b.put_varint(*frame_type)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;
            },

            Frame::ApplicationClose { error_code, reason } => {
                b.put_varint(0x1d)?;

                b.put_varint(*error_code)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;
            },

            Frame::HandshakeDone => {
                b.put_varint(0x1e)?;
            },

            Frame::Datagram { data } => {
                encode_dgram_header(data.len() as u64, b)?;

                b.put_bytes(data.as_ref())?;
            },

            Frame::DatagramHeader { .. } => (),

            Frame::ACKMP {
                space_identifier,
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                if ecn_counts.is_none() {
                    b.put_varint(0x15228c00)?;
                } else {
                    b.put_varint(0x15228c01)?;
                }
                b.put_varint(*space_identifier)?;
                common_ack_to_bytes(b, ack_delay, ranges, ecn_counts)?;
            },

            Frame::PathAbandon {
                dcid_seq_num,
                error_code,
                reason,
            } => {
                b.put_varint(0x15228c05)?;

                b.put_varint(*dcid_seq_num)?;
                b.put_varint(*error_code)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;
            },

            Frame::McAnnounce {
                channel_id,
                path_type,
                auth_type,
                is_ipv6,
                full_reliability,
                source_ip,
                group_ip,
                udp_port,
                expiration_timer,
                public_key,
            } => {
                debug!("Going to encode the MC_ANNOUNCE frame");
                debug!("Before putting the frame: {}", b.off());
                b.put_varint(MC_ANNOUNCE_CODE)?;
                b.put_u8(channel_id.len() as u8)?;
                b.put_bytes(channel_id.as_ref())?;
                b.put_varint(*path_type)?;
                b.put_varint(*auth_type)?;
                b.put_u8(*is_ipv6)?;
                b.put_u8(*full_reliability)?;
                b.put_bytes(source_ip)?;
                b.put_bytes(group_ip)?;
                b.put_u16(*udp_port)?;
                b.put_u64(*expiration_timer)?;
                b.put_varint(public_key.len() as u64)?;
                b.put_bytes(public_key)?;
                debug!("After putting the frame: {}", b.off());
            },

            Frame::McState {
                channel_id,
                action,
                action_data,
            } => {
                debug!("Going to encode the MC_STATE frame");
                b.put_varint(MC_STATE_CODE)?;
                b.put_u8(channel_id.len() as u8)?;
                b.put_bytes(channel_id.as_ref())?;
                b.put_varint(*action)?;
                b.put_varint(*action_data)?;
            },

            Frame::McKey {
                channel_id,
                key,
                algo,
                first_pn,
                client_id,
                stream_states,
            } => {
                debug!("Going to encode the MC_KEY frame");
                b.put_varint(MC_KEY_CODE)?;
                b.put_u8(channel_id.len() as u8)?;
                b.put_bytes(channel_id.as_ref())?;
                b.put_varint(key.len() as u64)?;
                b.put_bytes(key)?;
                b.put_u8(algo.to_owned().try_into().unwrap())?;
                b.put_varint(*first_pn)?;
                b.put_varint(*client_id)?;
                b.put_varint(stream_states.len() as u64)?;
                stream_states
                    .iter()
                    .map(|s| s.to_bytes(b))
                    .collect::<Result<_>>()?;
            },

            Frame::McExpire {
                channel_id,
                expiration_type,
                pkt_num,
                fec_metadata,
            } => {
                debug!("Going to encode the MC_EXPIRE frame");
                b.put_varint(MC_EXPIRE_CODE)?;
                b.put_u8(channel_id.len() as u8)?;
                b.put_bytes(channel_id.as_ref())?;
                b.put_u8(*expiration_type)?;
                if let Some(pkt_num) = pkt_num {
                    b.put_varint(*pkt_num)?;
                }
                if let Some(fec_metadata) = fec_metadata {
                    b.put_varint(*fec_metadata)?;
                }
            },

            Frame::McAuth {
                channel_id,
                pn,
                signatures,
            } => {
                debug!(
                    "Going to encode the MC_AUTH frame: {:?} {:?} {:?}",
                    channel_id, pn, signatures
                );
                b.put_varint(MC_AUTH_CODE)?;
                b.put_u8(channel_id.len() as u8)?;
                b.put_bytes(channel_id.as_ref())?;
                b.put_varint(*pn)?;
                b.put_u8(signatures.len() as u8)?;
                for signature in signatures.iter() {
                    b.put_varint(signature.mc_client_id)?;
                    b.put_u8(signature.sign.len() as u8)?;
                    b.put_bytes(&signature.sign)?;
                }
            },

            Frame::McAsym { signature } => {
                debug!("going to encode the MC_ASYM frame: {:?}", signature);
                b.put_varint(MC_ASYM_CODE)?;
                b.put_u8(signature.len() as u8)?;
                b.put_bytes(signature)?;
            },

            Frame::McNack {
                channel_id,
                last_pn,
                nb_repair_needed,
                ranges,
            } => {
                debug!("Going to encode the MC_NACK frame: {:?}", ranges);
                b.put_varint(MC_NACK_CODE)?;
                b.put_u8(channel_id.len() as u8)?;
                b.put_bytes(channel_id.as_ref())?;
                b.put_varint(*last_pn)?;
                b.put_varint(*nb_repair_needed)?;
                common_ack_to_bytes(b, &0, ranges, &None)?;
            },

            Frame::Repair { repair_symbol } => {
                b.put_varint(0x32)?;
                b.put_bytes(repair_symbol.get())?;
            },
            Frame::SourceSymbolHeader { metadata, .. } => {
                // the source symbol frame only writes its metadata and we expect
                // next protected frames to be written afterwards
                // This is weird, the best would be to wrap the protected frames
                // inside the source symbol frame but we would
                // loose some view on what the packet contains and it would
                // require many changes to recover that
                b.put_varint(0x33)?;
                b.put_bytes(metadata)?;
            },
            Frame::SourceSymbol { source_symbol } => {
                // the source symbol frame only writes its metadata and we expect
                // next protected frames to be written afterwards
                // This is weird, the best would be to wrap the protected frames
                // inside the source symbol frame but we would
                // loose some view on what the packet contains and it would
                // require many changes to recover that
                b.put_varint(0x33)?;
                b.put_bytes(&source_symbol.metadata())?;
                b.put_bytes(source_symbol.get())?;
            },
            Frame::SourceSymbolACK { ranges } => {
                // the same as an ACK frame but acknowledging source symbols
                b.put_varint(0x34)?;
                let mut it = ranges.iter().rev();

                let first = it.next().unwrap();
                let ack_block = (first.end - 1) - first.start;

                b.put_varint(first.end - 1)?;
                b.put_varint(it.len() as u64)?;
                b.put_varint(ack_block)?;

                let mut smallest_ack = first.start;

                for block in it {
                    let gap = smallest_ack - block.end - 1;
                    let ack_block = (block.end - 1) - block.start;

                    b.put_varint(gap)?;
                    b.put_varint(ack_block)?;

                    smallest_ack = block.start;
                }
            },
            Frame::PathStandby {
                dcid_seq_num,
                seq_num,
            } => {
                b.put_varint(0x15228c07)?;

                b.put_varint(*dcid_seq_num)?;
                b.put_varint(*seq_num)?;
            },

            Frame::PathAvailable {
                dcid_seq_num,
                seq_num,
            } => {
                b.put_varint(0x15228c08)?;

                b.put_varint(*dcid_seq_num)?;
                b.put_varint(*seq_num)?;
            },
        }

        Ok(before - b.cap())
    }

    pub fn wire_len(&self) -> usize {
        match self {
            Frame::Padding { len } => *len,

            Frame::Ping => 1,

            Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                1 + // frame_type
                common_ack_wire_len(ack_delay, ranges, ecn_counts)
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(*error_code) + // error_code
                octets::varint_len(*final_size) // final_size
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(*error_code) // error_code
            },

            Frame::Crypto { data } => {
                1 + // frame type
                octets::varint_len(data.off()) + // offset
                2 + // length, always encode as 2-byte varint
                data.len() // data
            },

            Frame::CryptoHeader { offset, length, .. } => {
                1 + // frame type
                octets::varint_len(*offset) + // offset
                2 + // length, always encode as 2-byte varint
                length // data
            },

            Frame::NewToken { token } => {
                1 + // frame type
                octets::varint_len(token.len() as u64) + // token length
                token.len() // token
            },

            Frame::Stream { stream_id, data } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(data.off()) + // offset
                2 + // length, always encode as 2-byte varint
                data.len() // data
            },

            Frame::StreamHeader {
                stream_id,
                offset,
                length,
                ..
            } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(*offset) + // offset
                2 + // length, always encode as 2-byte varint
                length // data
            },

            Frame::MaxData { max } => {
                1 + // frame type
                octets::varint_len(*max) // max
            },

            Frame::MaxStreamData { stream_id, max } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(*max) // max
            },

            Frame::MaxStreamsBidi { max } => {
                1 + // frame type
                octets::varint_len(*max) // max
            },

            Frame::MaxStreamsUni { max } => {
                1 + // frame type
                octets::varint_len(*max) // max
            },

            Frame::DataBlocked { limit } => {
                1 + // frame type
                octets::varint_len(*limit) // limit
            },

            Frame::StreamDataBlocked { stream_id, limit } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(*limit) // limit
            },

            Frame::StreamsBlockedBidi { limit } => {
                1 + // frame type
                octets::varint_len(*limit) // limit
            },

            Frame::StreamsBlockedUni { limit } => {
                1 + // frame type
                octets::varint_len(*limit) // limit
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                1 + // frame type
                octets::varint_len(*seq_num) + // seq_num
                octets::varint_len(*retire_prior_to) + // retire_prior_to
                1 + // conn_id length
                conn_id.len() + // conn_id
                reset_token.len() // reset_token
            },

            Frame::RetireConnectionId { seq_num } => {
                1 + // frame type
                octets::varint_len(*seq_num) // seq_num
            },

            Frame::PathChallenge { .. } => {
                1 + // frame type
                8 // data
            },

            Frame::PathResponse { .. } => {
                1 + // frame type
                8 // data
            },

            Frame::ConnectionClose {
                frame_type,
                error_code,
                reason,
                ..
            } => {
                1 + // frame type
                octets::varint_len(*error_code) + // error_code
                octets::varint_len(*frame_type) + // frame_type
                octets::varint_len(reason.len() as u64) + // reason_len
                reason.len() // reason
            },

            Frame::ApplicationClose { reason, error_code } => {
                1 + // frame type
                octets::varint_len(*error_code) + // error_code
                octets::varint_len(reason.len() as u64) + // reason_len
                reason.len() // reason
            },

            Frame::HandshakeDone => {
                1 // frame type
            },

            Frame::Datagram { data } => {
                1 + // frame type
                2 + // length, always encode as 2-byte varint
                data.len() // data
            },

            Frame::DatagramHeader { length } => {
                1 + // frame type
                2 + // length, always encode as 2-byte varint
                *length // data
            },

            Frame::ACKMP {
                space_identifier,
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                4 + // frame_type
                octets::varint_len(*space_identifier) + // space_identifier
                common_ack_wire_len(ack_delay, ranges, ecn_counts)
            },

            Frame::PathAbandon {
                dcid_seq_num,
                error_code,
                reason,
            } => {
                4 + // frame type
                octets::varint_len(*dcid_seq_num) +
                octets::varint_len(*error_code) +
                octets::varint_len(reason.len() as u64) + // reason_len
                reason.len()
            },

            Frame::McAnnounce {
                channel_id,
                path_type,
                auth_type,
                is_ipv6: _,
                full_reliability: _,
                source_ip: _,
                group_ip: _,
                udp_port: _,
                expiration_timer: _,
                public_key,
            } => {
                let public_key_len_size =
                    octets::varint_len(public_key.len() as u64);
                let path_type_size = octets::varint_len(*path_type);
                let auth_type_size = octets::varint_len(*auth_type);
                let frame_type_size = octets::varint_len(MC_ANNOUNCE_CODE);
                frame_type_size + // frame type
                1 + // channel_id len
                channel_id.len() +
                path_type_size +
                auth_type_size +
                1 + // is_ipv6
                4 + // source_ip
                4 + // group_ip
                2 + // udp_port
                8 + // expiration_timer
                public_key_len_size +
                public_key.len()
            },

            Frame::McState {
                channel_id,
                action,
                action_data,
            } => {
                let action_size = octets::varint_len(*action);
                let action_data_size = octets::varint_len(*action_data);
                let frame_type_size = octets::varint_len(MC_STATE_CODE);
                frame_type_size + // frame type
                1 + // channel_id len
                channel_id.len() +
                action_size +
                action_data_size
            },

            Frame::McKey {
                channel_id,
                key,
                algo: _,
                first_pn,
                client_id,
                stream_states,
            } => {
                let key_len_size = octets::varint_len(key.len() as u64);
                let first_pn_size = octets::varint_len(*first_pn);
                let client_id_size = octets::varint_len(*client_id);
                let frame_type_size = octets::varint_len(MC_KEY_CODE);
                let nb_stream_state_size = octets::varint_len(stream_states.len() as u64);
                frame_type_size + // frame type
                1 + // channel_id len
                channel_id.len() +
                key_len_size +
                key.len() +
                1 + // algo len
                first_pn_size +
                client_id_size + 
                nb_stream_state_size +
                stream_states.iter().map(|s| s.len()).sum::<usize>()
            },

            Frame::McExpire {
                channel_id,
                expiration_type: _,
                pkt_num,
                fec_metadata,
            } => {
                let pkt_num_len = pkt_num.map(octets::varint_len).unwrap_or(0);
                let fec_metadata_len =
                    fec_metadata.map(octets::varint_len).unwrap_or(0);
                let frame_type_size = octets::varint_len(MC_EXPIRE_CODE);
                frame_type_size + // frame type
                1 + // channel_id len
                channel_id.len() +
                pkt_num_len +
                fec_metadata_len
            },

            Frame::McAuth {
                channel_id,
                pn,
                signatures,
            } => {
                let frame_type_size = octets::varint_len(MC_AUTH_CODE);
                let pn_len = octets::varint_len(*pn);
                let signatures_size: usize = signatures
                    .iter()
                    .map(|sign| {
                        octets::varint_len(sign.mc_client_id) +
                            1 +
                            sign.sign.len()
                    })
                    .sum();
                frame_type_size +
                1 + // channel_id len
                channel_id.len() +
                pn_len +
                1 + // signatures len
                signatures_size
            },

            Frame::McAsym { signature } => {
                let frame_type_size = octets::varint_len(MC_ASYM_CODE);
                frame_type_size +
                1 + // signature len
                signature.len()
            },

            Frame::McNack {
                channel_id,
                last_pn,
                nb_repair_needed,
                ranges,
            } => {
                let frame_type_size = octets::varint_len(MC_NACK_CODE);
                let last_pn_size = octets::varint_len(*last_pn);
                let nb_repair_needed_size = octets::varint_len(*nb_repair_needed);
                frame_type_size +
                1 + // channel_id_len
                channel_id.len() +
                last_pn_size +
                nb_repair_needed_size +
                common_ack_wire_len(&0, ranges, &None)
            },

            Frame::Repair { repair_symbol } => {
                1 + // frame_type
                repair_symbol.wire_len()
            },

            Frame::SourceSymbolHeader { metadata, .. } => {
                1 + // frame type
                metadata.len() // metadata
            },

            Frame::SourceSymbol { source_symbol } => {
                1 + // frame type
                source_symbol.metadata().len() + // metadata
                source_symbol.get().len()
            },
            Frame::SourceSymbolACK { ranges } => {
                let mut it = ranges.iter().rev();

                let first = it.next().unwrap();
                let ack_block = (first.end - 1) - first.start;

                let mut len = 1 + // frame type
                    octets::varint_len(first.end - 1) + // largest_ack
                    octets::varint_len(it.len() as u64) + // block_count
                    octets::varint_len(ack_block); // first_block

                let mut smallest_ack = first.start;

                for block in it {
                    let gap = smallest_ack - block.end - 1;
                    let ack_block = (block.end - 1) - block.start;

                    len += octets::varint_len(gap) + // gap
                           octets::varint_len(ack_block); // ack_block

                    smallest_ack = block.start;
                }
                len
            },

            Frame::PathStandby {
                dcid_seq_num,
                seq_num,
            } => {
                4 + // frame size
                octets::varint_len(*dcid_seq_num) +
                octets::varint_len(*seq_num)
            },

            Frame::PathAvailable {
                dcid_seq_num,
                seq_num,
            } => {
                4 + // frame size
                octets::varint_len(*dcid_seq_num) +
                octets::varint_len(*seq_num)
            },
        }
    }

    pub fn ack_eliciting(&self) -> bool {
        // Any other frame is ack-eliciting (note the `!`).
        !matches!(
            self,
            Frame::Padding { .. } |
                Frame::ACK { .. } |
                Frame::ApplicationClose { .. } |
                Frame::ConnectionClose { .. } |
                Frame::ACKMP { .. } |
                Frame::SourceSymbol { .. } |
                Frame::SourceSymbolHeader { .. } |
                Frame::SourceSymbolACK { .. }
        )
    }

    pub fn probing(&self) -> bool {
        matches!(
            self,
            Frame::Padding { .. } |
                Frame::NewConnectionId { .. } |
                Frame::PathChallenge { .. } |
                Frame::PathResponse { .. }
        )
    }

    #[cfg(feature = "qlog")]
    pub fn to_qlog(&self) -> QuicFrame {
        match self {
            Frame::Padding { .. } => QuicFrame::Padding,

            Frame::Ping { .. } => QuicFrame::Ping,

            Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                let ack_ranges = AckedRanges::Double(
                    ranges.iter().map(|r| (r.start, r.end - 1)).collect(),
                );

                let (ect0, ect1, ce) = match ecn_counts {
                    Some(ecn) => (
                        Some(ecn.ect0_count),
                        Some(ecn.ect1_count),
                        Some(ecn.ecn_ce_count),
                    ),

                    None => (None, None, None),
                };

                QuicFrame::Ack {
                    ack_delay: Some(*ack_delay as f32 / 1000.0),
                    acked_ranges: Some(ack_ranges),
                    ect1,
                    ect0,
                    ce,
                }
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => QuicFrame::ResetStream {
                stream_id: *stream_id,
                error_code: *error_code,
                final_size: *final_size,
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => QuicFrame::StopSending {
                stream_id: *stream_id,
                error_code: *error_code,
            },

            Frame::Crypto { data } => QuicFrame::Crypto {
                offset: data.off(),
                length: data.len() as u64,
            },

            Frame::CryptoHeader { offset, length } => QuicFrame::Crypto {
                offset: *offset,
                length: *length as u64,
            },

            Frame::NewToken { token } => QuicFrame::NewToken {
                token: qlog::Token {
                    // TODO: pick the token type some how
                    ty: Some(qlog::TokenType::Retry),
                    raw: Some(qlog::events::RawInfo {
                        data: qlog::HexSlice::maybe_string(Some(token)),
                        length: Some(token.len() as u64),
                        payload_length: None,
                    }),
                    details: None,
                },
            },

            Frame::Stream { stream_id, data } => QuicFrame::Stream {
                stream_id: *stream_id,
                offset: data.off(),
                length: data.len() as u64,
                fin: data.fin().then_some(true),
                raw: None,
            },

            Frame::StreamHeader {
                stream_id,
                offset,
                length,
                fin,
            } => QuicFrame::Stream {
                stream_id: *stream_id,
                offset: *offset,
                length: *length as u64,
                fin: fin.then(|| true),
                raw: None,
            },

            Frame::MaxData { max } => QuicFrame::MaxData { maximum: *max },

            Frame::MaxStreamData { stream_id, max } => QuicFrame::MaxStreamData {
                stream_id: *stream_id,
                maximum: *max,
            },

            Frame::MaxStreamsBidi { max } => QuicFrame::MaxStreams {
                stream_type: StreamType::Bidirectional,
                maximum: *max,
            },

            Frame::MaxStreamsUni { max } => QuicFrame::MaxStreams {
                stream_type: StreamType::Unidirectional,
                maximum: *max,
            },

            Frame::DataBlocked { limit } =>
                QuicFrame::DataBlocked { limit: *limit },

            Frame::StreamDataBlocked { stream_id, limit } =>
                QuicFrame::StreamDataBlocked {
                    stream_id: *stream_id,
                    limit: *limit,
                },

            Frame::StreamsBlockedBidi { limit } => QuicFrame::StreamsBlocked {
                stream_type: StreamType::Bidirectional,
                limit: *limit,
            },

            Frame::StreamsBlockedUni { limit } => QuicFrame::StreamsBlocked {
                stream_type: StreamType::Unidirectional,
                limit: *limit,
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => QuicFrame::NewConnectionId {
                sequence_number: *seq_num as u32,
                retire_prior_to: *retire_prior_to as u32,
                connection_id_length: Some(conn_id.len() as u8),
                connection_id: format!("{}", qlog::HexSlice::new(conn_id)),
                stateless_reset_token: qlog::HexSlice::maybe_string(Some(
                    reset_token,
                )),
            },

            Frame::RetireConnectionId { seq_num } =>
                QuicFrame::RetireConnectionId {
                    sequence_number: *seq_num as u32,
                },

            Frame::PathChallenge { .. } =>
                QuicFrame::PathChallenge { data: None },

            Frame::PathResponse { .. } => QuicFrame::PathResponse { data: None },

            Frame::ConnectionClose {
                error_code, reason, ..
            } => QuicFrame::ConnectionClose {
                error_space: Some(ErrorSpace::TransportError),
                error_code: Some(*error_code),
                error_code_value: None, // raw error is no different for us
                reason: Some(String::from_utf8_lossy(reason).into_owned()),
                trigger_frame_type: None, // don't know trigger type
            },

            Frame::ApplicationClose { error_code, reason } => {
                QuicFrame::ConnectionClose {
                    error_space: Some(ErrorSpace::ApplicationError),
                    error_code: Some(*error_code),
                    error_code_value: None, // raw error is no different for us
                    reason: Some(String::from_utf8_lossy(reason).into_owned()),
                    trigger_frame_type: None, // don't know trigger type
                }
            },

            Frame::HandshakeDone => QuicFrame::HandshakeDone,

            Frame::Datagram { data } => QuicFrame::Datagram {
                length: data.len() as u64,
                raw: None,
            },

            Frame::DatagramHeader { length } => QuicFrame::Datagram {
                length: *length as u64,
                raw: None,
            },

            Frame::ACKMP {
                space_identifier,
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                let ack_ranges = AckedRanges::Double(
                    ranges.iter().map(|r| (r.start, r.end - 1)).collect(),
                );

                let (ect0, ect1, ce) = match ecn_counts {
                    Some(ecn) => (
                        Some(ecn.ect0_count),
                        Some(ecn.ect1_count),
                        Some(ecn.ecn_ce_count),
                    ),

                    None => (None, None, None),
                };

                QuicFrame::AckMp {
                    space_identifier: *space_identifier,
                    ack_delay: Some(*ack_delay as f32 / 1000.0),
                    acked_ranges: Some(ack_ranges),
                    ect1,
                    ect0,
                    ce,
                }
            },

            Frame::PathAbandon {
                dcid_seq_num,
                error_code,
                reason,
            } => QuicFrame::PathAbandon {
                dcid_seq_num: *dcid_seq_num,
                error_code: *error_code,
                reason: Some(String::from_utf8_lossy(reason).into_owned()),
            },

            Frame::McAnnounce { .. } => QuicFrame::Unknown {
                raw_frame_type: MC_ANNOUNCE_CODE,
                frame_type_value: None,
                raw: None,
            },

            Frame::McState { .. } => QuicFrame::Unknown {
                raw_frame_type: MC_ANNOUNCE_CODE,
                frame_type_value: None,
                raw: None,
            },

            Frame::McKey { .. } => QuicFrame::Unknown {
                raw_frame_type: MC_ANNOUNCE_CODE,
                frame_type_value: None,
                raw: None,
            },

            Frame::McExpire { .. } => QuicFrame::Unknown {
                raw_frame_type: MC_EXPIRE_CODE,
                frame_type_value: None,
                raw: None,
            },

            Frame::McAuth { .. } => QuicFrame::Unknown {
                raw_frame_type: MC_AUTH_CODE,
                frame_type_value: None,
                raw: None,
            },

            Frame::McAsym { .. } => QuicFrame::Unknown {
                raw_frame_type: MC_ASYM_CODE,
                frame_type_value: None,
                raw: None,
            },

            Frame::McNack { .. } => QuicFrame::Unknown {
                raw_frame_type: MC_NACK_CODE,
                frame_type_value: None,
                raw: None,
            },

            Frame::Repair { .. } => QuicFrame::Unknown {
                raw_frame_type: 0x32,
                frame_type_value: None,
                raw: None,
            },

            Frame::SourceSymbolHeader { .. } => QuicFrame::Unknown {
                raw_frame_type: 0x33,
                frame_type_value: None,
                raw: None,
            },

            Frame::SourceSymbol { .. } => QuicFrame::Unknown {
                raw_frame_type: 0x33,
                frame_type_value: None,
                raw: None,
            },
            Frame::SourceSymbolACK { .. } => QuicFrame::Unknown {
                raw_frame_type: 0x34,
                frame_type_value: None,
                raw: None,
            },
            Frame::PathStandby {
                dcid_seq_num,
                seq_num,
            } => QuicFrame::PathStandby {
                dcid_seq_num: *dcid_seq_num,
                seq_num: *seq_num,
            },

            Frame::PathAvailable {
                dcid_seq_num,
                seq_num,
            } => QuicFrame::PathAvailable {
                dcid_seq_num: *dcid_seq_num,
                seq_num: *seq_num,
            },
        }
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Frame::Padding { len } => {
                write!(f, "PADDING len={len}")?;
            },

            Frame::Ping => {
                write!(f, "PING")?;
            },

            Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                write!(
                    f,
                    "ACK delay={ack_delay} blocks={ranges:?} ecn_counts={ecn_counts:?}"
                )?;
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                write!(
                    f,
                    "RESET_STREAM stream={stream_id} err={error_code:x} size={final_size}"
                )?;
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                write!(f, "STOP_SENDING stream={stream_id} err={error_code:x}")?;
            },

            Frame::Crypto { data } => {
                write!(f, "CRYPTO off={} len={}", data.off(), data.len())?;
            },

            Frame::CryptoHeader { offset, length } => {
                write!(f, "CRYPTO off={offset} len={length}")?;
            },

            Frame::NewToken { .. } => {
                write!(f, "NEW_TOKEN (TODO)")?;
            },

            Frame::Stream { stream_id, data } => {
                write!(
                    f,
                    "STREAM id={} off={} len={} fin={}",
                    stream_id,
                    data.off(),
                    data.len(),
                    data.fin()
                )?;
            },

            Frame::StreamHeader {
                stream_id,
                offset,
                length,
                fin,
            } => {
                write!(
                    f,
                    "STREAM id={stream_id} off={offset} len={length} fin={fin}"
                )?;
            },

            Frame::MaxData { max } => {
                write!(f, "MAX_DATA max={max}")?;
            },

            Frame::MaxStreamData { stream_id, max } => {
                write!(f, "MAX_STREAM_DATA stream={stream_id} max={max}")?;
            },

            Frame::MaxStreamsBidi { max } => {
                write!(f, "MAX_STREAMS type=bidi max={max}")?;
            },

            Frame::MaxStreamsUni { max } => {
                write!(f, "MAX_STREAMS type=uni max={max}")?;
            },

            Frame::DataBlocked { limit } => {
                write!(f, "DATA_BLOCKED limit={limit}")?;
            },

            Frame::StreamDataBlocked { stream_id, limit } => {
                write!(
                    f,
                    "STREAM_DATA_BLOCKED stream={stream_id} limit={limit}"
                )?;
            },

            Frame::StreamsBlockedBidi { limit } => {
                write!(f, "STREAMS_BLOCKED type=bidi limit={limit}")?;
            },

            Frame::StreamsBlockedUni { limit } => {
                write!(f, "STREAMS_BLOCKED type=uni limit={limit}")?;
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                write!(
                    f,
                    "NEW_CONNECTION_ID seq_num={seq_num} retire_prior_to={retire_prior_to} conn_id={conn_id:02x?} reset_token={reset_token:02x?}",
                )?;
            },

            Frame::RetireConnectionId { seq_num } => {
                write!(f, "RETIRE_CONNECTION_ID seq_num={seq_num}")?;
            },

            Frame::PathChallenge { data } => {
                write!(f, "PATH_CHALLENGE data={data:02x?}")?;
            },

            Frame::PathResponse { data } => {
                write!(f, "PATH_RESPONSE data={data:02x?}")?;
            },

            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                write!(
                    f,
                    "CONNECTION_CLOSE err={error_code:x} frame={frame_type:x} reason={reason:x?}"
                )?;
            },

            Frame::ApplicationClose { error_code, reason } => {
                write!(
                    f,
                    "APPLICATION_CLOSE err={error_code:x} reason={reason:x?}"
                )?;
            },

            Frame::HandshakeDone => {
                write!(f, "HANDSHAKE_DONE")?;
            },

            Frame::Datagram { data } => {
                write!(f, "DATAGRAM len={}", data.len())?;
            },

            Frame::DatagramHeader { length } => {
                write!(f, "DATAGRAM len={length}")?;
            },

            Frame::ACKMP {
                space_identifier,
                ack_delay,
                ranges,
                ecn_counts,
                ..
            } => {
                write!(
                    f,
                    "ACK_MP space_id={space_identifier} delay={ack_delay} blocks={ranges:?} ecn_counts={ecn_counts:?}",
                )?;
            },

            Frame::PathAbandon {
                dcid_seq_num,
                error_code,
                reason,
                ..
            } => {
                write!(
                    f,
                    "PATH_ABANDON dcid_seq_num={dcid_seq_num:x} err={error_code:x} reason={reason:x?}",
                )?;
            },

            Frame::McAnnounce {
                channel_id,
                path_type,
                auth_type,
                is_ipv6,
                full_reliability,
                source_ip,
                group_ip,
                udp_port,
                expiration_timer,
                public_key: _,
            } => {
                write!(f, "MC_ANNOUNCE channel ID={:?}, path_type={} auth_type={} is_ipv6={}, full_reliability={} source_ip={:?}, group_ip={:?}, udp_port={}, expiration_timer={}", channel_id, path_type, auth_type, is_ipv6, full_reliability, source_ip, group_ip, udp_port, expiration_timer)?;
            },

            Frame::McState {
                channel_id,
                action,
                action_data,
            } => {
                write!(
                    f,
                    "MC_STATE channel ID={:?}, action={}, action_data={}",
                    channel_id, action, action_data,
                )?;
            },

            Frame::McKey {
                channel_id,
                key,
                algo,
                first_pn,
                client_id,
                stream_states,
            } => {
                write!(
                    f,
                    "MC_KEY channel ID={:?} key={:?} algo={:?} first pn={:?} client id={:?} stream_states={:?}",
                    channel_id, key, algo, first_pn, client_id, stream_states,
                )?;
            },

            Frame::McExpire {
                channel_id,
                expiration_type,
                pkt_num,
                fec_metadata,
            } => {
                write!(f, "MC_EXPIRE channel ID={:?} expiration type: {:?} pkt_num: {:?} fec_metadata: {:?}", channel_id, expiration_type, pkt_num, fec_metadata)?;
            },

            Frame::McAuth {
                channel_id,
                pn,
                signatures,
            } => {
                write!(
                    f,
                    "MC_AUTH channel ID={:?} pn={:?} signatures={:?}",
                    channel_id, pn, signatures
                )?;
            },

            Frame::McAsym { signature } => {
                write!(f, "MC_ASYM signature={:?}", signature)?;
            },

            Frame::McNack {
                channel_id,
                last_pn,
                nb_repair_needed,
                ranges,
            } => {
                write!(
                    f,
                    "MC_NACK channel ID={:?} last pn={:?} nb repair needed={:?} ranges={:?}",
                    channel_id, last_pn, nb_repair_needed, ranges
                )?;
            },

            Frame::Repair { repair_symbol } => {
                write!(f, "REPAIR len={}", repair_symbol.wire_len())?;
            },

            Frame::SourceSymbolHeader { metadata, .. } => {
                write!(
                    f,
                    "SOURCE_SYMBOL, metadata={} len={}",
                    source_symbol_metadata_to_u64(*metadata),
                    metadata.len()
                )?;
            },

            Frame::SourceSymbol { source_symbol } => {
                write!(
                    f,
                    "SOURCE_SYMBOL, metadata={} len={}",
                    source_symbol_metadata_to_u64(source_symbol.metadata()),
                    source_symbol.metadata().len()
                )?;
            },
            Frame::SourceSymbolACK { ranges } => {
                write!(f, "SOURCE_SYMBOL_ACK blocks={:?}", ranges)?;
            },
            Frame::PathStandby {
                dcid_seq_num,
                seq_num,
            } => {
                write!(
                    f,
                    "PATH_STANDBY dcid_seq_num={dcid_seq_num:x} seq_num={seq_num:x}",
                )?
            },

            Frame::PathAvailable {
                dcid_seq_num,
                seq_num,
            } => {
                write!(
                    f,
                    "PATH_AVAILABLE dcid_seq_num={dcid_seq_num:x} seq_num={seq_num:x}",
                )?
            },
        }

        Ok(())
    }
}

fn parse_common_ack_frame(
    b: &mut octets::Octets, has_ecn: bool,
) -> Result<(u64, ranges::RangeSet, Option<EcnCounts>)> {
    let largest_ack = b.get_varint()?;
    let ack_delay = b.get_varint()?;
    let block_count = b.get_varint()?;
    let ack_block = b.get_varint()?;

    if largest_ack < ack_block {
        return Err(Error::InvalidFrame);
    }

    let mut smallest_ack = largest_ack - ack_block;

    let mut ranges = ranges::RangeSet::default();

    ranges.insert(smallest_ack..largest_ack + 1);

    for _i in 0..block_count {
        let gap = b.get_varint()?;

        if smallest_ack < 2 + gap {
            return Err(Error::InvalidFrame);
        }

        let largest_ack = (smallest_ack - gap) - 2;
        let ack_block = b.get_varint()?;

        if largest_ack < ack_block {
            return Err(Error::InvalidFrame);
        }

        smallest_ack = largest_ack - ack_block;

        ranges.insert(smallest_ack..largest_ack + 1);
    }

    let ecn_counts = if has_ecn {
        let ecn = EcnCounts {
            ect0_count: b.get_varint()?,
            ect1_count: b.get_varint()?,
            ecn_ce_count: b.get_varint()?,
        };

        Some(ecn)
    } else {
        None
    };

    Ok((ack_delay, ranges, ecn_counts))
}

fn parse_ack_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame> {
    let first = ty as u8;
    let (ack_delay, ranges, ecn_counts) =
        parse_common_ack_frame(b, first & 0x01 != 0)?;

    Ok(Frame::ACK {
        ack_delay,
        ranges,
        ecn_counts,
    })
}

fn parse_ack_mp_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame> {
    let space_identifier = b.get_varint()?;
    let (ack_delay, ranges, ecn_counts) =
        parse_common_ack_frame(b, ty & 0x01 != 0)?;

    Ok(Frame::ACKMP {
        space_identifier,
        ack_delay,
        ranges,
        ecn_counts,
    })
}

fn common_ack_to_bytes(
    b: &mut octets::OctetsMut, ack_delay: &u64, ranges: &ranges::RangeSet,
    ecn_counts: &Option<EcnCounts>,
) -> Result<()> {
    let mut it = ranges.iter().rev();

    let first = it.next().unwrap();
    let ack_block = (first.end - 1) - first.start;

    b.put_varint(first.end - 1)?;
    b.put_varint(*ack_delay)?;
    b.put_varint(it.len() as u64)?;
    b.put_varint(ack_block)?;

    let mut smallest_ack = first.start;

    for block in it {
        let gap = smallest_ack - block.end - 1;
        let ack_block = (block.end - 1) - block.start;

        b.put_varint(gap)?;
        b.put_varint(ack_block)?;

        smallest_ack = block.start;
    }

    if let Some(ecn) = ecn_counts {
        b.put_varint(ecn.ect0_count)?;
        b.put_varint(ecn.ect1_count)?;
        b.put_varint(ecn.ecn_ce_count)?;
    }

    Ok(())
}

fn common_ack_wire_len(
    ack_delay: &u64, ranges: &ranges::RangeSet, ecn_counts: &Option<EcnCounts>,
) -> usize {
    let mut it = ranges.iter().rev();

    let first = it.next().unwrap();
    let ack_block = (first.end - 1) - first.start;

    let mut len = octets::varint_len(first.end - 1) + // largest_ack
        octets::varint_len(*ack_delay) + // ack_delay
        octets::varint_len(it.len() as u64) + // block_count
        octets::varint_len(ack_block); // first_block

    let mut smallest_ack = first.start;

    for block in it {
        let gap = smallest_ack - block.end - 1;
        let ack_block = (block.end - 1) - block.start;

        len += octets::varint_len(gap) + // gap
                octets::varint_len(ack_block); // ack_block

        smallest_ack = block.start;
    }

    if let Some(ecn) = ecn_counts {
        len += octets::varint_len(ecn.ect0_count) +
            octets::varint_len(ecn.ect1_count) +
            octets::varint_len(ecn.ecn_ce_count);
    }

    len
}

fn parse_source_symbol_ack_frame(b: &mut octets::Octets) -> Result<Frame> {
    let largest_ack = b.get_varint()?;
    let block_count = b.get_varint()?;
    let ack_block = b.get_varint()?;

    if largest_ack < ack_block {
        return Err(Error::InvalidFrame);
    }

    let mut smallest_ack = largest_ack - ack_block;

    let mut ranges = ranges::RangeSet::default();

    ranges.insert(smallest_ack..largest_ack + 1);

    for _i in 0..block_count {
        let gap = b.get_varint()?;

        if smallest_ack < 2 + gap {
            return Err(Error::InvalidFrame);
        }

        let largest_ack = (smallest_ack - gap) - 2;
        let ack_block = b.get_varint()?;

        if largest_ack < ack_block {
            return Err(Error::InvalidFrame);
        }

        smallest_ack = largest_ack - ack_block;

        ranges.insert(smallest_ack..largest_ack + 1);
    }

    Ok(Frame::SourceSymbolACK { ranges })
}

pub fn encode_crypto_header(
    offset: u64, length: u64, b: &mut octets::OctetsMut,
) -> Result<()> {
    b.put_varint(0x06)?;

    b.put_varint(offset)?;

    // Always encode length field as 2-byte varint.
    b.put_varint_with_len(length, 2)?;

    Ok(())
}

pub fn encode_stream_header(
    stream_id: u64, offset: u64, length: u64, fin: bool,
    b: &mut octets::OctetsMut,
) -> Result<()> {
    let mut ty: u8 = 0x08;

    // Always encode offset.
    ty |= 0x04;

    // Always encode length.
    ty |= 0x02;

    if fin {
        ty |= 0x01;
    }

    b.put_varint(u64::from(ty))?;

    b.put_varint(stream_id)?;
    b.put_varint(offset)?;

    // Always encode length field as 2-byte varint.
    b.put_varint_with_len(length, 2)?;

    Ok(())
}

pub fn encode_dgram_header(length: u64, b: &mut octets::OctetsMut) -> Result<()> {
    let mut ty: u8 = 0x30;

    // Always encode length
    ty |= 0x01;

    b.put_varint(u64::from(ty))?;

    // Always encode length field as 2-byte varint.
    b.put_varint_with_len(length, 2)?;

    Ok(())
}

fn parse_stream_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame> {
    let first = ty as u8;

    let stream_id = b.get_varint()?;

    let offset = if first & 0x04 != 0 {
        b.get_varint()?
    } else {
        0
    };

    let len = if first & 0x02 != 0 {
        b.get_varint()? as usize
    } else {
        b.cap()
    };

    if offset + len as u64 >= MAX_STREAM_SIZE {
        return Err(Error::InvalidFrame);
    }

    let fin = first & 0x01 != 0;

    let data = b.get_bytes(len)?;
    let data = stream::RangeBuf::from(data.as_ref(), offset, fin);

    Ok(Frame::Stream { stream_id, data })
}

fn parse_datagram_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame> {
    let first = ty as u8;

    let len = if first & 0x01 != 0 {
        b.get_varint()? as usize
    } else {
        b.cap()
    };

    let data = b.get_bytes(len)?;

    Ok(Frame::Datagram {
        data: Vec::from(data.buf()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use networkcoding::vandermonde_lc::decoder::VLCDecoder;

    fn get_decoder() -> Decoder {
        Decoder::VLC(VLCDecoder::new(1300, 8000))
    }

    #[test]
    fn padding() {
        let mut d = [42; 128];

        let frame = Frame::Padding { len: 128 };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 128);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_ok());
    }

    #[test]
    fn ping() {
        let mut d = [42; 128];

        let frame = Frame::Ping;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 1);
        assert_eq!(&d[..wire_len], [0x01_u8]);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_ok());
    }

    #[test]
    fn ack() {
        let mut d = [42; 128];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(4..7);
        ranges.insert(9..12);
        ranges.insert(15..19);
        ranges.insert(3000..5000);

        let frame = Frame::ACK {
            ack_delay: 874_656_534,
            ranges,
            ecn_counts: None,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 17);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_ok());
    }

    #[test]
    fn ack_ecn() {
        let mut d = [42; 128];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(4..7);
        ranges.insert(9..12);
        ranges.insert(15..19);
        ranges.insert(3000..5000);

        let ecn_counts = Some(EcnCounts {
            ect0_count: 100,
            ect1_count: 200,
            ecn_ce_count: 300,
        });

        let frame = Frame::ACK {
            ack_delay: 874_656_534,
            ranges,
            ecn_counts,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 23);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_ok());
    }

    #[test]
    fn reset_stream() {
        let mut d = [42; 128];

        let frame = Frame::ResetStream {
            stream_id: 123_213,
            error_code: 21_123_767,
            final_size: 21_123_767,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 13);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn stop_sending() {
        let mut d = [42; 128];

        let frame = Frame::StopSending {
            stream_id: 123_213,
            error_code: 15_352,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 7);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn crypto() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Crypto {
            data: stream::RangeBuf::from(&data, 1230976, false),
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 19);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_ok());
    }

    #[test]
    fn new_token() {
        let mut d = [42; 128];

        let frame = Frame::NewToken {
            token: Vec::from("this is a token"),
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 17);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn stream() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Stream {
            stream_id: 32,
            data: stream::RangeBuf::from(&data, 1230976, true),
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 20);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn stream_too_big() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Stream {
            stream_id: 32,
            data: stream::RangeBuf::from(&data, MAX_STREAM_SIZE - 11, true),
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 24);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Err(Error::InvalidFrame)
        );
    }

    #[test]
    fn max_data() {
        let mut d = [42; 128];

        let frame = Frame::MaxData { max: 128_318_273 };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn max_stream_data() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamData {
            stream_id: 12_321,
            max: 128_318_273,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 7);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn max_streams_bidi() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamsBidi { max: 128_318_273 };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn max_streams_uni() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamsUni { max: 128_318_273 };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn data_blocked() {
        let mut d = [42; 128];

        let frame = Frame::DataBlocked { limit: 128_318_273 };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn stream_data_blocked() {
        let mut d = [42; 128];

        let frame = Frame::StreamDataBlocked {
            stream_id: 12_321,
            limit: 128_318_273,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 7);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn streams_blocked_bidi() {
        let mut d = [42; 128];

        let frame = Frame::StreamsBlockedBidi { limit: 128_318_273 };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn streams_blocked_uni() {
        let mut d = [42; 128];

        let frame = Frame::StreamsBlockedUni { limit: 128_318_273 };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn new_connection_id() {
        let mut d = [42; 128];

        let frame = Frame::NewConnectionId {
            seq_num: 123_213,
            retire_prior_to: 122_211,
            conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            reset_token: [0x42; 16],
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 41);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn retire_connection_id() {
        let mut d = [42; 128];

        let frame = Frame::RetireConnectionId { seq_num: 123_213 };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn path_challenge() {
        let mut d = [42; 128];

        let frame = Frame::PathChallenge {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 9);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn path_response() {
        let mut d = [42; 128];

        let frame = Frame::PathResponse {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 9);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn connection_close() {
        let mut d = [42; 128];

        let frame = Frame::ConnectionClose {
            error_code: 0xbeef,
            frame_type: 523_423,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 22);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_ok());
    }

    #[test]
    fn application_close() {
        let mut d = [42; 128];

        let frame = Frame::ApplicationClose {
            error_code: 0xbeef,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 18);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn handshake_done() {
        let mut d = [42; 128];

        let frame = Frame::HandshakeDone;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 1);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn datagram() {
        let mut d = [42; 128];

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Datagram { data: data.clone() };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 15);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());

        let frame_data = match &frame {
            Frame::Datagram { data } => data.clone(),

            _ => unreachable!(),
        };

        assert_eq!(frame_data, data);
    }

    #[test]
    fn path_abandon() {
        let mut d = [42; 128];

        let frame = Frame::PathAbandon {
            dcid_seq_num: 421_124,
            error_code: 0xbeef,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 25);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn ack_mp() {
        let mut d = [42; 128];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(4..7);
        ranges.insert(9..12);
        ranges.insert(15..19);
        ranges.insert(3000..5000);

        let frame = Frame::ACKMP {
            space_identifier: 894_994,
            ack_delay: 874_656_534,
            ranges,
            ecn_counts: None,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 24);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn ack_mp_ecn() {
        let mut d = [42; 128];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(4..7);
        ranges.insert(9..12);
        ranges.insert(15..19);
        ranges.insert(3000..5000);

        let ecn_counts = Some(EcnCounts {
            ect0_count: 100,
            ect1_count: 200,
            ecn_ce_count: 300,
        });

        let frame = Frame::ACKMP {
            space_identifier: 894_994,
            ack_delay: 874_656_534,
            ranges,
            ecn_counts,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 30);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame)
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn mc_announce() {
        let mut d = [42; 128];

        let frame = Frame::McAnnounce {
            channel_id: [
                180, 12, 104, 233, 220, 221, 226, 11, 141, 195, 27, 5, 100, 51,
                58, 220,
            ]
            .to_vec(),
            path_type: 0,
            auth_type: 3,
            is_ipv6: 0,
            full_reliability: 1,
            source_ip: [127, 0, 0, 1],
            group_ip: [239, 239, 239, 35],
            udp_port: 8889,
            expiration_timer: 350,
            public_key: vec![64, 33, 53, 127],
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 46);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn mc_state() {
        let mut d = [42; 128];

        let frame = Frame::McState {
            channel_id: [0xff, 0xdd, 0xee, 0xaa, 0xbb, 0x33, 0x66].to_vec(),
            action: 1,
            action_data: 0xff,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 13);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn mc_key() {
        let mut d = [41; 400];

        let stream_states = vec![
            FcStreamState::new(1, 100),
            FcStreamState::new(100, 0),
            FcStreamState::new(46929, 4567),
            FcStreamState::new(111111, 1),
        ];

        let frame = Frame::McKey {
            channel_id: [0xff, 0xdd, 0xee, 0xaa, 0xbb, 0x33, 0x66].to_vec(),
            key: vec![1; 32],
            algo: Algorithm::AES128_GCM,
            first_pn: 0xffffff,
            client_id: 0xabcd,
            stream_states,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 70);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn mc_expire() {
        let mut d = [41; 400];

        let frame = Frame::McExpire {
            channel_id: [0xff, 0xdd, 0xee, 0xaa, 0xbb, 0x33, 0x66].to_vec(),
            expiration_type: 7,
            pkt_num: Some(5678),
            fec_metadata: Some(91011),
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 17);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn mc_auth() {
        let mut d = [41; 400];

        let frame = Frame::McAuth {
            channel_id: [0xff, 0xdd, 0xee, 0xaa, 0xbb, 0x33, 0x66].to_vec(),
            pn: 0xff383c,
            signatures: vec![
                McSymSignature {
                    mc_client_id: 1,
                    sign: vec![0xff, 0xdd, 0xee],
                },
                McSymSignature {
                    mc_client_id: 3,
                    sign: vec![0xaf, 0xdd, 0x32, 43],
                },
            ],
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 26);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn mc_asym() {
        let mut d = [41; 400];

        let frame = Frame::McAsym {
            signature: vec![54, 244, 12, 65, 34],
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 8);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }

    #[test]
    fn mc_nack() {
        let mut d = [41; 400];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(0..4);
        ranges.insert(100..400);

        let frame = Frame::McNack {
            channel_id: vec![0xff, 0xee, 0x45],
            last_pn: 0xff4433,
            nb_repair_needed: 455,
            ranges,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 21);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short, &get_decoder()),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::Initial, &get_decoder())
                .is_err()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(
            Frame::from_bytes(&mut b, packet::Type::ZeroRTT, &get_decoder())
                .is_ok()
        );

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            &get_decoder()
        )
        .is_err());
    }
}
