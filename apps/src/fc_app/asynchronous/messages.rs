use std::collections::HashSet;
use std::sync::Arc;

use quiche::flexicast::ack::FcDelegatedStream;
use quiche::flexicast::ack::McStreamOff;
use quiche::flexicast::ack::OpenRangeSet;
use quiche::flexicast::control::OpenSent;
use quiche::RecvInfo;
use quiche::SendInfo;
use tokio::sync::mpsc;

use super::aggregator::FcAggregatedMsg;

#[derive(Debug)]
/// Messages sent to the controller.
pub enum MsgFcCtl {
    /// Stop RTP.
    /// Receivers listening to this flexicast channel can close their
    /// communication.
    CloseRtp(u64),

    /// New connection from a client.
    /// Indicate the channel to communicate with it and its client ID.
    NewClient((u64, mpsc::Sender<MsgRecv>)),

    /// The receiver joins a new flexicast flow.
    /// The first value is the client ID.
    /// The second value is the index of the flexicast flow.
    /// The third value is the current flow control limits of the receiver.
    /// The fourth value indicates the maximum received packet number on the
    /// flexicast flow before the last join, in case this was a unicast
    /// fallback.
    Join((u64, u64, Option<FcAggregatedMsg>, Option<u64>)),

    /// The receiver changes its flexicast flow.
    /// The first value is the client ID.
    /// The second value is the index of the old flexicast flow (to leave).
    /// The third value is the index of the new flexicast flow (to join).
    Change((u64, u64, u64)),

    /// New highest and lowest packet number sent on the flexicast flow.
    /// The controller informs all clients listening to this source.
    /// The first value is the index of the flexicast flow.
    /// The second value is the expired packet.
    NewHighestPn((u64, u64, u64)),

    /// The receiver acknowledges packets received on the flexicast flow.
    /// It also acknowledges stream pieces that have been delegated through the
    /// unicast path.
    ///
    /// The last value indicates the potentially recovered source symbols.
    /// This allows to avoid retransmission if the packet was recovered through
    /// Forward Erasure Correction.
    AckData(
        (
            u64,
            u64,
            Option<OpenRangeSet>,
            Option<McStreamOff>,
            Option<OpenRangeSet>,
        ),
    ),

    /// The flexicast source forwards to the controller the packet it just sent
    /// on the flexicast flow.
    Sent((u64, Arc<Vec<OpenSent>>)),

    /// The flexicast source forwards to the controller the delegated streams.
    /// These are the STREAM frames that have been lost, considering all
    /// receivers (using their ACK). The controller will handle the dispatch
    /// of the unicast retransmission to simplify the work of the flexicast
    /// source.
    ///
    /// The last value indicates either this delegation is issued
    /// by an early retransmit query from the controller.
    DelegateStreams((u64, Arc<Vec<FcDelegatedStream>>, bool)),

    /// The new receiver is ready to receive content on the flexicast path.
    RecvReady(u64),

    /// New RTP frame is received and must be sent via the unicast path.
    /// This message MUST only been used for receivers that are not part of a
    /// flexicast flow, included when flexicast is disabled.
    /// The controller is in charge to split the traffic towards the corrected
    /// receivers, i.e., receivers that are not part of a flexicast flow.
    /// The third value indicates whether the stream is finished.
    /// The last value indicates the lowest offset of the stream.
    StreamData((Arc<Vec<u8>>, u64, bool, u64)),

    /// The receiver falls-back on unicast and must receive content through its
    /// unicast path.
    RecvUcFallBack((u64, u64)),

    /// The unicast path asks for per-unicast retransmission.
    /// First value is the flexicast flow ID.
    /// Second value is the receiver ID.
    /// Third value is the vector of lost packet numbers.
    ///
    /// Used for Flexicast NACK extension.
    PerUcRetransmission((u64, u64, HashSet<u64>)),

    /// The flexicast flow source sends the per-unicast path retransmission to
    /// the controller.
    PerUcRetransmitted((u64, u64, Arc<Vec<FcDelegatedStream>>)),

    /// New aggregated control data from this receiver.
    AggregatedInfo((u64, u64, FcAggregatedMsg)),
}

/// Messages sent to the receiver.
pub enum MsgRecv {
    /// Stop RTP.
    CloseRtp,

    /// Highest packet number sent on the flexicat flow, and lowest packet
    /// number still in the sending queue.
    NewHighestPn((u64, u64, u64)),

    /// Packets sent on the flexicast flow that will be part of the state.
    Sent((u64, Arc<Vec<OpenSent>>)),

    /// Identical semantic as [`MsgFcCtl::DelegateStreams`].
    /// The last field contains boolean values to indicate whether the unicast
    /// path must actually delegate the stream piece. This is an
    /// optimisation to avoid modifying the [`FcDelegatedStream`] structure.
    /// This last value must be "zip"-iterated with the second.
    DelegateStreams((u64, Arc<Vec<FcDelegatedStream>>, Vec<bool>)),

    /// New packet from this receiver for the unicast instance to handle.
    NewPkt((Vec<u8>, RecvInfo)),

    /// The flexicast source is responsible to read application data.
    /// It sends the payload to the controller to allow receivers to fall-back
    /// on unicast / disable flexicast and still receive the content.
    /// The last value indicates whether the stream is finished.
    StreamData((Arc<Vec<u8>>, u64, Option<u64>, bool)),
}

/// Messages sent to the flexicast source.
pub enum MsgFcSource {
    /// Packet numbers acknowledged by all clients listening to the flexicast
    /// flow.
    AckPn(OpenRangeSet),

    /// Stream pieces that were delegated and now received by all clients that
    /// should receive it.
    AckStreamPieces(McStreamOff),

    /// All intended receivers are ready to receive content.
    Ready,

    /// Asks for a full retransmission.
    ///
    /// This call may be triggered if a receiver falls-back on unicast.
    /// At the same time, will retransmit "lost" frames to all other receivers.
    AskStreamPieces,

    /// The unicast path asks for per-unicast retransmission.
    /// First value is the receiver ID. It is not directly used by the flexicast
    /// flow source, but it will give back the information to the controller.
    /// Third value is the vector of lost packet numbers.
    ///
    /// Used for Flexicast NACK extension.
    PerUcRetransmission((u64, HashSet<u64>)),

    /// The controller sends aggregated control information to the flexicast
    /// flow.
    AggregatedInfo(FcAggregatedMsg),
}

/// Messages sent to the main thread.
pub enum MsgMain {
    /// A receiver notifies that a new connection ID is mapped to its
    /// connection.
    NewCID((u64, Vec<u8>)),

    /// A receiver notifies that a new packet must be sent on the wire.
    SendPkt((Vec<u8>, SendInfo)),

    /// The flexicast flow stopped.
    FcFlowStop(u64),
}
