//! This module defines the structures to handle the congestion control
//! algorithm on the flexicast flow.

use std::str::FromStr;

use crate::CongestionControlAlgorithm;

#[derive(Clone, PartialEq, Eq, Debug, Copy)]
/// Enumeration for the flexicast flow congestion window.
pub enum FcFlowCwnd {
    /// Use the specified congestion control algorithm.
    CCA(CongestionControlAlgorithm),

    /// Unlimited congestion window.
    Unlimited,

    /// Congestion window limited to the specified value.
    Limited(u64),
}

impl FromStr for FcFlowCwnd {
    type Err = crate::Error;

    /// Converts a string to `FcFlowCwnd`.
    ///
    /// If `name` is not valid, `Error::CongestionControl` is returned.
    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name {
            "reno" => Ok(FcFlowCwnd::CCA(CongestionControlAlgorithm::Reno)),
            "cubic" => Ok(FcFlowCwnd::CCA(CongestionControlAlgorithm::CUBIC)),
            "bbr" => Ok(FcFlowCwnd::CCA(CongestionControlAlgorithm::BBR)),
            "bbr2" => Ok(FcFlowCwnd::CCA(CongestionControlAlgorithm::BBR2)),
            "disabled" => Ok(FcFlowCwnd::Unlimited),
            s => match s.parse::<u64>() {
                Ok(v) => Ok(FcFlowCwnd::Limited(v)),
                Err(_) => Err(crate::Error::CongestionControl),
            },
        }
    }
}
