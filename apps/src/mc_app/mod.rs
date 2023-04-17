use std::str::FromStr;
use std::time;

use self::file_transfer::FileClient;
use self::file_transfer::FileServer;
use self::tixeo::TixeoClient;
use self::tixeo::TixeoServer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppError {
    /// Parsing app name.
    AppName,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

type Result<T> = std::result::Result<T, AppError>;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum McApp {
    Tixeo,

    File,
}

impl FromStr for McApp {
    type Err = AppError;

    /// Converts a string to `McAuthType`.
    ///
    /// If `name` is not valid,
    /// `Error::Multicast(MulticastError::McInvalidAuth)` is returned.
    fn from_str(name: &str) -> Result<Self> {
        match name {
            "tixeo" => Ok(McApp::Tixeo),
            "file" => Ok(McApp::File),
            _ => Err(AppError::AppName),
        }
    }
}

pub enum AppDataClient {
    Tixeo(TixeoClient),

    File(FileClient),
}

impl AppDataClient {
    #[inline]
    pub fn on_init(&mut self) {
        match self {
            AppDataClient::Tixeo(_) => (),
            AppDataClient::File(_) => (),
        }
    }

    #[inline]
    pub fn on_stream_complete(&mut self, buf: &[u8], stream_id: u64) {
        match self {
            AppDataClient::Tixeo(t) => t.on_stream_complete(buf, stream_id),
            AppDataClient::File(_f) => (),
        }
    }

    #[inline]
    pub fn on_finish(&mut self) {
        match self {
            AppDataClient::Tixeo(t) => t.on_finish(),
            AppDataClient::File(_f) => (),
        }
    }
}

pub enum AppDataServer {
    Tixeo(TixeoServer),

    File(FileServer),
}

impl AppDataServer {
    #[inline]
    pub fn on_init(&mut self) {
        match self {
            Self::Tixeo(_) => (),
            Self::File(_) => todo!(),
        }
    }

    #[inline]
    pub fn next_timeout(&self) -> Option<time::Duration> {
        match self {
            Self::Tixeo(t) => t.next_timeout(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn app_has_started(&self) -> bool {
        match self {
            Self::Tixeo(t) => t.app_has_started(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn app_has_finished(&self) -> bool {
        match self {
            Self::Tixeo(t) => t.app_has_finished(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        match self {
            Self::Tixeo(t) => t.is_active(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn start_content_delivery(&mut self) {
        match self {
            Self::Tixeo(t) => t.start_content_delivery(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn on_sent_to_quic(&mut self) {
        match self {
            Self::Tixeo(t) => t.on_sent_to_quic(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn on_sent_to_wire(&mut self) {
        match self {
            Self::Tixeo(t) => t.on_sent_to_wire(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn on_finish(&self) {
        match self {
            Self::Tixeo(t) => t.on_finish(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn get_app_data(&self) -> (u64, Vec<u8>) {
        match self {
            Self::Tixeo(t) => t.get_app_data(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn gen_nxt_app_data(&mut self) {
        match self {
            Self::Tixeo(t) => t.gen_nxt_app_data(),
            _ => todo!(),
        }
    }

    #[inline]
    pub fn should_send_app_data(&self) -> bool {
        match self {
            Self::Tixeo(t) => t.should_send_app_data(),
            _ => todo!(),
        }
    }
}

pub mod file_transfer;
pub mod tixeo;
