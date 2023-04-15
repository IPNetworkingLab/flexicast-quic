use std::str::FromStr;

use self::file_transfer::FileClient;
use self::tixeo::TixeoClient;

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
    pub fn on_init(&mut self) {
        match self {
            AppDataClient::Tixeo(_) => (),
            AppDataClient::File(_) => (),
        }
    }

    pub fn on_stream_complete(&mut self, buf: &[u8], stream_id: u64) {
        match self {
            AppDataClient::Tixeo(t) => t.on_stream_complete(buf, stream_id),
            AppDataClient::File(_f) => (),
        }
    }

    pub fn on_finish(&mut self) {
        match self {
            AppDataClient::Tixeo(t) => t.on_finish(),
            AppDataClient::File(_f) => (),
        }
    }
}

pub mod file_transfer;
pub mod tixeo;
