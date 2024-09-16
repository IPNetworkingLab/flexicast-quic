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
    /// `Error::Multicast(McError::McInvalidAuth)` is returned.
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
    pub fn new(app: McApp, output: &str) -> Self {
        match app {
            McApp::Tixeo => AppDataClient::Tixeo(TixeoClient::new(output)),
            McApp::File => AppDataClient::File(FileClient::new(output)),
        }
    }

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
            AppDataClient::File(f) => f.on_stream_complete(buf, stream_id),
        }
    }

    #[inline]
    pub fn on_finish(&mut self) {
        match self {
            AppDataClient::Tixeo(t) => t.on_finish(),
            AppDataClient::File(f) => f.on_finish(),
        }
    }

    #[inline]
    pub fn leave_on_mc_timeout(&self) -> bool {
        match self {
            AppDataClient::Tixeo(t) => t.leave_on_mc_timeout(),
            AppDataClient::File(f) => f.leave_on_mc_timeout(),
        }
    }
}

pub enum AppDataServer {
    Tixeo(TixeoServer),

    File(FileServer),
}

impl AppDataServer {
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app: McApp, filename: Option<&str>, nb_frames: Option<u64>, delay: u64,
        wait: bool, result_quic: &str, result_wire: &str, chunk_size: usize,
        delay_2: u64,
    ) -> Self {
        match app {
            McApp::Tixeo => Self::Tixeo(TixeoServer::new(
                filename,
                nb_frames,
                delay,
                wait,
                result_quic,
                result_wire,
            )),
            McApp::File => Self::File(
                FileServer::new(
                    filename,
                    nb_frames,
                    wait,
                    result_quic,
                    result_wire,
                    chunk_size,
                    delay,
                    delay_2,
                )
                .unwrap(),
            ),
        }
    }

    #[inline]
    pub fn on_init(&mut self) {
        match self {
            Self::Tixeo(_) => (),
            Self::File(_) => (),
        }
    }

    #[inline]
    pub fn next_timeout(&mut self) -> Option<time::Duration> {
        match self {
            Self::Tixeo(t) => t.next_timeout(),
            Self::File(f) => f.next_timeout(),
        }
    }

    #[inline]
    pub fn app_has_started(&self) -> bool {
        match self {
            Self::Tixeo(t) => t.app_has_started(),
            Self::File(f) => f.app_has_started(),
        }
    }

    #[inline]
    pub fn app_has_finished(&self) -> bool {
        match self {
            Self::Tixeo(t) => t.app_has_finished(),
            Self::File(f) => f.app_has_finished(),
        }
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        match self {
            Self::Tixeo(t) => t.is_active(),
            Self::File(f) => f.is_active(),
        }
    }

    #[inline]
    pub fn start_content_delivery(&mut self) {
        match self {
            Self::Tixeo(t) => t.start_content_delivery(),
            Self::File(f) => f.start_content_delivery(),
        }
    }

    #[inline]
    pub fn on_sent_to_quic(&mut self) {
        match self {
            Self::Tixeo(t) => t.on_sent_to_quic(),
            Self::File(f) => f.on_sent_to_quic(),
        }
    }

    #[inline]
    pub fn on_sent_to_wire(&mut self) {
        match self {
            Self::Tixeo(t) => t.on_sent_to_wire(),
            Self::File(f) => f.on_sent_to_wire(),
        }
    }

    #[inline]
    pub fn on_finish(&self) {
        match self {
            Self::Tixeo(t) => t.on_finish(),
            Self::File(f) => f.on_finish(),
        }
    }

    #[inline]
    pub fn get_app_data(&self) -> (u64, Vec<u8>) {
        match self {
            Self::Tixeo(t) => t.get_app_data(),
            Self::File(f) => f.get_app_data(),
        }
    }

    #[inline]
    pub fn gen_nxt_app_data(&mut self) {
        match self {
            Self::Tixeo(t) => t.gen_nxt_app_data(),
            Self::File(f) => f.gen_nxt_app_data(),
        }
    }

    #[inline]
    pub fn should_send_app_data(&mut self) -> bool {
        match self {
            Self::Tixeo(t) => t.should_send_app_data(),
            Self::File(f) => f.should_send_app_data(),
        }
    }

    #[inline]
    pub fn stream_written(&mut self, v: usize) {
        match self {
            Self::Tixeo(t) => t.stream_written(v),
            Self::File(f) => f.stream_written(v),
        }
    }

    #[inline]
    pub fn on_expiring(&mut self) {
        match self {
            Self::Tixeo(_) => (),
            Self::File(f) => f.on_expiring(),
        }
    }

    #[inline]
    pub fn has_sent_some_data(&self) -> bool {
        match self {
            Self::Tixeo(t) => t.has_sent_some_data(),
            Self::File(f) => f.has_sent_some_data(),
        }
    }

    #[inline]
    pub fn get_app_full_data(&self) -> (u64, Vec<u8>) {
        match self {
            Self::File(f) => f.get_app_full_data(),
            Self::Tixeo(t) => t.get_app_full_data(),
        }
    }
}

pub mod file_transfer;
pub mod tixeo;
pub mod http3;
pub mod quic_stream;
pub mod rtp;
pub mod control;