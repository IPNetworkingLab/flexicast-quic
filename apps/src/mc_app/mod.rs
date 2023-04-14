use std::str::FromStr;

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

pub mod tixeo;
pub mod file_transfer;