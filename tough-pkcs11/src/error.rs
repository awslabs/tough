use aws_lc_rs::error::KeyRejected;
use pk11_uri_parser::PK11URIError;
use snafu::{Backtrace, Snafu};

/// Alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for this library.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Error {
    #[snafu(display("failed to load module"))]
    LoadModule { source: cryptoki::error::Error },

    #[snafu(display("failed to initialise module"))]
    InitModule { source: cryptoki::error::Error },

    #[snafu(display("failed to get slot infos"))]
    GetSlotInfo { source: cryptoki::error::Error },

    #[snafu(display("failed to get key object"))]
    GetKey { source: cryptoki::error::Error },

    // TODO: add token info
    #[snafu(display("token not found"))]
    TokenNotFound,

    #[snafu(display("key not found"))]
    KeyNotFound,

    #[snafu(display("failed to open RO session"))]
    OpenRoSession { source: cryptoki::error::Error },

    #[snafu(display("login failed"))]
    LoginFailed { source: cryptoki::error::Error },

    #[snafu(display("failed to read public key"))]
    GetPubkey { source: cryptoki::error::Error },

    #[snafu(display("failed to parse public key"))]
    ParsePubkey { source: KeyRejected },

    #[snafu(display("token return unexpected response"))]
    UnexpectedResponse,

    #[snafu(display("unsupported key type"))]
    UnsupportedKeyType,

    #[snafu(display("failed to sign"))]
    SigningFailed { source: cryptoki::error::Error },

    #[snafu(display("returned signature is invalid"))]
    InvalidSignature,

    #[snafu(display("failed to join spawn_blocking task: {source}"))]
    JoinSpawnBlockingTask {
        source: tokio::task::JoinError,
        backtrace: Backtrace,
    },
}

/// The error type for URI parsing.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ParseUriError {
    #[snafu(display("failed to parse URI: {source}"))]
    Pk11UriError { source: PK11URIError },

    #[snafu(display("failed to decode field {field:?}: {cause}"))]
    DecodeField { cause: String, field: &'static str },

    #[snafu(display("pkcs11 URI requires {what}"))]
    Requires { what: &'static str },

    #[snafu(display("pkcs11 URI requires one of {oneof}"))]
    Conflict { oneof: &'static str },

    #[snafu(display("failed to read PIN from {path}: {source}"))]
    PinReadingFailed {
        source: std::io::Error,
        path: String,
    },
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
#[allow(missing_docs)]
pub struct WritingUnsupportedError;
