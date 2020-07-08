use std::io::Read;
use url::Url;

/// A trait to abstract over the method/protocol by which files are obtained.
pub trait Transport {
    /// The type of `Read` object that the `fetch` function will return.
    type Stream: Read;

    /// The type of error that the `fetch` function will return.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Opens a `Read` object for the file specified by `url`.
    fn fetch(&self, url: Url) -> Result<Self::Stream, Self::Error>;
}

/// Provides a `Transport` for local files.
#[derive(Debug, Clone, Copy)]
pub struct FilesystemTransport;

impl Transport for FilesystemTransport {
    type Stream = std::fs::File;
    type Error = std::io::Error;

    fn fetch(&self, url: Url) -> Result<Self::Stream, Self::Error> {
        use std::io::{Error, ErrorKind};

        if url.scheme() == "file" {
            std::fs::File::open(url.path())
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!("unexpected URL scheme: {}", url.scheme()),
            ))
        }
    }
}
