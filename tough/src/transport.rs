use std::io::Read;
use url::Url;

pub trait Transport {
    type Stream: Read;
    type Error: std::error::Error + Send + Sync + 'static;

    fn fetch(&self, url: Url) -> Result<Self::Stream, Self::Error>;
}

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
