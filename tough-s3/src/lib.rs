//! tough-s3 implements the `Transport` trait for AWS S3.
//!
//! This allows TUF repositories to be fetched from S3 buckets using s3:// URLs.

#![forbid(missing_debug_implementations, missing_copy_implementations)]
#![deny(rust_2018_idioms)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

/// Error types for tough-s3
pub mod error;

use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use bytes::Bytes;
use futures::stream::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use url::Url;

/// Implements the [`Transport`] trait for AWS S3 via [`S3Transport`]
#[derive(Clone, Debug)]
pub struct S3Transport {
    client: S3Client,
}

impl S3Transport {
    /// Create a new [`S3Transport`] with the default AWS configuration
    pub async fn new() -> Self {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let client = S3Client::new(&config);
        Self { client }
    }

    /// Create a new [`S3Transport`] with a custom S3 client
    pub fn new_with_client(client: S3Client) -> Self {
        Self { client }
    }

    /// Create a new [`S3Transport`] with a specific AWS region
    pub async fn new_with_region(region: &str) -> Self {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;
        Self {
            client: S3Client::new(&config),
        }
    }

    /// Parse an s3:// URL into bucket and key components
    fn parse_s3_url(url: &Url) -> Result<(String, String), error::Error> {
        if url.scheme() != "s3" {
            return Err(error::Error::InvalidS3Url {
                url: url.to_string(),
            });
        }

        let bucket = url
            .host_str()
            .ok_or_else(|| error::Error::InvalidS3Url {
                url: url.to_string(),
            })?
            .to_string();

        let key = url.path().trim_start_matches('/').to_string();

        if key.is_empty() {
            return Err(error::Error::InvalidS3Url {
                url: url.to_string(),
            });
        }

        Ok((bucket, key))
    }
}

#[async_trait]
impl Transport for S3Transport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        if url.scheme() != "s3" {
            return Err(TransportError::new(
                TransportErrorKind::UnsupportedUrlScheme,
                url,
            ));
        }

        let (bucket, key) = S3Transport::parse_s3_url(&url).map_err(|e| {
            TransportError::new_with_cause(TransportErrorKind::Other, url.clone(), e)
        })?;

        let result = self
            .client
            .get_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await;

        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let kind = if is_not_found(&e) {
                    TransportErrorKind::FileNotFound
                } else {
                    TransportErrorKind::Other
                };
                return Err(TransportError::new_with_cause(kind, url, Box::new(e)));
            }
        };

        let byte_stream = response.body;
        let stream = ByteStreamAdapter {
            inner: byte_stream,
            url: url.clone(),
        };

        Ok(Box::pin(stream))
    }
}

/// Check if an S3 error indicates the object was not found
fn is_not_found(
    err: &aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>,
) -> bool {
    matches!(
        err,
        aws_sdk_s3::error::SdkError::ServiceError(err)
            if err.err().is_no_such_key()
    )
}

/// Adapter to convert AWS SDK [`ByteStream`] to tough [`TransportStream`]
struct ByteStreamAdapter {
    inner: ByteStream,
    url: Url,
}

impl Stream for ByteStreamAdapter {
    type Item = Result<Bytes, TransportError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let inner = Pin::new(&mut self.inner);
        match inner.poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(bytes))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                self.url.clone(),
                err,
            )))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_s3_url_valid() {
        let url = Url::from_str("s3://my-bucket/path/to/key").unwrap();
        let (bucket, key) = S3Transport::parse_s3_url(&url).unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "path/to/key");
    }

    #[test]
    fn parse_s3_url_single_key() {
        let url = Url::from_str("s3://bucket/file.txt").unwrap();
        let (bucket, key) = S3Transport::parse_s3_url(&url).unwrap();
        assert_eq!(bucket, "bucket");
        assert_eq!(key, "file.txt");
    }

    #[test]
    fn parse_s3_url_invalid_scheme() {
        let url = Url::from_str("http://bucket/key").unwrap();
        assert!(S3Transport::parse_s3_url(&url).is_err());
    }

    #[test]
    fn parse_s3_url_missing_key() {
        let url = Url::from_str("s3://bucket/").unwrap();
        assert!(S3Transport::parse_s3_url(&url).is_err());
    }

    #[test]
    fn parse_s3_url_no_path() {
        let url = Url::from_str("s3://bucket").unwrap();
        assert!(S3Transport::parse_s3_url(&url).is_err());
    }
}
