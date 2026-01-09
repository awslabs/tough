//! Error types for the tough-s3 crate.
//!
//! This module defines error types that can occur when using S3 as a TUF transport.

use snafu::Snafu;

/// Result type for tough-s3 operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when using S3 as a transport
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    /// Invalid S3 URL format
    #[snafu(display("Invalid S3 URL: {}", url))]
    InvalidS3Url {
        /// The invalid URL
        url: String,
    },

    /// Failed to get object from S3
    #[snafu(display("Failed to get S3 object s3://{}/{}: {}", bucket, key, source))]
    S3GetObject {
        /// S3 bucket name
        bucket: String,
        /// S3 object key
        key: String,
        /// Underlying SDK error
        source: Box<aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>>,
    },

    /// Failed to read from S3 byte stream
    #[snafu(display("Failed to read S3 byte stream: {}", source))]
    S3ByteStream {
        /// Underlying byte stream error
        source: aws_sdk_s3::primitives::ByteStreamError,
    },
}
