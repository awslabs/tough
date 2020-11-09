// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contains the error type for this library.

#![allow(clippy::default_trait_access)]

use snafu::{Backtrace, Snafu};

/// Alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for this library.
#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Error {
    /// The library failed to authenticate Aws account.
    #[snafu(display("Error creating AWS credentials provider: {}", source))]
    RusotoCreds {
        source: rusoto_credential::CredentialsError,
        backtrace: Backtrace,
    },

    /// The library failed to get the region for the given profile.
    #[snafu(display("Unable to determine region from profile '{}': {}", profile, source))]
    RusotoRegionFromProfile {
        profile: String,
        source: rusoto_credential::CredentialsError,
        backtrace: Backtrace,
    },

    /// The library failed to identify the region obtained from the given profile.
    #[snafu(display("Unknown AWS region '{}': {}", region, source))]
    RusotoRegion {
        region: String,
        source: rusoto_core::region::ParseRegionError,
        backtrace: Backtrace,
    },

    /// The library failed to instantiate 'HttpClient'.
    #[snafu(display("Error creating AWS request dispatcher: {}", source))]
    RusotoTls {
        source: rusoto_core::request::TlsError,
        backtrace: Backtrace,
    },

    /// The library failed to instantiate 'tokio Runtime'.
    #[snafu(display("Unable to create tokio runtime: {}", source))]
    RuntimeCreation {
        source: std::io::Error,
        backtrace: Backtrace,
    },

    /// The library failed to get public key from AWS KMS
    #[snafu(display(
    "Failed to get public key for aws-kms://{}/{} : {}",
    profile.as_deref().unwrap_or(""),
    key_id,
    source,
    ))]
    KmsGetPublicKey {
        profile: Option<String>,
        key_id: String,
        source: rusoto_core::RusotoError<rusoto_kms::GetPublicKeyError>,
        backtrace: Backtrace,
    },

    /// Empty public key was returned by AWS KMS
    #[snafu(display("Public key does not exist"))]
    PublicKeyNone,

    /// Public key could not be parsed as an SPKI document
    #[snafu(display("Failed to parse public key: {}", source))]
    PublicKeyParse { source: tough::schema::Error },

    /// The library failed to get the message signature from AWS KMS
    #[snafu(display("Error while signing message for aws-kms://{}/{} : {}", profile.as_deref().unwrap_or(""), key_id, source))]
    KmsSignMessage {
        key_id: String,
        profile: Option<String>,
        source: rusoto_core::RusotoError<rusoto_kms::SignError>,
        backtrace: Backtrace,
    },

    /// Empty signature was returned by AWS KMS
    #[snafu(display("Empty signature returned by AWS KMS"))]
    SignatureNotFound,

    /// Provided signing algorithm is not valid
    #[snafu(display("Please provide valid signing algorithm"))]
    ValidSignAlgorithm,

    /// Supported signing algorithm list is missing for CMK in AWS KMS
    #[snafu(display(
        "Found public key from AWS KMS, but list of supported signing algorithm is missing"
    ))]
    MissingSignAlgorithm,

    #[snafu(display(
        "Found public key from AWS KMS, but the CustomerMasterKeySpec field is missing"
    ))]
    MissingCustomerMasterKeySpec,

    #[snafu(display("Unable to parse the CustomerMasterKeySpec: {}", spec))]
    BadCustomerMasterKeySpec { spec: String },

    #[snafu(display("Unable to parse the integer in CustomerMasterKeySpec: {}", spec))]
    BadCustomerMasterKeySpecInt {
        spec: String,
        source: std::num::ParseIntError,
    },

    #[snafu(display(
        "Signature is too long, modulus_size_bytes: {}, signature_size_bytes: {}",
        modulus_size_bytes,
        signature_size_bytes
    ))]
    SignatureTooLong {
        modulus_size_bytes: usize,
        signature_size_bytes: usize,
    },

    #[snafu(display(
        "The modulus bit size is {}, but should be divisible by 8. CustomerMasterKeySpec is {}.",
        modulus_size_bits,
        spec
    ))]
    UnsupportedModulusSize {
        modulus_size_bits: usize,
        spec: String,
    },
}
