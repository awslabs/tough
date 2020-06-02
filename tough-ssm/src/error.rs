// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use snafu::{Backtrace, Snafu};

pub type Result<T> = std::result::Result<T, Error>;

/// The error type for this library.
#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum Error {
    #[snafu(display("Unable to parse keypair: {}", source))]
    KeyPairParse {
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Error creating AWS credentials provider: {}", source))]
    RusotoCreds {
        source: rusoto_credential::CredentialsError,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to determine region from profile '{}': {}", profile, source))]
    RusotoRegionFromProfile {
        profile: String,
        source: rusoto_credential::CredentialsError,
        backtrace: Backtrace,
    },

    #[snafu(display("Unknown AWS region \"{}\": {}", region, source))]
    RusotoRegion {
        region: String,
        source: rusoto_core::region::ParseRegionError,
        backtrace: Backtrace,
    },

    #[snafu(display("Error creating AWS request dispatcher: {}", source))]
    RusotoTls {
        source: rusoto_core::request::TlsError,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to create tokio runtime: {}", source))]
    RuntimeCreation {
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display(
        "Failed to get aws-ssm://{}{}: {}",
        profile.as_deref().unwrap_or(""),
        parameter_name,
        source,
    ))]
    SsmGetParameter {
        profile: Option<String>,
        parameter_name: String,
        source: rusoto_core::RusotoError<rusoto_ssm::GetParameterError>,
        backtrace: Backtrace,
    },

    #[snafu(display(
        "Missing field in SSM response for parameter '{}': {}",
        parameter_name,
        field
    ))]
    SsmMissingField {
        parameter_name: String,
        field: &'static str,
        backtrace: Backtrace,
    },

    #[snafu(display(
        "Failed to put aws-ssm://{}{}: {}",
        profile.as_deref().unwrap_or(""),
        parameter_name,
        source,
    ))]
    SsmPutParameter {
        profile: Option<String>,
        parameter_name: String,
        source: rusoto_core::RusotoError<rusoto_ssm::PutParameterError>,
        backtrace: Backtrace,
    },
}
