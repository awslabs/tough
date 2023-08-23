// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use snafu::{Backtrace, Snafu};
use std::error::Error as _;

pub type Result<T> = std::result::Result<T, Error>;

/// The error type for this library.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Unable to parse keypair: {}", source))]
    KeyPairParse {
        #[snafu(source(from(tough::error::Error, Box::new)))]
        source: Box<tough::error::Error>,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to create tokio runtime: {}", source))]
    RuntimeCreation {
        source: std::io::Error,
        backtrace: Backtrace,
    },
    /// The library failed to join 'tokio Runtime'.
    #[snafu(display("Unable to join tokio thread used to offload async workloads"))]
    ThreadJoin,

    #[snafu(display(
        "Failed to get aws-ssm://{}{}: {}",
        profile.as_deref().unwrap_or(""),
        parameter_name,
        source.source().map_or("unknown".to_string(), std::string::ToString::to_string),
    ))]
    SsmGetParameter {
        profile: Option<String>,
        parameter_name: String,
        source:
            aws_sdk_ssm::error::SdkError<aws_sdk_ssm::operation::get_parameter::GetParameterError>,
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
        source.source().map_or("unknown".to_string(), std::string::ToString::to_string),
    ))]
    SsmPutParameter {
        profile: Option<String>,
        parameter_name: String,
        source:
            aws_sdk_ssm::error::SdkError<aws_sdk_ssm::operation::put_parameter::PutParameterError>,
        backtrace: Backtrace,
    },
}
