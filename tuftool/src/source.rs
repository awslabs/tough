// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::doc_markdown)]
//! Private keys are generally provided as paths, but may sometimes be provided as a URL. For
//! example, when one of the Rusoto features is enabled, you can use an aws-ssm:// special URL
//! to refer to a key accessible in SSM. (See below for more format examples)
//!
//! This module parses a key source command line parameter as a URL, relative to `file://$PWD`,
//! then matches the URL scheme against ones we understand.
//!
//! Currently supported key sources are local files and AWS SSM.
//!
//! Examples of currently supported formats:
//!
//! Local files may be specified using a path or "file:///" prefixed path:
//! "./a/key/file/here"
//! "file:///./a/key/file/here" (notice the 3 slashes after the colon)
//!
//! Keys stored in AWS SSM use a special format:
//! "aws-ssm://<aws profile>/key/path/in/SSM?kms-key-id=12345"
//!
//! "kms-key-id" is an optional parameter you can provide. It is only used for writing
//! a key back to SSM. If it is not provided, the default key associated with your AWS
//! account is used.
//!
//! For example, using a profile "foo" and a key located at "a/key"
//! "aws-ssm://foo/a/key"
//!
//! Adding a specific KMS key:
//! "aws-ssm://foo/a/key?kms-key-id=1234567890"
//!
//! You may also skip the profile bit and just use your local environment's default profile:
//! "aws-ssm:///a/key" (notice the 3 slashes after the colon)

use crate::error::{self, Result};
use snafu::ResultExt;
use std::path::PathBuf;
use tough::key_source::{KeySource, LocalKeySource};
use tough_kms::KmsKeySource;
use tough_ssm::SsmKeySource;
use url::Url;

/// Parses a user-specified source of signing keys.
/// Sources are passed to `tuftool` as arguments in string format:
/// "file:///..." or "./a/path/here" or "aws-ssm://...". See above
/// doc comment for more info on the appropriate format.
///
/// Users are welcome to add their own sources of keys by implementing
/// the `KeySource` trait in the `tough` library. A user can then add
/// to this parser to support them in `tuftool`.
pub(crate) fn parse_key_source(input: &str) -> Result<Box<dyn KeySource>> {
    let pwd_url = Url::from_directory_path(std::env::current_dir().context(error::CurrentDir)?)
        .expect("expected current directory to be absolute");
    let url = Url::options()
        .base_url(Some(&pwd_url))
        .parse(input)
        .context(error::UrlParse { url: input })?;
    match url.scheme() {
        "file" => Ok(Box::new(LocalKeySource {
            path: PathBuf::from(url.path()),
        })),
        #[cfg(any(feature = "rusoto-native-tls", feature = "rusoto-rustls"))]
        "aws-ssm" => Ok(Box::new(SsmKeySource {
            profile: url.host_str().and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_owned())
                }
            }),
            parameter_name: url.path().to_owned(),
            // If a key ID isn't provided, the system uses the default key
            // associated with your AWS account.
            key_id: url.query_pairs().find_map(|(k, v)| {
                if k == "kms-key-id" {
                    Some(v.into_owned())
                } else {
                    None
                }
            }),
        })),
        "aws-kms" => Ok(Box::new(KmsKeySource {
            profile: url.host_str().and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_owned())
                }
            }),
            // remove first '/' from the path to get the key_id
            key_id: url.path()[1..].to_string(),
            client: None,
        })),
        _ => error::UnrecognizedScheme {
            scheme: url.scheme(),
        }
        .fail(),
    }
}
