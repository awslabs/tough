// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Private keys are generally provided as paths, but may sometimes be provided as a URL. For
//! example, when one of the Rusoto features is enabled, you can use an aws-ssm:// URL to refer to
//! a key accessible in SSM.
//!
//! This module parses a key source command line parameter as a URL, relative to `file://$PWD`,
//! then matches the URL scheme against ones we understand.

use crate::error::{self, Error, Result};
use snafu::{OptionExt, ResultExt};
use std::path::PathBuf;
use std::str::FromStr;
use tough::schema::key::Key;
use tough::sign::{parse_keypair, Sign};
use url::Url;

#[derive(Debug)]
pub(crate) enum KeySource {
    Local(PathBuf),
    #[cfg(any(feature = "rusoto-native-tls", feature = "rusoto-rustls"))]
    Ssm {
        profile: Option<String>,
        parameter_name: String,
        key_id: Option<String>,
    },
}

impl KeySource {
    pub(crate) fn as_sign(&self) -> Result<Box<dyn Sign>> {
        let keypair = parse_keypair(&self.read()?).context(error::KeyPairParse)?;
        Ok(Box::new(keypair))
    }

    pub(crate) fn as_public_key(&self) -> Result<Key> {
        let data = self.read()?;
        if let Ok(key_pair) = parse_keypair(&data) {
            Ok(key_pair.tuf_key())
        } else {
            let data = String::from_utf8(data)
                .ok()
                .context(error::UnrecognizedKey)?;
            Key::from_str(&data).ok().context(error::UnrecognizedKey)
        }
    }

    fn read(&self) -> Result<Vec<u8>> {
        match self {
            KeySource::Local(path) => std::fs::read(path).context(error::FileRead { path }),
            #[cfg(any(feature = "rusoto-native-tls", feature = "rusoto-rustls"))]
            KeySource::Ssm {
                profile,
                parameter_name,
                ..
            } => KeySource::read_with_ssm_key(profile, &parameter_name),
        }
    }

    #[cfg(any(feature = "rusoto-native-tls", feature = "rusoto-rustls"))]
    fn read_with_ssm_key(profile: &Option<String>, parameter_name: &str) -> Result<Vec<u8>> {
        use crate::deref::OptionDeref;
        use rusoto_ssm::Ssm;

        let ssm_client = crate::ssm::build_client(profile.deref_shim())?;
        let fut = ssm_client.get_parameter(rusoto_ssm::GetParameterRequest {
            name: parameter_name.to_owned(),
            with_decryption: Some(true),
        });
        let response = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(fut)
            .context(error::SsmGetParameter {
                profile: profile.clone(),
                parameter_name,
            })?;
        Ok(response
            .parameter
            .context(error::SsmMissingField { field: "parameter" })?
            .value
            .context(error::SsmMissingField {
                field: "parameter.value",
            })?
            .as_bytes()
            .to_vec())
    }

    #[cfg_attr(
        not(any(feature = "rusoto-native-tls", feature = "rusoto-rustls")),
        allow(unused)
    )]
    pub(crate) fn write(&self, value: &str, key_id_hex: &str) -> Result<()> {
        match self {
            KeySource::Local(path) => {
                std::fs::write(path, value.as_bytes()).context(error::FileWrite { path })
            }
            #[cfg(any(feature = "rusoto-native-tls", feature = "rusoto-rustls"))]
            KeySource::Ssm {
                profile,
                parameter_name,
                key_id,
            } => KeySource::write_with_ssm_key(value, key_id_hex, profile, &parameter_name, key_id),
        }
    }

    #[cfg(any(feature = "rusoto-native-tls", feature = "rusoto-rustls"))]
    fn write_with_ssm_key(
        value: &str,
        key_id_hex: &str,
        profile: &Option<String>,
        parameter_name: &str,
        key_id: &Option<String>,
    ) -> Result<()> {
        use crate::deref::OptionDeref;
        use rusoto_ssm::Ssm;

        let ssm_client = crate::ssm::build_client(profile.deref_shim())?;
        let fut = ssm_client.put_parameter(rusoto_ssm::PutParameterRequest {
            name: parameter_name.to_owned(),
            description: Some(key_id_hex.to_owned()),
            key_id: key_id.as_ref().cloned(),
            overwrite: Some(true),
            type_: "SecureString".to_owned(),
            value: value.to_owned(),
            ..rusoto_ssm::PutParameterRequest::default()
        });
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(fut)
            .context(error::SsmPutParameter {
                profile: profile.clone(),
                parameter_name,
            })?;
        Ok(())
    }
}

impl FromStr for KeySource {
    type Err = Error;

    #[allow(clippy::find_map)]
    fn from_str(s: &str) -> Result<Self> {
        let pwd_url = Url::from_directory_path(std::env::current_dir().context(error::CurrentDir)?)
            .expect("expected current directory to be absolute");
        let url = Url::options()
            .base_url(Some(&pwd_url))
            .parse(s)
            .context(error::UrlParse { url: s })?;

        match url.scheme() {
            "file" => Ok(KeySource::Local(PathBuf::from(url.path()))),
            #[cfg(any(feature = "rusoto-native-tls", feature = "rusoto-rustls"))]
            "aws-ssm" => Ok(KeySource::Ssm {
                profile: url.host_str().and_then(|s| {
                    if s.is_empty() {
                        None
                    } else {
                        Some(s.to_owned())
                    }
                }),
                parameter_name: url.path().to_owned(),
                key_id: url
                    .query_pairs()
                    .find(|(k, _)| k == "kms-key-id")
                    .map(|(_, v)| v.into_owned()),
            }),
            _ => error::UnrecognizedScheme {
                scheme: url.scheme(),
            }
            .fail(),
        }
    }
}
