// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! tough-kms implements the `KeySource` trait found in [tough, a Rust TUF client](https://github.com/awslabs/tough).
//!
//! By implementing this trait, AWS KMS can become a source of keys used to sign a [TUF repository](https://theupdateframework.github.io/).
//!
//! # Testing
//!
//! Unit tests are run in the usual manner: `cargo test`.

#![forbid(missing_debug_implementations, missing_copy_implementations)]
#![deny(rust_2018_idioms)]
// missing_docs is on its own line to make it easy to comment out when making changes.
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

mod client;
pub mod error;
use ring::digest::{digest, SHA256};
use ring::rand::SecureRandom;
use rusoto_kms::{Kms, KmsClient, SignRequest};
use snafu::{OptionExt, ResultExt};
use std::collections::HashMap;
use std::fmt;
use tough::key_source::KeySource;
use tough::schema::decoded::{Decoded, RsaPem};
use tough::schema::key::{Key, RsaKey, RsaScheme};
use tough::sign::Sign;

/// Represents a Signing Algorithms for AWS KMS.
#[derive(Debug, Clone, PartialEq)]
pub enum KmsSigningAlgorithms {
    /// The key type
    Rsa(String),
}

/// Implements the `KeySource` trait for keys that live in AWS KMS
pub struct KmsKeySource {
    /// Identifies AWS account named profile, if not provided default AWS profile is used.
    pub profile: Option<String>,
    /// Identifies an asymmetric CMK in AWS KMS.
    pub key_id: String,
    /// KmsClient Object to query AWS KMS
    pub client: Option<KmsClient>,
}

impl fmt::Debug for KmsKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KmsKeySource")
            .field("key_id", &self.key_id)
            .field("profile", &self.profile)
            .finish()
    }
}

/// Implement the `KeySource` trait.
impl KeySource for KmsKeySource {
    fn as_sign(
        &self,
    ) -> std::result::Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        let kms_client = match self.client.to_owned() {
            Some(value) => value,
            None => client::build_client_kms(self.profile.as_deref())?,
        };
        // Get the public key from AWS KMS
        let fut = kms_client.get_public_key(rusoto_kms::GetPublicKeyRequest {
            key_id: self.key_id.clone(),
            ..rusoto_kms::GetPublicKeyRequest::default()
        });
        let response = tokio::runtime::Runtime::new()
            .context(error::RuntimeCreation)?
            .block_on(fut)
            .context(error::KmsGetPublicKey {
                profile: self.profile.clone(),
                key_id: self.key_id.clone(),
            })?;
        let pb_key: Decoded<RsaPem> = response
            .public_key
            .context(error::PublicKeyNone)?
            .to_vec()
            .into();
        Ok(Box::new(KmsRsaKey {
            profile: self.profile.clone(),
            client: Some(kms_client.clone()),
            key_id: self.key_id.clone(),
            public_key: pb_key,
            signing_algorithm: KmsSigningAlgorithms::Rsa(String::from("RSASSA_PSS_SHA_256")),
        }))
    }

    fn write(
        &self,
        _value: &str,
        _key_id_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(())
    }
}

/// Implements the Sign trait for KMS rsa Key
pub struct KmsRsaKey {
    /// Key Id of Customer Managed Key in KMS used to sign the message
    key_id: String,
    /// Aws account profile
    profile: Option<String>,
    /// KmsClient Object to query AWS KMS
    client: Option<KmsClient>,
    /// Public Key corresponding to Customer Managed Key
    public_key: Decoded<RsaPem>,
    /// Signing Algorithm to be used for the Customer Managed Key
    signing_algorithm: KmsSigningAlgorithms,
}

impl fmt::Debug for KmsRsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KmsRsaKey")
            .field("key_id", &self.key_id)
            .field("signing_algorithm", &self.signing_algorithm)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Sign for KmsRsaKey {
    fn tuf_key(&self) -> Key {
        // Create a Key struct for the public key
        Key::Rsa {
            keyval: RsaKey {
                public: self.public_key.to_owned(),
                _extra: HashMap::new(),
            },
            scheme: RsaScheme::RsassaPssSha256,
            _extra: HashMap::new(),
        }
    }

    fn sign(
        &self,
        msg: &[u8],
        _rng: &dyn SecureRandom,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let kms_client = match self.client.to_owned() {
            Some(value) => value,
            None => client::build_client_kms(self.profile.as_deref())?,
        };
        let sign_fut = kms_client.sign(SignRequest {
            key_id: self.key_id.clone(),
            message: digest(&SHA256, msg).as_ref().to_vec().into(),
            message_type: Some(String::from("DIGEST")),
            signing_algorithm: match self.signing_algorithm.clone() {
                KmsSigningAlgorithms::Rsa(algorithm) => algorithm,
            },
            ..rusoto_kms::SignRequest::default()
        });
        let response = tokio::runtime::Runtime::new()
            .context(error::RuntimeCreation)?
            .block_on(sign_fut)
            .context(error::KmsSignMessage {
                profile: self.profile.clone(),
                key_id: self.key_id.clone(),
            })?;
        let signature = response.signature.context(error::SignatureNotFound)?;
        Ok(signature.to_vec())
    }
}
