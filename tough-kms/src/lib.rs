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
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client as KmsClient;
use ring::digest::{digest, SHA256};
use ring::rand::SecureRandom;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::HashMap;
use std::fmt;
use tough::async_trait;
use tough::key_source::KeySource;
use tough::schema::decoded::{Decoded, RsaPem};
use tough::schema::key::{Key, RsaKey, RsaScheme};
use tough::sign::Sign;

/// Represents a Signing Algorithms for AWS KMS.
#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub enum KmsSigningAlgorithm {
    /// Signing Algorithm `RSASSA_PSS_SHA_256`
    RsassaPssSha256,
}

impl KmsSigningAlgorithm {
    fn value(self) -> aws_sdk_kms::types::SigningAlgorithmSpec {
        // Currently we are supporting only single algorithm, but code stub is added to support
        // multiple algorithms in future.
        match self {
            KmsSigningAlgorithm::RsassaPssSha256 => {
                aws_sdk_kms::types::SigningAlgorithmSpec::RsassaPssSha256
            }
        }
    }
}

/// Implements the `KeySource` trait for keys that live in AWS KMS
pub struct KmsKeySource {
    /// Identifies AWS account named profile, if not provided default AWS profile is used.
    pub profile: Option<String>,
    /// Identifies an asymmetric CMK in AWS KMS.
    pub key_id: String,
    /// KmsClient Object to query AWS KMS
    pub client: Option<KmsClient>,
    /// Signing Algorithm to be used for the message digest, only `KmsSigningAlgorithm::RsassaPssSha256` is supported at present.
    pub signing_algorithm: KmsSigningAlgorithm,
}

impl fmt::Debug for KmsKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KmsKeySource")
            .field("key_id", &self.key_id)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// Implement the `KeySource` trait.
#[async_trait]
impl KeySource for KmsKeySource {
    async fn as_sign(
        &self,
    ) -> std::result::Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        let kms_client = match self.client.clone() {
            Some(value) => value,
            None => client::build_client_kms(self.profile.as_deref()).await,
        };
        // Get the public key from AWS KMS
        let response = kms_client
            .get_public_key()
            .key_id(self.key_id.clone())
            .send()
            .await
            .context(error::KmsGetPublicKeySnafu {
                profile: self.profile.clone(),
                key_id: self.key_id.clone(),
            })?;

        let key = pem::encode_config(
            &pem::Pem::new(
                "PUBLIC KEY".to_owned(),
                response
                    .public_key
                    .context(error::PublicKeyNoneSnafu)?
                    .into_inner(),
            ),
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        );
        ensure!(
            response
                .signing_algorithms
                .context(error::MissingSignAlgorithmSnafu)?
                .contains(&self.signing_algorithm.value()),
            error::ValidSignAlgorithmSnafu
        );
        Ok(Box::new(KmsRsaKey {
            profile: self.profile.clone(),
            client: Some(kms_client),
            key_id: self.key_id.clone(),
            public_key: key.parse().context(error::PublicKeyParseSnafu)?,
            signing_algorithm: self.signing_algorithm,
            modulus_size_bytes: parse_modulus_length_bytes(
                response
                    .key_spec
                    .as_ref()
                    .context(error::MissingKeySpecSnafu)?
                    .as_str(),
            )?,
        }))
    }

    async fn write(
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
    signing_algorithm: KmsSigningAlgorithm,
    /// The size of the RSA key modulus in bytes.
    modulus_size_bytes: usize,
}

impl fmt::Debug for KmsRsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KmsRsaKey")
            .field("key_id", &self.key_id)
            .field("signing_algorithm", &self.signing_algorithm)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Sign for KmsRsaKey {
    fn tuf_key(&self) -> Key {
        // Create a Key struct for the public key
        Key::Rsa {
            keyval: RsaKey {
                public: self.public_key.clone(),
                _extra: HashMap::new(),
            },
            scheme: RsaScheme::RsassaPssSha256,
            _extra: HashMap::new(),
        }
    }

    async fn sign(
        &self,
        msg: &[u8],
        _rng: &(dyn SecureRandom + Sync),
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let kms_client = match self.client.clone() {
            Some(value) => value,
            None => client::build_client_kms(self.profile.as_deref()).await,
        };
        let blob = Blob::new(digest(&SHA256, msg).as_ref().to_vec());
        let response = kms_client
            .sign()
            .key_id(self.key_id.clone())
            .message(blob)
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .signing_algorithm(self.signing_algorithm.value())
            .send()
            .await
            .context(error::KmsSignMessageSnafu {
                profile: self.profile.clone(),
                key_id: self.key_id.clone(),
            })?;
        let signature = response
            .signature
            .context(error::SignatureNotFoundSnafu)?
            .into_inner();

        // sometimes KMS produces a signature that is shorter than the modulus. in those cases,
        // we have observed that openssl and KMS will both validate the signature, but ring will
        // not. if we pad the beginning of the signature with zeros to make the signature exactly
        // the same length as the modulus, then ring will verify the signature.
        let signature = match &self.signing_algorithm {
            KmsSigningAlgorithm::RsassaPssSha256 => {
                pad_signature(signature, self.modulus_size_bytes)?
            }
        };
        Ok(signature)
    }
}

/// Parses the `KeySpec` string returned by KMS, e.g. `RSA_3072` and returns the size of the modulus
/// in bytes. For example `RSA_3072` has a modulus of 3072 bits, so the function will return 384 ==
/// (3072 / 8). If the parsed number is not divisible by 8, an error is returned.
fn parse_modulus_length_bytes(spec: &str) -> error::Result<usize> {
    // only RSA is currently supported
    ensure!(spec.starts_with("RSA_"), error::BadKeySpecSnafu { spec });
    // prevent a panic if the string is precisely "RSA_"
    ensure!(spec.len() > 4, error::BadKeySpecSnafu { spec });
    // extract the digits
    let mod_len_str = &spec[4..];
    // parse the digits
    let mod_bits = mod_len_str
        .parse::<usize>()
        .context(error::BadKeySpecIntSnafu { spec })?;
    // make sure the modulus size is compatible with u8 bytes
    ensure!(
        mod_bits % 8 == 0,
        error::UnsupportedModulusSizeSnafu {
            modulus_size_bits: mod_bits,
            spec,
        }
    );
    // convert to 8-bit bytes
    Ok(mod_bits / 8)
}

/// * If the length of `signature` is less than `modulus_size_bytes`, this function will prepend the
///   `signature` with zeros so that `signature.len() == modulus_size_bytes`.
/// * If the `signature` already the same length as `modulus_size_bytes` then `signature` is
///   returned unchanged.
/// * If the `signature` is longer than `modulus_size_bytes`, an error is returned.
fn pad_signature(mut signature: Vec<u8>, modulus_size_bytes: usize) -> error::Result<Vec<u8>> {
    ensure!(
        signature.len() <= modulus_size_bytes,
        error::SignatureTooLongSnafu {
            modulus_size_bytes,
            signature_size_bytes: signature.len()
        },
    );
    if signature.len() == modulus_size_bytes {
        return Ok(signature);
    }
    // we now know that the signature is shorter than the modulus
    let padding_size: usize = modulus_size_bytes - signature.len();
    signature.splice(..0, [0].repeat(padding_size));
    Ok(signature)
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

#[test]
fn parse_modulus_length_wrong_alg() {
    let result = parse_modulus_length_bytes("ECC_SECG_P256K1");
    assert!(result.is_err());
}

#[test]
fn parse_modulus_length_bad_str() {
    let result = parse_modulus_length_bytes("RSA_");
    assert!(result.is_err());
}

#[test]
fn parse_modulus_length_3072() {
    let modulus_length = parse_modulus_length_bytes("RSA_3072").unwrap();
    // 3072 bits is 384 bytes
    assert_eq!(modulus_length, 384);
}

#[test]
fn parse_modulus_length_3073() {
    // 3073 is not divisible by 8, should error
    let result = parse_modulus_length_bytes("RSA_3073");
    assert!(result.is_err());
}

#[test]
fn pad_signature_too_long() {
    let signature: Vec<u8> = vec![1, 2, 3, 4, 5];
    let modulus_size: usize = 4;
    let result = pad_signature(signature, modulus_size);
    assert!(result.is_err());
}

#[test]
fn pad_signature_no_change() {
    let signature: Vec<u8> = vec![1, 2, 3, 4, 5];
    let expected: Vec<u8> = vec![1, 2, 3, 4, 5];
    let modulus_size: usize = 5;
    let actual = pad_signature(signature, modulus_size).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn pad_signature_short_by_one() {
    let signature: Vec<u8> = vec![1, 2, 3, 4, 5];
    let expected: Vec<u8> = vec![0, 1, 2, 3, 4, 5];
    let modulus_size: usize = 6;
    let actual = pad_signature(signature, modulus_size).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn pad_signature_short_by_two() {
    let signature: Vec<u8> = vec![1, 2, 3, 4];
    let expected: Vec<u8> = vec![0, 0, 1, 2, 3, 4];
    let modulus_size: usize = 6;
    let actual = pad_signature(signature, modulus_size).unwrap();
    assert_eq!(expected, actual);
}
