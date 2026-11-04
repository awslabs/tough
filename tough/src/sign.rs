// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provides the `Sign` trait which abstracts over the method of signing with different key types.

use crate::error::{self, Result};
use crate::schema::key::Key;
use crate::sign::SignKeyPair::ECDSA;
use crate::sign::SignKeyPair::ED25519;
use crate::sign::SignKeyPair::RSA;
use async_trait::async_trait;
use aws_lc_rs::rand::SecureRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};
use snafu::ResultExt;
use std::collections::HashMap;
use std::error::Error;

/// This trait must be implemented for each type of key with which you will
/// sign things.
#[async_trait]
pub trait Sign: Sync + Send {
    /// Returns the decoded key along with its scheme and other metadata
    fn tuf_key(&self) -> crate::schema::key::Key;

    /// Signs the supplied message
    async fn sign(
        &self,
        msg: &[u8],
        rng: &(dyn SecureRandom + Sync),
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>>;
}

/// Implements `Sign` for a reference to any type that implements `Sign`.
#[async_trait]
impl<T: Sign> Sign for &T {
    fn tuf_key(&self) -> Key {
        (*self).tuf_key()
    }

    async fn sign(
        &self,
        msg: &[u8],
        rng: &(dyn SecureRandom + Sync),
    ) -> std::prelude::rust_2015::Result<Vec<u8>, Box<dyn Error + Send + Sync + 'static>> {
        (*self).sign(msg, rng).await
    }
}

/// Implements the Sign trait for ED25519
#[async_trait]
impl Sign for Ed25519KeyPair {
    fn tuf_key(&self) -> Key {
        use crate::schema::key::{Ed25519Key, Ed25519Scheme};

        Key::Ed25519 {
            keyval: Ed25519Key {
                public: self.public_key().as_ref().to_vec().into(),
                _extra: HashMap::new(),
            },
            scheme: Ed25519Scheme::Ed25519,
            _extra: HashMap::new(),
        }
    }

    async fn sign(
        &self,
        msg: &[u8],
        _rng: &(dyn SecureRandom + Sync),
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let signature = self.sign(msg);
        Ok(signature.as_ref().to_vec())
    }
}

/// Implements the Sign trait for RSA keypairs
#[async_trait]
impl Sign for RsaKeyPair {
    fn tuf_key(&self) -> Key {
        use crate::schema::key::{RsaKey, RsaScheme};

        Key::Rsa {
            keyval: RsaKey {
                public: self.public_key().as_ref().to_vec().into(),
                _extra: HashMap::new(),
            },
            scheme: RsaScheme::RsassaPssSha256,
            _extra: HashMap::new(),
        }
    }

    async fn sign(
        &self,
        msg: &[u8],
        rng: &(dyn SecureRandom + Sync),
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut signature = vec![0; self.public_modulus_len()];
        self.sign(
            &aws_lc_rs::signature::RSA_PSS_SHA256,
            rng,
            msg,
            &mut signature,
        )
        .context(error::SignSnafu)?;
        Ok(signature)
    }
}

/// Implements the Sign trait for ECDSA keypairs
#[async_trait]
impl Sign for EcdsaKeyPair {
    fn tuf_key(&self) -> Key {
        use crate::schema::key::{EcdsaKey, EcdsaScheme};

        Key::Ecdsa {
            keyval: EcdsaKey {
                public: self.public_key().as_ref().to_vec().into(),
                _extra: HashMap::new(),
            },
            scheme: EcdsaScheme::EcdsaSha2Nistp256,
            _extra: HashMap::new(),
        }
    }

    async fn sign(
        &self,
        msg: &[u8],
        rng: &(dyn SecureRandom + Sync),
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let signature = self.sign(rng, msg).context(error::SignSnafu)?;
        Ok(signature.as_ref().to_vec())
    }
}

/// Keypair used for signing metadata
#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum SignKeyPair {
    /// RSA key pair
    RSA(RsaKeyPair),
    /// ED25519 key pair
    ED25519(Ed25519KeyPair),
    /// ECDSA key pair
    ECDSA(EcdsaKeyPair),
}

#[async_trait]
impl Sign for SignKeyPair {
    fn tuf_key(&self) -> Key {
        match self {
            RSA(key) => key.tuf_key(),
            ED25519(key) => key.tuf_key(),
            ECDSA(key) => key.tuf_key(),
        }
    }

    async fn sign(
        &self,
        msg: &[u8],
        rng: &(dyn SecureRandom + Sync),
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self {
            RSA(key) => (key as &dyn Sign).sign(msg, rng).await,
            ED25519(key) => (key as &dyn Sign).sign(msg, rng).await,
            ECDSA(key) => (key as &dyn Sign).sign(msg, rng).await,
        }
    }
}

/// Parses a supplied keypair and if it is recognized, returns an object that
/// implements the Sign trait
/// Accepted Keys: ED25519 pkcs8, Ecdsa pkcs8, RSA
pub fn parse_keypair(key: &[u8]) -> Result<impl Sign> {
    if let Ok(ed25519_key_pair) = Ed25519KeyPair::from_pkcs8(key).or_else(|e| {
        ring_legacy_ed25519_to_rfc5958(key)
            .ok_or(e)
            .and_then(|k| Ed25519KeyPair::from_pkcs8(&k))
    }) {
        Ok(SignKeyPair::ED25519(ed25519_key_pair))
    } else if let Ok(ecdsa_key_pair) =
        EcdsaKeyPair::from_pkcs8(&aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING, key)
    {
        Ok(SignKeyPair::ECDSA(ecdsa_key_pair))
    } else if let Ok(pem) = pem::parse(key) {
        match pem.tag() {
            "PRIVATE KEY" => {
                if let Ok(rsa_key_pair) = RsaKeyPair::from_pkcs8(pem.contents()) {
                    Ok(SignKeyPair::RSA(rsa_key_pair))
                } else {
                    error::KeyUnrecognizedSnafu.fail()
                }
            }
            "RSA PRIVATE KEY" => Ok(SignKeyPair::RSA(
                RsaKeyPair::from_der(pem.contents()).context(error::KeyRejectedSnafu)?,
            )),
            _ => error::KeyUnrecognizedSnafu.fail(),
        }
    } else {
        error::KeyUnrecognizedSnafu.fail()
    }
}

/// Re-encodes a ring-style PKCS#8 v2 Ed25519 key, whose public key is explicitly tagged
/// (`a1 23 03 21 00 ..`), into the RFC 5958 IMPLICIT form (`81 21 00 ..`) that aws-lc accepts.
/// Returns `None` if `key` is not in that layout.
fn ring_legacy_ed25519_to_rfc5958(key: &[u8]) -> Option<Vec<u8>> {
    const PREFIX: [u8; 16] = [
        0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    const LEGACY_PUB: [u8; 5] = [0xa1, 0x23, 0x03, 0x21, 0x00];
    if key.len() != 85 || key[..16] != PREFIX || key[48..53] != LEGACY_PUB {
        return None;
    }
    let mut out = Vec::with_capacity(83);
    out.extend_from_slice(&[0x30, 0x51]);
    out.extend_from_slice(&key[2..48]);
    out.extend_from_slice(&[0x81, 0x21, 0x00]);
    out.extend_from_slice(&key[53..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_data(name: &str) -> Vec<u8> {
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("data")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn parses_ring_legacy_ed25519_pkcs8() {
        for name in ["targetskey", "targetskey-1"] {
            let key = test_data(name);
            let keypair = parse_keypair(&key).unwrap();
            match keypair.tuf_key() {
                Key::Ed25519 { keyval, .. } => assert_eq!(*keyval.public, key[53..]),
                other => panic!("{}: expected an Ed25519 key, got {:?}", name, other),
            }
        }
    }

    #[test]
    fn rejects_non_legacy_input_for_rewrite() {
        assert!(ring_legacy_ed25519_to_rfc5958(&[0u8; 85]).is_none());
        assert!(ring_legacy_ed25519_to_rfc5958(&test_data("snakeoil.pem")).is_none());
    }
}
