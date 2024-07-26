
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
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pkcs8::der::Decode;
use snafu::ResultExt;
use std::collections::HashMap;
use std::error::Error;
use std::str;
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
impl<'a, T: Sign> Sign for &'a T {
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

/// Decrypts an RSA private key in PEM format using the given password.
/// Returns the decrypted key in PKCS8 format.
pub fn decrypt_key(
    encrypted_key: &[u8],
    password: &str,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pem_str = std::str::from_utf8(encrypted_key)?;
    let pem = pem::parse(pem_str)?;
    let encrypted_private_key_document = pkcs8::EncryptedPrivateKeyInfo::from_der(pem.contents())?;
    let decrypted_private_key_document =
        encrypted_private_key_document.decrypt(password.as_bytes())?;
    let decrypted_key_bytes: Vec<u8> = decrypted_private_key_document.as_bytes().to_vec();
    let decrypted_key_base64 = STANDARD.encode(decrypted_key_bytes);
    let pem_key =
        format!("-----BEGIN PRIVATE KEY-----\n{decrypted_key_base64}\n-----END PRIVATE KEY-----");
    let pem_key_bytes = pem_key.as_bytes().to_vec();
    Ok(pem_key_bytes)
}

/// Parses a supplied keypair and if it is recognized, returns an object that
/// implements the Sign trait
/// Accepted Keys: ED25519 pkcs8, Ecdsa pkcs8, RSA
pub fn parse_keypair(key: &[u8], password: Option<&str>) -> Result<impl Sign> {
    let decrypted_key = if let Some(pw) = password {
        decrypt_key(key, pw).unwrap_or_else(|_| key.to_vec())
    } else {
        key.to_vec()
    };
    let decrypted_key_slice: &[u8] = &decrypted_key;

    if let Ok(ed25519_key_pair) = Ed25519KeyPair::from_pkcs8(decrypted_key_slice) {
        Ok(SignKeyPair::ED25519(ed25519_key_pair))
    } else if let Ok(ecdsa_key_pair) =
        EcdsaKeyPair::from_pkcs8(&aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING, decrypted_key_slice)
    {
        Ok(SignKeyPair::ECDSA(ecdsa_key_pair))
    } else if let Ok(pem) = pem::parse(decrypted_key_slice) {
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
