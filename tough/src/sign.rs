// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};
use crate::schema::key::Key;
use ring::rand::SecureRandom;
use ring::signature::{KeyPair, RsaKeyPair};
use snafu::ResultExt;
use std::collections::HashMap;

/// This trait must be implemented for each type of key with which you will
/// sign things.
pub trait Sign: Sync + Send {
    /// Returns the decoded key along with its scheme and other metadata
    fn tuf_key(&self) -> crate::schema::key::Key;

    /// Signs the supplied message
    fn sign(&self, msg: &[u8], rng: &dyn SecureRandom) -> Result<Vec<u8>>;
}

/// Implements the Sign trait for RSA keypairs
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

    fn sign(&self, msg: &[u8], rng: &dyn SecureRandom) -> Result<Vec<u8>> {
        let mut signature = vec![0; self.public_modulus_len()];
        self.sign(&ring::signature::RSA_PSS_SHA256, rng, msg, &mut signature)
            .context(error::Sign)?;
        Ok(signature)
    }
}

/// Parses a supplied keypair and if it is recognized, returns an object that
/// implements the Sign trait
pub fn parse_keypair(key: &[u8]) -> Result<impl Sign> {
    if let Ok(pem) = pem::parse(key) {
        match pem.tag.as_str() {
            "PRIVATE KEY" => {
                if let Ok(rsa_key_pair) = RsaKeyPair::from_pkcs8(&pem.contents) {
                    Ok(rsa_key_pair)
                } else {
                    error::KeyUnrecognized.fail()
                }
            }
            "RSA PRIVATE KEY" => {
                Ok(RsaKeyPair::from_der(&pem.contents).context(error::KeyRejected)?)
            }
            _ => error::KeyUnrecognized.fail(),
        }
    } else {
        error::KeyUnrecognized.fail()
    }
}
