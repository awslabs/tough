// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod error;
mod signer;
pub mod uri;

use aws_lc_rs::rand::SecureRandom;
use snafu::ResultExt;
use tough::key_source::KeySource;
use tough::sign::Sign;
use tough::{async_trait, schema::key::Key};

pub use signer::{KeyId, Pkcs11Key, Pkcs11KeySource, TokenId};

#[async_trait]
impl Sign for Pkcs11Key {
    fn tuf_key(&self) -> Key {
        self.pub_key()
    }

    async fn sign(
        &self,
        msg: &[u8],
        _rng: &(dyn SecureRandom + Sync),
    ) -> core::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let this = self.clone();
        let msg = msg.to_vec();
        let signature = tokio::task::spawn_blocking(move || this.sign(&msg))
            .await
            .context(error::JoinSpawnBlockingTaskSnafu)??;

        Ok(signature)
    }
}

/// Implements the KeySource trait.
#[async_trait]
impl KeySource for Pkcs11KeySource {
    async fn as_sign(
        &self,
    ) -> std::result::Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        let this = self.clone();
        let key = tokio::task::spawn_blocking(move || this.to_key())
            .await
            .context(error::JoinSpawnBlockingTaskSnafu)??;

        Ok(Box::new(key))
    }

    async fn write(
        &self,
        _value: &str,
        _key_id_hex: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Err(error::WritingUnsupportedError.into())
    }
}
