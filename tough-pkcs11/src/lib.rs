// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod error;
mod signer;

use tough::async_trait;
use tough::key_source::KeySource;
use tough::sign::Sign;

pub use signer::{KeyId, Pkcs11KeySource, TokenId};

/// Implements the KeySource trait.
#[async_trait]
impl KeySource for Pkcs11KeySource {
    async fn as_sign(
        &self,
    ) -> std::result::Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        todo!()
    }

    async fn write(
        &self,
        _value: &str,
        _key_id_hex: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        todo!()
    }
}
