// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use tough::async_trait;
use tough::key_source::KeySource;
use tough::sign::Sign;

/// Implements the KeySource trait for keys that live in AWS SSM.
#[derive(Debug)]
pub struct Pkcs11KeySource {}

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
