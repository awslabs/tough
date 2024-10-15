// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provides an abstraction over the source of a signing key. This allows signing keys to be
//! obtained, for example, from local files or from cloud provider key stores.
use crate::error;
use crate::sign::{parse_keypair, Sign};
use async_trait::async_trait;
use snafu::ResultExt;
use std::fmt::Debug;
use std::path::PathBuf;
use std::result::Result;

/// This trait should be implemented for each source of signing keys. Examples
/// of sources include: files, AWS SSM, etc.
#[async_trait]
pub trait KeySource: Debug + Send + Sync {
    /// Returns an object that implements the `Sign` trait
    async fn as_sign(
        &self,
    ) -> Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// Writes a key back to the `KeySource`
    async fn write(
        &self,
        value: &str,
        key_id_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
}

/// Points to a local key using a filesystem path.
#[derive(Debug)]
pub struct LocalKeySource {
    /// The path to a local key file in PEM pkcs8 or RSA format.
    pub path: PathBuf,
    /// Optional password for the key file.
    pub password: Option<String>,
}

/// Implements the `KeySource` trait for a `LocalKeySource` (file)
#[async_trait]
impl KeySource for LocalKeySource {
    async fn as_sign(
        &self,
    ) -> Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let data = tokio::fs::read(&self.path)
            .await
            .context(error::FileReadSnafu { path: &self.path })?;
        let password: Option<&str> = self.password.as_deref();
        Ok(Box::new(parse_keypair(&data, password)?))
    }

    async fn write(
        &self,
        value: &str,
        _key_id_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(tokio::fs::write(&self.path, value.as_bytes())
            .await
            .context(error::FileWriteSnafu { path: &self.path })?)
    }
}
