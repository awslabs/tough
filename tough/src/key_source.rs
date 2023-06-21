// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provides an abstraction over the source of a signing key. This allows signing keys to be
//! obtained, for example, from local files or from cloud provider key stores.
use crate::error;
use crate::sign::{parse_keypair, Sign};
use snafu::ResultExt;
use std::fmt::Debug;
use std::path::PathBuf;
use std::result::Result;

/// This trait should be implemented for each source of signing keys. Examples
/// of sources include: files, AWS SSM, etc.
pub trait KeySource: Debug + Send + Sync + KeySourceClone {
    /// Returns an object that implements the `Sign` trait
    fn as_sign(&self) -> Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// Writes a key back to the `KeySource`
    fn write(
        &self,
        value: &str,
        key_id_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
}

/// Trait to allow a `KeySource` to be clonable for passing around copies of a `Box<dyn KeySource>`.
/// Necessary for supporting custom argument parsing with clap.
pub trait KeySourceClone {
    /// Clones the `KeySource` into a new `Box<dyn KeySource>`.
    fn clone_keysource(&self) -> Box<dyn KeySource>;
}

impl<T> KeySourceClone for T
where
    T: KeySource + Clone + 'static,
{
    fn clone_keysource(&self) -> Box<dyn KeySource> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn KeySource> {
    fn clone(&self) -> Self {
        self.clone_keysource()
    }
}

/// Points to a local key using a filesystem path.
#[derive(Debug, Clone)]
pub struct LocalKeySource {
    /// The path to a local key file in PEM pkcs8 or RSA format.
    pub path: PathBuf,
}

/// Implements the `KeySource` trait for a `LocalKeySource` (file)
impl KeySource for LocalKeySource {
    fn as_sign(&self) -> Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let data = std::fs::read(&self.path).context(error::FileReadSnafu { path: &self.path })?;
        Ok(Box::new(parse_keypair(&data)?))
    }

    fn write(
        &self,
        value: &str,
        _key_id_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(std::fs::write(&self.path, value.as_bytes())
            .context(error::FileWriteSnafu { path: &self.path })?)
    }
}
