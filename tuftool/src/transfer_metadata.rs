// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::common::read_root_bytes;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::ResultExt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use tough::editor::RepositoryEditor;
use tough::{ExpirationEnforcement, RepositoryLoader};
use url::Url;

#[cfg(feature = "s3")]
use tough_s3::S3Transport;

#[derive(Debug, Parser)]
pub(crate) struct TransferMetadataArgs {
    /// Allow repo update from expired metadata
    #[arg(long)]
    allow_expired_repo: bool,

    /// Key file to sign with
    #[arg(short, long = "key", required = true)]
    keys: Vec<String>,

    /// TUF repository metadata base URL
    #[arg(short, long = "metadata-url")]
    metadata_base_url: Url,

    /// Path to new root.json file to be updated
    #[arg(short, long = "new-root")]
    new_root: PathBuf,

    /// The directory where the repository will be written
    #[arg(short, long)]
    outdir: PathBuf,

    /// Path or S3 URI to existing root.json file for the repository
    #[arg(short = 'r', long = "current-root")]
    current_root: String,

    /// Expiration of snapshot.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long = "snapshot-expires", value_parser = parse_datetime)]
    snapshot_expires: DateTime<Utc>,
    /// Version of snapshot.json file
    #[arg(long = "snapshot-version")]
    snapshot_version: NonZeroU64,

    /// TUF repository targets base URL
    #[arg(short, long = "targets-url")]
    targets_base_url: Url,

    /// Expiration of targets.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long = "targets-expires", value_parser = parse_datetime)]
    targets_expires: DateTime<Utc>,
    /// Version of targets.json file
    #[arg(long = "targets-version")]
    targets_version: NonZeroU64,

    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long = "timestamp-expires", value_parser = parse_datetime)]
    timestamp_expires: DateTime<Utc>,
    /// Version of timestamp.json file
    #[arg(long = "timestamp-version")]
    timestamp_version: NonZeroU64,

    #[cfg(feature = "s3")]
    /// AWS region for S3 transport (required for s3:// URLs)
    #[arg(long)]
    s3_region: Option<String>,
}

fn expired_repo_warning(from_path: &str, to_path: &Path) {
    #[rustfmt::skip]
    eprintln!("\
=================================================================
Transferring metadata from {} to {}
WARNING: `--allow-expired-repo` was passed; this is unsafe and will not establish trust, use only for testing!
=================================================================",
              from_path,
              to_path.display());
}

impl TransferMetadataArgs {
    pub(crate) async fn run(&self) -> Result<()> {
        let mut keys = Vec::new();
        for source in &self.keys {
            let key_source = parse_key_source(source)?;
            keys.push(key_source);
        }

        let current_root = &self.current_root;
        let new_root = &self.new_root;

        // load repository
        let expiration_enforcement = if self.allow_expired_repo {
            expired_repo_warning(current_root, new_root);
            ExpirationEnforcement::Unsafe
        } else {
            ExpirationEnforcement::Safe
        };
        #[cfg(feature = "s3")]
        let s3_region = self.s3_region.as_deref();
        #[cfg(not(feature = "s3"))]
        let s3_region = None;
        let root_bytes = read_root_bytes(current_root, s3_region).await?;
        #[cfg_attr(not(feature = "s3"), allow(unused_mut))]
        let mut loader = RepositoryLoader::new(
            &root_bytes,
            self.metadata_base_url.clone(),
            self.targets_base_url.clone(),
        )
        .expiration_enforcement(expiration_enforcement);

        #[cfg(feature = "s3")]
        if self.metadata_base_url.scheme() == "s3" || self.targets_base_url.scheme() == "s3" {
            if let Some(region) = &self.s3_region {
                loader = loader.transport(S3Transport::new_with_region(region).await);
            }
        }

        let current_repo = loader.load().await.context(error::RepoLoadSnafu)?;

        let mut editor = RepositoryEditor::new(new_root)
            .await
            .context(error::EditorCreateSnafu { path: &new_root })?;

        editor
            .targets_version(self.targets_version)
            .context(error::DelegationStructureSnafu)?
            .targets_expires(self.targets_expires)
            .context(error::DelegationStructureSnafu)?
            .snapshot_version(self.snapshot_version)
            .snapshot_expires(self.snapshot_expires)
            .timestamp_version(self.timestamp_version)
            .timestamp_expires(self.timestamp_expires);

        let targets = current_repo.targets();
        for (target_name, target) in &targets.signed.targets {
            editor
                .add_target(target_name.clone(), target.clone())
                .context(error::DelegationStructureSnafu)?;
        }

        let signed_repo = editor.sign(&keys).await.context(error::SignRepoSnafu)?;

        let metadata_dir = &self.outdir.join("metadata");
        signed_repo
            .write(metadata_dir)
            .await
            .context(error::WriteRepoSnafu {
                directory: metadata_dir,
            })?;

        Ok(())
    }
}
