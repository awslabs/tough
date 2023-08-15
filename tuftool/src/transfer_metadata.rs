// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::ResultExt;
use std::fs::File;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use tough::editor::RepositoryEditor;
use tough::key_source::KeySource;
use tough::{ExpirationEnforcement, RepositoryLoader};
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct TransferMetadataArgs {
    /// Key file to sign with
    #[clap(short = 'k', long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// TUF repository metadata base URL
    #[clap(short = 'm', long = "metadata-url")]
    metadata_base_url: Url,

    /// TUF repository targets base URL
    #[clap(short = 't', long = "targets-url")]
    targets_base_url: Url,

    /// Version of snapshot.json file
    #[clap(long = "snapshot-version")]
    snapshot_version: NonZeroU64,
    /// Expiration of snapshot.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[clap(long = "snapshot-expires", parse(try_from_str = parse_datetime))]
    snapshot_expires: DateTime<Utc>,

    /// Version of targets.json file
    #[clap(long = "targets-version")]
    targets_version: NonZeroU64,
    /// Expiration of targets.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[clap(long = "targets-expires", parse(try_from_str = parse_datetime))]
    targets_expires: DateTime<Utc>,

    /// Version of timestamp.json file
    #[clap(long = "timestamp-version")]
    timestamp_version: NonZeroU64,
    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[clap(long = "timestamp-expires", parse(try_from_str = parse_datetime))]
    timestamp_expires: DateTime<Utc>,

    /// Path to existing root.json file for the repository
    #[clap(short = 'r', long = "current-root")]
    current_root: PathBuf,

    /// Path to new root.json file to be updated
    #[clap(short = 'n', long = "new-root")]
    new_root: PathBuf,

    /// The directory where the repository will be written
    #[clap(short = 'o', long = "outdir")]
    outdir: PathBuf,

    /// Allow repo update from expired metadata
    #[clap(long)]
    allow_expired_repo: bool,
}

fn expired_repo_warning<P: AsRef<Path>>(from_path: P, to_path: P) {
    #[rustfmt::skip]
    eprintln!("\
=================================================================
Transferring metadata from {} to {}
WARNING: `--allow-expired-repo` was passed; this is unsafe and will not establish trust, use only for testing!
=================================================================",
              from_path.as_ref().display(),
              to_path.as_ref().display());
}

impl TransferMetadataArgs {
    pub(crate) fn run(&self) -> Result<()> {
        let current_root = &self.current_root;
        let new_root = &self.new_root;

        // load repository
        let expiration_enforcement = if self.allow_expired_repo {
            expired_repo_warning(&current_root, &new_root);
            ExpirationEnforcement::Unsafe
        } else {
            ExpirationEnforcement::Safe
        };
        let current_repo = RepositoryLoader::new(
            File::open(current_root).context(error::OpenRootSnafu {
                path: &current_root,
            })?,
            self.metadata_base_url.clone(),
            self.targets_base_url.clone(),
        )
        .expiration_enforcement(expiration_enforcement)
        .load()
        .context(error::RepoLoadSnafu)?;

        let mut editor = RepositoryEditor::new(new_root)
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

        let signed_repo = editor.sign(&self.keys).context(error::SignRepoSnafu)?;

        let metadata_dir = &self.outdir.join("metadata");
        signed_repo
            .write(metadata_dir)
            .context(error::WriteRepoSnafu {
                directory: metadata_dir,
            })?;

        Ok(())
    }
}
