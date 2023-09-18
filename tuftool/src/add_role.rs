// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::common::load_metadata_repo;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::{OptionExt, ResultExt};
use std::num::NonZeroU64;
use std::path::PathBuf;
use tough::editor::{targets::TargetsEditor, RepositoryEditor};
use tough::schema::{PathHashPrefix, PathPattern, PathSet};
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct AddRoleArgs {
    /// The role being delegated
    #[arg(short, long = "delegated-role")]
    delegatee: String,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(short, long, value_parser = parse_datetime)]
    expires: DateTime<Utc>,

    /// Incoming metadata
    #[arg(short, long = "incoming-metadata")]
    indir: Url,

    /// Key files to sign with
    #[arg(short, long = "key", required = true)]
    keys: Vec<String>,

    /// TUF repository metadata base URL
    #[arg(short, long = "metadata-url")]
    metadata_base_url: Url,

    /// The directory where the repository will be written
    #[arg(short, long)]
    outdir: PathBuf,

    /// The delegated paths
    #[arg(short, long, conflicts_with = "path_hash_prefixes")]
    paths: Option<Vec<PathPattern>>,

    /// Path to root.json file for the repository
    #[arg(short, long)]
    root: PathBuf,

    /// Determines if entire repo should be signed
    #[arg(long)]
    sign_all: bool,

    /// Expiration of snapshot.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long, value_parser = parse_datetime)]
    snapshot_expires: Option<DateTime<Utc>>,
    /// Version of snapshot.json file
    #[arg(long)]
    snapshot_version: Option<NonZeroU64>,

    /// threshold of signatures to sign delegatee
    #[arg(short, long)]
    threshold: NonZeroU64,

    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long, value_parser = parse_datetime)]
    timestamp_expires: Option<DateTime<Utc>>,
    /// Version of timestamp.json file
    #[arg(long)]
    timestamp_version: Option<NonZeroU64>,

    /// Version of targets.json file
    #[arg(short, long)]
    version: NonZeroU64,

    /// The delegated paths hash prefixes
    #[arg(short = 'x', long)]
    path_hash_prefixes: Option<Vec<PathHashPrefix>>,
}

impl AddRoleArgs {
    pub(crate) async fn run(&self, role: &str) -> Result<()> {
        // load the repo
        let repository = load_metadata_repo(&self.root, self.metadata_base_url.clone()).await?;
        // if sign_all use Repository Editor to sign the entire repo if not use targets editor
        if self.sign_all {
            // Add a role using a `RepositoryEditor`
            self.with_repo_editor(
                role,
                RepositoryEditor::from_repo(&self.root, repository)
                    .await
                    .context(error::EditorFromRepoSnafu { path: &self.root })?,
            )
            .await
        } else {
            // Add a role using a `TargetsEditor`
            self.add_role(
                role,
                TargetsEditor::from_repo(repository, role)
                    .context(error::EditorFromRepoSnafu { path: &self.root })?,
            )
            .await
        }
    }

    #[allow(clippy::option_if_let_else)]
    /// Adds a role to metadata using targets Editor
    async fn add_role(&self, role: &str, mut editor: TargetsEditor) -> Result<()> {
        let paths = if let Some(paths) = &self.paths {
            PathSet::Paths(paths.clone())
        } else if let Some(path_hash_prefixes) = &self.path_hash_prefixes {
            PathSet::PathHashPrefixes(path_hash_prefixes.clone())
        } else {
            // Should warn that no paths are being delegated
            PathSet::Paths(Vec::new())
        };

        let mut keys = Vec::new();
        for source in &self.keys {
            let key_source = parse_key_source(source)?;
            keys.push(key_source);
        }

        let updated_role = editor
            .add_role(
                &self.delegatee,
                self.indir.as_str(),
                paths,
                self.threshold,
                None,
            )
            .await
            .context(error::LoadMetadataSnafu)?
            .version(self.version)
            .expires(self.expires)
            .sign(&keys)
            .await
            .context(error::SignRepoSnafu)?;
        let metadata_destination_out = &self.outdir.join("metadata");
        updated_role
            .write(metadata_destination_out, false)
            .await
            .context(error::WriteRolesSnafu {
                roles: [self.delegatee.clone(), role.to_string()].to_vec(),
            })?;

        Ok(())
    }

    #[allow(clippy::option_if_let_else)]
    /// Adds a role to metadata using repo Editor
    async fn with_repo_editor(&self, role: &str, mut editor: RepositoryEditor) -> Result<()> {
        let mut keys = Vec::new();
        for source in &self.keys {
            let key_source = parse_key_source(source)?;
            keys.push(key_source);
        }

        // Since we are using repo editor we will sign snapshot and timestamp
        // Check to make sure all versions and expirations are present
        let snapshot_version = self.snapshot_version.context(error::MissingSnafu {
            what: "snapshot version".to_string(),
        })?;
        let snapshot_expires = self.snapshot_expires.context(error::MissingSnafu {
            what: "snapshot expires".to_string(),
        })?;
        let timestamp_version = self.timestamp_version.context(error::MissingSnafu {
            what: "timestamp version".to_string(),
        })?;
        let timestamp_expires = self.timestamp_expires.context(error::MissingSnafu {
            what: "timestamp expires".to_string(),
        })?;
        let paths = if let Some(paths) = &self.paths {
            PathSet::Paths(paths.clone())
        } else if let Some(path_hash_prefixes) = &self.path_hash_prefixes {
            PathSet::PathHashPrefixes(path_hash_prefixes.clone())
        } else {
            // Should warn that no paths are being delegated
            PathSet::Paths(Vec::new())
        };
        // Sign the top level targets (it's currently the one in targets_editor)
        editor
            .targets_version(self.version)
            .context(error::DelegationStructureSnafu)?
            .targets_expires(self.expires)
            .context(error::DelegationStructureSnafu)?
            .sign_targets_editor(&keys)
            .await
            .context(error::DelegateeNotFoundSnafu {
                role: role.to_string(),
            })?;
        // Change the targets in targets_editor to the one we need to add the new role to
        editor
            .change_delegated_targets(role)
            .context(error::DelegateeNotFoundSnafu {
                role: role.to_string(),
            })?;
        // Add the new role to the signing role
        editor
            .add_role(
                &self.delegatee,
                self.indir.as_str(),
                paths,
                self.threshold,
                None,
            )
            .await
            .context(error::LoadMetadataSnafu)?
            .targets_version(self.version)
            .context(error::DelegationStructureSnafu)?
            .targets_expires(self.expires)
            .context(error::DelegationStructureSnafu)?
            .snapshot_version(snapshot_version)
            .snapshot_expires(snapshot_expires)
            .timestamp_version(timestamp_version)
            .timestamp_expires(timestamp_expires);

        let signed_repo = editor.sign(&keys).await.context(error::SignRepoSnafu)?;
        let metadata_destination_out = &self.outdir.join("metadata");
        signed_repo
            .write(metadata_destination_out)
            .await
            .context(error::WriteRolesSnafu {
                roles: [self.delegatee.clone(), role.to_string()].to_vec(),
            })?;

        Ok(())
    }
}
