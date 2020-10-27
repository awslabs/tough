// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use snafu::{OptionExt, ResultExt};
use std::fs::File;
use std::num::NonZeroU64;
use std::path::PathBuf;
use structopt::StructOpt;
use tough::editor::{targets::TargetsEditor, RepositoryEditor};
use tough::http::HttpTransport;
use tough::key_source::KeySource;
use tough::schema::PathSet;
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct AddRoleArgs {
    /// The role being delegated
    #[structopt(short = "d", long = "delegated-role")]
    delegatee: String,

    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(short = "e", long = "expires", parse(try_from_str = parse_datetime))]
    expires: DateTime<Utc>,

    /// Version of targets.json file
    #[structopt(short = "v", long = "version")]
    version: NonZeroU64,

    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// Incoming metadata
    #[structopt(short = "i", long = "incoming-metadata")]
    indir: Url,

    /// threshold of signatures to sign delegatee
    #[structopt(short = "t", long = "threshold")]
    threshold: NonZeroU64,

    /// The directory where the repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,

    /// The delegated paths
    #[structopt(short = "p", long = "paths", conflicts_with = "path-hash-prefixes")]
    paths: Option<Vec<String>>,

    /// The delegated paths hash prefixes
    #[structopt(short = "hp", long = "path-hash-prefixes")]
    path_hash_prefixes: Option<Vec<String>>,

    /// Determines if entire repo should be signed
    #[structopt(long = "sign-all")]
    sign_all: bool,

    /// Version of snapshot.json file
    #[structopt(long = "snapshot-version")]
    snapshot_version: Option<NonZeroU64>,
    /// Expiration of snapshot.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(long = "snapshot-expires", parse(try_from_str = parse_datetime))]
    snapshot_expires: Option<DateTime<Utc>>,

    /// Version of timestamp.json file
    #[structopt(long = "timestamp-version")]
    timestamp_version: Option<NonZeroU64>,

    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(long = "timestamp-expires", parse(try_from_str = parse_datetime))]
    timestamp_expires: Option<DateTime<Utc>>,
}

impl AddRoleArgs {
    pub(crate) fn run(&self, role: &str) -> Result<()> {
        // load the repo
        // We don't do anything with targets so we will use metadata url
        let settings = tough::Settings {
            root: File::open(&self.root).unwrap(),
            datastore: None,
            metadata_base_url: self.metadata_base_url.to_string(),
            targets_base_url: self.metadata_base_url.to_string(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        };
        // if sign_all use Repository Editor to sign the entire repo if not use targets editor
        if self.sign_all {
            // Load the `Repository` into the `RepositoryEditor`
            // Loading a `Repository` with different `Transport`s results in
            // different types. This is why we can't assign the `Repository`
            // to a variable with the if statement.
            if self.metadata_base_url.scheme() == "file" {
                let repository = Repository::load(Box::new(FilesystemTransport), settings)
                    .context(error::RepoLoad)?;
                self.with_repo_editor(
                    role,
                    RepositoryEditor::from_repo(&self.root, repository)
                        .context(error::EditorFromRepo { path: &self.root })?,
                )?;
            } else {
                let repository = Repository::load(Box::new(HttpTransport::new()), settings)
                    .context(error::RepoLoad)?;
                self.with_repo_editor(
                    role,
                    RepositoryEditor::from_repo(&self.root, repository)
                        .context(error::EditorFromRepo { path: &self.root })?,
                )?;
            }
        } else {
            // Load the `Repository` into the `TargetsEditor`
            // Loading a `Repository` with different `Transport`s results in
            // different types. This is why we can't assign the `Repository`
            // to a variable with the if statement.
            if self.metadata_base_url.scheme() == "file" {
                let repository = Repository::load(Box::new(FilesystemTransport), settings)
                    .context(error::RepoLoad)?;
                self.with_targets_editor(
                    role,
                    TargetsEditor::from_repo(repository, role)
                        .context(error::EditorFromRepo { path: &self.root })?,
                )?;
            } else {
                let repository = Repository::load(Box::new(HttpTransport::new()), settings)
                    .context(error::RepoLoad)?;
                self.with_targets_editor(
                    role,
                    TargetsEditor::from_repo(repository, role)
                        .context(error::EditorFromRepo { path: &self.root })?,
                )?;
            }
        }

        Ok(())
    }

    #[allow(clippy::option_if_let_else)]
    /// Adds a role to metadata using targets Editor
    fn with_targets_editor(&self, role: &str, mut editor: TargetsEditor) -> Result<()> {
        let paths = if let Some(paths) = &self.paths {
            PathSet::Paths(paths.clone())
        } else if let Some(path_hash_prefixes) = &self.path_hash_prefixes {
            PathSet::PathHashPrefixes(path_hash_prefixes.clone())
        } else {
            // Should warn that no paths are being delegated
            PathSet::Paths(Vec::new())
        };
        let updated_role = editor
            .add_role(
                &self.delegatee,
                self.indir.as_str(),
                paths,
                self.threshold,
                None,
            )
            .context(error::LoadMetadata)?
            .version(self.version)
            .expires(self.expires)
            .sign(&self.keys)
            .context(error::SignRepo)?;
        let metadata_destination_out = &self.outdir.join("metadata");
        updated_role
            .write(metadata_destination_out, false)
            .context(error::WriteRoles {
                roles: [self.delegatee.clone(), role.to_string()].to_vec(),
            })?;

        Ok(())
    }

    #[allow(clippy::option_if_let_else)]
    /// Adds a role to metadata using repo Editor
    fn with_repo_editor(&self, role: &str, mut editor: RepositoryEditor) -> Result<()> {
        // Since we are using repo editor we will sign snapshot and timestamp
        // Check to make sure all versions and expirations are present
        let snapshot_version = self.snapshot_version.context(error::Missing {
            what: "snapshot version".to_string(),
        })?;
        let snapshot_expires = self.snapshot_expires.context(error::Missing {
            what: "snapshot expires".to_string(),
        })?;
        let timestamp_version = self.timestamp_version.context(error::Missing {
            what: "timestamp version".to_string(),
        })?;
        let timestamp_expires = self.timestamp_expires.context(error::Missing {
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
            .context(error::DelegationStructure)?
            .targets_expires(self.expires)
            .context(error::DelegationStructure)?
            .sign_targets_editor(&self.keys)
            .context(error::DelegateeNotFound {
                role: role.to_string(),
            })?;
        // Change the targets in targets_editor to the one we need to add the new role to
        editor
            .change_delegated_targets(role)
            .context(error::DelegateeNotFound {
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
            .context(error::LoadMetadata)?
            .targets_version(self.version)
            .context(error::DelegationStructure)?
            .targets_expires(self.expires)
            .context(error::DelegationStructure)?
            .snapshot_version(snapshot_version)
            .snapshot_expires(snapshot_expires)
            .timestamp_version(timestamp_version)
            .timestamp_expires(timestamp_expires);

        let signed_repo = editor.sign(&self.keys).context(error::SignRepo)?;
        let metadata_destination_out = &self.outdir.join("metadata");
        signed_repo
            .write(metadata_destination_out)
            .context(error::WriteRoles {
                roles: [self.delegatee.clone(), role.to_string()].to_vec(),
            })?;

        Ok(())
    }
}
