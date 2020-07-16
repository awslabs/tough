// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use snafu::ResultExt;
use std::fs::File;
use std::num::NonZeroU64;
use std::path::PathBuf;
use structopt::StructOpt;
use tempfile::tempdir;
use tough::editor::RepositoryEditor;
use tough::http::HttpTransport;
use tough::key_source::KeySource;
use tough::schema::PathSet;
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct AddRoleArgs {
    /// Delegating role
    #[structopt(long = "role", required = true)]
    role: String,

    /// Delegatee role
    #[structopt(short = "d", long = "delegatee")]
    delegatee: String,

    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(short = "e", long = "expires", parse(try_from_str = parse_datetime))]
    expires: Option<DateTime<Utc>>,

    /// Version of targets.json file
    #[structopt(short = "v", long = "version")]
    version: Option<NonZeroU64>,

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
    threshold: Option<NonZeroU64>,

    /// The directory where the repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,

    /// The delegated paths
    #[structopt(short = "p", long = "paths")]
    paths: Option<Vec<String>>,

    /// The delegated paths hash prefixes
    #[structopt(short = "hp", long = "path-hash-prefixes")]
    path_hash_prefixes: Option<Vec<String>>,

    /// Determins if entire repo should be signed
    #[structopt(long = "sign-all")]
    sign_all: bool,
}

impl AddRoleArgs {
    pub(crate) fn run(&self) -> Result<()> {
        // load the repo
        let datastore = tempdir().context(error::TempDir)?;
        // We don't do anything with targets so we will use metadata url
        let settings = tough::Settings {
            root: File::open(&self.root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: self.metadata_base_url.as_str(),
            targets_base_url: self.metadata_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        };

        let paths = if let Some(paths) = &self.paths {
            PathSet::Paths(paths.clone())
        } else if let Some(path_hash_prefixes) = &self.path_hash_prefixes {
            PathSet::PathHashPrefixes(path_hash_prefixes.clone())
        } else {
            // Should warn that no paths are being delegated
            PathSet::Paths(Vec::new())
        };
        // Load the `Repository` into the `RepositoryEditor`
        // Loading a `Repository` with different `Transport`s results in
        // different types. This is why we can't assign the `Repository`
        // to a variable with the if statement.
        let editor = if self.metadata_base_url.scheme() == "file" {
            let mut repository =
                Repository::load(&FilesystemTransport, settings).context(error::RepoLoad)?;
            // Add incoming role metadata
            repository
                .load_add_delegated_role(
                    &self.delegatee,
                    &self.role,
                    paths,
                    *self
                        .threshold
                        .as_ref()
                        .unwrap_or(&NonZeroU64::new(1).unwrap()),
                    self.indir.as_str(),
                    self.version,
                )
                .context(error::LoadMetadata)?;
            RepositoryEditor::from_repo(&self.root, repository)
        } else {
            let transport = HttpTransport::new();
            let mut repository = Repository::load(&transport, settings).context(error::RepoLoad)?;
            // Add incoming role metadata
            repository
                .load_add_delegated_role(
                    &self.delegatee,
                    &self.role,
                    paths,
                    *self
                        .threshold
                        .as_ref()
                        .unwrap_or(&NonZeroU64::new(1).unwrap()),
                    self.indir.as_str(),
                    self.version,
                )
                .context(error::LoadMetadata)?;
            RepositoryEditor::from_repo(&self.root, repository)
        }
        .context(error::EditorFromRepo { path: &self.root })?;

        // if sign-all is included sign and write entire repo
        if self.sign_all {
            let signed_repo = editor.sign(&self.keys).context(error::SignRepo)?;
            let metadata_dir = &self.outdir.join("metadata");
            signed_repo.write(metadata_dir).context(error::WriteRepo {
                directory: metadata_dir,
            })?;

            return Ok(());
        }
        // if not, write new roles to outdir
        // sign the updated role and recieve SignedRole for the new role
        let mut roles = editor
            .sign_roles(
                &self.keys,
                [self.role.as_str(), self.delegatee.as_str()].to_vec(),
            )
            .context(error::SignRoles {
                roles: [self.role.clone()].to_vec(),
            })?;

        let metadata_destination_out = &self.outdir.join("metadata");
        // write the delegator role to outdir
        roles
            .remove(&self.role)
            .ok_or_else(|| error::Error::SignRolesRemove {
                roles: [self.role.clone()].to_vec(),
            })?
            .write_del_role(&metadata_destination_out, false, &self.role)
            .context(error::WriteRoles {
                roles: [self.role.clone()].to_vec(),
            })?;
        // write delegatee metadata to outdir
        roles
            .remove(&self.delegatee)
            .ok_or_else(|| error::Error::SignRolesRemove {
                roles: [self.delegatee.clone()].to_vec(),
            })?
            .write_del_role(&metadata_destination_out, false, &self.delegatee)
            .context(error::WriteRoles {
                roles: [self.delegatee.clone()].to_vec(),
            })?;

        Ok(())
    }
}
