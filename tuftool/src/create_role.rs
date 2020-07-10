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
pub(crate) struct CreateRoleArgs {
    /// Delegatee role
    #[structopt(long = "role", required = true)]
    role: String,

    /// Delegating role
    #[structopt(long = "from")]
    from: Option<String>,

    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(short = "e", long = "expires", required = true, parse(try_from_str = parse_datetime))]
    expires: DateTime<Utc>,

    /// Version of targets.json file
    #[structopt(short = "v", long = "version")]
    version: Option<NonZeroU64>,

    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// Threshold of signatures to sign role
    #[structopt(short = "t", long = "threshold")]
    threshold: Option<NonZeroU64>,

    /// The directory where the repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,
}

impl CreateRoleArgs {
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

        // Load the `Repository` into the `RepositoryEditor`
        // Loading a `Repository` with different `Transport`s results in
        // different types. This is why we can't assign the `Repository`
        // to a variable with the if statement.
        let mut editor = if self.metadata_base_url.scheme() == "file" {
            let repository =
                Repository::load(&FilesystemTransport, settings).context(error::RepoLoad)?;
            RepositoryEditor::from_repo(&self.root, repository)
        } else {
            let transport = HttpTransport::new();
            let repository = Repository::load(&transport, settings).context(error::RepoLoad)?;
            RepositoryEditor::from_repo(&self.root, repository)
        }
        .context(error::EditorFromRepo { path: &self.root })?;

        let targets_string = "targets".to_string();
        // create new delegated target as `role` from `from`
        let delegator = self.from.as_ref().unwrap_or(&targets_string);
        editor
            .add_delegate(
                &delegator,
                self.role.clone(),
                Some(&self.keys),
                PathSet::Paths(Vec::new()),
                self.expires,
                *self
                    .version
                    .as_ref()
                    .unwrap_or(&NonZeroU64::new(1).unwrap()),
            )
            .context(error::DelegateeNotFound {
                role: self.role.clone(),
            })?;

        // sign the role
        let role = editor
            .sign_roles(&self.keys, [self.role.as_str()].to_vec())
            .context(error::SignRoles {
                roles: [self.role.clone()].to_vec(),
            })?
            .remove(&self.role)
            .ok_or_else(|| error::Error::SignRolesRemove {
                roles: [self.role.clone()].to_vec(),
            })?;

        // write the role to outdir
        let metadata_destination_out = &self.outdir.join("metadata");
        role.write_del_role(&metadata_destination_out, false, &self.role)
            .context(error::WriteRoles {
                roles: [self.role.clone()].to_vec(),
            })?;

        Ok(())
    }
}
