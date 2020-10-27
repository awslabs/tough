// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use snafu::ResultExt;
use std::collections::HashMap;
use std::fs::File;
use std::num::NonZeroU64;
use std::path::PathBuf;
use structopt::StructOpt;
use tough::editor::targets::TargetsEditor;
use tough::http::HttpTransport;
use tough::key_source::KeySource;
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct AddKeyArgs {
    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// New keys to be used for role
    #[structopt(long = "new-key", required = true, parse(try_from_str = parse_key_source))]
    new_keys: Vec<Box<dyn KeySource>>,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(short = "e", long = "expires", parse(try_from_str = parse_datetime))]
    expires: DateTime<Utc>,

    /// Version of role file
    #[structopt(short = "v", long = "version")]
    version: NonZeroU64,

    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// The directory where the repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,

    /// The role for the keys to be added to
    #[structopt(long = "delegated-role")]
    delegated_role: Option<String>,
}

impl AddKeyArgs {
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

        Ok(())
    }

    /// Adds keys to a role using targets Editor
    fn with_targets_editor(&self, role: &str, mut editor: TargetsEditor) -> Result<()> {
        // create the keypairs to add
        let mut key_pairs = HashMap::new();
        for source in &self.new_keys {
            let key_pair = source
                .as_sign()
                .context(error::KeyPairFromKeySource)?
                .tuf_key();
            key_pairs.insert(
                key_pair
                    .key_id()
                    .context(error::JsonSerialization {})?
                    .clone(),
                key_pair,
            );
        }
        let updated_role = editor
            .add_key(
                key_pairs,
                match &self.delegated_role {
                    Some(role) => Some(role.as_str()),
                    None => None,
                },
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
                roles: [role.to_string()].to_vec(),
            })?;

        Ok(())
    }
}
