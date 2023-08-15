// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::common::load_metadata_repo;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::ResultExt;
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::PathBuf;
use tough::editor::targets::TargetsEditor;
use tough::key_source::KeySource;
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct AddKeyArgs {
    /// Key files to sign with
    #[arg(short, long = "key", required = true, value_parser = parse_key_source)]
    keys: Vec<Box<dyn KeySource>>,

    /// New keys to be used for role
    #[arg(long = "new-key", required = true, value_parser = parse_key_source)]
    new_keys: Vec<Box<dyn KeySource>>,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(short, long, value_parser = parse_datetime)]
    expires: DateTime<Utc>,

    /// Version of role file
    #[arg(short, long)]
    version: NonZeroU64,

    /// Path to root.json file for the repository
    #[arg(short, long)]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[arg(short, long = "metadata-url")]
    metadata_base_url: Url,

    /// The directory where the repository will be written
    #[arg(short, long)]
    outdir: PathBuf,

    /// The role for the keys to be added to
    #[arg(long)]
    delegated_role: Option<String>,
}

impl AddKeyArgs {
    pub(crate) fn run(&self, role: &str) -> Result<()> {
        // load the repo
        let repository = load_metadata_repo(&self.root, self.metadata_base_url.clone())?;
        self.add_key(
            role,
            TargetsEditor::from_repo(repository, role)
                .context(error::EditorFromRepoSnafu { path: &self.root })?,
        )
    }

    /// Adds keys to a role using targets Editor
    fn add_key(&self, role: &str, mut editor: TargetsEditor) -> Result<()> {
        // create the keypairs to add
        let mut key_pairs = HashMap::new();
        for source in &self.new_keys {
            let key_pair = source
                .as_sign()
                .context(error::KeyPairFromKeySourceSnafu)?
                .tuf_key();
            key_pairs.insert(
                key_pair
                    .key_id()
                    .context(error::JsonSerializationSnafu {})?
                    .clone(),
                key_pair,
            );
        }
        let updated_role = editor
            .add_key(key_pairs, self.delegated_role.as_deref())
            .context(error::LoadMetadataSnafu)?
            .version(self.version)
            .expires(self.expires)
            .sign(&self.keys)
            .context(error::SignRepoSnafu)?;
        let metadata_destination_out = &self.outdir.join("metadata");
        updated_role
            .write(metadata_destination_out, false)
            .context(error::WriteRolesSnafu {
                roles: [role.to_string()].to_vec(),
            })?;

        Ok(())
    }
}
