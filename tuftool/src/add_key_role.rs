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
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct AddKeyArgs {
    /// The role for the keys to be added to
    #[arg(long)]
    delegated_role: Option<String>,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(short, long, value_parser = parse_datetime)]
    expires: DateTime<Utc>,

    /// Key files to sign with
    #[arg(short, long = "key", required = true)]
    keys: Vec<String>,

    /// New keys to be used for role
    #[arg(long = "new-key", required = true)]
    new_keys: Vec<String>,

    /// TUF repository metadata base URL
    #[arg(short, long = "metadata-url")]
    metadata_base_url: Url,

    /// The directory where the repository will be written
    #[arg(short, long)]
    outdir: PathBuf,

    /// Path to root.json file for the repository
    #[arg(short, long)]
    root: PathBuf,

    /// Version of role file
    #[arg(short, long)]
    version: NonZeroU64,
}

impl AddKeyArgs {
    pub(crate) async fn run(&self, role: &str) -> Result<()> {
        // load the repo
        let repository = load_metadata_repo(&self.root, self.metadata_base_url.clone()).await?;
        self.add_key(
            role,
            TargetsEditor::from_repo(repository, role)
                .context(error::EditorFromRepoSnafu { path: &self.root })?,
        )
        .await
    }

    /// Adds keys to a role using targets Editor
    async fn add_key(&self, role: &str, mut editor: TargetsEditor) -> Result<()> {
        // create the keypairs to add
        let mut key_pairs = HashMap::new();
        for source in &self.new_keys {
            let key_source = parse_key_source(source)?;
            let key_pair = key_source
                .as_sign()
                .await
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

        let mut keys = Vec::new();
        for source in &self.keys {
            let key_source = parse_key_source(source)?;
            keys.push(key_source);
        }

        let updated_role = editor
            .add_key(key_pairs, self.delegated_role.as_deref())
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
                roles: [role.to_string()].to_vec(),
            })?;

        Ok(())
    }
}
