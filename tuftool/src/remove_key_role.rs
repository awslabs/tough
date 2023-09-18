// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::common::load_metadata_repo;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::ResultExt;
use std::num::NonZeroU64;
use std::path::PathBuf;
use tough::editor::targets::TargetsEditor;
use tough::schema::decoded::{Decoded, Hex};
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct RemoveKeyArgs {
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

    /// Key to be removed will look similar to `8ec3a843a0f9328c863cac4046ab1cacbbc67888476ac7acf73d9bcd9a223ada`
    #[arg(long = "keyid", required = true)]
    remove: Decoded<Hex>,

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

impl RemoveKeyArgs {
    pub(crate) async fn run(&self, role: &str) -> Result<()> {
        let repository = load_metadata_repo(&self.root, self.metadata_base_url.clone()).await?;
        self.remove_key(
            role,
            TargetsEditor::from_repo(repository, role)
                .context(error::EditorFromRepoSnafu { path: &self.root })?,
        )
        .await
    }

    /// Removes keys from a delegated role using targets Editor
    async fn remove_key(&self, role: &str, mut editor: TargetsEditor) -> Result<()> {
        let mut keys = Vec::new();
        for source in &self.keys {
            let key_source = parse_key_source(source)?;
            keys.push(key_source);
        }

        let updated_role = editor
            .remove_key(&self.remove, self.delegated_role.as_deref())
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
