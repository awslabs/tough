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
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct RemoveRoleArgs {
    /// The role to be removed
    #[arg(long)]
    delegated_role: String,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(short, long, value_parser = parse_datetime)]
    expires: DateTime<Utc>,

    /// Key files to sign with
    #[arg(short, long = "key", required = true)]
    keys: Vec<String>,

    /// TUF repository metadata base URL
    #[arg(short, long = "metadata-url")]
    metadata_base_url: Url,

    /// The directory where the repository will be written
    #[arg(short, long)]
    outdir: PathBuf,

    /// Path to root.json file for the repository
    #[arg(short, long)]
    root: PathBuf,

    /// Determine if the role should be removed even if it's not a direct delegatee
    #[arg(long)]
    recursive: bool,

    /// Version of role file
    #[arg(short, long)]
    version: NonZeroU64,
}

impl RemoveRoleArgs {
    pub(crate) async fn run(&self, role: &str) -> Result<()> {
        let repository = load_metadata_repo(&self.root, self.metadata_base_url.clone()).await?;
        self.remove_delegated_role(
            role,
            TargetsEditor::from_repo(repository, role)
                .context(error::EditorFromRepoSnafu { path: &self.root })?,
        )
        .await
    }

    /// Removes a delegated role from a `Targets` role using `TargetsEditor`
    async fn remove_delegated_role(&self, role: &str, mut editor: TargetsEditor) -> Result<()> {
        let mut keys = Vec::new();
        for source in &self.keys {
            let key_source = parse_key_source(source)?;
            keys.push(key_source);
        }

        let updated_role = editor
            .remove_role(&self.delegated_role, self.recursive)
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
