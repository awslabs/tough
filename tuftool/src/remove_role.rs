// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::common::load_metadata_repo;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::KeySourceValueParser;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::ResultExt;
use std::num::NonZeroU64;
use std::path::PathBuf;
use tough::editor::targets::TargetsEditor;
use tough::key_source::KeySource;
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct RemoveRoleArgs {
    /// Key files to sign with
    #[arg(short = 'k', long = "key", required = true, value_parser = KeySourceValueParser)]
    keys: Vec<Box<dyn KeySource>>,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(short = 'e', long = "expires", value_parser = parse_datetime)]
    expires: DateTime<Utc>,

    /// Version of role file
    #[arg(short = 'v', long = "version")]
    version: NonZeroU64,

    /// Path to root.json file for the repository
    #[arg(short = 'r', long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[arg(short = 'm', long = "metadata-url")]
    metadata_base_url: Url,

    /// The directory where the repository will be written
    #[arg(short = 'o', long = "outdir")]
    outdir: PathBuf,

    /// The role to be removed
    #[arg(long = "delegated-role")]
    delegated_role: String,

    /// Determine if the role should be removed even if it's not a direct delegatee
    #[arg(long = "recursive")]
    recursive: bool,
}

impl RemoveRoleArgs {
    pub(crate) fn run(&self, role: &str) -> Result<()> {
        let repository = load_metadata_repo(&self.root, self.metadata_base_url.clone())?;
        self.remove_delegated_role(
            role,
            TargetsEditor::from_repo(repository, role)
                .context(error::EditorFromRepoSnafu { path: &self.root })?,
        )
    }

    /// Removes a delegated role from a `Targets` role using `TargetsEditor`
    fn remove_delegated_role(&self, role: &str, mut editor: TargetsEditor) -> Result<()> {
        let updated_role = editor
            .remove_role(&self.delegated_role, self.recursive)
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
