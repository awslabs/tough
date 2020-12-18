// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::common::load_metadata_repo;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use snafu::ResultExt;
use std::num::NonZeroU64;
use std::path::PathBuf;
use structopt::StructOpt;
use tough::editor::targets::TargetsEditor;
use tough::key_source::KeySource;
use tough::schema::decoded::{Decoded, Hex};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct RemoveKeyArgs {
    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Key to be removed will look similar to `8ec3a843a0f9328c863cac4046ab1cacbbc67888476ac7acf73d9bcd9a223ada`
    #[structopt(long = "keyid", required = true)]
    remove: Decoded<Hex>,

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

impl RemoveKeyArgs {
    pub(crate) fn run(&self, role: &str) -> Result<()> {
        let repository = load_metadata_repo(&self.root, self.metadata_base_url.clone())?;
        self.remove_key(
            role,
            TargetsEditor::from_repo(repository, role)
                .context(error::EditorFromRepo { path: &self.root })?,
        )
    }

    /// Removes keys from a delegated role using targets Editor
    fn remove_key(&self, role: &str, mut editor: TargetsEditor) -> Result<()> {
        let updated_role = editor
            .remove_key(
                &self.remove,
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
