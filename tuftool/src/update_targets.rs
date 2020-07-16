// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
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
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct UpdateTargetsArgs {
    /// Delegatee role
    #[structopt(long = "role", required = true)]
    role: String,

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

    /// Directory of targets
    #[structopt(short = "t", long = "add-targets")]
    targets_indir: PathBuf,

    /// The directory where the repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,

    /// Follow symbolic links in the given directory when adding targets
    #[structopt(short = "f", long = "follow")]
    follow: bool,

    /// Determines if entire repo should be signed
    #[structopt(long = "sign-all")]
    sign_all: bool,

    // Use symlink instead of copying targets
    #[structopt(short = "l", long = "link")]
    link: bool,
}

impl UpdateTargetsArgs {
    pub(crate) fn run(&self) -> Result<()> {
        // load the repo
        let datastore = tempdir().context(error::TempDir)?;
        let settings = tough::Settings {
            root: File::open(&self.root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: self.metadata_base_url.as_str(),
            // We don't do anything with targets so we will use metadata url
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

        // add targets
        let new_targets = build_targets(&self.targets_indir, self.follow)?;

        for (filename, target) in new_targets {
            editor
                .add_target_to_delegatee(&filename, target, &self.role)
                .context(error::DelegateeNotFound {
                    role: self.role.clone(),
                })?;
        }

        // if sign_all is requested, sign and write entire repo
        if self.sign_all {
            let signed_repo = editor.sign(&self.keys).context(error::SignRepo)?;
            let metadata_dir = &self.outdir.join("metadata");
            signed_repo.write(metadata_dir).context(error::WriteRepo {
                directory: metadata_dir,
            })?;

            return Ok(());
        }
        // if not, write updated role to outdir/metadata
        // sign the updated role and receive SignedRole for the new role
        let mut roles = editor
            .sign_roles(&self.keys, [self.role.as_str()].to_vec())
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

        let targets_destination_out = &self.outdir.join("targets");

        if self.link {
            // link targets to outdir/targets
            editor.link_targets(&self.targets_indir, &targets_destination_out, Some(false))
        } else {
            // copy targets to outdir/targets
            editor.copy_targets(&self.targets_indir, &targets_destination_out, Some(false))
        }
        .context(error::LinkTargets {
            indir: &self.targets_indir,
            outdir: targets_destination_out,
        })?;

        Ok(())
    }
}
