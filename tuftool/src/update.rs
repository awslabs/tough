// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::common::UNUSED_URL;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::KeySourceValueParser;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::{OptionExt, ResultExt};
use std::fs::File;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::KeySource;
use tough::{ExpirationEnforcement, RepositoryLoader};
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct UpdateArgs {
    /// Key files to sign with
    #[arg(short = 'k', long = "key", required = true, value_parser = KeySourceValueParser)]
    keys: Vec<Box<dyn KeySource>>,

    /// Version of snapshot.json file
    #[arg(long = "snapshot-version")]
    snapshot_version: NonZeroU64,
    /// Expiration of snapshot.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long = "snapshot-expires", value_parser = parse_datetime)]
    snapshot_expires: DateTime<Utc>,

    /// Version of targets.json file
    #[arg(long = "targets-version")]
    targets_version: NonZeroU64,
    /// Expiration of targets.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long = "targets-expires", value_parser = parse_datetime)]
    targets_expires: DateTime<Utc>,

    /// Version of timestamp.json file
    #[arg(long = "timestamp-version")]
    timestamp_version: NonZeroU64,
    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long = "timestamp-expires", value_parser = parse_datetime)]
    timestamp_expires: DateTime<Utc>,

    /// Path to root.json file for the repository
    #[arg(short = 'r', long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[arg(short = 'm', long = "metadata-url")]
    metadata_base_url: Url,

    /// Directory of targets
    #[arg(short = 't', long = "add-targets")]
    targets_indir: Option<PathBuf>,

    /// Behavior when a target exists with the same name and hash in the desired repository
    /// directory, for example from another repository when you're sharing target directories.
    /// Options are "replace", "fail", and "skip"
    #[arg(long = "target-path-exists", default_value = "skip")]
    target_path_exists: PathExists,

    /// Follow symbolic links in the given directory when adding targets
    #[arg(short = 'f', long = "follow")]
    follow: bool,

    /// Number of target hashing threads to run when adding targets
    /// (default: number of cores)
    // No default is specified in structopt here. This is because rayon
    // automatically spawns the same number of threads as cores when any
    // of its parallel methods are called.
    #[arg(short = 'j', long = "jobs")]
    jobs: Option<NonZeroUsize>,

    /// The directory where the updated repository will be written
    #[arg(short = 'o', long = "outdir")]
    outdir: PathBuf,

    /// Incoming metadata from delegatee
    #[arg(short = 'i', long = "incoming-metadata")]
    indir: Option<Url>,

    /// Role of incoming metadata
    #[arg(long = "role")]
    role: Option<String>,

    /// Allow repo download for expired metadata
    #[arg(long)]
    allow_expired_repo: bool,
}

fn expired_repo_warning<P: AsRef<Path>>(path: P) {
    #[rustfmt::skip]
    eprintln!("\
=================================================================
Updating repo at {}
WARNING: `--allow-expired-repo` was passed; this is unsafe and will not establish trust, use only for testing!
=================================================================",
              path.as_ref().display());
}

impl UpdateArgs {
    pub(crate) fn run(&self) -> Result<()> {
        let expiration_enforcement = if self.allow_expired_repo {
            expired_repo_warning(&self.outdir);
            ExpirationEnforcement::Unsafe
        } else {
            ExpirationEnforcement::Safe
        };
        let repository = RepositoryLoader::new(
            File::open(&self.root).context(error::OpenRootSnafu { path: &self.root })?,
            self.metadata_base_url.clone(),
            Url::parse(UNUSED_URL).context(error::UrlParseSnafu { url: UNUSED_URL })?,
        )
        .expiration_enforcement(expiration_enforcement)
        .load()
        .context(error::RepoLoadSnafu)?;
        self.update_metadata(
            RepositoryEditor::from_repo(&self.root, repository)
                .context(error::EditorFromRepoSnafu { path: &self.root })?,
        )
    }

    fn update_metadata(&self, mut editor: RepositoryEditor) -> Result<()> {
        editor
            .targets_version(self.targets_version)
            .context(error::DelegationStructureSnafu)?
            .targets_expires(self.targets_expires)
            .context(error::DelegationStructureSnafu)?
            .snapshot_version(self.snapshot_version)
            .snapshot_expires(self.snapshot_expires)
            .timestamp_version(self.timestamp_version)
            .timestamp_expires(self.timestamp_expires);

        // If the "add-targets" argument was passed, build a list of targets
        // and add them to the repository. If a user specifies job count we
        // override the default, which is the number of cores.
        if let Some(ref targets_indir) = self.targets_indir {
            if let Some(jobs) = self.jobs {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(usize::from(jobs))
                    .build_global()
                    .context(error::InitializeThreadPoolSnafu)?;
            }

            let new_targets = build_targets(targets_indir, self.follow)?;

            for (target_name, target) in new_targets {
                editor
                    .add_target(target_name, target)
                    .context(error::DelegationStructureSnafu)?;
            }
        };

        // If a `Targets` metadata needs to be updated
        if self.role.is_some() && self.indir.is_some() {
            editor
                .sign_targets_editor(&self.keys)
                .context(error::DelegationStructureSnafu)?
                .update_delegated_targets(
                    self.role.as_ref().context(error::MissingSnafu {
                        what: "delegated role",
                    })?,
                    self.indir
                        .as_ref()
                        .context(error::MissingSnafu {
                            what: "delegated role metadata url",
                        })?
                        .as_str(),
                )
                .context(error::DelegateeNotFoundSnafu {
                    role: self.role.as_ref().unwrap().clone(),
                })?;
        }

        // Sign the repo
        let signed_repo = editor.sign(&self.keys).context(error::SignRepoSnafu)?;

        // Symlink any targets that were added
        if let Some(ref targets_indir) = self.targets_indir {
            let targets_outdir = &self.outdir.join("targets");
            signed_repo
                .link_targets(targets_indir, targets_outdir, self.target_path_exists)
                .context(error::LinkTargetsSnafu {
                    indir: &targets_indir,
                    outdir: targets_outdir,
                })?;
        };

        // Write the metadata to the outdir
        let metadata_dir = &self.outdir.join("metadata");
        signed_repo
            .write(metadata_dir)
            .context(error::WriteRepoSnafu {
                directory: metadata_dir,
            })?;

        Ok(())
    }
}
