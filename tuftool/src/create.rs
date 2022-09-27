// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::ResultExt;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::KeySource;

#[derive(Debug, Parser)]
pub(crate) struct CreateArgs {
    /// Key files to sign with
    #[clap(short = 'k', long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Version of snapshot.json file
    #[clap(long = "snapshot-version")]
    snapshot_version: NonZeroU64,
    /// Expiration of snapshot.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[clap(long = "snapshot-expires", parse(try_from_str = parse_datetime))]
    snapshot_expires: DateTime<Utc>,

    /// Version of targets.json file
    #[clap(long = "targets-version")]
    targets_version: NonZeroU64,
    /// Expiration of targets.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[clap(long = "targets-expires", parse(try_from_str = parse_datetime))]
    targets_expires: DateTime<Utc>,

    /// Version of timestamp.json file
    #[clap(long = "timestamp-version")]
    timestamp_version: NonZeroU64,
    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[clap(long = "timestamp-expires", parse(try_from_str = parse_datetime))]
    timestamp_expires: DateTime<Utc>,

    /// Path to root.json file for the repository
    #[clap(short = 'r', long = "root")]
    root: PathBuf,

    /// Directory of targets
    #[clap(short = 't', long = "add-targets")]
    targets_indir: PathBuf,

    /// Behavior when a target exists with the same name and hash in the targets directory,
    /// for example from another repository when they share a targets directory.
    /// Options are "replace", "fail", and "skip"
    #[clap(long = "target-path-exists", default_value = "skip")]
    target_path_exists: PathExists,

    /// Follow symbolic links in the given directory when adding targets
    #[clap(short = 'f', long = "follow")]
    follow: bool,

    /// Number of target hashing threads to run when adding targets
    /// (default: number of cores)
    // No default is specified in structopt here. This is because rayon
    // automatically spawns the same number of threads as cores when any
    // of its parallel methods are called.
    #[clap(short = 'j', long = "jobs")]
    jobs: Option<NonZeroUsize>,

    /// The directory where the repository will be written
    #[clap(short = 'o', long = "outdir")]
    outdir: PathBuf,
}

impl CreateArgs {
    pub(crate) fn run(&self) -> Result<()> {
        // If a user specifies job count we override the default, which is
        // the number of cores.
        if let Some(jobs) = self.jobs {
            rayon::ThreadPoolBuilder::new()
                .num_threads(usize::from(jobs))
                .build_global()
                .context(error::InitializeThreadPoolSnafu)?;
        }

        let targets = build_targets(&self.targets_indir, self.follow)?;
        let mut editor = RepositoryEditor::new(&self.root)
            .context(error::EditorCreateSnafu { path: &self.root })?;

        editor
            .targets_version(self.targets_version)
            .context(error::DelegationStructureSnafu)?
            .targets_expires(self.targets_expires)
            .context(error::DelegationStructureSnafu)?
            .snapshot_version(self.snapshot_version)
            .snapshot_expires(self.snapshot_expires)
            .timestamp_version(self.timestamp_version)
            .timestamp_expires(self.timestamp_expires);

        for (target_name, target) in targets {
            editor
                .add_target(target_name, target)
                .context(error::DelegationStructureSnafu)?;
        }

        let signed_repo = editor.sign(&self.keys).context(error::SignRepoSnafu)?;

        let metadata_dir = &self.outdir.join("metadata");
        let targets_outdir = &self.outdir.join("targets");
        signed_repo
            .link_targets(&self.targets_indir, targets_outdir, self.target_path_exists)
            .context(error::LinkTargetsSnafu {
                indir: &self.targets_indir,
                outdir: targets_outdir,
            })?;
        signed_repo
            .write(metadata_dir)
            .context(error::WriteRepoSnafu {
                directory: metadata_dir,
            })?;

        Ok(())
    }
}
