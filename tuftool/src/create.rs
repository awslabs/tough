// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use snafu::ResultExt;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use structopt::StructOpt;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::KeySource;

#[derive(Debug, StructOpt)]
pub(crate) struct CreateArgs {
    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Version of snapshot.json file
    #[structopt(long = "snapshot-version")]
    snapshot_version: NonZeroU64,
    /// Expiration of snapshot.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(long = "snapshot-expires", parse(try_from_str = parse_datetime))]
    snapshot_expires: DateTime<Utc>,

    /// Version of targets.json file
    #[structopt(long = "targets-version")]
    targets_version: NonZeroU64,
    /// Expiration of targets.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(long = "targets-expires", parse(try_from_str = parse_datetime))]
    targets_expires: DateTime<Utc>,

    /// Version of timestamp.json file
    #[structopt(long = "timestamp-version")]
    timestamp_version: NonZeroU64,
    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(long = "timestamp-expires", parse(try_from_str = parse_datetime))]
    timestamp_expires: DateTime<Utc>,

    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// Directory of targets
    #[structopt(short = "t", long = "add-targets")]
    targets_indir: PathBuf,

    /// Behavior when a target exists with the same name and hash in the targets directory,
    /// for example from another repository when they share a targets directory.
    /// Options are "replace", "fail", and "skip"
    #[structopt(long = "target-path-exists", default_value = "skip")]
    target_path_exists: PathExists,

    /// Follow symbolic links in the given directory when adding targets
    #[structopt(short = "f", long = "follow")]
    follow: bool,

    /// Number of target hashing threads to run when adding targets
    /// (default: number of cores)
    // No default is specified in structopt here. This is because rayon
    // automatically spawns the same number of threads as cores when any
    // of its parallel methods are called.
    #[structopt(short = "j", long = "jobs")]
    jobs: Option<NonZeroUsize>,

    /// The directory where the repository will be written
    #[structopt(short = "o", long = "outdir")]
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
                .context(error::InitializeThreadPool)?;
        }

        let targets = build_targets(&self.targets_indir, self.follow)?;
        let mut editor =
            RepositoryEditor::new(&self.root).context(error::EditorCreate { path: &self.root })?;

        editor
            .targets_version(self.targets_version)
            .context(error::DelegationStructure)?
            .targets_expires(self.targets_expires)
            .context(error::DelegationStructure)?
            .snapshot_version(self.snapshot_version)
            .snapshot_expires(self.snapshot_expires)
            .timestamp_version(self.timestamp_version)
            .timestamp_expires(self.timestamp_expires);

        for (filename, target) in targets {
            editor
                .add_target(&filename, target)
                .context(error::DelegationStructure)?;
        }

        let signed_repo = editor.sign(&self.keys).context(error::SignRepo)?;

        let metadata_dir = &self.outdir.join("metadata");
        let targets_outdir = &self.outdir.join("targets");
        signed_repo
            .link_targets(&self.targets_indir, targets_outdir, self.target_path_exists)
            .context(error::LinkTargets {
                indir: &self.targets_indir,
                outdir: targets_outdir,
            })?;
        signed_repo.write(metadata_dir).context(error::WriteRepo {
            directory: metadata_dir,
        })?;

        Ok(())
    }
}
