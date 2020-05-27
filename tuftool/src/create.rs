// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use rayon::prelude::*;
use snafu::{OptionExt, ResultExt};
use std::collections::HashMap;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use tough::editor::RepositoryEditor;
use tough::key_source::KeySource;
use tough::schema::Target;
use walkdir::WalkDir;

#[derive(Debug, StructOpt)]
pub(crate) struct CreateArgs {
    /// Follow symbolic links in `indir`
    #[structopt(short = "f", long = "follow")]
    follow: bool,

    /// Number of target hashing threads to run (default: number of cores)
    // No default is specified in structopt here. This is because rayon
    // automatically spawns the same number of threads as cores when any
    // of its parallel methods are called.
    #[structopt(short = "j", long = "jobs")]
    jobs: Option<NonZeroUsize>,

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
    indir: PathBuf,
    /// Repository output directory
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

        let targets = self.build_targets()?;
        let mut editor =
            RepositoryEditor::new(&self.root).context(error::EditorCreate { path: &self.root })?;

        editor
            .targets_version(self.targets_version)
            .targets_expires(self.targets_expires)
            .snapshot_version(self.snapshot_version)
            .snapshot_expires(self.snapshot_expires)
            .timestamp_version(self.timestamp_version)
            .timestamp_expires(self.timestamp_expires);

        for (filename, target) in targets {
            editor.add_target(filename, target);
        }

        let signed_repo = editor.sign(&self.keys).context(error::SignRepo)?;

        let metadata_dir = &self.outdir.join("metadata");
        let targets_dir = &self.outdir.join("targets");
        signed_repo
            .link_targets(&self.indir, targets_dir)
            .context(error::LinkTargets {
                indir: &self.indir,
                outdir: targets_dir,
            })?;
        signed_repo.write(metadata_dir).context(error::WriteRepo {
            directory: metadata_dir,
        })?;

        Ok(())
    }

    // Build a map of filename to Target structs, doing the hashing
    // of the targets in parallel.
    fn build_targets(&self) -> Result<HashMap<String, Target>> {
        WalkDir::new(&self.indir)
            .follow_links(self.follow)
            .into_iter()
            .par_bridge()
            .filter_map(|entry| match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        Some(Self::process_target(entry.path()))
                    } else {
                        None
                    }
                }
                Err(err) => Some(Err(err).context(error::WalkDir {
                    directory: &self.indir,
                })),
            })
            .collect()
    }

    fn process_target(path: &Path) -> Result<(String, Target)> {
        // Build a Target from the path given. If it is not a file, this will fail
        let target = Target::from_path(path).context(error::TargetFromPath { path })?;

        // Get the file name as a string
        let target_name = path
            .file_name()
            .context(error::NoFileName { path })?
            .to_str()
            .context(error::PathUtf8 { path })?
            .to_owned();
        Ok((target_name, target))
    }
}
