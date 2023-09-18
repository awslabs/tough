// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::common::load_metadata_repo;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::ResultExt;
use std::num::NonZeroU64;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use tough::editor::signed::PathExists;
use tough::editor::targets::TargetsEditor;
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct UpdateTargetsArgs {
    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(short, long, value_parser = parse_datetime)]
    expires: DateTime<Utc>,

    /// Follow symbolic links in the given directory when adding targets
    #[arg(short, long)]
    follow: bool,

    /// Number of target hashing threads to run when adding targets
    /// (default: number of cores)
    // No default is specified in structopt here. This is because rayon
    // automatically spawns the same number of threads as cores when any
    // of its parallel methods are called.
    #[arg(short, long)]
    jobs: Option<NonZeroUsize>,

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

    /// Directory of targets
    #[arg(short, long = "add-targets")]
    targets_indir: Option<PathBuf>,

    /// Behavior when a target exists with the same name and hash in the desired repository
    /// directory, for example from another repository when you're sharing target directories.
    /// Options are "replace", "fail", and "skip"
    #[arg(long, default_value = "skip")]
    target_path_exists: PathExists,

    /// Version of targets.json file
    #[arg(short, long)]
    version: NonZeroU64,
}

impl UpdateTargetsArgs {
    pub(crate) async fn run(&self, role: &str) -> Result<()> {
        let repository = load_metadata_repo(&self.root, self.metadata_base_url.clone()).await?;
        self.update_targets(
            TargetsEditor::from_repo(repository, role)
                .context(error::EditorFromRepoSnafu { path: &self.root })?,
        )
        .await
    }

    async fn update_targets(&self, mut editor: TargetsEditor) -> Result<()> {
        let mut keys = Vec::new();
        for source in &self.keys {
            let key_source = parse_key_source(source)?;
            keys.push(key_source);
        }

        editor.version(self.version).expires(self.expires);

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

            let new_targets = build_targets(targets_indir, self.follow).await?;

            for (target_name, target) in new_targets {
                editor
                    .add_target(target_name, target)
                    .context(error::InvalidTargetNameSnafu)?;
            }
        };

        // Sign the role
        let signed_role = editor.sign(&keys).await.context(error::SignRepoSnafu)?;

        // Copy any targets that were added
        if let Some(ref targets_indir) = self.targets_indir {
            let targets_outdir = &self.outdir.join("targets");
            signed_role
                .copy_targets(targets_indir, targets_outdir, self.target_path_exists)
                .await
                .context(error::LinkTargetsSnafu {
                    indir: &targets_indir,
                    outdir: targets_outdir,
                })?;
        };

        // Write the metadata to the outdir
        let metadata_dir = &self.outdir.join("metadata");
        signed_role
            .write(metadata_dir, false)
            .await
            .context(error::WriteRepoSnafu {
                directory: metadata_dir,
            })?;

        Ok(())
    }
}
