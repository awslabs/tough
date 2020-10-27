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
use std::num::NonZeroUsize;
use std::path::PathBuf;
use structopt::StructOpt;
use tough::editor::signed::PathExists;
use tough::editor::targets::TargetsEditor;
use tough::http::HttpTransport;
use tough::key_source::KeySource;
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct UpdateTargetsArgs {
    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(short = "e", long = "expires", parse(try_from_str = parse_datetime))]
    expires: DateTime<Utc>,

    /// Version of targets.json file
    #[structopt(short = "v", long = "version")]
    version: NonZeroU64,

    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// Directory of targets
    #[structopt(short = "t", long = "add-targets")]
    targets_indir: Option<PathBuf>,

    /// The directory where the repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,

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

    /// Behavior when a target exists with the same name and hash in the desired repository
    /// directory, for example from another repository when you're sharing target directories.
    /// Options are "replace", "fail", and "skip"
    #[structopt(long = "target-path-exists", default_value = "skip")]
    target_path_exists: PathExists,
}

impl UpdateTargetsArgs {
    pub(crate) fn run(&self, role: &str) -> Result<()> {
        // load the repo
        let settings = tough::Settings {
            root: File::open(&self.root).unwrap(),
            datastore: None,
            metadata_base_url: self.metadata_base_url.to_string(),
            // We don't do anything with targets so we will use metadata url
            targets_base_url: self.metadata_base_url.to_string(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        };

        // Load the `Repository` into the `RepositoryEditor`
        // Loading a `Repository` with different `Transport`s results in
        // different types. This is why we can't assign the `Repository`
        // to a variable with the if statement.
        if self.metadata_base_url.scheme() == "file" {
            let repository = Repository::load(Box::new(FilesystemTransport), settings)
                .context(error::RepoLoad)?;
            self.with_targets_editor(
                TargetsEditor::from_repo(repository, role)
                    .context(error::EditorFromRepo { path: &self.root })?,
            )?;
        } else {
            let repository = Repository::load(Box::new(HttpTransport::new()), settings)
                .context(error::RepoLoad)?;
            self.with_targets_editor(
                TargetsEditor::from_repo(repository, role)
                    .context(error::EditorFromRepo { path: &self.root })?,
            )?;
        }

        Ok(())
    }

    fn with_targets_editor(&self, mut editor: TargetsEditor) -> Result<()> {
        editor.version(self.version).expires(self.expires);

        // If the "add-targets" argument was passed, build a list of targets
        // and add them to the repository. If a user specifies job count we
        // override the default, which is the number of cores.
        if let Some(ref targets_indir) = self.targets_indir {
            if let Some(jobs) = self.jobs {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(usize::from(jobs))
                    .build_global()
                    .context(error::InitializeThreadPool)?;
            }

            let new_targets = build_targets(&targets_indir, self.follow)?;

            for (filename, target) in new_targets {
                editor.add_target(&filename, target);
            }
        };

        // Sign the role
        let signed_role = editor.sign(&self.keys).context(error::SignRepo)?;

        // Copy any targets that were added
        if let Some(ref targets_indir) = self.targets_indir {
            let targets_outdir = &self.outdir.join("targets");
            signed_role
                .copy_targets(&targets_indir, &targets_outdir, self.target_path_exists)
                .context(error::LinkTargets {
                    indir: &targets_indir,
                    outdir: targets_outdir,
                })?;
        };

        // Write the metadata to the outdir
        let metadata_dir = &self.outdir.join("metadata");
        signed_role
            .write(metadata_dir, false)
            .context(error::WriteRepo {
                directory: metadata_dir,
            })?;

        Ok(())
    }
}
