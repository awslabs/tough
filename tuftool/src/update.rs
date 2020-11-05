// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use snafu::{OptionExt, ResultExt};
use std::fs::File;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::http::HttpTransport;
use tough::key_source::KeySource;
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository, Transport};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct UpdateArgs {
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

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// Directory of targets
    #[structopt(short = "t", long = "add-targets")]
    targets_indir: Option<PathBuf>,

    /// Behavior when a target exists with the same name and hash in the desired repository
    /// directory, for example from another repository when you're sharing target directories.
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

    /// The directory where the updated repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,

    /// Incoming metadata from delegatee
    #[structopt(short = "i", long = "incoming-metadata")]
    indir: Option<Url>,

    /// Role of incoming metadata
    #[structopt(long = "role")]
    role: Option<String>,

    /// Allow repo download for expired metadata
    #[structopt(long)]
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
        // Create a temporary directory where the TUF client can store metadata
        let settings = tough::Settings {
            root: File::open(&self.root).context(error::FileOpen { path: &self.root })?,
            datastore: None,
            metadata_base_url: self.metadata_base_url.to_string(),
            // We never load any targets here so the real
            // `targets_base_url` isn't needed. `tough::Settings` requires
            // a value so we use `metadata_base_url` as a placeholder
            targets_base_url: self.metadata_base_url.to_string(),
            limits: Limits::default(),
            expiration_enforcement: if self.allow_expired_repo {
                expired_repo_warning(&self.outdir);
                ExpirationEnforcement::Unsafe
            } else {
                ExpirationEnforcement::Safe
            },
        };

        // Load the `Repository` into the `RepositoryEditor`
        // Loading a `Repository` with different `Transport`s results in
        // different types. This is why we can't assign the `Repository`
        // to a variable with the if statement.
        if self.metadata_base_url.scheme() == "file" {
            let repository =
                Repository::load(&FilesystemTransport, settings).context(error::RepoLoad)?;
            self.with_editor(
                RepositoryEditor::from_repo(&self.root, repository)
                    .context(error::EditorFromRepo { path: &self.root })?,
            )?;
        } else {
            let transport = HttpTransport::new();
            let repository = Repository::load(&transport, settings).context(error::RepoLoad)?;
            self.with_editor(
                RepositoryEditor::from_repo(&self.root, repository)
                    .context(error::EditorFromRepo { path: &self.root })?,
            )?;
        }

        Ok(())
    }

    fn with_editor<T>(&self, mut editor: RepositoryEditor<'_, T>) -> Result<()>
    where
        T: Transport,
    {
        editor
            .targets_version(self.targets_version)
            .context(error::DelegationStructure)?
            .targets_expires(self.targets_expires)
            .context(error::DelegationStructure)?
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
                    .context(error::InitializeThreadPool)?;
            }

            let new_targets = build_targets(&targets_indir, self.follow)?;

            for (filename, target) in new_targets {
                editor
                    .add_target(&filename, target)
                    .context(error::DelegationStructure)?;
            }
        };

        // If a `Targets` metadata needs to be updated
        if self.role.is_some() && self.indir.is_some() {
            editor
                .sign_targets_editor(&self.keys)
                .context(error::DelegationStructure)?
                .update_delegated_targets(
                    &self.role.as_ref().context(error::Missing {
                        what: "delegated role",
                    })?,
                    &self
                        .indir
                        .as_ref()
                        .context(error::Missing {
                            what: "delegated role metadata url",
                        })?
                        .as_str(),
                )
                .context(error::DelegateeNotFound {
                    role: self.role.as_ref().unwrap().clone(),
                })?;
        }

        // Sign the repo
        let signed_repo = editor.sign(&self.keys).context(error::SignRepo)?;

        // Symlink any targets that were added
        if let Some(ref targets_indir) = self.targets_indir {
            let targets_outdir = &self.outdir.join("targets");
            signed_repo
                .link_targets(&targets_indir, &targets_outdir, self.target_path_exists)
                .context(error::LinkTargets {
                    indir: &targets_indir,
                    outdir: targets_outdir,
                })?;
        };

        // Write the metadata to the outdir
        let metadata_dir = &self.outdir.join("metadata");
        signed_repo.write(metadata_dir).context(error::WriteRepo {
            directory: metadata_dir,
        })?;

        Ok(())
    }
}
