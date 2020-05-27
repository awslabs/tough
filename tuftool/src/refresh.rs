// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use snafu::ResultExt;
use std::fs::File;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use structopt::StructOpt;
use tough::editor::RepositoryEditor;
use tough::key_source::KeySource;
use tough::{ExpirationEnforcement, FilesystemTransport, HttpTransport, Limits, Repository};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct RefreshArgs {
    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// The working directory where the current metadata files will be written.
    #[structopt(short = "w", long = "workdir", default_value = ".")]
    workdir: PathBuf,

    /// The directory where the new metadata files will be written.
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,

    /// Number of target hashing threads to run (default: number of cores)
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
}

impl RefreshArgs {
    pub(crate) fn run(&self) -> Result<()> {
        let settings = tough::Settings {
            root: File::open(&self.root).context(error::FileOpen { path: &self.root })?,
            datastore: self.workdir.as_path(),
            metadata_base_url: self.metadata_base_url.as_str(),
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

        editor
            .targets_expires(self.targets_expires)
            .targets_version(self.targets_version)
            .snapshot_expires(self.snapshot_expires)
            .snapshot_version(self.snapshot_version)
            .timestamp_expires(self.timestamp_expires)
            .timestamp_version(self.timestamp_version);

        let signed_repo = editor.sign(&self.keys).context(error::SignRepo)?;

        let metadata_dir = &self.outdir.join("metadata");
        signed_repo.write(metadata_dir).context(error::WriteRepo {
            directory: metadata_dir,
        })
    }
}
