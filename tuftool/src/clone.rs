// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::common::UNUSED_URL;
use crate::download_root::download_root;
use crate::error::{self, Result};
use snafu::ResultExt;
use std::fs::File;
use std::num::NonZeroU64;
use std::path::PathBuf;
use structopt::StructOpt;
use tough::{ExpirationEnforcement, RepositoryLoader};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct CloneArgs {
    /// Path to root.json file for the repository
    #[structopt(
        short = "r",
        long = "root",
        required_if("allow-root-download", "false")
    )]
    root: Option<PathBuf>,

    /// Remote root.json version number
    #[structopt(short = "v", long = "root-version", default_value = "1")]
    root_version: NonZeroU64,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// TUF repository targets base URL
    #[structopt(short = "t", long = "targets-url", required_unless = "metadata-only")]
    targets_base_url: Option<Url>,

    /// Allow downloading the root.json file (unsafe)
    #[structopt(long)]
    allow_root_download: bool,

    /// Allow repo download for expired metadata (unsafe)
    #[structopt(long)]
    allow_expired_repo: bool,

    /// Download only these targets, if specified
    #[structopt(short = "n", long = "target-names", conflicts_with = "metadata-only")]
    target_names: Vec<String>,

    /// Output directory of targets
    #[structopt(long, required_unless = "metadata-only")]
    targets_dir: Option<PathBuf>,

    /// Output directory of metadata
    #[structopt(long)]
    metadata_dir: PathBuf,

    /// Only download the repository metadata, not the targets
    #[structopt(long, conflicts_with_all(&["target-names", "targets-dir", "targets-base-url"]))]
    metadata_only: bool,
}

#[rustfmt::skip]
fn expired_repo_warning() {
    eprintln!("\
=================================================================
WARNING: repo metadata is expired, meaning the owner hasn't verified its contents lately and it could be unsafe!
=================================================================");
}

impl CloneArgs {
    pub(crate) fn run(&self) -> Result<()> {
        // Use local root.json or download from repository
        let root_path = if let Some(path) = &self.root {
            PathBuf::from(path)
        } else if self.allow_root_download {
            let outdir = std::env::current_dir().context(error::CurrentDirSnafu)?;
            download_root(&self.metadata_base_url, self.root_version, outdir)?
        } else {
            eprintln!("No root.json available");
            std::process::exit(1);
        };

        // Structopt won't allow `targets_base_url` to be None when it is required.  We require the
        // user to supply `targets_base_url` in the case they actually plan to download targets.
        // When downloading metadata, we don't ever need to access the targets URL, so we use a
        // fake URL to satisfy the library.
        let targets_base_url = self
            .targets_base_url
            .as_ref()
            .unwrap_or(&Url::parse(UNUSED_URL).context(error::UrlParseSnafu {
                url: UNUSED_URL.to_owned(),
            })?)
            .clone();

        // Load repository
        let expiration_enforcement = if self.allow_expired_repo {
            expired_repo_warning();
            ExpirationEnforcement::Unsafe
        } else {
            ExpirationEnforcement::Safe
        };
        let repository = RepositoryLoader::new(
            File::open(&root_path).context(error::OpenRootSnafu { path: &root_path })?,
            self.metadata_base_url.clone(),
            targets_base_url,
        )
        .expiration_enforcement(expiration_enforcement)
        .load()
        .context(error::RepoLoadSnafu)?;

        // Clone the repository, downloading none, all, or a subset of targets
        if self.metadata_only {
            println!("Cloning repository metadata to {:?}", self.metadata_dir);
            repository
                .cache_metadata(&self.metadata_dir, true)
                .context(error::CloneRepositorySnafu)?;
        } else {
            // Similar to `targets_base_url, structopt's guard rails won't let us have a
            // `targets_dir` that is None when the argument is required.  We only require the user
            // to supply a targets directory if they actually plan on downloading targets.
            let targets_dir = self.targets_dir.as_ref().expect(
                "Developer error: `targets_dir` is required unless downloading metadata only",
            );

            println!(
                "Cloning repository:\n\tmetadata location: {:?}\n\ttargets location: {:?}",
                self.metadata_dir, targets_dir
            );
            if self.target_names.is_empty() {
                repository
                    .cache(&self.metadata_dir, &targets_dir, None::<&[&str]>, true)
                    .context(error::CloneRepositorySnafu)?;
            } else {
                repository
                    .cache(
                        &self.metadata_dir,
                        &targets_dir,
                        Some(self.target_names.as_slice()),
                        true,
                    )
                    .context(error::CloneRepositorySnafu)?;
            }
        };

        Ok(())
    }
}
