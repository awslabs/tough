// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::common::UNUSED_URL;
use crate::download_root::download_root;
use crate::error::{self, Result};
use clap::Parser;
use snafu::ResultExt;
use std::num::NonZeroU64;
use std::path::PathBuf;
use tough::{ExpirationEnforcement, RepositoryLoader};
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct CloneArgs {
    /// Allow repo download for expired metadata (unsafe)
    #[arg(long)]
    allow_expired_repo: bool,

    /// Allow downloading the root.json file (unsafe)
    #[arg(long)]
    allow_root_download: bool,

    /// Output directory of metadata
    #[arg(long)]
    metadata_dir: PathBuf,

    /// Only download the repository metadata, not the targets
    #[arg(long, conflicts_with_all(&["target_names", "targets_dir", "targets_base_url"]))]
    metadata_only: bool,

    /// TUF repository metadata base URL
    #[arg(short, long = "metadata-url")]
    metadata_base_url: Url,

    /// Path to root.json file for the repository
    #[arg(short, long, required_if_eq("allow_root_download", "false"))]
    root: Option<PathBuf>,

    /// Download only these targets, if specified
    #[arg(short = 'n', long, conflicts_with = "metadata_only")]
    target_names: Vec<String>,

    /// Output directory of targets
    #[arg(long, required_unless_present = "metadata_only")]
    targets_dir: Option<PathBuf>,

    /// TUF repository targets base URL
    #[arg(short, long = "targets-url", required_unless_present = "metadata_only")]
    targets_base_url: Option<Url>,

    /// Remote root.json version number
    #[arg(short = 'v', long, default_value = "1")]
    root_version: NonZeroU64,
}

#[rustfmt::skip]
fn expired_repo_warning() {
    eprintln!("\
=================================================================
WARNING: repo metadata is expired, meaning the owner hasn't verified its contents lately and it could be unsafe!
=================================================================");
}

impl CloneArgs {
    pub(crate) async fn run(&self) -> Result<()> {
        // Use local root.json or download from repository
        let root_path = if let Some(path) = &self.root {
            PathBuf::from(path)
        } else if self.allow_root_download {
            let outdir = std::env::current_dir().context(error::CurrentDirSnafu)?;
            download_root(&self.metadata_base_url, self.root_version, outdir).await?
        } else {
            eprintln!("No root.json available");
            std::process::exit(1);
        };

        // Clap won't allow `targets_base_url` to be None when it is required.  We require the
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
            &tokio::fs::read(&root_path)
                .await
                .context(error::OpenRootSnafu { path: &root_path })?,
            self.metadata_base_url.clone(),
            targets_base_url,
        )
        .expiration_enforcement(expiration_enforcement)
        .load()
        .await
        .context(error::RepoLoadSnafu)?;

        // Clone the repository, downloading none, all, or a subset of targets
        if self.metadata_only {
            println!("Cloning repository metadata to {:?}", self.metadata_dir);
            repository
                .cache_metadata(&self.metadata_dir, true)
                .await
                .context(error::CloneRepositorySnafu)?;
        } else {
            // Similar to `targets_base_url, structopt's guard rails won't let us have a
            // `targets_dir` that is None when the argument is required.  We only require the user
            // to supply a targets directory if they actually plan on downloading targets.
            let targets_dir = self.targets_dir.as_ref().expect(
                "Developer error: `targets_dir` is required unless downloading metadata only",
            );

            println!(
                "Cloning repository:\n\tmetadata location: {:?}\n\ttargets location: {targets_dir:?}",
                self.metadata_dir
            );
            if self.target_names.is_empty() {
                repository
                    .cache(&self.metadata_dir, targets_dir, None::<&[&str]>, true)
                    .await
                    .context(error::CloneRepositorySnafu)?;
            } else {
                repository
                    .cache(
                        &self.metadata_dir,
                        targets_dir,
                        Some(self.target_names.as_slice()),
                        true,
                    )
                    .await
                    .context(error::CloneRepositorySnafu)?;
            }
        };

        Ok(())
    }
}
