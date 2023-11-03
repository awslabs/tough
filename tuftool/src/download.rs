// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::download_root::download_root;
use crate::error::{self, Result};
use clap::Parser;
use snafu::{ensure, ResultExt};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use tough::{ExpirationEnforcement, Prefix, Repository, RepositoryLoader, TargetName};
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct DownloadArgs {
    /// Allow repo download for expired metadata
    #[clap(long)]
    allow_expired_repo: bool,

    /// Allow downloading the root.json file (unsafe)
    #[clap(long)]
    allow_root_download: bool,

    /// TUF repository metadata base URL
    #[clap(short, long = "metadata-url")]
    metadata_base_url: Url,

    /// Download only these targets, if specified
    #[clap(short = 'n', long = "target-name")]
    target_names: Vec<String>,

    /// Path to root.json file for the repository
    #[clap(short, long)]
    root: Option<PathBuf>,

    /// TUF repository targets base URL
    #[clap(short, long = "targets-url")]
    targets_base_url: Url,

    /// Output directory for targets (will be created and must not already exist)
    outdir: PathBuf,

    /// Remote root.json version number
    #[clap(short = 'v', long, default_value = "1")]
    root_version: NonZeroU64,
}

fn expired_repo_warning<P: AsRef<Path>>(path: P) {
    #[rustfmt::skip]
    eprintln!("\
=================================================================
Downloading repo to {}
WARNING: `--allow-expired-repo` was passed; this is unsafe and will not establish trust, use only for testing!
=================================================================",
              path.as_ref().display());
}

impl DownloadArgs {
    pub(crate) async fn run(&self) -> Result<()> {
        // To help ensure that downloads are safe, we require that the outdir does not exist.
        ensure!(
            !self.outdir.exists(),
            error::DownloadOutdirExistsSnafu { path: &self.outdir }
        );

        // use local root.json or download from repository
        let root_path = if let Some(path) = &self.root {
            PathBuf::from(path)
        } else if self.allow_root_download {
            let outdir = std::env::current_dir().context(error::CurrentDirSnafu)?;
            download_root(&self.metadata_base_url, self.root_version, outdir).await?
        } else {
            eprintln!("No root.json available");
            std::process::exit(1);
        };

        // load repository
        let expiration_enforcement = if self.allow_expired_repo {
            expired_repo_warning(&self.outdir);
            ExpirationEnforcement::Unsafe
        } else {
            ExpirationEnforcement::Safe
        };
        let repository = RepositoryLoader::new(
            &tokio::fs::read(&root_path)
                .await
                .context(error::OpenRootSnafu { path: &root_path })?,
            self.metadata_base_url.clone(),
            self.targets_base_url.clone(),
        )
        .expiration_enforcement(expiration_enforcement)
        .load()
        .await
        .context(error::RepoLoadSnafu)?;

        // download targets
        handle_download(&repository, &self.outdir, &self.target_names).await
    }
}

async fn handle_download(
    repository: &Repository,
    outdir: &Path,
    raw_names: &[String],
) -> Result<()> {
    let target_names: Result<Vec<TargetName>> = raw_names
        .iter()
        .map(|s| TargetName::new(s).context(error::InvalidTargetNameSnafu))
        .collect();
    let target_names = target_names?;
    let download_target = |name: TargetName| async move {
        println!("\t-> {}", name.raw());
        repository
            .save_target(&name, outdir, Prefix::None)
            .await
            .context(error::MetadataSnafu)?;
        Ok(())
    };

    // copy requested targets, or all available targets if not specified
    let targets: Vec<TargetName> = if target_names.is_empty() {
        repository
            .targets()
            .signed
            .targets
            .keys()
            .cloned()
            .collect()
    } else {
        target_names
    };

    println!("Downloading targets to {outdir:?}");
    tokio::fs::create_dir_all(outdir)
        .await
        .context(error::DirCreateSnafu { path: outdir })?;
    for target in targets {
        download_target(target).await?;
    }
    Ok(())
}
