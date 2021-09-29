// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::download_root::download_root;
use crate::error::{self, Result};
use snafu::{ensure, ResultExt};
use std::fs::File;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use tough::{ExpirationEnforcement, Prefix, Repository, RepositoryLoader, TargetName};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct DownloadArgs {
    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: Option<PathBuf>,

    /// Remote root.json version number
    #[structopt(short = "v", long = "root-version", default_value = "1")]
    root_version: NonZeroU64,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// TUF repository targets base URL
    #[structopt(short = "t", long = "targets-url")]
    targets_base_url: Url,

    /// Allow downloading the root.json file (unsafe)
    #[structopt(long)]
    allow_root_download: bool,

    /// Download only these targets, if specified
    #[structopt(short = "n", long = "target-name")]
    target_names: Vec<String>,

    /// Output directory for targets (will be created and must not already exist)
    outdir: PathBuf,

    /// Allow repo download for expired metadata
    #[structopt(long)]
    allow_expired_repo: bool,
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
    pub(crate) fn run(&self) -> Result<()> {
        // To help ensure that downloads are safe, we require that the outdir does not exist.
        ensure!(
            !self.outdir.exists(),
            error::DownloadOutdirExists { path: &self.outdir }
        );

        // use local root.json or download from repository
        let root_path = if let Some(path) = &self.root {
            PathBuf::from(path)
        } else if self.allow_root_download {
            let outdir = std::env::current_dir().context(error::CurrentDir)?;
            download_root(&self.metadata_base_url, self.root_version, outdir)?
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
            File::open(&root_path).context(error::OpenRoot { path: &root_path })?,
            self.metadata_base_url.clone(),
            self.targets_base_url.clone(),
        )
        .expiration_enforcement(expiration_enforcement)
        .load()
        .context(error::RepoLoad)?;

        // download targets
        handle_download(&repository, &self.outdir, &self.target_names)
    }
}

fn handle_download(repository: &Repository, outdir: &Path, raw_names: &[String]) -> Result<()> {
    let target_names: Result<Vec<TargetName>> = raw_names
        .iter()
        .map(|s| TargetName::new(s).context(error::InvalidTargetName))
        .collect();
    let target_names = target_names?;
    let download_target = |name: &TargetName| -> Result<()> {
        println!("\t-> {}", name.raw());
        repository
            .save_target(name, outdir, Prefix::None)
            .context(error::Metadata)?;
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

    println!("Downloading targets to {:?}", outdir);
    std::fs::create_dir_all(outdir).context(error::DirCreate { path: outdir })?;
    for target in targets {
        download_target(&target)?;
    }
    Ok(())
}
