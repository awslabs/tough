// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};
use snafu::{OptionExt, ResultExt};
use std::fs::{File, OpenOptions};
use std::io::{self};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use tempfile::tempdir;
use tough::http::HttpTransport;
use tough::{ExpirationEnforcement, Limits, Repository, Settings};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct DownloadArgs {
    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: Option<PathBuf>,

    /// Remote root.json version number
    #[structopt(short = "v", long = "root-version")]
    root_version: Option<NonZeroU64>,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: String,

    /// TUF repository target base URL
    #[structopt(short = "t", long = "target-url")]
    targets_base_url: String,

    /// Allow downloading the root.json file (unsafe)
    #[structopt(long)]
    allow_root_download: bool,

    /// Output directory of targets
    outdir: PathBuf,
}

fn root_warning<P: AsRef<Path>>(path: P) {
    #[rustfmt::skip]
    eprintln!("\
=================================================================
WARNING: Downloading root.json to {}
This is unsafe and will not establish trust, use only for testing
=================================================================",
              path.as_ref().display());
}

impl DownloadArgs {
    pub(crate) fn run(&self) -> Result<()> {
        // use local root.json or download from repository
        let root_path = if let Some(path) = &self.root {
            PathBuf::from(path)
        } else if self.allow_root_download {
            let name = if let Some(version) = self.root_version {
                format!("{}.root.json", version)
            } else {
                String::from("1.root.json")
            };
            let path = std::env::current_dir()
                .context(error::CurrentDir)?
                .join(&name);
            let url = Url::parse(&self.metadata_base_url)
                .context(error::UrlParse {
                    url: &self.metadata_base_url,
                })?
                .join(&name)
                .context(error::UrlParse {
                    url: &self.metadata_base_url,
                })?;

            root_warning(&path);

            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&path)
                .context(error::OpenFile { path: &path })?;
            reqwest::blocking::get(url.as_str())
                .context(error::ReqwestGet)?
                .copy_to(&mut f)
                .context(error::ReqwestCopy)?;
            path
        } else {
            eprintln!("No root.json available");
            std::process::exit(1);
        };

        // load repository
        let transport = HttpTransport::new();
        let repo_dir = tempdir().context(error::TempDir)?;
        let repository = Repository::load(
            &transport,
            Settings {
                root: File::open(&root_path).context(error::OpenRoot { path: &root_path })?,
                datastore: repo_dir.path(),
                metadata_base_url: &self.metadata_base_url,
                targets_base_url: &self.targets_base_url,
                limits: Limits {
                    ..tough::Limits::default()
                },
                expiration_enforcement: ExpirationEnforcement::Safe,
            },
        )
        .context(error::Metadata)?;

        // copy all available targets
        println!("Downloading targets to {:?}", &self.outdir);
        std::fs::create_dir_all(&self.outdir).context(error::DirCreate { path: &self.outdir })?;
        for target in repository.targets().signed.targets.keys() {
            let path = PathBuf::from(&self.outdir).join(target);
            println!("\t-> {}", &target);
            let mut reader = repository
                .read_target(target)
                .context(error::Metadata)?
                .context(error::TargetNotFound { target })?;
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&path)
                .context(error::OpenFile { path: &path })?;
            io::copy(&mut reader, &mut f).context(error::WriteTarget)?;
        }
        Ok(())
    }
}
