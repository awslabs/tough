// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};
use snafu::{OptionExt, ResultExt};
use std::fs::File;
use std::io::{self};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use tough::http::HttpTransport;
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository, Settings, Transport};
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
    metadata_base_url: Url,

    /// TUF repository target base URL
    #[structopt(short = "t", long = "target-url")]
    targets_base_url: Url,

    /// Allow downloading the root.json file (unsafe)
    #[structopt(long)]
    allow_root_download: bool,

    /// Download only these targets, if specified
    #[structopt(short = "n", long = "target-name")]
    target_names: Vec<String>,

    /// Output directory of targets
    outdir: PathBuf,

    /// Allow repo download for expired metadata
    #[structopt(long)]
    allow_expired_repo: bool,
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
            let url = self
                .metadata_base_url
                .join(&name)
                .context(error::UrlParse {
                    url: self.metadata_base_url.as_str(),
                })?;
            root_warning(&path);

            let mut f = File::create(&path).context(error::OpenFile { path: &path })?;
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
        let settings = Settings {
            root: File::open(&root_path).context(error::OpenRoot { path: &root_path })?,
            datastore: None,
            metadata_base_url: self.metadata_base_url.to_string(),
            targets_base_url: self.targets_base_url.to_string(),
            limits: Limits {
                ..tough::Limits::default()
            },
            expiration_enforcement: if self.allow_expired_repo {
                expired_repo_warning(&self.outdir);
                ExpirationEnforcement::Unsafe
            } else {
                ExpirationEnforcement::Safe
            },
        };
        if self.metadata_base_url.scheme() == "file" {
            let transport = FilesystemTransport;
            let repository = Repository::load(&transport, settings).context(error::Metadata)?;
            handle_download(&repository, &self.outdir, &self.target_names)?;
        } else {
            let transport = HttpTransport::new();
            let repository = Repository::load(&transport, settings).context(error::Metadata)?;
            handle_download(&repository, &self.outdir, &self.target_names)?;
        };
        Ok(())
    }
}

fn handle_download<T: Transport>(
    repository: &Repository<'_, T>,
    outdir: &PathBuf,
    target_names: &[String],
) -> Result<()> {
    let download_target = |target: &str| -> Result<()> {
        let path = PathBuf::from(outdir).join(target);
        println!("\t-> {}", &target);
        let mut reader = repository
            .read_target(target)
            .context(error::Metadata)?
            .context(error::TargetNotFound { target })?;
        let mut f = File::create(&path).context(error::OpenFile { path: &path })?;
        io::copy(&mut reader, &mut f).context(error::WriteTarget)?;
        Ok(())
    };

    // copy requested targets, or all available targets if not specified
    let targets = if target_names.is_empty() {
        repository
            .targets()
            .signed
            .targets
            .keys()
            .cloned()
            .collect()
    } else {
        target_names.to_owned()
    };

    println!("Downloading targets to {:?}", outdir);
    std::fs::create_dir_all(outdir).context(error::DirCreate { path: outdir })?;
    for target in targets {
        download_target(&target)?;
    }
    Ok(())
}
