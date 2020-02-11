// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::copylike::Copylike;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::key::RootKeys;
use crate::metadata;
use crate::root_digest::RootDigest;
use crate::source::KeySource;
use chrono::{DateTime, Utc};
use maplit::hashmap;
use rayon::prelude::*;
use ring::digest::{Context, SHA256, SHA256_OUTPUT_LEN};
use ring::rand::SystemRandom;
use serde::Serialize;
use snafu::{OptionExt, ResultExt};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use tough::schema::{
    decoded::Decoded, Hashes, Role, Snapshot, SnapshotMeta, Target, Targets, Timestamp,
    TimestampMeta,
};
use walkdir::WalkDir;

#[derive(Debug, StructOpt)]
pub(crate) struct CreateArgs {
    /// Copy files into `outdir` instead of symlinking them
    #[structopt(short = "c", long = "copy")]
    copy: bool,
    /// Hardlink files into `outdir` instead of symlinking them
    #[structopt(short = "H", long = "hardlink")]
    hardlink: bool,

    /// Follow symbolic links in `indir`
    #[structopt(short = "f", long = "follow")]
    follow: bool,

    /// Number of target hashing threads to run (default: number of cores)
    #[structopt(short = "j", long = "jobs")]
    jobs: Option<NonZeroUsize>,

    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true)]
    keys: Vec<KeySource>,

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

    /// Directory of targets
    indir: PathBuf,
    /// Repository output directory
    outdir: PathBuf,
}

impl CreateArgs {
    pub(crate) fn run(&self) -> Result<()> {
        if let Some(jobs) = self.jobs {
            rayon::ThreadPoolBuilder::new()
                .num_threads(usize::from(jobs))
                .build_global()
                .context(error::InitializeThreadPool)?;
        }

        let root_digest = RootDigest::load(&self.root)?;
        let key_pairs = root_digest.load_keys(&self.keys)?;

        CreateProcess {
            args: self,
            keys: key_pairs,
            rng: SystemRandom::new(),
            root_digest,
        }
        .run()
    }
}

struct CreateProcess<'a> {
    args: &'a CreateArgs,
    rng: SystemRandom,
    root_digest: RootDigest,
    keys: RootKeys,
}

impl<'a> CreateProcess<'a> {
    fn run(self) -> Result<()> {
        let root_path = self
            .args
            .outdir
            .join("metadata")
            .join(format!("{}.root.json", self.root_digest.root.version));
        self.copy_action()
            .run(&self.args.root, &root_path)
            .context(error::FileCopy {
                action: self.copy_action(),
                src: &self.args.root,
                dst: root_path,
            })?;

        let (targets_sha256, targets_length) = self.write_metadata(
            Targets {
                spec_version: crate::SPEC_VERSION.to_owned(),
                version: self.args.targets_version,
                expires: self.args.targets_expires,
                targets: self.build_targets()?,
                _extra: HashMap::new(),
            },
            self.args.targets_version,
            "targets.json",
        )?;

        let (snapshot_sha256, snapshot_length) = self.write_metadata(
            Snapshot {
                spec_version: crate::SPEC_VERSION.to_owned(),
                version: self.args.snapshot_version,
                expires: self.args.snapshot_expires,
                meta: hashmap! {
                    "root.json".to_owned() => SnapshotMeta {
                        hashes: Some(Hashes {
                            sha256: self.root_digest.digest.to_vec().into(),
                            _extra: HashMap::new(),
                        }),
                        length: Some(self.root_digest.size),
                        version: self.root_digest.root.version,
                        _extra: HashMap::new(),
                    },
                    "targets.json".to_owned() => SnapshotMeta {
                        hashes: Some(Hashes {
                            sha256: targets_sha256.to_vec().into(),
                            _extra: HashMap::new(),
                        }),
                        length: Some(targets_length),
                        version: self.args.targets_version,
                        _extra: HashMap::new(),
                    },
                },
                _extra: HashMap::new(),
            },
            self.args.snapshot_version,
            "snapshot.json",
        )?;

        self.write_metadata(
            Timestamp {
                spec_version: crate::SPEC_VERSION.to_owned(),
                version: self.args.timestamp_version,
                expires: self.args.timestamp_expires,
                meta: hashmap! {
                    "snapshot.json".to_owned() => TimestampMeta {
                        hashes: Hashes {
                            sha256: snapshot_sha256.to_vec().into(),
                            _extra: HashMap::new(),
                        },
                        length: snapshot_length,
                        version: self.args.snapshot_version,
                        _extra: HashMap::new(),
                    }
                },
                _extra: HashMap::new(),
            },
            self.args.timestamp_version,
            "timestamp.json",
        )?;

        Ok(())
    }

    // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

    fn copy_action(&self) -> Copylike {
        match (self.args.copy, self.args.hardlink) {
            (true, _) => Copylike::Copy, // --copy overrides --hardlink
            (false, true) => Copylike::Hardlink,
            (false, false) => Copylike::Symlink,
        }
    }

    fn build_targets(&self) -> Result<HashMap<String, Target>> {
        WalkDir::new(&self.args.indir)
            .follow_links(self.args.follow)
            .into_iter()
            .par_bridge()
            .filter_map(|entry| match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        Some(self.process_target(entry.path()))
                    } else {
                        None
                    }
                }
                Err(err) => Some(Err(err).context(error::WalkDir)),
            })
            .collect()
    }

    fn process_target(&self, path: &Path) -> Result<(String, Target)> {
        let target_name = path.strip_prefix(&self.args.indir).context(error::Prefix {
            path,
            base: &self.args.indir,
        })?;
        let target_name = target_name
            .to_str()
            .context(error::PathUtf8 { path: target_name })?
            .to_owned();

        let mut file = File::open(path).context(error::FileOpen { path })?;
        let mut digest = Context::new(&SHA256);
        let mut buf = [0; 8 * 1024];
        let mut length = 0;
        loop {
            match file.read(&mut buf).context(error::FileRead { path })? {
                0 => break,
                n => {
                    digest.update(&buf[..n]);
                    length += n as u64;
                }
            }
        }

        let target = Target {
            length,
            hashes: Hashes {
                sha256: Decoded::from(digest.finish().as_ref().to_vec()),
                _extra: HashMap::new(),
            },
            custom: HashMap::new(),
            _extra: HashMap::new(),
        };

        let dst = if self.root_digest.root.consistent_snapshot {
            self.args.outdir.join("targets").join(format!(
                "{}.{}",
                hex::encode(&target.hashes.sha256),
                target_name
            ))
        } else {
            self.args.outdir.join("targets").join(&target_name)
        };
        self.copy_action()
            .run(path, &dst)
            .context(error::FileCopy {
                action: self.copy_action(),
                src: path,
                dst,
            })?;

        Ok((target_name, target))
    }

    // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

    fn write_metadata<T: Role + Serialize>(
        &self,
        role: T,
        version: NonZeroU64,
        filename: &'static str,
    ) -> Result<([u8; SHA256_OUTPUT_LEN], u64)> {
        metadata::write_metadata(
            &self.args.outdir,
            &self.root_digest.root,
            &self.keys,
            role,
            version,
            filename,
            &self.rng,
        )
    }
}
