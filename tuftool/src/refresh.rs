// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::metadata;
use crate::root_digest::RootDigest;
use crate::source::KeySource;
use chrono::{DateTime, Utc};
use maplit::hashmap;
use ring::rand::SystemRandom;
use snafu::ResultExt;
use std::collections::HashMap;
use std::fs::File;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use structopt::StructOpt;
use tough::schema::{Hashes, Snapshot, SnapshotMeta, Targets, Timestamp, TimestampMeta};
use tough::{FilesystemTransport, HttpTransport, Limits, Repository, Transport};
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
}

impl RefreshArgs {
    pub(crate) fn run(&self) -> Result<()> {
        if let Some(jobs) = self.jobs {
            rayon::ThreadPoolBuilder::new()
                .num_threads(usize::from(jobs))
                .build_global()
                .context(error::InitializeThreadPool)?;
        }

        let settings = tough::Settings {
            root: File::open(&self.root).unwrap(),
            datastore: self.workdir.as_path(),
            metadata_base_url: self.metadata_base_url.as_str(),
            target_base_url: self.metadata_base_url.as_str(),
            limits: Limits::default(),
        };

        if self.metadata_base_url.scheme() == "file" {
            let repository =
                Repository::load(&FilesystemTransport, settings).context(error::Metadata)?;
            self.refresh(&repository)
        } else {
            let transport = HttpTransport::new();
            let repository = Repository::load(&transport, settings).context(error::Metadata)?;
            self.refresh(&repository)
        }
    }

    fn refresh<'a, T: Transport>(&self, repository: &Repository<'a, T>) -> Result<()> {
        // clone the targets.json file but with a new version number and expiration date
        let new_targets = Targets {
            spec_version: crate::SPEC_VERSION.to_owned(),
            version: self.targets_version,
            expires: self.targets_expires,
            targets: repository.targets().signed.targets.clone(),
            _extra: repository.targets().signed._extra.clone(),
        };

        // load the root.json file
        let root_digest = RootDigest::load(&self.root)?;

        // match the command line keys to the root.json keys
        let keys = root_digest.load_keys(&self.keys)?;

        // sign and write out the new targets.json file
        let rng = SystemRandom::new();
        let (targets_sha256, targets_length) = metadata::write_metadata(
            &self.outdir,
            &repository.root().signed,
            &keys,
            new_targets,
            self.targets_version,
            "targets.json",
            &rng,
        )?;

        // create, sign and write out the snapshot file
        let (snapshot_sha256, snapshot_length) = metadata::write_metadata(
            &self.outdir,
            &repository.root().signed,
            &keys,
            Snapshot {
                spec_version: crate::SPEC_VERSION.to_owned(),
                version: self.snapshot_version,
                expires: self.snapshot_expires,
                meta: hashmap! {
                    "root.json".to_owned() => SnapshotMeta {
                        hashes: Some(Hashes {
                            sha256: root_digest.digest.to_vec().into(),
                            _extra: HashMap::new(),
                        }),
                        length: Some(root_digest.size),
                        version: repository.root().signed.version,
                        _extra: HashMap::new(),
                    },
                    "targets.json".to_owned() => SnapshotMeta {
                        hashes: Some(Hashes {
                            sha256: targets_sha256.to_vec().into(),
                            _extra: HashMap::new(),
                        }),
                        length: Some(targets_length),
                        version: self.targets_version,
                        _extra: HashMap::new(),
                    },
                },
                _extra: HashMap::new(),
            },
            self.snapshot_version,
            "snapshot.json",
            &rng,
        )?;

        // create, sign and write out the timestamp file
        metadata::write_metadata(
            &self.outdir,
            &repository.root().signed,
            &keys,
            Timestamp {
                spec_version: crate::SPEC_VERSION.to_owned(),
                version: self.timestamp_version,
                expires: self.timestamp_expires,
                meta: hashmap! {
                    "snapshot.json".to_owned() => TimestampMeta {
                        hashes: Hashes {
                            sha256: snapshot_sha256.to_vec().into(),
                            _extra: HashMap::new(),
                        },
                        length: snapshot_length,
                        version: self.snapshot_version,
                        _extra: HashMap::new(),
                    }
                },
                _extra: HashMap::new(),
            },
            self.timestamp_version,
            "timestamp.json",
            &rng,
        )?;

        Ok(())
    }
}
