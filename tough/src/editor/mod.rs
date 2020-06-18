// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::used_underscore_binding)] // #20

mod keys;
pub mod signed;
mod test;

use crate::editor::signed::{SignedRepository, SignedRole};
use crate::error::{self, Result};
use crate::key_source::KeySource;
use crate::schema::{
    Hashes, Role, Root, Signed, Snapshot, SnapshotMeta, Target, Targets, Timestamp, TimestampMeta,
};
use crate::transport::Transport;
use crate::Repository;
use chrono::{DateTime, Utc};
use ring::digest::{SHA256, SHA256_OUTPUT_LEN};
use ring::rand::SystemRandom;
use serde_json::Value;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::Path;

const SPEC_VERSION: &str = "1.0.0";

/// `RepositoryEditor` contains the various bits of data needed to construct
/// or edit a TUF repository.
///
/// A new repository may be started using the `new()` method.
///
/// An existing `tough::Repository` may be loaded and edited using the
/// `from_repo()` method. When a repo is loaded in this way, versions and
/// expirations are discarded. It is good practice to update these whenever
/// a repo is changed.
///
/// Targets, versions, and expirations may be added to their respective roles
/// via the provided "setter" methods. The final step in the process is the
/// `sign()` method, which takes a given set of signing keys, builds each of
/// the roles using the data provided, and signs the roles. This results in a
/// `SignedRepository` which can be used to write the repo to disk.
#[derive(Debug)]
pub struct RepositoryEditor {
    signed_root: SignedRole<Root>,

    new_targets: Option<HashMap<String, Target>>,
    existing_targets: Option<HashMap<String, Target>>,
    targets_version: Option<NonZeroU64>,
    targets_expires: Option<DateTime<Utc>>,
    targets_extra: Option<HashMap<String, Value>>,

    snapshot_version: Option<NonZeroU64>,
    snapshot_expires: Option<DateTime<Utc>>,
    snapshot_extra: Option<HashMap<String, Value>>,

    timestamp_version: Option<NonZeroU64>,
    timestamp_expires: Option<DateTime<Utc>>,
    timestamp_extra: Option<HashMap<String, Value>>,
}

impl RepositoryEditor {
    /// Create a new, bare `RepositoryEditor`
    pub fn new<P>(root_path: P) -> Result<RepositoryEditor>
    where
        P: AsRef<Path>,
    {
        // Read and parse the root.json. Without a good root, it doesn't
        // make sense to continue
        let root_path = root_path.as_ref();
        let root_buf = std::fs::read(root_path).context(error::FileRead { path: root_path })?;
        let root_buf_len = root_buf.len() as u64;
        let root = serde_json::from_slice::<Signed<Root>>(&root_buf)
            .context(error::FileParseJson { path: root_path })?;
        let mut digest = [0; SHA256_OUTPUT_LEN];
        digest.copy_from_slice(ring::digest::digest(&SHA256, &root_buf).as_ref());

        let signed_root = SignedRole {
            signed: root,
            buffer: root_buf,
            sha256: digest,
            length: root_buf_len,
        };

        Ok(RepositoryEditor {
            signed_root,
            new_targets: None,
            existing_targets: None,
            targets_version: None,
            targets_expires: None,
            targets_extra: None,
            snapshot_version: None,
            snapshot_expires: None,
            snapshot_extra: None,
            timestamp_version: None,
            timestamp_expires: None,
            timestamp_extra: None,
        })
    }

    /// Given a `tough::Repository` and the path to a valid root.json, create a
    /// `RepositoryEditor`. This `RepositoryEditor` will include all of the targets
    /// and bits of _extra metadata from the roles included. It will not, however,
    /// include the versions or expirations and the user is expected to set them.
    pub fn from_repo<T, P>(root_path: P, repo: Repository<'_, T>) -> Result<RepositoryEditor>
    where
        P: AsRef<Path>,
        T: Transport,
    {
        let mut editor = RepositoryEditor::new(root_path)?;
        editor.targets(repo.targets.signed)?;
        editor.snapshot(repo.snapshot.signed)?;
        editor.timestamp(repo.timestamp.signed)?;

        Ok(editor)
    }

    /// Builds and signs each required role and returns a complete signed set
    /// of TUF repository metadata.
    ///
    /// While `RepositoryEditor`s fields are all `Option`s, this step requires,
    /// at the very least, that the "version" and "expiration" field is set for
    /// each role; e.g. `targets_version`, `targets_expires`, etc.
    pub fn sign(self, keys: &[Box<dyn KeySource>]) -> Result<SignedRepository> {
        let rng = SystemRandom::new();
        let root = &self.signed_root.signed.signed;

        let signed_targets = self
            .build_targets()
            .and_then(|targets| SignedRole::new(targets, root, keys, &rng))?;
        let signed_snapshot = self
            .build_snapshot(&signed_targets)
            .and_then(|snapshot| SignedRole::new(snapshot, root, keys, &rng))?;
        let signed_timestamp = self
            .build_timestamp(&signed_snapshot)
            .and_then(|timestamp| SignedRole::new(timestamp, root, keys, &rng))?;

        Ok(SignedRepository {
            root: self.signed_root,
            targets: signed_targets,
            snapshot: signed_snapshot,
            timestamp: signed_timestamp,
        })
    }

    /// Add an existing `Targets` struct to the repository. Any `Target`
    /// objects contained in the `Targets` struct will be preserved in
    /// `self.existing_targets`
    pub fn targets(&mut self, targets: Targets) -> Result<&mut Self> {
        ensure!(
            targets.spec_version == SPEC_VERSION,
            error::SpecVersion {
                given: targets.spec_version,
                supported: SPEC_VERSION
            }
        );

        // Hold on to the existing targets
        self.existing_targets = Some(targets.targets);
        self.targets_extra = Some(targets._extra);
        Ok(self)
    }

    /// Add an existing `Snapshot` to the repository. Only the `_extra` data
    /// is preserved
    pub fn snapshot(&mut self, snapshot: Snapshot) -> Result<&mut Self> {
        ensure!(
            snapshot.spec_version == SPEC_VERSION,
            error::SpecVersion {
                given: snapshot.spec_version,
                supported: SPEC_VERSION
            }
        );
        self.snapshot_extra = Some(snapshot._extra);
        Ok(self)
    }

    /// Add an existing `Timestamp` to the repository. Only the `_extra` data
    /// is preserved
    pub fn timestamp(&mut self, timestamp: Timestamp) -> Result<&mut Self> {
        ensure!(
            timestamp.spec_version == SPEC_VERSION,
            error::SpecVersion {
                given: timestamp.spec_version,
                supported: SPEC_VERSION
            }
        );
        self.timestamp_extra = Some(timestamp._extra);
        Ok(self)
    }

    /// Add a `Target` to the repository
    pub fn add_target(&mut self, name: String, target: Target) -> &mut Self {
        self.new_targets
            .get_or_insert_with(HashMap::new)
            .insert(name, target);
        self
    }

    /// Add a target to the repository using its path
    ///
    /// Note: This function builds a `Target` synchronously;
    /// no multithreading or parallelism is used. If you have a large number
    /// of targets to add, and require advanced performance, you may want to
    /// construct `Target`s directly in parallel and use `add_target()`.
    pub fn add_target_path<P>(&mut self, target_path: P) -> Result<&mut Self>
    where
        P: AsRef<Path>,
    {
        let target_path = target_path.as_ref();

        // Build a Target from the path given. If it is not a file, this will fail
        let target =
            Target::from_path(target_path).context(error::TargetFromPath { path: target_path })?;

        // Get the file name as a string
        let target_name = target_path
            .file_name()
            .context(error::NoFileName { path: target_path })?
            .to_str()
            .context(error::PathUtf8 { path: target_path })?
            .to_owned();

        self.add_target(target_name, target);
        Ok(self)
    }

    /// Add a list of target paths to the repository
    ///
    /// See the note on `add_target_path()` regarding performance.
    pub fn add_target_paths<P>(&mut self, targets: Vec<P>) -> Result<&mut Self>
    where
        P: AsRef<Path>,
    {
        for target in targets {
            self.add_target_path(target)?;
        }
        Ok(self)
    }

    /// Remove all targets from this repo
    pub fn clear_targets(&mut self) -> &mut Self {
        self.existing_targets
            .get_or_insert_with(HashMap::new)
            .clear();
        self.new_targets.get_or_insert_with(HashMap::new).clear();
        self
    }

    /// Set the `Snapshot` version
    pub fn snapshot_version(&mut self, snapshot_version: NonZeroU64) -> &mut Self {
        self.snapshot_version = Some(snapshot_version);
        self
    }

    /// Set the `Snapshot` expiration
    pub fn snapshot_expires(&mut self, snapshot_expires: DateTime<Utc>) -> &mut Self {
        self.snapshot_expires = Some(snapshot_expires);
        self
    }

    /// Set the `Targets` version
    pub fn targets_version(&mut self, targets_version: NonZeroU64) -> &mut Self {
        self.targets_version = Some(targets_version);
        self
    }

    /// Set the `Targets` expiration
    pub fn targets_expires(&mut self, targets_expires: DateTime<Utc>) -> &mut Self {
        self.targets_expires = Some(targets_expires);
        self
    }

    /// Set the `Timestamp` version
    pub fn timestamp_version(&mut self, timestamp_version: NonZeroU64) -> &mut Self {
        self.timestamp_version = Some(timestamp_version);
        self
    }

    /// Set the `Timestamp` expiration
    pub fn timestamp_expires(&mut self, timestamp_expires: DateTime<Utc>) -> &mut Self {
        self.timestamp_expires = Some(timestamp_expires);
        self
    }

    // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

    /// Build the `Targets` struct
    fn build_targets(&self) -> Result<Targets> {
        let version = self.targets_version.context(error::Missing {
            field: "targets version",
        })?;
        let expires = self.targets_expires.context(error::Missing {
            field: "targets expiration",
        })?;

        // BEWARE!!! We are allowing targets to be empty! While this isn't
        // the most common use case, it's possible this is what a user wants.
        // If it's important to have a non-empty targets, the object can be
        // inspected by the calling code.
        let mut targets: HashMap<String, Target> = HashMap::new();
        if let Some(ref existing_targets) = self.existing_targets {
            targets.extend(existing_targets.clone());
        }
        if let Some(ref new_targets) = self.new_targets {
            targets.extend(new_targets.clone());
        }

        let _extra = self.targets_extra.clone().unwrap_or_else(HashMap::new);
        Ok(Targets {
            spec_version: SPEC_VERSION.to_string(),
            version,
            expires,
            targets,
            _extra,
            delegations: None,
        })
    }

    /// Build the `Snapshot` struct
    fn build_snapshot(&self, signed_targets: &SignedRole<Targets>) -> Result<Snapshot> {
        let version = self.snapshot_version.context(error::Missing {
            field: "snapshot version",
        })?;
        let expires = self.snapshot_expires.context(error::Missing {
            field: "snapshot expiration",
        })?;
        let _extra = self.snapshot_extra.clone().unwrap_or_else(HashMap::new);

        let mut snapshot = Snapshot::new(SPEC_VERSION.to_string(), version, expires);

        // Snapshot stores metadata about targets and root
        let targets_meta = Self::snapshot_meta(signed_targets);
        let root_meta = Self::snapshot_meta(&self.signed_root);
        snapshot
            .meta
            .insert("targets.json".to_owned(), targets_meta);
        snapshot.meta.insert("root.json".to_owned(), root_meta);

        Ok(snapshot)
    }

    /// Build a `SnapshotMeta` struct from a given `SignedRole<T>`. This metadata
    /// includes the sha256 and length of the signed role.
    fn snapshot_meta<T>(role: &SignedRole<T>) -> SnapshotMeta
    where
        T: Role,
    {
        SnapshotMeta {
            hashes: Some(Hashes {
                sha256: role.sha256.to_vec().into(),
                _extra: HashMap::new(),
            }),
            length: Some(role.length),
            version: role.signed.signed.version(),
            _extra: HashMap::new(),
        }
    }

    /// Build the `Timestamp` struct
    fn build_timestamp(&self, signed_snapshot: &SignedRole<Snapshot>) -> Result<Timestamp> {
        let version = self.timestamp_version.context(error::Missing {
            field: "timestamp version",
        })?;
        let expires = self.timestamp_expires.context(error::Missing {
            field: "timestamp expiration",
        })?;
        let _extra = self.timestamp_extra.clone().unwrap_or_else(HashMap::new);
        let mut timestamp = Timestamp::new(SPEC_VERSION.to_string(), version, expires);

        // Timestamp stores metadata about snapshot
        let snapshot_meta = Self::timestamp_meta(signed_snapshot);
        timestamp
            .meta
            .insert("snapshot.json".to_owned(), snapshot_meta);
        timestamp._extra = _extra;

        Ok(timestamp)
    }

    /// Build a `TimestampMeta` struct from a given `SignedRole<T>`. This metadata
    /// includes the sha256 and length of the signed role.
    fn timestamp_meta<T>(role: &SignedRole<T>) -> TimestampMeta
    where
        T: Role,
    {
        TimestampMeta {
            hashes: Hashes {
                sha256: role.sha256.to_vec().into(),
                _extra: HashMap::new(),
            },
            length: role.length,
            version: role.signed.signed.version(),
            _extra: HashMap::new(),
        }
    }
}
