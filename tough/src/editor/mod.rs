// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::used_underscore_binding)] // #20

//! Provides a `RepositoryEditor` object for building and editing TUF repositories.

mod keys;
pub mod signed;
mod test;

use crate::editor::signed::copy_targets;
use crate::editor::signed::link_targets;
use crate::editor::signed::{SignedRepository, SignedRole};
use crate::error::{self, Result};
use crate::key_source::KeySource;
use crate::schema::decoded::{Decoded, Hex};
use crate::schema::{
    key::Key, DelegatedRole, Delegations, Hashes, PathSet, Role, Root, Signed, Snapshot,
    SnapshotMeta, Target, Targets, Timestamp, TimestampMeta,
};
use crate::transport::Transport;
use crate::Repository;
use chrono::{DateTime, Utc};
use ring::digest::{SHA256, SHA256_OUTPUT_LEN};
use ring::rand::SystemRandom;
use serde_json::Value;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::HashMap;
use std::convert::TryInto;
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

    targets_struct: Option<Targets>,

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
            targets_struct: Some(Targets::new(
                SPEC_VERSION.to_string(),
                NonZeroU64::new(1).unwrap(),
                Utc::now(),
            )),
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
        let signed_delegations = self
            .build_targets()
            .and_then(|targets| SignedRole::<Targets>::new_targets(&targets, keys, &rng, true))?;
        let signed_snapshot = self
            .build_snapshot(&signed_targets, &signed_delegations)
            .and_then(|snapshot| SignedRole::new(snapshot, root, keys, &rng))?;
        let signed_timestamp = self
            .build_timestamp(&signed_snapshot)
            .and_then(|timestamp| SignedRole::new(timestamp, root, keys, &rng))?;

        Ok(SignedRepository {
            root: self.signed_root,
            targets: signed_targets,
            snapshot: signed_snapshot,
            timestamp: signed_timestamp,
            delegations: signed_delegations,
        })
    }

    /// Sign delegated roles described in `names`. If no keys are provided for a role the current `Signed<Targets>` for the role is considered up to date.
    pub fn sign_roles(
        &self,
        keys: &[Box<dyn KeySource>],
        names: Vec<&str>,
    ) -> Result<HashMap<String, SignedRole<Targets>>> {
        let rng = SystemRandom::new();

        // Create `SignedRole` for each target
        let mut signed_roles = HashMap::new();
        let mut targets = self
            .build_targets()
            .and_then(|targets| SignedRole::<Targets>::new_targets(&targets, keys, &rng, false))?;

        // Take the signed targets we want
        for name in names {
            if name == "targets" {
                signed_roles.insert(
                    name.to_string(),
                    self.build_targets().and_then(|targets| {
                        SignedRole::new(targets, &self.signed_root.signed.signed, keys, &rng)
                    })?,
                );
                continue;
            }
            signed_roles.insert(
                name.to_string(),
                targets.remove(name).context(error::DelegateNotFound {
                    name: name.to_string(),
                })?,
            );
        }
        Ok(signed_roles)
    }

    /// Add an existing `Targets` struct to the repository.
    pub fn targets(&mut self, targets: Targets) -> Result<&mut Self> {
        ensure!(
            targets.spec_version == SPEC_VERSION,
            error::SpecVersion {
                given: targets.spec_version,
                supported: SPEC_VERSION
            }
        );
        // Hold on to the existing targets
        self.targets_struct = Some(targets);
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
        self.snapshot_version(snapshot.version);
        self.snapshot_expires(snapshot.expires);
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
        self.timestamp_expires(timestamp.expires());
        self.timestamp_version(timestamp.version);
        self.timestamp_extra = Some(timestamp._extra);
        Ok(self)
    }

    /// Add a `Target` to the repository
    pub fn add_target(&mut self, name: &str, target: Target) -> Result<&mut Self> {
        self.targets_struct
            .as_mut()
            .ok_or_else(|| error::Error::NoTargets)?
            .add_target(&name, target);

        Ok(self)
    }

    /// Remove a `Target` from the repository
    pub fn remove_target(&mut self, name: &str) -> Result<&mut Self> {
        self.targets_struct
            .as_mut()
            .ok_or_else(|| error::Error::NoTargets)?
            .remove_target(name);

        Ok(self)
    }

    /// Add a `Target` to the delegatee `role`
    pub fn add_target_to_delegatee(
        &mut self,
        name: &str,
        target: Target,
        role: &str,
    ) -> Result<&mut Self> {
        if role == "targets" {
            return self.add_target(name, target);
        }
        self.targets_struct
            .as_mut()
            .ok_or_else(|| error::Error::NoTargets)?
            .targets_by_name_verify_path(role, &name)
            .context(error::TargetsNotFound {
                name: name.to_string(),
            })?
            .add_target(&name, target);

        Ok(self)
    }

    /// Remove a `Target` from the delegatee `role`
    pub fn remove_target_from_delegatee(&mut self, name: &str, role: &str) -> Result<&mut Self> {
        if role == "targets" {
            return self.remove_target(name);
        }
        self.targets_struct
            .as_mut()
            .ok_or_else(|| error::Error::NoTargets)?
            .targets_by_name(role)
            .context(error::TargetsNotFound {
                name: name.to_string(),
            })?
            .remove_target(&name);

        Ok(self)
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
        let (target_name, target) = RepositoryEditor::build_target(target_path)?;
        self.add_target(&target_name, target)?;
        Ok(self)
    }

    /// Add a list of target paths to the repository
    ///
    /// See the note on `add_target_path()` regarding performance.
    pub fn add_target_paths<P>(&mut self, targets: Vec<P>, role: &str) -> Result<&mut Self>
    where
        P: AsRef<Path>,
    {
        let targets_struct = self
            .targets_struct
            .as_mut()
            .ok_or_else(|| error::Error::NoTargets)?;
        let cur_targets = match &role[..] {
            "targets" => targets_struct,
            _ => targets_struct
                .targets_by_name(role)
                .context(error::DelegateMissing { name: role })?,
        };
        for target in targets {
            let (target_name, target) = RepositoryEditor::build_target(target)?;
            cur_targets.add_target(&target_name, target);
        }

        Ok(self)
    }

    /// Builds a target struct for the given path
    pub fn build_target<P>(target_path: P) -> Result<(String, Target)>
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

        Ok((target_name, target))
    }

    /// Remove all targets from this repo
    pub fn clear_targets(&mut self) -> &mut Self {
        if let Some(targets) = self.targets_struct.as_mut() {
            targets.clear_targets();
        }
        self
    }

    /// Delegate target with name. If `key_source` is given, new keys are given to the role if not parent keys are used
    pub fn add_delegate(
        &mut self,
        from: &str,
        name: String,
        key_source: Option<&[Box<dyn KeySource>]>,
        paths: PathSet,
        expiration: DateTime<Utc>,
        version: NonZeroU64,
    ) -> Result<&mut Self> {
        // If we are delegating from targets all paths are valid
        if from != "targets" {
            let parent_delegated_role = self
                .targets_struct
                .as_ref()
                .ok_or_else(|| error::Error::NoTargets)?
                .delegated_role(from)
                .context(error::DelegateMissing {
                    name: from.to_string(),
                })?;
            // Verify that `from` has permission to delegate paths
            parent_delegated_role
                .verify_paths(&paths)
                .context(error::InvalidPathPermission {
                    name: from.to_string(),
                    paths: paths.vec().to_vec(),
                })?;
        }

        let targets = self
            .targets_struct
            .as_mut()
            .ok_or_else(|| error::Error::NoTargets)?;
        // Find the parent targets for the role we are creating
        let mut parent = if from == "targets" {
            targets
        } else {
            targets
                .targets_by_name(from)
                .context(error::DelegateMissing { name: from })?
        };
        // Get the keys used to sign the new role
        let (keyids, key_pairs) = if let Some(key) = key_source {
            let mut keyids = Vec::new();
            let mut key_pairs = HashMap::new();
            for source in key {
                let key_pair = source
                    .as_sign()
                    .context(error::KeyPairFromKeySource)?
                    .tuf_key();
                let key_id = RepositoryEditor::add_key(&mut parent, key_pair.clone())?;
                key_pairs.insert(key_id.clone(), key_pair);
                keyids.push(key_id);
            }
            (keyids, key_pairs)
        } else {
            // If we weren't given a new key source create a role using parent keys
            let mut keys = Vec::new();
            for key in parent
                .delegations
                .as_ref()
                .ok_or_else(|| error::Error::NoDelegations)?
                .keys
                .keys()
            {
                keys.push(key.clone());
            }

            (keys, HashMap::new())
        };
        let delegations = parent
            .delegations
            .as_mut()
            .ok_or_else(|| error::Error::NoDelegations)?;
        // Create new targets for `role`
        let mut new_targets = Targets::new(SPEC_VERSION.to_string(), version, expiration);
        let mut new_delegations = Delegations::new();
        new_delegations.keys.extend(key_pairs);
        // Create a new delegations for `role`
        new_targets.delegations = Some(new_delegations);
        let threshold = NonZeroU64::new(keyids.len().try_into().context(error::InvalidInto {})?)
            .context(error::InvalidThreshold {})?;
        delegations.roles.push(DelegatedRole {
            name,
            keyids,
            threshold,
            paths,
            terminating: false,
            targets: Some(Signed {
                signed: new_targets,
                signatures: Vec::new(),
            }),
        });

        Ok(self)
    }

    /// Adds a key to the targets delegation role if not already present, and returns a result with the key id.
    fn add_key(targets: &mut Targets, key: Key) -> Result<Decoded<Hex>> {
        let key_id = if let Some((key_id, _)) = targets
            .delegations
            .as_ref()
            .ok_or_else(|| error::Error::NoDelegations)?
            .keys
            .iter()
            .find(|(_, candidate_key)| key.eq(candidate_key))
        {
            key_id.clone()
        } else {
            // Key isn't present yet, so we need to add it
            let key_id = key.key_id().context(error::JsonSerialization {})?;

            targets
                .delegations
                .as_mut()
                .ok_or_else(|| error::Error::NoDelegations)?
                .keys
                .insert(key_id.clone(), key);
            key_id
        };

        Ok(key_id)
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
    pub fn targets_version(&mut self, targets_version: NonZeroU64) -> Result<&mut Self> {
        self.targets_struct
            .as_mut()
            .ok_or_else(|| error::Error::NoTargets)?
            .version = targets_version;
        Ok(self)
    }

    /// Set the `Targets` expiration
    pub fn targets_expires(&mut self, targets_expires: DateTime<Utc>) -> Result<&mut Self> {
        self.targets_struct
            .as_mut()
            .ok_or_else(|| error::Error::NoTargets)?
            .expires = targets_expires;
        Ok(self)
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
        Ok(self
            .targets_struct
            .as_ref()
            .ok_or_else(|| error::Error::NoDelegations)?
            .clone())
    }

    /// Build the `Snapshot` struct
    fn build_snapshot(
        &self,
        signed_targets: &SignedRole<Targets>,
        signed_delegated_targets: &HashMap<String, SignedRole<Targets>>,
    ) -> Result<Snapshot> {
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
        snapshot
            .meta
            .insert("targets.json".to_owned(), targets_meta);

        for (role, targets) in signed_delegated_targets {
            let meta = Self::snapshot_meta(targets);
            snapshot.meta.insert(format!("{}.json", role), meta);
        }

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

    /// Refreshes the timestamp and snapshot
    /// Allows for expirations to be changed
    pub fn update_snapshot<T>(
        repo: Repository<'_, T>,
        keys: &[Box<dyn KeySource>],
        timestamp_expiration: DateTime<Utc>,
        snapshot_expiration: DateTime<Utc>,
    ) -> Result<SignedRepository>
    where
        T: Transport,
    {
        let rng = SystemRandom::new();
        let signed_delegations =
            SignedRole::<Targets>::new_targets(&repo.targets.signed, &[], &rng, true)?;
        let signed_targets = SignedRole::from_signed(repo.targets)?;
        let signed_root = SignedRole::from_signed(repo.root)?;

        let mut snapshot = repo.snapshot.signed;
        // Update snapshot version and expiration
        snapshot.expires = snapshot_expiration;
        snapshot.version = NonZeroU64::new(
            u64::from(snapshot.version)
                .checked_add(1)
                .ok_or_else(|| error::Error::Overflow)?,
        )
        .ok_or_else(|| error::Error::Overflow)?;
        // Snapshot stores metadata about targets and root
        let targets_meta = Self::snapshot_meta(&signed_targets);
        let root_meta = Self::snapshot_meta(&signed_root);
        snapshot
            .meta
            .insert("targets.json".to_owned(), targets_meta);
        snapshot.meta.insert("root.json".to_owned(), root_meta);

        for (role, targets) in &signed_delegations {
            let meta = Self::snapshot_meta(targets);
            snapshot.meta.insert(format!("{}.json", role), meta);
        }

        let signed_snapshot = SignedRole::new(snapshot, &signed_root.signed.signed, keys, &rng)?;

        // Update timestamp to reflect changes to snapshot
        let mut timestamp = repo.timestamp.signed;
        timestamp.expires = timestamp_expiration;
        timestamp.version = NonZeroU64::new(
            u64::from(timestamp.version)
                .checked_add(1)
                .ok_or_else(|| error::Error::Overflow)?,
        )
        .ok_or_else(|| error::Error::Overflow)?;
        // Timestamp stores metadata about snapshot
        let snapshot_meta = Self::timestamp_meta(&signed_snapshot);
        timestamp
            .meta
            .insert("snapshot.json".to_owned(), snapshot_meta);

        let signed_timestamp = SignedRole::new(timestamp, &signed_root.signed.signed, keys, &rng)?;

        Ok(SignedRepository {
            timestamp: signed_timestamp,
            root: signed_root,
            delegations: signed_delegations,
            targets: signed_targets,
            snapshot: signed_snapshot,
        })
    }

    /// Crawls a given directory and symlinks any targets found to the given
    /// "out" directory. If consistent snapshots are used, the target files
    /// are prefixed with their `sha256`.
    ///
    /// For each file found in the `indir`, the method gets the filename and
    /// if the filename exists in `Targets`, the file's sha256 is compared
    /// against the data in `Targets`. If this data does not match, the
    /// method will fail.
    pub fn link_targets<P1, P2>(
        &self,
        indir: P1,
        outdir: P2,
        consistent_snapshot: Option<bool>,
    ) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        let consistent_snapshot = consistent_snapshot
            .unwrap_or_else(|| self.signed_root.signed.signed.consistent_snapshot);
        link_targets(
            indir.as_ref(),
            outdir.as_ref(),
            self.targets_struct.as_ref().context(error::NoTargets)?,
            consistent_snapshot,
        )
    }

    /// Crawls a given directory and copies any targets found to the given
    /// "out" directory. If consistent snapshots are used, the target files
    /// are prefixed with their `sha256`.
    ///
    /// For each file found in the `indir`, the method gets the filename and
    /// if the filename exists in `Targets`, the file's sha256 is compared
    /// against the data in `Targets`. If this data does not match, the
    /// method will fail.
    pub fn copy_targets<P1, P2>(
        &self,
        indir: P1,
        outdir: P2,
        consistent_snapshot: Option<bool>,
    ) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        let consistent_snapshot = consistent_snapshot
            .unwrap_or_else(|| self.signed_root.signed.signed.consistent_snapshot);
        copy_targets(
            indir.as_ref(),
            outdir.as_ref(),
            self.targets_struct.as_ref().context(error::NoTargets)?,
            consistent_snapshot,
        )
    }
}
