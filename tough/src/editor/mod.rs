// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::used_underscore_binding)] // #20

//! Provides a `RepositoryEditor` object for building and editing TUF repositories.

mod keys;
pub mod signed;
mod test;

use crate::editor::signed::copy_targets;
use crate::editor::signed::link_targets;
use crate::editor::signed::PathExists;
use crate::editor::signed::{SignedRepository, SignedRole};
use crate::error::{self, Result};
use crate::key_source::KeySource;
use crate::schema::decoded::{Decoded, Hex};
use crate::schema::{
    key::Key, DelegatedRole, DelegatedTargets, Delegations, Hashes, PathSet, Role, Root, Signed,
    Snapshot, SnapshotMeta, Target, Targets, Timestamp, TimestampMeta,
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

    targets_struct: Targets,

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
            targets_struct: Targets::new(
                SPEC_VERSION.to_string(),
                NonZeroU64::new(1).unwrap(),
                Utc::now(),
            ),
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

        let signed_targets = SignedRole::new(self.targets_struct.clone(), root, keys, &rng)?;

        let signed_delegations = if self.targets_struct.delegations.is_some() {
            Some(SignedRole::<DelegatedTargets>::signed_role_targets_map(
                &self.targets_struct,
                keys,
                &rng,
                true,
            )?)
        } else {
            None
        };

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
    pub fn sign_delegated_roles(
        &self,
        keys: &[Box<dyn KeySource>],
        names: Vec<&str>,
    ) -> Result<HashMap<String, SignedRole<DelegatedTargets>>> {
        let rng = SystemRandom::new();

        // Create `SignedRole` for each target
        let mut signed_roles = HashMap::new();
        let mut targets = SignedRole::<Targets>::signed_role_targets_map(
            &self.targets_struct,
            keys,
            &rng,
            false,
        )?;

        // Take the signed targets we want
        for name in names {
            if name == "targets" {
                signed_roles.insert(
                    name.to_string(),
                    SignedRole::new(
                        DelegatedTargets {
                            targets: self.targets_struct.clone(),
                            name: "targets".to_string(),
                        },
                        &self.signed_root.signed.signed,
                        keys,
                        &rng,
                    )?,
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
        self.targets_struct = targets;
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
        self.targets_struct.add_target(&name, target);

        Ok(self)
    }

    /// Remove a `Target` from the repository
    pub fn remove_target(&mut self, name: &str) -> Result<&mut Self> {
        self.targets_struct.remove_target(name);

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
    pub fn add_target_paths<P>(&mut self, targets: Vec<P>) -> Result<&mut Self>
    where
        P: AsRef<Path>,
    {
        for target in targets {
            let (target_name, target) = RepositoryEditor::build_target(target)?;
            self.add_target(&target_name, target)?;
        }

        Ok(self)
    }

    /// Add a `Target` to the delegatee `role`
    /// To add a target to top level targets use `add_target()`
    pub fn add_target_to_role(
        &mut self,
        name: &str,
        target: Target,
        role: &str,
    ) -> Result<&mut Self> {
        if role == "targets" {
            return self.add_target(name, target);
        }
        self.targets_struct
            .targets_by_name_verify_path(role, &name)
            .context(error::TargetsNotFound {
                name: name.to_string(),
            })?
            .add_target(&name, target);

        Ok(self)
    }

    /// Remove a `Target` from the delegated `role`
    /// To remove a target from top level targets use `remove_target()`
    pub fn remove_target_from_role(&mut self, name: &str, role: &str) -> Result<&mut Self> {
        if role == "targets" {
            return self.remove_target(name);
        }
        self.targets_struct
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
    /// construct `Target`s directly in parallel and use `add_target_to_role()`.
    /// To add a target to top level targets use `add_target_path()`
    pub fn add_target_path_to_role<P>(&mut self, target_path: P, role: &str) -> Result<&mut Self>
    where
        P: AsRef<Path>,
    {
        let (target_name, target) = RepositoryEditor::build_target(target_path)?;
        self.add_target_to_role(&target_name, target, role)?;
        Ok(self)
    }

    /// Add a list of target paths to the repository
    ///
    /// See the note on `add_target_path_to_role()` regarding performance.
    /// To add a target to top level targets use `add_target_paths()`
    pub fn add_target_paths_to_role<P>(&mut self, targets: Vec<P>, role: &str) -> Result<&mut Self>
    where
        P: AsRef<Path>,
    {
        for target in targets {
            let (target_name, target) = RepositoryEditor::build_target(target)?;
            self.add_target_to_role(&target_name, target, role)?;
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
        self.targets_struct.clear_targets();
        self
    }

    #[allow(clippy::too_many_arguments)]
    /// Delegate target with name. If `key_source` is given, new keys are given to the role if not parent keys are used
    pub fn delegate_role(
        &mut self,
        from: &str,
        name: &str,
        key_source: Option<&[Box<dyn KeySource>]>,
        paths: PathSet,
        threshold: Option<NonZeroU64>,
        expiration: DateTime<Utc>,
        version: NonZeroU64,
    ) -> Result<&mut Self> {
        // Steps to create a role
        // 1.Find the delegating role
        // 2.Get the signing keys for the new role using the delegating role's keys or the ones provided in key_source
        // 3.Create a Targets struct representing role
        // 4.Create the delegations for the new targets
        // 5.Add the public keys from key_source to the keys of the new role's delegations

        // If we are delegating from targets all paths are valid
        if from != "targets" {
            let parent_delegated_role =
                self.targets_struct
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

        // Find the parent targets for the role we are creating
        let mut parent = if from == "targets" {
            &mut self.targets_struct
        } else {
            self.targets_struct
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
        let threshold = threshold.unwrap_or(
            NonZeroU64::new(keyids.len().try_into().context(error::InvalidInto {})?)
                .context(error::InvalidThreshold {})?,
        );
        delegations.roles.push(DelegatedRole {
            name: name.to_string(),
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

    /// Adds a key to the targets' delegations if not already present, and returns a result with the key id.
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
    pub fn targets_version(&mut self, targets_version: NonZeroU64) -> &mut Self {
        self.targets_struct.version = targets_version;
        self
    }

    /// Set the `Targets` expiration
    pub fn targets_expires(&mut self, targets_expires: DateTime<Utc>) -> &mut Self {
        self.targets_struct.expires = targets_expires;
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

    /// Build the `Snapshot` struct
    fn build_snapshot(
        &self,
        signed_targets: &SignedRole<Targets>,
        signed_delegated_targets: &Option<HashMap<String, SignedRole<DelegatedTargets>>>,
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

        if let Some(delegated_roles) = signed_delegated_targets {
            for (role, targets) in delegated_roles {
                let meta = Self::snapshot_meta(targets);
                snapshot.meta.insert(format!("{}.json", role), meta);
            }
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
        replace_behavior: PathExists,
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
            replace_behavior,
            &self.targets_struct,
            consistent_snapshot,
        )
    }

    /// Crawls a given directory and links any targets found to the given
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
        replace_behavior: PathExists,
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
            replace_behavior,
            &self.targets_struct,
            consistent_snapshot,
        )
    }
}

/// `TargetsEditor` contains the various bits of data needed to construct
/// or edit a `Targets` role.
///
/// A new Targets may be created using the `new()` method.
///
/// An existing `Targets` may be loaded and edited using the
/// `targets_editor()` method. When a repo is loaded in this way, versions and
/// expirations are discarded. It is good practice to update these whenever
/// a repo is changed.
///
/// Targets, versions, and expirations may be added to their respective roles
/// via the provided "setter" methods. The final step in the process is the
/// `sign()` method, which takes a given set of signing keys, builds each of
/// the roles using the data provided, and signs the roles. This results in a
/// `SignedDelegatedTargets` which can be used to write the updated metadata to disk.
#[derive(Debug)]
pub struct TargetsEditor {
    /// The name of the targets role
    name: String,
    /// The metadata containing keyids for the role
    key_holder: Option<KeyHolder>,
    /// The delegations field of the Targets metadata
    delegations: Delegations,
    /// New targets that were added to `name`
    new_targets: Option<HashMap<String, Target>>,
    /// Targets that were previously in `name`
    existing_targets: Option<HashMap<String, Target>>,
    /// Version of the `Targets`
    version: Option<NonZeroU64>,
    /// Expiration of the `Targets`
    expires: Option<DateTime<Utc>>,
    /// New roles that were createed with the editor
    new_roles: Option<Vec<DelegatedRole>>,

    _extra: Option<HashMap<String, Value>>,
}

/// A `KeyHolder` is metadata that is responsible for verifying the signatures of a role.
/// `KeyHolder` contains
#[derive(Debug)]
pub enum KeyHolder {
    /// Delegations verify delegated targets
    Delegations(Delegations),
    /// Root verifies the top level targets
    Root(Root),
}

impl TargetsEditor {
    /// Creates a `TargetsEditor` for a newly created role
    pub fn new(name: &str) -> Self {
        TargetsEditor {
            key_holder: None,
            delegations: Delegations::new(),
            new_targets: None,
            existing_targets: None,
            version: None,
            expires: None,
            name: name.to_string(),
            new_roles: None,
            _extra: None,
        }
    }

    /// Creates a `TargetsEditor` with the provided targets and keyholder
    /// `version` and `expires` are thrown out to encourage updating the version and expiration
    pub fn from_targets(name: &str, targets: Targets, key_holder: KeyHolder) -> Result<Self> {
        Ok(TargetsEditor {
            key_holder: Some(key_holder),
            delegations: targets
                .delegations
                .ok_or_else(|| error::Error::NoDelegations)?,
            new_targets: None,
            existing_targets: Some(targets.targets),
            version: None,
            expires: None,
            name: name.to_string(),
            new_roles: None,
            _extra: Some(targets._extra),
        })
    }

    /// Add a `Target` to the `Targets` role
    pub fn add_target(&mut self, name: &str, target: Target) -> &mut Self {
        self.new_targets
            .get_or_insert_with(HashMap::new)
            .insert(name.to_string(), target);
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

        self.add_target(&target_name, target);
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

    /// Set the version
    pub fn version(&mut self, version: NonZeroU64) -> &mut Self {
        self.version = Some(version);
        self
    }

    /// Set the expiration
    pub fn expires(&mut self, expires: DateTime<Utc>) -> &mut Self {
        self.expires = Some(expires);
        self
    }

    /// Adds a key to delegations keyids
    pub fn add_key(&mut self, keys: &[Box<dyn KeySource>]) -> &mut Self {
        //TODO
        self
    }

    /// Removes a key from delegations keyids, if a role is specified only removes it from the role
    pub fn remove_key(&mut self, keyid: Decoded<Hex>, role: Option<&str>) -> &mut Self {
        //TODO
        self
    }

    /// Delegates `paths` to `targets` adding a `DelegatedRole` to new_roles
    pub fn delegate_role(
        &mut self,
        targets: DelegatedTargets,
        paths: PathSet,
        keyids: HashMap<Decoded<Hex>, Key>,
        threshold: Option<NonZeroU64>,
        expiration: DateTime<Utc>,
        version: NonZeroU64,
    ) -> Result<&mut Self> {
        //TODO
        Ok(self)
    }

    /// Removes a role from delegations if `recursive` is `false`
    /// requires the role to be an immediate delegated role
    /// if `true` removes whichever role eventually delegated 'role'
    pub fn remove_role(&mut self, role: &str, recursive: bool) -> &mut Self {
        //TODO
        self
    }

    /// Build the `Targets` struct
    /// Adds in the new roles and new targets
    pub fn build_targets(&self) -> Result<DelegatedTargets> {
        let version = self.version.context(error::Missing {
            field: "targets version",
        })?;
        let expires = self.expires.context(error::Missing {
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

        let _extra = self._extra.clone().unwrap_or_else(HashMap::new);
        Ok(DelegatedTargets {
            name: self.name.clone(),
            targets: Targets {
                spec_version: SPEC_VERSION.to_string(),
                version,
                expires,
                targets,
                _extra,
                delegations: Some(self.delegations.clone()),
            },
        })
    }
}
