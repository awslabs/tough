// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::used_underscore_binding)] // #20

//! Provides a `RepositoryEditor` object for building and editing TUF repositories.

mod keys;
pub mod signed;
mod test;

use crate::editor::signed::{SignedDelegatedTargets, SignedRepository, SignedRole};
use crate::error::{self, Result};
use crate::fetch::fetch_max_size;
use crate::key_source::KeySource;
use crate::schema::decoded::{Decoded, Hex};
use crate::schema::key::Key;
use crate::schema::{
    DelegatedRole, DelegatedTargets, Delegations, Hashes, KeyHolder, PathSet, Role, RoleType, Root,
    Signed, Snapshot, SnapshotMeta, Target, Targets, Timestamp, TimestampMeta,
};
use crate::transport::Transport;
use crate::Limits;
use crate::Repository;
use chrono::{DateTime, Utc};
use ring::digest::{SHA256, SHA256_OUTPUT_LEN};
use ring::rand::SystemRandom;
use serde_json::Value;
use snafu::{ensure, OptionExt, ResultExt};
use std::borrow::Cow;
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::Path;
use url::Url;

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
pub struct RepositoryEditor<'a, T: Transport> {
    signed_root: SignedRole<Root>,

    snapshot_version: Option<NonZeroU64>,
    snapshot_expires: Option<DateTime<Utc>>,
    snapshot_extra: Option<HashMap<String, Value>>,

    timestamp_version: Option<NonZeroU64>,
    timestamp_expires: Option<DateTime<Utc>>,
    timestamp_extra: Option<HashMap<String, Value>>,

    targets_editor: Option<TargetsEditor<'a, T>>,

    /// The signed top level targets, will be None if no top level targets have been signed
    signed_targets: Option<Signed<Targets>>,

    transport: Option<&'a T>,
    limits: Option<Limits>,
}

impl<'a, T: Transport> RepositoryEditor<'a, T> {
    /// Create a new, bare `RepositoryEditor`
    pub fn new<P>(root_path: P) -> Result<Self>
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

        let mut editor = TargetsEditor::new("targets");
        editor.key_holder = Some(KeyHolder::Root(signed_root.signed.signed.clone()));

        Ok(RepositoryEditor {
            signed_root,
            targets_editor: Some(editor),
            snapshot_version: None,
            snapshot_expires: None,
            snapshot_extra: None,
            timestamp_version: None,
            timestamp_expires: None,
            timestamp_extra: None,
            signed_targets: None,
            transport: None,
            limits: None,
        })
    }

    /// Given a `tough::Repository` and the path to a valid root.json, create a
    /// `RepositoryEditor`. This `RepositoryEditor` will include all of the targets
    /// and bits of _extra metadata from the roles included. It will not, however,
    /// include the versions or expirations and the user is expected to set them.
    pub fn from_repo<P>(root_path: P, repo: Repository<'a, T>) -> Result<RepositoryEditor<'a, T>>
    where
        P: AsRef<Path>,
    {
        let mut editor = RepositoryEditor::new(root_path)?;
        editor.targets(repo.targets)?;
        editor.snapshot(repo.snapshot.signed)?;
        editor.timestamp(repo.timestamp.signed)?;
        editor.transport = Some(repo.transport);
        editor.limits = Some(repo.limits);
        Ok(editor)
    }

    /// Builds and signs each required role and returns a complete signed set
    /// of TUF repository metadata.
    ///
    /// While `RepositoryEditor`s fields are all `Option`s, this step requires,
    /// at the very least, that the "version" and "expiration" field is set for
    /// each role; e.g. `targets_version`, `targets_expires`, etc.
    pub fn sign(mut self, keys: &[Box<dyn KeySource>]) -> Result<SignedRepository> {
        let rng = SystemRandom::new();
        let root = KeyHolder::Root(self.signed_root.signed.signed.clone());
        // Sign the targets editor if able to with the provided keys
        self.sign_targets_editor(keys)?;
        let targets = self.signed_targets.clone().context(error::NoTargets)?;
        let delegated_targets = targets.signed.signed_delegated_targets();
        let signed_targets = SignedRole::from_signed(targets)?;

        let signed_delegated_targets = if delegated_targets.is_empty() {
            None
        } else {
            let mut roles = Vec::new();
            for role in delegated_targets {
                roles.push(SignedRole::from_signed(role)?)
            }
            Some(SignedDelegatedTargets { roles })
        };

        let signed_snapshot = self
            .build_snapshot(&signed_targets, &signed_delegated_targets)
            .and_then(|snapshot| SignedRole::new(snapshot, &root, keys, &rng))?;
        let signed_timestamp = self
            .build_timestamp(&signed_snapshot)
            .and_then(|timestamp| SignedRole::new(timestamp, &root, keys, &rng))?;

        Ok(SignedRepository {
            root: self.signed_root,
            targets: signed_targets,
            snapshot: signed_snapshot,
            timestamp: signed_timestamp,
            delegated_targets: signed_delegated_targets,
        })
    }

    /// Add an existing `Targets` struct to the repository.
    pub fn targets(&mut self, targets: Signed<Targets>) -> Result<&mut Self> {
        ensure!(
            targets.signed.spec_version == SPEC_VERSION,
            error::SpecVersion {
                given: targets.signed.spec_version,
                supported: SPEC_VERSION
            }
        );
        // Save the existing targets
        self.signed_targets = Some(targets.clone());
        // Create a targets editor so that targets can be updated
        self.targets_editor = Some(TargetsEditor::from_targets(
            "targets",
            targets.signed,
            KeyHolder::Root(self.signed_root.signed.signed.clone()),
        ));
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

    /// Returns a mutable reference to the targets editor if it exists, or an error if it doesn't
    fn targets_editor_mut(&mut self) -> Result<&mut TargetsEditor<'a, T>> {
        self.targets_editor
            .as_mut()
            .ok_or_else(|| error::Error::NoTargets)
    }

    /// Add a `Target` to the repository
    pub fn add_target(&mut self, name: &str, target: Target) -> Result<&mut Self> {
        self.targets_editor_mut()?.add_target(&name, target);
        Ok(self)
    }

    /// Remove a `Target` from the repository
    pub fn remove_target(&mut self, name: &str) -> Result<&mut Self> {
        self.targets_editor_mut()?.remove_target(name);

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
        let (target_name, target) = RepositoryEditor::<T>::build_target(target_path)?;
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
            let (target_name, target) = RepositoryEditor::<T>::build_target(target)?;
            self.add_target(&target_name, target)?;
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
    pub fn clear_targets(&mut self) -> Result<&mut Self> {
        self.targets_editor_mut()?.clear_targets();
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    /// Delegate target with name. If `key_source` is given, new keys are given to the role if not parent keys are used
    pub fn delegate_role(
        &mut self,
        name: &str,
        key_source: &[Box<dyn KeySource>],
        paths: PathSet,
        threshold: NonZeroU64,
        expiration: DateTime<Utc>,
        version: NonZeroU64,
    ) -> Result<&mut Self> {
        // Create the new targets using targets editor
        let mut new_targets_editor = TargetsEditor::<'a, T>::new(name);
        // Set the version and expiration
        new_targets_editor.version(version).expires(expiration);
        // Sign the new targets
        let signed_delegated_targets = new_targets_editor.sign(key_source)?;
        // Extract the new targets
        let new_targets = signed_delegated_targets.role()?;
        // Find the keyids for key_source
        let mut keyids = Vec::new();
        let mut key_pairs = HashMap::new();
        for source in key_source {
            let key_pair = source
                .as_sign()
                .context(error::KeyPairFromKeySource)?
                .tuf_key();
            keyids.push(key_pair.key_id().context(error::JsonSerialization {})?);
            key_pairs.insert(
                key_pair.key_id().context(error::JsonSerialization {})?,
                key_pair,
            );
        }
        // Add the new role to targets_editor
        self.targets_editor_mut()?.delegate_role(
            new_targets.signed,
            paths,
            key_pairs,
            keyids,
            threshold,
        )?;

        Ok(self)
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
        self.targets_editor_mut()?.version(targets_version);
        Ok(self)
    }

    /// Set the `Targets` expiration
    pub fn targets_expires(&mut self, targets_expires: DateTime<Utc>) -> Result<&mut Self> {
        self.targets_editor_mut()?.expires(targets_expires);
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

    /// Takes the current Targets from `targets_editor` and moves inserts the role to its proper place in `signed_targets`
    /// Sets `targets_editor` to None
    pub fn sign_targets_editor(&mut self, keys: &[Box<dyn KeySource>]) -> Result<&mut Self> {
        if let Some(targets_editor) = self.targets_editor.as_mut() {
            let (name, targets) = targets_editor.create_signed(keys)?.to_targets();
            if name == "targets" {
                self.signed_targets = Some(targets);
            } else {
                self.signed_targets
                    .as_mut()
                    .context(error::NoTargets)?
                    .signed
                    .get_delegated_role_by_name(&name)
                    .context(error::DelegateMissing { name })?
                    .targets = Some(targets);
            }
        }
        self.targets_editor = None;
        Ok(self)
    }

    /// Changes the targets refered to in `targets_editor` to role
    /// If keys are supplied, the contents of the `targets_editor` are signed and stored
    pub fn change_targets(
        &mut self,
        role: &str,
        keys: Option<&[Box<dyn KeySource>]>,
    ) -> Result<&mut Self> {
        if let Some(keys) = keys {
            self.sign_targets_editor(keys)?;
        } // get rid of and error out if not already done
        let targets = &mut self
            .signed_targets
            .as_mut()
            .context(error::NoTargets)?
            .signed;
        let (key_holder, targets) = if role == "targets" {
            (
                KeyHolder::Root(self.signed_root.signed.signed.clone()),
                targets.clone(),
            )
        } else {
            let parent = targets
                .parent_of(role)
                .context(error::DelegateMissing {
                    name: role.to_string(),
                })?
                .clone();
            let targets = targets
                .targets_by_name(role)
                .context(error::DelegateMissing {
                    name: role.to_string(),
                })?
                .clone();
            (KeyHolder::Delegations(parent), targets)
        };
        self.targets_editor = Some(TargetsEditor::from_targets(role, targets, key_holder));

        Ok(self)
    }

    #[allow(clippy::too_many_lines)]
    /// Updates the metadata for `name`
    /// Clears the current `targets_editor`
    pub fn update_delegated_targets(
        &mut self,
        name: &str,
        metadata_url: &str,
    ) -> Result<&mut Self> {
        let limits = self.limits.context(error::MissingLimits)?;
        let transport = self.transport.context(error::MissingTransport)?;
        let targets = &mut self
            .signed_targets
            .as_mut()
            .context(error::NoTargets)?
            .signed;
        let metadata_base_url = parse_url(metadata_url)?;
        // path to updated metadata
        let role_url =
            metadata_base_url
                .join(&format!("{}.json", name))
                .context(error::JoinUrl {
                    path: name.to_string(),
                    url: metadata_base_url.to_owned(),
                })?;
        let reader = Box::new(fetch_max_size(
            transport,
            role_url,
            limits.max_targets_size,
            "max targets limit",
        )?);
        // Load incoming role metadata as Signed<Targets>
        let mut role: Signed<crate::schema::Targets> =
            serde_json::from_reader(reader).context(error::ParseMetadata {
                role: RoleType::Targets,
            })?;
        //verify role with the parent delegation
        let (parent, current_targets) = if name == "targets" {
            (
                KeyHolder::Root(self.signed_root.signed.signed.clone()),
                targets,
            )
        } else {
            let parent = targets
                .parent_of(name)
                .context(error::DelegateMissing {
                    name: name.to_string(),
                })?
                .clone();
            let targets = targets
                .targets_by_name(name)
                .context(error::DelegateMissing {
                    name: name.to_string(),
                })?;
            (KeyHolder::Delegations(parent), targets)
        };
        parent.verify_role(&role, name)?;
        // Make sure the version isn't downgraded
        ensure!(
            role.signed.version >= current_targets.version,
            error::VersionMismatch {
                role: RoleType::Targets,
                fetched: role.signed.version,
                expected: current_targets.version
            }
        );
        // get a list of roles that we don't have metadata for yet
        // and copy current_targets delegated targets to role
        let new_roles = current_targets.update_targets(&mut role);
        let delegations = role
            .signed
            .delegations
            .as_mut()
            .context(error::NoDelegations)?;
        // the new targets will be the keyholder for any of its newly delegated roles, so create a keyholder
        let key_holder = KeyHolder::Delegations(delegations.clone());
        // load the new roles
        for name in new_roles {
            // path to new metadata
            let role_url =
                metadata_base_url
                    .join(&format!("{}.json", name))
                    .context(error::JoinUrl {
                        path: name.to_string(),
                        url: metadata_base_url.to_owned(),
                    })?;
            let reader = Box::new(fetch_max_size(
                transport,
                role_url,
                limits.max_targets_size,
                "max targets limit",
            )?);
            // Load new role metadata as Signed<Targets>
            let new_role: Signed<crate::schema::Targets> = serde_json::from_reader(reader)
                .context(error::ParseMetadata {
                    role: RoleType::Targets,
                })?;
            // verify the role
            key_holder.verify_role(&new_role, &name)?;
            // add the new role
            delegations
                .roles
                .iter_mut()
                .find(|delegated_role| delegated_role.name == name)
                .context(error::DelegateNotFound { name: name.clone() })?
                .targets = Some(new_role.clone());
        }
        // Add our new role in place of the old one
        if name == "targets" {
            self.signed_targets = Some(role)
        } else {
            self.signed_targets
                .as_mut()
                .context(error::NoTargets)?
                .signed
                .get_delegated_role_by_name(name)
                .context(error::DelegateMissing {
                    name: name.to_string(),
                })?
                .targets = Some(role);
        }
        self.targets_editor = None;
        Ok(self)
    }

    /// Adds a role to the targets currently in `targets_editor`
    pub fn add_role(
        &mut self,
        name: &str,
        metadata_url: &str,
        paths: PathSet,
        threshold: NonZeroU64,
        keys: Option<HashMap<Decoded<Hex>, Key>>,
    ) -> Result<&mut Self> {
        let limits = self.limits.context(error::MissingLimits)?;
        let transport = self.transport.context(error::MissingTransport)?;

        self.targets_editor_mut()?.limits(limits);
        self.targets_editor_mut()?.transport(transport);
        self.targets_editor_mut()?
            .add_role(name, metadata_url, paths, threshold, keys)?;

        Ok(self)
    }

    // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

    /// Build the `Snapshot` struct
    fn build_snapshot(
        &self,
        signed_targets: &SignedRole<Targets>,
        signed_delegated_targets: &Option<SignedDelegatedTargets>,
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

        if let Some(signed_delegated_targets) = signed_delegated_targets.as_ref() {
            for delegated_targets in &signed_delegated_targets.roles {
                let meta = Self::snapshot_meta(delegated_targets);
                snapshot.meta.insert(
                    format!("{}.json", delegated_targets.signed.signed.name),
                    meta,
                );
            }
        }

        Ok(snapshot)
    }

    /// Build a `SnapshotMeta` struct from a given `SignedRole<R>`. This metadata
    /// includes the sha256 and length of the signed role.
    fn snapshot_meta<R>(role: &SignedRole<R>) -> SnapshotMeta
    where
        R: Role,
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

    /// Build a `TimestampMeta` struct from a given `SignedRole<R>`. This metadata
    /// includes the sha256 and length of the signed role.
    fn timestamp_meta<R>(role: &SignedRole<R>) -> TimestampMeta
    where
        R: Role,
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

fn parse_url(url: &str) -> Result<Url> {
    let mut url = Cow::from(url);
    if !url.ends_with('/') {
        url.to_mut().push('/');
    }
    Url::parse(&url).context(error::ParseUrl { url })
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
#[derive(Debug, Clone)]
pub struct TargetsEditor<'a, T: Transport> {
    /// The name of the targets role
    name: String,
    /// The metadata containing keyids for the role
    key_holder: Option<KeyHolder>,
    /// The delegations field of the Targets metadata
    /// delegations should only be None if the editor is
    /// for "targets" on a repository that doesn't use delegated targets
    delegations: Option<Delegations>,
    /// New targets that were added to `name`
    new_targets: Option<HashMap<String, Target>>,
    /// Targets that were previously in `name`
    existing_targets: Option<HashMap<String, Target>>,
    /// Version of the `Targets`
    version: Option<NonZeroU64>,
    /// Expiration of the `Targets`
    expires: Option<DateTime<Utc>>,
    /// New roles that were created with the editor
    new_roles: Option<Vec<DelegatedRole>>,

    _extra: Option<HashMap<String, Value>>,

    limits: Option<Limits>,

    transport: Option<&'a T>,
}

impl<'a, T: Transport> TargetsEditor<'a, T> {
    /// Creates a `TargetsEditor` for a newly created role
    pub fn new(name: &str) -> Self {
        TargetsEditor {
            key_holder: None,
            delegations: Some(Delegations::new()),
            new_targets: None,
            existing_targets: None,
            version: None,
            expires: None,
            name: name.to_string(),
            new_roles: None,
            _extra: None,
            limits: None,
            transport: None,
        }
    }

    /// Creates a `TargetsEditor` with the provided targets and keyholder
    /// `version` and `expires` are thrown out to encourage updating the version and expiration
    pub fn from_targets(name: &str, targets: Targets, key_holder: KeyHolder) -> Self {
        TargetsEditor {
            key_holder: Some(key_holder),
            delegations: targets.delegations,
            new_targets: None,
            existing_targets: Some(targets.targets),
            version: None,
            expires: None,
            name: name.to_string(),
            new_roles: None,
            _extra: Some(targets._extra),
            limits: None,
            transport: None,
        }
    }

    /// Creates a `TargetsEditor` with the provided targets from an already loaded repo
    /// `version` and `expires` are thrown out to encourage updating the version and expiration
    pub fn from_repo(repo: &Repository<'a, T>, name: &str) -> Result<Self>
    where
        T: Transport,
    {
        let targets = repo
            .delegated_role(name)
            .context(error::DelegateNotFound {
                name: name.to_string(),
            })?
            .targets
            .as_ref()
            .context(error::NoTargets)?
            .signed
            .clone();
        let key_holder = KeyHolder::Delegations(
            repo.targets
                .signed
                .parent_of(name)
                .context(error::DelegateMissing {
                    name: name.to_string(),
                })?
                .clone(),
        );
        Ok(TargetsEditor::<'a, T> {
            key_holder: Some(key_holder),
            delegations: targets.delegations,
            new_targets: None,
            existing_targets: Some(targets.targets),
            version: None,
            expires: None,
            name: name.to_string(),
            new_roles: None,
            _extra: Some(targets._extra),
            limits: Some(repo.limits),
            transport: Some(repo.transport),
        })
    }

    /// Adds limits to the `TargetsEditor`
    pub fn limits(&mut self, limits: Limits) {
        self.limits = Some(limits);
    }

    /// Add a transport to the `TargetsEditor`
    pub fn transport(&mut self, transport: &'a T) {
        self.transport = Some(transport);
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

    /// Remove a `Target` from the repository if it exists
    pub fn remove_target(&mut self, name: &str) -> &mut Self {
        if let Some(targets) = self.existing_targets.as_mut() {
            targets.remove(name);
        }
        if let Some(targets) = self.new_targets.as_mut() {
            targets.remove(name);
        }

        self
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

    /// Adds a key to delegations keyids, adds the key to `role` if it is provided
    pub fn add_key(
        &mut self,
        keys: HashMap<Decoded<Hex>, Key>,
        role: Option<&str>,
    ) -> Result<&mut Self> {
        let delegations = self.delegations.as_mut().context(error::NoDelegations)?;
        let mut keyids = Vec::new();
        for (keyid, key) in keys {
            // Check to see if the key is present
            if delegations
                .keys
                .iter()
                .find(|(_, candidate_key)| key.clone().eq(candidate_key))
                .is_none()
            {
                // Key isn't present yet, so we need to add it
                delegations.keys.insert(keyid.clone(), key);
            };
            keyids.push(keyid.clone());
        }

        // If a role was provided add keyids to the delegated role
        if let Some(role) = role {
            for delegated_role in &mut delegations.roles {
                if delegated_role.name == role {
                    delegated_role.keyids.extend(keyids.clone());
                }
            }
            for delegated_role in self.new_roles.get_or_insert(Vec::new()).iter_mut() {
                if delegated_role.name == role {
                    delegated_role.keyids.extend(keyids.clone());
                }
            }
        }
        Ok(self)
    }

    /// Removes a key from delegations keyids, if a role is specified only removes it from the role
    pub fn remove_key(&mut self, keyid: &Decoded<Hex>, role: Option<&str>) -> Result<&mut Self> {
        let delegations = self.delegations.as_mut().context(error::NoDelegations)?;
        delegations.keys.remove(keyid);
        // If a role was provided remove keyid from the delegated role
        if let Some(role) = role {
            for delegated_role in &mut delegations.roles {
                if delegated_role.name == role {
                    delegated_role.keyids.retain(|key| keyid != key);
                }
            }
        }
        Ok(self)
    }

    /// Delegates `paths` to `targets` adding a `DelegatedRole` to `new_roles`
    pub fn delegate_role(
        &mut self,
        targets: Signed<DelegatedTargets>,
        paths: PathSet,
        key_pairs: HashMap<Decoded<Hex>, Key>,
        keyids: Vec<Decoded<Hex>>,
        threshold: NonZeroU64,
    ) -> Result<&mut Self> {
        self.add_key(key_pairs, None)?;
        self.new_roles
            .get_or_insert(Vec::new())
            .push(DelegatedRole {
                name: targets.signed.name,
                paths,
                keyids,
                threshold,
                terminating: false,
                targets: Some(Signed {
                    signed: targets.signed.targets,
                    signatures: targets.signatures,
                }),
            });
        Ok(self)
    }

    /// Removes a role from delegations if `recursive` is `false`
    /// requires the role to be an immediate delegated role
    /// if `true` removes whichever role eventually delegated 'role'
    pub fn remove_role(&mut self, role: &str, recursive: bool) -> Result<&mut Self> {
        let delegations = self.delegations.as_mut().context(error::NoDelegations)?;
        // Keep all of the roles that are not `role`
        delegations
            .roles
            .retain(|delegated_role| delegated_role.name != role);
        if recursive {
            // Keep all roles that do not delegate `role` down the chain of delegations
            delegations.roles.retain(|delegated_role| {
                if let Some(targets) = delegated_role.targets.as_ref() {
                    targets.signed.delegated_role(role).is_err()
                } else {
                    true
                }
            });
        }
        Ok(self)
    }

    /// Adds a role to `new_roles`
    pub fn add_role(
        &mut self,
        name: &str,
        metadata_url: &str,
        paths: PathSet,
        threshold: NonZeroU64,
        keys: Option<HashMap<Decoded<Hex>, Key>>,
    ) -> Result<&mut Self> {
        let limits = self.limits.context(error::MissingLimits)?;
        let transport = self.transport.context(error::MissingTransport)?;

        let metadata_base_url = parse_url(metadata_url)?;
        // path to updated metadata
        let role_url =
            metadata_base_url
                .join(&format!("{}.json", name))
                .context(error::JoinUrl {
                    path: name.to_string(),
                    url: metadata_base_url,
                })?;
        let reader = Box::new(fetch_max_size(
            transport,
            role_url,
            limits.max_targets_size,
            "max targets limit",
        )?);
        // Load incoming role metadata as Signed<Targets>
        let role: Signed<crate::schema::Targets> =
            serde_json::from_reader(reader).context(error::ParseMetadata {
                role: RoleType::Targets,
            })?;

        // Create `Signed<DelegatedTargets>` for the role
        let delegated_targets = Signed {
            signed: DelegatedTargets {
                name: name.to_string(),
                targets: role.signed.clone(),
            },
            signatures: role.signatures.clone(),
        };
        let (keyids, key_pairs) = if let Some(keys) = keys {
            (keys.keys().cloned().collect(), keys)
        } else {
            let key_pairs = role
                .signed
                .delegations
                .context(error::NoDelegations)?
                .keys;
            (key_pairs.keys().cloned().collect(), key_pairs)
        };

        self.delegate_role(delegated_targets, paths, key_pairs, keyids, threshold)?;

        Ok(self)
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

        let mut delegations = self.delegations.clone();
        if let Some(delegations) = delegations.as_mut() {
            if let Some(new_roles) = self.new_roles.as_ref() {
                delegations.roles.extend(new_roles.clone());
            }
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
                delegations,
            },
        })
    }

    /// Creates a `Signed<Targets>` for this role using the provided keys
    pub fn create_signed(&self, keys: &[Box<dyn KeySource>]) -> Result<Signed<DelegatedTargets>> {
        let rng = SystemRandom::new();
        // create a signed role for the targets being edited
        let targets = self.build_targets().and_then(|targets| {
            SignedRole::new(
                targets,
                self.key_holder.as_ref().context(error::NoKeyHolder)?,
                keys,
                &rng,
            )
        })?;
        Ok(targets.signed)
    }

    /// Creates a `SignedDelegatedTargets` for the Targets role being edited and all added roles
    /// If `key_holder` was not assigned then this is a newly created role and needs to signed with a
    /// custom delegations as its `key_holder`
    pub fn sign(&self, keys: &[Box<dyn KeySource>]) -> Result<SignedDelegatedTargets> {
        let rng = SystemRandom::new();
        let mut roles = Vec::new();
        let key_holder = if let Some(key_holder) = self.key_holder.as_ref() {
            key_holder.clone()
        } else {
            // There isn't a KeyHolder, so create one based on the provided keys
            let mut temp_delegations = Delegations::new();
            // First create the tuf key pairs and keyids
            let mut keyids = Vec::new();
            let mut key_pairs = HashMap::new();
            for source in keys {
                let key_pair = source
                    .as_sign()
                    .context(error::KeyPairFromKeySource)?
                    .tuf_key();
                key_pairs.insert(
                    key_pair
                        .key_id()
                        .context(error::JsonSerialization {})?
                        .clone(),
                    key_pair.clone(),
                );
                keyids.push(
                    key_pair
                        .key_id()
                        .context(error::JsonSerialization {})?
                        .clone(),
                );
            }
            // Then add the keys to the new delegations keys
            temp_delegations.keys = key_pairs;
            // Now create a DelegatedRole for the new role
            temp_delegations.roles.push(DelegatedRole {
                name: self.name.clone(),
                threshold: NonZeroU64::new(1).unwrap(),
                paths: PathSet::Paths([].to_vec()),
                terminating: false,
                keyids,
                targets: None,
            });
            KeyHolder::Delegations(temp_delegations)
        };

        // create a signed role for the targets we are editing
        let signed_targets = self
            .build_targets()
            .and_then(|targets| SignedRole::new(targets, &key_holder, keys, &rng))?;
        roles.push(signed_targets);
        // create signed roles for any role metadata we added to this targets
        if let Some(new_roles) = &self.new_roles {
            for role in new_roles {
                roles.push(SignedRole::from_signed(
                    role.clone()
                        .to_signed_delegated_targets()
                        .ok_or_else(|| error::Error::NoTargets)?,
                )?)
            }
        }

        Ok(SignedDelegatedTargets { roles })
    }
}
