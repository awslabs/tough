// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provides the `SignedRepository` object which represents the output of `RepositoryEditor` after
//! signing, ready to be written to disk.
//! Provides the `SignedDelegatedTargets` object which represents the output of `TargetsEditor` after
//! signing, ready to be written to disk.

use crate::error::{self, Result};
use crate::io::{is_file, DigestAdapter};
use crate::key_source::KeySource;
use crate::schema::{
    DelegatedTargets, KeyHolder, Role, RoleType, Root, Signature, Signed, Snapshot, Target,
    Targets, Timestamp,
};
use async_trait::async_trait;
use aws_lc_rs::digest::{digest, SHA256, SHA256_OUTPUT_LEN, SHA512, SHA512_OUTPUT_LEN};
use aws_lc_rs::rand::SecureRandom;
use futures::TryStreamExt;
use olpc_cjson::CanonicalFormatter;
use serde::{Deserialize, Serialize};
use serde_plain::derive_fromstr_from_deserialize;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::HashMap;
use std::future::{ready, Future};
use tokio::fs::{canonicalize, copy, create_dir_all, remove_file, symlink_metadata};

#[cfg(not(target_os = "windows"))]
use tokio::fs::symlink;
#[cfg(target_os = "windows")]
use tokio::fs::symlink_file as symlink;

use crate::{FilesystemTransport, TargetName, Transport};
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use url::Url;
use walkdir::WalkDir;

/// A signed role, including its serialized form (`buffer`) which is meant to
/// be written to file. The `sha256` and `length` are calculated from this
/// buffer and included in metadata for other roles, which makes it
/// imperative that this buffer is what is written to disk.
///
/// Convenience methods are provided on `SignedRepository` to ensure that
/// each role's buffer is written correctly.
#[derive(Debug, Clone)]
pub struct SignedRole<T> {
    pub(crate) signed: Signed<T>,
    pub(crate) buffer: Vec<u8>,
    pub(crate) sha256: [u8; SHA256_OUTPUT_LEN],
    pub(crate) sha512: [u8; SHA512_OUTPUT_LEN],
    pub(crate) length: u64,
}

impl<T> SignedRole<T>
where
    T: Role + Serialize,
{
    /// Creates a new `SignedRole`
    pub async fn new(
        role: T,
        key_holder: &KeyHolder,
        keys: &[Box<dyn KeySource>],
        rng: &(dyn SecureRandom + Sync),
    ) -> Result<Self> {
        let root_keys = key_holder.get_keys(keys).await?;

        let role_keys = key_holder.role_keys(role.role_id())?;
        // Ensure the keys we have available to us will allow us
        // to sign this role. The role's key ids must match up with one of
        // the keys provided.
        let valid_keys = root_keys
            .iter()
            .filter(|(keyid, _signing_key)| role_keys.keyids.contains(keyid));

        // Create the `Signed` struct for this role. This struct will be
        // mutated later to contain the signatures.
        let mut role = Signed {
            signed: role,
            signatures: Vec::new(),
        };

        let mut data = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
        role.signed
            .serialize(&mut ser)
            .context(error::SerializeRoleSnafu {
                role: T::TYPE.to_string(),
            })?;
        for (signing_key_id, signing_key) in valid_keys {
            let sig = signing_key
                .sign(&data, rng)
                .await
                .context(error::SignMessageSnafu)?;

            // Add the signatures to the `Signed` struct for this role
            role.signatures.push(Signature {
                keyid: signing_key_id.clone(),
                sig: sig.into(),
            });
        }

        // since for root the check depends on cross-sign
        if T::TYPE != RoleType::Root && role_keys.threshold.get() > role.signatures.len() as u64 {
            return Err(error::Error::SigningKeysNotFound {
                role: T::TYPE.to_string(),
            });
        }
        SignedRole::from_signed(role)
    }

    /// Creates a `SignedRole<Role>` from a `Signed<Role>`.
    /// This is used to create signed roles for any signed metadata
    pub(crate) fn from_signed(role: Signed<T>) -> Result<SignedRole<T>> {
        // Serialize the role, and calculate its length and
        // sha256.
        let mut buffer =
            serde_json::to_vec_pretty(&role).context(error::SerializeSignedRoleSnafu {
                role: T::TYPE.to_string(),
            })?;
        buffer.push(b'\n');
        let length = buffer.len() as u64;

        let mut sha256 = [0; SHA256_OUTPUT_LEN];
        sha256.copy_from_slice(digest(&SHA256, &buffer).as_ref());

        // Calculate SHA-512
        let mut sha512 = [0; SHA512_OUTPUT_LEN];
        sha512.copy_from_slice(digest(&SHA512, &buffer).as_ref());

        // Create the `SignedRole` containing, the `Signed<role>`, serialized
        // buffer, length and sha256.
        let signed_role = SignedRole {
            signed: role,
            buffer,
            sha256,
            sha512,
            length,
        };

        Ok(signed_role)
    }

    /// Provides access to the internal signed metadata object.
    pub fn signed(&self) -> &Signed<T> {
        &self.signed
    }

    /// Provides access to the internal buffer containing the serialized form of the signed role.
    /// This buffer should be used anywhere this role is written to file.
    pub fn buffer(&self) -> &Vec<u8> {
        &self.buffer
    }

    /// Provides the sha256 digest of the signed role, if available.
    pub fn sha256(&self) -> Option<&[u8]> {
        if self.sha256.iter().any(|&byte| byte != 0) {
            Some(&self.sha256)
        } else {
            None
        }
    }

    /// Provides the sha512 digest of the signed role, if available.
    pub fn sha512(&self) -> Option<&[u8]> {
        if self.sha512.iter().any(|&byte| byte != 0) {
            Some(&self.sha512)
        } else {
            None
        }
    }

    /// Provides the length in bytes of the serialized representation of the signed role.
    pub fn length(&self) -> &u64 {
        &self.length
    }

    /// Write the current role's buffer to the given directory with the
    /// appropriate file name.
    pub async fn write<P>(&self, outdir: P, consistent_snapshot: bool) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let outdir = outdir.as_ref();
        tokio::fs::create_dir_all(outdir)
            .await
            .context(error::DirCreateSnafu { path: outdir })?;

        let filename = self.signed.signed.filename(consistent_snapshot);

        let path = outdir.join(filename);
        tokio::fs::write(&path, &self.buffer)
            .await
            .context(error::FileWriteSnafu { path })
    }

    /// Append the old signatures for root role
    pub fn add_old_signatures(mut self, old_signatures: Vec<Signature>) -> Result<Self> {
        for old_signature in old_signatures {
            //add only if the signature of the key does not exist
            if !self
                .signed
                .signatures
                .iter()
                .any(|new_sig| new_sig.keyid == old_signature.keyid)
            {
                self.signed.signatures.push(Signature {
                    keyid: old_signature.keyid,
                    sig: old_signature.sig,
                });
            }
        }
        SignedRole::from_signed(self.signed)
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// `PathExists` allows the user of our copy/link functions to specify what happens when the target
/// is being written to a shared targets directory and the file already exists from another repo.
#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum PathExists {
    /// Leave the existing file.
    Skip,
    /// Remove and replace the file; you might want this to update file metadata, for example.
    Replace,
    /// Stop writing targets and return an error.
    Fail,
}
derive_fromstr_from_deserialize!(PathExists);

/// `TargetPath` represents an existing file at the path generated by `target_path`, if any, and
/// the type of the file.  (Other file types will return an error instead.)  This can be used to
/// determine whether you want to continue or fail.
#[derive(Debug, Clone)]
enum TargetPath {
    /// No existing file found, we can create a new one at this path.
    New { path: PathBuf },
    /// Existing regular file found at this path.
    File { path: PathBuf },
    /// Existing symlink found at this path.
    Symlink { path: PathBuf },
}

/// A set of signed TUF Repository metadata.
///
/// This metadata represents a signed TUF repository and provides the ability
/// to write the metadata to disk.
///
/// Note: without the target files, the repository cannot be used. It is up
/// to the user to ensure all the target files referenced by the metadata are
/// available. There are convenience methods to help with this.
#[derive(Debug)]
pub struct SignedRepository {
    pub(crate) root: SignedRole<Root>,
    pub(crate) targets: SignedRole<Targets>,
    pub(crate) snapshot: SignedRole<Snapshot>,
    pub(crate) timestamp: SignedRole<Timestamp>,
    pub(crate) delegated_targets: Option<SignedDelegatedTargets>,
}

impl SignedRepository {
    /// Writes the metadata to the given directory. If consistent snapshots
    /// are used, the appropriate files are prefixed with their version.
    pub async fn write<P>(&self, outdir: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let consistent_snapshot = self.root.signed.signed.consistent_snapshot;
        self.root.write(&outdir, consistent_snapshot).await?;
        self.targets.write(&outdir, consistent_snapshot).await?;
        self.snapshot.write(&outdir, consistent_snapshot).await?;
        self.timestamp.write(&outdir, consistent_snapshot).await?;
        if let Some(delegated_targets) = &self.delegated_targets {
            delegated_targets
                .write(&outdir, consistent_snapshot)
                .await?;
        }
        Ok(())
    }

    /// Crawls a given directory and symlinks any targets found to the given
    /// "out" directory. If consistent snapshots are used, the target files
    /// are prefixed with their `sha256`.
    ///
    /// For each file found in the `indir`, the method gets the filename and
    /// if the filename exists in `Targets`, the file's sha256 is compared
    /// against the data in `Targets`. If this data does not match, the
    /// method will fail.
    pub async fn link_targets<P1, P2>(
        &self,
        indir: P1,
        outdir: P2,
        replace_behavior: PathExists,
    ) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        self.walk_targets(
            indir.as_ref(),
            outdir.as_ref(),
            Self::link_target,
            replace_behavior,
        )
        .await
    }

    /// Crawls a given directory and copies any targets found to the given
    /// "out" directory. If consistent snapshots are used, the target files
    /// are prefixed with their `sha256`.
    ///
    /// For each file found in the `indir`, the method gets the filename and
    /// if the filename exists in `Targets`, the file's sha256 is compared
    /// against the data in `Targets`. If this data does not match, the
    /// method will fail.
    pub async fn copy_targets<P1, P2>(
        &self,
        indir: P1,
        outdir: P2,
        replace_behavior: PathExists,
    ) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        self.walk_targets(
            indir.as_ref(),
            outdir.as_ref(),
            Self::copy_target,
            replace_behavior,
        )
        .await
    }

    /// Symlinks a single target to the desired directory. If `target_filename` is given, it
    /// becomes the filename suffix, otherwise the original filename is used. (A unique filename
    /// prefix is used if consistent snapshots are enabled.)  Fails if the target already exists in
    /// the repo with a different hash, or if it has the same hash but is not a symlink.  Using the
    /// `replace_behavior` parameter, you can decide what happens if it exists with the same hash
    /// and file type - skip, fail, or replace.
    pub async fn link_target(
        &self,
        input_path: &Path,
        outdir: &Path,
        replace_behavior: PathExists,
        target_filename: Option<&TargetName>,
    ) -> Result<()> {
        ensure!(
            is_file(input_path).await,
            error::PathIsNotFileSnafu { path: input_path }
        );
        match self
            .target_path(input_path, outdir, target_filename)
            .await?
        {
            TargetPath::New { path } => {
                symlink(input_path, &path)
                    .await
                    .context(error::LinkCreateSnafu { path })?;
            }
            TargetPath::Symlink { path } => match replace_behavior {
                PathExists::Skip => {}
                PathExists::Fail => error::PathExistsFailSnafu { path }.fail()?,
                PathExists::Replace => {
                    remove_file(&path)
                        .await
                        .context(error::RemoveTargetSnafu { path: &path })?;
                    symlink(input_path, &path)
                        .await
                        .context(error::LinkCreateSnafu { path })?;
                }
            },
            TargetPath::File { path } => {
                error::TargetFileTypeMismatchSnafu {
                    expected: "symlink",
                    found: "regular file",
                    path,
                }
                .fail()?;
            }
        }

        Ok(())
    }

    /// Copies a single target to the desired directory. If `target_filename` is given, it becomes
    /// the filename suffix, otherwise the original filename is used. (A unique filename prefix is
    /// used if consistent hashing is enabled.)  Fails if the target already exists in the repo
    /// with a different hash, or if it has the same hash but is not a regular file.  Using the
    /// `replace_behavior` parameter, you can decide what happens if it exists with the same hash
    /// and file type - skip, fail, or replace.
    pub async fn copy_target(
        &self,
        input_path: &Path,
        outdir: &Path,
        replace_behavior: PathExists,
        target_filename: Option<&TargetName>,
    ) -> Result<()> {
        ensure!(
            is_file(input_path).await,
            error::PathIsNotFileSnafu { path: input_path }
        );
        match self
            .target_path(input_path, outdir, target_filename)
            .await?
        {
            TargetPath::New { path } => {
                copy(input_path, &path)
                    .await
                    .context(error::FileWriteSnafu { path })?;
            }
            TargetPath::File { path } => match replace_behavior {
                PathExists::Skip => {}
                PathExists::Fail => error::PathExistsFailSnafu { path }.fail()?,
                PathExists::Replace => {
                    remove_file(&path)
                        .await
                        .context(error::RemoveTargetSnafu { path: &path })?;
                    copy(input_path, &path)
                        .await
                        .context(error::FileWriteSnafu { path })?;
                }
            },
            TargetPath::Symlink { path } => {
                error::TargetFileTypeMismatchSnafu {
                    expected: "regular file",
                    found: "symlink",
                    path,
                }
                .fail()?;
            }
        }

        Ok(())
    }
}

impl TargetsWalker for SignedRepository {
    fn targets(&self) -> HashMap<TargetName, &Target> {
        // Since there is access to `targets.json` metadata, all targets
        // can be found using `targets_map()`
        self.targets.signed.signed.targets_map()
    }

    fn consistent_snapshot(&self) -> bool {
        self.root.signed.signed.consistent_snapshot
    }
}

/// A set of signed targets role metadata.
#[derive(Debug)]
pub struct SignedDelegatedTargets {
    pub(crate) roles: Vec<SignedRole<DelegatedTargets>>,
    pub(crate) consistent_snapshot: bool,
}

impl SignedDelegatedTargets {
    /// Writes the metadata to the given directory. If consistent snapshots
    /// are used, the appropriate files are prefixed with their version.
    pub async fn write<P>(&self, outdir: P, consistent_snapshot: bool) -> Result<()>
    where
        P: AsRef<Path>,
    {
        for targets in &self.roles {
            targets.write(&outdir, consistent_snapshot).await?;
        }
        Ok(())
    }

    /// Returns all `SignedRole<DelegatedTargets>>` contained by this `SignedDelegatedTargets`
    pub fn roles(self) -> Vec<SignedRole<DelegatedTargets>> {
        self.roles
    }

    /// Crawls a given directory and symlinks any targets found to the given
    /// "out" directory. If consistent snapshots are used, the target files
    /// are prefixed with their `sha256`.
    ///
    /// For each file found in the `indir`, the method gets the filename and
    /// if the filename exists in `Targets`, the file's sha256 is compared
    /// against the data in `Targets`. If this data does not match, the
    /// method will fail.
    pub async fn link_targets<P1, P2>(
        &self,
        indir: P1,
        outdir: P2,
        replace_behavior: PathExists,
    ) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        self.walk_targets(
            indir.as_ref(),
            outdir.as_ref(),
            Self::link_target,
            replace_behavior,
        )
        .await
    }

    /// Crawls a given directory and copies any targets found to the given
    /// "out" directory. If consistent snapshots are used, the target files
    /// are prefixed with their `sha256`.
    ///
    /// For each file found in the `indir`, the method gets the filename and
    /// if the filename exists in `Targets`, the file's sha256 is compared
    /// against the data in `Targets`. If this data does not match, the
    /// method will fail.
    pub async fn copy_targets<P1, P2>(
        &self,
        indir: P1,
        outdir: P2,
        replace_behavior: PathExists,
    ) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        self.walk_targets(
            indir.as_ref(),
            outdir.as_ref(),
            Self::copy_target,
            replace_behavior,
        )
        .await
    }

    /// Symlinks a single target to the desired directory. If `target_filename` is given, it
    /// becomes the filename suffix, otherwise the original filename is used. (A unique filename
    /// prefix is used if consistent snapshots are enabled.)  Fails if the target already exists in
    /// the repo with a different hash, or if it has the same hash but is not a symlink.  Using the
    /// `replace_behavior` parameter, you can decide what happens if it exists with the same hash
    /// and file type - skip, fail, or replace.
    pub async fn link_target(
        &self,
        input_path: &Path,
        outdir: &Path,
        replace_behavior: PathExists,
        target_filename: Option<&TargetName>,
    ) -> Result<()> {
        ensure!(
            is_file(input_path).await,
            error::PathIsNotFileSnafu { path: input_path }
        );
        match self
            .target_path(input_path, outdir, target_filename)
            .await?
        {
            TargetPath::New { path } => {
                symlink(input_path, &path)
                    .await
                    .context(error::LinkCreateSnafu { path })?;
            }
            TargetPath::Symlink { path } => match replace_behavior {
                PathExists::Skip => {}
                PathExists::Fail => error::PathExistsFailSnafu { path }.fail()?,
                PathExists::Replace => {
                    remove_file(&path)
                        .await
                        .context(error::RemoveTargetSnafu { path: &path })?;
                    symlink(input_path, &path)
                        .await
                        .context(error::LinkCreateSnafu { path })?;
                }
            },
            TargetPath::File { path } => {
                error::TargetFileTypeMismatchSnafu {
                    expected: "symlink",
                    found: "regular file",
                    path,
                }
                .fail()?;
            }
        }

        Ok(())
    }

    /// Copies a single target to the desired directory. If `target_filename` is given, it becomes
    /// the filename suffix, otherwise the original filename is used. (A unique filename prefix is
    /// used if consistent hashing is enabled.)  Fails if the target already exists in the repo
    /// with a different hash, or if it has the same hash but is not a regular file.  Using the
    /// `replace_behavior` parameter, you can decide what happens if it exists with the same hash
    /// and file type - skip, fail, or replace.
    pub async fn copy_target(
        &self,
        input_path: &Path,
        outdir: &Path,
        replace_behavior: PathExists,
        target_filename: Option<&TargetName>,
    ) -> Result<()> {
        ensure!(
            is_file(input_path).await,
            error::PathIsNotFileSnafu { path: input_path }
        );
        match self
            .target_path(input_path, outdir, target_filename)
            .await?
        {
            TargetPath::New { path } => {
                copy(input_path, &path)
                    .await
                    .context(error::FileWriteSnafu { path })?;
            }
            TargetPath::File { path } => match replace_behavior {
                PathExists::Skip => {}
                PathExists::Fail => error::PathExistsFailSnafu { path }.fail()?,
                PathExists::Replace => {
                    remove_file(&path)
                        .await
                        .context(error::RemoveTargetSnafu { path: &path })?;
                    copy(input_path, &path)
                        .await
                        .context(error::FileWriteSnafu { path })?;
                }
            },
            TargetPath::Symlink { path } => {
                error::TargetFileTypeMismatchSnafu {
                    expected: "regular file",
                    found: "symlink",
                    path,
                }
                .fail()?;
            }
        }

        Ok(())
    }
}

impl TargetsWalker for SignedDelegatedTargets {
    fn targets(&self) -> HashMap<TargetName, &Target> {
        // There are multiple `Targets` roles here that may or may not be related,
        // so find all of the `Target`s related to each role and combine them.
        let mut targets_map = HashMap::new();
        for targets in &self.roles {
            targets_map.extend(targets.signed.signed.targets_map());
        }
        targets_map
    }

    fn consistent_snapshot(&self) -> bool {
        self.consistent_snapshot
    }
}

/// Wrapper trait to help with HKTB lifetimes
trait WalkOperator<S, In, Out, TN>:
    FnMut(S, In, Out, PathExists, Option<TN>) -> <Self as WalkOperator<S, In, Out, TN>>::Fut
{
    type Fut: Future<Output = <Self as WalkOperator<S, In, Out, TN>>::Output> + Send;
    type Output;
}
impl<S, In, Out, TN, F, Fut> WalkOperator<S, In, Out, TN> for F
where
    F: FnMut(S, In, Out, PathExists, Option<TN>) -> Fut,
    Fut: Future + Send,
{
    type Fut = Fut;
    type Output = Fut::Output;
}

/// `TargetsWalker` is used to unify the logic related to copying and linking targets.
/// `TargetsWalker`'s default implementation of `walk_targets()` and `target_path()` use
/// the trait's `targets()` and `consistent_snapshot()` methods to get a map of targets and
/// also determine if a file prefix needs to be used.
#[async_trait]
trait TargetsWalker {
    /// Returns a map of all targets this manager is responsible for
    fn targets(&self) -> HashMap<TargetName, &Target>;
    /// Determines whether or not consistent snapshot filenames should be used
    fn consistent_snapshot(&self) -> bool;

    /// Walks a given directory and calls the provided function with every file found.
    /// The function is given the file path, the output directory where the user expects
    /// it to go, and optionally a desired filename.
    async fn walk_targets<F>(
        &self,
        indir: &Path,
        outdir: &Path,
        mut f: F,
        replace_behavior: PathExists,
    ) -> Result<()>
    where
        F: for<'a, 'b, 'c, 'd> WalkOperator<
                &'a Self,
                &'b Path,
                &'c Path,
                &'d TargetName,
                Output = Result<()>,
            > + Send,
    {
        create_dir_all(outdir)
            .await
            .context(error::DirCreateSnafu { path: outdir })?;

        // Get the absolute path of the indir and outdir
        let abs_indir = canonicalize(indir)
            .await
            .context(error::AbsolutePathSnafu { path: indir })?;

        // Walk the absolute path of the indir. Using the absolute path here
        // means that `entry.path()` call will return its absolute path.
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let root = abs_indir.clone();
        tokio::task::spawn_blocking(move || {
            let walker = WalkDir::new(&root).follow_links(true);
            for entry in walker {
                if tx.blocking_send(entry).is_err() {
                    // Receiver error'ed out
                    break;
                };
            }
        });

        while let Some(entry) = rx.recv().await {
            let entry = entry.context(error::WalkDirSnafu {
                directory: &abs_indir,
            })?;

            // If the entry is not a file, move on
            if !entry.file_type().is_file() {
                continue;
            };

            // Call the requested function to manipulate the path we found
            if let Err(e) = f(self, entry.path(), outdir, replace_behavior, None).await {
                match e {
                    // If we found a path that isn't a known target in the repo, skip it.
                    error::Error::PathIsNotTarget { .. } => continue,
                    _ => return Err(e),
                }
            }
        }

        Ok(())
    }

    /// Determines the output path of a target based on consistent snapshot rules. Returns Err if
    /// the target already exists in the repo with a different hash, or if the target is not known
    /// to the repo.  (We're dealing with a signed repo, so it's too late to add targets.)
    async fn target_path(
        &self,
        input: &Path,
        outdir: &Path,
        target_filename: Option<&TargetName>,
    ) -> Result<TargetPath> {
        let outdir = tokio::fs::canonicalize(outdir)
            .await
            .context(error::AbsolutePathSnafu { path: outdir })?;

        // If the caller requested a specific target filename, use that, otherwise use the filename
        // component of the input path.
        let target_name = if let Some(target_filename) = target_filename {
            Cow::Borrowed(target_filename)
        } else {
            Cow::Owned(TargetName::new(
                input
                    .file_name()
                    .context(error::NoFileNameSnafu { path: input })?
                    .to_str()
                    .context(error::PathUtf8Snafu { path: input })?,
            )?)
        };

        // create a Target object using the input path.
        let target_from_path = Target::from_path(input)
            .await
            .context(error::TargetFromPathSnafu { path: input })?;

        // Use the file name to see if a target exists in the repo
        // with that name. If so...
        let repo_targets = &self.targets();
        let repo_target = repo_targets
            .get(&target_name)
            .context(error::PathIsNotTargetSnafu { path: input })?;
        // compare the hashes of the target from the repo and the target we just created.  They
        // should match, or we alert the caller; if target replacement is intended, it should
        // happen earlier, in RepositoryEditor.
        ensure!(
            target_from_path.hashes.sha256 == repo_target.hashes.sha256
                || target_from_path.hashes.sha512 == repo_target.hashes.sha512,
            error::HashMismatchSnafu {
                context: "target",
                calculated: format!(
                    "SHA-256: {}, SHA-512: {}",
                    hex::encode(
                        target_from_path
                            .hashes
                            .sha256
                            .as_ref()
                            .map_or(&[] as &[u8], |d| d.as_ref())
                    ),
                    hex::encode(
                        target_from_path
                            .hashes
                            .sha512
                            .as_ref()
                            .map_or(&[] as &[u8], |d| d.as_ref())
                    )
                ),
                expected: format!(
                    "SHA-256: {}, SHA-512: {}",
                    hex::encode(
                        repo_target
                            .hashes
                            .sha256
                            .as_ref()
                            .map_or(&[] as &[u8], |d| d.as_ref())
                    ),
                    hex::encode(
                        repo_target
                            .hashes
                            .sha512
                            .as_ref()
                            .map_or(&[] as &[u8], |d| d.as_ref())
                    )
                ),
            }
        );

        let dest = if self.consistent_snapshot() {
            outdir.join(format!(
                "{}.{}",
                hex::encode(
                    target_from_path
                        .hashes
                        .sha256
                        .or(target_from_path.hashes.sha512)
                        .unwrap()
                ),
                target_name.resolved()
            ))
        } else {
            outdir.join(target_name.resolved())
        };

        // Return the target path, using the `TargetPath` enum that represents the type of file
        // that already exists at that path (if any)
        if !dest.exists() {
            return Ok(TargetPath::New { path: dest });
        }

        // If we're using consistent snapshots, filenames include the checksum, so we know they're
        // unique; if we're not, then there could be a target from another repo with the same name
        // but different checksum.  We can't assume such conflicts are OK, so we fail.
        if !self.consistent_snapshot() {
            self.verify_existing_target(dest.clone(), repo_target)
                .await?;
        }

        let metadata = symlink_metadata(&dest)
            .await
            .context(error::FileMetadataSnafu { path: &dest })?;
        if metadata.file_type().is_file() {
            Ok(TargetPath::File { path: dest })
        } else if metadata.file_type().is_symlink() {
            Ok(TargetPath::Symlink { path: dest })
        } else {
            error::InvalidFileTypeSnafu { path: dest }.fail()
        }
    }

    async fn verify_existing_target(&self, dest: PathBuf, repo_target: &&Target) -> Result<()> {
        let url = Url::from_file_path(&dest)
            .ok()
            .context(error::FileUrlSnafu { path: &dest })?;

        let stream = FilesystemTransport
            .fetch(url.clone())
            .await
            .with_context(|_| error::TransportSnafu { url: url.clone() })?;

        let sha256_verified = if let Some(sha256) = &repo_target.hashes.sha256 {
            let sha256_stream = DigestAdapter::sha256(stream, sha256, url.clone());
            sha256_stream.try_for_each(|_| ready(Ok(()))).await.is_ok()
        } else {
            false
        };

        let sha512_verified = if sha256_verified {
            true
        } else {
            let stream = FilesystemTransport
                .fetch(url.clone())
                .await
                .with_context(|_| error::TransportSnafu { url: url.clone() })?;

            if let Some(sha512) = &repo_target.hashes.sha512 {
                let sha512_stream = DigestAdapter::sha512(stream, sha512, url.clone());
                sha512_stream.try_for_each(|_| ready(Ok(()))).await.is_ok()
            } else {
                false
            }
        };

        if !sha256_verified && !sha512_verified {
            error::HashMismatchSnafu {
                context: "target",
                calculated: format!(
                    "SHA-256: {}, SHA-512: {}",
                    hex::encode(
                        repo_target
                            .hashes
                            .sha256
                            .as_ref()
                            .map_or(&[] as &[u8], |d| d.as_ref())
                    ),
                    hex::encode(
                        repo_target
                            .hashes
                            .sha512
                            .as_ref()
                            .map_or(&[] as &[u8], |d| d.as_ref())
                    )
                ),
                expected: "None".to_string(),
            }
            .fail()
        } else {
            Ok(())
        }
    }
}
