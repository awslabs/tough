// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provides the `SignedRepository` object which represents the output of `RepositoryEditor` after
//! signing, ready to be written to disk.

use crate::editor::keys::get_root_keys;
use crate::error::{self, Result};
use crate::io::DigestAdapter;
use crate::key_source::KeySource;
use crate::schema::{
    Role, RoleType, Root, Signature, Signed, Snapshot, Target, Targets, Timestamp,
};
use olpc_cjson::CanonicalFormatter;
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_plain::forward_from_str_to_serde;
use snafu::{ensure, OptionExt, ResultExt};
use std::fs;
use std::os::unix::fs::symlink;
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
    pub(crate) length: u64,
}

impl<T> SignedRole<T>
where
    T: Role + Serialize,
{
    /// Creates a new `SignedRole`
    pub fn new(
        role: T,
        root: &Root,
        keys: &[Box<dyn KeySource>],
        rng: &dyn SecureRandom,
    ) -> Result<Self> {
        let root_keys = get_root_keys(root, keys)?;

        let role_keys = root.roles.get(&T::TYPE).context(error::NoRoleKeysinRoot {
            role: T::TYPE.to_string(),
        })?;
        // Ensure the keys we have available to us will allow us
        // to sign this role. The role's key ids must match up with one of
        // the keys provided.
        let (signing_key_id, signing_key) = root_keys
            .iter()
            .find(|(keyid, _signing_key)| role_keys.keyids.contains(&keyid))
            .context(error::SigningKeysNotFound {
                role: T::TYPE.to_string(),
            })?;

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
            .context(error::SerializeRole {
                role: T::TYPE.to_string(),
            })?;
        let sig = signing_key.sign(&data, rng)?;

        // Add the signatures to the `Signed` struct for this role
        role.signatures.push(Signature {
            keyid: signing_key_id.clone(),
            sig: sig.into(),
        });

        // Serialize the newly signed role, and calculate its length and
        // sha256.
        let mut buffer = serde_json::to_vec_pretty(&role).context(error::SerializeSignedRole {
            role: T::TYPE.to_string(),
        })?;
        buffer.push(b'\n');
        let length = buffer.len() as u64;

        let mut sha256 = [0; SHA256_OUTPUT_LEN];
        sha256.copy_from_slice(digest(&SHA256, &buffer).as_ref());

        // Create the `SignedRole` containing, the `Signed<role>`, serialized
        // buffer, length and sha256.
        let signed_role = SignedRole {
            signed: role,
            buffer,
            sha256,
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

    /// Provides the sha256 digest of the signed role.
    pub fn sha256(&self) -> &[u8] {
        &self.sha256
    }

    /// Provides the length in bytes of the serialized representation of the signed role.
    pub fn length(&self) -> &u64 {
        &self.length
    }

    /// Write the current role's buffer to the given directory with the
    /// appropriate file name.
    pub(crate) fn write<P>(&self, outdir: P, consistent_snapshot: bool) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let outdir = outdir.as_ref();
        std::fs::create_dir_all(outdir).context(error::DirCreate { path: outdir })?;

        let filename = match T::TYPE {
            RoleType::Targets => {
                if consistent_snapshot {
                    format!("{}.targets.json", self.signed.signed.version())
                } else {
                    "targets.json".to_string()
                }
            }
            RoleType::Snapshot => {
                if consistent_snapshot {
                    format!("{}.snapshot.json", self.signed.signed.version())
                } else {
                    "snapshot.json".to_string()
                }
            }
            RoleType::Timestamp => "timestamp.json".to_string(),
            RoleType::Root => format!("{}.root.json", self.signed.signed.version()),
        };

        let path = outdir.join(filename);
        std::fs::write(&path, &self.buffer).context(error::FileWrite { path })
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

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
}

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
forward_from_str_to_serde!(PathExists);

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

impl SignedRepository {
    /// Writes the metadata to the given directory. If consistent snapshots
    /// are used, the appropriate files are prefixed with their version.
    pub fn write<P>(&self, outdir: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let consistent_snapshot = self.root.signed.signed.consistent_snapshot;
        self.root.write(&outdir, consistent_snapshot)?;
        self.targets.write(&outdir, consistent_snapshot)?;
        self.snapshot.write(&outdir, consistent_snapshot)?;
        self.timestamp.write(&outdir, consistent_snapshot)
    }

    /// Walks a given directory and calls the provided function with every file found.
    /// The function is given the file path, the output directory where the user expects
    /// it to go, and optionally a desired filename.
    fn walk_targets<F>(
        &self,
        indir: &Path,
        outdir: &Path,
        f: F,
        replace_behavior: PathExists,
    ) -> Result<()>
    where
        F: Fn(&Self, &Path, &Path, PathExists, Option<&str>) -> Result<()>,
    {
        std::fs::create_dir_all(outdir).context(error::DirCreate { path: outdir })?;

        // Get the absolute path of the indir and outdir
        let abs_indir =
            std::fs::canonicalize(indir).context(error::AbsolutePath { path: indir })?;

        // Walk the absolute path of the indir. Using the absolute path here
        // means that `entry.path()` call will return its absolute path.
        let walker = WalkDir::new(&abs_indir).follow_links(true);
        for entry in walker {
            let entry = entry.context(error::WalkDir {
                directory: &abs_indir,
            })?;

            // If the entry is not a file, move on
            if !entry.file_type().is_file() {
                continue;
            };

            // Call the requested function to manipulate the path we found
            if let Err(e) = f(self, entry.path(), outdir, replace_behavior, None) {
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
    fn target_path(
        &self,
        input: &Path,
        outdir: &Path,
        target_filename: Option<&str>,
    ) -> Result<TargetPath> {
        let outdir = std::fs::canonicalize(outdir).context(error::AbsolutePath { path: outdir })?;

        // If the caller requested a specific target filename, use that, otherwise use the filename
        // component of the input path.
        let file_name = if let Some(target_filename) = target_filename {
            target_filename
        } else {
            input
                .file_name()
                .context(error::NoFileName { path: input })?
                .to_str()
                .context(error::PathUtf8 { path: input })?
        };

        // create a Target object using the input path.
        let target_from_path =
            Target::from_path(input).context(error::TargetFromPath { path: input })?;

        // Use the file name to see if a target exists in the repo
        // with that name. If so...
        let repo_targets = &self.targets.signed.signed.targets;
        let repo_target = repo_targets
            .get(file_name)
            .context(error::PathIsNotTarget { path: input })?;
        // compare the hashes of the target from the repo and the target we just created.  They
        // should match, or we alert the caller; if target replacement is intended, it should
        // happen earlier, in RepositoryEditor.
        ensure!(
            target_from_path.hashes.sha256 == repo_target.hashes.sha256,
            error::HashMismatch {
                context: "target",
                calculated: hex::encode(target_from_path.hashes.sha256),
                expected: hex::encode(&repo_target.hashes.sha256),
            }
        );

        let dest = if self.root.signed.signed.consistent_snapshot {
            outdir.join(format!(
                "{}.{}",
                hex::encode(&target_from_path.hashes.sha256),
                file_name
            ))
        } else {
            outdir.join(&file_name)
        };

        // Return the target path, using the `TargetPath` enum that represents the type of file
        // that already exists at that path (if any)
        if !dest.exists() {
            return Ok(TargetPath::New { path: dest });
        }

        // If we're using consistent snapshots, filenames include the checksum, so we know they're
        // unique; if we're not, then there could be a target from another repo with the same name
        // but different checksum.  We can't assume such conflicts are OK, so we fail.
        if !self.root.signed.signed.consistent_snapshot {
            // Use DigestAdapter to get a streaming checksum of the file without needing to hold
            // its contents.
            let f = fs::File::open(&dest).context(error::FileOpen { path: &dest })?;
            let mut reader = DigestAdapter::sha256(
                f,
                &repo_target.hashes.sha256,
                Url::from_file_path(&dest)
                    .ok() // dump unhelpful `()` error
                    .context(error::FileUrl { path: &dest })?,
            );
            let mut dev_null = std::io::sink();
            // The act of reading with the DigestAdapter verifies the checksum, assuming the read
            // succeeds.
            std::io::copy(&mut reader, &mut dev_null).context(error::FileRead { path: &dest })?;
        }

        let metadata = fs::symlink_metadata(&dest).context(error::FileMetadata { path: &dest })?;
        if metadata.file_type().is_file() {
            Ok(TargetPath::File { path: dest })
        } else if metadata.file_type().is_symlink() {
            Ok(TargetPath::Symlink { path: dest })
        } else {
            error::InvalidFileType { path: dest }.fail()
        }
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
    }

    /// Symlinks a single target to the desired directory. If `target_filename` is given, it
    /// becomes the filename suffix, otherwise the original filename is used. (A unique filename
    /// prefix is used if consistent snapshots are enabled.)  Fails if the target already exists in
    /// the repo with a different hash, or if it has the same hash but is not a symlink.  Using the
    /// `replace_behavior` parameter, you can decide what happens if it exists with the same hash
    /// and file type - skip, fail, or replace.
    pub fn link_target(
        &self,
        input_path: &Path,
        outdir: &Path,
        replace_behavior: PathExists,
        target_filename: Option<&str>,
    ) -> Result<()> {
        ensure!(
            input_path.is_file(),
            error::PathIsNotFile { path: input_path }
        );
        match self.target_path(input_path, outdir, target_filename)? {
            TargetPath::New { path } => {
                symlink(input_path, &path).context(error::LinkCreate { path })?;
            }
            TargetPath::Symlink { path } => match replace_behavior {
                PathExists::Skip => {}
                PathExists::Fail => error::PathExistsFail { path }.fail()?,
                PathExists::Replace => {
                    fs::remove_file(&path).context(error::RemoveTarget { path: &path })?;
                    symlink(input_path, &path).context(error::LinkCreate { path })?;
                }
            },
            TargetPath::File { path } => {
                error::TargetFileTypeMismatch {
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
    pub fn copy_target(
        &self,
        input_path: &Path,
        outdir: &Path,
        replace_behavior: PathExists,
        target_filename: Option<&str>,
    ) -> Result<()> {
        ensure!(
            input_path.is_file(),
            error::PathIsNotFile { path: input_path }
        );
        match self.target_path(input_path, outdir, target_filename)? {
            TargetPath::New { path } => {
                fs::copy(input_path, &path).context(error::FileWrite { path })?;
            }
            TargetPath::File { path } => match replace_behavior {
                PathExists::Skip => {}
                PathExists::Fail => error::PathExistsFail { path }.fail()?,
                PathExists::Replace => {
                    fs::remove_file(&path).context(error::RemoveTarget { path: &path })?;
                    fs::copy(input_path, &path).context(error::FileWrite { path })?;
                }
            },
            TargetPath::Symlink { path } => {
                error::TargetFileTypeMismatch {
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
