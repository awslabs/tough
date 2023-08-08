// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use crate::{load_file, write_file};
use chrono::{DateTime, Timelike, Utc};
use clap::Parser;
use log::warn;
use maplit::hashmap;
use ring::rand::SystemRandom;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::HashMap;
use std::io::Write;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use tough::editor::signed::SignedRole;
use tough::key_source::KeySource;
use tough::schema::decoded::{Decoded, Hex};
use tough::schema::{key::Key, KeyHolder, RoleKeys, RoleType, Root, Signed};
use tough::sign::{parse_keypair, Sign};

#[derive(Debug, Parser)]
pub(crate) enum Command {
    /// Create a new root.json metadata file
    Init {
        /// Path to new root.json
        path: PathBuf,
        /// Initial metadata file version
        #[clap(long)]
        version: Option<u64>,
    },
    /// Increment the version
    BumpVersion {
        /// Path to root.json
        path: PathBuf,
    },
    /// Set the expiration time for root.json
    Expire {
        /// Path to root.json
        path: PathBuf,
        /// Expiration of root; can be in full RFC 3339 format, or something like 'in
        /// 7 days'
        #[clap(parse(try_from_str = parse_datetime))]
        time: DateTime<Utc>,
    },
    /// Set the signature count threshold for a role
    SetThreshold {
        /// Path to root.json
        path: PathBuf,
        /// The role to set
        role: RoleType,
        /// The new threshold
        threshold: NonZeroU64,
    },
    /// Set the version number for root.json
    SetVersion {
        /// Path to root.json
        path: PathBuf,
        /// Version number
        version: NonZeroU64,
    },
    /// Add a key (public or private) to a role
    AddKey {
        /// Path to root.json
        path: PathBuf,
        /// The new key
        #[clap(parse(try_from_str = parse_key_source))]
        key_source: Box<dyn KeySource>,
        /// The role to add the key to
        #[clap(short = 'r', long = "role")]
        roles: Vec<RoleType>,
    },
    /// Remove a key ID, either entirely or from a single role
    RemoveKey {
        /// Path to root.json
        path: PathBuf,
        /// The key ID to remove
        key_id: Decoded<Hex>,
        /// Role to remove the key ID from (if provided, the public key will still be listed in the
        /// file)
        role: Option<RoleType>,
    },
    /// Generate a new RSA key pair, saving it to a file, and add it to a role
    GenRsaKey {
        /// Path to root.json
        path: PathBuf,
        /// Where to write the new key
        #[clap(parse(try_from_str = parse_key_source))]
        key_source: Box<dyn KeySource>,
        /// Bit length of new key
        #[clap(short = 'b', long = "bits", default_value = "2048")]
        bits: u16,
        /// Public exponent of new key
        #[clap(short = 'e', long = "exp", default_value = "65537")]
        exponent: u32,
        /// The role to add the key to
        #[clap(short = 'r', long = "role")]
        roles: Vec<RoleType>,
    },
    /// Sign the given root.json
    Sign {
        /// Path to root.json
        path: PathBuf,
        ///Key source(s) to sign the file with
        #[clap(short = 'k', long = "key",parse(try_from_str = parse_key_source))]
        key_sources: Vec<Box<dyn KeySource>>,
        ///Optional - Path of older root.json that contains the key-id
        #[clap(short = 'c', long = "cross-sign")]
        cross_sign: Option<PathBuf>,
        ///Ignore the threshold when signing with fewer keys
        #[clap(short = 'i', long = "ignore-threshold")]
        ignore_threshold: bool,
    },
}

macro_rules! role_keys {
    ($threshold:expr) => {
        RoleKeys {
            keyids: Vec::new(),
            threshold: $threshold,
            _extra: HashMap::new(),
        }
    };

    () => {
        // absurdly high threshold value so that someone realizes they need to change this
        role_keys!(NonZeroU64::new(1507).unwrap())
    };
}

impl Command {
    pub(crate) fn run(self) -> Result<()> {
        match self {
            Command::Init { path, version } => Command::init(&path, version),
            Command::BumpVersion { path } => Command::bump_version(&path),
            Command::Expire { path, time } => Command::expire(&path, &time),
            Command::SetThreshold {
                path,
                role,
                threshold,
            } => Command::set_threshold(&path, role, threshold),
            Command::SetVersion { path, version } => Command::set_version(&path, version),
            Command::AddKey {
                path,
                roles,
                key_source,
            } => Command::add_key(&path, &roles, &key_source),
            Command::RemoveKey { path, key_id, role } => Command::remove_key(&path, &key_id, role),
            Command::GenRsaKey {
                path,
                roles,
                key_source,
                bits,
                exponent,
            } => Command::gen_rsa_key(&path, &roles, &key_source, bits, exponent),
            Command::Sign {
                path,
                key_sources,
                cross_sign,
                ignore_threshold,
            } => Command::sign(&path, &key_sources, cross_sign, ignore_threshold),
        }
    }

    fn init(path: &Path, version: Option<u64>) -> Result<()> {
        let init_version = version.unwrap_or(1);
        write_file(
            path,
            &Signed {
                signed: Root {
                    spec_version: crate::SPEC_VERSION.to_owned(),
                    consistent_snapshot: true,
                    version: NonZeroU64::new(init_version).unwrap(),
                    expires: round_time(Utc::now()),
                    keys: HashMap::new(),
                    roles: hashmap! {
                        RoleType::Root => role_keys!(),
                        RoleType::Snapshot => role_keys!(),
                        RoleType::Targets => role_keys!(),
                        RoleType::Timestamp => role_keys!(),
                    },
                    _extra: HashMap::new(),
                },
                signatures: Vec::new(),
            },
        )
    }

    fn bump_version(path: &Path) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        root.signed.version = NonZeroU64::new(
            root.signed
                .version
                .get()
                .checked_add(1)
                .context(error::VersionOverflowSnafu)?,
        )
        .context(error::VersionZeroSnafu)?;
        clear_sigs(&mut root);
        write_file(path, &root)
    }

    fn expire(path: &Path, time: &DateTime<Utc>) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        root.signed.expires = round_time(*time);
        clear_sigs(&mut root);
        write_file(path, &root)
    }

    fn set_threshold(path: &Path, role: RoleType, threshold: NonZeroU64) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        root.signed
            .roles
            .entry(role)
            .and_modify(|rk| rk.threshold = threshold)
            .or_insert_with(|| role_keys!(threshold));
        clear_sigs(&mut root);
        write_file(path, &root)
    }

    fn set_version(path: &Path, version: NonZeroU64) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        root.signed.version = version;
        clear_sigs(&mut root);
        write_file(path, &root)
    }

    #[allow(clippy::borrowed_box)]
    fn add_key(path: &Path, roles: &[RoleType], key_source: &Box<dyn KeySource>) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        let key_pair = key_source
            .as_sign()
            .context(error::KeyPairFromKeySourceSnafu)?
            .tuf_key();
        let key_id = hex::encode(add_key(&mut root.signed, roles, key_pair)?);
        clear_sigs(&mut root);
        println!("{key_id}");
        write_file(path, &root)
    }

    fn remove_key(path: &Path, key_id: &Decoded<Hex>, role: Option<RoleType>) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        if let Some(role) = role {
            if let Some(role_keys) = root.signed.roles.get_mut(&role) {
                role_keys
                    .keyids
                    .iter()
                    .position(|k| k.eq(key_id))
                    .map(|pos| role_keys.keyids.remove(pos));
            }
        } else {
            for role_keys in root.signed.roles.values_mut() {
                role_keys
                    .keyids
                    .iter()
                    .position(|k| k.eq(key_id))
                    .map(|pos| role_keys.keyids.remove(pos));
            }
            root.signed.keys.remove(key_id);
        }
        clear_sigs(&mut root);
        write_file(path, &root)
    }

    #[allow(clippy::borrowed_box)]
    fn gen_rsa_key(
        path: &Path,
        roles: &[RoleType],
        key_source: &Box<dyn KeySource>,
        bits: u16,
        exponent: u32,
    ) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;

        // ring doesn't support RSA key generation yet
        // https://github.com/briansmith/ring/issues/219
        let mut command = std::process::Command::new("openssl");
        command.args(["genpkey", "-algorithm", "RSA", "-pkeyopt"]);
        command.arg(format!("rsa_keygen_bits:{bits}"));
        command.arg("-pkeyopt");
        command.arg(format!("rsa_keygen_pubexp:{exponent}"));

        let command_str = format!("{command:?}");
        let output = command.output().context(error::CommandExecSnafu {
            command_str: &command_str,
        })?;
        ensure!(
            output.status.success(),
            error::CommandStatusSnafu {
                command_str: &command_str,
                status: output.status
            }
        );
        let stdout =
            String::from_utf8(output.stdout).context(error::CommandUtf8Snafu { command_str })?;

        let key_pair = parse_keypair(stdout.as_bytes()).context(error::KeyPairParseSnafu)?;
        let key_id = hex::encode(add_key(&mut root.signed, roles, key_pair.tuf_key())?);
        key_source
            .write(&stdout, &key_id)
            .context(error::WriteKeySourceSnafu)?;
        clear_sigs(&mut root);
        println!("{key_id}");
        write_file(path, &root)
    }

    fn sign(
        path: &Path,
        key_source: &[Box<dyn KeySource>],
        cross_sign: Option<PathBuf>,
        ignore_threshold: bool,
    ) -> Result<()> {
        let root: Signed<Root> = load_file(path)?;
        // get the root based on cross-sign
        let loaded_root = match cross_sign {
            None => root.clone(),
            Some(cross_sign_root) => load_file(&cross_sign_root)?,
        };
        // sign the root
        let mut signed_root = SignedRole::new(
            root.signed.clone(),
            &KeyHolder::Root(loaded_root.signed),
            key_source,
            &SystemRandom::new(),
        )
        .context(error::SignRootSnafu { path })?;

        // append the existing signatures if present
        if !root.signatures.is_empty() {
            signed_root = signed_root
                .add_old_signatures(root.signatures)
                .context(error::SignRootSnafu { path })?;
        }

        // Quick check that root is signed by enough key IDs, in all its roles.
        for (roletype, rolekeys) in &signed_root.signed().signed.roles {
            let threshold = rolekeys.threshold.get();
            let keyids = rolekeys.keyids.len();
            if threshold > keyids as u64 {
                // Return an error when the referenced root.json isn't compliant with the
                // threshold. The referenced file could be a root.json used for cross signing,
                // which wasn't signed with enough keys.
                if !ignore_threshold {
                    return Err(error::Error::UnstableRoot {
                        role: *roletype,
                        threshold,
                        actual: keyids,
                    });
                }
                // Print out a warning to let the user know that the referenced root.json
                // file isn't compliant with the threshold specified for the role type.
                warn!(
                    "Loaded unstable root, role '{}' contains '{}' keys, expected '{}'",
                    *roletype, threshold, keyids
                );
            }
        }

        // Signature check for root
        let threshold = signed_root
            .signed()
            .signed
            .roles
            .get(&RoleType::Root)
            .ok_or(error::Error::UnstableRoot {
                // The code should never reach this point
                role: RoleType::Root,
                threshold: 0,
                actual: 0,
            })?
            .threshold
            .get();
        let signature_count = signed_root.signed().signatures.len();
        if threshold > signature_count as u64 {
            // Return an error when the "ignore-threshold" flag wasn't set
            if !ignore_threshold {
                return Err(error::Error::SignatureRoot {
                    threshold,
                    signature_count,
                });
            }
            // Print out a warning letting the user know that the target file isn't compliant with
            // the threshold used for the root role.
            warn!(
                "The root.json file requires at least {} signatures, the target file contains {}",
                threshold, signature_count
            );
        }

        // Use `tempfile::NamedTempFile::persist` to perform an atomic file write.
        let parent = path.parent().context(error::PathParentSnafu { path })?;
        let mut writer =
            NamedTempFile::new_in(parent).context(error::FileTempCreateSnafu { path: parent })?;
        writer
            .write_all(signed_root.buffer())
            .context(error::FileWriteSnafu { path })?;
        writer
            .persist(path)
            .context(error::FilePersistSnafu { path })?;
        Ok(())
    }
}

fn round_time(time: DateTime<Utc>) -> DateTime<Utc> {
    // `Timelike::with_nanosecond` returns None only when passed a value >= 2_000_000_000
    time.with_nanosecond(0).unwrap()
}

/// Removes signatures from a role. Useful if the content is updated.
fn clear_sigs<T>(role: &mut Signed<T>) {
    role.signatures.clear();
}

/// Adds a key to the root role if not already present, and adds its key ID to the specified role.
fn add_key(root: &mut Root, role: &[RoleType], key: Key) -> Result<Decoded<Hex>> {
    let key_id = if let Some((key_id, _)) = root
        .keys
        .iter()
        .find(|(_, candidate_key)| key.eq(candidate_key))
    {
        key_id.clone()
    } else {
        // Key isn't present yet, so we need to add it
        let key_id = key.key_id().context(error::KeyIdSnafu)?;
        ensure!(
            !root.keys.contains_key(&key_id),
            error::KeyDuplicateSnafu {
                key_id: hex::encode(&key_id)
            }
        );
        root.keys.insert(key_id.clone(), key);
        key_id
    };

    for r in role {
        let entry = root.roles.entry(*r).or_insert_with(|| role_keys!());
        if !entry.keyids.contains(&key_id) {
            entry.keyids.push(key_id.clone());
        }
    }

    Ok(key_id)
}
