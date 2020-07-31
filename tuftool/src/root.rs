// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use crate::{load_file, write_file};
use chrono::{DateTime, Timelike, Utc};
use maplit::hashmap;
use ring::rand::SystemRandom;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::HashMap;
use std::io::Write;
use std::num::NonZeroU64;
use std::path::PathBuf;
use structopt::StructOpt;
use tempfile::NamedTempFile;
use tough::editor::signed::SignedRole;
use tough::key_source::KeySource;
use tough::schema::decoded::{Decoded, Hex};
use tough::schema::{key::Key, KeyHolder, RoleKeys, RoleType, Root, Signed};
use tough::sign::{parse_keypair, Sign};

#[derive(Debug, StructOpt)]
pub(crate) enum Command {
    /// Create a new root.json metadata file
    Init {
        /// Path to new root.json
        path: PathBuf,
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
        #[structopt(parse(try_from_str = parse_datetime))]
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
    /// Add a key (public or private) to a role
    AddKey {
        /// Path to root.json
        path: PathBuf,
        /// The new key
        #[structopt(parse(try_from_str = parse_key_source))]
        key_source: Box<dyn KeySource>,
        /// The role to add the key to
        #[structopt(short = "r", long = "role")]
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
        #[structopt(parse(try_from_str = parse_key_source))]
        key_source: Box<dyn KeySource>,
        /// Bit length of new key
        #[structopt(short = "b", long = "bits", default_value = "2048")]
        bits: u16,
        /// Public exponent of new key
        #[structopt(short = "e", long = "exp", default_value = "65537")]
        exponent: u32,
        /// The role to add the key to
        #[structopt(short = "r", long = "role")]
        roles: Vec<RoleType>,
    },
    /// Sign the given root.json
    Sign {
        /// Path to root.json
        path: PathBuf,
        #[structopt(parse(try_from_str = parse_key_source))]
        key_source: Box<dyn KeySource>,
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
            Command::Init { path } => Command::init(&path),
            Command::BumpVersion { path } => Command::bump_version(&path),
            Command::Expire { path, time } => Command::expire(&path, &time),
            Command::SetThreshold {
                path,
                role,
                threshold,
            } => Command::set_threshold(&path, role, threshold),
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
            Command::Sign { path, key_source } => Command::sign(&path, key_source),
        }
    }

    fn init(path: &PathBuf) -> Result<()> {
        write_file(
            path,
            &Signed {
                signed: Root {
                    spec_version: crate::SPEC_VERSION.to_owned(),
                    consistent_snapshot: true,
                    version: NonZeroU64::new(1).unwrap(),
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

    fn bump_version(path: &PathBuf) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        root.signed.version = NonZeroU64::new(
            root.signed
                .version
                .get()
                .checked_add(1)
                .context(error::VersionOverflow)?,
        )
        .context(error::VersionZero)?;
        clear_sigs(&mut root);
        write_file(path, &root)
    }

    fn expire(path: &PathBuf, time: &DateTime<Utc>) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        root.signed.expires = round_time(*time);
        clear_sigs(&mut root);
        write_file(path, &root)
    }

    fn set_threshold(path: &PathBuf, role: RoleType, threshold: NonZeroU64) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        root.signed
            .roles
            .entry(role)
            .and_modify(|rk| rk.threshold = threshold)
            .or_insert_with(|| role_keys!(threshold));
        clear_sigs(&mut root);
        write_file(path, &root)
    }

    #[allow(clippy::borrowed_box)]
    fn add_key(path: &PathBuf, roles: &[RoleType], key_source: &Box<dyn KeySource>) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;
        let key_pair = key_source
            .as_sign()
            .context(error::KeyPairFromKeySource)?
            .tuf_key();
        let key_id = hex::encode(add_key(&mut root.signed, roles, key_pair)?);
        clear_sigs(&mut root);
        println!("{}", key_id);
        write_file(path, &root)
    }

    fn remove_key(path: &PathBuf, key_id: &Decoded<Hex>, role: Option<RoleType>) -> Result<()> {
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
        path: &PathBuf,
        roles: &[RoleType],
        key_source: &Box<dyn KeySource>,
        bits: u16,
        exponent: u32,
    ) -> Result<()> {
        let mut root: Signed<Root> = load_file(path)?;

        // ring doesn't support RSA key generation yet
        // https://github.com/briansmith/ring/issues/219
        let mut command = std::process::Command::new("openssl");
        command.args(&["genpkey", "-algorithm", "RSA", "-pkeyopt"]);
        command.arg(format!("rsa_keygen_bits:{}", bits));
        command.arg("-pkeyopt");
        command.arg(format!("rsa_keygen_pubexp:{}", exponent));

        let command_str = format!("{:?}", command);
        let output = command.output().context(error::CommandExec {
            command_str: &command_str,
        })?;
        ensure!(
            output.status.success(),
            error::CommandStatus {
                command_str: &command_str,
                status: output.status
            }
        );
        let stdout =
            String::from_utf8(output.stdout).context(error::CommandUtf8 { command_str })?;

        let key_pair = parse_keypair(stdout.as_bytes()).context(error::KeyPairParse)?;
        let key_id = hex::encode(add_key(&mut root.signed, roles, key_pair.tuf_key())?);
        key_source
            .write(&stdout, &key_id)
            .context(error::WriteKeySource)?;
        clear_sigs(&mut root);
        println!("{}", key_id);
        write_file(path, &root)
    }

    fn sign(path: &PathBuf, key_source: Box<dyn KeySource>) -> Result<()> {
        let root: Signed<Root> = load_file(path)?;

        let signed_root = SignedRole::new(
            root.signed.clone(),
            &KeyHolder::Root(root.signed),
            &[key_source],
            &SystemRandom::new(),
        )
        .context(error::SignRoot { path })?;

        // Use `tempfile::NamedTempFile::persist` to perform an atomic file write.
        let parent = path.parent().context(error::PathParent { path })?;
        let mut writer =
            NamedTempFile::new_in(parent).context(error::FileTempCreate { path: parent })?;
        writer
            .write_all(signed_root.buffer())
            .context(error::FileWrite { path })?;
        writer.persist(path).context(error::FilePersist { path })?;
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
        let key_id = key.key_id().context(error::KeyId)?;
        ensure!(
            !root.keys.contains_key(&key_id),
            error::KeyDuplicate {
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
