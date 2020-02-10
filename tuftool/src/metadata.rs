// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};
use crate::key::RootKeys;
use olpc_cjson::CanonicalFormatter;
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};
use ring::rand::SecureRandom;
use serde::Serialize;
use snafu::ResultExt;
use std::num::NonZeroU64;
use std::path::PathBuf;
use tough::schema::{Role, RoleType, Root, Signature, Signed};

fn sign_metadata_inner<T: Serialize>(
    root: &Root,
    keys: &RootKeys,
    role_type: RoleType,
    role: &mut Signed<T>,
    rng: &dyn SecureRandom,
) -> Result<()> {
    if let Some(role_keys) = root.roles.get(&role_type) {
        for (keyid, key) in keys {
            if role_keys.keyids.contains(&keyid) {
                let mut data = Vec::new();
                let mut ser =
                    serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
                role.signed.serialize(&mut ser).context(error::SignJson)?;
                let sig = key.sign(&data, rng).context(error::Sign)?;
                role.signatures.push(Signature {
                    keyid: keyid.clone(),
                    sig: sig.into(),
                });
            }
        }
    }

    Ok(())
}

pub(crate) fn write_metadata<T: Role + Serialize>(
    outdir: &PathBuf,
    root: &Root,
    keys: &RootKeys,
    role: T,
    version: NonZeroU64,
    filename: &'static str,
    rng: &dyn SecureRandom,
) -> Result<([u8; SHA256_OUTPUT_LEN], u64)> {
    let metadir = outdir.join("metadata");
    std::fs::create_dir_all(&metadir).context(error::FileCreate { path: &metadir })?;

    let path = metadir.join(
        if T::TYPE != RoleType::Timestamp && root.consistent_snapshot {
            format!("{}.{}", version, filename)
        } else {
            filename.to_owned()
        },
    );

    let mut role = Signed {
        signed: role,
        signatures: Vec::new(),
    };

    sign_metadata(root, keys, &mut role, rng)?;

    let mut buf = serde_json::to_vec_pretty(&role).context(error::FileWriteJson { path: &path })?;
    buf.push(b'\n');
    std::fs::write(&path, &buf).context(error::FileCreate { path: &path })?;

    let mut sha256 = [0; SHA256_OUTPUT_LEN];
    sha256.copy_from_slice(digest(&SHA256, &buf).as_ref());
    Ok((sha256, buf.len() as u64))
}

pub(crate) fn sign_metadata<T: Role + Serialize>(
    root: &Root,
    keys: &RootKeys,
    role: &mut Signed<T>,
    rng: &dyn SecureRandom,
) -> Result<()> {
    sign_metadata_inner(root, keys, T::TYPE, role, rng)
}
