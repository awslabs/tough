// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};
use olpc_cjson::CanonicalFormatter;
use ring::rand::SecureRandom;
use serde::Serialize;
use snafu::ResultExt;
use std::collections::HashMap;
use tough::schema::decoded::{Decoded, Hex};
use tough::schema::{RoleType, Root, Signature, Signed};
use tough::sign::Sign;

pub(crate) type RootKeys = HashMap<Decoded<Hex>, Box<dyn Sign>>;

pub(crate) fn sign_metadata<T: Serialize>(
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
