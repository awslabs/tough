// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::error::{self, Result};
use crate::key_source::KeySource;
use crate::schema::decoded::{Decoded, Hex};
use crate::schema::{Delegations, Root};
use crate::sign::Sign;
use snafu::{ensure, ResultExt};
use std::collections::HashMap;

/// A map of key ID (from root.json) to its corresponding signing key
pub(crate) type RootKeys = HashMap<Decoded<Hex>, Box<dyn Sign>>;

/// Gets the corresponding keys from Root (root.json) for the given `KeySource`s.
/// This is a convenience function that wraps `Root.key_id()` for multiple
/// `KeySource`s.
pub(crate) fn get_root_keys(root: &Root, keys: &[Box<dyn KeySource>]) -> Result<RootKeys> {
    let mut root_keys = RootKeys::new();

    for source in keys {
        // Get a keypair from the given source
        let key_pair = source.as_sign().context(error::KeyPairFromKeySource)?;

        // If the keypair matches any of the keys in the root.json,
        // add its ID and corresponding keypair the map to be returned
        if let Some(key_id) = root.key_id(key_pair.as_ref()) {
            root_keys.insert(key_id, key_pair);
        }
    }
    ensure!(!root_keys.is_empty(), error::KeysNotFoundInRoot);
    Ok(root_keys)
}

/// Gets the corresponding keys from delegations for the given `KeySource`s.
/// This is a convenience function that wraps `Delegations.key_id()` for multiple
/// `KeySource`s.
pub(crate) fn get_targets_keys(
    delegations: &Delegations,
    keys: &[Box<dyn KeySource>],
) -> Result<RootKeys> {
    let mut root_keys = RootKeys::new();
    for source in keys {
        // Get a keypair from the given source
        let key_pair = source.as_sign().context(error::KeyPairFromKeySource)?;
        // If the keypair matches any of the keys in the delegations metadata,
        // add its ID and corresponding keypair the map to be returned
        if let Some(key_id) = delegations.key_id(key_pair.as_ref()) {
            root_keys.insert(key_id, key_pair);
        }
    }
    Ok(root_keys)
}
