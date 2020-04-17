// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::Result;
use crate::key::sign_metadata;
use crate::root_digest::RootDigest;
use crate::source::parse_key_source;
use crate::{load_file, write_file};
use ring::rand::SystemRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use structopt::StructOpt;
use tough::key_source::KeySource;
use tough::schema::{RoleType, Signed};

#[derive(Debug, StructOpt)]
pub(crate) struct SignArgs {
    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// Key files to sign with
    #[structopt(short = "k", long = "key", parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Metadata file to sign
    metadata_file: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct PartialRole {
    #[serde(rename = "_type")]
    type_: RoleType,

    #[serde(flatten)]
    args: HashMap<String, serde_json::Value>,
}

impl SignArgs {
    pub(crate) fn run(&self) -> Result<()> {
        let root_digest = RootDigest::load(&self.root)?;
        let keys = root_digest.load_keys(&self.keys)?;
        let mut metadata: Signed<PartialRole> = load_file(&self.metadata_file)?;
        sign_metadata(
            &root_digest.root,
            &keys,
            metadata.signed.type_,
            &mut metadata,
            &SystemRandom::new(),
        )?;
        write_file(&self.metadata_file, &metadata)
    }
}
