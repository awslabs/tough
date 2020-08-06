// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;

use std::fs::File;
use tempfile::TempDir;
use test_utils::{dir_url, test_data};
use tough::{ExpirationEnforcement, Limits, Repository, Settings};

#[test]
fn rotated_root() {
    let base = test_data().join("rotated-root");
    let datastore = TempDir::new().unwrap();

    let metadata_base_url = &dir_url(&base);
    let targets_base_url = &dir_url(base.join("targets"));

    let repo = Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: File::open(base.join("1.root.json")).unwrap(),
            datastore: datastore.as_ref(),
            metadata_base_url,
            targets_base_url,
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    assert_eq!(u64::from(repo.root().signed.version), 2);
}
