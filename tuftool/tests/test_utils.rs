// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use assert_cmd::Command;
use chrono::{Duration, Utc};
use std::io::Read;
use std::path::{Path, PathBuf};
use url::Url;

/// Utilities for tests. Not every test module uses every function, so we suppress unused warnings.

/// Returns the path to our test data directory
#[allow(unused)]
pub fn test_data() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.join("tough").join("tests").join("data")
}

/// Converts a filepath into a URI formatted string
#[allow(unused)]
pub fn dir_url<P: AsRef<Path>>(path: P) -> String {
    Url::from_directory_path(path).unwrap().to_string()
}

/// Returns a vector of bytes from any object with the Read trait
#[allow(unused)]
pub fn read_to_end<R: Read>(mut reader: R) -> Vec<u8> {
    let mut v = Vec::new();
    reader.read_to_end(&mut v).unwrap();
    v
}

/// Creates a repository with expired timestamp metadata.
#[allow(unused)]
pub fn create_expired_repo<P: AsRef<Path>>(repo_dir: P) {
    // Expired time stamp
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(-1)).unwrap();
    let timestamp_version: u64 = 31;
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(2)).unwrap();
    let snapshot_version: u64 = 25;
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let targets_version: u64 = 17;
    let targets_input_dir = test_data().join("tuf-reference-impl").join("targets");
    let root_json = test_data().join("simple-rsa").join("root.json");
    let root_key = test_data().join("snakeoil.pem");

    // Create a repo using tuftool and the reference tuf implementation data
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "create",
            "-t",
            targets_input_dir.to_str().unwrap(),
            "-o",
            repo_dir.as_ref().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--targets-expires",
            targets_expiration.to_rfc3339().as_str(),
            "--targets-version",
            format!("{}", targets_version).as_str(),
            "--snapshot-expires",
            snapshot_expiration.to_rfc3339().as_str(),
            "--snapshot-version",
            format!("{}", snapshot_version).as_str(),
            "--timestamp-expires",
            timestamp_expiration.to_rfc3339().as_str(),
            "--timestamp-version",
            format!("{}", timestamp_version).as_str(),
        ])
        .assert()
        .success();
}
