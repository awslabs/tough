// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;

use assert_cmd::Command;
use chrono::{Duration, Utc};
use std::fs::File;
use tempfile::TempDir;
use tough::{ExpirationEnforcement, Limits, Repository, Settings};

#[test]
// Ensure we can read a repo created by the `tuftool` binary using the `tough` library
fn create_command() {
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version: u64 = 1234;
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version: u64 = 5432;
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version: u64 = 789;
    let targets_input_dir = test_utils::test_data()
        .join("tuf-reference-impl")
        .join("targets");
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = TempDir::new().unwrap();
    let load_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation targets
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "create",
            "-t",
            targets_input_dir.to_str().unwrap(),
            "-o",
            repo_dir.path().to_str().unwrap(),
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

    // Load our newly created repo
    let metadata_base_url = &test_utils::dir_url(repo_dir.path().join("metadata"));
    let targets_base_url = &test_utils::dir_url(repo_dir.path().join("targets"));
    let repo = Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: File::open(root_json).unwrap(),
            datastore: load_dir.as_ref(),
            metadata_base_url,
            targets_base_url,
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    // Ensure we can read the targets
    assert_eq!(
        test_utils::read_to_end(repo.read_target("file1.txt").unwrap().unwrap()),
        &b"This is an example target file."[..]
    );
    assert_eq!(
        test_utils::read_to_end(repo.read_target("file2.txt").unwrap().unwrap()),
        &b"This is an another example target file."[..]
    );
    assert_eq!(
        test_utils::read_to_end(repo.read_target("file3.txt").unwrap().unwrap()),
        &b"This is role1's target file."[..]
    );

    // Ensure the targets.json file is correct
    assert_eq!(
        repo.targets().signed.as_ref().version.get(),
        targets_version
    );
    assert_eq!(repo.targets().signed.as_ref().expires, targets_expiration);
    assert_eq!(repo.targets().signed.as_ref().targets.len(), 3);
    assert_eq!(
        repo.targets().signed.as_ref().targets["file1.txt"].length,
        31
    );
    assert_eq!(
        repo.targets().signed.as_ref().targets["file2.txt"].length,
        39
    );
    assert_eq!(
        repo.targets().signed.as_ref().targets["file3.txt"].length,
        28
    );
    assert_eq!(repo.targets().signatures.len(), 1);

    // Ensure the snapshot.json file is correct
    assert_eq!(repo.snapshot().signed.as_ref().version.get(), snapshot_version);
    assert_eq!(repo.snapshot().signed.as_ref().expires, snapshot_expiration);
    assert_eq!(repo.snapshot().signed.as_ref().meta.len(), 1);
    assert_eq!(
        repo.snapshot().signed.as_ref().version.get(),
        snapshot_version
    );
    assert_eq!(repo.snapshot().signed.as_ref().expires, snapshot_expiration);
    assert_eq!(repo.snapshot().signed.as_ref().meta.len(), 2);
    assert_eq!(
        repo.snapshot().signed.as_ref().meta["root.json"]
            .version
            .get(),
        1
    );
    assert_eq!(
        repo.snapshot().signed.as_ref().meta["targets.json"]
            .version
            .get(),
        targets_version
    );
    assert_eq!(repo.snapshot().signatures.len(), 1);

    // Ensure the timestamp.json file is correct
    assert_eq!(
        repo.timestamp().signed.as_ref().version.get(),
        timestamp_version
    );
    assert_eq!(
        repo.timestamp().signed.as_ref().expires,
        timestamp_expiration
    );
    assert_eq!(repo.timestamp().signed.as_ref().meta.len(), 1);
    assert_eq!(
        repo.timestamp().signed.as_ref().meta["snapshot.json"]
            .version
            .get(),
        snapshot_version
    );
    assert_eq!(repo.snapshot().signatures.len(), 1);
}

#[test]
// Ensure that the create command fails if none of the keys we give it match up with root.json.
fn create_with_incorrect_key() {
    let base = test_utils::test_data().join("tuf-reference-impl");
    let root_json = base.join("metadata").join("1.root.json");
    let bad_key = test_utils::test_data().join("snakeoil.pem");

    // Call the create command passing a single key that cannot be found in root.json. Assert that
    // the command fails.
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "create",
            "-t",
            "input/dir/does/not/matter",
            "-o",
            "output/dir/does/not/matter",
            "-k",
            bad_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--targets-expires",
            "in 7 days",
            "--targets-version",
            "1234",
            "--snapshot-expires",
            "in 7 days",
            "--snapshot-version",
            "1234",
            "--timestamp-expires",
            "in 7 days",
            "--timestamp-version",
            "1234",
        ])
        .assert()
        .failure();
}

#[test]
// Ensure we fail if no key is provided
fn create_with_no_key() {
    // Misuse the tuftool create command by not passing any keys and assert failure
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "create",
            "-t",
            "/input/dir/does/not/matter",
            "-o",
            "/output/dir/does/not/matter",
            "--root",
            "/root/does/not/matter",
            "--targets-expires",
            "in 7 days",
            "--targets-version",
            "1234",
            "--snapshot-expires",
            "in 7 days",
            "--snapshot-version",
            "1234",
            "--timestamp-expires",
            "in 7 days",
            "--timestamp-version",
            "1234",
        ])
        .assert()
        .failure();
}
