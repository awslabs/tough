// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod utl;

use assert_cmd::Command;
use chrono::{Duration, Utc};
use std::fs::File;
use tempfile::TempDir;
use tough::{ExpirationEnforcement, Limits, Repository, Settings};

#[test]
// Ensure we can read a repo that has been updated by `tuftool update`
fn update_command() {
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(1)).unwrap();
    let timestamp_version: u64 = 31;
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(2)).unwrap();
    let snapshot_version: u64 = 25;
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let targets_version: u64 = 17;
    let targets_input_dir = utl::test_data().join("tuf-reference-impl").join("targets");
    let root_json = utl::test_data().join("simple-rsa").join("root.json");
    let root_key = utl::test_data().join("snakeoil.pem");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "create",
            targets_input_dir.to_str().unwrap(),
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

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;
    let new_targets_input_dir = utl::test_data().join("targets");
    let metadata_base_url = &utl::dir_url(repo_dir.path().join("metadata"));
    let update_out = TempDir::new().unwrap();

    // Update the repo we just created
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "update",
            new_targets_input_dir.to_str().unwrap(),
            update_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url,
            "--targets-expires",
            new_targets_expiration.to_rfc3339().as_str(),
            "--targets-version",
            format!("{}", new_targets_version).as_str(),
            "--snapshot-expires",
            new_snapshot_expiration.to_rfc3339().as_str(),
            "--snapshot-version",
            format!("{}", new_snapshot_version).as_str(),
            "--timestamp-expires",
            new_timestamp_expiration.to_rfc3339().as_str(),
            "--timestamp-version",
            format!("{}", new_timestamp_version).as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo.
    let temp_datastore = TempDir::new().unwrap();
    let updated_metadata_base_url = &utl::dir_url(update_out.path().join("metadata"));
    let updated_targets_base_url = &utl::dir_url(update_out.path().join("targets"));
    let repo = Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: File::open(root_json).unwrap(),
            datastore: temp_datastore.as_ref(),
            metadata_base_url: updated_metadata_base_url,
            targets_base_url: updated_targets_base_url,
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    // Ensure all the targets (new and existing) are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 6);

    // Ensure we can read the newly added targets
    assert_eq!(
        utl::read_to_end(repo.read_target("file4.txt").unwrap().unwrap()),
        &b"This is an example target file."[..]
    );
    assert_eq!(
        utl::read_to_end(repo.read_target("file5.txt").unwrap().unwrap()),
        &b"This is another example target file."[..]
    );
    assert_eq!(
        utl::read_to_end(repo.read_target("file6.txt").unwrap().unwrap()),
        &b"This is yet another example target file."[..]
    );

    // Ensure all the metadata has been updated
    assert_eq!(repo.targets().signed.version.get(), new_targets_version);
    assert_eq!(repo.targets().signed.expires, new_targets_expiration);
    assert_eq!(repo.snapshot().signed.version.get(), new_snapshot_version);
    assert_eq!(repo.snapshot().signed.expires, new_snapshot_expiration);
    assert_eq!(repo.timestamp().signed.version.get(), new_timestamp_version);
    assert_eq!(repo.timestamp().signed.expires, new_timestamp_expiration);
}
