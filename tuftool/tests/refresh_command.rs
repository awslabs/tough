// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod utl;

use assert_cmd::Command;
use chrono::{Duration, Utc};
use std::fs;
use std::fs::File;
use tempfile::TempDir;
use tough::{Limits, Repository, Settings};

#[test]
// Ensure we can read a repo that has been refreshed by the `tuftool refresh`
fn refresh_command() {
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
    let load_dir = TempDir::new().unwrap();
    let refresh_wrk = TempDir::new().unwrap();
    let refresh_out = TempDir::new().unwrap();

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

    // Set new expiration dates and version numbers for the refresh command
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let timestamp_version: u64 = 310;
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let snapshot_version: u64 = 250;
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let targets_version: u64 = 170;

    // Use the refresh command to update the expiration dates.
    let metadata_base_url = &utl::dir_url(repo_dir.path().join("metadata"));
    let targets_base_url = &utl::dir_url(repo_dir.path().join("targets"));
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "refresh",
            "--workdir",
            refresh_wrk.path().to_str().unwrap(),
            "--outdir",
            refresh_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.clone().to_str().unwrap(),
            "--metadata-url",
            metadata_base_url,
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

    // Copy the new metadata files to the repo
    let targets_json_filename = format!("{}.targets.json", targets_version);
    let snapshot_json_filename = format!("{}.snapshot.json", snapshot_version);
    let timestamp_json_filename = "timestamp.json";
    let dest_dir = repo_dir.path().join("metadata");
    let src_dir = refresh_out.path().join("metadata");
    let copy = |filename: &str| fs::copy(src_dir.join(filename), dest_dir.join(filename)).unwrap();
    copy(targets_json_filename.as_str());
    copy(snapshot_json_filename.as_str());
    copy(timestamp_json_filename);

    // Load the refreshed repo
    let repo = Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: File::open(root_json).unwrap(),
            datastore: load_dir.as_ref(),
            metadata_base_url,
            targets_base_url,
            limits: Limits::default(),
        },
    )
    .unwrap();

    // Ensure we can read the targets
    assert_eq!(
        utl::read_to_end(repo.read_target("file1.txt").unwrap().unwrap()),
        &b"This is an example target file."[..]
    );
    assert_eq!(
        utl::read_to_end(repo.read_target("file2.txt").unwrap().unwrap()),
        &b"This is an another example target file."[..]
    );
    assert_eq!(
        utl::read_to_end(repo.read_target("file3.txt").unwrap().unwrap()),
        &b"This is role1's target file."[..]
    );

    // Ensure the targets.json file is correct
    assert_eq!(repo.targets().signed.version.get(), targets_version);
    assert_eq!(repo.targets().signed.expires, targets_expiration);
    assert_eq!(repo.targets().signed.targets.len(), 3);
    assert_eq!(repo.targets().signed.targets["file1.txt"].length, 31);
    assert_eq!(repo.targets().signed.targets["file2.txt"].length, 39);
    assert_eq!(repo.targets().signed.targets["file3.txt"].length, 28);
    assert_eq!(repo.targets().signatures.len(), 1);

    // Ensure the snapshot.json file is correct
    assert_eq!(repo.snapshot().signed.version.get(), snapshot_version);
    assert_eq!(repo.snapshot().signed.expires, snapshot_expiration);
    assert_eq!(repo.snapshot().signed.meta.len(), 2);
    assert_eq!(repo.snapshot().signed.meta["root.json"].version.get(), 1);
    assert_eq!(
        repo.snapshot().signed.meta["targets.json"].version.get(),
        targets_version
    );
    assert_eq!(repo.snapshot().signatures.len(), 1);

    // Ensure the timestamp.json file is correct
    assert_eq!(repo.timestamp().signed.version.get(), timestamp_version);
    assert_eq!(repo.timestamp().signed.expires, timestamp_expiration);
    assert_eq!(repo.timestamp().signed.meta.len(), 1);
    assert_eq!(
        repo.timestamp().signed.meta["snapshot.json"].version.get(),
        snapshot_version
    );
    assert_eq!(repo.snapshot().signatures.len(), 1);
}

#[test]
// Ensure that the refresh command fails if none of the keys we give it match up with root.json.
fn refresh_with_incorrect_key() {
    let base = utl::test_data().join("tuf-reference-impl");
    let root_json = base.join("metadata").join("1.root.json");
    let bad_key = utl::test_data().join("snakeoil.pem");

    // Call the create command passing a single key that cannot be found in root.json. Assert that
    // the command fails.
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "refresh",
            "--workdir",
            "/workdir/does/not/matter",
            "--outdir",
            "/outdir/does/not/matter",
            "-k",
            bad_key.to_str().unwrap(),
            "--root",
            root_json.clone().to_str().unwrap(),
            "--metadata-url",
            "https://metadata.url.does.not.matter",
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
fn refresh_with_no_key() {
    // Misuse the tuftool create command by not passing any keys and assert failure
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "refresh",
            "--workdir",
            "/workdir/does/not/matter",
            "--outdir",
            "/outdir/does/not/matter",
            "--root",
            "/root/does/not/matter",
            "--metadata-url",
            "https://metadata.url.does.not.matter",
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
