// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;

use assert_cmd::assert::Assert;
use assert_cmd::Command;
use chrono::{DateTime, Duration, Utc};
use std::path::Path;
use tempfile::TempDir;
use test_utils::dir_url;
use tough::{RepositoryLoader, TargetName};

fn create_repo<P: AsRef<Path>>(repo_dir: P) {
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(1)).unwrap();
    let timestamp_version: u64 = 31;
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(2)).unwrap();
    let snapshot_version: u64 = 25;
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let targets_version: u64 = 17;
    let targets_input_dir = test_utils::test_data()
        .join("tuf-reference-impl")
        .join("targets");
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");

    // Create a repo using tuftool and the reference tuf implementation data
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
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

#[tokio::test]
// Ensure we can read a repo that has had its metadata updated by `tuftool create`
async fn update_command_without_new_targets() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;
    let metadata_base_url = &dir_url(repo_dir.path().join("metadata"));
    let update_out = TempDir::new().unwrap();

    // Update the repo we just created
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "-o",
            update_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
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

    // Load the updated repo
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(update_out.path().join("metadata")),
        dir_url(update_out.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the existing targets are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 3);

    // Ensure all the metadata has been updated
    assert_eq!(repo.targets().signed.version.get(), new_targets_version);
    assert_eq!(repo.targets().signed.expires, new_targets_expiration);
    assert_eq!(repo.snapshot().signed.version.get(), new_snapshot_version);
    assert_eq!(repo.snapshot().signed.expires, new_snapshot_expiration);
    assert_eq!(repo.timestamp().signed.version.get(), new_timestamp_version);
    assert_eq!(repo.timestamp().signed.expires, new_timestamp_expiration);
}

#[tokio::test]
// Ensure we can read a repo that has had its metadata and targets updated
// by `tuftool create`
async fn update_command_with_new_targets() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;
    let new_targets_input_dir = test_utils::test_data().join("targets");
    let metadata_base_url = &dir_url(repo_dir.path().join("metadata"));
    let update_out = TempDir::new().unwrap();

    // Update the repo we just created
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "-t",
            new_targets_input_dir.to_str().unwrap(),
            "-o",
            update_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
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
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(update_out.path().join("metadata")),
        dir_url(update_out.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the targets (new and existing) are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 6);

    // Ensure we can read the newly added targets
    let file4 = TargetName::new("file4.txt").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&file4).await.unwrap().unwrap()).await,
        &b"This is an example target file."[..]
    );
    let file5 = TargetName::new("file5.txt").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&file5).await.unwrap().unwrap()).await,
        &b"This is another example target file."[..]
    );
    let file6 = TargetName::new("file6.txt").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&file6).await.unwrap().unwrap()).await,
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

#[test]
// Ensure that the update command fails if none of the keys we give it match up with root.json.
fn update_with_incorrect_key() {
    let base = test_utils::test_data().join("tuf-reference-impl");
    let root_json = base.join("metadata").join("1.root.json");
    let bad_key = test_utils::test_data().join("snakeoil.pem");

    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "--outdir",
            "/outdir/does/not/matter",
            "-k",
            bad_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
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
fn update_with_no_key() {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
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

fn updates_expired_repo(
    outdir: &TempDir,
    repo_dir: &TempDir,
    allow_expired_repo: bool,
) -> (
    Assert,
    DateTime<Utc>,
    u64,
    DateTime<Utc>,
    u64,
    DateTime<Utc>,
    u64,
) {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    // Set expiration dates and version numbers for the update command
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let timestamp_version: u64 = 310;
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let snapshot_version: u64 = 250;
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let targets_version: u64 = 170;
    let metadata_base_url = &test_utils::dir_url(repo_dir.path().join("metadata"));
    let mut cmd = Command::cargo_bin("tuftool").unwrap();
    cmd.args([
        "update",
        "-o",
        outdir.path().to_str().unwrap(),
        "-k",
        root_key.to_str().unwrap(),
        "--root",
        root_json.to_str().unwrap(),
        "--metadata-url",
        metadata_base_url.as_str(),
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
    ]);
    let assert = if allow_expired_repo {
        cmd.arg("--allow-expired-repo").assert()
    } else {
        cmd.assert()
    };
    (
        assert,
        timestamp_expiration,
        timestamp_version,
        snapshot_expiration,
        snapshot_version,
        targets_expiration,
        targets_version,
    )
}

#[test]
// Ensure we cannot update a repo that has had its metadata expired
fn update_command_expired_repo_fail() {
    let outdir = TempDir::new().unwrap();
    let repo_dir = TempDir::new().unwrap();
    // Create a expired repo using tuftool and the reference tuf implementation data
    test_utils::create_expired_repo(repo_dir.path());
    let update_expected = updates_expired_repo(&outdir, &repo_dir, false);
    // assert failure for update command
    update_expected.0.failure();
}

#[tokio::test]
// Ensure we can update a repo that has its metadata expired but --allow-expired-repo flag is passed
async fn update_command_expired_repo_allow() {
    let outdir = TempDir::new().unwrap();
    let repo_dir = TempDir::new().unwrap();
    // Create a expired repo using tuftool and the reference tuf implementation data
    test_utils::create_expired_repo(repo_dir.path());
    let update_expected = updates_expired_repo(&outdir, &repo_dir, true);
    // assert success for update command
    update_expected.0.success();
    // Load the updated repo
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(outdir.path().join("metadata")),
        dir_url(outdir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();
    // Ensure all the existing targets are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 3);
    // Ensure all the metadata has been updated
    assert_eq!(repo.timestamp().signed.expires, update_expected.1);
    assert_eq!(repo.timestamp().signed.version.get(), update_expected.2);
    assert_eq!(repo.snapshot().signed.expires, update_expected.3);
    assert_eq!(repo.snapshot().signed.version.get(), update_expected.4);
    assert_eq!(repo.targets().signed.expires, update_expected.5);
    assert_eq!(repo.targets().signed.version.get(), update_expected.6);
}
