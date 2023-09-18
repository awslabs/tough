// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;
use assert_cmd::Command;
use chrono::{Duration, Utc};
use std::env;
use tempfile::TempDir;
use test_utils::dir_url;
use tough::{RepositoryLoader, TargetName};

// This file include integration tests for KeySources: tough-ssm, tough-kms and local file key.
// Since the tests are run using the actual "AWS SSM and AWS KMS", you would have to configure
// AWS credentials with root permission.
// Refer https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html to configure named profile.
// Additionally, tough-kms key generation is not supported (issue  #211), so you would have to manually create kms CMK key.
// To run test include feature flag 'integ' like : "cargo test --features=integ"

fn get_profile() -> String {
    env::var("AWS_PROFILE").unwrap_or_default()
}

fn initialize_root_json(root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "init", root_json])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "expire", root_json, "3030-09-22T00:00:00Z"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "set-threshold", root_json, "root", "1"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "set-threshold", root_json, "snapshot", "1"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "set-threshold", root_json, "targets", "1"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "set-threshold", root_json, "timestamp", "1"])
        .assert()
        .success();
}

fn gen_key(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root",
            "gen-rsa-key",
            root_json,
            key,
            "--role",
            "root",
            "-b",
            "3072",
        ])
        .assert()
        .success();
}
fn add_root_key(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "add-key", root_json, key, "--role", "root"])
        .assert()
        .success();
}
fn add_key_all_role(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "add-key", root_json, key, "--role", "snapshot"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "add-key", root_json, key, "--role", "targets"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "add-key", root_json, key, "--role", "timestamp"])
        .assert()
        .success();
}

fn sign_root_json(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "sign", root_json, "-k", key])
        .assert()
        .success();
}

async fn create_repository(root_key: &str, auto_generate: bool) {
    // create a root.json file to create TUF repository metadata
    let root_json_dir = TempDir::new().unwrap();
    let root_json = root_json_dir.path().join("root.json");
    initialize_root_json(root_json.to_str().unwrap());
    if auto_generate {
        gen_key(root_key, root_json.to_str().unwrap());
    } else {
        add_root_key(root_key, root_json.to_str().unwrap());
    }
    add_key_all_role(root_key, root_json.to_str().unwrap());
    sign_root_json(root_key, root_json.to_str().unwrap());
    // Use root.json file to generate metadata using create command.
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version: u64 = 1234;
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version: u64 = 5432;
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version: u64 = 789;
    let targets_input_dir = test_utils::test_data()
        .join("tuf-reference-impl")
        .join("targets");
    let repo_dir = TempDir::new().unwrap();
    // Create a repo using tuftool and the reference tuf implementation targets
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "create",
            "-t",
            targets_input_dir.to_str().unwrap(),
            "-o",
            repo_dir.path().to_str().unwrap(),
            "-k",
            root_key,
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
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(repo_dir.path().join("metadata")),
        dir_url(repo_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure we can read the targets
    let file1 = TargetName::new("file1.txt").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&file1).await.unwrap().unwrap()).await,
        &b"This is an example target file."[..]
    );
    let file2 = TargetName::new("file2.txt").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&file2).await.unwrap().unwrap()).await,
        &b"This is an another example target file."[..]
    );
    let file3 = TargetName::new("file3.txt").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&file3).await.unwrap().unwrap()).await,
        &b"This is role1's target file."[..]
    );

    // Ensure the targets.json file is correct
    assert_eq!(repo.targets().signed.version.get(), targets_version);
    assert_eq!(repo.targets().signed.expires, targets_expiration);
    assert_eq!(repo.targets().signed.targets.len(), 3);
    assert_eq!(repo.targets().signed.targets[&file1].length, 31);
    assert_eq!(repo.targets().signed.targets[&file2].length, 39);
    assert_eq!(repo.targets().signed.targets[&file3].length, 28);
    assert_eq!(repo.targets().signatures.len(), 1);

    // Ensure the snapshot.json file is correct
    assert_eq!(repo.snapshot().signed.version.get(), snapshot_version);
    assert_eq!(repo.snapshot().signed.expires, snapshot_expiration);
    assert_eq!(repo.snapshot().signed.meta.len(), 1);
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
    root_json_dir.close().unwrap();
}

#[tokio::test]
#[cfg_attr(not(feature = "integ"), ignore)]
// Ensure we can use local rsa key to create and sign a repo created by the `tuftool` binary using the `tough` library
async fn create_repository_local_key() {
    let root_key_dir = TempDir::new().unwrap();
    let root_key_path = root_key_dir.path().join("local_key.pem");
    let root_key = &format!("file://{}", root_key_path.to_str().unwrap());
    create_repository(root_key, true).await;
}

#[tokio::test]
#[cfg_attr(not(feature = "integ"), ignore)]
// Ensure we can use ssm key to create and sign a repo created by the `tuftool` binary using the `tough` library
async fn create_repository_ssm_key() {
    let root_key = &format!("aws-ssm://{}/tough-integ/key-a", get_profile());
    create_repository(root_key, true).await;
}

#[tokio::test]
#[cfg_attr(not(feature = "integ"), ignore)]
// Ensure we can use kms key to create and sign a repo created by the `tuftool` binary using the `tough` library
async fn create_repository_kms_key() {
    let root_key = &format!("aws-kms://{}/alias/tough-integ/key-a", get_profile());
    create_repository(root_key, false).await;
}
