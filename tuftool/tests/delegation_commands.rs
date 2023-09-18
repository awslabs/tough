// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;

use assert_cmd::Command;
use chrono::{Duration, Utc};
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
// Ensure we can create a role, add the role to parent metadata, and sign repo
// Structure targets -> A -> B
async fn create_add_role_command() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let targets_key = test_utils::test_data().join("targetskey");
    let targets_key1 = test_utils::test_data().join("targetskey-1");
    let repo_dir = TempDir::new().unwrap();

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Set new expiration date for the new role
    let expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let metadata_base_url = &dir_url(repo_dir.path().join("metadata"));
    let meta_out = TempDir::new().unwrap();

    // create role A
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "create-role",
            "-o",
            meta_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let new_repo_dir = TempDir::new().unwrap();
    // add role to targets metadata and sign entire repo
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "add-role",
            "-o",
            new_repo_dir.path().to_str().unwrap(),
            "-i",
            dir_url(meta_out.path().join("metadata")).as_str(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "A",
            "-t",
            "1",
            "-v",
            "2",
            "--sign-all",
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
    let updated_metadata_base_url = &dir_url(new_repo_dir.path().join("metadata"));
    let updated_targets_base_url = &dir_url(new_repo_dir.path().join("targets"));
    let repo = RepositoryLoader::new(
        &tokio::fs::read(&root_json).await.unwrap(),
        updated_metadata_base_url.clone(),
        updated_targets_base_url.clone(),
    )
    .load()
    .await
    .unwrap();
    // Make sure `A` is added as a role
    assert!(repo.delegated_role("A").is_some());

    let create_out = TempDir::new().unwrap();
    // create role B
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "B",
            "create-role",
            "-o",
            create_out.path().to_str().unwrap(),
            "-k",
            targets_key1.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let add_b_out = TempDir::new().unwrap();
    // add role B to A metadata and sign A meta
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "add-role",
            "-o",
            add_b_out.path().to_str().unwrap(),
            "-i",
            dir_url(create_out.path().join("metadata")).as_str(),
            "-k",
            targets_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "B",
            "-t",
            "1",
            "-v",
            "2",
        ])
        .assert()
        .success();

    // update repo with new metadata

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
            updated_metadata_base_url.as_str(),
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
            "--role",
            "A",
            "-i",
            dir_url(add_b_out.path().join("metadata")).as_str(),
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

    // Make sure `B` is added as a role
    assert!(repo.delegated_role("B").is_some());
}
#[tokio::test]
// Ensure we can update targets of delegated roles
async fn update_target_command() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let targets_key = test_utils::test_data().join("targetskey");
    let repo_dir = TempDir::new().unwrap();

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Set new expiration date for the new role
    let expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let metadata_base_url = &dir_url(repo_dir.path().join("metadata"));
    let meta_out = TempDir::new().unwrap();

    // create role A
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "create-role",
            "-o",
            meta_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let new_repo_dir = TempDir::new().unwrap();
    // add role to targets metadata and sign entire repo
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "add-role",
            "-o",
            new_repo_dir.path().to_str().unwrap(),
            "-i",
            dir_url(meta_out.path().join("metadata")).as_str(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "A",
            "-t",
            "1",
            "-v",
            "2",
            "--sign-all",
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

    // Update A's targets
    let ut_out = TempDir::new().unwrap();
    let meta_out_url = dir_url(ut_out.path().join("metadata"));
    let targets_out_url = ut_out.path().join("targets");
    let updated_metadata_base_url = &dir_url(new_repo_dir.path().join("metadata"));
    let targets_input_dir = test_utils::test_data().join("targets");
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "update-delegated-targets",
            "-o",
            ut_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "-t",
            targets_input_dir.to_str().unwrap(),
            "-e",
            "in 5 days",
            "-v",
            "2",
        ])
        .assert()
        .success();

    // update repo with new metadata
    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;
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
            updated_metadata_base_url.as_str(),
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
            "--role",
            "A",
            "-i",
            meta_out_url.as_str(),
            "-t",
            targets_out_url.to_str().unwrap(),
            "-f",
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

    // Make sure we can read new target
    let file4 = TargetName::new("file4.txt").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&file4).await.unwrap().unwrap()).await,
        &b"This is an example target file."[..]
    );
}

#[tokio::test]
// Ensure we can add keys to A and B
// Adds new key to A and signs with it
async fn add_key_command() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let targets_key = test_utils::test_data().join("targetskey");
    let targets_key1 = test_utils::test_data().join("targetskey-1");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let metadata_base_url = &dir_url(repo_dir.path().join("metadata"));
    let meta_out = TempDir::new().unwrap();

    // create role A
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "create-role",
            "-o",
            meta_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let new_repo_dir = TempDir::new().unwrap();
    // add role to targets metadata and sign entire repo
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "add-role",
            "-o",
            new_repo_dir.path().to_str().unwrap(),
            "-i",
            dir_url(meta_out.path().join("metadata")).as_str(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "A",
            "-t",
            "1",
            "-v",
            "2",
            "--sign-all",
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
    let updated_metadata_base_url = &dir_url(new_repo_dir.path().join("metadata"));

    // add key to A
    let key_out = TempDir::new().unwrap();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "add-key",
            "-o",
            key_out.path().to_str().unwrap(),
            "--new-key",
            targets_key1.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
            "--delegated-role",
            "A",
        ])
        .assert()
        .success();

    //sign A's key addition as repo owner
    let new_repo_dir = TempDir::new().unwrap();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "--role",
            "targets",
            "-o",
            new_repo_dir.path().to_str().unwrap(),
            "-i",
            dir_url(key_out.path().join("metadata")).as_str(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "--targets-expires",
            expiration.to_rfc3339().as_str(),
            "--targets-version",
            "1",
            "--snapshot-expires",
            expiration.to_rfc3339().as_str(),
            "--snapshot-version",
            "1",
            "--timestamp-expires",
            expiration.to_rfc3339().as_str(),
            "--timestamp-version",
            "1",
        ])
        .assert()
        .success();

    let updated_metadata_base_url = &dir_url(new_repo_dir.path().join("metadata"));

    let create_out = TempDir::new().unwrap();
    // create role B
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "B",
            "create-role",
            "-o",
            create_out.path().to_str().unwrap(),
            "-k",
            targets_key1.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let add_b_out = TempDir::new().unwrap();
    // add role B to A metadata and sign A meta with the added key
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "add-role",
            "-o",
            add_b_out.path().to_str().unwrap(),
            "-i",
            dir_url(create_out.path().join("metadata")).as_str(),
            "-k",
            targets_key1.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "B",
            "-t",
            "1",
            "-v",
            "2",
        ])
        .assert()
        .success();

    // update repo with new metadata

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
            updated_metadata_base_url.as_str(),
            "--targets-expires",
            new_snapshot_expiration.to_rfc3339().as_str(),
            "--targets-version",
            format!("{}", new_snapshot_version).as_str(),
            "--snapshot-expires",
            new_snapshot_expiration.to_rfc3339().as_str(),
            "--snapshot-version",
            format!("{}", new_snapshot_version).as_str(),
            "--timestamp-expires",
            new_timestamp_expiration.to_rfc3339().as_str(),
            "--timestamp-version",
            format!("{}", new_timestamp_version).as_str(),
            "--role",
            "A",
            "-i",
            dir_url(add_b_out.path().join("metadata")).as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo
    let _repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(update_out.path().join("metadata")),
        dir_url(update_out.path().join("targets")),
    )
    .load()
    .await
    .unwrap();
}

#[test]
// Ensure we can remove keys from A
// Adds removes a key from A and makes sure we can't sign with it
fn remove_key_command() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let targets_key = test_utils::test_data().join("targetskey");
    let targets_key1 = test_utils::test_data().join("targetskey-1");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let metadata_base_url = &dir_url(repo_dir.path().join("metadata"));
    let meta_out = TempDir::new().unwrap();

    // create role A
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "create-role",
            "-o",
            meta_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "-k",
            targets_key1.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let new_repo_dir = TempDir::new().unwrap();
    // add role to targets metadata and sign entire repo
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "add-role",
            "-o",
            new_repo_dir.path().to_str().unwrap(),
            "-i",
            dir_url(meta_out.path().join("metadata")).as_str(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "A",
            "-t",
            "1",
            "-v",
            "2",
            "--sign-all",
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

    let updated_metadata_base_url = &dir_url(new_repo_dir.path().join("metadata"));

    // remove key from A
    let key_out = TempDir::new().unwrap();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "remove-key",
            "-o",
            key_out.path().to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
            "--keyid",
            "9d25bd7d096386713d823447e9920ea4b807bd95d1bf7a0d05a00979ab5eec00",
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "--delegated-role",
            "A",
        ])
        .assert()
        .success();

    //sign A's key removal as repo owner
    let new_repo_dir = TempDir::new().unwrap();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "--role",
            "targets",
            "-o",
            new_repo_dir.path().to_str().unwrap(),
            "-i",
            dir_url(key_out.path().join("metadata")).as_str(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "--targets-expires",
            expiration.to_rfc3339().as_str(),
            "--targets-version",
            "1",
            "--snapshot-expires",
            expiration.to_rfc3339().as_str(),
            "--snapshot-version",
            "1",
            "--timestamp-expires",
            expiration.to_rfc3339().as_str(),
            "--timestamp-version",
            "1",
        ])
        .assert()
        .success();

    let updated_metadata_base_url = &dir_url(new_repo_dir.path().join("metadata"));

    let create_out = TempDir::new().unwrap();
    // create role B
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "B",
            "create-role",
            "-o",
            create_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let add_b_out = TempDir::new().unwrap();
    // add role B to A metadata and sign A meta with the removed key
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "add-role",
            "-o",
            add_b_out.path().to_str().unwrap(),
            "-i",
            dir_url(create_out.path().join("metadata")).as_str(),
            "-k",
            targets_key1.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "B",
            "-t",
            "1",
            "-v",
            "2",
        ])
        .assert()
        .failure();
}

#[tokio::test]
// Ensure we can remove a role
async fn remove_role_command() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let targets_key = test_utils::test_data().join("targetskey");
    let targets_key1 = test_utils::test_data().join("targetskey-1");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let metadata_base_url = &dir_url(repo_dir.path().join("metadata"));
    let meta_out = TempDir::new().unwrap();

    // create role A
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "create-role",
            "-o",
            meta_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let new_repo_dir = TempDir::new().unwrap();
    // add role to targets metadata and sign entire repo
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "add-role",
            "-o",
            new_repo_dir.path().to_str().unwrap(),
            "-i",
            dir_url(meta_out.path().join("metadata")).as_str(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "A",
            "-t",
            "1",
            "-v",
            "2",
            "--sign-all",
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
    let updated_metadata_base_url = dir_url(new_repo_dir.path().join("metadata"));
    let updated_targets_base_url = dir_url(new_repo_dir.path().join("targets"));
    let repo = RepositoryLoader::new(
        &tokio::fs::read(&root_json).await.unwrap(),
        updated_metadata_base_url.clone(),
        updated_targets_base_url,
    )
    .load()
    .await
    .unwrap();
    // Make sure `A` is added as a role
    assert!(repo.delegated_role("A").is_some());

    let create_out = TempDir::new().unwrap();
    // create role B
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "B",
            "create-role",
            "-o",
            create_out.path().to_str().unwrap(),
            "-k",
            targets_key1.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let add_b_out = TempDir::new().unwrap();
    // add role B to A metadata
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "add-role",
            "-o",
            add_b_out.path().to_str().unwrap(),
            "-i",
            dir_url(create_out.path().join("metadata")).as_str(),
            "-k",
            targets_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "B",
            "-t",
            "1",
            "-v",
            "2",
        ])
        .assert()
        .success();

    // update repo with new metadata
    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;
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
            updated_metadata_base_url.as_str(),
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
            "--role",
            "A",
            "-i",
            dir_url(add_b_out.path().join("metadata")).as_str(),
        ])
        .assert()
        .success();

    // Remove B from the repo
    let remove_b_out = TempDir::new().unwrap();
    let updated_metadata_base_url = &dir_url(update_out.path().join("metadata"));

    // remove role B from A metadata and sign A meta
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "remove",
            "-o",
            remove_b_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "--delegated-role",
            "B",
            "-e",
            "in 4 days",
            "-v",
            "325",
        ])
        .assert()
        .success();

    // update repo with new metadata
    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;
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
            updated_metadata_base_url.as_str(),
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
            "--role",
            "A",
            "-i",
            dir_url(remove_b_out.path().join("metadata")).as_str(),
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

    // Make sure `B` is removed
    assert!(repo.delegated_role("B").is_none());
}

#[tokio::test]
// Ensure we can remove a role
async fn remove_role_recursive_command() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let targets_key = test_utils::test_data().join("targetskey");
    let targets_key1 = test_utils::test_data().join("targetskey-1");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let metadata_base_url = &dir_url(repo_dir.path().join("metadata"));
    let meta_out = TempDir::new().unwrap();

    // create role A
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "create-role",
            "-o",
            meta_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let new_repo_dir = TempDir::new().unwrap();
    // add role to targets metadata and sign entire repo
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "add-role",
            "-o",
            new_repo_dir.path().to_str().unwrap(),
            "-i",
            dir_url(meta_out.path().join("metadata")).as_str(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "A",
            "-t",
            "1",
            "-v",
            "2",
            "--sign-all",
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
    let updated_metadata_base_url = &dir_url(new_repo_dir.path().join("metadata"));
    let repo = RepositoryLoader::new(
        &tokio::fs::read(&root_json).await.unwrap(),
        updated_metadata_base_url.clone(),
        dir_url(new_repo_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();
    // Make sure `A` is added as a role
    assert!(repo.delegated_role("A").is_some());

    let create_out = TempDir::new().unwrap();
    // create role B
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "B",
            "create-role",
            "-o",
            create_out.path().to_str().unwrap(),
            "-k",
            targets_key1.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let add_b_out = TempDir::new().unwrap();
    // add role B to A metadata
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "A",
            "add-role",
            "-o",
            add_b_out.path().to_str().unwrap(),
            "-i",
            dir_url(create_out.path().join("metadata")).as_str(),
            "-k",
            targets_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            "B",
            "-t",
            "1",
            "-v",
            "2",
        ])
        .assert()
        .success();

    // update repo with new metadata
    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;
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
            updated_metadata_base_url.as_str(),
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
            "--role",
            "A",
            "-i",
            dir_url(add_b_out.path().join("metadata")).as_str(),
        ])
        .assert()
        .success();

    // Remove B from the repo
    let remove_b_out = TempDir::new().unwrap();
    let updated_metadata_base_url = &dir_url(update_out.path().join("metadata"));

    // remove role B from A metadata and sign A meta
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "remove",
            "-o",
            remove_b_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "--delegated-role",
            "B",
            "-e",
            "in 4 days",
            "-v",
            "325",
            "--recursive",
        ])
        .assert()
        .success();

    // update repo with new metadata
    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;
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
            updated_metadata_base_url.as_str(),
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
            "--role",
            "targets",
            "-i",
            dir_url(remove_b_out.path().join("metadata")).as_str(),
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

    // Make sure `A` and `B` are removed
    assert!(repo.delegated_role("A").is_none());
    assert!(repo.delegated_role("B").is_none());
}

#[tokio::test]
/// Ensure we that we percent encode path traversal characters when adding a role name such as
/// `../../strange/role/../name` and that we don't write files in unexpected places.
async fn dubious_role_name() {
    let dubious_role_name = "../../strange/role/../name";
    let dubious_name_encoded = "..%2F..%2Fstrange%2Frole%2F..%2Fname";
    let funny_role_name = "../🍺/( ͡° ͜ʖ ͡°)";
    let funny_name_encoded =
        "..%2F%F0%9F%8D%BA%2F%28%20%CD%A1%C2%B0%20%CD%9C%CA%96%20%CD%A1%C2%B0%29";
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let targets_key = test_utils::test_data().join("targetskey");
    let targets_key1 = test_utils::test_data().join("targetskey-1");
    let repo_dir = TempDir::new().unwrap();

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(Duration::days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(Duration::days(6)).unwrap();
    let new_targets_version: u64 = 170;

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Set new expiration date for the new role
    let expiration = Utc::now().checked_add_signed(Duration::days(4)).unwrap();
    let metadata_base_url = &dir_url(repo_dir.path().join("metadata"));
    let meta_out = TempDir::new().unwrap();

    // create role A
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            dubious_role_name,
            "create-role",
            "-o",
            meta_out.path().to_str().unwrap(),
            "-k",
            targets_key.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let new_repo_dir = TempDir::new().unwrap();
    // add role to targets metadata and sign entire repo
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            "targets",
            "add-role",
            "-o",
            new_repo_dir.path().to_str().unwrap(),
            "-i",
            dir_url(meta_out.path().join("metadata")).as_str(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            dubious_role_name,
            "-t",
            "1",
            "-v",
            "2",
            "--sign-all",
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
    let updated_metadata_base_url = &dir_url(new_repo_dir.path().join("metadata"));
    let updated_targets_base_url = &dir_url(new_repo_dir.path().join("targets"));
    let repo = RepositoryLoader::new(
        &tokio::fs::read(&root_json).await.unwrap(),
        updated_metadata_base_url.clone(),
        updated_targets_base_url.clone(),
    )
    .load()
    .await
    .unwrap();
    // Make sure `A` is added as a role
    assert!(repo.delegated_role(dubious_role_name).is_some());

    let create_out = TempDir::new().unwrap();
    // create role B
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            funny_role_name,
            "create-role",
            "-o",
            create_out.path().to_str().unwrap(),
            "-k",
            targets_key1.to_str().unwrap(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "-v",
            "1",
        ])
        .assert()
        .success();

    let add_b_out = TempDir::new().unwrap();
    // add role B to A metadata and sign A meta
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "delegation",
            "--signing-role",
            dubious_role_name,
            "add-role",
            "-o",
            add_b_out.path().to_str().unwrap(),
            "-i",
            dir_url(create_out.path().join("metadata")).as_str(),
            "-k",
            targets_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            updated_metadata_base_url.as_str(),
            "-e",
            expiration.to_rfc3339().as_str(),
            "--delegated-role",
            funny_role_name,
            "-t",
            "1",
            "-v",
            "2",
        ])
        .assert()
        .success();

    // Make sure the metadata files are in the right directory
    assert!(add_b_out
        .path()
        .join("metadata")
        .join(format!("{}.json", dubious_name_encoded))
        .is_file());
    assert!(add_b_out
        .path()
        .join("metadata")
        .join(format!("{}.json", funny_name_encoded))
        .is_file());

    // update repo with new metadata

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
            updated_metadata_base_url.as_str(),
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
            "--role",
            dubious_role_name,
            "-i",
            dir_url(add_b_out.path().join("metadata")).as_str(),
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

    // Make sure `B` is added as a role
    assert!(repo.delegated_role(funny_role_name).is_some());

    // Make sure the metadata files are in the right directory
    assert!(update_out
        .path()
        .join("metadata")
        .join(format!("{}.{}.json", 2, dubious_name_encoded))
        .is_file());
    assert!(update_out
        .path()
        .join("metadata")
        .join(format!("{}.{}.json", 1, funny_name_encoded))
        .is_file());
}
