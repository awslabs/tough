// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;
use assert_cmd::Command;
use std::fs::File;
use std::num::NonZeroU64;
use tempfile::TempDir;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::decoded::{Decoded, Hex};
use tough::schema::{Root, Signed};

fn initialize_root_json(root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "init", root_json])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "expire", root_json, "2020-09-22T00:00:00Z"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "set-threshold", root_json, "root", "2"])
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

fn add_key_root(keys: &Vec<&str>, root_json: &str) {
    let mut cmd = Command::cargo_bin("tuftool").unwrap();

    cmd.args(["root", "add-key", root_json, "--role", "root"]);

    for key in keys {
        cmd.args(["-k", key]);
    }

    cmd.assert().success();
}

fn add_key_timestamp(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root",
            "add-key",
            root_json,
            "-k",
            key,
            "--role",
            "timestamp",
        ])
        .assert()
        .success();
}

fn add_key_snapshot(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root", "add-key", root_json, "-k", key, "--role", "snapshot",
        ])
        .assert()
        .success();
}
fn add_key_targets(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "add-key", root_json, "-k", key, "--role", "targets"])
        .assert()
        .success();
}

fn add_keys_all_roles(keys: Vec<&str>, root_json: &str) {
    add_key_root(&keys, root_json);

    // Only add the first key for the rest until we have tests that want it for all keys
    let key = keys.first().unwrap();
    add_key_timestamp(key, root_json);
    add_key_snapshot(key, root_json);
    add_key_targets(key, root_json);
}

fn sign_root_json(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        // We don't have enough signatures to meet the threshold, so we have to pass `-i`
        .args(["root", "sign", root_json, "-i", "-k", key])
        .assert()
        .success();
}

fn sign_root_json_failure(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        // We don't have enough signatures to meet the threshold, so we should fail
        .args(["root", "sign", root_json, "-k", key])
        .assert()
        .failure();
}

fn sign_root_json_two_keys(key_1: &str, key_2: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "sign", root_json, "-k", key_1, "-k", key_2])
        .assert()
        .success();
}

fn cross_sign(old_root: &str, new_root: &str, key: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root",
            "sign",
            new_root,
            "-i",
            "-k",
            key,
            "--cross-sign",
            old_root,
        ])
        .assert()
        .success();
}

fn get_signed_root(root_json: &str) -> Signed<Root> {
    let root = File::open(root_json).unwrap();
    serde_json::from_reader(root).unwrap()
}

fn get_sign_len(root_json: &str) -> usize {
    let root = get_signed_root(root_json);
    root.signatures.len()
}

fn check_signature_exists(root_json: &str, key_id: Decoded<Hex>) -> bool {
    let root = get_signed_root(root_json);
    root.signatures.iter().any(|sig| sig.keyid == key_id)
}

fn get_version(root_json: &str) -> NonZeroU64 {
    let root = get_signed_root(root_json);
    root.signed.version
}

#[test]
// Ensure we can create and sign a root file
fn create_root() {
    let out_dir = TempDir::new().unwrap();
    let root_json = out_dir.path().join("root.json");
    let key_1 = test_utils::test_data().join("snakeoil.pem");
    let key_2 = test_utils::test_data().join("snakeoil_2.pem");

    // Create and initialise root.json
    initialize_root_json(root_json.to_str().unwrap());
    // Add keys for all roles
    add_keys_all_roles(vec![key_1.to_str().unwrap()], root_json.to_str().unwrap());
    // Add second key for root role
    add_key_root(&vec![key_2.to_str().unwrap()], root_json.to_str().unwrap());
    // Sign root.json with 1 key
    sign_root_json_two_keys(
        key_1.to_str().unwrap(),
        key_2.to_str().unwrap(),
        root_json.to_str().unwrap(),
    );
    assert_eq!(get_sign_len(root_json.to_str().unwrap()), 2);
}

#[test]
fn create_root_to_version() {
    let out_dir = TempDir::new().unwrap();
    let root_json = out_dir.path().join("root.json");
    let version = NonZeroU64::new(99).unwrap();

    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root",
            "init",
            root_json.to_str().unwrap(),
            "--version",
            "99",
        ])
        .assert()
        .success();

    // validate version number
    assert_eq!(get_version(root_json.to_str().unwrap()), version);
}

#[test]
fn create_root_invalid_version() {
    let out_dir = TempDir::new().unwrap();
    let root_json = out_dir.path().join("root.json");

    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root",
            "init",
            root_json.to_str().unwrap(),
            "--version",
            "0",
        ])
        .assert()
        .failure();
}

#[test]
// Ensure creating an unstable root throws error
fn create_unstable_root() {
    let out_dir = TempDir::new().unwrap();
    let key = test_utils::test_data().join("snakeoil.pem");
    let root_json = out_dir.path().join("root.json");

    // Create and initialise root.json
    initialize_root_json(root_json.to_str().unwrap());
    // Set the threshold for roles with targets being more than 1
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root",
            "set-threshold",
            root_json.to_str().unwrap(),
            "targets",
            "2",
        ])
        .assert()
        .success();
    // Add keys for all roles
    add_keys_all_roles(vec![key.to_str().unwrap()], root_json.to_str().unwrap());
    // Sign root.json (error because targets can never be validated root has 1 key but targets requires 2 signatures)
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root",
            "sign",
            out_dir.path().join("root.json").to_str().unwrap(),
            "-k",
            key.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
// Ensure signing a root with insufficient keys throws error
fn create_invalid_root() {
    let out_dir = TempDir::new().unwrap();
    let key = test_utils::test_data().join("snakeoil.pem");
    let root_json = out_dir.path().join("root.json");

    // Create and initialise root.json
    initialize_root_json(root_json.to_str().unwrap());
    // Add keys for all roles
    add_keys_all_roles(vec![key.to_str().unwrap()], root_json.to_str().unwrap());
    // Sign root.json (error because key is not valid)
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root",
            "sign",
            out_dir.path().join("root.json").to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[tokio::test]
async fn cross_sign_root() {
    let out_dir = TempDir::new().unwrap();
    let old_root_json = test_utils::test_data()
        .join("cross-sign-root")
        .join("1.root.json");
    // 1.root.json is signed with 'snakeoil.pem'
    let new_root_json = out_dir.path().join("2.root.json");
    let old_root_key = test_utils::test_data().join("snakeoil.pem");
    let new_root_key = test_utils::test_data().join("snakeoil_2.pem");
    let old_key_source = LocalKeySource {
        path: old_root_key.clone(),
    };
    let old_key_id = old_key_source
        .as_sign()
        .await
        .ok()
        .unwrap()
        .tuf_key()
        .key_id()
        .unwrap();
    // Create and initialise root.json
    initialize_root_json(new_root_json.to_str().unwrap());
    // Add keys for all roles
    add_keys_all_roles(
        vec![new_root_key.to_str().unwrap()],
        new_root_json.to_str().unwrap(),
    );
    //Sign 2.root.json with key from 1.root.json
    cross_sign(
        old_root_json.to_str().unwrap(),
        new_root_json.to_str().unwrap(),
        old_root_key.to_str().unwrap(),
    );
    assert!(check_signature_exists(
        new_root_json.to_str().unwrap(),
        old_key_id,
    ));
}

// cross-signing new_root.json with invalid key ( key not present in old_root.json )
#[test]
fn cross_sign_root_invalid_key() {
    let out_dir = TempDir::new().unwrap();
    let old_root_json = test_utils::test_data()
        .join("cross-sign-root")
        .join("1.root.json");
    let new_root_json = out_dir.path().join("2.root.json");
    let root_key = test_utils::test_data().join("snakeoil_2.pem");

    // Create and initialise root.json
    initialize_root_json(new_root_json.to_str().unwrap());
    // Add keys for all roles
    add_keys_all_roles(
        vec![root_key.to_str().unwrap()],
        new_root_json.to_str().unwrap(),
    );
    // Sign 2.root.json with key not in 1.root.json
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "root",
            "sign",
            new_root_json.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--cross-sign",
            old_root_json.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn append_signature_root() {
    let out_dir = TempDir::new().unwrap();
    let root_json = out_dir.path().join("root.json");
    let key_1 = test_utils::test_data().join("snakeoil.pem");
    let key_2 = test_utils::test_data().join("snakeoil_2.pem");

    // Create and initialise root.json
    initialize_root_json(root_json.to_str().unwrap());
    // Add key_1 for all roles
    add_keys_all_roles(vec![key_1.to_str().unwrap()], root_json.to_str().unwrap());
    // Add key_2 to root
    add_key_root(&vec![key_2.to_str().unwrap()], root_json.to_str().unwrap());
    // Sign root.json with key_1
    sign_root_json(key_1.to_str().unwrap(), root_json.to_str().unwrap());
    // Sign root.json with key_2
    sign_root_json(key_2.to_str().unwrap(), root_json.to_str().unwrap());

    //validate number of signatures
    assert_eq!(get_sign_len(root_json.to_str().unwrap()), 2);
}

#[test]
fn add_multiple_keys_root() {
    let out_dir = TempDir::new().unwrap();
    let root_json = out_dir.path().join("root.json");
    let key_1 = test_utils::test_data().join("snakeoil.pem");
    let key_2 = test_utils::test_data().join("snakeoil_2.pem");

    // Create and initialise root.json
    initialize_root_json(root_json.to_str().unwrap());
    // Add key_1 and key_2 for all roles
    add_keys_all_roles(
        vec![key_1.to_str().unwrap(), key_2.to_str().unwrap()],
        root_json.to_str().unwrap(),
    );
    // Sign root.json with key_1
    sign_root_json(key_1.to_str().unwrap(), root_json.to_str().unwrap());
    // Sign root.json with key_2
    sign_root_json(key_2.to_str().unwrap(), root_json.to_str().unwrap());

    //validate number of signatures
    assert_eq!(get_sign_len(root_json.to_str().unwrap()), 2);
}

#[test]
fn below_threshold_failure() {
    let out_dir = TempDir::new().unwrap();
    let root_json = out_dir.path().join("root.json");
    let key_1 = test_utils::test_data().join("snakeoil.pem");
    let key_2 = test_utils::test_data().join("snakeoil_2.pem");
    // Create and initialise root.json
    initialize_root_json(root_json.to_str().unwrap());
    // Add key_1 for all roles
    add_keys_all_roles(vec![key_1.to_str().unwrap()], root_json.to_str().unwrap());
    // Add key_2 to root
    add_key_root(&vec![key_2.to_str().unwrap()], root_json.to_str().unwrap());
    // Sign root.json with key_1 fails, when no `--ignore-threshold` is passed
    sign_root_json_failure(key_1.to_str().unwrap(), root_json.to_str().unwrap());
}

#[test]
fn set_version_root() {
    let out_dir = TempDir::new().unwrap();
    let root_json = out_dir.path().join("root.json");

    // Create and initialise root.json
    initialize_root_json(root_json.to_str().unwrap());
    let version = NonZeroU64::new(5).unwrap();

    // set version to 5
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(["root", "set-version", root_json.to_str().unwrap(), "5"])
        .assert()
        .success();

    // validate version number
    assert_eq!(get_version(root_json.to_str().unwrap()), version);
}
