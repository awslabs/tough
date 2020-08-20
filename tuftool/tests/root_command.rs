// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;
use assert_cmd::Command;
use tempfile::TempDir;

fn initialise_root_json(root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "init", root_json])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "expire", root_json, "2020-09-22T00:00:00Z"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "set-threshold", root_json, "root", "1"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "set-threshold", root_json, "snapshot", "1"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "set-threshold", root_json, "targets", "1"])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "set-threshold", root_json, "timestamp", "1"])
        .assert()
        .success();
}

fn add_key_root(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "add-key", root_json, key, "--role", "root"])
        .assert()
        .success();
}

fn add_key_timestamp(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "add-key", root_json, key, "--role", "timestamp"])
        .assert()
        .success();
}

fn add_key_snapshot(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "add-key", root_json, key, "--role", "snapshot"])
        .assert()
        .success();
}
fn add_key_targets(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "add-key", root_json, key, "--role", "targets"])
        .assert()
        .success();
}

fn add_key_all_roles(key: &str, root_json: &str) {
    add_key_root(key, root_json);
    add_key_timestamp(key, root_json);
    add_key_snapshot(key, root_json);
    add_key_targets(key, root_json);
}

fn sign_root_json(key: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "sign", root_json, "-k", key])
        .assert()
        .success();
}

fn sign_root_json_two_keys(key_1: &str, key_2: &str, root_json: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "sign", root_json, "-k", key_1, "-k", key_2])
        .assert()
        .success();
}

fn cross_sign(old_root: &str, new_root: &str, key: &str) {
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "sign",
            new_root,
            "-k",
            key,
            "--cross-sign",
            old_root,
        ])
        .assert()
        .success();
}

#[test]
// Ensure we can create and sign a root file
fn create_root() {
    let out_dir = TempDir::new().unwrap();
    let root_json = out_dir.path().join("root.json");
    let key = test_utils::test_data().join("snakeoil.pem");
    let key_2 = test_utils::test_data().join("snakeoil_2.pem");

    // Create and initialise root.json
    initialise_root_json(root_json.to_str().unwrap());
    // Add keys for all roles
    add_key_all_roles(key.to_str().unwrap(), root_json.to_str().unwrap());
    // Add second key for root role
    add_key_root(key_2.to_str().unwrap(), root_json.to_str().unwrap());
    // Sign root.json with 1 key
    sign_root_json_two_keys(
        key.to_str().unwrap(),
        key_2.to_str().unwrap(),
        root_json.to_str().unwrap(),
    );
}

#[test]
// Ensure creating an unstable root throws error
fn create_unstable_root() {
    let out_dir = TempDir::new().unwrap();
    let key = test_utils::test_data().join("snakeoil.pem");
    let root_json = out_dir.path().join("root.json");

    // Create and initialise root.json
    initialise_root_json(root_json.to_str().unwrap());
    // Set the threshold for roles with targets being more than 1
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            root_json.to_str().unwrap(),
            "targets",
            "2",
        ])
        .assert()
        .success();
    // Add keys for all roles
    add_key_all_roles(key.to_str().unwrap(), root_json.to_str().unwrap());
    // Sign root.json (error because targets can never be validated root has 1 key but targets requires 2 signatures)
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
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
    initialise_root_json(root_json.to_str().unwrap());
    // Add keys for all roles
    add_key_all_roles(key.to_str().unwrap(), root_json.to_str().unwrap());
    // Sign root.json (error because key is not valid)
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "sign",
            out_dir.path().join("root.json").to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn cross_sign_root() {
    let out_dir = TempDir::new().unwrap();
    let old_root_json = test_utils::test_data()
        .join("cross-sign-root")
        .join("1.root.json");
    let old_root_key = test_utils::test_data().join("snakeoil.pem");
    let new_root_json = out_dir.path().join("2.root.json");
    let new_key = test_utils::test_data().join("snakeoil_2.pem");

    // Create and initialise root.json
    initialise_root_json(new_root_json.to_str().unwrap());
    // Add keys for all roles
    add_key_all_roles(new_key.to_str().unwrap(), new_root_json.to_str().unwrap());
    //Sign 2.root.json with key from 1.root.json
    cross_sign(
        old_root_json.to_str().unwrap(),
        new_root_json.to_str().unwrap(),
        old_root_key.to_str().unwrap(),
    );
}

#[test]
fn root_multiple_signature() {
    let out_dir = TempDir::new().unwrap();
    let root_json = out_dir.path().join("root.json");
    let key_1 = test_utils::test_data().join("snakeoil.pem");
    let key_2 = test_utils::test_data().join("snakeoil_2.pem");

    // Create and initialise root.json
    initialise_root_json(root_json.to_str().unwrap());
    // Add key_1 for all roles
    add_key_all_roles(key_1.to_str().unwrap(), root_json.to_str().unwrap());
    // Add key 2 to root
    add_key_root(key_2.to_str().unwrap(), root_json.to_str().unwrap());
    // Sign root.json with key_1
    sign_root_json(key_1.to_str().unwrap(), root_json.to_str().unwrap());
    // Sign root.json with key_2
    sign_root_json(key_2.to_str().unwrap(), root_json.to_str().unwrap());
}
