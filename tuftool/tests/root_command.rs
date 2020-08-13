// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;
use tempfile::TempDir;

use assert_cmd::Command;

#[test]
// Ensure we can create and sign a root file
fn create_root() {
    let key = test_utils::test_data().join("snakeoil.pem");
    let key_2 = test_utils::test_data().join("snakeoil_2.pem");

    let outdir = TempDir::new().unwrap();

    // Create root.json
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "init",
            outdir.path().join("root.json").to_str().unwrap(),
        ])
        .assert()
        .success();

    // Set the threshold for roles
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "root",
            "1",
        ])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "targets",
            "1",
        ])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "snapshot",
            "1",
        ])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "timestamp",
            "1",
        ])
        .assert()
        .success();

    // Add keys for all roles
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "add-key",
            outdir.path().join("root.json").to_str().unwrap(),
            key.to_str().unwrap(),
            "-r",
            "root",
            "-r",
            "targets",
            "-r",
            "snapshot",
            "-r",
            "timestamp",
        ])
        .assert()
        .success();

    // Add second key for root role
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "add-key",
            outdir.path().join("root.json").to_str().unwrap(),
            key_2.to_str().unwrap(),
            "-r",
            "root",
        ])
        .assert()
        .success();

    // Sign root.json with 2 keys
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "sign",
            outdir.path().join("root.json").to_str().unwrap(),
            "-k",
            key.to_str().unwrap(),
            "-k",
            key_2.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
// Ensure creating an unstable root throws error
fn create_unstable_root() {
    let outdir = TempDir::new().unwrap();
    let key = test_utils::test_data().join("snakeoil.pem");
    // Create root.json
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "init",
            outdir.path().join("root.json").to_str().unwrap(),
        ])
        .assert()
        .success();

    // Set the threshold for roles with targets being more than 1
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "root",
            "1",
        ])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "targets",
            "2",
        ])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "snapshot",
            "1",
        ])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "timestamp",
            "1",
        ])
        .assert()
        .success();

    // Add keys for all roles
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "add-key",
            outdir.path().join("root.json").to_str().unwrap(),
            key.to_str().unwrap(),
            "-r",
            "root",
            "-r",
            "targets",
            "-r",
            "snapshot",
            "-r",
            "timestamp",
        ])
        .assert()
        .success();

    // Sign root.json (error because targets can never be validated root has 1 key but targets requires 2 signatures)
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "sign",
            outdir.path().join("root.json").to_str().unwrap(),
            "-k",
            key.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
// Ensure signing a root with insuffecient keys throws error
fn create_invalid_root() {
    let outdir = TempDir::new().unwrap();
    let key = test_utils::test_data().join("snakeoil.pem");
    // Create root.json
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "init",
            outdir.path().join("root.json").to_str().unwrap(),
        ])
        .assert()
        .success();

    // Set the threshold for roles
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "root",
            "1",
        ])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "targets",
            "1",
        ])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "snapshot",
            "1",
        ])
        .assert()
        .success();
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            outdir.path().join("root.json").to_str().unwrap(),
            "timestamp",
            "1",
        ])
        .assert()
        .success();

    // Add keys for all roles
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "add-key",
            outdir.path().join("root.json").to_str().unwrap(),
            key.to_str().unwrap(),
            "-r",
            "root",
            "-r",
            "targets",
            "-r",
            "snapshot",
            "-r",
            "timestamp",
        ])
        .assert()
        .success();

    // Sign root.json (error because key is not valid)
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "sign",
            outdir.path().join("root.json").to_str().unwrap(),
        ])
        .assert()
        .failure();
}
