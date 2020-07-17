// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;

use assert_cmd::Command;

#[ignore]
#[test]
// Ensure we can create and sign a root file
fn create_root() {
    let key = test_utils::test_data().join("snakeoil.pem");
    // Create root.json
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "init", "tests/root_test/root.json"])
        .assert()
        .success();

    // Set the threshold for roles
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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

    // Sign root.json
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "sign",
            "tests/root_test/root.json",
            key.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[ignore]
#[test]
// Ensure creating an unstable root throws error
fn create_unstable_root() {
    let key = test_utils::test_data().join("snakeoil.pem");
    // Create root.json
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "init", "tests/root_test/root.json"])
        .assert()
        .success();

    // Set the threshold for roles with targets being more than 1
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
            key.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[ignore]
#[test]
// Ensure signing a root with insuffecient keys throws error
fn create_invalid_root() {
    let key = test_utils::test_data().join("snakeoil.pem");
    // Create root.json
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&["root", "init", "tests/root_test/root.json"])
        .assert()
        .success();

    // Set the threshold for roles
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "root",
            "set-threshold",
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
            "tests/root_test/root.json",
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
        .args(&["root", "sign", "tests/root_test/root.json"])
        .assert()
        .failure();
}
