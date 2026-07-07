// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Regression tests for awslabs/tough#950: re-serializing parsed metadata must reproduce the
//! exact `expires` bytes that were signed (by default jiff normalizes trailing-zero fractional
//! seconds), so that lossy type round-trips cannot invalidate otherwise-valid signatures. Also
//! verifies that the editor preserves the signatures of delegated roles it cannot re-sign.

mod test_utils;

use crate::test_utils::{days, dir_url, test_data};
use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::rand::SystemRandom;
use jiff::Timestamp;
use olpc_cjson::CanonicalFormatter;
use serde::Serialize;
use serde_json::{json, Value};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::{PathPattern, PathSet};
use tough::RepositoryLoader;

/// An expiration date, in the future, whose fractional seconds end in a zero digit. jiff
/// normalizes this to `.12345678Z` when round-tripped through `Signed<T>`, which is exactly the
/// lossy re-serialization that broke signature verification in awslabs/tough#950.
const TRAILING_ZERO_EXPIRES: &str = "2222-01-01T00:00:00.123456780Z";

// Path to the root.json that corresponds with snakeoil.pem
fn root_path() -> PathBuf {
    test_data().join("simple-rsa").join("root.json")
}

// Key for all top-level roles in simple-rsa/root.json
fn key_path() -> PathBuf {
    test_data().join("snakeoil.pem")
}

// Key used for the delegated role; never handed to the second editor
fn delegated_key_path() -> PathBuf {
    test_data().join("targetskey")
}

/// Serializes the `signed` member of a metadata document as canonical JSON.
fn canonical_signed(doc: &Value) -> Vec<u8> {
    let mut data = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
    doc["signed"].serialize(&mut ser).unwrap();
    data
}

/// Re-signs a (possibly modified) metadata document with the given key, reusing the keyid of the
/// document's first signature, and writes it back to `path`.
async fn resign_and_write(path: &Path, key: PathBuf, doc: &mut Value) {
    let data = canonical_signed(doc);
    let key = LocalKeySource { path: key }.as_sign().await.unwrap();
    let sig = key.sign(&data, &SystemRandom::new()).await.unwrap();
    let keyid = doc["signatures"][0]["keyid"].clone();
    doc["signatures"] = json!([{ "keyid": keyid, "sig": hex::encode(sig) }]);
    tokio::fs::write(path, serde_json::to_vec_pretty(doc).unwrap())
        .await
        .unwrap();
}

/// Reads a metadata document from `path` as a JSON value.
async fn read_doc(path: &Path) -> Value {
    serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap()
}

/// A `RepositoryEditor` for the simple-rsa root with all versions and expirations set.
async fn base_editor() -> RepositoryEditor {
    let mut editor = RepositoryEditor::new(root_path()).await.unwrap();
    editor
        .targets_expires(Timestamp::now() + days(13))
        .unwrap()
        .targets_version(NonZeroU64::new(1).unwrap())
        .unwrap()
        .snapshot_expires(Timestamp::now() + days(21))
        .snapshot_version(NonZeroU64::new(1).unwrap())
        .timestamp_expires(Timestamp::now() + days(3))
        .timestamp_version(NonZeroU64::new(1).unwrap());
    editor
}

/// Direct repro of awslabs/tough#950: a repository whose `timestamp.json` has an `expires` with a
/// trailing-zero fractional-second digit must load successfully. The metadata written by the
/// editor is pretty-printed, so this also exercises verification of non-canonical documents.
#[tokio::test]
async fn load_succeeds_with_trailing_zero_fractional_seconds() {
    let targets_key: &[Box<dyn KeySource>] = &[Box::new(LocalKeySource { path: key_path() })];

    // Sanity check: jiff does normalize this timestamp when round-tripped through the type
    // system, i.e. re-serializing the parsed metadata would produce different signed bytes.
    let parsed: Timestamp = TRAILING_ZERO_EXPIRES.parse().unwrap();
    assert_ne!(parsed.to_string(), TRAILING_ZERO_EXPIRES);

    // Build and write a repository.
    let repo_dir = TempDir::new().unwrap();
    let metadata_dir = repo_dir.path().join("metadata");
    let editor = base_editor().await;
    let signed = editor.sign(targets_key).await.unwrap();
    signed.write(&metadata_dir).await.unwrap();

    // Rewrite timestamp.json with a trailing-zero fractional-second expiration and re-sign the
    // canonicalized `signed` value with the same key.
    let timestamp_path = metadata_dir.join("timestamp.json");
    let mut doc = read_doc(&timestamp_path).await;
    doc["signed"]["expires"] = json!(TRAILING_ZERO_EXPIRES);
    resign_and_write(&timestamp_path, key_path(), &mut doc).await;

    // The repository must load: signature verification operates on the raw document bytes.
    RepositoryLoader::new(
        &tokio::fs::read(root_path()).await.unwrap(),
        dir_url(&metadata_dir),
        dir_url(repo_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();
}

/// The editor must not invalidate signatures on delegated roles it cannot re-sign: a delegated
/// role signed by a foreign key (and carrying a normalization-sensitive `expires`) must be
/// written back by `sign()` + `write()` with its canonical signed bytes and signatures intact,
/// and the written repo must reload.
#[tokio::test]
async fn write_preserves_unmodified_delegated_role_bytes() {
    let targets_key: &[Box<dyn KeySource>] = &[Box::new(LocalKeySource { path: key_path() })];
    let role1_key: &[Box<dyn KeySource>] = &[Box::new(LocalKeySource {
        path: delegated_key_path(),
    })];

    // Build a repository with a delegated role "role1" signed by role1_key.
    let mut editor = base_editor().await;
    editor
        .delegate_role(
            "role1",
            role1_key,
            PathSet::Paths(vec![PathPattern::new("file?.txt").unwrap()]),
            false,
            NonZeroU64::new(1).unwrap(),
            Timestamp::now() + days(21),
            NonZeroU64::new(1).unwrap(),
        )
        .await
        .unwrap();
    let source_dir = TempDir::new().unwrap();
    let source_metadata = source_dir.path().join("metadata");
    let signed = editor.sign(targets_key).await.unwrap();
    signed.write(&source_metadata).await.unwrap();

    // simple-rsa uses consistent snapshots; all roles above were written as version 1.
    let role1_path = source_metadata.join("1.role1.json");
    let snapshot_path = source_metadata.join("1.snapshot.json");
    let timestamp_path = source_metadata.join("timestamp.json");

    // Give role1 a trailing-zero fractional-second expiration and re-sign it with its own
    // (foreign to the later editor) key.
    let mut role1_doc = read_doc(&role1_path).await;
    role1_doc["signed"]["expires"] = json!(TRAILING_ZERO_EXPIRES);
    resign_and_write(&role1_path, delegated_key_path(), &mut role1_doc).await;
    let role1_bytes = tokio::fs::read(&role1_path).await.unwrap();

    // Fix up the snapshot's hash/length for the modified role1 metadata and re-sign it.
    let mut snapshot_doc = read_doc(&snapshot_path).await;
    snapshot_doc["signed"]["meta"]["role1.json"]["hashes"]["sha256"] =
        json!(hex::encode(digest(&SHA256, &role1_bytes)));
    snapshot_doc["signed"]["meta"]["role1.json"]["length"] = json!(role1_bytes.len());
    resign_and_write(&snapshot_path, key_path(), &mut snapshot_doc).await;
    let snapshot_bytes = tokio::fs::read(&snapshot_path).await.unwrap();

    // Fix up the timestamp's hash/length for the modified snapshot metadata and re-sign it.
    let mut timestamp_doc = read_doc(&timestamp_path).await;
    timestamp_doc["signed"]["meta"]["snapshot.json"]["hashes"]["sha256"] =
        json!(hex::encode(digest(&SHA256, &snapshot_bytes)));
    timestamp_doc["signed"]["meta"]["snapshot.json"]["length"] = json!(snapshot_bytes.len());
    resign_and_write(&timestamp_path, key_path(), &mut timestamp_doc).await;

    // Load the repository (this alone exercises the #950 read-path fix for delegated roles).
    let root_bytes = tokio::fs::read(root_path()).await.unwrap();
    let repo = RepositoryLoader::new(
        &root_bytes,
        dir_url(&source_metadata),
        dir_url(source_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Re-sign the repository with only the top-level key. role1_key is not provided, so the
    // editor cannot re-sign role1 and must pass its original bytes through.
    let mut editor = RepositoryEditor::from_repo(root_path(), repo)
        .await
        .unwrap();
    editor
        .targets_expires(Timestamp::now() + days(13))
        .unwrap()
        .targets_version(NonZeroU64::new(2).unwrap())
        .unwrap()
        .snapshot_expires(Timestamp::now() + days(21))
        .snapshot_version(NonZeroU64::new(2).unwrap())
        .timestamp_expires(Timestamp::now() + days(3))
        .timestamp_version(NonZeroU64::new(2).unwrap());
    let signed = editor.sign(targets_key).await.unwrap();

    let out_dir = TempDir::new().unwrap();
    let out_metadata = out_dir.path().join("metadata");
    signed.write(&out_metadata).await.unwrap();

    // The written delegated role must carry the same signatures over the same canonical signed
    // bytes as the source file, so the foreign signature remains valid. (Byte-for-byte identity
    // is not guaranteed: the editor re-serializes metadata with its own formatting.)
    let written_role1 = read_doc(&out_metadata.join("1.role1.json")).await;
    let source_role1: Value = serde_json::from_slice(&role1_bytes).unwrap();
    assert_eq!(
        canonical_signed(&written_role1),
        canonical_signed(&source_role1)
    );
    assert_eq!(written_role1["signatures"], source_role1["signatures"]);

    // And the written repository must load successfully.
    RepositoryLoader::new(
        &root_bytes,
        dir_url(&out_metadata),
        dir_url(out_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();
}
