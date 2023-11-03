// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::test_utils::{dir_url, read_to_end, test_data};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tough::editor::signed::PathExists;
use tough::editor::{targets::TargetsEditor, RepositoryEditor};
use tough::key_source::KeySource;
use tough::key_source::LocalKeySource;
use tough::schema::decoded::Decoded;
use tough::schema::decoded::Hex;
use tough::schema::key::Key;
use tough::schema::{PathPattern, PathSet};
use tough::{Repository, RepositoryLoader, TargetName};
use url::Url;

mod test_utils;

struct RepoPaths {
    root_path: PathBuf,
    metadata_base_url: Url,
    targets_base_url: Url,
}

impl RepoPaths {
    fn new() -> Self {
        let base = test_data().join("tuf-reference-impl");
        RepoPaths {
            root_path: base.join("metadata").join("1.root.json"),
            metadata_base_url: dir_url(base.join("metadata")),
            targets_base_url: dir_url(base.join("targets")),
        }
    }

    async fn root(&self) -> Vec<u8> {
        tokio::fs::read(&self.root_path).await.unwrap()
    }
}

// Path to the root.json that corresponds with snakeoil.pem
fn root_path() -> PathBuf {
    test_data().join("simple-rsa").join("root.json")
}

fn key_path() -> PathBuf {
    test_data().join("snakeoil.pem")
}

fn targets_key_path() -> PathBuf {
    test_data().join("targetskey")
}

fn targets_key_path1() -> PathBuf {
    test_data().join("targetskey-1")
}

// Path to fake targets in the reference implementation
fn targets_path() -> PathBuf {
    test_data().join("tuf-reference-impl").join("targets")
}

async fn load_tuf_reference_impl(paths: &mut RepoPaths) -> Repository {
    RepositoryLoader::new(
        &paths.root().await,
        paths.metadata_base_url.clone(),
        paths.targets_base_url.clone(),
    )
    .load()
    .await
    .unwrap()
}

async fn test_repo_editor() -> RepositoryEditor {
    let root = root_path();
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version = NonZeroU64::new(1234).unwrap();
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version = NonZeroU64::new(5432).unwrap();
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version = NonZeroU64::new(789).unwrap();
    let target3 = targets_path().join("file3.txt");
    let target_list = vec![target3];

    let mut editor = RepositoryEditor::new(root).await.unwrap();
    editor
        .targets_expires(targets_expiration)
        .unwrap()
        .targets_version(targets_version)
        .unwrap()
        .snapshot_expires(snapshot_expiration)
        .snapshot_version(snapshot_version)
        .timestamp_expires(timestamp_expiration)
        .timestamp_version(timestamp_version)
        .add_target_paths(target_list)
        .await
        .unwrap();
    editor
}

async fn key_hash_map(keys: &[Box<dyn KeySource>]) -> HashMap<Decoded<Hex>, Key> {
    let mut key_pairs = HashMap::new();
    for source in keys {
        let key_pair = source.as_sign().await.unwrap().tuf_key();
        key_pairs.insert(key_pair.key_id().unwrap().clone(), key_pair.clone());
    }
    key_pairs
}

// Test a RepositoryEditor can be created from an existing Repo
#[tokio::test]
async fn repository_editor_from_repository() {
    // Load the reference_impl repo
    let mut repo_paths = RepoPaths::new();
    let root = repo_paths.root_path.clone();
    let repo = load_tuf_reference_impl(&mut repo_paths).await;

    assert!(RepositoryEditor::from_repo(root, repo).await.is_ok());
}

// Create sign write and reload repo
#[tokio::test]
async fn create_sign_write_reload_repo() {
    let root = root_path();
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version = NonZeroU64::new(1234).unwrap();
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version = NonZeroU64::new(5432).unwrap();
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version = NonZeroU64::new(789).unwrap();
    let target3 = targets_path().join("file3.txt");
    let target_list = vec![target3];

    let create_dir = TempDir::new().unwrap();

    let mut editor = RepositoryEditor::new(&root).await.unwrap();
    editor
        .targets_expires(targets_expiration)
        .unwrap()
        .targets_version(targets_version)
        .unwrap()
        .snapshot_expires(snapshot_expiration)
        .snapshot_version(snapshot_version)
        .timestamp_expires(timestamp_expiration)
        .timestamp_version(timestamp_version)
        .add_target_paths(target_list)
        .await
        .unwrap();

    let targets_key: &[std::boxed::Box<(dyn tough::key_source::KeySource + 'static)>] =
        &[Box::new(LocalKeySource { path: key_path() })];
    let role1_key: &[std::boxed::Box<(dyn tough::key_source::KeySource + 'static)>] =
        &[Box::new(LocalKeySource {
            path: targets_key_path(),
        })];
    let role2_key: &[std::boxed::Box<(dyn tough::key_source::KeySource + 'static)>] =
        &[Box::new(LocalKeySource {
            path: targets_key_path1(),
        })];

    // add role1 to targets
    editor
        .delegate_role(
            "role1",
            role1_key,
            PathSet::Paths(vec![PathPattern::new("file?.txt").unwrap()]),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .await
        .unwrap();
    // switch repo owner to role1
    editor
        .sign_targets_editor(targets_key)
        .await
        .unwrap()
        .change_delegated_targets("role1")
        .unwrap()
        .add_target_paths([targets_path().join("file1.txt").to_str().unwrap()].to_vec())
        .await
        .unwrap()
        .delegate_role(
            "role2",
            role2_key,
            PathSet::Paths(vec![PathPattern::new("file1.txt").unwrap()]),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .await
        .unwrap()
        .delegate_role(
            "role3",
            role1_key,
            PathSet::Paths(vec![PathPattern::new("file1.txt").unwrap()]),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .await
        .unwrap();
    editor
        .targets_version(targets_version)
        .unwrap()
        .targets_expires(targets_expiration)
        .unwrap()
        .sign_targets_editor(role1_key)
        .await
        .unwrap()
        .change_delegated_targets("targets")
        .unwrap()
        .delegate_role(
            "role4",
            role2_key,
            PathSet::Paths(vec![PathPattern::new("file1.txt").unwrap()]),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .await
        .unwrap()
        .targets_version(targets_version)
        .unwrap()
        .targets_expires(targets_expiration)
        .unwrap();

    let signed_repo = editor.sign(targets_key).await.unwrap();

    let metadata_destination = create_dir.path().join("metadata");
    let targets_destination = create_dir.path().join("targets");

    assert!(signed_repo.write(&metadata_destination).await.is_ok());
    assert!(signed_repo
        .link_targets(targets_path(), &targets_destination, PathExists::Skip)
        .await
        .is_ok());
    // Load the repo we just created
    let _new_repo = RepositoryLoader::new(
        &tokio::fs::read(&root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();
}

#[tokio::test]
/// Delegates role from Targets to A and then A to B
async fn create_role_flow() {
    let editor = test_repo_editor().await;

    let targets_key: &[std::boxed::Box<(dyn tough::key_source::KeySource + 'static)>] =
        &[Box::new(LocalKeySource { path: key_path() })];
    let role1_key: &[std::boxed::Box<(dyn tough::key_source::KeySource + 'static)>] =
        &[Box::new(LocalKeySource {
            path: targets_key_path(),
        })];
    let role2_key: &[std::boxed::Box<(dyn tough::key_source::KeySource + 'static)>] =
        &[Box::new(LocalKeySource {
            path: targets_key_path1(),
        })];

    // write the repo to temp location
    let repodir = TempDir::new().unwrap();
    let metadata_destination = repodir.as_ref().join("metadata");
    let targets_destination = repodir.as_ref().join("targets");
    let signed = editor.sign(targets_key).await.unwrap();
    signed.write(&metadata_destination).await.unwrap();

    // create new delegated target as "A" and sign with role1_key
    let new_role = TargetsEditor::new("A")
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .sign(role1_key)
        .await
        .unwrap();

    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    new_role
        .write(&metadata_destination_out, false)
        .await
        .unwrap();

    // reload repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(targets_destination),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    // add outdir to repo
    //create a new editor with the repo
    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo)
        .await
        .unwrap();
    editor
        .add_role(
            "A",
            metadata_base_url_out.as_str(),
            PathSet::Paths(vec![PathPattern::new("*.txt").unwrap()]),
            NonZeroU64::new(1).unwrap(),
            Some(key_hash_map(role1_key).await),
        )
        .await
        .unwrap();

    //sign everything since targets key is the same as snapshot and timestamp
    let root_key = key_path();
    let key_source = LocalKeySource { path: root_key };
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version = NonZeroU64::new(1234).unwrap();
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version = NonZeroU64::new(5432).unwrap();
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version = NonZeroU64::new(789).unwrap();
    editor
        .targets_expires(targets_expiration)
        .unwrap()
        .targets_version(targets_version)
        .unwrap()
        .snapshot_expires(snapshot_expiration)
        .snapshot_version(snapshot_version)
        .timestamp_expires(timestamp_expiration)
        .timestamp_version(timestamp_version);
    let signed = editor.sign(&[Box::new(key_source)]).await.unwrap();

    // write repo
    let new_dir = TempDir::new().unwrap();
    let metadata_destination = new_dir.as_ref().join("metadata");
    let targets_destination = new_dir.as_ref().join("targets");
    signed.write(&metadata_destination).await.unwrap();

    // reload repo and verify that A role is included
    // reload repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();
    new_repo.delegated_role("A").unwrap();

    // Delegate from A to B

    // create new delegated target as "B" and sign with role2_key
    let new_role = TargetsEditor::new("B")
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .sign(role2_key)
        .await
        .unwrap();
    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    new_role
        .write(&metadata_destination_out, false)
        .await
        .unwrap();

    // reload repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);

    // create a new editor with the repo
    let mut editor = TargetsEditor::from_repo(new_repo, "A").unwrap();

    // add B metadata to role A (without resigning targets)
    editor
        .add_role(
            "B",
            metadata_base_url_out.as_str(),
            PathSet::Paths(vec![PathPattern::new("file?.txt").unwrap()]),
            NonZeroU64::new(1).unwrap(),
            Some(key_hash_map(role2_key).await),
        )
        .await
        .unwrap()
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap());

    // sign A and write A and B metadata to output directory
    let signed_roles = editor.sign(role1_key).await.unwrap();

    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    signed_roles
        .write(&metadata_destination_out, false)
        .await
        .unwrap();

    // reload repo and add in A and B metadata and update snapshot
    // reload repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    // add outdir to repo
    let root_key = key_path();
    let key_source = LocalKeySource { path: root_key };

    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo)
        .await
        .unwrap();
    editor
        .update_delegated_targets("A", metadata_base_url_out.as_str())
        .await
        .unwrap();
    editor
        .snapshot_version(NonZeroU64::new(1).unwrap())
        .snapshot_expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .timestamp_version(NonZeroU64::new(1).unwrap())
        .timestamp_expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap());

    let signed_refreshed_repo = editor.sign(&[Box::new(key_source)]).await.unwrap();

    // write repo
    let end_repo = TempDir::new().unwrap();

    let metadata_destination = end_repo.as_ref().join("metadata");
    let targets_destination = end_repo.as_ref().join("targets");

    signed_refreshed_repo
        .write(&metadata_destination)
        .await
        .unwrap();

    // reload repo and verify that A and B role are included
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(metadata_destination),
        dir_url(targets_destination),
    )
    .load()
    .await
    .unwrap();

    // verify that role A and B are included
    new_repo.delegated_role("A").unwrap();
    new_repo.delegated_role("B").unwrap();
}

#[tokio::test]
/// Delegtes role from Targets to A and then A to B
async fn update_targets_flow() {
    // The beginning of this creates a repo with Target -> A ('*.txt') -> B ('file?.txt')
    let editor = test_repo_editor().await;

    let targets_key: &[std::boxed::Box<(dyn tough::key_source::KeySource + 'static)>] =
        &[Box::new(LocalKeySource { path: key_path() })];
    let role1_key: &[std::boxed::Box<(dyn tough::key_source::KeySource + 'static)>] =
        &[Box::new(LocalKeySource {
            path: targets_key_path(),
        })];
    let role2_key: &[std::boxed::Box<(dyn tough::key_source::KeySource + 'static)>] =
        &[Box::new(LocalKeySource {
            path: targets_key_path1(),
        })];

    // write the repo to temp location
    let repodir = TempDir::new().unwrap();
    let metadata_destination = repodir.as_ref().join("metadata");
    let targets_destination = repodir.as_ref().join("targets");
    let signed = editor.sign(targets_key).await.unwrap();
    signed.write(&metadata_destination).await.unwrap();

    // create new delegated target as "A" and sign with role1_key
    let new_role = TargetsEditor::new("A")
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .sign(role1_key)
        .await
        .unwrap();

    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    new_role
        .write(&metadata_destination_out, false)
        .await
        .unwrap();

    // reload repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(targets_destination),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    // add outdir to repo
    //create a new editor with the repo
    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo)
        .await
        .unwrap();
    editor
        .add_role(
            "A",
            metadata_base_url_out.as_str(),
            PathSet::Paths(vec![PathPattern::new("*.txt").unwrap()]),
            NonZeroU64::new(1).unwrap(),
            Some(key_hash_map(role1_key).await),
        )
        .await
        .unwrap();

    //sign everything since targets key is the same as snapshot and timestamp
    let root_key = key_path();
    let key_source = LocalKeySource { path: root_key };
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version = NonZeroU64::new(1234).unwrap();
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version = NonZeroU64::new(5432).unwrap();
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version = NonZeroU64::new(789).unwrap();
    editor
        .targets_expires(targets_expiration)
        .unwrap()
        .targets_version(targets_version)
        .unwrap()
        .snapshot_expires(snapshot_expiration)
        .snapshot_version(snapshot_version)
        .timestamp_expires(timestamp_expiration)
        .timestamp_version(timestamp_version);
    let signed = editor.sign(&[Box::new(key_source)]).await.unwrap();

    // write repo
    let new_dir = TempDir::new().unwrap();
    let metadata_destination = new_dir.as_ref().join("metadata");
    let targets_destination = new_dir.as_ref().join("targets");
    signed.write(&metadata_destination).await.unwrap();

    // reload repo and verify that A role is included
    // reload repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();
    new_repo.delegated_role("A").unwrap();

    // Delegate from A to B

    // create new delegated target as "B" and sign with role2_key
    let new_role = TargetsEditor::new("B")
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .sign(role2_key)
        .await
        .unwrap();
    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    new_role
        .write(&metadata_destination_out, false)
        .await
        .unwrap();

    // reload repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);

    // create a new editor with the repo
    let mut editor = TargetsEditor::from_repo(new_repo, "A").unwrap();

    // add B metadata to role A (without resigning targets)
    editor
        .add_role(
            "B",
            metadata_base_url_out.as_str(),
            PathSet::Paths(vec![PathPattern::new("file?.txt").unwrap()]),
            NonZeroU64::new(1).unwrap(),
            Some(key_hash_map(role2_key).await),
        )
        .await
        .unwrap()
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap());

    // sign A and write A and B metadata to output directory
    let signed_roles = editor.sign(role1_key).await.unwrap();

    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    signed_roles
        .write(&metadata_destination_out, false)
        .await
        .unwrap();

    // reload repo and add in A and B metadata and update snapshot
    // reload repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    // add outdir to repo
    let root_key = key_path();
    let key_source = LocalKeySource { path: root_key };

    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo)
        .await
        .unwrap();
    editor
        .update_delegated_targets("A", metadata_base_url_out.as_str())
        .await
        .unwrap();
    editor
        .snapshot_version(NonZeroU64::new(1).unwrap())
        .snapshot_expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .timestamp_version(NonZeroU64::new(1).unwrap())
        .timestamp_expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap());

    let signed_refreshed_repo = editor.sign(&[Box::new(key_source)]).await.unwrap();

    // write repo
    let end_repo = TempDir::new().unwrap();

    let metadata_destination = end_repo.as_ref().join("metadata");
    let targets_destination = end_repo.as_ref().join("targets");

    signed_refreshed_repo
        .write(&metadata_destination)
        .await
        .unwrap();

    // reload repo and verify that A and B role are included
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    // verify that role A and B are included
    new_repo.delegated_role("A").unwrap();
    new_repo.delegated_role("B").unwrap();

    // -------------------------------------------------------
    // Start test code for adding targets
    // -------------------------------------------------------

    // Add target file1.txt to A
    let mut editor = TargetsEditor::from_repo(new_repo, "A").unwrap();
    let file1 = targets_path().join("file1.txt");
    let targets = vec![file1];
    editor
        .add_target_paths(targets)
        .await
        .unwrap()
        .version(targets_version)
        .expires(targets_expiration);

    // Sign A metadata
    let role = editor.sign(role1_key).await.unwrap();

    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    let targets_destination_out = outdir.as_ref().join("targets");

    // Write metadata to outdir/metata/A.json
    role.write(&metadata_destination_out, false).await.unwrap();

    // Copy targets to outdir/targets/...
    role.copy_targets(targets_path(), &targets_destination_out, PathExists::Skip)
        .await
        .unwrap();

    // Add in edited A targets and update snapshot (update-repo)
    // load repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo)
        .await
        .unwrap();
    // update A metadata
    editor
        .update_delegated_targets("A", metadata_base_url_out.as_str())
        .await
        .unwrap()
        .snapshot_version(snapshot_version)
        .snapshot_expires(snapshot_expiration)
        .timestamp_version(timestamp_version)
        .timestamp_expires(timestamp_expiration);
    let signed_repo = editor.sign(targets_key).await.unwrap();

    // write signed repo
    let end_repo = TempDir::new().unwrap();

    let metadata_destination = end_repo.as_ref().join("metadata");
    let targets_destination = end_repo.as_ref().join("targets");

    signed_repo.write(&metadata_destination).await.unwrap();
    signed_repo
        .copy_targets(
            &targets_destination_out,
            &targets_destination,
            PathExists::Skip,
        )
        .await
        .unwrap();

    //load the updated repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    let file1 = TargetName::new("file1.txt").unwrap();
    assert_eq!(
        read_to_end(new_repo.read_target(&file1).await.unwrap().unwrap()).await,
        &b"This is an example target file."[..]
    );

    // Edit target "file1.txt"
    let mut editor = TargetsEditor::from_repo(new_repo, "A").unwrap();
    File::create(targets_destination_out.join("file1.txt"))
        .await
        .unwrap()
        .write_all(b"Updated file1.txt")
        .await
        .unwrap();
    let file1 = targets_destination_out.join("file1.txt");
    let targets = vec![file1];
    editor
        .add_target_paths(targets)
        .await
        .unwrap()
        .version(targets_version)
        .expires(targets_expiration);

    // Sign A metadata
    let role = editor.sign(role1_key).await.unwrap();

    let outdir = TempDir::new().unwrap();
    let metadata_destination_output = outdir.as_ref().join("metadata");
    let targets_destination_output = outdir.as_ref().join("targets");

    // Write metadata to outdir/metata/A.json
    role.write(&metadata_destination_output, false)
        .await
        .unwrap();

    // Copy targets to outdir/targets/...
    role.link_targets(
        &targets_destination_out,
        &targets_destination_output,
        PathExists::Skip,
    )
    .await
    .unwrap();

    // Add in edited A targets and update snapshot (update-repo)
    // load repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_output);
    let _targets_base_url_out = dir_url(&targets_destination_output);
    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo)
        .await
        .unwrap();
    // add in updated metadata
    editor
        .update_delegated_targets("A", metadata_base_url_out.as_str())
        .await
        .unwrap()
        .snapshot_version(snapshot_version)
        .snapshot_expires(snapshot_expiration)
        .timestamp_version(timestamp_version)
        .timestamp_expires(timestamp_expiration);
    let signed_repo = editor.sign(targets_key).await.unwrap();

    // write signed repo
    let end_repo = TempDir::new().unwrap();

    let metadata_destination = end_repo.as_ref().join("metadata");
    let targets_destination = end_repo.as_ref().join("targets");

    signed_repo.write(&metadata_destination).await.unwrap();
    signed_repo
        .link_targets(
            &targets_destination_out,
            &targets_destination,
            PathExists::Skip,
        )
        .await
        .unwrap();

    //load the updated repo
    let root = root_path();
    let new_repo = RepositoryLoader::new(
        &tokio::fs::read(root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    let file1 = TargetName::new("file1.txt").unwrap();
    assert_eq!(
        read_to_end(new_repo.read_target(&file1).await.unwrap().unwrap()).await,
        &b"Updated file1.txt"[..]
    );
}
