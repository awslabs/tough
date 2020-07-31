// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::test_utils::{dir_url, read_to_end, test_data};
use chrono::{Duration, Utc};
use ring::rand::SystemRandom;
use ring::signature;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::Write;
use std::io::Read;
use std::num::NonZeroU64;
use std::path::PathBuf;
use tempfile::TempDir;
use tough::editor::signed::PathExists;
use tough::editor::{RepositoryEditor, TargetsEditor};
use tough::key_source::KeySource;
use tough::key_source::LocalKeySource;
use tough::schema::decoded::Decoded;
use tough::schema::decoded::Hex;
use tough::schema::key::Key;
use tough::schema::PathSet;
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository, Settings};

mod test_utils;

struct RepoPaths {
    root_path: PathBuf,
    datastore: TempDir,
    metadata_base_url: String,
    targets_base_url: String,
}

impl RepoPaths {
    fn new() -> Self {
        let base = test_data().join("tuf-reference-impl");
        RepoPaths {
            root_path: base.join("metadata").join("1.root.json"),
            datastore: TempDir::new().unwrap(),
            metadata_base_url: dir_url(base.join("metadata")),
            targets_base_url: dir_url(base.join("targets")),
        }
    }

    fn root(&self) -> File {
        File::open(&self.root_path).unwrap()
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

fn load_tuf_reference_impl<'a>(paths: &'a mut RepoPaths) -> Repository<'a, FilesystemTransport> {
    Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: &mut paths.root(),
            datastore: paths.datastore.as_ref(),
            metadata_base_url: paths.metadata_base_url.as_str(),
            targets_base_url: paths.targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap()
}

fn test_repo_editor() -> RepositoryEditor<'static, FilesystemTransport> {
    let root = root_path();
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version = NonZeroU64::new(1234).unwrap();
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version = NonZeroU64::new(5432).unwrap();
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version = NonZeroU64::new(789).unwrap();
    let target3 = targets_path().join("file3.txt");
    let target_list = vec![target3];

    let mut editor = RepositoryEditor::new(&root).unwrap();
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
        .unwrap();
    editor
}

fn key_hash_map(keys: &[Box<dyn KeySource>]) -> HashMap<Decoded<Hex>, Key> {
    let mut key_pairs = HashMap::new();
    for source in keys {
        let key_pair = source.as_sign().unwrap().tuf_key();
        key_pairs.insert(key_pair.key_id().unwrap().clone(), key_pair.clone());
    }
    key_pairs
}

// Test a RepositoryEditor can be created from an existing Repo
#[test]
fn repository_editor_from_repository() {
    // Load the reference_impl repo
    let mut repo_paths = RepoPaths::new();
    let root = repo_paths.root_path.clone();
    let repo = load_tuf_reference_impl(&mut repo_paths);

    assert!(RepositoryEditor::from_repo(&root, repo).is_ok());
}

// Create sign write and reload repo
#[test]
fn create_sign_write_reload_repo() {
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

    let mut editor = RepositoryEditor::<FilesystemTransport>::new(&root).unwrap();
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
            PathSet::Paths(["file?.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
    // switch repo owner to role1
    editor
        .change_targets("role1", Some(targets_key))
        .unwrap()
        .add_target_paths([targets_path().join("file1.txt").to_str().unwrap()].to_vec())
        .unwrap()
        .delegate_role(
            "role2",
            role2_key,
            PathSet::Paths(["file1.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap()
        .delegate_role(
            "role3",
            role1_key,
            PathSet::Paths(["file1.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
    editor
        .targets_version(targets_version)
        .unwrap()
        .targets_expires(targets_expiration)
        .unwrap()
        .change_targets("targets", Some(role1_key))
        .unwrap()
        .delegate_role(
            "role4",
            role2_key,
            PathSet::Paths(["file1.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();

    let signed_repo = editor.sign(targets_key).unwrap();

    let metadata_destination = create_dir.path().join("metadata");
    let targets_destination = create_dir.path().join("targets");

    assert!(signed_repo.write(&metadata_destination).is_ok());
    assert!(signed_repo
        .link_targets(&targets_path(), &targets_destination, PathExists::Skip)
        .is_ok());
    // Load the repo we just created
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let _new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &create_dir.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();
}

//Test partial signing of newly created repo
#[test]
fn partial_sign() {
    let root = root_path();
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version = NonZeroU64::new(1234).unwrap();
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version = NonZeroU64::new(5432).unwrap();
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version = NonZeroU64::new(789).unwrap();
    let target3 = targets_path().join("file3.txt");
    let target_list = vec![target3];

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

    let create_dir = TempDir::new().unwrap();

    let mut editor = RepositoryEditor::<FilesystemTransport>::new(&root).unwrap();
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
        .unwrap();

    //add delegations
    editor
        .delegate_role(
            "role1",
            role1_key,
            PathSet::Paths(["file?.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
    editor
        .change_targets("role1", Some(targets_key))
        .unwrap()
        .add_target_paths([targets_path().join("file1.txt").to_str().unwrap()].to_vec())
        .unwrap()
        .delegate_role(
            "role2",
            role2_key,
            PathSet::Paths(["file1.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap()
        .delegate_role(
            "role3",
            role1_key,
            PathSet::Paths(["file1.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
    editor
        .targets_version(targets_version)
        .unwrap()
        .targets_expires(targets_expiration)
        .unwrap()
        .change_targets("role3", Some(role1_key))
        .unwrap()
        .delegate_role(
            "role4",
            role2_key,
            PathSet::Paths(["file1.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Utc::now().checked_add_signed(Duration::days(21)).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap()
        .targets_version(targets_version)
        .unwrap()
        .targets_expires(targets_expiration)
        .unwrap()
        .sign_targets_editor(role1_key)
        .unwrap();

    //sign the new repo
    let signed_repo = editor.sign(targets_key).unwrap();

    let metadata_destination = create_dir.path().join("metadata");
    let targets_destination = create_dir.path().join("targets");

    signed_repo.write(&metadata_destination).unwrap();
    signed_repo
        .link_targets(&targets_path(), &targets_destination, PathExists::Skip)
        .unwrap();
    // Load the repo we just created
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &create_dir.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    //create a new editor with the repo
    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo).unwrap();

    editor
        .targets_expires(targets_expiration)
        .unwrap()
        .targets_version(targets_version)
        .unwrap()
        .snapshot_expires(snapshot_expiration)
        .snapshot_version(snapshot_version)
        .timestamp_expires(timestamp_expiration)
        .timestamp_version(timestamp_version);

    //edit role 4
    assert!(editor
        .change_targets("role4", Some(targets_key))
        .unwrap()
        .add_target_path(targets_path().join("file2.txt").to_str().unwrap())
        .is_ok());

    //re-sign repo without key for roles 1,2,3
    let signed_repo = editor
        .sign(&[
            Box::new(LocalKeySource {
                path: targets_key_path1(),
            }),
            Box::new(LocalKeySource { path: key_path() }),
        ])
        .unwrap();

    assert!(signed_repo.write(&metadata_destination).is_ok());

    //make sure we can still load the repo
    assert!(Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &create_dir.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .is_ok());
}

// Load a repository, edit it, and write it to disk. Ensure it loads correctly
// and attempt to read a target
// Delegated targets only works with repos created by tough
#[test]
#[ignore]
fn repo_load_edit_write_load() {
    let mut repo_paths = RepoPaths::new();
    let repo = load_tuf_reference_impl(&mut repo_paths);

    let root = test_data().join("simple-rsa").join("root.json");
    let root_key = test_data().join("snakeoil.pem");
    let key_source = LocalKeySource { path: root_key };
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version = NonZeroU64::new(1234).unwrap();
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version = NonZeroU64::new(5432).unwrap();
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version = NonZeroU64::new(789).unwrap();
    let reference_targets_location = test_data().join("tuf-reference-impl").join("targets");
    let target3 = reference_targets_location.join("file3.txt");
    let targets_location = test_data().join("targets");
    let target4 = targets_location.join("file4.txt");

    // Load the reference_impl repo
    let mut editor = RepositoryEditor::from_repo(&root, repo).unwrap();

    // Add the required data and a new target
    // We clear the targets first because the reference implementation includes
    // "file1.txt" and "file2.txt". The reference implementation's "targets"
    // directory includes all 3 targets. We want to explicitly add "file3.txt"
    // as a target, and later ensure that "file3" is the only target in the
    // new repo and the only target that gets symlinked. Doing so tests the
    // implementation of `SignedRepository.link_targets()`.
    editor
        .targets_expires(targets_expiration)
        .unwrap()
        .targets_version(targets_version)
        .unwrap()
        .snapshot_expires(snapshot_expiration)
        .snapshot_version(snapshot_version)
        .timestamp_expires(timestamp_expiration)
        .timestamp_version(timestamp_version)
        .clear_targets()
        .unwrap()
        .add_target_path(target3)
        .unwrap()
        .add_target_path(target4)
        .unwrap();

    // Sign the newly updated repo
    let signed_repo = editor.sign(&[Box::new(key_source)]).unwrap();

    // Create the directories and write the repo to disk
    let destination = TempDir::new().unwrap();
    let metadata_destination = destination.as_ref().join("metadata");
    let targets_destination = destination.as_ref().join("targets");
    assert!(signed_repo.write(&metadata_destination).is_ok());
    assert!(signed_repo
        .link_targets(
            &reference_targets_location,
            &targets_destination,
            PathExists::Skip,
        )
        .is_ok());
    assert!(signed_repo
        .copy_targets(&targets_location, &targets_destination, PathExists::Skip)
        .is_ok());

    // Load the repo we just created
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: datastore.as_ref(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    // Ensure the new repo only has the single target
    assert_eq!(new_repo.targets().signed.targets.len(), 2);

    // The repo shouldn't contain file1 or file2
    // `read_target()` returns a Result(Option<>) which is why we unwrap
    assert!(new_repo.read_target("file1.txt").unwrap().is_none());
    assert!(new_repo.read_target("file2.txt").unwrap().is_none());

    // Read both new targets and ensure they're the right size
    let files_to_check = &[(28, "file3.txt"), (31, "file4.txt")];
    for (expected_file_size, filename) in files_to_check {
        let mut file_data = Vec::new();
        let actual_file_size = new_repo
            .read_target(filename)
            .unwrap()
            .unwrap()
            .read_to_end(&mut file_data)
            .unwrap();
        assert_eq!(*expected_file_size, actual_file_size);
    }
}

#[test]
fn gen_and_store_ed25519_keys() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let _key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let mut buffer = File::create(test_data().join("targetskey-2")).unwrap();
    buffer.write_all(pkcs8_bytes.as_ref()).unwrap();
}

#[test]
/// Delegates role from Targets to A and then A to B
fn create_role_flow() {
    let editor = test_repo_editor();

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
    let signed = editor.sign(targets_key).unwrap();
    signed.write(&metadata_destination).unwrap();

    // create new delegated target as "A" and sign with role1_key
    let new_role = TargetsEditor::<FilesystemTransport>::new("A")
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .sign(role1_key)
        .unwrap();

    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    new_role.write(&metadata_destination_out, false).unwrap();

    // reload repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    // add outdir to repo
    //create a new editor with the repo
    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo).unwrap();
    editor
        .add_role(
            "A",
            metadata_base_url_out.as_str(),
            PathSet::Paths(["*.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Some(key_hash_map(role1_key)),
        )
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
    let signed = editor.sign(&[Box::new(key_source)]).unwrap();

    // write repo
    let new_dir = TempDir::new().unwrap();
    let metadata_destination = new_dir.as_ref().join("metadata");
    let targets_destination = new_dir.as_ref().join("targets");
    signed.write(&metadata_destination).unwrap();

    // reload repo and verify that A role is included
    // reload repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();
    new_repo.delegated_role("A").unwrap();

    // Delegate from A to B

    // create new delegated target as "B" and sign with role2_key
    let new_role = TargetsEditor::<FilesystemTransport>::new("B")
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .sign(role2_key)
        .unwrap();
    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    new_role.write(&metadata_destination_out, false).unwrap();

    // reload repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);

    // create a new editor with the repo
    let mut editor = TargetsEditor::from_repo(&new_repo, "A").unwrap();

    // add B metadata to role A (without resigning targets)
    editor
        .add_role(
            "B",
            metadata_base_url_out.as_str(),
            PathSet::Paths(["file?.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Some(key_hash_map(role2_key)),
        )
        .unwrap()
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap());

    // sign A and write A and B metadata to output directory
    let signed_roles = editor.sign(role1_key).unwrap();

    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    signed_roles
        .write(&metadata_destination_out, false)
        .unwrap();

    // reload repo and add in A and B metadata and update snapshot
    // reload repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    // add outdir to repo
    let root_key = key_path();
    let key_source = LocalKeySource { path: root_key };

    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo).unwrap();
    editor
        .update_delegated_targets("A", metadata_base_url_out.as_str())
        .unwrap();
    editor
        .snapshot_version(NonZeroU64::new(1).unwrap())
        .snapshot_expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .timestamp_version(NonZeroU64::new(1).unwrap())
        .timestamp_expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap());

    let signed_refreshed_repo = editor.sign(&[Box::new(key_source)]).unwrap();

    // write repo
    let end_repo = TempDir::new().unwrap();

    let metadata_destination = end_repo.as_ref().join("metadata");
    let targets_destination = end_repo.as_ref().join("targets");

    signed_refreshed_repo.write(&metadata_destination).unwrap();

    // reload repo and verify that A and B role are included
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    // verify that role A and B are included
    new_repo.delegated_role("A").unwrap();
    new_repo.delegated_role("B").unwrap();
}

#[test]
/// Delegtes role from Targets to A and then A to B
fn update_targets_flow() {
    // The beginning of this creates a repo with Target -> A ('*.txt') -> B ('file?.txt')
    let editor = test_repo_editor();

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
    let signed = editor.sign(targets_key).unwrap();
    signed.write(&metadata_destination).unwrap();

    // create new delegated target as "A" and sign with role1_key
    let new_role = TargetsEditor::<FilesystemTransport>::new("A")
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .sign(role1_key)
        .unwrap();

    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    new_role.write(&metadata_destination_out, false).unwrap();

    // reload repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    // add outdir to repo
    //create a new editor with the repo
    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo).unwrap();
    editor
        .add_role(
            "A",
            metadata_base_url_out.as_str(),
            PathSet::Paths(["*.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Some(key_hash_map(role1_key)),
        )
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
    let signed = editor.sign(&[Box::new(key_source)]).unwrap();

    // write repo
    let new_dir = TempDir::new().unwrap();
    let metadata_destination = new_dir.as_ref().join("metadata");
    let targets_destination = new_dir.as_ref().join("targets");
    signed.write(&metadata_destination).unwrap();

    // reload repo and verify that A role is included
    // reload repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();
    new_repo.delegated_role("A").unwrap();

    // Delegate from A to B

    // create new delegated target as "B" and sign with role2_key
    let new_role = TargetsEditor::<FilesystemTransport>::new("B")
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .sign(role2_key)
        .unwrap();
    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    new_role.write(&metadata_destination_out, false).unwrap();

    // reload repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);

    // create a new editor with the repo
    let mut editor = TargetsEditor::from_repo(&new_repo, "A").unwrap();

    // add B metadata to role A (without resigning targets)
    editor
        .add_role(
            "B",
            metadata_base_url_out.as_str(),
            PathSet::Paths(["file?.txt".to_string()].to_vec()),
            NonZeroU64::new(1).unwrap(),
            Some(key_hash_map(role2_key)),
        )
        .unwrap()
        .version(NonZeroU64::new(1).unwrap())
        .expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap());

    // sign A and write A and B metadata to output directory
    let signed_roles = editor.sign(role1_key).unwrap();

    // write the role to outdir
    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    signed_roles
        .write(&metadata_destination_out, false)
        .unwrap();

    // reload repo and add in A and B metadata and update snapshot
    // reload repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    // add outdir to repo
    let root_key = key_path();
    let key_source = LocalKeySource { path: root_key };

    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo).unwrap();
    editor
        .update_delegated_targets("A", metadata_base_url_out.as_str())
        .unwrap();
    editor
        .snapshot_version(NonZeroU64::new(1).unwrap())
        .snapshot_expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap())
        .timestamp_version(NonZeroU64::new(1).unwrap())
        .timestamp_expires(Utc::now().checked_add_signed(Duration::days(21)).unwrap());

    let signed_refreshed_repo = editor.sign(&[Box::new(key_source)]).unwrap();

    // write repo
    let end_repo = TempDir::new().unwrap();

    let metadata_destination = end_repo.as_ref().join("metadata");
    let targets_destination = end_repo.as_ref().join("targets");

    signed_refreshed_repo.write(&metadata_destination).unwrap();

    // reload repo and verify that A and B role are included
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    // verify that role A and B are included
    new_repo.delegated_role("A").unwrap();
    new_repo.delegated_role("B").unwrap();

    // -------------------------------------------------------
    // Start test code for adding targets
    // -------------------------------------------------------

    // Add target file1.txt to A
    let mut editor = TargetsEditor::from_repo(&new_repo, "A").unwrap();
    let file1 = targets_path().join("file1.txt");
    let targets = vec![file1];
    editor
        .add_target_paths(targets)
        .unwrap()
        .version(targets_version)
        .expires(targets_expiration);

    // Sign A metadata
    let role = editor.sign(role1_key).unwrap();

    let outdir = TempDir::new().unwrap();
    let metadata_destination_out = outdir.as_ref().join("metadata");
    let targets_destination_out = outdir.as_ref().join("targets");

    // Write metadata to outdir/metata/A.json
    role.write(&metadata_destination_out, false).unwrap();

    // Copy targets to outdir/targets/...
    role.copy_targets(targets_path(), &targets_destination_out, PathExists::Skip)
        .unwrap();

    // Add in edited A targets and update snapshot (update-repo)
    // load repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_out);
    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo).unwrap();
    // update A metadata
    editor
        .update_delegated_targets("A", &metadata_base_url_out)
        .unwrap()
        .snapshot_version(snapshot_version)
        .snapshot_expires(snapshot_expiration)
        .timestamp_version(timestamp_version)
        .timestamp_expires(timestamp_expiration);
    let signed_repo = editor.sign(targets_key).unwrap();

    // write signed repo
    let end_repo = TempDir::new().unwrap();

    let metadata_destination = end_repo.as_ref().join("metadata");
    let targets_destination = end_repo.as_ref().join("targets");

    signed_repo.write(&metadata_destination).unwrap();
    signed_repo
        .copy_targets(
            &targets_destination_out,
            &targets_destination,
            PathExists::Skip,
        )
        .unwrap();

    //load the updated repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    assert_eq!(
        read_to_end(new_repo.read_target("file1.txt").unwrap().unwrap()),
        &b"This is an example target file."[..]
    );

    // Edit target "file1.txt"
    let mut editor = TargetsEditor::from_repo(&new_repo, "A").unwrap();
    File::create(targets_destination_out.join("file1.txt"))
        .unwrap()
        .write_all(b"Updated file1.txt")
        .unwrap();
    let file1 = targets_destination_out.join("file1.txt");
    let targets = vec![file1];
    editor
        .add_target_paths(targets)
        .unwrap()
        .version(targets_version)
        .expires(targets_expiration);

    // Sign A metadata
    let role = editor.sign(role1_key).unwrap();

    let outdir = TempDir::new().unwrap();
    let metadata_destination_output = outdir.as_ref().join("metadata");
    let targets_destination_output = outdir.as_ref().join("targets");

    // Write metadata to outdir/metata/A.json
    role.write(&metadata_destination_output, false).unwrap();

    // Copy targets to outdir/targets/...
    role.link_targets(
        &targets_destination_out,
        &targets_destination_output,
        PathExists::Skip,
    )
    .unwrap();

    // Add in edited A targets and update snapshot (update-repo)
    // load repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    let metadata_base_url_out = dir_url(&metadata_destination_output);
    let _targets_base_url_out = dir_url(&targets_destination_output);
    let mut editor = RepositoryEditor::from_repo(root_path(), new_repo).unwrap();
    // add in updated metadata
    editor
        .update_delegated_targets("A", &metadata_base_url_out)
        .unwrap()
        .snapshot_version(snapshot_version)
        .snapshot_expires(snapshot_expiration)
        .timestamp_version(timestamp_version)
        .timestamp_expires(timestamp_expiration);
    let signed_repo = editor.sign(targets_key).unwrap();

    // write signed repo
    let end_repo = TempDir::new().unwrap();

    let metadata_destination = end_repo.as_ref().join("metadata");
    let targets_destination = end_repo.as_ref().join("targets");

    signed_repo.write(&metadata_destination).unwrap();
    signed_repo
        .link_targets(
            &targets_destination_out,
            &targets_destination,
            PathExists::Skip,
        )
        .unwrap();

    //load the updated repo
    let root = root_path();
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    assert_eq!(
        read_to_end(new_repo.read_target("file1.txt").unwrap().unwrap()),
        &b"Updated file1.txt"[..]
    );
}
