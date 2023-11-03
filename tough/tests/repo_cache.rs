// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;
use tempfile::TempDir;
use test_utils::{dir_url, read_to_end, test_data, DATA_1, DATA_2};
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

async fn load_tuf_reference_impl(paths: &RepoPaths) -> Repository {
    RepositoryLoader::new(
        &paths.root().await,
        paths.metadata_base_url.clone(),
        paths.targets_base_url.clone(),
    )
    .load()
    .await
    .unwrap()
}

/// Test that the repo.cache() function works when given a list of multiple targets.
#[tokio::test]
async fn test_repo_cache_all_targets() {
    // load the reference_impl repo
    let repo_paths = RepoPaths::new();
    let repo = load_tuf_reference_impl(&repo_paths).await;

    // cache the repo for future use
    let destination = TempDir::new().unwrap();
    let metadata_destination = destination.as_ref().join("metadata");
    let targets_destination = destination.as_ref().join("targets");
    repo.cache(
        &metadata_destination,
        &targets_destination,
        None::<&[&str]>,
        true,
    )
    .await
    .unwrap();

    // check that we can load the copied repo.
    let copied_repo = RepositoryLoader::new(
        &repo_paths.root().await,
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    // the copied repo should have file1 and file2 (i.e. all of targets).
    let file1 = TargetName::new("file1.txt").unwrap();
    let file_data = read_to_end(copied_repo.read_target(&file1).await.unwrap().unwrap()).await;
    assert_eq!(31, file_data.len());

    let file2 = TargetName::new("file2.txt").unwrap();
    let file_data = read_to_end(copied_repo.read_target(&file2).await.unwrap().unwrap()).await;
    assert_eq!(39, file_data.len());
}

/// Test that the repo.cache() function works when given a list of multiple targets.
#[tokio::test]
async fn test_repo_cache_list_of_two_targets() {
    // load the reference_impl repo
    let repo_paths = RepoPaths::new();
    let repo = load_tuf_reference_impl(&repo_paths).await;

    // cache the repo for future use
    let destination = TempDir::new().unwrap();
    let metadata_destination = destination.as_ref().join("metadata");
    let targets_destination = destination.as_ref().join("targets");
    let targets_subset = vec!["file1.txt".to_string(), "file2.txt".to_string()];
    repo.cache(
        &metadata_destination,
        &targets_destination,
        Some(&targets_subset),
        true,
    )
    .await
    .unwrap();

    // check that we can load the copied repo.
    let copied_repo = RepositoryLoader::new(
        &repo_paths.root().await,
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    // the copied repo should have file1 and file2 (i.e. all of the listed targets).
    let file1 = TargetName::new("file1.txt").unwrap();
    let file_data = read_to_end(copied_repo.read_target(&file1).await.unwrap().unwrap()).await;
    assert_eq!(31, file_data.len());

    let file2 = TargetName::new("file2.txt").unwrap();
    let file_data = read_to_end(copied_repo.read_target(&file2).await.unwrap().unwrap()).await;
    assert_eq!(39, file_data.len());
}

/// Test that the repo.cache() function works when given a list of only one of the targets.
#[tokio::test]
async fn test_repo_cache_some() {
    // load the reference_impl repo
    let repo_paths = RepoPaths::new();
    let repo = load_tuf_reference_impl(&repo_paths).await;

    // cache the repo for future use
    let destination = TempDir::new().unwrap();
    let metadata_destination = destination.as_ref().join("metadata");
    let targets_destination = destination.as_ref().join("targets");
    let targets_subset = vec!["file2.txt".to_string()];
    repo.cache(
        &metadata_destination,
        &targets_destination,
        Some(&targets_subset),
        true,
    )
    .await
    .unwrap();

    // check that we can load the copied repo.
    let copied_repo = RepositoryLoader::new(
        &repo_paths.root().await,
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    // the copied repo should have file2 but not file1 (i.e. only the listed targets).
    let file1 = TargetName::new("file1.txt").unwrap();
    let read_target_result = copied_repo.read_target(&file1).await;
    assert!(read_target_result.is_err());

    let file2 = TargetName::new("file2.txt").unwrap();
    let file_data = read_to_end(copied_repo.read_target(&file2).await.unwrap().unwrap()).await;
    assert_eq!(39, file_data.len());
}

#[tokio::test]
async fn test_repo_cache_metadata() {
    // Load the reference_impl repo
    let repo_paths = RepoPaths::new();
    let repo = load_tuf_reference_impl(&repo_paths).await;

    // Cache the repo for future use
    let destination = TempDir::new().unwrap();
    let metadata_destination = destination.as_ref().join("metadata");
    repo.cache_metadata(&metadata_destination, true)
        .await
        .unwrap();

    // Load the copied repo - this validates we cached the metadata (if we didn't we couldn't load
    // the repo)
    let targets_destination = destination.as_ref().join("targets");
    let copied_repo = RepositoryLoader::new(
        &repo_paths.root().await,
        dir_url(&metadata_destination),
        dir_url(targets_destination),
    )
    .load()
    .await
    .unwrap();

    // Validate we didn't cache any targets
    for (target_name, _) in copied_repo.targets().signed.targets_map() {
        assert!(copied_repo.read_target(&target_name).await.is_err())
    }

    // Verify we also loaded the delegated role "role1"
    let read_delegated_role_option = copied_repo.delegated_role("role1");
    assert!(read_delegated_role_option.is_some());

    // Verify we cached the root.json
    assert!(metadata_destination.join("1.root.json").exists());
}

#[tokio::test]
async fn test_repo_cache_metadata_no_root_chain() {
    // Load the reference_impl repo
    let repo_paths = RepoPaths::new();
    let repo = load_tuf_reference_impl(&repo_paths).await;

    // Cache the repo for future use
    let destination = TempDir::new().unwrap();
    let metadata_destination = destination.as_ref().join("metadata");
    repo.cache_metadata(&metadata_destination, false)
        .await
        .unwrap();

    // Verify we did not cache the root.json
    assert!(!metadata_destination.join("1.root.json").exists());
}

/// Test that the repo.cache() function prepends target names with sha digest.
#[tokio::test]
async fn test_repo_cache_consistent_snapshots() {
    let repo_name = "consistent-snapshots";
    let metadata_dir = test_data().join(repo_name).join("metadata");
    let targets_dir = test_data().join(repo_name).join("targets");
    let root = metadata_dir.join("1.root.json");
    let repo = RepositoryLoader::new(
        &tokio::fs::read(&root).await.unwrap(),
        dir_url(metadata_dir),
        dir_url(targets_dir),
    )
    .load()
    .await
    .unwrap();

    // cache the repo for future use
    let destination = TempDir::new().unwrap();
    let metadata_destination = destination.as_ref().join("metadata");
    let targets_destination = destination.as_ref().join("targets");
    // let targets_subset = vec!["file2.txt".to_string()];
    repo.cache(
        &metadata_destination,
        &targets_destination,
        Option::<&[&str]>::None,
        true,
    )
    .await
    .unwrap();

    // check that we can load the copied repo.
    let copied_repo = RepositoryLoader::new(
        &tokio::fs::read(&root).await.unwrap(),
        dir_url(&metadata_destination),
        dir_url(&targets_destination),
    )
    .load()
    .await
    .unwrap();

    // the copied repo should have file2 but not file1 (i.e. only the listed targets).
    let data1 = String::from_utf8(
        read_to_end(
            copied_repo
                .read_target(&TargetName::new("data1.txt").unwrap())
                .await
                .unwrap()
                .unwrap(),
        )
        .await,
    )
    .unwrap();
    assert_eq!(data1, DATA_1);

    let data2 = String::from_utf8(
        read_to_end(
            copied_repo
                .read_target(&TargetName::new("data2.txt").unwrap())
                .await
                .unwrap()
                .unwrap(),
        )
        .await,
    )
    .unwrap();
    assert_eq!(data2, DATA_2);

    // assert that the target has its digest prepended
    let expected_filepath = targets_destination
        .join("5aa1d2b3bea034a0f9d0b27a1bc72919b3145a2b092b72ac0415a05e07e2bdd1.data1.txt");
    assert!(expected_filepath.is_file())
}
