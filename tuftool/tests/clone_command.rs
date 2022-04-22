mod test_utils;

use assert_cmd::Command;
use std::fs::read_to_string;
use std::path::PathBuf;
use tempfile::TempDir;
use test_utils::{dir_url, test_data};
use url::Url;

struct RepoPaths {
    root_path: PathBuf,
    metadata_base_url: Url,
    targets_base_url: Url,
    metadata_outdir: TempDir,
    targets_outdir: TempDir,
}

impl RepoPaths {
    fn new() -> Self {
        let base = test_data().join("tuf-reference-impl");
        RepoPaths {
            root_path: base.join("metadata").join("1.root.json"),
            metadata_base_url: dir_url(base.join("metadata")),
            targets_base_url: dir_url(base.join("targets")),
            metadata_outdir: TempDir::new().unwrap(),
            targets_outdir: TempDir::new().unwrap(),
        }
    }
}

enum FileType {
    Metadata,
    Target,
}

/// Asserts that a target file is identical to the TUF reference example
fn assert_target_match(indir: &TempDir, filename: &str) {
    assert_reference_file_match(indir, filename, FileType::Target)
}

/// Asserts that a metadata file is identical to the TUF reference example
fn assert_metadata_match(indir: &TempDir, filename: &str) {
    assert_reference_file_match(indir, filename, FileType::Metadata)
}

/// Asserts that the named file in `indir` exactly matches the file in `tuf-reference-impl/`
fn assert_reference_file_match(indir: &TempDir, filename: &str, filetype: FileType) {
    let got = read_to_string(indir.path().join(filename)).unwrap();

    let ref_dir = match filetype {
        FileType::Metadata => "metadata",
        FileType::Target => "targets",
    };
    let reference = read_to_string(
        test_utils::test_data()
            .join("tuf-reference-impl")
            .join(ref_dir)
            .join(filename),
    )
    .unwrap();

    assert_eq!(got, reference, "{} contents do not match.", filename);
}

/// Asserts that all metadata files that should exist do and are identical to the reference example
fn assert_all_metadata(metadata_dir: &TempDir) {
    for f in &[
        "snapshot.json",
        "targets.json",
        "timestamp.json",
        "1.root.json",
        "role1.json",
        "role2.json",
    ] {
        assert_metadata_match(metadata_dir, f)
    }
}

/// Given a `Command`, attach all the base args necessary for the `clone` subcommand
fn clone_base_command<'a>(cmd: &'a mut Command, repo_paths: &RepoPaths) -> &'a mut Command {
    cmd.args(&[
        "clone",
        "--root",
        repo_paths.root_path.to_str().unwrap(),
        "--metadata-url",
        repo_paths.metadata_base_url.as_str(),
        "--metadata-dir",
        repo_paths.metadata_outdir.path().to_str().unwrap(),
    ])
}

#[test]
// Ensure that we successfully clone all metadata
fn clone_metadata() {
    let repo_paths = RepoPaths::new();
    let mut cmd = Command::cargo_bin("tuftool").unwrap();
    clone_base_command(&mut cmd, &repo_paths)
        .args(&["--metadata-only"])
        .assert()
        .success();

    assert_all_metadata(&repo_paths.metadata_outdir)
}

#[test]
// Ensure that target arguments collide with the `--megadata-only` argument
fn clone_metadata_target_args_failure() {
    let repo_paths = RepoPaths::new();
    let mut cmd = Command::cargo_bin("tuftool").unwrap();
    // --target-names
    clone_base_command(&mut cmd, &repo_paths)
        .args(&["--metadata-only", "--target-names", "foo"])
        .assert()
        .failure();

    // --targets-url
    clone_base_command(&mut cmd, &repo_paths)
        .args(&[
            "--metadata-only",
            "--targets-url",
            repo_paths.targets_base_url.as_str(),
        ])
        .assert()
        .failure();

    // --targets-dir
    clone_base_command(&mut cmd, &repo_paths)
        .args(&[
            "--metadata-only",
            "--targets-dir",
            repo_paths.targets_outdir.path().to_str().unwrap(),
        ])
        .assert()
        .failure();

    // all target args
    clone_base_command(&mut cmd, &repo_paths)
        .args(&[
            "--metadata-only",
            "--targets-url",
            repo_paths.targets_base_url.as_str(),
            "--targets-dir",
            repo_paths.targets_outdir.path().to_str().unwrap(),
            "--target-names",
            "foo",
        ])
        .assert()
        .failure();
}

#[test]
// Ensure we can clone a subset of targets
fn clone_subset_targets() {
    let target_name = "file1.txt";
    let repo_paths = RepoPaths::new();
    let mut cmd = Command::cargo_bin("tuftool").unwrap();
    clone_base_command(&mut cmd, &repo_paths)
        .args(&[
            "--targets-url",
            repo_paths.targets_base_url.as_str(),
            "--targets-dir",
            repo_paths.targets_outdir.path().to_str().unwrap(),
            "--target-names",
            target_name,
        ])
        .assert()
        .success();

    assert_all_metadata(&repo_paths.metadata_outdir);
    assert_target_match(&repo_paths.targets_outdir, target_name);

    assert_eq!(
        repo_paths.targets_outdir.path().read_dir().unwrap().count(),
        1
    );
}

#[test]
// Ensure we can clone an entire repo
fn clone_full_repo() {
    let repo_paths = RepoPaths::new();
    let mut cmd = Command::cargo_bin("tuftool").unwrap();
    clone_base_command(&mut cmd, &repo_paths)
        .args(&[
            "--targets-url",
            repo_paths.targets_base_url.as_str(),
            "--targets-dir",
            repo_paths.targets_outdir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_all_metadata(&repo_paths.metadata_outdir);

    for f in &["file1.txt", "file2.txt", "file3.txt"] {
        assert_target_match(&repo_paths.targets_outdir, f)
    }
}
