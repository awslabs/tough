mod test_utils;

use assert_cmd::assert::Assert;
use assert_cmd::Command;
use httptest::{matchers::*, responders::*, Expectation, Server};
use std::fs::read_to_string;
use std::path::Path;
use std::str::FromStr;
use tempfile::TempDir;
use url::Url;

/// Set an expectation in a test HTTP server which serves a file from `tuf-reference-impl`.
fn create_successful_get(relative_path: &str) -> httptest::Expectation {
    let repo_dir = test_utils::test_data().join("tuf-reference-impl");
    let file_bytes = std::fs::read(&repo_dir.join(relative_path)).unwrap();
    Expectation::matching(request::method_path("GET", format!("/{}", relative_path)))
        .times(1)
        .respond_with(
            status_code(200)
                .append_header("content-type", "application/octet-stream")
                .body(file_bytes),
        )
}

/// Set an expectation in a test HTTP server to return a `403 Forbidden` status code.
/// This is necessary for objects like `x.root.json` as tough will continue to increment
/// `x.root.json` until it receives either `403 Forbidden` or `404 NotFound`.
/// S3 returns `403 Forbidden` when requesting a file that does not exist.
fn create_unsuccessful_get(relative_path: &str) -> httptest::Expectation {
    Expectation::matching(request::method_path("GET", format!("/{}", relative_path)))
        .times(1)
        .respond_with(status_code(403))
}

/// Asserts that the named file in `outdir` exactly matches the file in `tuf-reference-impl/targets`
fn assert_file_match(outdir: &Path, filename: &str) {
    let got = read_to_string(outdir.join(filename)).unwrap();
    let want = read_to_string(
        test_utils::test_data()
            .join("tuf-reference-impl")
            .join("targets")
            .join(filename),
    )
    .unwrap();
    assert_eq!(got, want, "{} contents do not match.", filename);
}

fn download_command(metadata_base_url: Url, targets_base_url: Url) {
    let tempdir = TempDir::new().unwrap();
    let outdir = tempdir.path().join("outdir");
    let root_json = test_utils::test_data()
        .join("tuf-reference-impl")
        .join("metadata")
        .join("root.json");

    // Download a test repo.
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "download",
            "-r",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "--targets-url",
            targets_base_url.as_str(),
            outdir.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Assert the files are exactly correct
    assert_file_match(&outdir, "file1.txt");
    assert_file_match(&outdir, "file2.txt");

    // Download again into the same outdir, this will fail because the directory exists.
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "download",
            "-r",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "--targets-url",
            targets_base_url.as_str(),
            outdir.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
// Ensure that the download command works with http transport and that we require outdir to
// not-exist.
fn download_http_transport() {
    let server = Server::run();
    server.expect(create_successful_get("metadata/role1.json"));
    server.expect(create_successful_get("metadata/role2.json"));
    server.expect(create_successful_get("metadata/snapshot.json"));
    server.expect(create_successful_get("metadata/targets.json"));
    server.expect(create_successful_get("metadata/timestamp.json"));
    server.expect(create_successful_get("targets/file1.txt"));
    server.expect(create_successful_get("targets/file2.txt"));
    server.expect(create_unsuccessful_get("metadata/2.root.json"));
    let metadata_base_url = Url::from_str(server.url_str("/metadata").as_str()).unwrap();
    let targets_base_url = Url::from_str(server.url_str("/targets").as_str()).unwrap();
    download_command(metadata_base_url, targets_base_url);
}

#[test]
// Ensure that the download command works with file transport, and that we require outdir to
// not-exist.
fn download_file_transport() {
    let repo_dir = test_utils::test_data().join("tuf-reference-impl");
    let metadata_base_url = test_utils::dir_url(repo_dir.join("metadata").to_str().unwrap());
    let targets_base_url = test_utils::dir_url(repo_dir.join("targets").to_str().unwrap());
    download_command(metadata_base_url, targets_base_url);
}

fn download_expired_repo(outdir: &Path, repo_dir: &TempDir, allow_expired_repo: bool) -> Assert {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let metadata_base_url = &test_utils::dir_url(repo_dir.path().join("metadata"));
    let targets_base_url = &test_utils::dir_url(repo_dir.path().join("targets"));
    let mut cmd = Command::cargo_bin("tuftool").unwrap();
    cmd.args(&[
        "download",
        "-r",
        root_json.to_str().unwrap(),
        "--metadata-url",
        metadata_base_url.as_str(),
        "--targets-url",
        targets_base_url.as_str(),
        outdir.to_str().unwrap(),
    ]);
    if allow_expired_repo {
        cmd.arg("--allow-expired-repo").assert()
    } else {
        cmd.assert()
    }
}

#[test]
// Ensure download command fails when metadata has expired
fn download_command_expired_repo_fail() {
    let outdir = TempDir::new().unwrap();
    let repo_dir = TempDir::new().unwrap();
    // Create a expired repo using tuftool
    test_utils::create_expired_repo(repo_dir.path());
    // assert failure for download command
    download_expired_repo(outdir.path(), &repo_dir, false).failure();
}

#[test]
// Ensure download command is successful when metadata has expired but --allow-expired-repo flag is passed
fn download_command_expired_repo_allow() {
    let tempdir = TempDir::new().unwrap();
    let outdir = tempdir.path().join("outdir");
    let repo_dir = TempDir::new().unwrap();
    // Create a expired repo using tuftool
    test_utils::create_expired_repo(repo_dir.path());
    // assert success for download command
    download_expired_repo(&outdir, &repo_dir, true).success();
    // Assert the files are exactly correct
    assert_file_match(&outdir, "file1.txt");
    assert_file_match(&outdir, "file2.txt");
}

#[test]
// Ensure that we handle path-like target names correctly.
fn download_safe_target_paths() {
    let repo_dir = test_utils::test_data().join("safe-target-paths");
    let root = repo_dir.join("metadata").join("1.root.json");
    let metadata_base_url = &test_utils::dir_url(repo_dir.join("metadata"));
    let targets_base_url = &test_utils::dir_url(repo_dir.join("targets"));
    let tempdir = TempDir::new().unwrap();
    let outdir = tempdir.path().join("outdir");
    let mut cmd = Command::cargo_bin("tuftool").unwrap();
    cmd.args(&[
        "download",
        "-r",
        root.to_str().unwrap(),
        "--metadata-url",
        metadata_base_url.as_str(),
        "--targets-url",
        targets_base_url.as_str(),
        outdir.to_str().unwrap(),
    ]);
    cmd.assert().success();
    assert!(outdir.join("data1.txt").is_file());
    assert!(outdir.join("foo/bar/data2.txt").is_file())
}
