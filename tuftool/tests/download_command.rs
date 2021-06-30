mod test_utils;

use assert_cmd::assert::Assert;
use assert_cmd::Command;
use httptest::{matchers::*, responders::*, Expectation, Server};
use std::fs::{read_to_string, OpenOptions};
use std::io::Write;
use std::str::FromStr;
use tempfile::TempDir;
use url::Url;

/// Set an expectation in a test HTTP server which serves a file from `tuf-reference-impl`.
fn create_successful_get(relative_path: &str) -> httptest::Expectation {
    let repo_dir = test_utils::test_data().join("tuf-reference-impl");
    let file_bytes = std::fs::read(&repo_dir.join(relative_path)).unwrap();
    Expectation::matching(request::method_path("GET", format!("/{}", relative_path)))
        .times(2)
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
        .times(2)
        .respond_with(status_code(403))
}

/// Asserts that the named file in `outdir` exactly matches the file in `tuf-reference-impl/targets`
fn assert_file_match(outdir: &TempDir, filename: &str) {
    let got = read_to_string(outdir.path().join(filename)).unwrap();
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
    let outdir = TempDir::new().unwrap();
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
            outdir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Assert the files are exactly correct
    assert_file_match(&outdir, "file1.txt");
    assert_file_match(&outdir, "file2.txt");

    // Add "bloop" to the end of file1.txt so that we can prove that the file is truncated when we
    // download the repo a second time into the same outdir.
    let mut f = OpenOptions::write(&mut OpenOptions::new(), true)
        .append(true)
        .open(outdir.path().join("file1.txt"))
        .unwrap();
    writeln!(f, "bloop").unwrap();

    // Download again into the same outdir
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
            outdir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Assert the files are exactly correct
    assert_file_match(&outdir, "file1.txt");
    assert_file_match(&outdir, "file2.txt");
}

#[test]
// Ensure that the download command works with http url, and that we truncate files when downloading into a non-
// empty directory (i.e. that issue #173 is fixed).
fn download_command_truncates_http() {
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
// Ensure that the download command works with file url, and that we truncate files when downloading into a non-
// empty directory (i.e. that issue #173 is fixed).
fn download_command_truncates_file() {
    let repo_dir = test_utils::test_data().join("tuf-reference-impl");
    let metadata_base_url = test_utils::dir_url(repo_dir.join("metadata").to_str().unwrap());
    let targets_base_url = test_utils::dir_url(repo_dir.join("targets").to_str().unwrap());
    download_command(metadata_base_url, targets_base_url);
}

fn download_expired_repo(outdir: &TempDir, repo_dir: &TempDir, allow_expired_repo: bool) -> Assert {
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
        outdir.path().to_str().unwrap(),
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
    download_expired_repo(&outdir, &repo_dir, false).failure();
}

#[test]
// Ensure download command is successful when metadata has expired but --allow-expired-repo flag is passed
fn download_command_expired_repo_allow() {
    let outdir = TempDir::new().unwrap();
    let repo_dir = TempDir::new().unwrap();
    // Create a expired repo using tuftool
    test_utils::create_expired_repo(repo_dir.path());
    // assert success for download command
    download_expired_repo(&outdir, &repo_dir, true).success();
    // Assert the files are exactly correct
    assert_file_match(&outdir, "file1.txt");
    assert_file_match(&outdir, "file2.txt");
}
