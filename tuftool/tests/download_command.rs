mod test_utils;

use assert_cmd::Command;
use mockito::mock;
use std::fs::{read_to_string, OpenOptions};
use std::io::Write;
use std::str::FromStr;
use tempfile::TempDir;
use url::Url;

/// Create a path in a mock HTTP server which serves a file from `tuf-reference-impl`.
fn create_successful_get_mock(relative_path: &str) -> mockito::Mock {
    let repo_dir = test_utils::test_data().join("tuf-reference-impl");
    let file_bytes = std::fs::read(&repo_dir.join(relative_path)).unwrap();
    mock("GET", ("/".to_owned() + relative_path).as_str())
        .with_status(200)
        .with_header("content-type", "application/octet-stream")
        .with_body(file_bytes.as_slice())
        .create()
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

fn download_command(metadata_base_url: String, targets_base_url: String) {
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
            "--target-url",
            targets_base_url.as_str(),
            outdir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Assert the files are exactly correct
    assert_file_match(&outdir, "file1.txt");
    assert_file_match(&outdir, "file2.txt");
    // TODO - assert_file_match(&outdir, "file3.txt"); when delegate support lands.

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
            "--target-url",
            targets_base_url.as_str(),
            outdir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Assert the files are exactly correct
    assert_file_match(&outdir, "file1.txt");
    assert_file_match(&outdir, "file2.txt");
    // TODO - assert_file_match(&outdir, "file3.txt"); when delegate support lands.
}

#[test]
// Ensure that the download command works with http url, and that we truncate files when downloading into a non-
// empty directory (i.e. that issue #173 is fixed).
fn download_command_truncates_http() {
    // let repo_dir = utl::test_data().join("tuf-reference-impl");
    let _role_1 = create_successful_get_mock("metadata/role1.json");
    let _role_2 = create_successful_get_mock("metadata/role2.json");
    let _snapshot = create_successful_get_mock("metadata/snapshot.json");
    let _targets = create_successful_get_mock("metadata/targets.json");
    let _timestamp = create_successful_get_mock("metadata/timestamp.json");
    let _file1 = create_successful_get_mock("targets/file1.txt");
    let _file2 = create_successful_get_mock("targets/file2.txt");
    let _file3 = create_successful_get_mock("targets/file3.txt");
    let base_url = Url::from_str(mockito::server_url().as_str()).unwrap();
    base_url.join("metadata").unwrap().to_string();
    let metadata_base_url = base_url.join("metadata").unwrap().to_string();
    let targets_base_url = base_url.join("targets").unwrap().to_string();
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
