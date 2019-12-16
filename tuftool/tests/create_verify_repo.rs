use assert_cmd::Command;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tough::{Limits, Repository, Settings};
use url::Url;

fn test_data() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.join("tough").join("tests").join("data")
}

fn dir_url<P: AsRef<Path>>(path: P) -> String {
    Url::from_directory_path(path).unwrap().to_string()
}

fn read_to_end<R: Read>(mut reader: R) -> Vec<u8> {
    let mut v = Vec::new();
    reader.read_to_end(&mut v).unwrap();
    v
}

#[test]
// Ensure we can read a repo created by the `tuftool` binary using the
// `tough` library
fn create_verify_repo() {
    let base = test_data().join("tuf-reference-impl");
    let targets_input_dir = base.join("targets");
    let root_json = base.join("metadata").join("1.root.json");
    let root_key = test_data().join("snakeoil.pem");
    let repo_temp_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    Command::cargo_bin("tuftool")
        .unwrap()
        .args(&[
            "create",
            targets_input_dir.to_str().unwrap(),
            repo_temp_dir.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--targets-expires",
            "in 7 days",
            "--targets-version",
            "1234",
            "--snapshot-expires",
            "in 7 days",
            "--snapshot-version",
            "1234",
            "--timestamp-expires",
            "in 7 days",
            "--timestamp-version",
            "1234",
        ])
        .assert()
        .success();

    // Load our newly created repo
    let metadata_base_url = &dir_url(base.join("metadata"));
    let target_base_url = &dir_url(targets_input_dir);
    let repo = Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: File::open(root_json).unwrap(),
            datastore: repo_temp_dir.as_ref(),
            metadata_base_url,
            target_base_url,
            limits: Limits::default(),
        },
    )
    .unwrap();

    // Ensure we can read the targets
    assert_eq!(
        read_to_end(repo.read_target("file1.txt").unwrap().unwrap()),
        &b"This is an example target file."[..]
    );
    assert_eq!(
        read_to_end(repo.read_target("file2.txt").unwrap().unwrap()),
        &b"This is an another example target file."[..]
    );
}
