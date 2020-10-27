mod test_utils;

/// Instead of guarding every individual thing with `#[cfg(feature = "http")]`, use a module.
#[cfg(feature = "http")]
mod http_happy {
    use crate::test_utils::{read_to_end, test_data};
    use mockito::mock;
    use std::fs::File;
    use std::str::FromStr;
    use tough::{
        DefaultTransport, ExpirationEnforcement, HttpTransport, Limits, Repository, Settings,
        Transport,
    };
    use url::Url;

    /// Create a path in a mock HTTP server which serves a file from `tuf-reference-impl`.
    fn create_successful_get_mock(relative_path: &str) -> mockito::Mock {
        let repo_dir = test_data().join("tuf-reference-impl");
        let file_bytes = std::fs::read(&repo_dir.join(relative_path)).unwrap();
        mock("GET", ("/".to_owned() + relative_path).as_str())
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_body(file_bytes.as_slice())
            .expect(1)
            .create()
    }

    /// Test that `tough` works with a healthy HTTP server.
    #[test]
    fn test_http_transport_happy_case() {
        run_http_test(Box::new(HttpTransport::new()));
    }

    /// Test that `DefaultTransport` works over HTTP when the `http` feature is enabled.
    #[test]
    fn test_http_default_transport() {
        run_http_test(Box::new(DefaultTransport::default()));
    }

    fn run_http_test(transport: Box<dyn Transport>) {
        let repo_dir = test_data().join("tuf-reference-impl");
        let mock_timestamp = create_successful_get_mock("metadata/timestamp.json");
        let mock_snapshot = create_successful_get_mock("metadata/snapshot.json");
        let mock_targets = create_successful_get_mock("metadata/targets.json");
        let mock_role1 = create_successful_get_mock("metadata/role1.json");
        let mock_role2 = create_successful_get_mock("metadata/role2.json");
        let mock_file1_txt = create_successful_get_mock("targets/file1.txt");
        let mock_file2_txt = create_successful_get_mock("targets/file2.txt");
        let base_url = Url::from_str(mockito::server_url().as_str()).unwrap();
        let repo = Repository::load(
            transport,
            Settings {
                root: File::open(repo_dir.join("metadata").join("1.root.json")).unwrap(),
                datastore: None,
                metadata_base_url: base_url.join("metadata").unwrap().to_string(),
                targets_base_url: base_url.join("targets").unwrap().to_string(),
                limits: Limits::default(),
                expiration_enforcement: ExpirationEnforcement::Safe,
            },
        )
        .unwrap();

        assert_eq!(
            read_to_end(repo.read_target("file1.txt").unwrap().unwrap()),
            &b"This is an example target file."[..]
        );
        assert_eq!(
            read_to_end(repo.read_target("file2.txt").unwrap().unwrap()),
            &b"This is an another example target file."[..]
        );
        assert_eq!(
            repo.targets()
                .signed
                .targets
                .get("file1.txt")
                .unwrap()
                .custom
                .get("file_permissions")
                .unwrap(),
            "0644"
        );

        mock_timestamp.assert();
        mock_snapshot.assert();
        mock_targets.assert();
        mock_role1.assert();
        mock_role2.assert();
        mock_file1_txt.assert();
        mock_file2_txt.assert();
    }
}

#[cfg(feature = "http")]
#[cfg(feature = "integ")]
mod http_integ {
    use crate::test_utils::test_data;
    use std::fs::File;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use tough::{
        ClientSettings, ExpirationEnforcement, HttpTransport, Limits, Repository, Settings,
    };

    pub fn integ_dir() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.join("integ").canonicalize().unwrap()
    }

    pub fn tuf_reference_impl() -> PathBuf {
        test_data().join("tuf-reference-impl")
    }

    pub fn tuf_reference_impl_metadata() -> PathBuf {
        tuf_reference_impl().join("metadata")
    }

    pub fn tuf_reference_impl_root_json() -> PathBuf {
        tuf_reference_impl_metadata().join("1.root.json")
    }

    /// Test `tough` using faulty HTTP connections.
    ///
    /// This test requires `docker` and should be disabled for PRs because it will not work with our
    /// current CI setup. It works by starting HTTP services in containers which serve the tuf-
    /// reference-impl through fault-ridden HTTP. We load the repo many times in a loop, and
    /// statistically exercise many of the retry code paths. In particular, the server aborts during
    /// the send which exercises the range-header retry in the `Read` loop, and 5XX's are also sent
    /// triggering retries in the `fetch` loop.
    #[test]
    fn test_retries() {
        // run docker images to create a faulty http representation of tuf-reference-impl
        let output = Command::new("bash")
            .arg(
                integ_dir()
                    .join("failure-server")
                    .join("run.sh")
                    .into_os_string(),
            )
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("failed to start server with docker containers");
        if !output.status.success() {
            panic!("Failed to run integration test HTTP servers, is docker running?");
        }

        // load the tuf-reference-impl repo via http repeatedly through faulty proxies
        for i in 0..5 {
            let transport = HttpTransport::from_settings(ClientSettings {
                timeout: std::time::Duration::from_secs(30),
                connect_timeout: std::time::Duration::from_secs(30),
                // the service we have created is very toxic with many failures, so we will do a
                // large number of retries, enough that we can be reasonably assured that we will
                // always succeed.
                tries: 200,
                // we don't want the test to take forever so we use small pauses
                initial_backoff: std::time::Duration::from_nanos(100),
                max_backoff: std::time::Duration::from_millis(1),
                backoff_factor: 1.5,
            });
            let root_path = tuf_reference_impl_root_json();
            Repository::load(
                Box::new(transport),
                Settings {
                    root: File::open(&root_path).unwrap(),
                    datastore: None,
                    metadata_base_url: "http://localhost:10103/metadata".into(),
                    targets_base_url: "http://localhost:10103/targets".into(),
                    limits: Limits::default(),
                    expiration_enforcement: ExpirationEnforcement::Safe,
                },
            )
            .unwrap();
            println!("{}:{} SUCCESSFULLY LOADED THE REPO {}", file!(), line!(), i,);
        }

        // stop and delete the docker containers, images and network
        let output = Command::new("bash")
            .arg(
                integ_dir()
                    .join("failure-server")
                    .join("teardown.sh")
                    .into_os_string(),
            )
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("failed to delete docker objects");
        assert!(output.status.success());
    }
}
