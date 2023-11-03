mod test_utils;

/// Instead of guarding every individual thing with `#[cfg(feature = "http")]`, use a module.
#[cfg(feature = "http")]
mod http_happy {
    use crate::test_utils::{read_to_end, test_data};
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use std::str::FromStr;
    use tough::{DefaultTransport, HttpTransport, RepositoryLoader, TargetName, Transport};
    use url::Url;

    /// Set an expectation in a test HTTP server which serves a file from `tuf-reference-impl`.
    async fn create_successful_get(relative_path: &str) -> httptest::Expectation {
        let repo_dir = test_data().join("tuf-reference-impl");
        let file_bytes = tokio::fs::read(repo_dir.join(relative_path)).await.unwrap();
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

    /// Test that `tough` works with a healthy HTTP server.
    #[tokio::test]
    async fn test_http_transport_happy_case() {
        run_http_test(HttpTransport::default()).await;
    }

    /// Test that `DefaultTransport` works over HTTP when the `http` feature is enabled.
    #[tokio::test]
    async fn test_http_default_transport() {
        run_http_test(DefaultTransport::default()).await;
    }

    async fn run_http_test<T: Transport + Send + Sync + 'static>(transport: T) {
        let server = Server::run();
        let repo_dir = test_data().join("tuf-reference-impl");
        server.expect(create_successful_get("metadata/timestamp.json").await);
        server.expect(create_successful_get("metadata/snapshot.json").await);
        server.expect(create_successful_get("metadata/targets.json").await);
        server.expect(create_successful_get("metadata/role1.json").await);
        server.expect(create_successful_get("metadata/role2.json").await);
        server.expect(create_successful_get("targets/file1.txt").await);
        server.expect(create_successful_get("targets/file2.txt").await);
        server.expect(create_unsuccessful_get("metadata/2.root.json"));
        let metadata_base_url = Url::from_str(server.url_str("/metadata").as_str()).unwrap();
        let targets_base_url = Url::from_str(server.url_str("/targets").as_str()).unwrap();
        let repo = RepositoryLoader::new(
            &tokio::fs::read(repo_dir.join("metadata").join("1.root.json"))
                .await
                .unwrap(),
            metadata_base_url,
            targets_base_url,
        )
        .transport(transport)
        .load()
        .await
        .unwrap();

        let file1 = TargetName::new("file1.txt").unwrap();
        assert_eq!(
            read_to_end(repo.read_target(&file1).await.unwrap().unwrap()).await,
            &b"This is an example target file."[..]
        );
        let file2 = TargetName::new("file2.txt").unwrap();
        assert_eq!(
            read_to_end(repo.read_target(&file2).await.unwrap().unwrap()).await,
            &b"This is an another example target file."[..]
        );
        assert_eq!(
            repo.targets()
                .signed
                .targets
                .get(&file1)
                .unwrap()
                .custom
                .get("file_permissions")
                .unwrap(),
            "0644"
        );
    }
}

#[cfg(feature = "http")]
#[cfg(feature = "integ")]
mod http_integ {
    use crate::test_utils::test_data;
    use failure_server::IntegServers;
    use std::path::PathBuf;
    use tough::{HttpTransportBuilder, RepositoryLoader};
    use url::Url;

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
    /// This works by starting HTTP services which serve the tuf-reference-impl through fault-ridden
    /// HTTP. We load the repo many times in a loop, and statistically exercise many of the retry
    /// code paths. In particular, the server aborts during the send which exercises the
    /// range-header retry in the `Read` loop, and 5XX's are also sent triggering retries in the
    /// `fetch` loop.
    #[tokio::test]
    async fn test_retries() {
        // create a faulty http representation of tuf-reference-impl
        let tuf_reference_path = tuf_reference_impl();
        let mut integ_servers = IntegServers::new(tuf_reference_path).unwrap();
        integ_servers
            .run()
            .await
            .expect("Failed to run integration test HTTP servers");

        // Load the tuf-reference-impl repo via http repeatedly through faulty proxies.
        for i in 0..5 {
            let transport = HttpTransportBuilder::new()
                // the service we have created is very toxic with many failures, so we will do a
                // large number of retries, enough that we can be reasonably assured that we
                // will always succeed.
                .tries(200)
                // we don't want the test to take forever so we use small pauses
                .initial_backoff(std::time::Duration::from_nanos(100))
                .max_backoff(std::time::Duration::from_millis(1))
                .build();
            let root_path = tuf_reference_impl_root_json();

            RepositoryLoader::new(
                &tokio::fs::read(&root_path).await.unwrap(),
                Url::parse("http://localhost:10102/metadata").unwrap(),
                Url::parse("http://localhost:10102/targets").unwrap(),
            )
            .transport(transport)
            .load()
            .await
            .unwrap();
            println!("{}:{} SUCCESSFULLY LOADED THE REPO {}", file!(), line!(), i,);
        }

        integ_servers
            .teardown()
            .expect("failed to stop HTTP servers");
    }
}
