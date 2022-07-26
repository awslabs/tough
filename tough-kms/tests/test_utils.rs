// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use aws_sdk_kms::{Client, Config, Credentials};
use aws_smithy_client::erase::DynConnector;
use aws_smithy_client::test_connection::TestConnection;
use aws_smithy_http::body::SdkBody;
use std::path::PathBuf;

/// Returns the path to our test data directory
pub fn test_data() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.join("tough-kms").join("tests").join("data")
}

pub fn mock_client(data_files: Vec<&str>) -> Client {
    let creds = Credentials::new(
        "ATESTCLIENT",
        "atestsecretkey",
        Some("atestsessiontoken".to_string()),
        None,
        "",
    );

    let conf = Config::builder()
        .credentials_provider(creds)
        .region(aws_sdk_kms::Region::new("us-east-1"))
        .build();
    // Get a vec of events based on the given data_files
    let events = data_files
        .iter()
        .map(|d| {
            let path = std::path::Path::new("tests/data").join(d);
            let data = std::fs::read_to_string(path).unwrap();

            // Events
            (
                // Request
                http::Request::builder()
                    .body(SdkBody::from("request body"))
                    .unwrap(),
                // Response
                http::Response::builder()
                    .status(200)
                    .body(SdkBody::from(data))
                    .unwrap(),
            )
        })
        .collect();

    let conn = TestConnection::new(events);
    let conn = DynConnector::new(conn);
    aws_sdk_kms::Client::from_conf_conn(conf, conn)
}

// Create a mock client that returns a specific status code and empty
// response body.
pub fn mock_client_with_status(status: u16) -> Client {
    let creds = Credentials::new(
        "ATESTCLIENT",
        "atestsecretkey",
        Some("atestsessiontoken".to_string()),
        None,
        "",
    );

    let conf = aws_sdk_kms::Config::builder()
        .credentials_provider(creds)
        .region(aws_sdk_kms::Region::new("us-east-1"))
        .build();

    let events = vec![(
        // Request
        http::Request::builder()
            .body(SdkBody::from("request body"))
            .unwrap(),
        // Response
        http::Response::builder()
            .status(status)
            .body("response body")
            .unwrap(),
    )];

    let conn = TestConnection::new(events);
    let conn = DynConnector::new(conn);
    aws_sdk_kms::Client::from_conf_conn(conf, conn)
}
