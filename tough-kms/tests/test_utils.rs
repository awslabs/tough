// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use aws_sdk_kms::config::{Credentials, Region};
use aws_sdk_kms::{Client, Config};
use aws_smithy_runtime::client::http::test_util::{ReplayEvent, StaticReplayClient};
use aws_smithy_types::body::SdkBody;
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

    // Get a vec of events based on the given data_files
    let events = data_files
        .iter()
        .map(|d| {
            let path = std::path::Path::new("tests/data").join(d);
            let data = std::fs::read_to_string(path).unwrap();

            // Events
            ReplayEvent::new(
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

    let conn = StaticReplayClient::new(events);

    let conf = Config::builder()
        .credentials_provider(creds)
        .region(Region::new("us-east-1"))
        .http_client(conn)
        .build();

    aws_sdk_kms::Client::from_conf(conf)
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

    let events = vec![ReplayEvent::new(
        // Request
        http::Request::builder()
            .body(SdkBody::from("request body"))
            .unwrap(),
        // Response
        http::Response::builder()
            .status(status)
            .body(SdkBody::from("response body"))
            .unwrap(),
    )];

    let conn = StaticReplayClient::new(events);

    let conf = aws_sdk_kms::Config::builder()
        .credentials_provider(creds)
        .region(Region::new("us-east-1"))
        .http_client(conn)
        .build();

    aws_sdk_kms::Client::from_conf(conf)
}
