use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::Client;
use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
use aws_smithy_types::body::SdkBody;
use std::str::FromStr;
use tough::{Transport, TransportErrorKind};
use tough_s3::S3Transport;
use url::Url;

fn mock_s3_client(status: u16, body: &str) -> Client {
    let creds = Credentials::new("TEST", "TEST", Some("TEST".into()), None, "");
    let events = vec![ReplayEvent::new(
        http::Request::builder().body(SdkBody::from("")).unwrap(),
        http::Response::builder()
            .status(status)
            .body(SdkBody::from(body))
            .unwrap(),
    )];
    let conn = StaticReplayClient::new(events);
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::v2025_08_07())
        .credentials_provider(creds)
        .region(Region::new("us-east-1"))
        .http_client(conn)
        .build();
    Client::from_conf(conf)
}

#[tokio::test]
async fn fetch_success() {
    let client = mock_s3_client(200, "test content");
    let transport = S3Transport::new_with_client(client);
    let url = Url::from_str("s3://bucket/key.txt").unwrap();
    let stream = transport.fetch(url).await.unwrap();
    let bytes: Vec<u8> = futures::StreamExt::collect::<Vec<_>>(stream)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .flat_map(|b| b.to_vec())
        .collect();
    assert_eq!(String::from_utf8(bytes).unwrap(), "test content");
}

#[tokio::test]
async fn fetch_invalid_scheme() {
    let client = mock_s3_client(200, "");
    let transport = S3Transport::new_with_client(client);
    let url = Url::from_str("http://bucket/key").unwrap();
    let result = transport.fetch(url).await;
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(matches!(
        err.kind(),
        TransportErrorKind::UnsupportedUrlScheme
    ));
}
