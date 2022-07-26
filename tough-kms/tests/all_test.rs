// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0
mod test_utils;
use ring::rand::SystemRandom;
use serde::{Deserialize, Deserializer};
use std::fs::File;
use std::io::BufReader;
use tough::key_source::KeySource;
use tough::schema::key::Key;
use tough_kms::KmsKeySource;
use tough_kms::KmsSigningAlgorithm::RsassaPssSha256;

/// Deserialize base64 to `bytes::Bytes`
fn de_bytes<'de, D>(deserializer: D) -> Result<bytes::Bytes, D::Error>
where
    D: Deserializer<'de>,
{
    let s = <String>::deserialize(deserializer)?;
    let b = base64::decode(s).unwrap();
    Ok(b.into())
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
struct PublicKeyResp {
    #[serde(rename = "PublicKey")]
    #[serde(deserialize_with = "de_bytes", default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: bytes::Bytes,
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
struct SignResp {
    #[serde(rename = "Signature")]
    #[serde(deserialize_with = "de_bytes", default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: bytes::Bytes,
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
struct CreateKeyResp {
    #[serde(rename = "KeyId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: String,
}

#[test]
// Ensure public key is returned on calling tuf_key
fn check_tuf_key_success() {
    let input = "response_public_key.json";
    let key_id = String::from("alias/some_alias");
    let file = File::open(
        test_utils::test_data()
            .join("expected_public_key.json")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let reader = BufReader::new(file);
    let expected_key: Key = serde_json::from_reader(reader).unwrap();

    let client = test_utils::mock_client(vec![input]);
    let kms_key = KmsKeySource {
        profile: None,
        key_id,
        client: Some(client),
        signing_algorithm: RsassaPssSha256,
    };
    let sign = kms_key.as_sign().unwrap();
    let key = sign.tuf_key();
    assert!(matches!(key, Key::Rsa { .. }));
    assert_eq!(key, expected_key);
}

#[test]
// Ensure message signature is returned on calling sign
fn check_sign_success() {
    let resp_public_key = "response_public_key.json";
    let resp_signature = "response_signature.json";
    let file = File::open(
        test_utils::test_data()
            .join(resp_signature)
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let client = test_utils::mock_client(vec![resp_public_key, resp_signature]);
    let reader = BufReader::new(file);
    let expected_json: SignResp = serde_json::from_reader(reader).unwrap();
    let expected_signature = expected_json.signature.to_vec();
    let kms_key = KmsKeySource {
        profile: None,
        key_id: String::from("alias/some_alias"),
        client: Some(client),
        signing_algorithm: RsassaPssSha256,
    };
    let rng = SystemRandom::new();
    let kms_sign = kms_key.as_sign().unwrap();
    let signature = kms_sign
        .sign("Some message to sign".as_bytes(), &rng)
        .unwrap();
    assert_eq!(signature, expected_signature);
}

#[test]
// Ensure call to tuf_key fails when public key is not available
fn check_public_key_failure() {
    let client = test_utils::mock_client_with_status(501);
    let key_id = String::from("alias/some_alias");
    let kms_key = KmsKeySource {
        profile: None,
        key_id: key_id.clone(),
        client: Some(client),
        signing_algorithm: RsassaPssSha256,
    };
    let result = kms_key.as_sign();
    assert!(result.is_err());
}

#[test]
// Ensure call to as_sign fails when signing algorithms are missing in get_public_key response
fn check_public_key_missing_algo() {
    let input = "response_public_key_no_algo.json";
    let client = test_utils::mock_client(vec![input]);
    let key_id = String::from("alias/some_alias");
    let kms_key = KmsKeySource {
        profile: None,
        key_id,
        client: Some(client),
        signing_algorithm: RsassaPssSha256,
    };
    let err = kms_key.as_sign().err().unwrap();
    assert_eq!(
        String::from(
            "Found public key from AWS KMS, but list of supported signing algorithm is missing"
        ),
        err.to_string()
    );
}

#[test]
// Ensure call to as_sign fails when provided signing algorithm does not match
fn check_public_key_unmatch_algo() {
    let input = "response_public_key_unmatch_algo.json";
    let key_id = String::from("alias/some_alias");
    let client = test_utils::mock_client(vec![input]);
    let kms_key = KmsKeySource {
        profile: None,
        key_id,
        client: Some(client),
        signing_algorithm: RsassaPssSha256,
    };
    let err = kms_key.as_sign().err().unwrap();
    assert_eq!(
        String::from("Please provide valid signing algorithm"),
        err.to_string()
    );
}

#[test]
// Ensure sign error when Kms returns empty signature.
fn check_signature_failure() {
    let resp_public_key = "response_public_key.json";
    let resp_signature = "response_signature_empty.json";
    let key_id = String::from("alias/some_alias");
    let client = test_utils::mock_client(vec![resp_public_key, resp_signature]);
    let kms_key = KmsKeySource {
        profile: None,
        key_id,
        client: Some(client),
        signing_algorithm: RsassaPssSha256,
    };
    let rng = SystemRandom::new();
    let kms_sign = kms_key.as_sign().unwrap();
    let result = kms_sign.sign("Some message to sign".as_bytes(), &rng);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert_eq!(
        format!("Empty signature returned by AWS KMS"),
        err.to_string()
    );
}

#[test]
fn check_write_ok() {
    let key_id = String::from("alias/some_alias");
    let kms_key = KmsKeySource {
        profile: None,
        key_id,
        client: None,
        signing_algorithm: RsassaPssSha256,
    };
    assert!(kms_key.write("", "").is_ok());
}
