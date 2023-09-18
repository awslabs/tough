// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_config::default_provider::region::DefaultRegionChain;
use aws_sdk_kms::Client as KmsClient;

/// Builds a KMS client for a given profile name.
pub(crate) async fn build_client_kms(profile: Option<&str>) -> KmsClient {
    let config = aws_config::from_env();
    let client_config = if let Some(profile) = profile {
        let region = DefaultRegionChain::builder()
            .profile_name(profile)
            .build()
            .region()
            .await;
        let creds = DefaultCredentialsChain::builder()
            .profile_name(profile)
            .region(region.clone())
            .build()
            .await;
        config
            .credentials_provider(creds)
            .region(region)
            .load()
            .await
    } else {
        config.load().await
    };
    KmsClient::new(&client_config)
}
