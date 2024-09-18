// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_config::default_provider::region::DefaultRegionChain;
use aws_config::BehaviorVersion;
use aws_sdk_ssm::Client as SsmClient;
use aws_smithy_experimental::hyper_1_0::{CryptoMode, HyperClientBuilder};
use snafu::ResultExt;
use std::thread;

use crate::error::{self, Result};

/// Builds an SSM client for a given profile name.
pub(crate) fn build_client(profile: Option<&str>) -> Result<SsmClient> {
    // We are cloning this so that we can send it across a thread boundary
    let profile = profile.map(|s| s.to_owned());
    // We need to spin up a new thread to deal with the async nature of the
    // AWS SDK Rust
    let client: Result<SsmClient> = thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().context(error::RuntimeCreationSnafu)?;
        Ok(runtime.block_on(async_build_client(profile)))
    })
    .join()
    .map_err(|_| error::Error::ThreadJoin {})?;
    client
}

async fn async_build_client(profile: Option<String>) -> SsmClient {
    let http_client = HyperClientBuilder::new()
        .crypto_mode(CryptoMode::AwsLc) // Choose a crypto provider.
        .build_https();
    let config = aws_config::defaults(BehaviorVersion::v2024_03_28()).http_client(http_client);
    let client_config = if let Some(profile) = profile {
        let region = DefaultRegionChain::builder()
            .profile_name(&profile)
            .build()
            .region()
            .await;
        let creds = DefaultCredentialsChain::builder()
            .profile_name(&profile)
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
    SsmClient::new(&client_config)
}
