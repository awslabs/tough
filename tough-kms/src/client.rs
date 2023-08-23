// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};
use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_config::default_provider::region::DefaultRegionChain;
use aws_sdk_kms::Client as KmsClient;
use snafu::ResultExt;
use std::thread;

/// Builds a KMS client for a given profile name.
pub(crate) fn build_client_kms(profile: Option<&str>) -> Result<KmsClient> {
    // We are cloning this so that we can send it across a thread boundary
    let profile = profile.map(std::borrow::ToOwned::to_owned);
    // We need to spin up a new thread to deal with the async nature of the
    // AWS SDK Rust
    let client: Result<KmsClient> = thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().context(error::RuntimeCreationSnafu)?;
        Ok(runtime.block_on(async_build_client_kms(profile)))
    })
    .join()
    .map_err(|_| error::Error::ThreadJoin {})?;
    client
}

async fn async_build_client_kms(profile: Option<String>) -> KmsClient {
    let config = aws_config::from_env();
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
    KmsClient::new(&client_config)
}
