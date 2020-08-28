// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};
use rusoto_core::{HttpClient, Region};
use rusoto_credential::ProfileProvider;
use rusoto_kms::KmsClient;
use snafu::ResultExt;
use std::str::FromStr;

/// Builds a KMS client for a given profile name.
pub(crate) fn build_client_kms(profile: Option<&str>) -> Result<KmsClient> {
    Ok(if let Some(profile) = profile {
        let mut provider = ProfileProvider::new().context(error::RusotoCreds)?;
        provider.set_profile(profile);
        let region = provider
            .region_from_profile()
            .context(error::RusotoRegionFromProfile { profile })?;

        KmsClient::new_with(
            HttpClient::new().context(error::RusotoTls)?,
            provider,
            match region {
                Some(region) => {
                    Region::from_str(&region).context(error::RusotoRegion { region })?
                }
                None => Region::default(),
            },
        )
    } else {
        KmsClient::new(Region::default())
    })
}
