use crate::error::{self, Result};
use rusoto_core::{HttpClient, Region};
use rusoto_credential::ProfileProvider;
use rusoto_ssm::SsmClient;
use snafu::ResultExt;
use std::str::FromStr;

/// Builds an SSM client for a given profile name.
pub(crate) fn build_client(profile: Option<&str>) -> Result<SsmClient> {
    Ok(if let Some(profile) = profile {
        let mut provider = ProfileProvider::new().context(error::RusotoCreds)?;
        provider.set_profile(profile);
        let region = provider
            .region_from_profile()
            .context(error::RusotoRegionFromProfile { profile })?;

        SsmClient::new_with(
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
        SsmClient::new(Region::default())
    })
}
