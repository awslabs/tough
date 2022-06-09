// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod client;
pub mod error;

use snafu::{OptionExt, ResultExt};
use tough::key_source::KeySource;
use tough::sign::{parse_keypair, Sign};

/// Implements the KeySource trait for keys that live in AWS SSM.
#[derive(Debug)]
pub struct SsmKeySource {
    pub profile: Option<String>,
    pub parameter_name: String,
    pub key_id: Option<String>,
}

/// Implements the KeySource trait.
impl KeySource for SsmKeySource {
    fn as_sign(
        &self,
    ) -> std::result::Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        let ssm_client = client::build_client(self.profile.as_deref())?;
        let fut = ssm_client
            .get_parameter()
            .name(self.parameter_name.to_owned())
            .with_decryption(true)
            .send();
        let response = tokio::runtime::Runtime::new()
            .context(error::RuntimeCreationSnafu)?
            .block_on(fut)
            .context(error::SsmGetParameterSnafu {
                profile: self.profile.clone(),
                parameter_name: &self.parameter_name,
            })?;
        let data = response
            .parameter
            .context(error::SsmMissingFieldSnafu {
                parameter_name: &self.parameter_name,
                field: "parameter",
            })?
            .value
            .context(error::SsmMissingFieldSnafu {
                parameter_name: &self.parameter_name,
                field: "parameter.value",
            })?
            .as_bytes()
            .to_vec();
        let sign = Box::new(parse_keypair(&data).context(error::KeyPairParseSnafu)?);
        Ok(sign)
    }

    fn write(
        &self,
        value: &str,
        key_id_hex: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let ssm_client = client::build_client(self.profile.as_deref())?;

        let fut = ssm_client
            .put_parameter()
            .name(self.parameter_name.to_owned())
            .description(key_id_hex.to_owned())
            .set_key_id(self.key_id.as_ref().cloned())
            .overwrite(true)
            .set_type(Some(aws_sdk_ssm::model::ParameterType::SecureString))
            .value(value.to_owned())
            .send();

        tokio::runtime::Runtime::new()
            .context(error::RuntimeCreationSnafu)?
            .block_on(fut)
            .context(error::SsmPutParameterSnafu {
                profile: self.profile.clone(),
                parameter_name: &self.parameter_name,
            })?;
        Ok(())
    }
}
