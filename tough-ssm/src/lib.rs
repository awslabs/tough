mod client;
pub mod error;

use rusoto_ssm::Ssm;
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
        let fut = ssm_client.get_parameter(rusoto_ssm::GetParameterRequest {
            name: self.parameter_name.to_owned(),
            with_decryption: Some(true),
        });
        let response = tokio::runtime::Runtime::new()
            .context(error::RuntimeCreation)?
            .block_on(fut)
            .context(error::SsmGetParameter {
                profile: self.profile.clone(),
                parameter_name: &self.parameter_name,
            })?;
        let data = response
            .parameter
            .context(error::SsmMissingField {
                parameter_name: &self.parameter_name,
                field: "parameter",
            })?
            .value
            .context(error::SsmMissingField {
                parameter_name: &self.parameter_name,
                field: "parameter.value",
            })?
            .as_bytes()
            .to_vec();
        let sign = Box::new(parse_keypair(&data).context(error::KeyPairParse)?);
        Ok(sign)
    }

    fn write(
        &self,
        value: &str,
        key_id_hex: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let ssm_client = client::build_client(self.profile.as_deref())?;
        let fut = ssm_client.put_parameter(rusoto_ssm::PutParameterRequest {
            name: self.parameter_name.to_owned(),
            description: Some(key_id_hex.to_owned()),
            key_id: self.key_id.as_ref().cloned(),
            overwrite: Some(true),
            type_: Some("SecureString".to_owned()),
            value: value.to_owned(),
            ..rusoto_ssm::PutParameterRequest::default()
        });
        tokio::runtime::Runtime::new()
            .context(error::RuntimeCreation)?
            .block_on(fut)
            .context(error::SsmPutParameter {
                profile: self.profile.clone(),
                parameter_name: &self.parameter_name,
            })?;
        Ok(())
    }
}
