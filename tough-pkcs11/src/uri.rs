use std::{borrow::Cow, path::PathBuf};

use cryptoki::types::AuthPin;
use snafu::{OptionExt, ResultExt};

use crate::{error, KeyId, Pkcs11KeySource, TokenId};

type Result<T> = core::result::Result<T, error::ParseUriError>;

trait PercentDecode<'a> {
    fn percent_decode(self, field: &'static str) -> Result<Cow<'a, str>>;
}

impl<'a> PercentDecode<'a> for &'a str {
    fn percent_decode(self, field: &'static str) -> Result<Cow<'a, str>> {
        percent_encoding::percent_decode_str(self)
            .decode_utf8()
            .map_err(|err| error::ParseUriError::DecodeField {
                field,
                cause: err.to_string(),
            })
    }
}

pub fn parse_key_source(uri: &str) -> Result<Pkcs11KeySource> {
    let uri = pk11_uri_parser::parse(uri).context(error::Pk11UriSnafu)?;
    let module = uri
        .module_path()
        .context(error::RequiresSnafu {
            what: "module-path field",
        })?
        .percent_decode("module-path")?;

    let token = parse_token_id(&uri)?;

    let key = parse_key_id(&uri)?;

    let pin = read_pin(uri.pin_value(), uri.pin_source())?;

    Ok(Pkcs11KeySource {
        module_path: PathBuf::from(module.to_string()),
        token,
        key,
        pin,
    })
}

fn parse_key_id(uri: &pk11_uri_parser::PK11URIMapping<'_>) -> Result<KeyId> {
    let key = match (uri.object(), uri.id()) {
        (Some(s), None) => KeyId::Label(s.percent_decode("object")?.into_owned()),
        (None, Some(s)) => KeyId::Id(percent_encoding::percent_decode_str(s).collect()),
        (None, None) => {
            return Err(error::ParseUriError::Requires {
                what: "key identifier (object= or id=)",
            })
        }
        (Some(_), Some(_)) => {
            return Err(error::ParseUriError::Conflict {
                oneof: "key identifiers (object= OR id=, not both)",
            })
        }
    };
    Ok(key)
}

fn parse_token_id(uri: &pk11_uri_parser::PK11URIMapping<'_>) -> Result<TokenId> {
    let token = match (uri.token(), uri.serial(), uri.slot_id()) {
        (Some(s), None, None) => TokenId::Label(s.percent_decode("token")?.into_owned()),
        (None, Some(s), None) => TokenId::Serial(s.percent_decode("serial")?.into_owned()),
        (None, None, Some(s)) => {
            let id = s
                .parse::<u64>()
                .map_err(|err| error::ParseUriError::DecodeField {
                    cause: err.to_string(),
                    field: "slot-id",
                })?;
            TokenId::SlotId(id)
        }
        (None, None, None) => {
            return Err(error::ParseUriError::Requires {
                what: "token identifier (one of token=, serial=, or slot-id=)",
            });
        }
        _ => {
            return Err(error::ParseUriError::Conflict {
                oneof: "one token identifier (token=, serial=, or slot-id=), but got multiple",
            })
        }
    };
    Ok(token)
}

fn read_pin(pin_value: Option<&str>, pin_source: Option<&str>) -> Result<Option<AuthPin>> {
    if let Some(pin) = pin_value {
        return Ok(Some(pin.percent_decode("pin-value")?.to_string().into()));
    }

    if let Some(pin_source) = pin_source {
        let pin =
            std::fs::read_to_string(pin_source).with_context(|_| error::PinReadingFailedSnafu {
                path: pin_source.to_string(),
            })?;

        Ok(Some(pin.trim().to_string().into()))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyId, TokenId};
    use secrecy::ExposeSecret;
    use std::io::Write;

    #[test]
    fn parses_token_label_and_object_label() {
        let uri = "pkcs11:token=My%20Token;object=my-key\
                    ?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-value=1234";

        let source = parse_key_source(uri).unwrap();

        assert_eq!(
            source.module_path,
            PathBuf::from("/usr/lib/softhsm/libsofthsm2.so")
        );
        assert_eq!(source.token, TokenId::Label("My Token".into()));
        assert_eq!(source.key, KeyId::Label("my-key".into()));
        assert_eq!(source.pin.unwrap().expose_secret(), "1234");
    }

    #[test]
    fn parses_serial_and_percent_encoded_id() {
        let uri = "pkcs11:serial=1234ABCD;id=%DE%AD%BE%EF\
                    ?module-path=/usr/lib/pkcs11.so&pin-value=secret";

        let source = parse_key_source(uri).unwrap();

        assert_eq!(source.token, TokenId::Serial("1234ABCD".into()));
        assert_eq!(source.key, KeyId::Id(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn parses_slot_id_as_number() {
        let uri = "pkcs11:slot-id=42;object=my-key?module-path=/usr/lib/pkcs11.so";

        let source = parse_key_source(uri).unwrap();

        assert!(matches!(source.token, TokenId::SlotId(42)));
        assert!(source.pin.is_none());
    }

    #[test]
    fn reads_pin_from_pin_source_file() {
        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        writeln!(file, "  supersecretpin  ").expect("write pin to temp file");
        let path = file.path().to_str().expect("path is valid utf8");

        let uri = format!(
            "pkcs11:token=Tok;object=my-key?module-path=/usr/lib/pkcs11.so&pin-source={path}"
        );

        let source = parse_key_source(&uri).unwrap();
        assert_eq!(source.pin.unwrap().expose_secret(), "supersecretpin");
    }

    #[test]
    fn module_path_is_percent_decoded() {
        let uri = "pkcs11:token=Tok;object=my-key\
                    ?module-path=/usr/lib/pkcs11%2Dv2.so";
        let source = parse_key_source(uri).unwrap();
        assert_eq!(source.module_path, PathBuf::from("/usr/lib/pkcs11-v2.so"));
    }

    #[test]
    fn missing_module_path_is_an_error() {
        let uri = "pkcs11:token=Tok;object=my-key";
        let err = parse_key_source(uri).expect_err("missing module-path must fail");
        assert!(format!("{err:?}").contains("module-path field"));
    }

    #[test]
    fn missing_token_identifier_is_an_error() {
        let uri = "pkcs11:object=my-key?module-path=/usr/lib/pkcs11.so";
        let err = parse_key_source(uri).expect_err("missing token identifier must fail");
        assert!(format!("{err:?}").contains("token identifier"));
    }

    #[test]
    fn conflicting_token_identifiers_is_an_error() {
        let uri = "pkcs11:token=Tok;serial=1234;object=my-key?module-path=/usr/lib/pkcs11.so";
        let err = parse_key_source(uri).expect_err("conflicting token identifiers must fail");
        assert!(format!("{err:?}").contains("token identifier"));
    }

    #[test]
    fn missing_key_identifier_is_an_error() {
        let uri = "pkcs11:token=Tok?module-path=/usr/lib/pkcs11.so";
        let err = parse_key_source(uri).expect_err("missing key identifier must fail");
        assert!(format!("{err:?}").contains("key identifier"));
    }

    #[test]
    fn conflicting_key_identifiers_is_an_error() {
        let uri = "pkcs11:token=Tok;object=my-key;id=%01%02?module-path=/usr/lib/pkcs11.so";
        let err = parse_key_source(uri).expect_err("conflicting key identifiers must fail");
        assert!(format!("{err:?}").contains("key identifiers"));
    }

    #[test]
    fn invalid_slot_id_is_an_error() {
        let uri = "pkcs11:slot-id=not-a-number;object=my-key\
                    ?module-path=/usr/lib/pkcs11.so";

        let err = parse_key_source(uri).expect_err("non-numeric slot-id must fail");
        assert!(format!("{err:?}").contains("slot-id"));
    }

    #[test]
    fn missing_pin_source_file_is_an_error() {
        let uri = "pkcs11:token=Tok;object=my-key\
                    ?module-path=/usr/lib/pkcs11.so&pin-source=/nonexistent/path/to/pin";
        let err = parse_key_source(uri).expect_err("unreadable pin-source file must fail");
        assert!(format!("{err:?}").contains("/nonexistent/path/to/pin"));
    }
}
