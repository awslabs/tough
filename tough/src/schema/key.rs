#![allow(clippy::use_self)]

//! Handles cryptographic keys and their serialization in TUF metadata files.

use crate::schema::decoded::{Decoded, EcdsaFlex, Hex, RsaPem};
use crate::schema::error::{self, Result};
use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::signature::VerificationAlgorithm;
use olpc_cjson::CanonicalFormatter;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snafu::ResultExt;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Serializes signing keys as defined by the TUF specification. All keys have the format
/// ```json
///  { "keytype" : "KEYTYPE",
///     "scheme" : "SCHEME",
///     "keyval" : "KEYVAL"
///  }
/// ```
/// where:
/// KEYTYPE is a string denoting a public key signature system, such as RSA or ECDSA.
///
/// SCHEME is a string denoting a corresponding signature scheme.  For example: "rsassa-pss-sha256"
/// and "ecdsa-sha2-nistp256".
///
/// KEYVAL is a dictionary containing the public portion of the key:
/// `"keyval" : {"public" : PUBLIC}`
/// where:
///  * `Rsa`: PUBLIC is in PEM format and a string. All RSA keys must be at least 2048 bits.
///  * `Ed25519`: PUBLIC is a 64-byte hex encoded string.
///  * `Ecdsa`: PUBLIC is in PEM format and a string.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "keytype")]
pub enum Key {
    /// An RSA key.
    Rsa {
        /// The RSA key.
        keyval: RsaKey,
        /// Denotes the key's signature scheme.
        scheme: RsaScheme,
        /// Any additional fields read during deserialization; will not be used.
        #[serde(flatten)]
        _extra: HashMap<String, Value>,
    },
    /// An Ed25519 key.
    Ed25519 {
        /// The Ed25519 key.
        keyval: Ed25519Key,
        /// Denotes the key's signature scheme.
        scheme: Ed25519Scheme,
        /// Any additional fields read during deserialization; will not be used.
        #[serde(flatten)]
        _extra: HashMap<String, Value>,
    },
    /// An Ecdsa key.
    Ecdsa {
        /// The Ecdsa key.
        keyval: EcdsaKey,
        /// Denotes the key's signature scheme.
        scheme: EcdsaScheme,
        /// Any additional fields read during deserialization; will not be used.
        #[serde(flatten)]
        _extra: HashMap<String, Value>,
    },
    /// An Ecdsa key with the old key type.
    #[serde(rename = "ecdsa-sha2-nistp256")]
    EcdsaOld {
        /// The Ecdsa key.
        keyval: EcdsaKey,
        /// Denotes the key's signature scheme.
        scheme: EcdsaScheme,
        /// Any additional fields read during deserialization; will not be used.
        #[serde(flatten)]
        _extra: HashMap<String, Value>,
    },
}

/// Used to identify the RSA signature scheme in use.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum RsaScheme {
    /// `rsassa-pss-sha256`: RSA Probabilistic signature scheme with appendix.
    RsassaPssSha256,
}

/// Represents a deserialized (decoded) RSA public key.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct RsaKey {
    /// The public key.
    pub public: Decoded<RsaPem>,

    /// Any additional fields read during deserialization; will not be used.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

/// Used to identify the `EdDSA` signature scheme in use.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Ed25519Scheme {
    /// 'ed25519': Elliptic curve digital signature algorithm based on Twisted Edwards curves.
    Ed25519,
}

/// Represents a deserialized (decoded) Ed25519 public key.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct Ed25519Key {
    /// The public key.
    pub public: Decoded<Hex>,

    /// Any additional fields read during deserialization; will not be used.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

/// Used to identify the ECDSA signature scheme in use.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum EcdsaScheme {
    /// `ecdsa-sha2-nistp256`: Elliptic Curve Digital Signature Algorithm with NIST P-256 curve
    /// signing and SHA-256 hashing.
    EcdsaSha2Nistp256,
}

/// Represents a deserialized (decoded)  Ecdsa public key.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct EcdsaKey {
    /// The public key.
    pub public: Decoded<EcdsaFlex>,

    /// Any additional fields read during deserialization; will not be used.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Key {
    /// Calculate the key ID for this key.
    pub fn key_id(&self) -> Result<KeyId> {
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        self.serialize(&mut ser)
            .context(error::JsonSerializationSnafu {
                what: "key".to_owned(),
            })?;
        Ok(KeyId(hex::encode(digest(&SHA256, &buf))))
    }

    /// Verify a signature of an object made with this key.
    pub(super) fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        let (alg, public_key): (&dyn VerificationAlgorithm, untrusted::Input<'_>) = match self {
            Key::Ecdsa {
                scheme: EcdsaScheme::EcdsaSha2Nistp256,
                keyval,
                ..
            }
            | Key::EcdsaOld {
                scheme: EcdsaScheme::EcdsaSha2Nistp256,
                keyval,
                ..
            } => (
                &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
                untrusted::Input::from(&keyval.public),
            ),
            Key::Ed25519 {
                scheme: Ed25519Scheme::Ed25519,
                keyval,
                ..
            } => (
                &aws_lc_rs::signature::ED25519,
                untrusted::Input::from(&keyval.public),
            ),
            Key::Rsa {
                scheme: RsaScheme::RsassaPssSha256,
                keyval,
                ..
            } => (
                &aws_lc_rs::signature::RSA_PSS_2048_8192_SHA256,
                untrusted::Input::from(&keyval.public),
            ),
        };

        alg.verify_sig(public_key.as_slice_less_safe(), msg, signature)
            .is_ok()
    }

    /// Return the underlying key material, without any attached metadata. This is meant to be used
    /// to check whether two keys point to the same underlying key material: it doesn't contain any
    /// arbitrary metadata.
    pub(super) fn material(&self) -> KeyMaterial {
        // It's intentional that we explicitly match over every field of the struct (and nested
        // structs too). Whenever a new field is added we want a compiler error to be triggered
        // here, to evaluate whether the new field needs to be added to the key material.
        match self.clone() {
            Key::Rsa {
                keyval: RsaKey { public, _extra: _ },
                scheme,
                _extra: _,
            } => KeyMaterial::Rsa { scheme, public },

            Key::Ed25519 {
                keyval: Ed25519Key { public, _extra: _ },
                scheme,
                _extra: _,
            } => KeyMaterial::Ed25519 { scheme, public },

            Key::Ecdsa {
                keyval: EcdsaKey { public, _extra: _ },
                scheme,
                _extra: _,
            }
            | Key::EcdsaOld {
                keyval: EcdsaKey { public, _extra: _ },
                scheme,
                _extra: _,
            } => KeyMaterial::Ecdsa { scheme, public },
        }
    }
}

impl FromStr for Key {
    type Err = KeyParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(public) = serde_plain::from_str::<Decoded<RsaPem>>(s) {
            Ok(Key::Rsa {
                keyval: RsaKey {
                    public,
                    _extra: HashMap::new(),
                },
                scheme: RsaScheme::RsassaPssSha256,
                _extra: HashMap::new(),
            })
        } else if let Ok(public) = serde_plain::from_str::<Decoded<Hex>>(s) {
            if public.len() == aws_lc_rs::signature::ED25519_PUBLIC_KEY_LEN {
                Ok(Key::Ed25519 {
                    keyval: Ed25519Key {
                        public,
                        _extra: HashMap::new(),
                    },
                    scheme: Ed25519Scheme::Ed25519,
                    _extra: HashMap::new(),
                })
            } else {
                Err(KeyParseError(()))
            }
        } else if let Ok(public) = serde_plain::from_str::<Decoded<EcdsaFlex>>(s) {
            Ok(Key::Ecdsa {
                keyval: EcdsaKey {
                    public,
                    _extra: HashMap::new(),
                },
                scheme: EcdsaScheme::EcdsaSha2Nistp256,
                _extra: HashMap::new(),
            })
        } else {
            Err(KeyParseError(()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum KeyMaterial {
    Rsa {
        scheme: RsaScheme,
        public: Decoded<RsaPem>,
    },
    Ed25519 {
        scheme: Ed25519Scheme,
        public: Decoded<Hex>,
    },
    Ecdsa {
        scheme: EcdsaScheme,
        public: Decoded<EcdsaFlex>,
    },
}

/// Unique identifier representing a key.
///
/// TUF version 1.0.0 (section 4.2) mandates that KEYID must be hexdigest of the SHA-256 hash of
/// the canonical JSON form of the key. TAP 12 changes the definition to allow arbitrary strings to
/// be key IDs.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct KeyId(String);

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <String as std::fmt::Display>::fmt(&self.0, f)
    }
}

impl std::str::FromStr for KeyId {
    type Err = KeyParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(KeyId(s.into()))
    }
}

/// An error object to be used when a key cannot be parsed.
#[derive(Debug, Clone, Copy)]
pub struct KeyParseError(());

impl fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unrecognized or invalid public key")
    }
}

impl std::error::Error for KeyParseError {}
