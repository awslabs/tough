// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;

use aws_lc_rs::{
    digest::{digest, SHA256},
    signature::{self, UnparsedPublicKey},
};
use cryptoki::{
    mechanism::{
        eddsa::{EddsaParams, EddsaSignatureScheme},
        Mechanism,
    },
    object::{Attribute, AttributeType, ObjectHandle},
    session::Session,
};
use snafu::{OptionExt, ResultExt};
use tough::schema::key::Key;
use tough::schema::key::{EcdsaKey, Ed25519Key};
use tough::schema::key::{EcdsaScheme, Ed25519Scheme};

use crate::error::{self, Result};

const P256_OID_DER: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const ED25519_OID_DER: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];
// Some tokens (e.g. SoftHSM builds) label the curve with the DER
// printable string "edwards25519" rather than the id-Ed25519 OID.
const ED25519_PARAMS_STR: [u8; 14] = [
    0x13, 0x0C, b'e', b'd', b'w', b'a', b'r', b'd', b's', b'2', b'5', b'5', b'1', b'9',
];

fn export_p256(point: &[u8]) -> Result<Key> {
    let sec1 = unwrap_p256_der1_to_sec1(point).context(error::UnexpectedResponseSnafu {
        reason: "failed to parse P256 point",
    })?;

    let parsed = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, sec1)
        .parse()
        .context(error::ParsePubkeySnafu)?;

    Ok(Key::Ecdsa {
        keyval: EcdsaKey {
            public: parsed.as_ref().to_vec().into(),
            _extra: HashMap::new(),
        },
        scheme: EcdsaScheme::EcdsaSha2Nistp256,
        _extra: HashMap::new(),
    })
}

fn export_ed25519(point: &[u8]) -> Result<Key> {
    // TUF/tough stores the bare 32-byte Ed25519 public key (hex-encoded), so
    // there's no SEC1/DER re-encoding to do like there is for P-256.
    let raw = unwrap_ed25519_der_to_raw(point).context(error::UnexpectedResponseSnafu {
        reason: "failed to parse ed25519 point",
    })?;

    Ok(Key::Ed25519 {
        keyval: Ed25519Key {
            public: raw.to_vec().into(),
            _extra: HashMap::new(),
        },
        scheme: Ed25519Scheme::Ed25519,
        _extra: HashMap::new(),
    })
}

pub fn export_pubkey(session: &Session, pubkey: ObjectHandle) -> Result<Key> {
    let attrs = session
        .get_attributes(pubkey, &[AttributeType::EcParams, AttributeType::EcPoint])
        .context(error::GetPubkeySnafu)?;

    let (mut params, mut point) = (None, None);
    for a in attrs {
        match a {
            Attribute::EcParams(v) => params = Some(v),
            Attribute::EcPoint(v) => point = Some(v),
            _ => {}
        }
    }

    let ec_params = params.context(error::UnexpectedResponseSnafu {
        reason: "failed to get EC params",
    })?;
    let point = point.context(error::UnexpectedResponseSnafu {
        reason: "failed to get EC point",
    })?;

    if ec_params == P256_OID_DER {
        export_p256(&point)
    } else if ec_params == ED25519_OID_DER || ec_params == ED25519_PARAMS_STR {
        export_ed25519(&point)
    } else {
        Err(error::Error::UnsupportedKeyType {
            got: format!("EC params {}", super::debug::oid_to_string(&ec_params)),
        })
    }
}

pub fn sign_p256(session: &Session, privkey: ObjectHandle, message: &[u8]) -> Result<Vec<u8>> {
    let hash = digest(&SHA256, message);
    let raw_sig = session
        .sign(&Mechanism::Ecdsa, privkey, hash.as_ref())
        .context(error::SigningFailedSnafu)?;

    // PKCS11 returns "2nLen" signature, or in other words "r || s" values,
    // which we need to convert to DER format
    let signature =
        p256::ecdsa::Signature::from_slice(&raw_sig).map_err(|_| error::Error::InvalidSignature)?;

    Ok(signature.to_der().as_bytes().to_vec())
}

pub fn sign_ed25519(session: &Session, privkey: ObjectHandle, message: &[u8]) -> Result<Vec<u8>> {
    // Ed25519 hashes the message internally, so no need to do it here.
    //
    // PKCS#11 returns the 64-byte raw signature (r || s), which is exactly the
    // encoding TUF/tough expects for ed25519.
    let signature = session
        .sign(
            &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
            privkey,
            message,
        )
        .context(error::SigningFailedSnafu)?;

    Ok(signature)
}

fn unwrap_p256_der1_to_sec1(raw: &[u8]) -> Option<&[u8]> {
    match raw {
        // DER OCTET STRING wrapped
        [0x04, 0x41, rest @ ..] if rest.len() == 65 => Some(rest),
        // already bare SEC1
        [0x04, ..] if raw.len() == 65 => Some(raw),
        _ => None,
    }
}

fn unwrap_ed25519_der_to_raw(raw: &[u8]) -> Option<&[u8]> {
    match raw {
        // DER OCTET STRING wrapped: 0x04 (OCTET STRING) 0x20 (len = 32) || key
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => Some(rest),
        // already the bare 32-byte public key
        _ if raw.len() == 32 => Some(raw),
        _ => None,
    }
}
