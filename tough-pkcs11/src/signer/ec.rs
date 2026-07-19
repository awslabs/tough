// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;

use aws_lc_rs::{
    digest::{digest, SHA256},
    signature::{self, UnparsedPublicKey},
};
use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectHandle},
    session::Session,
};
use snafu::{ensure, OptionExt, ResultExt};
use tough::schema::key::EcdsaKey;
use tough::schema::key::EcdsaScheme;
use tough::schema::key::Key;

use crate::error::{self, Result};

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

    const P256_OID_DER: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // TODO: add more info to the error
    let ec_params = params.context(error::UnexpectedResponseSnafu)?;
    let point = point.context(error::UnexpectedResponseSnafu)?;

    ensure!(ec_params == P256_OID_DER, error::UnsupportedKeyTypeSnafu);
    let sec1 = unwrap_p256_der1_to_sec1(&point).context(error::UnexpectedResponseSnafu)?;

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

fn unwrap_p256_der1_to_sec1(raw: &[u8]) -> Option<&[u8]> {
    match raw {
        // DER OCTET STRING wrapped
        [0x04, 0x41, rest @ ..] if rest.len() == 65 => Some(rest),
        // already bare SEC1
        [0x04, ..] if raw.len() == 65 => Some(raw),
        _ => None,
    }
}
