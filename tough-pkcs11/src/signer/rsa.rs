// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;

use aws_lc_rs::{
    digest::{digest, SHA256},
    encoding::AsDer,
    rsa::PublicKeyComponents,
    signature::RSA_PSS_2048_8192_SHA256,
};
use cryptoki::{
    mechanism::{
        rsa::{PkcsMgfType, PkcsPssParams},
        Mechanism, MechanismType,
    },
    object::{Attribute, AttributeType, ObjectHandle},
    session::Session,
};
use snafu::{OptionExt, ResultExt};
use tough::schema::key::{Key, RsaKey, RsaScheme};

use crate::error::{self, Result};

pub fn export_pubkey(session: &Session, pubkey: ObjectHandle) -> Result<Key> {
    let attrs = session
        .get_attributes(
            pubkey,
            &[AttributeType::Modulus, AttributeType::PublicExponent],
        )
        .context(error::GetPubkeySnafu)?;

    let (mut modulus, mut exponent) = (None, None);
    for a in attrs {
        match a {
            Attribute::Modulus(v) => modulus = Some(v),
            Attribute::PublicExponent(v) => exponent = Some(v),
            _ => {}
        }
    }

    let modulus = modulus.context(error::UnexpectedResponseSnafu {
        reason: "failed to get modulus",
    })?;
    let exponent = exponent.context(error::UnexpectedResponseSnafu {
        reason: "failed to get exponent",
    })?;

    let rsa = PublicKeyComponents {
        n: modulus,
        e: exponent,
    }
    .to_parsed_public_key(&RSA_PSS_2048_8192_SHA256)
    .context(error::ParsePubkeySnafu)?;

    let der = rsa.as_der().ok().context(error::UnexpectedResponseSnafu {
        reason: "failed to serialise RSA public key to DER",
    })?;

    let key = pem::encode_config(
        &pem::Pem::new("PUBLIC KEY".to_owned(), der.as_ref()),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );

    Ok(Key::Rsa {
        keyval: RsaKey {
            public: key.parse().ok().context(error::UnexpectedResponseSnafu {
                reason: "failed to parse RSA pubkey",
            })?,
            _extra: HashMap::new(),
        },
        scheme: RsaScheme::RsassaPssSha256,
        _extra: HashMap::new(),
    })
}

pub fn sign_pss_sha256(
    session: &Session,
    privkey: ObjectHandle,
    message: &[u8],
) -> Result<Vec<u8>> {
    let hash = digest(&SHA256, message);

    let params = PkcsPssParams {
        hash_alg: MechanismType::SHA256,
        mgf: PkcsMgfType::MGF1_SHA256,
        // Salt length must be equal the digest length
        s_len: 32.into(),
    };

    let signature = session
        .sign(&Mechanism::RsaPkcsPss(params), privkey, hash.as_ref())
        .context(error::SigningFailedSnafu)?;

    // RSASSA-PSS signatures are already the raw big-endian octet strings
    Ok(signature)
}
