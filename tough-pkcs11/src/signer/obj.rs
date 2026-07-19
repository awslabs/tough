// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use cryptoki::{
    object::{Attribute, ObjectClass, ObjectHandle},
    session::Session,
};
use snafu::{OptionExt, ResultExt};

use crate::{
    error::{self, Result},
    signer::KeyId,
};

fn key_search_template(class: ObjectClass, key: &KeyId) -> [Attribute; 2] {
    let key_attr = match key {
        KeyId::Label(label) => Attribute::Label(label.as_bytes().to_vec()),
        KeyId::Id(id) => Attribute::Id(id.clone()),
    };
    [Attribute::Class(class), key_attr]
}

fn find_objects(
    session: &Session,
    class: ObjectClass,
    key: &KeyId,
) -> core::result::Result<Vec<ObjectHandle>, cryptoki::error::Error> {
    session.find_objects(&key_search_template(class, key))
}

pub struct Pub(pub ObjectHandle);
pub struct Priv(pub ObjectHandle);

pub fn get_pub_priv(session: &Session, key: &KeyId) -> Result<(Pub, Priv)> {
    let pub_objects =
        find_objects(session, ObjectClass::PUBLIC_KEY, key).context(error::GetKeySnafu)?;

    let priv_objects =
        find_objects(session, ObjectClass::PRIVATE_KEY, key).context(error::GetKeySnafu)?;

    let pub_obj = pub_objects
        .into_iter()
        .next()
        .context(error::KeyNotFoundSnafu)?;
    let priv_obj = priv_objects
        .into_iter()
        .next()
        .context(error::KeyNotFoundSnafu)?;

    Ok((Pub(pub_obj), Priv(priv_obj)))
}
