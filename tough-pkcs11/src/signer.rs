// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod ec;
mod obj;
mod rsa;

#[cfg(test)]
mod tests;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::RvError,
    object::{Attribute, AttributeType, KeyType, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use snafu::{ensure, ResultExt};
use tough::schema::key::Key;
use tough::schema::key::{EcdsaScheme, RsaScheme};

use crate::error::{self, Error, Result};

#[derive(Debug, Clone)]
pub enum TokenId {
    /// Match by `CKT_TOKEN_LABEL` - `token=` in the URI.
    Label(String),
    /// Match by `CKT_TOKEN_SERIAL_NUMBER` - `serial=` in the URI.
    Serial(String),
    /// Use the slot directly - `slot-id=` in the URI.
    SlotId(u64),
}

#[derive(Debug, Clone)]
pub enum KeyId {
    /// Match by `CKA_LABEL` - `object=` in the URI.
    Label(String),
    /// Match by `CKA_ID` (raw bytes) - `id=` (percent-encoded) in the URI.
    Id(Vec<u8>),
}

/// Implements the KeySource trait for keys that live in AWS SSM.
#[derive(Debug, Clone)]
pub struct Pkcs11KeySource {
    module_path: PathBuf,
    token: TokenId,
    key: KeyId,
    pin: Option<AuthPin>,
}

fn key_source_to_pkcs11_key(source: &Pkcs11KeySource) -> Result<Pkcs11Key> {
    let pkcs11 = Pkcs11::new(&source.module_path).context(error::LoadModuleSnafu)?;

    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => {}
        // Another instance in the same process already initialized the
        // library. This is harmless — we can reuse the existing state.
        Err(cryptoki::error::Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(err) => return Err(Error::InitModule { source: err }),
    }

    let slot = find_slot(&pkcs11, &source.token)?;
    let session = pkcs11
        .open_ro_session(slot)
        .context(error::OpenRoSessionSnafu)?;

    session
        .login(UserType::User, source.pin.as_ref())
        .context(error::LoginFailedSnafu)?;

    let (obj::Pub(pub_obj), obj::Priv(priv_obj)) = obj::get_pub_priv(&session, &source.key)?;

    let pubkey = export_public_key(&session, pub_obj)?;

    Ok(Pkcs11Key {
        inner: Arc::new(Mutex::new(Pkcs11KeyInner {
            pub_key: pubkey,
            priv_obj,
            session,
        })),
    })
}

fn find_slot(pkcs11: &Pkcs11, token_id: &TokenId) -> Result<Slot> {
    let slots = pkcs11
        .get_slots_with_initialized_token()
        .context(error::GetSlotInfoSnafu)?;

    for slot in slots {
        let info = pkcs11
            .get_token_info(slot)
            .context(error::GetSlotInfoSnafu)?;

        let matched = match token_id {
            TokenId::Label(label) => info.label().trim() == label.trim(),
            TokenId::Serial(serial) => info.serial_number().trim() == serial.trim(),
            TokenId::SlotId(id) => slot.id() == *id,
        };
        if matched {
            return Ok(slot);
        }
    }
    Err(Error::TokenNotFound)
}

fn key_type(session: &Session, key: ObjectHandle) -> Result<KeyType> {
    match session
        .get_attributes(key, &[AttributeType::KeyType])
        .context(error::GetPubkeySnafu)?
        .into_iter()
        .next()
    {
        Some(Attribute::KeyType(kt)) => Ok(kt),
        _ => Err(Error::UnexpectedResponse),
    }
}

fn export_public_key(session: &Session, pubkey: ObjectHandle) -> Result<Key> {
    match key_type(session, pubkey)? {
        KeyType::EC => ec::export_pubkey(session, pubkey),
        KeyType::EC_EDWARDS => ec::export_pubkey(session, pubkey),
        KeyType::RSA => rsa::export_pubkey(session, pubkey),
        // TODO: provide more info
        _ => Err(Error::UnsupportedKeyType),
    }
}

fn sign(session: &Session, pubkey: &Key, privkey: ObjectHandle, message: &[u8]) -> Result<Vec<u8>> {
    match pubkey {
        Key::Ecdsa {
            scheme: EcdsaScheme::EcdsaSha2Nistp256,
            ..
        } => ec::sign_p256(session, privkey, message),
        Key::Ed25519 { .. } => ec::sign_ed25519(session, privkey, message),
        Key::Rsa {
            scheme: RsaScheme::RsassaPssSha256,
            ..
        } => rsa::sign_pss_sha256(session, privkey, message),
        _ => Err(Error::UnsupportedKeyType),
    }
}

impl Pkcs11KeySource {
    /// Load and initialize pkcs11 module, find the key objects,
    /// export the public key and prepare for signing.
    pub fn to_key(&self) -> Result<Pkcs11Key> {
        key_source_to_pkcs11_key(self)
    }
}

struct Pkcs11KeyInner {
    pub_key: Key,
    priv_obj: ObjectHandle,
    session: Session,
}

#[derive(Clone)]
pub struct Pkcs11Key {
    inner: Arc<Mutex<Pkcs11KeyInner>>,
}

impl Pkcs11Key {
    /// Get public key of the object.
    pub fn pub_key(&self) -> Key {
        self.inner.lock().expect("mutex poisoned").pub_key.clone()
    }

    /// Sign a message with PKCS11 key.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let state = self.inner.lock().expect("mutex poisoned");
        let sig = sign(&state.session, &state.pub_key, state.priv_obj, msg)?;
        ensure!(
            state.pub_key.verify(msg, &sig),
            error::InvalidSignatureSnafu
        );
        Ok(sig)
    }
}
