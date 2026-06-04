use super::error::{self, Result};
use super::{Delegations, Role, Root, Signed, Targets};
use crate::schema::key::{Key, KeyId};
use crate::KeyIdFormat;
use olpc_cjson::CanonicalFormatter;
use serde::Serialize;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;

impl Root {
    /// Checks that the given metadata role is valid based on a threshold of key signatures.
    pub fn verify_role<T: Role + Serialize>(
        &self,
        role: &Signed<T>,
        key_id_format: KeyIdFormat,
    ) -> Result<()> {
        let role_keys = self
            .roles
            .get(&T::TYPE)
            .context(error::MissingRoleSnafu { role: T::TYPE })?;

        verify_common(
            &self.keys,
            key_id_format,
            role,
            &T::TYPE.to_string(),
            &role_keys.keyids,
            role_keys.threshold,
        )
    }
}

impl Delegations {
    /// Verifies that roles matches contain valid keys
    pub fn verify_role(
        &self,
        role: &Signed<Targets>,
        name: &str,
        key_id_format: KeyIdFormat,
    ) -> Result<()> {
        let role_keys =
            self.roles
                .iter()
                .find(|role| role.name == name)
                .ok_or(error::Error::RoleNotFound {
                    name: name.to_string(),
                })?;

        verify_common(
            &self.keys,
            key_id_format,
            role,
            name,
            &role_keys.keyids,
            role_keys.threshold,
        )
    }
}

fn verify_common<T: Role + Serialize>(
    keys: &HashMap<KeyId, Key>,
    key_id_format: KeyIdFormat,
    role: &Signed<T>,
    role_name: &str,
    role_keys: &[KeyId],
    threshold: NonZeroU64,
) -> Result<()> {
    let mut valid = 0;

    let mut data = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
    role.signed
        .serialize(&mut ser)
        .context(error::JsonSerializationSnafu {
            what: format!("{role_name} role"),
        })?;

    let mut valid_keyids = HashSet::new();
    let mut contained_keyids = HashSet::new();
    let mut contained_materials = HashMap::new();

    for signature in &role.signatures {
        let keyid = &signature.keyid;

        ensure!(
            !contained_keyids.contains(keyid),
            error::DuplicateKeyIdSnafu {
                keyid: keyid.clone(),
            }
        );
        contained_keyids.insert(keyid);

        if role_keys.contains(keyid) {
            if let Some(key) = keys.get(keyid) {
                // TAP 12 proposes the wording "Clients MUST use each key only once during a
                // given signature verification". We thus check whether the underlying key material
                // was already used to verify a signature.
                //
                // Note that we cannot use the canonical key ID for this, as it contains arbitrary
                // user-defined fields. That'd allow a malformed root manifest to define multiple
                // keys (with unique canonical key IDs) pointing to the same key material.
                if let Some(rhs) = contained_materials.insert(key.material(), keyid.clone()) {
                    return error::MultipleKeyIdsForOneKeySnafu {
                        lhs: keyid.clone(),
                        rhs,
                    }
                    .fail();
                }

                match key_id_format {
                    KeyIdFormat::HashedKey => {
                        let canonical_keyid = key.key_id()?;
                        ensure!(
                            // Canonical key IDs are hex-encoded, so it's valid for them to be
                            // represented using both upper and lower case letters.
                            keyid.lowercase() == canonical_keyid.lowercase(),
                            error::InvalidKeyIdSnafu {
                                keyid: keyid.clone(),
                                calculated: canonical_keyid,
                            }
                        );
                    }
                    KeyIdFormat::Any => {}
                }

                if key.verify(&data, &signature.sig) {
                    // we have ensured that this keyid is not already
                    // present in valid_keyids with the test on
                    // contained_keyids.
                    valid_keyids.insert(keyid);
                    valid += 1;
                }
            }
        }
    }

    ensure!(
        valid >= u64::from(threshold),
        error::SignatureThresholdSnafu {
            role: T::TYPE,
            threshold,
            valid,
        }
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Root, Signed};
    use crate::KeyIdFormat;

    #[test]
    fn simple_rsa() {
        let root: Signed<Root> =
            serde_json::from_str(include_str!("../../tests/data/simple-rsa/root.json")).unwrap();
        root.signed
            .verify_role(&root, KeyIdFormat::HashedKey)
            .unwrap();
    }

    #[test]
    fn no_root_json_signatures_is_err() {
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/no-root-json-signatures/root.json"
        ))
        .expect("should be parsable root.json");
        root.signed
            .verify_role(&root, KeyIdFormat::HashedKey)
            .expect_err("missing signature should not verify");
    }

    #[test]
    fn invalid_root_json_signatures_is_err() {
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/invalid-root-json-signature/root.json"
        ))
        .expect("should be parsable root.json");
        root.signed
            .verify_role(&root, KeyIdFormat::HashedKey)
            .expect_err("invalid (unauthentic) root signature should not verify");
    }

    #[test]
    // FIXME: this is not actually testing for expired metadata!
    // These tests should be transformed into full repositories and go through Repository::load
    #[ignore]
    fn expired_root_json_signature_is_err() {
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/expired-root-json-signature/root.json"
        ))
        .expect("should be parsable root.json");
        root.signed
            .verify_role(&root, KeyIdFormat::HashedKey)
            .expect_err("expired root signature should not verify");
    }

    #[test]
    fn mismatched_root_json_keyids_is_err() {
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/mismatched-root-json-keyids/root.json"
        ))
        .expect("should be parsable root.json");
        root.signed
            .verify_role(&root, KeyIdFormat::HashedKey)
            .expect_err("mismatched root role keyids (provided and signed) should not verify");
    }

    #[test]
    fn duplicate_sigs_is_err() {
        let root: Signed<Root> =
            serde_json::from_str(include_str!("../../tests/data/duplicate-sigs/root.json"))
                .expect("should be parsable root.json");
        root.signed
            .verify_role(&root, KeyIdFormat::HashedKey)
            .expect_err("expired root signature should not verify");
    }

    #[test]
    fn duplicate_sig_keys_is_err() {
        // This metadata is signed with the non-deterministic rsassa-pss signing scheme to
        // demonstrate that we will will detect different signatures made by the same key.
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/duplicate-sig-keys/root.json"
        ))
        .expect("should be parsable root.json");
        root.signed
            .verify_role(&root, KeyIdFormat::HashedKey)
            .expect_err("expired root signature should not verify");
    }

    #[test]
    fn test_tap12_correct() {
        let root: Signed<Root> =
            serde_json::from_str(include_str!("../../tests/data/tap-12-good/root.json"))
                .expect("should be parseable root.json");

        let err = root
            .signed
            .verify_role(&root, KeyIdFormat::HashedKey)
            .expect_err("TAP 12 key names with KeyIdFormat::HashedKey should not verify");
        assert!(matches!(err, super::error::Error::InvalidKeyId { .. }));

        root.signed
            .verify_role(&root, KeyIdFormat::Any)
            .expect("TAP 12 key names with KeyIdFormat::Any should verify");
    }

    #[test]
    fn test_tap12_multiple_ids_for_a_key() {
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/tap-12-multiple-ids/root.json"
        ))
        .expect("should be parseable root.json");

        let err = root
            .signed
            .verify_role(&root, KeyIdFormat::Any)
            .expect_err("multiple key IDs pointing to the same key should not verify");
        assert!(matches!(
            err,
            super::error::Error::MultipleKeyIdsForOneKey { .. }
        ));
    }
}
