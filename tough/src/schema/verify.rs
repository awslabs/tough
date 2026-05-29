use super::error::{self, Result};
use super::{Delegations, Role, Root, Signed, Targets};
use crate::schema::key::{Key, KeyId};
use olpc_cjson::CanonicalFormatter;
use serde::Serialize;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;

impl Root {
    /// Checks that the given metadata role is valid based on a threshold of key signatures.
    pub fn verify_role<T: Role + Serialize>(&self, role: &Signed<T>) -> Result<()> {
        let role_keys = self
            .roles
            .get(&T::TYPE)
            .context(error::MissingRoleSnafu { role: T::TYPE })?;

        verify_common(
            &self.keys,
            role,
            &T::TYPE.to_string(),
            &role_keys.keyids,
            role_keys.threshold,
        )
    }
}

impl Delegations {
    /// Verifies that roles matches contain valid keys
    pub fn verify_role(&self, role: &Signed<Targets>, name: &str) -> Result<()> {
        let role_keys =
            self.roles
                .iter()
                .find(|role| role.name == name)
                .ok_or(error::Error::RoleNotFound {
                    name: name.to_string(),
                })?;

        verify_common(
            &self.keys,
            role,
            name,
            &role_keys.keyids,
            role_keys.threshold,
        )
    }
}

fn verify_common<T: Role + Serialize>(
    keys: &HashMap<KeyId, Key>,
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

    #[test]
    fn simple_rsa() {
        let root: Signed<Root> =
            serde_json::from_str(include_str!("../../tests/data/simple-rsa/root.json")).unwrap();
        root.signed.verify_role(&root).unwrap();
    }

    #[test]
    fn no_root_json_signatures_is_err() {
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/no-root-json-signatures/root.json"
        ))
        .expect("should be parsable root.json");
        root.signed
            .verify_role(&root)
            .expect_err("missing signature should not verify");
    }

    #[test]
    fn invalid_root_json_signatures_is_err() {
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/invalid-root-json-signature/root.json"
        ))
        .expect("should be parsable root.json");
        root.signed
            .verify_role(&root)
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
            .verify_role(&root)
            .expect_err("expired root signature should not verify");
    }

    #[test]
    fn mismatched_root_json_keyids_is_err() {
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/mismatched-root-json-keyids/root.json"
        ))
        .expect("should be parsable root.json");
        root.signed
            .verify_role(&root)
            .expect_err("mismatched root role keyids (provided and signed) should not verify");
    }

    #[test]
    fn duplicate_sigs_is_err() {
        let root: Signed<Root> =
            serde_json::from_str(include_str!("../../tests/data/duplicate-sigs/root.json"))
                .expect("should be parsable root.json");
        root.signed
            .verify_role(&root)
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
            .verify_role(&root)
            .expect_err("expired root signature should not verify");
    }
}
