use crate::schema::decoded::{Decoded, Hex};
use crate::schema::error;
use crate::schema::key::Key;
use serde::{de::Error as _, Deserialize, Deserializer};
use snafu::ensure;
use std::collections::HashMap;
use std::fmt;

/// Deserializes the keys map, rejecting duplicate key IDs.
pub(super) fn deserialize_keys<'de, D>(
    deserializer: D,
) -> Result<HashMap<Decoded<Hex>, Key>, D::Error>
where
    D: Deserializer<'de>,
{
    // An inner function that inserts each entry, failing if there is a duplicate key ID.
    //
    // Note: we intentionally do NOT recompute each key ID and reject mismatches. In modern
    // TUF a key ID is an opaque identifier chosen by the metadata producer; the spec does
    // not require `keyid == hash(key)`. Recomputing is also not interoperable in practice:
    // securesystemslib (tuf-on-ci) hashes only the canonical `{keytype, scheme, keyval}` and
    // excludes custom fields such as `x-tuf-on-ci-keyowner`, while older roots included them,
    // so no single canonicalization matches every real-world root. python-tuf and go-tuf both
    // treat the declared key ID as authoritative; tough now does the same. Signatures are still
    // fully verified against the key the producer associated with each ID.
    fn validate_and_insert_entry(
        keyid: Decoded<Hex>,
        key: Key,
        map: &mut HashMap<Decoded<Hex>, Key>,
    ) -> Result<(), error::Error> {
        let keyid_hex = hex::encode(&keyid);
        ensure!(
            map.insert(keyid, key).is_none(),
            error::DuplicateKeyIdSnafu { keyid: keyid_hex }
        );
        Ok(())
    }

    // The rest of this is fitting the above function into serde and doing error type conversion.
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = HashMap<Decoded<Hex>, Key>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut map = HashMap::new();
            while let Some((keyid, key)) = access.next_entry()? {
                validate_and_insert_entry(keyid, key, &mut map).map_err(M::Error::custom)?;
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(Visitor)
}

/// Deserializes the `_extra` field on roles, skipping the `_type` tag.
pub(super) fn extra_skip_type<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut map = HashMap::deserialize(deserializer)?;
    map.remove("_type");
    Ok(map)
}

#[cfg(test)]
mod tests {
    use crate::schema::{Root, Signed};

    #[test]
    fn duplicate_keyid() {
        assert!(serde_json::from_str::<Signed<Root>>(include_str!(
            "../../tests/data/duplicate-keyid/root.json"
        ))
        .is_err());
    }

    /// Ensure that we can deserialize a root.json file that has hex-encoded ECDSA keys. This uses
    /// sigstore's root.json file taken from here:
    /// `<https://sigstore-tuf-root.storage.googleapis.com/2.root.json>`
    #[test]
    fn ecdsa_hex_encoded_keys() {
        assert!(serde_json::from_str::<Signed<Root>>(include_str!(
            "../../tests/data/hex-encoded-ecdsa-sig-keys/root.json"
        ))
        .is_ok());
    }

    /// Ensure that we can deserialize a root.json file that has pem-encoded ECDSA keys. This uses
    /// sigstore's root.json file taken from here:
    /// `<https://github.com/sigstore/sigstore-rs/blob/8a269a3/trust_root/prod/root.json>`
    #[test]
    fn ecdsa_pem_encoded_keys() {
        assert!(serde_json::from_str::<Signed<Root>>(include_str!(
            "../../tests/data/pem-encoded-ecdsa-sig-keys/root.json"
        ))
        .is_ok());
    }
    /// Ensure that we can deserialize a root.json file that has ECDSA keys with new type ecdsa. This uses
    /// sigstore's root.json file taken from here:
    /// `<https://github.com/sigstore/root-signing/blob/d3738d62e92580b5b928d6212c927084ada2bfee/repository/repository/9.root.json>`
    #[test]
    fn ecdsa_new_type_keys() {
        assert!(serde_json::from_str::<Signed<Root>>(include_str!(
            "../../tests/data/ecdsa-new-type-sig-keys/root.json"
        ))
        .is_ok());
    }

    /// Regression: roots produced by tuf-on-ci / modern securesystemslib carry custom key
    /// fields (e.g. `x-tuf-on-ci-keyowner`) and compute the declared key ID over only
    /// `{keytype, scheme, keyval}`, excluding those fields. tough previously recomputed the
    /// key ID over the whole key and rejected the root with "Invalid key ID". This is
    /// GitHub's public TUF root (`https://tuf-repo.github.com`).
    ///
    /// We not only deserialize the root but verify its self-signatures against the
    /// producer-declared key IDs (exactly what `RepositoryLoader` does on bootstrap), to
    /// confirm that accepting declared key IDs does not weaken signature verification.
    #[test]
    fn tuf_on_ci_extra_key_fields() {
        let root: Signed<Root> = serde_json::from_str(include_str!(
            "../../tests/data/tuf-on-ci-extra-fields/root.json"
        ))
        .expect("tuf-on-ci root with custom key fields must deserialize");
        root.signed
            .verify_role(&root)
            .expect("root self-signatures must verify against declared key IDs");
    }
}
