// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `sonic_rs::format::Formatter` implementation of `CanonicalFormatter` (feature `sonic-rs`).

#[cfg(all(test, feature = "serde_json"))]
mod tests {
    use crate::CanonicalFormatter;
    use serde::Serialize;

    /// The canonical bytes through serde_json.
    fn via_serde_json(text: &str) -> Option<Vec<u8>> {
        let value: serde_json::Value = serde_json::from_str(text).ok()?;
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        value.serialize(&mut ser).ok()?;
        Some(buf)
    }

    /// The canonical bytes through sonic-rs.
    fn via_sonic(text: &str) -> Option<Vec<u8>> {
        let value: sonic_rs::Value = sonic_rs::from_str(text).ok()?;
        let mut ser = sonic_rs::Serializer::with_formatter(Vec::new(), CanonicalFormatter::new());
        value.serialize(&mut ser).ok()?;
        Some(ser.into_inner())
    }

    /// Inputs from the `serde_json` tests of this crate (JSON text instead of `json!`), plus
    /// strings that need escaping or normalizing and keys whose order depends on their escapes.
    const CORPUS: &[&str] = &[
        "[1, 2, 3]",
        "[]",
        "{}",
        r#"{"A": [99]}"#,
        r#"{"A": true}"#,
        r#"{"B": false}"#,
        r#"{"x": 3, "y": 2}"#,
        r#"{"x": 3, "y": null}"#,
        "8.0",
        r#"{"x": 8.0}"#,
        r#"{"x": 1e2}"#,
        r#""\u0000""#,
        r#""\u0001""#,
        r#""\b\t\n\f\r""#,
        r#""\u001f""#,
        r#"{"\t": "\n"}"#,
        r#""\\""#,
        r#""\"""#,
        r#""a/b\/c""#,
        r#""é""#,
        r#""é""#,
        r#""Å Å""#,
        r#"{"a\"b": 1, "a": 2, "a\\": 3, "a\u0001": 4, "b": 5}"#,
        r#"{"é": 1, "é": 2, "z": 3}"#,
        r#"{"nested": {"bad": true, "good": false}, "b": 2, "a": 1, "c": {"h": {"h": -5, "i": 3}, "a": null, "x": {}}}"#,
        r#"[{"b": [], "a": {}}, [[], [{}]], "x", null, false, -0, 0]"#,
        r#"{"signed": {"_type": "timestamp", "spec_version": "1.0.0", "version": 1604605512, "expires": "2020-11-12T19:45:12.613154979Z", "meta": {"snapshot.json": {"length": 1278, "hashes": {"sha256": "56c4ecc3b331f6154d9a5005f6e2978e4198cc8c3b79746c25a592043a2d83d4"}, "version": 1604605512}}}}"#,
    ];

    #[test]
    fn sonic_canonical_equals_serde_canonical() {
        for text in CORPUS {
            assert_eq!(via_sonic(text), via_serde_json(text), "{text}");
        }
        // the corpus has both outcomes
        assert!(via_sonic("[1, 2, 3]").is_some());
        assert!(via_sonic("8.0").is_none());
    }

    #[test]
    fn sonic_keys_are_ordered_by_their_escaped_bytes() {
        let out = via_sonic(r#"{"a\u0001": 4, "a\"b": 1, "a": 2, "a\\": 3}"#).unwrap();
        assert_eq!(out, b"{\"a\x01\":4,\"a\":2,\"a\\\"b\":1,\"a\\\\\":3}");
    }

    #[test]
    fn sonic_raw_values_are_written_canonically() {
        let text = r#"{"b": 2, "a": [{"z": 1, "y": "é"}]}"#;
        let raw: sonic_rs::LazyValue<'_> = sonic_rs::from_str(text).unwrap();
        let mut ser = sonic_rs::Serializer::with_formatter(Vec::new(), CanonicalFormatter::new());
        raw.serialize(&mut ser).unwrap();
        assert_eq!(
            ser.into_inner(),
            "{\"a\":[{\"y\":\"\u{e9}\",\"z\":1}],\"b\":2}".as_bytes()
        );

        // a float inside a raw value is refused, as it is outside of one
        let raw: sonic_rs::LazyValue<'_> = sonic_rs::from_str(r#"{"a": 1.5}"#).unwrap();
        let mut ser = sonic_rs::Serializer::with_formatter(Vec::new(), CanonicalFormatter::new());
        assert!(raw.serialize(&mut ser).is_err());
    }

    #[test]
    fn sonic_128_bit_integers() {
        #[derive(serde_derive::Serialize)]
        struct Object {
            u128: u128,
            i128: i128,
        }

        let value = Object {
            u128: u128::MAX,
            i128: i128::MIN,
        };
        let mut ser = sonic_rs::Serializer::with_formatter(Vec::new(), CanonicalFormatter::new());
        value.serialize(&mut ser).unwrap();
        assert_eq!(
            ser.into_inner(),
            br#"{"i128":-170141183460469231731687303715884105728,"u128":340282366920938463463374607431768211455}"#
        );
    }
}
