// SPDX-License-Identifier: MIT OR Apache-2.0

//! The [`sonic_rs::format::Formatter`] implementation of [`CanonicalFormatter`] (feature
//! `sonic-rs`).
//!
//! It produces the same bytes as the `serde_json` implementation. sonic-rs has no
//! `write_char_escape` or `write_string_fragment`: it hands a whole string to `write_string_fast`,
//! and a raw JSON document (`RawNumber`, `LazyValue`, a raw number inside a `Value`) to
//! `write_raw_value`. Those two are overridden here.

use crate::CanonicalFormatter;
use sonic_rs::format::{CompactFormatter, Formatter};
use sonic_rs::writer::WriteExt;
use std::io::{Error, Result, Write};
use unicode_normalization::UnicodeNormalization;

/// Wraps `sonic_rs::format::CompactFormatter` to use the appropriate writer (see
/// `CanonicalFormatter::writer`).
macro_rules! sonic_wrapper {
    ($f:ident) => {
        fn $f<W>(&mut self, writer: &mut W) -> Result<()>
        where
            W: ?Sized + Write,
        {
            CompactFormatter.$f(&mut self.writer(writer))
        }
    };

    ($f:ident, $t:ty) => {
        fn $f<W>(&mut self, writer: &mut W, arg: $t) -> Result<()>
        where
            W: ?Sized + Write,
        {
            CompactFormatter.$f(&mut self.writer(writer), arg)
        }
    };
}

impl Formatter for CanonicalFormatter {
    sonic_wrapper!(write_null);
    sonic_wrapper!(write_bool, bool);
    sonic_wrapper!(write_i8, i8);
    sonic_wrapper!(write_i16, i16);
    sonic_wrapper!(write_i32, i32);
    sonic_wrapper!(write_i64, i64);
    sonic_wrapper!(write_i128, i128);
    sonic_wrapper!(write_u8, u8);
    sonic_wrapper!(write_u16, u16);
    sonic_wrapper!(write_u32, u32);
    sonic_wrapper!(write_u64, u64);
    sonic_wrapper!(write_u128, u128);

    fn write_f32<W>(&mut self, _writer: &mut W, _value: f32) -> Result<()>
    where
        W: ?Sized + Write,
    {
        float_err!()
    }

    fn write_f64<W>(&mut self, _writer: &mut W, _value: f64) -> Result<()>
    where
        W: ?Sized + Write,
    {
        float_err!()
    }

    fn write_number_str<W>(&mut self, writer: &mut W, value: &str) -> Result<()>
    where
        W: ?Sized + Write,
    {
        write_number(&mut self.writer(writer), value)
    }

    sonic_wrapper!(begin_string);
    sonic_wrapper!(end_string);

    // Strings are normalized as Normalization Form C (NFC), and only quotes and backslashes are
    // escaped: every other character, control characters included, is written as it is.
    fn write_string_fast<W>(&mut self, writer: &mut W, value: &str, need_quote: bool) -> Result<()>
    where
        W: ?Sized + WriteExt,
    {
        let mut out = Vec::with_capacity(value.len() + 2);
        if need_quote {
            out.push(b'"');
        }
        for ch in value.nfc() {
            if ch == '"' || ch == '\\' {
                out.push(b'\\');
            }
            out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
        }
        if need_quote {
            out.push(b'"');
        }
        self.writer(writer).write_all(&out)
    }

    sonic_wrapper!(begin_array);
    sonic_wrapper!(end_array);
    sonic_wrapper!(begin_array_value, bool); // hack: this passes through the `first` argument
    sonic_wrapper!(end_array_value);

    // The object methods work as in the `serde_json` implementation: keys must be sorted, so an
    // object is kept in memory as a `BTreeMap` and written out when it ends.

    fn begin_object<W>(&mut self, writer: &mut W) -> Result<()>
    where
        W: ?Sized + Write,
    {
        CompactFormatter.begin_object(&mut self.writer(writer))?;
        self.object_stack.push(crate::Object::default());
        Ok(())
    }

    fn end_object<W>(&mut self, writer: &mut W) -> Result<()>
    where
        W: ?Sized + Write,
    {
        let object = self.object_stack.pop().ok_or_else(|| {
            Error::other("sonic-rs called Formatter::end_object without calling begin_object first")
        })?;
        let mut writer = self.writer(writer);
        let mut first = true;

        for (key, value) in object.obj {
            CompactFormatter.begin_object_key(&mut writer, first)?;
            writer.write_all(&key)?;
            CompactFormatter.end_object_key(&mut writer)?;

            CompactFormatter.begin_object_value(&mut writer)?;
            writer.write_all(&value)?;
            CompactFormatter.end_object_value(&mut writer)?;

            first = false;
        }

        CompactFormatter.end_object(&mut writer)
    }

    fn begin_object_key<W>(&mut self, _writer: &mut W, _first: bool) -> Result<()>
    where
        W: ?Sized + Write,
    {
        let object = self.obj_mut()?;
        object.key_done = false;
        Ok(())
    }

    fn end_object_key<W>(&mut self, _writer: &mut W) -> Result<()>
    where
        W: ?Sized + Write,
    {
        let object = self.obj_mut()?;
        object.key_done = true;
        Ok(())
    }

    fn begin_object_value<W>(&mut self, _writer: &mut W) -> Result<()>
    where
        W: ?Sized + Write,
    {
        Ok(())
    }

    fn end_object_value<W>(&mut self, _writer: &mut W) -> Result<()>
    where
        W: ?Sized + Write,
    {
        let object = self.obj_mut()?;
        let key = std::mem::take(&mut object.next_key);
        let value = std::mem::take(&mut object.next_value);
        object.obj.insert(key, value);
        Ok(())
    }

    // sonic-rs hands a raw JSON text here as it is: a number kept as text (`RawNumber`, or a raw
    // number inside a `Value`), a `LazyValue`, or an entry of a sorted map. A number is checked as
    // `write_number_str` does. Anything else is not good enough as it is, so we parse it and
    // immediately write it back out... as canonical JSON.
    fn write_raw_value<W>(&mut self, writer: &mut W, raw: &str) -> Result<()>
    where
        W: ?Sized + Write,
    {
        let raw = raw.trim();
        let mut writer = self.writer(writer);
        if raw.starts_with(|c: char| c == '-' || c.is_ascii_digit()) {
            return write_number(&mut writer, raw);
        }
        // numbers are kept as text, so that a float is refused whatever its value
        let value: sonic_rs::Value = sonic_rs::Deserializer::from_str(raw)
            .use_rawnumber()
            .deserialize()
            .map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let mut ser = sonic_rs::Serializer::with_formatter(Vec::new(), CanonicalFormatter::new());
        serde::Serialize::serialize(&value, &mut ser)
            .map_err(|e| Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        writer.write_all(&ser.into_inner())
    }
}

/// Writes a number given as text. A number with a fraction or an exponent is refused.
fn write_number<W: Write + ?Sized>(writer: &mut W, value: &str) -> Result<()> {
    if value.chars().any(|c| c == '.' || c == 'e' || c == 'E') {
        float_err!()
    } else {
        CompactFormatter.write_number_str(writer, value)
    }
}

#[cfg(all(test, feature = "serde_json"))]
#[allow(clippy::unicode_not_nfc, clippy::doc_markdown)]
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
