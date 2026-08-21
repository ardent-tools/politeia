//! Canonical JSON bytes for digest-critical records.
//!
//! A digest is only as stable as the bytes it hashes. `serde_json` produces
//! *deterministic* bytes for a given struct — it emits fields in declaration
//! order — but deterministic is not canonical: reorder two fields in the source
//! and every digest of that record moves, with nothing to notice.
//!
//! The rules here cover the JSON layer. The type layer carries its own and both
//! matter: identifiers encode as canonical lowercase-hyphenated UUID text,
//! timestamps as `Z`-suffixed RFC 3339, and enums through their serde
//! representation. A canonical JSON writer over a non-canonical value type
//! would still produce two encodings of one fact.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

/// A value could not be encoded canonically.
#[derive(Debug)]
#[non_exhaustive]
pub enum CanonicalError {
    /// The value could not be represented as JSON at all.
    Encoding(serde_json::Error),
    /// A floating-point number was encountered.
    ///
    /// Floats have no single canonical text: `1.0`, `1e0` and `1.000` denote one
    /// value, and round-tripping through a decimal form is lossy in ways that
    /// differ per implementation. A digest built on one of those spellings is a
    /// digest another correct implementation cannot reproduce, so this fails
    /// closed rather than picking a spelling and hoping.
    Float,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalError::Encoding(error) => {
                write!(formatter, "canonical encoding failed: {error}")
            }
            CanonicalError::Float => formatter.write_str(
                "a floating-point number has no canonical text form and cannot be digested",
            ),
        }
    }
}

impl std::error::Error for CanonicalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CanonicalError::Encoding(error) => Some(error),
            CanonicalError::Float => None,
        }
    }
}

impl From<serde_json::Error> for CanonicalError {
    fn from(error: serde_json::Error) -> Self {
        CanonicalError::Encoding(error)
    }
}

/// Encode a value as canonical JSON bytes.
///
/// Object keys are emitted in lexicographic order by Unicode scalar value,
/// with no insignificant whitespace.
///
/// # Errors
///
/// Returns [`CanonicalError::Encoding`] if the value cannot be represented as
/// JSON, and [`CanonicalError::Float`] if it contains a floating-point number.
pub fn to_canonical_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = serde_json::to_value(value)?;
    let mut out = String::new();
    write_canonical(&value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical(value: &serde_json::Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(true) => out.push_str("true"),
        serde_json::Value::Bool(false) => out.push_str("false"),
        serde_json::Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err(CanonicalError::Float);
            }
            out.push_str(&number.to_string());
        }
        // Delegated so that escaping matches the decoder's own expectations
        // exactly. Hand-rolling it is where a canonicalizer acquires a second,
        // subtly different notion of what a string is.
        serde_json::Value::String(text) => out.push_str(&serde_json::to_string(text)?),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Object(members) => {
            // WHY collected into a BTreeMap rather than trusting the map's own
            // iteration order: `serde_json`'s `Map` is sorted only while the
            // `preserve_order` feature is off, and cargo features are additive
            // and unified across a workspace. Any dependency — present or
            // future, direct or transitive — turning it on would silently make
            // these bytes insertion-ordered, and every digest would move with
            // no change to this file. Sorting here does not depend on a
            // decision made elsewhere in the graph.
            let sorted: BTreeMap<&str, &serde_json::Value> = members
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            out.push('{');
            for (index, (key, member)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                write_canonical(member, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot encode is a broken test, not a finding"
    )]
    fn canonical(value: serde_json::Value) -> String {
        String::from_utf8(to_canonical_bytes(&value).expect("the fixture must encode"))
            .expect("canonical bytes are UTF-8")
    }

    #[test]
    fn object_keys_are_emitted_in_lexicographic_order() {
        assert_eq!(
            canonical(serde_json::json!({"b": 1, "a": 2, "c": 3})),
            r#"{"a":2,"b":1,"c":3}"#
        );
    }

    #[test]
    fn nested_objects_are_ordered_too() {
        // A canonicalizer that sorts only the root looks correct on every flat
        // fixture, and every record here nests.
        assert_eq!(
            canonical(serde_json::json!({"outer": {"z": 1, "a": [{"y": 1, "x": 2}]}})),
            r#"{"outer":{"a":[{"x":2,"y":1}],"z":1}}"#
        );
    }

    #[test]
    fn declaration_order_does_not_survive() {
        // The property that matters: two encodings of the same fact converge.
        assert_eq!(
            canonical(serde_json::json!({"a": 1, "b": 2})),
            canonical(serde_json::json!({"b": 2, "a": 1}))
        );
    }

    #[test]
    fn array_order_is_preserved() {
        // Arrays are sequences, not sets. Sorting them would change the value
        // rather than normalise its spelling.
        assert_eq!(canonical(serde_json::json!([3, 1, 2])), "[3,1,2]");
    }

    #[test]
    fn null_is_encoded_rather_than_dropped() {
        // An omitted field and a null field must not encode alike: a record that
        // gains an optional field would otherwise digest as it did before.
        assert_eq!(canonical(serde_json::json!({"a": null})), r#"{"a":null}"#);
        assert_ne!(
            canonical(serde_json::json!({"a": null})),
            canonical(serde_json::json!({}))
        );
    }

    #[test]
    fn a_float_is_refused() {
        let result = to_canonical_bytes(&serde_json::json!({"ratio": 1.5}));
        assert!(
            matches!(result, Err(CanonicalError::Float)),
            "a float must fail closed rather than acquire a spelling"
        );
    }

    #[test]
    fn integers_at_the_type_boundary_survive() {
        assert_eq!(
            canonical(serde_json::json!({"max": u64::MAX, "min": i64::MIN})),
            format!(r#"{{"max":{},"min":{}}}"#, u64::MAX, i64::MIN)
        );
    }

    #[test]
    fn strings_keep_the_encoder_own_escaping() {
        assert_eq!(
            canonical(serde_json::json!({"quote": "a\"b", "tab": "a\tb"})),
            r#"{"quote":"a\"b","tab":"a\tb"}"#
        );
    }
}
