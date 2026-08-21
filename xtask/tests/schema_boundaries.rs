//! Boundary agreement between the published schemas and the Rust decoders.
//!
//! Every assertion here reads the checked-in `spec/*.schema.json` bytes. Rebuilding
//! a schema in memory would test the deriver against itself and say nothing about
//! what was published, which is the gap this suite exists to close.
//!
//! Validation runs with `jsonschema`'s defaults, where `format` is an annotation
//! rather than an assertion. That is deliberate: it is the posture a schema-only
//! consumer has unless it opts in, so a constraint that only holds under format
//! assertion does not count as closed here.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// Every schema `xtask -- derive` publishes.
const SPEC_FILES: &[&str] = &[
    "extension-manifest.schema.json",
    "semantic-operation.schema.json",
    "institution-workspace.schema.json",
    "commissioning-record.schema.json",
    "runtime-generation.schema.json",
    "execution-resource.schema.json",
    "execution-requirement.schema.json",
    "capability-profile.schema.json",
    "capability-verification.schema.json",
    "availability-snapshot.schema.json",
    "routing-decision.schema.json",
    "lifecycle-transition.schema.json",
    "handoff-receipt.schema.json",
];

fn spec_dir() -> PathBuf {
    // WHY not a relative path: `cargo test` sets the working directory to the
    // package root, so `spec/` resolves only from the workspace root and would
    // be NotFound here.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("spec")
}

fn load(name: &str) -> Value {
    let path = spec_dir().join(name);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// Validate against one node of a published document, carrying its `$defs` so
/// that a node whose value schema is a `$ref` still resolves.
fn validator_for_node(document: &Value, node: &Value) -> jsonschema::Validator {
    let mut schema = node.clone();
    let object = schema
        .as_object_mut()
        .unwrap_or_else(|| panic!("schema node is not an object: {node}"));
    object.insert(
        "$schema".to_string(),
        json!("https://json-schema.org/draft/2020-12/schema"),
    );
    if let Some(defs) = document.get("$defs") {
        object.insert("$defs".to_string(), defs.clone());
    }
    jsonschema::validator_for(&schema)
        .unwrap_or_else(|error| panic!("compile node schema: {error}"))
}

/// Visit every subschema-shaped object in a document.
fn walk(value: &Value, path: &str, visit: &mut impl FnMut(&Value, &str)) {
    match value {
        Value::Object(map) => {
            visit(value, path);
            for (key, child) in map {
                walk(child, &format!("{path}/{key}"), visit);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                walk(child, &format!("{path}/{index}"), visit);
            }
        }
        _ => {}
    }
}

fn format_of(node: &Value) -> Option<&str> {
    node.get("format").and_then(Value::as_str)
}

// --- Class sweeps -----------------------------------------------------------
//
// These bound the class rather than a sample: a field added later in any of the
// covered shapes fails here without anyone remembering to write a case for it.

#[test]
fn every_uuid_node_carries_a_pattern() {
    for name in SPEC_FILES {
        let document = load(name);
        walk(&document, "", &mut |node, path| {
            if format_of(node) == Some("uuid") {
                assert!(
                    node.get("pattern").is_some(),
                    "{name}{path}: format uuid with no pattern; \
                     format is an annotation by default, so this constrains nothing"
                );
            }
        });
    }
}

#[test]
fn every_date_time_node_carries_a_pattern() {
    for name in SPEC_FILES {
        let document = load(name);
        walk(&document, "", &mut |node, path| {
            if format_of(node) == Some("date-time") {
                assert!(
                    node.get("pattern").is_some(),
                    "{name}{path}: format date-time with no pattern"
                );
            }
        });
    }
}

#[test]
fn every_uint64_node_carries_the_type_maximum() {
    for name in SPEC_FILES {
        let document = load(name);
        walk(&document, "", &mut |node, path| {
            if format_of(node) == Some("uint64") {
                let maximum = node.get("maximum").and_then(Value::as_u64);
                assert_eq!(
                    maximum,
                    Some(u64::MAX),
                    "{name}{path}: uint64 without an exact u64::MAX maximum \
                     admits integers the decoder cannot represent"
                );
            }
        });
    }
}

#[test]
fn typed_identifier_maps_constrain_their_keys() {
    // schemars derives `patternProperties` from the key type's own pattern, so
    // this is emergent rather than authored. Asserting it here means a schemars
    // change that drops the derivation fails a test instead of silently
    // unconstraining every typed map key.
    let cases = [
        ("runtime-generation.schema.json", "ApprovedGenerationInputs"),
        ("routing-decision.schema.json", "RoutingDecision"),
    ];
    for (name, _owner) in cases {
        let document = load(name);
        let mut constrained_maps = 0;
        walk(&document, "", &mut |node, _path| {
            if node.get("patternProperties").is_some() {
                constrained_maps += 1;
                assert_eq!(
                    node.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "{name}: a map with patternProperties must close \
                     additionalProperties, or non-matching keys stay legal"
                );
            }
        });
        assert!(
            constrained_maps > 0,
            "{name}: no key-constrained map found; the identifier pattern did not \
             reach the map key, so schema-only consumers can still send any key"
        );
    }
}

// --- Rust and schema agree on one corpus ------------------------------------

#[test]
fn identifier_text_agrees_between_schema_and_decoder() {
    let document = load("execution-resource.schema.json");
    let node = document
        .pointer("/$defs/ExecutionResourceId")
        .unwrap_or_else(|| panic!("ExecutionResourceId is missing from $defs"));
    let validator = validator_for_node(&document, node);

    let canonical = json!("a1b2c3d4-e5f6-4789-8abc-d2e3f4a5b6c7");
    assert!(
        validator.is_valid(&canonical),
        "canonical UUID text rejected"
    );
    assert!(
        serde_json::from_value::<politeia_core::ExecutionResourceId>(canonical.clone()).is_ok(),
        "canonical UUID text rejected by the decoder"
    );

    // Each of these is a shape `uuid`'s own parser accepts and its printer never
    // emits. Both sides must reject them, or the published contract and the
    // decoder disagree about what an identifier is.
    let rejected = [
        json!("A1B2C3D4-E5F6-4789-8ABC-D2E3F4A5B6C7"),
        json!("a1b2c3d4e5f647898abcd2e3f4a5b6c7"),
        json!("{a1b2c3d4-e5f6-4789-8abc-d2e3f4a5b6c7}"),
        json!("urn:uuid:a1b2c3d4-e5f6-4789-8abc-d2e3f4a5b6c7"),
        json!("resource-primary"),
        json!(""),
    ];
    for instance in rejected {
        assert!(
            !validator.is_valid(&instance),
            "schema accepted non-canonical identifier {instance}"
        );
        assert!(
            serde_json::from_value::<politeia_core::ExecutionResourceId>(instance.clone()).is_err(),
            "decoder accepted non-canonical identifier {instance} the schema rejects"
        );
    }
}

#[test]
fn map_keys_agree_between_schema_and_decoder() {
    let document = load("routing-decision.schema.json");
    let node = document
        .pointer("/properties/rejected_resources")
        .unwrap_or_else(|| panic!("rejected_resources is missing"));
    let validator = validator_for_node(&document, node);

    assert!(validator.is_valid(&json!({})), "empty map rejected");
    assert!(
        validator.is_valid(&json!({"a1b2c3d4-e5f6-4789-8abc-d2e3f4a5b6c7": []})),
        "canonical identifier key rejected"
    );
    for key in [
        "A1B2C3D4-E5F6-4789-8ABC-D2E3F4A5B6C7",
        "a1b2c3d4e5f647898abcd2e3f4a5b6c7",
        "resource-primary",
    ] {
        assert!(
            !validator.is_valid(&json!({ key: [] })),
            "schema accepted map key {key} that the decoder rejects"
        );
    }
}

#[test]
fn integer_bounds_agree_between_schema_and_decoder() {
    let document = load("execution-resource.schema.json");
    let node = document
        .pointer("/properties/max_context_tokens")
        .unwrap_or_else(|| panic!("max_context_tokens is missing"));
    let validator = validator_for_node(&document, node);

    for instance in [json!(0), json!(131_072), json!(u64::MAX)] {
        assert!(
            validator.is_valid(&instance),
            "in-range integer {instance} rejected"
        );
        assert!(
            serde_json::from_value::<u64>(instance.clone()).is_ok(),
            "decoder rejected in-range integer {instance}"
        );
    }

    // 2^64 is the first integer the decoder cannot represent. Before this change
    // the schema admitted it, so a schema-validating producer could send a value
    // Politeia would refuse.
    let overflow: Value = serde_json::from_str("18446744073709551616")
        .unwrap_or_else(|error| panic!("parse overflow literal: {error}"));
    assert!(!validator.is_valid(&overflow), "schema accepted 2^64");
    assert!(
        serde_json::from_value::<u64>(overflow).is_err(),
        "decoder accepted 2^64"
    );

    for instance in [json!(-1), json!(1.5)] {
        assert!(!validator.is_valid(&instance), "schema accepted {instance}");
    }
}

#[test]
fn maximum_is_written_losslessly() {
    // `as_u64` returns Some only for an exact unsigned representation, so this
    // proves the published text carries u64::MAX itself rather than the nearest
    // double -- independent of how any validator later compares it.
    let document = load("execution-requirement.schema.json");
    let maximum = document
        .pointer("/properties/minimum_context_tokens/maximum")
        .and_then(Value::as_u64);
    assert_eq!(maximum, Some(u64::MAX));
}

#[test]
fn timestamp_text_agrees_where_both_sides_constrain() {
    let document = load("handoff-receipt.schema.json");
    let mut checked = 0;
    walk(&document.clone(), "", &mut |node, _path| {
        if format_of(node) != Some("date-time") {
            return;
        }
        checked += 1;
        let validator = validator_for_node(&document, node);

        for text in [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.5Z",
            "2026-01-01T00:00:00.123456789Z",
        ] {
            let instance = json!(text);
            assert!(
                validator.is_valid(&instance),
                "canonical timestamp {text} rejected"
            );
            assert!(
                serde_json::from_value::<jiff::Timestamp>(instance).is_ok(),
                "decoder rejected canonical timestamp {text}"
            );
        }

        // Rejected by both: neither side can read these as an instant.
        for text in ["2026-01-01T00:00:00", "not-a-timestamp", ""] {
            let instance = json!(text);
            assert!(!validator.is_valid(&instance), "schema accepted {text}");
            assert!(
                serde_json::from_value::<jiff::Timestamp>(instance).is_err(),
                "decoder accepted {text}"
            );
        }

        // Rejected by the schema only. `jiff` reads these; its printer never
        // writes them. Asserted one-sided on purpose -- claiming decoder
        // agreement here would be false, and narrowing `jiff` means wrapping a
        // foreign type at every timestamp field, which this change does not do.
        for text in [
            "2026-01-01T00:00:00+00:00",
            "2026-01-01t00:00:00z",
            "2026-01-01T00:00:00-04:00",
        ] {
            assert!(
                !validator.is_valid(&json!(text)),
                "schema accepted non-canonical timestamp {text}"
            );
        }
    });
    assert!(
        checked > 0,
        "handoff-receipt has no date-time node to check"
    );
}
