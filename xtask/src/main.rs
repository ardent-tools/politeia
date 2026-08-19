//! xtask: repository maintenance tasks (structural checks + spec derivation).

use std::path::Path;

use anyhow::Context;
use schemars::JsonSchema;

const GENERATED_COMMENT: &str = "First authoritative pre-release v1 projection, derived from the Rust types by cargo run -p xtask -- derive. The earlier starter schema was non-authoritative. Do not hand-edit.";

struct DerivedSpec {
    path: &'static str,
    urn: &'static str,
    bytes: Vec<u8>,
}

fn main() -> anyhow::Result<()> {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    match arg.as_str() {
        "derive" => derive(),
        "check" => check(),
        _ => {
            println!("usage: cargo run -p xtask -- [derive|check]");
            Ok(())
        }
    }
}

fn render_schema<T: JsonSchema>(
    path: &'static str,
    urn: &'static str,
) -> anyhow::Result<DerivedSpec> {
    let mut value = serde_json::to_value(schemars::schema_for!(T))?;
    let object = value.as_object_mut().context("schema root is an object")?;
    object.insert(
        "$id".to_string(),
        serde_json::Value::String(urn.to_string()),
    );
    object.insert(
        "$comment".to_string(),
        serde_json::Value::String(GENERATED_COMMENT.to_string()),
    );
    let mut bytes = serde_json::to_vec_pretty(&value)?;
    bytes.push(b'\n');
    Ok(DerivedSpec { path, urn, bytes })
}

fn generated_specs() -> anyhow::Result<[DerivedSpec; 2]> {
    Ok([
        render_schema::<politeia_sdk::ExtensionManifest>(
            "spec/extension-manifest.schema.json",
            "urn:politeia:extension-manifest:v1",
        )?,
        render_schema::<politeia_runtime::OperationIntent>(
            "spec/semantic-operation.schema.json",
            "urn:politeia:semantic-operation:v1",
        )?,
    ])
}

/// Emit public JSON schemas from their authoritative Rust types.
fn derive() -> anyhow::Result<()> {
    for spec in generated_specs()? {
        std::fs::write(spec.path, spec.bytes)
            .with_context(|| format!("write derived schema {}", spec.path))?;
        println!("derived {} ({})", spec.path, spec.urn);
    }
    Ok(())
}

/// Check structural invariants and exact generated-schema freshness without mutation.
fn check() -> anyhow::Result<()> {
    for required in [
        "docs/02-CONSTITUTION.md",
        "docs/03-ONTOLOGY.md",
        "docs/04-KERNEL_CONTRACT.md",
        "docs/18-FIRST_VERTICAL_SLICE.md",
    ] {
        anyhow::ensure!(Path::new(required).exists(), "missing {required}");
    }

    for spec in generated_specs()? {
        let checked_in = std::fs::read(spec.path)
            .with_context(|| format!("read checked-in schema {}", spec.path))?;
        anyhow::ensure!(
            checked_in == spec.bytes,
            "{} is stale; run cargo run -p xtask -- derive",
            spec.path
        );
    }
    println!("starter structural and generated-schema checks passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "generator invariants require both valid deterministic render passes"
    )]
    fn schema_rendering_is_deterministic_and_fail_closed() {
        let first = generated_specs().expect("the authoritative schemas must render");
        let second = generated_specs().expect("a repeated schema render must succeed");

        for (left, right) in first.iter().zip(second.iter()) {
            assert_eq!(
                left.bytes, right.bytes,
                "schema rendering must be a fixed point for {}",
                left.path
            );
            assert_eq!(
                left.bytes.last(),
                Some(&b'\n'),
                "generated schema must end in one canonical newline"
            );
            let value: serde_json::Value = serde_json::from_slice(&left.bytes)
                .expect("generated schema bytes must be valid JSON");
            assert_eq!(
                value.get("$id").and_then(serde_json::Value::as_str),
                Some(left.urn),
                "generated schema must retain its published identity"
            );
            assert_eq!(
                value.get("additionalProperties"),
                Some(&serde_json::Value::Bool(false)),
                "generated wire schemas must reject unknown root fields"
            );
        }
    }
}
