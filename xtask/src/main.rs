//! xtask: repository maintenance tasks (structural checks + spec derivation).

use std::path::Path;

use anyhow::Context;
use schemars::JsonSchema;

const GENERATED_COMMENT: &str = "Authoritative pre-release v1 projection, derived from the Rust types by cargo run -p xtask -- derive. Do not hand-edit.";

/// Canonical textual form `jiff::Timestamp` emits: RFC 3339, UTC, `Z`-suffixed.
///
/// WHY a pattern rather than the `format: "date-time"` schemars already emits:
/// JSON Schema 2020-12 treats `format` as an annotation unless a validator opts
/// into the format-assertion vocabulary, so a schema-only consumer using default
/// settings enforces nothing. `pattern` is core vocabulary and always asserts.
///
/// This is deliberately narrower than what `jiff` will parse. Its reader also
/// accepts numeric offsets, lowercase `z`, and bracketed IANA zone annotations
/// (`2024-03-10T02:05-04[America/New_York]`), none of which its writer ever
/// produces. Those forms are rejected by this schema and accepted by the
/// decoder -- a one-sided asymmetry, recorded rather than closed: `Timestamp` is
/// foreign, so narrowing its decoder would mean wrapping it at every timestamp
/// field across three crates, which is beyond this projection's scope.
const TIMESTAMP_TEXT_PATTERN: &str = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$";

/// True when a schema node admits the JSON string type.
///
/// WARNING: `type` is a string for a required field and an array for an
/// `Option`, so a `== "string"` test silently skips every nullable node. One
/// `Option<Timestamp>` exists today (`CommissionerGrantRecord::revoked_at`) and
/// would keep annotation-only enforcement under the simpler test.
fn schema_admits_string(schema: &schemars::Schema) -> bool {
    match schema.get("type") {
        Some(serde_json::Value::String(kind)) => kind == "string",
        Some(serde_json::Value::Array(kinds)) => {
            kinds.iter().any(|kind| kind.as_str() == Some("string"))
        }
        _ => false,
    }
}

/// Stamp the canonical RFC 3339 pattern onto any `date-time` node lacking one.
fn constrain_date_time(schema: &mut schemars::Schema) {
    let is_date_time = schema_admits_string(schema)
        && schema.get("format").and_then(serde_json::Value::as_str) == Some("date-time");
    if is_date_time && schema.get("pattern").is_none() {
        schema.insert(
            "pattern".to_string(),
            serde_json::Value::String(TIMESTAMP_TEXT_PATTERN.to_string()),
        );
    }
}

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
    let generator = schemars::generate::SchemaSettings::draft2020_12()
        .with_transform(schemars::transform::RecursiveTransform(constrain_date_time))
        .into_generator();
    let mut value = serde_json::to_value(generator.into_root_schema_for::<T>())?;
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

fn generated_specs() -> anyhow::Result<Vec<DerivedSpec>> {
    Ok(vec![
        render_schema::<politeia_sdk::ExtensionManifest>(
            "spec/extension-manifest.schema.json",
            "urn:politeia:extension-manifest:v1",
        )?,
        render_schema::<politeia_runtime::OperationIntent>(
            "spec/semantic-operation.schema.json",
            "urn:politeia:semantic-operation:v1",
        )?,
        render_schema::<politeia_core::institution::InstitutionWorkspace>(
            "spec/institution-workspace.schema.json",
            "urn:politeia:institution-workspace:v1",
        )?,
        render_schema::<politeia_evidence::CommissioningRecord>(
            "spec/commissioning-record.schema.json",
            "urn:politeia:commissioning-record:v1",
        )?,
        render_schema::<politeia_core::generation::RuntimeGeneration>(
            "spec/runtime-generation.schema.json",
            "urn:politeia:runtime-generation:v1",
        )?,
        render_schema::<politeia_runtime::routing::ExecutionResource>(
            "spec/execution-resource.schema.json",
            "urn:politeia:execution-resource:v1",
        )?,
        render_schema::<politeia_runtime::routing::ExecutionRequirement>(
            "spec/execution-requirement.schema.json",
            "urn:politeia:execution-requirement:v1",
        )?,
        render_schema::<politeia_runtime::routing::CapabilityProfile>(
            "spec/capability-profile.schema.json",
            "urn:politeia:capability-profile:v1",
        )?,
        render_schema::<politeia_runtime::routing::CapabilityVerificationRecord>(
            "spec/capability-verification.schema.json",
            "urn:politeia:capability-verification:v1",
        )?,
        render_schema::<politeia_runtime::routing::AvailabilitySnapshot>(
            "spec/availability-snapshot.schema.json",
            "urn:politeia:availability-snapshot:v1",
        )?,
        render_schema::<politeia_runtime::routing::RoutingDecision>(
            "spec/routing-decision.schema.json",
            "urn:politeia:routing-decision:v1",
        )?,
        render_schema::<politeia_core::lifecycle::LifecycleTransition>(
            "spec/lifecycle-transition.schema.json",
            "urn:politeia:lifecycle-transition:v1",
        )?,
        render_schema::<politeia_evidence::HandoffReceipt>(
            "spec/handoff-receipt.schema.json",
            "urn:politeia:handoff-receipt:v1",
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
