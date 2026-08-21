//! xtask: repository maintenance tasks (structural checks + spec derivation).

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context;
use schemars::JsonSchema;

const GENERATED_COMMENT: &str = "Authoritative pre-release v1 projection, derived from the Rust types by cargo run -p xtask -- derive. Do not hand-edit.";

/// Directory holding every published projection.
const SPEC_DIR: &str = "spec";

/// Suffix identifying a generated schema, as opposed to a hand-authored file.
const SCHEMA_SUFFIX: &str = ".schema.json";

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
    urn: String,
    bytes: Vec<u8>,
}

/// The published identity a projection carries, derived from where it is published.
///
/// WHY derived rather than declared beside the path: the file stem and the URN
/// segment are the same fact. Written as a pair they can disagree, and a schema
/// published under another schema's identity is not a defect any test here would
/// have caught -- the bytes are internally consistent and both strings look
/// plausible. Deriving removes the disagreement rather than checking for it.
fn published_urn(path: &str) -> anyhow::Result<String> {
    let name = Path::new(path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .with_context(|| format!("schema path has no file name: {path}"))?;
    let stem = name
        .strip_suffix(SCHEMA_SUFFIX)
        .with_context(|| format!("schema path must end in {SCHEMA_SUFFIX}: {path}"))?;
    anyhow::ensure!(!stem.is_empty(), "schema path has an empty stem: {path}");
    Ok(format!("urn:politeia:{stem}:v1"))
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

fn render_schema<T: JsonSchema>(path: &'static str) -> anyhow::Result<DerivedSpec> {
    let urn = published_urn(path)?;
    let generator = schemars::generate::SchemaSettings::draft2020_12()
        .with_transform(schemars::transform::RecursiveTransform(constrain_date_time))
        .into_generator();
    let mut value = serde_json::to_value(generator.into_root_schema_for::<T>())?;
    let object = value.as_object_mut().context("schema root is an object")?;
    object.insert("$id".to_string(), serde_json::Value::String(urn.clone()));
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
        render_schema::<politeia_sdk::ExtensionManifest>("spec/extension-manifest.schema.json")?,
        render_schema::<politeia_runtime::OperationIntent>("spec/semantic-operation.schema.json")?,
        render_schema::<politeia_core::institution::InstitutionWorkspace>(
            "spec/institution-workspace.schema.json",
        )?,
        render_schema::<politeia_evidence::CommissioningRecord>(
            "spec/commissioning-record.schema.json",
        )?,
        render_schema::<politeia_core::generation::RuntimeGeneration>(
            "spec/runtime-generation.schema.json",
        )?,
        render_schema::<politeia_runtime::routing::ExecutionResource>(
            "spec/execution-resource.schema.json",
        )?,
        render_schema::<politeia_runtime::routing::ExecutionRequirement>(
            "spec/execution-requirement.schema.json",
        )?,
        render_schema::<politeia_runtime::routing::CapabilityProfile>(
            "spec/capability-profile.schema.json",
        )?,
        render_schema::<politeia_runtime::routing::CapabilityVerificationRecord>(
            "spec/capability-verification.schema.json",
        )?,
        render_schema::<politeia_runtime::routing::AvailabilitySnapshot>(
            "spec/availability-snapshot.schema.json",
        )?,
        render_schema::<politeia_runtime::routing::RoutingDecision>(
            "spec/routing-decision.schema.json",
        )?,
        render_schema::<politeia_core::lifecycle::LifecycleTransition>(
            "spec/lifecycle-transition.schema.json",
        )?,
        render_schema::<politeia_evidence::HandoffReceipt>("spec/handoff-receipt.schema.json")?,
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

    let specs = generated_specs()?;
    for spec in &specs {
        let checked_in = std::fs::read(spec.path)
            .with_context(|| format!("read checked-in schema {}", spec.path))?;
        anyhow::ensure!(
            checked_in == spec.bytes,
            "{} is stale; run cargo run -p xtask -- derive",
            spec.path
        );
    }
    reject_unowned_schemas(&specs, Path::new(SPEC_DIR))?;

    println!(
        "starter structural checks passed; {} published schemas, none unowned",
        specs.len()
    );
    Ok(())
}

/// Fail when `spec/` holds a generated schema that no Rust owner declares.
///
/// WHY this is a separate pass: the freshness loop walks the declared population
/// and reads each file, so it catches a declared schema whose file is missing.
/// It cannot catch the opposite, because a file nobody declares is a file it
/// never looks at. That is the direction a deleted owner leaves behind -- the
/// projection stays published, stays byte-identical to itself forever, and every
/// check keeps passing while it describes a type the product no longer has.
///
/// Membership is derived from the directory rather than from a second list, so
/// adding a projection cannot also require remembering to register it here.
fn reject_unowned_schemas(specs: &[DerivedSpec], spec_dir: &Path) -> anyhow::Result<()> {
    let declared: BTreeSet<&str> = specs.iter().map(|spec| spec.path).collect();

    let entries = std::fs::read_dir(spec_dir)
        .with_context(|| format!("read the published schema directory {}", spec_dir.display()))?;
    for entry in entries {
        let path = entry
            .with_context(|| format!("read an entry of {}", spec_dir.display()))?
            .path();
        let name = path.file_name().and_then(std::ffi::OsStr::to_str);
        // Only generated projections are owned. Hand-authored companions such as
        // `policy-lifecycle.yaml` live here legitimately and have no Rust owner
        // to find, so the suffix -- not the directory -- decides membership.
        let Some(name) = name.filter(|name| name.ends_with(SCHEMA_SUFFIX)) else {
            continue;
        };
        let relative = format!("{SPEC_DIR}/{name}");
        anyhow::ensure!(
            declared.contains(relative.as_str()),
            "{relative} is published but no Rust type declares it; \
             either restore its owner in generated_specs() or delete the file"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published directory, resolved from the manifest rather than the
    /// working directory: `cargo test` runs from the package root, where a bare
    /// `spec/` does not exist.
    fn published_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(SPEC_DIR)
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the derivation must succeed for a path this repository actually publishes"
    )]
    fn published_identity_is_derived_from_the_publication_path() {
        assert_eq!(
            published_urn("spec/routing-decision.schema.json")
                .expect("a well-formed publication path yields an identity"),
            "urn:politeia:routing-decision:v1"
        );
    }

    #[test]
    fn a_path_that_is_not_a_published_schema_has_no_identity() {
        // The derivation must be able to refuse. A function that answers for any
        // input would hand `policy-lifecycle.yaml` an identity it has no right to.
        for path in [
            "spec/policy-lifecycle.yaml",
            "spec/routing-decision.json",
            "spec/.schema.json",
            "spec",
        ] {
            assert!(
                published_urn(path).is_err(),
                "{path} must not be given a published identity"
            );
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a population that cannot render or a directory that cannot be read is a broken fixture, not a finding"
    )]
    fn every_published_schema_has_exactly_one_owner() {
        let specs = generated_specs().expect("the authoritative schemas must render");

        let declared: BTreeSet<&str> = specs.iter().map(|spec| spec.path).collect();
        assert_eq!(
            declared.len(),
            specs.len(),
            "two owners declare the same publication path"
        );

        let mut on_disk = BTreeSet::new();
        for entry in std::fs::read_dir(published_dir()).expect("the published directory must exist")
        {
            let path = entry
                .expect("a published directory entry must be readable")
                .path();
            let name = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(str::to_owned);
            if let Some(name) = name.filter(|name| name.ends_with(SCHEMA_SUFFIX)) {
                on_disk.insert(format!("{SPEC_DIR}/{name}"));
            }
        }

        let declared_owned: BTreeSet<String> =
            declared.iter().map(|path| (*path).to_owned()).collect();
        assert_eq!(
            declared_owned, on_disk,
            "the declared population and the published files must be the same set"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the mutation needs a rendered population to remove one member from"
    )]
    fn an_unowned_schema_is_rejected() {
        // The guard is an absence check, so it passes trivially unless it is shown
        // failing. Dropping one owner makes its still-published file unowned --
        // exactly the state a deleted Rust type leaves behind.
        let mut specs = generated_specs().expect("the authoritative schemas must render");
        let orphaned = specs.pop().expect("the population is not empty");

        let result = reject_unowned_schemas(&specs, &published_dir());
        let error = result.expect_err("a published schema with no owner must be rejected");
        assert!(
            error.to_string().contains(orphaned.path),
            "the refusal must name the unowned file, got: {error}"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the positive control fails the fixture, not the assertion, if rendering breaks"
    )]
    fn the_full_population_is_accepted() {
        let specs = generated_specs().expect("the authoritative schemas must render");
        reject_unowned_schemas(&specs, &published_dir())
            .expect("every published schema is owned by the full population");
    }

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
                Some(left.urn.as_str()),
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
