//! xtask: repository maintenance tasks (structural checks + spec derivation).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::Context;
use schemars::JsonSchema;

const GENERATED_COMMENT: &str = "Authoritative pre-release v1 projection, derived from the Rust types by cargo run -p xtask -- derive. Do not hand-edit.";

/// Directory holding every published projection.
const SPEC_DIR: &str = "spec";

/// Suffix identifying a generated schema, as opposed to another projection.
const SCHEMA_SUFFIX: &str = ".schema.json";

/// Where the progressive-hardening ladder is published.
const POLICY_LIFECYCLE_PATH: &str = "spec/policy-lifecycle.yaml";

/// Where the canonical-encoding reference vectors are published.
const CANONICAL_VECTORS_PATH: &str = "spec/canonical-vectors.json";

/// Format version of the published ladder table.
///
/// This versions the *document shape* -- the `states`/`transitions` layout --
/// not the ladder. A rung added or an edge changed leaves this at 1; a consumer
/// reading `states` and `transitions` keeps working. It moves only when those
/// keys mean something else.
const POLICY_LIFECYCLE_VERSION: u32 = 1;

/// Tokens a YAML scalar may carry without quoting, and which cannot be read as
/// a boolean, null, or number.
///
/// WHY the generator asserts this rather than quoting defensively: quoting
/// everything would emit a table that no longer matches the hand-authored one
/// it replaces, and reviewing that diff would mean reading past the quotes to
/// find the real change. Asserting instead means a rung named `no` or `on`
/// fails the derivation, where it is a two-line fix, rather than shipping a
/// table a YAML reader parses into `false`.
fn is_plain_yaml_scalar(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '_')
}

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
    type_name: &'static str,
    bytes: Vec<u8>,
}

/// A published projection that is not a JSON Schema.
///
/// It carries no URN because it describes a relation rather than a record
/// shape, and `published_urn` deliberately refuses to mint an identity for one.
struct DerivedTable {
    path: &'static str,
    owner: &'static str,
    bytes: Vec<u8>,
}

/// A schema-bearing type deliberately absent from the published population.
struct WithheldSchema {
    type_name: &'static str,
    reason: &'static str,
}

/// Types that derive `JsonSchema` and are deliberately not projected.
///
/// WHY this list exists at all: a type that is simply missing from
/// `generated_specs()` and a type that was considered and held back look
/// identical from outside — both are absent — so absence alone records no
/// decision and a reader cannot tell an intention from an oversight.
///
/// Several of these are hardened and wire-tested exactly as the published roots
/// are, which is what makes their absence read as an oversight rather than a
/// choice. The choice is `AGENTS.md`'s: *do not add production breadth before
/// the first vertical slice is complete*. Publishing a projection is public
/// surface, and this scaffold has not earned more of it yet.
///
/// LIMIT, stated because the list looks more complete than it is: nothing here
/// proves the list is total. Rust offers no way to enumerate every `JsonSchema`
/// implementor, so a type added tomorrow appears in neither population and
/// nothing fails. Deriving membership mechanically is #9's authoritative-selector
/// work, and it is Phase 5.
const WITHHELD_SCHEMAS: &[WithheldSchema] = &[
    WithheldSchema {
        type_name: "politeia_policy::NormativeClause",
        reason: "policy authoring surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_policy::DetectorSpec",
        reason: "policy authoring surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_policy::PolicyBinding",
        reason: "policy authoring surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_policy::Waiver",
        reason: "policy authoring surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_policy::PolicyDecision",
        reason: "produced per authorization; no consumer reads it off the wire yet",
    },
    WithheldSchema {
        type_name: "politeia_sdk::DiscoveryProbe",
        reason: "reconnaissance authoring surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_core::outbox::OutboxDeclaration",
        reason: "institution boundary declaration; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_core::outbox::BoundaryCrossing",
        reason: "institution boundary declaration; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_core::outbox::Adjudication",
        reason: "produced per crossing; no consumer reads it off the wire yet",
    },
    WithheldSchema {
        type_name: "politeia_core::outbox::Sink",
        reason: "projected as part of OutboxDeclaration; no standalone wire consumer",
    },
    WithheldSchema {
        type_name: "politeia_core::outbox::SinkKind",
        reason: "projected as part of Sink; no standalone wire consumer",
    },
    WithheldSchema {
        type_name: "politeia_core::outbox::DenialReason",
        reason: "projected as part of Adjudication; no standalone wire consumer",
    },
    WithheldSchema {
        type_name: "politeia_core::knowledge::Observation",
        reason: "commissioning knowledge surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_core::knowledge::CandidateClaim",
        reason: "commissioning knowledge surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_core::knowledge::FactApproval",
        reason: "owner-approval surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_core::knowledge::ClaimStatus",
        reason: "projected as part of CandidateClaim; no standalone consumer reads it off the wire",
    },
    WithheldSchema {
        type_name: "politeia_core::knowledge::Support",
        reason: "projected as part of CandidateClaim; no standalone consumer reads it off the wire",
    },
    WithheldSchema {
        type_name: "politeia_core::reconnaissance::ReconnaissanceScope",
        reason: "commissioning authority surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_evidence::assessment::AssessmentRelation",
        reason: "correction/supersession authoring surface; publication waits on the first vertical slice",
    },
    WithheldSchema {
        type_name: "politeia_evidence::assessment::RelationKind",
        reason: "projected as part of AssessmentRelation; no standalone consumer reads it off the wire",
    },
    WithheldSchema {
        type_name: "politeia_evidence::Verification",
        reason: "independent-verification record; published with the assurance path, not before",
    },
    WithheldSchema {
        type_name: "politeia_evidence::Attestation",
        reason: "attestation record; published with the assurance path, not before",
    },
    WithheldSchema {
        type_name: "politeia_protocol::SemanticRequest",
        reason: "transport envelope; the payload is published, the envelope follows a transport",
    },
    WithheldSchema {
        type_name: "politeia_protocol::SemanticResponse",
        reason: "transport envelope; the payload is published, the envelope follows a transport",
    },
];

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
    Ok(DerivedSpec {
        path,
        urn,
        type_name: std::any::type_name::<T>(),
        bytes,
    })
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

/// The serde token a rung is published under.
///
/// Derived from `Serialize` rather than restated, so the table and the wire
/// format cannot disagree about what a rung is called.
fn rung_token(state: politeia_policy::hardening::HardeningState) -> anyhow::Result<String> {
    let value = serde_json::to_value(state)?;
    let token = value
        .as_str()
        .with_context(|| format!("{state:?} must serialize as a string"))?;
    anyhow::ensure!(
        is_plain_yaml_scalar(token),
        "rung `{token}` needs YAML quoting; the ladder projection emits plain scalars"
    );
    Ok(token.to_string())
}

/// Project the progressive-hardening ladder as a published transition table.
fn render_policy_lifecycle() -> anyhow::Result<DerivedTable> {
    use politeia_policy::hardening::HardeningState;

    let mut text = String::new();
    writeln!(text, "# {GENERATED_COMMENT}")?;
    writeln!(text, "version: {POLICY_LIFECYCLE_VERSION}")?;

    writeln!(text, "states:")?;
    for state in HardeningState::all() {
        writeln!(text, "  - {}", rung_token(state)?)?;
    }

    writeln!(text, "transitions:")?;
    for state in HardeningState::all() {
        let from = rung_token(state)?;
        for next in state.successors() {
            writeln!(text, "  - [{from}, {}]", rung_token(*next)?)?;
        }
    }

    Ok(DerivedTable {
        path: POLICY_LIFECYCLE_PATH,
        owner: std::any::type_name::<HardeningState>(),
        bytes: text.into_bytes(),
    })
}

/// Inputs whose canonical encoding is worth publishing, one per rule.
///
/// WHY the rules rather than the product records: a foreign implementation
/// needs to know how *this* encoder orders keys, spells integers and escapes
/// strings, and it can check that without holding any politeia type. A vector
/// over `OperationIntent` would test the reader's model of that struct at the
/// same time and fail for either reason.
fn canonical_vectors() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "object_keys_sort_by_unicode_scalar",
            serde_json::json!({"b": 1, "A": 2, "a": 3, "\u{00e1}": 4}),
        ),
        (
            "nesting_sorts_at_every_depth",
            serde_json::json!({"outer": {"z": 1, "a": [{"y": 1, "x": 2}]}}),
        ),
        (
            "arrays_keep_their_order",
            serde_json::json!({"sequence": [3, 1, 2]}),
        ),
        (
            "null_is_encoded_rather_than_omitted",
            serde_json::json!({"absent": null, "present": 1}),
        ),
        (
            "integers_at_the_type_boundary",
            serde_json::json!({"max": u64::MAX, "min": i64::MIN, "zero": 0}),
        ),
        (
            "strings_carry_the_encoder_escaping",
            serde_json::json!({"quote": "a\"b", "tab": "a\tb", "unicode": "\u{1f600}"}),
        ),
        (
            "an_empty_object_and_an_empty_array",
            serde_json::json!({"object": {}, "array": []}),
        ),
    ]
}

/// Inputs the canonical encoder must refuse, with the reason.
///
/// A vector file listing only what encodes describes half a contract. An
/// implementation that happily encoded a float would match every accepted
/// vector and disagree about the one case where two correct encoders can
/// produce different bytes for one value.
fn canonical_refusals() -> Vec<(&'static str, serde_json::Value, &'static str)> {
    vec![
        (
            "a_float_has_no_canonical_text",
            serde_json::json!({"ratio": 1.5}),
            "floats have several spellings of one value and no single canonical text",
        ),
        (
            "a_float_nested_in_an_array",
            serde_json::json!({"samples": [1, 2.0]}),
            "the refusal reaches every position, not only the top level",
        ),
    ]
}

/// Project the canonical-encoding rules as reference vectors.
fn render_canonical_vectors() -> anyhow::Result<DerivedTable> {
    let mut accepted = Vec::new();
    for (name, value) in canonical_vectors() {
        let bytes = politeia_core::canonical::to_canonical_bytes(&value)
            .with_context(|| format!("canonical vector {name} must encode"))?;
        let canonical = String::from_utf8(bytes.clone())
            .with_context(|| format!("canonical vector {name} must be UTF-8"))?;
        accepted.push(serde_json::json!({
            "name": name,
            "value": value,
            "canonical": canonical,
            "blake3": politeia_core::Digest::blake3(&bytes).as_str(),
        }));
    }

    let mut refused = Vec::new();
    for (name, value, reason) in canonical_refusals() {
        anyhow::ensure!(
            politeia_core::canonical::to_canonical_bytes(&value).is_err(),
            "refusal vector {name} was accepted; the published contract would be wrong"
        );
        refused.push(serde_json::json!({
            "name": name,
            "value": value,
            "reason": reason,
        }));
    }

    let document = serde_json::json!({
        "$comment": GENERATED_COMMENT,
        "rules": [
            "object members are emitted in ascending order of their keys' Unicode scalar values",
            "no whitespace appears between tokens",
            "array order is preserved; arrays are sequences, not sets",
            "a null member is emitted, not omitted",
            "numbers are integers; a float is refused rather than given a spelling",
            "strings use the JSON escaping the accompanying canonical text shows",
        ],
        "digest": "blake3 over the canonical bytes, lowercase hexadecimal",
        "accepted": accepted,
        "refused": refused,
    });
    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');

    Ok(DerivedTable {
        path: CANONICAL_VECTORS_PATH,
        owner: "politeia_core::canonical::to_canonical_bytes",
        bytes,
    })
}

/// Every published projection that is not a JSON Schema.
fn generated_tables() -> anyhow::Result<Vec<DerivedTable>> {
    Ok(vec![
        render_policy_lifecycle()?,
        render_canonical_vectors()?,
    ])
}

/// Emit public projections from their authoritative Rust types.
fn derive() -> anyhow::Result<()> {
    for spec in generated_specs()? {
        std::fs::write(spec.path, spec.bytes)
            .with_context(|| format!("write derived schema {}", spec.path))?;
        println!("derived {} ({})", spec.path, spec.urn);
    }
    for table in generated_tables()? {
        std::fs::write(table.path, table.bytes)
            .with_context(|| format!("write derived table {}", table.path))?;
        println!("derived {} ({})", table.path, table.owner);
    }
    Ok(())
}

/// A count with its noun, pluralised.
fn counted(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
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

    let tables = generated_tables()?;
    for table in &tables {
        let checked_in = std::fs::read(table.path)
            .with_context(|| format!("read checked-in table {}", table.path))?;
        anyhow::ensure!(
            checked_in == table.bytes,
            "{} is stale; run cargo run -p xtask -- derive",
            table.path
        );
    }

    reject_maintainer_notes_in_published_descriptions(&specs)?;
    reject_unowned_publications(&specs, &tables, Path::new(SPEC_DIR))?;
    reject_contradictory_population(&specs)?;

    println!(
        "starter structural checks passed; {} and {}, none unowned; \
         {} recorded as withheld",
        counted(specs.len(), "published schema"),
        counted(tables.len(), "published table"),
        counted(WITHHELD_SCHEMAS.len(), "schema-bearing type")
    );
    Ok(())
}

/// The bare type name, without its module path.
///
/// WHY compare on this rather than the full path: `std::any::type_name` reports
/// where a type is *defined*, while a withheld entry is written where the type is
/// *used from*, and re-exports make those differ. Matching on the last segment
/// keeps the check honest about the case it exists for — one type claimed by both
/// populations — at the cost of a false positive if two crates ever define types
/// of the same name and one is published. That direction fails loudly and is the
/// safe one.
fn bare_type_name(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

/// Fail when a type is both published and recorded as withheld.
///
/// The two lists are the whole of the recorded decision, so a type appearing in
/// both means the record contradicts itself and neither entry can be trusted.
/// This is the case that actually arises: publishing a withheld type is a normal
/// step, and forgetting to strike it from the withheld list leaves a reason
/// standing that argues against something already done.
fn reject_contradictory_population(specs: &[DerivedSpec]) -> anyhow::Result<()> {
    let published: BTreeSet<&str> = specs
        .iter()
        .map(|spec| bare_type_name(spec.type_name))
        .collect();

    let mut seen = BTreeSet::new();
    for withheld in WITHHELD_SCHEMAS {
        let bare = bare_type_name(withheld.type_name);
        anyhow::ensure!(
            !withheld.reason.trim().is_empty(),
            "{} is withheld with no reason; an unexplained exclusion records nothing",
            withheld.type_name
        );
        anyhow::ensure!(
            seen.insert(bare),
            "{} is recorded as withheld twice",
            withheld.type_name
        );
        anyhow::ensure!(
            !published.contains(bare),
            "{} is published and also recorded as withheld; \
             strike it from WITHHELD_SCHEMAS",
            withheld.type_name
        );
    }
    Ok(())
}

/// Structured tags this repository uses to mark maintainer reasoning.
///
/// `STANDARDS.md` reserves these for notes to whoever maintains the code. A
/// schema `description` is read by whoever consumes the wire format, and they
/// are different audiences with different questions.
const MAINTAINER_TAGS: &[&str] = &[
    "WHY ",
    "WARNING:",
    "NOTE ",
    "PERF",
    "SAFETY",
    "INVARIANT",
    "TODO(",
    "FIXME(",
];

/// Fail when a published description carries a note meant for a maintainer.
///
/// WHY this exists: `schemars` projects a type's doc comment verbatim into
/// `description`, so a `///` on a schema-bearing type is public API. That is
/// easy to forget while writing, because the comment reads as ordinary source
/// commentary right up until it is published -- and this repository's own
/// convention is to put substantial reasoning in doc comments.
///
/// It was found the expensive way: a paragraph explaining which Rust crate a
/// type should live in was projected into three published schemas, where it
/// told schema consumers something they cannot act on. The derived-spec check
/// caught the bytes changing; nothing said the new bytes were wrong.
///
/// The rule is narrow on purpose. It does not police prose -- only the tags
/// this repository already reserves for maintainer notes, which is exactly the
/// material that has no consumer meaning.
fn reject_maintainer_notes_in_published_descriptions(specs: &[DerivedSpec]) -> anyhow::Result<()> {
    for spec in specs {
        let document: serde_json::Value = serde_json::from_slice(&spec.bytes)
            .with_context(|| format!("parse derived schema {}", spec.path))?;
        let mut found = Vec::new();
        collect_descriptions(&document, &mut found);
        for description in found {
            for tag in MAINTAINER_TAGS {
                anyhow::ensure!(
                    !description.contains(tag),
                    "{} publishes a description containing the maintainer tag `{}`; \
                     a doc comment on a schema-bearing type is read by wire-format \
                     consumers, so maintainer reasoning belongs in a `//` comment: {}",
                    spec.path,
                    tag.trim(),
                    description.lines().next().unwrap_or(&description)
                );
            }
        }
    }
    Ok(())
}

/// Every `description` string anywhere in a schema document.
fn collect_descriptions(value: &serde_json::Value, into: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(members) => {
            for (key, member) in members {
                if key == "description" {
                    if let Some(text) = member.as_str() {
                        into.push(text.to_string());
                    }
                }
                collect_descriptions(member, into);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_descriptions(item, into);
            }
        }
        _ => {}
    }
}

/// Fail when `spec/` holds a file no Rust owner declares.
///
/// WHY this is a separate pass: the freshness loops walk the declared
/// population and read each file, so they catch a declared projection whose
/// file is missing. They cannot catch the opposite, because a file nobody
/// declares is a file they never look at. That is the direction a deleted owner
/// leaves behind -- the projection stays published, stays byte-identical to
/// itself forever, and every check keeps passing while it describes a type the
/// product no longer has.
///
/// WHY the whole directory decides membership, rather than the schema suffix:
/// every file here is now derived, so `spec/` can mean *published projection*
/// without qualification. While the ladder table was hand-authored the suffix
/// had to decide, and the cost was that the one file with no owner was also the
/// one file this check could not see. An unowned hand-authored file in a
/// directory of generated ones reads as a projection without being one, and
/// nothing but a reader's care distinguished them.
///
/// Membership is derived from the directory rather than from a second list, so
/// adding a projection cannot also require remembering to register it here.
fn reject_unowned_publications(
    specs: &[DerivedSpec],
    tables: &[DerivedTable],
    spec_dir: &Path,
) -> anyhow::Result<()> {
    let declared: BTreeSet<&str> = specs
        .iter()
        .map(|spec| spec.path)
        .chain(tables.iter().map(|table| table.path))
        .collect();

    let entries = std::fs::read_dir(spec_dir).with_context(|| {
        format!(
            "read the published projection directory {}",
            spec_dir.display()
        )
    })?;
    for entry in entries {
        let path = entry
            .with_context(|| format!("read an entry of {}", spec_dir.display()))?
            .path();
        let name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .with_context(|| format!("{} has no readable name", path.display()))?;
        let relative = format!("{SPEC_DIR}/{name}");
        anyhow::ensure!(
            declared.contains(relative.as_str()),
            "{relative} is published but nothing derives it; \
             either restore its owner in generated_specs()/generated_tables() or delete the file"
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
    fn every_published_file_has_exactly_one_owner() {
        let specs = generated_specs().expect("the authoritative schemas must render");
        let tables = generated_tables().expect("the authoritative tables must render");

        let declared: BTreeSet<&str> = specs
            .iter()
            .map(|spec| spec.path)
            .chain(tables.iter().map(|table| table.path))
            .collect();
        assert_eq!(
            declared.len(),
            specs.len() + tables.len(),
            "two owners declare the same publication path"
        );

        // WHY every entry, unfiltered: the suffix filter this once carried made
        // the set comparison blind to precisely the file that had no owner, so
        // the strongest-looking assertion in the file could not see the one
        // discrepancy that existed.
        let mut on_disk = BTreeSet::new();
        for entry in std::fs::read_dir(published_dir()).expect("the published directory must exist")
        {
            let path = entry
                .expect("a published directory entry must be readable")
                .path();
            let name = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .expect("a published file has a readable name")
                .to_owned();
            on_disk.insert(format!("{SPEC_DIR}/{name}"));
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
    fn an_unowned_publication_is_rejected() {
        // The guard is an absence check, so it passes trivially unless it is shown
        // failing. Dropping one owner makes its still-published file unowned --
        // exactly the state a deleted Rust type leaves behind.
        let mut specs = generated_specs().expect("the authoritative schemas must render");
        let tables = generated_tables().expect("the authoritative tables must render");
        let orphaned = specs.pop().expect("the population is not empty");

        let result = reject_unowned_publications(&specs, &tables, &published_dir());
        let error = result.expect_err("a published schema with no owner must be rejected");
        assert!(
            error.to_string().contains(orphaned.path),
            "the refusal must name the unowned file, got: {error}"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the mutation needs a rendered population to remove one member from"
    )]
    fn an_unowned_table_is_rejected() {
        // The same mutation from the other population. Without this, dropping
        // table ownership from the check would leave `an_unowned_publication_is_rejected`
        // passing on the schema half alone.
        let specs = generated_specs().expect("the authoritative schemas must render");
        let mut tables = generated_tables().expect("the authoritative tables must render");
        let orphaned = tables.pop().expect("the table population is not empty");

        let result = reject_unowned_publications(&specs, &tables, &published_dir());
        let error = result.expect_err("a published table with no owner must be rejected");
        assert!(
            error.to_string().contains(orphaned.path),
            "the refusal must name the unowned file, got: {error}"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the projection must render for a repository that publishes it"
    )]
    fn the_published_ladder_lists_every_rung_and_edge() {
        // The projection is a loop over `all()` and `successors()`, so it agrees
        // with itself by construction. What it cannot check is that it emitted
        // anything: an empty `states:` block is valid YAML and a silent lie.
        use politeia_policy::hardening::HardeningState;

        let table = render_policy_lifecycle().expect("the ladder projection must render");
        let text = String::from_utf8(table.bytes).expect("the table is UTF-8");

        let states = HardeningState::all();
        let edges: usize = states.iter().map(|state| state.successors().len()).sum();
        assert_eq!(
            text.matches("\n  - ").count(),
            states.len() + edges,
            "the table lists a different number of entries than the ladder declares:\n{text}"
        );
        assert!(
            text.contains("  - [advisory, enforced]"),
            "the edge progressive hardening is named for is missing:\n{text}"
        );
        assert!(
            !text.contains("  - [unknown, enforced]"),
            "the table publishes a shortcut the ladder refuses:\n{text}"
        );
    }

    #[test]
    fn every_withheld_type_carries_a_reason() {
        for withheld in WITHHELD_SCHEMAS {
            assert!(
                !withheld.reason.trim().is_empty(),
                "{} is withheld with no reason",
                withheld.type_name
            );
        }
        assert!(
            !WITHHELD_SCHEMAS.is_empty(),
            "an empty withheld list would make the contradiction check vacuous"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the mutation needs a real withheld entry to contradict"
    )]
    fn a_type_claimed_by_both_populations_is_rejected() {
        // The guard only ever sees two lists that already agree, so it passes
        // trivially until shown the disagreement it exists for: a type published
        // while its withholding reason still stands.
        let withheld = WITHHELD_SCHEMAS
            .first()
            .expect("the withheld population is not empty");
        let contradiction = DerivedSpec {
            path: "spec/contradiction.schema.json",
            urn: "urn:politeia:contradiction:v1".to_string(),
            type_name: withheld.type_name,
            bytes: Vec::new(),
        };

        let error = reject_contradictory_population(&[contradiction])
            .expect_err("a type in both populations must be rejected");
        assert!(
            error.to_string().contains(withheld.type_name),
            "the refusal must name the contradicted type, got: {error}"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the positive control fails the fixture, not the assertion, if rendering breaks"
    )]
    fn the_recorded_population_does_not_contradict_itself() {
        let specs = generated_specs().expect("the authoritative schemas must render");
        reject_contradictory_population(&specs)
            .expect("no published type may also be recorded as withheld");
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the positive control fails the fixture, not the assertion, if rendering breaks"
    )]
    fn the_full_population_is_accepted() {
        let specs = generated_specs().expect("the authoritative schemas must render");
        let tables = generated_tables().expect("the authoritative tables must render");
        reject_unowned_publications(&specs, &tables, &published_dir())
            .expect("every published file is owned by the full population");
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
