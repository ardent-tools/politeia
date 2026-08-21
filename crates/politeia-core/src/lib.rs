//! politeia-core: the typed kernel model.
//!
//! Canonical identities, delegations, budgets, effects, data classes, and the
//! epistemic states of institutional claims. Everything here is data and
//! invariant; policy evaluation and dispatch live in sibling crates.

#![deny(missing_docs)]

use std::collections::BTreeSet;

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

pub mod canonical;
pub mod commissioning;
pub mod evidence;
pub mod generation;
pub mod institution;
pub mod knowledge;
pub mod lifecycle;
pub mod reconnaissance;
pub mod records;

#[cfg(test)]
mod attenuation_properties;

#[cfg(test)]
mod digest_domains;

/// Canonical textual form of every typed identifier: lowercase hyphenated UUID.
///
/// WHY the schema and the decoder both cite this one constant: `uuid`'s own
/// `Deserialize` accepts four textual shapes (simple, hyphenated, braced,
/// `urn:uuid:`) case-insensitively, while its `Serialize` only ever emits the
/// hyphenated lowercase form. Publishing a schema pattern for the emitted form
/// alone would make the schema reject values the decoder accepts -- the inverse
/// of the divergence this pattern exists to close. The decoder below narrows to
/// match instead, so one canonical form is the whole contract in both directions.
const TYPED_ID_PATTERN: &str = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

macro_rules! typed_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[repr(transparent)]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        pub struct $name(#[schemars(regex(pattern = TYPED_ID_PATTERN))] pub Uuid);
        impl $name {
            /// Create a new identifier (UUIDv7: random with time-ordered prefix).
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                let parsed = Uuid::parse_str(&text).map_err(serde::de::Error::custom)?;
                // Re-encoding through `uuid`'s own printer derives the accepted
                // form from the emitted one rather than restating it, so the two
                // cannot drift apart in a later `uuid` release.
                if parsed.hyphenated().to_string() == text {
                    Ok(Self(parsed))
                } else {
                    Err(serde::de::Error::custom(
                        "identifier must be canonical lowercase-hyphenated UUID text",
                    ))
                }
            }
        }
    };
}

typed_id!(
    PrincipalId,
    "Identity of an actor capable of requesting work."
);
typed_id!(
    DelegationId,
    "Identity of a delegation from one authority context to another."
);
typed_id!(
    ArtifactId,
    "Identity of a content-addressable subject of work or evidence."
);
typed_id!(OperationId, "Identity of a typed operation contract.");
typed_id!(PolicyBundleId, "Identity of an immutable policy bundle.");
typed_id!(
    AdapterId,
    "Identity of an adapter bridging the semantic protocol to an external system."
);
typed_id!(
    EvidenceId,
    "Identity of a provenance-bearing evidence record admitted for a claim."
);
typed_id!(
    EffectLeaseId,
    "Identity of one dispatcher-issued, single-use effect lease."
);
typed_id!(
    BudgetReservationId,
    "Identity of one atomically reserved operation budget."
);
typed_id!(
    InstitutionId,
    "Identity of one institution authority domain."
);
typed_id!(
    InstitutionWorkspaceId,
    "Identity of one institution-owned commissioning workspace."
);
typed_id!(
    CommissioningRecordId,
    "Identity of one append-only commissioning provenance record."
);
typed_id!(
    ExecutionResourceId,
    "Identity of a model, deterministic tool, human, or service available for bounded work."
);
typed_id!(
    CapabilityProfileId,
    "Identity of an evidence-backed execution-resource capability profile."
);
typed_id!(
    CapabilityVerificationId,
    "Identity of one trusted, time-bounded verification of an exact capability profile."
);
typed_id!(
    RoutingDecisionId,
    "Identity of one evidence-bearing execution-resource selection or escalation."
);
typed_id!(
    ObservationId,
    "Identity of one sourced statement about reality."
);
typed_id!(
    ClaimId,
    "Identity of one interpreted proposition with provenance."
);
/// A content digest (blake3, lowercase hex).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct Digest(#[schemars(length(equal = 64), regex(pattern = "^[0-9a-f]{64}$"))] String);

/// Content-derived identity of an immutable runtime generation.
///
/// Unlike actor and record identifiers, a generation identity is never random:
/// the same canonical specialization inputs produce the same identity.
#[repr(transparent)]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct RuntimeGenerationId(Digest);

impl RuntimeGenerationId {
    /// Digest arbitrary content bytes into a generation identity.
    ///
    /// WARNING: this carries no semantic domain, so it identifies bytes rather
    /// than a generation. A real generation identity comes from
    /// [`RuntimeGenerationId::from_digest`] over a
    /// [`DigestDomain::RuntimeGenerationInputs`] digest; this remains for
    /// content whose meaning is fixed by its source rather than its type.
    pub fn derive(bytes: &[u8]) -> Self {
        Self(Digest::blake3(bytes))
    }

    /// Adopt an already domain-separated digest as a generation identity.
    pub fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// The canonical digest that identifies the generation.
    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

/// A string was not a canonical lowercase 32-byte hexadecimal digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDigest;

impl std::fmt::Display for InvalidDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("digest must be exactly 64 lowercase hexadecimal characters")
    }
}

impl std::error::Error for InvalidDigest {}

/// The semantic class a digest identifies.
///
/// WHY a digest carries its domain: `blake3` is a function of bytes alone, so
/// two records whose encodings coincide receive one identity. Nothing in the
/// type system prevents that coincidence — `Digest` and `RuntimeGenerationId`
/// are both `#[serde(transparent)]` over the same hex string and already encode
/// identically — and a digest here is not a checksum but a binding: the
/// dispatcher admits an execution assignment by comparing one. Tagging the
/// domain makes the collision unrepresentable rather than merely unlikely.
///
/// Tags are versioned and append-only. Changing one changes every digest in
/// that domain, which invalidates every stored binding that cites it, so a
/// changed encoding takes a new tag rather than an edited one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DigestDomain {
    /// An admitted evidence record.
    EvidenceRecord,
    /// An append-only commissioning provenance record.
    CommissioningRecord,
    /// The approved inputs a runtime generation is derived from.
    ApprovedGenerationInputs,
    /// The full input set identifying an immutable runtime generation.
    RuntimeGenerationInputs,
    /// A typed operation intent presented for authorization.
    OperationIntent,
    /// The sealed claims of one dispatcher-issued effect lease.
    LeaseClaims,
    /// An execution resource available for bounded work.
    ExecutionResource,
    /// An evidence-backed execution-resource capability profile.
    CapabilityProfile,
    /// One trusted, time-bounded verification of a capability profile.
    CapabilityVerification,
    /// A time-bounded execution-resource availability snapshot.
    AvailabilitySnapshot,
    /// The hard and soft requirements a routed operation declares.
    ExecutionRequirement,
    /// One evidence-bearing resource selection or escalation.
    RoutingDecision,
    /// The exact resource binding admitted for one routed operation.
    ExecutionAssignment,
}

impl DigestDomain {
    /// Every domain, in a form that cannot go stale.
    ///
    /// WHY the exhaustive match: a hand-kept list silently omits a variant
    /// added later, and the omission is invisible -- every consumer keeps
    /// working while covering one domain less. Matching exhaustively means a
    /// new variant stops the build until it is listed.
    pub fn all() -> Vec<Self> {
        let complete = |domain: Self| match domain {
            Self::EvidenceRecord
            | Self::CommissioningRecord
            | Self::ApprovedGenerationInputs
            | Self::RuntimeGenerationInputs
            | Self::OperationIntent
            | Self::LeaseClaims
            | Self::ExecutionResource
            | Self::CapabilityProfile
            | Self::CapabilityVerification
            | Self::AvailabilitySnapshot
            | Self::ExecutionRequirement
            | Self::RoutingDecision
            | Self::ExecutionAssignment => (),
        };

        let domains = vec![
            Self::EvidenceRecord,
            Self::CommissioningRecord,
            Self::ApprovedGenerationInputs,
            Self::RuntimeGenerationInputs,
            Self::OperationIntent,
            Self::LeaseClaims,
            Self::ExecutionResource,
            Self::CapabilityProfile,
            Self::CapabilityVerification,
            Self::AvailabilitySnapshot,
            Self::ExecutionRequirement,
            Self::RoutingDecision,
            Self::ExecutionAssignment,
        ];
        for domain in &domains {
            complete(*domain);
        }
        domains
    }

    /// The stable wire tag mixed into every digest of this domain.
    pub const fn tag(self) -> &'static str {
        match self {
            DigestDomain::EvidenceRecord => "evidence_record_v1",
            DigestDomain::CommissioningRecord => "commissioning_record_v1",
            DigestDomain::ApprovedGenerationInputs => "approved_generation_inputs_v1",
            DigestDomain::RuntimeGenerationInputs => "runtime_generation_inputs_v1",
            DigestDomain::OperationIntent => "operation_intent_v1",
            DigestDomain::LeaseClaims => "lease_claims_v1",
            DigestDomain::ExecutionResource => "execution_resource_v1",
            DigestDomain::CapabilityProfile => "capability_profile_v1",
            DigestDomain::CapabilityVerification => "capability_verification_v1",
            DigestDomain::AvailabilitySnapshot => "availability_snapshot_v1",
            DigestDomain::ExecutionRequirement => "execution_requirement_v1",
            DigestDomain::RoutingDecision => "routing_decision_v1",
            DigestDomain::ExecutionAssignment => "execution_assignment_v1",
        }
    }
}

/// A record encoded together with the domain it belongs to.
#[derive(Serialize)]
struct Domained<'a, T: Serialize> {
    kind: &'static str,
    value: &'a T,
}

/// The exact bytes [`Digest::of`] hashes.
///
/// WHY this is separate from [`Digest::of`]: a golden digest reports that the
/// envelope encoding moved, but not what it moved to, so the only way to answer
/// "is the new value correct?" is to trust whatever produced it. Exposing the
/// pre-image lets a test pin the text itself, which is checkable by hand and by
/// an implementation sharing no code with this one.
pub(crate) fn domained_bytes<T: Serialize>(
    domain: DigestDomain,
    value: &T,
) -> Result<Vec<u8>, canonical::CanonicalError> {
    canonical::to_canonical_bytes(&Domained {
        kind: domain.tag(),
        value,
    })
}

impl Digest {
    /// Hash bytes with blake3 and return the hex digest.
    ///
    /// WARNING: this identifies *content*, not a record. Two records that encode
    /// to the same bytes receive the same digest here, which is why every typed
    /// record uses [`Digest::of`] instead. Reserve this for opaque bytes whose
    /// meaning is fixed by where they came from — a file, an executable, a
    /// policy bundle — rather than by their type.
    pub fn blake3(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }

    /// Digest a typed record under its semantic domain.
    ///
    /// # Errors
    ///
    /// Returns the canonical-encoding failure if the record cannot be
    /// represented, including a floating-point value, which has no canonical
    /// text form.
    pub fn of<T: Serialize>(
        domain: DigestDomain,
        value: &T,
    ) -> Result<Self, canonical::CanonicalError> {
        domained_bytes(domain, value).map(|bytes| Self::blake3(&bytes))
    }

    /// The canonical lowercase hexadecimal representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Digest {
    type Error = InvalidDigest;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let valid = value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
        valid.then_some(Self(value)).ok_or(InvalidDigest)
    }
}

impl std::str::FromStr for Digest {
    type Err = InvalidDigest;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// An externally visible effect a protected operation may produce.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Read from a filesystem.
    ReadFilesystem,
    /// Write to a filesystem.
    WriteFilesystem,
    /// Spawn a process.
    SpawnProcess,
    /// Egress to a network.
    NetworkEgress,
    /// Read a secret.
    ReadSecret,
    /// Write a secret.
    WriteSecret,
    /// Read from an external system.
    ReadExternalSystem,
    /// Write to an external system.
    WriteExternalSystem,
    /// Create an artifact.
    CreateArtifact,
    /// Change an authorization.
    ChangeAuthorization,
}

impl Effect {
    /// Whether producing this effect can change something outside the system.
    ///
    /// WHY a method on the enum rather than a set at each call site: read-only
    /// is a property of an effect, and a caller that keeps its own list is one
    /// variant behind from the moment a new effect is added. The exhaustive
    /// match means a new variant stops the build until someone decides which
    /// side it falls on -- and the safe answer for something nobody has
    /// classified is that it mutates.
    ///
    /// NOTE on `NetworkEgress`, which is the classification a reader will
    /// question first: reading a remote system is `ReadExternalSystem`, and
    /// egress is data leaving for a network sink. `docs/16-DATA_GOVERNANCE.md`
    /// treats every sink as a governed boundary, so data reaching one is a
    /// change in the world even when nothing was stored. An adapter that
    /// genuinely needs to send has its egress granted explicitly rather than
    /// riding along with a read.
    ///
    /// `ReadSecret` falls on the other side, and that is not an oversight:
    /// retrieving secret material is *separately authorized* per the same
    /// document, and a delegation naming the effect has done that naming.
    pub const fn mutates(&self) -> bool {
        match self {
            Effect::ReadFilesystem | Effect::ReadSecret | Effect::ReadExternalSystem => false,
            Effect::WriteFilesystem
            | Effect::SpawnProcess
            | Effect::NetworkEgress
            | Effect::WriteSecret
            | Effect::WriteExternalSystem
            | Effect::CreateArtifact
            | Effect::ChangeAuthorization => true,
        }
    }
}

/// A data classification governing sources, transforms, retention, locality, and sinks.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Public information.
    Public,
    /// Internal information.
    Internal,
    /// Confidential information.
    Confidential,
    /// Secrets.
    Secret,
    /// Regulated data.
    Regulated,
    /// Personal data.
    Personal,
    /// Health data.
    Health,
    /// Financial data.
    Financial,
    /// A client-restricted class named by the client.
    ClientRestricted(String),
}

/// Bounded consumption limits on a delegation or operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    /// Wall-clock limit in milliseconds.
    #[schemars(range(max = u64::MAX))]
    pub wall_ms: Option<u64>,
    /// CPU-time limit in milliseconds.
    #[schemars(range(max = u64::MAX))]
    pub cpu_ms: Option<u64>,
    /// Memory limit in bytes.
    #[schemars(range(max = u64::MAX))]
    pub memory_bytes: Option<u64>,
    /// I/O limit in bytes.
    #[schemars(range(max = u64::MAX))]
    pub io_bytes: Option<u64>,
    /// Network transfer limit in bytes.
    #[schemars(range(max = u64::MAX))]
    pub network_bytes: Option<u64>,
    /// External spend limit in microunits.
    #[schemars(range(max = u64::MAX))]
    pub external_cost_microunits: Option<u64>,
}

impl ResourceBudget {
    /// True when every resource axis has an explicit finite cap.
    ///
    /// A finite request can be atomically reserved. `None` remains useful on
    /// parent delegations to mean uncapped authority, but an invocation may
    /// not ask a ledger to reserve an unknown maximum.
    pub fn is_finite(&self) -> bool {
        self.wall_ms.is_some()
            && self.cpu_ms.is_some()
            && self.memory_bytes.is_some()
            && self.io_bytes.is_some()
            && self.network_bytes.is_some()
            && self.external_cost_microunits.is_some()
    }

    /// A budget narrows a parent budget when every dimension is capped at most
    /// the parent's cap. A dimension the parent leaves uncapped may gain a cap
    /// in the child (narrowing); a dimension the parent caps may never become
    /// uncapped or looser in the child (widening).
    ///
    /// Time: O(1). Space: O(1).
    pub fn is_attenuation_of(&self, parent: &ResourceBudget) -> bool {
        fn narrows(child: Option<u64>, parent: Option<u64>) -> bool {
            match (child, parent) {
                (Some(c), Some(p)) => c <= p,
                (None, Some(_)) => false,
                (_, None) => true,
            }
        }
        narrows(self.wall_ms, parent.wall_ms)
            && narrows(self.cpu_ms, parent.cpu_ms)
            && narrows(self.memory_bytes, parent.memory_bytes)
            && narrows(self.io_bytes, parent.io_bytes)
            && narrows(self.network_bytes, parent.network_bytes)
            && narrows(
                self.external_cost_microunits,
                parent.external_cost_microunits,
            )
    }
}

/// An attenuation from one authority context to another. A child delegation
/// must narrow its parent on every axis; it may never exceed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    /// This delegation's identity.
    pub id: DelegationId,
    /// The principal issuing the delegation.
    pub issuer: PrincipalId,
    /// The principal receiving the delegation.
    pub subject: PrincipalId,
    /// The parent delegation this one attenuates, if any.
    pub parent: Option<DelegationId>,
    /// Permitted semantic actions.
    pub actions: BTreeSet<String>,
    /// Resources the delegation reaches.
    pub resources: BTreeSet<String>,
    /// Effects the delegation may produce.
    pub effects: BTreeSet<Effect>,
    /// Data classes the delegation may touch.
    pub data_classes: BTreeSet<DataClass>,
    /// Audiences the delegation may act for.
    pub audience: BTreeSet<String>,
    /// Expiry instant (fail-closed at and after this time).
    pub expires_at: Timestamp,
    /// Consumption bounds.
    pub budget: ResourceBudget,
}

impl Delegation {
    /// True when the delegation has expired at `now`.
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }

    /// True when this delegation narrows `parent` on every axis: actions,
    /// resources, effects, data classes, audience, expiry, and budget.
    ///
    /// Time: O(n log n) in the largest axis set. Space: O(1).
    pub fn is_attenuation_of(&self, parent: &Delegation) -> bool {
        self.actions.is_subset(&parent.actions)
            && self.resources.is_subset(&parent.resources)
            && self.effects.is_subset(&parent.effects)
            && self.data_classes.is_subset(&parent.data_classes)
            && self.audience.is_subset(&parent.audience)
            && self.expires_at <= parent.expires_at
            && self.budget.is_attenuation_of(&parent.budget)
    }
}

/// The epistemic state of an institutional claim. Inference never becomes
/// approved truth silently.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum EpistemicState {
    /// A sourced statement about reality.
    Observation,
    /// An interpreted proposition with confidence and provenance.
    Inferred,
    /// A claim with unresolved contradiction.
    Contested,
    /// An institutionally accepted fact.
    Approved,
}

/// An interpreted proposition about the institution, carrying its epistemic
/// state, confidence, provenance, and the axes known to be missing.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// The claim's key (what fact is claimed about).
    pub key: String,
    /// The claimed value.
    pub value: serde_json::Value,
    /// Epistemic state.
    pub state: EpistemicState,
    /// Confidence in [0, 1].
    pub confidence: f32,
    /// Provenance references (where the claim was observed or inferred from).
    pub provenance: Vec<String>,
    /// Axes known to be missing from the claim's evidence.
    pub missed_axes: Vec<String>,
}

/// A typed operation contract: what an operation may do, which effects and
/// data classes it touches, and which evidence it owes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationSpec {
    /// The operation's identity.
    pub id: OperationId,
    /// Human-readable operation name.
    pub name: String,
    /// Semantic actions the operation performs.
    pub actions: BTreeSet<String>,
    /// Effects the operation may produce.
    pub effects: BTreeSet<Effect>,
    /// Data classes the operation may touch.
    pub data_classes: BTreeSet<DataClass>,
    /// Evidence obligations the operation owes on completion.
    pub evidence_obligations: Vec<String>,
    /// Exact routing requirement that must produce an admitted execution
    /// assignment before this operation may be authorized.
    // WHY no `skip_serializing_if`: an omitted field and an absent one encode
    // alike, so a record that later gains an optional field would digest as it
    // did before it had one. Absence is encoded as an explicit null so that it
    // is a fact the digest covers. `default` stays, so records written before
    // the field existed still decode.
    #[serde(default)]
    pub execution_requirement: Option<Digest>,
    /// Whether the operation is safe to retry.
    pub retryable: bool,
    /// Whether the operation requires idempotency keys.
    pub requires_idempotency: bool,
}

#[cfg(test)]
mod tests {
    use jiff::SignedDuration;

    use super::*;

    fn budget(wall_ms: Option<u64>) -> ResourceBudget {
        ResourceBudget {
            wall_ms,
            cpu_ms: None,
            memory_bytes: None,
            io_bytes: None,
            network_bytes: None,
            external_cost_microunits: None,
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "wire fixtures must fail loudly if canonical digest encoding drifts"
    )]
    fn digest_wire_format_enforces_canonical_lowercase_hex() {
        let digest = Digest::blake3(b"canonical digest fixture");
        assert_eq!(
            digest.as_str().len(),
            64,
            "a blake3 digest must encode exactly 32 bytes"
        );
        let encoded = serde_json::to_string(&digest).expect("a valid digest must serialize");
        let decoded: Digest =
            serde_json::from_str(&encoded).expect("a canonical digest must deserialize");
        assert_eq!(decoded, digest, "a canonical digest must round-trip");

        for invalid in [
            "short",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ] {
            let encoded = serde_json::to_string(invalid).expect("the invalid fixture must encode");
            assert!(
                serde_json::from_str::<Digest>(&encoded).is_err(),
                "non-canonical digest {invalid:?} must fail closed"
            );
        }
    }

    #[test]
    fn budget_attenuation_matrix() {
        assert!(
            budget(Some(10)).is_attenuation_of(&budget(Some(10))),
            "an equal cap must attenuate"
        );
        assert!(
            budget(Some(5)).is_attenuation_of(&budget(Some(10))),
            "a tighter cap must attenuate"
        );
        assert!(
            !budget(Some(11)).is_attenuation_of(&budget(Some(10))),
            "a wider cap must not attenuate"
        );
        assert!(
            budget(Some(5)).is_attenuation_of(&budget(None)),
            "adding a cap to an unbounded parent must attenuate"
        );
        assert!(
            !budget(None).is_attenuation_of(&budget(Some(10))),
            "dropping a parent cap must not attenuate"
        );
        assert!(
            budget(None).is_attenuation_of(&budget(None)),
            "equal unbounded budgets must attenuate"
        );
    }

    fn root() -> Delegation {
        Delegation {
            id: DelegationId::new(),
            issuer: PrincipalId::new(),
            subject: PrincipalId::new(),
            parent: None,
            actions: BTreeSet::from(["read".to_string(), "write".to_string()]),
            resources: BTreeSet::from(["repo:main".to_string()]),
            effects: BTreeSet::from([Effect::ReadExternalSystem, Effect::WriteExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Public, DataClass::Internal]),
            audience: BTreeSet::from(["kernel".to_string()]),
            expires_at: Timestamp::now() + SignedDuration::from_hours(1),
            budget: budget(Some(1000)),
        }
    }

    fn child_of(parent: &Delegation) -> Delegation {
        Delegation {
            id: DelegationId::new(),
            issuer: parent.subject.clone(),
            subject: PrincipalId::new(),
            parent: Some(parent.id.clone()),
            actions: parent.actions.clone(),
            resources: parent.resources.clone(),
            effects: parent.effects.clone(),
            data_classes: parent.data_classes.clone(),
            audience: parent.audience.clone(),
            expires_at: parent.expires_at,
            budget: ResourceBudget {
                ..parent.budget.clone()
            },
        }
    }

    #[test]
    fn identical_child_is_an_attenuation() {
        let parent = root();
        let child = child_of(&parent);
        assert!(
            child.is_attenuation_of(&parent),
            "an identical child must attenuate its parent"
        );
    }

    #[test]
    fn widened_budget_breaks_attenuation() {
        let parent = root();
        let mut child = child_of(&parent);
        child.budget.wall_ms = Some(5000);
        assert!(
            !child.is_attenuation_of(&parent),
            "a wider wall-time budget must break attenuation"
        );
    }

    #[test]
    fn dropped_budget_cap_breaks_attenuation() {
        let parent = root();
        let mut child = child_of(&parent);
        child.budget.wall_ms = None;
        assert!(
            !child.is_attenuation_of(&parent),
            "dropping a wall-time cap must break attenuation"
        );
    }

    #[test]
    fn narrowed_axes_attenuate() {
        let parent = root();
        let mut child = child_of(&parent);
        child.actions = BTreeSet::from(["read".to_string()]);
        child.effects = BTreeSet::from([Effect::ReadExternalSystem]);
        child.data_classes = BTreeSet::from([DataClass::Public]);
        child.budget.wall_ms = Some(250);
        assert!(
            child.is_attenuation_of(&parent),
            "narrowing every changed axis must preserve attenuation"
        );
    }

    #[test]
    fn later_expiry_breaks_attenuation() {
        let parent = root();
        let mut child = child_of(&parent);
        child.expires_at = parent.expires_at + SignedDuration::from_hours(1);
        assert!(
            !child.is_attenuation_of(&parent),
            "a later expiry must break attenuation"
        );
    }
}
