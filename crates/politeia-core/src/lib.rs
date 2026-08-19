//! politeia-core: the typed kernel model.
//!
//! Canonical identities, delegations, budgets, effects, data classes, and the
//! epistemic states of institutional claims. Everything here is data and
//! invariant; policy evaluation and dispatch live in sibling crates.

#![deny(missing_docs)]

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

macro_rules! typed_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(
            Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
        )]
        pub struct $name(pub Uuid);
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
    RuntimeGenerationId,
    "Identity of an immutable runtime generation (executable + policy + schema + trusted packs/adapters)."
);
typed_id!(
    AdapterId,
    "Identity of an adapter bridging the semantic protocol to an external system."
);
typed_id!(
    EvidenceId,
    "Identity of a provenance-bearing evidence record admitted for a claim."
);

/// A content digest (blake3, lowercase hex).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Digest(pub String);

impl Digest {
    /// Hash bytes with blake3 and return the hex digest.
    pub fn blake3(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }
}

/// An externally visible effect a protected operation may produce.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
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

/// A data classification governing sources, transforms, retention, locality, and sinks.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
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
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceBudget {
    /// Wall-clock limit in milliseconds.
    pub wall_ms: Option<u64>,
    /// CPU-time limit in milliseconds.
    pub cpu_ms: Option<u64>,
    /// Memory limit in bytes.
    pub memory_bytes: Option<u64>,
    /// I/O limit in bytes.
    pub io_bytes: Option<u64>,
    /// Network transfer limit in bytes.
    pub network_bytes: Option<u64>,
    /// External spend limit in microunits.
    pub external_cost_microunits: Option<u64>,
}

impl ResourceBudget {
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
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => true,
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
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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
    /// Whether the operation is safe to retry.
    pub retryable: bool,
    /// Whether the operation requires idempotency keys.
    pub requires_idempotency: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::SignedDuration;

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
    fn budget_attenuation_matrix() {
        assert!(budget(Some(10)).is_attenuation_of(&budget(Some(10))));
        assert!(budget(Some(5)).is_attenuation_of(&budget(Some(10))));
        assert!(!budget(Some(11)).is_attenuation_of(&budget(Some(10))));
        assert!(budget(Some(5)).is_attenuation_of(&budget(None)));
        assert!(!budget(None).is_attenuation_of(&budget(Some(10))));
        assert!(budget(None).is_attenuation_of(&budget(None)));
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
        assert!(child.is_attenuation_of(&parent));
    }

    #[test]
    fn widened_budget_breaks_attenuation() {
        let parent = root();
        let mut child = child_of(&parent);
        child.budget.wall_ms = Some(5000);
        assert!(!child.is_attenuation_of(&parent));
    }

    #[test]
    fn dropped_budget_cap_breaks_attenuation() {
        let parent = root();
        let mut child = child_of(&parent);
        child.budget.wall_ms = None;
        assert!(!child.is_attenuation_of(&parent));
    }

    #[test]
    fn narrowed_axes_attenuate() {
        let parent = root();
        let mut child = child_of(&parent);
        child.actions = BTreeSet::from(["read".to_string()]);
        child.effects = BTreeSet::from([Effect::ReadExternalSystem]);
        child.data_classes = BTreeSet::from([DataClass::Public]);
        child.budget.wall_ms = Some(250);
        assert!(child.is_attenuation_of(&parent));
    }

    #[test]
    fn later_expiry_breaks_attenuation() {
        let parent = root();
        let mut child = child_of(&parent);
        child.expires_at = parent.expires_at + SignedDuration::from_hours(1);
        assert!(!child.is_attenuation_of(&parent));
    }
}
