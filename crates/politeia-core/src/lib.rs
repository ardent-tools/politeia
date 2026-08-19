use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
        pub struct $name(pub Uuid);
        impl $name {
            pub fn new() -> Self { Self(Uuid::now_v7()) }
        }
        impl Default for $name {
            fn default() -> Self { Self::new() }
        }
    };
}

typed_id!(PrincipalId);
typed_id!(DelegationId);
typed_id!(ArtifactId);
typed_id!(OperationId);
typed_id!(PolicyBundleId);
typed_id!(RuntimeGenerationId);
typed_id!(AdapterId);
typed_id!(EvidenceId);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Digest(pub String);

impl Digest {
    pub fn blake3(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub enum Effect {
    ReadFilesystem,
    WriteFilesystem,
    SpawnProcess,
    NetworkEgress,
    ReadSecret,
    WriteSecret,
    ReadExternalSystem,
    WriteExternalSystem,
    CreateArtifact,
    ChangeAuthorization,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    Secret,
    Regulated,
    Personal,
    Health,
    Financial,
    ClientRestricted(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceBudget {
    pub wall_ms: Option<u64>,
    pub cpu_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub io_bytes: Option<u64>,
    pub network_bytes: Option<u64>,
    pub external_cost_microunits: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Delegation {
    pub id: DelegationId,
    pub issuer: PrincipalId,
    pub subject: PrincipalId,
    pub parent: Option<DelegationId>,
    pub actions: BTreeSet<String>,
    pub resources: BTreeSet<String>,
    pub effects: BTreeSet<Effect>,
    pub data_classes: BTreeSet<DataClass>,
    pub audience: BTreeSet<String>,
    pub expires_at: DateTime<Utc>,
    pub budget: ResourceBudget,
}

impl Delegation {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    pub fn is_attenuation_of(&self, parent: &Delegation) -> bool {
        self.actions.is_subset(&parent.actions)
            && self.resources.is_subset(&parent.resources)
            && self.effects.is_subset(&parent.effects)
            && self.data_classes.is_subset(&parent.data_classes)
            && self.audience.is_subset(&parent.audience)
            && self.expires_at <= parent.expires_at
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum EpistemicState {
    Observation,
    Inferred,
    Contested,
    Approved,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Claim {
    pub key: String,
    pub value: serde_json::Value,
    pub state: EpistemicState,
    pub confidence: f32,
    pub provenance: Vec<String>,
    pub missed_axes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OperationSpec {
    pub id: OperationId,
    pub name: String,
    pub actions: BTreeSet<String>,
    pub effects: BTreeSet<Effect>,
    pub data_classes: BTreeSet<DataClass>,
    pub evidence_obligations: Vec<String>,
    pub retryable: bool,
    pub requires_idempotency: bool,
}
