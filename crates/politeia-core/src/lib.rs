use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(
            Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
        )]
        pub struct $name(pub Uuid);
        impl $name {
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

impl ResourceBudget {
    /// A budget narrows a parent budget when every dimension is capped at most
    /// the parent's cap. A dimension the parent leaves uncapped may gain a cap
    /// in the child (narrowing); a dimension the parent caps may never become
    /// uncapped or looser in the child (widening).
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
            && narrows(self.external_cost_microunits, parent.external_cost_microunits)
    }
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
            && self.budget.is_attenuation_of(&parent.budget)
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

#[cfg(test)]
mod tests {
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
            expires_at: Utc::now() + chrono::Duration::hours(1),
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
            budget: ResourceBudget { ..parent.budget.clone() },
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
        child.expires_at = parent.expires_at + chrono::Duration::hours(1);
        assert!(!child.is_attenuation_of(&parent));
    }
}
