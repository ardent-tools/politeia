//! Deployment topology and commissioning lifecycle contracts.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{DelegationId, EvidenceId, InstitutionId, PrincipalId};

/// Placement and assurance posture for a deployment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum DeploymentTopology {
    /// Single-operator development with local or in-memory state.
    LocalDevelopment,
    /// Dedicated client-controlled deployment with durable state.
    ClientControlledSingleTenant,
    /// Isolated deployment with stronger separation of duties and assurance.
    EnterpriseHighAssurance,
}

/// Authority and capability posture during an institution's lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum LifecycleProfile {
    /// Bounded read-heavy reconnaissance and candidate-model construction.
    Bootstrap,
    /// Institution-specific engineering and generation derivation.
    Commissioning,
    /// Narrow ordinary production operation.
    Operational,
    /// Bounded reconciliation and approved maintenance.
    Maintenance,
    /// Explicitly authorized return to broader engineering.
    Recommissioning,
}

impl LifecycleProfile {
    /// True only for an edge in the canonical lifecycle state machine.
    pub fn can_transition_to(&self, target: &Self) -> bool {
        matches!(
            (self, target),
            (Self::Bootstrap, Self::Commissioning)
                | (Self::Commissioning, Self::Operational)
                | (Self::Operational, Self::Maintenance)
                | (Self::Maintenance, Self::Operational)
                | (Self::Operational, Self::Recommissioning)
                | (Self::Maintenance, Self::Recommissioning)
                | (Self::Recommissioning, Self::Operational)
        )
    }
}

/// An authorized, evidence-bearing lifecycle transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LifecycleTransition {
    /// Institution whose lifecycle changes.
    institution: InstitutionId,
    /// Profile before the transition.
    from: LifecycleProfile,
    /// Profile after the transition.
    to: LifecycleProfile,
    /// Principal authorizing the transition.
    authorized_by: PrincipalId,
    /// Exact delegation carrying transition authority.
    authorization_delegation: DelegationId,
    /// Evidence proving preconditions, approval, and completion.
    evidence: BTreeSet<EvidenceId>,
}

/// A lifecycle transition is structurally illegal or lacks evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleTransitionError {
    /// The source and target do not form a legal lifecycle edge.
    IllegalEdge,
    /// The transition has no evidence references.
    MissingEvidence,
}

impl std::fmt::Display for LifecycleTransitionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IllegalEdge => formatter.write_str("illegal lifecycle transition"),
            Self::MissingEvidence => formatter.write_str("lifecycle transition lacks evidence"),
        }
    }
}

impl std::error::Error for LifecycleTransitionError {}

impl LifecycleTransition {
    /// Construct a legal transition with at least one evidence reference.
    ///
    /// Policy may impose additional owner approval or separation-of-duty
    /// requirements; this constructor owns only the structural floor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleTransitionError`] for an illegal edge or an empty
    /// evidence set.
    pub fn new(
        institution: InstitutionId,
        from: LifecycleProfile,
        to: LifecycleProfile,
        authorized_by: PrincipalId,
        authorization_delegation: DelegationId,
        evidence: BTreeSet<EvidenceId>,
    ) -> Result<Self, LifecycleTransitionError> {
        if !from.can_transition_to(&to) {
            return Err(LifecycleTransitionError::IllegalEdge);
        }
        if evidence.is_empty() {
            return Err(LifecycleTransitionError::MissingEvidence);
        }
        Ok(Self {
            institution,
            from,
            to,
            authorized_by,
            authorization_delegation,
            evidence,
        })
    }

    /// Institution whose lifecycle changes.
    pub fn institution(&self) -> &InstitutionId {
        &self.institution
    }

    /// Profile before the transition.
    pub fn from(&self) -> &LifecycleProfile {
        &self.from
    }

    /// Profile after the transition.
    pub fn to(&self) -> &LifecycleProfile {
        &self.to
    }

    /// Principal authorizing the transition.
    pub fn authorized_by(&self) -> &PrincipalId {
        &self.authorized_by
    }

    /// Exact delegation carrying transition authority.
    pub fn authorization_delegation(&self) -> &DelegationId {
        &self.authorization_delegation
    }

    /// Evidence proving preconditions, approval, and completion.
    pub fn evidence(&self) -> &BTreeSet<EvidenceId> {
        &self.evidence
    }
}

impl<'de> Deserialize<'de> for LifecycleTransition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireTransition {
            institution: InstitutionId,
            from: LifecycleProfile,
            to: LifecycleProfile,
            authorized_by: PrincipalId,
            authorization_delegation: DelegationId,
            evidence: BTreeSet<EvidenceId>,
        }

        let wire = WireTransition::deserialize(deserializer)?;
        Self::new(
            wire.institution,
            wire.from,
            wire.to,
            wire.authorized_by,
            wire.authorization_delegation,
            wire.evidence,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_transition_matrix_has_only_the_seven_declared_edges() {
        let profiles = [
            LifecycleProfile::Bootstrap,
            LifecycleProfile::Commissioning,
            LifecycleProfile::Operational,
            LifecycleProfile::Maintenance,
            LifecycleProfile::Recommissioning,
        ];
        let mut accepted = 0;
        for source in &profiles {
            for target in &profiles {
                if source.can_transition_to(target) {
                    accepted += 1;
                }
            }
        }
        assert_eq!(accepted, 7, "the lifecycle must expose exactly seven edges");
        assert!(
            !LifecycleProfile::Operational.can_transition_to(&LifecycleProfile::Commissioning),
            "operation cannot silently recover ambient commissioning authority"
        );
        assert!(
            !LifecycleProfile::Recommissioning.can_transition_to(&LifecycleProfile::Maintenance),
            "recommissioning must return through a verified operational generation"
        );
    }

    #[test]
    fn lifecycle_transition_requires_evidence() {
        let result = LifecycleTransition::new(
            InstitutionId::new(),
            LifecycleProfile::Bootstrap,
            LifecycleProfile::Commissioning,
            PrincipalId::new(),
            DelegationId::new(),
            BTreeSet::new(),
        );
        assert_eq!(
            result,
            Err(LifecycleTransitionError::MissingEvidence),
            "a legal edge without evidence must still fail closed"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "wire validation test requires one valid transition before adversarial mutation"
    )]
    fn deserialization_rejects_an_illegal_transition() {
        let transition = LifecycleTransition::new(
            InstitutionId::new(),
            LifecycleProfile::Bootstrap,
            LifecycleProfile::Commissioning,
            PrincipalId::new(),
            DelegationId::new(),
            BTreeSet::from([EvidenceId::new()]),
        )
        .expect("fixture transition is legal");
        let mut value = serde_json::to_value(&transition).expect("fixture transition encodes");
        let mut empty_evidence = value.clone();
        value["from"] = serde_json::Value::String("operational".to_string());

        assert!(
            serde_json::from_value::<LifecycleTransition>(value).is_err(),
            "wire input must not bypass the lifecycle edge validator"
        );
        empty_evidence["evidence"] = serde_json::Value::Array(Vec::new());
        assert!(
            serde_json::from_value::<LifecycleTransition>(empty_evidence).is_err(),
            "wire input must not bypass the nonempty-evidence validator"
        );
    }
}
