//! Deterministic specialization inputs and runtime-generation identity.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AdapterId, CommissioningRecordId, Digest, InstitutionId, InstitutionWorkspaceId,
    PolicyBundleId, RuntimeGenerationId,
    commissioning::CommissioningRecord,
    institution::{InstitutionWorkspace, TrustDomainId},
    lifecycle::{DeploymentTopology, LifecycleProfile},
};

/// Broad engineering capabilities that an operational generation excludes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CommissioningCapability {
    /// Open-ended institution reconnaissance.
    GenericReconnaissance,
    /// Editing the institution's approved semantic model.
    InstitutionAuthoring,
    /// Developing or changing external-system adapters.
    AdapterDevelopment,
    /// Authoring or changing policy semantics.
    PolicyAuthoring,
    /// Deriving a replacement runtime generation.
    GenerationDerivation,
}

impl CommissioningCapability {
    fn all() -> BTreeSet<Self> {
        BTreeSet::from([
            Self::GenericReconnaissance,
            Self::InstitutionAuthoring,
            Self::AdapterDevelopment,
            Self::PolicyAuthoring,
            Self::GenerationDerivation,
        ])
    }
}

/// Reproducibility posture for a runtime generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReproducibilityContract {
    /// Exact inputs must reproduce bit-for-bit identical generation bytes.
    Deterministic,
    /// Named fields may differ under an exact machine-readable contract.
    DeclaredNondeterminism {
        /// Canonical field paths allowed to vary.
        fields: BTreeSet<String>,
        /// Digest of the contract explaining and constraining those fields.
        contract_digest: Digest,
    },
}

/// Exact institution-approved inputs from which specialization may derive a generation.
///
/// Keeping these axes in one canonical value prevents a commissioner from preserving
/// the approved model and policy while substituting an adapter, pack, schema, topology,
/// toolchain, or weaker reproducibility posture during derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovedGenerationInputs {
    /// Exact public source revision/content digest.
    pub source_digest: Digest,
    /// Lifecycle authority/capability posture.
    pub lifecycle: LifecycleProfile,
    /// Placement/isolation and assurance posture.
    pub topology: DeploymentTopology,
    /// Public schemas included in the generation.
    pub schema_digests: BTreeMap<String, Digest>,
    /// Trusted adapters included in the generation.
    pub adapter_digests: BTreeMap<AdapterId, Digest>,
    /// Declarative domain packs included in the generation.
    pub pack_digests: BTreeMap<String, Digest>,
    /// Other exact executable, migration, projection, or update components.
    pub component_digests: BTreeMap<String, Digest>,
    /// Broad commissioning capabilities explicitly absent from this generation.
    pub excluded_commissioning_capabilities: BTreeSet<CommissioningCapability>,
    /// Digest of the specialization compiler and its configuration.
    pub specializer_digest: Digest,
    /// Digest of the exact build toolchain and compatibility inputs.
    pub toolchain_digest: Digest,
    /// Exact reproducibility or allowed-nondeterminism contract.
    pub reproducibility: ReproducibilityContract,
}

impl ApprovedGenerationInputs {
    /// Digest the complete approved specialization plan.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the plan cannot be represented.
    ///
    /// Time: O(n). Space: O(n), where n is the encoded plan size.
    pub fn digest(&self) -> Result<Digest, serde_json::Error> {
        serde_json::to_vec(self).map(|bytes| Digest::blake3(&bytes))
    }
}

/// Canonical inputs from which one immutable runtime generation is derived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeGenerationInputs {
    /// Institution whose operational generation is being derived.
    pub institution: InstitutionId,
    /// Client-owned commissioning workspace identity.
    pub workspace: InstitutionWorkspaceId,
    /// Digest of the exact workspace snapshot.
    pub workspace_digest: Digest,
    /// Client-controlled trust domain for the generation.
    pub trust_domain: TrustDomainId,
    /// Approved policy bundle identity.
    pub policy_bundle: PolicyBundleId,
    /// Digest of the exact approved policy bundle.
    pub policy_digest: Digest,
    /// Exact commissioning provenance record.
    pub commissioning_record: CommissioningRecordId,
    /// Digest of the exact commissioning record.
    pub commissioning_record_digest: Digest,
    /// Exact owner-approved specialization and build plan.
    pub approved: ApprovedGenerationInputs,
}

/// An immutable, content-addressed specialization of Politeia.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeGeneration {
    /// Digest-derived generation identity.
    id: RuntimeGenerationId,
    /// Canonical specialization inputs whose bytes derive `id`.
    inputs: RuntimeGenerationInputs,
}

/// Runtime-generation inputs were invalid or could not be encoded.
#[derive(Debug)]
#[non_exhaustive]
pub enum RuntimeGenerationError {
    /// An operational generation retained a broad commissioning capability.
    OperationalCapabilityPresent,
    /// A nondeterminism contract named no variable fields.
    EmptyNondeterminismDeclaration,
    /// A workspace or commissioning-record axis did not match the generation inputs.
    ProvenanceMismatch {
        /// Exact shared axis that disagreed.
        field: &'static str,
    },
    /// Canonical JSON encoding failed.
    Encoding(serde_json::Error),
}

impl std::fmt::Display for RuntimeGenerationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperationalCapabilityPresent => formatter.write_str(
                "operational generation does not exclude every broad commissioning capability",
            ),
            Self::EmptyNondeterminismDeclaration => {
                formatter.write_str("declared nondeterminism names no variable fields")
            }
            Self::ProvenanceMismatch { field } => {
                write!(formatter, "runtime-generation provenance mismatch: {field}")
            }
            Self::Encoding(_) => formatter.write_str("runtime-generation inputs cannot be encoded"),
        }
    }
}

impl std::error::Error for RuntimeGenerationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(source) => Some(source),
            _ => None,
        }
    }
}

impl RuntimeGeneration {
    /// Validate and derive a content-addressed generation from canonical inputs.
    ///
    /// Incidental build time is absent by construction. BTree-backed maps and
    /// sets make the serialized input ordering deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeGenerationError`] when an operational generation has
    /// not excluded every broad commissioning capability, a nondeterminism
    /// declaration is empty, or canonical encoding fails.
    ///
    /// Time: O(w + c + s), where w is workspace manifest size, c is the
    /// commissioning record size, and s is serialized generation-input size.
    /// Space: O(s) for canonical identity bytes.
    pub fn derive(
        inputs: RuntimeGenerationInputs,
        workspace: &InstitutionWorkspace,
        commissioning: &CommissioningRecord,
    ) -> Result<Self, RuntimeGenerationError> {
        if inputs.approved.lifecycle == LifecycleProfile::Operational
            && !CommissioningCapability::all()
                .is_subset(&inputs.approved.excluded_commissioning_capabilities)
        {
            return Err(RuntimeGenerationError::OperationalCapabilityPresent);
        }
        if matches!(
            &inputs.approved.reproducibility,
            ReproducibilityContract::DeclaredNondeterminism { fields, .. } if fields.is_empty()
        ) {
            return Err(RuntimeGenerationError::EmptyNondeterminismDeclaration);
        }
        Self::validate_bindings(&inputs, workspace, commissioning)?;
        let bytes = serde_json::to_vec(&inputs).map_err(RuntimeGenerationError::Encoding)?;
        Ok(Self {
            id: RuntimeGenerationId::derive(&bytes),
            inputs,
        })
    }

    fn validate_bindings(
        inputs: &RuntimeGenerationInputs,
        workspace: &InstitutionWorkspace,
        commissioning: &CommissioningRecord,
    ) -> Result<(), RuntimeGenerationError> {
        let workspace_digest = workspace
            .digest()
            .map_err(RuntimeGenerationError::Encoding)?;
        let commissioning_digest = commissioning
            .digest()
            .map_err(RuntimeGenerationError::Encoding)?;
        for (matches, field) in [
            (
                inputs.institution == workspace.institution,
                "workspace institution",
            ),
            (inputs.workspace == workspace.id, "workspace identity"),
            (
                inputs.workspace_digest == workspace_digest,
                "workspace digest",
            ),
            (
                inputs.trust_domain == workspace.trust_domain,
                "trust domain",
            ),
            (
                inputs.policy_bundle == workspace.policy_bundle,
                "workspace policy bundle",
            ),
            (
                inputs.policy_digest == workspace.policy_digest,
                "workspace policy digest",
            ),
            (
                inputs.approved == workspace.approved_generation,
                "workspace approved generation inputs",
            ),
            (
                commissioning.id().eq(&inputs.commissioning_record),
                "commissioning record identity",
            ),
            (
                inputs.commissioning_record_digest == commissioning_digest,
                "commissioning record digest",
            ),
            (
                commissioning.institution().eq(&inputs.institution),
                "commissioning institution",
            ),
            (
                commissioning.workspace().eq(&inputs.workspace),
                "commissioning workspace",
            ),
            (
                commissioning
                    .workspace_digest()
                    .eq(&inputs.workspace_digest),
                "commissioning workspace digest",
            ),
            (
                commissioning.policy_bundle().eq(&inputs.policy_bundle),
                "commissioning policy bundle",
            ),
            (
                commissioning.policy_digest().eq(&inputs.policy_digest),
                "commissioning policy digest",
            ),
            (
                commissioning.approved_generation().eq(&inputs.approved),
                "commissioning approved generation inputs",
            ),
        ] {
            if !matches {
                return Err(RuntimeGenerationError::ProvenanceMismatch { field });
            }
        }
        Ok(())
    }

    /// Revalidate this manifest against resolved workspace and commissioning records.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeGenerationError`] when any shared provenance axis differs.
    pub fn resolve_provenance(
        &self,
        workspace: &InstitutionWorkspace,
        commissioning: &CommissioningRecord,
    ) -> Result<&Self, RuntimeGenerationError> {
        Self::validate_bindings(&self.inputs, workspace, commissioning)?;
        Ok(self)
    }

    /// Content-derived generation identity.
    pub fn id(&self) -> &RuntimeGenerationId {
        &self.id
    }

    /// Canonical specialization inputs bound by the generation identity.
    pub fn inputs(&self) -> &RuntimeGenerationInputs {
        &self.inputs
    }

    /// Canonical manifest bytes used for byte-for-byte reproducibility checks.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the typed generation cannot be
    /// serialized.
    ///
    /// Time: O(n). Space: O(n), where n is the encoded manifest size.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::{SignedDuration, Timestamp};

    use crate::{
        DataClass, Delegation, DelegationId, Effect, EvidenceId, PrincipalId, ResourceBudget,
        commissioning::{
            ApprovedCommissioningSubject, CommissionerGrantRecord, CommissioningRecord,
            TrustedCommissionerGrantRegistry, commissioning_approval_subject_digest,
            commissioning_institution_audience, commissioning_observation_set_digest,
            commissioning_observation_subject_digest, commissioning_workspace_resource,
            unresolved_obligations_digest,
        },
        evidence::{EvidenceRecord, IndependenceClass, TrustedEvidenceRegistry},
    };

    struct Fixture {
        inputs: RuntimeGenerationInputs,
        workspace: InstitutionWorkspace,
        commissioning: CommissioningRecord,
    }

    #[expect(
        clippy::expect_used,
        reason = "canonical trust-domain fixture must fail loudly if validation drifts"
    )]
    fn fixture() -> Fixture {
        let institution = InstitutionId::new();
        let workspace_id = InstitutionWorkspaceId::new();
        let trust_domain = "client-a:production"
            .parse()
            .expect("fixture trust domain is canonical");
        let policy_bundle = PolicyBundleId::new();
        let policy_digest = Digest::blake3(b"policy");
        let component_digests =
            BTreeMap::from([("politeiad".to_string(), Digest::blake3(b"executable"))]);
        let approved_generation = ApprovedGenerationInputs {
            source_digest: Digest::blake3(b"source"),
            lifecycle: LifecycleProfile::Operational,
            topology: DeploymentTopology::ClientControlledSingleTenant,
            schema_digests: BTreeMap::from([("operation".to_string(), Digest::blake3(b"schema"))]),
            adapter_digests: BTreeMap::from([(AdapterId::new(), Digest::blake3(b"adapter"))]),
            pack_digests: BTreeMap::new(),
            component_digests,
            excluded_commissioning_capabilities: CommissioningCapability::all(),
            specializer_digest: Digest::blake3(b"specializer"),
            toolchain_digest: Digest::blake3(b"toolchain"),
            reproducibility: ReproducibilityContract::Deterministic,
        };
        let workspace = InstitutionWorkspace {
            id: workspace_id.clone(),
            institution: institution.clone(),
            trust_domain: trust_domain.clone(),
            owner: PrincipalId::new(),
            owner_delegation: DelegationId::new(),
            approved_model_digest: Digest::blake3(b"model"),
            policy_bundle: policy_bundle.clone(),
            policy_digest: policy_digest.clone(),
            approved_generation: approved_generation.clone(),
            secret_references: BTreeSet::new(),
        };
        let workspace_digest = workspace.digest().expect("fixture workspace encodes");
        let as_of = Timestamp::now();
        let commissioner = PrincipalId::new();
        let commissioner_delegation = Delegation {
            id: DelegationId::new(),
            issuer: workspace.owner.clone(),
            subject: commissioner.clone(),
            parent: Some(workspace.owner_delegation.clone()),
            actions: BTreeSet::from(["commission".to_string()]),
            resources: BTreeSet::from([commissioning_workspace_resource(&workspace.id)]),
            effects: BTreeSet::from([Effect::ReadExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from([commissioning_institution_audience(&workspace.institution)]),
            expires_at: as_of + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: Some(60_000),
                cpu_ms: Some(10_000),
                memory_bytes: Some(64 * 1024 * 1024),
                io_bytes: Some(1024 * 1024),
                network_bytes: Some(1024 * 1024),
                external_cost_microunits: Some(0),
            },
        };
        let grant = CommissionerGrantRecord {
            institution: workspace.institution.clone(),
            workspace: workspace.id.clone(),
            valid_from: as_of - SignedDuration::from_mins(1),
            revoked_at: None,
            delegation: commissioner_delegation.clone(),
        };
        let grant_digest = grant.digest().expect("fixture grant encodes");
        let observation = EvidenceRecord {
            id: EvidenceId::new(),
            subject: commissioning_observation_subject_digest(
                &workspace.institution,
                &workspace.id,
                &grant_digest,
                &Digest::blake3(b"observation payload"),
            )
            .expect("fixture observation subject encodes"),
            producer: commissioner,
            producer_delegation: commissioner_delegation.id.clone(),
            method: "bounded read-only discovery".to_string(),
            payload_digest: Digest::blake3(b"observation payload"),
            observed_at: as_of - SignedDuration::from_secs(30),
            independence: IndependenceClass::SelfReported,
        };
        let observation_set_digest =
            commissioning_observation_set_digest(std::slice::from_ref(&observation))
                .expect("fixture observation set encodes");
        let obligations = BTreeSet::new();
        let approved_subjects = [
            ApprovedCommissioningSubject::InstitutionalModel {
                digest: workspace.approved_model_digest.clone(),
            },
            ApprovedCommissioningSubject::PolicyBundle {
                id: workspace.policy_bundle.clone(),
                digest: workspace.policy_digest.clone(),
            },
            ApprovedCommissioningSubject::GenerationInputs {
                digest: approved_generation
                    .digest()
                    .expect("fixture generation plan encodes"),
            },
            ApprovedCommissioningSubject::UnresolvedObligations {
                digest: unresolved_obligations_digest(
                    &workspace.institution,
                    &workspace.id,
                    &obligations,
                )
                .expect("fixture obligations encode"),
            },
        ];
        let approvals: Vec<_> = approved_subjects
            .iter()
            .map(|subject| EvidenceRecord {
                id: EvidenceId::new(),
                subject: commissioning_approval_subject_digest(
                    &workspace.institution,
                    &workspace.id,
                    subject,
                    &observation_set_digest,
                )
                .expect("fixture approval subject encodes"),
                producer: workspace.owner.clone(),
                producer_delegation: workspace.owner_delegation.clone(),
                method: "institution-owner approval".to_string(),
                payload_digest: Digest::blake3(b"signed owner approval"),
                observed_at: as_of - SignedDuration::from_secs(10),
                independence: IndependenceClass::HumanAuthority,
            })
            .collect();
        let observation_ids = BTreeSet::from([observation.id.clone()]);
        let approval_ids = approvals.iter().map(|record| record.id.clone()).collect();
        let evidence = TrustedEvidenceRegistry::from_trusted_bootstrap(
            std::iter::once(observation).chain(approvals),
        )
        .expect("fixture evidence identities are unique");
        let grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(as_of, [grant])
            .expect("fixture grant is unique and active");
        let commissioning = CommissioningRecord::new(
            &workspace,
            &grants,
            &evidence,
            &observation_ids,
            &approval_ids,
            obligations,
        )
        .expect("fixture commissioning record is complete");
        let commissioning_record_digest = commissioning
            .digest()
            .expect("fixture commissioning record encodes");
        let inputs = RuntimeGenerationInputs {
            institution: institution.clone(),
            workspace: workspace_id.clone(),
            workspace_digest: workspace_digest.clone(),
            trust_domain,
            policy_bundle: policy_bundle.clone(),
            policy_digest: policy_digest.clone(),
            commissioning_record: commissioning.id().clone(),
            commissioning_record_digest: commissioning_record_digest.clone(),
            approved: approved_generation,
        };
        Fixture {
            inputs,
            workspace,
            commissioning,
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "generation fixtures must derive and encode to prove deterministic identity"
    )]
    fn identical_inputs_produce_identical_identity_and_bytes() {
        let fixture = fixture();
        let first = RuntimeGeneration::derive(
            fixture.inputs.clone(),
            &fixture.workspace,
            &fixture.commissioning,
        )
        .expect("inputs are valid");
        let second =
            RuntimeGeneration::derive(fixture.inputs, &fixture.workspace, &fixture.commissioning)
                .expect("same inputs remain valid");
        assert_eq!(
            first.id(),
            second.id(),
            "generation identity must be stable"
        );
        assert_eq!(
            first.canonical_bytes().expect("generation encodes"),
            second.canonical_bytes().expect("generation encodes again"),
            "generation bytes must be a fixed point"
        );
    }

    #[test]
    fn unapproved_generation_input_substitution_is_rejected() {
        let fixture = fixture();
        let mut changed_inputs = fixture.inputs;
        changed_inputs.approved.adapter_digests.insert(
            AdapterId::new(),
            Digest::blake3(b"unapproved effect adapter"),
        );
        assert!(matches!(
            RuntimeGeneration::derive(changed_inputs, &fixture.workspace, &fixture.commissioning),
            Err(RuntimeGenerationError::ProvenanceMismatch { .. })
        ));
    }

    #[test]
    fn cross_client_workspace_substitution_is_rejected() {
        let fixture = fixture();
        let mut other_workspace = fixture.workspace.clone();
        other_workspace.id = InstitutionWorkspaceId::new();

        assert!(matches!(
            RuntimeGeneration::derive(fixture.inputs, &other_workspace, &fixture.commissioning,),
            Err(RuntimeGenerationError::ProvenanceMismatch { .. })
        ));
    }

    #[test]
    fn operational_generation_must_exclude_commissioning_capabilities() {
        let fixture = fixture();
        let mut invalid = fixture.inputs;
        invalid
            .approved
            .excluded_commissioning_capabilities
            .remove(&CommissioningCapability::PolicyAuthoring);
        assert!(
            matches!(
                RuntimeGeneration::derive(invalid, &fixture.workspace, &fixture.commissioning),
                Err(RuntimeGenerationError::OperationalCapabilityPresent)
            ),
            "operational authoring authority must fail structurally"
        );
    }

    #[test]
    fn reproducibility_contract_rejects_unknown_variant_fields() {
        assert!(
            serde_json::from_str::<ReproducibilityContract>(
                r#"{"kind":"deterministic","ambient_input":"clock"}"#
            )
            .is_err(),
            "digest-critical tagged variants must reject unknown fields"
        );
    }
}
