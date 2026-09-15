//! Signed runtime-generation lifecycle at the installed service boundary.
//!
//! This module coordinates existing core provenance, artifact, assurance, and
//! storage contracts. It does not make a build-reproducibility claim: it
//! verifies the signed input and every published artifact byte.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use politeia_core::{
    AdapterId, Delegation, DelegationId, Digest, EvidenceId,
    commissioning::{
        COMMISSION_ACTION, CommissionerGrantRecord, CommissioningRecord,
        HistoricalReconnaissanceGrantRecord, TrustedCommissionerGrantRegistry,
        commissioning_institution_audience, commissioning_workspace_resource,
    },
    evidence::{EvidenceRequest, IndependenceClass, TrustedEvidenceRegistry},
    generation::RuntimeGenerationInputs,
    knowledge::{TrustedObservationRegistry, TrustedSourceCaptureRegistry},
    trust::{AdmissionKind, Admitted, SignedAdmissionWire},
};
use politeia_evidence::{
    assurance::{
        ActivationProof, AuthorizedControlRun, ControlRun, VerifiedActivation, clean_claim,
    },
    authority::AuthorityContext,
};
use politeia_policy::PolicyBinding;
use politeia_runtime::AuthorizationLedger;
use politeia_storage::{
    ActivationCommit, EvidenceAdmission, PostgresAuthorizationLedger, RuntimeGeneration,
    SignedRecord,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CoordinatorError, OperationResult,
    artifacts::{
        ArtifactSources, CommissioningProvenance, GenerationArtifactBuilder,
        VerifiedGenerationArtifact,
    },
    service::PoliteiadService,
    service_generation_validation::{GenerationValidationReport, LIFECYCLE_CALIBRATION_METHOD},
    service_operation::{
        ActiveOperationalRegistry, DetectorCalibrationEvidenceSubmission,
        direct_grant_authorization_digest,
    },
};

const ACTIVATE_CONTROL: &str = "generation:activate";
const ROLLBACK_CONTROL: &str = "generation:rollback";

/// One binding obligation covered by a candidate's detector activation proof.
///
/// The candidate registry validates supported scopes. Several obligations may
/// share one detector's exact policy and mediation path, hence one proof.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CandidateBlockingControl {
    binding: String,
    scope: String,
    control: String,
}

fn candidate_blocking_controls(bindings: &[PolicyBinding]) -> BTreeSet<CandidateBlockingControl> {
    bindings
        .iter()
        .filter(|binding| binding.is_blocking())
        .flat_map(|binding| {
            binding
                .detector_ids
                .iter()
                .cloned()
                .map(|control| CandidateBlockingControl {
                    binding: binding.id.clone(),
                    scope: binding.scope.clone(),
                    control,
                })
        })
        .collect()
}

#[cfg(test)]
mod control_set_tests {
    use super::{CandidateBlockingControl, candidate_blocking_controls};
    use politeia_policy::{
        Consequence, PolicyBinding,
        hardening::{BindingAuthority, HardeningLadder, HardeningState},
    };

    fn authority(
        states: &[HardeningState],
        consequence: Consequence,
    ) -> Result<BindingAuthority, String> {
        let mut ladder = HardeningLadder::new();
        for state in states {
            ladder.advance(*state).map_err(|error| error.to_string())?;
        }
        BindingAuthority::new(ladder, consequence).map_err(|error| error.to_string())
    }

    fn binding(
        id: &str,
        scope: &str,
        controls: &[&str],
        authority: BindingAuthority,
    ) -> PolicyBinding {
        PolicyBinding {
            id: id.to_owned(),
            clause_id: format!("clause:{id}"),
            detector_ids: controls.iter().map(ToString::to_string).collect(),
            scope: scope.to_owned(),
            authority,
        }
    }

    #[test]
    fn activation_coverage_retains_every_blocking_binding_and_scope() -> Result<(), String> {
        let enforced = [
            HardeningState::Observed,
            HardeningState::Proposed,
            HardeningState::Approved,
            HardeningState::Shadow,
            HardeningState::Calibrated,
            HardeningState::Advisory,
            HardeningState::Enforced,
        ];
        let advisory = [
            HardeningState::Observed,
            HardeningState::Proposed,
            HardeningState::Approved,
            HardeningState::Shadow,
            HardeningState::Calibrated,
            HardeningState::Advisory,
        ];
        let bindings = vec![
            binding(
                "manifest-deny",
                "operation:derive_resource_manifest",
                &["public-detector", "second-detector"],
                authority(&enforced, Consequence::Deny)?,
            ),
            binding(
                "context-deny",
                "operation:compile_institutional_context",
                &["public-detector"],
                authority(&enforced, Consequence::Deny)?,
            ),
            binding(
                "manifest-review",
                "operation:derive_resource_manifest",
                &["public-detector"],
                authority(&enforced, Consequence::RequireReview)?,
            ),
            binding(
                "advice-only",
                "operation:derive_resource_manifest",
                &["advisory-detector"],
                authority(&advisory, Consequence::Advisory)?,
            ),
        ];

        let required = candidate_blocking_controls(&bindings);

        assert_eq!(
            required,
            std::collections::BTreeSet::from([
                CandidateBlockingControl {
                    binding: "context-deny".to_owned(),
                    scope: "operation:compile_institutional_context".to_owned(),
                    control: "public-detector".to_owned(),
                },
                CandidateBlockingControl {
                    scope: "operation:derive_resource_manifest".to_owned(),
                    binding: "manifest-deny".to_owned(),
                    control: "public-detector".to_owned(),
                },
                CandidateBlockingControl {
                    binding: "manifest-deny".to_owned(),
                    scope: "operation:derive_resource_manifest".to_owned(),
                    control: "second-detector".to_owned(),
                },
                CandidateBlockingControl {
                    binding: "manifest-review".to_owned(),
                    scope: "operation:derive_resource_manifest".to_owned(),
                    control: "public-detector".to_owned(),
                },
            ])
        );
        Ok(())
    }
}

mod provenance;
mod reproduction;

/// Paths to complete artifact inputs, relative to the installed workspace.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSourcePaths {
    /// Public source archive.
    pub public_source: PathBuf,
    /// Policy bundle bytes.
    pub policy: PathBuf,
    /// Specializer configuration.
    pub specializer: PathBuf,
    /// Toolchain description.
    pub toolchain: PathBuf,
    /// Approved schemas.
    pub schemas: BTreeMap<String, PathBuf>,
    /// Approved adapters.
    pub adapters: BTreeMap<AdapterId, PathBuf>,
    /// Approved packs.
    pub packs: BTreeMap<String, PathBuf>,
    /// Complete remaining component set.
    pub components: BTreeMap<String, PathBuf>,
}

/// An immutable daemon-derived receipt for one exact commissioning record.
///
/// Clients carry this receipt into signed generation inputs, but it is never
/// trusted from transport alone: publication reloads the identical receipt
/// from durable authority and rederives the canonical core record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissioningReceipt {
    /// Exact commissioning record allocated by the canonical core.
    pub record: politeia_core::CommissioningRecordId,
    /// Digest of that exact canonical record.
    pub record_digest: Digest,
    /// Trusted point-in-time used for the grant/evidence reconstruction.
    pub captured_at: jiff::Timestamp,
    /// Principal holding the selected temporary commissioning grant.
    pub commissioner: politeia_core::PrincipalId,
    /// Durable temporary commissioner grant used for this record.
    pub delegation: DelegationId,
    /// Exact canonical digest of that commissioner grant record.
    pub commissioner_grant_digest: Digest,
    /// Discovery observations used by the record.
    pub observations: BTreeSet<EvidenceId>,
    /// Owner approvals used by the record.
    pub approvals: BTreeSet<EvidenceId>,
    /// Explicitly owner-approved open obligations.
    pub unresolved_obligations: BTreeSet<String>,
}

/// Inert selection submitted to ask the daemon to derive a commissioning
/// receipt from its already-admitted evidence and grant registry.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissioningRecordRequest {
    /// Durable temporary commissioner grant used for this record.
    pub delegation: DelegationId,
    /// Discovery observations used by the record.
    pub observations: BTreeSet<EvidenceId>,
    /// Owner approvals used by the record.
    pub approvals: BTreeSet<EvidenceId>,
    /// Explicitly owner-approved open obligations.
    pub unresolved_obligations: BTreeSet<String>,
}

/// Inert selection of an already-issued daemon commissioning receipt.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissioningSelection {
    /// Daemon-issued receipt selecting every immutable provenance input.
    pub receipt: CommissioningReceipt,
    /// Fresh live grant held by the signed generation-input publisher.
    ///
    /// This authorizes publication now; it is deliberately separate from the
    /// historical commissioner grant retained in `receipt`.
    pub publication_delegation: DelegationId,
}

/// Typed assurance material required for activation and rollback.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationAssurance {
    /// Verifier-signed calibration evidence retained by the activation proof.
    pub calibration: SignedAdmissionWire<EvidenceRequest>,
    /// Signed run of the exact lifecycle control.
    pub run: SignedAdmissionWire<ControlRun>,
    /// Signed direct grant for the control-run producer.
    pub run_authority: SignedAdmissionWire<Delegation>,
    /// Signed proof that the control fires on its mediation path.
    pub proof: SignedAdmissionWire<ActivationProof>,
    /// Signed direct grant for the independent activation verifier.
    pub proof_authority: SignedAdmissionWire<Delegation>,
    /// Complete independently admitted real-path qualification set for every
    /// blocking candidate-policy control.
    #[serde(default)]
    pub qualifications: Vec<DetectorCalibrationEvidenceSubmission>,
}

/// One typed lifecycle action that only the installed institution owner may
/// authorize for the active-generation pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationTransitionAction {
    /// Make a generation the active operational generation.
    Activate,
    /// Return a previously admitted generation to the active slot.
    Rollback,
}

impl GenerationTransitionAction {
    fn control(self) -> &'static str {
        match self {
            Self::Activate => ACTIVATE_CONTROL,
            Self::Rollback => ROLLBACK_CONTROL,
        }
    }
}

/// Exact installed-owner decision to change the active-generation pointer.
///
/// The signed envelope supplies the owner and workspace scope. Its payload
/// binds the lifecycle action, target, observed compare-and-swap state, and
/// complete signed assurance document so evidence producers cannot authorize
/// a deployment decision by themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationTransitionRequest {
    /// Identity under which the complete owner decision is retained as evidence.
    pub evidence: EvidenceId,
    /// The requested lifecycle action.
    pub action: GenerationTransitionAction,
    /// Exact admitted generation to activate.
    pub generation: Digest,
    /// Durable workspace revision the owner observed.
    pub expected_revision: i64,
    /// Active generation the owner observed, including explicit empty.
    pub expected_active: Option<Digest>,
    /// BLAKE3 of the exact canonical signed assurance document.
    pub assurance_digest: Digest,
}

/// Derive the canonical assurance binding used by an owner transition.
///
/// # Errors
///
/// Returns a canonical encoding error when the signed assurance cannot be
/// represented as canonical bytes.
pub fn activation_assurance_digest(
    assurance: &ActivationAssurance,
) -> Result<Digest, politeia_core::canonical::CanonicalError> {
    politeia_core::canonical::to_canonical_bytes(assurance).map(|bytes| Digest::blake3(&bytes))
}

/// Generation lifecycle requests carried by the commissioning transport.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GenerationRequest {
    /// Derive, publish, verify, and durably admit a complete generation.
    Publish {
        /// Exact signed specialization inputs.
        inputs: Box<SignedAdmissionWire<RuntimeGenerationInputs>>,
        /// Re-admitted commissioning selection.
        commissioning: CommissioningSelection,
        /// Workspace-confined bytes for every approved input.
        sources: ArtifactSourcePaths,
    },
    /// Re-admit stored signed inputs and verify every immutable artifact byte.
    Verify {
        /// Generation digest returned by publish.
        generation: Digest,
    },
    /// Materialize the retained inputs again and compare the complete bundle.
    Reproduce {
        /// Generation digest returned by publish.
        generation: Digest,
    },
    /// Exercise the installed artifact verifier on an exact known-good bundle
    /// and a private copied bundle with one planted substitution.
    Validate {
        /// Generation digest returned by publish.
        generation: Digest,
        /// Exact lifecycle control that will bind the unsigned report.
        control: String,
    },
    /// Change the active slot only under an installed-owner transition decision.
    Transition {
        /// Control run and independent activation proof.
        assurance: Box<ActivationAssurance>,
        /// Installed-owner deployment decision bound to this exact request.
        transition: Option<SignedAdmissionWire<GenerationTransitionRequest>>,
    },
    /// Admit a fresh replacement-maintainer grant before further commissioning.
    Recommission {
        /// Fresh owner-rooted delegation for the replacement maintainer.
        delegation: SignedAdmissionWire<Delegation>,
    },
    /// Rebuild and retain one complete owner-approved commissioning record.
    DeriveRecord {
        /// Exact durable evidence and grant selection to validate.
        selection: CommissioningRecordRequest,
    },
}

impl PoliteiadService {
    /// Execute one typed signed-generation lifecycle request.
    pub(crate) async fn handle_generation(
        &self,
        request: Value,
    ) -> Result<OperationResult, CoordinatorError> {
        let request: GenerationRequest = serde_json::from_value(request).map_err(|error| {
            CoordinatorError::Refused(format!("generation input is not typed JSON: {error}"))
        })?;
        match request {
            GenerationRequest::Publish {
                inputs,
                commissioning,
                sources,
            } => {
                self.publish_generation(*inputs, commissioning, sources)
                    .await
            }
            GenerationRequest::Verify { generation } => self.verify_generation(generation).await,
            GenerationRequest::Reproduce { generation } => {
                self.reproduce_generation(generation).await
            }
            GenerationRequest::Validate {
                generation,
                control,
            } => {
                let report = self
                    .generation_validation_report(generation, &control)
                    .await?;
                Ok(OperationResult::Coordinated {
                    result: json!({ "validation": report }),
                    evidence_refs: Vec::new(),
                })
            }
            GenerationRequest::Transition {
                assurance,
                transition,
            } => self.activate_generation(*assurance, transition).await,
            GenerationRequest::Recommission { delegation } => self.recommission(delegation).await,
            GenerationRequest::DeriveRecord { selection } => {
                self.derive_commissioning_receipt(selection).await
            }
        }
    }

    async fn publish_generation(
        &self,
        inputs: SignedAdmissionWire<RuntimeGenerationInputs>,
        selection: CommissioningSelection,
        sources: ArtifactSourcePaths,
    ) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::Generation, inputs.clone())
            .map_err(refusal)?;
        let commissioning = self
            .commissioning_record(
                &durable,
                &admitted.payload().commissioning_record,
                &admitted.payload().commissioning_record_digest,
                &selection.receipt,
            )
            .await?;
        let artifact = GenerationArtifactBuilder::new(self.layout().artifact_dir.clone())
            .publish_with_provenance(
                self.anchors(),
                inputs.clone(),
                self.workspace(),
                &commissioning,
                CommissioningProvenance {
                    delegation: selection.receipt.delegation.clone(),
                    observations: selection.receipt.observations.clone(),
                    approvals: selection.receipt.approvals.clone(),
                    unresolved_obligations: selection.receipt.unresolved_obligations.clone(),
                },
                &self.resolve_sources(sources)?,
            )
            .map_err(refusal)?;
        let generation = artifact.generation().id().digest().clone();
        let stored = RuntimeGeneration {
            scope: self.scope().clone(),
            generation_digest: generation.clone(),
            input_digest: generation_input_digest(admitted.payload())?,
            // The immutable manifest binds every exact component digest.
            artifact_digest: artifact.manifest_digest().clone(),
            manifest: signed_wire_record(&inputs)?,
        };
        let authority_chain = self
            .admit_live_delegation_chain(&selection.publication_delegation, admitted.signer())
            .await?;
        self.require_live_publication_grant(authority_chain.last().ok_or_else(|| {
            CoordinatorError::Refused("publication authority chain is empty".to_string())
        })?)?;
        self.storage()
            .admit_generation_authorized(&stored, durable.revision, &authority_chain)
            .await
            .map_err(storage_refusal)?;
        let verified = GenerationArtifactBuilder::new(self.layout().artifact_dir.clone())
            .verify(
                self.anchors(),
                self.workspace(),
                &commissioning,
                &generation,
            )
            .map_err(refusal)?;
        Ok(OperationResult::Coordinated {
            result: json!({
                "generation": generation,
                "artifact_manifest": verified.manifest_digest(),
                "admitted": true,
            }),
            evidence_refs: Vec::new(),
        })
    }

    async fn verify_generation(
        &self,
        generation: Digest,
    ) -> Result<OperationResult, CoordinatorError> {
        let artifact = self.verified_generation(&generation).await?;
        Ok(OperationResult::Coordinated {
            result: json!({
                "generation": generation,
                "artifact_manifest": artifact.manifest_digest(),
                "verified": true,
                "build_reproducibility": "not_claimed",
            }),
            evidence_refs: Vec::new(),
        })
    }

    /// Re-admit provenance and reread every byte of one durable generation.
    pub(crate) async fn verified_generation(
        &self,
        generation: &Digest,
    ) -> Result<VerifiedGenerationArtifact, CoordinatorError> {
        let stored = self
            .storage()
            .load_generation(self.scope(), generation)
            .await
            .map_err(storage_refusal)?;
        let inputs = stored_inputs(&stored)?;
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::Generation, inputs)
            .map_err(refusal)?;
        if generation_input_digest(admitted.payload())? != stored.input_digest {
            return Err(CoordinatorError::Refused(
                "stored generation input digest differs from signed inputs".to_string(),
            ));
        }
        let builder = GenerationArtifactBuilder::new(self.layout().artifact_dir.clone());
        let durable = self.durable_snapshot().await?;
        let commissioning = self
            .commissioning_record(
                &durable,
                &admitted.payload().commissioning_record,
                &admitted.payload().commissioning_record_digest,
                &self
                    .load_commissioning_receipt(&durable, &admitted.payload().commissioning_record)
                    .await?,
            )
            .await?;
        let artifact = builder
            .verify(self.anchors(), self.workspace(), &commissioning, generation)
            .map_err(refusal)?;
        if artifact.manifest_digest() != &stored.artifact_digest {
            return Err(CoordinatorError::Refused(
                "stored artifact manifest differs from immutable artifact bytes".to_string(),
            ));
        }
        Ok(artifact)
    }

    /// Recompute one unsigned lifecycle-calibration report from the installed
    /// artifact verifier.  This is intentionally separate from signed
    /// assurance: the service can report what it observed but cannot mint the
    /// producer or verifier evidence activation requires.
    async fn generation_validation_report(
        &self,
        generation: Digest,
        control: &str,
    ) -> Result<GenerationValidationReport, CoordinatorError> {
        if control != ACTIVATE_CONTROL && control != ROLLBACK_CONTROL {
            return Err(CoordinatorError::Refused(
                "generation validation control is not an installed lifecycle control".to_string(),
            ));
        }
        let stored = self
            .storage()
            .load_generation(self.scope(), &generation)
            .await
            .map_err(storage_refusal)?;
        let inputs = stored_inputs(&stored)?;
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::Generation, inputs)
            .map_err(refusal)?;
        if generation_input_digest(admitted.payload())? != stored.input_digest {
            return Err(CoordinatorError::Refused(
                "stored generation input digest differs from signed inputs".to_string(),
            ));
        }
        // The generic byte verifier establishes immutable provenance.  The
        // active service boundary additionally requires that the policy and
        // execution registry bytes decode as this generation's typed runtime
        // contracts before it reports calibration or permits activation.
        let operational_registry = self
            .operational_registry_for_generation(&generation)
            .await?;
        let durable = self.durable_snapshot().await?;
        let commissioning = self
            .commissioning_record(
                &durable,
                &admitted.payload().commissioning_record,
                &admitted.payload().commissioning_record_digest,
                &self
                    .load_commissioning_receipt(&durable, &admitted.payload().commissioning_record)
                    .await?,
            )
            .await?;
        let calibration = GenerationArtifactBuilder::new(self.layout().artifact_dir.clone())
            .calibrate(
                self.anchors(),
                self.workspace(),
                &commissioning,
                &generation,
            )
            .map_err(refusal)?;
        if calibration.artifact.manifest_digest() != &stored.artifact_digest {
            return Err(CoordinatorError::Refused(
                "stored artifact manifest differs from immutable artifact bytes".to_string(),
            ));
        }
        GenerationValidationReport::from_calibration(
            generation,
            control,
            operational_registry.policy().bundle().clone(),
            operational_registry.policy().digest().clone(),
            calibration,
        )
        .map_err(refusal)
    }

    async fn activate_generation(
        &self,
        assurance: ActivationAssurance,
        transition: Option<SignedAdmissionWire<GenerationTransitionRequest>>,
    ) -> Result<OperationResult, CoordinatorError> {
        let transition = transition.ok_or_else(|| {
            CoordinatorError::Refused(
                "generation transition requires an installed-owner signed authorization"
                    .to_string(),
            )
        })?;
        let admitted_transition = self
            .anchors()
            .admit_expected(AdmissionKind::GenerationTransition, transition.clone())
            .map_err(refusal)?;
        if admitted_transition.signer() != &self.workspace().owner {
            return Err(CoordinatorError::Refused(
                "only the installed institution owner may authorize a generation transition"
                    .to_string(),
            ));
        }
        let transition_request = admitted_transition.payload();
        let generation = transition_request.generation.clone();
        let expected_revision = transition_request.expected_revision;
        let expected_active = transition_request.expected_active.clone();
        let action = transition_request.action;
        if assurance.run.payload.control != action.control()
            || assurance.proof.payload.control != action.control()
        {
            return Err(CoordinatorError::Refused(
                "signed lifecycle assurance control differs from owner transition action"
                    .to_string(),
            ));
        }
        if assurance.run.payload.input_digest != generation
            || assurance.run.payload.subject != generation
        {
            return Err(CoordinatorError::Refused(
                "signed lifecycle assurance target differs from owner transition target"
                    .to_string(),
            ));
        }
        if transition_request.assurance_digest
            != activation_assurance_digest(&assurance).map_err(refusal)?
        {
            return Err(CoordinatorError::Refused(
                "owner generation transition assurance digest differs from supplied assurance"
                    .to_string(),
            ));
        }
        let durable = self.durable_snapshot().await?;
        if durable.revision != expected_revision || durable.active_generation != expected_active {
            return Err(CoordinatorError::Refused(
                "generation activation compare-and-swap is stale".to_string(),
            ));
        }
        let stored = self
            .storage()
            .load_generation(self.scope(), &generation)
            .await
            .map_err(storage_refusal)?;
        let validation = self
            .generation_validation_report(generation.clone(), action.control())
            .await?;

        let now = self.observed_at().await?;
        let context = AuthorityContext::new(
            self.workspace().institution.clone(),
            self.workspace().id.clone(),
            durable.owner.clone(),
            now,
        );
        self.require_current_direct_grant(&durable, &assurance.run_authority)?;
        self.require_current_direct_grant(&durable, &assurance.proof_authority)?;
        let calibration = self
            .anchors()
            .admit_expected(AdmissionKind::Evidence, assurance.calibration.clone())
            .map_err(refusal)?;
        let run = self
            .anchors()
            .admit_expected(AdmissionKind::ControlRun, assurance.run.clone())
            .map_err(refusal)?;
        let run_authority = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, assurance.run_authority.clone())
            .map_err(refusal)?;
        let proof = self
            .anchors()
            .admit_expected(AdmissionKind::ActivationProof, assurance.proof.clone())
            .map_err(refusal)?;
        let proof_authority = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, assurance.proof_authority.clone())
            .map_err(refusal)?;
        let authorized =
            AuthorizedControlRun::admit(&run, &run_authority, &context).map_err(refusal)?;
        let verified =
            VerifiedActivation::admit(&proof, &proof_authority, &context).map_err(refusal)?;
        let artifact = stored.artifact_digest.clone();
        let run_value = authorized.run();
        let proof_value = verified.proof();
        let validation_digest = validation.digest().map_err(refusal)?;
        if calibration.signer() != proof.signer()
            || calibration.payload().producer_delegation != proof_authority.payload().id
            || calibration.payload().method != LIFECYCLE_CALIBRATION_METHOD
            || calibration.payload().subject != validation_digest
            || calibration.payload().payload_digest != validation_digest
            || calibration.payload().independence != IndependenceClass::IndependentAgent
            || calibration.payload().observed_at > proof_value.proved_at
            || proof_value.proved_at > run_value.started_at
            || proof_value.retained_evidence != calibration.payload().id
        {
            return Err(CoordinatorError::Refused(
                "activation proof lacks exact verifier-signed lifecycle calibration evidence"
                    .to_string(),
            ));
        }
        let run_authorization =
            direct_grant_authorization_digest(run_authority.payload()).map_err(refusal)?;
        if run_value.authorization != run_authorization {
            return Err(CoordinatorError::Refused(
                "control run authorization digest differs from its admitted direct grant"
                    .to_string(),
            ));
        }
        if validation.artifact_manifest != artifact
            || run_value.control != validation.control
            || run_value.control_version != validation.control_version
            || run_value.input_digest != validation.generation
            || run_value.subject != validation.generation
            || run_value.population != validation.population
            || run_value.configuration_digest != validation.artifact_manifest
            || run_value.policy != validation.policy
            || run_value.policy_digest != validation.policy_digest
            || run_value.mediation_path != validation.mediation_path
            || run_value.result != validation.known_good_result
            || run_value.coverage != validation.coverage
            || proof_value.control != validation.control
            || proof_value.control_version != validation.control_version
            || proof_value.configuration_digest != validation.artifact_manifest
            || proof_value.policy != validation.policy
            || proof_value.policy_digest != validation.policy_digest
            || proof_value.population != validation.population
            || proof_value.mediation_path != validation.mediation_path
            || proof_value.known_good != validation.known_good
            || proof_value.known_good_result != validation.known_good_result
            || proof_value.planted_violation != validation.planted_violation
            || proof_value.planted_violation_result != validation.planted_violation_result
        {
            return Err(CoordinatorError::Refused(
                "signed lifecycle assurance differs from freshly calibrated artifact validation"
                    .to_string(),
            ));
        }
        clean_claim(&[authorized], action.control(), &generation, &verified).map_err(refusal)?;
        let registry = self
            .operational_registry_for_generation(&generation)
            .await?;
        self.require_candidate_control_qualifications(
            &durable,
            &registry,
            &generation,
            &artifact,
            &assurance,
            now,
        )
        .await?;
        let evidence = vec![
            EvidenceAdmission {
                id: transition_request.evidence.clone(),
                record: signed_wire_record(&transition)?,
            },
            EvidenceAdmission {
                id: assurance.calibration.payload.id.clone(),
                record: signed_wire_record(&assurance.calibration)?,
            },
            EvidenceAdmission {
                id: assurance.run.payload.id.clone(),
                record: signed_wire_record(&assurance.run)?,
            },
            EvidenceAdmission {
                id: assurance.proof.payload.id.clone(),
                record: signed_wire_record(&assurance.proof)?,
            },
        ];
        let transition = signed_wire_record(&transition)?;
        let mut authority_chains = vec![
            self.admit_live_delegation_chain(
                &run_authority.payload().id,
                &run_authority.payload().subject,
            )
            .await?,
            self.admit_live_delegation_chain(
                &proof_authority.payload().id,
                &proof_authority.payload().subject,
            )
            .await?,
        ];
        for qualification in &assurance.qualifications {
            let grant = &qualification.proof_authority.payload;
            authority_chains.push(
                self.admit_live_delegation_chain(&grant.id, &grant.subject)
                    .await?,
            );
        }
        let receipt = self
            .storage()
            .activate_generation_authorized(
                &ActivationCommit {
                    scope: self.scope().clone(),
                    expected_revision,
                    expected_active,
                    generation: generation.clone(),
                    transition,
                    evidence,
                    outbox: Vec::new(),
                },
                &authority_chains,
            )
            .await
            .map_err(storage_refusal)?;
        Ok(OperationResult::Coordinated {
            result: json!({
                "generation": generation,
                "active_generation": generation,
                "revision": receipt.revision,
                "transition": receipt.transition_digest,
                "control": action.control(),
            }),
            evidence_refs: vec![
                assurance.calibration.payload.id.0.to_string(),
                assurance.run.payload.id.0.to_string(),
                assurance.proof.payload.id.0.to_string(),
                transition_request.evidence.0.to_string(),
            ],
        })
    }

    /// Refuse a transition until every control that can block a candidate
    /// operation has one independently admitted, real-path qualification.
    ///
    /// The owner signs the complete collection through
    /// [`activation_assurance_digest`].  This method only resolves and checks
    /// it before the compare-and-swap commit; it never admits caller-supplied
    /// reports or treats a detector-only calibration as qualification.
    async fn require_candidate_control_qualifications(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        registry: &ActiveOperationalRegistry,
        generation: &Digest,
        artifact: &Digest,
        assurance: &ActivationAssurance,
        at: jiff::Timestamp,
    ) -> Result<(), CoordinatorError> {
        let required = candidate_blocking_controls(registry.policy().bindings());
        let required_controls: BTreeSet<_> = required
            .iter()
            .map(|obligation| obligation.control.clone())
            .collect();
        let mut supplied = BTreeSet::new();
        for qualification in &assurance.qualifications {
            let resolved = self
                .resolve_detector_qualification(
                    durable,
                    &qualification.report,
                    &qualification.evidence,
                    &qualification.proof,
                    &qualification.proof_authority,
                    at,
                )
                .await?;
            let report = resolved.report();
            let real_path = registry
                .policy()
                .validate_detector_qualification(report)
                .map_err(refusal)?;
            let registered = registry
                .execution()
                .exact_operation(real_path.operation())
                .ok_or_else(|| {
                    CoordinatorError::Refused(
                        "candidate control qualification operation differs from its execution registry"
                            .to_string(),
                    )
                })?;
            let handler = politeia_core::canonical::to_canonical_bytes(&registered.handler)
                .map(|bytes| Digest::blake3(&bytes))
                .map_err(refusal)?;
            let resource = registry
                .execution()
                .resource(real_path.resource())
                .ok_or_else(|| {
                    CoordinatorError::Refused(
                    "candidate control qualification resource differs from its execution registry"
                        .to_string(),
                )
                })?;
            if !real_path.matches_candidate(generation, artifact, self.running_executable_digest())
                || real_path.handler() != &handler
                || resource.adapter != *real_path.adapter()
            {
                return Err(CoordinatorError::Refused(
                    "candidate control qualification differs from the exact target generation"
                        .to_string(),
                ));
            }
            if !supplied.insert(real_path.control().to_owned()) {
                return Err(CoordinatorError::Refused(
                    "candidate control qualifications duplicate one detector".to_string(),
                ));
            }
        }
        if supplied != required_controls {
            return Err(CoordinatorError::Refused(format!(
                "candidate control qualification coverage differs: missing {:?}; unexpected {:?}",
                required
                    .iter()
                    .filter(|obligation| !supplied.contains(&obligation.control))
                    .collect::<Vec<_>>(),
                supplied.difference(&required_controls).collect::<Vec<_>>(),
            )));
        }
        Ok(())
    }

    async fn recommission(
        &self,
        delegation: SignedAdmissionWire<Delegation>,
    ) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, delegation.clone())
            .map_err(refusal)?;
        self.validate_delegation_authority(&durable, &admitted)?;
        self.storage()
            .admit_delegation(self.scope(), &admitted, &delegation)
            .await
            .map_err(storage_refusal)?;
        Ok(OperationResult::Coordinated {
            result: json!({ "delegation": admitted.payload().id, "recommissioned": true }),
            evidence_refs: Vec::new(),
        })
    }

    /// Derive one canonical commissioning record from durable evidence and
    /// retain the exact receipt before returning it to a public client.
    async fn derive_commissioning_receipt(
        &self,
        selection: CommissioningRecordRequest,
    ) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let persisted = durable
            .delegations
            .get(&selection.delegation)
            .ok_or_else(|| {
                CoordinatorError::Refused(
                    "commissioner delegation is not durably admitted".to_string(),
                )
            })?;
        if persisted.revoked {
            return Err(CoordinatorError::Refused(
                "commissioner delegation is revoked before receipt derivation".to_string(),
            ));
        }
        let delegation = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
            .map_err(refusal)?;
        self.validate_delegation_authority(&durable, &delegation)?;
        let captured_at = self.observed_at().await?;
        if delegation.payload().expires_at <= captured_at {
            return Err(CoordinatorError::Refused(
                "commissioner delegation expired before receipt derivation".to_string(),
            ));
        }
        let evidence = provenance::selected_evidence(
            self.anchors(),
            &durable.evidence,
            &selection.observations,
            &selection.approvals,
        )?;
        let grant = CommissionerGrantRecord {
            institution: self.workspace().institution.clone(),
            workspace: self.workspace().id.clone(),
            valid_from: persisted.admitted_at,
            revoked_at: None,
            delegation: delegation.into_payload(),
        };
        let grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(captured_at, [grant])
            .map_err(refusal)?;
        let historical_observations = historical_reconnaissance_observations(
            self,
            &durable,
            &evidence,
            &selection.observations,
            captured_at,
        )?;
        let record = CommissioningRecord::new_from_historical_observations(
            self.workspace(),
            &grants,
            &evidence,
            &selection.observations,
            &historical_observations,
            &selection.approvals,
            selection.unresolved_obligations.clone(),
        )
        .map_err(refusal)?;
        let receipt = CommissioningReceipt {
            record: record.id().clone(),
            record_digest: record.digest().map_err(refusal)?,
            captured_at: record.captured_at(),
            commissioner: record.commissioner().clone(),
            delegation: record.commissioner_delegation().clone(),
            commissioner_grant_digest: record.commissioner_grant_digest().clone(),
            observations: selection.observations,
            approvals: selection.approvals,
            unresolved_obligations: selection.unresolved_obligations,
        };
        let payload = politeia_core::canonical::to_canonical_bytes(&receipt).map_err(refusal)?;
        self.storage()
            .admit_commissioning_receipt(
                self.scope(),
                &politeia_storage::CommissioningReceipt {
                    record: receipt.record.clone(),
                    record_digest: receipt.record_digest.clone(),
                    payload_digest: Digest::blake3(&payload),
                    payload,
                },
            )
            .await
            .map_err(storage_refusal)?;
        Ok(OperationResult::Coordinated {
            result: serde_json::to_value(&receipt).map_err(refusal)?,
            evidence_refs: receipt
                .observations
                .iter()
                .chain(receipt.approvals.iter())
                .map(|id| id.0.to_string())
                .collect(),
        })
    }

    pub(crate) async fn load_commissioning_receipt(
        &self,
        _durable: &politeia_storage::WorkspaceSnapshot,
        record: &politeia_core::CommissioningRecordId,
    ) -> Result<CommissioningReceipt, CoordinatorError> {
        let stored = self
            .storage()
            .load_commissioning_receipt(self.scope(), record)
            .await
            .map_err(storage_refusal)?;
        let receipt: CommissioningReceipt =
            serde_json::from_slice(&stored.payload).map_err(|error| {
                CoordinatorError::Refused(format!(
                    "durable commissioning receipt is malformed: {error}"
                ))
            })?;
        if receipt.record != stored.record || receipt.record_digest != stored.record_digest {
            return Err(CoordinatorError::Refused(
                "durable commissioning receipt identity differs from its storage binding"
                    .to_string(),
            ));
        }
        Ok(receipt)
    }

    fn require_live_publication_grant(
        &self,
        grant: &Admitted<Delegation>,
    ) -> Result<(), CoordinatorError> {
        let delegation = grant.payload();
        if grant.signer() != &delegation.issuer
            || !delegation.actions.contains(COMMISSION_ACTION)
            || !delegation
                .resources
                .contains(&commissioning_workspace_resource(&self.workspace().id))
            || !delegation
                .audience
                .contains(&commissioning_institution_audience(
                    &self.workspace().institution,
                ))
        {
            return Err(CoordinatorError::Refused(
                "generation publisher lacks a scoped live commissioning grant".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn commissioning_record(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        record_id: &politeia_core::CommissioningRecordId,
        expected_digest: &Digest,
        receipt: &CommissioningReceipt,
    ) -> Result<CommissioningRecord, CoordinatorError> {
        let stored = self.load_commissioning_receipt(durable, record_id).await?;
        if stored != *receipt
            || receipt.record != *record_id
            || receipt.record_digest != *expected_digest
        {
            return Err(CoordinatorError::Refused(
                "generation request does not carry the durable daemon commissioning receipt"
                    .to_string(),
            ));
        }
        let persisted = durable
            .delegations
            .get(&receipt.delegation)
            .ok_or_else(|| {
                CoordinatorError::Refused(
                    "commissioner delegation is not durably admitted".to_string(),
                )
            })?;
        let delegation = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
            .map_err(refusal)?;
        if delegation.signer() != &delegation.payload().issuer
            || delegation.payload().subject != receipt.commissioner
        {
            return Err(CoordinatorError::Refused(
                "generation signer does not hold the selected commissioner delegation".to_string(),
            ));
        }
        let evidence = provenance::selected_evidence(
            self.anchors(),
            &durable.evidence,
            &receipt.observations,
            &receipt.approvals,
        )?;
        let grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(
            receipt.captured_at,
            [CommissionerGrantRecord {
                institution: self.workspace().institution.clone(),
                workspace: self.workspace().id.clone(),
                valid_from: persisted.admitted_at,
                // The historical registry sees revocation only if it had
                // already happened at this record's retained snapshot.
                revoked_at: revocation_as_of(persisted.revoked_at, receipt.captured_at),
                delegation: delegation.into_payload(),
            }],
        )
        .map_err(refusal)?;
        let record = CommissioningRecord::rebuild(
            record_id.clone(),
            self.workspace(),
            politeia_core::commissioning::CommissioningRebuild {
                grants: &grants,
                evidence: &evidence,
                observation_ids: &receipt.observations,
                approval_ids: &receipt.approvals,
                unresolved_obligations: receipt.unresolved_obligations.clone(),
                historical_observations: &historical_reconnaissance_observations(
                    self,
                    durable,
                    &evidence,
                    &receipt.observations,
                    receipt.captured_at,
                )?,
            },
        )
        .map_err(refusal)?;
        if record.digest().map_err(refusal)? != *expected_digest
            || record.captured_at() != receipt.captured_at
            || record.commissioner_grant_digest() != &receipt.commissioner_grant_digest
        {
            return Err(CoordinatorError::Refused(
                "re-admitted commissioning provenance differs from signed generation inputs"
                    .to_string(),
            ));
        }
        Ok(record)
    }

    fn resolve_sources(
        &self,
        sources: ArtifactSourcePaths,
    ) -> Result<ArtifactSources, CoordinatorError> {
        let root = &self.layout().workspace_dir;
        Ok(ArtifactSources {
            public_source: confined(root, &sources.public_source)?,
            policy: confined(root, &sources.policy)?,
            specializer: confined(root, &sources.specializer)?,
            toolchain: confined(root, &sources.toolchain)?,
            schemas: resolve_map(root, sources.schemas)?,
            adapters: resolve_map(root, sources.adapters)?,
            packs: resolve_map(root, sources.packs)?,
            components: resolve_map(root, sources.components)?,
        })
    }

    async fn observed_at(&self) -> Result<jiff::Timestamp, CoordinatorError> {
        PostgresAuthorizationLedger::new(self.storage().clone(), self.scope().clone())
            .observed_at()
            .await
            .map_err(|error| {
                CoordinatorError::Refused(format!(
                    "durable authorization clock refused operation: {error}"
                ))
            })
    }

    fn require_current_direct_grant(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        wire: &SignedAdmissionWire<Delegation>,
    ) -> Result<(), CoordinatorError> {
        if durable.owner != self.workspace().owner
            || durable.owner_delegation != self.workspace().owner_delegation
        {
            return Err(CoordinatorError::Refused(
                "durable workspace owner differs from installed workspace skeleton".to_string(),
            ));
        }
        let persisted = durable.delegations.get(&wire.payload.id).ok_or_else(|| {
            CoordinatorError::Refused("assurance delegation is not durably admitted".to_string())
        })?;
        if persisted.revoked || persisted.wire != *wire {
            return Err(CoordinatorError::Refused(
                "assurance delegation is revoked or differs from its durable admission".to_string(),
            ));
        }
        Ok(())
    }
}

fn confined(root: &Path, path: &Path) -> Result<PathBuf, CoordinatorError> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(CoordinatorError::Refused(
            "artifact source path escapes the installed workspace".to_string(),
        ));
    }
    Ok(root.join(path))
}

fn resolve_map<K: Ord>(
    root: &Path,
    paths: BTreeMap<K, PathBuf>,
) -> Result<BTreeMap<K, PathBuf>, CoordinatorError> {
    paths
        .into_iter()
        .map(|(key, path)| confined(root, &path).map(|path| (key, path)))
        .collect()
}

/// Recover preserved, signed reconnaissance provenance for the selected
/// evidence identities. Every source capture and observation is re-admitted;
/// the original delegation chain is then checked at the observation instant,
/// so a later revoke does not rewrite the past and an earlier revoke refuses.
fn historical_reconnaissance_observations(
    service: &PoliteiadService,
    durable: &politeia_storage::WorkspaceSnapshot,
    evidence: &TrustedEvidenceRegistry,
    evidence_ids: &BTreeSet<EvidenceId>,
    as_of: jiff::Timestamp,
) -> Result<
    BTreeMap<EvidenceId, politeia_core::commissioning::HistoricalObservationProvenance>,
    CoordinatorError,
> {
    let (capture_wires, observation_wires) =
        provenance::selected_reconnaissance_wires(durable, evidence_ids)?;
    let captures = TrustedSourceCaptureRegistry::admit_signed(service.anchors(), capture_wires)
        .map_err(refusal)?;
    let observations = TrustedObservationRegistry::admit_signed(
        service.workspace(),
        service.anchors(),
        evidence,
        &captures,
        observation_wires,
    )
    .map_err(refusal)?;
    evidence_ids
        .iter()
        .map(|evidence_id| {
            let observation = observations
                .resolve_by_evidence(evidence_id)
                .ok_or_else(|| {
                    CoordinatorError::Refused(
                        "commissioning evidence has no retained signed observation".to_string(),
                    )
                })?;
            let capture = captures.resolve(&observation.capture).ok_or_else(|| {
                CoordinatorError::Refused(
                    "commissioning observation has no retained signed capture".to_string(),
                )
            })?;
            let chain = service.admit_historical_delegation_chain(
                durable,
                &capture.request().reconnaissance_delegation,
                capture.signer(),
                observation.observed_at,
            )?;
            let leaf = chain.last().ok_or_else(|| {
                CoordinatorError::Refused("historical delegation chain is empty".to_string())
            })?;
            let persisted = durable.delegations.get(&leaf.payload().id).ok_or_else(|| {
                CoordinatorError::Refused(
                    "historical capture delegation is no longer durable".to_string(),
                )
            })?;
            let provenance = CommissioningRecord::historical_observation_from_trusted(
                service.workspace(),
                evidence,
                &captures,
                &observations,
                evidence_id,
                HistoricalReconnaissanceGrantRecord {
                    institution: service.workspace().institution.clone(),
                    workspace: service.workspace().id.clone(),
                    valid_from: persisted.admitted_at,
                    revoked_at: revocation_as_of(persisted.revoked_at, as_of),
                    scope: capture.request().reconnaissance.clone(),
                    delegation: leaf.payload().clone(),
                },
                as_of,
            )
            .map_err(refusal)?;
            Ok((evidence_id.clone(), provenance))
        })
        .collect()
}

/// Project durable revocation state into a retained historical snapshot.
/// A later revoke remains in PostgreSQL but was not a fact at this record's
/// capture instant; an earlier revoke remains visible and refuses replay.
fn revocation_as_of(
    revoked_at: Option<jiff::Timestamp>,
    as_of: jiff::Timestamp,
) -> Option<jiff::Timestamp> {
    revoked_at.filter(|revoked| *revoked <= as_of)
}

#[cfg(test)]
mod historical_replay_tests {
    use jiff::SignedDuration;

    use super::revocation_as_of;

    #[expect(
        clippy::expect_used,
        reason = "fixed historical snapshot witness must parse"
    )]
    fn captured_at() -> jiff::Timestamp {
        "2026-09-10T00:00:00Z"
            .parse()
            .expect("the witness timestamp is RFC 3339")
    }

    #[test]
    fn later_revoke_does_not_rewrite_a_historical_receipt() {
        let captured = captured_at();
        assert_eq!(
            revocation_as_of(Some(captured + SignedDuration::from_secs(1)), captured),
            None
        );
    }

    #[test]
    fn earlier_revoke_remains_visible_to_historical_replay() {
        let captured = captured_at();
        assert_eq!(
            revocation_as_of(Some(captured - SignedDuration::from_secs(1)), captured),
            Some(captured - SignedDuration::from_secs(1))
        );
    }
}

fn stored_inputs(
    stored: &RuntimeGeneration,
) -> Result<SignedAdmissionWire<RuntimeGenerationInputs>, CoordinatorError> {
    let wire: SignedAdmissionWire<RuntimeGenerationInputs> =
        serde_json::from_slice(stored.manifest.payload()).map_err(|error| {
            CoordinatorError::Refused(format!("stored generation wire is malformed: {error}"))
        })?;
    if wire.signer != *stored.manifest.signer() || wire.signature != stored.manifest.signature() {
        return Err(CoordinatorError::Refused(
            "stored generation wire differs from its durable signature".to_string(),
        ));
    }
    Ok(wire)
}

fn signed_wire_record<T: serde::Serialize>(
    wire: &SignedAdmissionWire<T>,
) -> Result<SignedRecord, CoordinatorError> {
    let value = serde_json::to_value(wire).map_err(|error| {
        CoordinatorError::Refused(format!("signed wire encoding failed: {error}"))
    })?;
    SignedRecord::from_json(&value, wire.signer.clone(), wire.signature.clone())
        .map_err(storage_refusal)
}

fn refusal(error: impl std::fmt::Display) -> CoordinatorError {
    CoordinatorError::Refused(error.to_string())
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as a Result::map_err adapter"
)]
fn storage_refusal(error: politeia_storage::StorageError) -> CoordinatorError {
    CoordinatorError::Refused(format!("durable authority refused operation: {error}"))
}

fn generation_input_digest(inputs: &RuntimeGenerationInputs) -> Result<Digest, CoordinatorError> {
    politeia_core::canonical::to_canonical_bytes(inputs)
        .map(|bytes| Digest::blake3(&bytes))
        .map_err(refusal)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::confined;

    #[test]
    fn artifact_inputs_are_relative_to_the_installed_workspace() {
        let root = Path::new("/installed/workspace");
        assert!(
            confined(root, Path::new("approved/policy.json"))
                .is_ok_and(|path| path == root.join("approved/policy.json"))
        );
        assert!(confined(root, Path::new("../outside")).is_err());
        assert!(confined(root, Path::new("/outside")).is_err());
        assert!(confined(root, &PathBuf::from("a/../../outside")).is_err());
    }
}
