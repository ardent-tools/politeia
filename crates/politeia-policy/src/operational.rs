//! Generation-bound policy registry and deterministic public controls.
//!
//! The immutable generation carries the exact bytes decoded here. A registry
//! cannot become active by deserialization alone: admission binds those bytes
//! to the generation's policy bundle and digest, validates every executable
//! detector configuration, and rejects ambiguous identities.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use politeia_core::canonical::{CanonicalError, to_canonical_bytes};
use politeia_core::trust::Admitted;
use politeia_core::{
    AdapterId, BudgetReservationId, Delegation, DelegationId, Digest, EffectLeaseId, EvidenceId,
    ExecutionResourceId, InstitutionId, InstitutionWorkspaceId, OperationSpec, PolicyBundleId,
    PrincipalId, RuntimeGenerationId,
};
use politeia_evidence::assurance::{
    ActivationProof, AuthorizedControlQualification, ControlQualificationVectorSet, ControlResult,
    ControlRun, Coverage,
};
use politeia_evidence::authority::AuthorityContext;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::evaluate::{
    EvaluationEvidence, EvaluationSubject, QualificationEvaluation, Unevaluable, evaluate,
    evaluate_with_qualification_target,
};
use crate::{
    ControlQualificationPurpose, DetectorSpec, PolicyBinding, PolicyDecision, QualificationVector,
};

/// Prefix for the operation-derived scope used by operational bindings.
pub const OPERATION_SCOPE_PREFIX: &str = "operation:";

/// An executable deterministic detector whose configuration is public.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicDetectorRule {
    /// Report a violation when any exact intent resource has this prefix.
    ResourcePrefixForbidden {
        /// Non-empty prefix that identifies forbidden resources.
        forbidden_prefix: String,
        /// Known-good calibration input retained in the policy artifact.
        known_good_resources: BTreeSet<String>,
        /// Calibration input containing at least one forbidden resource.
        planted_violation_resources: BTreeSet<String>,
    },
}

impl PublicDetectorRule {
    /// Digest the exact executable detector configuration.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if the rule cannot be represented.
    pub fn configuration_digest(&self) -> Result<Digest, CanonicalError> {
        digest(&DetectorConfiguration {
            kind: "politeia.public-detector.configuration.v1",
            rule: self,
        })
    }

    /// Digest the complete known-good and planted-negative calibration population.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if the population cannot be represented.
    pub fn calibration_population_digest(&self) -> Result<Digest, CanonicalError> {
        let (known_good, planted_violation) = match self {
            Self::ResourcePrefixForbidden {
                known_good_resources,
                planted_violation_resources,
                ..
            } => (known_good_resources, planted_violation_resources),
        };
        digest(&CalibrationPopulation {
            kind: "politeia.public-detector.calibration-population.v1",
            known_good,
            planted_violation,
        })
    }

    /// Derive a result and complete coverage from actual normalized resources.
    pub fn evaluate(&self, resources: &BTreeSet<String>) -> (ControlResult, Coverage) {
        let result = if resources.is_empty() {
            ControlResult::UnexpectedlyEmpty
        } else {
            match self {
                Self::ResourcePrefixForbidden {
                    forbidden_prefix, ..
                } if resources
                    .iter()
                    .any(|resource| resource.starts_with(forbidden_prefix)) =>
                {
                    ControlResult::Violation
                }
                Self::ResourcePrefixForbidden { .. } => ControlResult::Clean,
            }
        };
        let population = u64::try_from(resources.len()).unwrap_or(u64::MAX);
        (
            result,
            Coverage {
                population,
                observed: population,
            },
        )
    }

    /// Digest one exact detector input for a control run or activation proof.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if the input cannot be represented.
    pub fn input_digest(&self, resources: &BTreeSet<String>) -> Result<Digest, CanonicalError> {
        digest(&DetectorInput {
            kind: "politeia.public-detector.input.v1",
            resources,
        })
    }

    fn calibration_inputs(&self) -> (&BTreeSet<String>, &BTreeSet<String>) {
        match self {
            Self::ResourcePrefixForbidden {
                known_good_resources,
                planted_violation_resources,
                ..
            } => (known_good_resources, planted_violation_resources),
        }
    }

    fn validate(&self) -> Result<(), OperationalPolicyRefusal> {
        match self {
            Self::ResourcePrefixForbidden {
                forbidden_prefix,
                known_good_resources,
                planted_violation_resources,
            } => {
                if forbidden_prefix.is_empty()
                    || known_good_resources.is_empty()
                    || planted_violation_resources.is_empty()
                {
                    return Err(OperationalPolicyRefusal::InvalidDetectorCalibration);
                }
                if self.evaluate(known_good_resources).0 != ControlResult::Clean
                    || self.evaluate(planted_violation_resources).0 != ControlResult::Violation
                {
                    return Err(OperationalPolicyRefusal::InvalidDetectorCalibration);
                }
            }
        }
        Ok(())
    }
}

/// Metadata and executable rule for one public operational detector.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationalDetector {
    /// Assurance and binding metadata consumed by the normalized evaluator.
    pub spec: DetectorSpec,
    /// Deterministic public rule whose result the service recomputes.
    pub rule: PublicDetectorRule,
}

/// Reproducible known-good and planted-violation output from one public detector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicDetectorCalibration {
    /// Calibration payload schema.
    pub schema: String,
    /// Stable detector identity.
    pub control: String,
    /// Exact public detector version.
    pub control_version: String,
    /// Digest of the executable detector configuration.
    pub configuration_digest: Digest,
    /// Policy bundle in which the detector is installed.
    pub policy: PolicyBundleId,
    /// Digest of the exact canonical policy bytes.
    pub policy_digest: Digest,
    /// Digest of both public calibration inputs.
    pub population: Digest,
    /// Installed mediation path exercised by the detector.
    pub mediation_path: String,
    /// Exact public known-good resource set.
    pub known_good_resources: BTreeSet<String>,
    /// Actual result returned for the known-good set.
    pub known_good_result: ControlResult,
    /// Exact public planted-violation resource set.
    pub planted_violation_resources: BTreeSet<String>,
    /// Actual result returned for the planted violation.
    pub planted_violation_result: ControlResult,
    /// Sealed actual dispatcher exercise; absent on direct rule calibration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    qualification: Option<Box<DetectorQualification>>,
}

/// Typed reason the planted vector never received dispatcher authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DetectorQualificationDenial {
    /// The actual policy decision denied the planted control violation.
    PolicyDenied,
}

/// Durable database observations proving the planted denial had no effect path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualificationNoEffectObservation {
    /// Matching durable operation attempts observed after denial.
    pub attempts: u64,
    /// Calls observed by the concrete effect port used for the planted vector.
    pub port_invocations: u64,
}

impl QualificationNoEffectObservation {
    const fn is_empty(self) -> bool {
        self.attempts == 0 && self.port_invocations == 0
    }
}

/// Service observations supplied to the canonical qualification report owner.
///
/// These fields are inert until [`OperationalQualification::qualify_calibration`]
/// rechecks both actual target runs and seals all candidate axes into the
/// existing [`PublicDetectorCalibration`] report.
#[derive(Clone, Debug)]
pub struct DetectorQualificationObservation {
    /// Digest of the candidate's exact signed artifact manifest.
    pub artifact_manifest: Digest,
    /// Digest of the executable exercised by the daemon.
    pub executable: Digest,
    /// Digest of the installed handler selected for the operation.
    pub handler: Digest,
    /// Installed execution resource selected by routing.
    pub resource: ExecutionResourceId,
    /// Effect adapter actually reached by the known-good dispatch.
    pub adapter: AdapterId,
    /// Actual target run returned with the known-good policy decision.
    pub known_good_run: ControlRun,
    /// Dispatcher lease issued for the known-good operation.
    pub known_good_lease: EffectLeaseId,
    /// Durable reservation consumed by the known-good operation.
    pub known_good_reservation: BudgetReservationId,
    /// Digest of the canonical retained known-good operation receipt.
    pub known_good_receipt: Digest,
    /// Actual target run returned with the planted policy denial.
    pub planted_violation_run: ControlRun,
    /// Typed dispatcher refusal observed for the planted vector.
    pub planted_violation_denial: DetectorQualificationDenial,
    /// Durable proof that the planted vector created no effect-side state.
    pub planted_violation_no_effect: QualificationNoEffectObservation,
    /// Trusted instant immediately before the paired dispatcher exercise.
    pub observed_started_at: Timestamp,
    /// Trusted instant immediately after all outcomes and absence checks.
    pub observed_finished_at: Timestamp,
}

/// Real-path portion of the existing public detector calibration report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectorQualification {
    capability: Digest,
    candidate: RuntimeGenerationId,
    artifact_manifest: Digest,
    executable: Digest,
    binding: String,
    operation: OperationSpec,
    handler: Digest,
    resource: ExecutionResourceId,
    adapter: AdapterId,
    expected_active: Option<Digest>,
    expected_revision: i64,
    qualification_actor: PrincipalId,
    qualification_authority: DelegationId,
    qualification_authority_digest: Digest,
    known_good_intent: Digest,
    known_good_run: ControlRun,
    known_good_lease: EffectLeaseId,
    known_good_reservation: BudgetReservationId,
    known_good_receipt: Digest,
    planted_violation_intent: Digest,
    planted_violation_run: ControlRun,
    planted_violation_denial: DetectorQualificationDenial,
    planted_violation_no_effect: QualificationNoEffectObservation,
    observed_started_at: Timestamp,
    observed_finished_at: Timestamp,
}

impl DetectorQualification {
    /// Opaque capability whose two dispatcher exercises produced this report.
    pub fn capability(&self) -> &Digest {
        &self.capability
    }

    /// Inactive candidate generation exercised by the dispatcher.
    pub fn candidate(&self) -> &RuntimeGenerationId {
        &self.candidate
    }

    /// Authenticated actor who performed the two dispatcher exercises.
    pub fn qualification_actor(&self) -> &PrincipalId {
        &self.qualification_actor
    }

    /// Durable direct owner-grant identity retained for exact re-admission.
    pub fn qualification_authority_id(&self) -> &DelegationId {
        &self.qualification_authority
    }

    /// Actual known-good target-control invocation.
    pub fn known_good_run(&self) -> &ControlRun {
        &self.known_good_run
    }

    /// Lease issued by the dispatcher for the retained known-good exercise.
    pub fn known_good_lease(&self) -> &EffectLeaseId {
        &self.known_good_lease
    }

    /// Durable reservation claimed by the retained known-good exercise.
    pub fn known_good_reservation(&self) -> &BudgetReservationId {
        &self.known_good_reservation
    }

    /// Content digest of the retained known-good completion receipt.
    pub fn known_good_receipt(&self) -> &Digest {
        &self.known_good_receipt
    }

    /// Actual planted-violation target-control invocation.
    pub fn planted_violation_run(&self) -> &ControlRun {
        &self.planted_violation_run
    }

    /// Typed planted-vector denial observed on the dispatcher path.
    pub const fn planted_violation_denial(&self) -> DetectorQualificationDenial {
        self.planted_violation_denial
    }

    /// Durable absence observations for the refused planted vector.
    pub const fn planted_violation_no_effect(&self) -> QualificationNoEffectObservation {
        self.planted_violation_no_effect
    }

    /// Trusted instant immediately before the paired real-path exercise.
    pub const fn observed_started_at(&self) -> Timestamp {
        self.observed_started_at
    }

    /// Trusted instant after both outcomes and planted absence checks completed.
    pub const fn observed_finished_at(&self) -> Timestamp {
        self.observed_finished_at
    }
}

/// Registry-checked view of one exact blocking binding qualification.
///
/// Construction is private to
/// [`OperationalPolicyRegistry::validate_detector_qualification`].
pub struct CheckedDetectorQualification<'report> {
    qualification: &'report DetectorQualification,
    binding: &'report PolicyBinding,
    control: &'report str,
}

impl CheckedDetectorQualification<'_> {
    /// Exact blocking binding proved by this report.
    pub fn binding(&self) -> &str {
        &self.binding.id
    }

    /// Exact operation scope bound by the proved binding.
    pub fn scope(&self) -> &str {
        &self.binding.scope
    }

    /// Exact detector proved for that binding.
    pub fn control(&self) -> &str {
        self.control
    }

    /// Installed operation exercised on the real path.
    pub fn operation(&self) -> &OperationSpec {
        &self.qualification.operation
    }

    /// Installed handler digest claimed by the retained exercise.
    pub fn handler(&self) -> &Digest {
        &self.qualification.handler
    }

    /// Execution resource selected for the retained exercise.
    pub fn resource(&self) -> &ExecutionResourceId {
        &self.qualification.resource
    }

    /// Effect adapter reached by the known-good exercise.
    pub fn adapter(&self) -> &AdapterId {
        &self.qualification.adapter
    }

    /// Check the immutable candidate artifacts supplied by the lifecycle gate.
    ///
    /// The report retains the historical active pointer and revision used to
    /// fence reserve and claim. A later governed report commit necessarily
    /// advances the workspace, so the lifecycle transition must CAS its own
    /// current pointer and revision rather than compare them to that history.
    pub fn matches_candidate(
        &self,
        generation: &Digest,
        artifact_manifest: &Digest,
        executable: &Digest,
    ) -> bool {
        self.qualification.candidate.digest() == generation
            && &self.qualification.artifact_manifest == artifact_manifest
            && &self.qualification.executable == executable
    }
}

/// The two exact signed operation intents selected for one qualification.
///
/// This is inert constructor input. Exceptional dispatch authority exists only
/// after [`OperationalPolicyRegistry::admit_qualification`] checks each intent
/// against the immutable detector vector and the direct owner grant that names
/// both intent digests.
#[derive(Clone, Copy)]
pub struct QualificationVectorInputs<'input> {
    known_good: &'input OperationalEvaluationRequest,
    planted_violation: &'input OperationalEvaluationRequest,
}

impl<'input> QualificationVectorInputs<'input> {
    /// Pair the normalized requests derived from the two signed intents.
    pub const fn new(
        known_good: &'input OperationalEvaluationRequest,
        planted_violation: &'input OperationalEvaluationRequest,
    ) -> Self {
        Self {
            known_good,
            planted_violation,
        }
    }
}

/// Opaque authority for the two exact dispatcher exercises that establish one
/// inactive candidate control's activation evidence.
///
/// Private fields prevent a service from widening candidate admission after
/// the registry and direct-grant checks. Storage rechecks the mutable candidate
/// pointer and revision when either vector reaches reserve or claim.
#[derive(Clone, Debug)]
pub struct OperationalQualification {
    payload: OperationalQualificationPayload,
    digest: Digest,
    known_good_replay_domain: String,
    planted_violation_replay_domain: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationalQualificationPayload {
    schema: &'static str,
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    generation: RuntimeGenerationId,
    expected_active: Option<Digest>,
    expected_revision: i64,
    policy: PolicyBundleId,
    policy_digest: Digest,
    binding: String,
    control: String,
    control_version: String,
    configuration_digest: Digest,
    population: Digest,
    mediation_path: String,
    operation: OperationSpec,
    principal: PrincipalId,
    authority_actor: PrincipalId,
    authority: DelegationId,
    authority_digest: Digest,
    admitted_at: Timestamp,
    known_good: QualificationVectorBinding,
    planted_violation: QualificationVectorBinding,
    expires_at: Timestamp,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationVectorBinding {
    intent: Digest,
    subject: Digest,
    population: Digest,
    resources: BTreeSet<String>,
    run: EvidenceId,
    expected_result: ControlResult,
    expected_coverage: Coverage,
}

/// A target-control result produced inside one policy decision invocation.
///
/// The interval is not complete until the caller supplies the trusted finish
/// instant observed after evaluation. Only then can this become a dispatchable
/// [`QualifiedPolicyDecision`].
#[must_use = "a qualification evaluation is not dispatchable until its interval is finished"]
pub struct PendingQualificationDecision {
    decision: PolicyDecision,
    capability: Digest,
    vector: QualificationVector,
    generation: RuntimeGenerationId,
    replay_domain: String,
    expires_at: Timestamp,
    control_run: ControlRun,
}

impl PendingQualificationDecision {
    /// Close the actual target-control interval and obtain the checked bundle.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal::QualificationIntervalMismatch`]
    /// when the finish instant predates evaluation or reaches authority expiry.
    pub fn finish(
        mut self,
        finished_at: Timestamp,
    ) -> Result<QualifiedPolicyDecision, OperationalPolicyRefusal> {
        if finished_at < self.control_run.started_at || finished_at >= self.expires_at {
            return Err(OperationalPolicyRefusal::QualificationIntervalMismatch);
        }
        self.control_run.finished_at = finished_at;
        let purpose = ControlQualificationPurpose::new(
            self.capability,
            self.vector,
            self.generation,
            self.replay_domain,
            self.expires_at,
            self.control_run.clone(),
        );
        Ok(QualifiedPolicyDecision {
            decision: self
                .decision
                .with_qualification_purpose(purpose)
                .map_err(OperationalPolicyRefusal::Canonical)?,
            control_run: self.control_run,
        })
    }
}

/// Checked policy output and the actual target run from the same invocation.
///
/// A service may retain the run for the post-exercise report before moving the
/// decision into the ordinary dispatcher interface. Neither value is accepted
/// as activation proof by itself.
#[derive(Clone, Debug)]
pub struct QualifiedPolicyDecision {
    decision: PolicyDecision,
    control_run: ControlRun,
}

impl QualifiedPolicyDecision {
    /// Actual selected-control invocation produced with this decision.
    pub fn control_run(&self) -> &ControlRun {
        &self.control_run
    }

    /// Borrow the normalized decision supplied to the dispatcher.
    pub fn decision(&self) -> &PolicyDecision {
        &self.decision
    }

    /// Move the normalized decision into the ordinary dispatcher interface.
    pub fn into_decision(self) -> PolicyDecision {
        self.decision
    }
}

impl OperationalQualification {
    /// Canonical digest of every immutable capability axis.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Inactive runtime generation this capability is restricted to.
    pub fn generation(&self) -> &RuntimeGenerationId {
        &self.payload.generation
    }

    /// Institution whose storage authority may admit this candidate exercise.
    pub fn institution(&self) -> &InstitutionId {
        &self.payload.institution
    }

    /// Workspace whose storage authority may admit this candidate exercise.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.payload.workspace
    }

    /// Active-generation pointer observed when the capability was admitted.
    pub fn expected_active(&self) -> Option<&Digest> {
        self.payload.expected_active.as_ref()
    }

    /// Workspace revision observed when the capability was admitted.
    pub const fn expected_revision(&self) -> i64 {
        self.payload.expected_revision
    }

    /// Latest instant at which any authority behind this capability is live.
    pub const fn expires_at(&self) -> Timestamp {
        self.payload.expires_at
    }

    /// Durable direct owner grant that authorizes this qualification.
    pub fn authority(&self) -> &DelegationId {
        &self.payload.authority
    }

    /// Canonical digest of the exact direct owner grant.
    pub fn authority_digest(&self) -> &Digest {
        &self.payload.authority_digest
    }

    /// Authenticated actor entrusted with this exact qualification.
    pub fn actor(&self) -> &PrincipalId {
        &self.payload.authority_actor
    }

    /// Exact signed intent admitted for `vector`.
    pub fn intent(&self, vector: QualificationVector) -> &Digest {
        &self.vector(vector).intent
    }

    /// Exact immutable resource vector covered by this capability.
    pub fn resources(&self, vector: QualificationVector) -> &BTreeSet<String> {
        &self.vector(vector).resources
    }

    /// Target-control result that the immutable vector must produce.
    pub fn expected_result(&self, vector: QualificationVector) -> ControlResult {
        self.vector(vector).expected_result
    }

    /// Complete target-control coverage that the immutable vector must produce.
    pub fn expected_coverage(&self, vector: QualificationVector) -> Coverage {
        self.vector(vector).expected_coverage
    }

    /// Check that a run is the actual target observation bound by this capability.
    pub fn admits_control_run(&self, vector: QualificationVector, run: &ControlRun) -> bool {
        let expected = self.vector(vector);
        run.id == expected.run
            && run.control == self.payload.control
            && run.control_version == self.payload.control_version
            && run.configuration_digest == self.payload.configuration_digest
            && run.policy == self.payload.policy
            && run.policy_digest == self.payload.policy_digest
            && run.input_digest == expected.intent
            && run.subject == expected.subject
            && run.population == expected.population
            && run.authorization == self.payload.authority_digest
            && run.mediation_path == self.payload.mediation_path
            && run.started_at >= self.payload.admitted_at
            && run.finished_at >= run.started_at
            && run.finished_at < self.payload.expires_at
            && run.result == expected.expected_result
            && run.coverage == expected.expected_coverage
    }

    /// Seal actual dispatcher outcomes into the existing calibration report.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal::QualificationReportMismatch`] when
    /// the calibration, either actual target run, the exercise interval, or
    /// the planted no-effect observation differs from this capability.
    pub fn qualify_calibration(
        &self,
        mut calibration: PublicDetectorCalibration,
        observation: DetectorQualificationObservation,
    ) -> Result<PublicDetectorCalibration, OperationalPolicyRefusal> {
        let good = self.vector(QualificationVector::KnownGood);
        let planted = self.vector(QualificationVector::PlantedViolation);
        if calibration.qualification.is_some()
            || calibration.control != self.payload.control
            || calibration.control_version != self.payload.control_version
            || calibration.configuration_digest != self.payload.configuration_digest
            || calibration.policy != self.payload.policy
            || calibration.policy_digest != self.payload.policy_digest
            || calibration.population != self.payload.population
            || calibration.mediation_path != self.payload.mediation_path
            || calibration.known_good_resources != good.resources
            || calibration.known_good_result != good.expected_result
            || calibration.planted_violation_resources != planted.resources
            || calibration.planted_violation_result != planted.expected_result
            || !self.admits_control_run(QualificationVector::KnownGood, &observation.known_good_run)
            || !self.admits_control_run(
                QualificationVector::PlantedViolation,
                &observation.planted_violation_run,
            )
            || observation.known_good_run.id == observation.planted_violation_run.id
            || !observation.planted_violation_no_effect.is_empty()
            || observation.observed_started_at < self.payload.admitted_at
            || observation.observed_started_at > observation.known_good_run.started_at
            || observation.observed_started_at > observation.planted_violation_run.started_at
            || observation.observed_finished_at < observation.known_good_run.finished_at
            || observation.observed_finished_at < observation.planted_violation_run.finished_at
            || observation.observed_finished_at < observation.observed_started_at
            || observation.observed_finished_at >= self.payload.expires_at
        {
            return Err(OperationalPolicyRefusal::QualificationReportMismatch);
        }
        calibration.qualification = Some(Box::new(DetectorQualification {
            capability: self.digest.clone(),
            candidate: self.payload.generation.clone(),
            artifact_manifest: observation.artifact_manifest,
            executable: observation.executable,
            binding: self.payload.binding.clone(),
            operation: self.payload.operation.clone(),
            handler: observation.handler,
            resource: observation.resource,
            adapter: observation.adapter,
            expected_active: self.payload.expected_active.clone(),
            expected_revision: self.payload.expected_revision,
            qualification_actor: self.payload.authority_actor.clone(),
            qualification_authority: self.payload.authority.clone(),
            qualification_authority_digest: self.payload.authority_digest.clone(),
            known_good_intent: good.intent.clone(),
            known_good_run: observation.known_good_run,
            known_good_lease: observation.known_good_lease,
            known_good_reservation: observation.known_good_reservation,
            known_good_receipt: observation.known_good_receipt,
            planted_violation_intent: planted.intent.clone(),
            planted_violation_run: observation.planted_violation_run,
            planted_violation_denial: observation.planted_violation_denial,
            planted_violation_no_effect: observation.planted_violation_no_effect,
            observed_started_at: observation.observed_started_at,
            observed_finished_at: observation.observed_finished_at,
        }));
        Ok(calibration)
    }

    /// Stable vector-specific replay domain for durable replay and accounting.
    ///
    /// This identity excludes the grant, admission instant, workspace
    /// revision, active pointer, and reserved run identities. Re-admitting the
    /// same candidate control therefore cannot reset its durable replay
    /// history; the exact signed request remains distinguished by replay key.
    pub fn replay_domain(&self, vector: QualificationVector) -> String {
        match vector {
            QualificationVector::KnownGood => self.known_good_replay_domain.clone(),
            QualificationVector::PlantedViolation => self.planted_violation_replay_domain.clone(),
        }
    }

    fn vector(&self, vector: QualificationVector) -> &QualificationVectorBinding {
        match vector {
            QualificationVector::KnownGood => &self.payload.known_good,
            QualificationVector::PlantedViolation => &self.payload.planted_violation,
        }
    }
}

impl PublicDetectorCalibration {
    /// Actual dispatcher exercise attached to this calibration, when present.
    pub fn qualification(&self) -> Option<&DetectorQualification> {
        self.qualification.as_deref()
    }

    /// Digest this exact public calibration report.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if the report cannot be represented.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        digest(self)
    }

    /// Construct the activation proof that cites one retained report.
    pub fn activation_proof(
        &self,
        id: politeia_core::EvidenceId,
        retained_evidence: politeia_core::EvidenceId,
        proved_at: Timestamp,
    ) -> Result<ActivationProof, OperationalPolicyRefusal> {
        if self.qualification.is_none() {
            return Err(OperationalPolicyRefusal::MissingDispatcherQualification);
        }
        let proof = ActivationProof {
            id,
            control: self.control.clone(),
            control_version: self.control_version.clone(),
            configuration_digest: self.configuration_digest.clone(),
            policy: self.policy.clone(),
            policy_digest: self.policy_digest.clone(),
            population: self.population.clone(),
            mediation_path: self.mediation_path.clone(),
            planted_violation: digest(&DetectorInput {
                kind: "politeia.public-detector.input.v1",
                resources: &self.planted_violation_resources,
            })
            .map_err(OperationalPolicyRefusal::Canonical)?,
            planted_violation_result: self.planted_violation_result,
            known_good: digest(&DetectorInput {
                kind: "politeia.public-detector.input.v1",
                resources: &self.known_good_resources,
            })
            .map_err(OperationalPolicyRefusal::Canonical)?,
            known_good_result: self.known_good_result,
            retained_evidence,
            proved_at,
        };
        self.validate_retained_activation_proof(&proof, &proof.retained_evidence)?;
        Ok(proof)
    }

    /// Validate every proof axis against this retained real-path report.
    ///
    /// `retained_evidence` is the independently signed evidence record whose
    /// subject is the digest of these complete calibration bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal::ActivationReportMismatch`] unless
    /// all policy, detector, vector, retained-evidence, and post-exercise time
    /// axes agree exactly.
    pub fn validate_retained_activation_proof(
        &self,
        proof: &ActivationProof,
        retained_evidence: &EvidenceId,
    ) -> Result<(), OperationalPolicyRefusal> {
        let qualification = self
            .qualification()
            .ok_or(OperationalPolicyRefusal::MissingDispatcherQualification)?;
        let known_good = digest(&DetectorInput {
            kind: "politeia.public-detector.input.v1",
            resources: &self.known_good_resources,
        })
        .map_err(OperationalPolicyRefusal::Canonical)?;
        let planted_violation = digest(&DetectorInput {
            kind: "politeia.public-detector.input.v1",
            resources: &self.planted_violation_resources,
        })
        .map_err(OperationalPolicyRefusal::Canonical)?;
        if proof.control != self.control
            || proof.control_version != self.control_version
            || proof.configuration_digest != self.configuration_digest
            || proof.policy != self.policy
            || proof.policy_digest != self.policy_digest
            || proof.population != self.population
            || proof.mediation_path != self.mediation_path
            || proof.known_good != known_good
            || proof.known_good_result != self.known_good_result
            || proof.planted_violation != planted_violation
            || proof.planted_violation_result != self.planted_violation_result
            || &proof.retained_evidence != retained_evidence
            || proof.proved_at < qualification.observed_finished_at()
        {
            return Err(OperationalPolicyRefusal::ActivationReportMismatch);
        }
        Ok(())
    }

    /// Re-admit the exact direct owner grant retained by this qualification.
    ///
    /// This reconstructs the canonical qualification resource from the
    /// retained candidate, policy, binding, control, population, intent, and
    /// actual run identities. The supplied grant must still resolve under the
    /// current installed owner and trusted authority instant, and its durable
    /// identity and digest must equal the grant used for the exercise.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal::QualificationProvenanceMismatch`]
    /// when the report lacks qualification, the grant is stale or substituted,
    /// or any retained grant axis differs.
    pub fn validate_retained_qualification_authority(
        &self,
        authority: &Admitted<Delegation>,
        context: &AuthorityContext,
    ) -> Result<(), OperationalPolicyRefusal> {
        let qualification = self
            .qualification()
            .ok_or(OperationalPolicyRefusal::MissingDispatcherQualification)?;
        let vectors = ControlQualificationVectorSet::new(
            qualification.known_good_intent.clone(),
            qualification.known_good_run.id.clone(),
            qualification.planted_violation_intent.clone(),
            qualification.planted_violation_run.id.clone(),
        );
        let admitted = AuthorizedControlQualification::admit(
            authority,
            context,
            &qualification.qualification_actor,
            qualification.candidate.clone(),
            self.policy_digest.clone(),
            qualification.binding.clone(),
            self.control.clone(),
            self.population.clone(),
            vectors,
        )
        .map_err(|_| OperationalPolicyRefusal::QualificationProvenanceMismatch)?;
        let authority_digest = admitted
            .authority_digest()
            .map_err(OperationalPolicyRefusal::Canonical)?;
        if admitted.authority_id() != &qualification.qualification_authority
            || authority_digest != qualification.qualification_authority_digest
        {
            return Err(OperationalPolicyRefusal::QualificationProvenanceMismatch);
        }
        Ok(())
    }
}

/// An immutable, generation-bound operational policy registry.
#[derive(Clone, Debug)]
pub struct OperationalPolicyRegistry {
    document: OperationalPolicyDocument,
    digest: Digest,
}

impl OperationalPolicyRegistry {
    /// Build and validate canonical policy artifact bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal`] for ambiguous bindings, invalid
    /// detector calibration, or canonical encoding failure.
    pub fn new(
        bundle: PolicyBundleId,
        bindings: Vec<PolicyBinding>,
        detectors: BTreeMap<String, OperationalDetector>,
    ) -> Result<Self, OperationalPolicyRefusal> {
        let document = OperationalPolicyDocument {
            bundle,
            bindings,
            detectors,
        };
        validate_document(&document)?;
        let bytes = to_canonical_bytes(&document).map_err(OperationalPolicyRefusal::Canonical)?;
        Ok(Self {
            document,
            digest: Digest::blake3(&bytes),
        })
    }

    /// Decode exact artifact bytes only when the generation binds their bundle and digest.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal`] for malformed bytes, a substituted
    /// bundle or digest, ambiguous identities, or invalid detector calibration.
    pub fn from_artifact_bytes(
        bytes: &[u8],
        expected_bundle: &PolicyBundleId,
        expected_digest: &Digest,
    ) -> Result<Self, OperationalPolicyRefusal> {
        if &Digest::blake3(bytes) != expected_digest {
            return Err(OperationalPolicyRefusal::PolicyDigestMismatch);
        }
        let document: OperationalPolicyDocument = serde_json::from_slice(bytes)
            .map_err(|error| OperationalPolicyRefusal::Encoding(error.to_string()))?;
        if &document.bundle != expected_bundle {
            return Err(OperationalPolicyRefusal::PolicyBundleMismatch);
        }
        validate_document(&document)?;
        let canonical =
            to_canonical_bytes(&document).map_err(OperationalPolicyRefusal::Canonical)?;
        if canonical != bytes {
            return Err(OperationalPolicyRefusal::NonCanonicalArtifact);
        }
        Ok(Self {
            document,
            digest: expected_digest.clone(),
        })
    }

    /// Canonical artifact bytes suitable for a generation's policy component.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if the registry cannot be represented.
    pub fn artifact_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        to_canonical_bytes(&self.document)
    }

    /// Policy bundle identity carried by the exact artifact.
    pub fn bundle(&self) -> &PolicyBundleId {
        &self.document.bundle
    }

    /// Digest of the exact artifact bytes admitted for this registry.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Normalized bindings carried by the policy artifact.
    pub fn bindings(&self) -> &[PolicyBinding] {
        &self.document.bindings
    }

    /// Detector metadata keyed by its stable identity.
    pub fn detector_specs(&self) -> BTreeMap<String, DetectorSpec> {
        self.document
            .detectors
            .iter()
            .map(|(id, detector)| (id.clone(), detector.spec.clone()))
            .collect()
    }

    /// Execute both public calibration vectors for one installed detector.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal::UnknownDetector`] when `control`
    /// is absent or a canonical error when its population cannot be digested.
    pub fn calibrate_detector(
        &self,
        control: &str,
    ) -> Result<PublicDetectorCalibration, OperationalPolicyRefusal> {
        let detector = self
            .document
            .detectors
            .get(control)
            .ok_or(OperationalPolicyRefusal::UnknownDetector)?;
        let (known_good, planted_violation) = detector.rule.calibration_inputs();
        Ok(PublicDetectorCalibration {
            schema: "politeia.public-detector-calibration.v1".to_string(),
            control: control.to_string(),
            control_version: detector.spec.control_version.clone(),
            configuration_digest: detector.spec.configuration_digest.clone(),
            policy: self.bundle().clone(),
            policy_digest: self.digest().clone(),
            population: detector.spec.calibration_population.clone(),
            mediation_path: detector.spec.mediation_path.clone(),
            known_good_resources: known_good.clone(),
            known_good_result: detector.rule.evaluate(known_good).0,
            planted_violation_resources: planted_violation.clone(),
            planted_violation_result: detector.rule.evaluate(planted_violation).0,
            qualification: None,
        })
    }

    /// Admit the exceptional authority for one inactive candidate's exact
    /// known-good and planted-violation dispatcher exercises.
    ///
    /// `authority` is a direct owner grant over the candidate, control, and
    /// both signed intent digests. No caller-selected resource set survives
    /// this constructor: both requests must equal the immutable artifact
    /// vectors. The target control is evaluated later, inside each actual PDP
    /// invocation; no pre-exercise [`ControlRun`] is accepted here.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal`] when any candidate, policy,
    /// binding, vector, request, signed intent, or authority axis differs.
    #[expect(
        clippy::too_many_arguments,
        reason = "qualification binds candidate state, exact policy, and two independent vectors"
    )]
    pub fn admit_qualification(
        &self,
        generation: RuntimeGenerationId,
        expected_active: Option<Digest>,
        expected_revision: i64,
        binding_id: &str,
        control: &str,
        authority: &AuthorizedControlQualification<'_>,
        vectors: QualificationVectorInputs<'_>,
    ) -> Result<OperationalQualification, OperationalPolicyRefusal> {
        if expected_revision < 0
            || expected_active.as_ref() == Some(generation.digest())
            || authority.generation() != &generation
            || authority.policy_digest() != self.digest()
            || authority.binding() != binding_id
            || authority.control() != control
        {
            return Err(OperationalPolicyRefusal::QualificationAuthorityMismatch);
        }
        let binding = self
            .bindings()
            .iter()
            .find(|binding| binding.id == binding_id)
            .ok_or(OperationalPolicyRefusal::QualificationBindingMismatch)?;
        let detector = self
            .document
            .detectors
            .get(control)
            .ok_or(OperationalPolicyRefusal::UnknownDetector)?;
        if !binding.is_blocking()
            || !binding.detector_ids.iter().any(|id| id == control)
            || authority.population() != &detector.spec.calibration_population
        {
            return Err(OperationalPolicyRefusal::QualificationBindingMismatch);
        }

        let good_request = vectors.known_good;
        let planted_request = vectors.planted_violation;
        if good_request.institution != *authority.institution()
            || good_request.workspace != *authority.workspace()
            || good_request.institution != planted_request.institution
            || good_request.workspace != planted_request.workspace
            || good_request.principal != *authority.actor()
            || good_request.principal != planted_request.principal
            || good_request.operation != planted_request.operation
            || good_request.at != authority.valid_at()
            || planted_request.at != authority.valid_at()
            || good_request.intent_digest == planted_request.intent_digest
            || good_request.intent_digest != *authority.known_good_intent()
            || planted_request.intent_digest != *authority.planted_violation_intent()
            || binding.scope != operation_scope(&good_request.operation)
        {
            return Err(OperationalPolicyRefusal::QualificationRequestMismatch);
        }
        let (expected_good, expected_planted) = detector.rule.calibration_inputs();
        if &good_request.resources != expected_good
            || &planted_request.resources != expected_planted
        {
            return Err(OperationalPolicyRefusal::QualificationVectorMismatch);
        }

        let good = self.bind_qualification_vector(
            detector,
            good_request,
            authority.known_good_run(),
            ControlResult::Clean,
        )?;
        let planted = self.bind_qualification_vector(
            detector,
            planted_request,
            authority.planted_violation_run(),
            ControlResult::Violation,
        )?;
        let authority_digest = authority
            .authority_digest()
            .map_err(OperationalPolicyRefusal::Canonical)?;
        let expires_at = authority.expires_at();
        let payload = OperationalQualificationPayload {
            schema: "politeia.operational-qualification.v1",
            institution: good_request.institution.clone(),
            workspace: good_request.workspace.clone(),
            generation,
            expected_active,
            expected_revision,
            policy: self.bundle().clone(),
            policy_digest: self.digest().clone(),
            binding: binding.id.clone(),
            control: control.to_string(),
            control_version: detector.spec.control_version.clone(),
            configuration_digest: detector.spec.configuration_digest.clone(),
            population: detector.spec.calibration_population.clone(),
            mediation_path: detector.spec.mediation_path.clone(),
            operation: good_request.operation.clone(),
            principal: good_request.principal.clone(),
            authority_actor: authority.actor().clone(),
            authority: authority.authority_id().clone(),
            authority_digest,
            admitted_at: authority.valid_at(),
            known_good: good,
            planted_violation: planted,
            expires_at,
        };
        let digest = digest(&payload).map_err(OperationalPolicyRefusal::Canonical)?;
        let known_good_replay_domain = qualification_replay_domain(
            &payload.generation,
            &payload.policy_digest,
            &payload.binding,
            &payload.control,
            QualificationVector::KnownGood,
        )
        .map_err(OperationalPolicyRefusal::Canonical)?;
        let planted_violation_replay_domain = qualification_replay_domain(
            &payload.generation,
            &payload.policy_digest,
            &payload.binding,
            &payload.control,
            QualificationVector::PlantedViolation,
        )
        .map_err(OperationalPolicyRefusal::Canonical)?;
        Ok(OperationalQualification {
            payload,
            digest,
            known_good_replay_domain,
            planted_violation_replay_domain,
        })
    }

    /// Evaluate one exact vector under its checked candidate capability.
    ///
    /// This invokes the target detector over the request supplied to this PDP
    /// call and uses the ordinary evaluator for every other applicable
    /// control. Only the selected blocking pair omits its pre-existing run and
    /// activation proof. The resulting decision carries private qualification
    /// provenance that the dispatcher and ledger must preserve.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal`] for a substituted capability,
    /// vector, request, run, waiver, or premature activation.
    pub fn evaluate_qualification(
        &self,
        qualification: &OperationalQualification,
        vector: QualificationVector,
        request: &OperationalEvaluationRequest,
        evidence: &EvaluationEvidence<'_, '_>,
        started_at: Timestamp,
    ) -> Result<PendingQualificationDecision, OperationalPolicyRefusal> {
        let payload = &qualification.payload;
        if digest(payload).map_err(OperationalPolicyRefusal::Canonical)? != qualification.digest
            || payload.policy != *self.bundle()
            || payload.policy_digest != *self.digest()
        {
            return Err(OperationalPolicyRefusal::QualificationCapabilityMismatch);
        }
        let subject = request
            .evaluation_subject(self)
            .map_err(OperationalPolicyRefusal::Canonical)?;
        let expected = qualification.vector(vector);
        if request.institution != payload.institution
            || request.workspace != payload.workspace
            || request.operation != payload.operation
            || request.principal != payload.principal
            || request.at < payload.admitted_at
            || request.at >= payload.expires_at
            || started_at != request.at
            || request.intent_digest != expected.intent
            || request.resources != expected.resources
            || subject.subject != expected.subject
            || subject.population != expected.population
        {
            return Err(OperationalPolicyRefusal::QualificationRequestMismatch);
        }
        if !evidence.waivers().is_empty()
            || evidence
                .control_runs()
                .iter()
                .any(|run| run.run().control == payload.control)
            || evidence
                .activations()
                .iter()
                .any(|activation| activation.proof().control == payload.control)
        {
            return Err(OperationalPolicyRefusal::QualificationEvidenceMismatch);
        }
        let detector = self
            .document
            .detectors
            .get(&payload.control)
            .ok_or(OperationalPolicyRefusal::UnknownDetector)?;
        let (result, coverage) = detector.rule.evaluate(&request.resources);
        if result != expected.expected_result || coverage != expected.expected_coverage {
            return Err(OperationalPolicyRefusal::QualificationEvidenceMismatch);
        }

        let mut decision = evaluate_with_qualification_target(
            &subject,
            self.bindings(),
            &self.detector_specs(),
            evidence,
            Some(QualificationEvaluation {
                binding: &payload.binding,
                detector: &payload.control,
                result,
                coverage,
            }),
        )
        .map_err(OperationalPolicyRefusal::Evaluation)?;
        if decision.control_runs.contains(&expected.run) {
            return Err(OperationalPolicyRefusal::QualificationEvidenceMismatch);
        }
        decision.control_runs.push(expected.run.clone());
        decision.control_runs.sort();
        let control_run = ControlRun {
            id: expected.run.clone(),
            control: payload.control.clone(),
            control_version: payload.control_version.clone(),
            configuration_digest: payload.configuration_digest.clone(),
            policy: payload.policy.clone(),
            policy_digest: payload.policy_digest.clone(),
            input_digest: expected.intent.clone(),
            subject: expected.subject.clone(),
            population: expected.population.clone(),
            authorization: payload.authority_digest.clone(),
            mediation_path: payload.mediation_path.clone(),
            started_at,
            finished_at: started_at,
            result,
            coverage,
        };
        Ok(PendingQualificationDecision {
            decision,
            capability: qualification.digest.clone(),
            vector,
            generation: payload.generation.clone(),
            replay_domain: qualification.replay_domain(vector),
            expires_at: payload.expires_at,
            control_run,
        })
    }

    fn bind_qualification_vector(
        &self,
        detector: &OperationalDetector,
        request: &OperationalEvaluationRequest,
        run: &EvidenceId,
        expected_result: ControlResult,
    ) -> Result<QualificationVectorBinding, OperationalPolicyRefusal> {
        let subject = request
            .evaluation_subject(self)
            .map_err(OperationalPolicyRefusal::Canonical)?;
        let (actual_result, expected_coverage) = detector.rule.evaluate(&request.resources);
        if actual_result != expected_result {
            return Err(OperationalPolicyRefusal::QualificationVectorMismatch);
        }
        Ok(QualificationVectorBinding {
            intent: request.intent_digest.clone(),
            subject: subject.subject,
            population: subject.population,
            resources: request.resources.clone(),
            run: run.clone(),
            expected_result,
            expected_coverage,
        })
    }

    /// Verify that a signed run reports the public rule's actual result.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal`] when the detector is unknown or
    /// the claimed result/coverage differs from deterministic evaluation.
    pub fn validate_control_run(
        &self,
        request: &OperationalEvaluationRequest,
        run: &ControlRun,
    ) -> Result<(), OperationalPolicyRefusal> {
        let detector = self
            .document
            .detectors
            .get(&run.control)
            .ok_or(OperationalPolicyRefusal::UnknownDetector)?;
        let (expected_result, expected_coverage) = detector.rule.evaluate(&request.resources);
        if run.result != expected_result || run.coverage != expected_coverage {
            return Err(OperationalPolicyRefusal::ClaimedControlResultMismatch);
        }
        Ok(())
    }

    /// Execute one configured public detector against the exact request.
    ///
    /// The returned record is unsigned evidence input. A separately authorized
    /// control producer must sign it before the evaluator can admit it.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal::UnknownDetector`] when the control is
    /// absent or a canonical encoding error when the subject cannot be bound.
    #[expect(
        clippy::too_many_arguments,
        reason = "a control run binds independent identity, authority, and time axes"
    )]
    pub fn run_control(
        &self,
        request: &OperationalEvaluationRequest,
        id: politeia_core::EvidenceId,
        control: &str,
        authorization: Digest,
        started_at: Timestamp,
        finished_at: Timestamp,
    ) -> Result<ControlRun, OperationalPolicyRefusal> {
        let detector = self
            .document
            .detectors
            .get(control)
            .ok_or(OperationalPolicyRefusal::UnknownDetector)?;
        let subject = request
            .evaluation_subject(self)
            .map_err(OperationalPolicyRefusal::Canonical)?;
        let (result, coverage) = detector.rule.evaluate(&request.resources);
        Ok(ControlRun {
            id,
            control: control.to_owned(),
            control_version: detector.spec.control_version.clone(),
            configuration_digest: detector.spec.configuration_digest.clone(),
            policy: self.bundle().clone(),
            policy_digest: self.digest().clone(),
            input_digest: request.intent_digest.clone(),
            subject: subject.subject,
            population: subject.population,
            authorization,
            mediation_path: detector.spec.mediation_path.clone(),
            started_at,
            finished_at,
            result,
            coverage,
        })
    }

    /// Evaluate every applicable binding from authenticated assurance evidence.
    ///
    /// # Errors
    ///
    /// Returns a canonical binding error or the evaluator's specific
    /// fail-closed refusal. An empty or partial evidence set never becomes an
    /// allow decision.
    pub fn evaluate(
        &self,
        request: &OperationalEvaluationRequest,
        evidence: &EvaluationEvidence<'_, '_>,
    ) -> Result<PolicyDecision, OperationalPolicyRefusal> {
        let subject = request
            .evaluation_subject(self)
            .map_err(OperationalPolicyRefusal::Canonical)?;
        evaluate(&subject, self.bindings(), &self.detector_specs(), evidence)
            .map_err(OperationalPolicyRefusal::Evaluation)
    }

    /// Re-admit a retained report as one exact blocking binding qualification.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal::QualificationReportMismatch`] when
    /// the outer calibration, private real-path payload, target runs, binding,
    /// or installed detector differs on any axis.
    pub fn validate_detector_qualification<'report>(
        &'report self,
        report: &'report PublicDetectorCalibration,
    ) -> Result<CheckedDetectorQualification<'report>, OperationalPolicyRefusal> {
        let qualification = report
            .qualification()
            .ok_or(OperationalPolicyRefusal::MissingDispatcherQualification)?;
        let detector = self
            .document
            .detectors
            .get(&report.control)
            .ok_or(OperationalPolicyRefusal::UnknownDetector)?;
        let binding = self
            .bindings()
            .iter()
            .find(|binding| binding.id == qualification.binding)
            .ok_or(OperationalPolicyRefusal::QualificationBindingMismatch)?;
        let (known_good_resources, planted_violation_resources) =
            detector.rule.calibration_inputs();
        let (known_good_result, known_good_coverage) = detector.rule.evaluate(known_good_resources);
        let (planted_violation_result, planted_violation_coverage) =
            detector.rule.evaluate(planted_violation_resources);
        let known_good_subject = digest(&OperationalSubject {
            kind: "politeia.operational-subject.v1",
            intent: &qualification.known_good_intent,
            principal: &qualification.qualification_actor,
            operation: &qualification.operation,
            resources: known_good_resources,
        })
        .map_err(OperationalPolicyRefusal::Canonical)?;
        let planted_violation_subject = digest(&OperationalSubject {
            kind: "politeia.operational-subject.v1",
            intent: &qualification.planted_violation_intent,
            principal: &qualification.qualification_actor,
            operation: &qualification.operation,
            resources: planted_violation_resources,
        })
        .map_err(OperationalPolicyRefusal::Canonical)?;
        let known_good_population = digest(&DetectorInput {
            kind: "politeia.public-detector.input.v1",
            resources: known_good_resources,
        })
        .map_err(OperationalPolicyRefusal::Canonical)?;
        let planted_violation_population = digest(&DetectorInput {
            kind: "politeia.public-detector.input.v1",
            resources: planted_violation_resources,
        })
        .map_err(OperationalPolicyRefusal::Canonical)?;
        let run_matches = |run: &ControlRun,
                           intent: &Digest,
                           subject: &Digest,
                           population: &Digest,
                           result: ControlResult,
                           coverage: Coverage| {
            run.control == report.control
                && run.control_version == report.control_version
                && run.configuration_digest == report.configuration_digest
                && run.policy == report.policy
                && run.policy_digest == report.policy_digest
                && &run.input_digest == intent
                && &run.subject == subject
                && &run.population == population
                && run.authorization == qualification.qualification_authority_digest
                && run.mediation_path == report.mediation_path
                && run.started_at >= qualification.observed_started_at
                && run.finished_at >= run.started_at
                && run.finished_at <= qualification.observed_finished_at
                && run.result == result
                && run.coverage == coverage
        };
        if report.schema != "politeia.public-detector-calibration.v1"
            || report.control_version != detector.spec.control_version
            || report.configuration_digest != detector.spec.configuration_digest
            || report.policy != *self.bundle()
            || report.policy_digest != *self.digest()
            || report.population != detector.spec.calibration_population
            || report.mediation_path != detector.spec.mediation_path
            || &report.known_good_resources != known_good_resources
            || report.known_good_result != known_good_result
            || &report.planted_violation_resources != planted_violation_resources
            || report.planted_violation_result != planted_violation_result
            || !binding.is_blocking()
            || !binding
                .detector_ids
                .iter()
                .any(|control| control == &report.control)
            || binding.scope != operation_scope(&qualification.operation)
            || qualification.expected_revision < 0
            || qualification.expected_active.as_ref() == Some(qualification.candidate.digest())
            || qualification.known_good_run.id == qualification.planted_violation_run.id
            || !run_matches(
                &qualification.known_good_run,
                &qualification.known_good_intent,
                &known_good_subject,
                &known_good_population,
                known_good_result,
                known_good_coverage,
            )
            || !run_matches(
                &qualification.planted_violation_run,
                &qualification.planted_violation_intent,
                &planted_violation_subject,
                &planted_violation_population,
                planted_violation_result,
                planted_violation_coverage,
            )
            || qualification.planted_violation_denial != DetectorQualificationDenial::PolicyDenied
            || !qualification.planted_violation_no_effect.is_empty()
            || qualification.observed_finished_at < qualification.observed_started_at
        {
            return Err(OperationalPolicyRefusal::QualificationReportMismatch);
        }
        Ok(CheckedDetectorQualification {
            qualification,
            binding,
            control: &report.control,
        })
    }

    /// Verify activation evidence against the rule's real public test vectors.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalPolicyRefusal`] when the detector is unknown or
    /// either retained activation input differs from the artifact vectors.
    pub fn validate_activation_proof(
        &self,
        proof: &ActivationProof,
    ) -> Result<(), OperationalPolicyRefusal> {
        let detector = self
            .document
            .detectors
            .get(&proof.control)
            .ok_or(OperationalPolicyRefusal::UnknownDetector)?;
        let (known_good, planted_violation) = detector.rule.calibration_inputs();
        let known_good_digest = detector
            .rule
            .input_digest(known_good)
            .map_err(OperationalPolicyRefusal::Canonical)?;
        let planted_digest = detector
            .rule
            .input_digest(planted_violation)
            .map_err(OperationalPolicyRefusal::Canonical)?;
        if proof.known_good != known_good_digest
            || proof.planted_violation != planted_digest
            || proof.known_good_result != detector.rule.evaluate(known_good).0
            || proof.planted_violation_result != detector.rule.evaluate(planted_violation).0
        {
            return Err(OperationalPolicyRefusal::ActivationVectorMismatch);
        }
        Ok(())
    }
}

/// Exact public input from which operational subject, population, and scopes derive.
#[derive(Clone, Debug)]
pub struct OperationalEvaluationRequest {
    /// Institution whose active policy applies.
    pub institution: InstitutionId,
    /// Workspace whose active generation is executing.
    pub workspace: InstitutionWorkspaceId,
    /// Digest of the complete signed runtime operation intent.
    pub intent_digest: Digest,
    /// Authenticated requesting principal.
    pub principal: PrincipalId,
    /// Exact operation contract selected from the generation registry.
    pub operation: OperationSpec,
    /// Exact resources carried by the signed intent.
    pub resources: BTreeSet<String>,
    /// Trusted evaluation instant.
    pub at: Timestamp,
}

impl OperationalEvaluationRequest {
    /// Derive the normalized evaluator subject under one admitted policy registry.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if subject or population cannot be represented.
    pub fn evaluation_subject(
        &self,
        policy: &OperationalPolicyRegistry,
    ) -> Result<EvaluationSubject, CanonicalError> {
        let subject = digest(&OperationalSubject {
            kind: "politeia.operational-subject.v1",
            intent: &self.intent_digest,
            principal: &self.principal,
            operation: &self.operation,
            resources: &self.resources,
        })?;
        let population = digest(&DetectorInput {
            kind: "politeia.public-detector.input.v1",
            resources: &self.resources,
        })?;
        Ok(EvaluationSubject {
            institution: self.institution.clone(),
            workspace: self.workspace.clone(),
            bundle: policy.bundle().clone(),
            policy_digest: policy.digest().clone(),
            intent_digest: self.intent_digest.clone(),
            subject,
            population,
            principal: self.principal.clone(),
            scopes: BTreeSet::from([operation_scope(&self.operation)]),
            at: self.at,
        })
    }
}

/// Derive the sole policy scope from an exact operation contract.
pub fn operation_scope(operation: &OperationSpec) -> String {
    format!("{OPERATION_SCOPE_PREFIX}{}", operation.name)
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct OperationalPolicyDocument {
    bundle: PolicyBundleId,
    bindings: Vec<PolicyBinding>,
    detectors: BTreeMap<String, OperationalDetector>,
}

#[derive(Serialize)]
struct DetectorConfiguration<'a> {
    kind: &'static str,
    rule: &'a PublicDetectorRule,
}

#[derive(Serialize)]
struct CalibrationPopulation<'a> {
    kind: &'static str,
    known_good: &'a BTreeSet<String>,
    planted_violation: &'a BTreeSet<String>,
}

#[derive(Serialize)]
struct DetectorInput<'a> {
    kind: &'static str,
    resources: &'a BTreeSet<String>,
}

#[derive(Serialize)]
struct OperationalSubject<'a> {
    kind: &'static str,
    intent: &'a Digest,
    principal: &'a PrincipalId,
    operation: &'a OperationSpec,
    resources: &'a BTreeSet<String>,
}

#[derive(Serialize)]
struct QualificationReplayScope<'a> {
    kind: &'static str,
    candidate: &'a RuntimeGenerationId,
    policy_digest: &'a Digest,
    binding: &'a str,
    control: &'a str,
    vector: QualificationVector,
}

fn qualification_replay_domain(
    candidate: &RuntimeGenerationId,
    policy_digest: &Digest,
    binding: &str,
    control: &str,
    vector: QualificationVector,
) -> Result<String, CanonicalError> {
    digest(&QualificationReplayScope {
        kind: "politeia.policy-control-qualification-replay.v1",
        candidate,
        policy_digest,
        binding,
        control,
        vector,
    })
    .map(|identity| format!("qualification:{}", identity.as_str()))
}

fn validate_document(document: &OperationalPolicyDocument) -> Result<(), OperationalPolicyRefusal> {
    if document.bindings.is_empty() || document.detectors.is_empty() {
        return Err(OperationalPolicyRefusal::EmptyRegistry);
    }
    let mut binding_ids = BTreeSet::new();
    for binding in &document.bindings {
        if binding.id.is_empty()
            || !binding_ids.insert(binding.id.clone())
            || binding.detector_ids.is_empty()
        {
            return Err(OperationalPolicyRefusal::AmbiguousBinding);
        }
        for detector in &binding.detector_ids {
            let detector = document
                .detectors
                .get(detector)
                .ok_or(OperationalPolicyRefusal::UnknownDetector)?;
            if !detector.spec.supported_scopes.contains(&binding.scope) {
                return Err(OperationalPolicyRefusal::UnsupportedDetectorScope);
            }
        }
    }
    for (id, detector) in &document.detectors {
        if id.is_empty() || detector.spec.id != *id {
            return Err(OperationalPolicyRefusal::AmbiguousDetector);
        }
        detector.rule.validate()?;
        if detector.spec.configuration_digest
            != detector
                .rule
                .configuration_digest()
                .map_err(OperationalPolicyRefusal::Canonical)?
            || detector.spec.calibration_population
                != detector
                    .rule
                    .calibration_population_digest()
                    .map_err(OperationalPolicyRefusal::Canonical)?
        {
            return Err(OperationalPolicyRefusal::DetectorMetadataMismatch);
        }
    }
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<Digest, CanonicalError> {
    to_canonical_bytes(value).map(|bytes| Digest::blake3(&bytes))
}

/// Why operational policy artifact admission or public evaluation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum OperationalPolicyRefusal {
    /// Exact artifact bytes do not have the generation-approved digest.
    PolicyDigestMismatch,
    /// Artifact names another policy bundle.
    PolicyBundleMismatch,
    /// Artifact contains no bindings or no detectors.
    EmptyRegistry,
    /// Binding identity is duplicated, empty, or has no detectors.
    AmbiguousBinding,
    /// A binding or submitted result names an absent detector.
    UnknownDetector,
    /// A binding applies a detector outside that detector's declared scope.
    UnsupportedDetectorScope,
    /// Detector map key and embedded identity differ or are empty.
    AmbiguousDetector,
    /// Public detector calibration is empty or does not exercise both outcomes.
    InvalidDetectorCalibration,
    /// Detector metadata does not bind its executable rule and calibration population.
    DetectorMetadataMismatch,
    /// Signed control output differs from the public detector's actual result.
    ClaimedControlResultMismatch,
    /// Activation proof does not cite the artifact's exact public test vectors.
    ActivationVectorMismatch,
    /// Activation proof differs from its complete retained dispatcher report.
    ActivationReportMismatch,
    /// The explicit direct qualification grant differs from the candidate or policy.
    QualificationAuthorityMismatch,
    /// The requested qualification target is absent, nonblocking, or differently scoped.
    QualificationBindingMismatch,
    /// A qualification input differs from the immutable artifact vectors.
    QualificationVectorMismatch,
    /// A qualification request differs from its exact admitted capability.
    QualificationRequestMismatch,
    /// Signed runs, waivers, or activation inputs do not match qualification.
    QualificationEvidenceMismatch,
    /// The opaque capability was not produced by this exact policy registry.
    QualificationCapabilityMismatch,
    /// The actual selected-control interval is inverted or outlives authority.
    QualificationIntervalMismatch,
    /// Direct rule calibration has no actual dispatcher exercise attached.
    MissingDispatcherQualification,
    /// Actual report inputs differ from the checked capability or outcomes.
    QualificationReportMismatch,
    /// Retained qualification authority is stale, substituted, or differently scoped.
    QualificationProvenanceMismatch,
    /// Artifact JSON is malformed or contains unsupported fields.
    Encoding(String),
    /// Artifact JSON is typed but is not in the canonical byte representation.
    NonCanonicalArtifact,
    /// Canonical binding could not be encoded.
    Canonical(CanonicalError),
    /// Admitted evidence could not support a complete normalized decision.
    Evaluation(Unevaluable),
}

impl std::fmt::Display for OperationalPolicyRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::PolicyDigestMismatch => "policy artifact digest differs from the generation",
            Self::PolicyBundleMismatch => "policy artifact names another bundle",
            Self::EmptyRegistry => "operational policy registry is empty",
            Self::AmbiguousBinding => "operational policy binding is ambiguous",
            Self::UnknownDetector => "operational policy detector is absent",
            Self::UnsupportedDetectorScope => {
                "operational policy detector does not support the binding scope"
            }
            Self::AmbiguousDetector => "operational detector identity is ambiguous",
            Self::InvalidDetectorCalibration => "public detector calibration is invalid",
            Self::DetectorMetadataMismatch => "detector metadata differs from its public rule",
            Self::ClaimedControlResultMismatch => {
                "signed control result differs from public detector execution"
            }
            Self::ActivationVectorMismatch => {
                "activation proof differs from public detector calibration"
            }
            Self::ActivationReportMismatch => {
                "activation proof differs from retained dispatcher qualification"
            }
            Self::QualificationAuthorityMismatch => {
                "qualification authority differs from its candidate control"
            }
            Self::QualificationBindingMismatch => {
                "qualification does not name an exact blocking control binding"
            }
            Self::QualificationVectorMismatch => {
                "qualification input differs from the immutable detector vectors"
            }
            Self::QualificationRequestMismatch => {
                "qualification request differs from its admitted capability"
            }
            Self::QualificationEvidenceMismatch => {
                "qualification evidence is missing, substituted, waived, or already activated"
            }
            Self::QualificationCapabilityMismatch => {
                "qualification capability differs from the policy registry"
            }
            Self::QualificationIntervalMismatch => {
                "qualification control interval is inverted or outlives authority"
            }
            Self::MissingDispatcherQualification => {
                "activation proof requires an actual dispatcher qualification"
            }
            Self::QualificationReportMismatch => {
                "dispatcher qualification report differs from its checked capability"
            }
            Self::QualificationProvenanceMismatch => {
                "dispatcher qualification grant differs from retained provenance"
            }
            Self::Encoding(_) => "operational policy artifact is malformed",
            Self::NonCanonicalArtifact => "operational policy artifact bytes are not canonical",
            Self::Canonical(_) => "operational policy binding cannot be encoded",
            Self::Evaluation(_) => "operational policy evidence is incomplete or mismatched",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OperationalPolicyRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(source) => Some(source),
            Self::Evaluation(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "policy-construction fixtures must fail loudly when their canonical invariants drift"
)]
mod tests {
    use super::*;
    use crate::hardening::{BindingAuthority, HardeningLadder, HardeningState};
    use crate::{Consequence, DetectorSpec, EvidenceClass};

    const DETECTOR: &str = "public-scope-detector";
    const SUPPORTED_SCOPE: &str = "operation:accepted";
    const UNSUPPORTED_SCOPE: &str = "operation:rejected";

    fn enforced_authority() -> BindingAuthority {
        let mut ladder = HardeningLadder::new();
        for state in [
            HardeningState::Observed,
            HardeningState::Proposed,
            HardeningState::Approved,
            HardeningState::Shadow,
            HardeningState::Calibrated,
            HardeningState::Advisory,
            HardeningState::Enforced,
        ] {
            ladder.advance(state).expect("fixture ladder advances");
        }
        BindingAuthority::new(ladder, Consequence::Deny).expect("enforced fixture binding may deny")
    }

    fn binding(scope: &str) -> PolicyBinding {
        PolicyBinding {
            id: format!("binding:{scope}"),
            clause_id: "public-scope-clause".to_string(),
            detector_ids: vec![DETECTOR.to_string()],
            scope: scope.to_string(),
            authority: enforced_authority(),
        }
    }

    fn detector() -> OperationalDetector {
        let rule = PublicDetectorRule::ResourcePrefixForbidden {
            forbidden_prefix: "forbidden:".to_string(),
            known_good_resources: BTreeSet::from(["public:known-good".to_string()]),
            planted_violation_resources: BTreeSet::from(["forbidden:planted".to_string()]),
        };
        OperationalDetector {
            spec: DetectorSpec {
                id: DETECTOR.to_string(),
                evidence_class: EvidenceClass::Substance,
                control_version: "1.0.0".to_string(),
                configuration_digest: rule
                    .configuration_digest()
                    .expect("fixture detector configuration digests"),
                mediation_path: "dispatcher:authorize".to_string(),
                supported_scopes: BTreeSet::from([SUPPORTED_SCOPE.to_string()]),
                calibration_population: rule
                    .calibration_population_digest()
                    .expect("fixture detector population digests"),
                known_blind_spots: Vec::new(),
            },
            rule,
        }
    }

    fn detectors() -> BTreeMap<String, OperationalDetector> {
        BTreeMap::from([(DETECTOR.to_string(), detector())])
    }

    #[test]
    fn registry_construction_rejects_binding_outside_detector_scope() {
        let refusal = OperationalPolicyRegistry::new(
            PolicyBundleId::new(),
            vec![binding(UNSUPPORTED_SCOPE)],
            detectors(),
        )
        .expect_err("binding outside detector scope must not construct a registry");
        assert!(matches!(
            refusal,
            OperationalPolicyRefusal::UnsupportedDetectorScope
        ));
    }

    #[test]
    fn artifact_decode_rechecks_detector_scope_and_admits_supported_binding() {
        let bundle = PolicyBundleId::new();
        let valid = OperationalPolicyRegistry::new(
            bundle.clone(),
            vec![binding(SUPPORTED_SCOPE)],
            detectors(),
        )
        .expect("supported binding constructs a registry");
        let valid_bytes = valid.artifact_bytes().expect("valid registry encodes");
        assert!(
            OperationalPolicyRegistry::from_artifact_bytes(&valid_bytes, &bundle, valid.digest(),)
                .is_ok()
        );

        let invalid_document = OperationalPolicyDocument {
            bundle: bundle.clone(),
            bindings: vec![binding(UNSUPPORTED_SCOPE)],
            detectors: detectors(),
        };
        let invalid_bytes =
            to_canonical_bytes(&invalid_document).expect("invalid-scope document encodes");
        let refusal = OperationalPolicyRegistry::from_artifact_bytes(
            &invalid_bytes,
            &bundle,
            &Digest::blake3(&invalid_bytes),
        )
        .expect_err("artifact decode rechecks detector scope");
        assert!(matches!(
            refusal,
            OperationalPolicyRefusal::UnsupportedDetectorScope
        ));
    }
}
