//! Generation-bound policy registry and deterministic public controls.
//!
//! The immutable generation carries the exact bytes decoded here. A registry
//! cannot become active by deserialization alone: admission binds those bytes
//! to the generation's policy bundle and digest, validates every executable
//! detector configuration, and rejects ambiguous identities.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use politeia_core::canonical::{CanonicalError, to_canonical_bytes};
use politeia_core::{
    Digest, InstitutionId, InstitutionWorkspaceId, OperationSpec, PolicyBundleId, PrincipalId,
};
use politeia_evidence::assurance::{ActivationProof, ControlResult, ControlRun, Coverage};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::evaluate::{EvaluationEvidence, EvaluationSubject, Unevaluable, evaluate};
use crate::{DetectorSpec, PolicyBinding, PolicyDecision};

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
            if !document.detectors.contains_key(detector) {
                return Err(OperationalPolicyRefusal::UnknownDetector);
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
            Self::AmbiguousDetector => "operational detector identity is ambiguous",
            Self::InvalidDetectorCalibration => "public detector calibration is invalid",
            Self::DetectorMetadataMismatch => "detector metadata differs from its public rule",
            Self::ClaimedControlResultMismatch => {
                "signed control result differs from public detector execution"
            }
            Self::ActivationVectorMismatch => {
                "activation proof differs from public detector calibration"
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
