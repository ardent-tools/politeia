//! Normalize admitted control results into one policy decision.
//!
//! A binding contributes a consequence only when one of its declared controls
//! reports [`ControlResult::Violation`]. Absence and every unresolved control
//! state remain typed refusals. Blocking additionally requires separately
//! signed, directly delegated activation evidence for the exact control.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use politeia_core::{Digest, InstitutionId, InstitutionWorkspaceId, PolicyBundleId, PrincipalId};
use politeia_evidence::assurance::{
    AuthorizedControlRun, ControlResult, Coverage, VerifiedActivation,
};

use crate::hardening::HardeningState;
use crate::waiver::DelegatedWaiver;
use crate::{Consequence, DetectorSpec, EvidenceClass, PolicyBinding, PolicyDecision};

/// One exact operation and population, as policy sees them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationSubject {
    /// Institution whose policy is being evaluated.
    pub institution: InstitutionId,
    /// Institution workspace whose admitted material may contribute.
    pub workspace: InstitutionWorkspaceId,
    /// Policy bundle in force.
    pub bundle: PolicyBundleId,
    /// Digest of the exact bundle bytes.
    pub policy_digest: Digest,
    /// Digest of the normalized operation intent.
    pub intent_digest: Digest,
    /// Digest of the exact subject controls must judge.
    pub subject: Digest,
    /// Digest of the exact intended observation population.
    pub population: Digest,
    /// Principal the operation is for.
    pub principal: PrincipalId,
    /// Scopes the operation touches.
    pub scopes: BTreeSet<String>,
    /// Trusted instant for authority and freshness checks.
    pub at: Timestamp,
}

/// Admitted evidence available to one evaluation.
///
/// WHY this borrows authorized wrappers: the evaluator cannot accidentally
/// accept a deserialized run, a signer-selected kind, or a bare delegation.
pub struct EvaluationEvidence<'set, 'admission> {
    control_runs: &'set [AuthorizedControlRun<'admission>],
    activations: &'set [VerifiedActivation<'admission>],
    waivers: &'set [DelegatedWaiver<'admission>],
}

impl<'set, 'admission> EvaluationEvidence<'set, 'admission> {
    /// Assemble the authorized evidence considered by one evaluation.
    pub fn new(
        control_runs: &'set [AuthorizedControlRun<'admission>],
        activations: &'set [VerifiedActivation<'admission>],
        waivers: &'set [DelegatedWaiver<'admission>],
    ) -> Self {
        Self {
            control_runs,
            activations,
            waivers,
        }
    }

    pub(crate) fn control_runs(&self) -> &[AuthorizedControlRun<'admission>] {
        self.control_runs
    }

    pub(crate) fn activations(&self) -> &[VerifiedActivation<'admission>] {
        self.activations
    }

    pub(crate) fn waivers(&self) -> &[DelegatedWaiver<'admission>] {
        self.waivers
    }
}

/// Binding and detector identities attached to one refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlRef {
    /// Binding being evaluated.
    pub binding: String,
    /// Detector required by that binding.
    pub detector: String,
}

impl ControlRef {
    fn new(binding: &PolicyBinding, detector: &str) -> Self {
        Self {
            binding: binding.id.clone(),
            detector: detector.to_string(),
        }
    }
}

/// Identity axis on which evidence disagreed with an evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceAxis {
    /// Institution identity.
    Institution,
    /// Workspace identity.
    Workspace,
    /// Trusted authority-resolution instant.
    AuthorityTime,
    /// Producer independence from the operation actor.
    ProducerIndependence,
    /// Control version.
    ControlVersion,
    /// Control configuration digest.
    Configuration,
    /// Exact admitted input digest.
    Input,
    /// Exact subject digest.
    Subject,
    /// Policy bundle identity.
    PolicyBundle,
    /// Exact policy digest.
    PolicyDigest,
    /// Exact population digest.
    Population,
    /// Mediation path.
    MediationPath,
    /// Binding scope.
    Scope,
}

/// Why the complete policy set could not be evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unevaluable {
    /// The bundle does not declare a named detector.
    UnknownDetector(ControlRef),
    /// A binding has no evidence-producing detector.
    NoDetector {
        /// Binding identity.
        binding: String,
    },
    /// The detector does not support the binding scope.
    UnsupportedScope(ControlRef),
    /// No admitted authorized run exists.
    MissingControlRun(ControlRef),
    /// More than one run claims the same evaluation.
    DuplicateControlRun(ControlRef),
    /// A run is bound to another exact axis.
    ControlBindingMismatch {
        /// Control being evaluated.
        control: ControlRef,
        /// Axis that differed.
        axis: EvidenceAxis,
    },
    /// The control explicitly did not run.
    ControlNotRun(ControlRef),
    /// The control was unavailable.
    ControlUnavailable(ControlRef),
    /// The control ran but could not decide.
    ControlUnevaluable(ControlRef),
    /// The control observed an unexpectedly empty source.
    ControlUnexpectedlyEmpty(ControlRef),
    /// The control claimed not to apply to an applicable binding.
    ControlNotApplicable(ControlRef),
    /// The control outcome remains unresolved.
    ControlUnresolved(ControlRef),
    /// A future result state is unsupported until explicitly handled.
    UnsupportedControlResult(ControlRef),
    /// Coverage named an empty intended population.
    EmptyPopulation(ControlRef),
    /// Coverage observed none of a nonempty intended population.
    UnobservedPopulation(ControlRef),
    /// Coverage counts are impossible.
    InvalidCoverage {
        /// Control being evaluated.
        control: ControlRef,
        /// Observed member count.
        observed: u64,
        /// Intended member count.
        population: u64,
    },
    /// A clean run did not observe its complete population.
    PartialCleanCoverage {
        /// Control being evaluated.
        control: ControlRef,
        /// Observed member count.
        observed: u64,
        /// Intended member count.
        population: u64,
    },
    /// A blocking binding rests on heuristic evidence.
    HeuristicBlocking(ControlRef),
    /// A blocking control has no verified activation proof.
    MissingActivationProof(ControlRef),
    /// More than one activation proof claims the control.
    DuplicateActivationProof(ControlRef),
    /// An activation proof is bound to another exact axis.
    ActivationBindingMismatch {
        /// Control being evaluated.
        control: ControlRef,
        /// Axis that differed.
        axis: EvidenceAxis,
    },
    /// The control producer also signed its activation proof.
    SelfAttestedActivation(ControlRef),
    /// The activation proof postdates the evaluated run.
    ActivationAfterRun(ControlRef),
    /// Multiple exact waivers compete for one finding.
    DuplicateWaiver {
        /// Binding identity.
        binding: String,
    },
    /// A waiver for this binding is stale or differently scoped.
    WaiverBindingMismatch {
        /// Binding identity.
        binding: String,
        /// Axis that differed.
        axis: EvidenceAxis,
    },
    /// A selected qualification target did not name an applicable blocking control.
    UnusedQualificationTarget(ControlRef),
    /// The completed decision could not be sealed to its canonical wire bytes.
    DecisionEncoding,
}

impl std::fmt::Display for Unevaluable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownDetector(control) => write!(
                formatter,
                "{} names undeclared {}",
                control.binding, control.detector
            ),
            Self::NoDetector { binding } => {
                write!(formatter, "binding {binding} names no detector")
            }
            Self::UnsupportedScope(control) => write!(
                formatter,
                "{} does not support {} scope",
                control.detector, control.binding
            ),
            Self::MissingControlRun(control) => write!(
                formatter,
                "{} has no admitted run for {}",
                control.binding, control.detector
            ),
            Self::DuplicateControlRun(control) => write!(
                formatter,
                "{} has multiple runs for {}",
                control.binding, control.detector
            ),
            Self::ControlBindingMismatch { control, axis } => write!(
                formatter,
                "{} run for {} mismatches {axis:?}",
                control.detector, control.binding
            ),
            Self::ControlNotRun(control) => write!(
                formatter,
                "{} for {} did not run",
                control.detector, control.binding
            ),
            Self::ControlUnavailable(control) => write!(
                formatter,
                "{} for {} was unavailable",
                control.detector, control.binding
            ),
            Self::ControlUnevaluable(control) => write!(
                formatter,
                "{} for {} could not decide",
                control.detector, control.binding
            ),
            Self::ControlUnexpectedlyEmpty(control) => write!(
                formatter,
                "{} for {} observed an unexpectedly empty source",
                control.detector, control.binding
            ),
            Self::ControlNotApplicable(control) => write!(
                formatter,
                "{} claimed not to apply to {}",
                control.detector, control.binding
            ),
            Self::ControlUnresolved(control) => write!(
                formatter,
                "{} for {} remains unresolved",
                control.detector, control.binding
            ),
            Self::UnsupportedControlResult(control) => write!(
                formatter,
                "{} for {} returned an unsupported state",
                control.detector, control.binding
            ),
            Self::EmptyPopulation(control) => write!(
                formatter,
                "{} for {} names an empty population",
                control.detector, control.binding
            ),
            Self::UnobservedPopulation(control) => write!(
                formatter,
                "{} for {} observed none of its population",
                control.detector, control.binding
            ),
            Self::InvalidCoverage {
                control,
                observed,
                population,
            } => write!(
                formatter,
                "{} for {} observed {observed} of an impossible {population}",
                control.detector, control.binding
            ),
            Self::PartialCleanCoverage {
                control,
                observed,
                population,
            } => write!(
                formatter,
                "{} for {} claimed clean after observing {observed} of {population}",
                control.detector, control.binding
            ),
            Self::HeuristicBlocking(control) => write!(
                formatter,
                "{} blocks on heuristic {}",
                control.binding, control.detector
            ),
            Self::MissingActivationProof(control) => write!(
                formatter,
                "{} has no verified activation for {}",
                control.binding, control.detector
            ),
            Self::DuplicateActivationProof(control) => write!(
                formatter,
                "{} has multiple activations for {}",
                control.binding, control.detector
            ),
            Self::ActivationBindingMismatch { control, axis } => write!(
                formatter,
                "{} activation for {} mismatches {axis:?}",
                control.detector, control.binding
            ),
            Self::SelfAttestedActivation(control) => write!(
                formatter,
                "{} producer also vouched for {} activation",
                control.detector, control.binding
            ),
            Self::ActivationAfterRun(control) => write!(
                formatter,
                "{} activation for {} postdates its run",
                control.detector, control.binding
            ),
            Self::DuplicateWaiver { binding } => {
                write!(formatter, "binding {binding} has multiple exact waivers")
            }
            Self::WaiverBindingMismatch { binding, axis } => {
                write!(formatter, "waiver for {binding} mismatches {axis:?}")
            }
            Self::UnusedQualificationTarget(control) => write!(
                formatter,
                "qualification target {} on {} was not applicable",
                control.detector, control.binding
            ),
            Self::DecisionEncoding => {
                formatter.write_str("policy decision could not be encoded canonically")
            }
        }
    }
}

impl std::error::Error for Unevaluable {}

/// Evaluate every applicable binding from admitted control results.
///
/// # Errors
///
/// Returns the first [`Unevaluable`] input. No decision is assembled from a
/// subset of the applicable bindings.
pub fn evaluate(
    subject: &EvaluationSubject,
    bindings: &[PolicyBinding],
    detectors: &BTreeMap<String, DetectorSpec>,
    evidence: &EvaluationEvidence<'_, '_>,
) -> Result<PolicyDecision, Unevaluable> {
    evaluate_with_qualification_target(subject, bindings, detectors, evidence, None)
}

pub(crate) struct QualificationEvaluation<'target> {
    pub(crate) binding: &'target str,
    pub(crate) detector: &'target str,
    pub(crate) result: ControlResult,
    pub(crate) coverage: Coverage,
}

pub(crate) fn evaluate_with_qualification_target(
    subject: &EvaluationSubject,
    bindings: &[PolicyBinding],
    detectors: &BTreeMap<String, DetectorSpec>,
    evidence: &EvaluationEvidence<'_, '_>,
    qualification_target: Option<QualificationEvaluation<'_>>,
) -> Result<PolicyDecision, Unevaluable> {
    let mut binding_ids = Vec::new();
    let mut control_run_ids = BTreeSet::new();
    let mut activation_ids = BTreeSet::new();
    let mut waiver_ids = BTreeSet::new();
    let mut reasons = Vec::new();
    let mut allowed = true;
    let mut used_qualification_target = false;

    for binding in bindings {
        if !subject.scopes.contains(&binding.scope) {
            continue;
        }
        if binding.detector_ids.is_empty() {
            return Err(Unevaluable::NoDetector {
                binding: binding.id.clone(),
            });
        }
        binding_ids.push(binding.id.clone());
        let consequence = binding.authority.consequence();
        let blocks = binding.is_blocking();
        let mut violation = false;

        for detector_id in &binding.detector_ids {
            let control_ref = ControlRef::new(binding, detector_id);
            let detector = detectors
                .get(detector_id)
                .ok_or_else(|| Unevaluable::UnknownDetector(control_ref.clone()))?;
            if !detector.supported_scopes.contains(&binding.scope) {
                return Err(Unevaluable::UnsupportedScope(control_ref));
            }
            if blocks && matches!(detector.evidence_class, EvidenceClass::Heuristic) {
                return Err(Unevaluable::HeuristicBlocking(control_ref));
            }

            if let Some(target) = qualification_target
                .as_ref()
                .filter(|target| binding.id == target.binding && detector_id == target.detector)
            {
                used_qualification_target = true;
                violation |= normalize_control_result(
                    binding,
                    detector_id,
                    target.result,
                    &target.coverage,
                )?;
                continue;
            }

            let run = one_run(evidence.control_runs, binding, detector_id)?;
            validate_run(subject, binding, detector_id, detector, run)?;
            control_run_ids.insert(run.run().id.clone());
            violation |= normalize_result(binding, detector_id, run)?;

            if blocks {
                let activation = one_activation(evidence.activations, binding, detector_id)?;
                validate_activation(subject, binding, detector_id, detector, run, activation)?;
                activation_ids.insert(activation.proof().id.clone());
            }
        }

        if !violation {
            reasons.push(format!("{} clean", binding.id));
            continue;
        }
        if let Some(waiver) = exact_waiver(evidence.waivers, subject, binding)? {
            waiver_ids.insert(waiver.waiver().id.clone());
            reasons.push(format!(
                "{} violation waived by {}: {}",
                binding.id,
                waiver.waiver().id,
                waiver.waiver().reason
            ));
            continue;
        }
        if blocks {
            allowed = false;
            reasons.push(format!("{} violation applies {consequence:?}", binding.id));
        } else {
            reasons.push(format!("{} violation records {consequence:?}", binding.id));
        }
    }

    if let Some(target) = qualification_target {
        if !used_qualification_target {
            return Err(Unevaluable::UnusedQualificationTarget(ControlRef {
                binding: target.binding.to_string(),
                detector: target.detector.to_string(),
            }));
        }
    }

    PolicyDecision::operational(
        subject.bundle.clone(),
        subject.policy_digest.clone(),
        subject.intent_digest.clone(),
        subject.subject.clone(),
        subject.population.clone(),
        subject.principal.clone(),
        allowed,
        binding_ids,
        control_run_ids.into_iter().collect(),
        activation_ids.into_iter().collect(),
        waiver_ids.into_iter().collect(),
        reasons,
    )
    .map_err(|_| Unevaluable::DecisionEncoding)
}

fn one_run<'set, 'admission>(
    runs: &'set [AuthorizedControlRun<'admission>],
    binding: &PolicyBinding,
    detector: &str,
) -> Result<&'set AuthorizedControlRun<'admission>, Unevaluable> {
    let control_ref = ControlRef::new(binding, detector);
    let mut matching = runs.iter().filter(|run| run.run().control == detector);
    let run = matching
        .next()
        .ok_or_else(|| Unevaluable::MissingControlRun(control_ref.clone()))?;
    if matching.next().is_some() {
        return Err(Unevaluable::DuplicateControlRun(control_ref));
    }
    Ok(run)
}

pub(crate) fn validate_run(
    subject: &EvaluationSubject,
    binding: &PolicyBinding,
    detector_id: &str,
    detector: &DetectorSpec,
    admitted: &AuthorizedControlRun<'_>,
) -> Result<(), Unevaluable> {
    let run = admitted.run();
    let mismatch = |axis| Unevaluable::ControlBindingMismatch {
        control: ControlRef::new(binding, detector_id),
        axis,
    };
    if admitted.institution() != &subject.institution {
        return Err(mismatch(EvidenceAxis::Institution));
    }
    if admitted.workspace() != &subject.workspace {
        return Err(mismatch(EvidenceAxis::Workspace));
    }
    if admitted.valid_at() != subject.at {
        return Err(mismatch(EvidenceAxis::AuthorityTime));
    }
    if admitted.producer() == &subject.principal {
        return Err(mismatch(EvidenceAxis::ProducerIndependence));
    }
    if run.control_version != detector.control_version {
        return Err(mismatch(EvidenceAxis::ControlVersion));
    }
    if run.configuration_digest != detector.configuration_digest {
        return Err(mismatch(EvidenceAxis::Configuration));
    }
    if run.input_digest != subject.intent_digest {
        return Err(mismatch(EvidenceAxis::Input));
    }
    if run.subject != subject.subject {
        return Err(mismatch(EvidenceAxis::Subject));
    }
    if run.policy != subject.bundle {
        return Err(mismatch(EvidenceAxis::PolicyBundle));
    }
    if run.policy_digest != subject.policy_digest {
        return Err(mismatch(EvidenceAxis::PolicyDigest));
    }
    if run.population != subject.population {
        return Err(mismatch(EvidenceAxis::Population));
    }
    if run.mediation_path != detector.mediation_path {
        return Err(mismatch(EvidenceAxis::MediationPath));
    }
    Ok(())
}

fn normalize_result(
    binding: &PolicyBinding,
    detector: &str,
    admitted: &AuthorizedControlRun<'_>,
) -> Result<bool, Unevaluable> {
    let run = admitted.run();
    normalize_control_result(binding, detector, run.result, &run.coverage)
}

fn normalize_control_result(
    binding: &PolicyBinding,
    detector: &str,
    result: ControlResult,
    coverage: &Coverage,
) -> Result<bool, Unevaluable> {
    let control_ref = || ControlRef::new(binding, detector);
    match result {
        ControlResult::NotRun => return Err(Unevaluable::ControlNotRun(control_ref())),
        ControlResult::Unavailable => {
            return Err(Unevaluable::ControlUnavailable(control_ref()));
        }
        ControlResult::Unevaluable => {
            return Err(Unevaluable::ControlUnevaluable(control_ref()));
        }
        ControlResult::UnexpectedlyEmpty => {
            return Err(Unevaluable::ControlUnexpectedlyEmpty(control_ref()));
        }
        ControlResult::NotApplicable => {
            return Err(Unevaluable::ControlNotApplicable(control_ref()));
        }
        ControlResult::Unresolved => {
            return Err(Unevaluable::ControlUnresolved(control_ref()));
        }
        ControlResult::Clean | ControlResult::Violation => {}
        _ => return Err(Unevaluable::UnsupportedControlResult(control_ref())),
    }
    if coverage.population == 0 {
        return Err(Unevaluable::EmptyPopulation(control_ref()));
    }
    if coverage.observed == 0 {
        return Err(Unevaluable::UnobservedPopulation(control_ref()));
    }
    if coverage.observed > coverage.population {
        return Err(Unevaluable::InvalidCoverage {
            control: control_ref(),
            observed: coverage.observed,
            population: coverage.population,
        });
    }
    if result == ControlResult::Clean && !coverage.is_complete() {
        return Err(Unevaluable::PartialCleanCoverage {
            control: control_ref(),
            observed: coverage.observed,
            population: coverage.population,
        });
    }
    Ok(result == ControlResult::Violation)
}

fn one_activation<'set, 'admission>(
    activations: &'set [VerifiedActivation<'admission>],
    binding: &PolicyBinding,
    detector: &str,
) -> Result<&'set VerifiedActivation<'admission>, Unevaluable> {
    let control_ref = ControlRef::new(binding, detector);
    let mut matching = activations
        .iter()
        .filter(|activation| activation.proof().control == detector);
    let activation = matching
        .next()
        .ok_or_else(|| Unevaluable::MissingActivationProof(control_ref.clone()))?;
    if matching.next().is_some() {
        return Err(Unevaluable::DuplicateActivationProof(control_ref));
    }
    Ok(activation)
}

fn validate_activation(
    subject: &EvaluationSubject,
    binding: &PolicyBinding,
    detector_id: &str,
    detector: &DetectorSpec,
    run: &AuthorizedControlRun<'_>,
    activation: &VerifiedActivation<'_>,
) -> Result<(), Unevaluable> {
    let proof = activation.proof();
    let mismatch = |axis| Unevaluable::ActivationBindingMismatch {
        control: ControlRef::new(binding, detector_id),
        axis,
    };
    if activation.institution() != &subject.institution {
        return Err(mismatch(EvidenceAxis::Institution));
    }
    if activation.workspace() != &subject.workspace {
        return Err(mismatch(EvidenceAxis::Workspace));
    }
    if activation.valid_at() != subject.at {
        return Err(mismatch(EvidenceAxis::AuthorityTime));
    }
    if activation.verifier() == run.producer() || activation.verifier() == &subject.principal {
        return Err(Unevaluable::SelfAttestedActivation(ControlRef::new(
            binding,
            detector_id,
        )));
    }
    if proof.proved_at > run.run().started_at {
        return Err(Unevaluable::ActivationAfterRun(ControlRef::new(
            binding,
            detector_id,
        )));
    }
    if proof.control_version != detector.control_version {
        return Err(mismatch(EvidenceAxis::ControlVersion));
    }
    if proof.configuration_digest != detector.configuration_digest {
        return Err(mismatch(EvidenceAxis::Configuration));
    }
    if proof.policy != subject.bundle {
        return Err(mismatch(EvidenceAxis::PolicyBundle));
    }
    if proof.policy_digest != subject.policy_digest {
        return Err(mismatch(EvidenceAxis::PolicyDigest));
    }
    if proof.population != detector.calibration_population {
        return Err(mismatch(EvidenceAxis::Population));
    }
    if proof.mediation_path != detector.mediation_path {
        return Err(mismatch(EvidenceAxis::MediationPath));
    }
    Ok(())
}

fn exact_waiver<'set, 'admission>(
    waivers: &'set [DelegatedWaiver<'admission>],
    subject: &EvaluationSubject,
    binding: &PolicyBinding,
) -> Result<Option<&'set DelegatedWaiver<'admission>>, Unevaluable> {
    let matching: Vec<_> = waivers
        .iter()
        .filter(|waiver| waiver.waiver().binding_id == binding.id)
        .collect();
    if matching.len() > 1 {
        return Err(Unevaluable::DuplicateWaiver {
            binding: binding.id.clone(),
        });
    }
    let Some(waiver) = matching.first().copied() else {
        return Ok(None);
    };
    let signed = waiver.waiver();
    let mismatch = |axis| Unevaluable::WaiverBindingMismatch {
        binding: binding.id.clone(),
        axis,
    };
    if waiver.institution() != &subject.institution {
        return Err(mismatch(EvidenceAxis::Institution));
    }
    if waiver.workspace() != &subject.workspace {
        return Err(mismatch(EvidenceAxis::Workspace));
    }
    if waiver.valid_at() != subject.at {
        return Err(mismatch(EvidenceAxis::AuthorityTime));
    }
    if signed.policy != subject.bundle {
        return Err(mismatch(EvidenceAxis::PolicyBundle));
    }
    if signed.policy_digest != subject.policy_digest {
        return Err(mismatch(EvidenceAxis::PolicyDigest));
    }
    if signed.subject != subject.subject {
        return Err(mismatch(EvidenceAxis::Subject));
    }
    if signed.population != subject.population {
        return Err(mismatch(EvidenceAxis::Population));
    }
    if signed.scope != binding.scope || !subject.scopes.contains(&signed.scope) {
        return Err(mismatch(EvidenceAxis::Scope));
    }
    Ok(Some(waiver))
}

/// The rung a binding must have climbed before it may block at all.
pub const fn blocking_requires_at_least() -> HardeningState {
    HardeningState::Enforced
}
